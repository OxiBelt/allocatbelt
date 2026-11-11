//! Managed resource accounting: a scope's budget of zero-filled byte
//! buffers and its bounds on concurrent disk and network operations, kept
//! in one ledger behind one lock.
//!
//! A [`ResourceScope`] is a handle to that ledger. It charges each
//! [`ManagedBuf`] it allocates and each [`OperationPermit`] it grants; the
//! buffer or permit owns its charge and returns it when it is dropped, so
//! the ledger counts include live owners and in-progress allocation reservations.
//! Buffers and permits keep the ledger alive and may outlive every scope
//! handle.
//!
//! # What is counted
//!
//! A buffer's Memory charge is its retained vector capacity. Clones share that
//! storage and its one charge, which is released after the storage is freed,
//! when the last clone is dropped. A scope from [`ResourceScope::try_from_tenant`]
//! additionally charges the declared `Ledger` and `Backing` payload sizes to
//! Control. Legacy [`ResourceScope::new`] and [`ResourceScope::from_tenant`]
//! retain their previous uncharged metadata behavior. These charges do not
//! cover allocator headers, Arc control blocks, page residency (RSS), or
//! memory allocated outside the scope. Initial Backing admission couples its
//! requested Memory and Control payloads. Growth keeps that one Backing charge
//! and reserves the complete replacement Memory while the old storage remains
//! charged.
//!
//! A permit holds disk and network operation slots: concurrency counts the
//! caller declares, released exactly once when the permit is dropped. There
//! are no byte-rate or bandwidth limits here, and this module does not
//! account CPU.
//!
//! # Allocation failure
//!
//! A buffer's storage is reserved in the ledger first and then allocated
//! with `Vec::try_reserve_exact`. When the allocator refuses, Memory and any
//! coupled Control reservation are released and [`ResourceError::OutOfMemory`]
//! is returned. For controlled scopes, the declared Backing payload charge is
//! reserved before `Arc::new`; Arc allocator headers and allocator failure
//! for the Arc or ledger follow Rust's usual out-of-memory handling
//! (`handle_alloc_error`, which aborts by default) instead of returning an
//! error.
//!
//! # Locks
//!
//! The ledger lock is held only for checked arithmetic on the counts. No
//! user code runs, nothing is allocated or freed and nothing can panic under
//! it: storage is allocated after its reservation is stored and freed before
//! its charge is released. A poisoned lock therefore still holds consistent
//! counts and is used as is; no panic is caught.

use std::array;
use std::fmt;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::resource_domain::{
  ControlCharge, DomainError, DomainReservation, DomainResource, DomainResources, TenantDomain,
};

#[cfg(all(test, loom))]
#[path = "managed_model.rs"]
mod model;

#[cfg(all(test, loom))]
mod domain_model {
  use loom::thread;

  use super::{Backing, Ledger, ResourceError, ResourceLimits, ResourceScope, domain_memory};
  use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};

  #[test]
  fn loom_bound_scopes_compete_in_the_same_global_and_tenant_ledger() {
    loom::model(|| {
      let ceiling = DomainResources::ZERO
        .with(DomainResource::Memory, 8)
        .with(DomainResource::Control, 4096);
      let domain = ResourceDomain::new(ceiling, 2).unwrap();
      let tenant_ceiling = domain_memory(8).with(DomainResource::Control, 4096);
      let left = ResourceScope::from_tenant(
        ResourceLimits {
          managed_memory: 8,
          ..ResourceLimits::default()
        },
        domain.tenant(tenant_ceiling).unwrap(),
      );
      let right = ResourceScope::from_tenant(
        ResourceLimits {
          managed_memory: 8,
          ..ResourceLimits::default()
        },
        domain.tenant(tenant_ceiling).unwrap(),
      );

      let left = thread::spawn(move || left.try_alloc_zeroed(8));
      let right = thread::spawn(move || right.try_alloc_zeroed(8));
      let left = left.join().unwrap();
      let right = right.join().unwrap();
      assert_ne!(left.is_ok(), right.is_ok());
      assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 8);
      drop(left);
      drop(right);
      assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 0);
    });
  }

  #[test]
  fn loom_controlled_backings_admit_memory_and_control_as_one_vector() {
    loom::model(|| {
      let scope_bytes = std::mem::size_of::<Ledger>();
      let backing_bytes = std::mem::size_of::<Backing>();
      let ceiling = DomainResources::ZERO
        .with(DomainResource::Memory, 16)
        .with(DomainResource::Control, 1 << 16);
      let domain = ResourceDomain::with_waiters(ceiling, 1, 0).unwrap();
      let tenant_ceiling = ceiling
        .with(DomainResource::Memory, 16)
        .with(DomainResource::Control, scope_bytes + backing_bytes);
      let tenant = domain.tenant(tenant_ceiling).unwrap();
      tenant.set_limits(tenant_ceiling).unwrap();
      let baseline_control = domain.snapshot().used.get(DomainResource::Control);
      let scope = ResourceScope::try_from_tenant(
        ResourceLimits {
          managed_memory: 32,
          ..ResourceLimits::default()
        },
        tenant,
      )
      .unwrap();

      let first_scope = scope.clone();
      let second_scope = scope.clone();
      let first = thread::spawn(move || first_scope.try_alloc_zeroed(8));
      let second = thread::spawn(move || second_scope.try_alloc_zeroed(8));
      let first = first.join().unwrap();
      let second = second.join().unwrap();
      let (buffer, rejected) = match (first, second) {
        (Ok(buffer), Err(error)) | (Err(error), Ok(buffer)) => (buffer, error),
        (Ok(_), Ok(_)) => panic!("both controlled allocations were admitted"),
        (Err(first), Err(_second)) => panic!("both controlled allocations failed: {first:?}"),
      };
      assert_eq!(rejected, ResourceError::DomainControlExhausted);
      assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 8);
      assert_eq!(
        domain.snapshot().used.get(DomainResource::Control),
        baseline_control + scope_bytes + backing_bytes
      );
      drop(buffer);
      drop(scope);
      assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 0);
      assert_eq!(
        domain.snapshot().used.get(DomainResource::Control),
        baseline_control
      );
    });
  }
}

#[cfg(all(test, not(loom)))]
#[path = "managed_domain_tests.rs"]
mod domain_tests;

/// The largest storage a buffer can request: a Rust allocation is at most
/// `isize::MAX` bytes.
const MAX_STORAGE: usize = isize::MAX.unsigned_abs();

/// The bounds of a [`ResourceScope`], fixed when it is created.
///
/// The default (all zero) admits only empty buffers and empty operation
/// requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ResourceLimits {
  /// Bytes of [`ManagedBuf`] storage the scope's live buffers may be
  /// charged at once.
  pub managed_memory: usize,
  /// Disk operation slots the scope's live permits may hold at once.
  pub disk_concurrent_ops: usize,
  /// Network operation slots the scope's live permits may hold at once.
  pub network_concurrent_ops: usize,
}

/// A resource a [`ResourceScope`] accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResourceKind {
  /// Managed buffer storage, in bytes.
  Memory,
  /// Concurrent disk operation slots.
  Disk,
  /// Concurrent network operation slots.
  Network,
}

impl fmt::Display for ResourceKind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Memory => "managed memory",
      Self::Disk => "disk operation",
      Self::Network => "network operation",
    })
  }
}

/// Why a buffer allocation, resize or operation permit was refused. On
/// every error the ledger and the buffer are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResourceError {
  /// The request exceeds the scope's limit for the resource, or for memory
  /// the largest possible allocation (`isize::MAX` bytes), and can never
  /// succeed in this scope.
  Invalid(ResourceKind),
  /// The request fits the limit but not what is free now (a total that
  /// would overflow `usize` included); it may succeed after other charges
  /// or permits are released.
  Exhausted(ResourceKind),
  /// The memory was reserved, but the allocator refused the storage. The
  /// reservation has been released.
  OutOfMemory,
  /// The buffer has other clones, and only a uniquely owned buffer can be
  /// resized.
  Shared,
  /// The attached tenant has closed admission. Existing charges remain live
  /// until their buffers and permits are dropped.
  Closed,
  /// The domain could not admit charged metadata or another fixed control
  /// reservation.
  DomainControlExhausted,
  /// The attached domain refused admission for a condition outside the
  /// managed memory, disk and network resource kinds.
  DomainAdmission,
}

impl fmt::Display for ResourceError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Invalid(kind) => write!(f, "request exceeds the scope's {kind} limit"),
      Self::Exhausted(kind) => write!(f, "not enough free {kind} capacity"),
      Self::OutOfMemory => f.write_str("the allocator refused the buffer's storage"),
      Self::Shared => f.write_str("the buffer has other clones"),
      Self::Closed => f.write_str("the attached tenant has closed admission"),
      Self::DomainControlExhausted => {
        f.write_str("the resource domain has no free control reservation capacity")
      }
      Self::DomainAdmission => f.write_str("the resource domain refused admission"),
    }
  }
}

impl std::error::Error for ResourceError {}

/// Disk and network operation slots requested together by
/// [`ResourceScope::try_acquire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct OperationRequest {
  /// Disk operation slots.
  pub disk: usize,
  /// Network operation slots.
  pub network: usize,
}

/// A point-in-time view of a scope's ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceSnapshot {
  /// The scope's limits.
  pub limits: ResourceLimits,
  /// Bytes charged to live buffers and in-progress storage reservations.
  /// At most `limits.managed_memory`.
  pub managed_memory: usize,
  /// Disk slots held by live permits. At most `limits.disk_concurrent_ops`.
  pub disk_ops: usize,
  /// Network slots held by live permits. At most
  /// `limits.network_concurrent_ops`.
  pub network_ops: usize,
}

/// The limits and what live buffers and permits are charged against them.
///
/// Invariant: every count is at most its limit. Each charge is checked
/// against the limit before it is stored, so no sum wraps, and while every
/// charge is released at most once no release underflows.
#[derive(Debug)]
struct Ledger {
  limits: ResourceLimits,
  memory: usize,
  disk: usize,
  network: usize,
  // A controlled tenant scope accounts for this shared ledger payload. The
  // charge lives here so buffers and permits retain it through their Arc.
  _control: Option<ControlCharge>,
}

/// `used + request` when it is at most `limit`, otherwise `Exhausted`.
fn add_within(
  used: usize,
  request: usize,
  limit: usize,
  kind: ResourceKind,
) -> Result<usize, ResourceError> {
  match used.checked_add(request) {
    Some(total) if total <= limit => Ok(total),
    _ => Err(ResourceError::Exhausted(kind)),
  }
}

impl Ledger {
  const fn new(limits: ResourceLimits) -> Self {
    Self::new_with_control(limits, None)
  }

  const fn new_with_control(limits: ResourceLimits, control: Option<ControlCharge>) -> Self {
    Self {
      limits,
      memory: 0,
      disk: 0,
      network: 0,
      _control: control,
    }
  }

  /// Charges `extra` more bytes for a buffer whose storage grows to
  /// `target` bytes. `Invalid` when `target` alone exceeds the limit,
  /// `Exhausted` when `extra` does not fit what is free now.
  fn reserve_memory(&mut self, target: usize, extra: usize) -> Result<(), ResourceError> {
    let limit = self.limits.managed_memory;
    if target > limit {
      return Err(ResourceError::Invalid(ResourceKind::Memory));
    }
    self.memory = add_within(self.memory, extra, limit, ResourceKind::Memory)?;
    Ok(())
  }

  /// Returns `bytes` of charge. `false`, leaving the count unchanged, when
  /// less than that is charged.
  fn release_memory(&mut self, bytes: usize) -> bool {
    let Some(memory) = self.memory.checked_sub(bytes) else {
      return false;
    };
    self.memory = memory;
    true
  }

  /// Takes every slot of `request` or none. A component above its limit is
  /// reported as `Invalid` before any is reported as `Exhausted`.
  fn acquire_ops(&mut self, request: OperationRequest) -> Result<(), ResourceError> {
    let disk_limit = self.limits.disk_concurrent_ops;
    let network_limit = self.limits.network_concurrent_ops;
    if request.disk > disk_limit {
      return Err(ResourceError::Invalid(ResourceKind::Disk));
    }
    if request.network > network_limit {
      return Err(ResourceError::Invalid(ResourceKind::Network));
    }
    let disk = add_within(self.disk, request.disk, disk_limit, ResourceKind::Disk)?;
    let network = add_within(
      self.network,
      request.network,
      network_limit,
      ResourceKind::Network,
    )?;
    self.disk = disk;
    self.network = network;
    Ok(())
  }

  /// Returns the slots of `request`. `false`, leaving the counts unchanged,
  /// when fewer than that are held.
  fn release_ops(&mut self, request: OperationRequest) -> bool {
    let (Some(disk), Some(network)) = (
      self.disk.checked_sub(request.disk),
      self.network.checked_sub(request.network),
    ) else {
      return false;
    };
    self.disk = disk;
    self.network = network;
    true
  }

  const fn snapshot(&self) -> ResourceSnapshot {
    ResourceSnapshot {
      limits: self.limits,
      managed_memory: self.memory,
      disk_ops: self.disk,
      network_ops: self.network,
    }
  }
}

/// The lock runs no user code and cannot panic while held, so a poisoned
/// lock still holds consistent counts.
fn lock(ledger: &Mutex<Ledger>) -> MutexGuard<'_, Ledger> {
  ledger.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A handle to a shared resource ledger with fixed [`ResourceLimits`].
///
/// Cloning the handle shares the same ledger and reserves nothing. Buffers
/// and permits hold the ledger themselves, so every scope handle may be
/// dropped while they live; their charges are still returned when they are
/// dropped. A scope made with [`ResourceScope::from_tenant`] also charges
/// those resources to one global and one tenant ledger under the resource
/// domain's lock. Its local snapshot remains scoped to this handle's
/// [`ResourceLimits`]; it is not a transactional view of both locks.
#[derive(Clone)]
pub struct ResourceScope {
  ledger: Arc<Mutex<Ledger>>,
  tenant: Option<TenantDomain>,
  control_metadata: bool,
}

impl ResourceScope {
  /// A scope with nothing charged. The ledger is allocated by `Arc::new`
  /// (see the module documentation on allocation failure).
  #[must_use]
  pub fn new(limits: ResourceLimits) -> Self {
    Self {
      ledger: Arc::new(Mutex::new(Ledger::new(limits))),
      tenant: None,
      control_metadata: false,
    }
  }

  /// A scope with local limits that also reserves every managed memory,
  /// disk and network charge from `tenant`'s global and tenant domain ledgers.
  ///
  /// Each domain reservation updates the global and tenant dimensions
  /// atomically. The local [`ResourceLimits`] remain an additional bound and
  /// can reject earlier; [`ResourceScope::snapshot`] reports only that local
  /// ledger. Clones, buffers and permits retain the tenant owner so the
  /// tenant generation cannot be recycled while any bounded handle remains.
  /// Closing the tenant rejects new positive memory reservations and operation
  /// permits while existing buffers and permits continue to hold their
  /// reservations until their actual drop. This legacy constructor does not
  /// charge the scope or backing payloads to `Control`; use
  /// [`ResourceScope::try_from_tenant`] for metadata accounting.
  #[must_use]
  pub fn from_tenant(limits: ResourceLimits, tenant: TenantDomain) -> Self {
    Self {
      ledger: Arc::new(Mutex::new(Ledger::new(limits))),
      tenant: Some(tenant),
      control_metadata: false,
    }
  }

  /// Creates a tenant-bound scope that charges its shared ledger and each
  /// live buffer backing to `Control` in addition to declared resource use.
  ///
  /// The ledger payload is reserved before its `Arc` allocation. Initial
  /// Backing admission reserves requested Memory and known Backing Control
  /// payloads together in the domain's atomic vector; growth retains that one
  /// Backing charge while reserving complete replacement Memory. The charges
  /// follow the last buffer clone, even if every scope handle is dropped. Arc
  /// allocator headers and allocations outside this scope remain unmeasured.
  pub fn try_from_tenant(
    limits: ResourceLimits,
    tenant: TenantDomain,
  ) -> Result<Self, DomainError> {
    let control = ControlCharge::try_new(Some(&tenant), std::mem::size_of::<Ledger>())?;
    Ok(Self {
      ledger: Arc::new(Mutex::new(Ledger::new_with_control(limits, Some(control)))),
      tenant: Some(tenant),
      control_metadata: true,
    })
  }

  /// The shared tenant used for global admission, when this scope is bound.
  /// Cloning this handle retains the same tenant generation.
  #[must_use]
  pub fn tenant_domain(&self) -> Option<&TenantDomain> {
    self.tenant.as_ref()
  }

  /// Whether this scope's shared ledger and Backing payloads consume Control.
  #[must_use]
  pub(crate) const fn is_control_accounted(&self) -> bool {
    self.control_metadata
  }

  /// The limits the scope was created with.
  #[must_use]
  pub fn limits(&self) -> ResourceLimits {
    lock(&self.ledger).limits
  }

  /// The limits and current charges, read under the ledger lock.
  #[must_use]
  pub fn snapshot(&self) -> ResourceSnapshot {
    lock(&self.ledger).snapshot()
  }

  /// A zero-filled buffer of `len` bytes, charged its retained vector capacity.
  /// The initial reservation covers `len`; excess returned capacity must also
  /// fit the ledger before the buffer becomes accessible.
  ///
  /// The bytes are reserved in the ledger before the storage is allocated
  /// fallibly; if the allocator refuses, the reservation is released before
  /// this returns. A zero `len` charges and allocates no storage. The
  /// buffer's shared header is then allocated by `Arc::new`, which does not
  /// return an error (see the module documentation).
  ///
  /// # Errors
  ///
  /// `Invalid(Memory)` when `len` exceeds the memory limit or `isize::MAX`,
  /// `Exhausted(Memory)` when it does not fit what is free now, and
  /// `OutOfMemory` when the allocator refuses the storage.
  pub fn try_alloc_zeroed(&self, len: usize) -> Result<ManagedBuf, ResourceError> {
    let mut backing = Backing {
      storage: Vec::new(),
      charged: 0,
      ledger: Arc::clone(&self.ledger),
      domain_charges: empty_domain_charges(),
      backing_control: None,
      tenant: self.tenant.clone(),
      control_metadata: self.is_control_accounted(),
    };
    backing.try_resize(len)?;
    Ok(ManagedBuf {
      backing: Arc::new(backing),
    })
  }

  /// A permit holding every slot of `request`, or none of them.
  ///
  /// Both components are checked and taken under one lock acquisition, so
  /// a refused request leaves the ledger unchanged. A zero request holds no
  /// operation slots; a tenant-bound request still requires open admission
  /// and retains that tenant generation until the permit drops.
  ///
  /// # Errors
  ///
  /// `Invalid(Disk)` or `Invalid(Network)` when a component exceeds its
  /// limit (checked first, for both), otherwise `Exhausted(Disk)` or
  /// `Exhausted(Network)` when a component does not fit what is free now.
  pub fn try_acquire(&self, request: OperationRequest) -> Result<OperationPermit, ResourceError> {
    lock(&self.ledger).acquire_ops(request)?;
    let domain_charge = match self.tenant.as_ref() {
      Some(tenant) => match tenant.try_acquire(domain_ops(request)) {
        Ok(reservation) => Some(reservation),
        Err(error) => {
          // The domain and local ledgers have separate locks. Roll the local
          // reservation back only after the domain lock has been released.
          let released = lock(&self.ledger).release_ops(request);
          debug_assert!(released, "operation slots rolled back without a charge");
          return Err(map_domain_error(error));
        }
      },
      None => None,
    };
    Ok(OperationPermit {
      ledger: Arc::clone(&self.ledger),
      request,
      _domain_charge: domain_charge,
      _tenant: self.tenant.clone(),
    })
  }
}

impl fmt::Debug for ResourceScope {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let snapshot = self.snapshot();
    f.debug_struct("ResourceScope")
      .field("snapshot", &snapshot)
      .finish()
  }
}

/// Disk and network operation slots held from a [`ResourceScope`] until
/// the permit is dropped.
///
/// Not `Clone`: each permit returns its slots exactly once, in `Drop`.
#[must_use = "the slots are released as soon as the permit is dropped"]
pub struct OperationPermit {
  ledger: Arc<Mutex<Ledger>>,
  request: OperationRequest,
  // Drop the reservation before the final tenant handle. Neither destructor
  // runs while the local ledger lock is held.
  _domain_charge: Option<DomainReservation>,
  _tenant: Option<TenantDomain>,
}

impl OperationPermit {
  /// Disk operation slots held.
  #[must_use]
  pub const fn disk(&self) -> usize {
    self.request.disk
  }

  /// Network operation slots held.
  #[must_use]
  pub const fn network(&self) -> usize {
    self.request.network
  }
}

impl Drop for OperationPermit {
  fn drop(&mut self) {
    if self.request.disk == 0 && self.request.network == 0 {
      return;
    }
    let released = lock(&self.ledger).release_ops(self.request);
    debug_assert!(released, "operation slots released without a permit");
  }
}

impl fmt::Debug for OperationPermit {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("OperationPermit")
      .field("disk", &self.request.disk)
      .field("network", &self.request.network)
      .finish_non_exhaustive()
  }
}

/// A buffer's storage and the charge it owns.
///
/// Invariant: `storage.capacity() == charged >= storage.len()`, and the
/// ledger holds `charged` bytes for this storage until it is freed.
struct Backing {
  storage: Vec<u8>,
  charged: usize,
  ledger: Arc<Mutex<Ledger>>,
  // At most two tickets account for this Vec: its requested length and any
  // capacity the allocator returned beyond that length. New tickets replace
  // this fixed array during growth; the list cannot grow with resize history.
  domain_charges: [Option<DomainReservation>; 2],
  // The Backing payload is allocated once and reused by uniquely owned Vec
  // growth, so its Control ticket is separate from replaceable Memory.
  backing_control: Option<ControlCharge>,
  tenant: Option<TenantDomain>,
  control_metadata: bool,
}

fn empty_domain_charges() -> [Option<DomainReservation>; 2] {
  array::from_fn(|_| None)
}

fn domain_memory(bytes: usize) -> DomainResources {
  DomainResources::ZERO.with(DomainResource::Memory, bytes)
}

fn domain_backing(memory_bytes: usize, control_bytes: usize) -> DomainResources {
  DomainResources::ZERO
    .with(DomainResource::Memory, memory_bytes)
    .with(DomainResource::Control, control_bytes)
}

fn domain_ops(request: OperationRequest) -> DomainResources {
  DomainResources::ZERO
    .with(DomainResource::Disk, request.disk)
    .with(DomainResource::Network, request.network)
}

fn map_domain_error(error: DomainError) -> ResourceError {
  match error {
    DomainError::Closed => ResourceError::Closed,
    DomainError::AboveCeiling(DomainResource::Memory) => {
      ResourceError::Invalid(ResourceKind::Memory)
    }
    DomainError::AboveCeiling(DomainResource::Disk) => ResourceError::Invalid(ResourceKind::Disk),
    DomainError::AboveCeiling(DomainResource::Network) => {
      ResourceError::Invalid(ResourceKind::Network)
    }
    DomainError::Exhausted(DomainResource::Memory) => {
      ResourceError::Exhausted(ResourceKind::Memory)
    }
    DomainError::Exhausted(DomainResource::Disk) => ResourceError::Exhausted(ResourceKind::Disk),
    DomainError::Exhausted(DomainResource::Network) => {
      ResourceError::Exhausted(ResourceKind::Network)
    }
    DomainError::AboveCeiling(DomainResource::Control)
    | DomainError::Exhausted(DomainResource::Control)
    | DomainError::WaitersFull => ResourceError::DomainControlExhausted,
    // Managed scopes never request CPU, tasks or control. Keep every
    // unexpected domain refusal visible as a typed error rather than
    // bypassing domain admission.
    DomainError::Invalid
    | DomainError::OutOfMemory
    | DomainError::TenantsFull
    | DomainError::GenerationExhausted
    | DomainError::AboveCeiling(DomainResource::Cpu | DomainResource::Tasks)
    | DomainError::Exhausted(DomainResource::Cpu | DomainResource::Tasks) => {
      ResourceError::DomainAdmission
    }
  }
}

impl Backing {
  /// Sets the length to `new_len`, zero-filling new bytes; see
  /// [`ManagedBuf::try_resize`]. On an error nothing has changed.
  fn try_resize(&mut self, new_len: usize) -> Result<(), ResourceError> {
    if new_len <= self.charged {
      if self.control_metadata && self.backing_control.is_none() {
        let Some(tenant) = &self.tenant else {
          return Err(ResourceError::DomainAdmission);
        };
        let control_bytes = std::mem::size_of::<Backing>();
        let ticket = tenant
          .try_acquire(domain_backing(0, control_bytes))
          .map_err(map_domain_error)?;
        self.backing_control = Some(ControlCharge::from_ticket(
          Some(tenant),
          ticket,
          control_bytes,
        ));
      }
      // Capacity is already charged, so this neither reserves nor reallocates.
      self.storage.resize(new_len, 0);
      return Ok(());
    }
    if new_len > MAX_STORAGE {
      return Err(ResourceError::Invalid(ResourceKind::Memory));
    }
    // The old storage remains live until replacement succeeds. Reserving
    // only a size delta would undercount the moving allocation's peak.
    lock(&self.ledger).reserve_memory(new_len, new_len)?;
    let mut domain_charges = empty_domain_charges();
    let mut backing_control = None;
    if let Some(tenant) = &self.tenant {
      let control_bytes = if self.control_metadata && self.backing_control.is_none() {
        std::mem::size_of::<Backing>()
      } else {
        0
      };
      match tenant.try_acquire(domain_backing(new_len, control_bytes)) {
        Ok(mut reservation) => {
          if control_bytes != 0 {
            match reservation
              .split_off(DomainResources::ZERO.with(DomainResource::Control, control_bytes))
            {
              Ok(ticket) => {
                backing_control = Some(ControlCharge::from_ticket(
                  Some(tenant),
                  ticket,
                  control_bytes,
                ));
              }
              Err(error) => {
                drop(reservation);
                self.release(new_len);
                return Err(map_domain_error(error));
              }
            }
          }
          if new_len != 0 {
            domain_charges[0] = Some(reservation);
          } else {
            drop(reservation);
          }
        }
        Err(error) => {
          self.release(new_len);
          return Err(map_domain_error(error));
        }
      }
    }
    let mut replacement = Vec::new();
    if replacement.try_reserve_exact(new_len).is_err() {
      drop(domain_charges);
      self.release(new_len);
      return Err(ResourceError::OutOfMemory);
    }
    let capacity = replacement.capacity();
    // Vec may provide more capacity than requested. Account it before use
    // and free the replacement before rolling back a refused reservation.
    if capacity > new_len {
      let reservation = lock(&self.ledger).reserve_memory(capacity, capacity - new_len);
      if let Err(error) = reservation {
        drop(replacement);
        drop(domain_charges);
        self.release(new_len);
        return Err(error);
      }
      if let Some(tenant) = &self.tenant {
        match tenant.try_acquire(domain_memory(capacity - new_len)) {
          Ok(reservation) => domain_charges[1] = Some(reservation),
          Err(error) => {
            drop(replacement);
            drop(domain_charges);
            self.release(capacity);
            return Err(map_domain_error(error));
          }
        }
      }
    }
    replacement.resize(new_len, 0);
    replacement[..self.storage.len()].copy_from_slice(&self.storage);
    let old_charge = self.charged;
    let old_storage = std::mem::replace(&mut self.storage, replacement);
    let old_domain_charges = std::mem::replace(&mut self.domain_charges, domain_charges);
    self.charged = capacity;
    if let Some(control) = backing_control {
      debug_assert!(self.backing_control.is_none());
      self.backing_control = Some(control);
    }
    drop(old_storage);
    self.release(old_charge);
    // Ticket drops take the domain mutex, so keep them outside the local
    // ledger lock and after the replaced storage has actually been freed.
    drop(old_domain_charges);
    Ok(())
  }

  fn release(&self, bytes: usize) {
    let released = lock(&self.ledger).release_memory(bytes);
    debug_assert!(released, "managed memory released without a charge");
  }
}

impl Drop for Backing {
  fn drop(&mut self) {
    // Free the storage before returning its charge, so the ledger never
    // shows less than the live storage.
    self.storage = Vec::new();
    if self.charged != 0 {
      self.release(self.charged);
    }
  }
}

/// A zero-initialized byte buffer charged to a [`ResourceScope`].
///
/// Clones share the same immutable storage and its one charge; the storage
/// is freed and the charge returned when the last clone is dropped, even
/// if every scope handle was dropped before. A uniquely owned buffer can be
/// written through [`ManagedBuf::get_mut`] and resized with
/// [`ManagedBuf::try_resize`].
#[derive(Clone)]
pub struct ManagedBuf {
  backing: Arc<Backing>,
}

impl ManagedBuf {
  /// The length in bytes.
  #[must_use]
  pub fn len(&self) -> usize {
    self.backing.storage.len()
  }

  /// Whether the length is zero.
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.backing.storage.is_empty()
  }

  /// The bytes.
  #[must_use]
  pub fn as_slice(&self) -> &[u8] {
    &self.backing.storage
  }

  /// Bytes charged to the scope for retained vector capacity, shared by
  /// all clones. Shrinking the length retains both storage and its charge.
  #[must_use]
  pub fn charged_bytes(&self) -> usize {
    self.backing.charged
  }

  /// The bytes, writable, or `None` while other clones exist.
  pub fn get_mut(&mut self) -> Option<&mut [u8]> {
    let backing = Arc::get_mut(&mut self.backing)?;
    Some(backing.storage.as_mut_slice())
  }

  /// Resizes a uniquely owned buffer to `new_len` bytes; bytes past the old
  /// length read as zero.
  ///
  /// Shrinking keeps the storage and its charge. Growing within the charged
  /// storage (up to [`ManagedBuf::charged_bytes`]) needs neither a
  /// reservation nor an allocation. Growing past it reserves the full
  /// replacement first while the old storage remains charged, then copies
  /// into fallibly allocated storage and frees the old storage. A growth
  /// can therefore be exhausted even when its final size fits the limit. On an error the contents, length and charge are
  /// unchanged.
  ///
  /// # Errors
  ///
  /// `Shared` while other clones exist; otherwise, when growing past the
  /// charged storage, as [`ResourceScope::try_alloc_zeroed`] for `new_len`.
  pub fn try_resize(&mut self, new_len: usize) -> Result<(), ResourceError> {
    Arc::get_mut(&mut self.backing)
      .ok_or(ResourceError::Shared)?
      .try_resize(new_len)
  }
}

impl Deref for ManagedBuf {
  type Target = [u8];

  fn deref(&self) -> &[u8] {
    self.as_slice()
  }
}

impl AsRef<[u8]> for ManagedBuf {
  fn as_ref(&self) -> &[u8] {
    self.as_slice()
  }
}

impl fmt::Debug for ManagedBuf {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ManagedBuf")
      .field("len", &self.len())
      .field("charged", &self.charged_bytes())
      .finish_non_exhaustive()
  }
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::thread;

  use super::{Ledger, MAX_STORAGE, ManagedBuf, OperationPermit, OperationRequest};
  use super::{ResourceError, ResourceKind, ResourceLimits, ResourceScope};
  use crate::runtime::resource_domain::{
    DomainError, DomainResource, DomainResources, ResourceDomain,
  };

  const MEMORY: ResourceKind = ResourceKind::Memory;
  const DISK: ResourceKind = ResourceKind::Disk;
  const NETWORK: ResourceKind = ResourceKind::Network;

  fn limits(memory: usize, disk: usize, network: usize) -> ResourceLimits {
    ResourceLimits {
      managed_memory: memory,
      disk_concurrent_ops: disk,
      network_concurrent_ops: network,
    }
  }

  fn ops(disk: usize, network: usize) -> OperationRequest {
    OperationRequest { disk, network }
  }

  /// `(managed_memory, disk_ops, network_ops)`.
  fn used(scope: &ResourceScope) -> (usize, usize, usize) {
    let s = scope.snapshot();
    (s.managed_memory, s.disk_ops, s.network_ops)
  }

  #[test]
  fn handles_are_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<ResourceScope>();
    check::<ManagedBuf>();
    check::<OperationPermit>();
  }

  #[test]
  fn controlled_scope_and_zero_length_backing_charge_until_last_clone() {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Memory, 256)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 0).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let control_before = domain.snapshot().used.get(DomainResource::Control);
    let scope_control = std::mem::size_of::<Ledger>();
    let backing_control = std::mem::size_of::<super::Backing>();
    tenant
      .set_limits(DomainResources::ZERO.with(DomainResource::Control, 0))
      .unwrap();
    assert_eq!(
      ResourceScope::try_from_tenant(limits(128, 0, 0), tenant.clone()).map(drop),
      Err(DomainError::Exhausted(DomainResource::Control))
    );
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      control_before
    );
    tenant.set_limits(ceiling).unwrap();
    let scope = ResourceScope::try_from_tenant(limits(128, 0, 0), tenant).unwrap();
    assert!(scope.is_control_accounted());
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      control_before + scope_control
    );

    let empty = scope.try_alloc_zeroed(0).unwrap();
    assert_eq!(empty.charged_bytes(), 0);
    assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 0);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      control_before + scope_control + backing_control
    );
    let last = empty.clone();
    drop(scope);
    drop(empty);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      control_before + scope_control + backing_control
    );
    drop(last);
    assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 0);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      control_before
    );

    let legacy_tenant = domain.tenant(ceiling).unwrap();
    let legacy = ResourceScope::from_tenant(limits(128, 0, 0), legacy_tenant);
    let legacy_empty = legacy.try_alloc_zeroed(0).unwrap();
    assert!(!legacy.is_control_accounted());
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      control_before
    );
    drop(legacy_empty);
    drop(legacy);
  }

  #[test]
  fn controlled_control_admission_is_coupled_once_and_growth_reuses_backing_metadata() {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Memory, 1 << 20)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 0).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let baseline_control = domain.snapshot().used.get(DomainResource::Control);
    let scope_control = std::mem::size_of::<Ledger>();
    let backing_control = std::mem::size_of::<super::Backing>();
    tenant
      .set_limits(ceiling.with(DomainResource::Control, scope_control))
      .unwrap();
    let scope = ResourceScope::try_from_tenant(limits(512, 0, 0), tenant.clone()).unwrap();
    let scope_charge = domain.snapshot().used.get(DomainResource::Control);
    assert_eq!(scope_charge, baseline_control + scope_control);
    assert_eq!(
      scope.try_alloc_zeroed(32).map(drop),
      Err(ResourceError::DomainControlExhausted)
    );
    assert_eq!(scope.snapshot().managed_memory, 0);
    assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 0);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      scope_charge
    );

    tenant
      .set_limits(ceiling.with(DomainResource::Control, scope_control + backing_control))
      .unwrap();
    let mut buffer = scope.try_alloc_zeroed(32).unwrap();
    let old_capacity = buffer.charged_bytes();
    let memory_before = domain.snapshot().used.get(DomainResource::Memory);
    let control_before = domain.snapshot().used.get(DomainResource::Control);
    let local_before = scope.snapshot().managed_memory;
    let next_len = old_capacity + 1;
    assert_eq!(
      control_before,
      baseline_control + scope_control + backing_control
    );

    tenant
      .set_limits(
        ceiling
          .with(DomainResource::Memory, old_capacity)
          .with(DomainResource::Control, scope_control + backing_control),
      )
      .unwrap();
    assert_eq!(
      buffer.try_resize(next_len),
      Err(ResourceError::Exhausted(ResourceKind::Memory))
    );
    assert_eq!(buffer.len(), 32);
    assert_eq!(buffer.charged_bytes(), old_capacity);
    assert_eq!(scope.snapshot().managed_memory, local_before);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Memory),
      memory_before
    );
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      control_before
    );

    tenant.set_limits(ceiling).unwrap();
    buffer.try_resize(next_len).unwrap();
    assert_eq!(buffer.len(), next_len);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Memory),
      buffer.charged_bytes()
    );
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      control_before
    );
    drop(buffer);
    drop(scope);
    assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 0);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline_control
    );
  }

  #[test]
  fn buffers_are_zeroed_and_charge_their_length() {
    let scope = ResourceScope::new(limits(100, 0, 0));
    let buf = scope.try_alloc_zeroed(64).unwrap();
    assert_eq!(buf.len(), 64);
    assert!(buf.iter().all(|&b| b == 0));
    assert_eq!(buf.charged_bytes(), 64);
    assert_eq!(used(&scope), (64, 0, 0));
    let empty = scope.try_alloc_zeroed(0).unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty.charged_bytes(), 0);
    assert_eq!(used(&scope), (64, 0, 0));
    drop(buf);
    drop(empty);
    assert_eq!(used(&scope), (0, 0, 0));
  }

  #[test]
  fn clones_share_storage_and_one_charge_until_the_last_drops() {
    let scope = ResourceScope::new(limits(100, 0, 0));
    let mut a = scope.try_alloc_zeroed(32).unwrap();
    a.get_mut().unwrap()[0] = 7;
    let b = a.clone();
    let mut c = b.clone();
    assert!(std::ptr::eq(a.as_slice(), c.as_slice()));
    assert_eq!(c[0], 7);
    assert_eq!(used(&scope).0, 32);
    assert!(a.get_mut().is_none());
    assert!(c.get_mut().is_none());
    drop(a);
    drop(b);
    assert_eq!(used(&scope).0, 32);
    // Unique again: writable, and still the one charge.
    c.get_mut().unwrap()[1] = 9;
    assert_eq!(&c[..2], &[7, 9]);
    assert_eq!(used(&scope).0, 32);
    drop(c);
    assert_eq!(used(&scope).0, 0);
  }

  #[test]
  fn buffers_outlive_every_scope_handle() {
    let scope = ResourceScope::new(limits(16, 0, 0));
    let observer = scope.clone();
    let buf = scope.try_alloc_zeroed(16).unwrap();
    let copy = buf.clone();
    drop(scope);
    assert_eq!(used(&observer).0, 16);
    assert_eq!(
      observer.try_alloc_zeroed(1).unwrap_err(),
      ResourceError::Exhausted(MEMORY)
    );
    drop(buf);
    assert_eq!(used(&observer).0, 16);
    drop(observer);
    // The ledger lives on in `copy`, which still reads and frees cleanly.
    assert_eq!(copy.len(), 16);
    assert!(copy.iter().all(|&b| b == 0));
    drop(copy);
  }

  #[test]
  fn scope_clones_reserve_nothing() {
    let scope = ResourceScope::new(limits(8, 1, 1));
    let clones: Vec<ResourceScope> = (0..4).map(|_| scope.clone()).collect();
    assert_eq!(used(&scope), (0, 0, 0));
    let buf = clones[3].try_alloc_zeroed(8).unwrap();
    let permit = clones[1].try_acquire(ops(1, 1)).unwrap();
    assert_eq!(used(&scope), (8, 1, 1));
    drop(clones);
    assert_eq!(used(&scope), (8, 1, 1));
    drop(buf);
    drop(permit);
    assert_eq!(used(&scope), (0, 0, 0));
    assert_eq!(scope.limits(), limits(8, 1, 1));
  }

  #[test]
  fn memory_limit_separates_invalid_from_exhausted() {
    let scope = ResourceScope::new(limits(100, 0, 0));
    let invalid = Err(ResourceError::Invalid(MEMORY));
    let exhausted = Err(ResourceError::Exhausted(MEMORY));
    assert_eq!(scope.try_alloc_zeroed(101).map(drop), invalid);
    let a = scope.try_alloc_zeroed(60).unwrap();
    assert_eq!(scope.try_alloc_zeroed(41).map(drop), exhausted);
    // Still invalid, not exhausted, while memory is in use.
    assert_eq!(scope.try_alloc_zeroed(101).map(drop), invalid);
    assert_eq!(used(&scope).0, 60);
    let b = scope.try_alloc_zeroed(40).unwrap();
    assert_eq!(used(&scope).0, 100);
    assert_eq!(scope.try_alloc_zeroed(1).map(drop), exhausted);
    assert_eq!(scope.try_alloc_zeroed(0).map(drop), Ok(()));
    drop(a);
    drop(b);
    assert_eq!(scope.try_alloc_zeroed(100).map(drop), Ok(()));
    assert_eq!(used(&scope).0, 0);
  }

  #[test]
  fn ledger_sums_do_not_wrap() {
    let mut ledger = Ledger::new(limits(usize::MAX, 0, 0));
    assert_eq!(ledger.reserve_memory(usize::MAX, usize::MAX), Ok(()));
    assert_eq!(
      ledger.reserve_memory(1, 1),
      Err(ResourceError::Exhausted(MEMORY))
    );
    assert_eq!(ledger.memory, usize::MAX);
    assert!(ledger.release_memory(usize::MAX));
    // An unmatched release changes nothing.
    assert!(!ledger.release_memory(1));
    assert_eq!(ledger.memory, 0);
    assert!(!ledger.release_ops(ops(1, 0)));
    assert!(!ledger.release_ops(ops(0, 1)));
    assert_eq!((ledger.disk, ledger.network), (0, 0));
  }

  #[test]
  fn refused_allocations_roll_back_their_reservation() {
    let scope = ResourceScope::new(limits(usize::MAX, 0, 0));
    assert_eq!(
      scope.try_alloc_zeroed(MAX_STORAGE + 1).map(drop),
      Err(ResourceError::Invalid(MEMORY))
    );
    // `isize::MAX` bytes exceed every supported user address space: the
    // reservation is stored, then the allocation fails.
    assert_eq!(
      scope.try_alloc_zeroed(MAX_STORAGE).map(drop),
      Err(ResourceError::OutOfMemory)
    );
    assert_eq!(used(&scope).0, 0);
  }

  #[test]
  fn failed_growth_leaves_the_buffer_and_ledger_unchanged() {
    let scope = ResourceScope::new(limits(10, 0, 0));
    let mut a = scope.try_alloc_zeroed(4).unwrap();
    a.get_mut().unwrap().copy_from_slice(&[1, 2, 3, 4]);
    let b = scope.try_alloc_zeroed(4).unwrap();
    for (len, error) in [
      (11, ResourceError::Invalid(MEMORY)),
      (7, ResourceError::Exhausted(MEMORY)),
      (MAX_STORAGE + 1, ResourceError::Invalid(MEMORY)),
    ] {
      assert_eq!(a.try_resize(len), Err(error));
      assert_eq!(a.as_slice(), &[1, 2, 3, 4]);
      assert_eq!((a.charged_bytes(), used(&scope).0), (4, 8));
    }
    let shared = a.clone();
    assert_eq!(a.try_resize(6), Err(ResourceError::Shared));
    assert_eq!(a.try_resize(2), Err(ResourceError::Shared));
    drop(shared);
    assert_eq!(a.try_resize(6), Err(ResourceError::Exhausted(MEMORY)));
    drop(b);
    assert_eq!(a.try_resize(6), Ok(()));
    assert_eq!(a.as_slice(), &[1, 2, 3, 4, 0, 0]);
    assert_eq!((a.charged_bytes(), used(&scope).0), (6, 6));

    let roomy = ResourceScope::new(limits(usize::MAX, 0, 0));
    let mut c = roomy.try_alloc_zeroed(4).unwrap();
    c.get_mut().unwrap().copy_from_slice(&[5, 6, 7, 8]);
    assert_eq!(c.try_resize(MAX_STORAGE), Err(ResourceError::OutOfMemory));
    assert_eq!(c.as_slice(), &[5, 6, 7, 8]);
    assert_eq!((c.charged_bytes(), used(&roomy).0), (4, 4));
  }

  #[test]
  fn growth_reserves_old_and_replacement_storage() {
    let scope = ResourceScope::new(limits(100, 0, 0));
    let mut buf = scope.try_alloc_zeroed(60).unwrap();
    buf.get_mut().unwrap().fill(7);
    assert_eq!(buf.try_resize(100), Err(ResourceError::Exhausted(MEMORY)));
    assert_eq!((buf.len(), used(&scope).0), (60, 60));
    assert!(buf.iter().all(|byte| *byte == 7));
    let roomy = ResourceScope::new(limits(160, 0, 0));
    let mut buf = roomy.try_alloc_zeroed(60).unwrap();
    buf.get_mut().unwrap().fill(7);
    buf.try_resize(100).unwrap();
    assert_eq!(used(&roomy).0, buf.backing.storage.capacity());
    assert_eq!(&buf[..60], &[7; 60]);
    assert_eq!(&buf[60..], &[0; 40]);
    drop(buf);
    assert_eq!(used(&roomy).0, 0);
  }

  #[cfg(not(loom))]
  #[test]
  fn joined_result_keeps_its_storage_charged() {
    use crate::runtime::{Config, Resources, Runtime, ShutdownMode};
    let scope = ResourceScope::new(limits(64, 0, 0));
    let producer = scope.clone();
    let mut rt = Runtime::new(Config {
      workers: 1,
      max_outstanding: 1,
      capacity: Resources::ZERO,
    })
    .unwrap();
    let job = rt
      .try_spawn(Resources::ZERO, move |_| {
        producer.try_alloc_zeroed(64).unwrap()
      })
      .unwrap();
    let result = job.join().unwrap();
    rt.shutdown(ShutdownMode::Drain).unwrap();
    assert_eq!(used(&scope).0, 64);
    let retained = result.clone();
    drop(result);
    assert_eq!(used(&scope).0, 64);
    drop(retained);
    assert_eq!(used(&scope).0, 0);
  }

  #[test]
  fn shrinking_keeps_the_charge_and_regrowth_is_zeroed() {
    let scope = ResourceScope::new(limits(8, 0, 0));
    let mut buf = scope.try_alloc_zeroed(8).unwrap();
    buf.get_mut().unwrap().fill(0xff);
    assert_eq!(buf.try_resize(2), Ok(()));
    assert_eq!((buf.len(), buf.charged_bytes(), used(&scope).0), (2, 8, 8));
    // Regrowth within the charged storage needs no free memory.
    assert_eq!(buf.try_resize(8), Ok(()));
    assert_eq!(buf.as_slice(), &[0xff, 0xff, 0, 0, 0, 0, 0, 0]);
    assert_eq!(used(&scope).0, 8);
    drop(buf);
    assert_eq!(used(&scope).0, 0);
  }

  #[test]
  fn multi_resource_acquisition_is_all_or_nothing() {
    let scope = ResourceScope::new(limits(0, 2, 1));
    let first = scope.try_acquire(ops(1, 1)).unwrap();
    assert_eq!((first.disk(), first.network()), (1, 1));
    // Disk fits, network does not: neither is taken.
    assert_eq!(
      scope.try_acquire(ops(1, 1)).map(drop),
      Err(ResourceError::Exhausted(NETWORK))
    );
    assert_eq!(used(&scope), (0, 1, 1));
    // A component that can never fit is invalid even while another is
    // exhausted.
    assert_eq!(
      scope.try_acquire(ops(1, 2)).map(drop),
      Err(ResourceError::Invalid(NETWORK))
    );
    assert_eq!(
      scope.try_acquire(ops(3, 0)).map(drop),
      Err(ResourceError::Invalid(DISK))
    );
    assert_eq!(used(&scope), (0, 1, 1));
    let second = scope.try_acquire(ops(1, 0)).unwrap();
    assert_eq!(
      scope.try_acquire(ops(1, 0)).map(drop),
      Err(ResourceError::Exhausted(DISK))
    );
    let empty = scope.try_acquire(ops(0, 0)).unwrap();
    assert_eq!(used(&scope), (0, 2, 1));
    drop(first);
    assert_eq!(used(&scope), (0, 1, 0));
    drop(empty);
    drop(second);
    assert_eq!(used(&scope), (0, 0, 0));
  }

  #[test]
  fn operation_counts_do_not_wrap() {
    let scope = ResourceScope::new(limits(0, usize::MAX, usize::MAX));
    let all = scope.try_acquire(ops(usize::MAX, usize::MAX)).unwrap();
    assert_eq!(
      scope.try_acquire(ops(1, 0)).map(drop),
      Err(ResourceError::Exhausted(DISK))
    );
    assert_eq!(
      scope.try_acquire(ops(0, 1)).map(drop),
      Err(ResourceError::Exhausted(NETWORK))
    );
    assert_eq!(used(&scope), (0, usize::MAX, usize::MAX));
    drop(all);
    assert_eq!(used(&scope), (0, 0, 0));
  }

  #[test]
  fn concurrent_holders_stay_within_limits_and_release_everything() {
    const THREADS: usize = 8;
    const ROUNDS: usize = 500;
    let scope = ResourceScope::new(limits(64, 2, 3));
    let shared = scope.try_alloc_zeroed(16).unwrap();
    // Raised after a permit is granted and lowered before it is dropped, so
    // they never exceed what the ledger holds.
    let held_disk = AtomicUsize::new(0);
    let held_network = AtomicUsize::new(0);
    let granted = AtomicUsize::new(0);
    thread::scope(|s| {
      for t in 0..THREADS {
        let (scope, shared) = (scope.clone(), shared.clone());
        let (held_disk, held_network, granted) = (&held_disk, &held_network, &granted);
        s.spawn(move || {
          for i in 0..ROUNDS {
            match scope.try_acquire(ops((t + i) % 2, 1)) {
              Ok(permit) => {
                let disk = held_disk.fetch_add(permit.disk(), Ordering::SeqCst);
                let network = held_network.fetch_add(permit.network(), Ordering::SeqCst);
                assert!(disk + permit.disk() <= 2);
                assert!(network + permit.network() <= 3);
                granted.fetch_add(1, Ordering::Relaxed);
                held_disk.fetch_sub(permit.disk(), Ordering::SeqCst);
                held_network.fetch_sub(permit.network(), Ordering::SeqCst);
                drop(permit);
              }
              Err(ResourceError::Exhausted(_)) => thread::yield_now(),
              Err(error) => panic!("unexpected error: {error}"),
            }
            if let Ok(buf) = scope.try_alloc_zeroed(16) {
              let copy = buf.clone();
              drop(buf);
              assert!(copy.iter().all(|&b| b == 0));
            }
            assert!(scope.snapshot().managed_memory <= 64);
            drop(shared.clone());
          }
        });
      }
    });
    assert!(granted.load(Ordering::Relaxed) > 0);
    assert_eq!(used(&scope), (16, 0, 0));
    drop(shared);
    assert_eq!(used(&scope), (0, 0, 0));
  }

  #[test]
  fn errors_name_the_resource() {
    assert_eq!(
      ResourceError::Invalid(DISK).to_string(),
      "request exceeds the scope's disk operation limit"
    );
    assert_eq!(
      ResourceError::Exhausted(MEMORY).to_string(),
      "not enough free managed memory capacity"
    );
    let scope = ResourceScope::new(limits(4, 0, 0));
    let buf = scope.try_alloc_zeroed(4).unwrap();
    assert_eq!(format!("{buf:?}"), "ManagedBuf { len: 4, charged: 4, .. }");
    assert!(format!("{scope:?}").contains("managed_memory: 4"));
  }
}
