//! Atomic global and tenant admission for managed resources.
//!
//! One mutex protects both ledgers. An admission takes every requested
//! component or none. Reservations retain their tenant generation through
//! actual cleanup; closing a tenant does not release its live resources.
//! Counts describe declared managed ownership, not process RSS or CPU time.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::task::Waker;

#[cfg(loom)]
use loom::sync::{Arc, Mutex, MutexGuard};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(loom))]
use std::sync::{Arc, Mutex, MutexGuard};

const KINDS: usize = 6;
static NEXT_DOMAIN_ID: AtomicU64 = AtomicU64::new(1);

fn next_domain_identity() -> Result<DomainIdentity, DomainError> {
  NEXT_DOMAIN_ID
    .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
      next.checked_add(1)
    })
    .map(DomainIdentity)
    .map_err(|_| DomainError::GenerationExhausted)
}

/// Independently admitted resources in a managed domain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(usize)]
pub enum DomainResource {
  Cpu = 0,
  Memory = 1,
  Disk = 2,
  Network = 3,
  Tasks = 4,
  Control = 5,
}

const RESOURCES: [DomainResource; KINDS] = [
  DomainResource::Cpu,
  DomainResource::Memory,
  DomainResource::Disk,
  DomainResource::Network,
  DomainResource::Tasks,
  DomainResource::Control,
];

/// A fixed-size resource vector. Zero disables admission for that component.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DomainResources([usize; KINDS]);

impl DomainResources {
  pub const ZERO: Self = Self([0; KINDS]);

  #[must_use]
  pub const fn with(mut self, resource: DomainResource, amount: usize) -> Self {
    self.0[resource as usize] = amount;
    self
  }

  #[must_use]
  pub const fn get(self, resource: DomainResource) -> usize {
    self.0[resource as usize]
  }

  fn empty(self) -> bool {
    self.0.iter().all(|value| *value == 0)
  }
}

/// Why a domain operation was refused without partial admission.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum DomainError {
  Invalid,
  OutOfMemory,
  TenantsFull,
  WaitersFull,
  GenerationExhausted,
  Closed,
  AboveCeiling(DomainResource),
  Exhausted(DomainResource),
}

impl fmt::Display for DomainError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "resource domain operation refused: {self:?}")
  }
}

impl std::error::Error for DomainError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Key {
  index: usize,
  generation: u64,
}

struct TenantSlot {
  generation: u64,
  occupied: bool,
  owner_live: bool,
  closed: bool,
  ceiling: DomainResources,
  limit: DomainResources,
  used: DomainResources,
  reservations: usize,
}

impl TenantSlot {
  fn empty() -> Self {
    Self {
      generation: 0,
      occupied: false,
      owner_live: false,
      closed: false,
      ceiling: DomainResources::ZERO,
      limit: DomainResources::ZERO,
      used: DomainResources::ZERO,
      reservations: 0,
    }
  }
}

struct State {
  ceiling: DomainResources,
  limit: DomainResources,
  used: DomainResources,
  tenants: Vec<TenantSlot>,
  waiters: Vec<WaiterSlot>,
  next_waiter_pool: u64,
  next_wait_sequence: u64,
}

struct WaiterSlot {
  pool: Option<u64>,
  generation: u64,
  leased: bool,
  waiting: bool,
  tenant: Option<Key>,
  sequence: u64,
  waker: Option<Waker>,
}

impl WaiterSlot {
  fn empty() -> Self {
    Self {
      pool: None,
      generation: 0,
      leased: false,
      waiting: false,
      tenant: None,
      sequence: 0,
      waker: None,
    }
  }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
  state.lock().unwrap_or_else(|error| error.into_inner())
}

fn check_ceiling(limit: DomainResources, ceiling: DomainResources) -> Result<(), DomainError> {
  for resource in RESOURCES {
    if limit.get(resource) > ceiling.get(resource) {
      return Err(DomainError::AboveCeiling(resource));
    }
  }
  Ok(())
}

fn admitted(
  used: DomainResources,
  request: DomainResources,
  limit: DomainResources,
) -> Result<DomainResources, DomainError> {
  let mut next = used;
  for resource in RESOURCES {
    if request.get(resource) == 0 {
      continue;
    }
    let value = used
      .get(resource)
      .checked_add(request.get(resource))
      .filter(|value| *value <= limit.get(resource))
      .ok_or(DomainError::Exhausted(resource))?;
    next.0[resource as usize] = value;
  }
  Ok(next)
}

fn subtract(used: &mut DomainResources, request: DomainResources) {
  for resource in RESOURCES {
    used.0[resource as usize] -= request.get(resource);
  }
}

/// A fixed-storage managed domain. Clones share the same global ledger.
#[derive(Clone)]
pub struct ResourceDomain {
  state: Arc<Mutex<State>>,
  identity: DomainIdentity,
}

impl fmt::Debug for ResourceDomain {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ResourceDomain")
      .field("snapshot", &self.snapshot())
      .finish()
  }
}

/// Coherent counts sampled under the domain lock. Lowered soft limits may
/// temporarily be below live usage; hard ceilings remain invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DomainSnapshot {
  pub ceiling: DomainResources,
  pub limit: DomainResources,
  pub used: DomainResources,
  pub live_tenants: usize,
}

impl ResourceDomain {
  /// Reserves every tenant slot before exposing the domain. Fixed slot
  /// payload bytes, shared-state payload and a tenant-owner payload for each
  /// slot are charged to global `Control`; allocation/header overhead is not
  /// represented as measured physical memory. Owner storage is reserved by
  /// the domain, so zero-Control tenant ceilings remain valid.
  pub fn new(ceiling: DomainResources, max_tenants: usize) -> Result<Self, DomainError> {
    Self::with_waiters(ceiling, max_tenants, 0)
  }

  /// Creates a domain with a fixed CPU-waiter table. The table is allocated
  /// before the domain is exposed, and its actual retained slot capacity is
  /// charged to `Control`. Runtime builders must lease disjoint waiter shares
  /// before starting their workers.
  pub fn with_waiters(
    ceiling: DomainResources,
    max_tenants: usize,
    max_waiters: usize,
  ) -> Result<Self, DomainError> {
    if max_tenants == 0 {
      return Err(DomainError::Invalid);
    }
    let owner_bytes = max_tenants
      .checked_mul(std::mem::size_of::<TenantOwner>())
      .ok_or(DomainError::Invalid)?;
    let fixed_bytes = std::mem::size_of::<Mutex<State>>()
      .checked_add(owner_bytes)
      .ok_or(DomainError::Invalid)?;
    let requested_waiter_bytes = max_waiters
      .checked_mul(std::mem::size_of::<WaiterSlot>())
      .ok_or(DomainError::Invalid)?;
    let tenant_bytes = max_tenants
      .checked_mul(std::mem::size_of::<TenantSlot>())
      .and_then(|bytes| bytes.checked_add(fixed_bytes))
      .ok_or(DomainError::Invalid)?;
    let requested_bytes = tenant_bytes
      .checked_add(requested_waiter_bytes)
      .ok_or(DomainError::Invalid)?;
    if requested_bytes > ceiling.get(DomainResource::Control) {
      return Err(DomainError::Exhausted(DomainResource::Control));
    }
    let mut tenants = Vec::new();
    tenants
      .try_reserve_exact(max_tenants)
      .map_err(|_| DomainError::OutOfMemory)?;
    let actual_bytes = tenants
      .capacity()
      .checked_mul(std::mem::size_of::<TenantSlot>())
      .and_then(|bytes| bytes.checked_add(fixed_bytes))
      .ok_or(DomainError::Invalid)?;
    let reconciled_request = actual_bytes
      .checked_add(requested_waiter_bytes)
      .ok_or(DomainError::Invalid)?;
    if reconciled_request > ceiling.get(DomainResource::Control) {
      return Err(DomainError::Exhausted(DomainResource::Control));
    }
    tenants.resize_with(max_tenants, TenantSlot::empty);
    let mut waiters = Vec::new();
    waiters
      .try_reserve_exact(max_waiters)
      .map_err(|_| DomainError::OutOfMemory)?;
    let waiter_bytes = waiters
      .capacity()
      .checked_mul(std::mem::size_of::<WaiterSlot>())
      .ok_or(DomainError::Invalid)?;
    let control_bytes = actual_bytes
      .checked_add(waiter_bytes)
      .ok_or(DomainError::Invalid)?;
    if control_bytes > ceiling.get(DomainResource::Control) {
      return Err(DomainError::Exhausted(DomainResource::Control));
    }
    waiters.resize_with(max_waiters, WaiterSlot::empty);
    let used = DomainResources::ZERO.with(DomainResource::Control, control_bytes);
    let identity = next_domain_identity()?;
    Ok(Self {
      state: Arc::new(Mutex::new(State {
        ceiling,
        limit: ceiling,
        used,
        tenants,
        waiters,
        next_waiter_pool: 1,
        next_wait_sequence: 1,
      })),
      identity,
    })
  }

  /// Creates a tenant whose hard ceilings cannot exceed the global ceilings.
  pub fn tenant(&self, ceiling: DomainResources) -> Result<TenantDomain, DomainError> {
    let mut state = lock(&self.state);
    check_ceiling(ceiling, state.ceiling)?;
    let Some(index) = state
      .tenants
      .iter()
      .position(|slot| !slot.occupied && slot.generation != u64::MAX)
    else {
      return Err(if state.tenants.iter().any(|slot| !slot.occupied) {
        DomainError::GenerationExhausted
      } else {
        DomainError::TenantsFull
      });
    };
    let slot = &mut state.tenants[index];
    slot.generation += 1;
    slot.occupied = true;
    slot.owner_live = true;
    slot.closed = false;
    slot.ceiling = ceiling;
    slot.limit = ceiling;
    slot.used = DomainResources::ZERO;
    slot.reservations = 0;
    let key = Key {
      index,
      generation: slot.generation,
    };
    drop(state);
    Ok(TenantDomain {
      owner: Arc::new(TenantOwner {
        domain: self.clone(),
        key,
      }),
    })
  }

  /// Applies a soft limit without preempting or refunding live ownership.
  pub fn set_limits(&self, limit: DomainResources) -> Result<(), DomainError> {
    let mut state = lock(&self.state);
    check_ceiling(limit, state.ceiling)?;
    let cpu_increased = limit.get(DomainResource::Cpu) > state.limit.get(DomainResource::Cpu);
    state.limit = limit;
    drop(state);
    if cpu_increased {
      self.wake_waiters();
    }
    Ok(())
  }

  /// Changes one soft-limit component only if its current value still equals
  /// `expected`. Other components keep concurrent updates. Returns `false`
  /// without mutation when another controller changed the component first.
  pub fn compare_exchange_limit(
    &self,
    resource: DomainResource,
    expected: usize,
    desired: usize,
  ) -> Result<bool, DomainError> {
    let mut state = lock(&self.state);
    if state.limit.get(resource) != expected {
      return Ok(false);
    }
    let next = state.limit.with(resource, desired);
    check_ceiling(next, state.ceiling)?;
    state.limit = next;
    let cpu_increased = resource == DomainResource::Cpu && desired > expected;
    drop(state);
    if cpu_increased {
      self.wake_waiters();
    }
    Ok(true)
  }

  pub fn snapshot(&self) -> DomainSnapshot {
    let state = lock(&self.state);
    DomainSnapshot {
      ceiling: state.ceiling,
      limit: state.limit,
      used: state.used,
      live_tenants: state.tenants.iter().filter(|slot| slot.occupied).count(),
    }
  }

  fn wake_waiters(&self) {
    loop {
      let waker = {
        let mut state = lock(&self.state);
        if state.used.get(DomainResource::Cpu) >= state.limit.get(DomainResource::Cpu) {
          return;
        }
        let mut selected = None;
        let mut sequence = u64::MAX;
        for (index, waiter) in state.waiters.iter().enumerate() {
          if !waiter.leased
            || !waiter.waiting
            || waiter.waker.is_none()
            || waiter.sequence >= sequence
            || !waiter.tenant.is_some_and(|key| can_admit_cpu(&state, key))
          {
            continue;
          }
          sequence = waiter.sequence;
          selected = Some(index);
        }
        selected.and_then(|index| state.waiters[index].waker.take())
      };
      let Some(waker) = waker else {
        return;
      };
      if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake()))
      {
        drop_contained(payload);
      }
    }
  }
}

struct TenantOwner {
  domain: ResourceDomain,
  key: Key,
}

impl TenantOwner {
  fn close(&self, last_owner: bool) {
    let mut state = lock(&self.domain.state);
    let slot = &mut state.tenants[self.key.index];
    if slot.occupied && slot.generation == self.key.generation {
      slot.closed = true;
      if last_owner {
        slot.owner_live = false;
      }
      if !slot.owner_live && slot.used.empty() && slot.reservations == 0 {
        slot.occupied = false;
      }
    }
  }
}

impl Drop for TenantOwner {
  fn drop(&mut self) {
    self.close(true);
  }
}

/// A clonable tenant handle. Last-handle drop closes admission; retained
/// reservations and closed handles keep the original slot occupied until
/// actual release. Keeping closed handles therefore cannot allocate more
/// tenant-owner generations than the fixed tenant-slot ceiling.
#[derive(Clone)]
pub struct TenantDomain {
  owner: Arc<TenantOwner>,
}

/// Process-unique, non-wrapping domain identity. It retains no domain table;
/// exhausted identity space refuses construction instead of reusing a value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DomainIdentity(u64);

impl fmt::Debug for TenantDomain {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("TenantDomain")
      .field("key", &self.owner.key)
      .finish_non_exhaustive()
  }
}

impl TenantDomain {
  /// Whether both handles identify the same global-domain tenant generation.
  ///
  /// Identity remains stable after closure. Equal limits alone do not identify
  /// the same account; this comparison exposes no reusable slot identifier.
  #[must_use]
  pub fn same_account(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.owner, &other.owner)
  }

  pub(crate) fn domain_identity(&self) -> DomainIdentity {
    self.owner.domain.identity
  }

  /// Takes the complete vector under one lock or changes neither ledger.
  pub fn try_acquire(&self, request: DomainResources) -> Result<DomainReservation, DomainError> {
    let mut state = lock(&self.owner.domain.state);
    let key = self.owner.key;
    let slot = &state.tenants[key.index];
    if !slot.occupied || slot.generation != key.generation || slot.closed {
      return Err(DomainError::Closed);
    }
    check_ceiling(request, slot.ceiling)?;
    let global = admitted(state.used, request, state.limit)?;
    let tenant = admitted(slot.used, request, slot.limit)?;
    let reservations = slot
      .reservations
      .checked_add(1)
      .ok_or(DomainError::Exhausted(DomainResource::Control))?;
    state.used = global;
    state.tenants[key.index].used = tenant;
    state.tenants[key.index].reservations = reservations;
    Ok(DomainReservation {
      domain: self.owner.domain.clone(),
      key,
      request,
    })
  }

  pub fn set_limits(&self, limit: DomainResources) -> Result<(), DomainError> {
    let mut state = lock(&self.owner.domain.state);
    let slot = &mut state.tenants[self.owner.key.index];
    if !slot.occupied || slot.generation != self.owner.key.generation || slot.closed {
      return Err(DomainError::Closed);
    }
    check_ceiling(limit, slot.ceiling)?;
    let cpu_increased = limit.get(DomainResource::Cpu) > slot.limit.get(DomainResource::Cpu);
    slot.limit = limit;
    drop(state);
    if cpu_increased {
      self.owner.domain.wake_waiters();
    }
    Ok(())
  }

  /// Changes one tenant soft-limit component only if it still equals
  /// `expected`, preserving concurrent changes to every other component.
  pub fn compare_exchange_limit(
    &self,
    resource: DomainResource,
    expected: usize,
    desired: usize,
  ) -> Result<bool, DomainError> {
    let mut state = lock(&self.owner.domain.state);
    let slot = &mut state.tenants[self.owner.key.index];
    if !slot.occupied || slot.generation != self.owner.key.generation || slot.closed {
      return Err(DomainError::Closed);
    }
    if slot.limit.get(resource) != expected {
      return Ok(false);
    }
    let next = slot.limit.with(resource, desired);
    check_ceiling(next, slot.ceiling)?;
    slot.limit = next;
    let cpu_increased = resource == DomainResource::Cpu && desired > expected;
    drop(state);
    if cpu_increased {
      self.owner.domain.wake_waiters();
    }
    Ok(true)
  }

  /// Reserves a disjoint share of the domain's fixed CPU-waiter table for a
  /// runtime. A task, blocking job or borrowed root call must lease one slot
  /// from this share before it is admitted. The share remains reserved while
  /// any pool or waiter handle is alive.
  pub(crate) fn reserve_waiters(&self, count: usize) -> Result<DomainWaitPool, DomainError> {
    if count == 0 {
      return Err(DomainError::Invalid);
    }
    let control = ControlCharge::try_new(Some(self), std::mem::size_of::<DomainWaitPoolInner>())?;
    let mut state = lock(&self.owner.domain.state);
    let key = self.owner.key;
    let Some(tenant) = state.tenants.get(key.index) else {
      return Err(DomainError::Closed);
    };
    if !tenant.occupied || tenant.generation != key.generation || tenant.closed {
      return Err(DomainError::Closed);
    }
    if state.ceiling.get(DomainResource::Cpu) == 0 || tenant.ceiling.get(DomainResource::Cpu) == 0 {
      return Err(DomainError::AboveCeiling(DomainResource::Cpu));
    }
    if state.ceiling.get(DomainResource::Tasks) == 0
      || tenant.ceiling.get(DomainResource::Tasks) == 0
    {
      return Err(DomainError::AboveCeiling(DomainResource::Tasks));
    }
    let available = state
      .waiters
      .iter()
      .filter(|slot| slot.pool.is_none() && slot.generation < u64::MAX)
      .count();
    if available < count {
      return Err(DomainError::WaitersFull);
    }
    let pool_id = state.next_waiter_pool;
    let Some(next_pool) = pool_id.checked_add(1) else {
      return Err(DomainError::GenerationExhausted);
    };
    state.next_waiter_pool = next_pool;
    let mut remaining = count;
    for slot in &mut state.waiters {
      if slot.pool.is_none() && slot.generation < u64::MAX {
        slot.pool = Some(pool_id);
        remaining -= 1;
        if remaining == 0 {
          break;
        }
      }
    }
    drop(state);
    Ok(DomainWaitPool {
      inner: Arc::new(DomainWaitPoolInner {
        domain: self.owner.domain.clone(),
        id: pool_id,
        _control: control,
      }),
    })
  }

  /// Whether this tenant can ever issue one active CPU ticket under its hard
  /// ceilings. Soft limits may be zero and can be raised later.
  pub(crate) fn validate_cpu_execution(&self) -> Result<(), DomainError> {
    let state = lock(&self.owner.domain.state);
    let key = self.owner.key;
    let Some(slot) = state.tenants.get(key.index) else {
      return Err(DomainError::Closed);
    };
    if !slot.occupied || slot.generation != key.generation || slot.closed {
      return Err(DomainError::Closed);
    }
    if state.ceiling.get(DomainResource::Cpu) == 0 || slot.ceiling.get(DomainResource::Cpu) == 0 {
      return Err(DomainError::AboveCeiling(DomainResource::Cpu));
    }
    Ok(())
  }

  pub(crate) fn same_domain(&self, other: &TenantDomain) -> bool {
    Arc::ptr_eq(&self.owner.domain.state, &other.owner.domain.state)
  }

  /// Closes all clones' admission without dropping user reservations.
  pub fn close(&self) {
    self.owner.close(false);
  }

  pub fn snapshot(&self) -> Result<DomainSnapshot, DomainError> {
    let state = lock(&self.owner.domain.state);
    let slot = &state.tenants[self.owner.key.index];
    if !slot.occupied || slot.generation != self.owner.key.generation {
      return Err(DomainError::Closed);
    }
    Ok(DomainSnapshot {
      ceiling: slot.ceiling,
      limit: slot.limit,
      used: slot.used,
      live_tenants: 1,
    })
  }
}

/// A pre-reserved share of a domain's waiter table. Clones share one share;
/// they cannot reserve the same slots again.
#[derive(Clone, Debug)]
pub(crate) struct DomainWaitPool {
  inner: Arc<DomainWaitPoolInner>,
}

#[derive(Debug)]
struct DomainWaitPoolInner {
  domain: ResourceDomain,
  id: u64,
  _control: ControlCharge,
}

impl DomainWaitPool {
  #[cfg(all(test, not(loom)))]
  pub(crate) const fn control_payload_bytes() -> usize {
    std::mem::size_of::<DomainWaitPoolInner>()
  }

  pub(crate) fn try_lease(&self) -> Result<DomainWaiter, DomainError> {
    let mut state = lock(&self.inner.domain.state);
    let Some(index) = state.waiters.iter().position(|slot| {
      slot.pool == Some(self.inner.id) && !slot.leased && slot.generation < u64::MAX
    }) else {
      return Err(
        if state
          .waiters
          .iter()
          .any(|slot| slot.pool == Some(self.inner.id) && !slot.leased)
        {
          DomainError::GenerationExhausted
        } else {
          DomainError::WaitersFull
        },
      );
    };
    let slot = &mut state.waiters[index];
    slot.generation += 1;
    slot.leased = true;
    slot.waiting = false;
    slot.tenant = None;
    slot.sequence = 0;
    debug_assert!(slot.waker.is_none());
    let generation = slot.generation;
    drop(state);
    Ok(DomainWaiter {
      pool: Arc::clone(&self.inner),
      index,
      generation,
    })
  }
}

impl Drop for DomainWaitPoolInner {
  fn drop(&mut self) {
    loop {
      let waker = {
        let mut state = lock(&self.domain.state);
        let Some(index) = state
          .waiters
          .iter()
          .position(|slot| slot.pool == Some(self.id))
        else {
          return;
        };
        let slot = &mut state.waiters[index];
        debug_assert!(!slot.leased);
        slot.pool = None;
        slot.waiting = false;
        slot.tenant = None;
        slot.sequence = 0;
        slot.waker.take()
      };
      drop_contained(waker);
    }
  }
}

/// One generation-stamped, bounded CPU admission waiter.
pub(crate) struct DomainWaiter {
  pool: Arc<DomainWaitPoolInner>,
  index: usize,
  generation: u64,
}

impl DomainWaiter {
  /// Admits one CPU unit, or atomically enrolls `waker` until capacity is
  /// released or a soft limit rises. Waker operations always occur outside
  /// the domain lock.
  pub(crate) fn try_acquire_or_register(
    &self,
    tenant: &TenantDomain,
    waker: &Waker,
  ) -> Result<Option<DomainReservation>, DomainError> {
    if !Arc::ptr_eq(&self.pool.domain.state, &tenant.owner.domain.state) {
      return Err(DomainError::Invalid);
    }
    let mut replacement = Some(waker.clone());
    let request = DomainResources::ZERO.with(DomainResource::Cpu, 1);
    let key = tenant.owner.key;
    let mut state = lock(&self.pool.domain.state);
    let Some(tenant_slot) = state.tenants.get(key.index) else {
      drop(state);
      drop_contained(replacement);
      return Err(DomainError::Closed);
    };
    let tenant_valid = tenant_slot.occupied && tenant_slot.generation == key.generation;
    let tenant_cpu_ceiling = tenant_slot.ceiling.get(DomainResource::Cpu);
    if !tenant_valid {
      drop(state);
      drop_contained(replacement);
      return Err(DomainError::Closed);
    }
    if state.ceiling.get(DomainResource::Cpu) == 0 || tenant_cpu_ceiling == 0 {
      drop(state);
      drop_contained(replacement);
      return Err(DomainError::AboveCeiling(DomainResource::Cpu));
    }
    let Some(waiter) = state.waiters.get(self.index) else {
      drop(state);
      drop_contained(replacement);
      return Err(DomainError::GenerationExhausted);
    };
    if waiter.pool != Some(self.pool.id) || !waiter.leased || waiter.generation != self.generation {
      drop(state);
      drop_contained(replacement);
      return Err(DomainError::GenerationExhausted);
    }
    if !waiter.waiting {
      let Some(next) = state.next_wait_sequence.checked_add(1) else {
        drop(state);
        drop_contained(replacement);
        return Err(DomainError::GenerationExhausted);
      };
      let sequence = state.next_wait_sequence;
      state.next_wait_sequence = next;
      let waiter = &mut state.waiters[self.index];
      waiter.waiting = true;
      waiter.tenant = Some(key);
      waiter.sequence = sequence;
    }
    let sequence = state.waiters[self.index].sequence;
    let has_earlier_eligible = state.waiters.iter().any(|waiter| {
      waiter.leased
        && waiter.waiting
        && waiter.sequence < sequence
        && waiter
          .tenant
          .is_some_and(|waiter_tenant| can_admit_cpu(&state, waiter_tenant))
    });
    let can_acquire = !has_earlier_eligible && can_admit_cpu(&state, key);
    let mut old_waker = None;
    if can_acquire {
      let global = admitted(state.used, request, state.limit)?;
      let tenant_next = admitted(
        state.tenants[key.index].used,
        request,
        state.tenants[key.index].limit,
      )?;
      let reservations = state.tenants[key.index]
        .reservations
        .checked_add(1)
        .ok_or(DomainError::Exhausted(DomainResource::Control))?;
      state.used = global;
      let tenant_slot = &mut state.tenants[key.index];
      tenant_slot.used = tenant_next;
      tenant_slot.reservations = reservations;
      let waiter = &mut state.waiters[self.index];
      waiter.waiting = false;
      waiter.tenant = None;
      waiter.sequence = 0;
      old_waker = waiter.waker.take();
    } else {
      let waiter = &mut state.waiters[self.index];
      if let Some(replacement) = replacement.take() {
        old_waker = waiter.waker.replace(replacement);
      }
    }
    let ticket = can_acquire.then(|| DomainReservation {
      domain: self.pool.domain.clone(),
      key,
      request,
    });
    drop(state);
    drop_contained(old_waker);
    drop_contained(replacement);
    Ok(ticket)
  }

  /// Removes a pending notification without returning this slot to the pool.
  pub(crate) fn cancel_wait(&self) {
    let waker = {
      let mut state = lock(&self.pool.domain.state);
      let Some(waiter) = state.waiters.get_mut(self.index) else {
        return;
      };
      if waiter.pool != Some(self.pool.id) || !waiter.leased || waiter.generation != self.generation
      {
        return;
      }
      waiter.waiting = false;
      waiter.tenant = None;
      waiter.sequence = 0;
      waiter.waker.take()
    };
    drop_contained(waker);
    self.pool.domain.wake_waiters();
  }
}

impl Drop for DomainWaiter {
  fn drop(&mut self) {
    let waker = {
      let mut state = lock(&self.pool.domain.state);
      let Some(waiter) = state.waiters.get_mut(self.index) else {
        return;
      };
      if waiter.pool != Some(self.pool.id) || !waiter.leased || waiter.generation != self.generation
      {
        return;
      }
      waiter.leased = false;
      waiter.waiting = false;
      waiter.tenant = None;
      waiter.sequence = 0;
      waiter.waker.take()
    };
    drop_contained(waker);
    self.pool.domain.wake_waiters();
  }
}

impl Drop for DomainReservation {
  fn drop(&mut self) {
    let cpu_released = self.request.get(DomainResource::Cpu) != 0;
    {
      let mut state = lock(&self.domain.state);
      let slot = &mut state.tenants[self.key.index];
      debug_assert!(slot.occupied && slot.generation == self.key.generation);
      subtract(&mut slot.used, self.request);
      slot.reservations -= 1;
      if slot.closed && !slot.owner_live && slot.used.empty() && slot.reservations == 0 {
        slot.occupied = false;
      }
      subtract(&mut state.used, self.request);
    }
    if cpu_released {
      self.domain.wake_waiters();
    }
  }
}

fn can_admit_cpu(state: &State, key: Key) -> bool {
  let Some(tenant) = state.tenants.get(key.index) else {
    return false;
  };
  tenant.occupied
    && tenant.generation == key.generation
    && state
      .used
      .get(DomainResource::Cpu)
      .checked_add(1)
      .is_some_and(|next| next <= state.limit.get(DomainResource::Cpu))
    && tenant
      .used
      .get(DomainResource::Cpu)
      .checked_add(1)
      .is_some_and(|next| next <= tenant.limit.get(DomainResource::Cpu))
}

fn drop_contained<T>(value: T) {
  if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(value)))
    && let Err(second) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)))
  {
    std::mem::forget(second);
  }
}

/// Owned global+tenant reservation. It is deliberately not clonable; place
/// it inside a shared result owner if a charge must survive result clones.
#[must_use = "retain through actual execution or cleanup"]
pub struct DomainReservation {
  domain: ResourceDomain,
  key: Key,
  request: DomainResources,
}

impl fmt::Debug for DomainReservation {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("DomainReservation")
      .field("request", &self.request)
      .finish_non_exhaustive()
  }
}

impl DomainReservation {
  pub fn resources(&self) -> DomainResources {
    self.request
  }

  pub(crate) fn domain_identity(&self) -> DomainIdentity {
    self.domain.identity
  }

  /// Splits a resource vector from this ticket without changing global or tenant usage.
  ///
  /// The tenant's outstanding-reservation count is incremented under the
  /// domain lock. If that checked count cannot grow, this ticket and both
  /// resource ledgers remain unchanged. This is used to admit task and
  /// control resources atomically, then release the task portion separately
  /// from retained completion metadata.
  pub(crate) fn split_off(
    &mut self,
    part: DomainResources,
  ) -> Result<DomainReservation, DomainError> {
    let mut remaining = self.request;
    for resource in RESOURCES {
      let amount = part.get(resource);
      let Some(left) = remaining.get(resource).checked_sub(amount) else {
        return Err(DomainError::Invalid);
      };
      remaining.0[resource as usize] = left;
    }
    if part.empty() {
      return Err(DomainError::Invalid);
    }

    let mut state = lock(&self.domain.state);
    let slot = &state.tenants[self.key.index];
    if !slot.occupied || slot.generation != self.key.generation {
      return Err(DomainError::Closed);
    }
    let reservations = slot
      .reservations
      .checked_add(1)
      .ok_or(DomainError::Exhausted(DomainResource::Control))?;
    state.tenants[self.key.index].reservations = reservations;
    drop(state);

    self.request = remaining;
    Ok(DomainReservation {
      domain: self.domain.clone(),
      key: self.key,
      request: part,
    })
  }

  /// Atomically adjusts this ticket against both the global and tenant
  /// ledgers. Shrinks always return their released dimensions; growth is
  /// admitted as a complete vector or changes neither ledger nor ticket.
  pub(crate) fn try_resize(&mut self, target: DomainResources) -> Result<(), DomainError> {
    if target == self.request {
      return Ok(());
    }

    let mut increase = DomainResources::ZERO;
    let mut decrease = DomainResources::ZERO;
    for resource in RESOURCES {
      let current = self.request.get(resource);
      let desired = target.get(resource);
      if desired > current {
        increase.0[resource as usize] = desired - current;
      } else {
        decrease.0[resource as usize] = current - desired;
      }
    }

    let mut state = lock(&self.domain.state);
    let slot = &state.tenants[self.key.index];
    if !slot.occupied || slot.generation != self.key.generation {
      return Err(DomainError::Closed);
    }
    if slot.closed && !increase.empty() {
      return Err(DomainError::Closed);
    }
    check_ceiling(target, slot.ceiling)?;
    let global_after_growth = admitted(state.used, increase, state.limit)?;
    let tenant_after_growth = admitted(slot.used, increase, slot.limit)?;
    let mut global = global_after_growth;
    let mut tenant = tenant_after_growth;
    subtract(&mut global, decrease);
    subtract(&mut tenant, decrease);
    let cpu_released = decrease.get(DomainResource::Cpu) != 0;
    state.used = global;
    let slot = &mut state.tenants[self.key.index];
    slot.used = tenant;
    drop(state);

    self.request = target;
    if cpu_released {
      self.domain.wake_waiters();
    }
    Ok(())
  }
}

/// One bounded Control reservation owned by runtime metadata. Its optional
/// tenant handle keeps zero-byte and temporarily empty charges tied to the
/// same tenant generation. The reservation is dropped before the owner.
#[must_use = "retain with the metadata whose Control bytes it accounts"]
pub(crate) struct ControlCharge {
  ticket: Option<DomainReservation>,
  tenant: Option<TenantDomain>,
  bytes: usize,
}

impl fmt::Debug for ControlCharge {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ControlCharge")
      .field("bytes", &self.bytes)
      .finish_non_exhaustive()
  }
}

impl ControlCharge {
  pub(crate) const fn unbounded(bytes: usize) -> Self {
    Self {
      ticket: None,
      tenant: None,
      bytes,
    }
  }

  pub(crate) fn from_ticket(
    tenant: Option<&TenantDomain>,
    ticket: DomainReservation,
    bytes: usize,
  ) -> Self {
    debug_assert_eq!(
      ticket.resources(),
      DomainResources::ZERO.with(DomainResource::Control, bytes)
    );
    Self {
      ticket: Some(ticket),
      tenant: tenant.cloned(),
      bytes,
    }
  }

  pub(crate) fn try_new(tenant: Option<&TenantDomain>, bytes: usize) -> Result<Self, DomainError> {
    let tenant = tenant.cloned();
    let ticket = match (&tenant, bytes) {
      (Some(tenant), amount) if amount != 0 => {
        Some(tenant.try_acquire(DomainResources::ZERO.with(DomainResource::Control, amount))?)
      }
      _ => None,
    };
    Ok(Self {
      ticket,
      tenant,
      bytes,
    })
  }

  pub(crate) fn bytes(&self) -> usize {
    self.bytes
  }

  /// Reconciles a reservation to the exact retained payload size. The
  /// Control resize takes the global and tenant dimensions under one lock.
  pub(crate) fn try_resize(&mut self, bytes: usize) -> Result<(), DomainError> {
    if bytes == self.bytes {
      return Ok(());
    }
    if let Some(ticket) = &mut self.ticket {
      ticket.try_resize(DomainResources::ZERO.with(DomainResource::Control, bytes))?;
      if bytes == 0 {
        // Drop a zero-vector ticket only after its domain lock has been
        // released. The owner handle remains here for a possible regrowth.
        drop(self.ticket.take());
      }
    } else if bytes != 0
      && let Some(tenant) = &self.tenant
    {
      self.ticket =
        Some(tenant.try_acquire(DomainResources::ZERO.with(DomainResource::Control, bytes))?);
    }
    self.bytes = bytes;
    Ok(())
  }

  /// Transfers bytes of this charge to a second owner without increasing
  /// global or tenant usage. Failed partitions leave this charge untouched.
  pub(crate) fn split_off(&mut self, bytes: usize) -> Result<Self, DomainError> {
    let Some(remaining) = self.bytes.checked_sub(bytes) else {
      return Err(DomainError::Invalid);
    };
    let ticket = if bytes == 0 {
      None
    } else if let Some(ticket) = &mut self.ticket {
      Some(ticket.split_off(DomainResources::ZERO.with(DomainResource::Control, bytes))?)
    } else {
      None
    };
    self.bytes = remaining;
    if remaining == 0 {
      // Avoid keeping a zero-resource reservation count after transferring
      // the complete charge. The tenant handle still retains the generation.
      drop(self.ticket.take());
    }
    Ok(Self {
      ticket,
      tenant: self.tenant.clone(),
      bytes,
    })
  }
}

/// The bytes occupied by capacity slots of T, using checked arithmetic.
pub(crate) fn payload_bytes<T>(capacity: usize) -> Result<usize, DomainError> {
  capacity
    .checked_mul(std::mem::size_of::<T>())
    .ok_or(DomainError::Invalid)
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::Wake;

  fn limits(cpu: usize, memory: usize) -> DomainResources {
    DomainResources::ZERO
      .with(DomainResource::Cpu, cpu)
      .with(DomainResource::Memory, memory)
      .with(DomainResource::Disk, 2)
      .with(DomainResource::Network, 2)
      .with(DomainResource::Tasks, 4)
      .with(DomainResource::Control, 4096)
  }

  #[test]
  fn fixed_metadata_fee_covers_shared_state_tables_and_reserved_tenant_owners() {
    let ceilings = limits(2, 32);
    let domain = ResourceDomain::with_waiters(ceilings, 2, 3).unwrap();
    let expected = {
      let state = lock(&domain.state);
      std::mem::size_of::<Mutex<State>>()
        + state.tenants.len() * std::mem::size_of::<TenantOwner>()
        + state.tenants.capacity() * std::mem::size_of::<TenantSlot>()
        + state.waiters.capacity() * std::mem::size_of::<WaiterSlot>()
    };
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      expected
    );
    let first = domain.tenant(DomainResources::ZERO).unwrap();
    let retained = first.clone();
    let second = domain.tenant(DomainResources::ZERO).unwrap();
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      expected
    );
    assert_eq!(first.snapshot().unwrap().used, DomainResources::ZERO);
    drop(first);
    assert_eq!(domain.snapshot().live_tenants, 2);
    drop(retained);
    drop(second);
    assert_eq!(domain.snapshot().live_tenants, 0);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      expected
    );

    let too_small = ceilings.with(DomainResource::Control, expected - 1);
    assert!(matches!(
      ResourceDomain::with_waiters(too_small, 2, 3),
      Err(DomainError::Exhausted(DomainResource::Control))
    ));
  }

  #[test]
  fn split_reservation_preserves_usage_and_releases_components_independently() {
    let limits = limits(1, 0);
    let domain = ResourceDomain::new(limits, 1).unwrap();
    let tenant = domain.tenant(limits).unwrap();
    let baseline = domain.snapshot();
    let request = DomainResources::ZERO
      .with(DomainResource::Tasks, 1)
      .with(DomainResource::Control, 128);
    let mut combined = tenant.try_acquire(request).unwrap();
    let before = domain.snapshot();

    let task = combined
      .split_off(DomainResources::ZERO.with(DomainResource::Tasks, 1))
      .unwrap();
    assert_eq!(domain.snapshot(), before);
    assert_eq!(
      task.resources(),
      DomainResources::ZERO.with(DomainResource::Tasks, 1)
    );
    assert_eq!(
      combined.resources(),
      DomainResources::ZERO.with(DomainResource::Control, 128)
    );
    drop(task);
    assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 0);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      before.used.get(DomainResource::Control)
    );
    drop(combined);
    assert_eq!(domain.snapshot().used, baseline.used);
  }

  #[test]
  fn failed_split_at_reservation_count_limit_keeps_original_ticket() {
    let limits = limits(1, 0);
    let domain = ResourceDomain::new(limits, 1).unwrap();
    let tenant = domain.tenant(limits).unwrap();
    let mut ticket = tenant
      .try_acquire(DomainResources::ZERO.with(DomainResource::Control, 32))
      .unwrap();
    let original = ticket.resources();
    let used = domain.snapshot().used;
    {
      let mut state = lock(&domain.state);
      state.tenants[tenant.owner.key.index].reservations = usize::MAX;
    }

    assert_eq!(
      ticket
        .split_off(DomainResources::ZERO.with(DomainResource::Control, 8))
        .err(),
      Some(DomainError::Exhausted(DomainResource::Control))
    );
    assert_eq!(ticket.resources(), original);
    assert_eq!(domain.snapshot().used, used);
    lock(&domain.state).tenants[tenant.owner.key.index].reservations = 1;
  }

  #[test]
  fn resize_checks_only_positive_deltas_and_rolls_back_both_ledgers() {
    let ceiling = limits(1, 0);
    let domain = ResourceDomain::new(ceiling, 1).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let mut ticket = tenant
      .try_acquire(
        DomainResources::ZERO
          .with(DomainResource::Cpu, 1)
          .with(DomainResource::Control, 20),
      )
      .unwrap();

    domain
      .set_limits(ceiling.with(DomainResource::Cpu, 0))
      .unwrap();
    tenant
      .set_limits(
        ceiling
          .with(DomainResource::Cpu, 0)
          .with(DomainResource::Control, 25),
      )
      .unwrap();
    let global_before = domain.snapshot().used;
    let tenant_before = tenant.snapshot().unwrap().used;
    let desired = DomainResources::ZERO
      .with(DomainResource::Cpu, 1)
      .with(DomainResource::Control, 40);
    assert_eq!(
      ticket.try_resize(desired),
      Err(DomainError::Exhausted(DomainResource::Control))
    );
    assert_eq!(ticket.resources().get(DomainResource::Control), 20);
    assert_eq!(domain.snapshot().used, global_before);
    assert_eq!(tenant.snapshot().unwrap().used, tenant_before);

    // Raising the tenant cap is not enough while the global soft cap still
    // blocks the positive Control delta.
    tenant
      .set_limits(
        ceiling
          .with(DomainResource::Cpu, 0)
          .with(DomainResource::Control, 40),
      )
      .unwrap();
    let baseline = domain.snapshot().used.get(DomainResource::Control);
    domain
      .set_limits(
        ceiling
          .with(DomainResource::Cpu, 0)
          .with(DomainResource::Control, baseline + 10),
      )
      .unwrap();
    let global_before = domain.snapshot().used;
    let tenant_before = tenant.snapshot().unwrap().used;
    assert_eq!(
      ticket.try_resize(desired),
      Err(DomainError::Exhausted(DomainResource::Control))
    );
    assert_eq!(domain.snapshot().used, global_before);
    assert_eq!(tenant.snapshot().unwrap().used, tenant_before);

    domain
      .set_limits(
        ceiling
          .with(DomainResource::Cpu, 0)
          .with(DomainResource::Control, baseline + 40),
      )
      .unwrap();
    ticket.try_resize(desired).unwrap();
    assert_eq!(ticket.resources(), desired);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline + 20
    );

    tenant.close();
    let smaller = desired.with(DomainResource::Control, 10);
    ticket.try_resize(smaller).unwrap();
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline - 10
    );
    assert_eq!(ticket.try_resize(desired), Err(DomainError::Closed));
    assert_eq!(ticket.resources(), smaller);
    drop(ticket);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline - 20
    );
  }

  #[test]
  fn control_charge_tracks_splits_and_reconciled_bytes() {
    let limits = limits(1, 0);
    let domain = ResourceDomain::new(limits, 1).unwrap();
    let tenant = domain.tenant(limits).unwrap();
    let baseline = domain.snapshot().used.get(DomainResource::Control);
    let mut charge = ControlCharge::try_new(Some(&tenant), 32).unwrap();
    let remainder = charge.split_off(12).unwrap();
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline + 32
    );
    assert_eq!(charge.bytes(), 20);
    assert_eq!(remainder.bytes(), 12);
    charge.try_resize(24).unwrap();
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline + 36
    );
    drop(remainder);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline + 24
    );
    charge.try_resize(0).unwrap();
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline
    );
    assert_eq!(payload_bytes::<u64>(3), Ok(24));
    assert_eq!(payload_bytes::<u64>(usize::MAX), Err(DomainError::Invalid));
  }

  #[test]
  fn waiter_pool_control_owner_survives_until_last_waiter_after_close() {
    let limits = limits(1, 0);
    let domain = ResourceDomain::with_waiters(limits, 1, 1).unwrap();
    let tenant = domain.tenant(limits).unwrap();
    let baseline = domain.snapshot().used.get(DomainResource::Control);
    let pool_bytes = DomainWaitPool::control_payload_bytes();
    let pool = tenant.reserve_waiters(1).unwrap();
    let waiter = pool.try_lease().unwrap();
    let retained_pool = pool.clone();
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline + pool_bytes
    );

    tenant.close();
    drop(tenant);
    drop(pool);
    drop(retained_pool);
    assert_eq!(domain.snapshot().live_tenants, 1);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline + pool_bytes
    );
    assert_eq!(domain.tenant(limits).unwrap_err(), DomainError::TenantsFull);

    drop(waiter);
    assert_eq!(domain.snapshot().live_tenants, 0);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline
    );
    assert!(domain.tenant(limits).is_ok());
  }

  #[test]
  fn global_and_tenant_admission_roll_back_every_component() {
    let domain = ResourceDomain::new(limits(2, 20), 2).unwrap();
    let first = domain.tenant(limits(2, 10)).unwrap();
    let second = domain.tenant(limits(2, 10)).unwrap();
    let request = DomainResources::ZERO
      .with(DomainResource::Cpu, 1)
      .with(DomainResource::Memory, 8);
    let held = first.try_acquire(request).unwrap();
    let before = domain.snapshot();
    assert_eq!(
      first.try_acquire(request).unwrap_err(),
      DomainError::Exhausted(DomainResource::Memory)
    );
    assert_eq!(domain.snapshot(), before);
    let other = second.try_acquire(request).unwrap();
    assert_eq!(
      first
        .try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 1))
        .unwrap_err(),
      DomainError::Exhausted(DomainResource::Cpu)
    );
    drop(other);
    drop(held);
    assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 0);
  }

  #[test]
  fn closed_tenant_remains_owned_until_last_result_clone_releases() {
    let domain = ResourceDomain::new(limits(1, 20), 1).unwrap();
    let tenant = domain.tenant(limits(1, 20)).unwrap();
    let held = std::sync::Arc::new(
      tenant
        .try_acquire(DomainResources::ZERO.with(DomainResource::Memory, 10))
        .unwrap(),
    );
    let clone = held.clone();
    drop(tenant);
    assert_eq!(
      domain.tenant(limits(1, 20)).unwrap_err(),
      DomainError::TenantsFull
    );
    drop(held);
    assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 10);
    drop(clone);
    let next = domain.tenant(limits(1, 20)).unwrap();
    assert_eq!(next.snapshot().unwrap().used, DomainResources::ZERO);
  }

  #[test]
  fn lowering_soft_caps_drains_without_preemption_and_preserves_hard_ceiling() {
    let domain = ResourceDomain::new(limits(2, 20), 1).unwrap();
    let tenant = domain.tenant(limits(2, 20)).unwrap();
    let held = tenant
      .try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 2))
      .unwrap();
    domain.set_limits(limits(1, 20)).unwrap();
    assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 2);
    assert_eq!(
      tenant
        .try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 1))
        .unwrap_err(),
      DomainError::Exhausted(DomainResource::Cpu)
    );
    assert_eq!(
      domain.set_limits(limits(3, 20)),
      Err(DomainError::AboveCeiling(DomainResource::Cpu))
    );
    drop(held);
    let _held = tenant
      .try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 1))
      .unwrap();
  }

  #[test]
  fn component_compare_exchange_preserves_other_limits_and_resumes_waiters() {
    let ceiling = limits(2, 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 1).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let tenant_limits = ceiling
      .with(DomainResource::Cpu, 0)
      .with(DomainResource::Disk, 1);
    tenant.set_limits(tenant_limits).unwrap();
    let pool = tenant.reserve_waiters(1).unwrap();
    let waiter = pool.try_lease().unwrap();
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountWake(Arc::clone(&wakes))));
    assert!(
      waiter
        .try_acquire_or_register(&tenant, &waker)
        .unwrap()
        .is_none()
    );

    assert!(
      !tenant
        .compare_exchange_limit(DomainResource::Disk, 2, 0)
        .unwrap()
    );
    assert!(
      tenant
        .compare_exchange_limit(DomainResource::Cpu, 0, 1)
        .unwrap()
    );
    let snapshot = tenant.snapshot().unwrap();
    assert_eq!(snapshot.limit.get(DomainResource::Cpu), 1);
    assert_eq!(snapshot.limit.get(DomainResource::Disk), 1);
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    let cpu = waiter
      .try_acquire_or_register(&tenant, &waker)
      .unwrap()
      .unwrap();
    drop(cpu);

    let before = domain.snapshot().limit;
    assert!(
      domain
        .compare_exchange_limit(DomainResource::Cpu, 2, 1)
        .unwrap()
    );
    assert_eq!(domain.snapshot().limit, before.with(DomainResource::Cpu, 1));
    assert!(
      !domain
        .compare_exchange_limit(DomainResource::Cpu, 2, 0)
        .unwrap()
    );
    assert_eq!(
      domain.compare_exchange_limit(DomainResource::Cpu, 1, 3),
      Err(DomainError::AboveCeiling(DomainResource::Cpu))
    );
  }

  #[test]
  fn closed_handles_retain_bounded_owner_slots_until_last_clone_drops() {
    let domain = ResourceDomain::new(limits(1, 20), 1).unwrap();
    let old = domain.tenant(limits(1, 20)).unwrap();
    let clone = old.clone();
    old.close();
    assert_eq!(
      domain.tenant(limits(1, 20)).unwrap_err(),
      DomainError::TenantsFull
    );
    assert_eq!(
      old.try_acquire(DomainResources::ZERO).unwrap_err(),
      DomainError::Closed
    );
    drop(old);
    assert_eq!(
      domain.tenant(limits(1, 20)).unwrap_err(),
      DomainError::TenantsFull
    );
    drop(clone);
    let new = domain.tenant(limits(1, 20)).unwrap();
    let held = new
      .try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 1))
      .unwrap();
    assert_eq!(new.snapshot().unwrap().used.get(DomainResource::Cpu), 1);
    drop(held);
  }

  #[test]
  fn zero_reservations_retain_generation_and_do_not_require_unrequested_capacity() {
    let domain = ResourceDomain::new(limits(2, 20), 1).unwrap();
    let tenant = domain.tenant(limits(2, 20)).unwrap();
    let cpu = tenant
      .try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 2))
      .unwrap();
    domain.set_limits(limits(1, 20)).unwrap();
    let zero = tenant.try_acquire(DomainResources::ZERO).unwrap();
    let memory = tenant
      .try_acquire(DomainResources::ZERO.with(DomainResource::Memory, 1))
      .unwrap();
    tenant.close();
    drop(tenant);
    drop(cpu);
    drop(memory);
    assert_eq!(
      domain.tenant(limits(2, 20)).unwrap_err(),
      DomainError::TenantsFull
    );
    drop(zero);
    domain.tenant(limits(2, 20)).unwrap();
  }

  struct CountWake(Arc<AtomicUsize>);

  impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  struct SnapshotWake {
    tenant: TenantDomain,
    wakes: Arc<AtomicUsize>,
  }

  impl Wake for SnapshotWake {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      assert!(self.tenant.snapshot().is_ok());
      self.wakes.fetch_add(1, Ordering::SeqCst);
    }
  }

  struct PanicDropWake(TenantDomain);

  impl Wake for PanicDropWake {
    fn wake(self: Arc<Self>) {
      assert!(self.0.snapshot().is_ok());
    }

    fn wake_by_ref(self: &Arc<Self>) {
      assert!(self.0.snapshot().is_ok());
    }
  }

  impl Drop for PanicDropWake {
    fn drop(&mut self) {
      assert!(self.0.snapshot().is_ok());
      panic!("injected waker destructor panic");
    }
  }

  #[test]
  fn fixed_waiter_capacity_is_control_charged_and_leased_disjointly() {
    let ceiling = limits(1, 20).with(DomainResource::Control, 4096);
    let domain = ResourceDomain::with_waiters(ceiling, 2, 4).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let first = tenant.reserve_waiters(3).unwrap();
    let _waiter = first.try_lease().unwrap();
    assert_eq!(
      tenant.reserve_waiters(2).unwrap_err(),
      DomainError::WaitersFull
    );
    let state = lock(&domain.state);
    let table_bytes = state.tenants.capacity() * std::mem::size_of::<TenantSlot>()
      + state.waiters.capacity() * std::mem::size_of::<WaiterSlot>();
    let fixed_bytes = std::mem::size_of::<Mutex<State>>()
      + state.tenants.len() * std::mem::size_of::<TenantOwner>();
    drop(state);
    let expected = fixed_bytes + table_bytes + DomainWaitPool::control_payload_bytes();
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      expected
    );

    let too_small = ceiling.with(DomainResource::Control, fixed_bytes + table_bytes - 1);
    assert_eq!(
      ResourceDomain::with_waiters(too_small, 2, 4).unwrap_err(),
      DomainError::Exhausted(DomainResource::Control)
    );
  }

  #[test]
  fn cpu_waiters_wake_in_order_and_resume_after_soft_limit_increase() {
    let ceiling = limits(1, 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 2).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let pool = tenant.reserve_waiters(2).unwrap();
    let first = pool.try_lease().unwrap();
    let second = pool.try_lease().unwrap();
    let held = tenant
      .try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 1))
      .unwrap();
    let first_wakes = Arc::new(AtomicUsize::new(0));
    let second_wakes = Arc::new(AtomicUsize::new(0));
    let first_waker = Waker::from(Arc::new(CountWake(Arc::clone(&first_wakes))));
    let second_waker = Waker::from(Arc::new(CountWake(Arc::clone(&second_wakes))));

    assert!(
      first
        .try_acquire_or_register(&tenant, &first_waker)
        .unwrap()
        .is_none()
    );
    assert!(
      second
        .try_acquire_or_register(&tenant, &second_waker)
        .unwrap()
        .is_none()
    );
    drop(held);
    assert_eq!(first_wakes.load(Ordering::SeqCst), 1);
    assert_eq!(second_wakes.load(Ordering::SeqCst), 1);

    let first_cpu = first
      .try_acquire_or_register(&tenant, &first_waker)
      .unwrap()
      .unwrap();
    assert!(
      second
        .try_acquire_or_register(&tenant, &second_waker)
        .unwrap()
        .is_none()
    );
    drop(first_cpu);
    assert_eq!(second_wakes.load(Ordering::SeqCst), 2);
    let second_cpu = second
      .try_acquire_or_register(&tenant, &second_waker)
      .unwrap()
      .unwrap();
    drop(second_cpu);

    tenant
      .set_limits(ceiling.with(DomainResource::Cpu, 0))
      .unwrap();
    assert!(
      first
        .try_acquire_or_register(&tenant, &first_waker)
        .unwrap()
        .is_none()
    );
    let before = first_wakes.load(Ordering::SeqCst);
    tenant.set_limits(ceiling).unwrap();
    assert_eq!(first_wakes.load(Ordering::SeqCst), before + 1);
    let final_cpu = first
      .try_acquire_or_register(&tenant, &first_waker)
      .unwrap()
      .unwrap();
    drop(final_cpu);
  }

  #[test]
  fn panicking_waker_drop_cannot_leak_cpu_or_strand_the_next_waiter() {
    let ceiling = limits(1, 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 2).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let pool = tenant.reserve_waiters(2).unwrap();
    let first = pool.try_lease().unwrap();
    let second = pool.try_lease().unwrap();
    tenant
      .set_limits(ceiling.with(DomainResource::Cpu, 0))
      .unwrap();

    let panic_waker = Waker::from(Arc::new(PanicDropWake(tenant.clone())));
    let wakes = Arc::new(AtomicUsize::new(0));
    let next_waker = Waker::from(Arc::new(SnapshotWake {
      tenant: tenant.clone(),
      wakes: Arc::clone(&wakes),
    }));
    assert!(
      first
        .try_acquire_or_register(&tenant, &panic_waker)
        .unwrap()
        .is_none()
    );
    assert!(
      second
        .try_acquire_or_register(&tenant, &next_waker)
        .unwrap()
        .is_none()
    );
    drop_contained(panic_waker);

    // Stage the soft-limit increase without notifying: the first waiter must
    // acquire and dispose its retained waker before the next release wakes
    // the FIFO successor.
    {
      let mut state = lock(&domain.state);
      state.tenants[tenant.owner.key.index].limit = ceiling;
    }
    let ticket = first
      .try_acquire_or_register(&tenant, Waker::noop())
      .unwrap()
      .unwrap();
    assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 1);
    drop(ticket);
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    let next = second
      .try_acquire_or_register(&tenant, &next_waker)
      .unwrap()
      .unwrap();
    drop(next);
    assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
  }

  #[test]
  fn cancelling_a_waiter_with_a_panicking_waker_still_notifies_the_fifo_successor() {
    let ceiling = limits(1, 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 2).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let pool = tenant.reserve_waiters(2).unwrap();
    let first = pool.try_lease().unwrap();
    let second = pool.try_lease().unwrap();
    tenant
      .set_limits(ceiling.with(DomainResource::Cpu, 0))
      .unwrap();
    let panic_waker = Waker::from(Arc::new(PanicDropWake(tenant.clone())));
    let wakes = Arc::new(AtomicUsize::new(0));
    let next_waker = Waker::from(Arc::new(SnapshotWake {
      tenant: tenant.clone(),
      wakes: Arc::clone(&wakes),
    }));
    assert!(
      first
        .try_acquire_or_register(&tenant, &panic_waker)
        .unwrap()
        .is_none()
    );
    assert!(
      second
        .try_acquire_or_register(&tenant, &next_waker)
        .unwrap()
        .is_none()
    );
    drop_contained(panic_waker);
    {
      let mut state = lock(&domain.state);
      state.tenants[tenant.owner.key.index].limit = ceiling;
    }

    first.cancel_wait();
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    let ticket = second
      .try_acquire_or_register(&tenant, &next_waker)
      .unwrap()
      .unwrap();
    drop(ticket);
    assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
  }

  struct ThreadWake(std::thread::Thread);

  impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.0.unpark();
    }
  }

  #[test]
  fn native_cpu_admission_races_never_exceed_global_or_tenant_limit() {
    const THREADS: usize = 6;
    const ROUNDS: usize = 200;
    let ceiling = limits(2, 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, THREADS).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let pool = tenant.reserve_waiters(THREADS).unwrap();
    let waiters: Vec<_> = (0..THREADS).map(|_| pool.try_lease().unwrap()).collect();
    let active = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
      for waiter in waiters {
        let tenant = tenant.clone();
        let active = Arc::clone(&active);
        scope.spawn(move || {
          let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
          for _ in 0..ROUNDS {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let cpu = loop {
              if let Some(cpu) = waiter.try_acquire_or_register(&tenant, &waker).unwrap() {
                break cpu;
              }
              assert!(
                std::time::Instant::now() < deadline,
                "CPU waiter was not resumed"
              );
              std::thread::park_timeout(std::time::Duration::from_millis(100));
            };
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            assert!(now <= 2, "domain over-admitted {now} active CPU tickets");
            std::thread::yield_now();
            active.fetch_sub(1, Ordering::SeqCst);
            drop(cpu);
          }
        });
      }
    });
    assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
  }
}

#[cfg(all(test, not(loom)))]
#[path = "control_budget.rs"]
mod control_budget_tests;

#[cfg(all(test, loom))]
mod model {
  use super::*;
  use loom::sync::Arc as LoomArc;
  use loom::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::Arc as StdArc;
  use std::task::Wake;

  struct CountWake(LoomArc<AtomicUsize>);

  impl Wake for CountWake {
    fn wake(self: StdArc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &StdArc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }
  #[test]
  fn loom_global_and_tenant_reservations_never_overadmit() {
    loom::model(|| {
      let limits = DomainResources::ZERO
        .with(DomainResource::Cpu, 1)
        .with(DomainResource::Control, 4096);
      let domain = ResourceDomain::new(limits, 2).unwrap();
      let first = domain.tenant(limits).unwrap();
      let second = domain.tenant(limits).unwrap();
      let worker = loom::thread::spawn(move || {
        let _held = first.try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 1));
      });
      let held = second.try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 1));
      assert!(domain.snapshot().used.get(DomainResource::Cpu) <= 1);
      drop(held);
      worker.join().unwrap();
      assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
    });
  }

  #[test]
  fn loom_waiter_enrollment_racing_release_is_not_lost() {
    loom::model(|| {
      let ceiling = DomainResources::ZERO
        .with(DomainResource::Cpu, 1)
        .with(DomainResource::Tasks, 2)
        .with(DomainResource::Control, 4096);
      let domain = ResourceDomain::with_waiters(ceiling, 1, 1).unwrap();
      let tenant = domain.tenant(ceiling).unwrap();
      let pool = tenant.reserve_waiters(1).unwrap();
      let waiter = pool.try_lease().unwrap();
      let held = tenant
        .try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 1))
        .unwrap();
      let wakes = LoomArc::new(AtomicUsize::new(0));
      let waker = Waker::from(StdArc::new(CountWake(LoomArc::clone(&wakes))));
      let register = loom::thread::spawn(move || {
        let result = waiter.try_acquire_or_register(&tenant, &waker).unwrap();
        (waiter, tenant, waker, result)
      });
      let release = loom::thread::spawn(move || drop(held));
      release.join().unwrap();
      let (waiter, tenant, waker, result) = register.join().unwrap();
      let was_admitted = result.is_some();
      assert!(was_admitted || wakes.load(Ordering::SeqCst) > 0);
      drop(result);
      if !was_admitted {
        let admitted = waiter
          .try_acquire_or_register(&tenant, &waker)
          .unwrap()
          .unwrap();
        drop(admitted);
      }
      assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
    });
  }

  #[test]
  fn loom_waiter_cancellation_cannot_wake_a_reused_generation() {
    loom::model(|| {
      let ceiling = DomainResources::ZERO
        .with(DomainResource::Cpu, 1)
        .with(DomainResource::Tasks, 2)
        .with(DomainResource::Control, 4096);
      let domain = ResourceDomain::with_waiters(ceiling, 1, 1).unwrap();
      let tenant = domain.tenant(ceiling).unwrap();
      let pool = tenant.reserve_waiters(1).unwrap();
      let old_waiter = pool.try_lease().unwrap();
      let held = tenant
        .try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 1))
        .unwrap();
      let old_wakes = LoomArc::new(AtomicUsize::new(0));
      let old_waker = Waker::from(StdArc::new(CountWake(LoomArc::clone(&old_wakes))));
      assert!(
        old_waiter
          .try_acquire_or_register(&tenant, &old_waker)
          .unwrap()
          .is_none()
      );

      let cancel = loom::thread::spawn(move || {
        old_waiter.cancel_wait();
        old_waiter
      });
      let release = loom::thread::spawn(move || drop(held));
      release.join().unwrap();
      drop(cancel.join().unwrap());
      let old_wake_count = old_wakes.load(Ordering::SeqCst);
      assert!(old_wake_count <= 1);

      let new_waiter = pool.try_lease().unwrap();
      let new_wakes = LoomArc::new(AtomicUsize::new(0));
      let new_waker = Waker::from(StdArc::new(CountWake(LoomArc::clone(&new_wakes))));
      let admitted = new_waiter
        .try_acquire_or_register(&tenant, &new_waker)
        .unwrap()
        .unwrap();
      drop(admitted);
      assert_eq!(new_wakes.load(Ordering::SeqCst), 0);
      assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
    });
  }

  #[test]
  fn loom_task_control_partition_releases_tasks_before_retained_control() {
    loom::model(|| {
      let ceiling = DomainResources::ZERO
        .with(DomainResource::Tasks, 1)
        .with(DomainResource::Control, 4096);
      let domain = ResourceDomain::new(ceiling, 2).unwrap();
      let baseline = domain.snapshot().used.get(DomainResource::Control);
      domain
        .set_limits(ceiling.with(DomainResource::Control, baseline + 64))
        .unwrap();
      let left = domain.tenant(ceiling).unwrap();
      let right = domain.tenant(ceiling).unwrap();
      let request = DomainResources::ZERO
        .with(DomainResource::Tasks, 1)
        .with(DomainResource::Control, 64);

      let acquire = move |tenant: TenantDomain| {
        tenant.try_acquire(request).ok().map(|mut combined| {
          let task = combined
            .split_off(DomainResources::ZERO.with(DomainResource::Tasks, 1))
            .unwrap();
          drop(task);
          combined
        })
      };
      let left = loom::thread::spawn(move || acquire(left));
      let right = loom::thread::spawn(move || acquire(right));
      let left = left.join().unwrap();
      let right = right.join().unwrap();
      assert_ne!(left.is_some(), right.is_some());
      let held = domain.snapshot().used;
      assert_eq!(held.get(DomainResource::Tasks), 0);
      assert_eq!(held.get(DomainResource::Control), baseline + 64);

      drop(left);
      drop(right);
      assert_eq!(
        domain.snapshot().used.get(DomainResource::Control),
        baseline
      );
    });
  }
}
