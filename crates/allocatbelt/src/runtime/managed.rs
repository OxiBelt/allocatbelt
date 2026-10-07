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
//! A buffer is charged the storage length requested from the allocator for
//! its bytes, which is its retained vector capacity. Clones share that storage
//! and its one charge, which is released after the storage is freed, when
//! the last clone is dropped. The charge is not a measure of physical
//! memory: allocator rounding and metadata, the shared header holding the
//! storage and its clone count, page residency (RSS) and memory allocated any other way are not counted,
//! and nothing stops code from allocating outside a scope. Growing a buffer
//! reserves its entire replacement while the old storage remains charged.
//!
//! A permit holds disk and network operation slots: concurrency counts the
//! caller declares, released exactly once when the permit is dropped. There
//! are no byte-rate or bandwidth limits here, and this module does not
//! account CPU.
//!
//! # Allocation failure
//!
//! A buffer's storage is reserved in the ledger first and then allocated
//! with `Vec::try_reserve_exact`. When the allocator refuses, the
//! reservation is released and [`ResourceError::OutOfMemory`] returned. The
//! small shared header of a new buffer is allocated afterwards by
//! `Arc::new`, and the ledger by [`ResourceScope::new`]; those follow Rust's
//! usual out-of-memory handling (`handle_alloc_error`, which aborts by
//! default) instead of returning an error.
//!
//! # Locks
//!
//! The ledger lock is held only for checked arithmetic on the counts. No
//! user code runs, nothing is allocated or freed and nothing can panic under
//! it: storage is allocated after its reservation is stored and freed before
//! its charge is released. A poisoned lock therefore still holds consistent
//! counts and is used as is; no panic is caught.

use std::fmt;
use std::ops::Deref;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[cfg(all(test, loom))]
#[path = "managed_model.rs"]
mod model;

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
}

impl fmt::Display for ResourceError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Invalid(kind) => write!(f, "request exceeds the scope's {kind} limit"),
      Self::Exhausted(kind) => write!(f, "not enough free {kind} capacity"),
      Self::OutOfMemory => f.write_str("the allocator refused the buffer's storage"),
      Self::Shared => f.write_str("the buffer has other clones"),
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
    Self {
      limits,
      memory: 0,
      disk: 0,
      network: 0,
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
/// dropped.
#[derive(Clone)]
pub struct ResourceScope {
  ledger: Arc<Mutex<Ledger>>,
}

impl ResourceScope {
  /// A scope with nothing charged. The ledger is allocated by `Arc::new`
  /// (see the module documentation on allocation failure).
  #[must_use]
  pub fn new(limits: ResourceLimits) -> Self {
    Self {
      ledger: Arc::new(Mutex::new(Ledger::new(limits))),
    }
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
    };
    backing.try_resize(len)?;
    Ok(ManagedBuf {
      backing: Arc::new(backing),
    })
  }

  /// A permit holding every slot of `request`, or none of them.
  ///
  /// Both components are checked and taken under one lock acquisition, so
  /// a refused request leaves the ledger unchanged. A zero request always
  /// succeeds and holds nothing.
  ///
  /// # Errors
  ///
  /// `Invalid(Disk)` or `Invalid(Network)` when a component exceeds its
  /// limit (checked first, for both), otherwise `Exhausted(Disk)` or
  /// `Exhausted(Network)` when a component does not fit what is free now.
  pub fn try_acquire(&self, request: OperationRequest) -> Result<OperationPermit, ResourceError> {
    lock(&self.ledger).acquire_ops(request)?;
    Ok(OperationPermit {
      ledger: Arc::clone(&self.ledger),
      request,
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
}

impl Backing {
  /// Sets the length to `new_len`, zero-filling new bytes; see
  /// [`ManagedBuf::try_resize`]. On an error nothing has changed.
  fn try_resize(&mut self, new_len: usize) -> Result<(), ResourceError> {
    if new_len <= self.charged {
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
    let mut replacement = Vec::new();
    if replacement.try_reserve_exact(new_len).is_err() {
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
        self.release(new_len);
        return Err(error);
      }
    }
    replacement.resize(new_len, 0);
    replacement[..self.storage.len()].copy_from_slice(&self.storage);
    let old_charge = self.charged;
    let old_storage = std::mem::replace(&mut self.storage, replacement);
    self.charged = capacity;
    drop(old_storage);
    self.release(old_charge);
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
