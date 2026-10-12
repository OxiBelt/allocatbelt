//! Atomic global and tenant admission for managed resources.
//!
//! One mutex protects both ledgers. An admission takes every requested
//! component or none. Reservations retain their tenant generation through
//! actual cleanup; closing a tenant does not release its live resources.
//! Counts describe declared managed ownership, not process RSS or CPU time.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;

#[cfg(loom)]
use loom::sync::{Arc, Mutex, MutexGuard};
#[cfg(not(loom))]
use std::sync::{Arc, Mutex, MutexGuard};

const KINDS: usize = 6;

/// Independently admitted resources in a managed domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DomainError {
  Invalid,
  OutOfMemory,
  TenantsFull,
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
  /// payload bytes are charged to `Control`; allocation/header overhead is
  /// not represented as measured physical memory.
  pub fn new(ceiling: DomainResources, max_tenants: usize) -> Result<Self, DomainError> {
    if max_tenants == 0 {
      return Err(DomainError::Invalid);
    }
    let bytes = max_tenants
      .checked_mul(std::mem::size_of::<TenantSlot>())
      .ok_or(DomainError::Invalid)?;
    if bytes > ceiling.get(DomainResource::Control) {
      return Err(DomainError::Exhausted(DomainResource::Control));
    }
    let mut tenants = Vec::new();
    tenants
      .try_reserve_exact(max_tenants)
      .map_err(|_| DomainError::OutOfMemory)?;
    let actual_bytes = tenants
      .capacity()
      .checked_mul(std::mem::size_of::<TenantSlot>())
      .ok_or(DomainError::Invalid)?;
    if actual_bytes > ceiling.get(DomainResource::Control) {
      return Err(DomainError::Exhausted(DomainResource::Control));
    }
    tenants.resize_with(max_tenants, TenantSlot::empty);
    let used = DomainResources::ZERO.with(DomainResource::Control, actual_bytes);
    Ok(Self {
      state: Arc::new(Mutex::new(State {
        ceiling,
        limit: ceiling,
        used,
        tenants,
      })),
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
    state.limit = limit;
    Ok(())
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

impl fmt::Debug for TenantDomain {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("TenantDomain")
      .field("key", &self.owner.key)
      .finish_non_exhaustive()
  }
}

impl TenantDomain {
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
    slot.limit = limit;
    Ok(())
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
}

impl Drop for DomainReservation {
  fn drop(&mut self) {
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
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;
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
}

#[cfg(all(test, loom))]
mod model {
  use super::*;
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
}
