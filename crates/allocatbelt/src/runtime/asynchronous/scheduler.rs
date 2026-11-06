//! Bounded async task admission and scheduling. Scheduler state is reserved
//! before workers start; the mutex protects bookkeeping only and is released
//! before polling, dropping task values, or invoking wakers. Dispatch uses
//! per-dispatcher FIFO lanes and shared overflow for cleanup and abandoned lanes.

#![forbid(unsafe_code)]

use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Waker};

#[path = "distributed.rs"]
mod distributed;
#[path = "free_slots.rs"]
mod free_slots;
#[cfg(all(test, not(loom)))]
#[path = "join_word_tests.rs"]
mod join_word_tests;

use super::handoff;
use super::handoff_protocol::{DispatchTurn, HandoffLoan};
use super::identity;
use super::join::AsyncJob;
use super::metrics::{Padded, RuntimeMetrics};
use super::protocol::{ScopeProtocol, SlotProtocol};
use super::task::{
  DomainCpuAdmission, ErasedTask, Lease, PollNotify, PollResult, Task, TaskSlot, TaskWord,
};
use super::thread_options::AsyncThreadContext;
#[cfg(all(test, not(loom)))]
use super::thread_options::AsyncThreadOptions;
use super::{AsyncConfig, AsyncError, AsyncSpawnError};
use crate::runtime::cache;
use crate::runtime::managed::ResourceScope;
use crate::runtime::resource_domain::{
  ControlCharge, DomainError, DomainReservation, DomainResource, DomainResources, DomainWaitPool,
  DomainWaiter, TenantDomain, payload_bytes,
};
use distributed::Distributed;
use free_slots::FreeSlots;

thread_local! {
  static WORKER_RUNTIME: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

static NEXT_RUNTIME: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ScopeRef {
  index: usize,
  generation: u64,
}

impl ScopeRef {
  /// The root scope occupies the first scope slot for the runtime's whole
  /// lifetime, so its cell is reachable without the scope table.
  pub(super) const ROOT: Self = Self {
    index: 0,
    generation: 1,
  };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TaskRef {
  index: usize,
  generation: u64,
}

#[cfg(test)]
impl TaskRef {
  pub(super) const fn test_sentinel() -> Self {
    Self {
      index: 0,
      generation: 1,
    }
  }
}

struct ScopeSlot {
  generation: u64,
  scope: Option<Arc<ScopeCell>>,
}

impl ScopeSlot {
  const fn new(generation: u64, scope: Option<Arc<ScopeCell>>) -> Self {
    Self { generation, scope }
  }
}

// Declaration order is layout order: the fields every spawn and completion
// write (`admitted`, the inline free-slot word) and the flag they only read
// (`closed`) follow the lock word within one cache line; the scope table
// header is only read.
#[repr(C)]
struct State {
  admitted: usize,
  free_tasks: FreeSlots,
  closed: bool,
  scopes: Vec<ScopeSlot>,
}

pub(super) struct Shared {
  id: u64,
  max_handoffs: usize,
  workers: usize,
  pub(super) metrics: RuntimeMetrics,
  thread_options: super::ControlledThreadOptions,
  /// Admission bookkeeping on its own line pair, so the lock word, the
  /// admitted count and the first free-slot word arrive with the lock.
  state: Padded<Mutex<State>>,
  /// The root scope's cell, also held by the first scope slot. Tasks of the
  /// root scope reach it here instead of retaining their own owner.
  pub(super) root: Arc<ScopeCell>,
  distributed: Distributed,
  /// Deterministic admission interleavings; absent from non-test builds.
  #[cfg(all(test, not(loom)))]
  spawn_admission_test_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
  #[cfg(all(test, not(loom)))]
  spawn_reserved_test_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
  #[cfg(all(test, not(loom)))]
  lock_acquisitions: AtomicUsize,
  _control: ControlCharge,
}

pub(super) struct ScopeCell {
  reference: Option<ScopeRef>,
  shared: Option<Weak<Shared>>,
  max_active_polls: usize,
  binding: bool,
  dispatch: Mutex<super::protocol::ScopeDispatch>,
  active_stat: AtomicUsize,
  resources: Option<ResourceScope>,
  tenant: Option<TenantDomain>,
  task_waiters: Option<DomainWaitPool>,
  root_waiters: Option<DomainWaitPool>,
  protocol: ScopeProtocol,
  completion: Mutex<Option<Waker>>,
  _control: Option<ControlCharge>,
}

impl Drop for Shared {
  fn drop(&mut self) {
    // No dispatcher can still be running when its last Shared owner drops.
    // Retained join/abort handles and wakers must not retain admitted futures.
    self.distributed.cancel_remaining();
    // Every slot is released now; retained metrics handles read zero and
    // stop pinning this allocation through their weak owner.
    self.metrics.unbind_admission();
  }
}

impl ScopeCell {
  fn new(
    reference: Option<ScopeRef>,
    shared: Option<Weak<Shared>>,
    poll_limits: (usize, usize),
    resources: Option<ResourceScope>,
    task_waiters: Option<DomainWaitPool>,
    root_waiters: Option<DomainWaitPool>,
    control: Option<ControlCharge>,
  ) -> Self {
    let (max_active_polls, dispatch_ceiling) = poll_limits;
    let tenant = resources
      .as_ref()
      .and_then(ResourceScope::tenant_domain)
      .cloned();
    Self {
      reference,
      shared,
      max_active_polls,
      binding: max_active_polls < dispatch_ceiling,
      dispatch: Mutex::new(super::protocol::ScopeDispatch::new(max_active_polls)),
      active_stat: AtomicUsize::new(0),
      resources,
      tenant,
      task_waiters,
      root_waiters,
      protocol: ScopeProtocol::new(reference.is_none()),
      completion: Mutex::new(None),
      _control: control,
    }
  }

  fn lock_completion(&self) -> MutexGuard<'_, Option<Waker>> {
    self
      .completion
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
  }

  fn completed(&self) {
    if self.protocol.complete_one() {
      if let (Some(reference), Some(shared)) = (self.reference, &self.shared)
        && let Some(shared) = shared.upgrade()
      {
        shared.release_scope(reference, self);
      }
      let wake = self.lock_completion().take();
      if let Some(waker) = wake
        && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
      {
        super::task::drop_contained(payload);
      }
    }
  }
}

impl Shared {
  pub(super) fn new(
    config: AsyncConfig,
    max_handoffs: usize,
    resources: Option<ResourceScope>,
    thread_options: super::ControlledThreadOptions,
    metrics: RuntimeMetrics,
    park_spin: super::park_spin::Policy,
  ) -> Result<(Arc<Self>, ScopeRef), AsyncError> {
    let tenant = resources.as_ref().and_then(ResourceScope::tenant_domain);
    let mut requested_control = std::mem::size_of::<Shared>();
    for bytes in [
      FreeSlots::requested_control(config.max_outstanding)?,
      payload_bytes::<ScopeSlot>(config.max_scopes).map_err(AsyncError::ResourceDomain)?,
      std::mem::size_of::<ScopeCell>(),
    ] {
      requested_control = requested_control
        .checked_add(bytes)
        .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
    }
    requested_control = requested_control
      .checked_add(Distributed::requested_control(config)?)
      .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
    let mut control =
      ControlCharge::try_new(tenant, requested_control).map_err(AsyncError::ResourceDomain)?;

    let free_tasks = FreeSlots::new(config.max_outstanding)?;
    let mut scopes = Vec::new();
    scopes
      .try_reserve_exact(config.max_scopes)
      .map_err(|_| AsyncError::OutOfMemory)?;
    scopes.resize_with(config.max_scopes, || ScopeSlot::new(0, None));
    let Some(id) = NEXT_RUNTIME
      .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
      .ok()
    else {
      return Err(AsyncError::InvalidConfig);
    };
    let (task_waiters, root_waiters) = if let Some(tenant) = tenant {
      tenant
        .validate_cpu_execution()
        .map_err(AsyncError::ResourceDomain)?;
      let task_waiters = tenant
        .reserve_waiters(config.max_outstanding)
        .map_err(AsyncError::ResourceDomain)?;
      let root_waiters = tenant
        .reserve_waiters(config.workers)
        .map_err(AsyncError::ResourceDomain)?;
      (Some(task_waiters), Some(root_waiters))
    } else {
      (None, None)
    };
    let root_scope = Arc::new(ScopeCell::new(
      None,
      None,
      (config.workers, config.workers + max_handoffs),
      resources,
      task_waiters,
      root_waiters,
      None,
    ));
    let root = ScopeRef::ROOT;
    scopes[root.index] = ScopeSlot::new(root.generation, Some(Arc::clone(&root_scope)));
    let distributed = Distributed::new(config, max_handoffs, park_spin)?;
    let mut actual_control = std::mem::size_of::<Shared>();
    for bytes in [
      free_tasks.actual_control()?,
      payload_bytes::<ScopeSlot>(scopes.capacity()).map_err(AsyncError::ResourceDomain)?,
      std::mem::size_of::<ScopeCell>(),
    ] {
      actual_control = actual_control
        .checked_add(bytes)
        .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
    }
    actual_control = actual_control
      .checked_add(distributed.actual_control()?)
      .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
    control
      .try_resize(actual_control)
      .map_err(AsyncError::ResourceDomain)?;
    let shared = Arc::new(Self {
      id,
      max_handoffs,
      workers: config.workers,
      metrics,
      thread_options,
      distributed,
      state: Padded(Mutex::new(State {
        closed: false,
        admitted: 0,
        free_tasks,
        scopes,
      })),
      root: root_scope,
      #[cfg(all(test, not(loom)))]
      spawn_admission_test_hook: Mutex::new(None),
      #[cfg(all(test, not(loom)))]
      spawn_reserved_test_hook: Mutex::new(None),
      #[cfg(all(test, not(loom)))]
      lock_acquisitions: AtomicUsize::new(0),
      _control: control,
    });
    shared.metrics.bind_admission(Arc::downgrade(&shared));
    Ok((shared, root))
  }

  /// The admitted, unfinished task count, read under the admission mutex.
  pub(super) fn alive_tasks(&self) -> usize {
    self.lock().admitted
  }

  fn lock(&self) -> MutexGuard<'_, State> {
    distributed::assert_admission_order();
    #[cfg(all(test, not(loom)))]
    self.lock_acquisitions.fetch_add(1, Ordering::Relaxed);
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }

  #[cfg(all(test, not(loom)))]
  pub(super) fn set_spawn_admission_test_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
    *self
      .spawn_admission_test_hook
      .lock()
      .unwrap_or_else(PoisonError::into_inner) = Some(hook);
  }

  #[cfg(all(test, not(loom)))]
  fn before_spawn_admission_for_test(&self) {
    let hook = self
      .spawn_admission_test_hook
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .clone();
    if let Some(hook) = hook {
      hook();
    }
  }

  #[cfg(all(test, not(loom)))]
  pub(super) fn set_spawn_reserved_test_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
    *self
      .spawn_reserved_test_hook
      .lock()
      .unwrap_or_else(PoisonError::into_inner) = Some(hook);
  }

  #[cfg(all(test, not(loom)))]
  fn after_spawn_reservation_for_test(&self) {
    let hook = self
      .spawn_reserved_test_hook
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .clone();
    if let Some(hook) = hook {
      hook();
    }
  }

  fn invoke_hook(
    &self,
    hook: Option<&Arc<dyn Fn(AsyncThreadContext) + Send + Sync>>,
    context: AsyncThreadContext,
  ) {
    if let Some(hook) = hook
      && let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(context)))
    {
      self
        .metrics
        .inner()
        .hook_panics
        .fetch_add(1, Ordering::Relaxed);
      super::task::drop_contained(payload);
    }
  }

  fn thread_started(&self, context: AsyncThreadContext) {
    if let Some(metrics) = self.metrics.inner().thread(context.physical_index) {
      metrics.alive.store(true, Ordering::Relaxed);
      metrics.starts.fetch_add(1, Ordering::Relaxed);
    }
    self.invoke_hook(self.thread_options.start_hook(), context);
  }

  fn thread_stopped(&self, context: AsyncThreadContext) {
    self.invoke_hook(self.thread_options.stop_hook(), context);
    if let Some(metrics) = self.metrics.inner().thread(context.physical_index) {
      metrics.stops.fetch_add(1, Ordering::Relaxed);
      metrics.alive.store(false, Ordering::Relaxed);
    }
  }

  fn thread_park_attempted(&self, context: AsyncThreadContext) {
    self.invoke_hook(self.thread_options.park_hook(), context);
  }

  fn thread_parked(&self, context: AsyncThreadContext) {
    if let Some(metrics) = self.metrics.inner().thread(context.physical_index) {
      metrics.parks.fetch_add(1, Ordering::Relaxed);
    }
  }

  fn thread_unparked(&self, context: AsyncThreadContext) {
    if let Some(metrics) = self.metrics.inner().thread(context.physical_index) {
      metrics.unparks.fetch_add(1, Ordering::Relaxed);
    }
    self.invoke_hook(self.thread_options.unpark_hook(), context);
  }

  fn thread_unpark_callback(&self, context: AsyncThreadContext) {
    self.invoke_hook(self.thread_options.unpark_hook(), context);
  }

  fn release_scope(&self, scope_ref: ScopeRef, cell: &ScopeCell) {
    let retired = {
      let mut state = self.lock();
      let Some(slot) = state.scopes.get_mut(scope_ref.index) else {
        return;
      };
      if slot.generation != scope_ref.generation
        || !slot
          .scope
          .as_ref()
          .is_some_and(|current| std::ptr::eq(Arc::as_ptr(current), cell))
        || !cell.protocol.can_reclaim()
      {
        return;
      }
      cell.protocol.mark_reclaimed();
      slot.scope.take()
    };
    drop(retired);
  }

  pub(super) fn new_scope(
    self: &Arc<Self>,
    max_active_polls: usize,
    resources: Option<ResourceScope>,
  ) -> Result<OwnedTaskScope, AsyncError> {
    if max_active_polls == 0 {
      return Err(AsyncError::InvalidConfig);
    }
    let (index, generation, root_cell, max_tasks) = {
      let state = self.lock();
      if state.closed {
        return Err(AsyncError::Closed);
      }
      let Some(index) = state.scopes.iter().position(|slot| slot.scope.is_none()) else {
        return Err(AsyncError::TooManyScopes);
      };
      let Some(generation) = state.scopes[index].generation.checked_add(1) else {
        return Err(AsyncError::TooManyScopes);
      };
      let Some(root_cell) = state
        .scopes
        .first()
        .and_then(|slot| slot.scope.as_ref())
        .cloned()
      else {
        return Err(AsyncError::Closed);
      };
      (index, generation, root_cell, self.distributed.slots_len())
    };
    let root_resources = root_cell.resources.clone();
    let root_tenant = root_cell.tenant.clone();
    let (resources, task_waiters, root_waiters) = match root_tenant {
      Some(root_tenant) => {
        let resources = match resources {
          Some(resources) => {
            let Some(tenant) = resources.tenant_domain() else {
              return Err(AsyncError::ResourceDomain(DomainError::Invalid));
            };
            if !root_tenant.same_domain(tenant) {
              return Err(AsyncError::ResourceDomain(DomainError::Invalid));
            }
            tenant
              .validate_cpu_execution()
              .map_err(AsyncError::ResourceDomain)?;
            Some(resources)
          }
          None => root_resources,
        };
        (
          resources,
          root_cell.task_waiters.clone(),
          root_cell.root_waiters.clone(),
        )
      }
      None => (resources, None, None),
    };
    let tenant = resources.as_ref().and_then(ResourceScope::tenant_domain);
    let makes_wait_pools = root_cell.tenant.is_none() && tenant.is_some();
    let scope_bytes = std::mem::size_of::<ScopeCell>();
    let control =
      ControlCharge::try_new(tenant, scope_bytes).map_err(AsyncError::ResourceDomain)?;
    let (task_waiters, root_waiters) = if makes_wait_pools {
      let tenant = tenant.ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
      tenant
        .validate_cpu_execution()
        .map_err(AsyncError::ResourceDomain)?;
      let task_waiters = tenant
        .reserve_waiters(max_tasks)
        .map_err(AsyncError::ResourceDomain)?;
      let root_waiters = tenant
        .reserve_waiters(self.workers)
        .map_err(AsyncError::ResourceDomain)?;
      (Some(task_waiters), Some(root_waiters))
    } else {
      (task_waiters, root_waiters)
    };
    let scope_ref = ScopeRef { index, generation };
    let cell = Arc::new(ScopeCell::new(
      Some(scope_ref),
      Some(Arc::downgrade(self)),
      (max_active_polls, self.workers + self.max_handoffs),
      resources,
      task_waiters,
      root_waiters,
      Some(control),
    ));
    let mut state = self.lock();
    if state.closed {
      drop(state);
      drop(cell);
      return Err(AsyncError::Closed);
    }
    if state.scopes[index].scope.is_some()
      || state.scopes[index].generation.checked_add(1) != Some(generation)
    {
      drop(state);
      drop(cell);
      return Err(AsyncError::TooManyScopes);
    }
    state.scopes[index].generation = generation;
    state.scopes[index].scope = Some(Arc::clone(&cell));
    Ok(OwnedTaskScope {
      shared: Arc::clone(self),
      scope: scope_ref,
      cell,
      closed: false,
    })
  }

  pub(super) fn default_scope_poll_limit(&self) -> usize {
    self.workers
  }

  pub(super) fn root_resources(&self) -> Option<ResourceScope> {
    self
      .lock()
      .scopes
      .first()
      .and_then(|slot| slot.scope.as_ref())
      .and_then(|scope| scope.resources.clone())
  }

  pub(super) fn context_tenant(
    &self,
    scope_ref: ScopeRef,
    scope_owner: Option<&Arc<ScopeCell>>,
    resources: Option<&ResourceScope>,
  ) -> Option<TenantDomain> {
    let scope_tenant = scope_owner
      .and_then(|scope| scope.tenant.clone())
      .or_else(|| {
        let state = self.lock();
        get_scope(&state, scope_ref).and_then(|scope| scope.tenant.clone())
      });
    scope_tenant.or_else(|| resources.and_then(ResourceScope::tenant_domain).cloned())
  }

  pub(super) fn reserve_root_control(
    &self,
    scope_ref: ScopeRef,
    resources: Option<&ResourceScope>,
    frame_bytes: usize,
  ) -> Result<ControlCharge, AsyncError> {
    let default_tenant = {
      let state = self.lock();
      let Some(scope) = get_scope(&state, scope_ref) else {
        return Err(AsyncError::Closed);
      };
      scope.tenant.clone()
    };
    let tenant = resources
      .and_then(ResourceScope::tenant_domain)
      .cloned()
      .or(default_tenant);
    let bytes = frame_bytes
      .checked_add(std::mem::size_of::<RootAdmission>())
      .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
    ControlCharge::try_new(tenant.as_ref(), bytes).map_err(AsyncError::ResourceDomain)
  }

  pub(super) fn root_admission(
    &self,
    scope_ref: ScopeRef,
    resources: Option<&ResourceScope>,
  ) -> Result<RootAdmission, AsyncError> {
    let (default_tenant, root_waiters) = {
      let state = self.lock();
      let Some(scope) = get_scope(&state, scope_ref) else {
        return Err(AsyncError::Closed);
      };
      (scope.tenant.clone(), scope.root_waiters.clone())
    };
    let tenant = resources
      .and_then(ResourceScope::tenant_domain)
      .cloned()
      .or(default_tenant);
    let Some(tenant) = tenant else {
      return Ok(RootAdmission {
        tenant: None,
        waiter: None,
        _task_admission: None,
      });
    };
    tenant
      .validate_cpu_execution()
      .map_err(AsyncError::ResourceDomain)?;
    let waiter = root_waiters
      .ok_or(DomainError::WaitersFull)
      .and_then(|pool| pool.try_lease())
      .map_err(AsyncError::ResourceDomain)?;
    let task_admission = tenant
      .try_acquire(DomainResources::ZERO.with(DomainResource::Tasks, 1))
      .map_err(AsyncError::ResourceDomain)?;
    Ok(RootAdmission {
      tenant: Some(tenant),
      waiter: Some(waiter),
      _task_admission: Some(task_admission),
    })
  }

  fn scope_snapshot(&self, scope_ref: ScopeRef) -> Option<super::AsyncScopeSnapshot> {
    let state = self.lock();
    let slot = state.scopes.get(scope_ref.index)?;
    if slot.generation != scope_ref.generation {
      return None;
    }
    let cell = Arc::clone(slot.scope.as_ref()?);
    drop(state);
    Some(distributed::scope_snapshot(&cell))
  }

  pub(super) fn spawn<F>(
    self: &Arc<Self>,
    scope: ScopeRef,
    future: F,
  ) -> Result<AsyncJob<F::Output>, AsyncSpawnError<F>>
  where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
  {
    self.distributed.spawn(self, scope, future)
  }

  pub(super) fn close(&self, cancel: bool) {
    self.distributed.close(self, cancel);
  }

  fn request_scope_close(&self, scope: ScopeRef) {
    self.distributed.request_scope_close(self, scope);
  }

  #[cfg(test)]
  pub(super) fn wake(&self, task_ref: TaskRef) {
    self.distributed.wake(self, task_ref);
  }

  /// The task waker: one RMW on the task's word, and a queue insertion only
  /// when that RMW found the task idle. No slot mutex. A wake that won the
  /// entry after the runtime was dropped has nothing left to queue.
  pub(super) fn wake_task(shared: &Weak<Self>, word: &TaskWord, task_ref: TaskRef) {
    if word.notify() == PollNotify::Enqueue
      && let Some(shared) = shared.upgrade()
    {
      shared.distributed.enqueue_woken(&shared, task_ref);
    }
  }

  pub(super) fn abort(&self, task_ref: TaskRef) {
    self.distributed.abort(self, task_ref);
  }

  pub(super) fn handoffs_enabled(&self) -> bool {
    self.max_handoffs != 0
  }

  /// Converts the caller's turn into a handoff loan, or returns the turn
  /// unchanged when every slot is loaned.
  pub(super) fn hand_off(&self, turn: DispatchTurn) -> Result<HandoffLoan, DispatchTurn> {
    self.distributed.hand_off(turn)
  }

  /// Waits, with priority over new turns, until the loan's thread holds a
  /// dispatcher permit again. Admission closure does not prevent this.
  pub(super) fn restore(&self, loan: HandoffLoan, context: AsyncThreadContext) -> DispatchTurn {
    self.distributed.restore(self, loan, context)
  }

  /// Checks the coordinator bounds and returns its turn, loan, restoration
  /// and helper counts.
  #[cfg(all(test, not(loom)))]
  pub(super) fn turn_counts(&self) -> (usize, usize, usize, usize) {
    self.distributed.turn_counts()
  }

  /// Releases the permit of a thread that unwound out of a turn.
  pub(super) fn abandon_turn(&self, turn: DispatchTurn) {
    self.distributed.abandon_turn(self, turn);
  }
}

/// An owned scope admits only owned `Send + 'static` futures. Dropping it
/// requests cancellation without waiting; workers perform future cleanup.
pub struct OwnedTaskScope {
  shared: Arc<Shared>,
  scope: ScopeRef,
  cell: Arc<ScopeCell>,
  closed: bool,
}

impl OwnedTaskScope {
  /// A clonable handle whose tasks belong to this scope.
  #[must_use]
  pub fn handle(&self) -> super::AsyncHandle {
    super::AsyncHandle {
      shared: Arc::clone(&self.shared),
      scope: self.scope,
      resources: self.cell.resources.clone(),
      _scope_owner: Some(Arc::clone(&self.cell)),
    }
  }

  /// Admits a task to this scope.
  pub fn spawn<F>(&self, future: F) -> Result<AsyncJob<F::Output>, AsyncSpawnError<F>>
  where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
  {
    self.shared.spawn(self.scope, future)
  }

  /// Returns task and active-poll counts for this scope. The task count may
  /// change concurrently. Poll counts use the scope quota lock for binding
  /// limits and a relaxed diagnostic count otherwise.
  #[must_use]
  pub fn snapshot(&self) -> super::AsyncScopeSnapshot {
    self
      .shared
      .scope_snapshot(self.scope)
      .unwrap_or(super::AsyncScopeSnapshot {
        active_tasks: self.cell.protocol.active(),
        active_polls: 0,
        max_active_polls: self.cell.max_active_polls,
      })
  }

  /// Requests cancellation and returns a future that resolves after every
  /// task and its future destructor has completed.
  pub fn close(mut self) -> ScopeClose {
    self.closed = true;
    self.shared.request_scope_close(self.scope);
    ScopeClose {
      cell: Arc::clone(&self.cell),
    }
  }
}

impl Drop for OwnedTaskScope {
  fn drop(&mut self) {
    if !self.closed {
      self.shared.request_scope_close(self.scope);
    }
  }
}

/// Completes once scope cancellation cleanup has finished.
pub struct ScopeClose {
  cell: Arc<ScopeCell>,
}

impl Future for ScopeClose {
  type Output = ();

  fn poll(
    self: std::pin::Pin<&mut Self>,
    cx: &mut std::task::Context<'_>,
  ) -> std::task::Poll<Self::Output> {
    if self.cell.protocol.is_ready() {
      return std::task::Poll::Ready(());
    }
    let replacement = cx.waker().clone();
    let mut slot = self.cell.lock_completion();
    if self.cell.protocol.is_ready() {
      drop(slot);
      return std::task::Poll::Ready(());
    }
    let old = slot.replace(replacement);
    drop(slot);
    drop(old);
    std::task::Poll::Pending
  }
}

impl Drop for ScopeClose {
  fn drop(&mut self) {
    let old = self.cell.lock_completion().take();
    drop(old);
  }
}

fn get_scope(state: &State, scope: ScopeRef) -> Option<&Arc<ScopeCell>> {
  state
    .scopes
    .get(scope.index)
    .filter(|slot| slot.generation == scope.generation)
    .and_then(|slot| slot.scope.as_ref())
}

/// Adds an admitted task to its scope's ready list at most once.
/// A dispatched turn: the slot's owner of the task, lent to the turn
/// without a reference-count update, ends with the turn.
enum Selected {
  Poll(TaskRef, Lease<dyn ErasedTask>, PollPermit),
  Cancel(TaskRef, Lease<dyn ErasedTask>),
}

/// Releases one scope's active-poll reservation on every exit path before
/// terminal future/output cleanup can run. A CPU ticket held for the poll is
/// passed beside the permit, so the common unbounded poll moves only this
/// small value.
pub(super) struct PollPermit {
  release: PermitRelease,
}

enum PermitRelease {
  Scope {
    shared: Weak<Shared>,
    cell: Arc<ScopeCell>,
  },
  Counted {
    cell: Arc<ScopeCell>,
  },
  Free,
}

pub(super) struct RootAdmission {
  pub(super) tenant: Option<TenantDomain>,
  pub(super) waiter: Option<DomainWaiter>,
  _task_admission: Option<DomainReservation>,
}

impl Drop for PollPermit {
  // The root scope's free permit drops inline.
  #[inline]
  fn drop(&mut self) {
    if !matches!(self.release, PermitRelease::Free) {
      self.release_slow();
    }
  }
}

impl PollPermit {
  #[cold]
  fn release_slow(&mut self) {
    match &self.release {
      PermitRelease::Scope { shared, cell } => {
        if let Some(shared) = shared.upgrade() {
          shared.distributed.release_permit(&shared, cell);
        }
      }
      PermitRelease::Counted { cell } => {
        cell.active_stat.fetch_sub(1, Ordering::Relaxed);
      }
      PermitRelease::Free => {}
    }
  }
}

fn executor_thread<R>(
  shared: &Arc<Shared>,
  context: AsyncThreadContext,
  context_control: ControlCharge,
  run: impl FnOnce() -> R,
) -> R {
  let shard = context.physical_index;
  WORKER_RUNTIME.set(shared.id);
  cache::set_shard(shard);
  let _worker_context = super::entry::WorkerContextGuard::enter();
  let worker_handle = super::AsyncHandle {
    shared: Arc::clone(shared),
    scope: ScopeRef {
      index: 0,
      generation: 1,
    },
    resources: shared.root_resources(),
    _scope_owner: None,
  };
  let _runtime_context =
    super::entry::EnterGuard::enter_with_control(&worker_handle, context_control);
  let _dispatcher = handoff::DispatcherGuard::install(shared, context);
  shared.thread_started(context);
  struct StopGuard<'a> {
    shared: &'a Shared,
    context: AsyncThreadContext,
  }
  impl Drop for StopGuard<'_> {
    fn drop(&mut self) {
      handoff::pause_busy();
      self.shared.thread_stopped(self.context);
    }
  }
  let _stop = StopGuard { shared, context };
  run()
}

pub(super) fn worker(
  shared: Arc<Shared>,
  context: AsyncThreadContext,
  context_control: ControlCharge,
) {
  executor_thread(&shared, context, context_control, || {
    shared.distributed.run_seat(&shared, context);
    cache::flush();
  });
}

/// A prestarted handoff helper with its own shard hint. It parks until a
/// handoff loan leaves fewer dispatching threads than workers, dispatches
/// turns while it is needed, and retires only between turns.
pub(super) fn helper(
  shared: Arc<Shared>,
  context: AsyncThreadContext,
  context_control: ControlCharge,
) {
  executor_thread(&shared, context, context_control, || {
    shared.distributed.helper(&shared, context);
    cache::flush();
  });
}

pub(super) fn is_worker(shared: &Shared) -> bool {
  WORKER_RUNTIME.with(|id| id.get() == shared.id)
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::super::{AsyncJoinError, AsyncRuntime, AsyncRuntimeOptions, AsyncShutdown, yield_now};
  use super::*;
  use crate::runtime::managed::{ResourceLimits, ResourceScope};
  use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};
  use std::future::Future;
  use std::pin::Pin;
  use std::sync::atomic::AtomicBool;
  use std::sync::mpsc;
  use std::task::Poll;
  use std::time::{Duration, Instant};

  fn wait_for_scheduler(predicate: impl Fn() -> bool, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !predicate() {
      assert!(Instant::now() < deadline, "timed out waiting for {message}");
      std::thread::yield_now();
    }
  }

  fn wait_for_parked_workers(shared: &Shared) {
    wait_for_scheduler(
      || {
        shared
          .metrics
          .snapshot()
          .threads
          .iter()
          .all(|thread| thread.parks > thread.unparks)
      },
      "every worker to park",
    );
  }

  fn finish_job<T>(mut job: AsyncJob<T>) -> Result<T, AsyncJoinError> {
    wait_for_scheduler(|| job.is_finished(), "task completion");
    match Pin::new(&mut job).poll(&mut Context::from_waker(Waker::noop())) {
      Poll::Ready(result) => result,
      Poll::Pending => panic!("finished job was still pending"),
    }
  }

  fn shutdown_with_deadline(runtime: AsyncRuntime, mode: AsyncShutdown) {
    let (sender, receiver) = mpsc::channel();
    let thread = std::thread::spawn(move || {
      let _ = sender.send(runtime.shutdown(mode));
    });
    receiver
      .recv_timeout(Duration::from_secs(30))
      .unwrap_or_else(|_| panic!("shutdown timed out"))
      .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
    thread
      .join()
      .unwrap_or_else(|_| panic!("shutdown thread panicked"));
  }

  async fn wait_for_external_wake(ready: Arc<AtomicBool>, registered: mpsc::Sender<Waker>) {
    let mut registered = Some(registered);
    std::future::poll_fn(move |context| {
      if ready.load(Ordering::Acquire) {
        Poll::Ready(())
      } else {
        if let Some(sender) = registered.take() {
          sender.send(context.waker().clone()).unwrap();
        }
        Poll::Pending
      }
    })
    .await;
  }

  /// A regression guard: a self-waking task keeps its only worker
  /// dispatching. It does not count condvar notifications.
  #[test]
  fn yielding_on_one_worker_does_not_park_per_poll() {
    const YIELDS: usize = 16_384;
    let parks = Arc::new(AtomicUsize::new(0));
    let unparks = Arc::new(AtomicUsize::new(0));
    let options = AsyncThreadOptions::new()
      .on_thread_park({
        let parks = Arc::clone(&parks);
        move |_| {
          parks.fetch_add(1, Ordering::Relaxed);
        }
      })
      .on_thread_unpark({
        let unparks = Arc::clone(&unparks);
        move |_| {
          unparks.fetch_add(1, Ordering::Relaxed);
        }
      });
    let runtime = AsyncRuntime::new_with_options(
      AsyncConfig {
        workers: 1,
        max_outstanding: 1,
        max_scopes: 1,
      },
      AsyncRuntimeOptions::new().thread_options(options),
    )
    .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
    wait_for_parked_workers(&runtime.shared);
    let polls = Arc::new(AtomicUsize::new(0));
    let task_polls = Arc::clone(&polls);
    let job = runtime
      .handle()
      .spawn(std::future::poll_fn(move |context| {
        if task_polls.fetch_add(1, Ordering::Relaxed) < YIELDS {
          context.waker().wake_by_ref();
          Poll::Pending
        } else {
          Poll::Ready(())
        }
      }))
      .unwrap_or_else(|error| panic!("spawn failed: {error}"));
    finish_job(job).unwrap();
    wait_for_parked_workers(&runtime.shared);
    assert_eq!(polls.load(Ordering::Relaxed), YIELDS + 1);
    shutdown_with_deadline(runtime, AsyncShutdown::Drain);
    // Allow a few spurious waits, while rejecting park cycles proportional to polls.
    assert!(parks.load(Ordering::Relaxed) < 16);
    assert_eq!(
      parks.load(Ordering::Relaxed),
      unparks.load(Ordering::Relaxed)
    );
  }

  #[test]
  fn many_ready_tasks_and_external_wakes_make_progress() {
    const TASKS: usize = 2048;
    const EXTERNAL_TASKS: usize = 32;
    let runtime = AsyncRuntime::new(AsyncConfig {
      workers: 4,
      max_outstanding: TASKS + EXTERNAL_TASKS,
      max_scopes: 1,
    })
    .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
    let start = Arc::new(AtomicBool::new(false));
    let external_ready = Arc::new(AtomicBool::new(false));
    let (registered, registrations) = mpsc::channel();
    let (external_registered, external_registrations) = mpsc::channel();
    let polls = Arc::new(AtomicUsize::new(0));
    let mut jobs = Vec::new();
    for _ in 0..TASKS {
      let start = Arc::clone(&start);
      let registered = registered.clone();
      let polls = Arc::clone(&polls);
      jobs.push(
        runtime
          .handle()
          .spawn(async move {
            wait_for_external_wake(start, registered).await;
            for _ in 0..8 {
              polls.fetch_add(1, Ordering::Relaxed);
              yield_now().await;
            }
          })
          .unwrap_or_else(|error| panic!("spawn failed: {error}")),
      );
    }
    let mut external_jobs = Vec::new();
    for _ in 0..EXTERNAL_TASKS {
      external_jobs.push(
        runtime
          .handle()
          .spawn(wait_for_external_wake(
            Arc::clone(&external_ready),
            external_registered.clone(),
          ))
          .unwrap_or_else(|error| panic!("external spawn failed: {error}")),
      );
    }
    let wakers: Vec<_> = (0..TASKS)
      .map(|_| registrations.recv_timeout(Duration::from_secs(30)).unwrap())
      .collect();
    let external_wakers: Vec<_> = (0..EXTERNAL_TASKS)
      .map(|_| {
        external_registrations
          .recv_timeout(Duration::from_secs(30))
          .unwrap()
      })
      .collect();
    wait_for_parked_workers(&runtime.shared);
    start.store(true, Ordering::Release);
    for waker in wakers {
      waker.wake();
    }
    for job in jobs {
      finish_job(job).unwrap();
    }
    assert_eq!(polls.load(Ordering::Relaxed), TASKS * 8);
    wait_for_parked_workers(&runtime.shared);
    let external = std::thread::spawn(move || {
      // Only creates a longer park opportunity; registration and parking are observed above.
      std::thread::sleep(Duration::from_millis(10));
      external_ready.store(true, Ordering::Release);
      for waker in external_wakers {
        waker.wake();
      }
    });
    for job in external_jobs {
      finish_job(job).unwrap();
    }
    external.join().unwrap();
    shutdown_with_deadline(runtime, AsyncShutdown::Drain);
  }

  #[test]
  fn parked_workers_finish_cancellation_and_graceful_shutdown() {
    for mode in [AsyncShutdown::CancelPending, AsyncShutdown::Drain] {
      let runtime = AsyncRuntime::new(AsyncConfig {
        workers: 4,
        max_outstanding: 16,
        max_scopes: 1,
      })
      .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
      let ready = Arc::new(AtomicBool::new(false));
      let (registered, registrations) = mpsc::channel();
      let jobs: Vec<_> = (0..16)
        .map(|_| {
          runtime
            .handle()
            .spawn(wait_for_external_wake(
              Arc::clone(&ready),
              registered.clone(),
            ))
            .unwrap_or_else(|error| panic!("spawn failed: {error}"))
        })
        .collect();
      let wakers: Vec<_> = (0..16)
        .map(|_| registrations.recv_timeout(Duration::from_secs(30)).unwrap())
        .collect();
      wait_for_parked_workers(&runtime.shared);
      let shared = Arc::clone(&runtime.shared);
      let external = std::thread::spawn(move || {
        wait_for_scheduler(|| shared.lock().closed, "runtime closure");
        if mode == AsyncShutdown::Drain {
          ready.store(true, Ordering::Release);
          for waker in wakers {
            waker.wake();
          }
        }
      });
      shutdown_with_deadline(runtime, mode);
      external.join().unwrap();
      for job in jobs {
        match mode {
          AsyncShutdown::CancelPending => {
            assert!(matches!(finish_job(job), Err(AsyncJoinError::Cancelled)))
          }
          AsyncShutdown::Drain => finish_job(job).unwrap(),
        }
      }
    }
  }

  #[test]
  fn task_allocation_constructors_cover_spawn_cached_waker_and_completion() {
    let runtime = AsyncRuntime::new(AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 1,
    })
    .unwrap();
    let before = super::super::allocation_tests::count();
    let task_ref = TaskRef {
      index: 0,
      generation: 1,
    };
    let admission = Task::<std::future::Ready<usize>>::reserve_domain_admission(None).unwrap();
    let (task, job) = Task::create(
      std::future::ready(7usize),
      super::super::identity::TaskId::test_sentinel(),
      None,
      admission,
      Arc::downgrade(&runtime.shared),
      task_ref,
    );
    let abort = job.abort_handle();
    let waker = task.clone().task_waker();
    let cached = task.clone().task_waker();
    assert!(waker.will_wake(&cached));
    drop(cached);
    let permit = PollPermit {
      release: PermitRelease::Free,
    };
    assert!(matches!(
      task
        .as_ref()
        .poll(&mut Context::from_waker(&waker), permit, &mut None),
      (PollResult::Ready, None)
    ));
    task.publish();
    drop(task);
    assert!(job.is_finished());
    drop(job);
    assert!(abort.is_finished());
    drop(abort);
    drop(waker);
    assert_eq!(super::super::allocation_tests::count() - before, 1);
    runtime.shutdown(AsyncShutdown::Drain).unwrap();
  }

  /// Checks that terminal cleanup breaks the typed Arc waker cache cycle,
  /// including a cache recreated after terminal cleanup.
  fn assert_terminal_path_has_no_waker_cycle<F>(
    future: F,
    finish: impl FnOnce(Pin<&dyn ErasedTask>),
  ) where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
  {
    let admission = Task::<F>::reserve_domain_admission(None).unwrap();
    let (task, job) = Task::create(
      future,
      super::super::identity::TaskId::test_sentinel(),
      None,
      admission,
      Weak::new(),
      TaskRef::test_sentinel(),
    );
    let before = strong_count(&task);
    let waker = task.clone().task_waker();
    assert_eq!(strong_count(&task), before + 1);
    let cached = task.clone().task_waker();
    assert!(waker.will_wake(&cached));
    drop(cached);
    finish(task.as_ref());
    assert_eq!(strong_count(&task), before + 1);
    drop(waker);
    assert_eq!(strong_count(&task), before);
    // A dispatch after cleanup finds no future; its waker has no cached owner.
    let recreated = task.clone().task_waker();
    assert!(matches!(
      task.as_ref().poll(
        &mut Context::from_waker(&recreated),
        unscheduled_permit(),
        &mut None
      ),
      (PollResult::Ready, None)
    ));
    assert_eq!(strong_count(&task), before + 1);
    drop(recreated);
    drop(job);
    // Only the local handle is left, so the last drop frees the allocation.
    assert_eq!(strong_count(&task), 1);
    drop(task);
  }

  /// The owners of an erased task allocation: handles, wakers and `task`.
  fn strong_count(task: &Pin<Arc<dyn ErasedTask>>) -> usize {
    task.clone().strong_count()
  }

  fn unscheduled_permit() -> PollPermit {
    PollPermit {
      release: PermitRelease::Free,
    }
  }

  #[test]
  fn completed_task_has_no_waker_cycle() {
    assert_terminal_path_has_no_waker_cycle(std::future::ready(()), |task| {
      assert!(matches!(
        task.poll(
          &mut Context::from_waker(Waker::noop()),
          unscheduled_permit(),
          &mut None
        ),
        (PollResult::Ready, None)
      ));
    });
  }

  #[test]
  fn cancel_panic_and_resource_failure_have_no_waker_cycle() {
    assert_terminal_path_has_no_waker_cycle(std::future::pending::<()>(), |task| task.cancel());
    assert_terminal_path_has_no_waker_cycle(std::future::pending::<()>(), |task| {
      task.fail_resource(DomainError::WaitersFull);
    });
    assert_terminal_path_has_no_waker_cycle(
      std::future::poll_fn(|_| -> std::task::Poll<()> { panic!("contained poll panic") }),
      |task| {
        assert!(matches!(
          task.poll(
            &mut Context::from_waker(Waker::noop()),
            unscheduled_permit(),
            &mut None
          ),
          (PollResult::Ready, None)
        ));
      },
    );
  }

  #[test]
  fn scope_close_stays_pending_until_zero_count_slot_reclamation() {
    let (shared, _) = Shared::new(
      AsyncConfig {
        workers: 1,
        max_outstanding: 1,
        max_scopes: 2,
      },
      0,
      None,
      super::super::ControlledThreadOptions::unbounded(AsyncThreadOptions::default()),
      RuntimeMetrics::try_new(
        1,
        [AsyncThreadContext {
          role: super::super::thread_options::AsyncThreadRole::Worker,
          index: 0,
          physical_index: 0,
        }],
        1,
        None,
      )
      .unwrap_or_else(|error| panic!("metrics allocation failed: {error:?}")),
      super::super::park_spin::Policy::default(),
    )
    .unwrap_or_else(|error| panic!("shared construction failed: {error}"));
    let scope = shared
      .new_scope(2, None)
      .unwrap_or_else(|error| panic!("scope construction failed: {error}"));
    let old_reference = scope.scope;
    let cell = Arc::clone(&scope.cell);
    // Force the production interleaving after the last decrement but before
    // its generation-checked table retirement.
    cell.protocol.add_task();
    let mut close = Box::pin(scope.close());
    assert_eq!(cell.protocol.active(), 1);
    assert!(!cell.protocol.is_reclaimed());
    assert!(cell.protocol.complete_one());

    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
      close.as_mut().poll(&mut context),
      std::task::Poll::Pending
    ));
    shared.release_scope(old_reference, &cell);
    assert!(cell.protocol.is_reclaimed());
    assert!(matches!(
      close.as_mut().poll(&mut context),
      std::task::Poll::Ready(())
    ));

    let replacement = shared
      .new_scope(1, None)
      .unwrap_or_else(|error| panic!("reclaimed scope slot unavailable: {error}"));
    assert_eq!(replacement.scope.index, old_reference.index);
    assert!(replacement.scope.generation > old_reference.generation);
    assert_eq!(replacement.snapshot().active_polls, 0);
    assert_eq!(replacement.snapshot().max_active_polls, 1);
  }

  #[test]
  fn closed_scope_retains_inherited_waiter_pools_after_shared_drop_exactly() {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 2)
      .with(DomainResource::Tasks, 8)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 8).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let resources = ResourceScope::from_tenant(ResourceLimits::default(), tenant.clone());
    let global_base = domain.snapshot().used.get(DomainResource::Control);
    let tenant_base = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    let metrics = RuntimeMetrics::try_new(
      1,
      [AsyncThreadContext {
        role: super::super::thread_options::AsyncThreadRole::Worker,
        index: 0,
        physical_index: 0,
      }],
      1,
      Some(&tenant),
    )
    .unwrap();
    let (shared, _) = Shared::new(
      AsyncConfig {
        workers: 1,
        max_outstanding: 2,
        max_scopes: 2,
      },
      0,
      Some(resources),
      super::super::ControlledThreadOptions::unbounded(
        super::super::thread_options::AsyncThreadOptions::default(),
      ),
      metrics,
      super::super::park_spin::Policy::default(),
    )
    .unwrap();
    let scope = shared.new_scope(1, None).unwrap();
    let scope_bytes = scope.cell._control.as_ref().unwrap().bytes();
    let pool_bytes = DomainWaitPool::control_payload_bytes();
    let close = scope.close();
    drop(shared);

    let retained = global_base + scope_bytes + 2 * pool_bytes;
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      retained
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      tenant_base + scope_bytes + 2 * pool_bytes
    );
    drop(close);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      tenant_base
    );
  }

  #[test]
  fn closed_runtime_finishes_pending_self_yields_with_a_deadline() {
    for mode in [AsyncShutdown::Drain, AsyncShutdown::CancelPending] {
      let runtime = AsyncRuntime::new(AsyncConfig {
        workers: 4,
        max_outstanding: 8,
        max_scopes: 1,
      })
      .unwrap();
      let release = Arc::new(AtomicBool::new(false));
      let mut jobs = Vec::new();
      let started = Arc::new(AtomicUsize::new(0));
      for _ in 0..8 {
        let started = Arc::clone(&started);
        let shared = Arc::clone(&runtime.shared);
        let release = Arc::clone(&release);
        let mut polls = 0;
        let mut first = true;
        jobs.push(
          runtime
            .handle()
            .spawn(std::future::poll_fn(move |cx| {
              if first {
                first = false;
                started.fetch_add(1, Ordering::Release);
              }
              // Drain must finish self-yielding tasks after admission closes.
              if release.load(Ordering::Acquire) && shared.lock().closed {
                polls += 1;
                if polls == 10 {
                  return Poll::Ready(());
                }
              }
              cx.waker().wake_by_ref();
              Poll::Pending
            }))
            .unwrap(),
        );
      }
      wait_for_scheduler(|| started.load(Ordering::Acquire) == 8, "initial polls");
      // Complete the close request before allowing normal completion so
      // CancelPending cannot race a task finishing during its slot scan.
      runtime.shared.close(mode == AsyncShutdown::CancelPending);
      release.store(true, Ordering::Release);
      shutdown_with_deadline(runtime, mode);
      for job in jobs {
        match finish_job(job) {
          Ok(()) => assert_eq!(mode, AsyncShutdown::Drain),
          Err(AsyncJoinError::Cancelled) => assert_eq!(mode, AsyncShutdown::CancelPending),
          Err(error) => panic!("unexpected join error: {error}"),
        }
      }
    }
  }
}
