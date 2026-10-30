//! Bounded async task admission and scheduling. Scheduler state is reserved
//! before workers start; the mutex protects bookkeeping only and is released
//! before polling, dropping task values, or invoking wakers. Each scope keeps
//! its queued tasks in an intrusive FIFO list threaded through the task table,
//! so queueing, selection and schedule refresh do not scan other scopes' work.

use std::collections::VecDeque;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Wake, Waker};

use super::handoff;
use super::handoff_protocol::{DispatchTurn, HandoffLoan, HelperLease, TurnCoordinator};
use super::identity;
use super::join::AsyncJob;
use super::metrics::RuntimeMetrics;
use super::protocol::{PollFinish, PollProtocol, PollQuota, ScopeProtocol};
use super::task::{DomainCpuAdmission, ErasedTask, PollResult, Task};
use super::thread_options::AsyncThreadContext;
#[cfg(test)]
use super::thread_options::AsyncThreadOptions;
use super::{AsyncConfig, AsyncError, AsyncSpawnError};
use crate::runtime::cache;
use crate::runtime::managed::ResourceScope;
use crate::runtime::resource_domain::{
  ControlCharge, DomainError, DomainIdentity, DomainReservation, DomainResource, DomainResources,
  DomainWaitPool, DomainWaiter, TenantDomain, payload_bytes,
};

thread_local! {
  static WORKER_RUNTIME: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

static NEXT_RUNTIME: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ScopeRef {
  index: usize,
  generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TaskRef {
  index: usize,
  generation: u64,
}

struct ScopeSlot {
  generation: u64,
  scope: Option<Arc<ScopeCell>>,
  ready: bool,
  quota_blocked: bool,
  quota: PollQuota,
  /// The scope's queued tasks in push order, linked through `TaskSlot`.
  ready_head: Option<usize>,
  ready_tail: Option<usize>,
  ready_len: usize,
  /// Linked tasks counted as `aborting_queued`.
  aborting: usize,
}

impl ScopeSlot {
  const fn new(generation: u64, scope: Option<Arc<ScopeCell>>, quota: PollQuota) -> Self {
    Self {
      generation,
      scope,
      ready: false,
      quota_blocked: false,
      quota,
      ready_head: None,
      ready_tail: None,
      ready_len: 0,
      aborting: 0,
    }
  }

  fn ready_empty(&self) -> bool {
    self.ready_head.is_none()
      && self.ready_tail.is_none()
      && self.ready_len == 0
      && self.aborting == 0
  }
}

/// A task is linked into its scope's ready list exactly while its
/// `PollProtocol` is queued.
struct TaskSlot {
  protocol: PollProtocol,
  task: Option<Arc<dyn ErasedTask>>,
  scope: Option<ScopeRef>,
  ready_linked: bool,
  ready_prev: Option<usize>,
  ready_next: Option<usize>,
  /// Whether this linked task is counted in its scope's `aborting`.
  ready_abort: bool,
}

impl TaskSlot {
  const fn new() -> Self {
    Self {
      protocol: PollProtocol::new(),
      task: None,
      scope: None,
      ready_linked: false,
      ready_prev: None,
      ready_next: None,
      ready_abort: false,
    }
  }
}

struct State {
  closed: bool,
  cancel_all: bool,
  tasks: Vec<TaskSlot>,
  scopes: Vec<ScopeSlot>,
  round_robin: VecDeque<ScopeRef>,
  idle: usize,
  turns: TurnCoordinator,
}

pub(super) struct Shared {
  id: u64,
  max_handoffs: usize,
  workers: usize,
  pub(super) metrics: RuntimeMetrics,
  thread_options: super::ControlledThreadOptions,
  state: Mutex<State>,
  work: Condvar,
  /// Inactive helpers and restoring threads wait here; `work` waiters are
  /// dispatchers.
  handoff: Condvar,
  /// Deterministic admission interleavings; absent from non-test builds.
  #[cfg(all(test, not(loom)))]
  spawn_admission_test_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
  _control: ControlCharge,
}

pub(super) struct ScopeCell {
  reference: Option<ScopeRef>,
  shared: Option<Weak<Shared>>,
  max_active_polls: usize,
  resources: Option<ResourceScope>,
  tenant: Option<TenantDomain>,
  task_waiters: Option<DomainWaitPool>,
  root_waiters: Option<DomainWaitPool>,
  protocol: ScopeProtocol,
  completion: Mutex<Option<Waker>>,
  _control: Option<ControlCharge>,
}

impl ScopeCell {
  fn new(
    reference: Option<ScopeRef>,
    shared: Option<Weak<Shared>>,
    max_active_polls: usize,
    resources: Option<ResourceScope>,
    task_waiters: Option<DomainWaitPool>,
    root_waiters: Option<DomainWaitPool>,
    control: Option<ControlCharge>,
  ) -> Self {
    let tenant = resources
      .as_ref()
      .and_then(ResourceScope::tenant_domain)
      .cloned();
    Self {
      reference,
      shared,
      max_active_polls,
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
  ) -> Result<(Arc<Self>, ScopeRef), AsyncError> {
    let tenant = resources.as_ref().and_then(ResourceScope::tenant_domain);
    let mut requested_control = std::mem::size_of::<Shared>();
    for bytes in [
      payload_bytes::<TaskSlot>(config.max_outstanding).map_err(AsyncError::ResourceDomain)?,
      payload_bytes::<ScopeSlot>(config.max_scopes).map_err(AsyncError::ResourceDomain)?,
      payload_bytes::<ScopeRef>(config.max_scopes).map_err(AsyncError::ResourceDomain)?,
      std::mem::size_of::<ScopeCell>(),
    ] {
      requested_control = requested_control
        .checked_add(bytes)
        .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
    }
    let mut control =
      ControlCharge::try_new(tenant, requested_control).map_err(AsyncError::ResourceDomain)?;

    let mut tasks = Vec::new();
    tasks
      .try_reserve_exact(config.max_outstanding)
      .map_err(|_| AsyncError::OutOfMemory)?;
    tasks.resize_with(config.max_outstanding, TaskSlot::new);
    let mut scopes = Vec::new();
    scopes
      .try_reserve_exact(config.max_scopes)
      .map_err(|_| AsyncError::OutOfMemory)?;
    scopes.resize_with(config.max_scopes, || {
      ScopeSlot::new(0, None, PollQuota::new(1))
    });
    let mut round_robin = VecDeque::new();
    round_robin
      .try_reserve_exact(config.max_scopes)
      .map_err(|_| AsyncError::OutOfMemory)?;
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
      config.workers,
      resources,
      task_waiters,
      root_waiters,
      None,
    ));
    scopes[0] = ScopeSlot::new(1, Some(root_scope), PollQuota::new(config.workers));
    let root = ScopeRef {
      index: 0,
      generation: 1,
    };
    let mut actual_control = std::mem::size_of::<Shared>();
    for bytes in [
      payload_bytes::<TaskSlot>(tasks.capacity()).map_err(AsyncError::ResourceDomain)?,
      payload_bytes::<ScopeSlot>(scopes.capacity()).map_err(AsyncError::ResourceDomain)?,
      payload_bytes::<ScopeRef>(round_robin.capacity()).map_err(AsyncError::ResourceDomain)?,
      std::mem::size_of::<ScopeCell>(),
    ] {
      actual_control = actual_control
        .checked_add(bytes)
        .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
    }
    control
      .try_resize(actual_control)
      .map_err(AsyncError::ResourceDomain)?;
    Ok((
      Arc::new(Self {
        id,
        max_handoffs,
        workers: config.workers,
        metrics,
        thread_options,
        state: Mutex::new(State {
          closed: false,
          cancel_all: false,
          tasks,
          scopes,
          round_robin,
          idle: 0,
          turns: TurnCoordinator::new(config.workers, max_handoffs),
        }),
        work: Condvar::new(),
        handoff: Condvar::new(),
        #[cfg(all(test, not(loom)))]
        spawn_admission_test_hook: Mutex::new(None),
        _control: control,
      }),
      root,
    ))
  }

  fn lock(&self) -> MutexGuard<'_, State> {
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
      debug_assert!(slot.ready_empty());
      slot.ready = false;
      slot.quota_blocked = false;
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
      (index, generation, root_cell, state.tasks.len())
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
      max_active_polls,
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
    debug_assert!(state.scopes[index].ready_empty());
    state.scopes[index].generation = generation;
    state.scopes[index].scope = Some(Arc::clone(&cell));
    state.scopes[index].ready = false;
    state.scopes[index].quota_blocked = false;
    state.scopes[index].quota = PollQuota::new(max_active_polls);
    Ok(OwnedTaskScope {
      shared: Arc::clone(self),
      scope: scope_ref,
      cell,
      closed: false,
    })
  }

  pub(super) fn default_scope_poll_limit(&self) -> usize {
    self.lock().scopes[0].quota.maximum()
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
    if slot.generation != scope_ref.generation || slot.scope.is_none() {
      return None;
    }
    let cell = slot.scope.as_ref()?;
    Some(super::AsyncScopeSnapshot {
      active_tasks: cell.protocol.active(),
      active_polls: slot.quota.active(),
      max_active_polls: slot.quota.maximum(),
    })
  }

  fn release_poll(&self, scope_ref: ScopeRef) {
    let notify = {
      let mut state = self.lock();
      let Some(slot) = state.scopes.get_mut(scope_ref.index) else {
        return;
      };
      if slot.generation != scope_ref.generation || slot.scope.is_none() {
        return;
      }
      let capacity_available = slot.quota.release();
      if capacity_available && slot.quota_blocked {
        refresh_scope_schedule(&mut state, scope_ref);
        true
      } else {
        false
      }
    };
    if notify {
      self.work.notify_all();
    }
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
    let scope_cell = {
      let state = self.lock();
      if state.closed {
        return Err(AsyncSpawnError::new(AsyncError::Closed, future));
      }
      let Some(scope_cell) = get_scope(&state, scope).cloned() else {
        return Err(AsyncSpawnError::new(AsyncError::Closed, future));
      };
      if scope_cell.protocol.is_closed() {
        return Err(AsyncSpawnError::new(AsyncError::Closed, future));
      }
      if !state.tasks.iter().any(|slot| {
        slot.task.is_none()
          && !slot.protocol.admitted()
          && slot.protocol.next_generation().is_some()
      }) {
        return Err(AsyncSpawnError::new(AsyncError::Full, future));
      }
      scope_cell
    };

    let tenant = scope_cell.tenant.as_ref();
    if let Some(tenant) = tenant
      && let Err(error) = tenant.validate_cpu_execution()
    {
      return Err(AsyncSpawnError::new(
        AsyncError::ResourceDomain(error),
        future,
      ));
    }
    let mut domain = match Task::<F>::reserve_domain_admission(tenant) {
      Ok(domain) => domain,
      Err(error) => {
        return Err(AsyncSpawnError::new(
          AsyncError::ResourceDomain(error),
          future,
        ));
      }
    };
    if tenant.is_some() {
      let waiter = match scope_cell
        .task_waiters
        .as_ref()
        .ok_or(DomainError::WaitersFull)
        .and_then(DomainWaitPool::try_lease)
      {
        Ok(waiter) => waiter,
        Err(error) => {
          drop(domain);
          return Err(AsyncSpawnError::new(
            AsyncError::ResourceDomain(error),
            future,
          ));
        }
      };
      domain.waiter = Some(waiter);
    }
    let Some(task_id) = identity::allocate() else {
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::TaskIdExhausted, future));
    };
    #[cfg(all(test, not(loom)))]
    // Resource reservations are complete, and no scheduler lock is held.
    self.before_spawn_admission_for_test();
    let mut state = self.lock();
    if state.closed {
      drop(state);
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::Closed, future));
    }
    let Some(current_scope) = get_scope(&state, scope) else {
      drop(state);
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::Closed, future));
    };
    if current_scope.protocol.is_closed() {
      drop(state);
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::Closed, future));
    }
    if !Arc::ptr_eq(current_scope, &scope_cell) {
      drop(state);
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::Full, future));
    }
    let Some((index, generation)) = state.tasks.iter().enumerate().find_map(|(index, slot)| {
      if slot.task.is_none() && !slot.protocol.admitted() {
        slot
          .protocol
          .next_generation()
          .map(|generation| (index, generation))
      } else {
        None
      }
    }) else {
      drop(state);
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::Full, future));
    };
    let task_ref = TaskRef { index, generation };
    let (task, job) = Task::create(
      future,
      task_id,
      scope_cell.resources.clone(),
      domain,
      Arc::downgrade(self),
      task_ref,
    );
    state.tasks[index].protocol.admit(generation);
    state.tasks[index].scope = Some(scope);
    state.tasks[index].task = Some(task);
    scope_cell.protocol.add_task();
    self
      .metrics
      .inner()
      .alive_tasks
      .fetch_add(1, Ordering::Relaxed);
    schedule(&mut state, task_ref, &self.metrics.inner().queue_depth);
    drop(state);
    self.work.notify_one();
    Ok(job)
  }

  pub(super) fn close(&self, cancel: bool) {
    let mut state = self.lock();
    state.closed = true;
    state.cancel_all |= cancel;
    if cancel {
      for index in 0..state.tasks.len() {
        if state.tasks[index].task.is_some() {
          let inserted = state.tasks[index].protocol.abort();
          let task_ref = TaskRef {
            index,
            generation: state.tasks[index].protocol.generation(),
          };
          if inserted {
            push_ready(&mut state, task_ref, &self.metrics.inner().queue_depth);
          }
          sync_ready_abort(&mut state, index);
          refresh_task_scope(&mut state, task_ref);
        }
      }
      for scope in &mut state.scopes {
        if let Some(cell) = &scope.scope {
          cell.protocol.close();
        }
      }
    }
    drop(state);
    self.work.notify_all();
    self.handoff.notify_all();
  }

  fn request_scope_close(&self, scope: ScopeRef) {
    let mut state = self.lock();
    if let Some(cell) = get_scope(&state, scope) {
      cell.protocol.close();
    }
    for index in 0..state.tasks.len() {
      if state.tasks[index].task.is_some() && state.tasks[index].scope == Some(scope) {
        let inserted = state.tasks[index].protocol.abort();
        let task = TaskRef {
          index,
          generation: state.tasks[index].protocol.generation(),
        };
        if inserted {
          push_ready(&mut state, task, &self.metrics.inner().queue_depth);
        }
        sync_ready_abort(&mut state, index);
        refresh_task_scope(&mut state, task);
      }
    }
    let retired = if scope.index != 0
      && let Some(slot) = state.scopes.get_mut(scope.index)
      && slot.generation == scope.generation
      && slot
        .scope
        .as_ref()
        .is_some_and(|cell| cell.protocol.can_reclaim())
    {
      debug_assert!(slot.ready_empty());
      slot.ready = false;
      slot.quota_blocked = false;
      if let Some(cell) = &slot.scope {
        cell.protocol.mark_reclaimed();
      }
      slot.scope.take()
    } else {
      None
    };
    drop(state);
    drop(retired);
    self.work.notify_all();
  }

  fn wake(&self, task_ref: TaskRef) {
    let mut state = self.lock();
    let Some(task) = state.tasks.get_mut(task_ref.index) else {
      return;
    };
    if !task.protocol.matches(task_ref.generation) || task.task.is_none() {
      return;
    }
    let inserted = task.protocol.wake();
    if inserted {
      push_ready(&mut state, task_ref, &self.metrics.inner().queue_depth);
    }
    drop(state);
    if inserted {
      self.work.notify_one();
    }
  }

  pub(super) fn abort(&self, task_ref: TaskRef) {
    let mut state = self.lock();
    let Some(slot) = state.tasks.get_mut(task_ref.index) else {
      return;
    };
    if !slot.protocol.matches(task_ref.generation) || slot.task.is_none() {
      return;
    }
    let inserted = slot.protocol.abort();
    if inserted {
      push_ready(&mut state, task_ref, &self.metrics.inner().queue_depth);
    }
    sync_ready_abort(&mut state, task_ref.index);
    refresh_task_scope(&mut state, task_ref);
    drop(state);
    self.work.notify_all();
  }

  pub(super) fn handoffs_enabled(&self) -> bool {
    self.max_handoffs != 0
  }

  /// Converts the caller's turn into a handoff loan, or returns the turn
  /// unchanged when every slot is loaned.
  pub(super) fn hand_off(&self, turn: DispatchTurn) -> Result<HandoffLoan, DispatchTurn> {
    let loan = self.lock().turns.try_hand_off(turn)?;
    // The released permit may serve a helper, a dispatcher or a restorer.
    self.handoff.notify_all();
    self.work.notify_all();
    Ok(loan)
  }

  /// Waits, with priority over new turns, until the loan's thread holds a
  /// dispatcher permit again. Admission closure does not prevent this.
  pub(super) fn restore(&self, loan: HandoffLoan, context: AsyncThreadContext) -> DispatchTurn {
    let mut state = self.lock();
    let mut ticket = state.turns.begin_restore(loan);
    let mut flushed = false;
    loop {
      match state.turns.try_restore(ticket) {
        Ok(turn) => {
          drop(state);
          // Helpers beyond the remaining loans retire between turns.
          self.work.notify_all();
          return turn;
        }
        Err(waiting) => ticket = waiting,
      }
      if flushed {
        drop(state);
        self.thread_park_attempted(context);
        state = self.lock();
        match state.turns.try_restore(ticket) {
          Ok(turn) => {
            drop(state);
            self.thread_unpark_callback(context);
            self.work.notify_all();
            return turn;
          }
          Err(waiting) => ticket = waiting,
        }
        self.thread_parked(context);
        state = self
          .handoff
          .wait(state)
          .unwrap_or_else(PoisonError::into_inner);
        drop(state);
        self.thread_unparked(context);
        state = self.lock();
      } else {
        drop(state);
        cache::flush();
        flushed = true;
        state = self.lock();
      }
    }
  }

  /// Checks the coordinator bounds and returns its turn, loan, restoration
  /// and helper counts.
  #[cfg(all(test, not(loom)))]
  pub(super) fn turn_counts(&self) -> (usize, usize, usize, usize) {
    let state = self.lock();
    state.turns.check();
    state.turns.counts()
  }

  /// Releases the permit of a thread that unwound out of a turn.
  pub(super) fn abandon_turn(&self, turn: DispatchTurn) {
    let mut state = self.lock();
    end_turn(self, &mut state, turn);
  }
}

/// Releases one dispatcher permit and wakes whoever it unblocks: a restorer,
/// or, for the final release after close, every thread waiting to exit.
fn end_turn(shared: &Shared, state: &mut State, turn: DispatchTurn) {
  let end = state.turns.end_turn(turn);
  if end.wake_restorer {
    shared.handoff.notify_all();
  }
  if shared.handoffs_enabled() && end.quiescent && state.closed {
    shared.work.notify_all();
    shared.handoff.notify_all();
  }
}

fn admission_empty(state: &State) -> bool {
  state.closed && !state.tasks.iter().any(|slot| slot.task.is_some())
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
  /// change concurrently; the active-poll count and configured maximum are
  /// sampled together under the scheduler lock.
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

struct TaskWake {
  shared: Weak<Shared>,
  task: TaskRef,
  _control: ControlCharge,
}

impl Wake for TaskWake {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    if let Some(shared) = self.shared.upgrade() {
      shared.wake(self.task);
    }
  }
}

/// The admission-independent wake handle. It holds no task, future, or
/// result, so a retained stale waker cannot keep completed user data alive.
fn task_waker(
  shared: &Arc<Shared>,
  task: TaskRef,
  tenant: Option<&TenantDomain>,
) -> Result<Waker, DomainError> {
  let control = ControlCharge::try_new(tenant, std::mem::size_of::<TaskWake>())?;
  Ok(Waker::from(Arc::new(TaskWake {
    shared: Arc::downgrade(shared),
    task,
    _control: control,
  })))
}

fn get_scope(state: &State, scope: ScopeRef) -> Option<&Arc<ScopeCell>> {
  state
    .scopes
    .get(scope.index)
    .filter(|slot| slot.generation == scope.generation)
    .and_then(|slot| slot.scope.as_ref())
}

/// Adds an admitted task to its scope's ready list at most once.
fn schedule(state: &mut State, task_ref: TaskRef, queue_depth: &AtomicUsize) -> bool {
  let Some(slot) = state.tasks.get_mut(task_ref.index) else {
    return false;
  };
  if !slot.protocol.matches(task_ref.generation) || slot.task.is_none() || !slot.protocol.queue() {
    return false;
  }
  push_ready(state, task_ref, queue_depth);
  true
}

/// Appends a task to its scope's ready list after `PollProtocol` has reserved
/// the task's one ready position.
fn push_ready(state: &mut State, task_ref: TaskRef, queue_depth: &AtomicUsize) {
  let Some(slot) = state.tasks.get(task_ref.index) else {
    return;
  };
  let Some(scope_ref) = slot.scope else {
    return;
  };
  link_ready(state, task_ref.index, scope_ref);
  queue_depth.fetch_add(1, Ordering::Relaxed);
  refresh_scope_schedule(state, scope_ref);
}

/// Links a newly queued task at its scope's ready-list tail.
fn link_ready(state: &mut State, index: usize, scope_ref: ScopeRef) {
  let Some(scope) = state.scopes.get_mut(scope_ref.index) else {
    return;
  };
  let tail = scope.ready_tail.replace(index);
  if tail.is_none() {
    scope.ready_head = Some(index);
  }
  scope.ready_len += 1;
  let slot = &mut state.tasks[index];
  debug_assert!(!slot.ready_linked && !slot.ready_abort);
  slot.ready_linked = true;
  slot.ready_prev = tail;
  slot.ready_next = None;
  if let Some(tail) = tail {
    state.tasks[tail].ready_next = Some(index);
  }
  sync_ready_abort(state, index);
}

/// Removes a linked task from its scope's ready list before its protocol
/// leaves the queued state.
fn unlink_ready(state: &mut State, index: usize, scope_ref: ScopeRef) {
  let slot = &mut state.tasks[index];
  debug_assert!(slot.ready_linked);
  slot.ready_linked = false;
  let prev = slot.ready_prev.take();
  let next = slot.ready_next.take();
  let counted_abort = std::mem::take(&mut slot.ready_abort);
  match prev {
    Some(prev) => state.tasks[prev].ready_next = next,
    None => state.scopes[scope_ref.index].ready_head = next,
  }
  match next {
    Some(next) => state.tasks[next].ready_prev = prev,
    None => state.scopes[scope_ref.index].ready_tail = prev,
  }
  let scope = &mut state.scopes[scope_ref.index];
  scope.ready_len -= 1;
  if counted_abort {
    scope.aborting -= 1;
  }
}

/// Recounts a linked task's abort status after a protocol change. An abort
/// request can mark an already queued task without requeueing it.
fn sync_ready_abort(state: &mut State, index: usize) {
  let Some(slot) = state.tasks.get_mut(index) else {
    return;
  };
  if !slot.ready_linked {
    return;
  }
  let aborting = slot.protocol.aborting_queued();
  if aborting == slot.ready_abort {
    return;
  }
  let Some(scope_ref) = slot.scope else {
    return;
  };
  slot.ready_abort = aborting;
  let scope = &mut state.scopes[scope_ref.index];
  if aborting {
    scope.aborting += 1;
  } else {
    scope.aborting -= 1;
  }
}

/// Returns the scope's first ready task in push order that is counted as
/// aborting. Only called while the scope has aborting entries.
fn first_ready_abort(state: &State, scope_ref: ScopeRef) -> Option<usize> {
  let mut cursor = state.scopes[scope_ref.index].ready_head;
  while let Some(index) = cursor {
    let slot = &state.tasks[index];
    if slot.ready_abort {
      return Some(index);
    }
    cursor = slot.ready_next;
  }
  None
}

fn refresh_task_scope(state: &mut State, task_ref: TaskRef) {
  if let Some(scope_ref) = state
    .tasks
    .get(task_ref.index)
    .filter(|task| task.protocol.matches(task_ref.generation))
    .and_then(|task| task.scope)
  {
    refresh_scope_schedule(state, scope_ref);
  }
}

/// Ensures a scope has one RR token exactly when it has dispatchable work.
/// All callers hold the scheduler mutex, serializing this transition with
/// poll-quota release so a scope cannot lose the release-before-block race.
fn refresh_scope_schedule(state: &mut State, scope_ref: ScopeRef) {
  let Some(scope) = state.scopes.get(scope_ref.index) else {
    return;
  };
  if scope.generation != scope_ref.generation || scope.scope.is_none() {
    return;
  }
  let scope = &mut state.scopes[scope_ref.index];
  if scope.ready_len == 0 {
    scope.quota_blocked = false;
    return;
  }
  if scope.quota.active() < scope.quota.maximum() || scope.aborting > 0 {
    scope.quota_blocked = false;
    if !scope.ready {
      scope.ready = true;
      state.round_robin.push_back(scope_ref);
    }
  } else {
    scope.quota_blocked = true;
    scope.ready = false;
  }
}

enum Work {
  Poll(TaskRef, Arc<dyn ErasedTask>, PollPermit, DispatchTurn),
  Cancel(TaskRef, Arc<dyn ErasedTask>, DispatchTurn),
  Park,
  /// An activated helper is no longer needed and returns to waiting.
  Retire,
  Exit,
}

enum Selected {
  Poll(TaskRef, Arc<dyn ErasedTask>, PollPermit),
  Cancel(TaskRef, Arc<dyn ErasedTask>),
}

impl Selected {
  fn into_work(self, turn: DispatchTurn) -> Work {
    match self {
      Self::Poll(task_ref, task, permit) => Work::Poll(task_ref, task, permit, turn),
      Self::Cancel(task_ref, task) => Work::Cancel(task_ref, task, turn),
    }
  }
}

/// Releases one scope's active-poll reservation on every exit path. The task
/// drops this immediately after the user's `Future::poll` returns, before any
/// future/output cleanup can run.
pub(super) struct PollPermit {
  shared: Weak<Shared>,
  scope: ScopeRef,
  cpu_ticket: Option<DomainReservation>,
}

impl PollPermit {
  pub(super) fn cpu_domain_identity(&self) -> Option<DomainIdentity> {
    self
      .cpu_ticket
      .as_ref()
      .map(DomainReservation::domain_identity)
  }

  fn set_cpu_ticket(&mut self, ticket: DomainReservation) {
    debug_assert!(self.cpu_ticket.is_none());
    self.cpu_ticket = Some(ticket);
  }
}

pub(super) struct RootAdmission {
  pub(super) tenant: Option<TenantDomain>,
  pub(super) waiter: Option<DomainWaiter>,
  _task_admission: Option<DomainReservation>,
}

impl Drop for PollPermit {
  fn drop(&mut self) {
    if let Some(shared) = self.shared.upgrade() {
      shared.release_poll(self.scope);
    }
  }
}

/// Selects the next poll or cancellation cleanup from the scope round-robin
/// queue, or returns `None` once that queue is empty. Within a scope, the
/// first aborting task in push order wins; otherwise the ready-list head is
/// polled when the scope's quota allows.
fn dequeue(shared: &Arc<Shared>, state: &mut State) -> Option<Selected> {
  while let Some(scope_ref) = state.round_robin.pop_front() {
    // A token from a retired generation has no linked tasks.
    let Some(scope) = state.scopes.get_mut(scope_ref.index) else {
      continue;
    };
    if scope.generation != scope_ref.generation {
      continue;
    }
    scope.ready = false;
    let quota_available = scope.scope.is_some() && scope.quota.active() < scope.quota.maximum();
    let head = scope.ready_head;
    let abort = if scope.aborting > 0 {
      first_ready_abort(state, scope_ref)
    } else {
      None
    };
    debug_assert_eq!(abort.is_some(), state.scopes[scope_ref.index].aborting > 0);
    let (index, selected_abort) = match abort {
      Some(index) => (Some(index), true),
      None => (head.filter(|_| quota_available), false),
    };
    if let Some(index) = index {
      let acquired = if selected_abort {
        false
      } else {
        state.scopes[scope_ref.index].quota.try_acquire()
      };
      if !selected_abort && !acquired {
        refresh_scope_schedule(state, scope_ref);
        continue;
      }
      unlink_ready(state, index, scope_ref);
      let task_ref = TaskRef {
        index,
        generation: state.tasks[index].protocol.generation(),
      };
      shared
        .metrics
        .inner()
        .queue_depth
        .fetch_sub(1, Ordering::Relaxed);
      let task = state.tasks[task_ref.index].task.as_ref().map(Arc::clone);
      let began = state.tasks[task_ref.index].protocol.begin_poll();
      if let (Some(task), Some(aborting)) = (task, began) {
        let permit = if aborting {
          if acquired {
            state.scopes[scope_ref.index].quota.release();
          }
          None
        } else {
          debug_assert!(acquired);
          Some(PollPermit {
            shared: Arc::downgrade(shared),
            scope: scope_ref,
            cpu_ticket: None,
          })
        };
        refresh_scope_schedule(state, scope_ref);
        if aborting || selected_abort {
          return Some(Selected::Cancel(task_ref, task));
        } else if let Some(permit) = permit {
          return Some(Selected::Poll(task_ref, task, permit));
        }
        continue;
      }
      if acquired {
        state.scopes[scope_ref.index].quota.release();
      }
      refresh_scope_schedule(state, scope_ref);
    }
  }
  None
}

/// Ends the caller's finished turn, then returns its next turn, a park or
/// retirement between turns, or exit. A new turn needs one of the `workers`
/// dispatcher permits and yields to waiting restorations.
fn take_next(
  shared: &Arc<Shared>,
  shard: usize,
  context: AsyncThreadContext,
  lease: &mut Option<HelperLease>,
  finished: Option<DispatchTurn>,
) -> Work {
  let mut state = shared.lock();
  if let Some(turn) = finished {
    end_turn(shared, &mut state, turn);
  }
  loop {
    if let Some(held) = lease.take() {
      match state.turns.retire_helper(held) {
        Ok(()) => {
          if !state.round_robin.is_empty() {
            // A wake meant for a dispatcher may have reached this helper.
            shared.work.notify_all();
          }
          return Work::Retire;
        }
        Err(held) => *lease = Some(held),
      }
    }
    if !state.round_robin.is_empty()
      && let Some(turn) = state.turns.try_begin_turn()
    {
      if let Some(selected) = dequeue(shared, &mut state) {
        return selected.into_work(turn);
      }
      end_turn(shared, &mut state, turn);
    }
    if state.turns.may_exit(admission_empty(&state)) {
      return Work::Exit;
    }
    state.idle += 1;
    drop(state);
    cache::flush();
    state = shared.lock();
    let excess = lease.is_some() && state.turns.helper_is_excess();
    let dispatchable = !state.round_robin.is_empty() && state.turns.can_begin_turn();
    if !excess && !dispatchable && !state.turns.may_exit(admission_empty(&state)) {
      drop(state);
      shared.thread_park_attempted(context);
      state = shared.lock();
      let excess = lease.is_some() && state.turns.helper_is_excess();
      let dispatchable = !state.round_robin.is_empty() && state.turns.can_begin_turn();
      if !excess && !dispatchable && !state.turns.may_exit(admission_empty(&state)) {
        shared.thread_parked(context);
        state = shared
          .work
          .wait(state)
          .unwrap_or_else(PoisonError::into_inner);
        drop(state);
        shared.thread_unparked(context);
        state = shared.lock();
      } else {
        drop(state);
        shared.thread_unpark_callback(context);
        state = shared.lock();
      }
    }
    state.idle = state.idle.saturating_sub(1);
    cache::set_shard(shard);
    if state.closed && state.cancel_all {
      for index in 0..state.tasks.len() {
        if state.tasks[index].task.is_some() && state.tasks[index].protocol.abort() {
          let reference = TaskRef {
            index,
            generation: state.tasks[index].protocol.generation(),
          };
          push_ready(&mut state, reference, &shared.metrics.inner().queue_depth);
        }
        // `close(true)` already counted queued aborts; this keeps the count
        // exact if a later path sets `cancel_all` first.
        sync_ready_abort(&mut state, index);
      }
    }
    if state.round_robin.is_empty() && !state.closed {
      return Work::Park;
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
  Retire,
  Exit,
}

/// Runs owned turns on an executor thread. Each turn's task, waker and
/// published values are dropped before the turn's permit is released.
fn run_turns(
  shared: &Arc<Shared>,
  shard: usize,
  context: AsyncThreadContext,
  lease: &mut Option<HelperLease>,
) -> Stop {
  let mut finished = None;
  loop {
    match take_next(shared, shard, context, lease, finished.take()) {
      Work::Poll(task_ref, task, permit, turn) => {
        handoff::enter_turn(turn);
        super::entry::reset_budget();
        let waker = match task_waker(shared, task_ref, task.tenant_domain()) {
          Ok(waker) => waker,
          Err(error) => {
            task.fail_resource(error);
            finish_poll(shared, task_ref, PollResult::Ready);
            drop(permit);
            drop(task);
            finished = handoff::leave_turn();
            continue;
          }
        };
        let mut context = Context::from_waker(&waker);
        match task.acquire_cpu(&waker) {
          DomainCpuAdmission::Unbounded => {
            let result = task.poll(&mut context, permit);
            finish_poll(shared, task_ref, result);
          }
          DomainCpuAdmission::Acquired(ticket) => {
            let mut permit = permit;
            permit.set_cpu_ticket(ticket);
            let result = task.poll(&mut context, permit);
            finish_poll(shared, task_ref, result);
          }
          DomainCpuAdmission::Waiting => {
            finish_poll(shared, task_ref, PollResult::Pending);
            drop(permit);
          }
          DomainCpuAdmission::Rejected(error) => {
            task.fail_resource(error);
            finish_poll(shared, task_ref, PollResult::Ready);
            drop(permit);
          }
        }
        drop(task);
        drop(waker);
        finished = handoff::leave_turn();
      }
      Work::Cancel(task_ref, task, turn) => {
        handoff::enter_turn(turn);
        task.cancel();
        finish_cancel(shared, task_ref, task);
        finished = handoff::leave_turn();
      }
      Work::Park => {}
      Work::Retire => return Stop::Retire,
      Work::Exit => return Stop::Exit,
    }
  }
}

/// Marks this thread as one of the runtime's executor threads. The worker
/// identity makes `shutdown` from any of its code, handed-off closures
/// included, return `WouldDeadlock`.
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
    let _ = run_turns(&shared, context.physical_index, context, &mut None);
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
  let shard = context.physical_index;
  executor_thread(&shared, context, context_control, || {
    while let Some(lease) = wait_for_activation(&shared, shard, context) {
      let mut lease = Some(lease);
      let stop = run_turns(&shared, shard, context, &mut lease);
      debug_assert!(lease.is_none());
      if stop == Stop::Exit {
        break;
      }
    }
    cache::flush();
  });
}

fn wait_for_activation(
  shared: &Arc<Shared>,
  shard: usize,
  context: AsyncThreadContext,
) -> Option<HelperLease> {
  let mut state = shared.lock();
  loop {
    if let Some(lease) = state.turns.try_activate_helper() {
      drop(state);
      cache::set_shard(shard);
      return Some(lease);
    }
    if state.turns.may_exit(admission_empty(&state)) {
      return None;
    }
    drop(state);
    cache::flush();
    state = shared.lock();
    if !state.turns.can_activate_helper() && !state.turns.may_exit(admission_empty(&state)) {
      drop(state);
      shared.thread_park_attempted(context);
      state = shared.lock();
      if !state.turns.can_activate_helper() && !state.turns.may_exit(admission_empty(&state)) {
        shared.thread_parked(context);
        state = shared
          .handoff
          .wait(state)
          .unwrap_or_else(PoisonError::into_inner);
        drop(state);
        shared.thread_unparked(context);
        state = shared.lock();
      } else {
        drop(state);
        shared.thread_unpark_callback(context);
        state = shared.lock();
      }
    }
  }
}

fn finish_cancel(shared: &Arc<Shared>, task_ref: TaskRef, task: Arc<dyn ErasedTask>) {
  let mut completed_scope = None;
  let mut state = shared.lock();
  let Some(slot) = state.tasks.get_mut(task_ref.index) else {
    return;
  };
  if !slot.protocol.matches(task_ref.generation) || slot.task.is_none() {
    return;
  }
  let slot_task = slot.task.take();
  let scope_ref = slot.scope.take();
  slot.protocol.finish_cancel();
  shared
    .metrics
    .inner()
    .alive_tasks
    .fetch_sub(1, Ordering::Relaxed);
  if let Some(scope_ref) = scope_ref
    && let Some(scope) = state.scopes.get(scope_ref.index)
    && scope.generation == scope_ref.generation
  {
    completed_scope = scope.scope.as_ref().map(Arc::clone);
  }
  drop(state);
  drop(slot_task);
  task.publish();
  if let Some(scope) = completed_scope {
    scope.completed();
  }
  shared.work.notify_all();
}

fn finish_poll(shared: &Arc<Shared>, task_ref: TaskRef, result: PollResult) {
  let mut publish = None;
  let mut cancel = None;
  let mut completed_scope = None;
  let mut state = shared.lock();
  let cancel_all = state.cancel_all;
  let Some(slot) = state.tasks.get_mut(task_ref.index) else {
    return;
  };
  if !slot.protocol.matches(task_ref.generation) || slot.task.is_none() {
    return;
  }
  let finish = slot
    .protocol
    .finish_poll(matches!(result, PollResult::Ready), cancel_all);
  match finish {
    PollFinish::Complete => {
      shared
        .metrics
        .inner()
        .alive_tasks
        .fetch_sub(1, Ordering::Relaxed);
      publish = slot.task.take();
      let scope_ref = slot.scope.take();
      if let Some(scope_ref) = scope_ref
        && let Some(scope) = state.scopes.get(scope_ref.index)
        && scope.generation == scope_ref.generation
      {
        completed_scope = scope.scope.as_ref().map(Arc::clone);
      }
    }
    PollFinish::CancelCleanup => {
      cancel = slot.task.as_ref().map(Arc::clone);
    }
    PollFinish::Requeue => push_ready(&mut state, task_ref, &shared.metrics.inner().queue_depth),
    PollFinish::Idle => {}
    PollFinish::Stale => return,
  }
  drop(state);
  if let Some(task) = cancel {
    task.cancel();
    finish_cancel(shared, task_ref, task);
    return;
  }
  if let Some(task) = publish {
    task.publish();
  }
  if let Some(scope) = completed_scope {
    scope.completed();
  }
  shared.work.notify_all();
}

pub(super) fn is_worker(shared: &Shared) -> bool {
  WORKER_RUNTIME.with(|id| id.get() == shared.id)
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;
  use crate::runtime::managed::{ResourceLimits, ResourceScope};
  use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};
  use std::future::Future;

  fn shared_with_task_slots(max_outstanding: usize) -> (Arc<Shared>, ScopeRef) {
    shared_with_config(AsyncConfig {
      workers: 1,
      max_outstanding,
      max_scopes: 1,
    })
  }

  /// Builds scheduler state without starting executor threads, so tests
  /// drive `dequeue` and the poll/cancel completions directly.
  fn shared_with_config(config: AsyncConfig) -> (Arc<Shared>, ScopeRef) {
    let metrics = RuntimeMetrics::try_new(
      1,
      [AsyncThreadContext {
        role: super::super::thread_options::AsyncThreadRole::Worker,
        index: 0,
        physical_index: 0,
      }],
      1,
      None,
    )
    .unwrap_or_else(|error| panic!("metrics allocation failed: {error:?}"));
    Shared::new(
      config,
      0,
      None,
      super::super::ControlledThreadOptions::unbounded(AsyncThreadOptions::default()),
      metrics,
    )
    .unwrap_or_else(|error| panic!("shared construction failed: {error}"))
  }

  #[test]
  fn exhausted_task_generation_is_skipped_without_hiding_other_slots() {
    let (shared, root) = shared_with_task_slots(2);
    {
      let mut state = shared.lock();
      state.tasks[0].protocol.admit(u64::MAX);
      state.tasks[0].protocol.finish_cancel();
    }

    let job = shared
      .spawn(root, std::future::pending::<()>())
      .unwrap_or_else(|error| panic!("usable task slot was hidden: {}", error.kind));
    {
      let state = shared.lock();
      check_ready_lists(&shared, &state);
      assert_eq!(state.tasks[0].protocol.generation(), u64::MAX);
      assert!(!state.tasks[0].protocol.admitted());
      assert_eq!(state.tasks[1].protocol.generation(), 1);
      assert!(state.tasks[1].protocol.admitted());
    }
    drop(job);
    shared.close(true);
    drop(shared);
  }

  #[test]
  fn all_exhausted_task_generations_return_full_without_admission() {
    let (shared, root) = shared_with_task_slots(2);
    {
      let mut state = shared.lock();
      for slot in &mut state.tasks {
        slot.protocol.admit(u64::MAX);
        slot.protocol.finish_cancel();
      }
    }

    let error = shared
      .spawn(root, std::future::pending::<()>())
      .err()
      .unwrap_or_else(|| panic!("table with no usable generation admitted a task"));
    assert_eq!(error.kind, AsyncError::Full);
    {
      let state = shared.lock();
      check_ready_lists(&shared, &state);
      assert!(state.tasks.iter().all(|slot| {
        slot.protocol.generation() == u64::MAX && !slot.protocol.admitted() && slot.task.is_none()
      }));
    }
    drop(error.into_future());
    shared.close(true);
    drop(shared);
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

  /// Walks every scope's ready list and checks its links, length and abort
  /// count against the task table and the queue-depth metric.
  fn check_ready_lists(shared: &Shared, state: &State) {
    let mut linked = 0;
    for (scope_index, scope) in state.scopes.iter().enumerate() {
      let mut len = 0;
      let mut aborting = 0;
      let mut prev = None;
      let mut cursor = scope.ready_head;
      while let Some(index) = cursor {
        let slot = &state.tasks[index];
        assert!(slot.ready_linked, "unlinked task {index} reachable");
        assert_eq!(slot.ready_prev, prev, "task {index} has a stale back link");
        assert_eq!(slot.scope.map(|scope| scope.index), Some(scope_index));
        assert_eq!(
          slot.scope.map(|scope| scope.generation),
          Some(scope.generation)
        );
        assert!(slot.protocol.admitted() && slot.task.is_some());
        assert_eq!(slot.ready_abort, slot.protocol.aborting_queued());
        aborting += usize::from(slot.ready_abort);
        len += 1;
        assert!(len <= state.tasks.len(), "ready list cycle");
        prev = Some(index);
        cursor = slot.ready_next;
      }
      assert_eq!(scope.ready_tail, prev);
      assert_eq!(scope.ready_len, len);
      assert_eq!(scope.aborting, aborting);
      if scope.scope.is_none() {
        assert!(scope.ready_empty());
      }
      linked += len;
    }
    assert_eq!(
      state.tasks.iter().filter(|slot| slot.ready_linked).count(),
      linked
    );
    assert_eq!(
      shared.metrics.inner().queue_depth.load(Ordering::Relaxed),
      linked
    );
  }

  fn take(shared: &Arc<Shared>) -> Option<Selected> {
    let mut state = shared.lock();
    let selected = dequeue(shared, &mut state);
    check_ready_lists(shared, &state);
    selected
  }

  fn take_poll(shared: &Arc<Shared>) -> (TaskRef, Arc<dyn ErasedTask>, PollPermit) {
    match take(shared) {
      Some(Selected::Poll(task_ref, task, permit)) => (task_ref, task, permit),
      Some(Selected::Cancel(task_ref, _)) => panic!("unexpected cancel of {}", task_ref.index),
      None => panic!("no dispatchable task"),
    }
  }

  /// Polls the next task without running it and leaves it idle.
  fn poll_idle(shared: &Arc<Shared>) -> TaskRef {
    let (task_ref, task, permit) = take_poll(shared);
    finish_poll(shared, task_ref, PollResult::Pending);
    drop(permit);
    drop(task);
    check_ready_lists(shared, &shared.lock());
    task_ref
  }

  fn cancel_next(shared: &Arc<Shared>) -> TaskRef {
    match take(shared) {
      Some(Selected::Cancel(task_ref, task)) => {
        task.cancel();
        finish_cancel(shared, task_ref, task);
        check_ready_lists(shared, &shared.lock());
        task_ref
      }
      Some(Selected::Poll(task_ref, ..)) => panic!("unexpected poll of {}", task_ref.index),
      None => panic!("no dispatchable task"),
    }
  }

  fn spawn_pending(shared: &Arc<Shared>, scope: ScopeRef) -> (TaskRef, AsyncJob<()>) {
    let job = shared
      .spawn(scope, std::future::pending::<()>())
      .unwrap_or_else(|error| panic!("spawn failed: {}", error.kind));
    let state = shared.lock();
    check_ready_lists(shared, &state);
    let index = state.scopes[scope.index]
      .ready_tail
      .unwrap_or_else(|| panic!("spawned task was not queued"));
    let task_ref = TaskRef {
      index,
      generation: state.tasks[index].protocol.generation(),
    };
    (task_ref, job)
  }

  fn finish(shared: Arc<Shared>) {
    shared.close(true);
    check_ready_lists(&shared, &shared.lock());
    drop(shared);
  }

  #[test]
  fn ready_list_keeps_push_order_within_a_scope() {
    let (shared, root) = shared_with_task_slots(16);
    let tasks: Vec<_> = (0..16).map(|_| spawn_pending(&shared, root)).collect();
    for (task_ref, _) in &tasks {
      assert_eq!(poll_idle(&shared), *task_ref);
    }
    assert!(take(&shared).is_none());
    // Wake order, not slot order, defines the next pass.
    for (task_ref, _) in tasks.iter().rev() {
      shared.wake(*task_ref);
    }
    shared.wake(tasks[3].0);
    check_ready_lists(&shared, &shared.lock());
    assert_eq!(shared.lock().scopes[0].ready_len, 16);
    for (task_ref, _) in tasks.iter().rev() {
      assert_eq!(poll_idle(&shared), *task_ref);
    }
    assert!(take(&shared).is_none());
    drop(tasks);
    finish(shared);
  }

  #[test]
  fn newly_queued_abort_passes_earlier_ordinary_entries() {
    let (shared, root) = shared_with_task_slots(4);
    let tasks: Vec<_> = (0..4).map(|_| spawn_pending(&shared, root)).collect();
    for _ in &tasks {
      poll_idle(&shared);
    }
    shared.wake(tasks[0].0);
    shared.wake(tasks[1].0);
    shared.abort(tasks[3].0);
    shared.wake(tasks[2].0);
    assert_eq!(shared.lock().scopes[0].aborting, 1);
    assert_eq!(cancel_next(&shared), tasks[3].0);
    assert_eq!(shared.lock().scopes[0].aborting, 0);
    for (task_ref, _) in &tasks[..3] {
      assert_eq!(poll_idle(&shared), *task_ref);
    }
    assert!(take(&shared).is_none());
    drop(tasks);
    finish(shared);
  }

  #[test]
  fn abort_of_queued_task_is_counted_and_selected_first() {
    let (shared, root) = shared_with_task_slots(5);
    let tasks: Vec<_> = (0..5).map(|_| spawn_pending(&shared, root)).collect();
    shared.abort(tasks[3].0);
    shared.abort(tasks[1].0);
    {
      let state = shared.lock();
      assert_eq!(state.scopes[0].ready_len, 5);
      assert_eq!(state.scopes[0].aborting, 2);
    }
    // Cancellation keeps push order among aborting entries.
    assert_eq!(cancel_next(&shared), tasks[1].0);
    assert_eq!(cancel_next(&shared), tasks[3].0);
    for index in [0, 2, 4] {
      assert_eq!(poll_idle(&shared), tasks[index].0);
    }
    assert!(take(&shared).is_none());
    drop(tasks);
    finish(shared);
  }

  #[test]
  fn quota_blocked_scope_keeps_order_and_admits_cancellation() {
    let (shared, root) = shared_with_task_slots(4);
    let tasks: Vec<_> = (0..4).map(|_| spawn_pending(&shared, root)).collect();
    let (first, task, permit) = take_poll(&shared);
    assert_eq!(first, tasks[0].0);
    assert!(shared.lock().scopes[0].quota_blocked);
    assert!(take(&shared).is_none());

    shared.abort(tasks[2].0);
    assert!(!shared.lock().scopes[0].quota_blocked);
    assert_eq!(cancel_next(&shared), tasks[2].0);
    assert!(take(&shared).is_none());
    assert!(shared.lock().scopes[0].quota_blocked);

    finish_poll(&shared, first, PollResult::Pending);
    drop(permit);
    drop(task);
    for index in [1, 3] {
      assert_eq!(poll_idle(&shared), tasks[index].0);
    }
    assert!(take(&shared).is_none());
    drop(tasks);
    finish(shared);
  }

  #[test]
  fn ready_scopes_alternate_one_poll_per_turn() {
    let (shared, _) = shared_with_config(AsyncConfig {
      workers: 1,
      max_outstanding: 6,
      max_scopes: 3,
    });
    let first = shared
      .new_scope(1, None)
      .unwrap_or_else(|error| panic!("scope construction failed: {error}"));
    let second = shared
      .new_scope(1, None)
      .unwrap_or_else(|error| panic!("scope construction failed: {error}"));
    let a: Vec<_> = (0..3)
      .map(|_| spawn_pending(&shared, first.scope))
      .collect();
    let b: Vec<_> = (0..3)
      .map(|_| spawn_pending(&shared, second.scope))
      .collect();
    for index in 0..3 {
      assert_eq!(poll_idle(&shared), a[index].0);
      assert_eq!(poll_idle(&shared), b[index].0);
    }
    assert!(take(&shared).is_none());
    drop((a, b));
    drop(first);
    drop(second);
    check_ready_lists(&shared, &shared.lock());
    finish(shared);
  }
}
