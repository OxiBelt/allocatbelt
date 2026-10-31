//! Bounded async task admission and scheduling. Scheduler state is reserved
//! before workers start; the mutex protects bookkeeping only and is released
//! before polling, dropping task values, or invoking wakers. Each scope keeps
//! its queued tasks in an intrusive FIFO list threaded through the task table,
//! so queueing, selection and schedule refresh do not scan other scopes' work.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Wake, Waker};

#[path = "distributed.rs"]
mod distributed;

use super::handoff;
use super::handoff_protocol::{DispatchTurn, HandoffLoan, HelperLease, TurnCoordinator};
use super::identity;
use super::join::AsyncJob;
use super::metrics::RuntimeMetrics;
use super::protocol::{PollFinish, PollProtocol, PollQuota, PollWord, ScopeProtocol};
use super::task::{DomainCpuAdmission, ErasedTask, PollResult, Task};
use super::thread_options::AsyncThreadContext;
#[cfg(all(test, not(loom)))]
use super::thread_options::AsyncThreadOptions;
use super::{AsyncConfig, AsyncDispatch, AsyncError, AsyncSpawnError};
use crate::runtime::cache;
use crate::runtime::managed::ResourceScope;
use crate::runtime::resource_domain::{
  ControlCharge, DomainError, DomainIdentity, DomainReservation, DomainResource, DomainResources,
  DomainWaitPool, DomainWaiter, TenantDomain, payload_bytes,
};
use distributed::Distributed;

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
  admitted: usize,
  cancel_all: bool,
  tasks: Vec<TaskSlot>,
  free_tasks: BinaryHeap<Reverse<usize>>,
  scopes: Vec<ScopeSlot>,
  round_robin: VecDeque<ScopeRef>,
  idle: usize,
  turns: TurnCoordinator,
}

pub(super) struct Shared {
  id: u64,
  pub(super) dispatch: AsyncDispatch,
  max_handoffs: usize,
  workers: usize,
  pub(super) metrics: RuntimeMetrics,
  thread_options: super::ControlledThreadOptions,
  /// One wake record per task slot, indexed like `State::tasks` and read
  /// without the scheduler mutex.
  poll_words: Vec<PollWord>,
  state: Mutex<State>,
  distributed: Option<Distributed>,
  work: Condvar,
  /// Inactive helpers and restoring threads wait here; `work` waiters are
  /// dispatchers.
  handoff: Condvar,
  /// Deterministic admission interleavings; absent from non-test builds.
  #[cfg(all(test, not(loom)))]
  spawn_admission_test_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
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
    dispatch: AsyncDispatch,
    max_handoffs: usize,
    resources: Option<ResourceScope>,
    thread_options: super::ControlledThreadOptions,
    metrics: RuntimeMetrics,
  ) -> Result<(Arc<Self>, ScopeRef), AsyncError> {
    let distributed_mode = dispatch == AsyncDispatch::Distributed;
    let strict_tasks = if distributed_mode {
      0
    } else {
      config.max_outstanding
    };
    let strict_scopes = if distributed_mode {
      0
    } else {
      config.max_scopes
    };
    let tenant = resources.as_ref().and_then(ResourceScope::tenant_domain);
    let mut requested_control = std::mem::size_of::<Shared>();
    for bytes in [
      payload_bytes::<TaskSlot>(strict_tasks).map_err(AsyncError::ResourceDomain)?,
      payload_bytes::<Reverse<usize>>(config.max_outstanding)
        .map_err(AsyncError::ResourceDomain)?,
      payload_bytes::<PollWord>(strict_tasks).map_err(AsyncError::ResourceDomain)?,
      payload_bytes::<ScopeSlot>(config.max_scopes).map_err(AsyncError::ResourceDomain)?,
      payload_bytes::<ScopeRef>(strict_scopes).map_err(AsyncError::ResourceDomain)?,
      std::mem::size_of::<ScopeCell>(),
    ] {
      requested_control = requested_control
        .checked_add(bytes)
        .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
    }
    if distributed_mode {
      requested_control = requested_control
        .checked_add(Distributed::requested_control(config)?)
        .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
    }
    let mut control =
      ControlCharge::try_new(tenant, requested_control).map_err(AsyncError::ResourceDomain)?;

    let mut tasks = Vec::new();
    tasks
      .try_reserve_exact(strict_tasks)
      .map_err(|_| AsyncError::OutOfMemory)?;
    tasks.resize_with(strict_tasks, TaskSlot::new);
    let mut free_tasks = BinaryHeap::new();
    free_tasks
      .try_reserve_exact(config.max_outstanding)
      .map_err(|_| AsyncError::OutOfMemory)?;
    for index in 0..config.max_outstanding {
      free_tasks.push(Reverse(index));
    }
    let mut poll_words = Vec::new();
    poll_words
      .try_reserve_exact(strict_tasks)
      .map_err(|_| AsyncError::OutOfMemory)?;
    poll_words.resize_with(strict_tasks, PollWord::new);
    let mut scopes = Vec::new();
    scopes
      .try_reserve_exact(config.max_scopes)
      .map_err(|_| AsyncError::OutOfMemory)?;
    scopes.resize_with(config.max_scopes, || {
      ScopeSlot::new(0, None, PollQuota::new(1))
    });
    let mut round_robin = VecDeque::new();
    round_robin
      .try_reserve_exact(strict_scopes)
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
      (config.workers, config.workers + max_handoffs),
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
    let distributed = if distributed_mode {
      Some(Distributed::new(config, max_handoffs)?)
    } else {
      None
    };
    let mut actual_control = std::mem::size_of::<Shared>();
    for bytes in [
      payload_bytes::<TaskSlot>(tasks.capacity()).map_err(AsyncError::ResourceDomain)?,
      payload_bytes::<Reverse<usize>>(free_tasks.capacity()).map_err(AsyncError::ResourceDomain)?,
      payload_bytes::<PollWord>(poll_words.capacity()).map_err(AsyncError::ResourceDomain)?,
      payload_bytes::<ScopeSlot>(scopes.capacity()).map_err(AsyncError::ResourceDomain)?,
      payload_bytes::<ScopeRef>(round_robin.capacity()).map_err(AsyncError::ResourceDomain)?,
      std::mem::size_of::<ScopeCell>(),
    ] {
      actual_control = actual_control
        .checked_add(bytes)
        .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
    }
    if let Some(d) = &distributed {
      actual_control = actual_control
        .checked_add(d.actual_control()?)
        .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
    }
    control
      .try_resize(actual_control)
      .map_err(AsyncError::ResourceDomain)?;
    Ok((
      Arc::new(Self {
        id,
        dispatch,
        max_handoffs,
        workers: config.workers,
        metrics,
        thread_options,
        poll_words,
        distributed,
        state: Mutex::new(State {
          closed: false,
          admitted: 0,
          cancel_all: false,
          tasks,
          free_tasks,
          scopes,
          round_robin,
          idle: 0,
          turns: TurnCoordinator::new(config.workers, max_handoffs),
        }),
        work: Condvar::new(),
        handoff: Condvar::new(),
        #[cfg(all(test, not(loom)))]
        spawn_admission_test_hook: Mutex::new(None),
        #[cfg(all(test, not(loom)))]
        lock_acquisitions: AtomicUsize::new(0),
        _control: control,
      }),
      root,
    ))
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
      (
        index,
        generation,
        root_cell,
        self
          .distributed
          .as_ref()
          .map_or(state.tasks.len(), Distributed::slots_len),
      )
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
    if self.distributed.is_some() {
      let cell = Arc::clone(cell);
      drop(state);
      return Some(distributed::scope_snapshot(&cell));
    }
    Some(super::AsyncScopeSnapshot {
      active_tasks: cell.protocol.active(),
      active_polls: slot.quota.active(),
      max_active_polls: slot.quota.maximum(),
    })
  }

  fn release_poll(&self, scope_ref: ScopeRef) {
    let notify = {
      let mut state = self.lock();
      release_poll_locked(&mut state, scope_ref)
    };
    if notify {
      // One released quota adds one RR token; only parked dispatchers need a wake.
      self.work.notify_one();
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
    if let Some(d) = &self.distributed {
      return d.spawn(self, scope, future);
    }
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
      if state.free_tasks.peek().is_none() {
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
    let Some(Reverse(index)) = state.free_tasks.peek().copied() else {
      drop(state);
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::Full, future));
    };
    let slot = &state.tasks[index];
    let Some(generation) = (slot.task.is_none() && !slot.protocol.admitted())
      .then(|| slot.protocol.next_generation())
      .flatten()
    else {
      drop(state);
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::Full, future));
    };
    let popped = state.free_tasks.pop();
    debug_assert_eq!(popped, Some(Reverse(index)));
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
    let notify = state.idle > 0;
    drop(state);
    if notify {
      // Non-idle dispatchers recheck the ready list under the same mutex.
      self.work.notify_one();
    }
    Ok(job)
  }

  pub(super) fn close(&self, cancel: bool) {
    if let Some(d) = &self.distributed {
      return d.close(self, cancel);
    }
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
    if let Some(d) = &self.distributed {
      return d.request_scope_close(self, scope);
    }
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
    if let Some(d) = &self.distributed {
      return d.wake(self, task_ref);
    }
    // A wake of the running poll, often the task's own, only records
    // `NOTIFIED`; `finish_poll` hands it to `PollProtocol` under the mutex.
    if self
      .poll_words
      .get(task_ref.index)
      .is_some_and(|word| word.notify_running(task_ref.generation))
    {
      return;
    }
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
    let notify = inserted && state.idle > 0;
    drop(state);
    if notify {
      // One inserted task needs one waiter; non-idle threads recheck before parking.
      self.work.notify_one();
    }
  }

  pub(super) fn abort(&self, task_ref: TaskRef) {
    if let Some(d) = &self.distributed {
      return d.abort(self, task_ref);
    }
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
    if let Some(d) = &self.distributed {
      return d.hand_off(turn);
    }
    let loan = self.lock().turns.try_hand_off(turn)?;
    // The released permit may serve a helper, a dispatcher or a restorer.
    self.handoff.notify_all();
    self.work.notify_all();
    Ok(loan)
  }

  /// Waits, with priority over new turns, until the loan's thread holds a
  /// dispatcher permit again. Admission closure does not prevent this.
  pub(super) fn restore(&self, loan: HandoffLoan, context: AsyncThreadContext) -> DispatchTurn {
    if let Some(d) = &self.distributed {
      return d.restore(self, loan, context);
    }
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
    if let Some(d) = &self.distributed {
      return d.turn_counts();
    }
    let state = self.lock();
    state.turns.check();
    state.turns.counts()
  }

  /// Releases the permit of a thread that unwound out of a turn.
  pub(super) fn abandon_turn(&self, turn: DispatchTurn) {
    if let Some(d) = &self.distributed {
      return d.abandon_turn(self, turn);
    }
    let mut state = self.lock();
    end_turn(self, &mut state, turn);
  }
}

/// Returns whether releasing this quota unblocked a scope with an idle waiter.
fn release_poll_locked(state: &mut State, scope_ref: ScopeRef) -> bool {
  let Some(slot) = state.scopes.get_mut(scope_ref.index) else {
    return false;
  };
  if slot.generation != scope_ref.generation || slot.scope.is_none() {
    return false;
  }
  let capacity_available = slot.quota.release();
  if capacity_available && slot.quota_blocked {
    refresh_scope_schedule(state, scope_ref);
    state.idle > 0
  } else {
    false
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
  /// change concurrently. Strict samples poll counts under the scheduler
  /// lock; Distributed uses the scope quota lock for binding limits and a
  /// relaxed diagnostic count otherwise.
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

/// Creates the admission-independent wake handle cached per task generation.
/// It holds no task, future, or result, so a retained stale waker cannot keep
/// completed user data alive.
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

/// Releases one scope's active-poll reservation on every exit path. Pending
/// polls return it for locked completion; terminal polls drop it before any
/// future/output cleanup can run.
pub(super) struct PollPermit {
  release: PermitRelease,
  cpu_ticket: Option<DomainReservation>,
}

enum PermitRelease {
  Strict {
    shared: Weak<Shared>,
    scope: ScopeRef,
  },
  Scope {
    shared: Weak<Shared>,
    cell: Arc<ScopeCell>,
  },
  Counted {
    cell: Arc<ScopeCell>,
  },
  Free,
  Disarmed,
}

impl PollPermit {
  pub(super) fn cpu_domain_identity(&self) -> Option<DomainIdentity> {
    self
      .cpu_ticket
      .as_ref()
      .map(DomainReservation::domain_identity)
  }

  /// Releases the poll slot under the caller's scheduler lock. The fallback
  /// release is disarmed first, so a panic here cannot relock the scheduler.
  /// The CPU ticket must already be gone: its drop may run wakers.
  fn release_locked(mut self, state: &mut State) -> bool {
    debug_assert!(self.cpu_ticket.is_none());
    let release = std::mem::replace(&mut self.release, PermitRelease::Disarmed);
    match release {
      PermitRelease::Strict { scope, .. } => release_poll_locked(state, scope),
      _ => unreachable!("distributed permit on strict path"),
    }
  }

  /// Returns the CPU ticket so it can be dropped as soon as the poll ends.
  fn take_cpu_ticket(&mut self) -> Option<DomainReservation> {
    self.cpu_ticket.take()
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
    match std::mem::replace(&mut self.release, PermitRelease::Disarmed) {
      PermitRelease::Strict { shared, scope } => {
        if let Some(shared) = shared.upgrade() {
          shared.release_poll(scope);
        }
      }
      PermitRelease::Scope { shared, cell } => {
        if let Some(shared) = shared.upgrade()
          && let Some(d) = &shared.distributed
        {
          d.release_permit(&shared, &cell);
        }
      }
      PermitRelease::Counted { cell } => {
        cell.active_stat.fetch_sub(1, Ordering::Relaxed);
      }
      PermitRelease::Free | PermitRelease::Disarmed => {}
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
            release: PermitRelease::Strict {
              shared: Arc::downgrade(shared),
              scope: scope_ref,
            },
            cpu_ticket: None,
          })
        };
        refresh_scope_schedule(state, scope_ref);
        if aborting || selected_abort {
          return Some(Selected::Cancel(task_ref, task));
        } else if let Some(permit) = permit {
          shared.poll_words[task_ref.index].begin(task_ref.generation);
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

struct PendingFinish {
  task: TaskRef,
  permit: Option<PollPermit>,
}

/// Finishes a pending poll while retaining the turn for cancellation cleanup.
fn finish_pending_locked(
  shared: &Shared,
  state: &mut State,
  task_ref: TaskRef,
) -> Option<Arc<dyn ErasedTask>> {
  let cancel_all = state.cancel_all;
  let slot = state.tasks.get_mut(task_ref.index)?;
  if !slot.protocol.matches(task_ref.generation) || slot.task.is_none() {
    return None;
  }
  if shared.poll_words[task_ref.index].finish() {
    let inserted = slot.protocol.wake();
    debug_assert!(!inserted);
  }
  match slot.protocol.finish_poll(false, cancel_all) {
    PollFinish::CancelCleanup => slot.task.as_ref().map(Arc::clone),
    PollFinish::Requeue => {
      push_ready(state, task_ref, &shared.metrics.inner().queue_depth);
      None
    }
    PollFinish::Idle | PollFinish::Stale => None,
    PollFinish::Complete => unreachable!("pending poll completed admission"),
  }
}

/// Completes the caller's pending poll, if any, under the same lock: it
/// releases the poll slot, finishes the task and requeues it. Cancellation
/// cleanup keeps the finished turn and returns as `Work::Cancel`. Otherwise
/// ends that turn, then returns the next turn, a park or retirement between
/// turns, or exit. A new turn needs one of the `workers` dispatcher permits
/// and yields to waiting restorations.
fn take_next(
  shared: &Arc<Shared>,
  shard: usize,
  context: AsyncThreadContext,
  lease: &mut Option<HelperLease>,
  finished: Option<DispatchTurn>,
  pending: Option<PendingFinish>,
) -> Work {
  let mut state = shared.lock();
  let mut notify_pending = pending.is_some();
  if let Some(PendingFinish { task, permit }) = pending {
    if let Some(permit) = permit {
      // Dispatch below consumes the released capacity; on other paths the
      // backlog notification below replaces the quota/requeue notifications.
      permit.release_locked(&mut state);
    }
    let cancel = finish_pending_locked(shared, &mut state, task);
    // Pending completion, including idle/stale, must let closed waiters
    // recheck cancellation and exit just as the separate finish did.
    let broadcast = state.closed;
    if let Some(cancel) = cancel {
      // Cleanup keeps this turn and cannot consume released quota's work.
      let notify = !state.round_robin.is_empty() && state.idle > 0;
      drop(state);
      if broadcast {
        shared.work.notify_all();
      } else if notify {
        shared.work.notify_one();
      }
      if let Some(turn) = finished {
        return Work::Cancel(task, cancel, turn);
      }
      // Without a TLS turn, the old finish_poll still cleaned up
      // synchronously before dispatching any new work.
      cancel.cancel();
      finish_cancel(shared, task, cancel);
      return take_next(shared, shard, context, lease, None, None);
    }
    if broadcast {
      drop(state);
      shared.work.notify_all();
      state = shared.lock();
    }
  }
  if let Some(turn) = finished {
    end_turn(shared, &mut state, turn);
  }
  loop {
    if let Some(held) = lease.take() {
      match state.turns.retire_helper(held) {
        Ok(()) => {
          if !state.round_robin.is_empty() {
            // Retirement cannot consume the pending quota/requeue backlog;
            // a wake meant for a dispatcher may have reached this helper.
            shared.work.notify_all();
          }
          drop(state);
          return Work::Retire;
        }
        Err(held) => *lease = Some(held),
      }
    }
    if !state.round_robin.is_empty()
      && let Some(turn) = state.turns.try_begin_turn()
    {
      if let Some(selected) = dequeue(shared, &mut state) {
        // Pass a remaining backlog to one parked thread, which repeats this
        // step, so dispatch scales out without waking every waiter per poll.
        let propagate = !state.round_robin.is_empty() && state.idle > 0;
        drop(state);
        if propagate {
          shared.work.notify_one();
        }
        return selected.into_work(turn);
      }
      end_turn(shared, &mut state, turn);
    }
    // No dispatch: exit, park, or a restorer preventing a new turn must
    // pass any quota/requeue backlog to an idle dispatcher.
    let backlog = notify_pending && !state.round_robin.is_empty() && state.idle > 0;
    notify_pending = false;
    if state.turns.may_exit(admission_empty(&state)) {
      drop(state);
      if backlog {
        shared.work.notify_one();
      }
      return Work::Exit;
    }
    state.idle += 1;
    drop(state);
    if backlog {
      shared.work.notify_one();
    }
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

/// Runs owned turns on an executor thread. Each turn's task, waker clone and
/// published values are dropped before the turn's permit is released; the
/// task keeps its cached waker until it finishes.
fn run_turns(
  shared: &Arc<Shared>,
  shard: usize,
  context: AsyncThreadContext,
  lease: &mut Option<HelperLease>,
) -> Stop {
  let mut finished = None;
  let mut pending = None;
  loop {
    match take_next(
      shared,
      shard,
      context,
      lease,
      finished.take(),
      pending.take(),
    ) {
      Work::Poll(task_ref, task, permit, turn) => {
        handoff::enter_turn(turn);
        super::entry::reset_budget();
        let waker =
          match task.task_waker(&mut || task_waker(shared, task_ref, task.tenant_domain())) {
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
        let (result, permit) = match task.acquire_cpu(&waker) {
          DomainCpuAdmission::Unbounded => task.poll(&mut context, permit),
          DomainCpuAdmission::Acquired(ticket) => {
            let mut permit = permit;
            permit.set_cpu_ticket(ticket);
            task.poll(&mut context, permit)
          }
          DomainCpuAdmission::Waiting => (PollResult::Pending, Some(permit)),
          DomainCpuAdmission::Rejected(error) => {
            task.fail_resource(error);
            finish_poll(shared, task_ref, PollResult::Ready);
            drop(permit);
            drop(task);
            drop(waker);
            finished = handoff::leave_turn();
            continue;
          }
        };
        match result {
          PollResult::Pending => {
            let mut permit = permit;
            // Return CPU capacity now, unlocked: a ticket held until the
            // next dispatch would refuse the requeued task's admission, and
            // its release may run wakers.
            drop(permit.as_mut().and_then(PollPermit::take_cpu_ticket));
            pending = Some(PendingFinish {
              task: task_ref,
              permit,
            })
          }
          PollResult::Ready => {
            finish_poll(shared, task_ref, PollResult::Ready);
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
    if let Some(d) = &shared.distributed {
      d.run_seat(&shared, context);
    } else {
      let _ = run_turns(&shared, context.physical_index, context, &mut None);
    }
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
    if let Some(d) = &shared.distributed {
      d.helper(&shared, context);
      cache::flush();
      return;
    }
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
  let reusable = slot.protocol.next_generation().is_some();
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
  if reusable {
    state.free_tasks.push(Reverse(task_ref.index));
  }
  let closed = state.closed;
  drop(state);
  drop(slot_task);
  task.publish();
  if let Some(scope) = completed_scope {
    scope.completed();
  }
  if closed {
    // Removing admission can enable exit only after runtime closure.
    shared.work.notify_all();
  }
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
  // A wake taken from the word is the same pending wake as a locked one.
  if shared.poll_words[task_ref.index].finish() {
    let inserted = slot.protocol.wake();
    debug_assert!(!inserted);
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
      let reusable = slot.protocol.next_generation().is_some();
      if reusable {
        state.free_tasks.push(Reverse(task_ref.index));
      }
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
  let closed = state.closed;
  let notify = finish == PollFinish::Requeue && !state.round_robin.is_empty() && state.idle > 0;
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
  if closed {
    // Closed admission needs every dispatcher to recheck cleanup and exit.
    shared.work.notify_all();
  } else if notify {
    // A requeue with an RR token needs one waiter; idle/complete add no work.
    shared.work.notify_one();
  }
}

pub(super) fn is_worker(shared: &Shared) -> bool {
  WORKER_RUNTIME.with(|id| id.get() == shared.id)
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::super::{
    AsyncJoinError, AsyncRuntime, AsyncRuntimeOptions, AsyncShutdown, strict_runtime, yield_now,
  };
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
        let state = shared.lock();
        // Parks are counted under this lock immediately before the condvar wait.
        state.idle == shared.workers
          && shared
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
      AsyncRuntimeOptions::new()
        .dispatch(AsyncDispatch::Strict)
        .thread_options(options),
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
    let runtime = strict_runtime(AsyncConfig {
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
      let runtime = strict_runtime(AsyncConfig {
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
  fn completed_task_releases_cached_waker_before_task_drop() {
    struct Probe(std::sync::atomic::AtomicUsize);
    impl Wake for Probe {
      fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
      }
    }

    let admission = Task::<std::future::Ready<()>>::reserve_domain_admission(None)
      .unwrap_or_else(|error| panic!("admission failed: {error}"));
    let (task, _job) = Task::create(
      std::future::ready(()),
      super::super::identity::TaskId::test_sentinel(),
      None,
      admission,
      Weak::new(),
      TaskRef {
        index: 0,
        generation: 1,
      },
    );
    let probe = Arc::new(Probe(std::sync::atomic::AtomicUsize::new(0)));
    let waker = task
      .task_waker(&mut || Ok(Waker::from(Arc::clone(&probe))))
      .unwrap_or_else(|error| panic!("waker creation failed: {error}"));
    assert_eq!(Arc::strong_count(&probe), 3);
    let permit = PollPermit {
      release: PermitRelease::Strict {
        shared: Weak::new(),
        scope: ScopeRef {
          index: 0,
          generation: 1,
        },
      },
      cpu_ticket: None,
    };
    assert!(matches!(
      task.poll(&mut Context::from_waker(&waker), permit),
      (PollResult::Ready, None)
    ));
    assert_eq!(Arc::strong_count(&probe), 2);
    drop(waker);
    assert_eq!(Arc::strong_count(&probe), 1);
  }

  #[derive(Default)]
  struct CountingWake(AtomicUsize);

  impl Wake for CountingWake {
    fn wake(self: Arc<Self>) {
      self.0.fetch_add(1, Ordering::Relaxed);
    }
  }

  /// Creates an unbound task with a cached probe waker, runs one terminal
  /// path, and checks that the task released its cached reference.
  fn assert_terminal_path_releases_cached_waker<F>(future: F, finish: impl FnOnce(&dyn ErasedTask))
  where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
  {
    let admission = Task::<F>::reserve_domain_admission(None)
      .unwrap_or_else(|error| panic!("admission failed: {error}"));
    let (task, _job) = Task::create(
      future,
      super::super::identity::TaskId::test_sentinel(),
      None,
      admission,
      Weak::new(),
      TaskRef {
        index: 0,
        generation: 1,
      },
    );
    let probe = Arc::new(CountingWake::default());
    let waker = task
      .task_waker(&mut || Ok(Waker::from(Arc::clone(&probe))))
      .unwrap_or_else(|error| panic!("waker creation failed: {error}"));
    assert_eq!(Arc::strong_count(&probe), 3);
    finish(task.as_ref());
    assert_eq!(Arc::strong_count(&probe), 2);
    drop(waker);
    assert_eq!(Arc::strong_count(&probe), 1);
  }

  fn unscheduled_permit() -> PollPermit {
    PollPermit {
      release: PermitRelease::Strict {
        shared: Weak::new(),
        scope: ScopeRef {
          index: 0,
          generation: 1,
        },
      },
      cpu_ticket: None,
    }
  }

  #[test]
  fn cancel_panic_and_resource_failure_release_cached_waker() {
    assert_terminal_path_releases_cached_waker(std::future::pending::<()>(), |task| task.cancel());
    assert_terminal_path_releases_cached_waker(std::future::pending::<()>(), |task| {
      task.fail_resource(DomainError::WaitersFull);
    });
    assert_terminal_path_releases_cached_waker(
      std::future::poll_fn(|_| -> std::task::Poll<()> { panic!("contained poll panic") }),
      |task| {
        let waker = Waker::noop();
        assert!(matches!(
          task.poll(&mut Context::from_waker(waker), unscheduled_permit()),
          (PollResult::Ready, None)
        ));
      },
    );
    // A dispatch after cleanup finds no future and releases a recreated waker.
    assert_terminal_path_releases_cached_waker(std::future::pending::<()>(), |task| {
      task.cancel();
      let probe = Arc::new(CountingWake::default());
      let recreated = task
        .task_waker(&mut || Ok(Waker::from(Arc::clone(&probe))))
        .unwrap_or_else(|error| panic!("waker creation failed: {error}"));
      assert_eq!(Arc::strong_count(&probe), 3);
      assert!(matches!(
        task.poll(&mut Context::from_waker(&recreated), unscheduled_permit()),
        (PollResult::Ready, None)
      ));
      assert_eq!(Arc::strong_count(&probe), 2);
      drop(recreated);
      assert_eq!(Arc::strong_count(&probe), 1);
    });
  }

  fn shared_with_task_slots(max_outstanding: usize) -> (Arc<Shared>, ScopeRef) {
    shared_with_config(AsyncConfig {
      workers: 1,
      max_outstanding,
      max_scopes: 1,
    })
  }

  /// Builds scheduler state without starting executor threads, so tests
  /// drive strict `dequeue` and the poll/cancel completions directly.
  fn shared_with_config(config: AsyncConfig) -> (Arc<Shared>, ScopeRef) {
    let metrics = RuntimeMetrics::try_new(
      AsyncDispatch::Strict,
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
      AsyncDispatch::Strict,
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
      discard_free_task_for_test(&mut state, 0);
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
      for index in 0..state.tasks.len() {
        discard_free_task_for_test(&mut state, index);
      }
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
      AsyncDispatch::Strict,
      0,
      None,
      super::super::ControlledThreadOptions::unbounded(AsyncThreadOptions::default()),
      RuntimeMetrics::try_new(
        AsyncDispatch::Strict,
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
      AsyncDispatch::Strict,
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
      AsyncDispatch::Strict,
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

  /// Removes a slot from the free heap before a test makes it unusable.
  fn discard_free_task_for_test(state: &mut State, index: usize) {
    state
      .free_tasks
      .retain(|Reverse(candidate)| *candidate != index);
  }

  /// Walks every scope's ready list and checks its links, length and abort
  /// count against the task table and the queue-depth metric. Also checks
  /// that the free heap holds exactly the free reusable slots.
  fn check_ready_lists(shared: &Shared, state: &State) {
    let mut free_heap = state
      .free_tasks
      .iter()
      .map(|Reverse(index)| *index)
      .collect::<Vec<_>>();
    free_heap.sort_unstable();
    assert!(free_heap.windows(2).all(|pair| pair[0] != pair[1]));
    let expected_free = state
      .tasks
      .iter()
      .enumerate()
      .filter_map(|(index, slot)| {
        (slot.task.is_none()
          && !slot.protocol.admitted()
          && slot.protocol.next_generation().is_some())
        .then_some(index)
      })
      .collect::<Vec<_>>();
    assert_eq!(free_heap, expected_free, "free task heap is inconsistent");

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
  fn pending_self_yields_take_one_scheduler_lock_per_poll() {
    let runtime = strict_runtime(AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 1,
    })
    .unwrap();
    let shared = Arc::clone(&runtime.shared);
    let mut previous = None;
    let mut pending_polls = 0;
    let job = runtime
      .handle()
      .spawn(std::future::poll_fn(move |cx| {
        let locks = shared.lock_acquisitions.load(Ordering::Relaxed);
        if let Some(previous) = previous {
          assert_eq!(locks - previous, 1);
        }
        previous = Some(locks);
        if pending_polls == 1_000 {
          return Poll::Ready(pending_polls);
        }
        pending_polls += 1;
        cx.waker().wake_by_ref();
        Poll::Pending
      }))
      .unwrap();
    assert_eq!(finish_job(job).unwrap(), 1_000);
    shutdown_with_deadline(runtime, AsyncShutdown::Drain);
  }

  #[test]
  fn quota_one_pending_tasks_alternate_until_both_complete() {
    let (shared, _) = shared_with_config(AsyncConfig {
      workers: 1,
      max_outstanding: 2,
      max_scopes: 2,
    });
    let scope = shared.new_scope(1, None).unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let jobs: Vec<_> = (0..2)
      .map(|id| {
        let order = Arc::clone(&order);
        let mut polls = 0;
        shared
          .spawn(
            scope.scope,
            std::future::poll_fn(move |cx| {
              order.lock().unwrap().push(id);
              polls += 1;
              if polls == 4 {
                Poll::Ready(())
              } else {
                cx.waker().wake_by_ref();
                Poll::Pending
              }
            }),
          )
          .unwrap()
      })
      .collect();
    // Start both tasks queued so the FIFO witness is deterministic.
    let context = AsyncThreadContext {
      role: super::super::thread_options::AsyncThreadRole::Worker,
      index: 0,
      physical_index: 0,
    };
    shared.close(false);
    // A leaked poll slot would park this dispatcher forever; fail instead.
    let (done, finished) = mpsc::channel();
    let dispatcher = Arc::clone(&shared);
    std::thread::spawn(move || {
      let _dispatcher = handoff::DispatcherGuard::install(&dispatcher, context);
      let _ = done.send(run_turns(&dispatcher, 0, context, &mut None));
    });
    assert_eq!(
      finished
        .recv_timeout(std::time::Duration::from_secs(30))
        .unwrap_or_else(|error| panic!("dispatcher did not exit: {error}")),
      Stop::Exit
    );
    assert_eq!(*order.lock().unwrap(), vec![0, 1, 0, 1, 0, 1, 0, 1]);
    for job in jobs {
      finish_job(job).unwrap();
    }
    assert_eq!(scope.snapshot().active_polls, 0);
    drop(scope);
  }

  struct PendingAbortProbe {
    shared: Arc<Shared>,
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    polls: Arc<AtomicUsize>,
    cleanup_turns: Arc<AtomicUsize>,
  }

  impl Future for PendingAbortProbe {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
      self.polls.fetch_add(1, Ordering::Relaxed);
      self.entered.send(()).unwrap();
      self.release.recv_timeout(Duration::from_secs(30)).unwrap();
      cx.waker().wake_by_ref();
      Poll::Pending
    }
  }

  impl Drop for PendingAbortProbe {
    fn drop(&mut self) {
      let state = self.shared.lock();
      self
        .cleanup_turns
        .store(state.turns.counts().0, Ordering::Relaxed);
      assert_eq!(state.scopes[1].quota.active(), 0);
    }
  }

  #[test]
  fn abort_during_pending_poll_cleans_up_in_the_same_turn() {
    let runtime = strict_runtime(AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 2,
    })
    .unwrap();
    let scope = runtime
      .scope_with_config(super::super::AsyncScopeConfig {
        max_active_polls: 1,
      })
      .unwrap();
    let (entered, arrival) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let polls = Arc::new(AtomicUsize::new(0));
    let cleanup_turns = Arc::new(AtomicUsize::new(0));
    let job = scope
      .handle()
      .spawn(PendingAbortProbe {
        shared: Arc::clone(&runtime.shared),
        entered,
        release: resume,
        polls: Arc::clone(&polls),
        cleanup_turns: Arc::clone(&cleanup_turns),
      })
      .unwrap();
    arrival.recv_timeout(Duration::from_secs(30)).unwrap();
    job.abort();
    let mut close = Box::pin(scope.close());
    assert!(
      close
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending()
    );
    release.send(()).unwrap();
    assert!(matches!(finish_job(job), Err(AsyncJoinError::Cancelled)));
    assert_eq!(polls.load(Ordering::Relaxed), 1);
    assert_eq!(cleanup_turns.load(Ordering::Relaxed), 1);
    let deadline = Instant::now() + Duration::from_secs(30);
    while close
      .as_mut()
      .poll(&mut Context::from_waker(Waker::noop()))
      .is_pending()
    {
      assert!(Instant::now() < deadline, "scope close timed out");
      std::thread::yield_now();
    }
    shutdown_with_deadline(runtime, AsyncShutdown::Drain);
  }

  #[test]
  fn pending_cancellation_without_a_tls_turn_cleans_up_before_exit() {
    let (shared, root) = shared_with_task_slots(1);
    let (task_ref, job) = spawn_pending(&shared, root);
    let (selected, task, permit) = take_poll(&shared);
    assert_eq!(selected, task_ref);
    let (result, permit) = task.poll(&mut Context::from_waker(Waker::noop()), permit);
    assert!(matches!(result, PollResult::Pending));
    shared.abort(task_ref);
    shared.close(false);
    drop(task);
    let context = AsyncThreadContext {
      role: super::super::thread_options::AsyncThreadRole::Worker,
      index: 0,
      physical_index: 0,
    };
    assert!(matches!(
      take_next(
        &shared,
        0,
        context,
        &mut None,
        None,
        Some(PendingFinish {
          task: task_ref,
          permit,
        })
      ),
      Work::Exit
    ));
    assert!(matches!(finish_job(job), Err(AsyncJoinError::Cancelled)));
    assert_eq!(shared.turn_counts(), (0, 0, 0, 0));
    assert_eq!(shared.lock().scopes[0].quota.active(), 0);
  }

  #[test]
  fn closed_runtime_finishes_pending_self_yields_with_a_deadline() {
    for mode in [AsyncShutdown::Drain, AsyncShutdown::CancelPending] {
      let runtime = strict_runtime(AsyncConfig {
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
              // Keep self-yielding through closure; Drain must finish these
              // through the merged path after admission closes.
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
  fn free_task_heap_reuses_the_lowest_completed_slot() {
    let (shared, root) = shared_with_task_slots(4);
    let jobs: Vec<_> = (0..4).map(|_| spawn_pending(&shared, root)).collect();
    let task_refs = jobs
      .iter()
      .map(|(task_ref, _)| *task_ref)
      .collect::<Vec<_>>();
    for task_ref in &task_refs {
      assert_eq!(poll_idle(&shared), *task_ref);
    }

    for index in [2, 0, 3, 1] {
      let task_ref = task_refs[index];
      shared.wake(task_ref);
      let (selected, task, permit) = take_poll(&shared);
      assert_eq!(selected, task_ref);
      finish_poll(&shared, selected, PollResult::Ready);
      drop(permit);
      drop(task);
      check_ready_lists(&shared, &shared.lock());
    }

    let (reused, job) = spawn_pending(&shared, root);
    assert_eq!(reused.index, 0);
    check_ready_lists(&shared, &shared.lock());
    drop(job);
    drop(jobs);
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
  fn running_wakes_use_the_word_and_requeue_once_at_finish() {
    let (shared, root) = shared_with_task_slots(2);
    let (task_ref, job) = spawn_pending(&shared, root);
    let (polled, task, permit) = take_poll(&shared);
    assert_eq!(polled, task_ref);
    assert_eq!(shared.poll_words[task_ref.index].flags(), (true, false));
    for _ in 0..3 {
      shared.wake(task_ref);
    }
    assert_eq!(shared.poll_words[task_ref.index].flags(), (true, true));
    assert!(
      !shared.lock().tasks[task_ref.index]
        .protocol
        .aborting_queued()
    );
    assert_eq!(shared.lock().scopes[0].ready_len, 0);
    finish_poll(&shared, task_ref, PollResult::Pending);
    drop(permit);
    drop(task);
    assert_eq!(shared.poll_words[task_ref.index].flags(), (false, false));
    assert_eq!(shared.lock().scopes[0].ready_len, 1);
    // Once queued, a wake takes the locked path and coalesces.
    shared.wake(task_ref);
    check_ready_lists(&shared, &shared.lock());
    assert_eq!(shared.lock().scopes[0].ready_len, 1);
    assert_eq!(poll_idle(&shared), task_ref);
    assert!(take(&shared).is_none());
    drop(job);
    finish(shared);
  }

  #[test]
  fn stale_generation_wake_of_a_running_reused_slot_is_inert() {
    let (shared, root) = shared_with_task_slots(1);
    let (old, old_job) = spawn_pending(&shared, root);
    assert_eq!(poll_idle(&shared), old);
    shared.abort(old);
    assert_eq!(cancel_next(&shared), old);
    drop(old_job);
    let (current, job) = spawn_pending(&shared, root);
    assert_eq!(current.index, old.index);
    assert_ne!(current.generation, old.generation);

    let (polled, task, permit) = take_poll(&shared);
    assert_eq!(polled, current);
    shared.wake(old);
    assert_eq!(shared.poll_words[current.index].flags(), (true, false));
    finish_poll(&shared, current, PollResult::Pending);
    assert!(take(&shared).is_none());
    shared.wake(old);
    assert!(take(&shared).is_none());
    drop((permit, task));

    // A truncated-tag alias can only cost the occupant one spurious poll.
    shared.wake(current);
    let (polled, task, permit) = take_poll(&shared);
    assert_eq!(polled, current);
    shared.wake(TaskRef {
      index: current.index,
      generation: current.generation.wrapping_add(1 << 62),
    });
    assert_eq!(shared.poll_words[current.index].flags(), (true, true));
    finish_poll(&shared, current, PollResult::Pending);
    drop((permit, task));
    assert_eq!(poll_idle(&shared), current);
    assert!(take(&shared).is_none());
    drop(job);
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
