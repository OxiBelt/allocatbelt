//! Owner-thread executor for local (`!Send`) futures, with a bounded
//! cross-thread submission handle for `Send` futures.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, ThreadId};

use super::entry::{BlockOnGuard, LocalExecutionGuard, TaskContextGuard};
use super::identity::{self, TaskId};
use super::join::{
  AbortAction, AbortMetadata, AsyncJob, AsyncJoinError, JoinState, abort_metadata_bytes,
  finished_flag_bytes, new_abort_metadata,
};
use super::protocol::{PollFinish, PollProtocol};
use super::task::{DomainCpuAdmission, drop_contained};
use crate::runtime::blocking::Handle as BlockingHandle;
use crate::runtime::cpu_execution::{CpuExecutionGuard, active_for_domain};
use crate::runtime::managed::ResourceScope;
use crate::runtime::resource_domain::{
  ControlCharge, DomainError, DomainReservation, DomainResource, DomainResources, DomainWaitPool,
  DomainWaiter, TenantDomain, payload_bytes,
};
use crate::runtime::time::{AutoAdvance, IdleCoordinator, IdleSignal, TimerHandle};

#[cfg(all(test, not(loom)))]
#[path = "local_tests.rs"]
mod tests;

/// Fixed bounds for a [`LocalRuntime`]. The implicit root scope counts toward
/// `max_scopes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalConfig {
  /// Maximum unfinished local tasks plus queued external submissions.
  pub max_outstanding: usize,
  /// Maximum simultaneously live local scopes, including the root scope.
  pub max_scopes: usize,
}

/// Construction, admission or owner-thread failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocalError {
  /// A required capacity is zero or could not be reserved.
  InvalidConfig,
  /// The shared outstanding-task bound is full.
  Full,
  /// The runtime or task scope is closed.
  Closed,
  /// A local-only operation ran off the runtime's owner thread.
  WrongThread,
  /// No scope slot is available.
  TooManyScopes,
  /// `block_on` was nested on this thread or called from a worker.
  BlockOnRejected,
  /// The process-wide task identifier space is exhausted.
  TaskIdExhausted,
  /// A bound global/tenant resource could not be admitted.
  ResourceDomain(DomainError),
}

impl fmt::Display for LocalError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::InvalidConfig => "invalid local runtime configuration",
      Self::Full => "local outstanding-task bound reached",
      Self::Closed => "local runtime or task scope is closed",
      Self::WrongThread => "local runtime used from a non-owner thread",
      Self::TooManyScopes => "local scope bound reached",
      Self::BlockOnRejected => "local block_on is nested or called from a worker",
      Self::TaskIdExhausted => "process-wide async task identifiers are exhausted",
      Self::ResourceDomain(_) => "local resource-domain admission failed",
    })
  }
}

impl std::error::Error for LocalError {}

fn control_error(error: DomainError, bound: bool) -> LocalError {
  if bound {
    LocalError::ResourceDomain(error)
  } else {
    LocalError::InvalidConfig
  }
}

/// A rejected local submission and its unchanged future.
pub struct LocalSpawnError<F> {
  /// Why the task was not admitted.
  pub kind: LocalError,
  future: F,
}

impl<F> LocalSpawnError<F> {
  fn new(kind: LocalError, future: F) -> Self {
    Self { kind, future }
  }

  /// Returns ownership of the future that was not admitted.
  #[must_use]
  pub fn into_future(self) -> F {
    self.future
  }
}

impl<F> fmt::Debug for LocalSpawnError<F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("LocalSpawnError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl<F> fmt::Display for LocalSpawnError<F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "local task rejected: {}", self.kind)
  }
}

impl<F> std::error::Error for LocalSpawnError<F> {}

struct AdmissionState {
  closed: bool,
  outstanding: usize,
}

struct AdmissionGate {
  maximum: usize,
  state: Mutex<AdmissionState>,
}

impl AdmissionGate {
  fn new(maximum: usize) -> Arc<Self> {
    Arc::new(Self {
      maximum,
      state: Mutex::new(AdmissionState {
        closed: false,
        outstanding: 0,
      }),
    })
  }

  fn lock(&self) -> MutexGuard<'_, AdmissionState> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }

  fn reserve(self: &Arc<Self>) -> Result<AdmissionPermit, LocalError> {
    let mut state = self.lock();
    self.reserve_locked(&mut state)
  }

  /// The caller keeps this gate locked while enqueueing, so close and
  /// submission have one linearization order.
  fn reserve_locked(
    self: &Arc<Self>,
    state: &mut AdmissionState,
  ) -> Result<AdmissionPermit, LocalError> {
    if state.closed {
      return Err(LocalError::Closed);
    }
    if state.outstanding == self.maximum {
      return Err(LocalError::Full);
    }
    state.outstanding += 1;
    Ok(AdmissionPermit(Arc::clone(self)))
  }

  fn close(&self) {
    self.lock().closed = true;
  }

  fn release(&self) {
    let mut state = self.lock();
    debug_assert!(state.outstanding > 0);
    if state.outstanding > 0 {
      state.outstanding -= 1;
    }
  }
}

struct AdmissionPermit(Arc<AdmissionGate>);

impl Drop for AdmissionPermit {
  fn drop(&mut self) {
    self.0.release();
  }
}

struct Notifier {
  signal: Arc<IdleSignal>,
  coordinator: Arc<IdleCoordinator>,
  _support_control: Arc<ControlCharge>,
}

impl Notifier {
  fn new(
    signal: Arc<IdleSignal>,
    coordinator: Arc<IdleCoordinator>,
    support_control: Arc<ControlCharge>,
  ) -> Arc<Self> {
    Arc::new(Self {
      signal,
      coordinator,
      _support_control: support_control,
    })
  }

  fn notify(&self) {
    self.coordinator.signal();
    self.unpark();
  }

  fn unpark(&self) {
    self.signal.notify();
  }

  fn park(&self) {
    self.signal.park();
  }
}

impl Wake for Notifier {
  fn wake(self: Arc<Self>) {
    self.notify();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.notify();
  }
}

struct LocalTaskAbort {
  control: Weak<Control>,
  notifier: Arc<Notifier>,
  task: TaskRef,
}

struct LocalAbortFlag {
  value: AtomicBool,
  _control: ControlCharge,
}

impl LocalAbortFlag {
  fn new(control: ControlCharge) -> Self {
    Self {
      value: AtomicBool::new(false),
      _control: control,
    }
  }

  fn load(&self, ordering: Ordering) -> bool {
    self.value.load(ordering)
  }

  fn store(&self, value: bool, ordering: Ordering) {
    self.value.store(value, ordering);
  }
}

struct LocalAbortTarget {
  task: Mutex<Option<TaskRef>>,
  _control: ControlCharge,
}

impl LocalAbortTarget {
  fn new(control: ControlCharge) -> Self {
    Self {
      task: Mutex::new(None),
      _control: control,
    }
  }

  fn load(&self) -> Option<TaskRef> {
    *self.task.lock().unwrap_or_else(PoisonError::into_inner)
  }

  fn store(&self, task: Option<TaskRef>) {
    *self.task.lock().unwrap_or_else(PoisonError::into_inner) = task;
  }
}

impl AbortAction for LocalTaskAbort {
  fn abort(&self) {
    if let Some(control) = self.control.upgrade() {
      let changed = self.notifier.coordinator.changed();
      let aborted = control.abort(self.task);
      drop(changed);
      if aborted {
        self.notifier.unpark();
      }
    }
  }
}

struct LocalSendAbort {
  abort: Arc<LocalAbortFlag>,
  target: Arc<LocalAbortTarget>,
  control: Weak<Control>,
  notifier: Arc<Notifier>,
}

impl AbortAction for LocalSendAbort {
  fn abort(&self) {
    let changed = self.notifier.coordinator.changed();
    self.abort.store(true, Ordering::Release);
    if let Some(task_ref) = self.target.load()
      && let Some(control) = self.control.upgrade()
    {
      let _ = control.abort(task_ref);
    }
    drop(changed);
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScopeRef {
  index: usize,
  generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TaskRef {
  index: usize,
  generation: u64,
}

struct TaskMeta {
  protocol: PollProtocol,
  scope: Option<ScopeRef>,
  next_ready: Option<TaskRef>,
}

struct ScopeMeta {
  generation: u64,
  occupied: bool,
  ready: bool,
  ready_head: Option<TaskRef>,
  ready_tail: Option<TaskRef>,
}

struct SchedulerState {
  closed: bool,
  tasks: Vec<TaskMeta>,
  free_tasks: Vec<usize>,
  scopes: Vec<ScopeMeta>,
  round_robin: VecDeque<ScopeRef>,
}

struct Control {
  state: Mutex<SchedulerState>,
  _control: ControlCharge,
}

impl Control {
  fn lock(&self) -> MutexGuard<'_, SchedulerState> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }

  fn new(
    max_outstanding: usize,
    max_scopes: usize,
    tenant: Option<&TenantDomain>,
  ) -> Result<(Arc<Self>, ScopeRef), LocalError> {
    let bound = tenant.is_some();
    let mut requested = std::mem::size_of::<Control>();
    for bytes in [
      payload_bytes::<TaskMeta>(max_outstanding).map_err(|error| control_error(error, bound))?,
      payload_bytes::<usize>(max_outstanding).map_err(|error| control_error(error, bound))?,
      payload_bytes::<ScopeMeta>(max_scopes).map_err(|error| control_error(error, bound))?,
      payload_bytes::<ScopeRef>(max_scopes).map_err(|error| control_error(error, bound))?,
    ] {
      requested = requested
        .checked_add(bytes)
        .ok_or_else(|| control_error(DomainError::Invalid, bound))?;
    }
    let mut control =
      ControlCharge::try_new(tenant, requested).map_err(|error| control_error(error, bound))?;
    let mut tasks = Vec::new();
    tasks
      .try_reserve_exact(max_outstanding)
      .map_err(|_| LocalError::InvalidConfig)?;
    tasks.resize_with(max_outstanding, || TaskMeta {
      protocol: PollProtocol::new(),
      scope: None,
      next_ready: None,
    });
    let mut free_tasks = Vec::new();
    free_tasks
      .try_reserve_exact(max_outstanding)
      .map_err(|_| LocalError::InvalidConfig)?;
    free_tasks.extend((0..max_outstanding).rev());
    let mut scopes = Vec::new();
    scopes
      .try_reserve_exact(max_scopes)
      .map_err(|_| LocalError::InvalidConfig)?;
    scopes.resize_with(max_scopes, || ScopeMeta {
      generation: 0,
      occupied: false,
      ready: false,
      ready_head: None,
      ready_tail: None,
    });
    let mut round_robin = VecDeque::new();
    round_robin
      .try_reserve_exact(max_scopes)
      .map_err(|_| LocalError::InvalidConfig)?;
    scopes[0] = ScopeMeta {
      generation: 1,
      occupied: true,
      ready: false,
      ready_head: None,
      ready_tail: None,
    };
    let root = ScopeRef {
      index: 0,
      generation: 1,
    };
    let mut actual = std::mem::size_of::<Control>();
    for bytes in [
      payload_bytes::<TaskMeta>(tasks.capacity()).map_err(|error| control_error(error, bound))?,
      payload_bytes::<usize>(free_tasks.capacity()).map_err(|error| control_error(error, bound))?,
      payload_bytes::<ScopeMeta>(scopes.capacity()).map_err(|error| control_error(error, bound))?,
      payload_bytes::<ScopeRef>(round_robin.capacity())
        .map_err(|error| control_error(error, bound))?,
    ] {
      actual = actual
        .checked_add(bytes)
        .ok_or_else(|| control_error(DomainError::Invalid, bound))?;
    }
    control
      .try_resize(actual)
      .map_err(|error| control_error(error, bound))?;
    Ok((
      Arc::new(Self {
        state: Mutex::new(SchedulerState {
          closed: false,
          tasks,
          free_tasks,
          scopes,
          round_robin,
        }),
        _control: control,
      }),
      root,
    ))
  }

  fn admit(&self, scope: ScopeRef) -> Result<TaskRef, LocalError> {
    let mut state = self.lock();
    if state.closed {
      return Err(LocalError::Closed);
    }
    let valid_scope = state
      .scopes
      .get(scope.index)
      .is_some_and(|slot| slot.occupied && slot.generation == scope.generation);
    if !valid_scope {
      return Err(LocalError::Closed);
    }
    let Some(index) = state.free_tasks.pop() else {
      return Err(LocalError::Full);
    };
    let Some(generation) = state.tasks[index].protocol.next_generation() else {
      state.free_tasks.push(index);
      return Err(LocalError::Full);
    };
    let task_ref = TaskRef { index, generation };
    state.tasks[index].protocol.admit(generation);
    state.tasks[index].scope = Some(scope);
    state.tasks[index].next_ready = None;
    if state.tasks[index].protocol.queue() {
      enqueue_ready(&mut state, task_ref);
    }
    Ok(task_ref)
  }

  fn admit_scope(&self) -> Result<ScopeRef, LocalError> {
    let mut state = self.lock();
    if state.closed {
      return Err(LocalError::Closed);
    }
    let Some(index) = state.scopes.iter().position(|slot| !slot.occupied) else {
      return Err(LocalError::TooManyScopes);
    };
    let Some(generation) = state.scopes[index].generation.checked_add(1) else {
      return Err(LocalError::TooManyScopes);
    };
    state.scopes[index] = ScopeMeta {
      generation,
      occupied: true,
      ready: false,
      ready_head: None,
      ready_tail: None,
    };
    Ok(ScopeRef { index, generation })
  }

  fn close_all(&self) {
    self.lock().closed = true;
  }

  fn wake(&self, task_ref: TaskRef) -> bool {
    let mut state = self.lock();
    let Some(task) = state.tasks.get_mut(task_ref.index) else {
      return false;
    };
    if !task.protocol.matches(task_ref.generation) {
      return false;
    }
    if task.protocol.wake() {
      enqueue_ready(&mut state, task_ref);
      true
    } else {
      false
    }
  }

  fn abort(&self, task_ref: TaskRef) -> bool {
    let mut state = self.lock();
    let Some(task) = state.tasks.get_mut(task_ref.index) else {
      return false;
    };
    if !task.protocol.matches(task_ref.generation) {
      return false;
    }
    if task.protocol.abort() {
      enqueue_ready(&mut state, task_ref);
      true
    } else {
      false
    }
  }

  fn abort_scope(&self, scope: ScopeRef) {
    let mut state = self.lock();
    for index in 0..state.tasks.len() {
      if state.tasks[index].scope == Some(scope) && state.tasks[index].protocol.admitted() {
        let queued = state.tasks[index].protocol.abort();
        let task_ref = TaskRef {
          index,
          generation: state.tasks[index].protocol.generation(),
        };
        if queued {
          enqueue_ready(&mut state, task_ref);
        }
      }
    }
  }

  fn close_scope(&self, scope: ScopeRef) {
    let mut state = self.lock();
    if let Some(slot) = state.scopes.get_mut(scope.index)
      && slot.generation == scope.generation
      && slot.occupied
    {
      // Called only after the final task cleanup, so the scope's ready queue
      // must be empty. The bounded round-robin queue also drops stale tokens
      // before this slot can be reused.
      slot.occupied = false;
      slot.ready = false;
      slot.ready_head = None;
      slot.ready_tail = None;
      state.round_robin.retain(|candidate| *candidate != scope);
    }
  }

  fn take_ready(&self) -> Option<(TaskRef, bool)> {
    let mut state = self.lock();
    while let Some(scope_ref) = state.round_robin.pop_front() {
      let Some(scope) = state.scopes.get_mut(scope_ref.index) else {
        continue;
      };
      if !scope.occupied || scope.generation != scope_ref.generation {
        continue;
      }
      scope.ready = false;
      let Some(task_ref) = scope.ready_head else {
        continue;
      };
      let next = state.tasks[task_ref.index].next_ready;
      state.scopes[scope_ref.index].ready_head = next;
      if next.is_none() {
        state.scopes[scope_ref.index].ready_tail = None;
      }
      state.tasks[task_ref.index].next_ready = None;
      if state.scopes[scope_ref.index].ready_head.is_some() {
        state.scopes[scope_ref.index].ready = true;
        state.round_robin.push_back(scope_ref);
      }
      let task = &mut state.tasks[task_ref.index];
      if !task.protocol.matches(task_ref.generation) {
        continue;
      }
      if let Some(aborting) = task.protocol.begin_poll() {
        return Some((task_ref, aborting));
      }
    }
    None
  }

  fn has_ready(&self) -> bool {
    !self.lock().round_robin.is_empty()
  }

  fn finish(&self, task_ref: TaskRef, ready: bool) -> PollFinish {
    let mut state = self.lock();
    let Some(task) = state.tasks.get_mut(task_ref.index) else {
      return PollFinish::Stale;
    };
    if !task.protocol.matches(task_ref.generation) {
      return PollFinish::Stale;
    }
    let result = task.protocol.finish_poll(ready, false);
    match result {
      PollFinish::Complete => {
        task.scope = None;
        task.next_ready = None;
        state.free_tasks.push(task_ref.index);
      }
      PollFinish::Requeue => {
        enqueue_ready(&mut state, task_ref);
      }
      PollFinish::CancelCleanup | PollFinish::Idle | PollFinish::Stale => {}
    }
    result
  }

  fn finish_cancel(&self, task_ref: TaskRef) -> Option<ScopeRef> {
    let mut state = self.lock();
    let task = state.tasks.get_mut(task_ref.index)?;
    if !task.protocol.matches(task_ref.generation) {
      return None;
    }
    task.protocol.finish_cancel();
    task.next_ready = None;
    let scope = task.scope.take();
    state.free_tasks.push(task_ref.index);
    scope
  }

  fn abandon(&self, task_ref: TaskRef) -> Option<ScopeRef> {
    self.finish_cancel(task_ref)
  }
}

fn enqueue_ready(state: &mut SchedulerState, task_ref: TaskRef) {
  let Some(scope_ref) = state.tasks.get(task_ref.index).and_then(|task| task.scope) else {
    return;
  };
  if !state
    .scopes
    .get(scope_ref.index)
    .is_some_and(|scope| scope.occupied && scope.generation == scope_ref.generation)
  {
    return;
  }
  let was_ready = state.scopes[scope_ref.index].ready;
  let previous_tail = state.scopes[scope_ref.index].ready_tail;
  if let Some(previous_tail) = previous_tail {
    state.tasks[previous_tail.index].next_ready = Some(task_ref);
  } else {
    state.scopes[scope_ref.index].ready_head = Some(task_ref);
  }
  state.scopes[scope_ref.index].ready_tail = Some(task_ref);
  if !was_ready {
    state.scopes[scope_ref.index].ready = true;
    state.round_robin.push_back(scope_ref);
  }
}

struct LocalTaskWake {
  control: Weak<Control>,
  task: TaskRef,
  notifier: Arc<Notifier>,
  _control: ControlCharge,
}

impl Wake for LocalTaskWake {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    if let Some(control) = self.control.upgrade() {
      let changed = self.notifier.coordinator.changed();
      let woke = control.wake(self.task);
      drop(changed);
      if woke {
        self.notifier.unpark();
      }
    }
  }
}

struct ScopeCell {
  reference: ScopeRef,
  resources: Option<ResourceScope>,
  tenant: Option<TenantDomain>,
  task_waiters: Option<DomainWaitPool>,
  root_waiters: Option<DomainWaitPool>,
  active: Cell<usize>,
  closed: Cell<bool>,
  reclaimed: Cell<bool>,
  completion: RefCell<Option<Waker>>,
  _control: ControlCharge,
}

impl ScopeCell {
  fn new(
    reference: ScopeRef,
    resources: Option<ResourceScope>,
    task_waiters: Option<DomainWaitPool>,
    root_waiters: Option<DomainWaitPool>,
    control: ControlCharge,
  ) -> Rc<Self> {
    let tenant = resources
      .as_ref()
      .and_then(ResourceScope::tenant_domain)
      .cloned();
    Rc::new(Self {
      reference,
      resources,
      tenant,
      task_waiters,
      root_waiters,
      active: Cell::new(0),
      closed: Cell::new(false),
      reclaimed: Cell::new(reference.index == 0),
      completion: RefCell::new(None),
      _control: control,
    })
  }

  fn add_task(&self) {
    self.active.set(self.active.get() + 1);
  }

  fn complete(&self, control: &Control) {
    let active = self.active.get();
    debug_assert!(active > 0);
    let remaining = active - 1;
    self.active.set(remaining);
    if remaining == 0 && self.closed.get() {
      control.close_scope(self.reference);
      self.reclaimed.set(true);
      let waker = self.completion.borrow_mut().take();
      if let Some(waker) = waker
        && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
      {
        drop_contained(payload);
      }
    }
  }

  fn is_ready(&self) -> bool {
    self.active.get() == 0 && self.reclaimed.get()
  }
}

struct LocalTaskSlot {
  generation: u64,
  scope: ScopeRef,
  abort: Arc<LocalAbortFlag>,
  task: Option<Box<dyn LocalTask>>,
}

struct LocalCore {
  owner: ThreadId,
  gate: Arc<AdmissionGate>,
  control: Arc<Control>,
  tasks: RefCell<Vec<Option<LocalTaskSlot>>>,
  scopes: RefCell<Vec<Option<Rc<ScopeCell>>>>,
  notifier: Arc<Notifier>,
  coordinator: Arc<IdleCoordinator>,
  _support_control: Arc<ControlCharge>,
  _control: ControlCharge,
  _not_send: PhantomData<Rc<()>>,
}

impl LocalCore {
  fn root_admission(
    &self,
    scope_ref: ScopeRef,
    frame_bytes: usize,
  ) -> Result<LocalRootAdmission, LocalError> {
    let scope = self.scope_cell(scope_ref).ok_or(LocalError::Closed)?;
    let control_bytes = frame_bytes
      .checked_add(std::mem::size_of::<LocalRootAdmission>())
      .ok_or(LocalError::ResourceDomain(DomainError::Invalid))?;
    let Some(tenant) = scope.tenant.clone() else {
      return Ok(LocalRootAdmission {
        tenant: None,
        waiter: None,
        _task_admission: None,
        _control: ControlCharge::unbounded(control_bytes),
      });
    };
    tenant
      .validate_cpu_execution()
      .map_err(LocalError::ResourceDomain)?;
    let waiter = scope
      .root_waiters
      .as_ref()
      .ok_or(DomainError::WaitersFull)
      .and_then(DomainWaitPool::try_lease)
      .map_err(LocalError::ResourceDomain)?;
    let request = DomainResources::ZERO
      .with(DomainResource::Tasks, 1)
      .with(DomainResource::Control, control_bytes);
    let mut combined = tenant
      .try_acquire(request)
      .map_err(LocalError::ResourceDomain)?;
    let task_admission = combined
      .split_off(DomainResources::ZERO.with(DomainResource::Tasks, 1))
      .map_err(LocalError::ResourceDomain)?;
    let control = ControlCharge::from_ticket(Some(&tenant), combined, control_bytes);
    Ok(LocalRootAdmission {
      tenant: Some(tenant),
      waiter: Some(waiter),
      _task_admission: Some(task_admission),
      _control: control,
    })
  }

  fn check_owner(&self) -> Result<(), LocalError> {
    if thread::current().id() == self.owner {
      Ok(())
    } else {
      Err(LocalError::WrongThread)
    }
  }

  fn scope_cell(&self, scope: ScopeRef) -> Option<Rc<ScopeCell>> {
    self
      .scopes
      .borrow()
      .get(scope.index)
      .and_then(Option::as_ref)
      .filter(|cell| cell.reference.generation == scope.generation)
      .cloned()
  }

  fn insert_task(
    &self,
    task_ref: TaskRef,
    scope: Rc<ScopeCell>,
    abort: Arc<LocalAbortFlag>,
    task: Box<dyn LocalTask>,
  ) {
    scope.add_task();
    let mut tasks = self.tasks.borrow_mut();
    debug_assert!(tasks[task_ref.index].is_none());
    tasks[task_ref.index] = Some(LocalTaskSlot {
      generation: task_ref.generation,
      scope: scope.reference,
      abort,
      task: Some(task),
    });
  }

  fn abort_action(&self, task_ref: TaskRef) -> LocalTaskAbort {
    LocalTaskAbort {
      control: Arc::downgrade(&self.control),
      notifier: Arc::clone(&self.notifier),
      task: task_ref,
    }
  }

  fn take_task(&self, task_ref: TaskRef) -> Option<LocalTaskSlot> {
    let mut tasks = self.tasks.borrow_mut();
    let entry = tasks.get_mut(task_ref.index)?;
    if !entry
      .as_ref()
      .is_some_and(|slot| slot.generation == task_ref.generation)
    {
      return None;
    }
    entry.take()
  }

  fn restore_task(&self, task_ref: TaskRef, slot: LocalTaskSlot) {
    let mut tasks = self.tasks.borrow_mut();
    debug_assert!(tasks[task_ref.index].is_none());
    tasks[task_ref.index] = Some(slot);
  }

  fn complete_scope(&self, scope_ref: ScopeRef) {
    if let Some(scope) = self.scope_cell(scope_ref) {
      scope.complete(&self.control);
      if scope.reference.index != 0 && scope.is_ready() {
        let mut scopes = self.scopes.borrow_mut();
        if scopes[scope_ref.index]
          .as_ref()
          .is_some_and(|current| Rc::ptr_eq(current, &scope))
        {
          scopes[scope_ref.index] = None;
        }
      }
    }
  }

  fn request_scope_close(&self, scope: &Rc<ScopeCell>) {
    self.begin_scope_close(scope);
    self.finish_scope_close(scope);
  }

  fn begin_scope_close(&self, scope: &Rc<ScopeCell>) {
    if !scope.closed.replace(true) {
      self.control.abort_scope(scope.reference);
      self.notifier.notify();
    }
  }

  fn finish_scope_close(&self, scope: &Rc<ScopeCell>) {
    if scope.closed.get() && scope.active.get() == 0 && !scope.reclaimed.replace(true) {
      self.control.close_scope(scope.reference);
      let waker = scope.completion.borrow_mut().take();
      if let Some(waker) = waker
        && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
      {
        drop_contained(payload);
      }
      if scope.reference.index != 0 {
        let mut scopes = self.scopes.borrow_mut();
        if scopes[scope.reference.index]
          .as_ref()
          .is_some_and(|current| Rc::ptr_eq(current, scope))
        {
          scopes[scope.reference.index] = None;
        }
      }
    }
  }
}

struct LocalRootAdmission {
  tenant: Option<TenantDomain>,
  waiter: Option<DomainWaiter>,
  _task_admission: Option<DomainReservation>,
  _control: ControlCharge,
}

struct LocalTaskAdmission {
  task: Option<DomainReservation>,
  task_control: ControlCharge,
  join_control: ControlCharge,
  abort_control: ControlCharge,
  finished_control: ControlCharge,
  abort_flag_control: ControlCharge,
  abort_target_control: ControlCharge,
  request_control: ControlCharge,
}

fn reserve_local_task_admission<F, A>(
  tenant: Option<&TenantDomain>,
  request_bytes: usize,
  external_abort_target: bool,
) -> Result<LocalTaskAdmission, DomainError>
where
  F: Future + 'static,
  F::Output: 'static,
  A: AbortAction,
{
  let task_control_bytes = std::mem::size_of::<Task<F>>()
    .checked_add(std::mem::size_of::<F>())
    .ok_or(DomainError::Invalid)?;
  let join_control_bytes = std::mem::size_of::<JoinState<F::Output>>();
  let abort_control_bytes = abort_metadata_bytes::<A>();
  let finished_control_bytes = finished_flag_bytes();
  let abort_flag_control_bytes = std::mem::size_of::<LocalAbortFlag>();
  let abort_target_control_bytes = if external_abort_target {
    std::mem::size_of::<LocalAbortTarget>()
  } else {
    0
  };
  let all_control_bytes = task_control_bytes
    .checked_add(join_control_bytes)
    .and_then(|bytes| bytes.checked_add(abort_control_bytes))
    .and_then(|bytes| bytes.checked_add(finished_control_bytes))
    .and_then(|bytes| bytes.checked_add(abort_flag_control_bytes))
    .and_then(|bytes| bytes.checked_add(abort_target_control_bytes))
    .and_then(|bytes| bytes.checked_add(request_bytes))
    .ok_or(DomainError::Invalid)?;
  let (task, mut control) = if let Some(tenant) = tenant {
    let request = DomainResources::ZERO
      .with(DomainResource::Tasks, 1)
      .with(DomainResource::Control, all_control_bytes);
    let mut combined = tenant.try_acquire(request)?;
    let task = combined.split_off(DomainResources::ZERO.with(DomainResource::Tasks, 1))?;
    (
      Some(task),
      ControlCharge::from_ticket(Some(tenant), combined, all_control_bytes),
    )
  } else {
    (None, ControlCharge::unbounded(all_control_bytes))
  };
  let task_control = control.split_off(task_control_bytes)?;
  let join_control = control.split_off(join_control_bytes)?;
  let abort_control = control.split_off(abort_control_bytes)?;
  let finished_control = control.split_off(finished_control_bytes)?;
  let abort_flag_control = control.split_off(abort_flag_control_bytes)?;
  let abort_target_control = control.split_off(abort_target_control_bytes)?;
  let request_control = control;
  Ok(LocalTaskAdmission {
    task,
    task_control,
    join_control,
    abort_control,
    finished_control,
    abort_flag_control,
    abort_target_control,
    request_control,
  })
}

trait LocalTask {
  fn poll(&mut self, context: &mut Context<'_>, cpu_ticket: Option<DomainReservation>) -> Poll<()>;
  fn cancel(&mut self);
  fn acquire_cpu(&mut self, waker: &Waker) -> DomainCpuAdmission;
  fn tenant_domain(&self) -> Option<&TenantDomain>;
  fn fail_resource(&mut self, error: DomainError);
  fn release_admission(&mut self);
  fn complete_scope(&mut self, core: &LocalCore);
  fn publish(&mut self);
}

struct Task<F: Future + 'static> {
  future: Option<Pin<Box<F>>>,
  staged: Option<Result<F::Output, AsyncJoinError>>,
  join: Arc<JoinState<F::Output>>,
  id: TaskId,
  admission: Option<AdmissionPermit>,
  tenant: Option<TenantDomain>,
  waiter: Option<DomainWaiter>,
  task_admission: Option<DomainReservation>,
  scope: Rc<ScopeCell>,
  resources: Option<ResourceScope>,
  _abort_metadata: Arc<dyn AbortMetadata>,
  task_control: Option<ControlCharge>,
}

impl<F: Future + 'static> Task<F> {
  fn drop_future(&mut self) -> Option<Box<dyn Any + Send>> {
    let future = self.future.take();
    let panic = panic::catch_unwind(AssertUnwindSafe(|| drop(future))).err();
    self.release_future_control();
    panic
  }

  fn release_future_control(&mut self) {
    if let Some(control) = &mut self.task_control {
      let result = control.try_resize(std::mem::size_of::<Self>());
      debug_assert!(
        result.is_ok(),
        "released local future Control charge failed"
      );
    }
  }
}

impl<F: Future + 'static> LocalTask for Task<F> {
  fn poll(&mut self, context: &mut Context<'_>, cpu_ticket: Option<DomainReservation>) -> Poll<()> {
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(self.id), self.resources.clone());
    let Some(mut future) = self.future.take() else {
      return Poll::Ready(());
    };
    let _cpu_execution =
      CpuExecutionGuard::enter(cpu_ticket.as_ref().map(DomainReservation::domain_identity));
    let result = {
      let _cooperative_poll = super::entry::CooperativePollGuard::enter();
      panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context)))
    };
    drop(_cpu_execution);
    drop(cpu_ticket);
    match result {
      Ok(Poll::Pending) => {
        self.future = Some(future);
        Poll::Pending
      }
      Ok(Poll::Ready(output)) => {
        if let Some(payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(future))).err() {
          drop_contained(output);
          self.staged = Some(Err(AsyncJoinError::Panicked(payload)));
        } else {
          self.staged = Some(Ok(output));
        }
        self.release_future_control();
        Poll::Ready(())
      }
      Err(payload) => {
        if let Err(cleanup) = panic::catch_unwind(AssertUnwindSafe(|| drop(future))) {
          drop_contained(cleanup);
        }
        self.release_future_control();
        self.staged = Some(Err(AsyncJoinError::Panicked(payload)));
        Poll::Ready(())
      }
    }
  }

  fn cancel(&mut self) {
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(self.id), self.resources.clone());
    let outcome = match self.drop_future() {
      Some(payload) => Err(AsyncJoinError::Panicked(payload)),
      None => Err(AsyncJoinError::Cancelled),
    };
    self.staged = Some(outcome);
    if let Some(waiter) = &self.waiter {
      waiter.cancel_wait();
    }
  }

  fn acquire_cpu(&mut self, waker: &Waker) -> DomainCpuAdmission {
    let Some(tenant) = &self.tenant else {
      return DomainCpuAdmission::Unbounded;
    };
    let Some(waiter) = &self.waiter else {
      return DomainCpuAdmission::Rejected(DomainError::WaitersFull);
    };
    match waiter.try_acquire_or_register(tenant, waker) {
      Ok(Some(ticket)) => DomainCpuAdmission::Acquired(ticket),
      Ok(None) => DomainCpuAdmission::Waiting,
      Err(error) => DomainCpuAdmission::Rejected(error),
    }
  }

  fn tenant_domain(&self) -> Option<&TenantDomain> {
    self.tenant.as_ref()
  }

  fn fail_resource(&mut self, error: DomainError) {
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(self.id), self.resources.clone());
    let outcome = match self.drop_future() {
      Some(payload) => Err(AsyncJoinError::Panicked(payload)),
      None => Err(AsyncJoinError::ResourceDomain(error)),
    };
    self.staged = Some(outcome);
    if let Some(waiter) = &self.waiter {
      waiter.cancel_wait();
    }
  }

  fn release_admission(&mut self) {
    if let Some(waiter) = self.waiter.take() {
      drop(waiter);
    }
    drop(self.task_admission.take());
    drop(self.admission.take());
  }

  fn complete_scope(&mut self, core: &LocalCore) {
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(self.id), self.resources.clone());
    core.complete_scope(self.scope.reference);
  }

  fn publish(&mut self) {
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(self.id), self.resources.clone());
    if let Some(outcome) = self.staged.take()
      && let Some(unclaimed) = self.join.publish(outcome)
    {
      drop_contained(unclaimed);
    }
  }
}

trait ExternalRequest: Send {
  fn import(self: Box<Self>, core: &LocalCore, task_ref: TaskRef, scope: Rc<ScopeCell>);
  fn cancel_on_owner(self: Box<Self>);
  fn reject(self: Box<Self>) -> Box<dyn Any + Send>;
}

struct SendRequest<F: Future + Send + 'static>
where
  F::Output: Send + 'static,
{
  future: F,
  id: TaskId,
  join: Arc<JoinState<F::Output>>,
  abort: Arc<LocalAbortFlag>,
  abort_target: Arc<LocalAbortTarget>,
  admission: AdmissionPermit,
  resources: Option<ResourceScope>,
  tenant: Option<TenantDomain>,
  waiter: Option<DomainWaiter>,
  task_admission: Option<DomainReservation>,
  task_control: ControlCharge,
  abort_metadata: Arc<dyn AbortMetadata>,
  _request_control: ControlCharge,
}

impl<F> ExternalRequest for SendRequest<F>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  fn import(self: Box<Self>, core: &LocalCore, task_ref: TaskRef, scope: Rc<ScopeCell>) {
    let Self {
      future,
      id,
      join,
      abort,
      abort_target,
      admission,
      resources: _,
      tenant,
      waiter,
      task_admission,
      task_control,
      abort_metadata,
      _request_control,
    } = *self;
    let task = Task {
      future: Some(Box::pin(future)),
      staged: None,
      join,
      id,
      admission: Some(admission),
      tenant,
      waiter,
      task_admission,
      resources: scope.resources.clone(),
      scope: Rc::clone(&scope),
      _abort_metadata: abort_metadata,
      task_control: Some(task_control),
    };
    drop(_request_control);
    core.insert_task(task_ref, scope, Arc::clone(&abort), Box::new(task));
    abort_target.store(Some(task_ref));
    if abort.load(Ordering::Acquire) {
      let _ = core.control.abort(task_ref);
      core.notifier.notify();
    }
  }

  fn cancel_on_owner(self: Box<Self>) {
    let Self {
      future,
      id,
      join,
      abort: _,
      abort_target: _,
      admission,
      resources,
      tenant: _,
      waiter,
      task_admission,
      task_control,
      abort_metadata: _,
      _request_control,
    } = *self;
    let _task_context = TaskContextGuard::enter_with_resource(Some(id), resources);
    let outcome = match panic::catch_unwind(AssertUnwindSafe(|| drop(future))) {
      Ok(()) => Err(AsyncJoinError::Cancelled),
      Err(payload) => Err(AsyncJoinError::Panicked(payload)),
    };
    drop(waiter);
    drop(task_admission);
    drop(task_control);
    drop(admission);
    if let Some(unclaimed) = join.publish(outcome) {
      drop_contained(unclaimed);
    }
  }

  fn reject(self: Box<Self>) -> Box<dyn Any + Send> {
    let Self {
      future,
      id: _,
      join: _,
      abort: _,
      abort_target: _,
      admission,
      resources: _,
      tenant: _,
      waiter,
      task_admission,
      task_control,
      abort_metadata: _,
      _request_control,
    } = *self;
    drop(waiter);
    drop(task_admission);
    drop(task_control);
    drop(admission);
    Box::new(future)
  }
}

/// An owner-thread executor for owned local futures. Its tasks, outputs,
/// handles and scopes cannot cross threads. A separate [`LocalSendHandle`]
/// permits bounded cross-thread submission of `Send` futures.
///
/// ```compile_fail
/// use allocatbelt::runtime::asynchronous::LocalRuntime;
/// fn require_send<T: Send>() {}
/// require_send::<LocalRuntime>();
/// ```
pub struct LocalRuntime {
  core: Rc<LocalCore>,
  sender: SyncSender<Box<dyn ExternalRequest>>,
  receiver: Receiver<Box<dyn ExternalRequest>>,
  root_scope: ScopeRef,
  root_cell: Rc<ScopeCell>,
  idle_clock: Option<IdleClock>,
  closed: bool,
  shutdown_complete: bool,
  _not_send: PhantomData<Rc<()>>,
  _control: ControlCharge,
  _channel_control: Arc<ControlCharge>,
  _support_control: Arc<ControlCharge>,
}

struct IdleClock {
  timer: TimerHandle,
  blocking: Option<BlockingHandle>,
}

enum IdleStep {
  Retry,
  Park,
  Advanced,
}

impl LocalRuntime {
  /// Allocates all bounded task and scope tables before exposing handles.
  pub fn new(config: LocalConfig) -> Result<Self, LocalError> {
    Self::build(config, None)
  }

  /// Creates a local runtime whose existing implicit root scope uses the
  /// supplied resource ledger for root polls and root tasks. The root binding
  /// does not consume an additional scope slot.
  pub(in crate::runtime) fn with_resources(
    config: LocalConfig,
    resources: ResourceScope,
  ) -> Result<Self, LocalError> {
    Self::build(config, Some(resources))
  }

  fn build(config: LocalConfig, resources: Option<ResourceScope>) -> Result<Self, LocalError> {
    if config.max_outstanding == 0 || config.max_scopes == 0 {
      return Err(LocalError::InvalidConfig);
    }
    let tenant = resources.as_ref().and_then(ResourceScope::tenant_domain);
    let bound = tenant.is_some();
    if let Some(tenant) = tenant {
      tenant
        .validate_cpu_execution()
        .map_err(LocalError::ResourceDomain)?;
    }

    let runtime_control = ControlCharge::try_new(tenant, std::mem::size_of::<LocalRuntime>())
      .map_err(|error| control_error(error, bound))?;
    let channel_payload = payload_bytes::<Box<dyn ExternalRequest>>(config.max_outstanding)
      .map_err(|error| control_error(error, bound))?;
    let channel_bytes = std::mem::size_of::<ControlCharge>()
      .checked_add(channel_payload)
      .ok_or_else(|| control_error(DomainError::Invalid, bound))?;
    let channel_control = Arc::new(
      ControlCharge::try_new(tenant, channel_bytes).map_err(|error| control_error(error, bound))?,
    );
    let support_bytes = [
      std::mem::size_of::<ControlCharge>(),
      std::mem::size_of::<AdmissionGate>(),
      std::mem::size_of::<Notifier>(),
      std::mem::size_of::<IdleSignal>(),
      std::mem::size_of::<IdleCoordinator>(),
    ]
    .into_iter()
    .try_fold(0_usize, usize::checked_add)
    .ok_or_else(|| control_error(DomainError::Invalid, bound))?;
    let support_control = Arc::new(
      ControlCharge::try_new(tenant, support_bytes).map_err(|error| control_error(error, bound))?,
    );
    let scope_bytes = std::mem::size_of::<ScopeCell>();
    let root_scope_control =
      ControlCharge::try_new(tenant, scope_bytes).map_err(|error| control_error(error, bound))?;
    let (task_waiters, root_waiters) = if let Some(tenant) = tenant {
      let task_waiters = tenant
        .reserve_waiters(config.max_outstanding)
        .map_err(LocalError::ResourceDomain)?;
      let root_waiters = tenant
        .reserve_waiters(1)
        .map_err(LocalError::ResourceDomain)?;
      (Some(task_waiters), Some(root_waiters))
    } else {
      (None, None)
    };
    let (control, root_scope) = Control::new(config.max_outstanding, config.max_scopes, tenant)?;
    let gate = AdmissionGate::new(config.max_outstanding);
    let (sender, receiver) = mpsc::sync_channel(config.max_outstanding);
    let mut core_bytes = std::mem::size_of::<LocalCore>();
    for bytes in [
      payload_bytes::<Option<LocalTaskSlot>>(config.max_outstanding)
        .map_err(|error| control_error(error, bound))?,
      payload_bytes::<Option<Rc<ScopeCell>>>(config.max_scopes)
        .map_err(|error| control_error(error, bound))?,
    ] {
      core_bytes = core_bytes
        .checked_add(bytes)
        .ok_or_else(|| control_error(DomainError::Invalid, bound))?;
    }
    let mut core_control =
      ControlCharge::try_new(tenant, core_bytes).map_err(|error| control_error(error, bound))?;
    let mut tasks = Vec::new();
    tasks
      .try_reserve_exact(config.max_outstanding)
      .map_err(|_| LocalError::InvalidConfig)?;
    tasks.resize_with(config.max_outstanding, || None);
    let mut scopes = Vec::new();
    scopes
      .try_reserve_exact(config.max_scopes)
      .map_err(|_| LocalError::InvalidConfig)?;
    scopes.resize_with(config.max_scopes, || None);
    let actual_core_bytes = std::mem::size_of::<LocalCore>()
      .checked_add(
        payload_bytes::<Option<LocalTaskSlot>>(tasks.capacity())
          .map_err(|error| control_error(error, bound))?,
      )
      .and_then(|bytes| {
        payload_bytes::<Option<Rc<ScopeCell>>>(scopes.capacity())
          .ok()
          .and_then(|scope_bytes| bytes.checked_add(scope_bytes))
      })
      .ok_or_else(|| control_error(DomainError::Invalid, bound))?;
    core_control
      .try_resize(actual_core_bytes)
      .map_err(|error| control_error(error, bound))?;
    let root = ScopeCell::new(
      root_scope,
      resources,
      task_waiters,
      root_waiters,
      root_scope_control,
    );
    scopes[0] = Some(Rc::clone(&root));
    let owner = thread::current();
    let signal = IdleSignal::new(owner.clone());
    let coordinator = IdleCoordinator::new(Some(Arc::clone(&signal)));
    let notifier = Notifier::new(
      signal,
      Arc::clone(&coordinator),
      Arc::clone(&support_control),
    );
    Ok(Self {
      core: Rc::new(LocalCore {
        owner: owner.id(),
        gate,
        control,
        tasks: RefCell::new(tasks),
        scopes: RefCell::new(scopes),
        notifier,
        coordinator,
        _support_control: Arc::clone(&support_control),
        _control: core_control,
        _not_send: PhantomData,
      }),
      sender,
      receiver,
      root_scope,
      root_cell: root,
      idle_clock: None,
      closed: false,
      shutdown_complete: false,
      _not_send: PhantomData,
      _control: runtime_control,
      _channel_control: channel_control,
      _support_control: support_control,
    })
  }

  /// Returns a local handle for the implicit root scope.
  #[must_use]
  pub fn handle(&self) -> LocalHandle {
    LocalHandle {
      core: Rc::clone(&self.core),
      scope: self.root_scope,
      _scope_owner: Some(Rc::clone(&self.root_cell)),
      _not_send: PhantomData,
    }
  }

  pub(crate) fn idle_coordinator(&self) -> Arc<IdleCoordinator> {
    Arc::clone(&self.core.coordinator)
  }

  pub(crate) fn attach_idle_clock(&mut self, timer: TimerHandle, blocking: Option<BlockingHandle>) {
    debug_assert!(Arc::ptr_eq(&self.core.coordinator, timer.coordinator()));
    self.idle_clock = Some(IdleClock { timer, blocking });
  }

  /// Returns a cross-thread handle that accepts only `Send` futures and
  /// outputs. Its admissions share `max_outstanding` with local tasks and use
  /// the implicit root scope. Its futures use this runtime's explicitly bound
  /// root ledger when imported or cleaned up; the submitting thread's context
  /// is never inherited.
  #[must_use]
  pub fn send_handle(&self) -> LocalSendHandle {
    let root = self.core.scope_cell(self.root_scope);
    LocalSendHandle {
      sender: self.sender.clone(),
      gate: Arc::clone(&self.core.gate),
      notifier: Arc::clone(&self.core.notifier),
      control: Arc::clone(&self.core.control),
      resources: root.as_ref().and_then(|scope| scope.resources.clone()),
      tenant: root.as_ref().and_then(|scope| scope.tenant.clone()),
      task_waiters: root.and_then(|scope| scope.task_waiters.clone()),
      _channel_control: Arc::clone(&self._channel_control),
      _support_control: Arc::clone(&self._support_control),
    }
  }

  /// Creates an independently cancellable owner-thread scope.
  pub fn scope(&self) -> Result<LocalTaskScope, LocalError> {
    self.create_scope(None)
  }

  /// Creates a local task scope whose futures and runtime-owned cleanup can
  /// explicitly access `resources` through `current_resource_scope`. Only
  /// managed buffers and operation permits are charged.
  pub fn scope_with_resources(
    &self,
    resources: &ResourceScope,
  ) -> Result<LocalTaskScope, LocalError> {
    self.create_scope(Some(resources.clone()))
  }

  fn create_scope(&self, resources: Option<ResourceScope>) -> Result<LocalTaskScope, LocalError> {
    self.core.check_owner()?;
    let root = self
      .core
      .scope_cell(self.root_scope)
      .ok_or(LocalError::Closed)?;
    let (resources, task_waiters, root_waiters) = match root.tenant.as_ref() {
      Some(root_tenant) => {
        let resources = match resources {
          Some(resources) => {
            let Some(tenant) = resources.tenant_domain() else {
              return Err(LocalError::ResourceDomain(DomainError::Invalid));
            };
            if !root_tenant.same_domain(tenant) {
              return Err(LocalError::ResourceDomain(DomainError::Invalid));
            }
            tenant
              .validate_cpu_execution()
              .map_err(LocalError::ResourceDomain)?;
            Some(resources)
          }
          None => root.resources.clone(),
        };
        (
          resources,
          root.task_waiters.clone(),
          root.root_waiters.clone(),
        )
      }
      None => (resources, None, None),
    };
    let tenant = resources.as_ref().and_then(ResourceScope::tenant_domain);
    let makes_wait_pools = root.tenant.is_none() && tenant.is_some();
    let scope_bytes = std::mem::size_of::<ScopeCell>();
    let control = ControlCharge::try_new(tenant, scope_bytes)
      .map_err(|error| control_error(error, tenant.is_some()))?;
    let (task_waiters, root_waiters) = if makes_wait_pools {
      let tenant = tenant.ok_or(LocalError::ResourceDomain(DomainError::Invalid))?;
      tenant
        .validate_cpu_execution()
        .map_err(LocalError::ResourceDomain)?;
      let task_waiters = tenant
        .reserve_waiters(self.core.tasks.borrow().len())
        .map_err(LocalError::ResourceDomain)?;
      let root_waiters = tenant
        .reserve_waiters(1)
        .map_err(LocalError::ResourceDomain)?;
      (Some(task_waiters), Some(root_waiters))
    } else {
      (task_waiters, root_waiters)
    };
    let reference = self.core.control.admit_scope()?;
    let cell = ScopeCell::new(reference, resources, task_waiters, root_waiters, control);
    self.core.scopes.borrow_mut()[reference.index] = Some(Rc::clone(&cell));
    Ok(LocalTaskScope {
      handle: LocalHandle {
        core: Rc::clone(&self.core),
        scope: reference,
        _scope_owner: Some(Rc::clone(&cell)),
        _not_send: PhantomData,
      },
      cell,
      closed: false,
    })
  }

  /// Polls a caller-owned root future and runs ready local tasks one poll turn
  /// at a time until the root completes. The root may borrow data and need not
  /// be `Send`; spawned local futures must be `'static`. The borrowed runtime
  /// root has no task ID. If this runtime was created by the owning facade,
  /// its configured resource ledger is bound for the duration of the root
  /// poll and restored on return or unwind.
  pub fn block_on<F: Future>(&mut self, future: F) -> Result<F::Output, LocalError> {
    self.core.check_owner()?;
    if self.closed {
      return Err(LocalError::Closed);
    }
    let _block_on = BlockOnGuard::enter().map_err(|_| LocalError::BlockOnRejected)?;
    let root_admission = self
      .core
      .root_admission(self.root_scope, std::mem::size_of::<F>())?;
    let _local_execution = LocalExecutionGuard::enter();
    let root_resources = self
      .core
      .scope_cell(self.root_scope)
      .and_then(|scope| scope.resources.clone());
    let _task_context = match root_resources {
      Some(resources) => TaskContextGuard::enter_with_resource(None, Some(resources)),
      None => TaskContextGuard::enter(None),
    };
    let _context = LocalEnterGuard::enter(&self.handle());
    let root_waker = Waker::from(Arc::clone(&self.core.notifier));
    let mut context = Context::from_waker(&root_waker);
    let mut future = Box::pin(future);
    loop {
      let poll_epoch = self.core.coordinator.epoch();
      let cpu_ticket = match (&root_admission.tenant, &root_admission.waiter) {
        (Some(tenant), Some(waiter)) => {
          match waiter
            .try_acquire_or_register(tenant, &root_waker)
            .map_err(LocalError::ResourceDomain)?
          {
            Some(ticket) => Some(ticket),
            None if active_for_domain(&tenant.domain_identity()) => {
              waiter.cancel_wait();
              return Err(LocalError::ResourceDomain(DomainError::Exhausted(
                DomainResource::Cpu,
              )));
            }
            None => None,
          }
        }
        (None, None) => None,
        _ => return Err(LocalError::ResourceDomain(DomainError::WaitersFull)),
      };
      let root_unbounded = root_admission.tenant.is_none();
      if root_unbounded || cpu_ticket.is_some() {
        super::entry::reset_budget();
        let poll = {
          let _cpu_execution =
            CpuExecutionGuard::enter(cpu_ticket.as_ref().map(DomainReservation::domain_identity));
          let _cooperative_poll = super::entry::CooperativePollGuard::enter();
          let poll = future.as_mut().poll(&mut context);
          drop(_cooperative_poll);
          drop(_cpu_execution);
          poll
        };
        drop(cpu_ticket);
        if let Poll::Ready(output) = poll {
          return Ok(output);
        }
      }
      self.import_external();
      if let Some((task_ref, aborting)) = self.core.control.take_ready() {
        self.run_task(task_ref, aborting);
      } else {
        match self.try_auto_advance(poll_epoch) {
          IdleStep::Retry | IdleStep::Advanced => continue,
          IdleStep::Park => self.core.notifier.park(),
        }
      }
    }
  }

  fn try_auto_advance(&mut self, poll_epoch: Option<u64>) -> IdleStep {
    let (Some(expected), Some(idle_clock)) = (poll_epoch, self.idle_clock.as_ref()) else {
      return IdleStep::Park;
    };
    let coordinator = Arc::clone(&self.core.coordinator);
    let Some(quiescent) = coordinator.quiescent(expected) else {
      return IdleStep::Retry;
    };
    if self.core.control.has_ready() {
      return IdleStep::Retry;
    }
    match self.receiver.try_recv() {
      Ok(request) => {
        drop(quiescent);
        self.import_request(request);
        return IdleStep::Retry;
      }
      Err(TryRecvError::Disconnected) => return IdleStep::Retry,
      Err(TryRecvError::Empty) => {}
    }
    let blocking_inhibited = idle_clock.blocking.as_ref().is_some_and(|blocking| {
      let snapshot = blocking.snapshot();
      snapshot.outstanding != 0 || snapshot.running != 0
    });
    match idle_clock
      .timer
      .auto_advance_if_idle(quiescent, blocking_inhibited)
    {
      AutoAdvance::Advanced => IdleStep::Advanced,
      AutoAdvance::Raced => IdleStep::Retry,
      AutoAdvance::Inactive | AutoAdvance::Inhibited | AutoAdvance::NoDeadline => IdleStep::Park,
    }
  }

  fn import_external(&mut self) {
    loop {
      match self.receiver.try_recv() {
        Ok(request) => self.import_request(request),
        Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
      }
    }
  }

  fn import_request(&mut self, request: Box<dyn ExternalRequest>) {
    if let Some(scope) = self.core.scope_cell(self.root_scope) {
      match self.core.control.admit(self.root_scope) {
        Ok(task_ref) => request.import(&self.core, task_ref, scope),
        Err(_) => request.cancel_on_owner(),
      }
    } else {
      request.cancel_on_owner();
    }
  }

  fn run_task(&mut self, task_ref: TaskRef, aborting: bool) {
    let Some(mut slot) = self.core.take_task(task_ref) else {
      self.core.control.abandon(task_ref);
      return;
    };
    let task_handle = LocalHandle {
      core: Rc::clone(&self.core),
      scope: slot.scope,
      _scope_owner: None,
      _not_send: PhantomData,
    };
    let _task_context = LocalEnterGuard::enter(&task_handle);
    let aborting = aborting || slot.abort.load(Ordering::Acquire);
    let task = slot.task.as_mut();
    let poll_result = if aborting {
      if let Some(task) = task {
        task.cancel();
      }
      Poll::Ready(())
    } else if let Some(task) = task {
      match ControlCharge::try_new(task.tenant_domain(), std::mem::size_of::<LocalTaskWake>()) {
        Ok(wake_control) => {
          let wake = Arc::new(LocalTaskWake {
            control: Arc::downgrade(&self.core.control),
            task: task_ref,
            notifier: Arc::clone(&self.core.notifier),
            _control: wake_control,
          });
          let waker = Waker::from(wake);
          let mut context = Context::from_waker(&waker);
          super::entry::reset_budget();
          match task.acquire_cpu(&waker) {
            DomainCpuAdmission::Unbounded => task.poll(&mut context, None),
            DomainCpuAdmission::Acquired(ticket) => task.poll(&mut context, Some(ticket)),
            DomainCpuAdmission::Waiting => Poll::Pending,
            DomainCpuAdmission::Rejected(error) => {
              task.fail_resource(error);
              Poll::Ready(())
            }
          }
        }
        Err(error) => {
          task.fail_resource(error);
          Poll::Ready(())
        }
      }
    } else {
      Poll::Ready(())
    };

    if poll_result.is_pending() {
      match self.core.control.finish(task_ref, false) {
        PollFinish::CancelCleanup | PollFinish::Stale => {
          if let Some(task) = slot.task.as_mut() {
            task.cancel();
          }
          self.finish_cancel(task_ref, slot);
        }
        PollFinish::Idle | PollFinish::Requeue => self.core.restore_task(task_ref, slot),
        PollFinish::Complete => {
          self.finish_complete(task_ref, slot);
        }
      }
      return;
    }

    if aborting {
      self.finish_cancel(task_ref, slot);
    } else {
      let _ = self.core.control.finish(task_ref, true);
      self.finish_complete(task_ref, slot);
    }
  }

  fn finish_cancel(&self, task_ref: TaskRef, mut slot: LocalTaskSlot) {
    let _scope_ref = self.core.control.finish_cancel(task_ref);
    if let Some(task) = slot.task.as_mut() {
      task.release_admission();
      task.publish();
      task.complete_scope(&self.core);
    }
    drop(slot);
    self.core.notifier.notify();
  }

  fn finish_complete(&self, task_ref: TaskRef, mut slot: LocalTaskSlot) {
    let _ = task_ref;
    if let Some(task) = slot.task.as_mut() {
      task.release_admission();
      task.publish();
      task.complete_scope(&self.core);
    }
    drop(slot);
    self.core.notifier.notify();
  }

  fn close_and_cleanup(&mut self) {
    if self.shutdown_complete {
      return;
    }
    let _local_execution = LocalExecutionGuard::enter();
    self.request_shutdown();
    while !self.shutdown_complete {
      match self.drive_shutdown_step() {
        Ok(true) | Err(_) => break,
        Ok(false) => {}
      }
    }
  }

  /// Closes local admission and requests cancellation while keeping every
  /// task and cleanup owner on this thread. This does not run future
  /// destructors or stored completion wakers.
  pub(in crate::runtime) fn request_shutdown(&mut self) {
    if self.closed || self.shutdown_complete {
      return;
    }
    self.closed = true;
    self.core.gate.close();
    self.core.control.close_all();
    let scope_count = self.core.scopes.borrow().len();
    for index in 0..scope_count {
      let scope = self
        .core
        .scopes
        .borrow()
        .get(index)
        .and_then(Option::as_ref)
        .cloned();
      if let Some(scope) = scope {
        self.core.begin_scope_close(&scope);
      }
    }
    self.core.notifier.notify();
  }

  /// Runs at most one local cleanup step, then reports whether every queued
  /// external future, task and scope has actually been cleaned up. A future
  /// destructor or completion waker may itself take unbounded time.
  pub(in crate::runtime) fn drive_shutdown_step(&mut self) -> Result<bool, LocalError> {
    self.core.check_owner()?;
    if self.shutdown_complete {
      return Ok(true);
    }
    self.request_shutdown();

    if let Ok(request) = self.receiver.try_recv() {
      let root_handle = self.handle();
      let _root_context = LocalEnterGuard::enter(&root_handle);
      request.cancel_on_owner();
      return Ok(false);
    }

    let task_count = self.core.tasks.borrow().len();
    for index in 0..task_count {
      let task_ref = self
        .core
        .tasks
        .borrow()
        .get(index)
        .and_then(Option::as_ref)
        .map(|slot| TaskRef {
          index,
          generation: slot.generation,
        });
      let Some(task_ref) = task_ref else {
        continue;
      };
      if let Some(mut slot) = self.core.take_task(task_ref) {
        let task_handle = LocalHandle {
          core: Rc::clone(&self.core),
          scope: slot.scope,
          _scope_owner: None,
          _not_send: PhantomData,
        };
        let _task_context = LocalEnterGuard::enter(&task_handle);
        if let Some(task) = slot.task.as_mut() {
          task.cancel();
          self.core.control.abandon(task_ref);
          task.release_admission();
          task.publish();
          task.complete_scope(&self.core);
        }
        return Ok(false);
      }
    }

    let scope_count = self.core.scopes.borrow().len();
    for index in 0..scope_count {
      let scope = self
        .core
        .scopes
        .borrow()
        .get(index)
        .and_then(Option::as_ref)
        .cloned();
      if let Some(scope) = scope
        && scope.closed.get()
        && !scope.reclaimed.get()
        && scope.active.get() == 0
      {
        self.core.finish_scope_close(&scope);
        return Ok(false);
      }
    }

    self.shutdown_complete = true;
    Ok(true)
  }

  pub(in crate::runtime) fn shutdown_complete(&self) -> bool {
    self.shutdown_complete
  }
}

impl Drop for LocalRuntime {
  fn drop(&mut self) {
    self.close_and_cleanup();
  }
}

impl fmt::Debug for LocalRuntime {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("LocalRuntime")
      .field("owner", &self.core.owner)
      .finish_non_exhaustive()
  }
}

/// Owner-thread handle for local tasks in one scope.
pub struct LocalHandle {
  core: Rc<LocalCore>,
  scope: ScopeRef,
  _scope_owner: Option<Rc<ScopeCell>>,
  _not_send: PhantomData<Rc<()>>,
}

impl LocalHandle {
  /// Submits a local future and returns its awaitable join. The future must be
  /// `'static` and is always dropped by the owner thread. A `!Send` output
  /// remains thread-affine; a `Send` output may be moved or dropped by the
  /// thread that observes or discards the join result.
  pub fn spawn_local<F>(&self, future: F) -> Result<AsyncJob<F::Output>, LocalSpawnError<F>>
  where
    F: Future + 'static,
    F::Output: 'static,
  {
    if let Err(error) = self.core.check_owner() {
      return Err(LocalSpawnError::new(error, future));
    }
    let permit = match self.core.gate.reserve() {
      Ok(permit) => permit,
      Err(error) => return Err(LocalSpawnError::new(error, future)),
    };
    let scope = match self.core.scope_cell(self.scope) {
      Some(scope) if !scope.closed.get() => scope,
      _ => return Err(LocalSpawnError::new(LocalError::Closed, future)),
    };
    if let Some(tenant) = &scope.tenant
      && let Err(error) = tenant.validate_cpu_execution()
    {
      return Err(LocalSpawnError::new(
        LocalError::ResourceDomain(error),
        future,
      ));
    }
    let mut domain =
      match reserve_local_task_admission::<F, LocalTaskAbort>(scope.tenant.as_ref(), 0, false) {
        Ok(domain) => domain,
        Err(error) => {
          return Err(LocalSpawnError::new(
            LocalError::ResourceDomain(error),
            future,
          ));
        }
      };
    let waiter = if scope.tenant.is_some() {
      match scope
        .task_waiters
        .as_ref()
        .ok_or(DomainError::WaitersFull)
        .and_then(DomainWaitPool::try_lease)
      {
        Ok(waiter) => Some(waiter),
        Err(error) => {
          drop(domain);
          return Err(LocalSpawnError::new(
            LocalError::ResourceDomain(error),
            future,
          ));
        }
      }
    } else {
      None
    };
    let Some(id) = identity::allocate() else {
      drop(waiter);
      drop(domain);
      return Err(LocalSpawnError::new(LocalError::TaskIdExhausted, future));
    };
    let task_ref = match self.core.control.admit(self.scope) {
      Ok(task_ref) => task_ref,
      Err(error) => {
        drop(waiter);
        drop(domain);
        return Err(LocalSpawnError::new(error, future));
      }
    };
    let join_control = std::mem::replace(&mut domain.join_control, ControlCharge::unbounded(0));
    let abort_control = std::mem::replace(&mut domain.abort_control, ControlCharge::unbounded(0));
    let finished_control =
      std::mem::replace(&mut domain.finished_control, ControlCharge::unbounded(0));
    let abort_flag_control =
      std::mem::replace(&mut domain.abort_flag_control, ControlCharge::unbounded(0));
    let task_control = std::mem::replace(&mut domain.task_control, ControlCharge::unbounded(0));
    let task_admission = domain.task.take();
    let join = JoinState::with_id(id, join_control, finished_control);
    let abort_metadata = new_abort_metadata(
      self.core.abort_action(task_ref),
      join.finished_flag(),
      abort_control,
    );
    let abort = Arc::new(LocalAbortFlag::new(abort_flag_control));
    let task = Task {
      future: Some(Box::pin(future)),
      staged: None,
      join: Arc::clone(&join),
      id,
      admission: Some(permit),
      tenant: scope.tenant.clone(),
      waiter,
      task_admission,
      resources: scope.resources.clone(),
      scope: Rc::clone(&scope),
      _abort_metadata: Arc::clone(&abort_metadata),
      task_control: Some(task_control),
    };
    self
      .core
      .insert_task(task_ref, scope, Arc::clone(&abort), Box::new(task));
    self.core.notifier.notify();
    Ok(AsyncJob::new_with_metadata(join, abort_metadata))
  }

  /// Enters this local handle as the current local runtime context.
  #[must_use]
  pub fn enter(&self) -> LocalEnterGuard {
    LocalEnterGuard::enter(self)
  }

  /// Returns the current local handle, panicking when no local context is
  /// active on this thread.
  #[must_use]
  pub fn current() -> Self {
    try_current().unwrap_or_else(|| panic!("no allocatbelt local runtime is entered"))
  }

  /// Returns the current local handle, if any.
  #[must_use]
  pub fn try_current() -> Option<Self> {
    try_current()
  }
}

impl Clone for LocalHandle {
  fn clone(&self) -> Self {
    Self {
      core: Rc::clone(&self.core),
      scope: self.scope,
      _scope_owner: self._scope_owner.as_ref().map(Rc::clone),
      _not_send: PhantomData,
    }
  }
}

impl fmt::Debug for LocalHandle {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("LocalHandle")
      .field("scope", &self.scope)
      .finish_non_exhaustive()
  }
}

/// Cross-thread handle that admits only `Send + 'static` futures and outputs.
#[derive(Clone)]
pub struct LocalSendHandle {
  sender: SyncSender<Box<dyn ExternalRequest>>,
  gate: Arc<AdmissionGate>,
  notifier: Arc<Notifier>,
  control: Arc<Control>,
  resources: Option<ResourceScope>,
  tenant: Option<TenantDomain>,
  task_waiters: Option<DomainWaitPool>,
  _channel_control: Arc<ControlCharge>,
  _support_control: Arc<ControlCharge>,
}

impl LocalSendHandle {
  /// Submits a `Send` future to be imported and polled by the owner thread.
  pub fn spawn<F>(&self, future: F) -> Result<AsyncJob<F::Output>, LocalSpawnError<F>>
  where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
  {
    if let Some(tenant) = &self.tenant
      && let Err(error) = tenant.validate_cpu_execution()
    {
      return Err(LocalSpawnError::new(
        LocalError::ResourceDomain(error),
        future,
      ));
    }
    let request_bytes =
      match std::mem::size_of::<SendRequest<F>>().checked_sub(std::mem::size_of::<F>()) {
        Some(bytes) => bytes,
        None => {
          return Err(LocalSpawnError::new(
            LocalError::ResourceDomain(DomainError::Invalid),
            future,
          ));
        }
      };
    let mut domain = match reserve_local_task_admission::<F, LocalSendAbort>(
      self.tenant.as_ref(),
      request_bytes,
      true,
    ) {
      Ok(domain) => domain,
      Err(error) => {
        return Err(LocalSpawnError::new(
          LocalError::ResourceDomain(error),
          future,
        ));
      }
    };
    let waiter = if self.tenant.is_some() {
      match self
        .task_waiters
        .as_ref()
        .ok_or(DomainError::WaitersFull)
        .and_then(DomainWaitPool::try_lease)
      {
        Ok(waiter) => Some(waiter),
        Err(error) => {
          drop(domain);
          return Err(LocalSpawnError::new(
            LocalError::ResourceDomain(error),
            future,
          ));
        }
      }
    } else {
      None
    };

    let changed = self.notifier.coordinator.changed();
    let mut gate = self.gate.lock();
    let admission = match self.gate.reserve_locked(&mut gate) {
      Ok(admission) => admission,
      Err(error) => {
        drop(gate);
        drop(changed);
        drop(waiter);
        drop(domain);
        return Err(LocalSpawnError::new(error, future));
      }
    };
    let Some(id) = identity::allocate() else {
      drop(gate);
      drop(changed);
      drop(waiter);
      drop(domain);
      drop(admission);
      return Err(LocalSpawnError::new(LocalError::TaskIdExhausted, future));
    };
    let task_admission = domain.task.take();
    let task_control = std::mem::replace(&mut domain.task_control, ControlCharge::unbounded(0));
    let join_control = std::mem::replace(&mut domain.join_control, ControlCharge::unbounded(0));
    let abort_control = std::mem::replace(&mut domain.abort_control, ControlCharge::unbounded(0));
    let finished_control =
      std::mem::replace(&mut domain.finished_control, ControlCharge::unbounded(0));
    let abort_flag_control =
      std::mem::replace(&mut domain.abort_flag_control, ControlCharge::unbounded(0));
    let abort_target_control = std::mem::replace(
      &mut domain.abort_target_control,
      ControlCharge::unbounded(0),
    );
    let request_control =
      std::mem::replace(&mut domain.request_control, ControlCharge::unbounded(0));
    drop(domain);
    let join = JoinState::with_id(id, join_control, finished_control);
    let abort = Arc::new(LocalAbortFlag::new(abort_flag_control));
    let abort_target = Arc::new(LocalAbortTarget::new(abort_target_control));
    let abort_metadata = new_abort_metadata(
      LocalSendAbort {
        abort: Arc::clone(&abort),
        target: Arc::clone(&abort_target),
        control: Arc::downgrade(&self.control),
        notifier: Arc::clone(&self.notifier),
      },
      join.finished_flag(),
      abort_control,
    );
    let request = SendRequest {
      future,
      id,
      join: Arc::clone(&join),
      abort_metadata: Arc::clone(&abort_metadata),
      abort: Arc::clone(&abort),
      abort_target: Arc::clone(&abort_target),
      admission,
      resources: self.resources.clone(),
      tenant: self.tenant.clone(),
      waiter,
      task_admission,
      task_control,
      _request_control: request_control,
    };
    let job = AsyncJob::new_with_metadata(join, abort_metadata);
    match self.sender.try_send(Box::new(request)) {
      Ok(()) => {
        drop(gate);
        drop(changed);
        Ok(job)
      }
      Err(error) => {
        let (request, kind) = match error {
          TrySendError::Full(request) => (request, LocalError::Full),
          TrySendError::Disconnected(request) => (request, LocalError::Closed),
        };
        drop(gate);
        drop(changed);
        drop(job);
        let recovered = request.reject();
        match recovered.downcast::<F>() {
          Ok(future) => Err(LocalSpawnError::new(kind, *future)),
          Err(_) => unreachable!("send request preserved its original future type"),
        }
      }
    }
  }
}

impl fmt::Debug for LocalSendHandle {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("LocalSendHandle").finish_non_exhaustive()
  }
}

/// An owner-thread cancellable task scope.
pub struct LocalTaskScope {
  handle: LocalHandle,
  cell: Rc<ScopeCell>,
  closed: bool,
}

impl LocalTaskScope {
  /// Returns the scope's owner-thread admission handle.
  #[must_use]
  pub fn handle(&self) -> LocalHandle {
    self.handle.clone()
  }

  /// Admits an owned local future to this scope.
  pub fn spawn_local<F>(&self, future: F) -> Result<AsyncJob<F::Output>, LocalSpawnError<F>>
  where
    F: Future + 'static,
    F::Output: 'static,
  {
    self.handle.spawn_local(future)
  }

  /// Requests cancellation and returns a future resolving after task cleanup
  /// and scope-slot reclamation.
  pub fn close(mut self) -> LocalScopeClose {
    self.closed = true;
    self.handle.core.request_scope_close(&self.cell);
    LocalScopeClose {
      cell: Rc::clone(&self.cell),
    }
  }
}

impl Drop for LocalTaskScope {
  fn drop(&mut self) {
    if !self.closed {
      self.handle.core.request_scope_close(&self.cell);
    }
  }
}

/// Waits until a local scope's children have been cancelled and cleaned up.
pub struct LocalScopeClose {
  cell: Rc<ScopeCell>,
}

impl Future for LocalScopeClose {
  type Output = ();

  fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
    if self.cell.is_ready() {
      return Poll::Ready(());
    }
    let replacement = context.waker().clone();
    let old = self.cell.completion.borrow_mut().replace(replacement);
    drop(old);
    if self.cell.is_ready() {
      let old = self.cell.completion.borrow_mut().take();
      drop(old);
      Poll::Ready(())
    } else {
      Poll::Pending
    }
  }
}

impl Drop for LocalScopeClose {
  fn drop(&mut self) {
    let old = self.cell.completion.borrow_mut().take();
    drop(old);
  }
}

struct LocalContextNode {
  handle: LocalHandle,
  parent: Option<Rc<LocalContextNode>>,
  active: Cell<bool>,
}

thread_local! {
  static LOCAL_CURRENT: RefCell<Option<Rc<LocalContextNode>>> = const { RefCell::new(None) };
}

/// Thread-affine local runtime context guard; nested and out-of-order drops
/// restore the most recently entered live local context.
pub struct LocalEnterGuard {
  node: Option<Rc<LocalContextNode>>,
  _not_send: PhantomData<Rc<()>>,
}

impl LocalEnterGuard {
  fn enter(handle: &LocalHandle) -> Self {
    let parent = LOCAL_CURRENT
      .try_with(|current| current.borrow().clone())
      .unwrap_or(None);
    let node = Rc::new(LocalContextNode {
      handle: handle.clone(),
      parent,
      active: Cell::new(true),
    });
    let replaced = LOCAL_CURRENT
      .try_with(|current| current.replace(Some(Rc::clone(&node))))
      .ok();
    drop(replaced);
    Self {
      node: Some(node),
      _not_send: PhantomData,
    }
  }
}

impl Drop for LocalEnterGuard {
  fn drop(&mut self) {
    let Some(node) = self.node.take() else {
      return;
    };
    node.active.set(false);
    let removed = LOCAL_CURRENT
      .try_with(|current| {
        if !current
          .borrow()
          .as_ref()
          .is_some_and(|top| Rc::ptr_eq(top, &node))
        {
          return None;
        }
        let mut parent = node.parent.clone();
        while parent
          .as_ref()
          .is_some_and(|candidate| !candidate.active.get())
        {
          parent = parent.and_then(|candidate| candidate.parent.clone());
        }
        Some(current.replace(parent))
      })
      .ok()
      .flatten();
    drop(removed);
  }
}

fn try_current() -> Option<LocalHandle> {
  LOCAL_CURRENT
    .try_with(|current| {
      current
        .borrow()
        .as_ref()
        .filter(|node| node.active.get())
        .map(|node| node.handle.clone())
    })
    .unwrap_or(None)
}

#[cfg(all(test, not(loom)))]
mod control_owner_tests {
  use super::*;
  use crate::runtime::managed::ResourceLimits;
  use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};

  fn domain() -> (ResourceDomain, TenantDomain) {
    let limits = DomainResources::ZERO
      .with(DomainResource::Cpu, 2)
      .with(DomainResource::Tasks, 8)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::new(limits, 1).unwrap();
    let tenant = domain.tenant(limits).unwrap();
    (domain, tenant)
  }

  #[test]
  fn closed_scope_retains_inherited_waiter_pools_after_runtime_drop_exactly() {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 2)
      .with(DomainResource::Tasks, 8)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 8).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let resources = ResourceScope::from_tenant(ResourceLimits::default(), tenant.clone());
    let global_base = domain.snapshot().used.get(DomainResource::Control);
    let tenant_base = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    let runtime = LocalRuntime::with_resources(
      LocalConfig {
        max_outstanding: 2,
        max_scopes: 2,
      },
      resources,
    )
    .unwrap();
    let scope = runtime.scope().unwrap();
    let scope_bytes = scope.cell._control.bytes();
    let pool_bytes = DomainWaitPool::control_payload_bytes();
    let close = scope.close();
    drop(runtime);

    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base + scope_bytes + 2 * pool_bytes
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
  fn local_send_admission_charges_abort_pointees_and_request_wrapper_exactly() {
    let (domain, tenant) = domain();
    let global_base = domain.snapshot().used.get(DomainResource::Control);
    let tenant_base = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    type F = std::future::Ready<()>;
    let local_bytes = std::mem::size_of::<Task<F>>()
      + std::mem::size_of::<F>()
      + std::mem::size_of::<JoinState<()>>()
      + abort_metadata_bytes::<LocalTaskAbort>()
      + finished_flag_bytes()
      + std::mem::size_of::<LocalAbortFlag>();
    let local = reserve_local_task_admission::<F, LocalTaskAbort>(Some(&tenant), 0, false).unwrap();
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base + local_bytes
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      tenant_base + local_bytes
    );
    assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 1);
    drop(local);

    let request_bytes = std::mem::size_of::<SendRequest<F>>() - std::mem::size_of::<F>();
    let send_bytes = std::mem::size_of::<Task<F>>()
      + std::mem::size_of::<F>()
      + std::mem::size_of::<JoinState<()>>()
      + abort_metadata_bytes::<LocalSendAbort>()
      + finished_flag_bytes()
      + std::mem::size_of::<LocalAbortFlag>()
      + std::mem::size_of::<LocalAbortTarget>()
      + request_bytes;
    let send =
      reserve_local_task_admission::<F, LocalSendAbort>(Some(&tenant), request_bytes, true)
        .unwrap();
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base + send_bytes
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      tenant_base + send_bytes
    );
    assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 1);
    drop(send);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      tenant_base
    );
    assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 0);
  }

  #[test]
  fn local_abort_pointees_remain_charged_through_final_arc_clone() {
    let (domain, tenant) = domain();
    let global_base = domain.snapshot().used.get(DomainResource::Control);
    let tenant_base = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    let flag_bytes = std::mem::size_of::<LocalAbortFlag>();
    let target_bytes = std::mem::size_of::<LocalAbortTarget>();

    let flag = Arc::new(LocalAbortFlag::new(
      ControlCharge::try_new(Some(&tenant), flag_bytes).unwrap(),
    ));
    let flag_clone = Arc::clone(&flag);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base + flag_bytes
    );
    drop(flag);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base + flag_bytes
    );
    drop(flag_clone);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base
    );

    let target = Arc::new(LocalAbortTarget::new(
      ControlCharge::try_new(Some(&tenant), target_bytes).unwrap(),
    ));
    let target_clone = Arc::clone(&target);
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      tenant_base + target_bytes
    );
    drop(target);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base + target_bytes
    );
    drop(target_clone);
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
  fn local_send_abort_handle_retains_exact_flag_target_and_notifier_owners() {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 2)
      .with(DomainResource::Tasks, 8)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 8).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let resources = ResourceScope::from_tenant(ResourceLimits::default(), tenant.clone());
    let global_base = domain.snapshot().used.get(DomainResource::Control);
    let tenant_base = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    let mut runtime = LocalRuntime::with_resources(
      LocalConfig {
        max_outstanding: 2,
        max_scopes: 2,
      },
      resources,
    )
    .unwrap();
    let support_bytes = runtime._support_control.bytes();
    let send = runtime.send_handle();
    let job = send.spawn(std::future::ready(())).unwrap();
    let abort = job.abort_handle();
    runtime
      .block_on(job)
      .unwrap_or_else(|error| panic!("local block_on failed: {error}"))
      .unwrap_or_else(|error| panic!("send task failed: {error}"));
    assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 0);

    drop(send);
    drop(runtime);
    let retained = support_bytes
      + abort_metadata_bytes::<LocalSendAbort>()
      + finished_flag_bytes()
      + std::mem::size_of::<LocalAbortFlag>()
      + std::mem::size_of::<LocalAbortTarget>();
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base + retained
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      tenant_base + retained
    );
    drop(abort);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      tenant_base
    );
  }
}
