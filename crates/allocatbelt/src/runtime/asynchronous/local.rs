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
use std::thread::{self, Thread, ThreadId};

use super::entry::{BlockOnGuard, TaskContextGuard};
use super::identity::{self, TaskId};
use super::join::{AsyncJob, AsyncJoinError, JoinState};
use super::protocol::{PollFinish, PollProtocol};
use super::task::drop_contained;
use crate::runtime::managed::ResourceScope;

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
    })
  }
}

impl std::error::Error for LocalError {}

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
  thread: Thread,
  notified: AtomicBool,
}

impl Notifier {
  fn new(thread: Thread) -> Arc<Self> {
    Arc::new(Self {
      thread,
      notified: AtomicBool::new(false),
    })
  }

  fn notify(&self) {
    self.notified.swap(true, Ordering::Release);
    self.thread.unpark();
  }

  fn park(&self) {
    while !self.notified.swap(false, Ordering::AcqRel) {
      thread::park();
    }
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
}

impl Control {
  fn lock(&self) -> MutexGuard<'_, SchedulerState> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }

  fn new(max_outstanding: usize, max_scopes: usize) -> Result<(Arc<Self>, ScopeRef), LocalError> {
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
    Ok((
      Arc::new(Self {
        state: Mutex::new(SchedulerState {
          closed: false,
          tasks,
          free_tasks,
          scopes,
          round_robin,
        }),
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
}

impl Wake for LocalTaskWake {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    if let Some(control) = self.control.upgrade()
      && control.wake(self.task)
    {
      self.notifier.notify();
    }
  }
}

struct ScopeCell {
  reference: ScopeRef,
  resources: Option<ResourceScope>,
  active: Cell<usize>,
  closed: Cell<bool>,
  reclaimed: Cell<bool>,
  completion: RefCell<Option<Waker>>,
}

impl ScopeCell {
  fn new(reference: ScopeRef, resources: Option<ResourceScope>) -> Rc<Self> {
    Rc::new(Self {
      reference,
      resources,
      active: Cell::new(0),
      closed: Cell::new(false),
      reclaimed: Cell::new(reference.index == 0),
      completion: RefCell::new(None),
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
  abort: Arc<AtomicBool>,
  task: Option<Box<dyn LocalTask>>,
}

struct LocalCore {
  owner: ThreadId,
  gate: Arc<AdmissionGate>,
  control: Arc<Control>,
  tasks: RefCell<Vec<Option<LocalTaskSlot>>>,
  scopes: RefCell<Vec<Option<Rc<ScopeCell>>>>,
  notifier: Arc<Notifier>,
  _not_send: PhantomData<Rc<()>>,
}

impl LocalCore {
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
    abort: Arc<AtomicBool>,
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

  fn make_abort(&self, task_ref: TaskRef) -> Arc<dyn Fn() + Send + Sync> {
    let control = Arc::downgrade(&self.control);
    let notifier = Arc::clone(&self.notifier);
    Arc::new(move || {
      if let Some(control) = control.upgrade()
        && control.abort(task_ref)
      {
        notifier.notify();
      }
    })
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
    if scope.closed.replace(true) {
      return;
    }
    self.control.abort_scope(scope.reference);
    self.notifier.notify();
    if scope.active.get() == 0 {
      self.control.close_scope(scope.reference);
      scope.reclaimed.set(true);
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

trait LocalTask {
  fn poll(&mut self, context: &mut Context<'_>) -> Poll<()>;
  fn cancel(&mut self);
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
  scope: Rc<ScopeCell>,
  resources: Option<ResourceScope>,
}

impl<F: Future + 'static> Task<F> {
  fn drop_future(&mut self) -> Option<Box<dyn Any + Send>> {
    let future = self.future.take();
    panic::catch_unwind(AssertUnwindSafe(|| drop(future))).err()
  }
}

impl<F: Future + 'static> LocalTask for Task<F> {
  fn poll(&mut self, context: &mut Context<'_>) -> Poll<()> {
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(self.id), self.resources.clone());
    let Some(mut future) = self.future.take() else {
      return Poll::Ready(());
    };
    match panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
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
        Poll::Ready(())
      }
      Err(payload) => {
        if let Err(cleanup) = panic::catch_unwind(AssertUnwindSafe(|| drop(future))) {
          drop_contained(cleanup);
        }
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
  }

  fn release_admission(&mut self) {
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
  abort: Arc<AtomicBool>,
  abort_target: Arc<Mutex<Option<TaskRef>>>,
  admission: AdmissionPermit,
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
    } = *self;
    let task = Task {
      future: Some(Box::pin(future)),
      staged: None,
      join,
      id,
      admission: Some(admission),
      resources: scope.resources.clone(),
      scope: Rc::clone(&scope),
    };
    core.insert_task(task_ref, scope, Arc::clone(&abort), Box::new(task));
    *abort_target.lock().unwrap_or_else(PoisonError::into_inner) = Some(task_ref);
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
    } = *self;
    let _task_context = TaskContextGuard::enter_with_resource(Some(id), None);
    let outcome = match panic::catch_unwind(AssertUnwindSafe(|| drop(future))) {
      Ok(()) => Err(AsyncJoinError::Cancelled),
      Err(payload) => Err(AsyncJoinError::Panicked(payload)),
    };
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
    } = *self;
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
  closed: bool,
  _not_send: PhantomData<Rc<()>>,
}

impl LocalRuntime {
  /// Allocates all bounded task and scope tables before exposing handles.
  pub fn new(config: LocalConfig) -> Result<Self, LocalError> {
    if config.max_outstanding == 0 || config.max_scopes == 0 {
      return Err(LocalError::InvalidConfig);
    }
    let (control, root_scope) = Control::new(config.max_outstanding, config.max_scopes)?;
    let gate = AdmissionGate::new(config.max_outstanding);
    let (sender, receiver) = mpsc::sync_channel(config.max_outstanding);
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
    let root = ScopeCell::new(root_scope, None);
    scopes[0] = Some(Rc::clone(&root));
    let owner = thread::current();
    let notifier = Notifier::new(owner.clone());
    Ok(Self {
      core: Rc::new(LocalCore {
        owner: owner.id(),
        gate,
        control,
        tasks: RefCell::new(tasks),
        scopes: RefCell::new(scopes),
        notifier,
        _not_send: PhantomData,
      }),
      sender,
      receiver,
      root_scope,
      closed: false,
      _not_send: PhantomData,
    })
  }

  /// Returns a local handle for the implicit root scope.
  #[must_use]
  pub fn handle(&self) -> LocalHandle {
    LocalHandle {
      core: Rc::clone(&self.core),
      scope: self.root_scope,
      _not_send: PhantomData,
    }
  }

  /// Returns a cross-thread handle that accepts only `Send` futures and
  /// outputs. Its admissions share `max_outstanding` with local tasks and use
  /// the unbound implicit root scope; the submitting thread's resource context
  /// is never inherited.
  #[must_use]
  pub fn send_handle(&self) -> LocalSendHandle {
    LocalSendHandle {
      sender: self.sender.clone(),
      gate: Arc::clone(&self.core.gate),
      notifier: Arc::clone(&self.core.notifier),
      control: Arc::clone(&self.core.control),
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
    let reference = self.core.control.admit_scope()?;
    let cell = ScopeCell::new(reference, resources);
    self.core.scopes.borrow_mut()[reference.index] = Some(Rc::clone(&cell));
    Ok(LocalTaskScope {
      handle: LocalHandle {
        core: Rc::clone(&self.core),
        scope: reference,
        _not_send: PhantomData,
      },
      cell,
      closed: false,
    })
  }

  /// Polls a caller-owned root future and runs ready local tasks one poll turn
  /// at a time until the root completes. The root may borrow data and need not
  /// be `Send`; spawned local futures must be `'static`. The borrowed runtime
  /// root has no task ID or managed-resource binding, even when called while
  /// another task's resource context is active; that context is restored on
  /// return or unwind.
  pub fn block_on<F: Future>(&mut self, future: F) -> Result<F::Output, LocalError> {
    self.core.check_owner()?;
    if self.closed {
      return Err(LocalError::Closed);
    }
    let _block_on = BlockOnGuard::enter().map_err(|_| LocalError::BlockOnRejected)?;
    let _task_context = TaskContextGuard::enter(None);
    let _context = LocalEnterGuard::enter(&self.handle());
    let root_waker = Waker::from(Arc::clone(&self.core.notifier));
    let mut context = Context::from_waker(&root_waker);
    let mut future = Box::pin(future);
    loop {
      super::entry::reset_budget();
      if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
        return Ok(output);
      }
      self.import_external();
      if let Some((task_ref, aborting)) = self.core.control.take_ready() {
        self.run_task(task_ref, aborting);
      } else {
        self.core.notifier.park();
      }
    }
  }

  fn import_external(&mut self) {
    loop {
      match self.receiver.try_recv() {
        Ok(request) => {
          if let Some(scope) = self.core.scope_cell(self.root_scope) {
            match self.core.control.admit(self.root_scope) {
              Ok(task_ref) => request.import(&self.core, task_ref, scope),
              Err(_) => request.cancel_on_owner(),
            }
          } else {
            request.cancel_on_owner();
          }
        }
        Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
      }
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
    } else {
      let wake = Arc::new(LocalTaskWake {
        control: Arc::downgrade(&self.core.control),
        task: task_ref,
        notifier: Arc::clone(&self.core.notifier),
      });
      let waker = Waker::from(wake);
      let mut context = Context::from_waker(&waker);
      super::entry::reset_budget();
      if let Some(task) = task {
        task.poll(&mut context)
      } else {
        Poll::Ready(())
      }
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
    if self.closed {
      return;
    }
    self.closed = true;
    self.core.gate.close();
    self.core.control.close_all();
    while let Ok(request) = self.receiver.try_recv() {
      let root_handle = self.handle();
      let _root_context = LocalEnterGuard::enter(&root_handle);
      request.cancel_on_owner();
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
      if let Some(scope) = scope {
        self.core.request_scope_close(&scope);
      }
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
      }
    }
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
    let Some(id) = identity::allocate() else {
      return Err(LocalSpawnError::new(LocalError::TaskIdExhausted, future));
    };
    let task_ref = match self.core.control.admit(self.scope) {
      Ok(task_ref) => task_ref,
      Err(error) => return Err(LocalSpawnError::new(error, future)),
    };
    let join = JoinState::with_id(id);
    let abort = Arc::new(AtomicBool::new(false));
    let task = Task {
      future: Some(Box::pin(future)),
      staged: None,
      join: Arc::clone(&join),
      id,
      admission: Some(permit),
      scope: Rc::clone(&scope),
      resources: scope.resources.clone(),
    };
    self
      .core
      .insert_task(task_ref, scope, Arc::clone(&abort), Box::new(task));
    let abort_callback = self.core.make_abort(task_ref);
    self.core.notifier.notify();
    Ok(AsyncJob::new(join, abort_callback))
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
}

impl LocalSendHandle {
  /// Submits a `Send` future to be imported and polled by the owner thread.
  pub fn spawn<F>(&self, future: F) -> Result<AsyncJob<F::Output>, LocalSpawnError<F>>
  where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
  {
    let mut gate = self.gate.lock();
    let admission = match self.gate.reserve_locked(&mut gate) {
      Ok(admission) => admission,
      Err(error) => return Err(LocalSpawnError::new(error, future)),
    };
    let Some(id) = identity::allocate() else {
      drop(gate);
      drop(admission);
      return Err(LocalSpawnError::new(LocalError::TaskIdExhausted, future));
    };
    let join = JoinState::with_id(id);
    let abort = Arc::new(AtomicBool::new(false));
    let abort_target = Arc::new(Mutex::new(None));
    let request = SendRequest {
      future,
      id,
      join: Arc::clone(&join),
      abort: Arc::clone(&abort),
      abort_target: Arc::clone(&abort_target),
      admission,
    };
    let job_abort = Arc::clone(&abort);
    let job_abort_target = Arc::clone(&abort_target);
    let control = Arc::downgrade(&self.control);
    let notifier = Arc::clone(&self.notifier);
    let job = AsyncJob::new(
      join,
      Arc::new(move || {
        job_abort.store(true, Ordering::Release);
        if let Some(task_ref) = *job_abort_target
          .lock()
          .unwrap_or_else(PoisonError::into_inner)
          && let Some(control) = control.upgrade()
        {
          let _ = control.abort(task_ref);
        }
        notifier.notify();
      }),
    );
    match self.sender.try_send(Box::new(request)) {
      Ok(()) => {
        drop(gate);
        self.notifier.notify();
        Ok(job)
      }
      Err(error) => {
        let (request, kind) = match error {
          TrySendError::Full(request) => (request, LocalError::Full),
          TrySendError::Disconnected(request) => (request, LocalError::Closed),
        };
        drop(gate);
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
