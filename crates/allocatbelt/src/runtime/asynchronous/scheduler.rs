//! Bounded async task admission and scheduling. Scheduler state is reserved
//! before workers start; the mutex protects bookkeeping only and is released
//! before polling, dropping task values, or invoking wakers.

use std::collections::VecDeque;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Wake, Waker};

use super::identity;
use super::join::AsyncJob;
use super::protocol::{PollFinish, PollProtocol, ScopeProtocol};
use super::task::{ErasedTask, PollResult, Task};
use super::{AsyncConfig, AsyncError, AsyncSpawnError};
use crate::runtime::cache;

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
}

struct TaskSlot {
  protocol: PollProtocol,
  task: Option<Arc<dyn ErasedTask>>,
  scope: Option<ScopeRef>,
}

struct State {
  closed: bool,
  cancel_all: bool,
  tasks: Vec<TaskSlot>,
  ready: VecDeque<TaskRef>,
  scopes: Vec<ScopeSlot>,
  round_robin: VecDeque<ScopeRef>,
  idle: usize,
}

pub(super) struct Shared {
  id: u64,
  state: Mutex<State>,
  work: Condvar,
}

struct ScopeCell {
  reference: Option<ScopeRef>,
  shared: Option<Weak<Shared>>,
  protocol: ScopeProtocol,
  completion: Mutex<Option<Waker>>,
}

impl ScopeCell {
  fn new(reference: Option<ScopeRef>, shared: Option<Weak<Shared>>) -> Self {
    Self {
      reference,
      shared,
      protocol: ScopeProtocol::new(reference.is_none()),
      completion: Mutex::new(None),
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
  pub(super) fn new(config: AsyncConfig) -> Result<(Arc<Self>, ScopeRef), AsyncError> {
    let mut tasks = Vec::new();
    tasks
      .try_reserve_exact(config.max_outstanding)
      .map_err(|_| AsyncError::OutOfMemory)?;
    tasks.resize_with(config.max_outstanding, || TaskSlot {
      protocol: PollProtocol::new(),
      task: None,
      scope: None,
    });
    let mut ready = VecDeque::new();
    ready
      .try_reserve_exact(config.max_outstanding)
      .map_err(|_| AsyncError::OutOfMemory)?;
    let mut scopes = Vec::new();
    scopes
      .try_reserve_exact(config.max_scopes)
      .map_err(|_| AsyncError::OutOfMemory)?;
    scopes.resize_with(config.max_scopes, || ScopeSlot {
      generation: 0,
      scope: None,
      ready: false,
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
    let root_scope = Arc::new(ScopeCell::new(None, None));
    scopes[0] = ScopeSlot {
      generation: 1,
      scope: Some(root_scope),
      ready: false,
    };
    let root = ScopeRef {
      index: 0,
      generation: 1,
    };
    Ok((
      Arc::new(Self {
        id,
        state: Mutex::new(State {
          closed: false,
          cancel_all: false,
          tasks,
          ready,
          scopes,
          round_robin,
          idle: 0,
        }),
        work: Condvar::new(),
      }),
      root,
    ))
  }

  fn lock(&self) -> MutexGuard<'_, State> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
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
      slot.ready = false;
      cell.protocol.mark_reclaimed();
      slot.scope.take()
    };
    drop(retired);
  }

  pub(super) fn new_scope(self: &Arc<Self>) -> Result<OwnedTaskScope, AsyncError> {
    let mut state = self.lock();
    if state.closed {
      return Err(AsyncError::Closed);
    }
    let Some(index) = state.scopes.iter().position(|slot| slot.scope.is_none()) else {
      return Err(AsyncError::TooManyScopes);
    };
    let Some(generation) = state.scopes[index].generation.checked_add(1) else {
      return Err(AsyncError::TooManyScopes);
    };
    let scope_ref = ScopeRef { index, generation };
    let cell = Arc::new(ScopeCell::new(Some(scope_ref), Some(Arc::downgrade(self))));
    state.scopes[index].generation = generation;
    state.scopes[index].scope = Some(Arc::clone(&cell));
    Ok(OwnedTaskScope {
      shared: Arc::clone(self),
      scope: scope_ref,
      cell,
      closed: false,
    })
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
    let mut state = self.lock();
    if state.closed {
      drop(state);
      return Err(AsyncSpawnError::new(AsyncError::Closed, future));
    }
    let Some(scope_cell) = get_scope(&state, scope).cloned() else {
      drop(state);
      return Err(AsyncSpawnError::new(AsyncError::Closed, future));
    };
    if scope_cell.protocol.is_closed() {
      drop(state);
      return Err(AsyncSpawnError::new(AsyncError::Closed, future));
    }
    let Some(index) = state
      .tasks
      .iter()
      .position(|slot| slot.task.is_none() && !slot.protocol.admitted())
    else {
      drop(state);
      return Err(AsyncSpawnError::new(AsyncError::Full, future));
    };
    let Some(generation) = state.tasks[index].protocol.next_generation() else {
      drop(state);
      return Err(AsyncSpawnError::new(AsyncError::Full, future));
    };
    let Some(task_id) = identity::allocate() else {
      drop(state);
      return Err(AsyncSpawnError::new(AsyncError::TaskIdExhausted, future));
    };
    let task_ref = TaskRef { index, generation };
    let (task, job) = Task::create(future, task_id, Arc::downgrade(self), task_ref);
    state.tasks[index].protocol.admit(generation);
    state.tasks[index].scope = Some(scope);
    state.tasks[index].task = Some(task);
    scope_cell.protocol.add_task();
    schedule(&mut state, task_ref);
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
        if state.tasks[index].task.is_some() && state.tasks[index].protocol.abort() {
          let task_ref = TaskRef {
            index,
            generation: state.tasks[index].protocol.generation(),
          };
          push_ready(&mut state, task_ref);
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
  }

  fn request_scope_close(&self, scope: ScopeRef) {
    let mut state = self.lock();
    if let Some(cell) = get_scope(&state, scope) {
      cell.protocol.close();
    }
    for index in 0..state.tasks.len() {
      if state.tasks[index].task.is_some()
        && state.tasks[index].scope == Some(scope)
        && state.tasks[index].protocol.abort()
      {
        let task = TaskRef {
          index,
          generation: state.tasks[index].protocol.generation(),
        };
        push_ready(&mut state, task);
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
      slot.ready = false;
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
      push_ready(&mut state, task_ref);
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
    if slot.protocol.abort() {
      push_ready(&mut state, task_ref);
    }
    drop(state);
    self.work.notify_all();
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
fn task_waker(shared: &Arc<Shared>, task: TaskRef) -> Waker {
  Waker::from(Arc::new(TaskWake {
    shared: Arc::downgrade(shared),
    task,
  }))
}

fn get_scope(state: &State, scope: ScopeRef) -> Option<&Arc<ScopeCell>> {
  state
    .scopes
    .get(scope.index)
    .filter(|slot| slot.generation == scope.generation)
    .and_then(|slot| slot.scope.as_ref())
}

/// Adds an admitted task to the single bounded ready queue at most once.
fn schedule(state: &mut State, task_ref: TaskRef) -> bool {
  let Some(slot) = state.tasks.get_mut(task_ref.index) else {
    return false;
  };
  if !slot.protocol.matches(task_ref.generation) || slot.task.is_none() || !slot.protocol.queue() {
    return false;
  }
  push_ready(state, task_ref);
  true
}

/// Publishes a queue token after `PollProtocol` has reserved the task's one
/// ready position.
fn push_ready(state: &mut State, task_ref: TaskRef) {
  let Some(slot) = state.tasks.get(task_ref.index) else {
    return;
  };
  let Some(scope_ref) = slot.scope else {
    return;
  };
  state.ready.push_back(task_ref);
  if let Some(scope) = state.scopes.get_mut(scope_ref.index)
    && scope.generation == scope_ref.generation
    && !scope.ready
  {
    scope.ready = true;
    state.round_robin.push_back(scope_ref);
  }
}

enum Work {
  Poll(TaskRef, Arc<dyn ErasedTask>),
  Cancel(TaskRef, Arc<dyn ErasedTask>),
  Park,
  Exit,
}

fn take_next(shared: &Arc<Shared>, worker_index: usize) -> Work {
  let mut state = shared.lock();
  loop {
    if let Some(scope_ref) = state.round_robin.pop_front() {
      if let Some(scope) = state.scopes.get_mut(scope_ref.index)
        && scope.generation == scope_ref.generation
      {
        scope.ready = false;
      }
      let position = state.ready.iter().position(|task_ref| {
        state.tasks.get(task_ref.index).is_some_and(|task| {
          task.protocol.matches(task_ref.generation) && task.scope == Some(scope_ref)
        })
      });
      if let Some(position) = position {
        let Some(task_ref) = state.ready.remove(position) else {
          continue;
        };
        let remaining = state.ready.iter().any(|queued| {
          state.tasks.get(queued.index).is_some_and(|task| {
            task.protocol.matches(queued.generation) && task.scope == Some(scope_ref)
          })
        });
        if remaining
          && let Some(scope) = state.scopes.get_mut(scope_ref.index)
          && scope.generation == scope_ref.generation
        {
          scope.ready = true;
          state.round_robin.push_back(scope_ref);
        }
        if let Some(slot) = state.tasks.get_mut(task_ref.index)
          && let Some(task) = slot.task.as_ref().map(Arc::clone)
          && let Some(aborting) = slot.protocol.begin_poll()
        {
          return if aborting {
            Work::Cancel(task_ref, task)
          } else {
            Work::Poll(task_ref, task)
          };
        }
      }
      continue;
    }
    if state.closed && !state.tasks.iter().any(|slot| slot.task.is_some()) {
      return Work::Exit;
    }
    state.idle += 1;
    drop(state);
    cache::flush();
    state = shared.lock();
    if state.ready.is_empty()
      && !(state.closed && !state.tasks.iter().any(|slot| slot.task.is_some()))
    {
      state = shared
        .work
        .wait(state)
        .unwrap_or_else(PoisonError::into_inner);
    }
    state.idle = state.idle.saturating_sub(1);
    cache::set_shard(worker_index);
    if state.closed && state.cancel_all {
      for index in 0..state.tasks.len() {
        if state.tasks[index].task.is_some() && state.tasks[index].protocol.abort() {
          let reference = TaskRef {
            index,
            generation: state.tasks[index].protocol.generation(),
          };
          push_ready(&mut state, reference);
        }
      }
    }
    if state.ready.is_empty() && !state.closed {
      return Work::Park;
    }
  }
}

pub(super) fn worker(shared: Arc<Shared>, index: usize) {
  WORKER_RUNTIME.set(shared.id);
  cache::set_shard(index);
  let _worker_context = super::entry::WorkerContextGuard::enter();
  let worker_handle = super::AsyncHandle {
    shared: Arc::clone(&shared),
    scope: ScopeRef {
      index: 0,
      generation: 1,
    },
  };
  let _runtime_context = super::entry::EnterGuard::enter(&worker_handle);
  loop {
    match take_next(&shared, index) {
      Work::Poll(task_ref, task) => {
        super::entry::reset_budget();
        let waker = task_waker(&shared, task_ref);
        let mut context = Context::from_waker(&waker);
        let result = task.poll(&mut context);
        finish_poll(&shared, task_ref, result);
      }
      Work::Cancel(task_ref, task) => {
        task.cancel();
        finish_cancel(&shared, task_ref, task);
      }
      Work::Park => continue,
      Work::Exit => break,
    }
  }
  cache::flush();
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
    PollFinish::Requeue => push_ready(&mut state, task_ref),
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
  use std::future::Future;

  #[test]
  fn scope_close_stays_pending_until_zero_count_slot_reclamation() {
    let (shared, _) = Shared::new(AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 2,
    })
    .unwrap_or_else(|error| panic!("shared construction failed: {error}"));
    let scope = shared
      .new_scope()
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
      .new_scope()
      .unwrap_or_else(|error| panic!("reclaimed scope slot unavailable: {error}"));
    assert_eq!(replacement.scope.index, old_reference.index);
    assert!(replacement.scope.generation > old_reference.generation);
  }
}
