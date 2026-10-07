//! Safe caller-thread polling, entered-runtime context, and cooperative
//! utilities. The budget is opt-in: futures must await `consume_budget()` at
//! points where they can safely yield.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use super::identity::TaskId;
use super::{AsyncError, AsyncHandle};
use crate::runtime::managed::ResourceScope;

const DEFAULT_BUDGET: u16 = 64;

thread_local! {
  static CURRENT: RefCell<Option<Rc<ContextNode>>> = const { RefCell::new(None) };
  static BLOCK_ON_ACTIVE: Cell<bool> = const { Cell::new(false) };
  static EXECUTOR_WORKER: Cell<bool> = const { Cell::new(false) };
  static COOPERATIVE_BUDGET: Cell<u16> = const { Cell::new(DEFAULT_BUDGET) };
  static CURRENT_TASK_ID: Cell<Option<TaskId>> = const { Cell::new(None) };
  static LOCAL_EXECUTION: Cell<bool> = const { Cell::new(false) };
  static CURRENT_RESOURCE_SCOPE: RefCell<Option<ResourceScope>> = const { RefCell::new(None) };
}

struct ContextNode {
  handle: AsyncHandle,
  parent: Option<Rc<ContextNode>>,
  active: Cell<bool>,
}

/// A thread-affine entered runtime context. The current context is the most
/// recently entered live guard. Dropping a guard removes its context even
/// when guards are dropped out of order or user code unwinds.
///
/// The guard cannot be moved to another thread:
///
/// ```compile_fail
/// use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncRuntime};
///
/// let runtime = AsyncRuntime::new(AsyncConfig {
///   workers: 1,
///   max_outstanding: 1,
///   max_scopes: 1,
/// }).unwrap();
/// let guard = runtime.handle().enter();
/// std::thread::spawn(move || drop(guard));
/// ```
pub struct EnterGuard {
  node: Option<Rc<ContextNode>>,
  _not_send: PhantomData<Rc<()>>,
}

impl EnterGuard {
  pub(super) fn enter(handle: &AsyncHandle) -> Self {
    let parent = CURRENT
      .try_with(|current| current.borrow().clone())
      .unwrap_or(None);
    let node = Rc::new(ContextNode {
      handle: handle.clone(),
      parent,
      active: Cell::new(true),
    });
    let replaced = CURRENT
      .try_with(|current| current.replace(Some(Rc::clone(&node))))
      .ok();
    // Releasing an old context can drop the last Shared handle; do so outside
    // the TLS RefCell borrow.
    drop(replaced);
    Self {
      node: Some(node),
      _not_send: PhantomData,
    }
  }
}

impl Drop for EnterGuard {
  fn drop(&mut self) {
    let Some(node) = self.node.take() else {
      return;
    };
    node.active.set(false);
    let removed = CURRENT
      .try_with(|current| {
        let is_top = current
          .borrow()
          .as_ref()
          .is_some_and(|top| Rc::ptr_eq(top, &node));
        if !is_top {
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
    // The removed node may own the last runtime handle. Drop it after the
    // TLS borrow has ended.
    drop(removed);
  }
}

/// Marks polling or cleanup on a fixed executor worker. Nested use preserves
/// the outer marker, so reentrant callbacks cannot make `block_on` appear safe.
pub(super) struct WorkerContextGuard {
  previous: bool,
  _not_send: PhantomData<Rc<()>>,
}

impl WorkerContextGuard {
  pub(super) fn enter() -> Self {
    let previous = EXECUTOR_WORKER.with(|worker| worker.replace(true));
    Self {
      previous,
      _not_send: PhantomData,
    }
  }
}

impl Drop for WorkerContextGuard {
  fn drop(&mut self) {
    let _ = EXECUTOR_WORKER.try_with(|worker| worker.set(self.previous));
  }
}

/// Restores the previous task identity after polling, callbacks, or unwind.
pub(super) struct TaskContextGuard {
  previous: Option<TaskId>,
  previous_resources: Option<ResourceScope>,
  _not_send: PhantomData<Rc<()>>,
}

impl TaskContextGuard {
  pub(super) fn enter(task_id: Option<TaskId>) -> Self {
    Self::enter_with_resource(task_id, None)
  }

  pub(super) fn enter_with_resource(
    task_id: Option<TaskId>,
    resources: Option<ResourceScope>,
  ) -> Self {
    let previous = CURRENT_TASK_ID.with(|current| current.replace(task_id));
    let previous_resources = CURRENT_RESOURCE_SCOPE.with(|current| current.replace(resources));
    Self {
      previous,
      previous_resources,
      _not_send: PhantomData,
    }
  }
}

impl Drop for TaskContextGuard {
  fn drop(&mut self) {
    let _ = CURRENT_TASK_ID.try_with(|current| current.set(self.previous));
    let _ = CURRENT_RESOURCE_SCOPE.try_with(|current| {
      let replaced = current.replace(self.previous_resources.take());
      drop(replaced);
    });
  }
}

/// Returns the explicitly bound managed-resource ledger during a task poll,
/// runtime-owned cleanup/publication, or a resource-bound handle's borrowed
/// root poll. Unbound contexts return `None`.
#[must_use]
pub fn try_current_resource_scope() -> Option<ResourceScope> {
  CURRENT_RESOURCE_SCOPE
    .try_with(|current| current.borrow().clone())
    .unwrap_or(None)
}

/// Returns the explicitly bound managed-resource ledger for the current task
/// or bound-handle root poll.
///
/// # Panics
///
/// Panics when the current task or root poll has no resource binding. This
/// accessor exposes only the managed ledger; ordinary allocations remain
/// outside its accounting.
#[must_use]
pub fn current_resource_scope() -> ResourceScope {
  try_current_resource_scope()
    .unwrap_or_else(|| panic!("no managed resource scope is bound to this async context"))
}

/// Marks actual `LocalRuntime` polling or cleanup on this thread. Entering a
/// `LocalHandle` context alone does not set it. Nested use preserves the
/// outer marker.
pub(super) struct LocalExecutionGuard {
  previous: bool,
  _not_send: PhantomData<Rc<()>>,
}

impl LocalExecutionGuard {
  pub(super) fn enter() -> Self {
    let previous = LOCAL_EXECUTION.with(|local| local.replace(true));
    Self {
      previous,
      _not_send: PhantomData,
    }
  }
}

impl Drop for LocalExecutionGuard {
  fn drop(&mut self) {
    let _ = LOCAL_EXECUTION.try_with(|local| local.set(self.previous));
  }
}

pub(super) fn local_execution_active() -> bool {
  LOCAL_EXECUTION.try_with(Cell::get).unwrap_or(false)
}

/// Saves the borrowed-root marker and cooperative budget, and optionally the
/// executor-worker marker, around a blocking closure so that the closure may
/// run one nested `block_on` on its thread. Task identity and entered
/// contexts are left unchanged. Dropping the guard, on return or unwind,
/// restores every saved value.
pub(super) struct ClosureContextGuard {
  executor_worker: Option<bool>,
  block_on_active: bool,
  budget: u16,
  _not_send: PhantomData<Rc<()>>,
}

impl ClosureContextGuard {
  pub(super) fn suspend(suspend_worker: bool) -> Self {
    let executor_worker = if suspend_worker {
      EXECUTOR_WORKER
        .try_with(|worker| worker.replace(false))
        .ok()
    } else {
      None
    };
    let block_on_active = BLOCK_ON_ACTIVE
      .try_with(|active| active.replace(false))
      .unwrap_or(false);
    let budget = COOPERATIVE_BUDGET
      .try_with(Cell::get)
      .unwrap_or(DEFAULT_BUDGET);
    Self {
      executor_worker,
      block_on_active,
      budget,
      _not_send: PhantomData,
    }
  }
}

impl Drop for ClosureContextGuard {
  fn drop(&mut self) {
    if let Some(previous) = self.executor_worker {
      let _ = EXECUTOR_WORKER.try_with(|worker| worker.set(previous));
    }
    let _ = BLOCK_ON_ACTIVE.try_with(|active| active.set(self.block_on_active));
    let _ = COOPERATIVE_BUDGET.try_with(|budget| budget.set(self.budget));
  }
}

/// Returns the identity of the task currently being polled or cleaned up.
#[must_use]
pub fn try_task_id() -> Option<TaskId> {
  CURRENT_TASK_ID.try_with(Cell::get).unwrap_or(None)
}

/// Returns the identity of the task currently being polled or cleaned up.
///
/// # Panics
///
/// Panics when called outside a spawned task's poll or cleanup context. A
/// caller-owned root future passed to `block_on` has no task ID.
#[must_use]
pub fn task_id() -> TaskId {
  try_task_id().unwrap_or_else(|| panic!("no allocatbelt async task is active"))
}

/// Returns the currently entered runtime handle, if any.
#[must_use]
pub fn try_current() -> Option<AsyncHandle> {
  CURRENT
    .try_with(|current| {
      current
        .borrow()
        .as_ref()
        .filter(|node| node.active.get())
        .map(|node| node.handle.clone())
    })
    .unwrap_or(None)
}

/// Returns the currently entered runtime handle.
///
/// # Panics
///
/// Panics when called outside an entered runtime context. Use
/// [`try_current`] when that is an expected condition.
#[must_use]
pub fn current() -> AsyncHandle {
  try_current().unwrap_or_else(|| panic!("no allocatbelt async runtime is entered"))
}

/// Polls one non-`Send`, possibly borrowed future on the caller's thread.
pub(super) fn block_on<F: Future>(
  handle: &AsyncHandle,
  future: F,
) -> Result<F::Output, AsyncError> {
  let _block = BlockOnGuard::enter()?;
  let _task_context = TaskContextGuard::enter_with_resource(None, handle.resources.clone());
  let _context = EnterGuard::enter(handle);
  Ok(block_on_caller_thread(future))
}

pub(super) struct BlockOnGuard;

impl BlockOnGuard {
  pub(super) fn enter() -> Result<Self, AsyncError> {
    if EXECUTOR_WORKER.with(Cell::get) {
      return Err(AsyncError::BlockOnFromWorker);
    }
    let already_active = BLOCK_ON_ACTIVE.with(|active| active.replace(true));
    if already_active {
      BLOCK_ON_ACTIVE.with(|active| active.set(true));
      return Err(AsyncError::NestedBlockOn);
    }
    Ok(Self)
  }
}

impl Drop for BlockOnGuard {
  fn drop(&mut self) {
    let _ = BLOCK_ON_ACTIVE.try_with(|active| active.set(false));
    let _ = COOPERATIVE_BUDGET.try_with(|budget| budget.set(DEFAULT_BUDGET));
  }
}

fn block_on_caller_thread<F: Future>(future: F) -> F::Output {
  let parker = Arc::new(Parker::new(thread::current()));
  let waker = Waker::from(Arc::clone(&parker));
  let mut context = Context::from_waker(&waker);
  let mut future = Box::pin(future);
  loop {
    reset_budget();
    if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
      return output;
    }
    parker.park();
  }
}

struct Parker {
  thread: Thread,
  notified: AtomicBool,
}

impl Parker {
  fn new(thread: Thread) -> Self {
    Self {
      thread,
      notified: AtomicBool::new(false),
    }
  }

  fn park(&self) {
    while !self.notified.swap(false, Ordering::AcqRel) {
      thread::park();
    }
  }

  fn unpark(&self) {
    self.notified.swap(true, Ordering::Release);
    self.thread.unpark();
  }
}

impl Wake for Parker {
  fn wake(self: Arc<Self>) {
    self.unpark();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.unpark();
  }
}

/// A future that yields once by arranging exactly one wake of its current
/// task, then completes on its next poll.
#[derive(Debug, Default)]
pub struct YieldNow {
  yielded: bool,
}

impl Future for YieldNow {
  type Output = ();

  fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
    if self.yielded {
      Poll::Ready(())
    } else {
      self.yielded = true;
      context.waker().wake_by_ref();
      Poll::Pending
    }
  }
}

/// Yields to the scheduler once. This does not guarantee another task runs;
/// the executor may immediately poll this task again.
#[must_use]
pub fn yield_now() -> YieldNow {
  YieldNow::default()
}

/// A cooperative checkpoint. It completes for the first 64 calls during one
/// task poll; the next call arranges one wake and yields. Callers must place
/// checkpoints in long-running work. No preemption occurs between checkpoints.
#[derive(Debug, Default)]
pub struct ConsumeBudget;

impl Future for ConsumeBudget {
  type Output = ();

  fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
    let exhausted = COOPERATIVE_BUDGET.with(|budget| {
      let remaining = budget.get();
      if remaining == 0 {
        budget.set(DEFAULT_BUDGET);
        true
      } else {
        budget.set(remaining - 1);
        false
      }
    });
    if exhausted {
      context.waker().wake_by_ref();
      Poll::Pending
    } else {
      Poll::Ready(())
    }
  }
}

/// Returns a cooperative checkpoint future. It yields only after the
/// per-poll budget is exhausted, and only where the caller awaits it.
#[must_use]
pub fn consume_budget() -> ConsumeBudget {
  ConsumeBudget
}

pub(super) fn reset_budget() {
  COOPERATIVE_BUDGET.with(|budget| budget.set(DEFAULT_BUDGET));
}

#[cfg(all(test, not(loom)))]
pub(super) fn budget_remaining() -> u16 {
  COOPERATIVE_BUDGET.with(Cell::get)
}

#[cfg(all(test, not(loom)))]
pub(super) fn block_on_active() -> bool {
  BLOCK_ON_ACTIVE.with(Cell::get)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn yield_now_self_wakes_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    struct Counter(AtomicUsize);
    impl Wake for Counter {
      fn wake(self: Arc<Self>) {
        self.wake_by_ref();
      }

      fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
      }
    }

    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&counter));
    let mut context = Context::from_waker(&waker);
    let mut future = yield_now();
    assert!(Pin::new(&mut future).poll(&mut context).is_pending());
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
    assert!(Pin::new(&mut future).poll(&mut context).is_ready());
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);
  }

  #[test]
  fn caller_parker_cannot_lose_a_wake_before_park() {
    struct WakeOnFirstPoll(bool);

    impl Future for WakeOnFirstPoll {
      type Output = usize;

      fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<usize> {
        if self.0 {
          Poll::Ready(2)
        } else {
          self.0 = true;
          context.waker().wake_by_ref();
          Poll::Pending
        }
      }
    }

    assert_eq!(block_on_caller_thread(WakeOnFirstPoll(false)), 2);
  }

  #[test]
  fn self_wake_pending_does_not_park_forever() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    struct WakeOnFirstPoll {
      consumed_permit: bool,
      captured_waker: std::sync::mpsc::SyncSender<Waker>,
    }

    impl Future for WakeOnFirstPoll {
      type Output = usize;

      fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<usize> {
        if self.consumed_permit {
          Poll::Ready(2)
        } else {
          self.consumed_permit = true;
          let _ = self.captured_waker.send(context.waker().clone());
          context.waker().wake_by_ref();
          // Reproduce a root future that consumes the thread's unpark permit
          // before returning Pending. The per-parker notification must remain
          // visible so block_on polls again instead of sleeping indefinitely.
          thread::park_timeout(Duration::ZERO);
          Poll::Pending
        }
      }
    }

    let rescued = Arc::new(AtomicBool::new(false));
    let watchdog_flag = Arc::clone(&rescued);
    let (capture_waker, captured_waker) = std::sync::mpsc::sync_channel::<Waker>(1);
    let (cancel, canceled) = std::sync::mpsc::channel();
    let watchdog = thread::spawn(move || {
      if let Ok(waker) = captured_waker.recv_timeout(Duration::from_secs(1))
        && canceled.recv_timeout(Duration::from_secs(1)).is_err()
      {
        watchdog_flag.store(true, Ordering::SeqCst);
        waker.wake();
      }
    });

    assert_eq!(
      block_on_caller_thread(WakeOnFirstPoll {
        consumed_permit: false,
        captured_waker: capture_waker,
      }),
      2
    );
    let _ = cancel.send(());
    watchdog
      .join()
      .unwrap_or_else(|_| panic!("watchdog thread panicked"));
    assert!(
      !rescued.load(Ordering::SeqCst),
      "watchdog had to rescue block_on"
    );
  }

  #[test]
  fn budget_checkpoint_yields_after_sixty_four_completions() {
    reset_budget();
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = ConsumeBudget;
    for _ in 0..DEFAULT_BUDGET {
      assert!(Pin::new(&mut future).poll(&mut context).is_ready());
    }
    assert!(Pin::new(&mut future).poll(&mut context).is_pending());
    assert!(Pin::new(&mut future).poll(&mut context).is_ready());
    reset_budget();
  }
}
