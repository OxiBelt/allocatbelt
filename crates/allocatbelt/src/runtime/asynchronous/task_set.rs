//! Bounded collection of owned jobs yielded in completion-notification order.

use super::task::drop_contained;
use super::{AsyncError, AsyncHandle, AsyncJob, AsyncJoinError, AsyncSpawnError};
#[cfg(loom)]
use loom::sync::{Mutex, MutexGuard};
use std::collections::{TryReserveError, VecDeque};
use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, Weak};
#[cfg(not(loom))]
use std::sync::{Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};

static NEXT_SET_ID: AtomicU64 = AtomicU64::new(1);

/// Errors constructing a bounded task set.
#[derive(Debug)]
pub enum TaskSetError {
  /// The fixed job table or completion queue could not be reserved.
  Allocation(TryReserveError),
  /// The process-wide, non-reusing set identifier space is exhausted.
  IdExhausted,
}

impl fmt::Display for TaskSetError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Allocation(error) => write!(f, "task set storage reservation failed: {error}"),
      Self::IdExhausted => f.write_str("task set identifier space exhausted"),
    }
  }
}

impl std::error::Error for TaskSetError {}

/// Identifies one admission in a particular task set.
///
/// The identifier is opaque and remains unique when a table slot is reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SetTaskId {
  set: u64,
  slot: usize,
  generation: u64,
}

impl SetTaskId {
  /// Returns this admission's slot index.
  #[must_use]
  pub const fn slot(self) -> usize {
    self.slot
  }

  /// Returns this admission's slot generation.
  #[must_use]
  pub const fn generation(self) -> u64 {
    self.generation
  }

  /// Returns the identity of the task set that created this identifier.
  #[must_use]
  pub const fn set_identity(self) -> u64 {
    self.set
  }
}

struct Entry<T> {
  generation: u64,
  job: Option<AsyncJob<T>>,
  retired: bool,
}

#[derive(Clone, Copy)]
struct Notice {
  slot: usize,
  generation: u64,
}

struct NoticeSlot {
  generation: u64,
  occupied: bool,
  queued: bool,
  retired: bool,
}

struct QueueState {
  slots: Vec<NoticeSlot>,
  notices: VecDeque<Notice>,
  consumer: Option<Waker>,
}

struct CompletionQueue {
  state: Mutex<QueueState>,
}

impl CompletionQueue {
  fn lock(&self) -> MutexGuard<'_, QueueState> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }

  fn notify(&self, notice: Notice) {
    let consumer = {
      let mut state = self.lock();
      let Some(slot) = state.slots.get_mut(notice.slot) else {
        return;
      };
      if slot.retired || !slot.occupied || slot.generation != notice.generation || slot.queued {
        return;
      }
      slot.queued = true;
      state.notices.push_back(notice);
      state.consumer.take()
    };
    if let Some(consumer) = consumer
      && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| consumer.wake()))
    {
      drop_contained(payload);
    }
  }

  fn register_consumer(&self, replacement: Waker) {
    let old = {
      let mut state = self.lock();
      state.consumer.replace(replacement)
    };
    if let Some(old) = old
      && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(old)))
    {
      drop_contained(payload);
    }
  }

  fn clear_consumer(&self) {
    let old = {
      let mut state = self.lock();
      state.consumer.take()
    };
    if let Some(old) = old
      && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(old)))
    {
      drop_contained(payload);
    }
  }

  fn take_notice(&self) -> Option<Notice> {
    let mut state = self.lock();
    let notice = state.notices.pop_front()?;
    if let Some(slot) = state.slots.get_mut(notice.slot)
      && slot.generation == notice.generation
    {
      slot.queued = false;
    }
    Some(notice)
  }

  fn release(&self, notice: Notice) -> Option<u64> {
    let mut state = self.lock();
    let slot = state.slots.get(notice.slot)?;
    if slot.retired || !slot.occupied || slot.generation != notice.generation {
      return None;
    }
    state
      .notices
      .retain(|queued| queued.slot != notice.slot || queued.generation != notice.generation);
    let slot = &mut state.slots[notice.slot];
    slot.occupied = false;
    slot.queued = false;
    match slot.generation.checked_add(1) {
      Some(generation) => {
        slot.generation = generation;
        Some(generation)
      }
      None => {
        slot.retired = true;
        None
      }
    }
  }

  fn has_capacity(&self) -> bool {
    self
      .lock()
      .slots
      .iter()
      .any(|slot| !slot.occupied && !slot.retired)
  }
}

struct CompletionWake {
  queue: Weak<CompletionQueue>,
  notice: Notice,
}

impl Wake for CompletionWake {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    if let Some(queue) = self.queue.upgrade() {
      queue.notify(self.notice);
    }
  }
}

/// A fixed-capacity owner of async joins.
///
/// Completion items are yielded in the order their one-shot notifications are
/// enqueued. Concurrent completions have no wall-clock ordering guarantee.
pub struct TaskSet<T> {
  identity: u64,
  entries: Vec<Entry<T>>,
  queue: Arc<CompletionQueue>,
  len: usize,
}

impl<T> TaskSet<T> {
  /// Constructs a task set with storage reserved for at most `max_jobs` jobs.
  pub fn new(max_jobs: usize) -> Result<Self, TaskSetError> {
    let identity = NEXT_SET_ID
      .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        value.checked_add(1)
      })
      .map_err(|_| TaskSetError::IdExhausted)?;

    let mut entries = Vec::new();
    entries
      .try_reserve_exact(max_jobs)
      .map_err(TaskSetError::Allocation)?;
    entries.extend((0..max_jobs).map(|_| Entry {
      generation: 1,
      job: None,
      retired: false,
    }));

    let mut slots = Vec::new();
    slots
      .try_reserve_exact(max_jobs)
      .map_err(TaskSetError::Allocation)?;
    slots.extend((0..max_jobs).map(|_| NoticeSlot {
      generation: 1,
      occupied: false,
      queued: false,
      retired: false,
    }));

    let mut notices = VecDeque::new();
    notices
      .try_reserve_exact(max_jobs)
      .map_err(TaskSetError::Allocation)?;

    Ok(Self {
      identity,
      entries,
      queue: Arc::new(CompletionQueue {
        state: Mutex::new(QueueState {
          slots,
          notices,
          consumer: None,
        }),
      }),
      len: 0,
    })
  }

  /// Maximum number of jobs this set can own at once.
  #[must_use]
  pub fn capacity(&self) -> usize {
    self.entries.len()
  }

  /// Number of jobs currently owned by the set.
  #[must_use]
  pub const fn len(&self) -> usize {
    self.len
  }

  /// Whether the set currently owns no jobs.
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.len == 0
  }

  /// Whether at least one slot is available for a new job.
  #[must_use]
  pub fn has_capacity(&self) -> bool {
    self.queue.has_capacity()
  }

  /// Takes ownership of an already spawned job, or returns it unchanged when
  /// this set has reached its bound.
  pub fn try_insert(&mut self, job: AsyncJob<T>) -> Result<SetTaskId, AsyncJob<T>> {
    let Some(index) = self
      .entries
      .iter()
      .position(|entry| entry.job.is_none() && !entry.retired)
    else {
      return Err(job);
    };
    Ok(self.insert_at(index, job))
  }

  fn insert_at(&mut self, index: usize, job: AsyncJob<T>) -> SetTaskId {
    let generation = self.entries[index].generation;
    let notice = Notice {
      slot: index,
      generation,
    };
    {
      let mut state = self.queue.lock();
      let slot = &mut state.slots[index];
      debug_assert!(!slot.occupied && !slot.retired && slot.generation == generation);
      slot.occupied = true;
      slot.queued = false;
    }
    self.entries[index].job = Some(job);
    self.len += 1;

    let waker = Waker::from(Arc::new(CompletionWake {
      queue: Arc::downgrade(&self.queue),
      notice,
    }));
    let mut context = Context::from_waker(&waker);
    let job = match self.entries[index].job.as_mut() {
      Some(job) => job,
      None => unreachable!("insert_at always stores its job"),
    };
    let completed = Pin::new(job).poll_finished(&mut context).is_ready();
    if completed {
      self.queue.notify(notice);
    }
    SetTaskId {
      set: self.identity,
      slot: index,
      generation,
    }
  }

  /// Checks set capacity before spawning and returns the original future on
  /// either set rejection or executor rejection.
  pub fn try_spawn<F>(
    &mut self,
    handle: &AsyncHandle,
    future: F,
  ) -> Result<SetTaskId, AsyncSpawnError<F>>
  where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
  {
    let Some(index) = self
      .entries
      .iter()
      .position(|entry| entry.job.is_none() && !entry.retired)
    else {
      return Err(AsyncSpawnError::new(AsyncError::Full, future));
    };
    let job = handle.spawn(future)?;
    Ok(self.insert_at(index, job))
  }

  /// Returns a borrowed future that yields the next completed job, or `None`
  /// when the set is empty. Dropping a pending future removes its parent waker.
  pub fn join_next(&mut self) -> JoinNext<'_, T> {
    JoinNext { set: self }
  }

  /// Requests cancellation of every owned job. Cleanup remains asynchronous.
  pub fn abort_all(&self) {
    for entry in &self.entries {
      if let Some(job) = &entry.job
        && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| job.abort()))
      {
        drop_contained(payload);
      }
    }
  }
}

impl<T> Drop for TaskSet<T> {
  fn drop(&mut self) {
    // Request every abort before any join (and therefore any retained result)
    // is dropped by field destruction.
    self.abort_all();
    self.queue.clear_consumer();
    for entry in &mut self.entries {
      if let Some(job) = entry.job.take()
        && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(job)))
      {
        drop_contained(payload);
      }
    }
  }
}

/// Borrowing future returned by [`TaskSet::join_next`].
pub struct JoinNext<'a, T> {
  set: &'a mut TaskSet<T>,
}

impl<T> Future for JoinNext<'_, T> {
  type Output = Option<(SetTaskId, Result<T, AsyncJoinError>)>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    loop {
      let Some(notice) = this.set.queue.take_notice() else {
        if this.set.len == 0 {
          return Poll::Ready(None);
        }
        this.set.queue.register_consumer(cx.waker().clone());
        // Close the completion race with registration: a completion either
        // took the waker above or left a notice ready for this poll.
        if !this.set.queue.lock().notices.is_empty() {
          this.set.queue.clear_consumer();
          continue;
        }
        return Poll::Pending;
      };
      if notice.slot >= this.set.entries.len() {
        continue;
      }
      let entry = &mut this.set.entries[notice.slot];
      if entry.generation != notice.generation {
        continue;
      }
      let Some(job) = entry.job.as_mut() else {
        continue;
      };
      let Some(outcome) = job.take_finished() else {
        // Re-arm the internal observer if a stale or inconsistent notice was
        // encountered. This path does not clone the caller's waker.
        let notification_waker = Waker::from(Arc::new(CompletionWake {
          queue: Arc::downgrade(&this.set.queue),
          notice,
        }));
        let mut notification_context = Context::from_waker(&notification_waker);
        if Pin::new(job)
          .poll_finished(&mut notification_context)
          .is_ready()
        {
          this.set.queue.notify(notice);
          continue;
        }
        this.set.queue.register_consumer(cx.waker().clone());
        if !this.set.queue.lock().notices.is_empty() {
          this.set.queue.clear_consumer();
          continue;
        }
        return Poll::Pending;
      };
      let id = SetTaskId {
        set: this.set.identity,
        slot: notice.slot,
        generation: notice.generation,
      };
      let removed = this.set.queue.release(notice);
      entry.job = None;
      this.set.len -= 1;
      if let Some(generation) = removed {
        entry.generation = generation;
      } else {
        entry.retired = true;
      }
      return Poll::Ready(Some((id, outcome)));
    }
  }
}

impl<T> Drop for JoinNext<'_, T> {
  fn drop(&mut self) {
    self.set.queue.clear_consumer();
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::{CompletionQueue, Notice, NoticeSlot, SetTaskId, TaskSet};
  use crate::runtime::asynchronous::join::JoinState;
  use crate::runtime::asynchronous::{
    AsyncConfig, AsyncError, AsyncJob, AsyncJoinError, AsyncRuntime,
  };
  use crate::runtime::managed::{ResourceLimits, ResourceScope};
  use std::collections::VecDeque;
  use std::future::Future;
  use std::pin::Pin;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::{Arc, Mutex};
  use std::task::{Context, Poll, Wake, Waker};

  fn manual_job<T>() -> (AsyncJob<T>, Arc<JoinState<T>>, Arc<AtomicUsize>) {
    let state = JoinState::new();
    let aborts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&aborts);
    let job = AsyncJob::new(
      Arc::clone(&state),
      Arc::new(move || {
        observed.fetch_add(1, Ordering::SeqCst);
      }),
    );
    (job, state, aborts)
  }

  fn poll_join<T>(set: &mut TaskSet<T>) -> Poll<Option<(SetTaskId, Result<T, AsyncJoinError>)>> {
    let mut next = Box::pin(set.join_next());
    let mut context = Context::from_waker(Waker::noop());
    Pin::as_mut(&mut next).poll(&mut context)
  }

  struct GateState {
    released: std::sync::atomic::AtomicBool,
    started: std::sync::atomic::AtomicBool,
    waker: Mutex<Option<Waker>>,
  }

  impl GateState {
    fn new() -> Arc<Self> {
      Arc::new(Self {
        released: std::sync::atomic::AtomicBool::new(false),
        started: std::sync::atomic::AtomicBool::new(false),
        waker: Mutex::new(None),
      })
    }

    fn release(&self) {
      self.released.store(true, Ordering::Release);
      let waker = self.waker.lock().unwrap().take();
      if let Some(waker) = waker {
        waker.wake();
      }
    }
  }

  struct Gate {
    state: Arc<GateState>,
    value: usize,
  }

  impl Future for Gate {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
      let this = self.get_mut();
      if this.state.released.load(Ordering::Acquire) {
        return Poll::Ready(this.value);
      }
      this.state.started.store(true, Ordering::Release);
      let mut replacement = Some(cx.waker().clone());
      let (old, released) = {
        let mut waker = this.state.waker.lock().unwrap();
        if this.state.released.load(Ordering::Acquire) {
          (None, true)
        } else {
          (waker.replace(replacement.take().unwrap()), false)
        }
      };
      drop(old);
      drop(replacement);
      if released {
        Poll::Ready(this.value)
      } else {
        Poll::Pending
      }
    }
  }

  fn wait_until_started(states: &[Arc<GateState>]) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while states
      .iter()
      .any(|state| !state.started.load(Ordering::Acquire))
    {
      assert!(
        std::time::Instant::now() < deadline,
        "gated tasks did not start"
      );
      std::thread::yield_now();
    }
  }

  #[test]
  fn yields_jobs_in_completion_notification_order_and_retains_result_in_join_state() {
    let mut set = TaskSet::new(2).unwrap();
    let (first, first_state, _) = manual_job();
    let (second, second_state, _) = manual_job();
    let first_id = set.try_insert(first).unwrap();
    let second_id = set.try_insert(second).unwrap();

    assert!(poll_join(&mut set).is_pending());
    assert!(second_state.publish(Ok(22)).is_none());
    assert!(first_state.publish(Ok(11)).is_none());

    match poll_join(&mut set) {
      Poll::Ready(Some((id, Ok(value)))) => {
        assert_eq!(id, second_id);
        assert_eq!(value, 22);
      }
      other => panic!("expected second completion first, got {other:?}"),
    }
    match poll_join(&mut set) {
      Poll::Ready(Some((id, Ok(value)))) => {
        assert_eq!(id, first_id);
        assert_eq!(value, 11);
      }
      other => panic!("expected first completion second, got {other:?}"),
    }
    assert!(set.is_empty());
  }

  #[test]
  fn executor_jobs_wait_and_are_yielded_in_completion_order() {
    let runtime = AsyncRuntime::new(AsyncConfig {
      workers: 2,
      max_outstanding: 4,
      max_scopes: 1,
    })
    .unwrap();
    let handle = runtime.handle();
    let mut set = TaskSet::new(2).unwrap();
    let first = GateState::new();
    let second = GateState::new();
    set
      .try_spawn(
        &handle,
        Gate {
          state: Arc::clone(&first),
          value: 1,
        },
      )
      .unwrap();
    set
      .try_spawn(
        &handle,
        Gate {
          state: Arc::clone(&second),
          value: 2,
        },
      )
      .unwrap();
    wait_until_started(&[Arc::clone(&first), Arc::clone(&second)]);

    second.release();
    assert!(matches!(
      runtime.block_on(set.join_next()).unwrap(),
      Some((_, Ok(2)))
    ));
    first.release();
    assert!(matches!(
      runtime.block_on(set.join_next()).unwrap(),
      Some((_, Ok(1)))
    ));
  }

  #[test]
  fn spawn_rejection_preserves_future_and_abort_and_panic_yield_join_errors() {
    struct RejectedFuture(Arc<AtomicUsize>);
    impl Future for RejectedFuture {
      type Output = usize;
      fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
      }
    }
    impl Drop for RejectedFuture {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }

    let runtime = AsyncRuntime::new(AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 1,
    })
    .unwrap();
    let handle = runtime.handle();
    let mut set = TaskSet::new(2).unwrap();
    set
      .try_spawn(&handle, std::future::pending::<usize>())
      .unwrap();

    let drops = Arc::new(AtomicUsize::new(0));
    let error = set
      .try_spawn(&handle, RejectedFuture(Arc::clone(&drops)))
      .unwrap_err();
    assert_eq!(error.kind, AsyncError::Full);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(error.into_future());
    assert_eq!(drops.load(Ordering::SeqCst), 1);

    set.abort_all();
    assert!(matches!(
      runtime.block_on(set.join_next()).unwrap(),
      Some((_, Err(AsyncJoinError::Cancelled)))
    ));

    set
      .try_spawn(
        &handle,
        std::future::poll_fn(|_| -> Poll<usize> { panic!("task panic") }),
      )
      .unwrap();
    assert!(matches!(
      runtime.block_on(set.join_next()).unwrap(),
      Some((_, Err(AsyncJoinError::Panicked(_))))
    ));
  }

  #[test]
  fn insertion_observes_already_finished_jobs_and_full_returns_original_job() {
    let mut set = TaskSet::new(1).unwrap();
    let (first, first_state, _) = manual_job();
    assert!(first_state.publish(Ok(5)).is_none());
    let id = set.try_insert(first).unwrap();

    let (second, _, aborts) = manual_job::<usize>();
    let returned = set.try_insert(second).unwrap_err();
    returned.abort();
    assert_eq!(aborts.load(Ordering::SeqCst), 1);

    match poll_join(&mut set) {
      Poll::Ready(Some((completed_id, Ok(5)))) => assert_eq!(completed_id, id),
      other => panic!("expected immediate completion, got {other:?}"),
    }
  }

  #[test]
  fn spawn_checks_set_capacity_before_executor_admission() {
    struct NeverPolled(Arc<AtomicUsize>);
    impl Future for NeverPolled {
      type Output = usize;
      fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
      }
    }
    impl Drop for NeverPolled {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }

    let runtime = AsyncRuntime::new(AsyncConfig {
      workers: 1,
      max_outstanding: 2,
      max_scopes: 1,
    })
    .unwrap();
    let handle = runtime.handle();
    let mut set = TaskSet::new(1).unwrap();
    set
      .try_spawn(&handle, std::future::pending::<usize>())
      .unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let rejected = set
      .try_spawn(&handle, NeverPolled(Arc::clone(&drops)))
      .unwrap_err();
    assert_eq!(rejected.kind, AsyncError::Full);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(rejected.into_future());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    set.abort_all();
    assert!(matches!(
      runtime.block_on(set.join_next()).unwrap(),
      Some((_, Err(AsyncJoinError::Cancelled)))
    ));
  }

  #[test]
  fn local_non_send_outputs_can_be_owned_and_joined_locally() {
    let mut set = TaskSet::new(1).unwrap();
    let (job, state, _) = manual_job::<std::rc::Rc<usize>>();
    let id = set.try_insert(job).unwrap();
    assert!(state.publish(Ok(std::rc::Rc::new(6))).is_none());
    assert!(matches!(
      poll_join(&mut set),
      Poll::Ready(Some((completed, Ok(value)))) if completed == id && *value == 6
    ));
  }

  #[test]
  fn stale_generation_notification_cannot_complete_reused_slot() {
    let mut set = TaskSet::new(1).unwrap();
    let (old, old_state, _) = manual_job::<usize>();
    let old_id = set.try_insert(old).unwrap();
    assert!(old_state.publish(Ok(1)).is_none());
    assert!(matches!(poll_join(&mut set), Poll::Ready(Some((id, Ok(1)))) if id == old_id));

    let (current, current_state, _) = manual_job::<usize>();
    let current_id = set.try_insert(current).unwrap();
    set.queue.notify(Notice {
      slot: old_id.slot(),
      generation: old_id.generation(),
    });
    assert!(poll_join(&mut set).is_pending());

    assert!(current_state.publish(Ok(2)).is_none());
    assert!(matches!(poll_join(&mut set), Poll::Ready(Some((id, Ok(2)))) if id == current_id));
  }

  #[test]
  fn empty_sets_have_no_capacity_and_ids_are_set_scoped() {
    let mut empty = TaskSet::<usize>::new(0).unwrap();
    assert!(empty.is_empty());
    assert!(!empty.has_capacity());
    assert!(matches!(poll_join(&mut empty), Poll::Ready(None)));

    let mut first = TaskSet::new(1).unwrap();
    let mut second = TaskSet::new(1).unwrap();
    let (first_job, first_state, _) = manual_job();
    let (second_job, second_state, _) = manual_job();
    let first_id = first.try_insert(first_job).unwrap();
    let second_id = second.try_insert(second_job).unwrap();
    assert_ne!(first_id, second_id);
    assert_ne!(first_id.set_identity(), second_id.set_identity());
    assert!(first_state.publish(Ok(1)).is_none());
    assert!(second_state.publish(Ok(2)).is_none());
  }

  #[test]
  fn maximum_slot_generation_retires_without_wrapping() {
    let mut set = TaskSet::new(1).unwrap();
    set.entries[0].generation = u64::MAX;
    set.queue.lock().slots[0].generation = u64::MAX;
    let (job, state, _) = manual_job();
    let id = set.try_insert(job).unwrap();
    assert_eq!(id.generation(), u64::MAX);
    assert!(state.publish(Ok(1)).is_none());
    assert!(
      matches!(poll_join(&mut set), Poll::Ready(Some((completed, Ok(1)))) if completed == id)
    );
    assert!(!set.has_capacity());
  }

  #[test]
  fn publication_racing_observer_registration_is_not_lost() {
    for _ in 0..64 {
      let mut set = TaskSet::new(1).unwrap();
      let (job, state, _) = manual_job();
      let barrier = Arc::new(std::sync::Barrier::new(2));
      let publisher_barrier = Arc::clone(&barrier);
      let publisher = std::thread::spawn(move || {
        publisher_barrier.wait();
        assert!(state.publish(Ok(4)).is_none());
      });
      barrier.wait();
      set.try_insert(job).unwrap();
      publisher.join().unwrap();
      assert!(matches!(poll_join(&mut set), Poll::Ready(Some((_, Ok(4))))));
    }
  }

  #[test]
  fn publication_racing_join_next_registration_is_not_lost() {
    for _ in 0..64 {
      let mut set = TaskSet::new(1).unwrap();
      let (job, state, _) = manual_job();
      set.try_insert(job).unwrap();
      let barrier = Arc::new(std::sync::Barrier::new(2));
      let publisher_barrier = Arc::clone(&barrier);
      let publisher = std::thread::spawn(move || {
        publisher_barrier.wait();
        assert!(state.publish(Ok(8)).is_none());
      });
      let mut next = Box::pin(set.join_next());
      let mut context = Context::from_waker(Waker::noop());
      barrier.wait();
      let first = Pin::as_mut(&mut next).poll(&mut context);
      publisher.join().unwrap();
      let completed = match first {
        Poll::Ready(completed) => completed,
        Poll::Pending => match Pin::as_mut(&mut next).poll(&mut context) {
          Poll::Ready(completed) => completed,
          Poll::Pending => panic!("completion notification was lost"),
        },
      };
      assert!(matches!(completed, Some((_, Ok(8)))));
    }
  }

  #[test]
  fn completion_queue_wakes_parent_outside_its_mutex() {
    struct ReentrantWake(Arc<CompletionQueue>);
    impl Wake for ReentrantWake {
      fn wake(self: Arc<Self>) {
        self.0.has_capacity();
      }
      fn wake_by_ref(self: &Arc<Self>) {
        self.0.has_capacity();
      }
    }

    let queue = Arc::new(CompletionQueue {
      state: Mutex::new(super::QueueState {
        slots: vec![NoticeSlot {
          generation: 1,
          occupied: true,
          queued: false,
          retired: false,
        }],
        notices: VecDeque::with_capacity(1),
        consumer: None,
      }),
    });
    queue.register_consumer(Waker::from(Arc::new(ReentrantWake(Arc::clone(&queue)))));
    let worker_queue = Arc::clone(&queue);
    std::thread::spawn(move || {
      worker_queue.notify(Notice {
        slot: 0,
        generation: 1,
      })
    })
    .join()
    .unwrap();
  }

  #[test]
  fn dropping_pending_join_next_removes_its_parent_waker() {
    struct CountDrop(Arc<AtomicUsize>, Arc<AtomicUsize>);
    impl Wake for CountDrop {
      fn wake(self: Arc<Self>) {
        self.1.fetch_add(1, Ordering::SeqCst);
      }
      fn wake_by_ref(self: &Arc<Self>) {
        self.1.fetch_add(1, Ordering::SeqCst);
      }
    }
    impl Drop for CountDrop {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }

    let mut set = TaskSet::new(1).unwrap();
    let (job, _, _) = manual_job::<usize>();
    set.try_insert(job).unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let data = Arc::new(CountDrop(Arc::clone(&drops), Arc::new(AtomicUsize::new(0))));
    let waker = Waker::from(Arc::clone(&data));
    {
      let mut context = Context::from_waker(&waker);
      {
        let mut next = Box::pin(set.join_next());
        assert!(Pin::as_mut(&mut next).poll(&mut context).is_pending());
        assert_eq!(Arc::strong_count(&data), 3);
      }
    }
    assert_eq!(Arc::strong_count(&data), 2);
    drop(waker);
    drop(data);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn dropping_parent_waker_runs_reentrant_drop_outside_queue_lock() {
    struct ReentrantDrop {
      queue: Arc<CompletionQueue>,
      dropped: Arc<std::sync::atomic::AtomicBool>,
      wakes: Arc<AtomicUsize>,
    }
    impl Wake for ReentrantDrop {
      fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
      }
    }
    impl Drop for ReentrantDrop {
      fn drop(&mut self) {
        let _ = self.queue.has_capacity();
        self.dropped.store(true, Ordering::SeqCst);
      }
    }

    let mut set = TaskSet::new(1).unwrap();
    let (job, _, _) = manual_job::<usize>();
    set.try_insert(job).unwrap();
    let queue = Arc::clone(&set.queue);
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let data = Arc::new(ReentrantDrop {
      queue,
      dropped: Arc::clone(&dropped),
      wakes: Arc::new(AtomicUsize::new(0)),
    });
    let waker = Waker::from(Arc::clone(&data));
    let mut next = Box::pin(set.join_next());
    {
      let mut context = Context::from_waker(&waker);
      assert!(Pin::as_mut(&mut next).poll(&mut context).is_pending());
    }
    drop(waker);
    drop(data);
    drop(next);
    assert!(dropped.load(Ordering::SeqCst));
  }

  #[test]
  fn dropping_join_next_contains_a_panicking_parent_waker_destructor() {
    struct PanicOnDrop(Arc<AtomicUsize>);
    impl Wake for PanicOnDrop {
      fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }
    impl Drop for PanicOnDrop {
      fn drop(&mut self) {
        panic!("parent waker destructor panic");
      }
    }

    let mut set = TaskSet::new(1).unwrap();
    let (job, _, _) = manual_job::<usize>();
    set.try_insert(job).unwrap();
    let wake_count = Arc::new(AtomicUsize::new(0));
    let data = Arc::new(PanicOnDrop(Arc::clone(&wake_count)));
    let waker = Waker::from(Arc::clone(&data));
    let mut next = Box::pin(set.join_next());
    {
      let mut context = Context::from_waker(&waker);
      assert!(Pin::as_mut(&mut next).poll(&mut context).is_pending());
    }
    drop(waker);
    drop(data);
    drop(next);
    assert_eq!(wake_count.load(Ordering::SeqCst), 0);
  }

  #[test]
  fn managed_result_remains_charged_after_join_next_returns_it() {
    let resources = ResourceScope::new(ResourceLimits {
      managed_memory: 16,
      ..ResourceLimits::default()
    });
    let buffer = resources.try_alloc_zeroed(8).unwrap();
    let mut set = TaskSet::new(1).unwrap();
    let (job, state, _) = manual_job();
    let id = set.try_insert(job).unwrap();
    assert!(state.publish(Ok(buffer)).is_none());

    let result = match poll_join(&mut set) {
      Poll::Ready(Some((completed_id, Ok(buffer)))) => {
        assert_eq!(completed_id, id);
        buffer
      }
      other => panic!("expected managed result, got {other:?}"),
    };
    assert_eq!(resources.snapshot().managed_memory, result.charged_bytes());
    drop(result);
    assert_eq!(resources.snapshot().managed_memory, 0);
  }

  #[test]
  fn set_drop_aborts_all_jobs_before_dropping_ready_results() {
    struct ObserveAbort {
      observed: Arc<AtomicUsize>,
      dropped_with_aborts: Arc<AtomicUsize>,
    }
    impl Drop for ObserveAbort {
      fn drop(&mut self) {
        self
          .dropped_with_aborts
          .store(self.observed.load(Ordering::SeqCst), Ordering::SeqCst);
      }
    }

    let mut set = TaskSet::new(1).unwrap();
    let (job, state, aborts) = manual_job();
    set.try_insert(job).unwrap();
    let dropped_with_aborts = Arc::new(AtomicUsize::new(0));
    assert!(
      state
        .publish(Ok(ObserveAbort {
          observed: Arc::clone(&aborts),
          dropped_with_aborts: Arc::clone(&dropped_with_aborts)
        }))
        .is_none()
    );
    drop(set);
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
    assert_eq!(dropped_with_aborts.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn panicking_abort_callbacks_do_not_skip_later_jobs() {
    let mut set = TaskSet::new(2).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    for _ in 0..2 {
      let state = JoinState::<usize>::new();
      let observed = Arc::clone(&calls);
      let job = AsyncJob::new(
        state,
        Arc::new(move || {
          observed.fetch_add(1, Ordering::SeqCst);
          panic!("abort callback panic");
        }),
      );
      set.try_insert(job).unwrap();
    }
    set.abort_all();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
  }

  #[test]
  fn set_drop_contains_multiple_panicking_result_destructors() {
    struct PanicDrop(Arc<AtomicUsize>);
    impl Drop for PanicDrop {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("result destructor panic");
      }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let mut set = TaskSet::new(2).unwrap();
    for _ in 0..2 {
      let (job, state, _) = manual_job();
      set.try_insert(job).unwrap();
      assert!(state.publish(Ok(PanicDrop(Arc::clone(&drops)))).is_none());
    }
    drop(set);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
  }

  #[test]
  fn cancellation_and_panic_outcomes_are_yielded_without_special_storage() {
    let mut set = TaskSet::new(2).unwrap();
    let (cancelled, cancelled_state, _) = manual_job::<usize>();
    let (panicked, panicked_state, _) = manual_job::<usize>();
    let cancelled_id = set.try_insert(cancelled).unwrap();
    let panicked_id = set.try_insert(panicked).unwrap();
    assert!(
      cancelled_state
        .publish(Err(AsyncJoinError::Cancelled))
        .is_none()
    );
    assert!(
      panicked_state
        .publish(Err(AsyncJoinError::Panicked(Box::new("panic"))))
        .is_none()
    );
    assert!(
      matches!(poll_join(&mut set), Poll::Ready(Some((id, Err(AsyncJoinError::Cancelled)))) if id == cancelled_id)
    );
    assert!(
      matches!(poll_join(&mut set), Poll::Ready(Some((id, Err(AsyncJoinError::Panicked(_))))) if id == panicked_id)
    );
  }
}

#[cfg(all(test, loom))]
mod model {
  // These models exercise the production queue mutex transitions only. They
  // omit TaskSet entry ownership, executor scheduling, and user waker behavior.
  use super::{CompletionQueue, Notice, NoticeSlot, QueueState};
  use loom::sync::{Arc, Mutex};
  use loom::thread;
  use std::collections::VecDeque;

  fn queue() -> Arc<CompletionQueue> {
    Arc::new(CompletionQueue {
      state: Mutex::new(QueueState {
        slots: vec![NoticeSlot {
          generation: 1,
          occupied: true,
          queued: false,
          retired: false,
        }],
        notices: VecDeque::with_capacity(1),
        consumer: None,
      }),
    })
  }

  #[test]
  fn simultaneous_notifications_coalesce_once() {
    loom::model(|| {
      let queue = queue();
      let first = Arc::clone(&queue);
      let second = Arc::clone(&queue);
      let a = thread::spawn(move || {
        first.notify(Notice {
          slot: 0,
          generation: 1,
        })
      });
      let b = thread::spawn(move || {
        second.notify(Notice {
          slot: 0,
          generation: 1,
        })
      });
      a.join().unwrap();
      b.join().unwrap();
      assert!(queue.take_notice().is_some());
      assert!(queue.take_notice().is_none());
    });
  }

  #[test]
  fn removal_racing_notification_leaves_no_old_generation_notice() {
    loom::model(|| {
      let queue = queue();
      let notifier = Arc::clone(&queue);
      let remover = Arc::clone(&queue);
      let notify = thread::spawn(move || {
        notifier.notify(Notice {
          slot: 0,
          generation: 1,
        })
      });
      let remove = thread::spawn(move || {
        remover.release(Notice {
          slot: 0,
          generation: 1,
        })
      });
      notify.join().unwrap();
      assert_eq!(remove.join().unwrap(), Some(2));
      assert!(queue.take_notice().is_none());
      assert!(queue.has_capacity());
    });
  }
}
