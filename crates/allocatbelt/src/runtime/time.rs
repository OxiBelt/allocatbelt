//! A bounded timer driver: one service thread completes [`Sleep`] futures at
//! their deadlines under a fixed bound on outstanding registrations, and
//! [`Timeout`] and [`Interval`] are built on those sleeps. Like the rest of
//! the runtime this is an experimental research foundation.
//!
//! # Ownership
//!
//! A [`TimerDriver`] owns the service thread. [`TimerHandle`]s are clonable
//! and create timers, but do not keep the driver running. Dropping the
//! driver, or [`TimerDriver::shutdown`], closes it: every still-registered
//! sleep resolves to [`TimerError::Closed`] and its waker runs on the thread
//! that owns the close drain before that close returns; concurrent external
//! callers wait for the drain, and every later registration through any
//! handle is refused with `Closed`.
//! `shutdown` then joins the service
//! thread unless it runs on that thread (from a waker the driver wakes),
//! where it returns [`TimerError::WouldDeadlock`] instead of joining itself.
//! A close owner wakes registered sleeps with `Closed` before the close
//! completes; concurrent close callers wait for that drain, except a service
//! thread caller which must not wait on an external waker that might join it.
//! Dropping the driver never joins; the thread exits on its own once it sees
//! the close.
//! A sleep already fired and removed from the registration table keeps its
//! published `Ok` outcome. Its service-thread callback may still run after
//! driver drop returns. An external `shutdown` joins that thread and waits
//! for those callbacks too; a service-thread `shutdown` returns
//! `WouldDeadlock` after closing instead of waiting for its own callback.
//!
//! # Registrations
//!
//! A sleep whose deadline is in the future holds one of the driver's
//! `max_registered` registrations while it waits. The registration is
//! released when the driver fires the sleep, when the driver closes, when
//! the sleep is reset to a deadline already reached, or when it is dropped,
//! which cancels it. In each case the release happens before the outcome is
//! published or a waker is woken, so a task that observes completion also
//! observes the freed capacity. A sleep whose deadline has already been
//! reached when it is created or reset completes at once and holds no
//! registration, so it is accepted even while every registration is taken.
//!
//! Every arming of a sleep (creation or reset) gets a fresh 64-bit generation
//! id in a preallocated indexed min-heap and registration table. Moving a
//! sleep updates its heap entry under the same lock that changes its current
//! key, and the driver completes a sleep only when the fired generation is
//! still current, so a deadline a sleep was reset away from never completes
//! it. Equal deadlines fire in arming order.
//!
//! The bound counts registrations. The driver reserves its heap, table and
//! free-index storage at construction; reservation failure returns
//! `TimerError::OutOfMemory`. Each sleep still allocates shared state through
//! the global allocator. Completion batches use fixed-size stack storage.
//!
//! # Deadlines
//!
//! A real-clock driver fires a sleep once its monotonic clock on the service
//! thread reaches the deadline, never earlier; it is late by the thread's
//! scheduling latency. Between deadlines the thread waits on a condition
//! variable until the earliest deadline or a new earlier registration; it
//! does not poll. There is no thread per sleep.
//! [`TimerDriver::new_paused`] instead supplies a [`ManualClock`]: real time
//! never fires its registrations, and `advance` publishes due outcomes through
//! fixed batches on the advancing thread. Sleeps, timeouts, intervals and
//! resets all use that driver's clock. Advancement does not poll executor
//! tasks or automatically jump to the next deadline when tasks are idle.
//!
//! # Locks and user code
//!
//! The driver lock guards the queue; each sleep's lock guards its outcome
//! and stored waker, and is only ever taken inside the driver lock or alone.
//! Neither lock is held while a waker is cloned, woken or dropped. `poll`
//! clones the task's waker before it takes the sleep lock and rechecks the
//! outcome under it, and the driver publishes an outcome and takes the waker
//! under that same lock, so a wakeup is never lost. Stored wakers are
//! replaced or taken under the lock and dropped or woken after it is
//! released.
//!
//! A panic of a waker's `wake` or `Drop` run by the timer is contained, and
//! a panic payload whose own `Drop` panics is leaked, so the service thread
//! keeps running. Cloning the task's waker in `poll` is not contained: it
//! happens before anything changes and unwinds to the caller, as does a
//! panic of the inner future of a [`Timeout`]. With `panic = abort`, or a
//! panic while already unwinding, the process aborts as usual.
//!
//! # Timeouts
//!
//! [`Timeout`] boxes its inner future, so it is `Unpin` without unsafe
//! pinning. Ties go to the deadline: each poll first checks the timer and
//! returns [`TimeoutError::Elapsed`] when the sleep has fired or
//! the driver's clock has reached the deadline, or [`TimeoutError::Timer`]
//! when the driver closed, without polling the inner future. Only otherwise
//! is the inner future polled. A zero timeout therefore always elapses and
//! never polls its future. On completion the sleep is dropped, returning its
//! registration, and then the inner future, before the result is returned.
//!
//! # Intervals
//!
//! An [`Interval`] ticks first at its start (at once for
//! [`TimerHandle::interval`]) and then every period. When a tick is observed
//! more than five milliseconds after its scheduled deadline, its
//! [`MissedTickBehavior`] chooses the next deadline with a constant number of
//! checked operations, never a catch-up loop. A tick is returned only after
//! the following deadline is armed; when arming fails (`Full`, `Closed`, or
//! `Invalid` for an unrepresentable deadline) the error is returned instead
//! and the tick stays due.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::{Duration, Instant};

use crate::runtime::task::drop_contained;

/// Registrations taken off the queue per driver lock acquisition, by the
/// service thread or a close. Their wakers run after the lock is released.
const BATCH: usize = 64;

/// Identifies one use of an indexed registration slot. `generation` is a
/// globally increasing arming id, so a stale sleep cannot remove a reused
/// slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Key {
  index: usize,
  generation: u64,
}

/// Why a timer could not be created, reset or completed, or the driver
/// could not reserve storage, start or shut down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TimerError {
  /// A zero registration bound or interval period, or a deadline `Instant`
  /// cannot represent.
  Invalid,
  /// Every registration is taken (or, never in practice, the 64-bit arming
  /// ids are exhausted).
  Full,
  /// The timer could not reserve its bounded registration storage.
  OutOfMemory,
  /// The driver was shut down or dropped.
  Closed,
  /// The service thread could not be started.
  Spawn,
  /// [`TimerDriver::shutdown`] ran on the service thread, which cannot join
  /// itself. The driver is closed nonetheless.
  WouldDeadlock,
  /// The service thread panicked.
  DriverPanicked,
}

impl fmt::Display for TimerError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Invalid => "invalid timer bound, period or deadline",
      Self::Full => "timer registration bound reached",
      Self::OutOfMemory => "timer registration storage could not be reserved",
      Self::Closed => "timer driver is closed",
      Self::Spawn => "timer service thread could not be started",
      Self::WouldDeadlock => "timer shutdown from its service thread would deadlock",
      Self::DriverPanicked => "timer service thread panicked",
    })
  }
}

impl std::error::Error for TimerError {}

/// Why a [`Timeout`] completed without its inner future's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TimeoutError {
  /// The deadline was reached first (ties included).
  Elapsed,
  /// The timer failed first: the driver closed.
  Timer(TimerError),
}

impl fmt::Display for TimeoutError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Elapsed => f.write_str("deadline elapsed"),
      Self::Timer(error) => write!(f, "timeout timer failed: {error}"),
    }
  }
}

impl std::error::Error for TimeoutError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Elapsed => None,
      Self::Timer(error) => Some(error),
    }
  }
}

struct Shared {
  state: Mutex<State>,
  /// Signals the service thread: a new earliest registration, or the close.
  wakeup: Condvar,
  max_registered: usize,
}

/// The registrations, under the driver lock.
struct State {
  closed: bool,
  close_complete: bool,
  close_owner: Option<ThreadId>,
  next_id: u64,
  manual_now: Option<Instant>,
  queue: RegistrationQueue,
}

impl State {
  fn now(&self) -> Instant {
    self.manual_now.unwrap_or_else(Instant::now)
  }
}

/// Bounded indexed min-heap. Every backing vector is reserved at driver
/// construction; inserting, moving and removing a registration never grows
/// a collection. Heap positions live here rather than in `Slot`, so heap
/// swaps never acquire another sleep lock.
struct RegistrationQueue {
  entries: Vec<Option<Entry>>,
  free: Vec<usize>,
  heap: Vec<usize>,
}

struct Entry {
  key: Key,
  deadline: Instant,
  heap_position: usize,
  slot: Weak<Slot>,
}

impl RegistrationQueue {
  fn new(capacity: usize) -> Result<Self, TimerError> {
    let mut entries = Vec::new();
    entries
      .try_reserve_exact(capacity)
      .map_err(|_| TimerError::OutOfMemory)?;
    entries.resize_with(capacity, || None);

    let mut free = Vec::new();
    free
      .try_reserve_exact(capacity)
      .map_err(|_| TimerError::OutOfMemory)?;
    free.extend((0..capacity).rev());

    let mut heap = Vec::new();
    heap
      .try_reserve_exact(capacity)
      .map_err(|_| TimerError::OutOfMemory)?;
    Ok(Self {
      entries,
      free,
      heap,
    })
  }

  fn len(&self) -> usize {
    self.heap.len()
  }

  fn first(&self) -> Option<Key> {
    self.heap.first().and_then(|index| {
      self
        .entries
        .get(*index)
        .and_then(Option::as_ref)
        .map(|entry| entry.key)
    })
  }

  fn first_deadline(&self) -> Option<Instant> {
    self.heap.first().and_then(|index| {
      self
        .entries
        .get(*index)
        .and_then(Option::as_ref)
        .map(|entry| entry.deadline)
    })
  }

  fn get(&self, key: Key) -> Option<&Entry> {
    self
      .entries
      .get(key.index)?
      .as_ref()
      .filter(|entry| entry.key == key)
  }

  fn insert(&mut self, deadline: Instant, generation: u64, slot: Weak<Slot>) -> Option<Key> {
    let index = self.free.pop()?;
    let key = Key { index, generation };
    let heap_position = self.heap.len();
    self.entries[index] = Some(Entry {
      key,
      deadline,
      heap_position,
      slot,
    });
    self.heap.push(index);
    self.sift_up(heap_position);
    Some(key)
  }

  fn update(&mut self, key: Key, deadline: Instant, generation: u64) -> Option<Key> {
    let entry = self.entries.get_mut(key.index)?.as_mut()?;
    if entry.key != key {
      return None;
    }
    let new_key = Key {
      index: key.index,
      generation,
    };
    entry.key = new_key;
    entry.deadline = deadline;
    let position = entry.heap_position;
    self.repair(position);
    Some(new_key)
  }

  fn remove(&mut self, key: Key) -> Option<Weak<Slot>> {
    let entry = self.get(key)?;
    let position = entry.heap_position;
    self.heap.swap_remove(position);
    let removed = self.entries[key.index].take()?;
    self.free.push(key.index);
    if position < self.heap.len() {
      let moved_index = self.heap[position];
      if let Some(moved) = self.entries[moved_index].as_mut() {
        moved.heap_position = position;
      }
      self.repair(position);
    }
    Some(removed.slot)
  }

  fn pop_first(&mut self) -> Option<(Key, Instant, Weak<Slot>)> {
    let key = self.first()?;
    let deadline = self.get(key)?.deadline;
    self.remove(key).map(|slot| (key, deadline, slot))
  }

  fn pop_due(&mut self, due: Instant) -> Option<(Key, Instant, Weak<Slot>)> {
    if self
      .first_deadline()
      .is_some_and(|deadline| deadline <= due)
    {
      self.pop_first()
    } else {
      None
    }
  }

  fn less_at(&self, left: usize, right: usize) -> bool {
    let Some(left_entry) = self
      .heap
      .get(left)
      .and_then(|index| self.entries.get(*index))
      .and_then(Option::as_ref)
    else {
      return false;
    };
    let Some(right_entry) = self
      .heap
      .get(right)
      .and_then(|index| self.entries.get(*index))
      .and_then(Option::as_ref)
    else {
      return false;
    };
    (left_entry.deadline, left_entry.key.generation)
      < (right_entry.deadline, right_entry.key.generation)
  }

  fn swap_heap(&mut self, left: usize, right: usize) {
    self.heap.swap(left, right);
    if let Some(entry) = self.entries[self.heap[left]].as_mut() {
      entry.heap_position = left;
    }
    if let Some(entry) = self.entries[self.heap[right]].as_mut() {
      entry.heap_position = right;
    }
  }

  fn sift_up(&mut self, mut position: usize) {
    while position > 0 {
      let parent = (position - 1) / 2;
      if !self.less_at(position, parent) {
        break;
      }
      self.swap_heap(position, parent);
      position = parent;
    }
  }

  fn sift_down(&mut self, mut position: usize) {
    loop {
      let left = position * 2 + 1;
      if left >= self.heap.len() {
        break;
      }
      let right = left + 1;
      let child = if right < self.heap.len() && self.less_at(right, left) {
        right
      } else {
        left
      };
      if !self.less_at(child, position) {
        break;
      }
      self.swap_heap(position, child);
      position = child;
    }
  }

  fn repair(&mut self, position: usize) {
    if position > 0 && self.less_at(position, (position - 1) / 2) {
      self.sift_up(position);
    } else {
      self.sift_down(position);
    }
  }

  #[cfg(all(test, not(loom)))]
  fn deadlines(&self) -> Vec<Instant> {
    let mut deadlines = self
      .heap
      .iter()
      .filter_map(|index| self.entries.get(*index).and_then(Option::as_ref))
      .map(|entry| entry.deadline)
      .collect::<Vec<_>>();
    deadlines.sort_unstable();
    deadlines
  }
}

/// One sleep's completion state, shared with the queue by a `Weak`.
struct Slot {
  state: Mutex<SlotState>,
}

/// Invariant: while its sleep lives and after it was first armed, exactly
/// one of `key` (registered) and `outcome` (completed) is set. `key` is
/// only set behind the sleep's `&mut self`, with the driver lock held.
struct SlotState {
  key: Option<Key>,
  outcome: Option<Result<(), TimerError>>,
  waker: Option<Waker>,
}

impl SlotState {
  /// Publishes a transition under the slot lock; only the current generation
  /// may complete this sleep.
  fn publish(&mut self, key: Key, outcome: Result<(), TimerError>) -> Option<Waker> {
    if self.key != Some(key) {
      return None;
    }
    self.key = None;
    self.outcome = Some(outcome);
    self.waker.take()
  }

  /// Updates the current arming after its queue entry has been secured.
  fn arm(&mut self, key: Key) {
    self.key = Some(key);
    self.outcome = None;
  }

  fn complete_current(&mut self, outcome: Result<(), TimerError>) -> Option<Waker> {
    self.key = None;
    self.outcome = Some(outcome);
    self.waker.take()
  }

  /// Rechecks completion and registers the cloned task waker atomically with
  /// respect to publication.
  fn register_waker(&mut self, waker: Waker) -> (Poll<Result<(), TimerError>>, Option<Waker>) {
    match self.outcome {
      Some(outcome) => (Poll::Ready(outcome), Some(waker)),
      None => (Poll::Pending, self.waker.replace(waker)),
    }
  }
}

/// What arming did, finished by [`Shared::finish`] once the locks are
/// released.
enum Armed {
  /// Registered; `earliest` when it now has the first deadline.
  Registered { earliest: bool },
  /// The deadline had been reached: completed, with any waker to wake.
  Elapsed(Option<Waker>),
}

/// A registration taken off the queue, woken and dropped after the driver
/// lock is released.
struct Fired {
  slot: Arc<Slot>,
  waker: Option<Waker>,
}

/// Fixed-size completion scratch space, so timer firing and close do not
/// allocate while removing registrations.
struct FiredBatch {
  entries: [Option<Fired>; BATCH],
  len: usize,
}

impl FiredBatch {
  fn new() -> Self {
    Self {
      entries: std::array::from_fn(|_| None),
      len: 0,
    }
  }

  fn len(&self) -> usize {
    self.len
  }

  fn is_empty(&self) -> bool {
    self.len == 0
  }

  fn push(&mut self, fired: Fired) {
    if let Some(slot) = self.entries.get_mut(self.len) {
      *slot = Some(fired);
      self.len += 1;
    }
  }

  fn drain(&mut self) -> impl Iterator<Item = Fired> + '_ {
    let len = std::mem::replace(&mut self.len, 0);
    self.entries[..len].iter_mut().filter_map(Option::take)
  }
}

/// No user code runs, and nothing the timer does panics, while a timer lock
/// is held, so a poisoned lock still holds consistent state.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Waits on `wakeup`, for at most `timeout` when one is given.
fn wait<'a>(
  wakeup: &Condvar,
  state: MutexGuard<'a, State>,
  timeout: Option<Duration>,
) -> MutexGuard<'a, State> {
  let Some(timeout) = timeout else {
    return wakeup.wait(state).unwrap_or_else(PoisonError::into_inner);
  };
  let waited = wakeup.wait_timeout(state, timeout);
  waited.unwrap_or_else(PoisonError::into_inner).0
}

/// Wakes `waker`, containing a panic of its `wake` or of the `Drop` that
/// `wake` may run.
fn wake_contained(waker: Waker) {
  if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(move || waker.wake())) {
    drop_contained(payload);
  }
}

impl Shared {
  /// Arms `slot` for `deadline`, observed at `now`: registers it, moving an
  /// existing registration, or completes it at once when the deadline has
  /// been reached, releasing any registration. On an error nothing changed.
  fn arm(
    &self,
    state: &mut State,
    slot: &Arc<Slot>,
    armed: &mut SlotState,
    deadline: Instant,
    now: Instant,
  ) -> Result<Armed, TimerError> {
    if state.closed {
      return Err(TimerError::Closed);
    }
    if deadline <= now {
      if armed.key.is_some_and(|old| state.queue.get(old).is_none()) {
        return Err(TimerError::Invalid);
      }
      if let Some(old) = armed.key.take() {
        let _ = state.queue.remove(old);
      }
      return Ok(Armed::Elapsed(armed.complete_current(Ok(()))));
    }
    let id = state.next_id;
    let next_id = id.checked_add(1).ok_or(TimerError::Full)?;
    if armed.key.is_none() && state.queue.len() >= self.max_registered {
      return Err(TimerError::Full);
    }
    let key = if let Some(old) = armed.key {
      state
        .queue
        .update(old, deadline, id)
        .ok_or(TimerError::Invalid)?
    } else {
      state
        .queue
        .insert(deadline, id, Arc::downgrade(slot))
        .ok_or(TimerError::Full)?
    };
    state.next_id = next_id;
    armed.arm(key);
    let earliest = state.queue.first() == Some(key);
    Ok(Armed::Registered { earliest })
  }

  /// [`Shared::arm`] under both locks, taken in the driver-then-sleep order.
  fn arm_locked(&self, slot: &Arc<Slot>, deadline: Instant) -> Result<Armed, TimerError> {
    let mut state = lock(&self.state);
    let mut armed = lock(&slot.state);
    let now = state.now();
    self.arm(&mut state, slot, &mut armed, deadline, now)
  }

  /// Finishes an arming with no lock held.
  fn finish(&self, armed: Armed) {
    match armed {
      Armed::Registered { earliest: true } => self.wakeup.notify_one(),
      Armed::Registered { earliest: false } | Armed::Elapsed(None) => {}
      Armed::Elapsed(Some(waker)) => wake_contained(waker),
    }
  }

  /// Claims and performs close, or waits for the current close owner to
  /// finish. A service-thread caller never waits for an external closer: that
  /// closer may be running a waker that joins the service thread.
  fn close(&self, called_from_service: bool) {
    let owner = thread::current().id();
    let mut state = lock(&self.state);
    loop {
      if !state.closed {
        state.closed = true;
        state.close_owner = Some(owner);
        break;
      }
      if state.close_complete || state.close_owner == Some(owner) || called_from_service {
        return;
      }
      state = self
        .wakeup
        .wait(state)
        .unwrap_or_else(PoisonError::into_inner);
    }
    drop(state);
    self.wakeup.notify_all();
    self.finish_close();
  }

  /// The service thread claims close on an unexpected exit, but returns if an
  /// external caller already owns the drain instead of stealing a batch.
  fn close_from_service(&self) {
    let owner = thread::current().id();
    let mut state = lock(&self.state);
    if state.closed {
      return;
    }
    state.closed = true;
    state.close_owner = Some(owner);
    drop(state);
    self.wakeup.notify_all();
    self.finish_close();
  }

  fn finish_close(&self) {
    let mut batch = FiredBatch::new();
    loop {
      {
        let mut state = lock(&self.state);
        take_due(&mut state, None, Err(TimerError::Closed), &mut batch);
        if batch.is_empty() {
          state.close_complete = true;
          state.close_owner = None;
          drop(state);
          self.wakeup.notify_all();
          return;
        }
      }
      complete(&mut batch);
    }
  }

  fn registered(&self) -> usize {
    lock(&self.state).queue.len()
  }

  fn now(&self) -> Instant {
    lock(&self.state).now()
  }

  fn is_closed(&self) -> bool {
    lock(&self.state).closed
  }
}

/// Takes up to [`BATCH`] registrations off the front of the queue: those
/// due by `due`, or any when it is `None`. Each is released (removed) before
/// `outcome` is published to its sleep; its slot and taken waker go to
/// `batch`, so both are woken or dropped after the driver lock is released.
fn take_due(
  state: &mut State,
  due: Option<Instant>,
  outcome: Result<(), TimerError>,
  batch: &mut FiredBatch,
) {
  while batch.len() < BATCH {
    let next = match due {
      Some(due) => state.queue.pop_due(due),
      None => state.queue.pop_first(),
    };
    let Some((key, _, weak)) = next else {
      break;
    };
    // A sleep unregisters before its slot is freed, so this always upgrades.
    let Some(slot) = weak.upgrade() else {
      continue;
    };
    let waker = {
      let mut armed = lock(&slot.state);
      armed.publish(key, outcome)
    };
    batch.push(Fired { slot, waker });
  }
}

/// Wakes and drops what [`take_due`] collected, with no lock held.
fn complete(batch: &mut FiredBatch) {
  for Fired { slot, waker } in batch.drain() {
    if let Some(waker) = waker {
      wake_contained(waker);
    }
    // Possibly the last reference. Its waker was taken, but the drop is
    // contained regardless.
    drop_contained(slot);
  }
}

/// Closes the driver when the service thread exits, unwinding included, so
/// no sleep waits on a thread that is gone.
struct CloseOnExit<'a>(&'a Shared);

impl Drop for CloseOnExit<'_> {
  fn drop(&mut self) {
    self.0.close_from_service();
  }
}

/// The service thread: fires due registrations in deadline order and waits
/// for the next deadline, until the driver closes.
fn drive(shared: &Shared) {
  let _close = CloseOnExit(shared);
  let mut batch = FiredBatch::new();
  // Declared last, so released before `_close` takes the lock again.
  let mut state = lock(&shared.state);
  while !state.closed {
    if state.manual_now.is_some() {
      state = wait(&shared.wakeup, state, None);
      continue;
    }
    let now = state.now();
    let earliest = state.queue.first_deadline();
    match earliest {
      None => state = wait(&shared.wakeup, state, None),
      Some(deadline) if deadline > now => {
        let timeout = deadline.duration_since(now);
        state = wait(&shared.wakeup, state, Some(timeout));
      }
      Some(_) => {
        take_due(&mut state, Some(now), Ok(()), &mut batch);
        drop(state);
        complete(&mut batch);
        state = lock(&shared.state);
      }
    }
  }
}

/// Owns the timer's service thread; see the module documentation.
pub struct TimerDriver {
  shared: Arc<Shared>,
  thread: Option<JoinHandle<()>>,
}

impl TimerDriver {
  /// Reserves storage for at most `max_registered` outstanding registrations
  /// and starts the service thread.
  ///
  /// # Errors
  ///
  /// `Invalid` when `max_registered` is zero, `OutOfMemory` when bounded
  /// registration storage cannot be reserved, and `Spawn` when the thread
  /// cannot be started.
  pub fn new(max_registered: usize) -> Result<Self, TimerError> {
    Self::build(max_registered, None)
  }

  /// Creates a driver whose clock advances only through [`ManualClock::advance`].
  /// The clock starts at construction's `Instant`; use [`TimerHandle::now`]
  /// for deadlines. Advancing publishes due outcomes synchronously, without
  /// automatically driving an executor or jumping time when tasks are idle.
  pub fn new_paused(max_registered: usize) -> Result<(Self, ManualClock), TimerError> {
    let driver = Self::build(max_registered, Some(Instant::now()))?;
    let clock = ManualClock {
      shared: Arc::clone(&driver.shared),
    };
    Ok((driver, clock))
  }

  fn build(max_registered: usize, manual_now: Option<Instant>) -> Result<Self, TimerError> {
    if max_registered == 0 {
      return Err(TimerError::Invalid);
    }
    let shared = Arc::new(Shared {
      state: Mutex::new(State {
        closed: false,
        close_complete: false,
        close_owner: None,
        next_id: 0,
        manual_now,
        queue: RegistrationQueue::new(max_registered)?,
      }),
      wakeup: Condvar::new(),
      max_registered,
    });
    let worker = Arc::clone(&shared);
    let thread = thread::Builder::new()
      .name("allocatbelt-timer".into())
      .spawn(move || drive(&worker))
      .map_err(|_| TimerError::Spawn)?;
    Ok(Self {
      shared,
      thread: Some(thread),
    })
  }

  /// A clonable handle that creates timers on this driver.
  #[must_use]
  pub fn handle(&self) -> TimerHandle {
    TimerHandle {
      shared: Arc::clone(&self.shared),
    }
  }

  /// Closes the driver, resolving and waking every registered sleep with
  /// `Closed` before returning, then waits for the service thread to exit.
  /// The thread that first claims close runs the wakers; concurrent callers
  /// wait for its drain to finish.
  ///
  /// # Errors
  ///
  /// `WouldDeadlock` when called on the service thread, which is then left
  /// to exit on its own; `DriverPanicked` when the service thread panicked.
  pub fn shutdown(mut self) -> Result<(), TimerError> {
    let on_service_thread = self
      .thread
      .as_ref()
      .is_some_and(|thread| thread.thread().id() == thread::current().id());
    self.shared.close(on_service_thread);
    if on_service_thread {
      return Err(TimerError::WouldDeadlock);
    }
    let Some(thread) = self.thread.take() else {
      return Ok(());
    };
    thread.join().map_err(|payload| {
      drop_contained(payload);
      TimerError::DriverPanicked
    })
  }
}

/// A monotonic manual clock belonging to exactly one paused driver.
/// Clones share the same clock and do not keep the driver open.
#[derive(Clone)]
pub struct ManualClock {
  shared: Arc<Shared>,
}

impl ManualClock {
  /// This driver's current time, unchanged by real elapsed time.
  #[must_use]
  pub fn now(&self) -> Instant {
    self.shared.now()
  }

  /// Advances by `duration` and publishes outcomes for registrations due at
  /// the new time. The clock update serializes with arming and other advances.
  /// Callback code runs outside locks and may advance this clock again.
  ///
  /// Returns the time of this update, which can precede a concurrent or
  /// reentrant advance. Callbacks already claimed by another advance may still
  /// be running. A concurrent driver close may resolve sleeps with `Closed`.
  /// `Invalid` (overflow) and a close observed before this update leave the
  /// clock unchanged. This neither polls tasks nor automatically advances idle
  /// time, and the real-clock driver cannot be paused after construction.
  pub fn advance(&self, duration: Duration) -> Result<Instant, TimerError> {
    let target = {
      let mut state = lock(&self.shared.state);
      if state.closed {
        return Err(TimerError::Closed);
      }
      let now = state.manual_now.ok_or(TimerError::Invalid)?;
      let target = now.checked_add(duration).ok_or(TimerError::Invalid)?;
      state.manual_now = Some(target);
      target
    };
    let mut batch = FiredBatch::new();
    loop {
      {
        let mut state = lock(&self.shared.state);
        if state.closed {
          break;
        }
        take_due(&mut state, Some(target), Ok(()), &mut batch);
      }
      if batch.is_empty() {
        break;
      }
      complete(&mut batch);
    }
    Ok(target)
  }
}

impl fmt::Debug for ManualClock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ManualClock")
      .field("now", &self.now())
      .finish()
  }
}

impl Drop for TimerDriver {
  fn drop(&mut self) {
    let on_service_thread = self
      .thread
      .as_ref()
      .is_some_and(|thread| thread.thread().id() == thread::current().id());
    self.shared.close(on_service_thread);
    // Dropping the `JoinHandle` detaches; the thread sees the close and
    // exits. Dropping the driver never blocks on a waker it is running.
    self.thread = None;
  }
}

impl fmt::Debug for TimerDriver {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("TimerDriver")
      .field("registered", &self.shared.registered())
      .field("max_registered", &self.shared.max_registered)
      .finish_non_exhaustive()
  }
}

/// Creates timers on a [`TimerDriver`]. Cloning shares the driver and
/// registers nothing; a handle does not keep the driver open.
#[derive(Clone)]
pub struct TimerHandle {
  shared: Arc<Shared>,
}

impl TimerHandle {
  /// This driver's clock: real monotonic time, or its controlled paused time.
  #[must_use]
  pub fn now(&self) -> Instant {
    self.shared.now()
  }
  /// A sleep that completes `duration` from now.
  ///
  /// # Errors
  ///
  /// As [`TimerHandle::sleep_until`], and `Invalid` when the deadline
  /// cannot be represented.
  pub fn sleep(&self, duration: Duration) -> Result<Sleep, TimerError> {
    let deadline = self
      .now()
      .checked_add(duration)
      .ok_or(TimerError::Invalid)?;
    self.sleep_until(deadline)
  }

  /// A sleep that completes at `deadline`: registered when the deadline is
  /// in the future, otherwise already complete and holding no registration.
  ///
  /// # Errors
  ///
  /// `Closed` once the driver closed; `Full` when the deadline is in the
  /// future and every registration is taken.
  pub fn sleep_until(&self, deadline: Instant) -> Result<Sleep, TimerError> {
    let slot = Arc::new(Slot {
      state: Mutex::new(SlotState {
        key: None,
        outcome: None,
        waker: None,
      }),
    });
    let armed = self.shared.arm_locked(&slot, deadline)?;
    self.shared.finish(armed);
    Ok(Sleep {
      shared: Arc::clone(&self.shared),
      slot,
      deadline,
    })
  }

  /// Runs `future` until it completes or `duration` from now elapses,
  /// whichever comes first (the deadline on a tie; see the module
  /// documentation).
  ///
  /// # Errors
  ///
  /// As [`TimerHandle::sleep`]; `future` is dropped.
  pub fn timeout<F: Future>(
    &self,
    duration: Duration,
    future: F,
  ) -> Result<Timeout<F>, TimerError> {
    let sleep = self.sleep(duration)?;
    Ok(Timeout::new(sleep, future))
  }

  /// Runs `future` until it completes or `deadline` is reached, whichever
  /// comes first (the deadline on a tie).
  ///
  /// # Errors
  ///
  /// As [`TimerHandle::sleep_until`]; `future` is dropped.
  pub fn timeout_at<F: Future>(
    &self,
    deadline: Instant,
    future: F,
  ) -> Result<Timeout<F>, TimerError> {
    let sleep = self.sleep_until(deadline)?;
    Ok(Timeout::new(sleep, future))
  }

  /// An interval whose first tick is now and which then ticks every
  /// `period`.
  ///
  /// # Errors
  ///
  /// As [`TimerHandle::interval_at`].
  pub fn interval(
    &self,
    period: Duration,
    missed: MissedTickBehavior,
  ) -> Result<Interval, TimerError> {
    self.interval_at(self.now(), period, missed)
  }

  /// An interval whose first tick is at `start` and which then ticks every
  /// `period`. A `start` already reached ticks at once and holds no
  /// registration until that tick is taken.
  ///
  /// # Errors
  ///
  /// `Invalid` when `period` is zero or `start + period` cannot be
  /// represented, otherwise as [`TimerHandle::sleep_until`] for `start`.
  pub fn interval_at(
    &self,
    start: Instant,
    period: Duration,
    missed: MissedTickBehavior,
  ) -> Result<Interval, TimerError> {
    if period.is_zero() || start.checked_add(period).is_none() {
      return Err(TimerError::Invalid);
    }
    let sleep = self.sleep_until(start)?;
    Ok(Interval {
      sleep,
      next: start,
      period,
      missed,
    })
  }

  /// Registrations held now, read under the driver lock.
  #[must_use]
  pub fn registered(&self) -> usize {
    self.shared.registered()
  }

  /// The registration bound the driver was created with.
  #[must_use]
  pub fn max_registered(&self) -> usize {
    self.shared.max_registered
  }

  /// Whether the driver has closed.
  #[must_use]
  pub fn is_closed(&self) -> bool {
    self.shared.is_closed()
  }
}

impl fmt::Debug for TimerHandle {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("TimerHandle")
      .field("registered", &self.registered())
      .field("max_registered", &self.max_registered())
      .finish_non_exhaustive()
  }
}

/// A future that resolves to `Ok(())` once its deadline is reached, or to
/// `Err(Closed)` when the driver closes first.
///
/// Completion is sticky: later polls return the same outcome. Dropping an
/// unfinished sleep cancels it and returns its registration before `drop`
/// returns.
#[must_use = "futures do nothing unless polled"]
pub struct Sleep {
  shared: Arc<Shared>,
  slot: Arc<Slot>,
  deadline: Instant,
}

impl Sleep {
  /// The deadline the sleep was last armed for.
  #[must_use]
  pub const fn deadline(&self) -> Instant {
    self.deadline
  }

  /// Whether the deadline has been reached and the sleep completed with
  /// `Ok(())`.
  #[must_use]
  pub fn is_elapsed(&self) -> bool {
    lock(&self.slot.state).outcome == Some(Ok(()))
  }

  /// Re-arms the sleep for `deadline`, pending or complete. A registered
  /// sleep moves its own registration, even while every other registration
  /// is taken; a complete one needs a new registration. A deadline already
  /// reached completes the sleep at once, releasing any registration, and
  /// wakes its stored waker; otherwise the stored waker is kept for the new
  /// deadline. The old deadline never completes the sleep.
  ///
  /// # Errors
  ///
  /// `Closed` once the driver closed, and `Full` when the sleep is complete,
  /// `deadline` is in the future and every registration is taken. On an
  /// error the sleep, its deadline and its registration are unchanged.
  pub fn reset(&mut self, deadline: Instant) -> Result<(), TimerError> {
    let armed = self.shared.arm_locked(&self.slot, deadline)?;
    self.deadline = deadline;
    self.shared.finish(armed);
    Ok(())
  }
}

impl Future for Sleep {
  type Output = Result<(), TimerError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let slot = &self.slot;
    {
      let armed = lock(&slot.state);
      if let Some(outcome) = armed.outcome {
        return Poll::Ready(outcome);
      }
      // Already stored: nothing to clone or replace.
      let stored = armed.waker.as_ref();
      if stored.is_some_and(|stored| stored.will_wake(cx.waker())) {
        return Poll::Pending;
      }
    }
    // Cloned with no lock held. The outcome is checked again under the lock
    // the driver publishes it under, so a completion in between is seen.
    let waker = cx.waker().clone();
    let mut armed = lock(&slot.state);
    let (poll, unused) = armed.register_waker(waker);
    drop(armed);
    drop_contained(unused);
    poll
  }
}

impl Drop for Sleep {
  fn drop(&mut self) {
    // `key` is set only behind `&mut self`, so once it reads unset it stays
    // unset and the driver lock is not needed.
    let registered = lock(&self.slot.state).key.is_some();
    let waker = if registered {
      let mut state = lock(&self.shared.state);
      let mut armed = lock(&self.slot.state);
      if let Some(key) = armed.key.take() {
        let _ = state.queue.remove(key);
      }
      armed.waker.take()
    } else {
      lock(&self.slot.state).waker.take()
    };
    drop_contained(waker);
  }
}

impl fmt::Debug for Sleep {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Sleep")
      .field("deadline", &self.deadline)
      .field("elapsed", &self.is_elapsed())
      .finish_non_exhaustive()
  }
}

/// Runs an inner future against a deadline; see the module documentation
/// for the tie policy. Polling it again after it completed panics.
#[must_use = "futures do nothing unless polled"]
pub struct Timeout<F> {
  /// The sleep and the boxed inner future, dropped in that order on
  /// completion.
  inner: Option<(Sleep, Pin<Box<F>>)>,
}

impl<F> Timeout<F> {
  fn new(sleep: Sleep, future: F) -> Self {
    Self {
      inner: Some((sleep, Box::pin(future))),
    }
  }
}

impl<F: Future> Future for Timeout<F> {
  type Output = Result<F::Output, TimeoutError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    let Some((sleep, future)) = this.inner.as_mut() else {
      panic!("`Timeout` polled after completion");
    };
    let timer = Pin::new(&mut *sleep).poll(cx);
    let output = match timer {
      Poll::Ready(Ok(())) => Err(TimeoutError::Elapsed),
      Poll::Ready(Err(error)) => Err(TimeoutError::Timer(error)),
      // Reached but not yet fired by the driver: still the deadline's tie.
      Poll::Pending if sleep.shared.now() >= sleep.deadline() => Err(TimeoutError::Elapsed),
      Poll::Pending => match future.as_mut().poll(cx) {
        Poll::Ready(output) => Ok(output),
        Poll::Pending => return Poll::Pending,
      },
    };
    // Taken first, so a panicking inner `Drop` leaves it completed.
    drop(this.inner.take());
    Poll::Ready(output)
  }
}

impl<F> fmt::Debug for Timeout<F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Timeout")
      .field("sleep", &self.inner.as_ref().map(|(sleep, _)| sleep))
      .finish_non_exhaustive()
  }
}

/// What an [`Interval`] does when a tick is observed more than five
/// milliseconds after its scheduled deadline. Earlier ticks keep the
/// original schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MissedTickBehavior {
  /// Keep the schedule: each missed tick is returned at once, one per call,
  /// until the interval has caught up.
  Burst,
  /// Restart the schedule one period after the late tick was observed.
  Delay,
  /// Keep the phase: skip the missed ticks, and schedule the first deadline
  /// of the original schedule that is after the late tick was observed.
  Skip,
}

impl MissedTickBehavior {
  /// The deadline of the tick after the one scheduled at `scheduled`,
  /// observed at `now`, or `None` when it cannot be represented. Constant
  /// time, whatever the number of missed ticks.
  fn next_deadline(self, scheduled: Instant, period: Duration, now: Instant) -> Option<Instant> {
    let following = scheduled.checked_add(period)?;
    if now.saturating_duration_since(scheduled) <= MISSED_TICK_TOLERANCE {
      return Some(following);
    }
    match self {
      Self::Burst => Some(following),
      Self::Delay => now.checked_add(period),
      Self::Skip => {
        let period = period.as_nanos();
        let behind = now.duration_since(scheduled).as_nanos();
        // The smallest multiple of `period` past `behind`.
        let periods = behind.checked_div(period)?.checked_add(1)?;
        let offset = duration_from_nanos(periods.checked_mul(period)?)?;
        scheduled.checked_add(offset)
      }
    }
  }
}

/// Small timer-wheel/OS scheduling jitter does not count as a missed tick.
const MISSED_TICK_TOLERANCE: Duration = Duration::from_millis(5);

/// `nanos` as a `Duration`, or `None` beyond `Duration::MAX`.
fn duration_from_nanos(nanos: u128) -> Option<Duration> {
  const NANOS_PER_SEC: u128 = 1_000_000_000;
  let secs = u64::try_from(nanos / NANOS_PER_SEC).ok()?;
  let subsec = u32::try_from(nanos % NANOS_PER_SEC).ok()?;
  Some(Duration::new(secs, subsec))
}

/// Ticks at its start and then every period, under a
/// [`MissedTickBehavior`]. It holds one registration while the next tick's
/// deadline is in the future; dropping it returns that registration.
pub struct Interval {
  /// Armed for `next`.
  sleep: Sleep,
  /// The deadline of the next tick.
  next: Instant,
  period: Duration,
  missed: MissedTickBehavior,
}

impl Interval {
  /// Completes with the next tick's scheduled deadline. Dropping the future
  /// before it completes loses no tick.
  pub fn tick(&mut self) -> Tick<'_> {
    Tick { interval: self }
  }

  /// Resets the next tick to one period from now.
  ///
  /// This ignores the missed-tick behavior and is equivalent to
  /// [`Interval::reset_after`] with this interval's period. If arming the new
  /// deadline fails, the interval remains unchanged.
  pub fn reset(&mut self) -> Result<(), TimerError> {
    self.reset_after(self.period)
  }

  /// Resets the next tick to `deadline`, preserving the period and
  /// missed-tick behavior. A pending registration is moved in place; a tick
  /// already due completes immediately and releases its registration.
  ///
  /// On `Full`, `Closed`, or `Invalid`, the interval retains its prior next
  /// deadline and registration.
  pub fn reset_at(&mut self, deadline: Instant) -> Result<(), TimerError> {
    self.sleep.reset(deadline)?;
    self.next = deadline;
    Ok(())
  }

  /// Resets the next tick to `duration` from now, preserving the period and
  /// ignoring the missed-tick behavior. On error the interval is unchanged.
  pub fn reset_after(&mut self, duration: Duration) -> Result<(), TimerError> {
    let deadline = self
      .sleep
      .shared
      .now()
      .checked_add(duration)
      .ok_or(TimerError::Invalid)?;
    self.reset_at(deadline)
  }

  /// Resets the next tick to now, so the next [`Interval::tick`] is ready
  /// immediately. This ignores the missed-tick behavior.
  pub fn reset_immediately(&mut self) -> Result<(), TimerError> {
    self.reset_at(self.sleep.shared.now())
  }

  /// Selects what happens when a tick is observed more than five
  /// milliseconds after its scheduled deadline.
  pub fn set_missed_tick_behavior(&mut self, behavior: MissedTickBehavior) {
    self.missed = behavior;
  }

  /// Polls for the next tick, returning its scheduled deadline once it is
  /// due and the tick after it is armed.
  ///
  /// # Errors
  ///
  /// `Closed` once the driver closed; when arming the following tick fails,
  /// `Full` or `Invalid` (its deadline cannot be represented). On an error
  /// the tick stays due.
  pub fn poll_tick(&mut self, cx: &mut Context<'_>) -> Poll<Result<Instant, TimerError>> {
    match Pin::new(&mut self.sleep).poll(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Ready(Ok(())) => {
        let now = self.sleep.shared.now();
        let Some(following) = self.missed.next_deadline(self.next, self.period, now) else {
          return Poll::Ready(Err(TimerError::Invalid));
        };
        if let Err(error) = self.sleep.reset(following) {
          return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(std::mem::replace(&mut self.next, following)))
      }
    }
  }

  /// The period between scheduled ticks.
  #[must_use]
  pub const fn period(&self) -> Duration {
    self.period
  }

  /// What a late tick does.
  #[must_use]
  pub const fn missed_tick_behavior(&self) -> MissedTickBehavior {
    self.missed
  }
}

impl fmt::Debug for Interval {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Interval")
      .field("next", &self.next)
      .field("period", &self.period)
      .field("missed", &self.missed)
      .finish_non_exhaustive()
  }
}

/// The next tick of an [`Interval`]; see [`Interval::poll_tick`].
#[must_use = "futures do nothing unless polled"]
pub struct Tick<'a> {
  interval: &'a mut Interval,
}

impl Future for Tick<'_> {
  type Output = Result<Instant, TimerError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    self.get_mut().interval.poll_tick(cx)
  }
}

impl fmt::Debug for Tick<'_> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Tick").finish_non_exhaustive()
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use std::sync::Arc as StdArc;
  use std::sync::Weak;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::{Poll, Wake, Waker};
  use std::time::{Duration, Instant};

  use loom::sync::{Arc, Mutex};
  use loom::thread;

  use super::{Key, RegistrationQueue, SlotState, TimerError};

  struct WakeCounter(StdArc<AtomicUsize>);

  impl Wake for WakeCounter {
    fn wake(self: StdArc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  #[test]
  fn loom_poll_registration_racing_completion_never_loses_readiness() {
    loom::model(|| {
      let key = Key {
        index: 0,
        generation: 0,
      };
      let state = Arc::new(Mutex::new(SlotState {
        key: Some(key),
        outcome: None,
        waker: None,
      }));
      let wakes = StdArc::new(AtomicUsize::new(0));
      let waker = Waker::from(StdArc::new(WakeCounter(StdArc::clone(&wakes))));

      let polling = Arc::clone(&state);
      let poll = thread::spawn(move || {
        let (result, unused) = polling.lock().unwrap().register_waker(waker);
        drop(unused);
        result
      });
      let firing = Arc::clone(&state);
      let fire = thread::spawn(move || {
        let waker = firing.lock().unwrap().publish(key, Ok(()));
        if let Some(waker) = waker {
          waker.wake();
        }
      });
      let observed = poll.join().unwrap();
      fire.join().unwrap();

      let state = state.lock().unwrap();
      assert_eq!(state.key, None);
      assert_eq!(state.outcome, Some(Ok(())));
      assert!(state.waker.is_none());
      match observed {
        Poll::Pending => assert_eq!(wakes.load(Ordering::SeqCst), 1),
        Poll::Ready(Ok(())) => assert_eq!(wakes.load(Ordering::SeqCst), 0),
        Poll::Ready(Err(error)) => panic!("unexpected completion: {error}"),
      }
    });
  }

  struct Model {
    closed: bool,
    queue: RegistrationQueue,
    slot: SlotState,
  }

  #[test]
  fn loom_reset_fire_close_and_slot_reuse_reject_stale_generations() {
    loom::model(|| {
      let deadline = Instant::now() + Duration::from_secs(10);
      let later = deadline + Duration::from_secs(10);
      let mut queue = RegistrationQueue::new(1).unwrap();
      let first = queue.insert(deadline, 0, Weak::new()).unwrap();
      let model = Arc::new(Mutex::new(Model {
        closed: false,
        queue,
        slot: SlotState {
          key: Some(first),
          outcome: None,
          waker: None,
        },
      }));

      let resetting = Arc::clone(&model);
      let reset = thread::spawn(move || {
        let mut model = resetting.lock().unwrap();
        if model.closed {
          return;
        }
        let new_key = if let Some(old) = model.slot.key {
          model.queue.update(old, later, 1).unwrap()
        } else {
          model.queue.insert(later, 1, Weak::new()).unwrap()
        };
        model.slot.arm(new_key);
      });
      let firing = Arc::clone(&model);
      let fire = thread::spawn(move || {
        let mut model = firing.lock().unwrap();
        if let Some((key, _, _)) = model.queue.pop_due(deadline) {
          model.slot.publish(key, Ok(()));
        }
      });
      let closing = Arc::clone(&model);
      let close = thread::spawn(move || {
        let mut model = closing.lock().unwrap();
        model.closed = true;
        while let Some((key, _, _)) = model.queue.pop_first() {
          model.slot.publish(key, Err(TimerError::Closed));
        }
      });
      reset.join().unwrap();
      fire.join().unwrap();
      close.join().unwrap();

      let mut model = model.lock().unwrap();
      assert!(model.closed);
      assert_eq!(model.queue.len(), 0);
      assert_eq!(model.slot.key, None);
      assert!(matches!(
        model.slot.outcome,
        Some(Ok(()) | Err(TimerError::Closed))
      ));

      let old = first;
      let reused = model
        .queue
        .insert(later, 2, Weak::new())
        .expect("close released the table slot");
      model.slot.arm(reused);
      assert_eq!(reused.index, old.index);
      assert_ne!(reused.generation, old.generation);
      assert!(model.queue.remove(old).is_none());
      assert!(model.slot.publish(old, Ok(())).is_none());
      assert_eq!(model.slot.key, Some(reused));
      if let Some((key, _, _)) = model.queue.pop_first() {
        model.slot.publish(key, Err(TimerError::Closed));
      }
      assert_eq!(model.slot.outcome, Some(Err(TimerError::Closed)));
    });
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use std::future::{Future, Ready, ready};
  use std::pin::{Pin, pin};
  use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
  use std::sync::{Arc, Mutex, mpsc};
  use std::task::{Context, Poll, Wake, Waker};
  use std::thread::{self, Thread};
  use std::time::{Duration, Instant};

  use super::{BATCH, TimerDriver, TimerError, TimerHandle, lock};
  use super::{Interval, MISSED_TICK_TOLERANCE, MissedTickBehavior, Sleep, Timeout, TimeoutError};

  #[test]
  fn paused_clock_ignores_real_time_and_reset_generations() {
    let (driver, clock) = TimerDriver::new_paused(2).unwrap();
    let handle = driver.handle();
    let start = handle.now();
    let mut sleep = handle.sleep(2 * MS).unwrap();
    let (woken, waker) = counter();
    assert!(poll_with(&mut sleep, &waker).is_pending());
    thread::sleep(4 * MS);
    assert_eq!(handle.now(), start);
    assert!(poll_with(&mut sleep, &waker).is_pending());
    sleep.reset(start + 5 * MS).unwrap();
    assert_eq!(clock.advance(2 * MS).unwrap(), start + 2 * MS);
    assert!(poll_with(&mut sleep, &waker).is_pending());
    assert_eq!(woken.wakes(), 0);
    clock.advance(3 * MS).unwrap();
    assert_eq!(poll_with(&mut sleep, Waker::noop()), Poll::Ready(Ok(())));
    assert_eq!(woken.wakes(), 1);
    assert_eq!(handle.registered(), 0);
    driver.shutdown().unwrap();
  }

  #[test]
  fn paused_intervals_use_the_controlled_clock_for_every_policy_and_reset() {
    for (policy, expected) in [
      (MissedTickBehavior::Burst, 20),
      (MissedTickBehavior::Delay, 45),
      (MissedTickBehavior::Skip, 40),
    ] {
      let (driver, clock) = TimerDriver::new_paused(1).unwrap();
      let handle = driver.handle();
      let start = handle.now();
      let mut interval = handle.interval(10 * MS, policy).unwrap();
      assert_eq!(
        interval.poll_tick(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(start))
      );
      clock.advance(35 * MS).unwrap();
      assert_eq!(
        interval.poll_tick(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(start + 10 * MS))
      );
      assert_eq!(interval.next, start + expected * MS);
      interval.reset().unwrap();
      assert_eq!(interval.next, start + 45 * MS);
      interval.reset_after(2 * MS).unwrap();
      assert_eq!(interval.next, start + 37 * MS);
      interval.reset_immediately().unwrap();
      assert_eq!(interval.next, start + 35 * MS);
      driver.shutdown().unwrap();
    }
  }

  struct ManualOrder {
    id: usize,
    log: Arc<Mutex<Vec<usize>>>,
  }

  impl Wake for ManualOrder {
    fn wake(self: Arc<Self>) {
      lock(&self.log).push(self.id);
    }
  }

  #[test]
  fn manual_advance_publishes_multiple_batches_in_equal_deadline_order() {
    let (driver, clock) = TimerDriver::new_paused(129).unwrap();
    let handle = driver.handle();
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut sleeps = Vec::new();
    for id in 0..129 {
      let mut sleep = handle.sleep(MS).unwrap();
      let waker = Waker::from(Arc::new(ManualOrder {
        id,
        log: Arc::clone(&log),
      }));
      assert!(poll_with(&mut sleep, &waker).is_pending());
      sleeps.push(sleep);
    }
    clock.advance(MS).unwrap();
    assert_eq!(*lock(&log), (0..129).collect::<Vec<_>>());
    assert_eq!(handle.registered(), 0);
    assert!(
      sleeps
        .iter_mut()
        .all(|sleep| poll_with(sleep, Waker::noop()) == Poll::Ready(Ok(())))
    );
    driver.shutdown().unwrap();
  }

  struct AdvanceOnWake(super::ManualClock);

  impl Wake for AdvanceOnWake {
    fn wake(self: Arc<Self>) {
      self.0.advance(2 * MS).unwrap();
    }
  }

  #[test]
  fn manual_advance_callbacks_can_advance_again_without_lock_reentrancy() {
    let (driver, clock) = TimerDriver::new_paused(2).unwrap();
    let handle = driver.handle();
    let start = clock.now();
    let mut first = handle.sleep(MS).unwrap();
    let mut second = handle.sleep(3 * MS).unwrap();
    let waker = Waker::from(Arc::new(AdvanceOnWake(clock.clone())));
    assert!(poll_with(&mut first, &waker).is_pending());
    assert!(poll_with(&mut second, Waker::noop()).is_pending());
    assert_eq!(clock.advance(MS).unwrap(), start + MS);
    assert_eq!(clock.now(), start + 3 * MS);
    assert_eq!(poll_with(&mut first, Waker::noop()), Poll::Ready(Ok(())));
    assert_eq!(poll_with(&mut second, Waker::noop()), Poll::Ready(Ok(())));
    driver.shutdown().unwrap();
  }

  #[test]
  fn manual_clock_overflow_and_closed_advance_leave_time_unchanged() {
    let (driver, clock) = TimerDriver::new_paused(1).unwrap();
    let start = clock.now();
    assert_eq!(clock.advance(Duration::MAX), Err(TimerError::Invalid));
    assert_eq!(clock.now(), start);
    drop(driver);
    assert_eq!(clock.advance(MS), Err(TimerError::Closed));
    assert_eq!(clock.now(), start);
  }

  #[test]
  fn manual_timeout_checks_controlled_deadline_before_polling_its_inner() {
    let (driver, clock) = TimerDriver::new_paused(1).unwrap();
    let (inner, polls, dropped) = probe(true);
    let mut timeout = driver.handle().timeout(MS, inner).unwrap();
    clock.advance(MS).unwrap();
    assert_eq!(
      poll_with(&mut timeout, Waker::noop()),
      Poll::Ready(Err(TimeoutError::Elapsed))
    );
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert!(dropped.load(Ordering::SeqCst));
    driver.shutdown().unwrap();
  }

  #[test]
  fn concurrent_manual_advances_serialize_without_losing_elapsed_time() {
    let (driver, clock) = TimerDriver::new_paused(1).unwrap();
    let start = clock.now();
    let mut sleep = driver.handle().sleep(2 * HOUR).unwrap();
    let other = clock.clone();
    let worker = thread::spawn(move || other.advance(HOUR).unwrap());
    let first = clock.advance(HOUR).unwrap();
    let second = worker.join().unwrap();
    assert_ne!(first, second);
    assert_eq!(clock.now(), start + 2 * HOUR);
    assert_eq!(poll_with(&mut sleep, Waker::noop()), Poll::Ready(Ok(())));
    driver.shutdown().unwrap();
  }

  const HOUR: Duration = Duration::from_secs(3600);
  const MS: Duration = Duration::from_millis(1);
  /// Bounds every blocking wait, so a lost wakeup fails a test instead of
  /// hanging it.
  const WATCHDOG: Duration = Duration::from_secs(10);

  struct Unpark(Thread);

  impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
      self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.0.unpark();
    }
  }

  /// Polls `future` on this thread, parking between polls. A pending poll
  /// must be followed by a wakeup within [`WATCHDOG`]; the timeout fails the
  /// test rather than polling again, so a lost wakeup cannot pass.
  fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
      if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
        return output;
      }
      let limit = Instant::now() + WATCHDOG;
      thread::park_timeout(WATCHDOG);
      assert!(
        Instant::now() < limit,
        "lost wakeup: the task was not woken"
      );
    }
  }

  /// Parks until `done` holds. The wakers it waits on unpark this thread
  /// after recording their effect, so this needs no timing assumption; the
  /// watchdog only bounds a lost wakeup.
  fn wait_until(done: impl Fn() -> bool) {
    let limit = Instant::now() + WATCHDOG;
    while !done() {
      let now = Instant::now();
      assert!(now < limit, "lost wakeup: the waker never ran");
      thread::park_timeout(limit - now);
    }
  }

  /// Counts its wakes and unparks the thread that created it.
  struct Counter {
    wakes: AtomicUsize,
    owner: Thread,
  }

  impl Counter {
    fn wakes(&self) -> usize {
      self.wakes.load(Ordering::SeqCst)
    }
  }

  impl Wake for Counter {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.wakes.fetch_add(1, Ordering::SeqCst);
      self.owner.unpark();
    }
  }

  fn counter() -> (Arc<Counter>, Waker) {
    let counter = Arc::new(Counter {
      wakes: AtomicUsize::new(0),
      owner: thread::current(),
    });
    (Arc::clone(&counter), Waker::from(counter))
  }

  fn poll_with<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(waker))
  }

  fn driver(max_registered: usize) -> (TimerDriver, TimerHandle) {
    let driver = TimerDriver::new(max_registered).unwrap();
    let handle = driver.handle();
    (driver, handle)
  }

  /// The deadlines in the queue, in firing order.
  fn deadlines(handle: &TimerHandle) -> Vec<Instant> {
    let state = lock(&handle.shared.state);
    state.queue.deadlines()
  }

  #[test]
  fn construction_is_validated_and_timers_are_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<TimerDriver>();
    check::<TimerHandle>();
    check::<Sleep>();
    check::<Interval>();
    check::<Timeout<Ready<()>>>();
    assert_eq!(TimerDriver::new(0).map(drop), Err(TimerError::Invalid));
    assert_eq!(
      TimerDriver::new(usize::MAX).map(drop),
      Err(TimerError::OutOfMemory)
    );
    let (driver, handle) = driver(1);
    assert_eq!(handle.max_registered(), 1);
    assert_eq!(
      handle.sleep(Duration::MAX).map(drop),
      Err(TimerError::Invalid)
    );
    let burst = MissedTickBehavior::Burst;
    assert_eq!(
      handle.interval(Duration::ZERO, burst).map(drop),
      Err(TimerError::Invalid)
    );
    assert_eq!(
      handle.interval(Duration::MAX, burst).map(drop),
      Err(TimerError::Invalid)
    );
    assert_eq!(handle.registered(), 0);
    driver.shutdown().unwrap();
  }

  #[test]
  fn zero_duration_completes_at_once_without_a_registration() {
    let (driver, handle) = driver(1);
    let _held = handle.sleep(HOUR).unwrap();
    assert_eq!(handle.sleep(HOUR).map(drop), Err(TimerError::Full));
    // Full, yet a deadline already reached needs no registration.
    let mut zero = handle.sleep(Duration::ZERO).unwrap();
    assert!(zero.is_elapsed());
    assert_eq!(poll_with(&mut zero, Waker::noop()), Poll::Ready(Ok(())));
    // Completion is sticky.
    assert_eq!(poll_with(&mut zero, Waker::noop()), Poll::Ready(Ok(())));
    assert_eq!(
      block_on(handle.sleep_until(Instant::now()).unwrap()),
      Ok(())
    );
    assert_eq!(handle.registered(), 1);
    driver.shutdown().unwrap();
  }

  #[test]
  fn full_capacity_is_owned_and_cancellation_returns_it_at_once() {
    let (driver, handle) = driver(2);
    let first = handle.sleep(HOUR).unwrap();
    let mut second = handle.sleep(HOUR).unwrap();
    assert_eq!(poll_with(&mut second, Waker::noop()), Poll::Pending);
    assert_eq!(handle.registered(), 2);
    assert_eq!(handle.sleep(HOUR).map(drop), Err(TimerError::Full));
    assert_eq!(
      handle.clone().timeout(HOUR, ready(())).map(drop),
      Err(TimerError::Full)
    );
    drop(first);
    assert_eq!(handle.registered(), 1);
    let third = handle.sleep(HOUR).unwrap();
    assert_eq!(handle.registered(), 2);
    drop(second);
    drop(third);
    assert_eq!(handle.registered(), 0);
    driver.shutdown().unwrap();
  }

  #[test]
  fn completion_releases_the_registration_before_it_is_observed() {
    let (driver, handle) = driver(1);
    let mut sleep = handle.sleep(MS).unwrap();
    assert_eq!(block_on(&mut sleep), Ok(()));
    // Still alive, but holding nothing once its completion is visible.
    assert_eq!(handle.registered(), 0);
    assert!(sleep.is_elapsed());
    let other = handle.sleep(HOUR).unwrap();
    drop(sleep);
    assert_eq!(handle.registered(), 1);
    drop(other);
    driver.shutdown().unwrap();
  }

  #[test]
  fn reset_moves_the_registration_and_stale_deadlines_never_fire() {
    let (driver, handle) = driver(2);
    let (woken, waker) = counter();
    let mut sleep = handle.sleep(HOUR).unwrap();
    assert_eq!(poll_with(&mut sleep, &waker), Poll::Pending);
    let near = Instant::now() + 100 * MS;
    sleep.reset(near).unwrap();
    assert_eq!(deadlines(&handle), [near]);
    let far = near + HOUR;
    sleep.reset(far).unwrap();
    assert_eq!(deadlines(&handle), [far]);
    // The driver passes the deadline the sleep was moved away from.
    block_on(handle.sleep_until(near + 20 * MS).unwrap()).unwrap();
    assert_eq!(woken.wakes(), 0);
    // Replaces (and drops) the counting waker until it is stored again below.
    assert_eq!(poll_with(&mut sleep, Waker::noop()), Poll::Pending);
    assert_eq!(handle.registered(), 1);
    // Earlier again: fires, keeping one registration until then.
    sleep.reset(Instant::now() + MS).unwrap();
    assert_eq!(block_on(&mut sleep), Ok(()));
    assert_eq!(handle.registered(), 0);
    // A complete sleep re-arms, and a reached deadline completes it at once
    // and wakes its stored waker.
    sleep.reset(Instant::now() + HOUR).unwrap();
    assert_eq!(handle.registered(), 1);
    assert_eq!(poll_with(&mut sleep, &waker), Poll::Pending);
    sleep.reset(Instant::now()).unwrap();
    assert_eq!(woken.wakes(), 1);
    assert_eq!(handle.registered(), 0);
    assert_eq!(poll_with(&mut sleep, Waker::noop()), Poll::Ready(Ok(())));
    driver.shutdown().unwrap();
  }

  #[test]
  fn a_refused_reset_leaves_the_sleep_unchanged() {
    let (driver, handle) = driver(1);
    let mut held = handle.sleep(HOUR).unwrap();
    let held_deadline = held.deadline();
    let mut done = handle.sleep(Duration::ZERO).unwrap();
    let done_deadline = done.deadline();
    assert_eq!(done.reset(Instant::now() + HOUR), Err(TimerError::Full));
    assert!(done.is_elapsed());
    assert_eq!(done.deadline(), done_deadline);
    assert_eq!(deadlines(&handle), [held_deadline]);
    // A registered sleep moves its own registration, even while full.
    let moved = held_deadline + HOUR;
    held.reset(moved).unwrap();
    assert_eq!(deadlines(&handle), [moved]);
    assert_eq!(poll_with(&mut held, Waker::noop()), Poll::Pending);
    drop(driver);
    assert_eq!(held.reset(moved + HOUR), Err(TimerError::Closed));
    assert_eq!(held.deadline(), moved);
    assert_eq!(
      poll_with(&mut held, Waker::noop()),
      Poll::Ready(Err(TimerError::Closed))
    );
    assert_eq!(done.reset(Instant::now()), Err(TimerError::Closed));
    assert!(done.is_elapsed());
  }

  #[test]
  fn only_the_latest_waker_is_woken() {
    let (driver, handle) = driver(2);
    let (stale, stale_waker) = counter();
    let (latest, latest_waker) = counter();
    let mut sleep = handle.sleep(HOUR).unwrap();
    assert_eq!(poll_with(&mut sleep, &stale_waker), Poll::Pending);
    assert_eq!(poll_with(&mut sleep, &latest_waker), Poll::Pending);
    assert_eq!(poll_with(&mut sleep, &latest_waker), Poll::Pending);
    sleep.reset(Instant::now() + MS).unwrap();
    wait_until(|| latest.wakes() == 1);
    // The replaced waker was dropped, so nothing can wake it later.
    assert_eq!((stale.wakes(), latest.wakes()), (0, 1));
    assert_eq!(poll_with(&mut sleep, Waker::noop()), Poll::Ready(Ok(())));
    driver.shutdown().unwrap();
  }

  #[test]
  fn concurrent_sleeps_lose_no_wakeups_and_release_every_registration() {
    const THREADS: u64 = 4;
    const ROUNDS: u64 = 64;
    let (driver, handle) = driver(2);
    let completed = AtomicUsize::new(0);
    thread::scope(|s| {
      for t in 0..THREADS {
        let (handle, completed) = (handle.clone(), &completed);
        s.spawn(move || {
          for i in 0..ROUNDS {
            let duration = Duration::from_micros((t + i) % 4 * 100);
            match handle.sleep(duration) {
              Ok(sleep) => {
                assert!(handle.registered() <= 2);
                assert_eq!(block_on(sleep), Ok(()));
                completed.fetch_add(1, Ordering::Relaxed);
              }
              Err(TimerError::Full) => thread::yield_now(),
              Err(error) => panic!("unexpected error: {error}"),
            }
            // Race a cancellation against the firing.
            if let Ok(mut racing) = handle.sleep(duration) {
              let _ = poll_with(&mut racing, Waker::noop());
              drop(racing);
            }
          }
        });
      }
    });
    assert!(completed.load(Ordering::Relaxed) > 0);
    assert_eq!(handle.registered(), 0);
    driver.shutdown().unwrap();
  }

  #[test]
  fn resets_racing_the_driver_keep_one_current_registration() {
    let (driver, handle) = driver(1);
    let (_, waker) = counter();
    let mut sleep = handle.sleep(HOUR).unwrap();
    for i in 0..200u64 {
      let deadline = Instant::now() + Duration::from_micros(i % 3 * 20);
      sleep.reset(deadline).unwrap();
      let _ = poll_with(&mut sleep, &waker);
      assert!(handle.registered() <= 1);
    }
    sleep.reset(Instant::now() + MS).unwrap();
    assert_eq!(block_on(&mut sleep), Ok(()));
    assert_eq!(handle.registered(), 0);
    driver.shutdown().unwrap();
  }

  #[test]
  fn shutdown_and_drop_resolve_and_wake_outstanding_sleeps() {
    for explicit in [true, false] {
      let (driver, handle) = driver(4);
      let mut sleeps: Vec<(Sleep, Arc<Counter>, Waker)> = (0..3)
        .map(|_| {
          let (woken, waker) = counter();
          (handle.sleep(HOUR).unwrap(), woken, waker)
        })
        .collect();
      for (sleep, _, waker) in &mut sleeps {
        assert_eq!(poll_with(sleep, waker), Poll::Pending);
      }
      let done = handle.sleep(Duration::ZERO).unwrap();
      if explicit {
        driver.shutdown().unwrap();
      } else {
        drop(driver);
      }
      // Woken on this thread before the close returned.
      for (sleep, woken, _) in &mut sleeps {
        assert_eq!(woken.wakes(), 1);
        assert_eq!(
          poll_with(sleep, Waker::noop()),
          Poll::Ready(Err(TimerError::Closed))
        );
      }
      assert!(done.is_elapsed());
      assert!(handle.is_closed());
      assert_eq!(handle.registered(), 0);
      // A handle outliving its driver refuses everything.
      assert_eq!(
        handle.sleep(Duration::ZERO).map(drop),
        Err(TimerError::Closed)
      );
      assert_eq!(handle.sleep(HOUR).map(drop), Err(TimerError::Closed));
      assert_eq!(
        handle.interval(HOUR, MissedTickBehavior::Skip).map(drop),
        Err(TimerError::Closed)
      );
    }
  }

  struct GatedWake {
    id: usize,
    events: mpsc::Sender<(usize, thread::ThreadId)>,
    gate: Option<Arc<(Mutex<bool>, std::sync::Condvar)>>,
  }

  impl Wake for GatedWake {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      let _ = self.events.send((self.id, thread::current().id()));
      if let Some(gate) = &self.gate {
        let mut released = lock(&gate.0);
        while !*released {
          released = gate
            .1
            .wait(released)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
      }
    }
  }

  #[test]
  fn close_owns_all_batches_and_waits_for_blocked_wakers() {
    const SLEEPS: usize = BATCH * 2 + 3;
    let (mut driver, handle) = driver(SLEEPS);
    let timer_join = driver
      .thread
      .take()
      .expect("the timer service thread is running");
    let deadline = Instant::now() + HOUR;
    let (events_tx, events_rx) = mpsc::channel();
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let mut sleeps = Vec::with_capacity(SLEEPS);
    for id in 0..SLEEPS {
      let waker = Waker::from(Arc::new(GatedWake {
        id,
        events: events_tx.clone(),
        gate: (id == 0).then(|| Arc::clone(&gate)),
      }));
      let mut sleep = handle.sleep_until(deadline).unwrap();
      assert_eq!(poll_with(&mut sleep, &waker), Poll::Pending);
      sleeps.push(sleep);
    }
    drop(events_tx);

    let closer = thread::spawn(move || {
      let id = thread::current().id();
      drop(driver);
      id
    });
    let (first_id, first_thread) = events_rx.recv_timeout(WATCHDOG).unwrap();
    assert_eq!(first_id, 0);

    // Let the service thread take its exit path while the first close batch's
    // waker is gated. It must not steal later batches from the close owner.
    let limit = Instant::now() + WATCHDOG;
    while !timer_join.is_finished() && Instant::now() < limit {
      thread::sleep(MS);
    }
    assert!(
      timer_join.is_finished(),
      "timer service did not exit on close"
    );
    let stolen_event = events_rx.try_recv().ok();
    let stolen = stolen_event.is_some();

    *lock(&gate.0) = true;
    gate.1.notify_all();
    let closing_thread = closer.join().unwrap();
    assert_eq!(first_thread, closing_thread);
    let mut observed = vec![(first_id, first_thread)];
    if let Some(event) = stolen_event {
      observed.push(event);
    }
    while let Ok(event) = events_rx.try_recv() {
      observed.push(event);
    }
    assert_eq!(observed.len(), SLEEPS);
    assert!(observed.iter().all(|(_, id)| *id == closing_thread));
    assert!(
      observed
        .iter()
        .enumerate()
        .all(|(id, (observed_id, _))| id == *observed_id)
    );
    assert!(!stolen, "the service thread stole a close batch");
    assert!(sleeps.iter().all(|sleep| !sleep.is_elapsed()));
    assert!(
      sleeps
        .iter_mut()
        .all(|sleep| { poll_with(sleep, Waker::noop()) == Poll::Ready(Err(TimerError::Closed)) })
    );
    timer_join.join().unwrap();
  }

  /// Shuts down the driver it owns from its `wake`.
  struct ShutdownOnWake {
    driver: Mutex<Option<TimerDriver>>,
    result: mpsc::Sender<Result<(), TimerError>>,
  }

  impl Wake for ShutdownOnWake {
    fn wake(self: Arc<Self>) {
      let driver = self.driver.lock().unwrap().take();
      if let Some(driver) = driver {
        let _ = self.result.send(driver.shutdown());
      }
    }
  }

  #[test]
  fn shutdown_on_the_service_thread_closes_without_joining_itself() {
    let (driver, handle) = driver(2);
    let (result, results) = mpsc::channel();
    let waker = Waker::from(Arc::new(ShutdownOnWake {
      driver: Mutex::new(Some(driver)),
      result,
    }));
    let mut sleep = handle.sleep(HOUR).unwrap();
    assert_eq!(poll_with(&mut sleep, &waker), Poll::Pending);
    // Far enough ahead to be fired by the service thread, not completed at
    // once by this reset on the test thread.
    sleep.reset(Instant::now() + 50 * MS).unwrap();
    assert_eq!(
      results.recv_timeout(WATCHDOG),
      Ok(Err(TimerError::WouldDeadlock))
    );
    assert!(handle.is_closed());
    assert_eq!(poll_with(&mut sleep, Waker::noop()), Poll::Ready(Ok(())));
    assert_eq!(handle.sleep(HOUR).map(drop), Err(TimerError::Closed));
  }

  /// Counts its wakes and unparks its owner, then panics with a payload
  /// whose own `Drop` panics.
  struct PanicOnWake {
    wakes: AtomicUsize,
    owner: Thread,
  }

  impl Wake for PanicOnWake {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.wakes.fetch_add(1, Ordering::SeqCst);
      self.owner.unpark();
      std::panic::panic_any(PanicOnDrop);
    }
  }

  struct PanicOnDrop;

  impl Drop for PanicOnDrop {
    fn drop(&mut self) {
      panic!("panic payload dropped");
    }
  }

  /// A waker whose last reference, when dropped, records it and unparks
  /// its owner, then panics.
  struct PanicOnRelease {
    released: Arc<AtomicBool>,
    owner: Thread,
  }

  impl Wake for PanicOnRelease {
    fn wake(self: Arc<Self>) {
      drop(self);
    }
  }

  impl Drop for PanicOnRelease {
    fn drop(&mut self) {
      self.released.store(true, Ordering::SeqCst);
      self.owner.unpark();
      panic!("waker dropped");
    }
  }

  fn release_waker(released: &Arc<AtomicBool>) -> Waker {
    Waker::from(Arc::new(PanicOnRelease {
      released: Arc::clone(released),
      owner: thread::current(),
    }))
  }

  #[test]
  fn waker_panics_are_contained_and_the_driver_keeps_running() {
    let (driver, handle) = driver(4);
    let panicking = Arc::new(PanicOnWake {
      wakes: AtomicUsize::new(0),
      owner: thread::current(),
    });
    let released = Arc::new(AtomicBool::new(false));
    let mut woken = handle.sleep(HOUR).unwrap();
    let mut dropped = handle.sleep(HOUR).unwrap();
    let panicking_waker = Waker::from(Arc::clone(&panicking));
    assert_eq!(poll_with(&mut woken, &panicking_waker), Poll::Pending);
    assert_eq!(
      poll_with(&mut dropped, &release_waker(&released)),
      Poll::Pending
    );
    let start = Instant::now();
    woken.reset(start + MS).unwrap();
    dropped.reset(start + 2 * MS).unwrap();
    wait_until(|| {
      let woke = panicking.wakes.load(Ordering::SeqCst) == 1;
      woke && released.load(Ordering::SeqCst)
    });
    assert_eq!(poll_with(&mut woken, Waker::noop()), Poll::Ready(Ok(())));
    assert_eq!(poll_with(&mut dropped, Waker::noop()), Poll::Ready(Ok(())));
    // A waker replaced in `poll` is dropped outside the lock, contained too.
    let replaced = Arc::new(AtomicBool::new(false));
    let mut sleep = handle.sleep(HOUR).unwrap();
    assert_eq!(
      poll_with(&mut sleep, &release_waker(&replaced)),
      Poll::Pending
    );
    assert_eq!(poll_with(&mut sleep, Waker::noop()), Poll::Pending);
    assert!(replaced.load(Ordering::SeqCst));
    // The service thread survived every panic.
    assert_eq!(block_on(handle.sleep(MS).unwrap()), Ok(()));
    drop(sleep);
    driver.shutdown().unwrap();
  }

  /// An inner future that counts its polls and records its drop. It is
  /// ready on its first poll when `ready`, otherwise it never is.
  struct Probe {
    ready: bool,
    polls: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
  }

  impl Future for Probe {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<u32> {
      self.polls.fetch_add(1, Ordering::SeqCst);
      if self.ready {
        Poll::Ready(7)
      } else {
        Poll::Pending
      }
    }
  }

  impl Drop for Probe {
    fn drop(&mut self) {
      self.dropped.store(true, Ordering::SeqCst);
    }
  }

  fn probe(ready: bool) -> (Probe, Arc<AtomicUsize>, Arc<AtomicBool>) {
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let probe = Probe {
      ready,
      polls: Arc::clone(&polls),
      dropped: Arc::clone(&dropped),
    };
    (probe, polls, dropped)
  }

  #[test]
  fn timeout_returns_the_output_and_releases_its_registration() {
    let (driver, handle) = driver(1);
    let (inner, polls, dropped) = probe(true);
    let mut timeout = handle.timeout(HOUR, inner).unwrap();
    assert_eq!(handle.registered(), 1);
    assert_eq!(block_on(&mut timeout), Ok(7));
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    // Both released on completion, while the `Timeout` is still alive.
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(handle.registered(), 0);
    drop(timeout);
    driver.shutdown().unwrap();
  }

  #[test]
  fn an_elapsed_timeout_drops_the_losing_future_at_once() {
    let (driver, handle) = driver(1);
    let (inner, _, dropped) = probe(false);
    let mut timeout = handle.timeout(2 * MS, inner).unwrap();
    assert_eq!(block_on(&mut timeout), Err(TimeoutError::Elapsed));
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(handle.registered(), 0);
    drop(timeout);
    // Cancelling drops both and returns the registration.
    let (inner, _, dropped) = probe(false);
    let mut cancelled = handle.timeout(HOUR, inner).unwrap();
    assert_eq!(poll_with(&mut cancelled, Waker::noop()), Poll::Pending);
    drop(cancelled);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(handle.registered(), 0);
    driver.shutdown().unwrap();
  }

  #[test]
  fn ties_go_to_the_deadline_without_polling_the_inner_future() {
    let (driver, handle) = driver(1);
    let (inner, polls, dropped) = probe(true);
    let mut zero = handle.timeout(Duration::ZERO, inner).unwrap();
    assert_eq!(
      poll_with(&mut zero, Waker::noop()),
      Poll::Ready(Err(TimeoutError::Elapsed))
    );
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert!(dropped.load(Ordering::SeqCst));
    // A reached deadline wins whether or not the driver has fired it yet.
    let (inner, polls, _) = probe(true);
    let mut reached = handle.timeout_at(Instant::now() + MS, inner).unwrap();
    thread::sleep(2 * MS);
    assert_eq!(
      poll_with(&mut reached, Waker::noop()),
      Poll::Ready(Err(TimeoutError::Elapsed))
    );
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    driver.shutdown().unwrap();
  }

  #[test]
  fn a_closed_driver_fails_a_pending_timeout() {
    let (driver, handle) = driver(1);
    let (inner, _, dropped) = probe(false);
    let (woken, waker) = counter();
    let mut timeout = handle.timeout(HOUR, inner).unwrap();
    assert_eq!(poll_with(&mut timeout, &waker), Poll::Pending);
    drop(driver);
    assert_eq!(woken.wakes(), 1);
    assert_eq!(
      poll_with(&mut timeout, Waker::noop()),
      Poll::Ready(Err(TimeoutError::Timer(TimerError::Closed)))
    );
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(
      handle.timeout(HOUR, ready(())).map(drop),
      Err(TimerError::Closed)
    );
  }

  #[test]
  fn the_first_tick_is_immediate_and_arms_the_next() {
    let (driver, handle) = driver(1);
    let before = Instant::now();
    let mut interval = handle.interval(HOUR, MissedTickBehavior::Skip).unwrap();
    assert_eq!(handle.registered(), 0);
    let first = poll_with(&mut interval.tick(), Waker::noop());
    let Poll::Ready(Ok(first)) = first else {
      panic!("the first tick was not immediate: {first:?}");
    };
    assert!(before <= first && first <= Instant::now());
    assert_eq!(handle.registered(), 1);
    assert_eq!(
      poll_with(&mut interval.tick(), Waker::noop()),
      Poll::Pending
    );
    assert_eq!(interval.period(), HOUR);
    drop(driver);
    assert_eq!(
      poll_with(&mut interval.tick(), Waker::noop()),
      Poll::Ready(Err(TimerError::Closed))
    );
    drop(interval);
    assert_eq!(handle.registered(), 0);
  }

  #[test]
  fn missed_tick_policies_pick_one_deadline_in_constant_time() {
    use MissedTickBehavior::{Burst, Delay, Skip};
    let base = Instant::now();
    let period = 10 * MS;
    let at = |offset: Duration| base + offset;
    // On time, every policy keeps the schedule.
    for missed in [Burst, Delay, Skip] {
      assert_eq!(
        missed.next_deadline(base, period, at(3 * MS)),
        Some(at(period))
      );
    }
    // Observed three periods and a half late.
    let late = at(35 * MS);
    assert_eq!(Burst.next_deadline(base, period, late), Some(at(period)));
    assert_eq!(Delay.next_deadline(base, period, late), Some(at(45 * MS)));
    assert_eq!(Skip.next_deadline(base, period, late), Some(at(40 * MS)));
    // Observed exactly at the following deadline counts as missed.
    let edge = at(period);
    assert_eq!(Burst.next_deadline(base, period, edge), Some(at(period)));
    assert_eq!(
      Delay.next_deadline(base, period, edge),
      Some(at(2 * period))
    );
    assert_eq!(Skip.next_deadline(base, period, edge), Some(at(2 * period)));
    // Tokio-compatible tolerance: a tick 500 ms late with a 1 s period is
    // considered missed even though its following deadline is still ahead.
    let second = Duration::from_secs(1);
    let half_late = at(second / 2);
    assert_eq!(
      Burst.next_deadline(base, second, half_late),
      Some(at(second))
    );
    assert_eq!(
      Delay.next_deadline(base, second, half_late),
      Some(at(second + second / 2))
    );
    assert_eq!(
      Skip.next_deadline(base, second, half_late),
      Some(at(second))
    );
    // Exactly the tolerance remains on schedule; one nanosecond more is late.
    let tolerance = at(MISSED_TICK_TOLERANCE);
    assert_eq!(
      Delay.next_deadline(base, second, tolerance),
      Some(at(second))
    );
    let beyond_tolerance = tolerance + Duration::from_nanos(1);
    assert_eq!(
      Delay.next_deadline(base, second, beyond_tolerance),
      Some(beyond_tolerance + second)
    );
    // A million periods behind is one division, not a million steps.
    let far = at(period * 1_000_000 + Duration::from_nanos(1));
    assert_eq!(
      Skip.next_deadline(base, period, far),
      Some(at(period * 1_000_001))
    );
    // Unrepresentable deadlines are reported, never wrapped.
    for missed in [Burst, Delay, Skip] {
      assert_eq!(missed.next_deadline(base, Duration::MAX, base), None);
    }
    assert_eq!(Skip.next_deadline(base, Duration::ZERO, edge), None);
  }

  #[test]
  fn burst_returns_missed_ticks_one_per_call() {
    let (driver, handle) = driver(1);
    let period = 10 * MS;
    let start = Instant::now().checked_sub(35 * MS).unwrap();
    let burst = MissedTickBehavior::Burst;
    let mut interval = handle.interval_at(start, period, burst).unwrap();
    for k in 0..4 {
      assert_eq!(
        poll_with(&mut interval.tick(), Waker::noop()),
        Poll::Ready(Ok(start + period * k))
      );
    }
    assert_eq!(block_on(interval.tick()), Ok(start + period * 4));
    driver.shutdown().unwrap();
  }

  #[test]
  fn skip_and_delay_reschedule_after_a_late_tick() {
    let (driver, handle) = driver(2);
    let period = 10 * MS;
    let before = Instant::now();
    let start = before.checked_sub(35 * MS).unwrap();
    let mut skip = handle
      .interval_at(start, period, MissedTickBehavior::Skip)
      .unwrap();
    let mut delay = handle
      .interval_at(start, period, MissedTickBehavior::Delay)
      .unwrap();
    assert_eq!(block_on(skip.tick()), Ok(start));
    assert_eq!(block_on(delay.tick()), Ok(start));
    // The first deadline of the original schedule after the late tick.
    let skipped = block_on(skip.tick()).unwrap();
    assert!(skipped > before);
    assert_eq!((skipped - start).as_nanos() % period.as_nanos(), 0);
    // A period after the late tick was observed.
    let delayed = block_on(delay.tick()).unwrap();
    assert!(delayed >= before + period);
    driver.shutdown().unwrap();
  }

  #[test]
  fn interval_resets_preserve_registration_and_rollback_on_failure() {
    let (driver, handle) = driver(1);
    let original = Instant::now() + HOUR;
    let mut interval = handle
      .interval_at(original, HOUR, MissedTickBehavior::Skip)
      .unwrap();
    assert_eq!(handle.registered(), 1);

    let moved = original + HOUR;
    interval.reset_at(moved).unwrap();
    assert_eq!(interval.next, moved);
    assert_eq!(deadlines(&handle), [moved]);

    let after = Duration::from_secs(2);
    let before_after = Instant::now();
    interval.reset_after(after).unwrap();
    assert!(interval.next >= before_after + after);
    assert_eq!(deadlines(&handle), [interval.next]);

    let current = interval.next;
    assert_eq!(
      interval.reset_after(Duration::MAX),
      Err(TimerError::Invalid)
    );
    assert_eq!(interval.next, current);
    assert_eq!(deadlines(&handle), [current]);

    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    assert_eq!(interval.missed_tick_behavior(), MissedTickBehavior::Delay);
    let before_reset = Instant::now();
    interval.reset().unwrap();
    assert!(interval.next >= before_reset + HOUR);
    assert_eq!(handle.registered(), 1);
    assert_eq!(
      poll_with(&mut interval.tick(), Waker::noop()),
      Poll::Pending
    );
    interval.reset_immediately().unwrap();
    assert!(interval.next <= Instant::now());
    assert_eq!(handle.registered(), 0);
    let tick_deadline = interval.next;
    assert_eq!(block_on(interval.tick()), Ok(tick_deadline));
    assert_eq!(handle.registered(), 1);

    let registered = handle.sleep(HOUR).unwrap_err();
    assert_eq!(registered, TimerError::Full);
    driver.shutdown().unwrap();
    let prior = interval.next;
    assert_eq!(interval.reset_at(Instant::now()), Err(TimerError::Closed));
    assert_eq!(interval.next, prior);
  }

  #[test]
  fn interval_reset_and_reset_immediately_have_distinct_deadlines() {
    let (driver, handle) = driver(1);
    let mut interval = handle.interval(HOUR, MissedTickBehavior::Burst).unwrap();
    // Consume the constructor's immediate tick and arm its successor.
    assert!(block_on(interval.tick()).is_ok());
    assert_eq!(handle.registered(), 1);
    let before_reset = Instant::now();
    interval.reset().unwrap();
    assert!(interval.next >= before_reset + HOUR);
    assert_eq!(handle.registered(), 1);
    assert_eq!(
      poll_with(&mut interval.tick(), Waker::noop()),
      Poll::Pending
    );
    interval.reset_immediately().unwrap();
    assert_eq!(handle.registered(), 0);
    assert!(block_on(interval.tick()).is_ok());
    assert_eq!(handle.registered(), 1);
    driver.shutdown().unwrap();
  }

  #[test]
  fn indexed_heap_keeps_order_after_moves_cancels_and_slot_reuse() {
    let (driver, handle) = driver(32);
    let base = Instant::now() + HOUR;
    let mut sleeps = (0..32)
      .map(|index| {
        handle
          .sleep_until(base + Duration::from_millis((31 - index) as u64))
          .unwrap()
      })
      .collect::<Vec<_>>();
    for index in (0..32).step_by(2) {
      sleeps[index]
        .reset(base + Duration::from_millis((index + 40) as u64))
        .unwrap();
    }
    assert_eq!(handle.registered(), 32);
    let earliest = sleeps.iter().map(Sleep::deadline).min().unwrap();
    assert_eq!(
      lock(&handle.shared.state).queue.first_deadline(),
      Some(earliest)
    );

    let stale_key = lock(&sleeps[31].slot.state).key.unwrap();
    for index in (1..32).step_by(2) {
      drop(std::mem::replace(
        &mut sleeps[index],
        handle.sleep(Duration::ZERO).unwrap(),
      ));
    }
    assert_eq!(handle.registered(), 16);
    let tied_deadline = base + MS;
    let mut reused = (0..16)
      .map(|_| handle.sleep_until(tied_deadline).unwrap())
      .collect::<Vec<_>>();
    let reused_key = lock(&reused[0].slot.state).key.unwrap();
    assert_eq!(reused_key.index, stale_key.index);
    assert_ne!(reused_key.generation, stale_key.generation);
    {
      let mut state = lock(&handle.shared.state);
      assert_eq!(state.queue.first(), Some(reused_key));
      assert!(state.queue.remove(stale_key).is_none());
      assert_eq!(state.queue.len(), 32);
    }

    for index in (0..32).step_by(2) {
      drop(std::mem::replace(
        &mut sleeps[index],
        handle.sleep(Duration::ZERO).unwrap(),
      ));
    }
    assert_eq!(handle.registered(), 16);
    for _ in 0..16 {
      let key = lock(&handle.shared.state).queue.first().unwrap();
      let index = reused
        .iter()
        .position(|sleep| lock(&sleep.slot.state).key == Some(key))
        .unwrap();
      drop(std::mem::replace(
        &mut reused[index],
        handle.sleep(Duration::ZERO).unwrap(),
      ));
    }
    assert_eq!(handle.registered(), 0);
    drop(sleeps);
    drop(reused);
    driver.shutdown().unwrap();
  }
}
