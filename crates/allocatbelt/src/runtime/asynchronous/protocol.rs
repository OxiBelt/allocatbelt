//! Per-task dispatch, wake, abort, and generation transitions. The local
//! executor holds `PollProtocol` under its state mutex; the distributed
//! executor holds `SlotProtocol` under each slot mutex and keeps queued,
//! running, complete and join state in the task's word (the task cell's
//! `runtime_task_word.rs`), which wakes, pending poll finishes, publication
//! and the join handle change without that mutex. Loom uses the same helpers under its
//! mutexes to explore operation orderings.

#[cfg(loom)]
use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PollFinish {
  Stale,
  Complete,
  CancelCleanup,
  Requeue,
  Idle,
}

/// A scope's active-poll quota. Scope dispatch owns this value under its
/// mutex; keeping acquire/release in this helper lets Loom exercise the exact
/// production counter transition without modeling unrelated queue details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PollQuota {
  maximum: usize,
  active: usize,
}

impl PollQuota {
  pub(super) const fn new(maximum: usize) -> Self {
    Self { maximum, active: 0 }
  }

  pub(super) fn try_acquire(&mut self) -> bool {
    if self.active >= self.maximum {
      return false;
    }
    self.active += 1;
    true
  }

  /// Releases a previously acquired poll slot and reports whether capacity
  /// became available to a blocked scope.
  pub(super) fn release(&mut self) -> bool {
    debug_assert!(self.active > 0);
    if self.active == 0 {
      return false;
    }
    self.active -= 1;
    self.active < self.maximum
  }

  pub(super) const fn active(&self) -> usize {
    self.active
  }

  pub(super) const fn maximum(&self) -> usize {
    self.maximum
  }
}

/// A binding scope's quota and FIFO waiters. Both acquisition and release
/// require exclusive access under the scope mutex. A transferred permit stays
/// counted until its selected task dispatches or returns it on cancellation.
#[derive(Debug)]
pub(super) struct ScopeDispatch {
  quota: PollQuota,
  blocked_head: usize,
  blocked_tail: usize,
  blocked_len: usize,
}

impl ScopeDispatch {
  pub(super) const fn new(maximum: usize) -> Self {
    Self {
      quota: PollQuota::new(maximum),
      blocked_head: super::lane::NIL,
      blocked_tail: super::lane::NIL,
      blocked_len: 0,
    }
  }

  pub(super) fn try_acquire(&mut self) -> bool {
    self.quota.try_acquire()
  }

  pub(super) fn block(&mut self, links: &[super::lane::QueueLink], index: usize) {
    debug_assert!(!links[index].blocked.load(Ordering::Relaxed));
    let nil = super::lane::NIL;
    links[index]
      .prev
      .store(self.blocked_tail, Ordering::Relaxed);
    links[index].next.store(nil, Ordering::Relaxed);
    if self.blocked_tail == nil {
      self.blocked_head = index;
    } else {
      links[self.blocked_tail]
        .next
        .store(index, Ordering::Relaxed);
    }
    self.blocked_tail = index;
    self.blocked_len += 1;
    links[index].blocked.store(true, Ordering::Relaxed);
  }

  pub(super) fn unlink_blocked(&mut self, links: &[super::lane::QueueLink], index: usize) -> bool {
    if !links[index].blocked.load(Ordering::Relaxed) {
      return false;
    }
    let nil = super::lane::NIL;
    let prev = links[index].prev.load(Ordering::Relaxed);
    let next = links[index].next.load(Ordering::Relaxed);
    if prev == nil {
      self.blocked_head = next;
    } else {
      links[prev].next.store(next, Ordering::Relaxed);
    }
    if next == nil {
      self.blocked_tail = prev;
    } else {
      links[next].prev.store(prev, Ordering::Relaxed);
    }
    self.blocked_len -= 1;
    links[index].prev.store(nil, Ordering::Relaxed);
    links[index].next.store(nil, Ordering::Relaxed);
    links[index].blocked.store(false, Ordering::Relaxed);
    true
  }

  pub(super) fn release_or_transfer(&mut self, links: &[super::lane::QueueLink]) -> Option<usize> {
    debug_assert!(self.quota.active() > 0);
    if self.blocked_len != 0 {
      let index = self.blocked_head;
      let removed = self.unlink_blocked(links, index);
      debug_assert!(removed);
      return Some(index);
    }
    self.quota.release();
    None
  }

  pub(super) const fn active(&self) -> usize {
    self.quota.active()
  }
  pub(super) const fn maximum(&self) -> usize {
    self.quota.maximum()
  }
  pub(super) const fn blocked_len(&self) -> usize {
    self.blocked_len
  }

  #[cfg(test)]
  pub(super) fn check(&self, links: &[super::lane::QueueLink]) -> Vec<usize> {
    assert!(self.active() <= self.maximum());
    let mut indices = Vec::new();
    let mut prev = super::lane::NIL;
    let mut index = self.blocked_head;
    while index != super::lane::NIL {
      assert!(
        indices.len() < self.blocked_len,
        "cycle or incorrect blocked length"
      );
      assert_eq!(links[index].prev.load(Ordering::Relaxed), prev);
      assert!(links[index].blocked.load(Ordering::Relaxed));
      indices.push(index);
      prev = index;
      index = links[index].next.load(Ordering::Relaxed);
    }
    assert_eq!(indices.len(), self.blocked_len);
    assert_eq!(prev, self.blocked_tail);
    indices
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct PollProtocol {
  generation: u64,
  admitted: bool,
  queued: bool,
  running: bool,
  wake_pending: bool,
  abort: bool,
}

impl PollProtocol {
  pub(super) const fn new() -> Self {
    Self {
      generation: 0,
      admitted: false,
      queued: false,
      running: false,
      wake_pending: false,
      abort: false,
    }
  }

  pub(super) fn next_generation(&self) -> Option<u64> {
    self.generation.checked_add(1)
  }

  pub(super) fn admit(&mut self, generation: u64) {
    debug_assert!(!self.admitted);
    self.generation = generation;
    self.admitted = true;
    self.queued = false;
    self.running = false;
    self.wake_pending = false;
    self.abort = false;
  }

  pub(super) fn admitted(&self) -> bool {
    self.admitted
  }

  pub(super) fn generation(&self) -> u64 {
    self.generation
  }

  pub(super) fn matches(&self, generation: u64) -> bool {
    self.admitted && self.generation == generation
  }

  #[cfg(all(test, loom))]
  pub(super) fn is_running(&self) -> bool {
    self.running
  }

  /// Queues an idle admitted task, at most once.
  pub(super) fn queue(&mut self) -> bool {
    if !self.admitted || self.queued || self.running {
      return false;
    }
    self.queued = true;
    true
  }

  /// Marks a wake. While polling it records one pending wake; while queued
  /// it coalesces; otherwise it requests one queue insertion.
  pub(super) fn wake(&mut self) -> bool {
    if !self.admitted {
      return false;
    }
    if self.running {
      self.wake_pending = true;
      false
    } else {
      self.queue()
    }
  }

  /// Requests abort and schedules cleanup when no poll is in progress.
  pub(super) fn abort(&mut self) -> bool {
    if !self.admitted {
      return false;
    }
    self.abort = true;
    if self.running { false } else { self.queue() }
  }

  /// Starts the one queued poll/cleanup turn, returning whether abort had
  /// already won before dequeue.
  pub(super) fn begin_poll(&mut self) -> Option<bool> {
    if !self.admitted || !self.queued || self.running {
      return None;
    }
    self.queued = false;
    self.running = true;
    Some(self.abort)
  }

  /// Resolves one completed poll under its task lock.
  pub(super) fn finish_poll(&mut self, ready: bool) -> PollFinish {
    if !self.admitted || !self.running {
      return PollFinish::Stale;
    }
    if ready {
      self.release();
      return PollFinish::Complete;
    }
    if self.abort {
      self.wake_pending = false;
      // Keep `running` set until the worker drops the future and releases the
      // admission; no wake can dispatch cleanup concurrently.
      return PollFinish::CancelCleanup;
    }
    self.running = false;
    if self.wake_pending {
      self.wake_pending = false;
      self.queued = true;
      PollFinish::Requeue
    } else {
      PollFinish::Idle
    }
  }

  /// Releases a cancelled task after its future cleanup has completed.
  pub(super) fn finish_cancel(&mut self) {
    self.release();
  }

  fn release(&mut self) {
    self.admitted = false;
    self.queued = false;
    self.running = false;
    self.wake_pending = false;
    self.abort = false;
  }
}

/// The distributed executor's per-slot admission state, held under the
/// slot mutex: the generation that names the occupant, whether the slot is
/// admitted, and whether cancellation was requested. Whether the occupant
/// is queued or running lives in the task's word, which belongs to the
/// task object rather than the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct SlotProtocol {
  generation: u64,
  admitted: bool,
  abort: bool,
}

impl SlotProtocol {
  pub(super) const fn new() -> Self {
    Self {
      generation: 0,
      admitted: false,
      abort: false,
    }
  }

  pub(super) fn next_generation(&self) -> Option<u64> {
    self.generation.checked_add(1)
  }

  pub(super) fn admit(&mut self, generation: u64) {
    debug_assert!(!self.admitted);
    self.generation = generation;
    self.admitted = true;
    self.abort = false;
  }

  pub(super) fn admitted(&self) -> bool {
    self.admitted
  }

  pub(super) fn generation(&self) -> u64 {
    self.generation
  }

  pub(super) fn matches(&self, generation: u64) -> bool {
    self.admitted && self.generation == generation
  }

  /// Requests cancellation of the admitted occupant; false when the slot is
  /// free. Routing the cleanup turn is the caller's job, through the word.
  pub(super) fn abort(&mut self) -> bool {
    if !self.admitted {
      return false;
    }
    self.abort = true;
    true
  }

  /// Whether the next dispatch of this occupant must cancel it.
  pub(super) fn aborting(&self) -> bool {
    self.admitted && self.abort
  }

  /// Frees the slot after completion or cancellation cleanup.
  pub(super) fn release(&mut self) {
    self.admitted = false;
    self.abort = false;
  }
}

/// The atomics that gate owned-scope close readiness. Scheduler slot removal
/// is serialized separately; a close is ready only after that removal sets
/// `reclaimed` for the same generation.
pub(super) struct ScopeProtocol {
  active: AtomicUsize,
  closed: AtomicBool,
  reclaimed: AtomicBool,
}

impl ScopeProtocol {
  pub(super) fn new(root_scope: bool) -> Self {
    Self {
      active: AtomicUsize::new(0),
      closed: AtomicBool::new(false),
      reclaimed: AtomicBool::new(root_scope),
    }
  }

  pub(super) fn add_task(&self) {
    self.active.fetch_add(1, Ordering::AcqRel);
  }

  pub(super) fn close(&self) {
    self.closed.store(true, Ordering::Release);
  }

  /// Returns true for the final child completion.
  pub(super) fn complete_one(&self) -> bool {
    self.active.fetch_sub(1, Ordering::AcqRel) == 1
  }

  pub(super) fn active(&self) -> usize {
    self.active.load(Ordering::Acquire)
  }

  pub(super) fn is_closed(&self) -> bool {
    self.closed.load(Ordering::Acquire)
  }

  pub(super) fn is_reclaimed(&self) -> bool {
    self.reclaimed.load(Ordering::Acquire)
  }

  pub(super) fn mark_reclaimed(&self) {
    self.reclaimed.store(true, Ordering::Release);
  }

  /// The scheduler's scope-table lock must still validate the slot
  /// generation and identity before acting on this predicate.
  pub(super) fn can_reclaim(&self) -> bool {
    self.is_closed() && self.active() == 0
  }

  pub(super) fn is_ready(&self) -> bool {
    self.active() == 0 && self.is_reclaimed()
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use loom::sync::{Arc, Mutex};
  use loom::thread;

  use super::super::task::{PollNotify, PollWord};
  use super::{PollFinish, PollProtocol, PollQuota, ScopeProtocol, SlotProtocol};

  fn lock<T>(mutex: &Mutex<T>) -> loom::sync::MutexGuard<'_, T> {
    mutex
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
  }

  fn bounded_model(check: impl Fn() + Sync + Send + 'static) {
    let mut model = loom::model::Builder::new();
    // This protocol has three actors and several atomics; keep unit-test
    // runtime predictable while still exploring a broad schedule set.
    model.max_permutations = Some(10_000);
    model.check(check);
  }

  fn admitted() -> PollProtocol {
    let mut state = PollProtocol::new();
    state.admit(1);
    assert!(state.queue());
    state
  }

  #[test]
  fn loom_wake_abort_and_dispatch_release_one_task_once() {
    loom::model(|| {
      let state = Arc::new(Mutex::new(admitted()));
      let wake = {
        let state = Arc::clone(&state);
        thread::spawn(move || lock(&state).wake())
      };
      let abort = {
        let state = Arc::clone(&state);
        thread::spawn(move || lock(&state).abort())
      };
      let dispatch = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          let mut state = lock(&state);
          state.begin_poll()
        })
      };
      let _ = wake.join().unwrap();
      let _ = abort.join().unwrap();
      let _ = dispatch.join().unwrap();

      let mut state = lock(&state);
      while state.admitted() {
        if state.is_running() {
          if state.finish_poll(false) == PollFinish::CancelCleanup {
            state.finish_cancel();
          }
        } else if let Some(aborting) = state.begin_poll() {
          if aborting || state.finish_poll(false) == PollFinish::CancelCleanup {
            state.finish_cancel();
          }
        } else {
          // One final wake/abort after an idle poll must leave a dispatchable
          // entry; after the cleanup poll it releases exactly once.
          let _ = state.abort();
        }
      }
      assert!(!state.admitted());
      assert!(!state.queued);
      assert!(!state.running);
      assert_eq!(state.finish_poll(false), PollFinish::Stale);
    });
  }

  #[test]
  fn loom_poll_quota_serializes_acquire_and_release_at_capacity_one() {
    bounded_model(|| {
      let state = Arc::new(Mutex::new((PollQuota::new(1), 0usize, 0usize)));
      let first = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          loop {
            let acquired = {
              let mut state = lock(&state);
              if state.0.try_acquire() {
                state.1 += 1;
                state.2 += 1;
                assert_eq!(state.0.active(), 1);
                assert_eq!(state.1, 1);
                true
              } else {
                false
              }
            };
            if acquired {
              break;
            }
            thread::yield_now();
          }
          thread::yield_now();
          let mut state = lock(&state);
          assert!(state.0.release());
          state.1 -= 1;
        })
      };
      let second = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          loop {
            let acquired = {
              let mut state = lock(&state);
              if state.0.try_acquire() {
                state.1 += 1;
                state.2 += 1;
                assert_eq!(state.0.active(), 1);
                assert_eq!(state.1, 1);
                true
              } else {
                false
              }
            };
            if acquired {
              break;
            }
            thread::yield_now();
          }
          thread::yield_now();
          let mut state = lock(&state);
          assert!(state.0.release());
          state.1 -= 1;
        })
      };
      first.join().unwrap();
      second.join().unwrap();
      let state = lock(&state);
      assert_eq!(state.0.active(), 0);
      assert_eq!(state.1, 0);
      assert_eq!(state.2, 2);
    });
  }

  #[test]
  fn loom_wake_between_pending_poll_and_finish_is_coalesced() {
    loom::model(|| {
      let state = Arc::new(Mutex::new(admitted()));
      {
        let mut state = lock(&state);
        assert_eq!(state.begin_poll(), Some(false));
      }
      let wake = {
        let state = Arc::clone(&state);
        thread::spawn(move || lock(&state).wake())
      };
      let did_enqueue = wake.join().unwrap();
      let mut state = lock(&state);
      assert!(!did_enqueue);
      assert_eq!(state.finish_poll(false), PollFinish::Requeue);
      assert_eq!(state.begin_poll(), Some(false));
      assert_eq!(state.finish_poll(true), PollFinish::Complete);
      assert!(!state.admitted());
    });
  }

  #[test]
  fn loom_wake_after_or_during_pending_finish_leaves_one_dispatch() {
    bounded_model(|| {
      let mut initial = admitted();
      assert_eq!(initial.begin_poll(), Some(false));
      let state = Arc::new(Mutex::new(initial));
      let finish = {
        let state = Arc::clone(&state);
        thread::spawn(move || lock(&state).finish_poll(false))
      };
      let wake = {
        let state = Arc::clone(&state);
        thread::spawn(move || lock(&state).wake())
      };
      let _ = finish.join().unwrap();
      let _ = wake.join().unwrap();
      let mut state = lock(&state);
      assert!(state.queued);
      assert!(!state.running);
      assert_eq!(state.begin_poll(), Some(false));
      assert_eq!(state.finish_poll(true), PollFinish::Complete);
    });
  }

  #[test]
  fn loom_abort_racing_ready_or_pending_finish_has_one_terminal_release() {
    bounded_model(|| {
      for ready in [false, true] {
        let mut initial = admitted();
        assert_eq!(initial.begin_poll(), Some(false));
        let state = Arc::new(Mutex::new(initial));
        let abort = {
          let state = Arc::clone(&state);
          thread::spawn(move || lock(&state).abort())
        };
        let finish = {
          let state = Arc::clone(&state);
          thread::spawn(move || lock(&state).finish_poll(ready))
        };
        let _ = abort.join().unwrap();
        let outcome = finish.join().unwrap();
        let mut state = lock(&state);
        match outcome {
          PollFinish::Complete => assert!(!state.admitted()),
          PollFinish::CancelCleanup => {
            state.finish_cancel();
            assert!(!state.admitted());
          }
          PollFinish::Idle if !ready => {
            // Pending may commit before abort; abort then reserves the next
            // cleanup dispatch rather than racing the completed poll.
            assert_eq!(state.begin_poll(), Some(true));
            state.finish_cancel();
            assert!(!state.admitted());
          }
          other => panic!("unexpected terminal outcome: {other:?}"),
        }
        assert_eq!(state.finish_poll(false), PollFinish::Stale);
      }
    });
  }

  #[test]
  fn loom_stale_generation_wake_and_abort_are_inert_after_reuse() {
    loom::model(|| {
      let mut state = admitted();
      assert_eq!(state.begin_poll(), Some(false));
      assert_eq!(state.finish_poll(true), PollFinish::Complete);
      state.admit(2);
      assert!(state.queue());
      if state.matches(1) {
        let _ = state.wake();
        let _ = state.abort();
      }
      assert_eq!(state.begin_poll(), Some(false));
      assert_eq!(state.finish_poll(false), PollFinish::Idle);
      assert!(state.admitted());
      assert!(!state.queued);
      assert!(!state.abort);
    });
  }

  #[test]
  fn loom_abort_before_dequeue_or_during_poll_cleans_once() {
    bounded_model(|| {
      let state = Arc::new(Mutex::new(admitted()));
      let abort = {
        let state = Arc::clone(&state);
        thread::spawn(move || lock(&state).abort())
      };
      let dispatch = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          let mut state = lock(&state);
          state.begin_poll()
        })
      };
      let _ = abort.join().unwrap();
      let _ = dispatch.join().unwrap();

      let mut state = lock(&state);
      if state.is_running() {
        assert_eq!(state.finish_poll(false), PollFinish::CancelCleanup);
        state.finish_cancel();
      } else {
        assert_eq!(state.begin_poll(), Some(true));
        state.finish_cancel();
      }
      assert!(!state.admitted());
      assert_eq!(state.finish_poll(false), PollFinish::Stale);
    });
  }

  #[test]
  fn loom_repeated_wakes_and_abort_during_cleanup_never_requeue() {
    bounded_model(|| {
      let mut state = admitted();
      assert_eq!(state.begin_poll(), Some(false));
      assert!(!state.abort());
      assert!(!state.wake());
      assert!(!state.wake());
      assert_eq!(state.finish_poll(false), PollFinish::CancelCleanup);
      assert!(!state.queue());
      assert!(!state.wake());
      assert!(!state.abort());
      state.finish_cancel();
      assert!(!state.admitted());
      assert!(!state.queued);
    });
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  enum Entry {
    Ready,
    Cleanup,
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  enum Turn {
    Poll,
    Cancel,
  }

  /// One distributed slot: `SlotProtocol` under the slot mutex, the task's
  /// word, and the ready queue the word's queue entry lives in. The model
  /// has one task, so a correct protocol never holds two entries or inserts
  /// while a dequeued entry has not begun its turn.
  struct WordSlot {
    locked: Mutex<SlotProtocol>,
    word: PollWord,
    queue: Mutex<Vec<Entry>>,
    cancelled: Mutex<usize>,
  }

  impl WordSlot {
    /// An admitted task in the state the given transitions leave it in.
    fn new(running: bool, idle: bool) -> Arc<Self> {
      let mut protocol = SlotProtocol::new();
      protocol.admit(1);
      let word = PollWord::new(true);
      // Publication queues the task.
      assert_eq!(word.notify(), PollNotify::Enqueue);
      if running || idle {
        assert!(word.begin());
      }
      if idle {
        assert!(!word.finish_pending());
      }
      let queue = if running || idle {
        Vec::new()
      } else {
        vec![Entry::Ready]
      };
      Arc::new(Self {
        locked: Mutex::new(protocol),
        word,
        queue: Mutex::new(queue),
        cancelled: Mutex::new(0),
      })
    }

    fn push(&self, entry: Entry) {
      let mut queue = lock(&self.queue);
      assert!(queue.is_empty(), "second queue entry for one task");
      queue.push(entry);
    }

    /// The `Wake` implementation: one word RMW and, if it won, an insert.
    fn wake(&self) {
      if self.word.notify() == PollNotify::Enqueue {
        self.push(Entry::Ready);
      }
    }

    /// `abort_slot`: the request is recorded under the slot mutex; only an
    /// idle task needs a new (cleanup) entry, won through the same RMW.
    fn abort(&self) {
      let enqueue = {
        let mut locked = lock(&self.locked);
        if !locked.abort() {
          return;
        }
        self.word.notify() == PollNotify::Enqueue
      };
      if enqueue {
        self.push(Entry::Cleanup);
      }
    }

    /// `dispatch_decision` for a dequeued entry, under the slot mutex.
    fn dispatch(&self) -> Option<Turn> {
      let entry = lock(&self.queue).pop()?;
      let locked = lock(&self.locked);
      assert!(locked.admitted(), "{entry:?} outlived its task");
      assert!(self.word.begin());
      Some(if locked.aborting() {
        Turn::Cancel
      } else {
        Turn::Poll
      })
    }

    /// The pending finish takes no slot mutex.
    fn finish_pending(&self) {
      if self.word.finish_pending() {
        self.push(Entry::Ready);
      }
    }

    /// Completion and cancellation cleanup release the slot under its
    /// mutex; publication then sets `COMPLETE` without it. Wakes in between
    /// find the word running and queue nothing.
    fn release(&self, turn: Turn) {
      {
        let mut locked = lock(&self.locked);
        assert!(locked.admitted());
        locked.release();
      }
      self.word.complete();
      if turn == Turn::Cancel {
        *lock(&self.cancelled) += 1;
      }
    }

    /// Runs the remaining turns; pending polls stay pending.
    fn drain(&self) {
      while let Some(turn) = self.dispatch() {
        match turn {
          Turn::Poll => self.finish_pending(),
          Turn::Cancel => self.release(turn),
        }
      }
    }
  }

  #[test]
  fn loom_word_wakes_racing_pending_finish_requeue_exactly_once() {
    bounded_model(|| {
      let slot = WordSlot::new(true, false);
      let poller = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || {
          // A self-wake during the poll, then the lock-free finish.
          slot.wake();
          slot.finish_pending();
        })
      };
      let waker = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || slot.wake())
      };
      poller.join().unwrap();
      waker.join().unwrap();
      assert_eq!(*lock(&slot.queue), [Entry::Ready]);
      assert!(slot.word.is_queued());
    });
  }

  #[test]
  fn loom_word_wake_racing_pending_finish_is_never_lost() {
    bounded_model(|| {
      let slot = WordSlot::new(true, false);
      let poller = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || slot.finish_pending())
      };
      let waker = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || slot.wake())
      };
      poller.join().unwrap();
      waker.join().unwrap();
      // Either the finish took `NOTIFIED`, or the wake found the word idle
      // and inserted; never both, never neither.
      assert_eq!(lock(&slot.queue).len(), 1);
      assert!(slot.word.is_queued());
      assert_eq!(slot.dispatch(), Some(Turn::Poll));
    });
  }

  #[test]
  fn loom_word_wake_racing_completion_never_queues() {
    bounded_model(|| {
      let slot = WordSlot::new(true, false);
      let poller = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || slot.release(Turn::Poll))
      };
      let waker = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || slot.wake())
      };
      poller.join().unwrap();
      waker.join().unwrap();
      assert!(lock(&slot.queue).is_empty());
      assert!(slot.word.is_complete());
      assert!(!lock(&slot.locked).admitted());
    });
  }

  #[test]
  fn loom_word_abort_while_running_cancels_on_the_next_dispatch() {
    bounded_model(|| {
      let slot = WordSlot::new(true, false);
      let poller = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || slot.finish_pending())
      };
      let aborter = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || slot.abort())
      };
      let waker = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || slot.wake())
      };
      poller.join().unwrap();
      aborter.join().unwrap();
      waker.join().unwrap();
      // The finish requeued the task, or abort (or the wake) found it idle.
      assert_eq!(lock(&slot.queue).len(), 1);
      assert_eq!(slot.dispatch(), Some(Turn::Cancel));
      slot.release(Turn::Cancel);
      slot.wake();
      assert!(lock(&slot.queue).is_empty());
      assert_eq!(*lock(&slot.cancelled), 1);
    });
  }

  #[test]
  fn loom_word_abort_of_idle_task_racing_wake_inserts_one_entry() {
    bounded_model(|| {
      let slot = WordSlot::new(false, true);
      let aborter = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || slot.abort())
      };
      let waker = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || slot.wake())
      };
      aborter.join().unwrap();
      waker.join().unwrap();
      let entries = lock(&slot.queue).clone();
      assert!(entries == [Entry::Ready] || entries == [Entry::Cleanup]);
      // Whichever entry won, dispatch sees the abort under the slot mutex.
      slot.drain();
      assert_eq!(*lock(&slot.cancelled), 1);
      assert!(slot.word.is_complete());
    });
  }

  #[test]
  fn loom_word_dispatch_racing_wake_and_abort_cancels_once() {
    bounded_model(|| {
      let slot = WordSlot::new(false, false);
      let dispatcher = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || match slot.dispatch() {
          Some(Turn::Poll) => slot.finish_pending(),
          Some(Turn::Cancel) => slot.release(Turn::Cancel),
          None => unreachable!("the published entry is the only one"),
        })
      };
      let waker = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || slot.wake())
      };
      let aborter = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || slot.abort())
      };
      dispatcher.join().unwrap();
      waker.join().unwrap();
      aborter.join().unwrap();
      slot.drain();
      assert!(lock(&slot.queue).is_empty());
      assert_eq!(*lock(&slot.cancelled), 1);
      assert!(slot.word.is_complete());
    });
  }

  #[test]
  fn loom_stale_word_wake_cannot_queue_a_reused_slot() {
    bounded_model(|| {
      // A retained stale waker reaches its own finished word; only the slot
      // index is reused by the running replacement.
      let stale = Arc::new(PollWord::new(true));
      assert_eq!(stale.notify(), PollNotify::Enqueue);
      assert!(stale.begin());
      stale.complete();
      let slot = WordSlot::new(true, false);
      let waker = {
        let slot = Arc::clone(&slot);
        let stale = Arc::clone(&stale);
        thread::spawn(move || {
          if stale.notify() == PollNotify::Enqueue {
            slot.push(Entry::Ready);
          }
        })
      };
      let poller = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || slot.finish_pending())
      };
      waker.join().unwrap();
      poller.join().unwrap();
      assert!(lock(&slot.queue).is_empty());
      assert_eq!(slot.word.flags(), (false, false));
      assert!(stale.is_complete());
    });
  }

  #[derive(Clone, Copy)]
  struct ScopeSlot {
    generation: u64,
    occupied: bool,
  }

  fn retire_scope(protocol: &ScopeProtocol, slot: &Mutex<ScopeSlot>, generation: u64) {
    let mut slot = lock(slot);
    if slot.generation == generation && slot.occupied && protocol.can_reclaim() {
      slot.occupied = false;
      protocol.mark_reclaimed();
    }
  }

  #[test]
  fn loom_last_children_race_close_and_reclaim_scope_once() {
    bounded_model(|| {
      let protocol = Arc::new(ScopeProtocol::new(false));
      protocol.add_task();
      protocol.add_task();
      let slot = Arc::new(Mutex::new(ScopeSlot {
        generation: 1,
        occupied: true,
      }));
      let closer = {
        let protocol = Arc::clone(&protocol);
        let slot = Arc::clone(&slot);
        thread::spawn(move || {
          protocol.close();
          retire_scope(&protocol, &slot, 1);
        })
      };
      let children: Vec<_> = (0..2)
        .map(|_| {
          let protocol = Arc::clone(&protocol);
          let slot = Arc::clone(&slot);
          thread::spawn(move || {
            if protocol.complete_one() {
              retire_scope(&protocol, &slot, 1);
            }
          })
        })
        .collect();
      closer.join().unwrap();
      for child in children {
        child.join().unwrap();
      }
      assert!(protocol.is_ready());
      assert!(!lock(&slot).occupied);
      assert_eq!(protocol.active(), 0);
    });
  }

  #[derive(Default)]
  struct Waiter {
    registered: bool,
    notified: bool,
  }

  fn poll_close(protocol: &ScopeProtocol, waiter: &Mutex<Waiter>) -> bool {
    if protocol.is_ready() {
      return true;
    }
    let mut waiter = lock(waiter);
    if protocol.is_ready() {
      return true;
    }
    waiter.registered = true;
    false
  }

  fn notify_close(protocol: &ScopeProtocol, waiter: &Mutex<Waiter>) {
    let mut waiter = lock(waiter);
    if waiter.registered && protocol.is_ready() {
      waiter.notified = true;
    }
  }

  #[test]
  fn loom_close_wait_registration_cannot_miss_final_reclaim() {
    loom::model(|| {
      let protocol = Arc::new(ScopeProtocol::new(false));
      protocol.add_task();
      protocol.close();
      let slot = Arc::new(Mutex::new(ScopeSlot {
        generation: 1,
        occupied: true,
      }));
      let waiter = Arc::new(Mutex::new(Waiter::default()));
      let poll = {
        let protocol = Arc::clone(&protocol);
        let waiter = Arc::clone(&waiter);
        thread::spawn(move || poll_close(&protocol, &waiter))
      };
      let completion = {
        let protocol = Arc::clone(&protocol);
        let slot = Arc::clone(&slot);
        let waiter = Arc::clone(&waiter);
        thread::spawn(move || {
          assert!(protocol.complete_one());
          retire_scope(&protocol, &slot, 1);
          // Production takes and invokes the registered waker after releasing
          // both scheduler and completion locks.
          notify_close(&protocol, &waiter);
        })
      };
      let was_ready = poll.join().unwrap();
      completion.join().unwrap();
      let waiter = lock(&waiter);
      assert!(protocol.is_ready());
      assert!(was_ready || waiter.notified);
    });
  }

  #[test]
  fn loom_old_close_cannot_reclaim_a_reused_scope_generation() {
    loom::model(|| {
      let old = ScopeProtocol::new(false);
      old.add_task();
      old.close();
      assert!(old.complete_one());
      let slot = Mutex::new(ScopeSlot {
        generation: 1,
        occupied: true,
      });
      retire_scope(&old, &slot, 1);
      assert!(old.is_ready());
      {
        let mut current = lock(&slot);
        current.generation = 2;
        current.occupied = true;
      }
      // A delayed old-generation cleanup attempt must leave the replacement
      // scope untouched.
      retire_scope(&old, &slot, 1);
      assert_eq!(lock(&slot).generation, 2);
      assert!(lock(&slot).occupied);
    });
  }

  struct DispatchSlot {
    protocol: PollProtocol,
    ready: bool,
    reserved: bool,
    permit: bool,
    polls: usize,
    cleanups: usize,
    finished: usize,
  }

  struct ScopeModel {
    scope: Mutex<super::ScopeDispatch>,
    slots: [Mutex<DispatchSlot>; 2],
    links: [super::super::lane::QueueLink; 3],
  }

  impl ScopeModel {
    fn new() -> Self {
      Self {
        scope: Mutex::new(super::ScopeDispatch::new(1)),
        slots: std::array::from_fn(|_| {
          Mutex::new(DispatchSlot {
            protocol: admitted(),
            ready: true,
            reserved: false,
            permit: false,
            polls: 0,
            cleanups: 0,
            finished: 0,
          })
        }),
        links: std::array::from_fn(|_| super::super::lane::QueueLink::new()),
      }
    }

    fn dispatch(&self, index: usize) {
      let mut slot = lock(&self.slots[index]);
      if !std::mem::take(&mut slot.ready) {
        return;
      }
      assert!(slot.protocol.admitted() && !slot.protocol.is_running());
      let reserved = std::mem::take(&mut slot.reserved);
      if slot.protocol.abort {
        assert_eq!(slot.protocol.begin_poll(), Some(true));
        slot.protocol.finish_cancel();
        slot.cleanups += 1;
        slot.finished += 1;
        drop(slot);
        if reserved {
          self.release();
        }
        return;
      }
      if !reserved {
        let mut scope = lock(&self.scope);
        if !scope.try_acquire() {
          scope.block(&self.links, index);
          scope.check(&self.links);
          return;
        }
        assert_eq!(scope.active(), 1);
      }
      assert_eq!(slot.protocol.begin_poll(), Some(false));
      slot.permit = true;
      slot.polls += 1;
    }

    fn abort(&self, index: usize) {
      let mut slot = lock(&self.slots[index]);
      if slot.protocol.abort() {
        slot.ready = true;
      }
      if lock(&self.scope).unlink_blocked(&self.links, index) {
        slot.ready = true;
      }
    }

    fn release(&self) {
      let transferred = {
        let mut scope = lock(&self.scope);
        let index = scope.release_or_transfer(&self.links);
        // A transfer keeps the permit counted, including in release builds.
        assert_eq!(scope.active(), usize::from(index.is_some()));
        scope.check(&self.links);
        index
      };
      // No scope lock while taking the selected slot lock.
      if let Some(index) = transferred {
        let mut slot = lock(&self.slots[index]);
        assert!(!slot.reserved && !slot.ready);
        slot.reserved = true;
        slot.ready = true;
      }
    }

    fn complete(&self, index: usize) {
      let mut slot = lock(&self.slots[index]);
      if !std::mem::take(&mut slot.permit) {
        return;
      }
      assert_eq!(slot.protocol.finish_poll(true), PollFinish::Complete);
      slot.finished += 1;
      drop(slot);
      self.release();
    }

    fn drain_and_check(&self) {
      for _ in 0..3 {
        for index in 0..2 {
          self.dispatch(index);
          self.complete(index);
        }
      }
      let scope = lock(&self.scope);
      assert_eq!(scope.active(), 0);
      assert_eq!(scope.blocked_len(), 0);
      assert!(scope.check(&self.links).is_empty());
      drop(scope);
      for (index, slot) in self.slots.iter().enumerate() {
        let slot = lock(slot);
        assert!(!slot.protocol.admitted());
        assert!(!slot.reserved && !slot.permit && !slot.ready);
        assert!(!self.links[index].blocked.load(super::Ordering::Relaxed));
        assert_eq!(slot.finished, 1);
        assert_eq!(slot.polls + slot.cleanups, 1);
      }
    }
  }

  #[test]
  fn loom_dispatch_abort_and_release_return_reserved_permits() {
    bounded_model(|| {
      let model = Arc::new(ScopeModel::new());
      model.dispatch(0);
      let popper = {
        let model = Arc::clone(&model);
        thread::spawn(move || model.dispatch(1))
      };
      let aborter = {
        let model = Arc::clone(&model);
        thread::spawn(move || model.abort(1))
      };
      let releaser = {
        let model = Arc::clone(&model);
        thread::spawn(move || model.complete(0))
      };
      popper.join().unwrap();
      aborter.join().unwrap();
      releaser.join().unwrap();
      model.drain_and_check();
    });
  }

  #[test]
  fn loom_scope_transfer_is_fifo_and_cannot_reblock() {
    bounded_model(|| {
      let links = Arc::new([
        super::super::lane::QueueLink::new(),
        super::super::lane::QueueLink::new(),
      ]);
      let mut initial = super::ScopeDispatch::new(1);
      assert!(initial.try_acquire());
      initial.block(&links[..], 0);
      initial.block(&links[..], 1);
      let scope = Arc::new(Mutex::new(initial));
      let releaser = {
        let links = Arc::clone(&links);
        let scope = Arc::clone(&scope);
        thread::spawn(move || {
          for index in 0..2 {
            let mut scope = lock(&scope);
            assert_eq!(scope.release_or_transfer(&links[..]), Some(index));
            assert_eq!(scope.active(), 1);
            // The permit is reserved, so no reacquire or blocking is needed.
            assert!(!scope.try_acquire());
            assert!(!links[index].blocked.load(super::Ordering::Relaxed));
            scope.check(&links[..]);
          }
          assert_eq!(lock(&scope).release_or_transfer(&links[..]), None);
        })
      };
      let newcomer = {
        let links = Arc::clone(&links);
        let scope = Arc::clone(&scope);
        thread::spawn(move || {
          let mut scope = lock(&scope);
          if scope.try_acquire() {
            assert_eq!(scope.blocked_len(), 0);
            assert_eq!(scope.release_or_transfer(&links[..]), None);
          }
          scope.check(&links[..]);
        })
      };
      releaser.join().unwrap();
      newcomer.join().unwrap();
      assert_eq!(lock(&scope).active(), 0);
    });
  }

  #[test]
  fn loom_close_races_spawn_reservation_publication_and_rollback() {
    // Runtime drain, runtime cancellation, and owned-scope close.
    for close_kind in 0..3 {
      for publish in [false, true] {
        bounded_model(move || {
          // The admission count includes reserved, not yet published slots;
          // such a slot is not admitted, so close scans skip it.
          let admission = Arc::new(Mutex::new((false, 0usize)));
          let mut protocol = PollProtocol::new();
          protocol.admit(u64::MAX - 1);
          protocol.finish_cancel();
          let slot = Arc::new(Mutex::new((protocol, false)));
          let closing = Arc::new(super::AtomicBool::new(false));
          let scope = Arc::new(ScopeProtocol::new(false));
          let spawner = {
            let admission = Arc::clone(&admission);
            let slot = Arc::clone(&slot);
            let closing = Arc::clone(&closing);
            let scope = Arc::clone(&scope);
            thread::spawn(move || {
              {
                let mut state = lock(&admission);
                if state.0 || scope.is_closed() {
                  return false;
                }
                scope.add_task();
                state.1 += 1;
              }
              // Fallible domain reservations hold neither scheduler lock. The
              // one slot lock of the spawn admits only when close has not won.
              {
                let mut slot = lock(&slot);
                assert!(!slot.0.admitted());
                if publish && !closing.load(super::Ordering::Acquire) && !scope.is_closed() {
                  slot.0.admit(u64::MAX);
                  assert!(slot.0.queue());
                  slot.1 = true;
                  return true;
                }
              }
              // Return the still-movable original future: nothing was
              // admitted and no generation was consumed.
              lock(&admission).1 -= 1;
              assert!(scope.complete_one());
              false
            })
          };
          let closer = {
            let admission = Arc::clone(&admission);
            let slot = Arc::clone(&slot);
            let closing = Arc::clone(&closing);
            let scope = Arc::clone(&scope);
            thread::spawn(move || {
              if close_kind != 2 {
                closing.store(true, super::Ordering::Release);
              }
              {
                let mut state = lock(&admission);
                if close_kind == 2 {
                  scope.close();
                } else {
                  state.0 = true;
                }
                if state.1 == 0 {
                  assert!(!lock(&slot).0.admitted());
                }
              }
              if close_kind != 0 {
                let mut slot = lock(&slot);
                if slot.0.admitted() {
                  // Published: the queued entry is aborted in place.
                  let _ = slot.0.abort();
                } else {
                  // Reserved or free: nothing to abort; a later publication
                  // sees the close flag under this same slot lock.
                  assert!(!slot.1);
                }
              }
            })
          };
          let spawned = spawner.join().unwrap();
          closer.join().unwrap();
          assert_eq!(*lock(&admission), (close_kind != 2, usize::from(spawned)));
          assert_eq!(scope.active(), usize::from(spawned));
          let mut slot = lock(&slot);
          assert_eq!(slot.0.admitted(), spawned);
          assert_eq!(slot.1, spawned);
          assert_eq!(slot.0.generation(), u64::MAX - u64::from(!spawned));
          if spawned {
            let cancel = close_kind != 0;
            assert_eq!(slot.0.begin_poll(), Some(cancel));
            if cancel {
              slot.0.finish_cancel();
            } else {
              assert_eq!(slot.0.finish_poll(true), PollFinish::Complete);
            }
            lock(&admission).1 -= 1;
            assert!(scope.complete_one());
          }
          assert!(!slot.0.admitted());
          assert_eq!(lock(&admission).1, 0);
          assert_eq!(scope.active(), 0);
        });
      }
    }
  }

  #[test]
  fn loom_stolen_dispatch_races_release_and_owner_pop() {
    use super::super::lane::LaneQueue;

    bounded_model(|| {
      let model = Arc::new(ScopeModel::new());
      model.dispatch(0);
      assert_eq!(lock(&model.scope).active(), 1);
      // The second same-scope task competes with the owner's pop. The
      // sentinel exercises both a multi-entry steal and a final-entry steal.
      let mut victim = LaneQueue::new();
      victim.push(&model.links, 1);
      victim.push(&model.links, 2);
      let victim = Arc::new(Mutex::new(victim));
      let owner = {
        let model = Arc::clone(&model);
        let victim = Arc::clone(&victim);
        thread::spawn(move || {
          let index = lock(&victim).pop(&model.links).unwrap();
          if index == 1 {
            model.dispatch(index);
          }
          index
        })
      };
      let thief = {
        let model = Arc::clone(&model);
        let victim = Arc::clone(&victim);
        thread::spawn(move || {
          let chain = lock(&victim).steal_front(&model.links);
          chain.map(|chain| {
            // A two-entry victim yields one entry, dispatched directly
            // without entering the receiving lane.
            let index = chain.into_single().unwrap();
            assert!(index == 1 || index == 2);
            if index == 1 {
              model.dispatch(index);
            }
            index
          })
        })
      };
      let releaser = {
        let model = Arc::clone(&model);
        // Release can precede dispatch, or transfer to its blocked task.
        thread::spawn(move || model.complete(0))
      };
      let mut popped = vec![owner.join().unwrap()];
      popped.extend(thief.join().unwrap());
      releaser.join().unwrap();
      model.drain_and_check();
      let mut victim = lock(&victim);
      popped.extend(victim.pop(&model.links));
      popped.sort_unstable();
      assert_eq!(popped, [1, 2]);
      assert!(victim.check(&model.links).is_empty());
    });
  }

  /// The distributed task's join protocol on its word, through the Loom
  /// stand-in of the task cell (the word and the join transitions are the
  /// cell's own source; the outcome and waker cells assert that no access
  /// overlaps an exclusive one).
  mod join_word {
    use super::super::super::task::{TaskCell, TaskJoin, TaskWord};
    use super::bounded_model;
    use loom::sync::Arc;
    use loom::sync::atomic::{AtomicUsize, Ordering};
    use loom::thread;
    use std::pin::Pin;
    use std::sync::Arc as StdArc;
    use std::task::{Poll, Wake, Waker};

    type Cell = TaskCell<(), std::future::Pending<()>, Output>;

    /// Counts its drops: the outcome must be dropped exactly once.
    struct Output(Arc<AtomicUsize>);

    impl Drop for Output {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }

    struct Counters {
      wakes: AtomicUsize,
      drops: Arc<AtomicUsize>,
    }

    struct CountWake(Arc<Counters>);

    impl Wake for CountWake {
      fn wake(self: StdArc<Self>) {
        self.0.wakes.fetch_add(1, Ordering::SeqCst);
      }

      fn wake_by_ref(self: &StdArc<Self>) {
        self.0.wakes.fetch_add(1, Ordering::SeqCst);
      }
    }

    impl Drop for CountWake {
      fn drop(&mut self) {
        self.0.drops.fetch_add(1, Ordering::SeqCst);
      }
    }

    fn waker() -> (Arc<Counters>, Waker) {
      let counters = Arc::new(Counters {
        wakes: AtomicUsize::new(0),
        drops: Arc::new(AtomicUsize::new(0)),
      });
      let waker = Waker::from(StdArc::new(CountWake(Arc::clone(&counters))));
      (counters, waker)
    }

    fn task() -> (Pin<std::sync::Arc<Cell>>, TaskJoin<Cell>, Arc<AtomicUsize>) {
      let (task, join) = TaskCell::new_with_join((), std::future::pending(), |task| task);
      (task, join, Arc::new(AtomicUsize::new(0)))
    }

    /// The final turn: store the outcome, then publish it outside every
    /// lock, dropping what publication hands back.
    fn publish(task: &Pin<std::sync::Arc<Cell>>, drops: &Arc<AtomicUsize>) {
      let output = Output(Arc::clone(drops));
      assert!(task.as_ref().finish(move |_| output));
      let publication = task.publish();
      assert!(publication.published);
      drop(publication);
    }

    #[test]
    fn loom_join_registration_racing_publication_wakes_once_or_returns() {
      bounded_model(|| {
        let (task, mut join, drops) = task();
        let publisher = {
          let drops = Arc::clone(&drops);
          thread::spawn(move || publish(&task, &drops))
        };
        let (counters, waker) = waker();
        let first = join.poll(&waker);
        publisher.join().unwrap();
        let output = match first {
          Poll::Ready(output) => output,
          Poll::Pending => {
            assert_eq!(counters.wakes.load(Ordering::SeqCst), 1);
            match join.poll(&waker) {
              Poll::Ready(output) => output,
              Poll::Pending => panic!("woken without a published outcome"),
            }
          }
        };
        assert!(output.is_some());
        // Taken exactly once.
        assert!(matches!(join.poll(&waker), Poll::Ready(None)));
        drop(output);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(counters.wakes.load(Ordering::SeqCst) <= 1);
        drop(join);
        drop(waker);
        assert_eq!(counters.drops.load(Ordering::SeqCst), 1);
      });
    }

    #[test]
    fn loom_join_reregistration_racing_publication_wakes_the_latest_waker() {
      bounded_model(|| {
        let (task, mut join, drops) = task();
        let (first, first_waker) = waker();
        let (second, second_waker) = waker();
        assert!(join.poll(&first_waker).is_pending());
        let publisher = {
          let drops = Arc::clone(&drops);
          thread::spawn(move || publish(&task, &drops))
        };
        let again = join.poll(&second_waker);
        publisher.join().unwrap();
        let first_wakes = first.wakes.load(Ordering::SeqCst);
        let second_wakes = second.wakes.load(Ordering::SeqCst);
        assert!(first_wakes + second_wakes <= 1, "woken twice");
        if again.is_pending() {
          // Registered before publication: the replacement is the one woken.
          assert_eq!((first_wakes, second_wakes), (0, 1));
        } else {
          assert_eq!(second_wakes, 0);
        }
        drop((again, join, first_waker, second_waker));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(first.drops.load(Ordering::SeqCst), 1);
        assert_eq!(second.drops.load(Ordering::SeqCst), 1);
      });
    }

    #[test]
    fn loom_join_detach_racing_publication_drops_outcome_and_waker_once() {
      bounded_model(|| {
        let (task, mut join, drops) = task();
        let (counters, waker) = waker();
        assert!(join.poll(&waker).is_pending());
        drop(waker);
        let publisher = {
          let drops = Arc::clone(&drops);
          thread::spawn(move || publish(&task, &drops))
        };
        drop(join);
        publisher.join().unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(counters.drops.load(Ordering::SeqCst), 1);
        assert!(counters.wakes.load(Ordering::SeqCst) <= 1);
      });
    }

    /// Publication races a completion-only registration, a join
    /// registration and a move of the completion-only waiter: every waiter
    /// whose poll stayed pending is woken once, none twice.
    #[test]
    fn loom_join_and_finished_registrations_racing_publication_wake_each_once() {
      bounded_model(|| {
        let (task, mut join, drops) = task();
        let (finished_counters, finished_waker) = waker();
        let (joiner, join_waker) = waker();
        let (moved, moved_waker) = waker();
        let publisher = {
          let drops = Arc::clone(&drops);
          thread::spawn(move || publish(&task, &drops))
        };
        let _registered = join.poll_complete(&finished_waker);
        let second = join.poll(&join_waker);
        let third = join.poll_complete(&moved_waker).is_pending();
        publisher.join().unwrap();
        let finished = finished_counters.wakes.load(Ordering::SeqCst);
        let joined = joiner.wakes.load(Ordering::SeqCst);
        let moved_wakes = moved.wakes.load(Ordering::SeqCst);
        assert!(
          finished <= 1 && joined <= 1 && moved_wakes <= 1,
          "woken twice"
        );
        if second.is_pending() {
          assert_eq!(joined, 1, "pending join waiter not woken");
        }
        // The completion-only role is one waiter: its latest pending
        // registration is woken; a re-registration that returned ready has
        // already observed completion. Never more than one wake for it.
        assert!(
          finished + moved_wakes <= 1,
          "completion-only waiter woken twice"
        );
        if third {
          assert_eq!(moved_wakes, 1, "pending completion-only waiter not woken");
        }
        drop(second);
        drop(join);
        drop((finished_waker, join_waker, moved_waker));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(finished_counters.drops.load(Ordering::SeqCst), 1);
        assert_eq!(joiner.drops.load(Ordering::SeqCst), 1);
        assert_eq!(moved.drops.load(Ordering::SeqCst), 1);
      });
    }

    /// Cancellation requests only notify the scheduling bits: the join bits,
    /// the waker and the outcome change only at publication, which here
    /// publishes the cancelled outcome while the handle registers and then
    /// detaches.
    #[test]
    fn loom_cancellation_publication_racing_register_and_detach() {
      bounded_model(|| {
        let (task, mut join, drops) = task();
        let word_owner = Pin::clone(&task);
        let abort = thread::spawn(move || {
          let word: &TaskWord = word_owner.word();
          // `abort_slot`: one wake RMW on the word, under the slot mutex in
          // production; it never reads or writes the join bits.
          let _ = word.notify();
        });
        let publisher = {
          let drops = Arc::clone(&drops);
          thread::spawn(move || publish(&task, &drops))
        };
        let (counters, waker) = waker();
        let polled = join.poll(&waker);
        drop(join);
        drop(waker);
        abort.join().unwrap();
        publisher.join().unwrap();
        drop(polled);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(counters.drops.load(Ordering::SeqCst), 1);
        assert!(counters.wakes.load(Ordering::SeqCst) <= 1);
      });
    }
  }
}

#[cfg(all(test, not(loom)))]
mod scope_dispatch_tests {
  use super::super::lane::{NIL, QueueLink};
  use super::{Ordering, ScopeDispatch};

  #[test]
  fn scope_dispatch_transfers_permits_in_fifo_order() {
    let links: Vec<_> = (0..4).map(|_| QueueLink::new()).collect();
    let mut scope = ScopeDispatch::new(1);
    assert_eq!(scope.maximum(), 1);
    assert!(scope.try_acquire());
    for index in 0..4 {
      assert!(!scope.try_acquire());
      scope.block(&links, index);
      assert_eq!(scope.blocked_len(), index + 1);
    }
    assert_eq!(scope.check(&links), [0, 1, 2, 3]);
    for index in 0..4 {
      assert_eq!(scope.release_or_transfer(&links), Some(index));
      assert_eq!(scope.active(), 1);
      assert!(!scope.try_acquire());
      assert!(!links[index].blocked.load(Ordering::Relaxed));
      assert_eq!(links[index].next.load(Ordering::Relaxed), NIL);
      assert_eq!(links[index].prev.load(Ordering::Relaxed), NIL);
      scope.check(&links);
    }
    assert_eq!(scope.release_or_transfer(&links), None);
    assert_eq!(scope.active(), 0);
    assert!(scope.try_acquire());
  }

  #[test]
  fn scope_dispatch_unlinks_head_middle_tail_and_singleton() {
    for order in [[0, 1, 2, 3], [1, 3, 0, 2], [3, 2, 1, 0]] {
      let links: Vec<_> = (0..4).map(|_| QueueLink::new()).collect();
      let mut scope = ScopeDispatch::new(2);
      assert!(scope.try_acquire());
      assert!(scope.try_acquire());
      assert!(!scope.try_acquire());
      for index in 0..4 {
        scope.block(&links, index);
      }
      let mut expected = vec![0, 1, 2, 3];
      for index in order {
        assert!(scope.unlink_blocked(&links, index));
        assert!(!scope.unlink_blocked(&links, index));
        expected.retain(|&entry| entry != index);
        assert_eq!(scope.check(&links), expected);
        assert_eq!(scope.blocked_len(), expected.len());
      }
      assert_eq!(scope.release_or_transfer(&links), None);
      assert_eq!(scope.active(), 1);
      assert_eq!(scope.release_or_transfer(&links), None);
      assert_eq!(scope.active(), 0);
    }
  }
}
