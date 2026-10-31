//! Per-task dispatch, wake, abort, and generation transitions. Production
//! holds this state under the task slot mutex. Loom uses the same helpers
//! under its mutexes to explore operation orderings. `PollWord` is the one
//! per-task word a wake may change without that mutex.

#[cfg(loom)]
use loom::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

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

  pub(super) fn aborting_queued(&self) -> bool {
    self.admitted && self.queued && self.abort && !self.running
  }

  #[cfg(test)]
  pub(super) fn is_running(&self) -> bool {
    self.running
  }

  #[cfg(all(test, not(loom)))]
  pub(super) fn is_queued(&self) -> bool {
    self.queued
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

const RUNNING: u64 = 1;
const NOTIFIED: u64 = 1 << 1;
const FLAGS: u64 = RUNNING | NOTIFIED;

/// A task slot's lock-free wake record: the low 62 bits of the polled
/// generation, shifted above `RUNNING` and `NOTIFIED`. The scheduler mutex
/// owns every transition except `notify_running`, which only sets `NOTIFIED`
/// on a running word with the waker's tag. Admission, generation and abort
/// state stay in `PollProtocol`.
pub(super) struct PollWord(AtomicU64);

impl PollWord {
  pub(super) fn new() -> Self {
    Self(AtomicU64::new(0))
  }

  /// A stale waker whose generation aliases the current one after 2^62 slot
  /// reuses can only set `NOTIFIED`, which requests one spurious poll; futures
  /// must already tolerate that.
  const fn tag(generation: u64) -> u64 {
    generation << 2
  }

  /// Marks a poll of `generation` as running. Called under the scheduler
  /// mutex while the flags are clear, so no unlocked writer races the store.
  pub(super) fn begin(&self, generation: u64) {
    debug_assert_eq!(self.0.load(Ordering::Relaxed) & FLAGS, 0);
    self
      .0
      .store(Self::tag(generation) | RUNNING, Ordering::Release);
  }

  /// Records a wake of a running `generation` poll without the scheduler
  /// mutex. Each success is a release RMW, so `finish` acquires the waker's
  /// prior writes. False sends the caller to the locked wake path.
  pub(super) fn notify_running(&self, generation: u64) -> bool {
    let running = Self::tag(generation) | RUNNING;
    let mut current = self.0.load(Ordering::Acquire);
    while current & !NOTIFIED == running {
      match self.0.compare_exchange(
        current,
        current | NOTIFIED,
        Ordering::AcqRel,
        Ordering::Acquire,
      ) {
        Ok(_) => return true,
        Err(actual) => current = actual,
      }
    }
    false
  }

  /// Ends the running poll under the scheduler mutex, clearing `RUNNING` and
  /// taking `NOTIFIED` in one RMW. Later wakes take the locked path.
  pub(super) fn finish(&self) -> bool {
    self.0.fetch_and(!FLAGS, Ordering::AcqRel) & NOTIFIED != 0
  }

  /// Returns the `RUNNING` and `NOTIFIED` flags.
  #[cfg(test)]
  pub(super) fn flags(&self) -> (bool, bool) {
    let word = self.0.load(Ordering::Acquire);
    (word & RUNNING != 0, word & NOTIFIED != 0)
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

  use super::{PollFinish, PollProtocol, PollQuota, PollWord, ScopeProtocol};

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

  /// One task slot as the scheduler holds it: `PollProtocol` and a count of
  /// queue insertions under the slot mutex, and the unlocked wake word.
  struct WordSlot {
    locked: Mutex<(PollProtocol, usize)>,
    word: PollWord,
  }

  /// Admits `generation`, queues it and begins its poll, as dispatch does.
  fn running_slot(generation: u64) -> Arc<WordSlot> {
    let mut protocol = PollProtocol::new();
    protocol.admit(generation);
    assert!(protocol.queue());
    assert_eq!(protocol.begin_poll(), Some(false));
    let word = PollWord::new();
    word.begin(generation);
    Arc::new(WordSlot {
      locked: Mutex::new((protocol, 0)),
      word,
    })
  }

  fn locked_wake(slot: &WordSlot, generation: u64) {
    let mut locked = lock(&slot.locked);
    if locked.0.matches(generation) && locked.0.wake() {
      locked.1 += 1;
    }
  }

  fn word_wake(slot: &WordSlot, generation: u64) {
    if !slot.word.notify_running(generation) {
      locked_wake(slot, generation);
    }
  }

  fn word_finish(slot: &WordSlot, ready: bool) -> PollFinish {
    let mut locked = lock(&slot.locked);
    if slot.word.finish() {
      assert!(!locked.0.wake());
    }
    let finish = locked.0.finish_poll(ready);
    if finish == PollFinish::Requeue {
      locked.1 += 1;
    }
    finish
  }

  #[test]
  fn loom_lock_free_self_wake_racing_finish_and_wakes_queues_once() {
    bounded_model(|| {
      let slot = running_slot(1);
      let poller = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || {
          word_wake(&slot, 1);
          word_finish(&slot, false)
        })
      };
      let waker = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || word_wake(&slot, 1))
      };
      let locked = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || locked_wake(&slot, 1))
      };
      let finish = poller.join().unwrap();
      waker.join().unwrap();
      locked.join().unwrap();
      assert_eq!(finish, PollFinish::Requeue);
      assert_eq!(slot.word.flags(), (false, false));
      let mut locked = lock(&slot.locked);
      assert_eq!(locked.1, 1);
      assert!(locked.0.queued);
      assert_eq!(locked.0.begin_poll(), Some(false));
      assert_eq!(locked.0.finish_poll(true), PollFinish::Complete);
    });
  }

  #[test]
  fn loom_lock_free_wake_racing_pending_finish_is_never_lost() {
    bounded_model(|| {
      let slot = running_slot(1);
      let poller = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || word_finish(&slot, false))
      };
      let waker = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || word_wake(&slot, 1))
      };
      let _ = poller.join().unwrap();
      waker.join().unwrap();
      assert_eq!(slot.word.flags(), (false, false));
      let locked = lock(&slot.locked);
      // Either `finish` took `NOTIFIED`, or the wake saw `RUNNING` clear and
      // queued under the mutex; never both, never neither.
      assert_eq!(locked.1, 1);
      assert!(locked.0.queued && !locked.0.running);
    });
  }

  #[test]
  fn loom_lock_free_wake_racing_ready_finish_releases_without_queueing() {
    bounded_model(|| {
      let slot = running_slot(1);
      let poller = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || word_finish(&slot, true))
      };
      let waker = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || word_wake(&slot, 1))
      };
      assert_eq!(poller.join().unwrap(), PollFinish::Complete);
      waker.join().unwrap();
      assert_eq!(slot.word.flags(), (false, false));
      let locked = lock(&slot.locked);
      assert_eq!(locked.1, 0);
      assert!(!locked.0.admitted() && !locked.0.queued);
    });
  }

  #[test]
  fn loom_stale_generation_word_wake_cannot_queue_a_reused_slot() {
    bounded_model(|| {
      let slot = running_slot(2);
      let stale = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || word_wake(&slot, 1))
      };
      let poller = {
        let slot = Arc::clone(&slot);
        thread::spawn(move || word_finish(&slot, false))
      };
      stale.join().unwrap();
      assert_eq!(poller.join().unwrap(), PollFinish::Idle);
      assert_eq!(slot.word.flags(), (false, false));
      let mut locked = lock(&slot.locked);
      assert_eq!(locked.1, 0);
      assert!(!locked.0.queued);
      // A truncated-tag alias of the running generation only adds one poll.
      assert!(locked.0.queue());
      assert_eq!(locked.0.begin_poll(), Some(false));
      slot.word.begin(2);
      drop(locked);
      assert!(slot.word.notify_running(2 + (1 << 62)));
      assert_eq!(word_finish(&slot, false), PollFinish::Requeue);
      assert_eq!(lock(&slot.locked).1, 1);
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
  fn loom_close_races_spawn_and_aborts_every_admitted_slot() {
    bounded_model(|| {
      let admission = Arc::new(Mutex::new(false));
      let slot = Arc::new(Mutex::new(PollProtocol::new()));
      let spawner = {
        let admission = Arc::clone(&admission);
        let slot = Arc::clone(&slot);
        thread::spawn(move || {
          let closed = lock(&admission);
          if *closed {
            return false;
          }
          let mut slot = lock(&slot);
          slot.admit(1);
          assert!(slot.queue());
          true
        })
      };
      let closer = {
        let admission = Arc::clone(&admission);
        let slot = Arc::clone(&slot);
        thread::spawn(move || {
          *lock(&admission) = true;
          let mut slot = lock(&slot);
          if slot.admitted() {
            let _ = slot.abort();
          }
        })
      };
      let spawned = spawner.join().unwrap();
      closer.join().unwrap();
      assert!(*lock(&admission));
      let mut slot = lock(&slot);
      assert_eq!(slot.admitted(), spawned);
      if spawned {
        assert_eq!(slot.begin_poll(), Some(true));
        slot.finish_cancel();
      }
      assert!(!slot.admitted());
    });
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
            // Release the victim before acquiring the receiving lane.
            let own = Mutex::new(LaneQueue::new());
            let index = {
              let mut own = lock(&own);
              own.append_chain(&model.links, chain);
              let index = own.pop(&model.links).unwrap();
              assert!(own.check(&model.links).is_empty());
              index
            };
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
