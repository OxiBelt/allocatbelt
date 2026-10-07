//! Per-task dispatch, wake, abort, and generation transitions. Production
//! holds this state under the scheduler mutex; Loom tests use the same helper
//! under Loom's mutex to explore operation orderings.

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

  /// Resolves one completed poll under the scheduler lock.
  pub(super) fn finish_poll(&mut self, ready: bool, cancel_all: bool) -> PollFinish {
    if !self.admitted || !self.running {
      return PollFinish::Stale;
    }
    if ready {
      self.release();
      return PollFinish::Complete;
    }
    if self.abort || cancel_all {
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

  use super::{PollFinish, PollProtocol, ScopeProtocol};

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
          if state.finish_poll(false, false) == PollFinish::CancelCleanup {
            state.finish_cancel();
          }
        } else if let Some(aborting) = state.begin_poll() {
          if aborting || state.finish_poll(false, false) == PollFinish::CancelCleanup {
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
      assert_eq!(state.finish_poll(false, false), PollFinish::Stale);
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
      assert_eq!(state.finish_poll(false, false), PollFinish::Requeue);
      assert_eq!(state.begin_poll(), Some(false));
      assert_eq!(state.finish_poll(true, false), PollFinish::Complete);
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
        thread::spawn(move || lock(&state).finish_poll(false, false))
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
      assert_eq!(state.finish_poll(true, false), PollFinish::Complete);
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
          thread::spawn(move || lock(&state).finish_poll(ready, false))
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
        assert_eq!(state.finish_poll(false, false), PollFinish::Stale);
      }
    });
  }

  #[test]
  fn loom_stale_generation_wake_and_abort_are_inert_after_reuse() {
    loom::model(|| {
      let mut state = admitted();
      assert_eq!(state.begin_poll(), Some(false));
      assert_eq!(state.finish_poll(true, false), PollFinish::Complete);
      state.admit(2);
      assert!(state.queue());
      if state.matches(1) {
        let _ = state.wake();
        let _ = state.abort();
      }
      assert_eq!(state.begin_poll(), Some(false));
      assert_eq!(state.finish_poll(false, false), PollFinish::Idle);
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
        assert_eq!(state.finish_poll(false, false), PollFinish::CancelCleanup);
        state.finish_cancel();
      } else {
        assert_eq!(state.begin_poll(), Some(true));
        state.finish_cancel();
      }
      assert!(!state.admitted());
      assert_eq!(state.finish_poll(false, false), PollFinish::Stale);
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
      assert_eq!(state.finish_poll(false, false), PollFinish::CancelCleanup);
      assert!(!state.queue());
      assert!(!state.wake());
      assert!(!state.abort());
      state.finish_cancel();
      assert!(!state.admitted());
      assert!(!state.queued);
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
}
