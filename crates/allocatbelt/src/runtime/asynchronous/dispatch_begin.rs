//! The start of a dispatch for a slot whose task takes no scope permit: the
//! turn begins through the slot's published task pointer without the slot
//! lock, which the dispatch then takes only when an abort may be pending.
//!
//! An abort sets the slot's cleanup flag under the slot lock before its wake
//! read-modify-write on the task word, and `begin` is a read-modify-write on
//! the same word. If the wake comes first, `begin` reads it (or a later
//! value of the word) and the flag load that follows sees the abort, which
//! the slot lock then decides. If `begin` comes first, the wake finds the
//! turn running and leaves `NOTIFIED`, so the turn's finish requeues the
//! task and its next dispatch sees the flag. Either way every abort is
//! decided under the slot lock; this path only proves, without the lock,
//! that the current turn has none to decide.

#![forbid(unsafe_code)]

#[cfg(loom)]
use loom::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicBool, Ordering};

use super::task::{Lease, PublishedTask, TaskLend};

/// A slot's state for a dispatch that begins on the task word without the
/// slot mutex: whether its occupant's polls take no scope permit, and the
/// occupant's published pointer. Both are written only under the slot lock,
/// at publication before the first queue entry is inserted and at release
/// when no entry exists, so the holder of a queue entry reads the values of
/// the current occupancy.
pub(super) struct DispatchBegin<T: ?Sized + TaskLend> {
  permit_free: AtomicBool,
  published: PublishedTask<T>,
}

/// How a dequeued entry's dispatch continues.
pub(super) enum Begin<T: ?Sized + TaskLend> {
  /// The occupant takes a permit: decide under the slot lock.
  Locked,
  /// The turn began and no abort preceded it: poll with a free permit.
  Poll(Lease<T>),
  /// The turn began, but an abort may be pending: decide under the slot
  /// lock with this turn.
  Decide(Lease<T>),
  /// The entry began no turn.
  Stale,
}

impl<T: ?Sized + TaskLend> DispatchBegin<T> {
  pub(super) fn new() -> Self {
    Self {
      permit_free: AtomicBool::new(false),
      published: PublishedTask::empty(),
    }
  }

  /// The cell the slot publishes its occupant's pointer into.
  pub(super) fn published(&self) -> &PublishedTask<T> {
    &self.published
  }

  /// Under the slot lock: after the occupant was installed and before its
  /// first entry is inserted, or (false) when the slot releases it.
  pub(super) fn set_permit_free(&self, permit_free: bool) {
    self.permit_free.store(permit_free, Ordering::Relaxed);
  }

  /// Begins the turn for the caller's dequeued entry when the occupant
  /// takes no permit. `cleanup` is the slot's abort flag.
  ///
  /// The caller must hold the occupant's queue entry, which the
  /// publication's insertion ordered after both writes above.
  #[inline]
  pub(super) fn begin(&self, cleanup: &AtomicBool) -> Begin<T> {
    if !self.permit_free.load(Ordering::Relaxed) {
      return Begin::Locked;
    }
    let Some(lease) = self.published.lend() else {
      return Begin::Stale;
    };
    // `begin`'s AcqRel read-modify-write reads every abort wake that
    // precedes it on the word; the flag was set before that wake.
    if cleanup.load(Ordering::SeqCst) {
      Begin::Decide(lease)
    } else {
      Begin::Poll(lease)
    }
  }
}

/// Loom models of a turn begun on the task word without the slot mutex
/// against the slot's abort, wakes, final turn and reuse, and of the keyed
/// value claims. They drive the real `DispatchBegin` and task word through
/// the cell's stand-in, whose published pointer reads with `Relaxed` ordering
/// and fails on a task its slot already released, and whose claims fail when
/// two overlap. The slot lock and the lane are Loom mutexes; the slot logic
/// around them follows `Distributed` (publication, `abort_slot`,
/// `dispatch_decision`, `finish_poll` and `finish_turn`) in miniature.
#[cfg(all(test, loom))]
mod model {
  use super::super::task::{CellPoll, PollNotify, TaskCell, TaskHeader, TaskSlot, TaskWord};
  use super::{Begin, DispatchBegin};
  use loom::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
  use loom::sync::{Arc, Mutex};
  use loom::thread;
  use std::collections::VecDeque;
  use std::future::Future;
  use std::pin::Pin;
  use std::task::{Context, Poll, Waker};

  type Entries = Arc<Mutex<VecDeque<u32>>>;

  /// Wakes insert the one entry an idle word hands out, tagged with the
  /// occupancy they were inserted for.
  struct Header {
    serial: u32,
    entries: Entries,
  }

  impl TaskHeader for Header {
    fn wake_by_ref(&self, word: &TaskWord) {
      if word.notify() == PollNotify::Enqueue {
        self.entries.lock().unwrap().push_back(self.serial);
      }
    }
  }

  /// Pending `remaining` times, then ready; wakes itself when `wake` is set.
  struct Yielding {
    remaining: u32,
    wake: bool,
  }

  impl Future for Yielding {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
      if self.remaining == 0 {
        return Poll::Ready(());
      }
      self.remaining -= 1;
      if self.wake {
        cx.waker().wake_by_ref();
      }
      Poll::Pending
    }
  }

  type Model = TaskCell<Header, Yielding, ()>;

  const ABORT_NONE: u8 = 0;
  /// The abort's wake found no turn: every later turn must see the abort.
  const ABORT_FOUND_IDLE: u8 = 1;
  /// The abort's wake found a turn, whose finish requeues the task.
  const ABORT_FOUND_RUNNING: u8 = 2;

  struct SlotState {
    task: TaskSlot<Model>,
    aborting: bool,
  }

  struct Harness {
    slot: Mutex<SlotState>,
    begin: DispatchBegin<Model>,
    cleanup: AtomicBool,
    entries: Entries,
    abort_found: AtomicU8,
    finished: AtomicUsize,
    cancelled: AtomicUsize,
  }

  impl Harness {
    fn new() -> Arc<Self> {
      Arc::new(Self {
        slot: Mutex::new(SlotState {
          task: TaskSlot::empty(),
          aborting: false,
        }),
        begin: DispatchBegin::new(),
        cleanup: AtomicBool::new(false),
        entries: Arc::new(Mutex::new(VecDeque::new())),
        abort_found: AtomicU8::new(ABORT_NONE),
        finished: AtomicUsize::new(0),
        cancelled: AtomicUsize::new(0),
      })
    }

    /// Publication: install and publish under the slot lock, then insert
    /// the first entry. Returns a waker for the new task.
    fn publish(&self, serial: u32, future: Yielding) -> Waker {
      let task = TaskCell::new_queued(
        Header {
          serial,
          entries: Arc::clone(&self.entries),
        },
        future,
      );
      let waker = TaskCell::into_waker(Pin::clone(&task));
      {
        let mut slot = self.slot.lock().unwrap();
        self.cleanup.store(false, Ordering::Relaxed);
        slot.aborting = false;
        slot.task.install(task, self.begin.published());
        self.begin.set_permit_free(true);
      }
      self.entries.lock().unwrap().push_back(serial);
      waker
    }

    /// `abort_slot`: the flag, the mark and the wake under the slot lock,
    /// then the requeue a won entry needs.
    fn abort(&self) {
      let enqueue = {
        let mut slot = self.slot.lock().unwrap();
        let Some(task) = slot.task.get().map(Pin::clone) else {
          return;
        };
        self.cleanup.store(true, Ordering::SeqCst);
        slot.aborting = true;
        let found = task.word().notify();
        self.abort_found.store(
          if found == PollNotify::Running {
            ABORT_FOUND_RUNNING
          } else {
            ABORT_FOUND_IDLE
          },
          Ordering::SeqCst,
        );
        (found == PollNotify::Enqueue).then_some(task.header().serial)
      };
      if let Some(serial) = enqueue {
        self.entries.lock().unwrap().push_back(serial);
      }
    }

    /// One dispatch of one dequeued entry; false when the lane was empty.
    fn dispatch(&self) -> bool {
      let Some(serial) = self.entries.lock().unwrap().pop_front() else {
        return false;
      };
      let (lease, cancel) = match self.begin.begin(&self.cleanup) {
        Begin::Poll(lease) => {
          // A permit-free start only proves there is no abort to decide.
          assert_ne!(
            self.abort_found.load(Ordering::SeqCst),
            ABORT_FOUND_IDLE,
            "polled after an abort without deciding it"
          );
          (lease, false)
        }
        Begin::Decide(lease) => {
          let aborting = self.slot.lock().unwrap().aborting;
          assert!(aborting, "cleanup flag without an abort");
          (lease, true)
        }
        Begin::Locked => unreachable!("every model occupant is permit-free"),
        Begin::Stale => panic!("an entry began no turn"),
      };
      assert_eq!(lease.task().header().serial, serial, "stale publication");
      if cancel {
        assert!(lease.task().finish(&lease.key(), |_| ()));
        self.cancelled.fetch_add(1, Ordering::Relaxed);
      } else {
        let waker = lease.waker();
        let polled = lease
          .task()
          .poll_future(&lease.key(), &mut Context::from_waker(&waker));
        if matches!(polled, CellPoll::Pending) {
          if lease.finish_pending() {
            self.entries.lock().unwrap().push_back(serial);
          }
          return true;
        }
        assert!(lease.task().finish(&lease.key(), |_| ()));
      }
      // `finish_turn`: release under the slot lock, publish outside it.
      let owner = {
        let mut slot = self.slot.lock().unwrap();
        self.begin.set_permit_free(false);
        slot.task.take(lease, self.begin.published())
      };
      assert!(owner.publish().published);
      self.finished.fetch_add(1, Ordering::Relaxed);
      true
    }

    fn drain(&self) {
      while self.dispatch() {}
    }

    /// After every actor joined: no entry is left behind and no turn can
    /// reach the released occupant.
    fn check_released(&self, finished: usize) {
      assert_eq!(self.finished.load(Ordering::Relaxed), finished);
      assert!(self.entries.lock().unwrap().is_empty());
      assert!(!self.slot.lock().unwrap().task.is_occupied());
      assert!(self.begin.published().lend().is_none());
    }
  }

  fn bounded(check: impl Fn() + Sync + Send + 'static) {
    let mut model = loom::model::Builder::new();
    model.preemption_bound = Some(3);
    model.check(check);
  }

  #[test]
  fn loom_begin_on_the_word_races_abort_and_external_wake() {
    bounded(|| {
      let harness = Harness::new();
      let waker = harness.publish(
        1,
        Yielding {
          remaining: 2,
          wake: false,
        },
      );
      let dispatcher = {
        let harness = Arc::clone(&harness);
        thread::spawn(move || harness.drain())
      };
      let abort = {
        let harness = Arc::clone(&harness);
        thread::spawn(move || harness.abort())
      };
      let wake = thread::spawn(move || waker.wake());
      dispatcher.join().unwrap();
      abort.join().unwrap();
      wake.join().unwrap();
      // At most two polls before the abort: the task cannot complete, so
      // the abort must have been decided under the slot lock.
      harness.drain();
      harness.check_released(1);
      assert_eq!(harness.cancelled.load(Ordering::Relaxed), 1);
    });
  }

  #[test]
  fn loom_abort_during_a_turn_begun_on_the_word_is_decided_on_the_requeue() {
    bounded(|| {
      let harness = Harness::new();
      // Each poll wakes the task, so its finish requeues it; the abort can
      // land before a begin, during a turn, or after completion.
      let _waker = harness.publish(
        1,
        Yielding {
          remaining: 2,
          wake: true,
        },
      );
      let dispatcher = {
        let harness = Arc::clone(&harness);
        thread::spawn(move || harness.drain())
      };
      let abort = {
        let harness = Arc::clone(&harness);
        thread::spawn(move || harness.abort())
      };
      dispatcher.join().unwrap();
      abort.join().unwrap();
      harness.drain();
      harness.check_released(1);
      // Cancelled unless every poll began before the abort's wake.
      let found = harness.abort_found.load(Ordering::SeqCst);
      if harness.cancelled.load(Ordering::Relaxed) == 0 {
        assert_ne!(found, ABORT_FOUND_IDLE);
      }
    });
  }

  #[test]
  fn loom_final_turn_release_and_slot_reuse_never_reach_a_stale_task() {
    bounded(|| {
      let harness = Harness::new();
      // The first occupant wakes itself once, so it completes whatever the
      // external wake does.
      let stale = harness.publish(
        1,
        Yielding {
          remaining: 1,
          wake: true,
        },
      );
      // The first dispatcher finishes the first occupant when it can and
      // reuses the slot; the second dispatches whatever it dequeues; a
      // waker of the first occupant wakes it once, possibly after release.
      let first = {
        let harness = Arc::clone(&harness);
        thread::spawn(move || {
          harness.drain();
          (harness.finished.load(Ordering::Relaxed) == 1).then(|| {
            harness.publish(
              2,
              Yielding {
                remaining: 0,
                wake: false,
              },
            )
          })
        })
      };
      let second = {
        let harness = Arc::clone(&harness);
        thread::spawn(move || harness.drain())
      };
      let wake = thread::spawn(move || stale.wake());
      let reused = first.join().unwrap();
      second.join().unwrap();
      wake.join().unwrap();
      harness.drain();
      let reused = reused.or_else(|| {
        (harness.finished.load(Ordering::Relaxed) == 1).then(|| {
          harness.publish(
            2,
            Yielding {
              remaining: 0,
              wake: false,
            },
          )
        })
      });
      assert!(reused.is_some(), "the first occupant was lost");
      harness.drain();
      harness.check_released(2);
    });
  }

  #[test]
  fn loom_keyed_claims_of_a_turn_an_idle_take_and_a_word_claim_never_overlap() {
    bounded(|| {
      let harness = Harness::new();
      let _waker = harness.publish(
        1,
        Yielding {
          remaining: 1,
          wake: false,
        },
      );
      let task = Pin::clone(harness.slot.lock().unwrap().task.get().unwrap());
      let finishes = Arc::new(AtomicUsize::new(0));
      // A dispatcher polls under its lease's key (a load and a store), a
      // final owner takes the slot idle and finishes under its key, and a
      // caller without a slot takes the turn through the word alone. Only
      // the word's `RUNNING` orders the third against the other two.
      let dispatcher = {
        let harness = Arc::clone(&harness);
        thread::spawn(move || {
          let lease = harness.slot.lock().unwrap().task.lend();
          if let Some(lease) = lease {
            let polled = lease
              .task()
              .poll_future(&lease.key(), &mut Context::from_waker(Waker::noop()));
            assert!(!matches!(polled, CellPoll::Ready(())));
            let _ = lease.finish_pending();
          }
        })
      };
      let idle = {
        let harness = Arc::clone(&harness);
        let finishes = Arc::clone(&finishes);
        thread::spawn(move || {
          let idle = {
            let mut slot = harness.slot.lock().unwrap();
            slot.task.take_idle(harness.begin.published())
          };
          idle.map(|idle| {
            if idle.task().finish(&idle.key(), |_| ()) {
              finishes.fetch_add(1, Ordering::Relaxed);
            }
            assert!(idle.task().publish().published);
          })
        })
      };
      let unslotted = {
        let finishes = Arc::clone(&finishes);
        thread::spawn(move || {
          if let Some(turn) = task.as_ref().claim_turn()
            && task.as_ref().finish(&turn.key(), |_| ())
          {
            finishes.fetch_add(1, Ordering::Relaxed);
          }
        })
      };
      dispatcher.join().unwrap();
      unslotted.join().unwrap();
      let taken = idle.join().unwrap();
      if taken.is_none() {
        let idle = harness
          .slot
          .lock()
          .unwrap()
          .task
          .take_idle(harness.begin.published())
          .unwrap();
        if idle.task().finish(&idle.key(), |_| ()) {
          finishes.fetch_add(1, Ordering::Relaxed);
        }
        assert!(idle.task().publish().published);
      }
      assert_eq!(finishes.load(Ordering::Relaxed), 1);
      assert!(harness.begin.published().lend().is_none());
      assert!(!harness.slot.lock().unwrap().task.is_occupied());
    });
  }
}
