//! The atomic word of one native async task (optional `runtime`), and the
//! join protocol it governs.
//!
//! This file has no `unsafe`. It is a private module of
//! [`runtime_task_cell`](super), which keeps the cells the word governs (the
//! stored outcome and the one join waker), and Loom compiles the same file
//! into the runtime's boxed stand-in for that cell, so the models exercise
//! these transitions rather than a copy of them.
//!
//! Bits:
//! - `RUNNING`, `NOTIFIED`: scheduling. `NOTIFIED` alone means one queue
//!   entry exists; `RUNNING` means one dispatcher holds the task, and
//!   `RUNNING | NOTIFIED` that its finish requeues it.
//! - `COMPLETE`: the outcome was published. Set once, by publication, and
//!   never cleared; a task that completed inside a turn keeps `RUNNING`
//!   beside it, and a late wake may leave `NOTIFIED`.
//! - `JOIN_INTEREST`: the one join handle still exists. Only dropping that
//!   handle clears it.
//! - `JOIN_WAKER`: the join waker cell holds the wakers that publication
//!   will wake: the handle's join waker and its completion-only waker, one
//!   fixed slot each. While it is clear and the task is not complete, only the join
//!   handle touches the cell; while it is set, both sides may only read the
//!   cell.
//!
//! The outcome cell is written once, before publication, by the cell's own
//! claim; after `COMPLETE` it belongs to the join handle while
//! `JOIN_INTEREST` was set at publication, and to the publisher otherwise.

#[cfg(loom)]
use loom::sync::atomic::{AtomicU64, Ordering};
use std::any::Any;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::Arc;
#[cfg(not(loom))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Poll, Waker};

const RUNNING: u64 = 1;
const NOTIFIED: u64 = 1 << 1;
const COMPLETE: u64 = 1 << 2;
const JOIN_INTEREST: u64 = 1 << 3;
const JOIN_WAKER: u64 = 1 << 4;

/// What a [`TaskWord::notify`] found, and so what its caller must do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PollNotify {
  /// The task was idle: the caller now owns its one queue entry and must
  /// insert it.
  Enqueue,
  /// The task already has a queue entry that no dispatch has begun.
  Queued,
  /// A poll or cleanup turn is in progress; its finish requeues the task.
  Running,
  /// The task finished; nothing may queue it again.
  Complete,
}

/// The task's atomic word. See the module documentation for its bits.
pub(crate) struct PollWord(AtomicU64);

impl PollWord {
  /// A fresh word: idle, with `JOIN_INTEREST` when a join handle is created
  /// together with the task.
  pub(crate) fn new(join_interest: bool) -> Self {
    Self(AtomicU64::new(if join_interest {
      JOIN_INTEREST
    } else {
      0
    }))
  }

  /// Records a wake with one RMW and reports which state it found. Only an
  /// idle word moves to `NOTIFIED` with a new queue entry; a running word
  /// gains `NOTIFIED`, and a queued or complete word keeps its state.
  ///
  /// The RMW reads the latest word value, so a wake can never act on a
  /// state that a finish already left: either the finish takes the
  /// `NOTIFIED` this sets, or this finds the word idle and enqueues. The
  /// release half publishes the waker's prior writes to the turn that
  /// begins or finishes after it; the acquire half pairs with a finish's
  /// release, so the caller's queue insertion follows that poll.
  pub(crate) fn notify(&self) -> PollNotify {
    let previous = self.0.fetch_or(NOTIFIED, Ordering::AcqRel);
    if previous & COMPLETE != 0 {
      PollNotify::Complete
    } else if previous & RUNNING != 0 {
      PollNotify::Running
    } else if previous & NOTIFIED != 0 {
      PollNotify::Queued
    } else {
      PollNotify::Enqueue
    }
  }

  /// Begins a poll or cleanup turn for the entry the caller dequeued: one
  /// compare-and-swap that sets `RUNNING` and clears `NOTIFIED`, keeping the
  /// join bits. Wakes cannot change a queued word, so this is the only
  /// transition out of it; it fails, changing nothing, unless the word is
  /// queued (`NOTIFIED`, neither `RUNNING` nor `COMPLETE`). Only one turn can
  /// therefore hold `RUNNING`.
  pub(crate) fn begin(&self) -> bool {
    self
      .update(|word| {
        (word & (RUNNING | NOTIFIED | COMPLETE) == NOTIFIED).then_some(word ^ (RUNNING | NOTIFIED))
      })
      .is_ok()
  }

  /// Whether a turn holds the word.
  pub(crate) fn is_running(&self) -> bool {
    self.load() & RUNNING != 0
  }

  /// Ends a pending poll in one RMW: `RUNNING` becomes idle, and
  /// `RUNNING | NOTIFIED` becomes `NOTIFIED`, in which case the caller owns
  /// the new queue entry and must insert it.
  pub(crate) fn finish_pending(&self) -> bool {
    let previous = self.0.fetch_and(!RUNNING, Ordering::AcqRel);
    debug_assert_eq!(
      previous & (RUNNING | COMPLETE),
      RUNNING,
      "pending finish without a running turn"
    );
    previous & NOTIFIED != 0
  }

  /// Sets `COMPLETE` once. Returns the previous word, or `None` when an
  /// earlier publication already set it. The release half publishes the
  /// stored outcome (and the claim that stored it) to the join side; the
  /// acquire half makes a registered waker visible to the publisher.
  fn publish(&self) -> Option<u64> {
    let previous = self.0.fetch_or(COMPLETE, Ordering::AcqRel);
    (previous & COMPLETE == 0).then_some(previous)
  }

  /// Ends the publisher's read of the join waker. Returns true when the
  /// join handle was dropped meanwhile, so the publisher drops the waker.
  fn release_join_waker(&self) -> bool {
    let previous = self.0.fetch_and(!JOIN_WAKER, Ordering::AcqRel);
    debug_assert_ne!(previous & JOIN_WAKER, 0);
    previous & JOIN_INTEREST == 0
  }

  fn load(&self) -> u64 {
    self.0.load(Ordering::Acquire)
  }

  /// Hands the join waker cell to publication; fails once complete.
  fn set_join_waker(&self) -> Result<(), ()> {
    self
      .update(|word| {
        debug_assert_ne!(word & JOIN_INTEREST, 0);
        debug_assert_eq!(word & JOIN_WAKER, 0);
        (word & COMPLETE == 0).then_some(word | JOIN_WAKER)
      })
      .map(drop)
  }

  /// Takes the join waker cell back from publication; fails once complete.
  fn unset_join_waker(&self) -> Result<(), ()> {
    self
      .update(|word| {
        // Once complete, publication may already have cleared the bit.
        debug_assert!(word & (COMPLETE | JOIN_WAKER) != 0);
        (word & COMPLETE == 0).then_some(word & !JOIN_WAKER)
      })
      .map(drop)
  }

  /// Drops the join handle's interest; before completion it also takes the
  /// waker cell back. Returns the previous word.
  fn drop_join_interest(&self) -> u64 {
    match self.update(|word| {
      debug_assert_ne!(word & JOIN_INTEREST, 0);
      Some(if word & COMPLETE == 0 {
        word & !(JOIN_INTEREST | JOIN_WAKER)
      } else {
        word & !JOIN_INTEREST
      })
    }) {
      Ok(previous) => previous,
      Err(()) => unreachable!("the join transition always applies"),
    }
  }

  /// A compare-and-swap loop that starts from a fresh load and retries on
  /// the value each failed compare-and-swap observed.
  fn update(&self, mut next: impl FnMut(u64) -> Option<u64>) -> Result<u64, ()> {
    let mut current = self.load();
    loop {
      let Some(new) = next(current) else {
        return Err(());
      };
      match self
        .0
        .compare_exchange_weak(current, new, Ordering::AcqRel, Ordering::Acquire)
      {
        Ok(previous) => return Ok(previous),
        Err(observed) => current = observed,
      }
    }
  }

  /// Whether the word holds a queue entry that no turn has begun.
  #[cfg(test)]
  pub(crate) fn is_queued(&self) -> bool {
    self.load() & (RUNNING | NOTIFIED | COMPLETE) == NOTIFIED
  }

  /// Returns the `RUNNING` and `NOTIFIED` flags.
  #[cfg(test)]
  pub(crate) fn flags(&self) -> (bool, bool) {
    let word = self.load();
    (word & RUNNING != 0, word & NOTIFIED != 0)
  }

  /// Returns the `JOIN_INTEREST` and `JOIN_WAKER` flags.
  #[cfg(all(test, not(loom)))]
  pub(crate) fn join_flags(&self) -> (bool, bool) {
    let word = self.load();
    (word & JOIN_INTEREST != 0, word & JOIN_WAKER != 0)
  }

  pub(crate) fn is_complete(&self) -> bool {
    self.load() & COMPLETE != 0
  }

  /// Publication's word transition alone, for models without cells.
  #[cfg(all(test, loom))]
  pub(crate) fn complete(&self) {
    assert!(self.publish().is_some(), "published twice");
  }
}

/// The face of a task's word that the runtime may use: wakes, which set
/// only `NOTIFIED`, and reads. Turns begin and end through the slot
/// container's lease, which owns `RUNNING`.
pub(crate) struct TaskWord(PollWord);

impl TaskWord {
  pub(crate) fn new(join_interest: bool) -> Self {
    Self(PollWord::new(join_interest))
  }

  /// See [`PollWord::notify`].
  pub(crate) fn notify(&self) -> PollNotify {
    self.0.notify()
  }

  /// Whether the outcome was published.
  pub(crate) fn is_complete(&self) -> bool {
    self.0.is_complete()
  }

  #[cfg(all(test, not(loom)))]
  pub(crate) fn is_queued(&self) -> bool {
    self.0.is_queued()
  }

  #[cfg(all(test, not(loom)))]
  pub(crate) fn flags(&self) -> (bool, bool) {
    self.0.flags()
  }

  #[cfg(all(test, not(loom)))]
  pub(crate) fn join_flags(&self) -> (bool, bool) {
    self.0.join_flags()
  }

  /// The whole word, for the cell that owns it.
  pub(super) fn inner(&self) -> &PollWord {
    &self.0
  }
}

/// The two fixed waker slots of the one join handle: one for joining
/// (`poll`) and one for completion-only waiting (`poll_finished`). Both live
/// in one cell behind `JOIN_WAKER`, because only the one handle writes them.
#[derive(Default)]
pub(crate) struct JoinWakers {
  pub(crate) finished: Option<Waker>,
  pub(crate) join: Option<Waker>,
}

/// Which of the handle's two waker slots a poll registers in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WakerSlot {
  Join,
  Finished,
}

impl JoinWakers {
  fn slot(&mut self, slot: WakerSlot) -> &mut Option<Waker> {
    match slot {
      WakerSlot::Join => &mut self.join,
      WakerSlot::Finished => &mut self.finished,
    }
  }

  pub(crate) fn get(&self, slot: WakerSlot) -> Option<&Waker> {
    match slot {
      WakerSlot::Join => self.join.as_ref(),
      WakerSlot::Finished => self.finished.as_ref(),
    }
  }

  /// Stores `waker` in `slot`, returning the waker it replaces.
  pub(crate) fn replace(&mut self, slot: WakerSlot, waker: Option<Waker>) -> Option<Waker> {
    std::mem::replace(self.slot(slot), waker)
  }
}

/// Access to the two cells the word governs. Implemented by the task cell;
/// each method is called only in the state the protocol below names.
pub(crate) trait JoinCells {
  type Output;
  /// Shared read of the join waker cell.
  fn waker_will_wake(&self, slot: WakerSlot, waker: &Waker) -> bool;
  /// Shared read of the join waker cell: wakes the waker in `slot` by
  /// reference.
  fn wake_join(&self, slot: WakerSlot);
  /// Exclusive access to the join waker cell.
  fn update_join_wakers<R>(&self, update: impl FnOnce(&mut JoinWakers) -> R) -> R;
  /// Exclusive access to the outcome cell after publication.
  fn take_output(&self) -> Option<Self::Output>;
}

/// What publication leaves for its caller to drop outside every lock: the
/// outcome when no join handle remained, the handle's wakers when it was
/// dropped while they were being woken, and the payloads of panicking
/// wakes.
pub(crate) struct Publication<O> {
  pub(crate) published: bool,
  pub(crate) output: Option<O>,
  pub(crate) wakers: JoinWakers,
  pub(crate) wake_panics: [Option<Box<dyn Any + Send>>; 2],
}

impl<O> Publication<O> {
  pub(crate) fn refused() -> Self {
    Self {
      published: false,
      output: None,
      wakers: JoinWakers::default(),
      wake_panics: [None, None],
    }
  }
}

/// Publishes a stored outcome: sets `COMPLETE`, then either hands the
/// outcome back (no join handle) or wakes each registered waker of the
/// handle once, the completion-only waiter first. The caller has checked,
/// with acquire ordering, that the outcome is stored.
pub(crate) fn publish<C: JoinCells>(word: &PollWord, cells: &C) -> Publication<C::Output> {
  let Some(previous) = word.publish() else {
    return Publication::refused();
  };
  let mut publication = Publication::refused();
  publication.published = true;
  if previous & JOIN_INTEREST == 0 {
    // The handle detached before completion and took its wakers back.
    publication.output = cells.take_output();
  } else if previous & JOIN_WAKER != 0 {
    for (index, slot) in [WakerSlot::Finished, WakerSlot::Join]
      .into_iter()
      .enumerate()
    {
      publication.wake_panics[index] =
        panic::catch_unwind(AssertUnwindSafe(|| cells.wake_join(slot))).err();
    }
    if word.release_join_waker() {
      publication.wakers = cells.update_join_wakers(std::mem::take);
    }
  }
  publication
}

/// Wakes a waker whose publication was missed, containing its panics.
fn wake_contained(waker: Waker) {
  if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
    && let Err(second) = panic::catch_unwind(AssertUnwindSafe(|| drop(payload)))
  {
    std::mem::forget(second);
  }
}

/// One poll of the join handle: returns the outcome (when `take`) once
/// published, or registers `waker` in `slot`, leaving the other slot's
/// waker in place. A stored waker that will wake the same task is kept
/// without a clone.
pub(crate) fn join_poll<C: JoinCells>(
  word: &PollWord,
  cells: &C,
  slot: WakerSlot,
  waker: &Waker,
  take: bool,
) -> Poll<Option<C::Output>> {
  let current = word.load();
  if current & COMPLETE == 0 {
    if current & JOIN_WAKER != 0 && cells.waker_will_wake(slot, waker) {
      return Poll::Pending;
    }
    // Cloned (user code) before the cells change hands, so a panicking
    // clone leaves the registered wakers with publication.
    let replacement = waker.clone();
    let owned = current & JOIN_WAKER == 0 || word.unset_join_waker().is_ok();
    if owned {
      // `JOIN_WAKER` is clear and only this handle sets it: the cell is
      // this handle's alone until the transition below.
      let old = cells.update_join_wakers(|wakers| wakers.replace(slot, Some(replacement)));
      if word.set_join_waker().is_ok() {
        drop(old);
        return Poll::Pending;
      }
      // Completion won while this handle held the cell, so publication
      // woke nobody: this caller sees the outcome now, and the other
      // slot's waiter is woken here, once.
      let wakers = cells.update_join_wakers(std::mem::take);
      let other = match slot {
        WakerSlot::Join => wakers.finished,
        WakerSlot::Finished => wakers.join,
      };
      drop(old);
      if let Some(other) = other {
        wake_contained(other);
      }
    } else {
      drop(replacement);
    }
  }
  Poll::Ready(if take { cells.take_output() } else { None })
}

/// Takes the outcome once published: `None` before publication, then
/// `Some(None)` after an earlier take.
pub(crate) fn join_take<C: JoinCells>(word: &PollWord, cells: &C) -> Option<Option<C::Output>> {
  word.is_complete().then(|| cells.take_output())
}

/// Detaches the join handle. Returns what the handle must drop: the
/// published outcome, and its wakers unless publication is still reading
/// them (then publication drops them).
pub(crate) fn join_detach<C: JoinCells>(
  word: &PollWord,
  cells: &C,
) -> (Option<C::Output>, JoinWakers) {
  let previous = word.drop_join_interest();
  let complete = previous & COMPLETE != 0;
  let output = if complete { cells.take_output() } else { None };
  let wakers = if !complete || previous & JOIN_WAKER == 0 {
    cells.update_join_wakers(std::mem::take)
  } else {
    JoinWakers::default()
  };
  (output, wakers)
}

/// Implemented only by the task cell.
pub(crate) trait Sealed {}

/// Proof that a join operation comes from the one [`TaskJoin`]; only this
/// module constructs it.
pub(crate) struct JoinKey(());

/// The join side of a task cell, reached through a [`TaskJoin`].
pub(crate) trait JoinSide: Sealed + Send + Sync {
  type Output;
  fn join_complete(&self) -> bool;
  fn join_poll(
    &self,
    key: JoinKey,
    slot: WakerSlot,
    waker: &Waker,
    take: bool,
  ) -> Poll<Option<Self::Output>>;
  fn join_take(&self, key: JoinKey) -> Option<Option<Self::Output>>;
  fn join_detach(&self, key: JoinKey) -> (Option<Self::Output>, JoinWakers);
}

/// The one join handle of a task cell, created with the cell. Dropping it
/// detaches: it clears `JOIN_INTEREST` and drops a published outcome.
pub(crate) struct TaskJoin<J: ?Sized + JoinSide> {
  task: Pin<Arc<J>>,
}

impl<J: ?Sized + JoinSide> TaskJoin<J> {
  /// Only the cell's constructor calls this, once per cell.
  pub(super) fn new(task: Pin<Arc<J>>) -> Self {
    Self { task }
  }

  /// The task allocation, for handles that do not join.
  pub(crate) fn task(&self) -> &Pin<Arc<J>> {
    &self.task
  }

  /// Whether the outcome was published.
  pub(crate) fn is_complete(&self) -> bool {
    self.task.join_complete()
  }

  /// Takes the outcome once published, or registers `waker` as the join
  /// waker.
  pub(crate) fn poll(&mut self, waker: &Waker) -> Poll<Option<J::Output>> {
    self
      .task
      .join_poll(JoinKey(()), WakerSlot::Join, waker, true)
  }

  /// Waits for publication without taking the outcome, registering
  /// `waker` as the completion-only waker; the join waker is kept.
  pub(crate) fn poll_complete(&mut self, waker: &Waker) -> Poll<()> {
    self
      .task
      .join_poll(JoinKey(()), WakerSlot::Finished, waker, false)
      .map(drop)
  }

  /// See [`join_take`].
  pub(crate) fn take(&mut self) -> Option<Option<J::Output>> {
    self.task.join_take(JoinKey(()))
  }
}

impl<J: ?Sized + JoinSide> Drop for TaskJoin<J> {
  fn drop(&mut self) {
    let (output, wakers) = self.task.join_detach(JoinKey(()));
    drop(wakers);
    drop(output);
  }
}
