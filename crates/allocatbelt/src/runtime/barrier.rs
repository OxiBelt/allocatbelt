//! A bounded reusable asynchronous barrier.
//!
//! Dropping an enrolled wait before its round completes breaks that round for
//! its other enrolled waits, frees the canceled slot, and advances the
//! barrier. Callers must handle [`BarrierError::Broken`] and retry or abandon
//! their operation. A completed round remains successful if the barrier is
//! subsequently closed.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::PoisonError;
use std::task::{Context, Poll, Waker};

#[cfg(loom)]
use loom::sync::{Arc, Mutex, MutexGuard};
#[cfg(not(loom))]
use std::sync::{Arc, Mutex, MutexGuard};

use crate::runtime::task::drop_contained;

/// A reusable barrier with a fixed participant count and bounded waiter table.
///
/// The table bound counts enrolled waits whose result has not been observed,
/// including successful and failed results. Construction reserves the full
/// table. Calls to [`wait`](Self::wait) do not enroll a future until its first
/// poll; a full table returns [`BarrierError::Full`] without counting an
/// arrival.
pub struct Barrier {
  shared: Arc<Shared>,
}

struct Shared {
  ledger: Mutex<Ledger>,
}

/// An owned wait for one barrier round. The future is enrolled on first poll.
#[must_use = "futures do nothing unless polled"]
pub struct BarrierWait {
  shared: Arc<Shared>,
  key: Option<WaiterKey>,
  completed: bool,
}

/// The successful outcome of a barrier wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarrierOutcome {
  /// The monotonically increasing round this wait joined, starting at zero.
  pub round: u64,
  /// Exactly one successful wait in a round is its leader.
  pub leader: bool,
}

/// An error returned by a barrier wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierError {
  /// The bounded table has no slot for this future.
  Full,
  /// The barrier was closed before the current round completed.
  Closed,
  /// Another enrolled future was canceled before this round completed.
  Broken,
  /// The barrier round counter or this future's slot generation is exhausted.
  Exhausted,
  /// A custom waker panicked while being cloned. Any prior enrollment was
  /// canceled, breaking its round if that round was still unfinished.
  WakerPanicked,
  /// This future was polled after it returned a result.
  Completed,
}

impl fmt::Display for BarrierError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Full => "barrier waiter table is full",
      Self::Closed => "barrier is closed",
      Self::Broken => "barrier round was broken by cancellation",
      Self::Exhausted => "barrier generation is exhausted",
      Self::WakerPanicked => "barrier waker clone panicked",
      Self::Completed => "barrier wait future was already completed",
    })
  }
}

impl std::error::Error for BarrierError {}

/// Why barrier construction failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierBuildError {
  /// A barrier must have at least one participant.
  ZeroParticipants,
  /// The waiter table must have at least one slot.
  ZeroCapacity,
  /// The waiter table must hold at least one full participant group.
  CapacityTooSmall,
  /// The table size overflowed or cannot be represented by a Rust allocation.
  CapacityOverflow,
  /// The preallocated waiter table could not be reserved.
  AllocationFailed,
}

impl fmt::Display for BarrierBuildError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::ZeroParticipants => "barrier participant count must be nonzero",
      Self::ZeroCapacity => "barrier waiter capacity must be nonzero",
      Self::CapacityTooSmall => "barrier waiter capacity is smaller than participants",
      Self::CapacityOverflow => "barrier waiter capacity overflowed",
      Self::AllocationFailed => "barrier waiter table allocation failed",
    })
  }
}

impl std::error::Error for BarrierBuildError {}

impl Barrier {
  /// Creates a barrier for `participants` and at most `max_waiters` live
  /// futures. Both counts must be nonzero and `max_waiters` must be at least
  /// `participants`.
  pub fn new(participants: usize, max_waiters: usize) -> Result<Self, BarrierBuildError> {
    if participants == 0 {
      return Err(BarrierBuildError::ZeroParticipants);
    }
    if max_waiters == 0 {
      return Err(BarrierBuildError::ZeroCapacity);
    }
    if max_waiters < participants {
      return Err(BarrierBuildError::CapacityTooSmall);
    }
    let bytes = max_waiters
      .checked_mul(std::mem::size_of::<WaiterSlot>())
      .ok_or(BarrierBuildError::CapacityOverflow)?;
    if bytes > isize::MAX as usize {
      return Err(BarrierBuildError::CapacityOverflow);
    }

    let mut slots = Vec::new();
    slots
      .try_reserve_exact(max_waiters)
      .map_err(|_| BarrierBuildError::AllocationFailed)?;
    for index in 0..max_waiters {
      slots.push(WaiterSlot {
        generation: 0,
        round: 0,
        state: SlotState::Free,
        free_next: index.checked_add(1).filter(|next| *next < max_waiters),
        waker: None,
      });
    }

    Ok(Self {
      shared: Arc::new(Shared {
        ledger: Mutex::new(Ledger {
          participants,
          round: 0,
          arrivals: 0,
          closed: false,
          exhausted: false,
          free_head: Some(0),
          slots,
        }),
      }),
    })
  }

  /// Returns an owned future that lazily joins the current round on first poll.
  pub fn wait(&self) -> BarrierWait {
    BarrierWait {
      shared: Arc::clone(&self.shared),
      key: None,
      completed: false,
    }
  }

  /// Closes the barrier and completes unfinished current-round waits with
  /// [`BarrierError::Closed`]. Results from rounds that already completed stay
  /// successful, even if their futures have not observed those results yet.
  pub fn close(&self) {
    {
      let mut ledger = lock(&self.shared.ledger);
      if ledger.closed {
        return;
      }
      ledger.closed = true;
      let round = ledger.round;
      for slot in &mut ledger.slots {
        if slot.round == round && matches!(slot.state, SlotState::Waiting) {
          slot.state = SlotState::Closed;
        }
      }
      ledger.arrivals = 0;
    }
    wake_terminal(&self.shared);
  }

  /// Returns the configured participant count.
  #[must_use]
  pub fn participants(&self) -> usize {
    lock(&self.shared.ledger).participants
  }

  /// Returns the fixed waiter-table capacity.
  #[must_use]
  pub fn max_waiters(&self) -> usize {
    lock(&self.shared.ledger).slots.len()
  }

  /// Returns whether the barrier has been closed or exhausted.
  #[must_use]
  pub fn is_closed(&self) -> bool {
    lock(&self.shared.ledger).closed
  }
}

impl Future for BarrierWait {
  type Output = Result<BarrierOutcome, BarrierError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.completed {
      return Poll::Ready(Err(BarrierError::Completed));
    }

    // Waker cloning may invoke user RawWaker code, so do it before taking the
    // ledger lock. A panicking clone is contained and leaves no arrival.
    let mut new_waker = match panic::catch_unwind(AssertUnwindSafe(|| cx.waker().clone())) {
      Ok(waker) => Some(waker),
      Err(payload) => {
        drop_contained(payload);
        if let Some(key) = this.key.take() {
          // A failed clone on a later poll must not strand the enrolled slot.
          // Treat it like cancellation so the unfinished round is broken and
          // its other arrivals can make progress.
          cancel_enrolled(&this.shared, key);
        }
        this.completed = true;
        return Poll::Ready(Err(BarrierError::WakerPanicked));
      }
    };

    let action = match this.key {
      Some(key) => poll_enrolled(&this.shared, key, &mut new_waker),
      None => poll_first(&this.shared, &mut new_waker),
    };
    match action {
      PollAction::Pending(key, old_waker) => {
        this.key = Some(key);
        drop_waker(old_waker);
        drop_waker(new_waker.take());
        Poll::Pending
      }
      PollAction::Ready(result, old_waker) => {
        this.key = None;
        this.completed = true;
        drop_waker(old_waker);
        drop_waker(new_waker.take());
        Poll::Ready(result)
      }
      PollAction::Immediate(result) => {
        this.completed = true;
        drop_waker(new_waker.take());
        Poll::Ready(result)
      }
    }
  }
}

impl Drop for BarrierWait {
  fn drop(&mut self) {
    let Some(key) = self.key.take() else {
      return;
    };
    cancel_enrolled(&self.shared, key);
  }
}

impl Clone for Barrier {
  fn clone(&self) -> Self {
    Self {
      shared: Arc::clone(&self.shared),
    }
  }
}

impl fmt::Debug for Barrier {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let (participants, round, arrivals, closed, max_waiters) = {
      let ledger = lock(&self.shared.ledger);
      (
        ledger.participants,
        ledger.round,
        ledger.arrivals,
        ledger.closed,
        ledger.slots.len(),
      )
    };
    f.debug_struct("Barrier")
      .field("participants", &participants)
      .field("round", &round)
      .field("arrivals", &arrivals)
      .field("closed", &closed)
      .field("max_waiters", &max_waiters)
      .finish()
  }
}

impl fmt::Debug for BarrierWait {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BarrierWait")
      .field("enrolled", &self.key.is_some())
      .field("completed", &self.completed)
      .finish()
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WaiterKey {
  index: usize,
  generation: u64,
  round: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
  Free,
  Waiting,
  Success { leader: bool },
  Broken,
  Closed,
  Exhausted,
  Retired,
}

struct WaiterSlot {
  generation: u64,
  round: u64,
  state: SlotState,
  free_next: Option<usize>,
  waker: Option<Waker>,
}

struct Ledger {
  participants: usize,
  round: u64,
  arrivals: usize,
  closed: bool,
  exhausted: bool,
  free_head: Option<usize>,
  slots: Vec<WaiterSlot>,
}

impl Ledger {
  fn allocate(&mut self, waker: Waker) -> Result<WaiterKey, Waker> {
    let Some(index) = self.free_head else {
      return Err(waker);
    };
    let slot = &self.slots[index];
    if slot.state != SlotState::Free {
      return Err(waker);
    }
    self.free_head = slot.free_next;
    let round = self.round;
    self.slots[index].free_next = None;
    self.slots[index].round = round;
    self.slots[index].state = SlotState::Waiting;
    self.slots[index].waker = Some(waker);
    self.arrivals += 1;
    Ok(WaiterKey {
      index,
      generation: self.slots[index].generation,
      round,
    })
  }

  fn valid(&self, key: WaiterKey) -> bool {
    self.slots.get(key.index).is_some_and(|slot| {
      slot.generation == key.generation && slot.round == key.round && slot.state != SlotState::Free
    })
  }

  fn recycle(&mut self, index: usize) -> Option<Waker> {
    let old = self.slots[index].waker.take();
    let slot = &mut self.slots[index];
    slot.free_next = None;
    if let Some(generation) = slot.generation.checked_add(1) {
      slot.generation = generation;
      slot.state = SlotState::Free;
      slot.free_next = self.free_head;
      self.free_head = Some(index);
    } else {
      slot.state = SlotState::Retired;
      if self
        .slots
        .iter()
        .filter(|entry| entry.state != SlotState::Retired)
        .count()
        < self.participants
      {
        self.closed = true;
        self.exhausted = true;
        self.arrivals = 0;
        for entry in &mut self.slots {
          if entry.state == SlotState::Waiting {
            entry.state = SlotState::Exhausted;
          }
        }
      }
    }
    old
  }
}

impl Drop for Ledger {
  fn drop(&mut self) {
    for slot in &mut self.slots {
      drop_waker(slot.waker.take());
    }
  }
}

enum PollAction {
  Pending(WaiterKey, Option<Waker>),
  Ready(Result<BarrierOutcome, BarrierError>, Option<Waker>),
  Immediate(Result<BarrierOutcome, BarrierError>),
}

fn poll_first(shared: &Arc<Shared>, new_waker: &mut Option<Waker>) -> PollAction {
  let Some(waker) = new_waker.take() else {
    return PollAction::Immediate(Err(BarrierError::WakerPanicked));
  };
  let (action, completed_round) = {
    let mut ledger = lock(&shared.ledger);
    if ledger.closed {
      let error = if ledger.exhausted {
        BarrierError::Exhausted
      } else {
        BarrierError::Closed
      };
      drop(ledger);
      drop_waker(Some(waker));
      return PollAction::Immediate(Err(error));
    } else {
      match ledger.allocate(waker) {
        Err(waker) => {
          drop(ledger);
          drop_waker(Some(waker));
          return PollAction::Immediate(Err(BarrierError::Full));
        }
        Ok(key) if ledger.arrivals == ledger.participants => {
          for (index, slot) in ledger.slots.iter_mut().enumerate() {
            if slot.round == key.round && slot.state == SlotState::Waiting {
              slot.state = SlotState::Success {
                leader: index == key.index,
              };
            }
          }
          ledger.arrivals = 0;
          if let Some(next_round) = ledger.round.checked_add(1) {
            ledger.round = next_round;
          } else {
            // This round did complete. Preserve its successes, then reject all
            // subsequent waits with an explicit exhausted result.
            ledger.closed = true;
            ledger.exhausted = true;
          }
          let old = ledger.recycle(key.index);
          (
            PollAction::Ready(
              Ok(BarrierOutcome {
                round: key.round,
                leader: true,
              }),
              old,
            ),
            true,
          )
        }
        Ok(key) => (PollAction::Pending(key, None), false),
      }
    }
  };
  drop_waker(new_waker.take());
  if completed_round {
    wake_terminal(shared);
  }
  action
}

fn poll_enrolled(
  shared: &Arc<Shared>,
  key: WaiterKey,
  new_waker: &mut Option<Waker>,
) -> PollAction {
  let mut replacement = new_waker.take();
  let (action, old, newly_exhausted) = {
    let mut ledger = lock(&shared.ledger);
    let was_exhausted = ledger.exhausted;
    let (action, old) = if !ledger.valid(key) {
      (PollAction::Immediate(Err(BarrierError::Exhausted)), None)
    } else {
      match ledger.slots[key.index].state {
        SlotState::Waiting => {
          let old = std::mem::replace(&mut ledger.slots[key.index].waker, replacement.take());
          (PollAction::Pending(key, None), old)
        }
        SlotState::Success { leader } => {
          let old = ledger.recycle(key.index);
          (
            PollAction::Ready(
              Ok(BarrierOutcome {
                round: key.round,
                leader,
              }),
              None,
            ),
            old,
          )
        }
        SlotState::Broken => {
          let old = ledger.recycle(key.index);
          (PollAction::Ready(Err(BarrierError::Broken), None), old)
        }
        SlotState::Closed => {
          let old = ledger.recycle(key.index);
          (PollAction::Ready(Err(BarrierError::Closed), None), old)
        }
        SlotState::Exhausted => {
          let old = ledger.recycle(key.index);
          (PollAction::Ready(Err(BarrierError::Exhausted), None), old)
        }
        SlotState::Free | SlotState::Retired => {
          (PollAction::Immediate(Err(BarrierError::Exhausted)), None)
        }
      }
    };
    (action, old, !was_exhausted && ledger.exhausted)
  };
  drop_waker(old);
  drop_waker(replacement);
  if newly_exhausted {
    wake_terminal(shared);
  }
  action
}

fn cancel_enrolled(shared: &Arc<Shared>, key: WaiterKey) {
  let (old, broke_round) = {
    let mut ledger = lock(&shared.ledger);
    if !ledger.valid(key) {
      return;
    }
    let unfinished = ledger.slots[key.index].state == SlotState::Waiting
      && ledger.round == key.round
      && !ledger.closed;
    if unfinished {
      let next_round = ledger.round.checked_add(1);
      for (index, slot) in ledger.slots.iter_mut().enumerate() {
        if slot.round == key.round && slot.state == SlotState::Waiting {
          slot.state = if index == key.index {
            SlotState::Free
          } else if next_round.is_some() {
            SlotState::Broken
          } else {
            SlotState::Exhausted
          };
        }
      }
      ledger.arrivals = 0;
      if let Some(next_round) = next_round {
        ledger.round = next_round;
      } else {
        ledger.closed = true;
        ledger.exhausted = true;
      }
      (ledger.recycle(key.index), true)
    } else {
      let was_exhausted = ledger.exhausted;
      let old = ledger.recycle(key.index);
      (old, !was_exhausted && ledger.exhausted)
    }
  };
  drop_waker(old);
  if broke_round {
    wake_terminal(shared);
  }
}

fn wake_terminal(shared: &Arc<Shared>) {
  // Take one waker at a time so the fixed table remains the only wake list.
  // A callback may reenter this barrier; all callbacks run after unlocking.
  loop {
    let waker = {
      let mut ledger = lock(&shared.ledger);
      ledger.slots.iter_mut().find_map(|slot| {
        if matches!(
          slot.state,
          SlotState::Success { .. } | SlotState::Broken | SlotState::Closed | SlotState::Exhausted
        ) {
          slot.waker.take()
        } else {
          None
        }
      })
    };
    let Some(waker) = waker else { return };
    wake_contained(Some(waker));
  }
}

fn wake_contained(waker: Option<Waker>) {
  if let Some(waker) = waker
    && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
  {
    drop_contained(payload);
  }
}

fn drop_waker(waker: Option<Waker>) {
  if let Some(waker) = waker {
    drop_contained(waker);
  }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;
  use std::task::Wake;
  use std::thread;
  use std::time::{Duration, Instant};

  struct ThreadWake(thread::Thread);
  impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
      self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
      self.0.unpark();
    }
  }

  fn waker() -> Waker {
    Waker::from(Arc::new(ThreadWake(thread::current())))
  }

  fn poll_once<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    let mut cx = Context::from_waker(waker);
    future.poll(&mut cx)
  }

  fn block_on<F: Future>(future: F) -> F::Output {
    let waker = waker();
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
      if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
        return value;
      }
      assert!(Instant::now() < deadline, "barrier wait exceeded deadline");
      thread::park_timeout(Duration::from_millis(10));
    }
  }

  struct PanicWake;
  impl Wake for PanicWake {
    fn wake(self: Arc<Self>) {
      panic!("intentional waker panic");
    }
    fn wake_by_ref(self: &Arc<Self>) {
      panic!("intentional waker panic");
    }
  }

  struct ReentrantWake(Barrier);
  impl Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
      self.0.close();
    }
    fn wake_by_ref(self: &Arc<Self>) {
      self.0.close();
    }
  }

  struct PanicPayload;
  impl Drop for PanicPayload {
    fn drop(&mut self) {
      panic!("intentional panic payload destructor panic");
    }
  }

  struct PayloadPanicWake;
  impl Wake for PayloadPanicWake {
    fn wake(self: Arc<Self>) {
      panic::panic_any(PanicPayload);
    }
  }

  #[test]
  fn panicking_wake_payload_destructor_cannot_lose_leader_result() {
    let barrier = Barrier::new(2, 2).unwrap();
    let mut first = Box::pin(barrier.wait());
    let payload_waker = Waker::from(Arc::new(PayloadPanicWake));
    assert!(poll_once(first.as_mut(), &payload_waker).is_pending());
    let mut last = Box::pin(barrier.wait());
    assert_eq!(
      poll_once(last.as_mut(), &waker()),
      Poll::Ready(Ok(BarrierOutcome {
        round: 0,
        leader: true
      }))
    );
    assert_eq!(
      poll_once(first.as_mut(), &waker()),
      Poll::Ready(Ok(BarrierOutcome {
        round: 0,
        leader: false
      }))
    );
  }

  #[test]
  fn partial_slot_retirement_exhausts_and_wakes_an_impossible_round() {
    struct CountingWake(std::sync::atomic::AtomicUsize);
    impl Wake for CountingWake {
      fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
      }
    }
    let barrier = Barrier::new(2, 2).unwrap();
    lock(&barrier.shared.ledger).slots[0].generation = u64::MAX;
    let wk = waker();
    let mut first = Box::pin(barrier.wait());
    assert!(poll_once(first.as_mut(), &wk).is_pending());
    assert!(poll_once(Box::pin(barrier.wait()).as_mut(), &wk).is_ready());
    let counter = Arc::new(CountingWake(std::sync::atomic::AtomicUsize::new(0)));
    let count_waker = Waker::from(Arc::clone(&counter));
    let mut next_round = Box::pin(barrier.wait());
    assert!(poll_once(next_round.as_mut(), &count_waker).is_pending());
    assert_eq!(
      poll_once(first.as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: 0,
        leader: false
      }))
    );
    assert!(barrier.is_closed());
    assert_eq!(counter.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
      poll_once(next_round.as_mut(), &wk),
      Poll::Ready(Err(BarrierError::Exhausted))
    );
    assert_eq!(
      poll_once(Box::pin(barrier.wait()).as_mut(), &wk),
      Poll::Ready(Err(BarrierError::Exhausted))
    );
  }

  #[test]
  fn rejects_invalid_bounds_and_first_poll_is_lazy() {
    assert_eq!(
      Barrier::new(0, 1).err(),
      Some(BarrierBuildError::ZeroParticipants)
    );
    assert_eq!(
      Barrier::new(1, 0).err(),
      Some(BarrierBuildError::ZeroCapacity)
    );
    assert_eq!(
      Barrier::new(3, 2).err(),
      Some(BarrierBuildError::CapacityTooSmall)
    );
    let barrier = Barrier::new(2, 2).unwrap();
    let _unpolled = barrier.wait();
    let mut first = Box::pin(barrier.wait());
    assert!(poll_once(first.as_mut(), &waker()).is_pending());
    assert_eq!(lock(&barrier.shared.ledger).arrivals, 1);
  }

  #[test]
  fn fixed_table_counts_unobserved_results_and_full_does_not_arrive() {
    let barrier = Barrier::new(2, 2).unwrap();
    let wk = waker();
    let mut a = Box::pin(barrier.wait());
    let mut b = Box::pin(barrier.wait());
    assert!(poll_once(a.as_mut(), &wk).is_pending());
    assert_eq!(
      poll_once(b.as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: 0,
        leader: true
      }))
    );
    let mut extra = Box::pin(barrier.wait());
    assert!(poll_once(extra.as_mut(), &wk).is_pending());
    let mut overflow = Box::pin(barrier.wait());
    assert_eq!(
      poll_once(overflow.as_mut(), &wk),
      Poll::Ready(Err(BarrierError::Full))
    );
    assert_eq!(lock(&barrier.shared.ledger).arrivals, 1);
    assert_eq!(
      poll_once(a.as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: 0,
        leader: false
      }))
    );
    let mut next = Box::pin(barrier.wait());
    assert_eq!(
      poll_once(next.as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: 1,
        leader: true
      }))
    );
  }

  #[test]
  fn multiple_rounds_have_exactly_one_leader() {
    let barrier = Barrier::new(3, 6).unwrap();
    for round in 0..5 {
      let (a, b, c) = (barrier.wait(), barrier.wait(), barrier.wait());
      let outcomes = thread::scope(|scope| {
        let a = scope.spawn(|| block_on(a));
        let b = scope.spawn(|| block_on(b));
        let c = scope.spawn(|| block_on(c));
        [
          a.join().unwrap().unwrap(),
          b.join().unwrap().unwrap(),
          c.join().unwrap().unwrap(),
        ]
      });
      assert!(outcomes.iter().all(|outcome| outcome.round == round));
      assert_eq!(outcomes.iter().filter(|outcome| outcome.leader).count(), 1);
    }
  }

  #[test]
  fn cancellation_breaks_unfinished_round_and_allows_recovery() {
    let barrier = Barrier::new(3, 4).unwrap();
    let wk = waker();
    let mut a = Box::pin(barrier.wait());
    let mut b = Box::pin(barrier.wait());
    assert!(poll_once(a.as_mut(), &wk).is_pending());
    assert!(poll_once(b.as_mut(), &wk).is_pending());
    drop(a);
    assert_eq!(
      poll_once(b.as_mut(), &wk),
      Poll::Ready(Err(BarrierError::Broken))
    );
    let (a, b, c) = (barrier.wait(), barrier.wait(), barrier.wait());
    let outcomes = thread::scope(|scope| {
      let a = scope.spawn(|| block_on(a));
      let b = scope.spawn(|| block_on(b));
      let c = scope.spawn(|| block_on(c));
      [
        a.join().unwrap().unwrap(),
        b.join().unwrap().unwrap(),
        c.join().unwrap().unwrap(),
      ]
    });
    assert!(outcomes.iter().all(|outcome| outcome.round == 1));
  }

  #[test]
  fn close_rejects_pending_waits_and_preserves_completed_success() {
    let barrier = Barrier::new(2, 4).unwrap();
    let wk = waker();
    let mut pending = Box::pin(barrier.wait());
    assert!(poll_once(pending.as_mut(), &wk).is_pending());
    barrier.close();
    assert_eq!(
      poll_once(pending.as_mut(), &wk),
      Poll::Ready(Err(BarrierError::Closed))
    );
    let mut after = Box::pin(barrier.wait());
    assert_eq!(
      poll_once(after.as_mut(), &wk),
      Poll::Ready(Err(BarrierError::Closed))
    );

    let barrier = Barrier::new(2, 2).unwrap();
    let mut a = Box::pin(barrier.wait());
    let mut b = Box::pin(barrier.wait());
    assert!(poll_once(a.as_mut(), &wk).is_pending());
    assert_eq!(
      poll_once(b.as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: 0,
        leader: true
      }))
    );
    barrier.close();
    assert_eq!(
      poll_once(a.as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: 0,
        leader: false
      }))
    );
  }

  #[test]
  fn stale_key_cannot_consume_reused_slot_result() {
    let barrier = Barrier::new(1, 1).unwrap();
    let wk = waker();
    assert_eq!(
      poll_once(Box::pin(barrier.wait()).as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: 0,
        leader: true
      }))
    );
    let stale = WaiterKey {
      index: 0,
      generation: 0,
      round: 0,
    };
    assert_eq!(
      poll_once(Box::pin(barrier.wait()).as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: 1,
        leader: true
      }))
    );
    let mut no_waker = None;
    assert!(matches!(
      poll_enrolled(&barrier.shared, stale, &mut no_waker),
      PollAction::Immediate(Err(BarrierError::Exhausted))
    ));
  }

  #[test]
  fn generation_and_round_exhaustion_are_explicit() {
    let barrier = Barrier::new(1, 1).unwrap();
    lock(&barrier.shared.ledger).slots[0].generation = u64::MAX;
    let wk = waker();
    assert_eq!(
      poll_once(Box::pin(barrier.wait()).as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: 0,
        leader: true
      }))
    );
    assert!(barrier.is_closed());
    assert_eq!(
      poll_once(Box::pin(barrier.wait()).as_mut(), &wk),
      Poll::Ready(Err(BarrierError::Exhausted))
    );

    let barrier = Barrier::new(1, 1).unwrap();
    lock(&barrier.shared.ledger).round = u64::MAX;
    assert_eq!(
      poll_once(Box::pin(barrier.wait()).as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: u64::MAX,
        leader: true
      }))
    );
    assert!(barrier.is_closed());
  }

  #[test]
  fn one_participant_completes_immediately_with_one_bounded_slot() {
    let barrier = Barrier::new(1, 1).unwrap();
    assert_eq!(barrier.max_waiters(), 1);
    let wk = waker();
    for round in 0..3 {
      assert_eq!(
        poll_once(Box::pin(barrier.wait()).as_mut(), &wk),
        Poll::Ready(Ok(BarrierOutcome {
          round,
          leader: true
        }))
      );
      let ledger = lock(&barrier.shared.ledger);
      assert_eq!(ledger.arrivals, 0);
      assert_eq!(ledger.free_head, Some(0));
      assert_eq!(ledger.slots.len(), 1);
    }
  }

  #[test]
  fn panic_and_reentrant_wakers_are_contained() {
    let barrier = Barrier::new(2, 2).unwrap();
    let panic_waker = Waker::from(Arc::new(PanicWake));
    let wk = waker();
    let mut a = Box::pin(barrier.wait());
    let mut b = Box::pin(barrier.wait());
    assert!(poll_once(a.as_mut(), &panic_waker).is_pending());
    assert_eq!(
      poll_once(b.as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: 0,
        leader: true
      }))
    );
    assert_eq!(
      poll_once(a.as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: 0,
        leader: false
      }))
    );

    let barrier = Barrier::new(2, 2).unwrap();
    let reentrant = Waker::from(Arc::new(ReentrantWake(barrier.clone())));
    let mut a = Box::pin(barrier.wait());
    let mut b = Box::pin(barrier.wait());
    assert!(poll_once(a.as_mut(), &reentrant).is_pending());
    assert_eq!(
      poll_once(b.as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: 0,
        leader: true
      }))
    );
    assert_eq!(
      poll_once(a.as_mut(), &wk),
      Poll::Ready(Ok(BarrierOutcome {
        round: 0,
        leader: false
      }))
    );
    assert!(barrier.is_closed());
  }

  #[test]
  fn concurrent_round_completes_before_deadline() {
    let barrier = Barrier::new(8, 16).unwrap();
    thread::scope(|scope| {
      let threads: Vec<_> = (0..8)
        .map(|_| {
          let barrier = barrier.clone();
          scope.spawn(move || block_on(barrier.wait()))
        })
        .collect();
      let outcomes: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap().unwrap())
        .collect();
      assert_eq!(outcomes.iter().filter(|outcome| outcome.leader).count(), 1);
    });
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use super::*;
  use loom::sync::Arc as LoomArc;
  use loom::thread;
  use std::sync::Arc as StdArc;
  use std::task::Wake;

  struct NoopWake;
  impl Wake for NoopWake {
    fn wake(self: StdArc<Self>) {}
    fn wake_by_ref(self: &StdArc<Self>) {}
  }

  fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = Waker::from(StdArc::new(NoopWake));
    let mut cx = Context::from_waker(&waker);
    future.poll(&mut cx)
  }

  #[test]
  fn cancellation_racing_last_arrival_keeps_epochs_separate() {
    loom::model(|| {
      let barrier = Barrier::new(2, 4).unwrap();
      let mut cancelled = Box::pin(barrier.wait());
      assert!(poll_once(cancelled.as_mut()).is_pending());
      let arriving = barrier.wait();
      let barrier_after_race = barrier.clone();
      let cancel_thread = thread::spawn(move || drop(cancelled));
      let arrive_thread = thread::spawn(move || {
        let mut arriving = Box::pin(arriving);
        let result = poll_once(arriving.as_mut());
        (arriving, result)
      });
      cancel_thread.join().unwrap();
      let (mut arriving, arrival_result) = arrive_thread.join().unwrap();
      match arrival_result {
        Poll::Ready(Ok(outcome)) => assert_eq!(outcome.round, 0),
        Poll::Pending => {
          let mut replacement = Box::pin(barrier_after_race.wait());
          assert!(poll_once(replacement.as_mut()).is_ready());
          assert!(matches!(
            poll_once(arriving.as_mut()),
            Poll::Ready(Ok(BarrierOutcome { round: 1, .. }))
          ));
        }
        Poll::Ready(Err(error)) => panic!("unexpected arrival outcome: {error:?}"),
      }
    });
  }

  #[test]
  fn close_racing_success_preserves_completed_round() {
    loom::model(|| {
      let barrier = Barrier::new(2, 2).unwrap();
      let mut waiting = Box::pin(barrier.wait());
      assert!(poll_once(waiting.as_mut()).is_pending());
      let arriving = barrier.wait();
      let close_barrier = barrier.clone();
      let close_thread = thread::spawn(move || close_barrier.close());
      let arrive_thread = thread::spawn(move || {
        let mut arriving = Box::pin(arriving);
        poll_once(arriving.as_mut())
      });
      close_thread.join().unwrap();
      match arrive_thread.join().unwrap() {
        Poll::Ready(Ok(outcome)) => {
          assert_eq!(outcome.round, 0);
          assert!(matches!(poll_once(waiting.as_mut()), Poll::Ready(Ok(_))));
        }
        Poll::Ready(Err(BarrierError::Closed)) => {
          assert_eq!(
            poll_once(waiting.as_mut()),
            Poll::Ready(Err(BarrierError::Closed))
          );
        }
        other => panic!("unexpected result racing close: {other:?}"),
      }
    });
  }

  #[test]
  fn three_concurrent_arrivals_publish_one_leader() {
    loom::model(|| {
      let barrier = Barrier::new(3, 3).unwrap();
      let futures = LoomArc::new(Mutex::new(Vec::new()));
      let mut threads = Vec::new();
      for _ in 0..3 {
        let barrier = barrier.clone();
        let futures = LoomArc::clone(&futures);
        threads.push(thread::spawn(move || {
          let mut future = Box::pin(barrier.wait());
          let result = poll_once(future.as_mut());
          futures.lock().unwrap().push((future, result));
        }));
      }
      for thread in threads {
        thread.join().unwrap();
      }
      let mut futures = futures.lock().unwrap();
      assert_eq!(futures.len(), 3);
      let mut successes = Vec::new();
      for (future, result) in futures.iter_mut() {
        match result {
          Poll::Ready(result) => successes.push(result.unwrap()),
          Poll::Pending => match poll_once(future.as_mut()) {
            Poll::Ready(Ok(outcome)) => successes.push(outcome),
            other => panic!("unexpected pending future state: {other:?}"),
          },
        }
      }
      assert_eq!(successes.len(), 3);
      assert_eq!(successes.iter().filter(|outcome| outcome.leader).count(), 1);
    });
  }
}
