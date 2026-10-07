//! A bounded, FIFO notification primitive for the optional blocking runtime.
//!
//! The waiter table is allocated once by [`Notify::new`]. Registered futures
//! occupy a slot until they observe a notification or are dropped. A slot
//! generation is advanced on reuse and a slot is retired rather than wrapping.
//! A `notify_one` with no waiter stores one coalescing permit. Broadcasts use a
//! checked generation so futures created before a broadcast are eligible even
//! when they have not yet been polled.

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

use super::task::drop_contained;

/// A bounded notification source with FIFO waiter assignment.
pub struct Notify {
  shared: Arc<Shared>,
}

struct Shared {
  ledger: Mutex<Ledger>,
}

/// An owned future waiting for a notification.
///
/// `enable` registers the future before returning, allowing a caller to check
/// its own condition without losing a concurrent `notify_one`.
#[must_use = "futures do nothing unless polled"]
pub struct OwnedNotifiedFuture {
  shared: Arc<Shared>,
  broadcast_generation: u64,
  waiter: Option<WaiterKey>,
  outcome: Option<Result<(), NotifyError>>,
}

/// Why a notification operation could not complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotifyError {
  /// The bounded waiter table has no free slot.
  Full,
  /// The notification source has closed.
  Closed,
  /// The broadcast generation reached its checked limit and closed the source.
  GenerationExhausted,
}

impl fmt::Display for NotifyError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Full => "notification waiter table is full",
      Self::Closed => "notification source is closed",
      Self::GenerationExhausted => "notification broadcast generation is exhausted",
    })
  }
}

impl std::error::Error for NotifyError {}

/// Why notification construction failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotifyBuildError {
  /// The waiter table size overflowed or could not be represented.
  CapacityOverflow,
  /// The preallocated waiter table could not be reserved.
  AllocationFailed,
}

impl fmt::Display for NotifyBuildError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::CapacityOverflow => "notification waiter capacity overflowed",
      Self::AllocationFailed => "notification waiter table allocation failed",
    })
  }
}

impl std::error::Error for NotifyBuildError {}

impl Notify {
  /// Creates a notification source with at most `max_waiters` registered
  /// futures. The complete fixed waiter table is reserved before construction.
  pub fn new(max_waiters: usize) -> Result<Self, NotifyBuildError> {
    let table_bytes = max_waiters
      .checked_mul(std::mem::size_of::<WaiterSlot>())
      .ok_or(NotifyBuildError::CapacityOverflow)?;
    if table_bytes > isize::MAX as usize {
      return Err(NotifyBuildError::CapacityOverflow);
    }

    let mut slots = Vec::new();
    slots
      .try_reserve_exact(max_waiters)
      .map_err(|_| NotifyBuildError::AllocationFailed)?;
    for index in 0..max_waiters {
      slots.push(WaiterSlot {
        generation: 0,
        state: SlotState::Free,
        free_next: index.checked_add(1).filter(|next| *next < max_waiters),
        previous: None,
        next: None,
        waker: None,
      });
    }

    Ok(Self {
      shared: Arc::new(Shared {
        ledger: Mutex::new(Ledger {
          closed: false,
          permit: false,
          broadcast_generation: 0,
          wait_head: None,
          wait_tail: None,
          free_head: (max_waiters > 0).then_some(0),
          slots,
        }),
      }),
    })
  }

  /// Creates an owned future that records the current broadcast generation.
  ///
  /// A later [`notify_waiters`](Self::notify_waiters) completes this future
  /// even if it is not polled until after that broadcast.
  pub fn notified(&self) -> OwnedNotifiedFuture {
    OwnedNotifiedFuture::new(Arc::clone(&self.shared))
  }

  /// Creates an owned future from a notification handle.
  pub fn notified_owned(&self) -> OwnedNotifiedFuture {
    OwnedNotifiedFuture::new(Arc::clone(&self.shared))
  }

  /// Notifies the oldest registered future, or stores one permit if none is
  /// registered. Repeated unused calls coalesce into one permit.
  pub fn notify_one(&self) -> Result<(), NotifyError> {
    self.notify_with_order(NotifyOrder::Fifo)
  }

  /// Notifies the newest registered future, or stores one permit if none is
  /// registered. Repeated unused calls coalesce into one permit.
  pub fn notify_last(&self) -> Result<(), NotifyError> {
    self.notify_with_order(NotifyOrder::Lifo)
  }

  fn notify_with_order(&self, order: NotifyOrder) -> Result<(), NotifyError> {
    let waker = {
      let mut ledger = lock(&self.shared.ledger);
      if ledger.closed {
        return Err(NotifyError::Closed);
      }
      let index = if order == NotifyOrder::Lifo {
        ledger.wait_tail
      } else {
        ledger.wait_head
      };
      let Some(index) = index else {
        ledger.permit = true;
        return Ok(());
      };
      ledger.unlink_waiter(index);
      let slot = &mut ledger.slots[index];
      slot.state = SlotState::Granted { order };
      slot.waker.take()
    };
    wake_contained(waker);
    Ok(())
  }

  /// Broadcasts to all futures created before this call and all currently
  /// registered futures. Broadcasts do not create a persistent permit.
  ///
  /// If the checked generation is exhausted, the source closes and registered
  /// waiters are woken. Futures already eligible from an earlier broadcast
  /// retain that success; other unfinished futures resolve with
  /// [`NotifyError::Closed`] when polled.
  pub fn notify_waiters(&self) -> Result<(), NotifyError> {
    let exhausted = {
      let mut ledger = lock(&self.shared.ledger);
      if ledger.closed {
        return Err(NotifyError::Closed);
      }
      match ledger.broadcast_generation.checked_add(1) {
        Some(generation) => {
          ledger.broadcast_generation = generation;
          while let Some(index) = ledger.wait_head {
            ledger.unlink_waiter(index);
            ledger.slots[index].state = SlotState::Broadcasted;
          }
          false
        }
        None => {
          ledger.closed = true;
          true
        }
      }
    };

    if exhausted {
      self.close_slots();
      return Err(NotifyError::GenerationExhausted);
    }

    // Broadcasted slots retain their waiter metadata until observed or
    // cancelled. Taking each waker separately avoids allocating a wake list.
    let capacity = lock(&self.shared.ledger).slots.len();
    for index in 0..capacity {
      let waker = {
        let mut ledger = lock(&self.shared.ledger);
        if ledger.slots[index].state == SlotState::Broadcasted {
          ledger.slots[index].waker.take()
        } else {
          None
        }
      };
      wake_contained(waker);
    }
    Ok(())
  }

  /// Closes the source and wakes all registered futures. An observed
  /// notification remains successful; queued or granted but unobserved
  /// `notify_one` assignments complete with [`NotifyError::Closed`].
  pub fn close(&self) {
    self.close_slots();
  }

  fn close_slots(&self) {
    {
      let mut ledger = lock(&self.shared.ledger);
      ledger.closed = true;
      ledger.permit = false;
    }

    // Free slots before running each custom waker. The closed bit is already
    // visible, so races with poll observe closure even before this sweep.
    let capacity = lock(&self.shared.ledger).slots.len();
    for index in 0..capacity {
      let waker = {
        let mut ledger = lock(&self.shared.ledger);
        match ledger.slots[index].state {
          SlotState::Free | SlotState::Retired => None,
          SlotState::Waiting => {
            ledger.unlink_waiter(index);
            ledger.recycle_slot(index)
          }
          SlotState::Granted { .. } | SlotState::Broadcasted => ledger.recycle_slot(index),
        }
      };
      wake_contained(waker);
    }
  }

  /// Returns whether the source is closed.
  #[must_use]
  pub fn is_closed(&self) -> bool {
    lock(&self.shared.ledger).closed
  }

  /// Returns the configured bound on registered and assigned futures.
  #[must_use]
  pub fn max_waiters(&self) -> usize {
    lock(&self.shared.ledger).slots.len()
  }
}

impl Clone for Notify {
  fn clone(&self) -> Self {
    Self {
      shared: Arc::clone(&self.shared),
    }
  }
}

impl OwnedNotifiedFuture {
  fn new(shared: Arc<Shared>) -> Self {
    let broadcast_generation = lock(&shared.ledger).broadcast_generation;
    Self {
      shared,
      broadcast_generation,
      waiter: None,
      outcome: None,
    }
  }

  /// Registers this future before the caller checks its condition.
  ///
  /// Returns `true` if a notification is already available, and propagates
  /// table exhaustion or closure as a typed error.
  pub fn enable(self: Pin<&mut Self>) -> Result<bool, NotifyError> {
    let this = self.get_mut();
    if let Some(outcome) = this.outcome {
      return outcome.map(|()| true);
    }
    match poll_inner(this, None) {
      Poll::Ready(Ok(())) => Ok(true),
      Poll::Ready(Err(error)) => Err(error),
      Poll::Pending => Ok(false),
    }
  }
}

impl Future for OwnedNotifiedFuture {
  type Output = Result<(), NotifyError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if let Some(outcome) = this.outcome {
      return Poll::Ready(outcome);
    }
    // RawWaker clone code is user code. Do it before acquiring the state lock.
    let mut waker = Some(cx.waker().clone());
    let result = poll_inner(this, Some(&mut waker));
    if result.is_ready() {
      drop_waker(waker.take());
    }
    result
  }
}

impl Drop for OwnedNotifiedFuture {
  fn drop(&mut self) {
    if let Some(key) = self.waiter.take() {
      cancel_waiter(&self.shared, key);
    }
  }
}

impl fmt::Debug for Notify {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let (closed, permit, broadcast_generation, max_waiters) = {
      let ledger = lock(&self.shared.ledger);
      (
        ledger.closed,
        ledger.permit,
        ledger.broadcast_generation,
        ledger.slots.len(),
      )
    };
    f.debug_struct("Notify")
      .field("closed", &closed)
      .field("permit", &permit)
      .field("broadcast_generation", &broadcast_generation)
      .field("max_waiters", &max_waiters)
      .finish()
  }
}

impl fmt::Debug for OwnedNotifiedFuture {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("OwnedNotifiedFuture")
      .field("waiting", &self.waiter.is_some())
      .field("outcome", &self.outcome)
      .finish()
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WaiterKey {
  index: usize,
  generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
  Free,
  Waiting,
  Granted { order: NotifyOrder },
  Broadcasted,
  Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NotifyOrder {
  Fifo,
  Lifo,
}

struct WaiterSlot {
  generation: u64,
  state: SlotState,
  free_next: Option<usize>,
  previous: Option<usize>,
  next: Option<usize>,
  waker: Option<Waker>,
}

struct Ledger {
  closed: bool,
  permit: bool,
  broadcast_generation: u64,
  wait_head: Option<usize>,
  wait_tail: Option<usize>,
  free_head: Option<usize>,
  slots: Vec<WaiterSlot>,
}

impl Ledger {
  fn allocate_waiter(&mut self, waker: Option<Waker>) -> Result<WaiterKey, Option<Waker>> {
    let Some(index) = self.free_head else {
      return Err(waker);
    };
    let slot = &mut self.slots[index];
    if slot.state != SlotState::Free {
      return Err(waker);
    }
    self.free_head = slot.free_next;
    slot.free_next = None;
    slot.state = SlotState::Waiting;
    slot.waker = waker;
    let key = WaiterKey {
      index,
      generation: slot.generation,
    };
    self.link_waiter(index);
    Ok(key)
  }

  fn valid_state(&self, key: WaiterKey) -> Option<SlotState> {
    let slot = self.slots.get(key.index)?;
    (slot.generation == key.generation).then_some(slot.state)
  }

  fn link_waiter(&mut self, index: usize) {
    let previous = self.wait_tail;
    self.slots[index].previous = previous;
    self.slots[index].next = None;
    if let Some(previous) = previous {
      self.slots[previous].next = Some(index);
    } else {
      self.wait_head = Some(index);
    }
    self.wait_tail = Some(index);
  }

  fn unlink_waiter(&mut self, index: usize) {
    let previous = self.slots[index].previous;
    let next = self.slots[index].next;
    if let Some(previous) = previous {
      self.slots[previous].next = next;
    } else {
      self.wait_head = next;
    }
    if let Some(next) = next {
      self.slots[next].previous = previous;
    } else {
      self.wait_tail = previous;
    }
    self.slots[index].previous = None;
    self.slots[index].next = None;
  }

  fn recycle_slot(&mut self, index: usize) -> Option<Waker> {
    let waker = self.slots[index].waker.take();
    let slot = &mut self.slots[index];
    slot.previous = None;
    slot.next = None;
    slot.free_next = None;
    if let Some(generation) = slot.generation.checked_add(1) {
      slot.generation = generation;
      slot.state = SlotState::Free;
      slot.free_next = self.free_head;
      self.free_head = Some(index);
    } else {
      slot.state = SlotState::Retired;
    }
    waker
  }
}

impl Drop for Ledger {
  fn drop(&mut self) {
    for slot in &mut self.slots {
      drop_waker(slot.waker.take());
    }
  }
}

fn poll_inner(
  future: &mut OwnedNotifiedFuture,
  waker: Option<&mut Option<Waker>>,
) -> Poll<Result<(), NotifyError>> {
  let mut ledger = lock(&future.shared.ledger);

  // A broadcast to an unpolled future is issued at the broadcast itself.
  // Check it before closure so a later close cannot retract that result.
  let state = future.waiter.and_then(|key| ledger.valid_state(key));
  if state == Some(SlotState::Broadcasted)
    || ledger.broadcast_generation != future.broadcast_generation
  {
    let old = future.waiter.take().and_then(|key| {
      if ledger.valid_state(key).is_some() {
        if ledger.slots[key.index].state == SlotState::Waiting {
          ledger.unlink_waiter(key.index);
        }
        ledger.recycle_slot(key.index)
      } else {
        None
      }
    });
    drop(ledger);
    drop_waker(old);
    future.outcome = Some(Ok(()));
    return Poll::Ready(Ok(()));
  }

  if ledger.closed {
    let old = future.waiter.take().and_then(|key| {
      if ledger.valid_state(key).is_some() {
        if ledger.slots[key.index].state == SlotState::Waiting {
          ledger.unlink_waiter(key.index);
        }
        ledger.recycle_slot(key.index)
      } else {
        None
      }
    });
    drop(ledger);
    drop_waker(old);
    future.outcome = Some(Err(NotifyError::Closed));
    return Poll::Ready(Err(NotifyError::Closed));
  }

  if let Some(key) = future.waiter {
    match ledger.valid_state(key) {
      Some(SlotState::Granted { .. }) => {
        let old = ledger.recycle_slot(key.index);
        future.waiter = None;
        drop(ledger);
        drop_waker(old);
        future.outcome = Some(Ok(()));
        return Poll::Ready(Ok(()));
      }
      Some(SlotState::Waiting) => {
        let old = if let Some(new_waker) = waker.and_then(Option::take) {
          ledger.slots[key.index].waker.replace(new_waker)
        } else {
          None
        };
        drop(ledger);
        drop_waker(old);
        return Poll::Pending;
      }
      Some(SlotState::Broadcasted) => unreachable!("broadcast state handled above"),
      Some(SlotState::Free | SlotState::Retired) | None => {
        future.waiter = None;
      }
    }
  }

  if ledger.permit {
    ledger.permit = false;
    drop(ledger);
    future.outcome = Some(Ok(()));
    return Poll::Ready(Ok(()));
  }

  let replacement = waker.and_then(Option::take);
  match ledger.allocate_waiter(replacement) {
    Ok(key) => {
      future.waiter = Some(key);
      drop(ledger);
      Poll::Pending
    }
    Err(unused) => {
      drop(ledger);
      drop_waker(unused);
      future.outcome = Some(Err(NotifyError::Full));
      Poll::Ready(Err(NotifyError::Full))
    }
  }
}

fn cancel_waiter(shared: &Arc<Shared>, key: WaiterKey) {
  let (old_waker, wake) = {
    let mut ledger = lock(&shared.ledger);
    let Some(state) = ledger.valid_state(key) else {
      return;
    };
    if ledger.closed {
      if state == SlotState::Waiting {
        ledger.unlink_waiter(key.index);
      }
      let old_waker = ledger.recycle_slot(key.index);
      (old_waker, None)
    } else {
      let mut wake = None;
      match state {
        SlotState::Waiting => {
          ledger.unlink_waiter(key.index);
        }
        SlotState::Granted { order } => {
          let next = match order {
            NotifyOrder::Fifo => ledger.wait_head,
            NotifyOrder::Lifo => ledger.wait_tail,
          };
          if let Some(next) = next {
            ledger.unlink_waiter(next);
            ledger.slots[next].state = SlotState::Granted { order };
            wake = ledger.slots[next].waker.take();
          } else {
            ledger.permit = true;
          }
        }
        SlotState::Broadcasted => {}
        SlotState::Free | SlotState::Retired => return,
      }
      let own_waker = ledger.recycle_slot(key.index);
      (own_waker, wake)
    }
  };
  drop_waker(old_waker);
  wake_contained(wake);
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
  use std::future::Future;
  use std::pin::Pin;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::{Arc, Mutex};
  use std::task::{Context, Wake, Waker};

  use super::{Notify, NotifyError, OwnedNotifiedFuture};

  fn poll(future: Pin<&mut OwnedNotifiedFuture>, waker: &Waker) -> PollResult {
    let mut context = Context::from_waker(waker);
    match future.poll(&mut context) {
      std::task::Poll::Ready(result) => PollResult::Ready(result),
      std::task::Poll::Pending => PollResult::Pending,
    }
  }

  #[derive(Debug, PartialEq, Eq)]
  enum PollResult {
    Ready(Result<(), NotifyError>),
    Pending,
  }

  fn noop_waker() -> Waker {
    (*Waker::noop()).clone()
  }

  #[test]
  fn coalesces_unused_one_notifications() {
    let notify = Arc::new(Notify::new(2).unwrap());
    notify.notify_one().unwrap();
    notify.notify_one().unwrap();
    let waker = noop_waker();
    let mut first = Box::pin(notify.notified());
    let mut second = Box::pin(notify.notified());
    assert_eq!(poll(first.as_mut(), &waker), PollResult::Ready(Ok(())));
    assert_eq!(poll(second.as_mut(), &waker), PollResult::Pending);
  }

  #[test]
  fn previous_broadcast_does_not_consume_a_later_single_permit() {
    let notify = Arc::new(Notify::new(2).unwrap());
    let mut broadcast_eligible = Box::pin(notify.notified());
    notify.notify_waiters().unwrap();
    notify.notify_one().unwrap();
    let mut later = Box::pin(notify.notified());
    let waker = noop_waker();

    assert_eq!(
      poll(broadcast_eligible.as_mut(), &waker),
      PollResult::Ready(Ok(()))
    );
    assert_eq!(poll(later.as_mut(), &waker), PollResult::Ready(Ok(())));
  }

  #[test]
  fn assigns_fifo_and_notify_last_selects_tail() {
    let notify = Arc::new(Notify::new(3).unwrap());
    let waker = noop_waker();
    let mut first = Box::pin(notify.notified());
    let mut second = Box::pin(notify.notified());
    let mut last = Box::pin(notify.notified());
    assert_eq!(poll(first.as_mut(), &waker), PollResult::Pending);
    assert_eq!(poll(second.as_mut(), &waker), PollResult::Pending);
    assert_eq!(poll(last.as_mut(), &waker), PollResult::Pending);
    notify.notify_last().unwrap();
    assert_eq!(poll(last.as_mut(), &waker), PollResult::Ready(Ok(())));
    notify.notify_one().unwrap();
    assert_eq!(poll(first.as_mut(), &waker), PollResult::Ready(Ok(())));
    assert_eq!(poll(second.as_mut(), &waker), PollResult::Pending);
  }

  #[test]
  fn cancelling_notify_last_grant_hands_it_to_newest_remaining_waiter() {
    let notify = Arc::new(Notify::new(3).unwrap());
    let waker = noop_waker();
    let mut first = Box::pin(notify.notified());
    let mut second = Box::pin(notify.notified());
    let mut last = Box::pin(notify.notified());
    assert_eq!(poll(first.as_mut(), &waker), PollResult::Pending);
    assert_eq!(poll(second.as_mut(), &waker), PollResult::Pending);
    assert_eq!(poll(last.as_mut(), &waker), PollResult::Pending);

    notify.notify_last().unwrap();
    drop(last);
    assert_eq!(poll(second.as_mut(), &waker), PollResult::Ready(Ok(())));
    assert_eq!(poll(first.as_mut(), &waker), PollResult::Pending);
  }

  #[test]
  fn cancellation_hands_grant_to_next_waiter_or_stores_one_permit() {
    let notify = Arc::new(Notify::new(2).unwrap());
    let waker = noop_waker();
    let mut first = Box::pin(notify.notified());
    let mut second = Box::pin(notify.notified());
    assert_eq!(poll(first.as_mut(), &waker), PollResult::Pending);
    assert_eq!(poll(second.as_mut(), &waker), PollResult::Pending);
    notify.notify_one().unwrap();
    drop(first);
    assert_eq!(poll(second.as_mut(), &waker), PollResult::Ready(Ok(())));

    let mut third = Box::pin(notify.notified());
    assert_eq!(poll(third.as_mut(), &waker), PollResult::Pending);
    notify.notify_one().unwrap();
    drop(third);
    let mut fourth = Box::pin(notify.notified());
    assert_eq!(poll(fourth.as_mut(), &waker), PollResult::Ready(Ok(())));
  }

  #[test]
  fn broadcast_reaches_unpolled_preexisting_future_without_permit() {
    let notify = Arc::new(Notify::new(1).unwrap());
    let mut before = Box::pin(notify.notified());
    notify.notify_waiters().unwrap();
    let waker = noop_waker();
    assert_eq!(poll(before.as_mut(), &waker), PollResult::Ready(Ok(())));

    let mut after = Box::pin(notify.notified());
    assert_eq!(poll(after.as_mut(), &waker), PollResult::Pending);
  }

  #[test]
  fn enable_registers_before_external_condition_check() {
    let notify = Arc::new(Notify::new(1).unwrap());
    let mut future = Box::pin(notify.notified());
    assert!(!future.as_mut().enable().unwrap());
    notify.notify_one().unwrap();
    let waker = noop_waker();
    assert_eq!(poll(future.as_mut(), &waker), PollResult::Ready(Ok(())));
  }

  #[test]
  fn close_rejects_queued_and_unobserved_grant_but_preserves_observed() {
    let notify = Arc::new(Notify::new(2).unwrap());
    let waker = noop_waker();
    let mut queued = Box::pin(notify.notified());
    assert_eq!(poll(queued.as_mut(), &waker), PollResult::Pending);
    notify.close();
    assert_eq!(
      poll(queued.as_mut(), &waker),
      PollResult::Ready(Err(NotifyError::Closed))
    );

    let notify = Arc::new(Notify::new(1).unwrap());
    let mut assigned = Box::pin(notify.notified());
    assert_eq!(poll(assigned.as_mut(), &waker), PollResult::Pending);
    notify.notify_one().unwrap();
    notify.close();
    assert_eq!(
      poll(assigned.as_mut(), &waker),
      PollResult::Ready(Err(NotifyError::Closed))
    );

    let notify = Arc::new(Notify::new(1).unwrap());
    let mut observed = Box::pin(notify.notified());
    notify.notify_one().unwrap();
    assert_eq!(poll(observed.as_mut(), &waker), PollResult::Ready(Ok(())));
    notify.close();
    assert_eq!(poll(observed.as_mut(), &waker), PollResult::Ready(Ok(())));

    let notify = Arc::new(Notify::new(1).unwrap());
    let mut broadcasted = Box::pin(notify.notified());
    assert_eq!(poll(broadcasted.as_mut(), &waker), PollResult::Pending);
    notify.notify_waiters().unwrap();
    notify.close();
    assert_eq!(
      poll(broadcasted.as_mut(), &waker),
      PollResult::Ready(Ok(()))
    );

    let notify = Arc::new(Notify::new(1).unwrap());
    let mut unpolled_broadcast = Box::pin(notify.notified());
    notify.notify_waiters().unwrap();
    notify.close();
    assert_eq!(
      poll(unpolled_broadcast.as_mut(), &waker),
      PollResult::Ready(Ok(()))
    );
  }

  #[test]
  fn cancellation_after_close_does_not_restore_a_permit_or_grant() {
    let notify = Arc::new(Notify::new(2).unwrap());
    let waker = noop_waker();
    let mut first = Box::pin(notify.notified());
    let mut second = Box::pin(notify.notified());
    assert_eq!(poll(first.as_mut(), &waker), PollResult::Pending);
    assert_eq!(poll(second.as_mut(), &waker), PollResult::Pending);
    notify.notify_one().unwrap();
    notify.close();
    drop(first);

    let ledger = super::lock(&notify.shared.ledger);
    assert!(!ledger.permit);
    assert!(ledger.wait_head.is_none());
    assert!(
      ledger
        .slots
        .iter()
        .all(|slot| !matches!(slot.state, super::SlotState::Granted { .. }))
    );
    drop(ledger);
    assert_eq!(
      poll(second.as_mut(), &waker),
      PollResult::Ready(Err(NotifyError::Closed))
    );
  }

  #[test]
  fn debug_formatting_runs_after_releasing_the_ledger_lock() {
    struct ReentrantWriter {
      notify: Arc<Notify>,
      lock_was_available: bool,
      closed_after_reentry: bool,
      close_calls: usize,
    }

    impl std::fmt::Write for ReentrantWriter {
      fn write_str(&mut self, _: &str) -> std::fmt::Result {
        self.lock_was_available = match self.notify.shared.ledger.try_lock() {
          Ok(guard) => {
            drop(guard);
            true
          }
          Err(std::sync::TryLockError::Poisoned(error)) => {
            drop(error.into_inner());
            true
          }
          Err(std::sync::TryLockError::WouldBlock) => false,
        };
        if self.lock_was_available && self.close_calls == 0 {
          self.notify.close();
          self.close_calls += 1;
          self.closed_after_reentry = self.notify.is_closed();
        }
        Ok(())
      }
    }

    let notify = Arc::new(Notify::new(0).unwrap());
    let mut writer = ReentrantWriter {
      notify: Arc::clone(&notify),
      lock_was_available: false,
      closed_after_reentry: false,
      close_calls: 0,
    };
    assert!(std::fmt::write(&mut writer, format_args!("{notify:?}")).is_ok());
    assert!(writer.lock_was_available);
    assert!(writer.closed_after_reentry);
    assert_eq!(writer.close_calls, 1);
  }

  #[test]
  fn freed_slots_are_reused_with_a_new_generation() {
    let notify = Arc::new(Notify::new(1).unwrap());
    let waker = noop_waker();
    let mut first = Box::pin(notify.notified());
    assert_eq!(poll(first.as_mut(), &waker), PollResult::Pending);
    drop(first);
    let mut second = Box::pin(notify.notified());
    assert_eq!(poll(second.as_mut(), &waker), PollResult::Pending);
    notify.notify_one().unwrap();
    assert_eq!(poll(second.as_mut(), &waker), PollResult::Ready(Ok(())));
  }

  struct PanicWake;

  impl Wake for PanicWake {
    fn wake(self: Arc<Self>) {
      panic!("intentional test waker panic");
    }
  }

  #[test]
  fn panicking_waker_does_not_poison_or_hold_the_state_lock() {
    let notify = Arc::new(Notify::new(1).unwrap());
    let mut future = Box::pin(notify.notified());
    let waker = Waker::from(Arc::new(PanicWake));
    assert_eq!(poll(future.as_mut(), &waker), PollResult::Pending);
    notify.notify_one().unwrap();
    assert_eq!(
      poll(future.as_mut(), &noop_waker()),
      PollResult::Ready(Ok(()))
    );
    assert!(notify.notify_waiters().is_ok());
  }

  struct ReentrantWake(Arc<Notify>, Arc<AtomicUsize>);

  impl Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
      let closed = self.0.is_closed();
      if closed {
        self.1.fetch_add(1, Ordering::SeqCst);
      }
    }
  }

  #[test]
  fn close_runs_reentrant_wakers_after_releasing_state_lock() {
    let notify = Arc::new(Notify::new(1).unwrap());
    let woke = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(ReentrantWake(
      Arc::clone(&notify),
      Arc::clone(&woke),
    )));
    let mut future = Box::pin(notify.notified());
    assert_eq!(poll(future.as_mut(), &waker), PollResult::Pending);
    notify.close();
    assert_eq!(woke.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn table_full_is_typed_and_close_is_observable() {
    let notify = Arc::new(Notify::new(1).unwrap());
    let waker = noop_waker();
    let mut first = Box::pin(notify.notified());
    let mut second = Box::pin(notify.notified());
    assert_eq!(poll(first.as_mut(), &waker), PollResult::Pending);
    assert_eq!(
      poll(second.as_mut(), &waker),
      PollResult::Ready(Err(NotifyError::Full))
    );
    notify.close();
    assert!(notify.is_closed());
  }

  #[test]
  fn slot_generation_retires_instead_of_wrapping() {
    let notify = Arc::new(Notify::new(1).unwrap());
    {
      let mut ledger = super::lock(&notify.shared.ledger);
      ledger.slots[0].generation = u64::MAX;
      ledger.slots[0].state = super::SlotState::Waiting;
      ledger.free_head = None;
      ledger.wait_head = Some(0);
      ledger.wait_tail = Some(0);
    }
    let key = super::WaiterKey {
      index: 0,
      generation: u64::MAX,
    };
    super::cancel_waiter(&notify.shared, key);
    let mut future = Box::pin(notify.notified());
    assert_eq!(
      poll(future.as_mut(), &noop_waker()),
      PollResult::Ready(Err(NotifyError::Full))
    );
  }

  #[test]
  fn broadcast_generation_exhaustion_closes_explicitly() {
    let notify = Arc::new(Notify::new(1).unwrap());
    super::lock(&notify.shared.ledger).broadcast_generation = u64::MAX - 1;
    let mut eligible_from_prior_broadcast = Box::pin(notify.notified());
    super::lock(&notify.shared.ledger).broadcast_generation = u64::MAX;
    let mut not_yet_eligible = Box::pin(notify.notified());
    assert_eq!(
      notify.notify_waiters(),
      Err(NotifyError::GenerationExhausted)
    );
    assert!(notify.is_closed());
    let waker = noop_waker();
    assert_eq!(
      poll(eligible_from_prior_broadcast.as_mut(), &waker),
      PollResult::Ready(Ok(()))
    );
    assert_eq!(
      poll(not_yet_eligible.as_mut(), &waker),
      PollResult::Ready(Err(NotifyError::Closed))
    );
  }

  #[test]
  fn waker_drop_callbacks_do_not_run_under_lock() {
    struct DropProbe(
      Arc<Mutex<Option<Arc<Notify>>>>,
      Arc<AtomicUsize>,
      Arc<AtomicUsize>,
    );
    impl Wake for DropProbe {
      fn wake(self: Arc<Self>) {
        self.2.fetch_add(1, Ordering::SeqCst);
      }
    }
    impl Drop for DropProbe {
      fn drop(&mut self) {
        if let Some(notify) = self.0.lock().unwrap().take() {
          let _ = notify.notify_one();
          self.1.fetch_add(1, Ordering::SeqCst);
        }
      }
    }

    let notify = Arc::new(Notify::new(1).unwrap());
    let reference = Arc::new(Mutex::new(Some(Arc::clone(&notify))));
    let drops = Arc::new(AtomicUsize::new(0));
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(DropProbe(
      Arc::clone(&reference),
      Arc::clone(&drops),
      Arc::clone(&wakes),
    )));
    let mut future = Box::pin(notify.notified());
    assert_eq!(poll(future.as_mut(), &waker), PollResult::Pending);
    drop(waker);
    drop(future);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(wakes.load(Ordering::SeqCst), 0);
    assert!(notify.notify_one().is_ok());
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use std::future::Future;
  use std::pin::Pin;
  use std::sync::Arc as StdArc;
  use std::task::{Context, Wake, Waker};

  use loom::sync::atomic::{AtomicUsize, Ordering};
  use loom::sync::{Arc, Mutex};
  use loom::thread;

  use super::{Notify, OwnedNotifiedFuture};

  struct Flag(Arc<AtomicUsize>);

  impl Wake for Flag {
    fn wake(self: StdArc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  fn poll(
    future: Pin<&mut OwnedNotifiedFuture>,
    waker: &Waker,
  ) -> std::task::Poll<Result<(), super::NotifyError>> {
    let mut context = Context::from_waker(waker);
    future.poll(&mut context)
  }

  #[test]
  fn notify_racing_with_registration_cannot_lose_the_notification() {
    loom::model(|| {
      let notify = Arc::new(Notify::new(1).unwrap());
      let mut future = Box::pin(notify.notified());
      let observed = Arc::new(AtomicUsize::new(0));
      let waker = Waker::from(StdArc::new(Flag(Arc::clone(&observed))));
      let notifier = Arc::clone(&notify);
      let sender = thread::spawn(move || notifier.notify_one().is_ok());
      let first = poll(future.as_mut(), &waker);
      assert!(sender.join().unwrap());
      if first.is_pending() {
        assert!(observed.load(Ordering::SeqCst) > 0);
      }
      assert!(poll(future.as_mut(), &waker).is_ready());
    });
  }

  #[test]
  fn cancel_granted_waiter_hands_notification_to_next_fifo_waiter() {
    loom::model(|| {
      let notify = Arc::new(Notify::new(2).unwrap());
      let mut first = Box::pin(notify.notified());
      let mut second = Box::pin(notify.notified());
      let waker = Waker::noop().clone();
      assert!(poll(first.as_mut(), &waker).is_pending());
      assert!(poll(second.as_mut(), &waker).is_pending());

      let first = Arc::new(Mutex::new(Some(first)));
      let dropper = Arc::clone(&first);
      let cancel = thread::spawn(move || drop(dropper.lock().unwrap().take()));
      let notifier = Arc::clone(&notify);
      let send = thread::spawn(move || notifier.notify_one());
      cancel.join().unwrap();
      send.join().unwrap().unwrap();
      assert!(poll(second.as_mut(), &waker).is_ready());
    });
  }

  #[test]
  fn notify_last_cancellation_racing_with_another_lifo_grant_preserves_order() {
    loom::model(|| {
      let notify = Arc::new(Notify::new(4).unwrap());
      let mut first = Box::pin(notify.notified());
      let mut second = Box::pin(notify.notified());
      let mut third = Box::pin(notify.notified());
      let mut last = Box::pin(notify.notified());
      let waker = Waker::noop().clone();
      assert!(poll(first.as_mut(), &waker).is_pending());
      assert!(poll(second.as_mut(), &waker).is_pending());
      assert!(poll(third.as_mut(), &waker).is_pending());
      assert!(poll(last.as_mut(), &waker).is_pending());
      notify.notify_last().unwrap();

      let last = Arc::new(Mutex::new(Some(last)));
      let dropper = Arc::clone(&last);
      let cancel = thread::spawn(move || drop(dropper.lock().unwrap().take()));
      let notifier = Arc::clone(&notify);
      let next = thread::spawn(move || notifier.notify_last());
      cancel.join().unwrap();
      next.join().unwrap().unwrap();

      assert!(poll(first.as_mut(), &waker).is_pending());
      assert!(poll(second.as_mut(), &waker).is_ready());
      assert!(poll(third.as_mut(), &waker).is_ready());
    });
  }

  #[test]
  fn close_racing_with_grant_cancellation_cannot_restore_closed_permit() {
    loom::model(|| {
      let notify = Arc::new(Notify::new(2).unwrap());
      let mut first = Box::pin(notify.notified());
      let mut second = Box::pin(notify.notified());
      let waker = Waker::noop().clone();
      assert!(poll(first.as_mut(), &waker).is_pending());
      assert!(poll(second.as_mut(), &waker).is_pending());
      notify.notify_one().unwrap();

      let first = Arc::new(Mutex::new(Some(first)));
      let dropper = Arc::clone(&first);
      let cancel = thread::spawn(move || drop(dropper.lock().unwrap().take()));
      let closer = Arc::clone(&notify);
      let close = thread::spawn(move || closer.close());
      cancel.join().unwrap();
      close.join().unwrap();

      let ledger = super::lock(&notify.shared.ledger);
      assert!(!ledger.permit);
      assert!(ledger.wait_head.is_none());
      assert!(
        ledger
          .slots
          .iter()
          .all(|slot| !matches!(slot.state, super::SlotState::Granted { .. }))
      );
      drop(ledger);
      assert!(matches!(
        poll(second.as_mut(), &waker),
        std::task::Poll::Ready(Err(super::NotifyError::Closed))
      ));
    });
  }
}
