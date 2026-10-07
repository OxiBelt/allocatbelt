//! A bounded, fair semaphore for the optional blocking runtime.
//!
//! The permit count covers available permits, permits returned to a waiter
//! but not yet observed by its future, and permits held by returned
//! [`Permit`]s. It does not account for this module's helper metadata, process
//! RSS, or arbitrary allocations made by callers.

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

/// A bounded semaphore whose waiters are admitted to a preallocated table.
///
/// `initial_permits` is the number of permits initially available. Calls to
/// [`add_permits`](Self::add_permits) may increase the total while its
/// checked count still fits in `usize`. `max_waiters` bounds futures that have
/// queued or received a grant but have not yet observed it. Construction
/// reserves that waiter table before creating the lock.
///
/// Waiters are served in FIFO order. A waiter at the head that requests more
/// permits than are currently available blocks every waiter behind it, even
/// if a later request would fit. Immediate [`try_acquire_many`](Self::try_acquire_many)
/// calls also fail while a waiter is queued, so they cannot take permits from
/// the queue.
///
/// Closing rejects new acquisitions and completes all queued and granted but
/// unobserved acquisitions with [`AcquireError::Closed`]. Their reserved
/// permits are returned to the semaphore. A grant becomes an issued permit
/// when its future claims the grant; an issued permit remains valid after
/// close and returns its permits when dropped.
pub struct Semaphore {
  shared: Arc<Shared>,
}

struct Shared {
  ledger: Mutex<Ledger>,
}

/// An owned reservation from a [`Semaphore`].
///
/// Dropping the permit returns its count. Calling [`forget`](Self::forget)
/// consumes the permit and permanently removes its count from the semaphore;
/// a later explicit [`Semaphore::add_permits`] can add permits back if the
/// checked total still fits in `usize`.
pub struct Permit {
  shared: Arc<Shared>,
  count: usize,
  active: bool,
}

/// A future returned by [`Semaphore::acquire_many`].
///
/// Dropping a pending future removes its waiter. If the semaphore had already
/// granted it permits, dropping the future restores those permits and wakes
/// the next eligible waiter.
#[must_use = "futures do nothing unless polled"]
pub struct AcquireMany {
  shared: Arc<Shared>,
  count: usize,
  waiter: Option<WaiterKey>,
  completed: bool,
}

/// Why a semaphore operation could not complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcquireError {
  /// The semaphore was closed before this acquisition was issued.
  Closed,
  /// No permits are immediately available, or the bounded waiter table is full.
  Full,
  /// This future was polled again after returning a result.
  Completed,
}

impl fmt::Display for AcquireError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Closed => f.write_str("semaphore is closed"),
      Self::Full => f.write_str("semaphore has no available capacity"),
      Self::Completed => f.write_str("acquisition future was already completed"),
    }
  }
}

impl std::error::Error for AcquireError {}

/// Why semaphore construction failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemaphoreBuildError {
  /// The waiter table size overflowed or could not be represented.
  CapacityOverflow,
  /// The preallocated waiter table could not be reserved.
  AllocationFailed,
}

impl fmt::Display for SemaphoreBuildError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::CapacityOverflow => f.write_str("semaphore waiter capacity overflowed"),
      Self::AllocationFailed => f.write_str("semaphore waiter table allocation failed"),
    }
  }
}

impl std::error::Error for SemaphoreBuildError {}

/// Why [`Semaphore::add_permits`] could not add permits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddPermitsError {
  /// The semaphore has been closed.
  Closed,
  /// Adding the permits would overflow the total permit count.
  Overflow,
}

impl fmt::Display for AddPermitsError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Closed => f.write_str("semaphore is closed"),
      Self::Overflow => f.write_str("semaphore permit count would overflow"),
    }
  }
}

impl std::error::Error for AddPermitsError {}

impl Semaphore {
  /// Creates a semaphore with `initial_permits` and at most `max_waiters`.
  ///
  /// The waiter table is reserved before the semaphore lock is constructed.
  /// `max_waiters == 0` allows immediate acquisitions, but no future can wait
  /// when permits are unavailable. A zero-sized acquisition is valid.
  pub fn new(initial_permits: usize, max_waiters: usize) -> Result<Self, SemaphoreBuildError> {
    let table_bytes = max_waiters
      .checked_mul(std::mem::size_of::<WaiterSlot>())
      .ok_or(SemaphoreBuildError::CapacityOverflow)?;
    if table_bytes > isize::MAX as usize {
      return Err(SemaphoreBuildError::CapacityOverflow);
    }

    let mut slots = Vec::new();
    slots
      .try_reserve_exact(max_waiters)
      .map_err(|_| SemaphoreBuildError::AllocationFailed)?;

    for index in 0..max_waiters {
      let free_next = index.checked_add(1).filter(|next| *next < max_waiters);
      slots.push(WaiterSlot {
        generation: 0,
        state: SlotState::Free,
        free_next,
        previous: None,
        next: None,
        waker: None,
      });
    }

    Ok(Self {
      shared: Arc::new(Shared {
        ledger: Mutex::new(Ledger {
          available: initial_permits,
          held: 0,
          closed: false,
          wait_head: None,
          wait_tail: None,
          grant_head: None,
          grant_tail: None,
          free_head: (max_waiters > 0).then_some(0),
          slots,
        }),
      }),
    })
  }

  /// Returns an owned future for `count` permits.
  ///
  /// `count == 0` is allowed. The future is queued behind existing waiters so
  /// it cannot jump the FIFO queue, and the queue's configured bound applies
  /// while it waits.
  pub fn acquire_many(&self, count: usize) -> AcquireMany {
    AcquireMany {
      shared: Arc::clone(&self.shared),
      count,
      waiter: None,
      completed: false,
    }
  }

  /// Tries to reserve `count` permits without waiting.
  ///
  /// Returns [`AcquireError::Full`] when permits are unavailable or when any
  /// waiter is ahead of this request.
  pub fn try_acquire_many(&self, count: usize) -> Result<Permit, AcquireError> {
    {
      let mut ledger = lock(&self.shared.ledger);
      if ledger.closed {
        return Err(AcquireError::Closed);
      }
      if ledger.wait_head.is_some() || ledger.available < count {
        return Err(AcquireError::Full);
      }
      let Some(held) = ledger.held.checked_add(count) else {
        return Err(AcquireError::Full);
      };
      ledger.available -= count;
      ledger.held = held;
    }

    Ok(Permit {
      shared: Arc::clone(&self.shared),
      count,
      active: true,
    })
  }

  /// Adds permits, waking as many FIFO waiters as now fit.
  ///
  /// The sum of available and held permits is checked before the update. A
  /// closed semaphore rejects additions.
  pub fn add_permits(&self, count: usize) -> Result<(), AddPermitsError> {
    {
      let mut ledger = lock(&self.shared.ledger);
      if ledger.closed {
        return Err(AddPermitsError::Closed);
      }
      let Some(total) = ledger.available.checked_add(ledger.held) else {
        return Err(AddPermitsError::Overflow);
      };
      let Some(total) = total.checked_add(count) else {
        return Err(AddPermitsError::Overflow);
      };
      let Some(available) = ledger.available.checked_add(count) else {
        return Err(AddPermitsError::Overflow);
      };
      debug_assert!(available <= total);
      ledger.available = available;
    }

    dispatch(&self.shared);
    Ok(())
  }

  /// Closes the semaphore and completes outstanding acquisitions with
  /// [`AcquireError::Closed`].
  ///
  /// Waiters and grants not yet claimed by their futures are rejected. Their
  /// permit counts are restored. Acquisitions already returned to callers
  /// remain valid and can be dropped normally.
  pub fn close(&self) {
    loop {
      let (waker, finished) = {
        let mut ledger = lock(&self.shared.ledger);
        ledger.closed = true;
        if let Some(index) = ledger.wait_head {
          ledger.unlink_waiter(index);
          let slot = &mut ledger.slots[index];
          slot.state = SlotState::Closed;
          (slot.waker.take(), false)
        } else if let Some(index) = ledger.grant_head {
          ledger.unlink_grant(index);
          let count = match ledger.slots[index].state {
            SlotState::Granted { count } => count,
            _ => 0,
          };
          let _ = restore_grant(&mut ledger, count);
          let slot = &mut ledger.slots[index];
          slot.state = SlotState::Closed;
          (slot.waker.take(), false)
        } else {
          (None, true)
        }
      };

      if finished {
        return;
      }
      wake_contained(waker);
    }
  }

  /// Returns the permits currently available for acquisition.
  #[must_use]
  pub fn available_permits(&self) -> usize {
    lock(&self.shared.ledger).available
  }

  /// Returns whether the semaphore has been closed.
  #[must_use]
  pub fn is_closed(&self) -> bool {
    lock(&self.shared.ledger).closed
  }

  /// Returns the configured bound on queued and granted-but-unobserved
  /// acquisition futures.
  #[must_use]
  pub fn max_waiters(&self) -> usize {
    lock(&self.shared.ledger).slots.len()
  }
}

impl Permit {
  /// Returns the number of permits represented by this token.
  #[must_use]
  pub const fn count(&self) -> usize {
    self.count
  }

  /// Permanently removes this permit's count from the semaphore.
  ///
  /// The count is no longer returned by `Drop`, reducing the semaphore's
  /// current total capacity. A later [`Semaphore::add_permits`] may
  /// explicitly add permits again, subject to checked `usize` bounds.
  pub fn forget(mut self) {
    self.active = false;
    let mut ledger = lock(&self.shared.ledger);
    ledger.held = ledger.held.saturating_sub(self.count);
  }
}

impl Future for AcquireMany {
  type Output = Result<Permit, AcquireError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.completed {
      return Poll::Ready(Err(AcquireError::Completed));
    }

    // A waker clone may invoke its RawWaker implementation. Clone it before
    // taking the semaphore lock; any unused clone is dropped after unlocking.
    let mut new_waker = Some(cx.waker().clone());
    let action = if let Some(key) = this.waiter {
      poll_waiter(&this.shared, key, &mut new_waker)
    } else {
      poll_first(&this.shared, this.count, &mut new_waker)
    };

    match action {
      PollAction::Pending(key, old_waker) => {
        if let Some(key) = key {
          this.waiter = Some(key);
        }
        drop_waker(old_waker);
        drop_waker(new_waker.take());
        Poll::Pending
      }
      PollAction::Permit(count, old_waker) => {
        this.waiter = None;
        this.completed = true;
        drop_waker(old_waker);
        drop_waker(new_waker.take());
        Poll::Ready(Ok(Permit {
          shared: Arc::clone(&this.shared),
          count,
          active: true,
        }))
      }
      PollAction::Closed(old_waker) => {
        this.waiter = None;
        this.completed = true;
        drop_waker(old_waker);
        drop_waker(new_waker.take());
        Poll::Ready(Err(AcquireError::Closed))
      }
      PollAction::Full => {
        this.waiter = None;
        this.completed = true;
        drop_waker(new_waker.take());
        Poll::Ready(Err(AcquireError::Full))
      }
    }
  }
}

impl Drop for AcquireMany {
  fn drop(&mut self) {
    let Some(key) = self.waiter.take() else {
      return;
    };
    cancel_waiter(&self.shared, key);
  }
}

impl Drop for Permit {
  fn drop(&mut self) {
    if self.active {
      release_permits(&self.shared, self.count);
      self.active = false;
    }
  }
}

impl Clone for Semaphore {
  fn clone(&self) -> Self {
    Self {
      shared: Arc::clone(&self.shared),
    }
  }
}

impl fmt::Debug for Semaphore {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let (available, held, closed, max_waiters) = {
      let ledger = lock(&self.shared.ledger);
      (
        ledger.available,
        ledger.held,
        ledger.closed,
        ledger.slots.len(),
      )
    };
    f.debug_struct("Semaphore")
      .field("available", &available)
      .field("held", &held)
      .field("closed", &closed)
      .field("max_waiters", &max_waiters)
      .finish()
  }
}

impl fmt::Debug for Permit {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Permit")
      .field("count", &self.count)
      .field("active", &self.active)
      .finish()
  }
}

impl fmt::Debug for AcquireMany {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AcquireMany")
      .field("count", &self.count)
      .field("waiting", &self.waiter.is_some())
      .field("completed", &self.completed)
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
  Waiting { count: usize },
  Granted { count: usize },
  Closed,
  Retired,
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
  available: usize,
  /// Includes both caller-held permits and grants not yet observed by futures.
  held: usize,
  closed: bool,
  wait_head: Option<usize>,
  wait_tail: Option<usize>,
  grant_head: Option<usize>,
  grant_tail: Option<usize>,
  free_head: Option<usize>,
  slots: Vec<WaiterSlot>,
}

impl Ledger {
  fn allocate_waiter(&mut self, count: usize, waker: Waker) -> Result<WaiterKey, Waker> {
    let Some(index) = self.free_head else {
      return Err(waker);
    };
    if self.slots[index].state != SlotState::Free {
      return Err(waker);
    }
    let free_next = self.slots[index].free_next;
    self.free_head = free_next;
    let slot = &mut self.slots[index];
    slot.free_next = None;
    slot.state = SlotState::Waiting { count };
    slot.waker = Some(waker);
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
    {
      let slot = &mut self.slots[index];
      slot.previous = previous;
      slot.next = None;
    }
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

  fn link_grant(&mut self, index: usize) {
    let previous = self.grant_tail;
    {
      let slot = &mut self.slots[index];
      slot.previous = previous;
      slot.next = None;
    }
    if let Some(previous) = previous {
      self.slots[previous].next = Some(index);
    } else {
      self.grant_head = Some(index);
    }
    self.grant_tail = Some(index);
  }

  fn unlink_grant(&mut self, index: usize) {
    let previous = self.slots[index].previous;
    let next = self.slots[index].next;
    if let Some(previous) = previous {
      self.slots[previous].next = next;
    } else {
      self.grant_head = next;
    }
    if let Some(next) = next {
      self.slots[next].previous = previous;
    } else {
      self.grant_tail = previous;
    }
    self.slots[index].previous = None;
    self.slots[index].next = None;
  }

  /// Releases a slot and advances its generation. A generation at `u64::MAX`
  /// retires the slot instead of wrapping and making an old key valid again.
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
    // The final ledger is destroyed without holding its mutex. Contain
    // custom RawWaker destructors just as all other explicit drops do.
    for slot in &mut self.slots {
      drop_waker(slot.waker.take());
    }
  }
}

enum PollAction {
  Pending(Option<WaiterKey>, Option<Waker>),
  Permit(usize, Option<Waker>),
  Closed(Option<Waker>),
  Full,
}

fn poll_first(shared: &Arc<Shared>, count: usize, new_waker: &mut Option<Waker>) -> PollAction {
  let mut ledger = lock(&shared.ledger);
  if ledger.closed {
    return PollAction::Closed(None);
  }
  if ledger.wait_head.is_none() && ledger.available >= count {
    let Some(held) = ledger.held.checked_add(count) else {
      return PollAction::Full;
    };
    ledger.available -= count;
    ledger.held = held;
    return PollAction::Permit(count, None);
  }
  let Some(waker) = new_waker.take() else {
    return PollAction::Full;
  };
  match ledger.allocate_waiter(count, waker) {
    Ok(key) => PollAction::Pending(Some(key), None),
    Err(waker) => {
      *new_waker = Some(waker);
      PollAction::Full
    }
  }
}

fn poll_waiter(shared: &Arc<Shared>, key: WaiterKey, new_waker: &mut Option<Waker>) -> PollAction {
  let mut ledger = lock(&shared.ledger);
  let Some(state) = ledger.valid_state(key) else {
    return PollAction::Closed(None);
  };

  if ledger.closed {
    match state {
      SlotState::Waiting { .. } => ledger.unlink_waiter(key.index),
      SlotState::Granted { count } => {
        ledger.unlink_grant(key.index);
        let _ = restore_grant(&mut ledger, count);
      }
      SlotState::Closed => {}
      SlotState::Free | SlotState::Retired => return PollAction::Closed(None),
    }
    return PollAction::Closed(ledger.recycle_slot(key.index));
  }

  match state {
    SlotState::Waiting { .. } => {
      let replacement = new_waker.take();
      let old = std::mem::replace(&mut ledger.slots[key.index].waker, replacement);
      PollAction::Pending(Some(key), old)
    }
    SlotState::Granted { count } => {
      ledger.unlink_grant(key.index);
      PollAction::Permit(count, ledger.recycle_slot(key.index))
    }
    SlotState::Closed => PollAction::Closed(ledger.recycle_slot(key.index)),
    SlotState::Free | SlotState::Retired => PollAction::Closed(None),
  }
}

fn cancel_waiter(shared: &Arc<Shared>, key: WaiterKey) {
  let old_waker = {
    let mut ledger = lock(&shared.ledger);
    let Some(state) = ledger.valid_state(key) else {
      return;
    };
    match state {
      SlotState::Waiting { .. } => ledger.unlink_waiter(key.index),
      SlotState::Granted { count } => {
        ledger.unlink_grant(key.index);
        let _ = restore_grant(&mut ledger, count);
      }
      SlotState::Closed => {}
      SlotState::Free | SlotState::Retired => return,
    }
    ledger.recycle_slot(key.index)
  };
  drop_waker(old_waker);
  dispatch(shared);
}

fn release_permits(shared: &Arc<Shared>, count: usize) {
  {
    let mut ledger = lock(&shared.ledger);
    if !restore_grant(&mut ledger, count) {
      return;
    }
  }
  dispatch(shared);
}

/// Moves a grant from held to available without wrapping either counter.
fn restore_grant(ledger: &mut Ledger, count: usize) -> bool {
  let Some(held) = ledger.held.checked_sub(count) else {
    return false;
  };
  let Some(available) = ledger.available.checked_add(count) else {
    return false;
  };
  ledger.held = held;
  ledger.available = available;
  true
}

fn dispatch(shared: &Arc<Shared>) {
  loop {
    let waker = {
      let mut ledger = lock(&shared.ledger);
      if ledger.closed {
        return;
      }
      let Some(index) = ledger.wait_head else {
        return;
      };
      let count = match ledger.slots[index].state {
        SlotState::Waiting { count } => count,
        _ => return,
      };
      if ledger.available < count {
        return;
      }
      let Some(held) = ledger.held.checked_add(count) else {
        return;
      };
      ledger.unlink_waiter(index);
      ledger.available -= count;
      ledger.held = held;
      ledger.slots[index].state = SlotState::Granted { count };
      ledger.link_grant(index);
      ledger.slots[index].waker.take()
    };
    wake_contained(waker);
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
  use std::future::Future;
  use std::pin::Pin;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::{Arc, Mutex};
  use std::task::{Context, Wake, Waker};
  use std::thread;

  use super::{AcquireError, Semaphore};

  fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> std::task::Poll<F::Output> {
    let mut context = Context::from_waker(waker);
    future.poll(&mut context)
  }

  fn noop_waker() -> Waker {
    (*Waker::noop()).clone()
  }

  #[test]
  fn impossible_waiter_table_fails_before_allocation() {
    assert!(matches!(
      Semaphore::new(0, usize::MAX),
      Err(super::SemaphoreBuildError::CapacityOverflow)
    ));
  }

  #[test]
  fn issued_permit_returns_after_close() {
    let semaphore = Semaphore::new(3, 0).unwrap();
    let permit = semaphore.try_acquire_many(2).unwrap();
    semaphore.close();
    assert_eq!(permit.count(), 2);
    assert_eq!(semaphore.available_permits(), 1);
    drop(permit);
    assert_eq!(semaphore.available_permits(), 3);
    assert!(matches!(
      semaphore.try_acquire_many(1),
      Err(AcquireError::Closed)
    ));
  }

  #[test]
  fn forgotten_permits_reduce_checked_total_until_explicitly_added() {
    let semaphore = Semaphore::new(usize::MAX, 0).unwrap();
    semaphore.try_acquire_many(2).unwrap().forget();
    assert_eq!(semaphore.available_permits(), usize::MAX - 2);
    semaphore.add_permits(2).unwrap();
    assert_eq!(semaphore.available_permits(), usize::MAX);
    assert_eq!(
      semaphore.add_permits(1),
      Err(super::AddPermitsError::Overflow)
    );
  }

  #[test]
  fn a_large_fifo_head_blocks_a_small_tail() {
    let semaphore = Semaphore::new(0, 2).unwrap();
    let mut head = Box::pin(semaphore.acquire_many(2));
    let mut tail = Box::pin(semaphore.acquire_many(1));
    let waker = noop_waker();

    assert!(poll(head.as_mut(), &waker).is_pending());
    assert!(poll(tail.as_mut(), &waker).is_pending());
    semaphore.add_permits(1).unwrap();
    assert!(poll(head.as_mut(), &waker).is_pending());
    assert!(poll(tail.as_mut(), &waker).is_pending());
    assert_eq!(semaphore.available_permits(), 1);
    assert!(semaphore.try_acquire_many(1).is_err());

    semaphore.add_permits(1).unwrap();
    let head_permit = match poll(head.as_mut(), &waker) {
      std::task::Poll::Ready(Ok(permit)) => permit,
      other => panic!("expected head grant, got {other:?}"),
    };
    assert!(poll(tail.as_mut(), &waker).is_pending());
    drop(head_permit);
    let tail_permit = match poll(tail.as_mut(), &waker) {
      std::task::Poll::Ready(Ok(permit)) => permit,
      other => panic!("expected tail grant, got {other:?}"),
    };
    assert_eq!(tail_permit.count(), 1);
  }

  #[test]
  fn cancelling_the_head_dispatches_the_next_waiter() {
    let semaphore = Semaphore::new(0, 2).unwrap();
    let mut head = Box::pin(semaphore.acquire_many(2));
    let mut tail = Box::pin(semaphore.acquire_many(1));
    let waker = noop_waker();
    assert!(poll(head.as_mut(), &waker).is_pending());
    assert!(poll(tail.as_mut(), &waker).is_pending());
    semaphore.add_permits(1).unwrap();
    drop(head);
    match poll(tail.as_mut(), &waker) {
      std::task::Poll::Ready(Ok(permit)) => assert_eq!(permit.count(), 1),
      other => panic!("expected tail grant after cancellation, got {other:?}"),
    }
  }

  #[test]
  fn dropping_a_future_after_its_grant_restores_the_reserved_permits() {
    let semaphore = Semaphore::new(0, 1).unwrap();
    let mut abandoned = Box::pin(semaphore.acquire_many(1));
    let waker = noop_waker();
    assert!(poll(abandoned.as_mut(), &waker).is_pending());
    semaphore.add_permits(1).unwrap();
    assert_eq!(semaphore.available_permits(), 0);
    drop(abandoned);
    assert_eq!(semaphore.available_permits(), 1);
    assert_eq!(semaphore.try_acquire_many(1).unwrap().count(), 1);
  }

  #[test]
  fn waiter_capacity_and_permit_addition_are_bounded() {
    let semaphore = Semaphore::new(0, 1).unwrap();
    let mut first = Box::pin(semaphore.acquire_many(1));
    let mut second = Box::pin(semaphore.acquire_many(1));
    let waker = noop_waker();
    assert!(poll(first.as_mut(), &waker).is_pending());
    assert!(matches!(
      poll(second.as_mut(), &waker),
      std::task::Poll::Ready(Err(AcquireError::Full))
    ));

    let full = Semaphore::new(usize::MAX, 0).unwrap();
    assert_eq!(full.add_permits(1), Err(super::AddPermitsError::Overflow));
  }

  #[test]
  fn zero_count_acquisitions_are_valid_and_fifo_ordered() {
    let semaphore = Semaphore::new(0, 2).unwrap();
    let mut first = Box::pin(semaphore.acquire_many(1));
    let mut zero = Box::pin(semaphore.acquire_many(0));
    let waker = noop_waker();
    assert_eq!(semaphore.try_acquire_many(0).unwrap().count(), 0);
    assert!(poll(first.as_mut(), &waker).is_pending());
    assert!(poll(zero.as_mut(), &waker).is_pending());
    assert!(semaphore.try_acquire_many(0).is_err());
    semaphore.add_permits(1).unwrap();
    let first_permit = match poll(first.as_mut(), &waker) {
      std::task::Poll::Ready(Ok(permit)) => permit,
      other => panic!("expected the FIFO head grant, got {other:?}"),
    };
    match poll(zero.as_mut(), &waker) {
      std::task::Poll::Ready(Ok(permit)) => assert_eq!(permit.count(), 0),
      other => panic!("expected the queued zero-count grant, got {other:?}"),
    }
    drop(first_permit);
  }

  struct CountWake(Arc<AtomicUsize>);

  impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  #[test]
  fn each_poll_replaces_the_stored_waker_with_the_latest_one() {
    let semaphore = Semaphore::new(0, 1).unwrap();
    let mut acquire = Box::pin(semaphore.acquire_many(1));
    let first_count = Arc::new(AtomicUsize::new(0));
    let latest_count = Arc::new(AtomicUsize::new(0));
    let first = Waker::from(Arc::new(CountWake(Arc::clone(&first_count))));
    let latest = Waker::from(Arc::new(CountWake(Arc::clone(&latest_count))));
    assert!(poll(acquire.as_mut(), &first).is_pending());
    assert!(poll(acquire.as_mut(), &latest).is_pending());
    semaphore.add_permits(1).unwrap();
    assert_eq!(first_count.load(Ordering::SeqCst), 0);
    assert_eq!(latest_count.load(Ordering::SeqCst), 1);
  }

  struct ReentrantWake {
    semaphore: Semaphore,
    release: Mutex<Option<super::Permit>>,
  }

  impl Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      drop(self.release.lock().unwrap().take());
      self.semaphore.close();
    }
  }

  #[test]
  fn waking_can_reenter_release_and_close() {
    let semaphore = Semaphore::new(1, 1).unwrap();
    let held = semaphore.try_acquire_many(1).unwrap();
    let wake = Waker::from(Arc::new(ReentrantWake {
      semaphore: semaphore.clone(),
      release: Mutex::new(Some(held)),
    }));
    let mut acquire = Box::pin(semaphore.acquire_many(1));
    assert!(poll(acquire.as_mut(), &wake).is_pending());
    semaphore.add_permits(1).unwrap();
    assert!(semaphore.is_closed());
    assert!(matches!(
      poll(acquire.as_mut(), &wake),
      std::task::Poll::Ready(Err(AcquireError::Closed))
    ));
  }

  struct CloseOnDrop(Semaphore);

  impl Drop for CloseOnDrop {
    fn drop(&mut self) {
      self.0.close();
    }
  }

  impl Wake for CloseOnDrop {
    fn wake(self: Arc<Self>) {
      self.0.close();
    }
  }

  #[test]
  fn replacing_and_dropping_a_waker_can_reenter_close() {
    let semaphore = Semaphore::new(0, 1).unwrap();
    let mut acquire = Box::pin(semaphore.acquire_many(1));
    let old = Waker::from(Arc::new(CloseOnDrop(semaphore.clone())));
    assert!(poll(acquire.as_mut(), &old).is_pending());
    drop(old);
    let replacement = noop_waker();
    assert!(poll(acquire.as_mut(), &replacement).is_pending());
    assert!(matches!(
      poll(acquire.as_mut(), &replacement),
      std::task::Poll::Ready(Err(AcquireError::Closed))
    ));
    assert!(semaphore.is_closed());
  }

  #[test]
  fn close_rejects_grants_not_yet_claimed_but_keeps_issued_permits_valid() {
    let semaphore = Semaphore::new(1, 1).unwrap();
    let issued = semaphore.try_acquire_many(1).unwrap();
    let mut waiting = Box::pin(semaphore.acquire_many(1));
    let waker = noop_waker();
    assert!(poll(waiting.as_mut(), &waker).is_pending());
    drop(issued);
    // The waiter now owns a grant, though its future has not observed it.
    semaphore.close();
    assert!(matches!(
      poll(waiting.as_mut(), &waker),
      std::task::Poll::Ready(Err(AcquireError::Closed))
    ));
    assert_eq!(semaphore.available_permits(), 1);
    assert!(semaphore.try_acquire_many(1).is_err());
    assert_eq!(
      semaphore.add_permits(1),
      Err(super::AddPermitsError::Closed)
    );
  }

  #[test]
  fn reused_slot_rejects_a_stale_generation() {
    let semaphore = Semaphore::new(0, 1).unwrap();
    let waker = noop_waker();
    let first_waker = waker.clone();
    let first = {
      let mut ledger = super::lock(&semaphore.shared.ledger);
      match ledger.allocate_waiter(1, first_waker) {
        Ok(key) => key,
        Err(_) => panic!("reserved waiter slot was unavailable"),
      }
    };
    let old_waker = {
      let mut ledger = super::lock(&semaphore.shared.ledger);
      ledger.unlink_waiter(first.index);
      ledger.recycle_slot(first.index)
    };
    super::drop_waker(old_waker);
    let second = {
      let mut ledger = super::lock(&semaphore.shared.ledger);
      match ledger.allocate_waiter(1, waker) {
        Ok(key) => key,
        Err(_) => panic!("recycled waiter slot was unavailable"),
      }
    };
    let ledger = super::lock(&semaphore.shared.ledger);
    assert_eq!(first.index, second.index);
    assert_ne!(first.generation, second.generation);
    assert_eq!(ledger.valid_state(first), None);
  }

  #[test]
  fn concurrent_permits_never_exceed_the_initial_capacity() {
    let semaphore = Semaphore::new(3, 0).unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let workers: Vec<_> = (0..8)
      .map(|_| {
        let semaphore = semaphore.clone();
        let active = Arc::clone(&active);
        thread::spawn(move || {
          for _ in 0..200 {
            loop {
              if let Ok(permit) = semaphore.try_acquire_many(1) {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                assert!(now <= 3);
                thread::yield_now();
                active.fetch_sub(1, Ordering::SeqCst);
                drop(permit);
                break;
              }
              thread::yield_now();
            }
          }
        })
      })
      .collect();
    for worker in workers {
      worker.join().unwrap();
    }
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(semaphore.available_permits(), 3);
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use loom::sync::Arc;
  use loom::sync::atomic::{AtomicUsize, Ordering};
  use loom::thread;

  use std::future::Future;
  use std::pin::Pin;
  use std::sync::Arc as StdArc;
  use std::sync::atomic::{AtomicUsize as StdAtomicUsize, Ordering as StdOrdering};
  use std::task::{Context, Poll, Wake, Waker};

  use super::{AcquireError, AcquireMany, Permit, Semaphore};

  struct WakeCounter(StdArc<StdAtomicUsize>);

  impl Wake for WakeCounter {
    fn wake(self: StdArc<Self>) {
      self.0.fetch_add(1, StdOrdering::SeqCst);
    }

    fn wake_by_ref(self: &StdArc<Self>) {
      self.0.fetch_add(1, StdOrdering::SeqCst);
    }
  }

  fn counter_waker() -> (Waker, StdArc<StdAtomicUsize>) {
    let count = StdArc::new(StdAtomicUsize::new(0));
    (
      Waker::from(StdArc::new(WakeCounter(StdArc::clone(&count)))),
      count,
    )
  }

  fn noop_waker() -> Waker {
    (*Waker::noop()).clone()
  }

  fn poll(future: &mut AcquireMany, waker: &Waker) -> Poll<Result<Permit, AcquireError>> {
    let mut context = Context::from_waker(waker);
    Pin::new(future).poll(&mut context)
  }

  #[test]
  fn actual_ledger_never_issues_more_than_its_available_count() {
    loom::model(|| {
      let semaphore = Arc::new(Semaphore::new(1, 0).unwrap());
      let active = Arc::new(AtomicUsize::new(0));
      let threads: Vec<_> = (0..2)
        .map(|_| {
          let semaphore = Arc::clone(&semaphore);
          let active = Arc::clone(&active);
          thread::spawn(move || {
            if let Ok(permit) = semaphore.try_acquire_many(1) {
              let count = active.fetch_add(1, Ordering::SeqCst) + 1;
              assert_eq!(count, 1);
              active.fetch_sub(1, Ordering::SeqCst);
              drop(permit);
            }
          })
        })
        .collect();
      for thread in threads {
        thread.join().unwrap();
      }
      assert_eq!(active.load(Ordering::SeqCst), 0);
      assert_eq!(semaphore.available_permits(), 1);
    });
  }

  #[test]
  fn queued_head_cancellation_racing_addition_grants_the_fifo_tail_once() {
    loom::model(|| {
      let semaphore = Semaphore::new(1, 2).unwrap();
      let (head_waker, head_wakes) = counter_waker();
      let (tail_waker, tail_wakes) = counter_waker();
      let mut head = semaphore.acquire_many(2);
      let mut tail = semaphore.acquire_many(1);
      assert!(poll(&mut head, &head_waker).is_pending());
      assert!(poll(&mut tail, &tail_waker).is_pending());

      let add_sem = semaphore.clone();
      let add = thread::spawn(move || add_sem.add_permits(1).unwrap());
      let cancel = thread::spawn(move || drop(head));
      add.join().unwrap();
      cancel.join().unwrap();

      // Whichever operation wins, the tail is granted exactly once. If the
      // addition grants the head first, cancelling that grant then advances
      // the queue; otherwise the tail receives the initial available permit.
      assert_eq!(tail_wakes.load(StdOrdering::SeqCst), 1);
      assert!(head_wakes.load(StdOrdering::SeqCst) <= 1);
      let tail_permit = match poll(&mut tail, &tail_waker) {
        Poll::Ready(Ok(permit)) => permit,
        other => panic!("expected the FIFO tail grant, got {other:?}"),
      };
      assert_eq!(tail_permit.count(), 1);
      assert_eq!(semaphore.available_permits(), 1);
      drop(tail_permit);
      assert_eq!(semaphore.available_permits(), 2);
    });
  }

  #[test]
  fn grant_close_and_cancel_conserve_permits_and_reject_stale_slot_keys() {
    loom::model(|| {
      let semaphore = Semaphore::new(0, 1).unwrap();
      let no_op = noop_waker();
      let mut cancelled = semaphore.acquire_many(1);
      assert!(poll(&mut cancelled, &no_op).is_pending());
      let stale_key = cancelled.waiter.expect("queued future has a slot key");
      drop(cancelled);

      let (waker, wakes) = counter_waker();
      let mut granted = semaphore.acquire_many(2);
      assert!(poll(&mut granted, &waker).is_pending());
      let grant_key = granted.waiter.expect("queued future has a slot key");
      assert_eq!(grant_key.index, stale_key.index);
      assert_ne!(grant_key.generation, stale_key.generation);
      {
        let ledger = super::lock(&semaphore.shared.ledger);
        assert_eq!(ledger.valid_state(stale_key), None);
      }

      semaphore.add_permits(2).unwrap();
      assert_eq!(wakes.load(StdOrdering::SeqCst), 1);
      let close_sem = semaphore.clone();
      let closer = thread::spawn(move || close_sem.close());
      let cancel = thread::spawn(move || drop(granted));
      closer.join().unwrap();
      cancel.join().unwrap();

      assert!(semaphore.is_closed());
      assert_eq!(semaphore.available_permits(), 2);
      let ledger = super::lock(&semaphore.shared.ledger);
      assert_eq!(ledger.held, 0);
      assert_eq!(ledger.valid_state(grant_key), None);
    });
  }
}
