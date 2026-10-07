//! A bounded multi-receiver broadcast channel.
//!
//! The ring and receiver table are allocated once by [`channel`]. Each active
//! receiver has one cursor and one registered waker. New receivers start at
//! the current send sequence, so they do not see earlier values. Receivers
//! that fall behind the ring receive [`TryRecvError::Lagged`] with the exact
//! number of skipped messages, then resume at the oldest retained value.
//!
//! Ring slots hold `Arc<T>` values so the payload can be cloned after releasing
//! the state mutex. Receiving requires `T: Clone`; using sender and receiver
//! handles across threads requires `T: Send + Sync` through their ordinary
//! auto-trait bounds. There is no `'static` requirement. Ring slots, cursors,
//! waiter state, and `Arc` bookkeeping are ordinary Rust allocations and are
//! not charged to the managed-resource ledger. A received clone belongs to the
//! caller; retained `Arc<T>` payloads are released when all eligible receivers
//! consume or drop them, or when the ring overwrites them.
//!
//! `Sender::closed` is ready when the active receiver count reaches zero,
//! even if a sender explicitly closed the channel while receiver handles
//! remain. A sender may subscribe again after that zero-receiver transition;
//! a closed future rechecks the active count after each broadcast and may
//! remain pending if a new receiver won that race.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::PoisonError;
use std::task::{Context, Poll, Waker};

use super::notify::{Notify, NotifyError, OwnedNotifiedFuture};

#[cfg(loom)]
use loom::sync::{Arc, Mutex, MutexGuard};
#[cfg(not(loom))]
use std::sync::{Arc, Mutex, MutexGuard};

use super::task::drop_contained;

const CLOSED_POLL_BUDGET: usize = 64;

/// Creates a broadcast channel with a fixed `capacity` ring and at most
/// `max_receivers` active or dropping receiver slots.
///
/// Both bounds must be nonzero. The returned receiver occupies one slot;
/// subsequent receivers are created with [`Sender::subscribe`].
pub fn channel<T>(
  capacity: usize,
  max_receivers: usize,
) -> Result<(Sender<T>, Receiver<T>), BroadcastBuildError> {
  if capacity == 0 {
    return Err(BroadcastBuildError::ZeroCapacity);
  }
  if max_receivers == 0 {
    return Err(BroadcastBuildError::ZeroReceivers);
  }

  let message_bytes = capacity
    .checked_mul(std::mem::size_of::<MessageSlot<T>>())
    .ok_or(BroadcastBuildError::CapacityOverflow)?;
  let receiver_bytes = max_receivers
    .checked_mul(std::mem::size_of::<ReceiverSlot>())
    .ok_or(BroadcastBuildError::CapacityOverflow)?;
  if message_bytes > isize::MAX as usize || receiver_bytes > isize::MAX as usize {
    return Err(BroadcastBuildError::CapacityOverflow);
  }

  let mut messages = Vec::new();
  messages
    .try_reserve_exact(capacity)
    .map_err(|_| BroadcastBuildError::AllocationFailed)?;
  messages.resize_with(capacity, MessageSlot::empty);

  let mut receivers = Vec::new();
  receivers
    .try_reserve_exact(max_receivers)
    .map_err(|_| BroadcastBuildError::AllocationFailed)?;
  for index in 0..max_receivers {
    receivers.push(ReceiverSlot {
      generation: 0,
      state: ReceiverState::Free,
      cursor: 0,
      free_next: index.checked_add(1).filter(|next| *next < max_receivers),
      waker: None,
      wake_pending: false,
    });
  }

  let closed_notify = match Notify::new(max_receivers) {
    Ok(notify) => notify,
    Err(super::notify::NotifyBuildError::CapacityOverflow) => {
      return Err(BroadcastBuildError::CapacityOverflow);
    }
    Err(super::notify::NotifyBuildError::AllocationFailed) => {
      return Err(BroadcastBuildError::AllocationFailed);
    }
  };

  let shared = Arc::new(Shared {
    closed_notify,
    ledger: Mutex::new(Ledger {
      messages,
      receivers,
      free_head: (max_receivers > 0).then_some(0),
      next_sequence: 0,
      active_receivers: 0,
      sender_count: 1,
      closed: false,
    }),
  });

  let receiver = {
    let mut ledger = lock(&shared.ledger);
    ledger
      .allocate_receiver(0)
      .ok_or(BroadcastBuildError::AllocationFailed)?
  };

  Ok((
    Sender {
      shared: Arc::clone(&shared),
      active: true,
    },
    Receiver {
      shared,
      key: receiver,
    },
  ))
}

/// Sending half of a bounded broadcast channel.
///
/// These handles and their receivers are `Send + Sync` when `T: Send + Sync`.
/// The channel stores payloads behind `Arc<T>` and imposes no `'static` bound.
///
/// ```compile_fail
/// use std::cell::Cell;
/// use allocatbelt::runtime::broadcast::channel;
/// fn require_send<T: Send>(_: T) {}
/// let (sender, _receiver) = channel::<Cell<u8>>(1, 1).unwrap();
/// require_send(sender);
/// ```
///
/// ```compile_fail
/// use std::rc::Rc;
/// use allocatbelt::runtime::broadcast::channel;
/// fn require_send<T: Send>(_: T) {}
/// let (sender, _receiver) = channel::<Rc<u8>>(1, 1).unwrap();
/// require_send(sender);
/// ```
pub struct Sender<T> {
  shared: Arc<Shared<T>>,
  active: bool,
}

/// A single-consumer receiver. Use [`resubscribe`](Self::resubscribe) or
/// [`Sender::subscribe`] to create another receiver beginning at the current
/// send sequence.
pub struct Receiver<T> {
  shared: Arc<Shared<T>>,
  key: ReceiverKey,
}

/// Future returned by [`Receiver::recv`]. Dropping a pending future removes
/// that receiver's registered waker.
#[must_use = "futures do nothing unless polled"]
pub struct Recv<'a, T> {
  receiver: &'a mut Receiver<T>,
  completed: bool,
}

/// A future that completes when the channel has no active receivers.
#[must_use = "futures do nothing unless polled"]
pub struct SenderClosed<'a, T> {
  sender: &'a Sender<T>,
  notified: Option<OwnedNotifiedFuture>,
  completed: bool,
}

/// Why a bounded sender-closure wait could not register.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClosedError {
  /// The channel's bounded closed-waiter table is full.
  Full,
  /// The notification source or its generation is exhausted.
  Exhausted,
  /// A custom raw waker panicked while being cloned.
  WakerPanicked,
  /// This future was polled after it completed.
  Completed,
}

impl fmt::Display for ClosedError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Full => "broadcast closed waiter table is full",
      Self::Exhausted => "broadcast closed notification is exhausted",
      Self::WakerPanicked => "broadcast closed waker clone panicked",
      Self::Completed => "broadcast closed future was already completed",
    })
  }
}

impl std::error::Error for ClosedError {}

struct Shared<T> {
  closed_notify: Notify,
  ledger: Mutex<Ledger<T>>,
}

struct Ledger<T> {
  messages: Vec<MessageSlot<T>>,
  receivers: Vec<ReceiverSlot>,
  free_head: Option<usize>,
  next_sequence: u64,
  active_receivers: usize,
  sender_count: usize,
  closed: bool,
}

struct MessageSlot<T> {
  sequence: u64,
  remaining: usize,
  value: Option<Arc<T>>,
}

impl<T> MessageSlot<T> {
  fn empty() -> Self {
    Self {
      sequence: 0,
      remaining: 0,
      value: None,
    }
  }
}

struct ReceiverSlot {
  generation: u64,
  state: ReceiverState,
  cursor: u64,
  free_next: Option<usize>,
  /// The sole waker registered by this receiver's current `Recv` future.
  waker: Option<Waker>,
  /// A send or close has made this receiver's current future eligible to wake.
  /// It lets the waker be taken under the lock and invoked after unlocking.
  wake_pending: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiverState {
  Free,
  Active,
  Dropping,
  Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiverKey {
  index: usize,
  generation: u64,
}

/// Why channel construction failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BroadcastBuildError {
  /// The ring capacity must be nonzero.
  ZeroCapacity,
  /// The channel starts with a receiver, so its receiver bound must be nonzero.
  ZeroReceivers,
  /// A requested table size overflowed or could not be represented.
  CapacityOverflow,
  /// The fixed ring or receiver table could not be reserved.
  AllocationFailed,
}

impl fmt::Display for BroadcastBuildError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::ZeroCapacity => "broadcast capacity must be nonzero",
      Self::ZeroReceivers => "broadcast receiver capacity must be nonzero",
      Self::CapacityOverflow => "broadcast capacity overflowed",
      Self::AllocationFailed => "broadcast channel storage allocation failed",
    })
  }
}

impl std::error::Error for BroadcastBuildError {}

/// Why a new receiver could not be created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscribeError {
  /// The fixed receiver table has no free slot.
  Full,
  /// All senders have dropped and the channel is closed.
  Closed,
}

impl fmt::Display for SubscribeError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Full => "broadcast receiver table is full",
      Self::Closed => "broadcast channel is closed",
    })
  }
}

impl std::error::Error for SubscribeError {}

/// Why a send was rejected. The original value remains available in
/// [`SendError::value`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendErrorKind {
  /// There were no active receivers. A later subscription may make sending
  /// possible again while a sender remains alive.
  NoReceivers,
  /// The last sender has closed the channel.
  Closed,
  /// The nonwrapping message sequence was exhausted; the channel is closed.
  SequenceExhausted,
}

/// A rejected send and its original value.
pub struct SendError<T> {
  /// The reason the send was rejected.
  pub kind: SendErrorKind,
  /// The original value, unchanged.
  pub value: T,
}

impl<T> SendError<T> {
  /// Returns the rejected value.
  pub fn into_inner(self) -> T {
    self.value
  }
}

impl<T> fmt::Debug for SendError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("SendError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Display for SendError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self.kind {
      SendErrorKind::NoReceivers => "broadcast channel has no receivers",
      SendErrorKind::Closed => "broadcast channel is closed",
      SendErrorKind::SequenceExhausted => "broadcast sequence is exhausted",
    })
  }
}

impl<T: 'static> std::error::Error for SendError<T> {}

/// An error returned by [`Receiver::recv`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecvError {
  /// All senders have closed and the receiver has drained retained values.
  Closed,
  /// The receiver skipped `u64` messages and now points to the oldest retained
  /// value. A later receive can return that value.
  Lagged(u64),
}

impl fmt::Display for RecvError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Closed => f.write_str("broadcast channel is closed"),
      Self::Lagged(skipped) => write!(f, "broadcast receiver lagged by {skipped}"),
    }
  }
}

impl std::error::Error for RecvError {}

/// An error returned by [`Receiver::try_recv`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TryRecvError {
  /// No value is ready and at least one sender remains.
  Empty,
  /// All senders have closed and the receiver has drained retained values.
  Closed,
  /// The receiver skipped `u64` messages and now points to the oldest retained
  /// value. A later receive can return that value.
  Lagged(u64),
}

impl fmt::Display for TryRecvError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Empty => f.write_str("broadcast channel is empty"),
      Self::Closed => f.write_str("broadcast channel is closed"),
      Self::Lagged(skipped) => write!(f, "broadcast receiver lagged by {skipped}"),
    }
  }
}

impl std::error::Error for TryRecvError {}

impl<T> Sender<T> {
  /// Sends one value to every active receiver.
  ///
  /// The return value is the number of receivers eligible when the send was
  /// committed. Receivers may subsequently drop or lag. A rejected send returns
  /// its original value unchanged.
  pub fn send(&self, value: T) -> Result<usize, SendError<T>> {
    let mut ledger = lock(&self.shared.ledger);
    if ledger.closed {
      return Err(SendError {
        kind: SendErrorKind::Closed,
        value,
      });
    }
    if ledger.active_receivers == 0 {
      return Err(SendError {
        kind: SendErrorKind::NoReceivers,
        value,
      });
    }
    let Some(next_sequence) = ledger.next_sequence.checked_add(1) else {
      ledger.closed = true;
      mark_waiters_for_wake(&mut ledger);
      drop(ledger);
      wake_all(&self.shared);
      return Err(SendError {
        kind: SendErrorKind::SequenceExhausted,
        value,
      });
    };

    let sequence = ledger.next_sequence;
    let receiver_count = ledger.active_receivers;
    let index = (sequence % ledger.messages.len() as u64) as usize;
    // Moving T into Arc invokes no user code. Allocation happens only after
    // the no-receiver, closed, and sequence checks.
    let payload = Arc::new(value);
    let retired = {
      let slot = &mut ledger.messages[index];
      slot.sequence = sequence;
      slot.remaining = receiver_count;
      slot.value.replace(payload)
    };
    ledger.next_sequence = next_sequence;
    for receiver in &mut ledger.receivers {
      if receiver.state == ReceiverState::Active && receiver.waker.is_some() {
        receiver.wake_pending = true;
      }
    }
    drop(ledger);

    drop_contained(retired);
    wake_all(&self.shared);
    Ok(receiver_count)
  }

  /// Creates a receiver starting at the current send sequence.
  pub fn subscribe(&self) -> Result<Receiver<T>, SubscribeError> {
    subscribe(&self.shared)
  }

  /// Explicitly closes the channel. Receivers can still drain retained values.
  pub fn close(&self) {
    {
      let mut ledger = lock(&self.shared.ledger);
      ledger.closed = true;
      mark_waiters_for_wake(&mut ledger);
    }
    wake_all(&self.shared);
  }

  /// Returns the number of active receivers.
  #[must_use]
  pub fn receiver_count(&self) -> usize {
    lock(&self.shared.ledger).active_receivers
  }

  /// Returns the configured maximum receiver count.
  #[must_use]
  pub fn max_receivers(&self) -> usize {
    lock(&self.shared.ledger).receivers.len()
  }

  /// Returns whether the channel has no active receivers.
  ///
  /// An explicit [`close`](Self::close) rejects future sends but does not
  /// count as receiver closure while existing receiver handles remain.
  #[must_use]
  pub fn is_closed(&self) -> bool {
    lock(&self.shared.ledger).active_receivers == 0
  }

  /// Waits until the active receiver count reaches zero.
  ///
  /// The bounded waiter capacity equals the channel's `max_receivers`. If
  /// that table is full, polling completes with [`ClosedError::Full`]. A
  /// receiver may subscribe after the count reaches zero, so this future
  /// checks the count again after each broadcast.
  pub fn closed(&self) -> SenderClosed<'_, T> {
    SenderClosed {
      sender: self,
      notified: Some(self.shared.closed_notify.notified_owned()),
      completed: false,
    }
  }
}

impl<T> Clone for Sender<T> {
  fn clone(&self) -> Self {
    let mut ledger = lock(&self.shared.ledger);
    let Some(sender_count) = ledger.sender_count.checked_add(1) else {
      panic!("broadcast sender count exhausted");
    };
    ledger.sender_count = sender_count;
    drop(ledger);
    Self {
      shared: Arc::clone(&self.shared),
      active: true,
    }
  }
}

impl<T> Drop for Sender<T> {
  fn drop(&mut self) {
    if !self.active {
      return;
    }
    self.active = false;
    let last = {
      let mut ledger = lock(&self.shared.ledger);
      if let Some(remaining) = ledger.sender_count.checked_sub(1) {
        ledger.sender_count = remaining;
        if remaining == 0 {
          ledger.closed = true;
          mark_waiters_for_wake(&mut ledger);
          true
        } else {
          false
        }
      } else {
        false
      }
    };
    if last {
      wake_all(&self.shared);
    }
  }
}

impl<T> Receiver<T> {
  /// Creates a receiver beginning at the current send sequence.
  pub fn resubscribe(&self) -> Result<Self, SubscribeError> {
    subscribe(&self.shared)
  }

  /// Attempts to receive one value without waiting.
  pub fn try_recv(&mut self) -> Result<T, TryRecvError>
  where
    T: Clone,
  {
    let mut unused_waker = None;
    match prepare_read(&self.shared, self.key, &mut unused_waker) {
      ReadAction::Value {
        sequence,
        value,
        old_waker,
      } => {
        drop_waker(old_waker);
        clone_and_commit(&self.shared, self.key, sequence, value).map_err(map_recv_error)
      }
      ReadAction::Empty(old_waker) => {
        drop_waker(old_waker);
        Err(TryRecvError::Empty)
      }
      ReadAction::Closed(old_waker) => {
        drop_waker(old_waker);
        Err(TryRecvError::Closed)
      }
      ReadAction::Lagged(skipped, old_waker) => {
        drop_waker(old_waker);
        Err(TryRecvError::Lagged(skipped))
      }
    }
  }

  /// Returns a future that waits for the next value.
  pub fn recv(&mut self) -> Recv<'_, T>
  where
    T: Clone,
  {
    Recv {
      receiver: self,
      completed: false,
    }
  }

  /// Returns the number of values sent since this receiver's cursor. This
  /// includes values that have been overwritten and would produce `Lagged`.
  #[must_use]
  pub fn len(&self) -> usize {
    let ledger = lock(&self.shared.ledger);
    let Some(cursor) = ledger.receiver_cursor(self.key) else {
      return 0;
    };
    usize::try_from(ledger.next_sequence.saturating_sub(cursor)).unwrap_or(usize::MAX)
  }

  /// Returns whether this receiver has no sent values waiting.
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.len() == 0
  }

  /// Returns whether all senders have closed the channel.
  #[must_use]
  pub fn is_closed(&self) -> bool {
    lock(&self.shared.ledger).closed
  }

  /// Returns whether two receivers share this channel.
  #[must_use]
  pub fn same_channel(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.shared, &other.shared)
  }
}

impl<T: Clone> Future for Recv<'_, T> {
  type Output = Result<T, RecvError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.completed {
      return Poll::Ready(Err(RecvError::Closed));
    }
    let mut new_waker = Some(cx.waker().clone());
    let action = prepare_read(&this.receiver.shared, this.receiver.key, &mut new_waker);
    drop_waker(new_waker);
    match action {
      ReadAction::Value {
        sequence,
        value,
        old_waker,
      } => {
        drop_waker(old_waker);
        let result = clone_and_commit(&this.receiver.shared, this.receiver.key, sequence, value);
        this.completed = true;
        Poll::Ready(result)
      }
      ReadAction::Empty(old_waker) => {
        drop_waker(old_waker);
        Poll::Pending
      }
      ReadAction::Closed(old_waker) => {
        drop_waker(old_waker);
        this.completed = true;
        Poll::Ready(Err(RecvError::Closed))
      }
      ReadAction::Lagged(skipped, old_waker) => {
        drop_waker(old_waker);
        this.completed = true;
        Poll::Ready(Err(RecvError::Lagged(skipped)))
      }
    }
  }
}

impl<T> Future for SenderClosed<'_, T> {
  type Output = Result<(), ClosedError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.completed {
      return Poll::Ready(Err(ClosedError::Completed));
    }
    let mut rearmed = 0;
    loop {
      if this.sender.is_closed() {
        this.completed = true;
        this.notified.take();
        return Poll::Ready(Ok(()));
      }
      let Some(notified) = this.notified.as_mut() else {
        this.completed = true;
        return Poll::Ready(Err(ClosedError::Completed));
      };
      let result = panic::catch_unwind(AssertUnwindSafe(|| Pin::new(notified).poll(cx)));
      match result {
        Ok(Poll::Pending) => return Poll::Pending,
        Ok(Poll::Ready(Ok(()))) => {
          // Capture the next broadcast before checking the live receiver
          // count, avoiding a lost zero transition during this poll.
          this.notified = Some(this.sender.shared.closed_notify.notified_owned());
          rearmed += 1;
          if rearmed == CLOSED_POLL_BUDGET {
            if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| cx.waker().wake_by_ref()))
            {
              drop_contained(payload);
              this.completed = true;
              this.notified.take();
              return Poll::Ready(Err(ClosedError::WakerPanicked));
            }
            return Poll::Pending;
          }
        }
        Ok(Poll::Ready(Err(NotifyError::Full))) => {
          this.completed = true;
          this.notified.take();
          return Poll::Ready(Err(ClosedError::Full));
        }
        Ok(Poll::Ready(Err(NotifyError::Closed | NotifyError::GenerationExhausted))) => {
          this.completed = true;
          this.notified.take();
          return Poll::Ready(Err(ClosedError::Exhausted));
        }
        Err(payload) => {
          drop_contained(payload);
          this.completed = true;
          this.notified.take();
          return Poll::Ready(Err(ClosedError::WakerPanicked));
        }
      }
    }
  }
}

impl<T> Drop for Recv<'_, T> {
  fn drop(&mut self) {
    if !self.completed {
      clear_waiter(&self.receiver.shared, self.receiver.key);
    }
  }
}

impl<T> Drop for Receiver<T> {
  fn drop(&mut self) {
    drop_receiver(&self.shared, self.key);
  }
}

impl<T> fmt::Debug for Sender<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let (closed, senders, receivers, capacity, max_receivers) = {
      let ledger = lock(&self.shared.ledger);
      (
        ledger.closed,
        ledger.sender_count,
        ledger.active_receivers,
        ledger.messages.len(),
        ledger.receivers.len(),
      )
    };
    f.debug_struct("BroadcastSender")
      .field("closed", &closed)
      .field("senders", &senders)
      .field("receivers", &receivers)
      .field("capacity", &capacity)
      .field("max_receivers", &max_receivers)
      .finish()
  }
}

impl<T> fmt::Debug for Receiver<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let (closed, cursor, next_sequence, capacity) = {
      let ledger = lock(&self.shared.ledger);
      (
        ledger.closed,
        ledger.receiver_cursor(self.key),
        ledger.next_sequence,
        ledger.messages.len(),
      )
    };
    f.debug_struct("BroadcastReceiver")
      .field("closed", &closed)
      .field("cursor", &cursor)
      .field("next_sequence", &next_sequence)
      .field("capacity", &capacity)
      .finish()
  }
}

enum ReadAction<T> {
  Value {
    sequence: u64,
    value: Arc<T>,
    old_waker: Option<Waker>,
  },
  Empty(Option<Waker>),
  Closed(Option<Waker>),
  Lagged(u64, Option<Waker>),
}

fn map_recv_error(error: RecvError) -> TryRecvError {
  match error {
    RecvError::Closed => TryRecvError::Closed,
    RecvError::Lagged(skipped) => TryRecvError::Lagged(skipped),
  }
}

impl<T> Ledger<T> {
  fn allocate_receiver(&mut self, cursor: u64) -> Option<ReceiverKey> {
    let index = self.free_head?;
    let active_receivers = self.active_receivers.checked_add(1)?;
    let receiver = &mut self.receivers[index];
    if receiver.state != ReceiverState::Free {
      return None;
    }
    self.free_head = receiver.free_next;
    receiver.free_next = None;
    receiver.state = ReceiverState::Active;
    receiver.cursor = cursor;
    receiver.waker = None;
    receiver.wake_pending = false;
    self.active_receivers = active_receivers;
    Some(ReceiverKey {
      index,
      generation: receiver.generation,
    })
  }

  fn valid_receiver(&self, key: ReceiverKey) -> Option<ReceiverState> {
    let slot = self.receivers.get(key.index)?;
    (slot.generation == key.generation).then_some(slot.state)
  }

  fn receiver_cursor(&self, key: ReceiverKey) -> Option<u64> {
    let slot = self.receivers.get(key.index)?;
    (slot.generation == key.generation && slot.state == ReceiverState::Active)
      .then_some(slot.cursor)
  }

  fn recycle_receiver(&mut self, index: usize) -> Option<Waker> {
    let receiver = &mut self.receivers[index];
    let waker = receiver.waker.take();
    receiver.wake_pending = false;
    receiver.free_next = None;
    if let Some(generation) = receiver.generation.checked_add(1) {
      receiver.generation = generation;
      receiver.state = ReceiverState::Free;
      receiver.free_next = self.free_head;
      self.free_head = Some(index);
    } else {
      receiver.state = ReceiverState::Retired;
    }
    waker
  }
}

fn subscribe<T>(shared: &Arc<Shared<T>>) -> Result<Receiver<T>, SubscribeError> {
  let key = {
    let mut ledger = lock(&shared.ledger);
    if ledger.closed {
      return Err(SubscribeError::Closed);
    }
    let cursor = ledger.next_sequence;
    let Some(key) = ledger.allocate_receiver(cursor) else {
      return Err(SubscribeError::Full);
    };
    key
  };
  Ok(Receiver {
    shared: Arc::clone(shared),
    key,
  })
}

fn prepare_read<T>(
  shared: &Arc<Shared<T>>,
  key: ReceiverKey,
  new_waker: &mut Option<Waker>,
) -> ReadAction<T> {
  let mut ledger = lock(&shared.ledger);
  if ledger.valid_receiver(key) != Some(ReceiverState::Active) {
    return ReadAction::Closed(None);
  }

  let cursor = ledger.receivers[key.index].cursor;
  let oldest = ledger
    .next_sequence
    .saturating_sub(ledger.messages.len() as u64);

  if cursor < oldest {
    let skipped = oldest - cursor;
    let receiver = &mut ledger.receivers[key.index];
    receiver.cursor = oldest;
    receiver.wake_pending = false;
    let old_waker = receiver.waker.take();
    drop(ledger);
    return ReadAction::Lagged(skipped, old_waker);
  }

  if cursor < ledger.next_sequence {
    let index = (cursor % ledger.messages.len() as u64) as usize;
    let slot = &ledger.messages[index];
    if slot.sequence == cursor
      && let Some(value) = slot.value.as_ref()
    {
      let value = Arc::clone(value);
      let receiver = &mut ledger.receivers[key.index];
      receiver.wake_pending = false;
      let old_waker = receiver.waker.take();
      drop(ledger);
      return ReadAction::Value {
        sequence: cursor,
        value,
        old_waker,
      };
    }
    // A slot mismatch means the cursor has fallen behind a concurrent wrap.
    // Recompute against the current tail on the next poll; normal send ordering
    // makes this reachable only at sequence exhaustion or after overwrite.
  }

  let closed = ledger.closed;
  let receiver = &mut ledger.receivers[key.index];
  receiver.wake_pending = false;
  let old_waker = if closed || new_waker.is_none() {
    receiver.waker.take()
  } else if let Some(new_waker) = new_waker.take() {
    receiver.waker.replace(new_waker)
  } else {
    None
  };
  drop(ledger);
  if closed {
    ReadAction::Closed(old_waker)
  } else {
    ReadAction::Empty(old_waker)
  }
}

fn clone_and_commit<T: Clone>(
  shared: &Arc<Shared<T>>,
  key: ReceiverKey,
  sequence: u64,
  value: Arc<T>,
) -> Result<T, RecvError> {
  let cloned = panic::catch_unwind(AssertUnwindSafe(|| value.as_ref().clone()));
  match cloned {
    Ok(cloned) => {
      let (retired, committed) = {
        let mut ledger = lock(&shared.ledger);
        if ledger.valid_receiver(key) != Some(ReceiverState::Active)
          || ledger.receivers[key.index].cursor != sequence
        {
          (None, false)
        } else {
          if let Some(next) = sequence.checked_add(1) {
            ledger.receivers[key.index].cursor = next;
            let index = (sequence % ledger.messages.len() as u64) as usize;
            let slot = &mut ledger.messages[index];
            let retired = if slot.sequence == sequence && slot.value.is_some() {
              if slot.remaining > 0 {
                slot.remaining -= 1;
              }
              if slot.remaining == 0 {
                slot.value.take()
              } else {
                None
              }
            } else {
              None
            };
            (retired, true)
          } else {
            (None, false)
          }
        }
      };
      drop_contained(value);
      drop_contained(retired);
      if committed {
        Ok(cloned)
      } else {
        Err(RecvError::Closed)
      }
    }
    Err(payload) => {
      // The cursor and per-message count are unchanged, so retrying preserves
      // the message unless ordinary ring overwrite has made it lagged.
      drop_contained(value);
      panic::resume_unwind(payload)
    }
  }
}

fn clear_waiter<T>(shared: &Arc<Shared<T>>, key: ReceiverKey) {
  let old_waker = {
    let mut ledger = lock(&shared.ledger);
    if ledger.valid_receiver(key) != Some(ReceiverState::Active) {
      return;
    }
    let receiver = &mut ledger.receivers[key.index];
    receiver.wake_pending = false;
    receiver.waker.take()
  };
  drop_waker(old_waker);
}

fn wake_all<T>(shared: &Arc<Shared<T>>) {
  let capacity = lock(&shared.ledger).receivers.len();
  for index in 0..capacity {
    let waker = {
      let mut ledger = lock(&shared.ledger);
      let receiver = &mut ledger.receivers[index];
      if receiver.state == ReceiverState::Active && receiver.wake_pending {
        receiver.wake_pending = false;
        receiver.waker.take()
      } else {
        None
      }
    };
    wake_contained(waker);
  }
}

fn mark_waiters_for_wake<T>(ledger: &mut Ledger<T>) {
  for receiver in &mut ledger.receivers {
    if receiver.state == ReceiverState::Active && receiver.waker.is_some() {
      receiver.wake_pending = true;
    }
  }
}

fn drop_receiver<T>(shared: &Arc<Shared<T>>, key: ReceiverKey) {
  let (cursor, until, waker, last_receiver) = {
    let mut ledger = lock(&shared.ledger);
    if ledger.valid_receiver(key) != Some(ReceiverState::Active) {
      return;
    }
    let Some(active) = ledger.active_receivers.checked_sub(1) else {
      return;
    };
    ledger.active_receivers = active;
    let until = ledger.next_sequence;
    let receiver = &mut ledger.receivers[key.index];
    receiver.state = ReceiverState::Dropping;
    receiver.wake_pending = false;
    (receiver.cursor, until, receiver.waker.take(), active == 0)
  };
  if last_receiver {
    let _ = shared.closed_notify.notify_waiters();
  }
  drop_waker(waker);

  let capacity = lock(&shared.ledger).messages.len();
  for index in 0..capacity {
    let retired = {
      let mut ledger = lock(&shared.ledger);
      let slot = &mut ledger.messages[index];
      if slot.value.is_some() && slot.sequence >= cursor && slot.sequence < until {
        if slot.remaining > 0 {
          slot.remaining -= 1;
        }
        if slot.remaining == 0 {
          slot.value.take()
        } else {
          None
        }
      } else {
        None
      }
    };
    drop_contained(retired);
  }

  let old_waker = {
    let mut ledger = lock(&shared.ledger);
    if ledger.valid_receiver(key) == Some(ReceiverState::Dropping) {
      ledger.recycle_receiver(key.index)
    } else {
      None
    }
  };
  drop_waker(old_waker);
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

impl<T> Drop for Ledger<T> {
  fn drop(&mut self) {
    for receiver in &mut self.receivers {
      drop_waker(receiver.waker.take());
    }
    for message in &mut self.messages {
      drop_contained(message.value.take());
    }
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use std::future::Future;
  use std::panic::AssertUnwindSafe;
  use std::pin::Pin;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::{Arc, Mutex};
  use std::task::{Context, Poll, Wake, Waker};

  use super::{BroadcastBuildError, RecvError, SendErrorKind, TryRecvError, channel};

  fn noop_waker() -> Waker {
    (*Waker::noop()).clone()
  }

  fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    let mut context = Context::from_waker(waker);
    future.poll(&mut context)
  }

  #[test]
  fn validates_fixed_bounds_and_fails_overflow() {
    assert!(matches!(
      channel::<u8>(0, 1),
      Err(BroadcastBuildError::ZeroCapacity)
    ));
    assert!(matches!(
      channel::<u8>(1, 0),
      Err(BroadcastBuildError::ZeroReceivers)
    ));
    assert!(matches!(
      channel::<u8>(usize::MAX, 1),
      Err(BroadcastBuildError::CapacityOverflow)
    ));
  }

  #[test]
  fn broadcasts_in_order_and_subscribe_starts_at_tail() {
    let (sender, mut first) = channel(4, 3).unwrap();
    assert_eq!(sender.send(10).unwrap(), 1);
    let mut second = sender.subscribe().unwrap();
    assert_eq!(sender.send(20).unwrap(), 2);
    assert_eq!(first.try_recv(), Ok(10));
    assert_eq!(first.try_recv(), Ok(20));
    assert_eq!(second.try_recv(), Ok(20));
  }

  #[test]
  fn lagged_reports_exact_skips_then_returns_oldest_retained() {
    let (sender, mut slow) = channel(2, 1).unwrap();
    sender.send(1).unwrap();
    sender.send(2).unwrap();
    sender.send(3).unwrap();
    assert_eq!(slow.try_recv(), Err(TryRecvError::Lagged(1)));
    assert_eq!(slow.try_recv(), Ok(2));
    assert_eq!(slow.try_recv(), Ok(3));
  }

  #[test]
  fn no_receiver_and_closed_send_return_the_original_value() {
    let (sender, receiver) = channel(2, 1).unwrap();
    drop(receiver);
    let error = sender.send(String::from("kept")).unwrap_err();
    assert_eq!(error.kind, SendErrorKind::NoReceivers);
    assert_eq!(error.into_inner(), "kept");

    let mut receiver = sender.subscribe().unwrap();
    sender.close();
    let error = sender.send(String::from("also kept")).unwrap_err();
    assert_eq!(error.kind, SendErrorKind::Closed);
    assert_eq!(error.into_inner(), "also kept");
    assert_eq!(receiver.try_recv(), Err(TryRecvError::Closed));
  }

  #[test]
  fn last_sender_closes_after_receivers_drain_retained_values() {
    let (sender, mut receiver) = channel(2, 1).unwrap();
    sender.send(1).unwrap();
    sender.send(2).unwrap();
    drop(sender);
    assert_eq!(receiver.try_recv(), Ok(1));
    assert_eq!(receiver.try_recv(), Ok(2));
    assert_eq!(receiver.try_recv(), Err(TryRecvError::Closed));
  }

  #[test]
  fn receiver_table_is_bounded_and_slots_reuse_after_drop() {
    let (sender, receiver) = channel::<u8>(1, 2).unwrap();
    let second = sender.subscribe().unwrap();
    assert!(matches!(
      sender.subscribe(),
      Err(super::SubscribeError::Full)
    ));
    drop(second);
    let third = sender.subscribe().unwrap();
    assert_eq!(sender.receiver_count(), 2);
    drop((receiver, third));
    assert_eq!(sender.receiver_count(), 0);
  }

  #[test]
  fn thread_safe_payloads_make_arc_backed_handles_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<super::Sender<u8>>();
    assert_send_sync::<super::Receiver<u8>>();
  }

  #[test]
  fn sender_closed_wait_is_bounded_and_tracks_receiver_resubscription() {
    let (sender, receiver) = channel::<u8>(1, 1).unwrap();
    let mut first = Box::pin(sender.closed());
    let mut full = Box::pin(sender.closed());
    let waker = noop_waker();
    assert!(poll(first.as_mut(), &waker).is_pending());
    assert_eq!(
      poll(full.as_mut(), &waker),
      Poll::Ready(Err(super::ClosedError::Full))
    );

    drop(receiver);
    let replacement = sender.subscribe().unwrap();
    assert!(!sender.is_closed());
    // The old zero-receiver broadcast cannot close a future while a new
    // receiver has already occupied the bounded slot.
    assert!(poll(first.as_mut(), &waker).is_pending());
    drop(replacement);
    assert_eq!(poll(first.as_mut(), &waker), Poll::Ready(Ok(())));
    assert!(sender.is_closed());
  }

  #[test]
  fn completed_sender_closed_future_releases_its_waiter_slot() {
    let (sender, receiver) = channel::<u8>(1, 1).unwrap();
    let mut closed = Box::pin(sender.closed());
    let waker = noop_waker();
    assert!(poll(closed.as_mut(), &waker).is_pending());
    drop(receiver);
    assert_eq!(poll(closed.as_mut(), &waker), Poll::Ready(Ok(())));

    let _receiver = sender.subscribe().unwrap();
    let mut next_closed = Box::pin(sender.closed());
    assert!(poll(next_closed.as_mut(), &waker).is_pending());
  }

  #[test]
  fn explicit_close_waits_for_receiver_handles_to_drop() {
    let (sender, receiver) = channel::<u8>(1, 1).unwrap();
    sender.close();
    assert!(!sender.is_closed());
    let mut closed = Box::pin(sender.closed());
    let waker = noop_waker();
    assert!(poll(closed.as_mut(), &waker).is_pending());
    drop(receiver);
    assert_eq!(poll(closed.as_mut(), &waker), Poll::Ready(Ok(())));
    assert!(sender.is_closed());
  }

  #[test]
  fn receiver_slot_retires_instead_of_wrapping_its_generation() {
    let (sender, mut receiver) = channel::<u8>(1, 1).unwrap();
    {
      let mut ledger = super::lock(&sender.shared.ledger);
      ledger.receivers[0].generation = u64::MAX;
      receiver.key.generation = u64::MAX;
    }
    drop(receiver);
    assert!(matches!(
      sender.subscribe(),
      Err(super::SubscribeError::Full)
    ));
  }

  #[test]
  fn sequence_exhaustion_closes_without_losing_the_rejected_value() {
    let (sender, mut receiver) = channel::<u8>(1, 1).unwrap();
    {
      let mut ledger = super::lock(&sender.shared.ledger);
      ledger.next_sequence = u64::MAX;
      ledger.receivers[0].cursor = u64::MAX;
    }
    let error = sender.send(42).unwrap_err();
    assert_eq!(error.kind, SendErrorKind::SequenceExhausted);
    assert_eq!(error.into_inner(), 42);
    assert_eq!(receiver.try_recv(), Err(TryRecvError::Closed));
  }

  #[test]
  fn receiver_drop_releases_payload_without_waiting_for_ring_overwrite() {
    struct DropCount(Arc<AtomicUsize>);
    impl Clone for DropCount {
      fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
      }
    }
    impl Drop for DropCount {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let (sender, receiver) = channel(1, 1).unwrap();
    sender.send(DropCount(Arc::clone(&drops))).unwrap();
    drop(receiver);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn dropping_last_payload_runs_user_drop_after_releasing_channel_lock() {
    struct ReenterDrop {
      sender: super::Sender<ReenterDrop>,
      drops: Arc<AtomicUsize>,
    }
    impl Clone for ReenterDrop {
      fn clone(&self) -> Self {
        Self {
          sender: self.sender.clone(),
          drops: Arc::clone(&self.drops),
        }
      }
    }
    impl Drop for ReenterDrop {
      fn drop(&mut self) {
        if self.drops.fetch_add(1, Ordering::SeqCst) == 0 {
          let _ = self.sender.send(Self {
            sender: self.sender.clone(),
            drops: Arc::clone(&self.drops),
          });
        }
      }
    }

    let (sender, receiver) = channel::<ReenterDrop>(1, 1).unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    sender
      .send(ReenterDrop {
        sender: sender.clone(),
        drops: Arc::clone(&drops),
      })
      .unwrap();
    drop(receiver);
    assert!(drops.load(Ordering::SeqCst) >= 2);
  }

  #[test]
  fn cancelled_recv_removes_its_waker() {
    let (sender, mut receiver) = channel::<u8>(1, 1).unwrap();
    let mut receive = Box::pin(receiver.recv());
    assert!(poll(receive.as_mut(), &noop_waker()).is_pending());
    drop(receive);
    sender.send(4).unwrap();
    assert_eq!(receiver.try_recv(), Ok(4));
  }

  #[test]
  fn panicking_clone_does_not_advance_cursor_or_corrupt_ring() {
    struct PanicClone(Arc<AtomicUsize>);
    impl Clone for PanicClone {
      fn clone(&self) -> Self {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
          panic!("clone panic");
        }
        Self(Arc::clone(&self.0))
      }
    }

    let clones = Arc::new(AtomicUsize::new(0));
    let (sender, mut receiver) = channel(2, 1).unwrap();
    sender.send(PanicClone(Arc::clone(&clones))).unwrap();
    let panic = std::panic::catch_unwind(AssertUnwindSafe(|| receiver.try_recv()));
    assert!(panic.is_err());
    assert!(receiver.try_recv().is_ok());
  }

  #[test]
  fn clone_and_drop_callbacks_can_reenter_channel() {
    struct Reenter {
      sender: Arc<Mutex<Option<super::Sender<Reenter>>>>,
      cloned: Arc<AtomicUsize>,
    }
    impl Clone for Reenter {
      fn clone(&self) -> Self {
        if self.cloned.fetch_add(1, Ordering::SeqCst) == 0
          && let Some(sender) = self.sender.lock().unwrap().as_ref()
        {
          let _ = sender.send(Self {
            sender: Arc::clone(&self.sender),
            cloned: Arc::clone(&self.cloned),
          });
        }
        Self {
          sender: Arc::clone(&self.sender),
          cloned: Arc::clone(&self.cloned),
        }
      }
    }

    let (sender, mut receiver) = channel::<Reenter>(1, 1).unwrap();
    let shared_sender = Arc::new(Mutex::new(Some(sender.clone())));
    let cloned = Arc::new(AtomicUsize::new(0));
    sender
      .send(Reenter {
        sender: Arc::clone(&shared_sender),
        cloned: Arc::clone(&cloned),
      })
      .unwrap();
    assert!(receiver.try_recv().is_ok());
    assert!(receiver.try_recv().is_ok());
    assert_eq!(cloned.load(Ordering::SeqCst), 2);
    assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
  }

  #[test]
  fn overwritten_arc_managed_payload_retains_its_permit_until_last_clone_drops() {
    use crate::runtime::managed::{ResourceLimits, ResourceScope};

    let scope = ResourceScope::new(ResourceLimits {
      managed_memory: 8,
      disk_concurrent_ops: 0,
      network_concurrent_ops: 0,
    });
    let (sender, mut first) = channel::<Arc<_>>(1, 2).unwrap();
    let mut second = sender.subscribe().unwrap();

    let original = Arc::new(scope.try_alloc_zeroed(4).unwrap());
    sender.send(original).unwrap();
    let retained = first.try_recv().unwrap();
    assert_eq!(scope.snapshot().managed_memory, 4);

    let replacement = Arc::new(scope.try_alloc_zeroed(4).unwrap());
    sender.send(replacement).unwrap();
    assert_eq!(scope.snapshot().managed_memory, 8);
    assert!(matches!(second.try_recv(), Err(TryRecvError::Lagged(1))));
    assert_eq!(second.try_recv().unwrap().len(), 4);
    drop(retained);
    assert_eq!(scope.snapshot().managed_memory, 4);

    drop((first, second, sender));
    assert_eq!(scope.snapshot().managed_memory, 0);
  }

  struct CountWake(Arc<AtomicUsize>);
  impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  #[test]
  fn send_wakes_waiting_receiver_outside_channel_lock() {
    let (sender, mut receiver) = channel(1, 1).unwrap();
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountWake(Arc::clone(&wakes))));
    let mut receive = Box::pin(receiver.recv());
    assert!(poll(receive.as_mut(), &waker).is_pending());
    sender.send(7).unwrap();
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    assert_eq!(poll(receive.as_mut(), &waker), Poll::Ready(Ok(7)));
  }

  #[test]
  fn panicking_waker_and_panicking_payload_drop_are_contained() {
    struct PanicPayload(Arc<AtomicUsize>);
    impl Drop for PanicPayload {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("panic while dropping panic payload");
      }
    }
    struct PanicWake(Arc<AtomicUsize>);
    impl Wake for PanicWake {
      fn wake(self: Arc<Self>) {
        std::panic::panic_any(PanicPayload(Arc::clone(&self.0)));
      }
      fn wake_by_ref(self: &Arc<Self>) {
        std::panic::panic_any(PanicPayload(Arc::clone(&self.0)));
      }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let (sender, mut receiver) = channel(1, 1).unwrap();
    let waker = Waker::from(Arc::new(PanicWake(Arc::clone(&drops))));
    let mut receive = Box::pin(receiver.recv());
    assert!(poll(receive.as_mut(), &waker).is_pending());
    sender.send(42).unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(poll(receive.as_mut(), &noop_waker()), Poll::Ready(Ok(42)));
  }

  #[test]
  fn wake_callback_can_reenter_channel_state() {
    struct ReenterWake(super::Sender<u8>, Arc<AtomicUsize>);
    impl Wake for ReenterWake {
      fn wake(self: Arc<Self>) {
        self.1.store(self.0.receiver_count(), Ordering::SeqCst);
      }
    }

    let (sender, mut receiver) = channel(1, 1).unwrap();
    let observed = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(ReenterWake(sender.clone(), Arc::clone(&observed))));
    let mut receive = Box::pin(receiver.recv());
    assert!(poll(receive.as_mut(), &waker).is_pending());
    sender.send(8).unwrap();
    assert_eq!(observed.load(Ordering::SeqCst), 1);
    assert_eq!(poll(receive.as_mut(), &waker), Poll::Ready(Ok(8)));
  }

  #[test]
  fn explicit_close_and_last_sender_drop_wake_empty_receivers() {
    let (sender, mut receiver) = channel::<u8>(1, 1).unwrap();
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountWake(Arc::clone(&wakes))));
    let mut receive = Box::pin(receiver.recv());
    assert!(poll(receive.as_mut(), &waker).is_pending());
    sender.close();
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    assert_eq!(
      poll(receive.as_mut(), &waker),
      Poll::Ready(Err(RecvError::Closed))
    );
    drop(receive);

    let (sender, mut receiver) = channel::<u8>(1, 1).unwrap();
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountWake(Arc::clone(&wakes))));
    let mut receive = Box::pin(receiver.recv());
    assert!(poll(receive.as_mut(), &waker).is_pending());
    drop(sender);
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    assert_eq!(
      poll(receive.as_mut(), &waker),
      Poll::Ready(Err(RecvError::Closed))
    );
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use std::future::Future;
  use std::pin::Pin;
  use std::sync::Arc as StdArc;
  use std::task::{Context, Wake, Waker};

  use loom::sync::Arc;
  use loom::sync::atomic::{AtomicUsize, Ordering};
  use loom::thread;

  use super::channel;

  struct CountWake(Arc<AtomicUsize>);
  impl Wake for CountWake {
    fn wake(self: StdArc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> std::task::Poll<F::Output> {
    let mut context = Context::from_waker(waker);
    future.poll(&mut context)
  }

  #[test]
  fn send_racing_with_receive_registration_cannot_lose_wake() {
    loom::model(|| {
      let (sender, mut receiver) = channel(1, 1).unwrap();
      let wakes = Arc::new(AtomicUsize::new(0));
      let waker = Waker::from(StdArc::new(CountWake(Arc::clone(&wakes))));
      let mut receive = Box::pin(receiver.recv());
      let send = thread::spawn(move || sender.send(9));
      let first = poll(receive.as_mut(), &waker);
      send.join().unwrap().unwrap();
      match first {
        std::task::Poll::Pending => {
          assert!(wakes.load(Ordering::SeqCst) > 0);
          assert!(matches!(
            poll(receive.as_mut(), &waker),
            std::task::Poll::Ready(Ok(9))
          ));
        }
        std::task::Poll::Ready(Ok(9)) => {}
        other => panic!("unexpected first poll: {other:?}"),
      }
    });
  }

  #[test]
  fn receiver_drop_racing_with_send_preserves_active_receiver_payload() {
    loom::model(|| {
      let (sender, first) = channel(1, 2).unwrap();
      let mut second = sender.subscribe().unwrap();
      let first_shared = Arc::new(loom::sync::Mutex::new(Some(first)));
      let dropper = Arc::clone(&first_shared);
      let drop_first = thread::spawn(move || drop(dropper.lock().unwrap().take()));
      let sending = sender.clone();
      let send = thread::spawn(move || sending.send(11));
      drop_first.join().unwrap();
      let result = send.join().unwrap();
      let eligible_receivers = result.unwrap();
      assert!((1..=2).contains(&eligible_receivers));
      assert_eq!(second.try_recv(), Ok(11));
    });
  }

  #[test]
  fn last_receiver_drop_racing_sender_closed_poll_cannot_lose_notification() {
    loom::model(|| {
      let (sender, receiver) = channel::<u8>(1, 1).unwrap();
      let dropper = thread::spawn(move || drop(receiver));
      let mut closed = Box::pin(sender.closed());
      let wakes = Arc::new(AtomicUsize::new(0));
      let waker = Waker::from(StdArc::new(CountWake(Arc::clone(&wakes))));
      let first = poll(closed.as_mut(), &waker);
      dropper.join().unwrap();
      match first {
        std::task::Poll::Pending => {
          assert!(wakes.load(Ordering::SeqCst) > 0);
          assert_eq!(
            poll(closed.as_mut(), &waker),
            std::task::Poll::Ready(Ok(()))
          );
        }
        std::task::Poll::Ready(Ok(())) => {}
        other => panic!("unexpected first closed poll: {other:?}"),
      }
    });
  }
}
