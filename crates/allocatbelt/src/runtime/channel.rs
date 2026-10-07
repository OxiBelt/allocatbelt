//! A bounded, single-receiver asynchronous message channel.
//!
//! The queue storage is allocated when [`channel`] is constructed. Each
//! queued message owns one private semaphore permit, so its slot stays
//! reserved until a receiver removes it. The semaphore also provides FIFO
//! admission to waiting send futures. `max_waiters` bounds those futures.
//! Concurrent send futures that already received permits enqueue in poll
//! order, so the channel does not promise FIFO message order across senders.
//!
//! The channel owns messages after enqueue. Closing the receiver rejects new
//! sends and wakes queued senders, while already-issued [`Permit`]s remain
//! valid and can publish a message as the receiver drains. EOF waits for those
//! permits to be sent or dropped. [`Sender::closed`] uses a separate bounded
//! waiter table. Dropping the receiver revokes unused permits and drops queued
//! messages after releasing the queue lock. Dropping an
//! unsubmitted [`SendFuture`] cancels its wait and drops its offered value
//! outside the queue lock; [`SendFuture::into_inner`] can recover that value
//! before it is submitted.
//!
//! Managed buffers keep their own accounting while held by the send future,
//! queued message, or receiver. Queue metadata is not part of that ledger.
//!
//! ```compile_fail
//! use allocatbelt::runtime::channel::Sender;
//! use std::rc::Rc;
//! fn require_send<T: Send>() {}
//! require_send::<Sender<Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::channel::Receiver;
//! use std::rc::Rc;
//! fn require_send<T: Send>() {}
//! require_send::<Receiver<Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::channel::SendFuture;
//! use std::rc::Rc;
//! fn require_send<T: Send>() {}
//! require_send::<SendFuture<Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::channel::RecvFuture;
//! use std::rc::Rc;
//! fn require_send<T: Send>() {}
//! require_send::<RecvFuture<'static, Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::channel::OwnedReserveFuture;
//! use std::rc::Rc;
//! fn require_send<T: Send>() {}
//! require_send::<OwnedReserveFuture<Rc<()>>>();
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

#[cfg(loom)]
use loom::sync::{Arc, Mutex, MutexGuard};
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::PoisonError;
#[cfg(not(loom))]
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use super::semaphore::{
  AcquireError, AcquireMany, Permit as SemaphorePermit, Semaphore, SemaphoreBuildError,
};
use super::task::drop_contained;

/// Constructs a bounded channel with a fixed message capacity and waiter
/// bound. A zero message capacity is invalid.
pub fn channel<T>(
  capacity: usize,
  max_waiters: usize,
) -> Result<(Sender<T>, Receiver<T>), BuildError> {
  if capacity == 0 {
    return Err(BuildError::ZeroCapacity);
  }
  let bytes = capacity
    .checked_mul(std::mem::size_of::<Envelope<T>>())
    .ok_or(BuildError::CapacityOverflow)?;
  if bytes > isize::MAX as usize {
    return Err(BuildError::CapacityOverflow);
  }
  let waiter_bytes = max_waiters
    .checked_mul(std::mem::size_of::<ClosedWaiterSlot>())
    .ok_or(BuildError::CapacityOverflow)?;
  if waiter_bytes > isize::MAX as usize {
    return Err(BuildError::CapacityOverflow);
  }

  let mut queue = VecDeque::new();
  queue
    .try_reserve_exact(capacity)
    .map_err(|_| BuildError::AllocationFailed)?;
  let mut closed_waiters = Vec::new();
  closed_waiters
    .try_reserve_exact(max_waiters)
    .map_err(|_| BuildError::AllocationFailed)?;
  closed_waiters.resize_with(max_waiters, ClosedWaiterSlot::new);
  let permits = Semaphore::new(capacity, max_waiters).map_err(|error| match error {
    SemaphoreBuildError::CapacityOverflow => BuildError::CapacityOverflow,
    SemaphoreBuildError::AllocationFailed => BuildError::AllocationFailed,
  })?;
  let shared = Arc::new(Shared {
    state: Mutex::new(QueueState {
      queue,
      closed: false,
      receiver_dropped: false,
      senders_gone: false,
      public_reservations: 0,
      receiver_waker: None,
      closed_waiters,
    }),
    permits,
  });
  let send_side = Arc::new(SendSide {
    shared: Arc::clone(&shared),
  });

  Ok((
    Sender {
      side: Arc::clone(&send_side),
    },
    Receiver { shared },
  ))
}

/// Why channel construction failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
  /// A channel must have room for at least one message.
  ZeroCapacity,
  /// The requested queue or waiter storage exceeded representable bounds.
  CapacityOverflow,
  /// The queue or waiter storage could not be reserved.
  AllocationFailed,
}

impl fmt::Display for BuildError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::ZeroCapacity => "channel capacity must be nonzero",
      Self::CapacityOverflow => "channel capacity overflowed",
      Self::AllocationFailed => "channel storage allocation failed",
    })
  }
}

impl std::error::Error for BuildError {}

/// Why a send was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendErrorKind {
  /// The channel has no free slot or its bounded waiter table is full.
  Full,
  /// The receiver has closed or been dropped.
  Closed,
}

/// Why a reservation could not be returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReserveError {
  /// The receiver closed before the reservation was published.
  Closed,
  /// The bounded semaphore waiter table is full.
  WaitersFull,
  /// The reservation future has already completed.
  Completed,
}

impl fmt::Display for ReserveError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Closed => "channel is closed",
      Self::WaitersFull => "channel waiter table is full",
      Self::Completed => "reservation future has completed",
    })
  }
}

impl std::error::Error for ReserveError {}

/// Why a [`Sender::closed`] waiter could not be registered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClosedWaitError {
  /// The bounded closed-waiter table has no free entry.
  WaitersFull,
  /// Every waiter entry has exhausted its generation counter.
  GenerationExhausted,
}

impl fmt::Display for ClosedWaitError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::WaitersFull => "closed waiter table is full",
      Self::GenerationExhausted => "closed waiter generations are exhausted",
    })
  }
}

impl std::error::Error for ClosedWaitError {}

impl fmt::Display for SendErrorKind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Full => "channel is full",
      Self::Closed => "channel is closed",
    })
  }
}

/// A rejected value returned to its sender.
pub struct SendError<T> {
  kind: SendErrorKind,
  value: T,
}

impl<T> SendError<T> {
  /// Returns why the value was rejected.
  #[must_use]
  pub const fn kind(&self) -> SendErrorKind {
    self.kind
  }

  /// Returns the original value.
  #[must_use]
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
    self.kind.fmt(f)
  }
}

impl<T: fmt::Debug> std::error::Error for SendError<T> {}

/// Why a nonblocking receive could not return a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TryRecvError {
  /// No message is queued yet.
  Empty,
  /// The channel is closed, queued messages are consumed, and reservations
  /// have been sent or dropped.
  Closed,
}

impl fmt::Display for TryRecvError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Empty => "channel is empty",
      Self::Closed => "channel is closed",
    })
  }
}

impl std::error::Error for TryRecvError {}

/// A cloneable sending handle. The last sender and all pending send futures
/// must be dropped before the receiver observes end-of-stream. A completed
/// send future releases its send-side reference when it returns `Ready`.
pub struct Sender<T> {
  side: Arc<SendSide<T>>,
}

/// The unique receiving handle.
pub struct Receiver<T> {
  shared: Arc<Shared<T>>,
}

/// A future returned by [`Sender::send`].
#[must_use = "futures do nothing unless polled"]
pub struct SendFuture<T> {
  side: Option<Arc<SendSide<T>>>,
  value: Option<T>,
  acquire: Option<AcquireMany>,
}

// The future never pins `T`; it moves the offered value into the queue.
impl<T> Unpin for SendFuture<T> {}

/// A future returned by [`Receiver::recv`].
#[must_use = "futures do nothing unless polled"]
pub struct RecvFuture<'a, T> {
  receiver: &'a mut Receiver<T>,
  registered: bool,
  completed: bool,
}

/// A future that waits for one bounded channel slot.
#[must_use = "futures do nothing unless polled"]
pub struct ReserveFuture<'a, T> {
  sender: &'a Sender<T>,
  acquire: Option<AcquireMany>,
  completed: bool,
}

/// An owned reservation future retaining a clone of its sender.
#[must_use = "futures do nothing unless polled"]
pub struct OwnedReserveFuture<T> {
  sender: Option<Sender<T>>,
  acquire: Option<AcquireMany>,
  completed: bool,
}

/// A borrowed channel slot. Dropping it returns capacity to the channel.
pub struct Permit<'a, T> {
  slot: Option<SlotPermit<T>>,
  _sender: &'a Sender<T>,
}

/// An owned channel slot. Dropping it returns capacity to the channel.
pub struct OwnedPermit<T> {
  slot: Option<SlotPermit<T>>,
  _sender: Option<Sender<T>>,
}

/// A future that completes after the receiver closes or is dropped.
#[must_use = "futures do nothing unless polled"]
pub struct ClosedFuture<'a, T> {
  sender: &'a Sender<T>,
  key: Option<WaiterKey>,
  completed: Option<Result<(), ClosedWaitError>>,
}

struct Envelope<T> {
  value: T,
  _permit: SemaphorePermit,
}

struct SlotPermit<T> {
  shared: Arc<Shared<T>>,
  semaphore: Option<SemaphorePermit>,
  active: bool,
}

struct ClosedWaiterSlot {
  generation: u64,
  exhausted: bool,
  waker: Option<Waker>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WaiterKey {
  index: usize,
  generation: u64,
}

struct SendSide<T> {
  shared: Arc<Shared<T>>,
}

struct Shared<T> {
  state: Mutex<QueueState<T>>,
  permits: Semaphore,
}

struct QueueState<T> {
  queue: VecDeque<Envelope<T>>,
  closed: bool,
  receiver_dropped: bool,
  senders_gone: bool,
  public_reservations: usize,
  receiver_waker: Option<Waker>,
  closed_waiters: Vec<ClosedWaiterSlot>,
}

impl<T> Sender<T> {
  /// Tries to enqueue `value` without waiting.
  pub fn try_send(&self, value: T) -> Result<(), SendError<T>> {
    match self.side.shared.permits.try_acquire_many(1) {
      Ok(permit) => enqueue(&self.side.shared, value, permit),
      Err(AcquireError::Closed) => Err(SendError {
        kind: SendErrorKind::Closed,
        value,
      }),
      Err(AcquireError::Full | AcquireError::Completed) => Err(SendError {
        kind: SendErrorKind::Full,
        value,
      }),
    }
  }

  /// Returns a future that waits fairly for a queue slot.
  pub fn send(&self, value: T) -> SendFuture<T> {
    SendFuture {
      side: Some(Arc::clone(&self.side)),
      value: Some(value),
      acquire: Some(self.side.shared.permits.acquire_many(1)),
    }
  }

  /// Waits for one queue slot without constructing or moving a message.
  /// The returned permit can still publish after an orderly receiver close.
  pub fn reserve(&self) -> ReserveFuture<'_, T> {
    ReserveFuture {
      sender: self,
      acquire: Some(self.side.shared.permits.acquire_many(1)),
      completed: false,
    }
  }

  /// Waits for one queue slot while retaining a clone of this sender.
  ///
  /// The original sender remains usable if this future is cancelled or
  /// rejected. Unlike Tokio's consuming `reserve_owned`, this method borrows
  /// the sender to create the owned handle.
  pub fn reserve_owned(&self) -> OwnedReserveFuture<T> {
    OwnedReserveFuture {
      sender: Some(self.clone()),
      acquire: Some(self.side.shared.permits.acquire_many(1)),
      completed: false,
    }
  }

  /// Waits until the receiver closes or is dropped.
  ///
  /// Registration uses the channel's bounded waiter table and may return
  /// [`ClosedWaitError::WaitersFull`]. Dropping a pending future unregisters
  /// only its own generation-tagged waiter.
  pub fn closed(&self) -> ClosedFuture<'_, T> {
    ClosedFuture {
      sender: self,
      key: None,
      completed: None,
    }
  }
}

impl<T> Clone for Sender<T> {
  fn clone(&self) -> Self {
    Self {
      side: Arc::clone(&self.side),
    }
  }
}

impl ClosedWaiterSlot {
  fn new() -> Self {
    Self {
      generation: 0,
      exhausted: false,
      waker: None,
    }
  }
}

impl<'a, T> Future for ReserveFuture<'a, T> {
  type Output = Result<Permit<'a, T>, ReserveError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if this.completed {
        return Poll::Ready(Err(ReserveError::Completed));
      }
      match poll_reservation(&this.sender.side.shared, &mut this.acquire, cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(error)) => {
          this.completed = true;
          Poll::Ready(Err(error))
        }
        Poll::Ready(Ok(slot)) => {
          this.completed = true;
          Poll::Ready(Ok(Permit {
            slot: Some(slot),
            _sender: this.sender,
          }))
        }
      }
    })
  }
}

impl<T> Future for OwnedReserveFuture<T> {
  type Output = Result<OwnedPermit<T>, ReserveError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if this.completed {
        return Poll::Ready(Err(ReserveError::Completed));
      }
      let Some(sender) = this.sender.as_ref() else {
        this.completed = true;
        return Poll::Ready(Err(ReserveError::Completed));
      };
      match poll_reservation(&sender.side.shared, &mut this.acquire, cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(error)) => {
          this.completed = true;
          this.acquire.take();
          drop(this.sender.take());
          Poll::Ready(Err(error))
        }
        Poll::Ready(Ok(slot)) => {
          this.completed = true;
          this.acquire.take();
          Poll::Ready(Ok(OwnedPermit {
            slot: Some(slot),
            _sender: this.sender.take(),
          }))
        }
      }
    })
  }
}

fn poll_reservation<T>(
  shared: &Arc<Shared<T>>,
  acquire_slot: &mut Option<AcquireMany>,
  cx: &mut Context<'_>,
) -> Poll<Result<SlotPermit<T>, ReserveError>> {
  let Some(acquire) = acquire_slot.as_mut() else {
    return Poll::Ready(Err(ReserveError::Completed));
  };
  match Pin::new(acquire).poll(cx) {
    Poll::Pending => Poll::Pending,
    Poll::Ready(Err(AcquireError::Closed)) => {
      *acquire_slot = None;
      Poll::Ready(Err(ReserveError::Closed))
    }
    Poll::Ready(Err(AcquireError::Full)) => {
      *acquire_slot = None;
      Poll::Ready(Err(ReserveError::WaitersFull))
    }
    Poll::Ready(Err(AcquireError::Completed)) => {
      *acquire_slot = None;
      Poll::Ready(Err(ReserveError::Completed))
    }
    Poll::Ready(Ok(semaphore)) => {
      *acquire_slot = None;
      let accepted = {
        let mut state = lock(&shared.state);
        if state.closed || state.receiver_dropped {
          false
        } else if let Some(count) = state.public_reservations.checked_add(1) {
          state.public_reservations = count;
          true
        } else {
          false
        }
      };
      if accepted {
        Poll::Ready(Ok(SlotPermit {
          shared: Arc::clone(shared),
          semaphore: Some(semaphore),
          active: true,
        }))
      } else {
        drop(semaphore);
        Poll::Ready(Err(ReserveError::Closed))
      }
    }
  }
}

impl<T> Future for ClosedFuture<'_, T> {
  type Output = Result<(), ClosedWaitError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if let Some(result) = this.completed {
        return Poll::Ready(result);
      }
      let mut replacement = Some(cx.waker().clone());
      let (result, old_waker) = {
        let mut state = lock(&this.sender.side.shared.state);
        if state.closed || state.receiver_dropped {
          (
            Some(Ok(())),
            this
              .key
              .take()
              .and_then(|key| take_closed_waiter(&mut state, key)),
          )
        } else if let Some(key) = this.key {
          match state.closed_waiters.get_mut(key.index) {
            Some(slot) if slot.generation == key.generation => {
              let replacement = match replacement.take() {
                Some(waker) => waker,
                None => unreachable!("replacement is retained until stored"),
              };
              (None, slot.waker.replace(replacement))
            }
            _ => (None, None),
          }
        } else {
          let mut registered = false;
          while let Some(index) = state
            .closed_waiters
            .iter()
            .position(|slot| !slot.exhausted && slot.waker.is_none())
          {
            if let Some(generation) = state.closed_waiters[index].generation.checked_add(1) {
              let slot = &mut state.closed_waiters[index];
              slot.generation = generation;
              slot.waker = replacement.take();
              this.key = Some(WaiterKey { index, generation });
              registered = true;
              break;
            }
            state.closed_waiters[index].exhausted = true;
          }
          if registered {
            (None, None)
          } else if !state.closed_waiters.is_empty()
            && state.closed_waiters.iter().all(|slot| slot.exhausted)
          {
            (Some(Err(ClosedWaitError::GenerationExhausted)), None)
          } else {
            (Some(Err(ClosedWaitError::WaitersFull)), None)
          }
        }
      };
      drop_waker(replacement);
      drop_waker(old_waker);
      if let Some(result) = result {
        this.completed = Some(result);
        Poll::Ready(result)
      } else {
        Poll::Pending
      }
    })
  }
}

impl<T> Drop for ClosedFuture<'_, T> {
  fn drop(&mut self) {
    let Some(key) = self.key.take() else {
      return;
    };
    let waker = {
      let mut state = lock(&self.sender.side.shared.state);
      if state.closed || state.receiver_dropped {
        None
      } else {
        take_closed_waiter(&mut state, key)
      }
    };
    drop_waker(waker);
  }
}

fn take_closed_waiter<T>(state: &mut QueueState<T>, key: WaiterKey) -> Option<Waker> {
  let slot = state.closed_waiters.get_mut(key.index)?;
  if slot.generation == key.generation {
    slot.waker.take()
  } else {
    None
  }
}

impl<'a, T> Permit<'a, T> {
  /// Publishes `value` using this reserved slot.
  ///
  /// An orderly receiver close preserves the reservation. If the receiver was
  /// dropped, the original value is returned in [`SendError`].
  pub fn send(mut self, value: T) -> Result<(), SendError<T>> {
    let Some(slot) = self.slot.take() else {
      return Err(SendError {
        kind: SendErrorKind::Closed,
        value,
      });
    };
    slot.send(value)
  }
}

impl<T> OwnedPermit<T> {
  /// Publishes `value` using this reserved slot.
  ///
  /// An orderly receiver close preserves the reservation. If the receiver was
  /// dropped, the original value is returned in [`SendError`].
  pub fn send(mut self, value: T) -> Result<(), SendError<T>> {
    let Some(slot) = self.slot.take() else {
      return Err(SendError {
        kind: SendErrorKind::Closed,
        value,
      });
    };
    slot.send(value)
  }
}

impl<T> SlotPermit<T> {
  fn send(mut self, value: T) -> Result<(), SendError<T>> {
    let mut value = Some(value);
    let outcome = {
      let mut state = lock(&self.shared.state);
      debug_assert!(self.active && state.public_reservations > 0);
      state.public_reservations -= 1;
      self.active = false;
      if state.receiver_dropped {
        Err(state.receiver_waker.take())
      } else {
        let semaphore = self.semaphore.take();
        let queued = match (value.take(), semaphore) {
          (Some(value), Some(permit)) => {
            state.queue.push_back(Envelope {
              value,
              _permit: permit,
            });
            true
          }
          _ => false,
        };
        debug_assert!(queued);
        Ok(state.receiver_waker.take())
      }
    };
    match outcome {
      Ok(waker) => {
        wake_contained(waker);
        Ok(())
      }
      Err(waker) => {
        drop(self.semaphore.take());
        wake_contained(waker);
        match value.take() {
          Some(value) => Err(SendError {
            kind: SendErrorKind::Closed,
            value,
          }),
          None => unreachable!("value is retained after receiver drop"),
        }
      }
    }
  }
}

impl<T> Drop for SlotPermit<T> {
  fn drop(&mut self) {
    let receiver_waker = {
      let mut state = lock(&self.shared.state);
      if !self.active {
        return;
      }
      debug_assert!(state.public_reservations > 0);
      state.public_reservations -= 1;
      self.active = false;
      if (state.closed || state.senders_gone)
        && state.queue.is_empty()
        && state.public_reservations == 0
      {
        state.receiver_waker.take()
      } else {
        None
      }
    };
    drop(self.semaphore.take());
    wake_contained(receiver_waker);
  }
}

impl<T> Receiver<T> {
  /// Receives the next queued message, or `None` after close and drain or
  /// after every sender and outstanding send future has been dropped.
  pub fn recv(&mut self) -> RecvFuture<'_, T> {
    RecvFuture {
      receiver: self,
      registered: false,
      completed: false,
    }
  }

  /// Removes a queued message without waiting.
  pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
    let (envelope, result, old_waker) = {
      let mut state = lock(&self.shared.state);
      if let Some(envelope) = state.queue.pop_front() {
        (Some(envelope), None, state.receiver_waker.take())
      } else {
        let result = if (state.closed || state.senders_gone) && state.public_reservations == 0 {
          TryRecvError::Closed
        } else {
          TryRecvError::Empty
        };
        (None, Some(result), None)
      }
    };
    match envelope {
      Some(envelope) => {
        let Envelope { value, _permit } = envelope;
        drop(_permit);
        drop_waker(old_waker);
        Ok(value)
      }
      None => {
        drop_waker(old_waker);
        match result {
          Some(result) => Err(result),
          None => unreachable!("empty receive result is retained"),
        }
      }
    }
  }

  /// Closes admission, rejects pending and future sends, and leaves queued
  /// messages available to receive.
  pub fn close(&mut self) {
    let (receiver_waker, closed_waiters) = {
      let mut state = lock(&self.shared.state);
      state.closed = true;
      (
        state.receiver_waker.take(),
        std::mem::take(&mut state.closed_waiters),
      )
    };
    self.shared.permits.close();
    wake_contained(receiver_waker);
    wake_waiters(closed_waiters);
  }
}

impl<T> Drop for Receiver<T> {
  fn drop(&mut self) {
    let (queued, receiver_waker, closed_waiters) = {
      let mut state = lock(&self.shared.state);
      state.closed = true;
      state.receiver_dropped = true;
      (
        std::mem::take(&mut state.queue),
        state.receiver_waker.take(),
        std::mem::take(&mut state.closed_waiters),
      )
    };
    self.shared.permits.close();
    wake_contained(receiver_waker);
    wake_waiters(closed_waiters);
    for envelope in queued {
      drop_contained(envelope);
    }
  }
}

impl<T> SendFuture<T> {
  /// Recovers the offered value if this future has not enqueued it.
  #[must_use]
  pub fn into_inner(mut self) -> Option<T> {
    self.value.take()
  }
}

impl<T> Drop for SendFuture<T> {
  fn drop(&mut self) {
    // End a pending semaphore wait and destroy the unsubmitted value before
    // the send-side Arc is dropped. Its final drop publishes sender EOF.
    drop(self.acquire.take());
    drop(self.value.take());
  }
}

impl<T> Future for SendFuture<T> {
  type Output = Result<(), SendError<T>>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if this.value.is_none() {
        return Poll::Pending;
      }

      let Some(side) = this.side.as_ref() else {
        return Poll::Pending;
      };
      if is_closed(&side.shared) {
        this.acquire.take();
        let Some(value) = this.value.take() else {
          return Poll::Pending;
        };
        this.side.take();
        return Poll::Ready(Err(SendError {
          kind: SendErrorKind::Closed,
          value,
        }));
      }

      let Some(acquire) = this.acquire.as_mut() else {
        return Poll::Pending;
      };
      match Pin::new(acquire).poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(AcquireError::Closed)) => {
          this.acquire.take();
          let Some(value) = this.value.take() else {
            return Poll::Pending;
          };
          this.side.take();
          Poll::Ready(Err(SendError {
            kind: SendErrorKind::Closed,
            value,
          }))
        }
        Poll::Ready(Err(AcquireError::Full | AcquireError::Completed)) => {
          this.acquire.take();
          let Some(value) = this.value.take() else {
            return Poll::Pending;
          };
          this.side.take();
          Poll::Ready(Err(SendError {
            kind: SendErrorKind::Full,
            value,
          }))
        }
        Poll::Ready(Ok(permit)) => {
          this.acquire.take();
          let Some(value) = this.value.take() else {
            drop(permit);
            this.side.take();
            return Poll::Pending;
          };
          let Some(side) = this.side.as_ref() else {
            drop(permit);
            return Poll::Pending;
          };
          let result = enqueue(&side.shared, value, permit);
          this.side.take();
          result.map_or_else(|error| Poll::Ready(Err(error)), |_| Poll::Ready(Ok(())))
        }
      }
    })
  }
}

impl<T> Drop for RecvFuture<'_, T> {
  fn drop(&mut self) {
    if self.registered && !self.completed {
      let old = {
        let mut state = lock(&self.receiver.shared.state);
        state.receiver_waker.take()
      };
      drop_waker(old);
    }
  }
}

impl<T> Future for RecvFuture<'_, T> {
  type Output = Option<T>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if this.completed {
        return Poll::Ready(None);
      }

      let mut new_waker = Some(cx.waker().clone());
      let (message, ended, old_waker) = {
        let mut state = lock(&this.receiver.shared.state);
        if let Some(envelope) = state.queue.pop_front() {
          (Some(envelope), false, state.receiver_waker.take())
        } else if (state.closed || state.senders_gone) && state.public_reservations == 0 {
          (None, true, state.receiver_waker.take())
        } else {
          let replacement = match new_waker.take() {
            Some(waker) => waker,
            None => unreachable!("receiver waker is cloned before locking"),
          };
          (None, false, state.receiver_waker.replace(replacement))
        }
      };

      if let Some(envelope) = message {
        this.registered = false;
        this.completed = true;
        // Return the slot before the caller can run a reentrant wake callback.
        let Envelope { value, _permit } = envelope;
        drop(_permit);
        drop_waker(old_waker);
        drop_waker(new_waker);
        Poll::Ready(Some(value))
      } else if ended {
        this.registered = false;
        this.completed = true;
        drop_waker(old_waker);
        drop_waker(new_waker);
        Poll::Ready(None)
      } else {
        this.registered = true;
        drop_waker(old_waker);
        drop_waker(new_waker);
        Poll::Pending
      }
    })
  }
}

fn enqueue<T>(
  shared: &Arc<Shared<T>>,
  value: T,
  permit: SemaphorePermit,
) -> Result<(), SendError<T>> {
  let result = {
    let mut state = lock(&shared.state);
    if state.closed {
      Err((value, permit))
    } else {
      state.queue.push_back(Envelope {
        value,
        _permit: permit,
      });
      Ok(state.receiver_waker.take())
    }
  };

  match result {
    Err((value, permit)) => {
      drop(permit);
      Err(SendError {
        kind: SendErrorKind::Closed,
        value,
      })
    }
    Ok(receiver_waker) => {
      wake_contained(receiver_waker);
      Ok(())
    }
  }
}

fn is_closed<T>(shared: &Arc<Shared<T>>) -> bool {
  let state = lock(&shared.state);
  state.closed || state.receiver_dropped
}

impl<T> Drop for SendSide<T> {
  fn drop(&mut self) {
    let receiver_waker = {
      let mut state = lock(&self.shared.state);
      state.senders_gone = true;
      state.receiver_waker.take()
    };
    wake_contained(receiver_waker);
  }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn wake_contained(waker: Option<Waker>) {
  if let Some(waker) = waker
    && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
  {
    drop_contained(payload);
  }
}

fn wake_waiters(waiters: Vec<ClosedWaiterSlot>) {
  for slot in waiters {
    wake_contained(slot.waker);
  }
}

fn drop_waker(waker: Option<Waker>) {
  if let Some(waker) = waker {
    drop_contained(waker);
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;
  use std::future::Future;
  use std::pin::pin;
  use std::sync::Barrier;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::{Wake, Waker};
  use std::thread;
  use std::time::{Duration, Instant};

  fn context() -> Context<'static> {
    Context::from_waker(Waker::noop())
  }

  fn ready<T, E>(poll: Poll<Result<T, E>>) -> Result<T, E> {
    match poll {
      Poll::Ready(result) => result,
      Poll::Pending => panic!("operation unexpectedly pending"),
    }
  }

  fn assert_cooperative_hot_loop_yields(
    future: impl Future<Output = ()> + Send + 'static,
    progress: Arc<AtomicUsize>,
  ) {
    use crate::runtime::asynchronous::{AsyncConfig, AsyncJoinError, AsyncRuntime, AsyncShutdown};

    let runtime = AsyncRuntime::new(AsyncConfig {
      workers: 1,
      max_outstanding: 4,
      max_scopes: 2,
    })
    .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
    let hot = runtime
      .handle()
      .spawn(future)
      .unwrap_or_else(|error| panic!("hot task spawn failed: {error}"));
    let deadline = Instant::now() + Duration::from_secs(3);
    while progress.load(Ordering::SeqCst) == 0 {
      assert!(Instant::now() < deadline, "hot loop did not start");
      thread::yield_now();
    }

    let seen = Arc::new(AtomicUsize::new(0));
    let sibling_seen = Arc::clone(&seen);
    let sibling_progress = Arc::clone(&progress);
    let sibling = runtime
      .handle()
      .spawn(async move {
        sibling_seen.store(sibling_progress.load(Ordering::SeqCst), Ordering::SeqCst);
      })
      .unwrap_or_else(|error| panic!("sibling task spawn failed: {error}"));
    let deadline = Instant::now() + Duration::from_secs(3);
    while !sibling.is_finished() {
      assert!(Instant::now() < deadline, "ready-loop sibling did not run");
      thread::yield_now();
    }
    assert!(seen.load(Ordering::SeqCst) > 0);
    assert!(!hot.is_finished(), "hot loop stopped before cancellation");

    hot.abort_handle().abort();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !hot.is_finished() {
      assert!(Instant::now() < deadline, "hot loop abort did not finish");
      thread::yield_now();
    }
    let hot_result = runtime
      .block_on(hot)
      .unwrap_or_else(|error| panic!("block_on failed: {error}"));
    assert!(matches!(hot_result, Err(AsyncJoinError::Cancelled)));
    let sibling_result = runtime
      .block_on(sibling)
      .unwrap_or_else(|error| panic!("block_on failed: {error}"));
    assert!(matches!(sibling_result, Ok(())));
    runtime
      .shutdown(AsyncShutdown::Drain)
      .unwrap_or_else(|error| panic!("runtime shutdown failed: {error}"));
  }

  #[derive(Default)]
  struct CountWake(AtomicUsize);

  impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  #[test]
  fn endpoints_and_futures_move_without_a_sync_message() {
    fn require_send<T: Send>(_: &T) {}
    fn require_sync<T: Sync>(_: &T) {}
    let (sender, mut receiver) = channel::<std::cell::Cell<usize>>(1, 1).unwrap();
    require_send(&sender);
    require_sync(&sender);
    require_send(&receiver);
    require_sync(&receiver);
    require_send(&sender.send(std::cell::Cell::new(0)));
    require_send(&receiver.recv());
  }

  #[test]
  fn bounded_try_send_and_drain_after_close() {
    let (tx, mut rx) = channel(1, 2).unwrap();
    tx.try_send(10).unwrap();
    let error = tx.try_send(20).unwrap_err();
    assert_eq!(error.kind(), SendErrorKind::Full);
    assert_eq!(error.into_inner(), 20);
    rx.close();
    assert_eq!(rx.try_recv(), Ok(10));
    assert_eq!(rx.try_recv(), Err(TryRecvError::Closed));
    let error = tx.try_send(30).unwrap_err();
    assert_eq!(error.kind(), SendErrorKind::Closed);
    assert_eq!(error.into_inner(), 30);
  }

  #[test]
  fn construction_rejects_unrepresentable_closed_waiter_storage() {
    assert!(matches!(
      channel::<u8>(1, usize::MAX),
      Err(BuildError::CapacityOverflow)
    ));
  }

  #[test]
  fn borrowed_and_owned_reservations_hold_and_return_capacity() {
    let (tx, mut rx) = channel(1, 2).unwrap();
    let permit = pin!(tx.reserve());
    let permit = ready(permit.poll(&mut context())).unwrap();
    assert_eq!(tx.try_send(1).unwrap_err().kind(), SendErrorKind::Full);
    permit.send(2).unwrap();
    assert_eq!(rx.try_recv(), Ok(2));

    let owned = pin!(tx.reserve_owned());
    let owned = ready(owned.poll(&mut context())).unwrap();
    drop(tx);
    owned.send(3).unwrap();
    assert_eq!(rx.try_recv(), Ok(3));
    assert_eq!(rx.try_recv(), Err(TryRecvError::Closed));
  }

  #[test]
  fn unused_reservations_release_capacity_and_close_waits_for_them() {
    let (tx, mut rx) = channel::<u8>(1, 1).unwrap();
    let permit = ready(pin!(tx.reserve()).poll(&mut context())).unwrap();
    rx.close();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));

    let wake = Arc::new(CountWake::default());
    let waker = Waker::from(Arc::clone(&wake));
    let mut cx = Context::from_waker(&waker);
    let mut recv = pin!(rx.recv());
    assert!(recv.as_mut().poll(&mut cx).is_pending());
    drop(permit);
    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
    assert_eq!(recv.as_mut().poll(&mut cx), Poll::Ready(None));
  }

  #[test]
  fn a_public_reservation_survives_close_but_receiver_drop_recovers_value() {
    let (tx, mut rx) = channel::<u8>(1, 1).unwrap();
    let permit = ready(pin!(tx.reserve()).poll(&mut context())).unwrap();
    rx.close();
    permit.send(7).unwrap();
    assert_eq!(rx.try_recv(), Ok(7));
    assert_eq!(rx.try_recv(), Err(TryRecvError::Closed));

    let (tx, rx) = channel(1, 1).unwrap();
    let permit = ready(pin!(tx.reserve()).poll(&mut context())).unwrap();
    drop(rx);
    let error = permit.send(19).unwrap_err();
    assert_eq!(error.kind(), SendErrorKind::Closed);
    assert_eq!(error.into_inner(), 19);
    assert!(tx.try_send(20).is_err());
  }

  #[test]
  fn owned_reserve_waiter_cancellation_preserves_original_sender() {
    let (tx, mut rx) = channel(1, 1).unwrap();
    tx.try_send(0).unwrap();
    {
      let mut reserve = pin!(tx.reserve_owned());
      assert!(reserve.as_mut().poll(&mut context()).is_pending());
    }
    assert_eq!(tx.try_send(1).unwrap_err().kind(), SendErrorKind::Full);
    assert_eq!(rx.try_recv(), Ok(0));
    tx.try_send(2).unwrap();
    assert_eq!(rx.try_recv(), Ok(2));
  }

  #[test]
  fn close_revokes_a_queued_internal_grant_before_public_reservation() {
    let (tx, mut rx) = channel::<u8>(1, 1).unwrap();
    tx.try_send(0).unwrap();
    let mut reserve = Box::pin(tx.reserve_owned());
    assert!(reserve.as_mut().poll(&mut context()).is_pending());

    // Dequeue grants the semaphore internally, but the reserve future has
    // not polled again to publish a public permit.
    assert_eq!(rx.try_recv(), Ok(0));
    rx.close();
    assert!(matches!(
      reserve.as_mut().poll(&mut context()),
      Poll::Ready(Err(ReserveError::Closed))
    ));
    assert_eq!(rx.try_recv(), Err(TryRecvError::Closed));
    assert_eq!(tx.try_send(1).unwrap_err().kind(), SendErrorKind::Closed);
  }

  #[test]
  fn reserve_ready_loop_yields_and_can_be_aborted() {
    let (sender, _receiver) = channel::<u8>(1, 1).unwrap();
    let progress = Arc::new(AtomicUsize::new(0));
    let loop_progress = Arc::clone(&progress);
    let future = async move {
      loop {
        let permit = sender
          .reserve()
          .await
          .unwrap_or_else(|error| panic!("reservation failed: {error}"));
        drop(permit);
        loop_progress.fetch_add(1, Ordering::SeqCst);
      }
    };
    assert_cooperative_hot_loop_yields(future, progress);
  }

  #[test]
  fn closed_ready_loop_yields_and_can_be_aborted() {
    let (sender, mut receiver) = channel::<u8>(1, 1).unwrap();
    receiver.close();
    let progress = Arc::new(AtomicUsize::new(0));
    let loop_progress = Arc::clone(&progress);
    let future = async move {
      loop {
        sender
          .closed()
          .await
          .unwrap_or_else(|error| panic!("closed wait failed: {error}"));
        loop_progress.fetch_add(1, Ordering::SeqCst);
      }
    };
    assert_cooperative_hot_loop_yields(future, progress);
  }

  #[test]
  fn pending_owned_reservation_keeps_sender_alive_until_cancelled() {
    let (tx, mut rx) = channel::<u8>(1, 1).unwrap();
    tx.try_send(0).unwrap();
    let mut reserve = Box::pin(tx.reserve_owned());
    assert!(reserve.as_mut().poll(&mut context()).is_pending());
    drop(tx);
    assert_eq!(rx.try_recv(), Ok(0));
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
    drop(reserve);
    assert_eq!(rx.try_recv(), Err(TryRecvError::Closed));
  }

  #[test]
  fn closed_waiters_are_bounded_cancel_safe_and_sticky() {
    let (tx, mut rx) = channel::<u8>(1, 1).unwrap();
    let mut first = Box::pin(tx.closed());
    assert!(first.as_mut().poll(&mut context()).is_pending());
    let mut second = pin!(tx.closed());
    assert_eq!(
      second.as_mut().poll(&mut context()),
      Poll::Ready(Err(ClosedWaitError::WaitersFull))
    );
    drop(first);

    let mut replacement = pin!(tx.closed());
    assert!(replacement.as_mut().poll(&mut context()).is_pending());
    rx.close();
    assert_eq!(
      replacement.as_mut().poll(&mut context()),
      Poll::Ready(Ok(()))
    );
    assert_eq!(
      replacement.as_mut().poll(&mut context()),
      Poll::Ready(Ok(()))
    );

    let (tx, mut rx) = channel::<u8>(1, 0).unwrap();
    let mut no_slot = pin!(tx.closed());
    assert_eq!(
      no_slot.as_mut().poll(&mut context()),
      Poll::Ready(Err(ClosedWaitError::WaitersFull))
    );
    rx.close();
    let mut after_close = pin!(tx.closed());
    assert_eq!(
      after_close.as_mut().poll(&mut context()),
      Poll::Ready(Ok(()))
    );
  }

  #[test]
  fn closed_waiter_callbacks_run_after_releasing_the_queue_lock() {
    struct Reenter {
      sender: Sender<u8>,
      calls: Arc<AtomicUsize>,
    }

    impl Wake for Reenter {
      fn wake(self: Arc<Self>) {
        self.wake_by_ref();
      }

      fn wake_by_ref(self: &Arc<Self>) {
        if self.sender.side.shared.state.try_lock().is_ok() {
          self.calls.fetch_add(1, Ordering::SeqCst);
        }
      }
    }

    let (tx, mut rx) = channel::<u8>(1, 1).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(Reenter {
      sender: tx.clone(),
      calls: Arc::clone(&calls),
    }));
    let mut cx = Context::from_waker(&waker);
    let mut closed = pin!(tx.closed());
    assert!(closed.as_mut().poll(&mut cx).is_pending());
    rx.close();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn closed_waiter_generation_exhaustion_is_not_reported_as_full() {
    let (tx, _rx) = channel::<u8>(1, 1).unwrap();
    {
      let mut state = lock(&tx.side.shared.state);
      state.closed_waiters[0].generation = u64::MAX;
    }
    let mut closed = pin!(tx.closed());
    assert_eq!(
      closed.as_mut().poll(&mut context()),
      Poll::Ready(Err(ClosedWaitError::GenerationExhausted))
    );
  }

  #[test]
  fn retired_closed_waiter_slots_are_skipped_or_report_full() {
    let (tx, _rx) = channel::<u8>(1, 2).unwrap();
    {
      let mut state = lock(&tx.side.shared.state);
      state.closed_waiters[0].generation = u64::MAX;
    }
    let mut future = pin!(tx.closed());
    assert!(future.as_mut().poll(&mut context()).is_pending());
    assert_eq!(future.as_ref().get_ref().key.unwrap().index, 1);

    let (tx, _rx) = channel::<u8>(1, 2).unwrap();
    {
      let mut state = lock(&tx.side.shared.state);
      state.closed_waiters[0].generation = u64::MAX;
      state.closed_waiters[1].generation = 1;
      state.closed_waiters[1].waker = Some(Waker::noop().clone());
    }
    let mut future = pin!(tx.closed());
    assert_eq!(
      future.as_mut().poll(&mut context()),
      Poll::Ready(Err(ClosedWaitError::WaitersFull))
    );
  }

  #[test]
  fn cancelling_an_old_closed_waiter_cannot_remove_a_reused_slot() {
    let (tx, _rx) = channel::<u8>(1, 1).unwrap();
    let old_key = {
      let mut old = Box::pin(tx.closed());
      assert!(old.as_mut().poll(&mut context()).is_pending());
      old.as_ref().get_ref().key.unwrap()
    };
    let mut current = Box::pin(tx.closed());
    assert!(current.as_mut().poll(&mut context()).is_pending());
    let current_key = current.as_ref().get_ref().key.unwrap();
    assert_ne!(old_key, current_key);
    {
      let mut state = lock(&tx.side.shared.state);
      assert!(take_closed_waiter(&mut state, old_key).is_none());
      assert!(state.closed_waiters[current_key.index].waker.is_some());
    }
  }

  #[test]
  fn reserved_send_error_value_drops_outside_the_queue_lock() {
    struct ReentrantDrop {
      sender: Sender<ReentrantDrop>,
      drops: Arc<AtomicUsize>,
    }

    impl Drop for ReentrantDrop {
      fn drop(&mut self) {
        if self.sender.side.shared.state.try_lock().is_ok() {
          self.drops.fetch_add(1, Ordering::SeqCst);
        }
      }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = channel::<ReentrantDrop>(1, 1).unwrap();
    let permit = ready(pin!(tx.reserve_owned()).poll(&mut context())).unwrap();
    drop(rx);
    let error = match permit.send(ReentrantDrop {
      sender: tx.clone(),
      drops: Arc::clone(&drops),
    }) {
      Ok(()) => panic!("dropped receiver accepted a reserved send"),
      Err(error) => error,
    };
    drop(error);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn send_waiter_is_cancelled_and_value_can_be_recovered() {
    let (tx, mut rx) = channel(1, 1).unwrap();
    tx.try_send(1).unwrap();
    {
      let mut send = pin!(tx.send(2));
      assert!(send.as_mut().poll(&mut context()).is_pending());
    }
    assert_eq!(rx.try_recv(), Ok(1));
    assert!(tx.try_send(3).is_ok());
  }

  #[test]
  fn into_inner_cancels_an_unsubmitted_send() {
    let (tx, _rx) = channel(1, 1).unwrap();
    tx.try_send(String::from("occupy")).unwrap();
    let send = tx.send(String::from("offered"));
    assert_eq!(send.into_inner().as_deref(), Some("offered"));
  }

  #[test]
  fn pending_send_is_rejected_when_close_races_with_a_grant() {
    let (tx, mut rx) = channel(1, 2).unwrap();
    tx.try_send(1).unwrap();
    let mut send = pin!(tx.send(2));
    assert!(send.as_mut().poll(&mut context()).is_pending());
    assert_eq!(rx.try_recv(), Ok(1));
    rx.close();
    let result = send.as_mut().poll(&mut context());
    assert!(matches!(
      result,
      Poll::Ready(Err(SendError {
        kind: SendErrorKind::Closed,
        ..
      }))
    ));
  }

  #[test]
  fn send_waiters_receive_grants_in_fifo_order() {
    let (tx, mut rx) = channel(1, 2).unwrap();
    tx.try_send(0).unwrap();
    let mut first = Box::pin(tx.send(1));
    let mut second = Box::pin(tx.send(2));
    assert!(first.as_mut().poll(&mut context()).is_pending());
    assert!(second.as_mut().poll(&mut context()).is_pending());

    assert_eq!(rx.try_recv(), Ok(0));
    // Poll the second future first. It cannot steal the permit granted to the
    // first waiter.
    assert!(second.as_mut().poll(&mut context()).is_pending());
    assert!(first.as_mut().poll(&mut context()).is_ready());
    assert_eq!(rx.try_recv(), Ok(1));
    assert!(second.as_mut().poll(&mut context()).is_ready());
    assert_eq!(rx.try_recv(), Ok(2));
  }

  #[test]
  fn dropping_a_granted_send_restores_its_slot_and_value() {
    let (tx, mut rx) = channel(1, 1).unwrap();
    tx.try_send(0).unwrap();
    let mut send = Box::pin(tx.send(1));
    assert!(send.as_mut().poll(&mut context()).is_pending());
    assert_eq!(rx.try_recv(), Ok(0));
    let future = *Pin::into_inner(send);
    assert_eq!(future.into_inner(), Some(1));
    assert!(tx.try_send(2).is_ok());
    assert_eq!(rx.try_recv(), Ok(2));
  }

  #[test]
  fn last_sender_and_outstanding_send_future_control_eof() {
    let (tx, mut rx) = channel::<u8>(1, 1).unwrap();
    let future = tx.send(1);
    drop(tx);
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
    drop(future);
    assert_eq!(rx.try_recv(), Err(TryRecvError::Closed));
  }

  #[test]
  fn completed_send_future_does_not_delay_receiver_eof() {
    let (tx, mut rx) = channel(1, 1).unwrap();
    let mut send = Box::pin(tx.send(5));
    assert!(send.as_mut().poll(&mut context()).is_ready());
    drop(tx);
    assert_eq!(rx.try_recv(), Ok(5));
    let mut recv = Box::pin(rx.recv());
    assert_eq!(recv.as_mut().poll(&mut context()), Poll::Ready(None));
    // Keep the completed send future alive through the EOF observation.
    drop(send);
  }

  #[test]
  fn last_sender_drop_wakes_a_waiting_receiver() {
    struct CountWake(Arc<AtomicUsize>);
    impl Wake for CountWake {
      fn wake(self: Arc<Self>) {
        self.wake_by_ref();
      }
      fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }

    let (tx, mut rx) = channel::<u8>(1, 1).unwrap();
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountWake(Arc::clone(&wakes))));
    let mut cx = Context::from_waker(&waker);
    let mut recv = Box::pin(rx.recv());
    assert!(recv.as_mut().poll(&mut cx).is_pending());
    drop(tx);
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    assert_eq!(recv.as_mut().poll(&mut cx), Poll::Ready(None));
  }

  #[test]
  fn pending_managed_buffer_stays_charged_through_closed_send_error() {
    use super::super::managed::{ResourceLimits, ResourceScope};

    let scope = ResourceScope::new(ResourceLimits {
      managed_memory: 16,
      ..ResourceLimits::default()
    });
    let buffer = scope.try_alloc_zeroed(8).unwrap();
    let (tx, mut rx) = channel(1, 1).unwrap();
    tx.try_send(scope.try_alloc_zeroed(8).unwrap()).unwrap();
    let mut send = Box::pin(tx.send(buffer));
    assert!(send.as_mut().poll(&mut context()).is_pending());
    assert_eq!(scope.snapshot().managed_memory, 16);
    rx.close();
    let Poll::Ready(Err(error)) = send.as_mut().poll(&mut context()) else {
      panic!("closed channel must reject the pending send");
    };
    assert_eq!(error.kind(), SendErrorKind::Closed);
    assert_eq!(scope.snapshot().managed_memory, 16);
    drop(error.into_inner());
    assert_eq!(scope.snapshot().managed_memory, 8);
    drop(rx.try_recv().unwrap());
    assert_eq!(scope.snapshot().managed_memory, 0);
  }

  #[test]
  fn receiver_future_waits_and_cancellation_unregisters_waker() {
    let (tx, mut rx) = channel(1, 1).unwrap();
    {
      let mut recv = pin!(rx.recv());
      assert!(recv.as_mut().poll(&mut context()).is_pending());
    }
    tx.try_send(7).unwrap();
    assert_eq!(rx.try_recv(), Ok(7));
  }

  #[test]
  fn receiver_waker_can_reenter_the_sender() {
    struct Reenter {
      sender: Sender<usize>,
      calls: Arc<AtomicUsize>,
    }
    impl Wake for Reenter {
      fn wake(self: Arc<Self>) {
        self.wake_by_ref();
      }
      fn wake_by_ref(self: &Arc<Self>) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.sender.try_send(2);
      }
    }

    let (tx, mut rx) = channel(2, 1).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(Reenter {
      sender: tx.clone(),
      calls: Arc::clone(&calls),
    }));
    let mut cx = Context::from_waker(&waker);
    let mut recv = Box::pin(rx.recv());
    assert!(recv.as_mut().poll(&mut cx).is_pending());
    tx.try_send(1).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(recv.as_mut().poll(&mut cx), Poll::Ready(Some(1))));
    drop(recv);
    assert_eq!(rx.try_recv(), Ok(2));
  }

  #[test]
  fn concurrent_senders_preserve_capacity_and_deliver_every_accepted_item() {
    let (tx, mut rx) = channel(8, 32).unwrap();
    let barrier = Arc::new(Barrier::new(5));
    let mut threads = Vec::new();
    for worker in 0..4 {
      let sender = tx.clone();
      let barrier = Arc::clone(&barrier);
      threads.push(thread::spawn(move || {
        barrier.wait();
        for item in 0..50 {
          let value = worker * 50 + item;
          loop {
            match sender.try_send(value) {
              Ok(()) => break,
              Err(error) if error.kind() == SendErrorKind::Full => thread::yield_now(),
              Err(error) => panic!("unexpected send rejection: {error}"),
            }
          }
        }
      }));
    }
    barrier.wait();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut received = std::collections::HashSet::new();
    while received.len() < 200 {
      if let Ok(value) = rx.try_recv() {
        assert!(received.insert(value));
      } else {
        assert!(
          std::time::Instant::now() < deadline,
          "senders did not complete"
        );
        thread::yield_now();
      }
    }
    for handle in threads {
      assert!(handle.join().is_ok());
    }
    assert_eq!(received, (0..200).collect());
  }

  #[test]
  fn dropping_receiver_drops_messages_outside_queue_lock() {
    struct ReentrantDrop {
      sender: Sender<ReentrantDrop>,
      drops: Arc<AtomicUsize>,
    }
    impl Drop for ReentrantDrop {
      fn drop(&mut self) {
        if self.sender.side.shared.state.try_lock().is_ok() {
          self.drops.fetch_add(1, Ordering::SeqCst);
        }
      }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = channel(2, 1).unwrap();
    tx.try_send(ReentrantDrop {
      sender: tx.clone(),
      drops: Arc::clone(&drops),
    })
    .unwrap();
    drop(rx);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn receiver_drop_contains_panics_from_each_queued_value() {
    struct PanicOnDrop(Arc<AtomicUsize>);
    impl Drop for PanicOnDrop {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("contained message destructor panic");
      }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = channel(2, 1).unwrap();
    tx.try_send(PanicOnDrop(Arc::clone(&drops))).unwrap();
    tx.try_send(PanicOnDrop(Arc::clone(&drops))).unwrap();
    drop(rx);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
  }

  #[test]
  fn managed_buffer_charge_remains_while_queued() {
    use super::super::managed::{ResourceLimits, ResourceScope};

    let scope = ResourceScope::new(ResourceLimits {
      managed_memory: 16,
      ..ResourceLimits::default()
    });
    let buffer = scope.try_alloc_zeroed(8).unwrap();
    let (tx, mut rx) = channel(1, 1).unwrap();
    tx.try_send(buffer).unwrap();
    assert_eq!(scope.snapshot().managed_memory, 8);
    drop(rx.try_recv().unwrap());
    assert_eq!(scope.snapshot().managed_memory, 0);
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use super::channel;
  use loom::thread;
  use std::future::Future;
  use std::pin::pin;
  use std::sync::Arc as StdArc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::{Context, Poll, Wake, Waker};

  fn context() -> Context<'static> {
    Context::from_waker(Waker::noop())
  }

  #[derive(Default)]
  struct CountWake(AtomicUsize);

  impl Wake for CountWake {
    fn wake(self: StdArc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &StdArc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  // Covers the close/enqueue linearization using the real channel state and
  // semaphore. It does not model async waiter scheduling or custom RawWakers.
  #[test]
  fn close_races_enqueue_without_losing_an_accepted_message() {
    loom::model(|| {
      let (sender, receiver) = channel(1, 0).unwrap();
      let send = thread::spawn(move || sender.try_send(17).is_ok());
      let close = thread::spawn(move || {
        let mut receiver = receiver;
        receiver.close();
        receiver
      });

      let accepted = send.join().unwrap();
      let mut receiver = close.join().unwrap();
      if accepted {
        assert_eq!(receiver.try_recv(), Ok(17));
      } else {
        assert_eq!(receiver.try_recv(), Err(super::TryRecvError::Closed));
      }
      assert_eq!(receiver.try_recv(), Err(super::TryRecvError::Closed));
    });
  }

  #[test]
  fn close_races_reservation_publication_without_losing_a_permit_message() {
    loom::model(|| {
      let (sender, receiver) = channel(1, 0).unwrap();
      let reserve = thread::spawn(move || {
        let mut future = Box::pin(sender.reserve_owned());
        match future.as_mut().poll(&mut context()) {
          Poll::Ready(Ok(permit)) => permit.send(42).is_ok(),
          Poll::Ready(Err(super::ReserveError::Closed)) => false,
          Poll::Ready(Err(_)) => panic!("single-slot reservation was unexpectedly rejected"),
          Poll::Pending => panic!("single-slot reservation unexpectedly pending"),
        }
      });
      let close = thread::spawn(move || {
        let mut receiver = receiver;
        receiver.close();
        receiver
      });

      let accepted = reserve.join().unwrap();
      let mut receiver = close.join().unwrap();
      if accepted {
        assert_eq!(receiver.try_recv(), Ok(42));
      } else {
        assert_eq!(receiver.try_recv(), Err(super::TryRecvError::Closed));
      }
      assert_eq!(receiver.try_recv(), Err(super::TryRecvError::Closed));
    });
  }

  #[test]
  fn reserved_send_races_receiver_destruction_and_recovers_if_it_loses() {
    loom::model(|| {
      let (sender, receiver) = channel(1, 0).unwrap();
      let permit = match pin!(sender.reserve_owned()).poll(&mut context()) {
        Poll::Ready(Ok(permit)) => permit,
        _ => panic!("single-slot reservation must complete"),
      };
      let send = thread::spawn(move || match permit.send(17) {
        Ok(()) => true,
        Err(error) => {
          assert_eq!(error.into_inner(), 17);
          false
        }
      });
      let drop_receiver = thread::spawn(move || drop(receiver));
      let _sent_before_drop = send.join().unwrap();
      drop_receiver.join().unwrap();
    });
  }

  #[test]
  fn final_unused_permit_drop_allows_closed_receiver_to_reach_eof() {
    loom::model(|| {
      let (sender, mut receiver) = channel::<u8>(1, 0).unwrap();
      let permit = match pin!(sender.reserve_owned()).poll(&mut context()) {
        Poll::Ready(Ok(permit)) => permit,
        _ => panic!("single-slot reservation must complete"),
      };
      receiver.close();
      let wake = StdArc::new(CountWake::default());
      let waker = Waker::from(StdArc::clone(&wake));
      let mut cx = Context::from_waker(&waker);
      let mut recv = pin!(receiver.recv());
      assert!(recv.as_mut().poll(&mut cx).is_pending());
      let drop_permit = thread::spawn(move || drop(permit));
      drop_permit.join().unwrap();
      assert_eq!(wake.0.load(Ordering::SeqCst), 1);
      assert_eq!(recv.as_mut().poll(&mut cx), Poll::Ready(None));
    });
  }

  #[test]
  fn closed_waiter_registration_races_close_and_remains_sticky() {
    loom::model(|| {
      let (sender, receiver) = channel::<u8>(1, 1).unwrap();
      let close = thread::spawn(move || {
        let mut receiver = receiver;
        receiver.close();
      });
      let registration = thread::spawn(move || {
        let wake = StdArc::new(CountWake::default());
        let waker = Waker::from(StdArc::clone(&wake));
        let mut cx = Context::from_waker(&waker);
        let mut future = pin!(sender.closed());
        let first = future.as_mut().poll(&mut cx);
        close.join().unwrap();
        let result = match first {
          Poll::Ready(result) => result,
          Poll::Pending => match future.as_mut().poll(&mut context()) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("closed waiter missed the close notification"),
          },
        };
        assert_eq!(result, Ok(()));
        if first.is_pending() {
          assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        }
        assert_eq!(future.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
      });
      registration.join().unwrap();
    });
  }

  #[test]
  fn try_recv_never_reports_closed_while_a_reserved_message_is_queued() {
    loom::model(|| {
      let (sender, mut receiver) = channel::<u8>(1, 0).unwrap();
      let permit = match pin!(sender.reserve_owned()).poll(&mut context()) {
        Poll::Ready(Ok(permit)) => permit,
        _ => panic!("single-slot reservation must complete"),
      };
      receiver.close();
      let send = thread::spawn(move || permit.send(9).is_ok());
      let receive = thread::spawn(move || {
        let result = receiver.try_recv();
        (receiver, result)
      });
      let sent = send.join().unwrap();
      let (mut receiver, result) = receive.join().unwrap();
      assert!(sent);
      match result {
        Ok(9) => assert_eq!(receiver.try_recv(), Err(super::TryRecvError::Closed)),
        Err(super::TryRecvError::Empty) => assert_eq!(receiver.try_recv(), Ok(9)),
        Err(super::TryRecvError::Closed) => {
          panic!("try_recv reported EOF before the reserved message was visible")
        }
        _ => panic!("try_recv returned an unexpected result"),
      }
    });
  }
}
