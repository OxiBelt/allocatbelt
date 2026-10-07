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
//! sends, wakes queued senders, and leaves already queued messages available
//! to drain. Dropping the receiver closes admission and drops queued messages
//! after releasing the queue lock. Dropping an unsubmitted [`SendFuture`]
//! cancels its wait and drops its offered value outside the queue lock;
//! [`SendFuture::into_inner`] can recover that value before it is submitted.
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

use super::semaphore::{AcquireError, AcquireMany, Permit, Semaphore, SemaphoreBuildError};
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

  let mut queue = VecDeque::new();
  queue
    .try_reserve_exact(capacity)
    .map_err(|_| BuildError::AllocationFailed)?;
  let permits = Semaphore::new(capacity, max_waiters).map_err(|error| match error {
    SemaphoreBuildError::CapacityOverflow => BuildError::CapacityOverflow,
    SemaphoreBuildError::AllocationFailed => BuildError::AllocationFailed,
  })?;
  let shared = Arc::new(Shared {
    state: Mutex::new(QueueState {
      queue,
      closed: false,
      senders_gone: false,
      receiver_waker: None,
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
  /// The channel is closed and all queued messages have been consumed.
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

struct Envelope<T> {
  value: T,
  _permit: Permit,
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
  senders_gone: bool,
  receiver_waker: Option<Waker>,
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
}

impl<T> Clone for Sender<T> {
  fn clone(&self) -> Self {
    Self {
      side: Arc::clone(&self.side),
    }
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
    match dequeue(&self.shared) {
      Some(value) => Ok(value),
      None => {
        let state = lock(&self.shared.state);
        if state.closed || state.senders_gone {
          Err(TryRecvError::Closed)
        } else {
          Err(TryRecvError::Empty)
        }
      }
    }
  }

  /// Closes admission, rejects pending and future sends, and leaves queued
  /// messages available to receive.
  pub fn close(&mut self) {
    let receiver_waker = {
      let mut state = lock(&self.shared.state);
      state.closed = true;
      state.receiver_waker.take()
    };
    self.shared.permits.close();
    wake_contained(receiver_waker);
  }
}

impl<T> Drop for Receiver<T> {
  fn drop(&mut self) {
    let (queued, receiver_waker) = {
      let mut state = lock(&self.shared.state);
      state.closed = true;
      (
        std::mem::take(&mut state.queue),
        state.receiver_waker.take(),
      )
    };
    self.shared.permits.close();
    wake_contained(receiver_waker);
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
        } else if state.closed || state.senders_gone {
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

fn enqueue<T>(shared: &Arc<Shared<T>>, value: T, permit: Permit) -> Result<(), SendError<T>> {
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

fn dequeue<T>(shared: &Arc<Shared<T>>) -> Option<T> {
  let (envelope, old_waker) = {
    let mut state = lock(&shared.state);
    (state.queue.pop_front(), state.receiver_waker.take())
  };
  let Some(envelope) = envelope else {
    drop_waker(old_waker);
    return None;
  };
  let Envelope { value, _permit } = envelope;
  drop(_permit);
  drop_waker(old_waker);
  Some(value)
}

fn is_closed<T>(shared: &Arc<Shared<T>>) -> bool {
  lock(&shared.state).closed
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

  fn context() -> Context<'static> {
    Context::from_waker(Waker::noop())
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
}
