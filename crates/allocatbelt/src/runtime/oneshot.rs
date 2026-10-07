//! A single-message channel with one sender and one receiver.
//!
//! Sending is synchronous and returns the original value if the receiver has
//! closed. Closing a receiver rejects future sends but preserves an already
//! sent value. Dropping it discards that value outside the state lock.
//! Each direction stores at most one waker. The small shared state follows
//! Rust's ordinary allocation-failure handling; message storage, including
//! managed-buffer charges, stays owned until received or discarded.
//!
//! ```compile_fail
//! use allocatbelt::runtime::oneshot::Receiver;
//! use std::rc::Rc;
//! fn require_send<T: Send>() {}
//! require_send::<Receiver<Rc<()>>>();
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::PoisonError;
use std::task::{Context, Poll, Waker};

#[cfg(loom)]
use loom::sync::{Arc, Mutex};
#[cfg(not(loom))]
use std::sync::{Arc, Mutex};

use super::task::drop_contained;

/// Creates a channel that can transfer exactly one value.
#[must_use]
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
  let shared = Arc::new(Shared {
    state: Mutex::new(State {
      value: None,
      sender_alive: true,
      receiver_closed: false,
      receiver_waker: None,
      sender_waker: None,
    }),
  });
  (
    Sender {
      shared: Some(Arc::clone(&shared)),
    },
    Receiver {
      shared,
      completed: false,
    },
  )
}

struct Shared<T> {
  state: Mutex<State<T>>,
}

struct State<T> {
  value: Option<T>,
  sender_alive: bool,
  receiver_closed: bool,
  receiver_waker: Option<Waker>,
  sender_waker: Option<Waker>,
}

/// The unique sending endpoint. Dropping it without sending closes the channel.
pub struct Sender<T> {
  shared: Option<Arc<Shared<T>>>,
}

/// The unique receiving endpoint and its awaitable result.
pub struct Receiver<T> {
  shared: Arc<Shared<T>>,
  completed: bool,
}

/// A borrow-tied notification that the receiver has closed or been dropped.
#[must_use = "futures do nothing unless polled"]
pub struct Closed<'a, T> {
  sender: &'a mut Sender<T>,
  completed: bool,
}

/// The channel closed without delivering a value, or the result was consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvError;

impl fmt::Display for RecvError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("single-message channel is closed")
  }
}

impl std::error::Error for RecvError {}

/// Why an immediate receive did not produce a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryRecvError {
  /// No value has been sent yet.
  Empty,
  /// The channel is closed or its value has already been consumed.
  Closed,
}

impl fmt::Display for TryRecvError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Empty => "single-message channel has no value yet",
      Self::Closed => "single-message channel is closed",
    })
  }
}

impl std::error::Error for TryRecvError {}

impl<T> Sender<T> {
  /// Sends the value, returning it unchanged if the receiver has closed.
  pub fn send(mut self, value: T) -> Result<(), T> {
    let shared = match self.shared.take() {
      Some(shared) => shared,
      None => return Err(value),
    };
    let (result, receiver, sender) = {
      let mut state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
      state.sender_alive = false;
      let result = if state.receiver_closed {
        Err(value)
      } else {
        state.value = Some(value);
        Ok(())
      };
      (
        result,
        state.receiver_waker.take(),
        state.sender_waker.take(),
      )
    };
    wake_contained(receiver);
    drop_contained(sender);
    result
  }

  /// Whether the receiver has explicitly closed or been dropped.
  #[must_use]
  pub fn is_closed(&self) -> bool {
    self.shared.as_ref().is_none_or(|shared| {
      shared
        .state
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .receiver_closed
    })
  }

  /// Waits for receiver closure. The mutable borrow bounds this direction to
  /// one active notification future; dropping it removes its stored waker.
  pub fn closed(&mut self) -> Closed<'_, T> {
    Closed {
      sender: self,
      completed: false,
    }
  }
}

impl<T> Drop for Sender<T> {
  fn drop(&mut self) {
    let Some(shared) = self.shared.take() else {
      return;
    };
    let (receiver, sender) = {
      let mut state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
      state.sender_alive = false;
      (state.receiver_waker.take(), state.sender_waker.take())
    };
    wake_contained(receiver);
    drop_contained(sender);
  }
}

impl<T> Receiver<T> {
  /// Rejects future sends while retaining a value already sent.
  pub fn close(&mut self) {
    let (receiver, sender) = {
      let mut state = self
        .shared
        .state
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
      state.receiver_closed = true;
      (state.receiver_waker.take(), state.sender_waker.take())
    };
    wake_contained(receiver);
    wake_contained(sender);
  }

  /// Receives immediately. Successful or terminal receives consume this
  /// endpoint; subsequent receives report closure.
  pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
    if self.completed {
      return Err(TryRecvError::Closed);
    }
    let (result, old) = {
      let mut state = self
        .shared
        .state
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
      if let Some(value) = state.value.take() {
        (Ok(value), state.receiver_waker.take())
      } else if state.receiver_closed || !state.sender_alive {
        (Err(TryRecvError::Closed), state.receiver_waker.take())
      } else {
        (Err(TryRecvError::Empty), None)
      }
    };
    if !matches!(&result, Err(TryRecvError::Empty)) {
      self.completed = true;
    }
    drop_contained(old);
    result
  }
}

impl<T> Future for Receiver<T> {
  type Output = Result<T, RecvError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if this.completed {
        return Poll::Ready(Err(RecvError));
      }
      let mut replacement = Some(cx.waker().clone());
      let (result, old) = {
        let mut state = this
          .shared
          .state
          .lock()
          .unwrap_or_else(PoisonError::into_inner);
        if let Some(value) = state.value.take() {
          (Poll::Ready(Ok(value)), state.receiver_waker.take())
        } else if state.receiver_closed || !state.sender_alive {
          (Poll::Ready(Err(RecvError)), state.receiver_waker.take())
        } else {
          let waker = match replacement.take() {
            Some(waker) => waker,
            None => unreachable!("replacement is prepared before locking"),
          };
          (Poll::Pending, state.receiver_waker.replace(waker))
        }
      };
      if result.is_ready() {
        this.completed = true;
      }
      drop_contained(old);
      drop_contained(replacement);
      result
    })
  }
}

impl<T> Drop for Receiver<T> {
  fn drop(&mut self) {
    let (value, receiver, sender) = {
      let mut state = self
        .shared
        .state
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
      state.receiver_closed = true;
      (
        state.value.take(),
        state.receiver_waker.take(),
        state.sender_waker.take(),
      )
    };
    wake_contained(sender);
    drop_contained(receiver);
    drop_contained(value);
  }
}

impl<T> Future for Closed<'_, T> {
  type Output = ();

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if this.completed {
        return Poll::Ready(());
      }
      let Some(shared) = &this.sender.shared else {
        this.completed = true;
        return Poll::Ready(());
      };
      let mut replacement = Some(cx.waker().clone());
      let (closed, old) = {
        let mut state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.receiver_closed {
          (true, state.sender_waker.take())
        } else {
          let waker = match replacement.take() {
            Some(waker) => waker,
            None => unreachable!("replacement is prepared before locking"),
          };
          (false, state.sender_waker.replace(waker))
        }
      };
      drop_contained(old);
      drop_contained(replacement);
      if closed {
        this.completed = true;
        Poll::Ready(())
      } else {
        Poll::Pending
      }
    })
  }
}

impl<T> Drop for Closed<'_, T> {
  fn drop(&mut self) {
    if let Some(shared) = &self.sender.shared {
      let old = {
        let mut state = shared.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.sender_waker.take()
      };
      drop_contained(old);
    }
  }
}

fn wake_contained(waker: Option<Waker>) {
  if let Some(waker) = waker
    && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
  {
    drop_contained(payload);
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;
  use std::cell::Cell;
  use std::sync::Weak;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::Wake;

  fn poll<T>(receiver: &mut Receiver<T>) -> Poll<Result<T, RecvError>> {
    Pin::new(receiver).poll(&mut Context::from_waker(Waker::noop()))
  }

  struct CountWake(AtomicUsize);
  impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  #[test]
  fn receives_exactly_once_and_close_preserves_an_already_sent_value() {
    let (sender, mut receiver) = channel();
    assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
    assert!(poll(&mut receiver).is_pending());
    assert!(sender.send(7).is_ok());
    receiver.close();
    assert_eq!(poll(&mut receiver), Poll::Ready(Ok(7)));
    assert_eq!(poll(&mut receiver), Poll::Ready(Err(RecvError)));
    assert_eq!(receiver.try_recv(), Err(TryRecvError::Closed));
  }

  #[test]
  fn closing_rejects_send_with_the_original_value() {
    let (sender, mut receiver) = channel();
    receiver.close();
    assert!(sender.is_closed());
    assert_eq!(
      sender.send(String::from("original")),
      Err(String::from("original"))
    );
    assert_eq!(poll(&mut receiver), Poll::Ready(Err(RecvError)));
  }

  #[test]
  fn dropping_sender_wakes_pending_receiver_and_publishes_closure() {
    let (sender, mut receiver) = channel::<usize>();
    let count = Arc::new(CountWake(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&count));
    assert!(
      Pin::new(&mut receiver)
        .poll(&mut Context::from_waker(&waker))
        .is_pending()
    );
    drop(sender);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert_eq!(poll(&mut receiver), Poll::Ready(Err(RecvError)));
  }

  #[test]
  fn cancelled_closed_notification_releases_waker_and_can_be_registered_again() {
    let (mut sender, receiver) = channel::<usize>();
    let count = Arc::new(CountWake(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&count));
    {
      let mut closed = Box::pin(sender.closed());
      assert!(
        closed
          .as_mut()
          .poll(&mut Context::from_waker(&waker))
          .is_pending()
      );
      assert_eq!(Arc::strong_count(&count), 3);
    }
    assert_eq!(Arc::strong_count(&count), 2);
    let mut closed = Box::pin(sender.closed());
    assert!(
      closed
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_pending()
    );
    drop(receiver);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert!(
      closed
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_ready()
    );
  }

  #[test]
  fn managed_output_charge_survives_send_and_receive_until_final_release() {
    use crate::runtime::managed::{ResourceLimits, ResourceScope};
    let scope = ResourceScope::new(ResourceLimits {
      managed_memory: 16,
      ..ResourceLimits::default()
    });
    let buffer = scope.try_alloc_zeroed(8).unwrap();
    let held = buffer.charged_bytes();
    let (sender, mut receiver) = channel();
    assert!(sender.send(buffer).is_ok());
    assert_eq!(scope.snapshot().managed_memory, held);
    let result = receiver.try_recv().unwrap();
    drop(receiver);
    assert_eq!(scope.snapshot().managed_memory, held);
    let clone = result.clone();
    drop(result);
    assert_eq!(scope.snapshot().managed_memory, held);
    drop(clone);
    assert_eq!(scope.snapshot().managed_memory, 0);
  }

  #[test]
  fn receiver_drop_destroys_message_outside_lock_and_contains_its_panic() {
    struct Probe {
      shared: Weak<Shared<Self>>,
      drops: Arc<AtomicUsize>,
    }
    impl Drop for Probe {
      fn drop(&mut self) {
        let shared = self.shared.upgrade().unwrap();
        assert!(shared.state.try_lock().is_ok());
        self.drops.fetch_add(1, Ordering::SeqCst);
        panic!("message destructor");
      }
    }
    let (sender, receiver) = channel();
    let drops = Arc::new(AtomicUsize::new(0));
    let probe = Probe {
      shared: Arc::downgrade(&receiver.shared),
      drops: Arc::clone(&drops),
    };
    assert!(sender.send(probe).is_ok());
    drop(receiver);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn a_panicking_receiver_wake_does_not_lose_the_sent_value() {
    struct PanicWake;
    impl Wake for PanicWake {
      fn wake(self: Arc<Self>) {
        panic!("receiver wake");
      }
    }
    let (sender, mut receiver) = channel();
    let waker = Waker::from(Arc::new(PanicWake));
    assert!(
      Pin::new(&mut receiver)
        .poll(&mut Context::from_waker(&waker))
        .is_pending()
    );
    assert!(sender.send(42).is_ok());
    assert_eq!(poll(&mut receiver), Poll::Ready(Ok(42)));
  }

  #[test]
  fn sender_receiver_and_closed_future_move_without_a_sync_value() {
    fn require_send<T: Send>(_: &T) {}
    fn require_sync<T: Sync>(_: &T) {}
    let (mut sender, receiver) = channel::<Cell<usize>>();
    require_send(&sender);
    require_sync(&sender);
    require_send(&receiver);
    require_sync(&receiver);
    require_send(&sender.closed());
  }
}

#[cfg(all(test, loom))]
mod model {
  use super::*;
  use loom::sync::atomic::{AtomicUsize, Ordering};
  use loom::thread;
  use std::sync::Arc as StdArc;
  use std::task::Wake;

  struct WakeCount(Arc<AtomicUsize>);
  impl Wake for WakeCount {
    fn wake(self: StdArc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  #[test]
  fn send_racing_registration_delivers_or_wakes() {
    loom::model(|| {
      let (sender, mut receiver) = channel();
      let count = Arc::new(AtomicUsize::new(0));
      let observed = Arc::clone(&count);
      let observer = thread::spawn(move || {
        let waker = Waker::from(StdArc::new(WakeCount(observed)));
        let first = Pin::new(&mut receiver).poll(&mut Context::from_waker(&waker));
        (receiver, first)
      });
      let publish = thread::spawn(move || assert!(sender.send(7).is_ok()));
      let (mut receiver, first) = observer.join().unwrap();
      publish.join().unwrap();
      match first {
        Poll::Ready(result) => assert_eq!(result, Ok(7)),
        Poll::Pending => {
          assert_eq!(count.load(Ordering::SeqCst), 1);
          assert_eq!(receiver.try_recv(), Ok(7));
        }
      }
    });
  }

  #[test]
  fn send_racing_receiver_drop_destroys_the_value_once() {
    loom::model(|| {
      struct Probe(Arc<AtomicUsize>);
      impl Drop for Probe {
        fn drop(&mut self) {
          self.0.fetch_add(1, Ordering::SeqCst);
        }
      }
      let drops = Arc::new(AtomicUsize::new(0));
      let value = Probe(Arc::clone(&drops));
      let (sender, receiver) = channel();
      let send = thread::spawn(move || drop(sender.send(value)));
      let close = thread::spawn(move || drop(receiver));
      send.join().unwrap();
      close.join().unwrap();
      assert_eq!(drops.load(Ordering::SeqCst), 1);
    });
  }
}
