use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use super::protocol::{Shared, wake_all};
use super::{SignalError, SignalKind};

struct CountWake(AtomicUsize);
impl Wake for CountWake {
  fn wake(self: Arc<Self>) {
    self.0.fetch_add(1, Ordering::SeqCst);
  }
}

fn deliver(shared: &Shared, mask: u64) {
  let mut wakes = Vec::with_capacity(shared.capacity());
  shared.deliver(mask, &mut wakes);
  wake_all(&mut wakes);
}

#[test]
fn invalid_signals_and_capacity_are_rejected_before_admission() {
  for raw in [-1, 0, 4, 8, 9, 11, 19, 32, 33, 65, i32::MAX] {
    assert_eq!(SignalKind::from_raw(raw), Err(SignalError::InvalidKind));
  }
  assert_eq!(SignalKind::from_raw(64).unwrap().mask(), 1 << 63);
  assert!(matches!(Shared::new(0), Err(SignalError::InvalidCapacity)));
  assert!(matches!(
    Shared::new(usize::MAX),
    Err(SignalError::InvalidCapacity)
  ));
}

#[test]
fn delivery_is_per_kind_coalesces_and_releases_listener_slots() {
  let shared = Shared::new(3).unwrap();
  let kind = SignalKind::user_defined1();
  let mut first = Shared::subscribe(&shared, kind).unwrap();
  let mut second = Shared::subscribe(&shared, kind).unwrap();
  let mut other = Shared::subscribe(&shared, SignalKind::terminate()).unwrap();
  assert!(matches!(
    Shared::subscribe(&shared, kind),
    Err(SignalError::Full)
  ));
  deliver(&shared, kind.mask());
  deliver(&shared, kind.mask());
  assert_eq!(first.try_recv(), Ok(true));
  assert_eq!(first.try_recv(), Ok(false));
  assert_eq!(second.try_recv(), Ok(true));
  assert_eq!(other.try_recv(), Ok(false));
  drop(first);
  let mut replacement = Shared::subscribe(&shared, kind).unwrap();
  assert_eq!(replacement.try_recv(), Ok(false));
}

#[test]
fn cancellation_removes_waker_but_preserves_unseen_event() {
  let shared = Shared::new(1).unwrap();
  let kind = SignalKind::interrupt();
  let mut signal = Shared::subscribe(&shared, kind).unwrap();
  let count = Arc::new(CountWake(AtomicUsize::new(0)));
  let waker = Waker::from(Arc::clone(&count));
  let mut future = signal.recv();
  assert_eq!(
    Pin::new(&mut future).poll(&mut Context::from_waker(&waker)),
    Poll::Pending
  );
  deliver(&shared, kind.mask());
  assert_eq!(count.0.load(Ordering::SeqCst), 1);
  drop(future);
  assert_eq!(signal.try_recv(), Ok(true));
  assert_eq!(signal.try_recv(), Ok(false));
  let mut next = signal.recv();
  assert_eq!(
    Pin::new(&mut next).poll(&mut Context::from_waker(&waker)),
    Poll::Pending
  );
  drop(next);
  deliver(&shared, kind.mask());
  assert_eq!(count.0.load(Ordering::SeqCst), 1);
  assert_eq!(signal.try_recv(), Ok(true));
}

#[test]
fn completed_receive_does_not_consume_a_later_event() {
  let shared = Shared::new(1).unwrap();
  let kind = SignalKind::interrupt();
  let mut signal = Shared::subscribe(&shared, kind).unwrap();
  deliver(&shared, kind.mask());
  let mut future = signal.recv();
  let mut cx = Context::from_waker(Waker::noop());
  assert_eq!(Pin::new(&mut future).poll(&mut cx), Poll::Ready(Ok(())));
  deliver(&shared, kind.mask());
  assert_eq!(
    Pin::new(&mut future).poll(&mut cx),
    Poll::Ready(Err(SignalError::Completed))
  );
  drop(future);
  assert_eq!(signal.try_recv(), Ok(true));
}

#[test]
fn close_wakes_waiters_preserves_pending_and_rejects_late_delivery() {
  let shared = Shared::new(2).unwrap();
  let kind = SignalKind::interrupt();
  let mut ready = Shared::subscribe(&shared, kind).unwrap();
  let mut waiting = Shared::subscribe(&shared, SignalKind::terminate()).unwrap();
  let count = Arc::new(CountWake(AtomicUsize::new(0)));
  let waker = Waker::from(Arc::clone(&count));
  let mut future = waiting.recv();
  assert_eq!(
    Pin::new(&mut future).poll(&mut Context::from_waker(&waker)),
    Poll::Pending
  );
  deliver(&shared, kind.mask());
  let mut wakes = Vec::with_capacity(2);
  shared.close(&mut wakes);
  wake_all(&mut wakes);
  assert_eq!(count.0.load(Ordering::SeqCst), 1);
  assert_eq!(
    Pin::new(&mut future).poll(&mut Context::from_waker(&waker)),
    Poll::Ready(Err(SignalError::Closed))
  );
  assert_eq!(ready.try_recv(), Ok(true));
  deliver(&shared, kind.mask());
  assert_eq!(ready.try_recv(), Err(SignalError::Closed));
  assert!(matches!(
    Shared::subscribe(&shared, kind),
    Err(SignalError::Closed)
  ));
}

#[test]
fn waker_callback_can_reenter_admission_without_a_held_lock() {
  struct ReentrantWake {
    shared: Arc<Shared>,
    retained: Mutex<Option<super::Signal>>,
  }
  impl Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
      let next = Shared::subscribe(&self.shared, SignalKind::terminate()).unwrap();
      *self.retained.lock().unwrap() = Some(next);
    }
  }
  let shared = Shared::new(2).unwrap();
  let kind = SignalKind::interrupt();
  let mut signal = Shared::subscribe(&shared, kind).unwrap();
  let wake = Arc::new(ReentrantWake {
    shared: Arc::clone(&shared),
    retained: Mutex::new(None),
  });
  let waker = Waker::from(Arc::clone(&wake));
  let mut future = signal.recv();
  assert_eq!(
    Pin::new(&mut future).poll(&mut Context::from_waker(&waker)),
    Poll::Pending
  );
  deliver(&shared, kind.mask());
  assert!(wake.retained.lock().unwrap().is_some());
  assert_eq!(
    Pin::new(&mut future).poll(&mut Context::from_waker(&waker)),
    Poll::Ready(Ok(()))
  );
}

#[test]
fn panicking_wake_does_not_prevent_delivery_to_another_listener() {
  struct PanicWake;
  impl Wake for PanicWake {
    fn wake(self: Arc<Self>) {
      panic!("signal wake panic");
    }
  }
  let shared = Shared::new(2).unwrap();
  let kind = SignalKind::interrupt();
  let mut first = Shared::subscribe(&shared, kind).unwrap();
  let mut second = Shared::subscribe(&shared, kind).unwrap();
  let bad = Waker::from(Arc::new(PanicWake));
  let good_count = Arc::new(CountWake(AtomicUsize::new(0)));
  let good = Waker::from(Arc::clone(&good_count));
  let mut a = first.recv();
  let mut b = second.recv();
  assert_eq!(
    Pin::new(&mut a).poll(&mut Context::from_waker(&bad)),
    Poll::Pending
  );
  assert_eq!(
    Pin::new(&mut b).poll(&mut Context::from_waker(&good)),
    Poll::Pending
  );
  deliver(&shared, kind.mask());
  assert_eq!(good_count.0.load(Ordering::SeqCst), 1);
  assert_eq!(
    Pin::new(&mut a).poll(&mut Context::from_waker(&bad)),
    Poll::Ready(Ok(()))
  );
  assert_eq!(
    Pin::new(&mut b).poll(&mut Context::from_waker(&good)),
    Poll::Ready(Ok(()))
  );
}
