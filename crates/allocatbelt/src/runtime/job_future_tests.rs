//! Awaited blocking-result publication and waker lifecycle regressions.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, Wake, Waker};

use super::{Control, Job, Packet};
use crate::runtime::worker::Ident;

struct Counter(AtomicUsize);
impl Wake for Counter {
  fn wake(self: Arc<Self>) {
    self.0.fetch_add(1, Ordering::SeqCst);
  }
}

fn job(packet: Arc<Packet<u64>>) -> Job<u64> {
  Job::new(Control::new(Ident::new(u64::MAX)), packet)
}

#[test]
fn awaited_job_wakes_once_and_yields_the_published_result() {
  let packet = Packet::new();
  let mut job = job(Arc::clone(&packet));
  let counter = Arc::new(Counter(AtomicUsize::new(0)));
  let waker = Waker::from(Arc::clone(&counter));
  let mut context = Context::from_waker(&waker);
  assert!(Pin::new(&mut job).poll(&mut context).is_pending());
  assert!(Pin::new(&mut job).poll(&mut context).is_pending());
  assert!(packet.publish(Ok(42)).is_none());
  assert_eq!(counter.0.load(Ordering::SeqCst), 1);
  assert!(matches!(
    Pin::new(&mut job).poll(&mut context),
    Poll::Ready(Ok(42))
  ));
}

#[test]
fn registration_racing_publication_does_not_lose_a_wake() {
  for _ in 0..64 {
    let packet = Packet::new();
    let mut job = job(Arc::clone(&packet));
    let counter = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&counter));
    let barrier = Arc::new(Barrier::new(2));
    let publisher = {
      let barrier = Arc::clone(&barrier);
      std::thread::spawn(move || {
        barrier.wait();
        assert!(packet.publish(Ok(7)).is_none());
      })
    };
    barrier.wait();
    let pending = Pin::new(&mut job)
      .poll(&mut Context::from_waker(&waker))
      .is_pending();
    publisher.join().unwrap();
    if pending {
      assert_eq!(counter.0.load(Ordering::SeqCst), 1);
      assert!(matches!(
        Pin::new(&mut job).poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Ok(7))
      ));
    }
  }
}

#[test]
fn publication_wakes_outside_the_packet_lock_and_contains_panic() {
  struct Adversarial(Arc<Packet<u64>>);
  impl Wake for Adversarial {
    fn wake(self: Arc<Self>) {
      assert!(self.0.slot.try_lock().is_ok());
      panic!("publication waker panics");
    }
  }
  let packet = Packet::new();
  let mut job = job(Arc::clone(&packet));
  let waker = Waker::from(Arc::new(Adversarial(Arc::clone(&packet))));
  let mut context = Context::from_waker(&waker);
  assert!(Pin::new(&mut job).poll(&mut context).is_pending());
  assert!(packet.publish(Ok(5)).is_none());
  assert!(matches!(
    Pin::new(&mut job).poll(&mut context),
    Poll::Ready(Ok(5))
  ));
}

#[test]
fn dropping_a_registered_join_returns_unclaimed_publication() {
  let packet = Packet::new();
  let mut job = job(Arc::clone(&packet));
  let counter = Arc::new(Counter(AtomicUsize::new(0)));
  let waker = Waker::from(Arc::clone(&counter));
  assert!(
    Pin::new(&mut job)
      .poll(&mut Context::from_waker(&waker))
      .is_pending()
  );
  drop(job);
  assert!(matches!(packet.publish(Ok(11)), Some(Ok(11))));
  assert_eq!(counter.0.load(Ordering::SeqCst), 0);
}
