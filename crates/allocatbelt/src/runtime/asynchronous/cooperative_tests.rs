use std::future::Future;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use super::{AsyncConfig, AsyncJoinError, AsyncRuntime, AsyncShutdown};

const WATCHDOG: Duration = Duration::from_secs(3);
const DEFAULT_BUDGET: usize = 64;

fn exhaust_budget(context: &mut Context<'_>) {
  for _ in 0..DEFAULT_BUDGET {
    assert!(super::poll_cooperative(context, |_| Poll::Ready(())).is_ready());
  }
  assert_eq!(super::entry::budget_remaining(), 0);
}

fn assert_ready_loop_yields(
  future: impl Future<Output = ()> + Send + 'static,
  progress: Arc<AtomicUsize>,
  max_batch: Arc<AtomicUsize>,
) {
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
  let deadline = Instant::now() + WATCHDOG;
  while progress.load(Ordering::SeqCst) == 0 {
    assert!(Instant::now() < deadline, "ready loop did not start");
    thread::yield_now();
  }

  let observed = Arc::new(AtomicUsize::new(0));
  let sibling_observed = Arc::clone(&observed);
  let sibling_progress = Arc::clone(&progress);
  let sibling = runtime
    .handle()
    .spawn(async move {
      sibling_observed.store(sibling_progress.load(Ordering::SeqCst), Ordering::SeqCst);
    })
    .unwrap_or_else(|error| panic!("sibling task spawn failed: {error}"));
  let deadline = Instant::now() + WATCHDOG;
  while !sibling.is_finished() {
    assert!(Instant::now() < deadline, "ready-loop sibling did not run");
    thread::yield_now();
  }

  let progress_at_sibling = observed.load(Ordering::SeqCst);
  hot.abort_handle().abort();
  let deadline = Instant::now() + WATCHDOG;
  while !hot.is_finished() {
    assert!(Instant::now() < deadline, "ready loop abort did not finish");
    thread::yield_now();
  }
  let hot_result = runtime
    .block_on(hot)
    .unwrap_or_else(|error| panic!("hot task join failed: {error}"));
  assert!(matches!(hot_result, Err(AsyncJoinError::Cancelled)));
  let sibling_result = runtime
    .block_on(sibling)
    .unwrap_or_else(|error| panic!("sibling task join failed: {error}"));
  assert!(matches!(sibling_result, Ok(())));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("runtime shutdown failed: {error}"));

  assert!(progress_at_sibling > 0, "sibling ran before the ready loop");
  assert!(
    max_batch.load(Ordering::SeqCst) <= DEFAULT_BUDGET,
    "one outer poll completed more than {DEFAULT_BUDGET} ready primitives"
  );
}

fn record_ready(
  progress: &AtomicUsize,
  max_batch: &AtomicUsize,
  batch: &mut usize,
  previous_remaining: &mut u16,
) {
  let remaining = super::entry::budget_remaining();
  if remaining >= *previous_remaining {
    *batch = 0;
  }
  *batch += 1;
  max_batch.fetch_max(*batch, Ordering::SeqCst);
  *previous_remaining = remaining;
  progress.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn notify_ready_loop_yields_at_the_shared_budget() {
  let notify = Arc::new(crate::runtime::notify::Notify::new(1).unwrap());
  let progress = Arc::new(AtomicUsize::new(0));
  let max_batch = Arc::new(AtomicUsize::new(0));
  let future_notify = Arc::clone(&notify);
  let loop_progress = Arc::clone(&progress);
  let loop_max_batch = Arc::clone(&max_batch);
  let future = async move {
    let mut batch = 0;
    let mut previous_remaining = DEFAULT_BUDGET as u16;
    loop {
      future_notify.notify_one().unwrap();
      future_notify.notified().await.unwrap();
      record_ready(
        &loop_progress,
        &loop_max_batch,
        &mut batch,
        &mut previous_remaining,
      );
    }
  };
  assert_ready_loop_yields(future, progress, max_batch);
}

#[test]
fn watch_changed_ready_loop_yields_at_the_shared_budget() {
  let (sender, mut receiver) = crate::runtime::watch::channel(0_u64, 1).unwrap();
  let progress = Arc::new(AtomicUsize::new(0));
  let max_batch = Arc::new(AtomicUsize::new(0));
  let loop_progress = Arc::clone(&progress);
  let loop_max_batch = Arc::clone(&max_batch);
  let future = async move {
    let mut version = 0_u64;
    let mut batch = 0;
    let mut previous_remaining = DEFAULT_BUDGET as u16;
    loop {
      version += 1;
      sender.send(version).unwrap();
      receiver.changed().await.unwrap();
      record_ready(
        &loop_progress,
        &loop_max_batch,
        &mut batch,
        &mut previous_remaining,
      );
    }
  };
  assert_ready_loop_yields(future, progress, max_batch);
}

#[test]
fn broadcast_ready_loop_yields_at_the_shared_budget() {
  let (sender, mut receiver) = crate::runtime::broadcast::channel(1, 1).unwrap();
  let progress = Arc::new(AtomicUsize::new(0));
  let max_batch = Arc::new(AtomicUsize::new(0));
  let loop_progress = Arc::clone(&progress);
  let loop_max_batch = Arc::clone(&max_batch);
  let future = async move {
    let mut sequence = 0_u64;
    let mut batch = 0;
    let mut previous_remaining = DEFAULT_BUDGET as u16;
    loop {
      sequence += 1;
      sender.send(sequence).unwrap();
      receiver.recv().await.unwrap();
      record_ready(
        &loop_progress,
        &loop_max_batch,
        &mut batch,
        &mut previous_remaining,
      );
    }
  };
  assert_ready_loop_yields(future, progress, max_batch);
}

#[test]
fn barrier_ready_loop_yields_at_the_shared_budget() {
  let barrier = Arc::new(crate::runtime::barrier::Barrier::new(1, 1).unwrap());
  let progress = Arc::new(AtomicUsize::new(0));
  let max_batch = Arc::new(AtomicUsize::new(0));
  let future_barrier = Arc::clone(&barrier);
  let loop_progress = Arc::clone(&progress);
  let loop_max_batch = Arc::clone(&max_batch);
  let future = async move {
    let mut batch = 0;
    let mut previous_remaining = DEFAULT_BUDGET as u16;
    loop {
      future_barrier.wait().await.unwrap();
      record_ready(
        &loop_progress,
        &loop_max_batch,
        &mut batch,
        &mut previous_remaining,
      );
    }
  };
  assert_ready_loop_yields(future, progress, max_batch);
}

#[test]
fn exhausted_budget_preserves_a_stored_notify_permit_without_registering() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let notify = crate::runtime::notify::Notify::new(1).unwrap();
  let mut notified = Box::pin(notify.notified());
  notify.notify_one().unwrap();
  let mut first_poll = true;

  runtime
    .block_on(poll_fn(|context| {
      if first_poll {
        first_poll = false;
        exhaust_budget(context);
        assert!(notified.as_mut().poll(context).is_pending());
        assert!(format!("{notified:?}").contains("waiting: false"));
        assert!(format!("{notify:?}").contains("permit: true"));
        Poll::Pending
      } else {
        notified.as_mut().poll(context)
      }
    }))
    .unwrap()
    .unwrap();
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
}

#[test]
fn exhausted_budget_preserves_an_unseen_watch_version_without_registration() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let (sender, mut receiver) = crate::runtime::watch::channel(0_u8, 1).unwrap();
  sender.send(1).unwrap();
  let mut first_poll = true;

  runtime
    .block_on(poll_fn(|context| {
      if first_poll {
        first_poll = false;
        exhaust_budget(context);
        let mut future = Box::pin(receiver.changed());
        assert!(future.as_mut().poll(context).is_pending());
        assert!(format!("{future:?}").contains("registered: false"));
        drop(future);
        assert_eq!(receiver.has_changed(), Ok(true));
        Poll::Pending
      } else {
        Box::pin(receiver.changed()).as_mut().poll(context)
      }
    }))
    .unwrap()
    .unwrap();
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
}

#[test]
fn exhausted_budget_preserves_a_broadcast_message_without_consuming_it() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let (sender, mut receiver) = crate::runtime::broadcast::channel(1, 1).unwrap();
  sender.send(42_u8).unwrap();
  let mut first_poll = true;

  let value = runtime
    .block_on(poll_fn(|context| {
      if first_poll {
        first_poll = false;
        exhaust_budget(context);
        let mut receive = Box::pin(receiver.recv());
        assert!(receive.as_mut().poll(context).is_pending());
        drop(receive);
        assert_eq!(receiver.len(), 1);
        Poll::Pending
      } else {
        Pin::new(&mut receiver.recv()).poll(context)
      }
    }))
    .unwrap()
    .unwrap();
  assert_eq!(value, 42);
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
}

#[test]
fn exhausted_budget_does_not_enroll_or_advance_a_ready_barrier_wait() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let barrier = crate::runtime::barrier::Barrier::new(1, 1).unwrap();
  let mut wait = Box::pin(barrier.wait());
  let mut first_poll = true;

  let outcome = runtime
    .block_on(poll_fn(|context| {
      if first_poll {
        first_poll = false;
        exhaust_budget(context);
        assert!(wait.as_mut().poll(context).is_pending());
        assert!(format!("{wait:?}").contains("enrolled: false"));
        assert!(format!("{barrier:?}").contains("round: 0"));
        assert!(format!("{barrier:?}").contains("arrivals: 0"));
        Poll::Pending
      } else {
        wait.as_mut().poll(context)
      }
    }))
    .unwrap()
    .unwrap();
  assert!(outcome.leader);
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
}
