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

struct DropCounter(Arc<AtomicUsize>);

impl Drop for DropCounter {
  fn drop(&mut self) {
    self.0.fetch_add(1, Ordering::SeqCst);
  }
}

struct CountReady {
  polls: Arc<AtomicUsize>,
  value: usize,
}

impl Future for CountReady {
  type Output = usize;

  fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
    self.polls.fetch_add(1, Ordering::SeqCst);
    Poll::Ready(self.value)
  }
}

struct CountingWake {
  wakes: Arc<AtomicUsize>,
  delegate: std::task::Waker,
}

impl std::task::Wake for CountingWake {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.wakes.fetch_add(1, Ordering::SeqCst);
    self.delegate.wake_by_ref();
  }
}

#[test]
fn initialized_once_cell_ready_loop_yields_at_the_shared_budget() {
  let cell = Arc::new(crate::runtime::once_cell::AsyncOnceCell::new_with(5, 0).unwrap());
  let calls = Arc::new(AtomicUsize::new(0));
  let progress = Arc::new(AtomicUsize::new(0));
  let max_batch = Arc::new(AtomicUsize::new(0));
  let loop_cell = Arc::clone(&cell);
  let loop_calls = Arc::clone(&calls);
  let loop_progress = Arc::clone(&progress);
  let loop_max_batch = Arc::clone(&max_batch);
  let future = async move {
    let mut batch = 0;
    let mut previous_remaining = DEFAULT_BUDGET as u16;
    loop {
      let calls = Arc::clone(&loop_calls);
      let result = loop_cell
        .get_or_init(move || {
          calls.fetch_add(1, Ordering::SeqCst);
          std::future::ready(9)
        })
        .await;
      assert!(matches!(result, Ok(snapshot) if *snapshot == 5));
      record_ready(
        &loop_progress,
        &loop_max_batch,
        &mut batch,
        &mut previous_remaining,
      );
    }
  };

  assert_ready_loop_yields(future, progress, max_batch);
  assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn exhausted_budget_preserves_initialized_once_cell_state_and_wakes() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let cell = crate::runtime::once_cell::AsyncOnceCell::new_with(5, 0).unwrap();
  let held_snapshot = cell.get().unwrap();
  let initial_strong_count = Arc::strong_count(&held_snapshot);
  let factory_drops = Arc::new(AtomicUsize::new(0));
  let factory_calls = Arc::new(AtomicUsize::new(0));
  let initializer_polls = Arc::new(AtomicUsize::new(0));
  let marker = DropCounter(Arc::clone(&factory_drops));
  let call_count = Arc::clone(&factory_calls);
  let poll_count = Arc::clone(&initializer_polls);
  let mut init = cell.get_or_init(move || {
    call_count.fetch_add(1, Ordering::SeqCst);
    drop(marker);
    CountReady {
      polls: poll_count,
      value: 9,
    }
  });
  let wakes = Arc::new(AtomicUsize::new(0));
  let mut first_poll = true;

  let snapshot = runtime
    .block_on(poll_fn(|context| {
      if first_poll {
        first_poll = false;
        exhaust_budget(context);
        let waker = std::task::Waker::from(Arc::new(CountingWake {
          wakes: Arc::clone(&wakes),
          delegate: context.waker().clone(),
        }));
        let mut gated_context = Context::from_waker(&waker);
        assert!(Pin::new(&mut init).poll(&mut gated_context).is_pending());
        assert_eq!(super::entry::budget_remaining(), 0);
        assert_eq!(Arc::strong_count(&held_snapshot), initial_strong_count);
        assert_eq!(factory_drops.load(Ordering::SeqCst), 0);
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        assert_eq!(initializer_polls.load(Ordering::SeqCst), 0);
        assert!(cell.initialized());
        Poll::Pending
      } else {
        match Pin::new(&mut init).poll(context) {
          Poll::Ready(Ok(snapshot)) => {
            assert_eq!(super::entry::budget_remaining(), DEFAULT_BUDGET as u16 - 1);
            Poll::Ready(snapshot)
          }
          Poll::Ready(Err(error)) => panic!("unexpected initialization result: {error:?}"),
          Poll::Pending => Poll::Pending,
        }
      }
    }))
    .unwrap();

  assert_eq!(wakes.load(Ordering::SeqCst), 1);
  assert_eq!(factory_drops.load(Ordering::SeqCst), 1);
  assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
  assert_eq!(initializer_polls.load(Ordering::SeqCst), 0);
  assert_eq!(Arc::strong_count(&held_snapshot), initial_strong_count + 1);
  assert!(Arc::ptr_eq(&snapshot, &held_snapshot));
  drop(snapshot);
  assert_eq!(Arc::strong_count(&held_snapshot), initial_strong_count);
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
}

#[test]
fn exhausted_budget_does_not_change_once_cell_admission() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();

  let cell = crate::runtime::once_cell::AsyncOnceCell::new(0).unwrap();
  let candidate_drops = Arc::new(AtomicUsize::new(0));
  let candidate_calls = Arc::new(AtomicUsize::new(0));
  let candidate_polls = Arc::new(AtomicUsize::new(0));
  let marker = DropCounter(Arc::clone(&candidate_drops));
  let call_count = Arc::clone(&candidate_calls);
  let poll_count = Arc::clone(&candidate_polls);
  let mut candidate = cell.get_or_init(move || {
    call_count.fetch_add(1, Ordering::SeqCst);
    drop(marker);
    CountReady {
      polls: poll_count,
      value: 11,
    }
  });
  let mut competitor = cell.get_or_init(|| std::future::ready(23));
  let wakes = Arc::new(AtomicUsize::new(0));
  let mut first_poll = true;

  let (winner, admitted_later) = runtime
    .block_on(poll_fn(|context| {
      if first_poll {
        first_poll = false;
        exhaust_budget(context);
        let waker = std::task::Waker::from(Arc::new(CountingWake {
          wakes: Arc::clone(&wakes),
          delegate: context.waker().clone(),
        }));
        let mut gated_context = Context::from_waker(&waker);
        assert!(
          Pin::new(&mut candidate)
            .poll(&mut gated_context)
            .is_pending()
        );
        assert_eq!(candidate_drops.load(Ordering::SeqCst), 0);
        assert_eq!(candidate_calls.load(Ordering::SeqCst), 0);
        assert_eq!(candidate_polls.load(Ordering::SeqCst), 0);
        assert!(!cell.initialized());
        Poll::Pending
      } else {
        let winner = match Pin::new(&mut competitor).poll(context) {
          Poll::Ready(Ok(snapshot)) => snapshot,
          Poll::Ready(Err(error)) => panic!("unexpected contender result: {error:?}"),
          Poll::Pending => return Poll::Pending,
        };
        let admitted_later = match Pin::new(&mut candidate).poll(context) {
          Poll::Ready(Ok(snapshot)) => snapshot,
          Poll::Ready(Err(error)) => panic!("unexpected candidate result: {error:?}"),
          Poll::Pending => return Poll::Pending,
        };
        Poll::Ready((winner, admitted_later))
      }
    }))
    .unwrap();

  assert_eq!(wakes.load(Ordering::SeqCst), 1);
  assert!(Arc::ptr_eq(&winner, &admitted_later));
  assert_eq!(*winner, 23);
  assert_eq!(candidate_drops.load(Ordering::SeqCst), 1);
  assert_eq!(candidate_calls.load(Ordering::SeqCst), 0);
  assert_eq!(candidate_polls.load(Ordering::SeqCst), 0);
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
}

#[test]
fn once_cell_initializer_keeps_descendant_charges_on_pending_and_unwind() {
  use std::panic::{AssertUnwindSafe, catch_unwind};

  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();

  let notify = Arc::new(crate::runtime::notify::Notify::new(1).unwrap());
  notify.notify_one().unwrap();
  let ready_cell = crate::runtime::once_cell::AsyncOnceCell::new(0).unwrap();
  let ready_notify = Arc::clone(&notify);
  let mut ready_init = ready_cell.get_or_init(move || async move {
    ready_notify.notified().await.unwrap();
    13
  });
  let ready_result = runtime
    .block_on(poll_fn(|context| {
      let before = super::entry::budget_remaining();
      match Pin::new(&mut ready_init).poll(context) {
        Poll::Ready(Ok(snapshot)) => {
          assert_eq!(super::entry::budget_remaining(), before - 2);
          Poll::Ready(snapshot)
        }
        Poll::Ready(Err(error)) => panic!("unexpected ready initializer result: {error:?}"),
        Poll::Pending => Poll::Pending,
      }
    }))
    .unwrap();
  assert_eq!(*ready_result, 13);

  let pending_notify = Arc::new(crate::runtime::notify::Notify::new(1).unwrap());
  pending_notify.notify_one().unwrap();
  let cell = crate::runtime::once_cell::AsyncOnceCell::new(0).unwrap();
  let initializer_notify = Arc::clone(&pending_notify);
  let mut init = cell.get_or_init(move || async move {
    initializer_notify.notified().await.unwrap();
    std::future::pending::<usize>().await
  });
  let mut first_poll = true;
  runtime
    .block_on(poll_fn(|context| {
      let before = super::entry::budget_remaining();
      assert!(Pin::new(&mut init).poll(context).is_pending());
      if first_poll {
        first_poll = false;
        assert_eq!(super::entry::budget_remaining(), before - 2);
        context.waker().wake_by_ref();
        Poll::Pending
      } else {
        assert_eq!(super::entry::budget_remaining(), before);
        Poll::Ready(())
      }
    }))
    .unwrap();
  assert!(!cell.initialized());
  drop(init);
  assert!(!cell.initialized());
  let mut retry = cell.get_or_init(|| std::future::ready(19));
  let retry_result = runtime
    .block_on(poll_fn(|context| {
      match Pin::new(&mut retry).poll(context) {
        Poll::Ready(result) => Poll::Ready(result),
        Poll::Pending => Poll::Pending,
      }
    }))
    .unwrap();
  assert!(matches!(retry_result, Ok(snapshot) if *snapshot == 19));

  let panic_notify = Arc::new(crate::runtime::notify::Notify::new(1).unwrap());
  panic_notify.notify_one().unwrap();
  let panicking_cell = crate::runtime::once_cell::AsyncOnceCell::new(0).unwrap();
  let initializer_notify = Arc::clone(&panic_notify);
  let mut panicking = panicking_cell.get_or_init(move || async move {
    initializer_notify.notified().await.unwrap();
    panic!("injected initializer panic after descendant progress");
  });
  runtime
    .block_on(poll_fn(|context| {
      let before = super::entry::budget_remaining();
      let panic = catch_unwind(AssertUnwindSafe(|| Pin::new(&mut panicking).poll(context)));
      assert!(panic.is_err());
      assert_eq!(super::entry::budget_remaining(), before - 2);
      assert!(!panicking_cell.initialized());
      assert!(matches!(
        Pin::new(&mut panicking).poll(context),
        Poll::Ready(Err(crate::runtime::once_cell::InitError::Completed))
      ));
      Poll::Ready(())
    }))
    .unwrap();
  let mut panic_retry = panicking_cell.get_or_init(|| std::future::ready(29));
  let retry_result = runtime
    .block_on(poll_fn(|context| {
      match Pin::new(&mut panic_retry).poll(context) {
        Poll::Ready(result) => Poll::Ready(result),
        Poll::Pending => Poll::Pending,
      }
    }))
    .unwrap();
  assert!(matches!(retry_result, Ok(snapshot) if *snapshot == 29));
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
}

#[test]
fn manual_once_cell_poll_remains_outside_cooperative_accounting() {
  let cell = crate::runtime::once_cell::AsyncOnceCell::new_with(31, 0).unwrap();
  let mut init = cell.get_or_init(|| std::future::ready(41));
  super::entry::reset_budget();
  assert!(!super::entry::cooperative_poll_active());
  assert_eq!(super::entry::budget_remaining(), DEFAULT_BUDGET as u16);
  assert!(matches!(
    Pin::new(&mut init).poll(&mut Context::from_waker(std::task::Waker::noop())),
    Poll::Ready(Ok(snapshot)) if *snapshot == 31
  ));
  assert_eq!(super::entry::budget_remaining(), DEFAULT_BUDGET as u16);
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
