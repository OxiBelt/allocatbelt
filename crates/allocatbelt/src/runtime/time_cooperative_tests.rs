use std::future::{Future, poll_fn, ready};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use crate::runtime::asynchronous::{AsyncConfig, AsyncJoinError, AsyncRuntime, AsyncShutdown};
use crate::runtime::notify::Notify;
use crate::runtime::time::{MissedTickBehavior, TimeoutError, TimerDriver};

const BUDGET: usize = 64;
const WATCHDOG: Duration = Duration::from_secs(3);

fn exhaust_budget(context: &mut Context<'_>) {
  for _ in 0..BUDGET {
    assert!(
      crate::runtime::asynchronous::poll_cooperative(context, |_| Poll::Ready(())).is_ready()
    );
  }
}

fn leave_one_budget_unit(context: &mut Context<'_>) {
  for _ in 0..(BUDGET - 1) {
    assert!(
      crate::runtime::asynchronous::poll_cooperative(context, |_| Poll::Ready(())).is_ready()
    );
  }
}

struct PollDropProbe {
  polls: Arc<AtomicUsize>,
  drops: Arc<AtomicUsize>,
}

impl Future for PollDropProbe {
  type Output = ();

  fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
    self.polls.fetch_add(1, Ordering::SeqCst);
    Poll::Pending
  }
}

impl Drop for PollDropProbe {
  fn drop(&mut self) {
    self.drops.fetch_add(1, Ordering::SeqCst);
  }
}

#[test]
fn exhausted_owned_poll_preserves_sleep_timeout_and_tick_state() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let (driver, clock) = TimerDriver::new_paused(4).unwrap();
  let handle = driver.handle();
  let mut sleep = handle.sleep(Duration::from_secs(60)).unwrap();
  let old_waker = Waker::noop();
  assert!(poll_once(&mut sleep, old_waker).is_pending());
  let old_stored = sleep
    .slot
    .state
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
    .waker
    .as_ref()
    .expect("sleep stores the first waker")
    .clone();

  let now = clock.now();
  let polls = Arc::new(AtomicUsize::new(0));
  let drops = Arc::new(AtomicUsize::new(0));
  let mut timeout = handle
    .timeout_at(
      now,
      PollDropProbe {
        polls: Arc::clone(&polls),
        drops: Arc::clone(&drops),
      },
    )
    .unwrap();
  let mut interval = handle
    .interval(Duration::from_millis(5), MissedTickBehavior::Burst)
    .unwrap();
  let old_next = interval.next;
  assert_eq!(interval.next, now);

  runtime
    .block_on(poll_fn(|context| {
      exhaust_budget(context);
      assert!(Pin::new(&mut sleep).poll(context).is_pending());
      assert!(Pin::new(&mut timeout).poll(context).is_pending());
      assert!(interval.poll_tick(context).is_pending());
      Poll::Ready(())
    }))
    .unwrap();

  let current_state = sleep
    .slot
    .state
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner());
  let current_stored = current_state
    .waker
    .as_ref()
    .expect("exhausted sleep poll leaves the stored waker in place")
    .clone();
  drop(current_state);
  assert!(current_stored.will_wake(&old_stored));
  assert_eq!(polls.load(Ordering::SeqCst), 0);
  assert_eq!(drops.load(Ordering::SeqCst), 0);
  assert_eq!(interval.next, old_next);
  assert!(interval.sleep.is_elapsed());

  clock.advance(Duration::from_secs(60)).unwrap();
  assert_eq!(runtime.block_on(&mut sleep).unwrap(), Ok(()));
  assert_eq!(runtime.block_on(interval.tick()).unwrap(), Ok(old_next));
  assert_eq!(
    runtime.block_on(&mut timeout).unwrap(),
    Err(TimeoutError::Elapsed)
  );
  assert_eq!(polls.load(Ordering::SeqCst), 0);
  assert_eq!(drops.load(Ordering::SeqCst), 1);
  drop((sleep, interval));
  driver.shutdown().unwrap();
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
}

#[test]
fn timeout_and_tick_charge_once_with_their_nested_sleep() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let (driver, _) = TimerDriver::new_paused(2).unwrap();
  let handle = driver.handle();
  let mut interval = handle
    .interval(Duration::from_millis(1), MissedTickBehavior::Burst)
    .unwrap();
  runtime
    .block_on(poll_fn(|context| {
      leave_one_budget_unit(context);
      assert!(matches!(interval.poll_tick(context), Poll::Ready(Ok(_))));
      assert!(
        crate::runtime::asynchronous::poll_cooperative(context, |_| Poll::Ready(())).is_pending()
      );
      Poll::Ready(())
    }))
    .unwrap();

  let mut timeout = handle.timeout(Duration::ZERO, ready(())).unwrap();
  runtime
    .block_on(poll_fn(|context| {
      leave_one_budget_unit(context);
      assert_eq!(
        Pin::new(&mut timeout).poll(context),
        Poll::Ready(Err(TimeoutError::Elapsed))
      );
      assert!(
        crate::runtime::asynchronous::poll_cooperative(context, |_| Poll::Ready(())).is_pending()
      );
      Poll::Ready(())
    }))
    .unwrap();

  driver.shutdown().unwrap();
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
}

fn poll_once<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
  Pin::new(future).poll(&mut Context::from_waker(waker))
}

#[test]
fn more_than_one_budget_of_nested_timeouts_reaches_a_ready_leaf() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let (driver, _) = TimerDriver::new_paused(128).unwrap();
  let handle = driver.handle();
  let mut nested: Pin<Box<dyn Future<Output = Result<(), TimeoutError>>>> = Box::pin(ready(Ok(())));
  for _ in 0..(BUDGET + 8) {
    let wrapped = handle.timeout(Duration::from_secs(60), nested).unwrap();
    nested = Box::pin(async move { wrapped.await? });
  }
  let first_poll = runtime
    .block_on(poll_fn(|context| {
      let result = nested.as_mut().poll(context);
      assert!(
        result.is_ready(),
        "nested deadlines used more than one poll budget"
      );
      Poll::Ready(result)
    }))
    .unwrap();
  assert_eq!(first_poll, Poll::Ready(Ok(())));
  assert_eq!(handle.registered(), 0);
  driver.shutdown().unwrap();
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
}

fn assert_hot_timer_yields(
  driver: TimerDriver,
  future: impl Future<Output = ()> + Send + 'static,
  progress: Arc<AtomicUsize>,
) {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 4,
    max_scopes: 2,
  })
  .unwrap();
  let hot = runtime.handle().spawn(future).unwrap();
  let deadline = Instant::now() + WATCHDOG;
  while progress.load(Ordering::SeqCst) == 0 {
    assert!(Instant::now() < deadline, "timer loop did not start");
    thread::yield_now();
  }

  let observed = Arc::new(AtomicUsize::new(0));
  let sibling_progress = Arc::clone(&progress);
  let sibling_observed = Arc::clone(&observed);
  let sibling = runtime
    .handle()
    .spawn(async move {
      sibling_observed.store(sibling_progress.load(Ordering::SeqCst), Ordering::SeqCst);
    })
    .unwrap();
  wait_finished(&sibling, "timer-loop sibling did not run");
  let progress_at_sibling = observed.load(Ordering::SeqCst);

  hot.abort_handle().abort();
  wait_finished(&hot, "timer loop did not cancel");
  assert!(matches!(
    runtime.block_on(hot).unwrap(),
    Err(AsyncJoinError::Cancelled)
  ));
  assert!(matches!(runtime.block_on(sibling).unwrap(), Ok(())));
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
  driver.shutdown().unwrap();
  assert!(progress_at_sibling > 0, "sibling ran before timer progress");
}

fn wait_finished<T>(job: &crate::runtime::asynchronous::AsyncJob<T>, message: &str) {
  let deadline = Instant::now() + WATCHDOG;
  while !job.is_finished() {
    assert!(Instant::now() < deadline, "{message}");
    thread::yield_now();
  }
}

#[test]
fn ready_sleep_loop_yields_to_a_sibling() {
  let (driver, _) = TimerDriver::new_paused(1).unwrap();
  let handle = driver.handle();
  let progress = Arc::new(AtomicUsize::new(0));
  let loop_progress = Arc::clone(&progress);
  let future = async move {
    let mut sleep = handle.sleep(Duration::ZERO).unwrap();
    loop {
      sleep.reset(handle.now()).unwrap();
      (&mut sleep).await.unwrap();
      loop_progress.fetch_add(1, Ordering::SeqCst);
    }
  };
  assert_hot_timer_yields(driver, future, progress);
}

#[test]
fn ready_timeout_loop_yields_to_a_sibling() {
  let (driver, _) = TimerDriver::new_paused(1).unwrap();
  let handle = driver.handle();
  let progress = Arc::new(AtomicUsize::new(0));
  let loop_progress = Arc::clone(&progress);
  let future = async move {
    loop {
      handle
        .timeout(Duration::ZERO, ready(()))
        .unwrap()
        .await
        .unwrap_err();
      loop_progress.fetch_add(1, Ordering::SeqCst);
    }
  };
  assert_hot_timer_yields(driver, future, progress);
}

#[test]
fn ready_interval_catchup_loop_yields_to_a_sibling() {
  let (driver, clock) = TimerDriver::new_paused(1).unwrap();
  let handle = driver.handle();
  let progress = Arc::new(AtomicUsize::new(0));
  let loop_progress = Arc::clone(&progress);
  let future = async move {
    let mut interval = handle
      .interval(Duration::from_millis(1), MissedTickBehavior::Burst)
      .unwrap();
    loop {
      clock.advance(Duration::from_millis(1)).unwrap();
      interval.tick().await.unwrap();
      loop_progress.fetch_add(1, Ordering::SeqCst);
    }
  };
  assert_hot_timer_yields(driver, future, progress);
}

#[test]
fn timeout_does_not_hide_cooperative_work_in_its_inner_future() {
  let (driver, _) = TimerDriver::new_paused(1).unwrap();
  let handle = driver.handle();
  let progress = Arc::new(AtomicUsize::new(0));
  let loop_progress = Arc::clone(&progress);
  let notify = Arc::new(Notify::new(1).unwrap());
  let loop_notify = Arc::clone(&notify);
  let inner = async move {
    loop {
      loop_notify.notify_one().unwrap();
      loop_notify.notified().await.unwrap();
      loop_progress.fetch_add(1, Ordering::SeqCst);
    }
  };
  let timeout = handle.timeout(Duration::from_secs(60), inner).unwrap();
  let future = async move { timeout.await.unwrap() };
  assert_hot_timer_yields(driver, future, progress);
}

#[test]
fn foreign_manual_timeout_polls_do_not_use_the_runtime_budget() {
  let (driver, _) = TimerDriver::new_paused(BUDGET + 1).unwrap();
  let handle = driver.handle();
  let waker = Waker::noop();
  let mut context = Context::from_waker(waker);
  for _ in 0..(BUDGET * 2) {
    let mut timeout = handle.timeout(Duration::ZERO, ready(())).unwrap();
    assert_eq!(
      Pin::new(&mut timeout).poll(&mut context),
      Poll::Ready(Err(TimeoutError::Elapsed))
    );
  }
  driver.shutdown().unwrap();
}
