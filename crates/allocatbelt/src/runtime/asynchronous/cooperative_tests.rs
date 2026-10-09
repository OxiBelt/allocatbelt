use std::future::Future;
use std::future::poll_fn;
use std::io::{IoSlice, IoSliceMut};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use super::{AsyncConfig, AsyncJoinError, AsyncRuntime, AsyncShutdown};
use crate::runtime::io::{AsyncRead, AsyncWrite};
use crate::runtime::process::pipe::{AsyncChildStdin, AsyncChildStdout};
use crate::runtime::reactor::{Reactor, ReactorConfig};

const WATCHDOG: Duration = Duration::from_secs(3);
const DEFAULT_BUDGET: usize = 64;

fn exhaust_budget(context: &mut Context<'_>) {
  for _ in 0..DEFAULT_BUDGET {
    assert!(super::poll_cooperative(context, |_| Poll::Ready(())).is_ready());
  }
  assert_eq!(super::entry::budget_remaining(), 0);
}

struct TestChild(Child);

impl Drop for TestChild {
  fn drop(&mut self) {
    let _ = self.0.kill();
    let _ = self.0.wait();
  }
}

fn child(script: &str, stdin: bool) -> TestChild {
  let mut command = Command::new("/bin/bash");
  command.args(["-c", script]).stdout(Stdio::piped());
  if stdin {
    command.stdin(Stdio::piped());
  }
  TestChild(command.spawn().expect("test child should start"))
}

fn pipe_reactor(
  registrations: usize,
  waiters: usize,
) -> (Reactor, crate::runtime::reactor::ReactorHandle) {
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: registrations,
    max_waiters: waiters,
  })
  .expect("test reactor should start");
  let handle = reactor.handle();
  (reactor, handle)
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

#[test]
fn child_pipe_vectored_polls_charge_once_and_gate_closed_fast_paths() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let (reactor, handle) = pipe_reactor(2, 2);
  let mut child = child(
    "IFS= read -r value; printf '%s' \"$value\"; exec sleep 20",
    true,
  );
  let mut writer = AsyncChildStdin::from_std(child.0.stdin.take().unwrap(), &handle).unwrap();
  let mut reader = AsyncChildStdout::from_std(child.0.stdout.take().unwrap(), &handle).unwrap();
  let mut write_stage = 0;
  let mut first = [0_u8; 6];
  let mut second = [0_u8; 7];
  let mut received = 0;
  let total = first.len() + second.len();

  let read = runtime
    .block_on(poll_fn(|context| {
      let before = super::entry::budget_remaining();
      if write_stage == 0 {
        match Pin::new(&mut writer).poll_write(context, b"scalar-") {
          Poll::Pending => {
            assert_eq!(super::entry::budget_remaining(), before);
            return Poll::Pending;
          }
          Poll::Ready(Ok(7)) => {
            write_stage = 1;
            assert_eq!(super::entry::budget_remaining(), before - 1);
          }
          Poll::Ready(Ok(count)) => panic!("unexpected scalar pipe write: {count}"),
          Poll::Ready(Err(error)) => panic!("child pipe write failed: {error}"),
        }
      }
      if write_stage == 1 {
        let before_vector = super::entry::budget_remaining();
        let bufs = [IoSlice::new(b"vector\n")];
        match Pin::new(&mut writer).poll_write_vectored(context, &bufs) {
          Poll::Pending => {
            assert_eq!(super::entry::budget_remaining(), before_vector);
            return Poll::Pending;
          }
          Poll::Ready(Ok(7)) => {
            write_stage = 2;
            assert_eq!(super::entry::budget_remaining(), before_vector - 1);
          }
          Poll::Ready(Ok(count)) => panic!("unexpected vectored pipe write: {count}"),
          Poll::Ready(Err(error)) => panic!("child pipe write failed: {error}"),
        }
      }

      while received < total {
        let before_read = super::entry::budget_remaining();
        let offered = total - received;
        let first_offset = received.min(first.len());
        let second_offset = received.saturating_sub(first.len());
        let mut bufs = [
          IoSliceMut::new(&mut first[first_offset..]),
          IoSliceMut::new(&mut second[second_offset..]),
        ];
        match Pin::new(&mut reader).poll_read_vectored(context, &mut bufs) {
          Poll::Pending => {
            assert_eq!(super::entry::budget_remaining(), before_read);
            return Poll::Pending;
          }
          Poll::Ready(Ok(0)) => panic!("child pipe reached EOF before the full payload"),
          Poll::Ready(Ok(count)) => {
            assert!(count <= offered);
            assert_eq!(super::entry::budget_remaining(), before_read - 1);
            received += count;
          }
          Poll::Ready(Err(error)) => panic!("child pipe read failed: {error}"),
        }
      }
      Poll::Ready(received)
    }))
    .unwrap();
  assert_eq!(read, 13);
  assert_eq!(&first, b"scalar");
  assert_eq!(&second, b"-vector");
  let _ = child.0.kill();
  let _ = child.0.wait();

  let mut first_fast_path_poll = true;
  runtime
    .block_on(poll_fn(|context| {
      if first_fast_path_poll {
        first_fast_path_poll = false;
        exhaust_budget(context);
        assert!(Pin::new(&mut writer).poll_shutdown(context).is_pending());
        assert_eq!(super::entry::budget_remaining(), 0);
        assert!(writer.get_ref().is_some());
        assert!(Pin::new(&mut writer).poll_flush(context).is_pending());
        assert_eq!(super::entry::budget_remaining(), 0);
        assert!(writer.get_ref().is_some());
        Poll::Pending
      } else {
        let before = super::entry::budget_remaining();
        assert!(Pin::new(&mut writer).poll_shutdown(context).is_ready());
        assert_eq!(super::entry::budget_remaining(), before - 1);
        assert!(writer.get_ref().is_none());
        assert_eq!(
          Pin::new(&mut writer)
            .poll_write(context, b"closed")
            .map(|result| result.unwrap_err().kind()),
          Poll::Ready(std::io::ErrorKind::BrokenPipe)
        );
        assert_eq!(super::entry::budget_remaining(), before - 2);
        assert!(Pin::new(&mut writer).poll_flush(context).is_ready());
        assert_eq!(super::entry::budget_remaining(), before - 3);
        Poll::Ready(())
      }
    }))
    .unwrap();
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
  reactor.shutdown().unwrap();
}

#[test]
fn exhausted_child_pipe_polls_preserve_buffer_and_waiter_then_resume() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let (reactor, handle) = pipe_reactor(1, 1);
  let mut child = child("IFS= read -r value; printf x; exec sleep 20", true);
  let mut signal = child.0.stdin.take().unwrap();
  let mut reader = AsyncChildStdout::from_std(child.0.stdout.take().unwrap(), &handle).unwrap();
  let mut buffer = [0_u8; 1];
  let mut first_poll = true;

  runtime
    .block_on(poll_fn(|context| {
      if first_poll {
        first_poll = false;
        assert!(
          Pin::new(&mut reader)
            .poll_read(context, &mut buffer)
            .is_pending()
        );
        assert_eq!(super::entry::budget_remaining(), DEFAULT_BUDGET as u16);
        assert!(format!("{reader:?}").contains("waiting: true"));

        exhaust_budget(context);
        assert!(
          Pin::new(&mut reader)
            .poll_read(context, &mut buffer)
            .is_pending()
        );
        assert_eq!(super::entry::budget_remaining(), 0);
        assert_eq!(buffer, [0]);
        assert!(format!("{reader:?}").contains("waiting: true"));

        assert!(
          Pin::new(&mut reader)
            .poll_read(context, &mut [])
            .is_pending()
        );
        assert_eq!(super::entry::budget_remaining(), 0);
        assert!(format!("{reader:?}").contains("waiting: true"));
        Poll::Pending
      } else {
        assert!(matches!(
          Pin::new(&mut reader).poll_read(context, &mut []),
          Poll::Ready(Ok(0))
        ));
        assert_eq!(super::entry::budget_remaining(), DEFAULT_BUDGET as u16 - 1);
        assert!(format!("{reader:?}").contains("waiting: false"));
        Poll::Ready(())
      }
    }))
    .unwrap();

  std::io::Write::write_all(&mut signal, b"go\n").unwrap();
  runtime
    .block_on(poll_fn(|context| {
      match Pin::new(&mut reader).poll_read(context, &mut buffer) {
        Poll::Pending => {
          assert_eq!(super::entry::budget_remaining(), DEFAULT_BUDGET as u16);
          Poll::Pending
        }
        Poll::Ready(Ok(1)) => {
          assert_eq!(super::entry::budget_remaining(), DEFAULT_BUDGET as u16 - 1);
          Poll::Ready(())
        }
        Poll::Ready(Ok(count)) => panic!("unexpected child pipe read count: {count}"),
        Poll::Ready(Err(error)) => panic!("child pipe read failed: {error}"),
      }
    }))
    .unwrap();
  assert_eq!(buffer, [b'x']);
  let _ = child.0.kill();
  let _ = child.0.wait();
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
  reactor.shutdown().unwrap();
}

#[test]
fn child_pipe_data_and_eof_ready_loop_yields_to_a_sibling_task() {
  let (reactor, handle) = pipe_reactor(1, 1);
  let mut child = child("head -c 16777216 /dev/zero", false);
  let mut reader = AsyncChildStdout::from_std(child.0.stdout.take().unwrap(), &handle).unwrap();
  let progress = Arc::new(AtomicUsize::new(0));
  let ready_reads = Arc::new(AtomicUsize::new(0));
  let max_batch = Arc::new(AtomicUsize::new(0));
  let loop_progress = Arc::clone(&progress);
  let loop_ready_reads = Arc::clone(&ready_reads);
  let loop_max_batch = Arc::clone(&max_batch);
  let future = async move {
    let mut buffer = [0_u8; 8192];
    let mut batch = 0;
    let mut previous_remaining = DEFAULT_BUDGET as u16;
    loop {
      let count = poll_fn(|context| Pin::new(&mut reader).poll_read(context, &mut buffer))
        .await
        .expect("child pipe read should succeed");
      record_ready(
        &loop_ready_reads,
        &loop_max_batch,
        &mut batch,
        &mut previous_remaining,
      );
      if count == 0 {
        // The finite producer has reached EOF. Keep polling the immediately
        // ready EOF result until the harness aborts this task, so normal
        // completion cannot race the sibling/cancellation assertions.
        // Signal the harness only after this continuously-ready phase starts.
        loop_progress.fetch_add(1, Ordering::SeqCst);
        continue;
      }
    }
  };
  assert_ready_loop_yields(future, progress, max_batch);
  let _ = child.0.kill();
  let _ = child.0.wait();
  reactor.shutdown().unwrap();
}

#[test]
fn external_executor_child_pipe_polls_keep_noop_accounting() {
  let (reactor, handle) = pipe_reactor(2, 2);
  let mut child = child("IFS= read -r value; printf '%s' \"$value\"", true);
  let mut writer = AsyncChildStdin::from_std(child.0.stdin.take().unwrap(), &handle).unwrap();
  let mut reader = AsyncChildStdout::from_std(child.0.stdout.take().unwrap(), &handle).unwrap();
  let mut context = Context::from_waker(std::task::Waker::noop());
  let deadline = Instant::now() + WATCHDOG;
  let write_bufs = [IoSlice::new(b"manual-"), IoSlice::new(b"pipe\n")];
  let mut written = None;

  super::entry::reset_budget();
  assert!(!super::entry::cooperative_poll_active());
  while written.is_none() {
    assert!(
      Instant::now() < deadline,
      "manual child-pipe write timed out"
    );
    match Pin::new(&mut writer).poll_write_vectored(&mut context, &write_bufs) {
      Poll::Pending => thread::sleep(Duration::from_millis(1)),
      Poll::Ready(Ok(count)) => written = Some(count),
      Poll::Ready(Err(error)) => panic!("manual child-pipe write failed: {error}"),
    }
    assert_eq!(super::entry::budget_remaining(), DEFAULT_BUDGET as u16);
  }
  assert_eq!(written, Some(12));

  let mut first = [0_u8; 6];
  let mut second = [0_u8; 5];
  let mut received = 0;
  let total = first.len() + second.len();
  while received < total {
    assert!(
      Instant::now() < deadline,
      "manual child-pipe read timed out"
    );
    let offered = total - received;
    let first_offset = received.min(first.len());
    let second_offset = received.saturating_sub(first.len());
    let mut bufs = [
      IoSliceMut::new(&mut first[first_offset..]),
      IoSliceMut::new(&mut second[second_offset..]),
    ];
    match Pin::new(&mut reader).poll_read_vectored(&mut context, &mut bufs) {
      Poll::Pending => thread::sleep(Duration::from_millis(1)),
      Poll::Ready(Ok(0)) => panic!("manual child pipe reached EOF before the full payload"),
      Poll::Ready(Ok(count)) => {
        assert!(count <= offered);
        received += count;
      }
      Poll::Ready(Err(error)) => panic!("manual child-pipe read failed: {error}"),
    }
    assert_eq!(super::entry::budget_remaining(), DEFAULT_BUDGET as u16);
  }
  assert_eq!(received, total);
  assert_eq!(&first, b"manual");
  assert_eq!(&second, b"-pipe");
  assert!(child.0.wait().unwrap().success());
  assert!(Pin::new(&mut writer).poll_flush(&mut context).is_ready());
  assert!(Pin::new(&mut writer).poll_shutdown(&mut context).is_ready());
  assert_eq!(super::entry::budget_remaining(), DEFAULT_BUDGET as u16);
  reactor.shutdown().unwrap();
}
