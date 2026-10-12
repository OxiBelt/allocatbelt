//! Native checks for physical worker options and retained diagnostics.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use super::{
  AsyncConfig, AsyncError, AsyncRuntime, AsyncScopeConfig, AsyncShutdown, AsyncThreadOptions,
  AsyncThreadRole, HandoffConfig, try_block_in_place,
};

fn config(workers: usize, max_outstanding: usize) -> AsyncConfig {
  AsyncConfig {
    workers,
    max_outstanding,
    max_scopes: 1,
  }
}

#[test]
fn thread_name_callback_gets_physical_roles_and_copied_options() {
  let (started_tx, started_rx) = mpsc::channel();
  let (stopped_tx, stopped_rx) = mpsc::channel();
  let options = AsyncThreadOptions::new()
    .thread_stack_size(2 * 1024 * 1024)
    .thread_name_fn(|context| match context.role {
      AsyncThreadRole::Worker => format!("probe-worker-{}", context.index),
      AsyncThreadRole::HandoffHelper => format!("probe-helper-{}", context.index),
    })
    .on_thread_start(move |context| {
      let _ = started_tx.send((context, thread::current().name().map(str::to_owned)));
    })
    .on_thread_stop(move |context| {
      let _ = stopped_tx.send(context);
    });
  let copied = options.clone();
  let runtime = AsyncRuntime::new_with_handoffs_and_thread_options(
    config(2, 4),
    HandoffConfig { max_handoffs: 1 },
    copied,
  )
  .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
  let mut started = Vec::new();
  for _ in 0..3 {
    started.push(
      started_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|_| panic!("thread start hook timed out")),
    );
  }
  assert_eq!(started.len(), runtime.metrics().snapshot().threads.len());
  for (context, name) in &started {
    assert_eq!(
      *name,
      Some(match context.role {
        AsyncThreadRole::Worker => format!("probe-worker-{}", context.index),
        AsyncThreadRole::HandoffHelper => format!("probe-helper-{}", context.index),
      })
    );
    assert_eq!(
      context.physical_index,
      match context.role {
        AsyncThreadRole::Worker => context.index,
        AsyncThreadRole::HandoffHelper => 2 + context.index,
      }
    );
  }
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  let mut stopped = Vec::new();
  for _ in 0..3 {
    stopped.push(
      stopped_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|_| panic!("thread stop hook timed out")),
    );
  }
  assert_eq!(
    started
      .iter()
      .map(|(context, _)| *context)
      .collect::<std::collections::HashSet<_>>(),
    stopped.into_iter().collect()
  );
}

#[test]
fn invalid_or_panicking_name_callbacks_fail_before_thread_start() {
  let context = super::AsyncThreadContext {
    role: AsyncThreadRole::Worker,
    index: 0,
    physical_index: 0,
  };
  assert_eq!(
    AsyncThreadOptions::new()
      .thread_name("fixed")
      .thread_name_fn(|_| "callback".to_owned())
      .resolve_name(context)
      .unwrap_or_else(|_| panic!("name should be valid")),
    "callback"
  );
  assert_eq!(
    AsyncThreadOptions::new()
      .thread_name_fn(|_| "callback".to_owned())
      .thread_name("fixed")
      .resolve_name(context)
      .unwrap_or_else(|_| panic!("name should be valid")),
    "fixed"
  );
  let invalid = AsyncThreadOptions::new().thread_name("bad\0name");
  assert!(matches!(
    AsyncRuntime::new_with_thread_options(config(1, 1), invalid),
    Err(AsyncError::InvalidConfig)
  ));
  let panicking = AsyncThreadOptions::new().thread_name_fn(|_| panic!("name callback panic"));
  assert!(matches!(
    AsyncRuntime::new_with_thread_options(config(1, 1), panicking),
    Err(AsyncError::InvalidConfig)
  ));
  let zero_stack = AsyncThreadOptions::new().thread_stack_size(0);
  assert!(matches!(
    AsyncRuntime::new_with_thread_options(config(1, 1), zero_stack),
    Err(AsyncError::InvalidConfig)
  ));
}

#[test]
fn pending_admission_is_alive_after_it_leaves_the_ready_queue() {
  let runtime = AsyncRuntime::new(config(1, 2))
    .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
  let handle = runtime.handle();
  let metrics = handle.metrics();
  let _job = handle
    .spawn(std::future::pending::<()>())
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  let deadline = Instant::now() + Duration::from_secs(2);
  loop {
    let snapshot = metrics.snapshot();
    if snapshot.num_alive_tasks == 1 && snapshot.global_queue_depth == 0 {
      break;
    }
    assert!(
      Instant::now() < deadline,
      "pending task did not leave the ready queue"
    );
    thread::yield_now();
  }
  runtime
    .shutdown(AsyncShutdown::CancelPending)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  let after = metrics
    .try_snapshot()
    .unwrap_or_else(|_| panic!("bounded metrics snapshot allocation failed"));
  assert_eq!(after.num_alive_tasks, 0);
  assert_eq!(after.global_queue_depth, 0);
  assert!(
    after
      .threads
      .iter()
      .all(|thread| !thread.alive && thread.starts == 1 && thread.stops == 1)
  );
  assert_eq!(metrics.num_workers(), 1);
  assert_eq!(metrics.dispatch_ceiling(), 1);
  assert_eq!(metrics.num_alive_tasks(), 0);
  assert_eq!(metrics.global_queue_depth(), 0);
  assert_eq!(metrics.thread_count(), 1);
  assert_eq!(metrics.thread(0), after.threads.first().copied());
  assert_eq!(metrics.thread(1), None);
}

#[test]
fn global_queue_depth_tracks_a_task_waiting_behind_a_gated_poll() {
  let runtime = AsyncRuntime::new(config(1, 2))
    .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
  let handle = runtime.handle();
  let metrics = handle.metrics();
  let (entered_tx, entered_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let first = handle
    .spawn(async move {
      let _ = entered_tx.send(());
      let _ = release_rx.recv_timeout(Duration::from_secs(2));
    })
    .unwrap_or_else(|error| panic!("first spawn failed: {error}"));
  entered_rx
    .recv_timeout(Duration::from_secs(2))
    .unwrap_or_else(|_| panic!("first task never entered its poll"));
  let second = handle
    .spawn(async {})
    .unwrap_or_else(|error| panic!("second spawn failed: {error}"));
  let queued = metrics.snapshot();
  assert_eq!(queued.num_alive_tasks, 2);
  assert_eq!(queued.global_queue_depth, 1);
  release_tx
    .send(())
    .unwrap_or_else(|_| panic!("gated task already exited"));
  runtime
    .block_on(first)
    .unwrap_or_else(|error| panic!("block_on failed: {error}"))
    .unwrap_or_else(|error| panic!("first task failed: {error}"));
  runtime
    .block_on(second)
    .unwrap_or_else(|error| panic!("block_on failed: {error}"))
    .unwrap_or_else(|error| panic!("second task failed: {error}"));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

struct DropGate {
  polled: mpsc::Sender<()>,
  dropped: mpsc::Sender<()>,
  release: mpsc::Receiver<()>,
  entered_poll: bool,
}

impl Future for DropGate {
  type Output = ();

  fn poll(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
    if !self.entered_poll {
      self.entered_poll = true;
      let _ = self.polled.send(());
    }
    Poll::Pending
  }
}

impl Drop for DropGate {
  fn drop(&mut self) {
    let _ = self.dropped.send(());
    let _ = self.release.recv_timeout(Duration::from_secs(2));
  }
}

#[test]
fn admitted_task_count_stays_live_until_future_cleanup_finishes() {
  let runtime = AsyncRuntime::new(config(1, 1))
    .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
  let metrics = runtime.metrics();
  let (polled_tx, polled_rx) = mpsc::channel();
  let (dropped_tx, dropped_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let _job = runtime
    .handle()
    .spawn(DropGate {
      polled: polled_tx,
      dropped: dropped_tx,
      release: release_rx,
      entered_poll: false,
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  polled_rx
    .recv_timeout(Duration::from_secs(2))
    .unwrap_or_else(|_| panic!("task never became pending"));
  let (shutdown_tx, shutdown_rx) = mpsc::channel();
  let shutdown = thread::spawn(move || {
    let _ = shutdown_tx.send(runtime.shutdown(AsyncShutdown::CancelPending));
  });
  dropped_rx
    .recv_timeout(Duration::from_secs(2))
    .unwrap_or_else(|_| panic!("task cleanup did not start"));
  assert_eq!(metrics.snapshot().num_alive_tasks, 1);
  release_tx
    .send(())
    .unwrap_or_else(|_| panic!("future cleanup already exited"));
  shutdown_rx
    .recv_timeout(Duration::from_secs(2))
    .unwrap_or_else(|_| panic!("shutdown did not finish"))
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  shutdown
    .join()
    .unwrap_or_else(|_| panic!("shutdown thread panicked"));
  assert_eq!(metrics.snapshot().num_alive_tasks, 0);
}

#[test]
fn lifecycle_hooks_can_reenter_metrics_and_submit_without_scheduler_locks() {
  let (handle_tx, handle_rx) = mpsc::channel::<super::AsyncHandle>();
  let handle_rx = Arc::new(Mutex::new(handle_rx));
  let entered = Arc::new(AtomicBool::new(false));
  let park_callbacks = Arc::new(AtomicUsize::new(0));
  let unpark_callbacks = Arc::new(AtomicUsize::new(0));
  let (submitted_tx, submitted_rx) = mpsc::channel();
  let options = AsyncThreadOptions::new()
    .on_thread_park({
      let handle_rx = Arc::clone(&handle_rx);
      let entered = Arc::clone(&entered);
      let park_callbacks = Arc::clone(&park_callbacks);
      move |_| {
        park_callbacks.fetch_add(1, Ordering::Relaxed);
        if !entered.swap(true, Ordering::SeqCst) {
          let handle = handle_rx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|_| panic!("handle was not published"));
          let metrics = handle.metrics();
          assert_eq!(metrics.snapshot().num_workers, 1);
          let accepted = handle.spawn(async {}).is_ok();
          let _ = submitted_tx.send(accepted);
        }
      }
    })
    .on_thread_unpark({
      let unpark_callbacks = Arc::clone(&unpark_callbacks);
      move |_| {
        unpark_callbacks.fetch_add(1, Ordering::Relaxed);
      }
    });
  let runtime = AsyncRuntime::new_with_thread_options(config(1, 2), options)
    .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
  let metrics = runtime.metrics();
  handle_tx
    .send(runtime.handle())
    .unwrap_or_else(|_| panic!("worker hook exited"));
  assert!(
    submitted_rx
      .recv_timeout(Duration::from_secs(2))
      .unwrap_or(false)
  );
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  assert_eq!(
    park_callbacks.load(Ordering::Relaxed),
    unpark_callbacks.load(Ordering::Relaxed)
  );
  assert!(
    metrics
      .try_snapshot()
      .unwrap_or_else(|_| panic!("bounded metrics snapshot allocation failed"))
      .threads
      .iter()
      .all(|thread| thread.parks == thread.unparks)
  );
}

#[test]
fn callback_panics_are_contained_and_counted_without_losing_workers() {
  let options = AsyncThreadOptions::new()
    .on_thread_start(|_| panic!("start hook"))
    .on_thread_stop(|_| panic!("stop hook"))
    .on_thread_park(|_| panic!("park hook"))
    .on_thread_unpark(|_| panic!("unpark hook"));
  let runtime = AsyncRuntime::new_with_thread_options(config(2, 2), options)
    .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
  let metrics = runtime.metrics();
  let handle = runtime.handle();
  let park_deadline = Instant::now() + Duration::from_secs(2);
  while metrics
    .snapshot()
    .threads
    .iter()
    .all(|thread| thread.parks == 0)
  {
    assert!(
      Instant::now() < park_deadline,
      "workers did not enter their park hooks"
    );
    thread::yield_now();
  }
  thread::sleep(Duration::from_millis(5));
  let _job = handle
    .spawn(async {})
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("contained hook panic escaped shutdown: {error}"));
  let snapshot = metrics.snapshot();
  assert!(snapshot.hook_panics >= 5);
  assert!(
    snapshot
      .threads
      .iter()
      .all(|thread| thread.starts == 1 && thread.stops == 1)
  );
}

#[test]
fn busy_duration_excludes_handoff_closure_and_attributes_helper_turns() {
  let worker_park_hooks = Arc::new(AtomicUsize::new(0));
  let worker_unpark_hooks = Arc::new(AtomicUsize::new(0));
  let options = AsyncThreadOptions::default()
    .on_thread_park({
      let worker_park_hooks = Arc::clone(&worker_park_hooks);
      move |context| {
        if context.role == AsyncThreadRole::Worker {
          worker_park_hooks.fetch_add(1, Ordering::Relaxed);
        }
      }
    })
    .on_thread_unpark({
      let worker_unpark_hooks = Arc::clone(&worker_unpark_hooks);
      move |context| {
        if context.role == AsyncThreadRole::Worker {
          worker_unpark_hooks.fetch_add(1, Ordering::Relaxed);
        }
      }
    });
  let runtime = AsyncRuntime::new_with_handoffs_and_thread_options(
    AsyncConfig {
      max_scopes: 2,
      ..config(1, 4)
    },
    HandoffConfig { max_handoffs: 1 },
    options,
  )
  .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
  let handle = runtime.handle();
  let helper_scope = runtime
    .scope_with_config(AsyncScopeConfig {
      max_active_polls: 1,
    })
    .unwrap_or_else(|error| panic!("helper scope creation failed: {error}"));
  let helper_handle = helper_scope.handle();
  let (helper_started_tx, helper_started_rx) = mpsc::channel();
  let metrics = runtime.metrics();
  let elapsed = Arc::new(Mutex::new(Duration::ZERO));
  let job = handle
    .spawn({
      let helper_handle = helper_handle.clone();
      let helper_started_tx = helper_started_tx.clone();
      let elapsed = Arc::clone(&elapsed);
      async move {
        let started = Instant::now();
        try_block_in_place(|| {
          let _helper_job = helper_handle
            .spawn(async move {
              let _ = helper_started_tx.send(());
              thread::sleep(Duration::from_millis(120));
            })
            .unwrap_or_else(|error| panic!("helper submission failed: {error}"));
          helper_started_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|_| panic!("helper task did not start"));
          thread::sleep(Duration::from_millis(10));
        })
        .unwrap_or_else(|error| panic!("handoff failed: {error}"));
        *elapsed.lock().unwrap_or_else(PoisonError::into_inner) = started.elapsed();
      }
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  runtime
    .block_on(job)
    .unwrap_or_else(|error| panic!("block_on failed: {error}"))
    .unwrap_or_else(|error| panic!("task failed: {error}"));
  let wall = *elapsed.lock().unwrap_or_else(PoisonError::into_inner);
  let before_shutdown = metrics.snapshot();
  assert!(
    before_shutdown
      .threads
      .iter()
      .any(
        |thread| thread.context.role == AsyncThreadRole::HandoffHelper
          && !thread.busy_duration.is_zero()
      )
  );
  let worker = before_shutdown
    .threads
    .iter()
    .find(|thread| thread.context.role == AsyncThreadRole::Worker)
    .unwrap_or_else(|| panic!("worker metrics missing"));
  assert!(
    worker.parks >= 1,
    "restoration wait did not increment worker park metrics"
  );
  assert!(
    worker.unparks >= 1,
    "restoration wait did not increment worker unpark metrics"
  );
  assert!(
    before_shutdown.threads.iter().any(
      |thread| thread.context.role == AsyncThreadRole::Worker && !thread.busy_duration.is_zero()
    )
  );
  assert!(
    before_shutdown
      .threads
      .iter()
      .find(|thread| thread.context.role == AsyncThreadRole::Worker)
      .is_some_and(|thread| thread.busy_duration + Duration::from_millis(50) < wall),
    "handoff closure time leaked into busy duration: busy={:?}, wall={wall:?}",
    before_shutdown.threads[0].busy_duration
  );
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  assert_eq!(
    worker_park_hooks.load(Ordering::Relaxed),
    worker_unpark_hooks.load(Ordering::Relaxed)
  );
  assert!(
    metrics
      .try_snapshot()
      .unwrap_or_else(|_| panic!("bounded metrics snapshot allocation failed"))
      .threads
      .iter()
      .all(|thread| thread.parks == thread.unparks)
  );
}
