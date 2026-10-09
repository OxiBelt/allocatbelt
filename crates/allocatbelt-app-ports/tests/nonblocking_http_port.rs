use std::future::{self, Future};
use std::pin::Pin;
use std::process::{Child, Command};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

use allocatbelt::runtime::asynchronous::{
  AsyncConfig, AsyncError, AsyncJoinError, AsyncRuntime, AsyncShutdown, OwnedTaskScope,
  consume_budget, yield_now,
};
use allocatbelt::runtime::managed::{OperationRequest, ResourceLimits, ResourceScope};
use allocatbelt::runtime::reactor::{Reactor, ReactorConfig, ReactorHandle};
use allocatbelt::runtime::time::{TimeoutError, TimerDriver, TimerError};
use allocatbelt::runtime::{
  Config as BlockingConfig, Resources, Runtime as BlockingRuntime, ShutdownMode,
};
use allocatbelt_app_ports::http::{self, HttpConfig, MAX_BODY_BYTES, MAX_REQUEST_BYTES};

fn blocking_runtime() -> BlockingRuntime {
  BlockingRuntime::new(BlockingConfig {
    workers: 1,
    max_outstanding: 2,
    capacity: Resources::ZERO,
  })
  .expect("blocking runtime should start")
}

fn async_runtime(max_outstanding: usize) -> AsyncRuntime {
  AsyncRuntime::new(AsyncConfig {
    workers: 2,
    max_outstanding,
    max_scopes: 2,
  })
  .expect("async runtime should start")
}

fn resource_scope(network: usize) -> ResourceScope {
  ResourceScope::new(ResourceLimits {
    managed_memory: 3 * MAX_REQUEST_BYTES + 512,
    disk_concurrent_ops: 0,
    network_concurrent_ops: network,
  })
}

fn reactor(max_registrations: usize) -> Reactor {
  Reactor::new(ReactorConfig {
    max_registrations,
    max_waiters: 6,
  })
  .expect("reactor should start")
}

fn assert_clean(
  scope: &OwnedTaskScope,
  runtime: &AsyncRuntime,
  resources: &ResourceScope,
  reactor: &ReactorHandle,
) {
  assert_resources_clean(resources, reactor);
  runtime
    .block_on(await_scope_accounting(scope))
    .expect("scope-accounting root poll should complete");
  assert_eq!(scope.snapshot().active_tasks, 0);
  assert_resources_clean(resources, reactor);
}

async fn await_scope_accounting(scope: &OwnedTaskScope) {
  let deadline = Instant::now() + Duration::from_secs(5);
  loop {
    let active_tasks = scope.snapshot().active_tasks;
    if active_tasks == 0 {
      return;
    }
    assert!(
      Instant::now() < deadline,
      "scope task accounting did not reach zero before the deadline; active_tasks={active_tasks}"
    );
    yield_now().await;
  }
}

fn assert_resources_clean(resources: &ResourceScope, reactor: &ReactorHandle) {
  let snapshot = resources.snapshot();
  assert_eq!(snapshot.managed_memory, 0);
  assert_eq!(snapshot.disk_ops, 0);
  assert_eq!(snapshot.network_ops, 0);
  assert_eq!(reactor.registrations(), 0);
  assert_eq!(reactor.waiters(), 0);
}

fn within_watchdog(test_name: &str, case: fn()) {
  const CHILD_MARKER: &str = "ALLOCATBELT_HTTP_WATCHDOG_CHILD";
  if std::env::var_os(CHILD_MARKER).is_some() {
    case();
    return;
  }

  let mut child = WatchdogChild(
    Command::new(std::env::current_exe().expect("test executable path should resolve"))
      .args(["--exact", test_name, "--nocapture"])
      .env(CHILD_MARKER, "1")
      .spawn()
      .expect("watchdog child should start"),
  );
  let deadline = Instant::now() + Duration::from_secs(45);
  loop {
    if let Some(status) = child
      .0
      .try_wait()
      .expect("watchdog child status should be readable")
    {
      assert!(
        status.success(),
        "child case {test_name} failed with {status:?}"
      );
      return;
    }
    if Instant::now() >= deadline {
      child
        .0
        .kill()
        .expect("timed-out test process should be killed");
      let status = child
        .0
        .wait()
        .expect("killed test process should be reaped");
      panic!(
        "whole test case {test_name} exceeded its 45-second watchdog; child status {status:?}"
      );
    }
    thread::sleep(Duration::from_millis(10));
  }
}

struct WatchdogChild(Child);

impl Drop for WatchdogChild {
  fn drop(&mut self) {
    if !matches!(self.0.try_wait(), Ok(Some(_))) {
      let _ = self.0.kill();
      let _ = self.0.wait();
    }
  }
}

macro_rules! watchdog_test {
  ($name:ident, $case:ident) => {
    #[test]
    fn $name() {
      within_watchdog(stringify!($name), $case);
    }
  };
}

struct ReleaseGate(Option<mpsc::Sender<()>>);

impl ReleaseGate {
  fn release(&mut self) {
    if let Some(sender) = self.0.take() {
      let _ = sender.send(());
    }
  }
}

impl Drop for ReleaseGate {
  fn drop(&mut self) {
    self.release();
  }
}

struct PublicationGate {
  entered: mpsc::Sender<()>,
  release: Mutex<mpsc::Receiver<()>>,
}

impl PublicationGate {
  fn pause(&self) {
    self
      .entered
      .send(())
      .expect("publication-gate observer should remain connected");
    self
      .release
      .lock()
      .expect("publication-gate receiver should remain available")
      .recv()
      .expect("the test releases its publication gate");
  }
}

impl Wake for PublicationGate {
  fn wake(self: Arc<Self>) {
    self.pause();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.pause();
  }
}

fn reusable_http_registration_rejection_aborts_server_and_frees_listener_case() {
  let mut blocking = blocking_runtime();
  let reactor = reactor(1);
  let reactor_handle = reactor.handle();
  let runtime = async_runtime(1);
  let resources = resource_scope(2);
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("HTTP scope should open");

  let outcome = runtime
    .block_on(http::loopback_transaction_nonblocking(
      &scope,
      blocking.handle(),
      reactor_handle.clone(),
      resources.clone(),
      HttpConfig {
        body_bytes: 32,
        seed: 0x72,
      },
    ))
    .expect("HTTP root poll should complete");
  assert!(outcome.is_err(), "client registration must be refused");
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(reactor_handle.waiters(), 0);
  assert_eq!(resources.snapshot().network_ops, 0);
  runtime
    .block_on(await_scope_accounting(&scope))
    .expect("scope-accounting root poll should complete");
  assert_eq!(scope.snapshot().active_tasks, 0);

  let sentinel = scope
    .spawn(async { 0x51u8 })
    .expect("cleaned-up server slot should be reusable");
  assert_eq!(
    runtime
      .block_on(sentinel)
      .expect("sentinel root poll should complete")
      .expect("sentinel should join"),
    0x51
  );
  assert_clean(&scope, &runtime, &resources, &reactor_handle);
  runtime
    .block_on(scope.close())
    .expect("HTTP scope should close");
  assert_resources_clean(&resources, &reactor_handle);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}

fn scope_accounting_helper_waits_for_join_publication_callbacks_case() {
  let runtime = async_runtime(1);
  let scope = runtime.scope().expect("test scope should open");
  let (started_sender, started_receiver) = mpsc::channel();
  let mut job = Box::pin(
    scope
      .spawn(async move {
        started_sender
          .send(())
          .expect("test should observe the task's first poll");
        future::pending::<()>().await;
        0x61u8
      })
      .expect("pending task should be admitted"),
  );

  let (entered_sender, entered_receiver) = mpsc::channel();
  let (release_sender, release_receiver) = mpsc::channel();
  let mut release_gate = ReleaseGate(Some(release_sender));
  let gate_waker = Waker::from(Arc::new(PublicationGate {
    entered: entered_sender,
    release: Mutex::new(release_receiver),
  }));
  let mut gate_context = Context::from_waker(&gate_waker);
  assert!(job.as_mut().poll(&mut gate_context).is_pending());
  started_receiver
    .recv_timeout(Duration::from_secs(5))
    .expect("worker should begin the pending task");

  job.as_ref().get_ref().abort();
  entered_receiver
    .recv_timeout(Duration::from_secs(5))
    .expect("terminal publication should enter the gated join callback");

  let mut noop_context = Context::from_waker(Waker::noop());
  assert!(matches!(
    job.as_mut().poll(&mut noop_context),
    Poll::Ready(Err(AsyncJoinError::Cancelled))
  ));
  assert_eq!(scope.snapshot().active_tasks, 1);

  let mut accounting = Box::pin(await_scope_accounting(&scope));
  assert!(accounting.as_mut().poll(&mut noop_context).is_pending());
  assert_eq!(scope.snapshot().active_tasks, 1);

  release_gate.release();
  runtime
    .block_on(accounting)
    .expect("scope-accounting root poll should complete");
  assert_eq!(scope.snapshot().active_tasks, 0);

  let sentinel = scope
    .spawn(async { 0x51u8 })
    .expect("cleaned-up scope slot should admit the sentinel");
  assert_eq!(
    runtime
      .block_on(sentinel)
      .expect("sentinel root poll should complete")
      .expect("sentinel task should join"),
    0x51
  );
  runtime
    .block_on(await_scope_accounting(&scope))
    .expect("sentinel scope-accounting poll should complete");
  assert_eq!(scope.snapshot().active_tasks, 0);
  runtime
    .block_on(scope.close())
    .expect("test scope should close");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
}

fn reusable_http_preoccupied_network_admission_is_clean_case() {
  let mut blocking = blocking_runtime();
  let reactor = reactor(3);
  let reactor_handle = reactor.handle();
  let runtime = async_runtime(2);
  let resources = resource_scope(1);
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("HTTP scope should open");
  let occupied = resources
    .try_acquire(OperationRequest {
      disk: 0,
      network: 1,
    })
    .expect("test holds the only network slot");

  let outcome = runtime
    .block_on(http::loopback_transaction_nonblocking(
      &scope,
      blocking.handle(),
      reactor_handle.clone(),
      resources.clone(),
      HttpConfig {
        body_bytes: 16,
        seed: 0x117,
      },
    ))
    .expect("HTTP root poll should complete");
  assert!(outcome.is_err(), "preoccupied network capacity must reject");
  assert_eq!(resources.snapshot().network_ops, 1);
  drop(occupied);
  assert_clean(&scope, &runtime, &resources, &reactor_handle);
  runtime
    .block_on(scope.close())
    .expect("HTTP scope should close");
  assert_resources_clean(&resources, &reactor_handle);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}

fn reusable_http_capacity_one_refuses_two_live_endpoints_case() {
  let mut blocking = blocking_runtime();
  let reactor = reactor(3);
  let reactor_handle = reactor.handle();
  let runtime = async_runtime(2);
  let resources = resource_scope(1);
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("HTTP scope should open");

  let outcome = runtime
    .block_on(http::loopback_transaction_nonblocking(
      &scope,
      blocking.handle(),
      reactor_handle.clone(),
      resources.clone(),
      HttpConfig {
        body_bytes: 128,
        seed: 0x127,
      },
    ))
    .expect("HTTP root poll should complete");
  assert!(
    outcome.is_err(),
    "the two endpoints cannot share one permit"
  );
  assert_clean(&scope, &runtime, &resources, &reactor_handle);
  runtime
    .block_on(scope.close())
    .expect("HTTP scope should close");
  assert_resources_clean(&resources, &reactor_handle);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}

fn reusable_http_rejects_invalid_body_before_listener_registration_case() {
  let mut blocking = blocking_runtime();
  let reactor = reactor(3);
  let reactor_handle = reactor.handle();
  let runtime = async_runtime(2);
  let resources = resource_scope(2);
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("HTTP scope should open");

  let outcome = runtime
    .block_on(http::loopback_transaction_nonblocking(
      &scope,
      blocking.handle(),
      reactor_handle.clone(),
      resources.clone(),
      HttpConfig {
        body_bytes: MAX_BODY_BYTES + 1,
        seed: 0x1,
      },
    ))
    .expect("HTTP root poll should complete");
  assert!(outcome.is_err());
  assert_eq!(scope.snapshot().active_tasks, 0);
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(resources.snapshot().network_ops, 0);
  assert_clean(&scope, &runtime, &resources, &reactor_handle);
  runtime
    .block_on(scope.close())
    .expect("HTTP scope should close");
  assert_resources_clean(&resources, &reactor_handle);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}

fn reusable_http_full_scope_rejects_server_and_drops_listener_case() {
  let mut blocking = blocking_runtime();
  let reactor = reactor(3);
  let reactor_handle = reactor.handle();
  let runtime = async_runtime(1);
  let resources = resource_scope(2);
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("HTTP scope should open");
  let (release_sender, release_receiver) = mpsc::channel();
  let mut release_gate = ReleaseGate(Some(release_sender));
  let blocker = scope
    .spawn(async move {
      release_receiver
        .recv()
        .expect("the test releases its scope-admission gate");
      0x81u8
    })
    .expect("gate task should occupy the only scope slot");
  assert_eq!(scope.snapshot().active_tasks, 1);

  let outcome = runtime
    .block_on(http::loopback_transaction_nonblocking(
      &scope,
      blocking.handle(),
      reactor_handle.clone(),
      resources.clone(),
      HttpConfig {
        body_bytes: 16,
        seed: 0x6,
      },
    ))
    .expect("HTTP root poll should complete");
  assert!(outcome.is_err(), "full scope must reject server admission");
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(reactor_handle.waiters(), 0);
  assert_eq!(scope.snapshot().active_tasks, 1);
  assert_eq!(resources.snapshot().network_ops, 0);
  release_gate.release();
  assert_eq!(
    runtime
      .block_on(blocker)
      .expect("gate task root poll should complete")
      .expect("gate task should finish"),
    0x81
  );
  assert_clean(&scope, &runtime, &resources, &reactor_handle);
  runtime
    .block_on(scope.close())
    .expect("full-admission scope should close after releasing its gate");
  assert_resources_clean(&resources, &reactor_handle);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}

fn consume_checkpoints(cx: &mut Context<'_>, count: usize) {
  for _ in 0..count {
    let mut checkpoint = consume_budget();
    assert!(Pin::new(&mut checkpoint).poll(cx).is_ready());
  }
}

fn admit_sentinel_after_server_cleanup(
  scope: &allocatbelt::runtime::asynchronous::OwnedTaskScope,
  runtime: &AsyncRuntime,
) {
  let deadline = Instant::now() + Duration::from_secs(5);
  let sentinel = loop {
    match scope.spawn(async { 0x51u8 }) {
      Ok(job) => break job,
      Err(error) if error.kind == AsyncError::Full => {
        drop(error.into_future());
        assert!(
          Instant::now() < deadline,
          "aborted HTTP server retained its task slot"
        );
        thread::yield_now();
      }
      Err(error) => panic!("sentinel admission failed unexpectedly: {}", error.kind),
    }
  };
  assert_eq!(
    runtime
      .block_on(sentinel)
      .expect("sentinel root poll should complete")
      .expect("sentinel task should finish"),
    0x51
  );
}

fn reusable_http_cancellation_after_connect_admission_reclaims_server_task_case() {
  let mut blocking = blocking_runtime();
  let reactor = reactor(3);
  let reactor_handle = reactor.handle();
  let runtime = async_runtime(1);
  let resources = resource_scope(2);
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("HTTP scope should open");
  let mut transaction = Box::pin(http::loopback_transaction_nonblocking(
    &scope,
    blocking.handle(),
    reactor_handle.clone(),
    resources.clone(),
    HttpConfig {
      body_bytes: 1024,
      seed: 0x4c,
    },
  ));
  let first_poll = scope
    .handle()
    .block_on(future::poll_fn(|cx| {
      consume_checkpoints(cx, 64);
      Poll::Ready(transaction.as_mut().poll(cx))
    }))
    .expect("bound borrowed root poll should complete");
  assert!(
    first_poll.is_pending(),
    "connect admission should yield after the exhausted cooperative budget"
  );
  drop(transaction);
  admit_sentinel_after_server_cleanup(&scope, &runtime);
  assert_clean(&scope, &runtime, &resources, &reactor_handle);
  runtime
    .block_on(scope.close())
    .expect("server abort cleanup should finish");
  assert_resources_clean(&resources, &reactor_handle);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}

fn reusable_http_timer_full_refuses_before_listener_or_task_admission_case() {
  let mut blocking = blocking_runtime();
  let reactor = reactor(3);
  let reactor_handle = reactor.handle();
  let runtime = async_runtime(2);
  let resources = resource_scope(2);
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("HTTP scope should open");
  let (timer, _clock) = TimerDriver::new_paused(1).expect("timer should start");
  let timer_handle = timer.handle();
  let held = timer_handle
    .sleep(Duration::from_secs(60))
    .expect("first timer registration should be admitted");
  let deadline = timer_handle.now() + Duration::from_secs(10);
  let timeout = timer_handle.timeout_at(
    deadline,
    http::loopback_transaction_nonblocking(
      &scope,
      blocking.handle(),
      reactor_handle.clone(),
      resources.clone(),
      HttpConfig {
        body_bytes: 16,
        seed: 0x18,
      },
    ),
  );
  assert!(matches!(timeout, Err(TimerError::Full)));
  drop(timeout);
  assert_eq!(timer_handle.registered(), 1);
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(scope.snapshot().active_tasks, 0);
  assert_eq!(resources.snapshot().network_ops, 0);
  drop(held);
  assert_eq!(timer_handle.registered(), 0);
  assert_clean(&scope, &runtime, &resources, &reactor_handle);
  runtime
    .block_on(scope.close())
    .expect("HTTP scope should close");
  assert_resources_clean(&resources, &reactor_handle);
  timer.shutdown().expect("timer should stop");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}

fn reusable_http_timeout_cleans_admitted_transaction_case() {
  let mut blocking = blocking_runtime();
  let reactor = reactor(4);
  let reactor_handle = reactor.handle();
  let runtime = async_runtime(1);
  let resources = resource_scope(2);
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("HTTP scope should open");
  let (timer, clock) = TimerDriver::new_paused(1).expect("timer should start");
  let timer_handle = timer.handle();
  let deadline = timer_handle.now() + Duration::from_secs(1);
  let mut timeout = Box::pin(
    timer_handle
      .timeout_at(
        deadline,
        http::loopback_transaction_nonblocking(
          &scope,
          blocking.handle(),
          reactor_handle.clone(),
          resources.clone(),
          HttpConfig {
            body_bytes: 2048,
            seed: 0x302,
          },
        ),
      )
      .expect("whole-transaction timeout should register"),
  );
  let first_poll = scope
    .handle()
    .block_on(future::poll_fn(|cx| {
      consume_checkpoints(cx, 63);
      Poll::Ready(timeout.as_mut().poll(cx))
    }))
    .expect("bound borrowed root poll should complete");
  assert!(
    first_poll.is_pending(),
    "timeout wrapper should remain pending before deadline"
  );
  assert!(
    resources.snapshot().network_ops > 0,
    "transaction should hold connect admission"
  );
  assert!(
    reactor_handle.registrations() >= 2,
    "listener and client registration should be live"
  );
  clock
    .advance(Duration::from_secs(1))
    .expect("manual clock should reach the deadline");
  let outcome = scope
    .handle()
    .block_on(timeout)
    .expect("timeout root poll should complete");
  assert!(matches!(outcome, Err(TimeoutError::Elapsed)));
  assert_eq!(timer_handle.registered(), 0);
  admit_sentinel_after_server_cleanup(&scope, &runtime);
  assert_clean(&scope, &runtime, &resources, &reactor_handle);
  runtime
    .block_on(scope.close())
    .expect("aborted server cleanup should finish");
  assert_resources_clean(&resources, &reactor_handle);
  timer.shutdown().expect("timer should stop");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}

fn reusable_http_timeout_preserves_timer_closed_error_case() {
  let mut blocking = blocking_runtime();
  let reactor = reactor(4);
  let reactor_handle = reactor.handle();
  let runtime = async_runtime(1);
  let resources = resource_scope(2);
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("HTTP scope should open");
  let (timer, _clock) = TimerDriver::new_paused(1).expect("timer should start");
  let timer_handle = timer.handle();
  let deadline = timer_handle.now() + Duration::from_secs(60);
  let mut timeout = Box::pin(
    timer_handle
      .timeout_at(
        deadline,
        http::loopback_transaction_nonblocking(
          &scope,
          blocking.handle(),
          reactor_handle.clone(),
          resources.clone(),
          HttpConfig {
            body_bytes: 2048,
            seed: 0x303,
          },
        ),
      )
      .expect("whole-transaction timeout should register"),
  );
  let first_poll = scope
    .handle()
    .block_on(future::poll_fn(|cx| {
      consume_checkpoints(cx, 63);
      Poll::Ready(timeout.as_mut().poll(cx))
    }))
    .expect("bound borrowed root poll should complete");
  assert!(first_poll.is_pending());
  assert!(resources.snapshot().network_ops > 0);
  assert!(reactor_handle.registrations() >= 2);
  timer
    .shutdown()
    .expect("closing the driver should wake timeout");
  let outcome = scope
    .handle()
    .block_on(timeout)
    .expect("timeout root poll should complete");
  assert!(matches!(
    outcome,
    Err(TimeoutError::Timer(TimerError::Closed))
  ));
  assert_eq!(timer_handle.registered(), 0);
  admit_sentinel_after_server_cleanup(&scope, &runtime);
  assert_clean(&scope, &runtime, &resources, &reactor_handle);
  runtime
    .block_on(scope.close())
    .expect("aborted server cleanup should finish");
  assert_resources_clean(&resources, &reactor_handle);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}

watchdog_test!(
  reusable_http_registration_rejection_aborts_server_and_frees_listener,
  reusable_http_registration_rejection_aborts_server_and_frees_listener_case
);
watchdog_test!(
  scope_accounting_helper_waits_for_join_publication_callbacks,
  scope_accounting_helper_waits_for_join_publication_callbacks_case
);
watchdog_test!(
  reusable_http_preoccupied_network_admission_is_clean,
  reusable_http_preoccupied_network_admission_is_clean_case
);
watchdog_test!(
  reusable_http_capacity_one_refuses_two_live_endpoints,
  reusable_http_capacity_one_refuses_two_live_endpoints_case
);
watchdog_test!(
  reusable_http_rejects_invalid_body_before_listener_registration,
  reusable_http_rejects_invalid_body_before_listener_registration_case
);
watchdog_test!(
  reusable_http_full_scope_rejects_server_and_drops_listener,
  reusable_http_full_scope_rejects_server_and_drops_listener_case
);
watchdog_test!(
  reusable_http_cancellation_after_connect_admission_reclaims_server_task,
  reusable_http_cancellation_after_connect_admission_reclaims_server_task_case
);
watchdog_test!(
  reusable_http_timer_full_refuses_before_listener_or_task_admission,
  reusable_http_timer_full_refuses_before_listener_or_task_admission_case
);
watchdog_test!(
  reusable_http_timeout_cleans_admitted_transaction,
  reusable_http_timeout_cleans_admitted_transaction_case
);
watchdog_test!(
  reusable_http_timeout_preserves_timer_closed_error,
  reusable_http_timeout_preserves_timer_closed_error_case
);
