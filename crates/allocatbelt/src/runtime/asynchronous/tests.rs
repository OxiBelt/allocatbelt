use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use super::{AsyncConfig, AsyncJoinError, AsyncRuntime, AsyncScopeConfig, AsyncShutdown};
use crate::runtime::managed::{ResourceLimits, ResourceScope};

fn runtime(workers: usize, max_outstanding: usize, max_scopes: usize) -> AsyncRuntime {
  AsyncRuntime::new(AsyncConfig {
    workers,
    max_outstanding,
    max_scopes,
  })
  .unwrap_or_else(|error| panic!("runtime construction failed: {error}"))
}

impl AsyncRuntime {
  fn shutdown_before_deadline(self, mode: AsyncShutdown) -> Result<(), super::AsyncError> {
    if super::scheduler::is_worker(&self.shared) {
      return self.shutdown(mode);
    }
    let (done, completion) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
      let _ = done.send(self.shutdown(mode));
    });
    let result = completion
      .recv_timeout(Duration::from_secs(30))
      .expect("async shutdown deadline");
    thread.join().unwrap();
    result
  }
}

#[test]
fn construction_defaults_and_options_run_tasks_and_retain_metrics() {
  use super::AsyncRuntimeOptions;
  let config = AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  };
  for runtime in [
    AsyncRuntime::new(config).unwrap(),
    AsyncRuntime::new_with_options(config, AsyncRuntimeOptions::default()).unwrap(),
    AsyncRuntime::new_with_options(config, AsyncRuntimeOptions::new()).unwrap(),
  ] {
    let metrics = runtime.metrics();
    assert_eq!(metrics.num_workers(), 1);
    let job = runtime.handle().spawn(async { 7 }).unwrap();
    assert_eq!(runtime.block_on(job).unwrap().unwrap(), 7);
    runtime
      .shutdown_before_deadline(AsyncShutdown::Drain)
      .unwrap();
    assert_eq!(metrics.num_alive_tasks(), 0);
  }
}

#[test]
fn distributed_handoffs_construct_with_thread_options_and_resources() {
  use super::{AsyncRuntimeOptions, AsyncThreadOptions, HandoffConfig};
  let config = AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  };
  let name_calls = Arc::new(AtomicUsize::new(0));
  let calls = Arc::clone(&name_calls);
  let options = AsyncRuntimeOptions::new()
    .handoffs(HandoffConfig { max_handoffs: 1 })
    .thread_options(AsyncThreadOptions::new().thread_name_fn(move |_| {
      calls.fetch_add(1, Ordering::Relaxed);
      String::from("dispatch-handoff")
    }));
  for runtime in [
    AsyncRuntime::new_with_options(config, options.clone()).unwrap(),
    AsyncRuntime::with_resources_and_options(
      config,
      ResourceScope::new(ResourceLimits::default()),
      options,
    )
    .unwrap(),
  ] {
    let job = runtime
      .handle()
      .spawn(async { super::try_block_in_place(|| 7).ok() })
      .unwrap();
    assert_eq!(runtime.block_on(job).unwrap().unwrap(), Some(7));
    runtime
      .shutdown_before_deadline(AsyncShutdown::Drain)
      .unwrap();
  }
  assert_eq!(name_calls.load(Ordering::Relaxed), 4);
}

#[test]
fn construction_options_combine_handoffs_and_thread_options() {
  use super::{AsyncRuntimeOptions, AsyncThreadOptions, HandoffConfig, try_block_in_place};

  let (names_tx, names_rx) = std::sync::mpsc::channel();
  let runtime = AsyncRuntime::new_with_options(
    AsyncConfig {
      workers: 1,
      max_outstanding: 2,
      max_scopes: 1,
    },
    AsyncRuntimeOptions::new()
      .handoffs(HandoffConfig { max_handoffs: 1 })
      .thread_options(AsyncThreadOptions::new().thread_name_fn(move |context| {
        let name = format!("options-thread-{}", context.physical_index);
        names_tx.send(name.clone()).unwrap();
        name
      })),
  )
  .unwrap();
  assert_eq!(runtime.metrics().thread_count(), 2);
  assert_eq!(
    names_rx.try_iter().collect::<Vec<_>>(),
    ["options-thread-0", "options-thread-1"]
  );
  let job = runtime
    .handle()
    .spawn(async { try_block_in_place(|| 9).unwrap() })
    .unwrap();
  assert_eq!(runtime.block_on(job).unwrap().unwrap(), 9);
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap();
}

#[test]
fn construction_options_reject_invalid_handoff_bounds() {
  use super::{AsyncError, AsyncRuntimeOptions, HandoffConfig};

  let config = AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  };
  for max_handoffs in [0, usize::MAX] {
    assert!(matches!(
      AsyncRuntime::new_with_options(
        config,
        AsyncRuntimeOptions::new().handoffs(HandoffConfig { max_handoffs }),
      ),
      Err(AsyncError::InvalidConfig)
    ));
  }
}

#[test]
fn resource_handoff_thread_options_wrapper_keeps_the_root_binding() {
  use super::{AsyncThreadOptions, HandoffConfig};

  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: 32,
    ..ResourceLimits::default()
  });
  let runtime = AsyncRuntime::with_resources_handoffs_and_thread_options(
    AsyncConfig {
      workers: 1,
      max_outstanding: 2,
      max_scopes: 1,
    },
    HandoffConfig { max_handoffs: 1 },
    resources.clone(),
    AsyncThreadOptions::new(),
  )
  .unwrap();
  assert_eq!(runtime.metrics().thread_count(), 2);
  let buffer = runtime
    .block_on(async {
      super::current_resource_scope()
        .try_alloc_zeroed(16)
        .unwrap()
    })
    .unwrap();
  assert_eq!(resources.snapshot().managed_memory, buffer.charged_bytes());
  drop(buffer);
  assert_eq!(resources.snapshot().managed_memory, 0);
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap();
}

fn wait_until(predicate: impl Fn() -> bool, message: &str) {
  let deadline = Instant::now() + Duration::from_secs(3);
  while !predicate() {
    assert!(Instant::now() < deadline, "timed out waiting for {message}");
    std::thread::yield_now();
  }
}

struct PendingAdmissionProbe {
  polls: Arc<AtomicUsize>,
  drops: Arc<AtomicUsize>,
}

impl Future for PendingAdmissionProbe {
  type Output = ();

  fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
    self.polls.fetch_add(1, Ordering::SeqCst);
    Poll::Pending
  }
}

impl Drop for PendingAdmissionProbe {
  fn drop(&mut self) {
    self.drops.fetch_add(1, Ordering::SeqCst);
  }
}

fn pending_admission_probe() -> (PendingAdmissionProbe, Arc<AtomicUsize>, Arc<AtomicUsize>) {
  let polls = Arc::new(AtomicUsize::new(0));
  let drops = Arc::new(AtomicUsize::new(0));
  (
    PendingAdmissionProbe {
      polls: Arc::clone(&polls),
      drops: Arc::clone(&drops),
    },
    polls,
    drops,
  )
}

type AdmissionGate = Arc<(Mutex<bool>, Condvar)>;
type AdmissionArrivals = Arc<(Mutex<usize>, Condvar)>;
type AdmissionHook = Arc<dyn Fn() + Send + Sync>;

fn admission_gate_hook() -> (AdmissionGate, AdmissionGate, Arc<AtomicBool>, AdmissionHook) {
  let entered = Arc::new((Mutex::new(false), Condvar::new()));
  let release = Arc::new((Mutex::new(false), Condvar::new()));
  let timed_out = Arc::new(AtomicBool::new(false));
  let hook_entered = Arc::clone(&entered);
  let hook_release = Arc::clone(&release);
  let hook_timed_out = Arc::clone(&timed_out);
  let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
    let (lock, cv) = &*hook_entered;
    *lock.lock().unwrap_or_else(|error| error.into_inner()) = true;
    cv.notify_all();
    let (lock, cv) = &*hook_release;
    let mut open = lock.lock().unwrap_or_else(|error| error.into_inner());
    let deadline = Instant::now() + Duration::from_secs(3);
    while !*open {
      let remaining = deadline.saturating_duration_since(Instant::now());
      if remaining.is_zero() {
        hook_timed_out.store(true, Ordering::SeqCst);
        return;
      }
      let (next, timeout) = cv
        .wait_timeout(open, remaining)
        .unwrap_or_else(|error| error.into_inner());
      open = next;
      if timeout.timed_out() && !*open {
        hook_timed_out.store(true, Ordering::SeqCst);
        return;
      }
    }
  });
  (entered, release, timed_out, hook)
}

fn spawn_pair_barrier_hook() -> (AdmissionArrivals, Arc<AtomicBool>, AdmissionHook) {
  let arrivals = Arc::new((Mutex::new(0usize), Condvar::new()));
  let timed_out = Arc::new(AtomicBool::new(false));
  let hook_arrivals = Arc::clone(&arrivals);
  let hook_timed_out = Arc::clone(&timed_out);
  let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
    let (lock, cv) = &*hook_arrivals;
    let mut count = lock.lock().unwrap_or_else(|error| error.into_inner());
    *count = count.saturating_add(1);
    cv.notify_all();
    let deadline = Instant::now() + Duration::from_secs(3);
    while *count < 2 {
      let remaining = deadline.saturating_duration_since(Instant::now());
      if remaining.is_zero() {
        hook_timed_out.store(true, Ordering::SeqCst);
        return;
      }
      let (next, timeout) = cv
        .wait_timeout(count, remaining)
        .unwrap_or_else(|error| error.into_inner());
      count = next;
      if timeout.timed_out() && *count < 2 {
        hook_timed_out.store(true, Ordering::SeqCst);
        return;
      }
    }
  });
  (arrivals, timed_out, hook)
}

fn wait_for_admission_hook(entered: &Arc<(Mutex<bool>, Condvar)>) -> bool {
  let (lock, cv) = &**entered;
  let mut reached = lock.lock().unwrap_or_else(|error| error.into_inner());
  let deadline = Instant::now() + Duration::from_secs(3);
  while !*reached {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
      return false;
    }
    let (next, timeout) = cv
      .wait_timeout(reached, remaining)
      .unwrap_or_else(|error| error.into_inner());
    reached = next;
    if timeout.timed_out() && !*reached {
      return false;
    }
  }
  true
}

fn release_admission_hook(release: &Arc<(Mutex<bool>, Condvar)>) {
  let (lock, cv) = &**release;
  *lock.lock().unwrap_or_else(|error| error.into_inner()) = true;
  cv.notify_all();
}

fn join_spawn_thread<T: Send + 'static>(
  handle: std::thread::JoinHandle<T>,
  label: &'static str,
) -> T {
  let (sender, receiver) = std::sync::mpsc::sync_channel(1);
  std::thread::spawn(move || {
    let _ = sender.send(handle.join());
  });
  match receiver.recv_timeout(Duration::from_secs(5)) {
    Ok(Ok(value)) => value,
    Ok(Err(_)) => panic!("{label} thread panicked"),
    Err(_) => panic!("{label} thread join timed out"),
  }
}

#[test]
fn concurrent_spawns_select_distinct_slots_after_the_shared_snapshot() {
  let runtime = runtime(1, 2, 1);
  let (arrivals, hook_timed_out, hook) = spawn_pair_barrier_hook();
  runtime.shared.set_spawn_admission_test_hook(hook);

  let (first_future, _first_polls, first_drops) = pending_admission_probe();
  let (second_future, _second_polls, second_drops) = pending_admission_probe();
  let first_handle = runtime.handle();
  let first_thread = std::thread::spawn(move || first_handle.spawn(first_future));
  let second_handle = runtime.handle();
  let second_thread = std::thread::spawn(move || second_handle.spawn(second_future));
  let first = join_spawn_thread(first_thread, "first spawn");
  let second = join_spawn_thread(second_thread, "second spawn");
  assert!(!hook_timed_out.load(Ordering::SeqCst));
  assert_eq!(
    *arrivals.0.lock().unwrap_or_else(|error| error.into_inner()),
    2
  );
  let first = first.unwrap_or_else(|error| panic!("first spawn rejected: {}", error.kind));
  let second = second.unwrap_or_else(|error| panic!("second spawn rejected: {}", error.kind));

  runtime
    .shutdown_before_deadline(AsyncShutdown::CancelPending)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  assert!(matches!(block_on(first), Err(AsyncJoinError::Cancelled)));
  assert!(matches!(block_on(second), Err(AsyncJoinError::Cancelled)));
  assert_eq!(first_drops.load(Ordering::SeqCst), 1);
  assert_eq!(second_drops.load(Ordering::SeqCst), 1);
}

#[test]
fn concurrent_spawn_with_one_slot_returns_full_and_preserves_the_rejected_future() {
  let runtime = runtime(1, 1, 1);
  let (arrivals, hook_timed_out, hook) = spawn_pair_barrier_hook();
  runtime.shared.set_spawn_admission_test_hook(hook);

  let (first_future, first_polls, first_drops) = pending_admission_probe();
  let (second_future, second_polls, second_drops) = pending_admission_probe();
  let first_handle = runtime.handle();
  let first_thread = std::thread::spawn(move || first_handle.spawn(first_future));
  let second_handle = runtime.handle();
  let second_thread = std::thread::spawn(move || second_handle.spawn(second_future));
  let outcomes = [
    (
      join_spawn_thread(first_thread, "first spawn"),
      first_polls,
      first_drops,
    ),
    (
      join_spawn_thread(second_thread, "second spawn"),
      second_polls,
      second_drops,
    ),
  ];
  assert!(!hook_timed_out.load(Ordering::SeqCst));
  assert_eq!(
    *arrivals.0.lock().unwrap_or_else(|error| error.into_inner()),
    2
  );

  let mut admitted = Vec::new();
  let mut rejected = 0;
  for (outcome, polls, drops) in outcomes {
    match outcome {
      Ok(job) => admitted.push((job, drops)),
      Err(error) => {
        assert_eq!(error.kind, super::AsyncError::Full);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        let future = error.into_future();
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(future);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        rejected += 1;
      }
    }
  }
  assert_eq!(admitted.len(), 1);
  assert_eq!(rejected, 1);

  runtime
    .shutdown_before_deadline(AsyncShutdown::CancelPending)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  for (job, drops) in admitted {
    assert!(matches!(block_on(job), Err(AsyncJoinError::Cancelled)));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
  }
}

#[test]
fn scope_close_after_domain_reservation_rolls_back_and_returns_the_future() {
  use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};

  let ceiling = DomainResources::ZERO
    .with(DomainResource::Cpu, 2)
    .with(DomainResource::Tasks, 4)
    .with(DomainResource::Control, 1 << 20);
  let domain = ResourceDomain::with_waiters(ceiling, 1, 4).unwrap();
  let tenant = domain.tenant(ceiling).unwrap();
  let resources = ResourceScope::from_tenant(ResourceLimits::default(), tenant);
  let runtime = runtime(1, 2, 2);
  let before_scope = domain.snapshot().used;
  let scope = runtime
    .scope_with_resources(&resources)
    .unwrap_or_else(|error| panic!("resource scope creation failed: {error}"));
  let scope_baseline = domain.snapshot().used;
  let (entered, release, hook_timed_out, hook) = admission_gate_hook();
  runtime.shared.set_spawn_admission_test_hook(hook);

  let (future, polls, drops) = pending_admission_probe();
  let handle = scope.handle();
  let spawn_thread = std::thread::spawn(move || handle.spawn(future));
  if !wait_for_admission_hook(&entered) {
    release_admission_hook(&release);
    match join_spawn_thread(spawn_thread, "scope-close spawn") {
      Ok(job) => drop(job),
      Err(error) => drop(error.into_future()),
    }
    block_on(scope.close());
    runtime
      .shutdown_before_deadline(AsyncShutdown::CancelPending)
      .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
    panic!("scope-close spawn did not reach final admission");
  }
  let reserved = domain.snapshot().used;
  assert_eq!(
    reserved.get(DomainResource::Tasks),
    scope_baseline.get(DomainResource::Tasks) + 1
  );
  assert!(reserved.get(DomainResource::Control) > scope_baseline.get(DomainResource::Control));

  block_on(scope.close());
  release_admission_hook(&release);
  let error = join_spawn_thread(spawn_thread, "scope-close spawn").unwrap_err();
  assert!(!hook_timed_out.load(Ordering::SeqCst));
  assert_eq!(error.kind, super::AsyncError::Closed);
  assert_eq!(polls.load(Ordering::SeqCst), 0);
  let future = error.into_future();
  assert_eq!(drops.load(Ordering::SeqCst), 0);
  drop(future);
  assert_eq!(drops.load(Ordering::SeqCst), 1);
  assert_eq!(domain.snapshot().used, before_scope);
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn runtime_close_after_spawn_reservation_returns_the_unpolled_future() {
  let runtime = runtime(1, 1, 1);
  let (entered, release, hook_timed_out, hook) = admission_gate_hook();
  runtime.shared.set_spawn_admission_test_hook(hook);

  let (future, polls, drops) = pending_admission_probe();
  let handle = runtime.handle();
  let spawn_thread = std::thread::spawn(move || handle.spawn(future));
  if !wait_for_admission_hook(&entered) {
    release_admission_hook(&release);
    match join_spawn_thread(spawn_thread, "runtime-close spawn") {
      Ok(job) => drop(job),
      Err(error) => drop(error.into_future()),
    }
    runtime
      .shutdown_before_deadline(AsyncShutdown::CancelPending)
      .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
    panic!("runtime-close spawn did not reach final admission");
  }
  runtime
    .shutdown_before_deadline(AsyncShutdown::CancelPending)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  release_admission_hook(&release);

  let error = join_spawn_thread(spawn_thread, "runtime-close spawn").unwrap_err();
  assert!(!hook_timed_out.load(Ordering::SeqCst));
  assert_eq!(error.kind, super::AsyncError::Closed);
  assert_eq!(polls.load(Ordering::SeqCst), 0);
  let future = error.into_future();
  assert_eq!(drops.load(Ordering::SeqCst), 0);
  drop(future);
  assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn ready_async_job_waits_at_zero_budget_and_keeps_its_output() {
  let runtime = runtime(1, 4, 2);
  let mut job = Box::pin(
    runtime
      .handle()
      .spawn(async { 42_usize })
      .unwrap_or_else(|error| panic!("spawn failed: {error}")),
  );
  wait_until(|| job.as_ref().get_ref().is_finished(), "ready task output");
  let waker = Waker::noop();
  let mut context = Context::from_waker(waker);
  {
    let _outer_poll = super::entry::CooperativePollGuard::enter();
    for _ in 0..64 {
      let mut checkpoint = std::pin::pin!(super::consume_budget());
      assert!(matches!(
        checkpoint.as_mut().poll(&mut context),
        Poll::Ready(())
      ));
    }
    assert!(job.as_mut().poll(&mut context).is_pending());
  }
  {
    let _outer_poll = super::entry::CooperativePollGuard::enter();
    assert!(matches!(
      job.as_mut().poll(&mut context),
      Poll::Ready(Ok(42))
    ));
  }
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn ready_blocking_job_waits_at_zero_budget_and_keeps_its_output() {
  use crate::runtime::blocking::{Config, Runtime, ShutdownMode};
  use crate::runtime::resources::Resources;

  let mut runtime = Runtime::new(Config {
    workers: 1,
    max_outstanding: 2,
    capacity: Resources::ZERO,
  })
  .unwrap_or_else(|error| panic!("blocking runtime construction failed: {error}"));
  let mut job = Box::pin(
    runtime
      .try_spawn(Resources::ZERO, |_| 42_usize)
      .unwrap_or_else(|error| panic!("blocking spawn failed: {error}")),
  );
  wait_until(
    || job.as_ref().get_ref().is_finished(),
    "ready blocking job result",
  );
  let waker = Waker::noop();
  let mut context = Context::from_waker(waker);
  {
    let _outer_poll = super::entry::CooperativePollGuard::enter();
    for _ in 0..64 {
      let mut checkpoint = std::pin::pin!(super::consume_budget());
      assert!(matches!(
        checkpoint.as_mut().poll(&mut context),
        Poll::Ready(())
      ));
    }
    assert!(job.as_mut().poll(&mut context).is_pending());
  }
  {
    let _outer_poll = super::entry::CooperativePollGuard::enter();
    assert!(matches!(
      job.as_mut().poll(&mut context),
      Poll::Ready(Ok(42))
    ));
  }
  runtime
    .shutdown(ShutdownMode::Drain)
    .unwrap_or_else(|error| panic!("blocking shutdown failed: {error}"));
}

struct ReleaseGate(Arc<(Mutex<bool>, Condvar)>);

impl Drop for ReleaseGate {
  fn drop(&mut self) {
    let (lock, cv) = &*self.0;
    *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
    cv.notify_all();
  }
}

struct ThreadWake(std::thread::Thread);

impl Wake for ThreadWake {
  fn wake(self: Arc<Self>) {
    self.0.unpark();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.unpark();
  }
}

fn block_on<F: Future>(future: F) -> F::Output {
  let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
  let mut context = Context::from_waker(&waker);
  let mut future = std::pin::pin!(future);
  loop {
    if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
      return output;
    }
    std::thread::park_timeout(Duration::from_secs(2));
  }
}

struct WakeDuringPoll {
  polls: Arc<AtomicUsize>,
}

impl Future for WakeDuringPoll {
  type Output = usize;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let count = self.polls.fetch_add(1, Ordering::SeqCst);
    if count == 0 {
      cx.waker().wake_by_ref();
      cx.waker().wake_by_ref();
      cx.waker().wake_by_ref();
      Poll::Pending
    } else {
      Poll::Ready(count + 1)
    }
  }
}

#[test]
fn wakes_during_poll_are_coalesced_without_losing_progress() {
  let runtime = runtime(2, 8, 4);
  let polls = Arc::new(AtomicUsize::new(0));
  let job = runtime
    .handle()
    .spawn(WakeDuringPoll {
      polls: Arc::clone(&polls),
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  assert!(matches!(block_on(job), Ok(2)));
  assert_eq!(polls.load(Ordering::SeqCst), 2);
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

async fn perpetually_ready_channel_task(
  sender: crate::runtime::channel::Sender<usize>,
  mut receiver: crate::runtime::channel::Receiver<usize>,
  progress: Arc<AtomicUsize>,
) {
  let mut value = 0usize;
  loop {
    sender
      .send(value)
      .await
      .unwrap_or_else(|_| panic!("self-send failed"));
    assert_eq!(receiver.recv().await, Some(value));
    value += 1;
    progress.store(value, Ordering::SeqCst);
  }
}

#[test]
fn automatic_channel_budget_runs_sibling_and_cancel_pending_shutdown_completes() {
  use crate::runtime::channel;

  let runtime = runtime(1, 4, 2);
  let (sender, receiver) = channel::channel(1, 4).unwrap();
  let progress = Arc::new(AtomicUsize::new(0));
  let hot = runtime
    .handle()
    .spawn(perpetually_ready_channel_task(
      sender,
      receiver,
      Arc::clone(&progress),
    ))
    .unwrap_or_else(|error| panic!("hot task spawn failed: {error}"));
  wait_until(
    || progress.load(Ordering::SeqCst) != 0,
    "channel hot loop start",
  );

  let seen = Arc::new(AtomicUsize::new(usize::MAX));
  let sibling_seen = Arc::clone(&seen);
  let sibling_progress = Arc::clone(&progress);
  let sibling = runtime
    .handle()
    .spawn(async move {
      sibling_seen.store(sibling_progress.load(Ordering::SeqCst), Ordering::SeqCst);
    })
    .unwrap_or_else(|error| panic!("sibling spawn failed: {error}"));
  wait_until(|| sibling.is_finished(), "sibling task completion");
  assert!(matches!(block_on(sibling), Ok(())));
  let observed = seen.load(Ordering::SeqCst);
  assert!(observed > 0, "sibling ran before the hot loop started");
  assert!(!hot.is_finished(), "hot loop stopped before cancellation");

  let (shutdown_tx, shutdown_rx) = std::sync::mpsc::sync_channel(1);
  let shutdown_thread = std::thread::spawn(move || {
    let _ = shutdown_tx.send(runtime.shutdown_before_deadline(AsyncShutdown::CancelPending));
  });
  shutdown_rx
    .recv_timeout(Duration::from_secs(3))
    .unwrap_or_else(|_| panic!("CancelPending shutdown timed out"))
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  shutdown_thread
    .join()
    .unwrap_or_else(|_| panic!("shutdown thread panicked"));
  wait_until(|| hot.is_finished(), "hot task cancellation publication");
  assert!(matches!(block_on(hot), Err(AsyncJoinError::Cancelled)));
}

#[test]
fn automatic_channel_budget_allows_abort_of_perpetually_ready_loop() {
  use crate::runtime::channel;

  let runtime = runtime(1, 4, 2);
  let (sender, receiver) = channel::channel(1, 4).unwrap();
  let progress = Arc::new(AtomicUsize::new(0));
  let hot = runtime
    .handle()
    .spawn(perpetually_ready_channel_task(
      sender,
      receiver,
      Arc::clone(&progress),
    ))
    .unwrap_or_else(|error| panic!("hot task spawn failed: {error}"));
  wait_until(
    || progress.load(Ordering::SeqCst) != 0,
    "channel hot loop start",
  );

  hot.abort_handle().abort();
  wait_until(|| hot.is_finished(), "hot task abort publication");
  assert!(matches!(block_on(hot), Err(AsyncJoinError::Cancelled)));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn ready_channel_and_mutex_chains_each_charge_one_shared_unit() {
  use crate::runtime::channel;
  use crate::runtime::mutex::AsyncMutex;

  let runtime = runtime(1, 2, 1);
  let (sender, _receiver) = channel::channel(1, 2).unwrap();
  let mutex = AsyncMutex::new(7usize, 2).unwrap();
  let remaining = runtime
    .block_on(std::future::poll_fn(|cx| {
      let mut send = std::pin::pin!(sender.send(3));
      assert!(send.as_mut().poll(cx).is_ready());
      let after_send = super::entry::budget_remaining();

      let mut lock = std::pin::pin!(mutex.lock());
      let Poll::Ready(Ok(guard)) = lock.as_mut().poll(cx) else {
        panic!("uncontended mutex did not acquire");
      };
      assert_eq!(*guard, 7);
      drop(guard);
      let after_lock = super::entry::budget_remaining();
      Poll::Ready((after_send, after_lock))
    }))
    .unwrap();

  assert_eq!(remaining, (63, 62));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn semaphore_pending_refunds_and_terminal_ready_error_charges() {
  use crate::runtime::semaphore::Semaphore;

  let runtime = runtime(1, 1, 1);
  let semaphore = Semaphore::new(0, 2).unwrap();
  let closed = Semaphore::new(0, 1).unwrap();
  closed.close();
  let remaining = runtime
    .block_on(std::future::poll_fn(|cx| {
      let mut acquire = std::pin::pin!(semaphore.acquire_many(1));
      assert!(acquire.as_mut().poll(cx).is_pending());
      let after_pending = super::entry::budget_remaining();
      semaphore.add_permits(1).unwrap();
      let Poll::Ready(permit) = acquire.as_mut().poll(cx) else {
        panic!("released semaphore did not acquire");
      };
      let after_acquire = super::entry::budget_remaining();
      drop(permit);

      let mut terminal = std::pin::pin!(closed.acquire_many(1));
      assert!(terminal.as_mut().poll(cx).is_ready());
      Poll::Ready((
        after_pending,
        after_acquire,
        super::entry::budget_remaining(),
      ))
    }))
    .unwrap();

  assert_eq!(remaining, (64, 63, 62));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn manually_polled_channel_primitives_bypass_automatic_budget() {
  use crate::runtime::channel;

  let (sender, mut receiver) = channel::channel(1, 2).unwrap();
  let mut context = Context::from_waker(Waker::noop());
  assert!(!super::entry::cooperative_poll_active());
  for value in 0..130 {
    let mut send = std::pin::pin!(sender.send(value));
    assert!(send.as_mut().poll(&mut context).is_ready());
    let mut recv = std::pin::pin!(receiver.recv());
    assert_eq!(recv.as_mut().poll(&mut context), Poll::Ready(Some(value)));
  }
  assert_eq!(super::entry::budget_remaining(), 64);
}

struct NoConcurrentPoll {
  active: Arc<AtomicBool>,
  polls: Arc<AtomicUsize>,
}

impl Future for NoConcurrentPoll {
  type Output = ();

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
    assert!(!self.active.swap(true, Ordering::SeqCst), "concurrent poll");
    let count = self.polls.fetch_add(1, Ordering::SeqCst);
    self.active.store(false, Ordering::SeqCst);
    if count < 20 {
      cx.waker().wake_by_ref();
      Poll::Pending
    } else {
      Poll::Ready(())
    }
  }
}

#[test]
fn a_task_is_never_polled_concurrently() {
  let runtime = runtime(4, 8, 4);
  let active = Arc::new(AtomicBool::new(false));
  let polls = Arc::new(AtomicUsize::new(0));
  let job = runtime
    .handle()
    .spawn(NoConcurrentPoll {
      active: Arc::clone(&active),
      polls: Arc::clone(&polls),
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  assert!(matches!(block_on(job), Ok(())));
  assert_eq!(polls.load(Ordering::SeqCst), 21);
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct Gate {
  gate: Arc<(Mutex<bool>, Condvar)>,
  started: Arc<(Mutex<bool>, Condvar)>,
}

impl Future for Gate {
  type Output = ();

  fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
    let (started_lock, started_cv) = &*self.started;
    *started_lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
    started_cv.notify_all();
    let (gate_lock, gate_cv) = &*self.gate;
    let mut ready = gate_lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*ready {
      ready = gate_cv.wait(ready).unwrap_or_else(|e| e.into_inner());
    }
    Poll::Ready(())
  }
}

#[test]
fn abort_before_start_drops_future_on_a_worker_and_publishes_cancelled() {
  let runtime = runtime(1, 4, 2);
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let first = runtime
    .handle()
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  let dropped = Arc::new(AtomicBool::new(false));
  struct DropMark(Arc<AtomicBool>);
  impl Future for DropMark {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for DropMark {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }
  let second = runtime
    .handle()
    .spawn(DropMark(Arc::clone(&dropped)))
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  let control = second.abort_handle();
  assert!(!second.is_finished());
  let external = control.clone();
  std::thread::spawn(move || external.abort()).join().unwrap();
  assert!(!control.is_finished());
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(block_on(second), Err(AsyncJoinError::Cancelled)));
  assert!(control.is_finished());
  assert!(dropped.load(Ordering::SeqCst));
  assert!(matches!(block_on(first), Ok(())));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn full_admission_returns_the_original_future() {
  let runtime = runtime(1, 1, 1);
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let first = runtime
    .handle()
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  struct DropMark(Arc<AtomicBool>);
  impl Future for DropMark {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for DropMark {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }
  let dropped = Arc::new(AtomicBool::new(false));
  let rejected = runtime
    .handle()
    .spawn(DropMark(Arc::clone(&dropped)))
    .err()
    .unwrap_or_else(|| panic!("full runtime admitted another task"));
  assert_eq!(rejected.kind, super::AsyncError::Full);
  let returned = rejected.into_future();
  assert!(!dropped.load(Ordering::SeqCst));
  drop(returned);
  assert!(dropped.load(Ordering::SeqCst));
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(block_on(first), Ok(())));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct SubmitOnWake {
  handle: super::AsyncHandle,
  admitted: Arc<AtomicBool>,
}

impl Wake for SubmitOnWake {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    if let Ok(job) = self.handle.spawn(async {}) {
      self.admitted.store(true, Ordering::SeqCst);
      drop(job);
    }
  }
}

#[test]
fn scheduler_slot_is_released_before_join_waker_runs() {
  let runtime = runtime(1, 1, 1);
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let mut job = runtime
    .handle()
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  let admitted = Arc::new(AtomicBool::new(false));
  let waker = Waker::from(Arc::new(SubmitOnWake {
    handle: runtime.handle(),
    admitted: Arc::clone(&admitted),
  }));
  let mut context = Context::from_waker(&waker);
  assert!(matches!(
    Pin::new(&mut job).poll(&mut context),
    Poll::Pending
  ));
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  let deadline = Instant::now() + Duration::from_secs(2);
  while !admitted.load(Ordering::SeqCst) && Instant::now() < deadline {
    std::thread::yield_now();
  }
  assert!(admitted.load(Ordering::SeqCst));
  let poll_waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
  let mut context = Context::from_waker(&poll_waker);
  assert!(matches!(
    Pin::new(&mut job).poll(&mut context),
    Poll::Ready(Ok(()))
  ));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct PanicWake(Arc<AtomicBool>);

impl Wake for PanicWake {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.store(true, Ordering::SeqCst);
    panic!("join waker panic");
  }
}

#[test]
fn panicking_join_waker_does_not_kill_worker() {
  let runtime = runtime(1, 4, 2);
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let mut job = runtime
    .handle()
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  let called = Arc::new(AtomicBool::new(false));
  let waker = Waker::from(Arc::new(PanicWake(Arc::clone(&called))));
  let mut context = Context::from_waker(&waker);
  assert!(matches!(
    Pin::new(&mut job).poll(&mut context),
    Poll::Pending
  ));
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  let deadline = Instant::now() + Duration::from_secs(2);
  while !called.load(Ordering::SeqCst) && Instant::now() < deadline {
    std::thread::yield_now();
  }
  assert!(called.load(Ordering::SeqCst));
  let poll_waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
  let mut context = Context::from_waker(&poll_waker);
  assert!(matches!(
    Pin::new(&mut job).poll(&mut context),
    Poll::Ready(Ok(()))
  ));
  let next = runtime
    .handle()
    .spawn(async { 19usize })
    .unwrap_or_else(|e| panic!("worker died after waker panic: {e}"));
  assert!(matches!(block_on(next), Ok(19)));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct PanicDrop(Arc<AtomicBool>);

impl Drop for PanicDrop {
  fn drop(&mut self) {
    self.0.store(true, Ordering::SeqCst);
    panic!("user destructor panic");
  }
}

#[test]
fn detached_panicking_outputs_and_panic_payloads_do_not_kill_worker() {
  let runtime = runtime(1, 8, 2);
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let blocker = runtime
    .handle()
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  let output_dropped = Arc::new(AtomicBool::new(false));
  let output = Arc::clone(&output_dropped);
  let detached_output = runtime
    .handle()
    .spawn(async move { PanicDrop(output) })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  drop(detached_output);

  let payload_dropped = Arc::new(AtomicBool::new(false));
  let payload = Arc::clone(&payload_dropped);
  let detached_panic = runtime
    .handle()
    .spawn(async move {
      std::panic::panic_any(PanicDrop(payload));
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  drop(detached_panic);

  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(block_on(blocker), Ok(())));
  let deadline = Instant::now() + Duration::from_secs(2);
  while (!output_dropped.load(Ordering::SeqCst) || !payload_dropped.load(Ordering::SeqCst))
    && Instant::now() < deadline
  {
    std::thread::yield_now();
  }
  assert!(output_dropped.load(Ordering::SeqCst));
  assert!(payload_dropped.load(Ordering::SeqCst));
  let next = runtime
    .handle()
    .spawn(async { 23usize })
    .unwrap_or_else(|e| panic!("worker died after destructor panic: {e}"));
  assert!(matches!(block_on(next), Ok(23)));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct AbortRace {
  gate: Arc<(Mutex<bool>, Condvar)>,
  started: Arc<(Mutex<bool>, Condvar)>,
  waker: Arc<Mutex<Option<Waker>>>,
  dropped: Arc<AtomicBool>,
}

impl Future for AbortRace {
  type Output = ();

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
    *self.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
    let (started_lock, started_cv) = &*self.started;
    *started_lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
    started_cv.notify_all();
    let (gate_lock, gate_cv) = &*self.gate;
    let mut ready = gate_lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*ready {
      ready = gate_cv.wait(ready).unwrap_or_else(|e| e.into_inner());
    }
    Poll::Pending
  }
}

impl Drop for AbortRace {
  fn drop(&mut self) {
    self.dropped.store(true, Ordering::SeqCst);
  }
}

#[test]
fn abort_during_poll_is_cleaned_after_that_poll_returns() {
  let runtime = runtime(1, 4, 2);
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let task_waker = Arc::new(Mutex::new(None));
  let dropped = Arc::new(AtomicBool::new(false));
  let job = runtime
    .handle()
    .spawn(AbortRace {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
      waker: Arc::clone(&task_waker),
      dropped: Arc::clone(&dropped),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  task_waker
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .as_ref()
    .unwrap_or_else(|| panic!("task did not publish its waker"))
    .wake_by_ref();
  job.abort();
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(block_on(job), Err(AsyncJoinError::Cancelled)));
  assert!(dropped.load(Ordering::SeqCst));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct RetainWaker {
  retained: Arc<Mutex<Option<Waker>>>,
  dropped: Arc<AtomicBool>,
}

impl Future for RetainWaker {
  type Output = ();

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
    *self.retained.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
    Poll::Ready(())
  }
}

impl Drop for RetainWaker {
  fn drop(&mut self) {
    self.dropped.store(true, Ordering::SeqCst);
  }
}

#[test]
fn retained_waker_does_not_keep_completed_future_alive() {
  let runtime = runtime(1, 4, 2);
  let retained = Arc::new(Mutex::new(None));
  let dropped = Arc::new(AtomicBool::new(false));
  let job = runtime
    .handle()
    .spawn(RetainWaker {
      retained: Arc::clone(&retained),
      dropped: Arc::clone(&dropped),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  assert!(matches!(block_on(job), Ok(())));
  assert!(dropped.load(Ordering::SeqCst));
  assert!(retained.lock().unwrap_or_else(|e| e.into_inner()).is_some());
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct SelfWakeLoop {
  polls: usize,
  remaining: usize,
}

impl Future for SelfWakeLoop {
  type Output = usize;

  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
    self.polls += 1;
    if self.remaining == 0 {
      return Poll::Ready(self.polls);
    }
    self.remaining -= 1;
    for _ in 0..3 {
      cx.waker().wake_by_ref();
    }
    Poll::Pending
  }
}

/// Fails instead of hanging when a lost wake leaves a job pending forever.
fn wait_finished<T>(jobs: &[super::AsyncJob<T>], message: &str) {
  let deadline = Instant::now() + Duration::from_secs(30);
  while !jobs.iter().all(super::AsyncJob::is_finished) {
    assert!(Instant::now() < deadline, "timed out waiting for {message}");
    std::thread::yield_now();
  }
}

#[test]
fn tasks_that_wake_themselves_many_times_complete_with_one_poll_per_round() {
  const ROUNDS: usize = 10_000;
  let runtime = runtime(4, 8, 2);
  let jobs: Vec<_> = (0..8)
    .map(|_| {
      runtime
        .handle()
        .spawn(SelfWakeLoop {
          polls: 0,
          remaining: ROUNDS,
        })
        .unwrap_or_else(|e| panic!("spawn failed: {e}"))
    })
    .collect();
  wait_finished(&jobs, "self-woken tasks");
  for job in jobs {
    // Each poll's coalesced self-wakes requeue it exactly once.
    assert!(matches!(block_on(job), Ok(polls) if polls == ROUNDS + 1));
  }
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct ExternalWakeTarget {
  sent: Arc<AtomicUsize>,
  waker: Arc<Mutex<Option<Waker>>>,
  total: usize,
}

impl Future for ExternalWakeTarget {
  type Output = ();

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
    let mut waker = self.waker.lock().unwrap_or_else(|e| e.into_inner());
    if waker.is_none() {
      *waker = Some(cx.waker().clone());
    }
    drop(waker);
    if self.sent.load(Ordering::Acquire) >= self.total {
      Poll::Ready(())
    } else {
      Poll::Pending
    }
  }
}

#[test]
fn external_wakes_racing_poll_completion_are_never_lost() {
  const TASKS: usize = 4;
  const WAKES: usize = 20_000;
  let runtime = runtime(4, TASKS, 2);
  let mut jobs = Vec::new();
  let mut wakers = Vec::new();
  for _ in 0..TASKS {
    let sent = Arc::new(AtomicUsize::new(0));
    let waker = Arc::new(Mutex::new(None));
    jobs.push(
      runtime
        .handle()
        .spawn(ExternalWakeTarget {
          sent: Arc::clone(&sent),
          waker: Arc::clone(&waker),
          total: WAKES,
        })
        .unwrap_or_else(|e| panic!("spawn failed: {e}")),
    );
    wakers.push((sent, waker));
  }
  let threads: Vec<_> = wakers
    .into_iter()
    .map(|(sent, waker)| {
      std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        let waker = loop {
          if let Some(waker) = waker.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            break waker;
          }
          assert!(Instant::now() < deadline, "task was never polled");
          std::thread::yield_now();
        };
        for sent_count in 1..=WAKES {
          sent.store(sent_count, Ordering::Release);
          waker.wake_by_ref();
        }
      })
    })
    .collect();
  for thread in threads {
    thread
      .join()
      .unwrap_or_else(|_| panic!("waking thread panicked"));
  }
  // A lost final wake leaves its task pending forever.
  wait_finished(&jobs, "the final external wakes");
  for job in jobs {
    assert!(matches!(block_on(job), Ok(())));
  }
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct WakeCount {
  polls: Arc<AtomicUsize>,
  current: Arc<Mutex<Option<Waker>>>,
}

struct RepeatedWake {
  wakers: Arc<Mutex<Vec<Waker>>>,
}

impl Future for RepeatedWake {
  type Output = ();

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
    let mut wakers = self.wakers.lock().unwrap_or_else(|e| e.into_inner());
    wakers.push(cx.waker().clone());
    if wakers.len() == 3 {
      Poll::Ready(())
    } else {
      cx.waker().wake_by_ref();
      Poll::Pending
    }
  }
}

#[test]
fn task_reuses_waker_across_polls() {
  let runtime = runtime(1, 4, 2);
  let wakers = Arc::new(Mutex::new(Vec::new()));
  let job = runtime
    .handle()
    .spawn(RepeatedWake {
      wakers: Arc::clone(&wakers),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  assert!(matches!(block_on(job), Ok(())));
  let wakers = wakers.lock().unwrap_or_else(|e| e.into_inner());
  assert_eq!(wakers.len(), 3);
  assert!(wakers.windows(2).all(|pair| pair[0].will_wake(&pair[1])));
  drop(wakers);
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

impl Future for WakeCount {
  type Output = usize;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
    *self.current.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
    let count = self.polls.fetch_add(1, Ordering::SeqCst);
    if count == 0 {
      Poll::Pending
    } else {
      Poll::Ready(count + 1)
    }
  }
}

#[test]
fn stale_waker_from_reused_slot_cannot_wake_the_new_generation() {
  let runtime = runtime(1, 1, 1);
  let stale = Arc::new(Mutex::new(None));
  let first = runtime
    .handle()
    .spawn(RetainWaker {
      retained: Arc::clone(&stale),
      dropped: Arc::new(AtomicBool::new(false)),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  assert!(matches!(block_on(first), Ok(())));
  let stale_waker = stale
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .as_ref()
    .cloned()
    .unwrap_or_else(|| panic!("first task did not retain its waker"));

  let polls = Arc::new(AtomicUsize::new(0));
  let current = Arc::new(Mutex::new(None));
  let second = runtime
    .handle()
    .spawn(WakeCount {
      polls: Arc::clone(&polls),
      current: Arc::clone(&current),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  let deadline = Instant::now() + Duration::from_secs(2);
  while polls.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
    std::thread::yield_now();
  }
  assert_eq!(polls.load(Ordering::SeqCst), 1);
  stale_waker.wake_by_ref();
  std::thread::sleep(Duration::from_millis(10));
  assert_eq!(polls.load(Ordering::SeqCst), 1);
  current
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .take()
    .unwrap_or_else(|| panic!("second task did not retain its waker"))
    .wake();
  assert!(matches!(block_on(second), Ok(2)));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn saturated_scope_allows_cancellation_and_independent_work() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 2,
    max_outstanding: 8,
    max_scopes: 4,
  })
  .unwrap();
  let limited = runtime
    .scope_with_config(AsyncScopeConfig {
      max_active_polls: 1,
    })
    .unwrap_or_else(|e| panic!("limited scope failed: {e}"));
  let other = runtime
    .scope()
    .unwrap_or_else(|e| panic!("other scope failed: {e}"));
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let _release_gate = ReleaseGate(Arc::clone(&gate));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let blocker = limited
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("blocker spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  assert_eq!(limited.snapshot().active_polls, 1);
  assert_eq!(limited.snapshot().max_active_polls, 1);

  let order = Arc::new(Mutex::new(Vec::new()));
  let head_order = Arc::clone(&order);
  let head = limited
    .spawn(async move {
      head_order.lock().unwrap_or_else(|e| e.into_inner()).push(1);
    })
    .unwrap_or_else(|e| panic!("head spawn failed: {e}"));
  let tail_order = Arc::clone(&order);
  let tail = limited
    .spawn(async move {
      tail_order.lock().unwrap_or_else(|e| e.into_inner()).push(2);
    })
    .unwrap_or_else(|e| panic!("tail spawn failed: {e}"));

  struct DropMark(Arc<AtomicBool>);
  impl Future for DropMark {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for DropMark {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }
  let dropped = Arc::new(AtomicBool::new(false));
  let cancelled = limited
    .spawn(DropMark(Arc::clone(&dropped)))
    .unwrap_or_else(|e| panic!("cancelled spawn failed: {e}"));

  let other_ran = Arc::new(AtomicBool::new(false));
  let other_flag = Arc::clone(&other_ran);
  let independent = other
    .spawn(async move {
      other_flag.store(true, Ordering::SeqCst);
    })
    .unwrap_or_else(|e| panic!("other spawn failed: {e}"));
  wait_until(|| other_ran.load(Ordering::SeqCst), "other scope dispatch");
  assert!(order.lock().unwrap_or_else(|e| e.into_inner()).is_empty());

  cancelled.abort_handle().abort();
  wait_until(
    || dropped.load(Ordering::SeqCst),
    "queued cancellation cleanup",
  );
  assert!(matches!(
    block_on(cancelled),
    Err(AsyncJoinError::Cancelled)
  ));
  assert!(order.lock().unwrap_or_else(|e| e.into_inner()).is_empty());

  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(block_on(blocker), Ok(())));
  assert!(matches!(block_on(head), Ok(())));
  assert!(matches!(block_on(tail), Ok(())));
  assert!(matches!(block_on(independent), Ok(())));
  let mut completed = order.lock().unwrap_or_else(|e| e.into_inner()).clone();
  completed.sort_unstable();
  assert_eq!(completed, [1, 2]);
  assert_eq!(limited.snapshot().active_polls, 0);
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn idle_pending_abort_gets_a_queue_token_and_invalid_poll_limits_reject() {
  assert!(matches!(
    runtime(1, 2, 2).scope_with_config(AsyncScopeConfig {
      max_active_polls: 0
    }),
    Err(super::AsyncError::InvalidConfig)
  ));
  let runtime = runtime(1, 2, 2);
  let scope = runtime
    .scope_with_config(AsyncScopeConfig {
      max_active_polls: 1,
    })
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let polls = Arc::new(AtomicUsize::new(0));
  let observed = Arc::clone(&polls);
  let job = scope
    .spawn(std::future::poll_fn(move |_cx| {
      observed.fetch_add(1, Ordering::SeqCst);
      Poll::<()>::Pending
    }))
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  wait_until(|| polls.load(Ordering::SeqCst) == 1, "first pending poll");
  let sentinel_ran = Arc::new(AtomicBool::new(false));
  let sentinel_flag = Arc::clone(&sentinel_ran);
  let sentinel = scope
    .spawn(async move {
      sentinel_flag.store(true, Ordering::SeqCst);
    })
    .unwrap_or_else(|e| panic!("sentinel spawn failed: {e}"));
  assert!(matches!(block_on(sentinel), Ok(())));
  assert!(sentinel_ran.load(Ordering::SeqCst));
  job.abort_handle().abort();
  assert!(matches!(block_on(job), Err(AsyncJoinError::Cancelled)));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn closing_a_quota_blocked_scope_reactivates_queued_cancellation() {
  let runtime = runtime(2, 4, 2);
  let scope = runtime
    .scope_with_config(AsyncScopeConfig {
      max_active_polls: 1,
    })
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let _release_gate = ReleaseGate(Arc::clone(&gate));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let blocker = scope
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("blocker spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  let dropped = Arc::new(AtomicBool::new(false));
  struct DropMark(Arc<AtomicBool>);
  impl Future for DropMark {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for DropMark {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }
  let queued = scope
    .spawn(DropMark(Arc::clone(&dropped)))
    .unwrap_or_else(|e| panic!("queued spawn failed: {e}"));
  let close = scope.close();
  wait_until(
    || dropped.load(Ordering::SeqCst),
    "scope-close cancellation bypass",
  );
  assert!(matches!(block_on(queued), Err(AsyncJoinError::Cancelled)));
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(block_on(blocker), Ok(())));
  assert_eq!(block_on(close), ());
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn cancel_pending_shutdown_reactivates_quota_blocked_work() {
  let runtime = runtime(2, 4, 3);
  let scope = runtime
    .scope_with_config(AsyncScopeConfig {
      max_active_polls: 1,
    })
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let _release_gate = ReleaseGate(Arc::clone(&gate));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let blocker = scope
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("blocker spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  let dropped = Arc::new(AtomicBool::new(false));
  struct DropMark(Arc<AtomicBool>);
  impl Future for DropMark {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for DropMark {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }
  let queued = scope
    .spawn(DropMark(Arc::clone(&dropped)))
    .unwrap_or_else(|e| panic!("queued spawn failed: {e}"));
  let release_gate = Arc::clone(&gate);
  let dropped_signal = Arc::clone(&dropped);
  let releaser = std::thread::spawn(move || {
    let _release_on_unwind = ReleaseGate(Arc::clone(&release_gate));
    wait_until(
      || dropped_signal.load(Ordering::SeqCst),
      "shutdown cancellation dispatch",
    );
    let (lock, cv) = &*release_gate;
    *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
    cv.notify_all();
  });
  runtime
    .shutdown_before_deadline(AsyncShutdown::CancelPending)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
  releaser
    .join()
    .unwrap_or_else(|_| panic!("gate releaser panicked"));
  assert!(matches!(block_on(queued), Err(AsyncJoinError::Cancelled)));
  assert!(matches!(block_on(blocker), Ok(())));
}

#[test]
fn native_resource_scope_binding_survives_task_and_buffer_lifetimes() {
  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: 32,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let runtime = runtime(2, 8, 3);
  let scope = runtime
    .scope_with_resources(&resources)
    .unwrap_or_else(|e| panic!("resource scope failed: {e}"));
  let handle = scope.handle();

  assert!(
    runtime
      .block_on(async { super::try_current_resource_scope().is_none() })
      .unwrap()
  );
  let bound_root = handle
    .block_on(async {
      (
        super::current_resource_scope().limits().managed_memory,
        super::try_task_id(),
      )
    })
    .unwrap();
  assert_eq!(bound_root, (32, None));

  let job = scope
    .spawn(async {
      assert_eq!(super::current_resource_scope().limits().managed_memory, 32);
      super::current_resource_scope()
        .try_alloc_zeroed(24)
        .unwrap_or_else(|e| panic!("managed buffer allocation failed: {e}"))
    })
    .unwrap_or_else(|e| panic!("bound task spawn failed: {e}"));
  let buffer = runtime
    .block_on(job)
    .unwrap()
    .unwrap_or_else(|e| panic!("bound task failed: {e}"));
  assert_eq!(resources.snapshot().managed_memory, 24);

  runtime
    .block_on(scope.close())
    .unwrap_or_else(|e| panic!("scope close failed: {e}"));
  assert_eq!(resources.snapshot().managed_memory, 24);
  drop(buffer);
  assert_eq!(resources.snapshot().managed_memory, 0);
}

#[test]
fn native_resource_context_is_explicit_restored_on_unwind_and_not_inherited() {
  use super::entry::TaskContextGuard;

  let outer = ResourceScope::new(ResourceLimits {
    managed_memory: 5,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let bound = ResourceScope::new(ResourceLimits {
    managed_memory: 17,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let runtime = runtime(2, 8, 3);
  let scope = runtime
    .scope_with_config_and_resources(
      AsyncScopeConfig {
        max_active_polls: 1,
      },
      &bound,
    )
    .unwrap_or_else(|e| panic!("resource scope failed: {e}"));
  let second_resources = ResourceScope::new(ResourceLimits {
    managed_memory: 23,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let second_scope = runtime
    .scope_with_resources(&second_resources)
    .unwrap_or_else(|e| panic!("second resource scope failed: {e}"));
  let handle = scope.handle();
  let root_handle = runtime.handle();

  let _outer = TaskContextGuard::enter_with_resource(None, Some(outer.clone()));
  let bound_limits = handle
    .block_on(async { super::current_resource_scope().limits().managed_memory })
    .unwrap();
  assert_eq!(bound_limits, 17);
  assert_eq!(
    super::try_current_resource_scope()
      .unwrap_or_else(|| panic!("outer binding was not restored"))
      .limits()
      .managed_memory,
    5
  );

  let first_limits = scope
    .spawn(async { super::current_resource_scope().limits().managed_memory })
    .unwrap_or_else(|e| panic!("first resource task failed admission: {e}"));
  let second_limits = second_scope
    .spawn(async { super::current_resource_scope().limits().managed_memory })
    .unwrap_or_else(|e| panic!("second resource task failed admission: {e}"));
  assert_eq!(runtime.block_on(first_limits).unwrap().unwrap(), 17);
  assert_eq!(runtime.block_on(second_limits).unwrap().unwrap(), 23);

  let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    let _ = handle.block_on(async { panic!("root poll panic") });
  }));
  assert!(unwind.is_err());
  assert_eq!(
    super::current_resource_scope().limits().managed_memory,
    5,
    "resource context was not restored after root-poll unwind"
  );

  let (child_tx, child_rx) = std::sync::mpsc::channel();
  let child_producer = scope
    .spawn(async move {
      assert_eq!(super::current_resource_scope().limits().managed_memory, 17);
      let child = root_handle
        .spawn(async { super::try_current_resource_scope().is_none() })
        .unwrap_or_else(|e| panic!("unbound child spawn failed: {e}"));
      child_tx
        .send(child)
        .unwrap_or_else(|_| panic!("child receiver disconnected"));
    })
    .unwrap_or_else(|e| panic!("bound task spawn failed: {e}"));
  assert!(runtime.block_on(child_producer).unwrap().is_ok());
  let child = child_rx
    .recv()
    .unwrap_or_else(|e| panic!("unbound child was not submitted: {e}"));
  assert!(runtime.block_on(child).unwrap().unwrap());
  runtime
    .block_on(scope.close())
    .unwrap_or_else(|e| panic!("scope close failed: {e}"));
  runtime
    .block_on(second_scope.close())
    .unwrap_or_else(|e| panic!("second scope close failed: {e}"));
}

#[test]
fn resource_bound_scope_rejection_returns_the_original_unpolled_future() {
  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: 13,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let runtime = runtime(1, 1, 2);
  let scope = runtime
    .scope_with_resources(&resources)
    .unwrap_or_else(|e| panic!("resource scope failed: {e}"));
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let _release_gate = ReleaseGate(Arc::clone(&gate));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let blocker = scope
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("blocker spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }

  struct TokenFuture {
    token: Arc<AtomicBool>,
    polled: Arc<AtomicBool>,
  }
  impl Future for TokenFuture {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      self.polled.store(true, Ordering::SeqCst);
      Poll::Ready(())
    }
  }
  let token = Arc::new(AtomicBool::new(false));
  let polled = Arc::new(AtomicBool::new(false));
  let rejected = scope
    .spawn(TokenFuture {
      token: Arc::clone(&token),
      polled: Arc::clone(&polled),
    })
    .err()
    .unwrap_or_else(|| panic!("full scope admitted another task"));
  assert_eq!(rejected.kind, super::AsyncError::Full);
  let returned = rejected.into_future();
  assert!(Arc::ptr_eq(&returned.token, &token));
  assert!(!polled.load(Ordering::SeqCst));
  drop(returned);

  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(runtime.block_on(blocker).unwrap(), Ok(())));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn native_runtime_owned_future_and_detached_output_drops_keep_scope_binding() {
  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: 41,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let runtime = runtime(2, 8, 3);
  let scope = runtime
    .scope_with_resources(&resources)
    .unwrap_or_else(|e| panic!("resource scope failed: {e}"));

  struct DropProbe(std::sync::mpsc::Sender<Option<usize>>);
  impl Future for DropProbe {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for DropProbe {
    fn drop(&mut self) {
      let observed = super::try_current_resource_scope().map(|scope| scope.limits().managed_memory);
      let _ = self.0.send(observed);
    }
  }
  let (future_tx, future_rx) = std::sync::mpsc::channel();
  let pending = scope
    .spawn(DropProbe(future_tx))
    .unwrap_or_else(|e| panic!("future-drop task spawn failed: {e}"));
  pending.abort_handle().abort();
  assert!(matches!(
    runtime.block_on(pending).unwrap(),
    Err(AsyncJoinError::Cancelled)
  ));
  assert_eq!(future_rx.recv().unwrap(), Some(41));

  struct OutputProbe(std::sync::mpsc::Sender<Option<usize>>);
  impl Drop for OutputProbe {
    fn drop(&mut self) {
      let observed = super::try_current_resource_scope().map(|scope| scope.limits().managed_memory);
      let _ = self.0.send(observed);
    }
  }
  let (output_tx, output_rx) = std::sync::mpsc::channel();
  let output_gate = Arc::new((Mutex::new(false), Condvar::new()));
  let _release_output_gate = ReleaseGate(Arc::clone(&output_gate));
  let output_started = Arc::new((Mutex::new(false), Condvar::new()));
  let task_gate = Arc::clone(&output_gate);
  let task_started = Arc::clone(&output_started);
  let detached = scope
    .spawn(async move {
      Gate {
        gate: task_gate,
        started: task_started,
      }
      .await;
      OutputProbe(output_tx)
    })
    .unwrap_or_else(|e| panic!("detached task spawn failed: {e}"));
  {
    let (lock, cv) = &*output_started;
    let mut started = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*started {
      started = cv.wait(started).unwrap_or_else(|e| e.into_inner());
    }
  }
  // Keep the future from producing its output until after the caller has
  // detached the job, so this observes producer-side discarded-output cleanup.
  drop(detached);
  {
    let (lock, cv) = &*output_gate;
    *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
    cv.notify_all();
  }
  assert_eq!(
    output_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
    Some(41)
  );
  runtime
    .block_on(scope.close())
    .unwrap_or_else(|e| panic!("scope close failed: {e}"));
}

#[test]
fn poll_quota_releases_before_a_panicking_future_destructor() {
  let runtime = runtime(2, 4, 2);
  let scope = runtime
    .scope_with_config(AsyncScopeConfig {
      max_active_polls: 1,
    })
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let drop_gate = Arc::new((Mutex::new(false), Condvar::new()));
  let _release_drop_gate = ReleaseGate(Arc::clone(&drop_gate));
  let drop_started = Arc::new(AtomicBool::new(false));
  struct PanicOnPoll {
    gate: Arc<(Mutex<bool>, Condvar)>,
    started: Arc<AtomicBool>,
  }
  impl Future for PanicOnPoll {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      panic!("expected poll panic");
    }
  }
  impl Drop for PanicOnPoll {
    fn drop(&mut self) {
      self.started.store(true, Ordering::SeqCst);
      let (lock, cv) = &*self.gate;
      let mut released = lock.lock().unwrap_or_else(|e| e.into_inner());
      while !*released {
        released = cv.wait(released).unwrap_or_else(|e| e.into_inner());
      }
    }
  }
  let panicked = scope
    .spawn(PanicOnPoll {
      gate: Arc::clone(&drop_gate),
      started: Arc::clone(&drop_started),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  wait_until(
    || drop_started.load(Ordering::SeqCst),
    "panicking future destructor",
  );

  assert_eq!(scope.snapshot().active_polls, 0);
  {
    // A lone successor can wait behind this lane owner's destructor. Check
    // quota release directly before permitting that destructor to finish.
    let (lock, cv) = &*drop_gate;
    *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
    cv.notify_all();
  }

  let successor_ran = Arc::new(AtomicBool::new(false));
  let flag = Arc::clone(&successor_ran);
  let successor = scope
    .spawn(async move {
      flag.store(true, Ordering::SeqCst);
    })
    .unwrap_or_else(|e| panic!("successor spawn failed: {e}"));
  wait_until(
    || successor_ran.load(Ordering::SeqCst),
    "successor poll during cleanup",
  );

  let (lock, cv) = &*drop_gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(
    block_on(panicked),
    Err(AsyncJoinError::Panicked(_))
  ));
  assert!(matches!(block_on(successor), Ok(())));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn panic_is_published_and_dropping_join_detaches() {
  let runtime = runtime(2, 8, 4);
  let panicked = runtime.handle().spawn(async {
    panic!("task panic");
  });
  let panicked = panicked.unwrap_or_else(|e| panic!("spawn failed: {e}"));
  assert!(matches!(
    block_on(panicked),
    Err(AsyncJoinError::Panicked(_))
  ));
  let ran = Arc::new(AtomicBool::new(false));
  let flag = Arc::clone(&ran);
  drop(
    runtime
      .handle()
      .spawn(async move {
        flag.store(true, Ordering::SeqCst);
      })
      .unwrap_or_else(|e| panic!("spawn failed: {e}")),
  );
  let deadline = Instant::now() + Duration::from_secs(2);
  while !ran.load(Ordering::SeqCst) && Instant::now() < deadline {
    std::thread::yield_now();
  }
  assert!(ran.load(Ordering::SeqCst));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn scope_drop_cancels_and_shutdown_from_worker_is_rejected() {
  let runtime = Arc::new(runtime(1, 8, 3));
  let scope = runtime
    .scope()
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let dropped = Arc::new(AtomicBool::new(false));
  struct Never(Arc<AtomicBool>);
  impl Future for Never {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for Never {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }
  let job = scope
    .spawn(Never(Arc::clone(&dropped)))
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  block_on(scope.close());
  assert!(matches!(block_on(job), Err(AsyncJoinError::Cancelled)));
  assert!(dropped.load(Ordering::SeqCst));
  let runtime_slot = Arc::new(Mutex::new(Some(
    Arc::try_unwrap(runtime).unwrap_or_else(|_| panic!("runtime still shared")),
  )));
  let handle = runtime_slot
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .as_ref()
    .map(AsyncRuntime::handle)
    .unwrap_or_else(|| panic!("runtime missing"));
  let worker_slot = Arc::clone(&runtime_slot);
  let worker_job = handle
    .spawn(async move {
      let runtime = worker_slot
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .unwrap_or_else(|| panic!("runtime missing"));
      runtime.shutdown_before_deadline(AsyncShutdown::Drain)
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  assert!(matches!(
    block_on(worker_job),
    Ok(Err(super::AsyncError::WouldDeadlock))
  ));
}

struct ManyGate {
  gate: Arc<(Mutex<bool>, Condvar)>,
  started: Arc<(Mutex<usize>, Condvar)>,
}

impl Future for ManyGate {
  type Output = ();

  fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
    let (started_lock, started_cv) = &*self.started;
    *started_lock.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    started_cv.notify_all();
    let (gate_lock, gate_cv) = &*self.gate;
    let mut ready = gate_lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*ready {
      ready = gate_cv.wait(ready).unwrap_or_else(|e| e.into_inner());
    }
    Poll::Ready(())
  }
}

#[test]
fn concurrent_last_scope_children_release_scope_capacity() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 2,
    max_outstanding: 8,
    max_scopes: 2,
  })
  .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
  let scope = runtime
    .scope()
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(0usize), Condvar::new()));
  for _ in 0..2 {
    let job = scope
      .spawn(ManyGate {
        gate: Arc::clone(&gate),
        started: Arc::clone(&started),
      })
      .unwrap_or_else(|e| panic!("spawn failed: {e}"));
    drop(job);
  }
  {
    let (lock, cv) = &*started;
    let mut count = lock.lock().unwrap_or_else(|e| e.into_inner());
    while *count < 2 {
      count = cv.wait(count).unwrap_or_else(|e| e.into_inner());
    }
  }
  let close = scope.close();
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  block_on(close);
  let replacement = runtime
    .scope()
    .unwrap_or_else(|e| panic!("scope slot leaked after concurrent cleanup: {e}"));
  drop(replacement);
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn block_on_accepts_borrowed_non_send_root_future() {
  use super::AsyncHandle;

  let runtime = runtime(1, 4, 2);
  let local = std::cell::Cell::new(0);
  let result = runtime
    .block_on(async {
      local.set(41);
      (local.get() + 1, AsyncHandle::try_current().is_some())
    })
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
  assert_eq!(result, (42, true));
  assert!(AsyncHandle::try_current().is_none());
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn block_on_parks_while_workers_progress_and_wake_it() {
  let runtime = runtime(2, 4, 2);
  let job = runtime
    .handle()
    .spawn(async {
      std::thread::sleep(Duration::from_millis(10));
      42
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  let joined = runtime
    .block_on(job)
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
  assert!(matches!(joined, Ok(42)));
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn nested_block_on_returns_error_and_entered_context_restores_after_unwind() {
  use super::AsyncHandle;

  let first = runtime(1, 4, 2);
  let second = runtime(1, 4, 2);
  let first_handle = first.handle();
  let second_handle = second.handle();
  assert!(AsyncHandle::try_current().is_none());
  {
    let _outer = first_handle.enter();
    assert!(Arc::ptr_eq(
      &AsyncHandle::current().shared,
      &first_handle.shared
    ));
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let _inner = second_handle.enter();
      assert!(Arc::ptr_eq(
        &AsyncHandle::current().shared,
        &second_handle.shared
      ));
      panic!("exercise context guard unwind");
    }));
    assert!(panic.is_err());
    assert!(Arc::ptr_eq(
      &AsyncHandle::current().shared,
      &first_handle.shared
    ));
  }
  assert!(AsyncHandle::try_current().is_none());

  let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    let _ = first.block_on(async { panic!("exercise block_on unwind guards") });
  }));
  assert!(panic.is_err());
  assert!(AsyncHandle::try_current().is_none());
  assert!(matches!(first.block_on(async { 3 }), Ok(3)));

  let nested = first
    .block_on(async { second_handle.block_on(async { 7 }) })
    .unwrap_or_else(|error| panic!("outer block_on failed: {error}"));
  assert!(matches!(nested, Err(super::AsyncError::NestedBlockOn)));
  first
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  second
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn entered_context_guards_restore_when_dropped_out_of_order() {
  use super::AsyncHandle;

  let first_runtime = runtime(1, 4, 2);
  let second_runtime = runtime(1, 4, 2);
  let first = first_runtime.handle();
  let second = second_runtime.handle();
  let first_guard = first.enter();
  let second_guard = second.enter();
  drop(first_guard);
  assert!(Arc::ptr_eq(&AsyncHandle::current().shared, &second.shared));
  drop(second_guard);
  assert!(AsyncHandle::try_current().is_none());
  first_runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  second_runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn block_on_can_return_an_enter_guard_without_resurrecting_the_root_context() {
  use super::AsyncHandle;

  let runtime = runtime(1, 2, 1);
  let handle = runtime.handle();
  let guard = runtime
    .block_on(async move { handle.enter() })
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
  assert!(Arc::ptr_eq(
    &AsyncHandle::current().shared,
    &runtime.handle().shared
  ));
  drop(guard);
  assert!(AsyncHandle::try_current().is_none());
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn worker_context_is_entered_and_block_on_is_rejected_there() {
  use super::AsyncHandle;

  let primary_runtime = runtime(1, 4, 2);
  let other_runtime = runtime(1, 4, 2);
  let handle = primary_runtime.handle();
  let other_handle = other_runtime.handle();
  let worker_handle = handle.clone();
  let block_on_handle = other_handle.clone();
  let job = handle
    .spawn(async move {
      (
        AsyncHandle::try_current()
          .is_some_and(|current| Arc::ptr_eq(&current.shared, &worker_handle.shared)),
        block_on_handle.block_on(async { 9 }),
      )
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  let result = block_on(job).unwrap_or_else(|error| panic!("join failed: {error}"));
  assert!(result.0);
  assert!(matches!(
    result.1,
    Err(super::AsyncError::BlockOnFromWorker)
  ));
  primary_runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  other_runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn a_handle_retained_after_shutdown_rejects_spawn_and_returns_future() {
  let runtime = runtime(1, 2, 1);
  let handle = runtime.handle();
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  let error = handle
    .spawn(async { 19 })
    .err()
    .unwrap_or_else(|| panic!("closed handle unexpectedly admitted a task"));
  assert!(matches!(error.kind, super::AsyncError::Closed));
  assert_eq!(block_on(error.into_future()), 19);
}

#[test]
fn cpu_limited_self_yielding_tasks_progress_and_return_cpu() {
  use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};

  let ceiling = DomainResources::ZERO
    .with(DomainResource::Cpu, 1)
    .with(DomainResource::Tasks, 8)
    .with(DomainResource::Control, 1 << 20);
  let domain = ResourceDomain::with_waiters(ceiling, 1, 8).unwrap();
  let tenant = domain.tenant(ceiling).unwrap();
  let runtime = AsyncRuntime::with_resources(
    AsyncConfig {
      workers: 2,
      max_outstanding: 4,
      max_scopes: 1,
    },
    ResourceScope::from_tenant(ResourceLimits::default(), tenant),
  )
  .unwrap_or_else(|error| panic!("runtime setup failed: {error}"));
  // Two tasks share one CPU ticket. A pending poll must return its ticket
  // before the scheduler lock is retaken, so the other worker can admit the
  // requeued task instead of stalling behind it.
  let jobs: Vec<_> = (0..2)
    .map(|_| {
      let mut polls = 0;
      runtime
        .handle()
        .spawn(std::future::poll_fn(move |cx| {
          polls += 1;
          if polls == 2_000 {
            Poll::Ready(polls)
          } else {
            cx.waker().wake_by_ref();
            Poll::Pending
          }
        }))
        .unwrap_or_else(|error| panic!("spawn failed: {}", error.kind))
    })
    .collect();
  let deadline = Instant::now() + Duration::from_secs(30);
  while !jobs.iter().all(|job| job.is_finished()) {
    assert!(Instant::now() < deadline, "CPU-limited tasks stalled");
    std::thread::sleep(Duration::from_millis(1));
  }
  for job in jobs {
    assert_eq!(runtime.block_on(job).unwrap().unwrap(), 2_000);
  }
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
  runtime
    .shutdown_before_deadline(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}
