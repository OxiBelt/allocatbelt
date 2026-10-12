//! Runtime Control-accounting integration tests.

#![cfg(all(test, not(loom)))]

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use crate::runtime::asynchronous::{
  AsyncConfig, AsyncError, AsyncJob, AsyncJoinError, AsyncRuntime, AsyncShutdown,
  AsyncThreadOptions, LocalConfig, LocalError, LocalRuntime,
};
use crate::runtime::managed::{ResourceLimits, ResourceScope};
use crate::runtime::resource_domain::{
  DomainError, DomainResource, DomainResources, DomainSnapshot, ResourceDomain, TenantDomain,
};
use crate::runtime::{Config, Resources, Runtime, ShutdownMode, SubmitErrorKind};

const CONTROL_CEILING: usize = 1 << 20;

fn bound_resources() -> (ResourceDomain, TenantDomain, ResourceScope) {
  let ceiling = DomainResources::ZERO
    .with(DomainResource::Cpu, 4)
    .with(DomainResource::Memory, 16 * 1024)
    .with(DomainResource::Disk, 4)
    .with(DomainResource::Network, 4)
    .with(DomainResource::Tasks, 32)
    .with(DomainResource::Control, CONTROL_CEILING);
  let domain = ResourceDomain::with_waiters(ceiling, 1, 128)
    .unwrap_or_else(|error| panic!("resource domain setup failed: {error}"));
  let tenant = domain
    .tenant(ceiling)
    .unwrap_or_else(|error| panic!("tenant setup failed: {error}"));
  let resources = ResourceScope::from_tenant(
    ResourceLimits {
      managed_memory: 16 * 1024,
      disk_concurrent_ops: 4,
      network_concurrent_ops: 4,
    },
    tenant.clone(),
  );
  (domain, tenant, resources)
}

fn control_used(snapshot: DomainSnapshot) -> usize {
  snapshot.used.get(DomainResource::Control)
}

fn tenant_control_used(tenant: &TenantDomain) -> usize {
  tenant
    .snapshot()
    .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"))
    .used
    .get(DomainResource::Control)
}

fn close_control_admission(domain: &ResourceDomain, tenant: &TenantDomain) {
  let global = domain.snapshot();
  domain
    .set_limits(
      global
        .limit
        .with(DomainResource::Control, control_used(global)),
    )
    .unwrap_or_else(|error| panic!("global Control limit update failed: {error}"));
  let tenant_snapshot = tenant
    .snapshot()
    .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"));
  tenant
    .set_limits(
      tenant_snapshot
        .limit
        .with(DomainResource::Control, control_used(tenant_snapshot)),
    )
    .unwrap_or_else(|error| panic!("tenant Control limit update failed: {error}"));
}

fn wait_until(mut condition: impl FnMut() -> bool) {
  let deadline = Instant::now() + Duration::from_secs(3);
  while !condition() {
    assert!(
      Instant::now() < deadline,
      "runtime Control ownership did not drain"
    );
    thread::yield_now();
  }
}

struct TaggedFuture {
  value: usize,
  polls: Arc<AtomicUsize>,
  payload: [u8; 128],
}

impl Future for TaggedFuture {
  type Output = usize;

  fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    let _retained_payload = this.payload[0];
    this.polls.fetch_add(1, Ordering::SeqCst);
    Poll::Ready(this.value)
  }
}

struct RetainWaker(Arc<Mutex<Option<Waker>>>);

impl Future for RetainWaker {
  type Output = usize;

  fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
    *self
      .0
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(context.waker().clone());
    Poll::Ready(41)
  }
}

struct ClampAndJoin<'a> {
  job: AsyncJob<usize>,
  domain: &'a ResourceDomain,
  tenant: &'a TenantDomain,
  clamped: bool,
}

impl Future for ClampAndJoin<'_> {
  type Output = Result<usize, AsyncJoinError>;

  fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if !this.clamped {
      close_control_admission(this.domain, this.tenant);
      this.clamped = true;
    }
    Pin::new(&mut this.job).poll(context)
  }
}

#[test]
fn async_control_exhaustion_precedes_name_callbacks_and_worker_start() {
  let (domain, tenant, resources) = bound_resources();
  close_control_admission(&domain, &tenant);
  let before = domain.snapshot();
  let tenant_before = tenant
    .snapshot()
    .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"));
  let names = Arc::new(AtomicUsize::new(0));
  let starts = Arc::new(AtomicUsize::new(0));
  let name_calls = Arc::clone(&names);
  let start_calls = Arc::clone(&starts);
  let options = AsyncThreadOptions::new()
    .thread_name_fn(move |_| {
      name_calls.fetch_add(1, Ordering::SeqCst);
      String::from("control-test")
    })
    .on_thread_start(move |_| {
      start_calls.fetch_add(1, Ordering::SeqCst);
    });

  let result = AsyncRuntime::with_resources_and_thread_options(
    AsyncConfig {
      workers: 1,
      max_outstanding: 2,
      max_scopes: 2,
    },
    resources,
    options,
  );
  assert_eq!(
    result.err(),
    Some(AsyncError::ResourceDomain(DomainError::Exhausted(
      DomainResource::Control
    )))
  );
  assert_eq!(names.load(Ordering::SeqCst), 0);
  assert_eq!(starts.load(Ordering::SeqCst), 0);
  assert_eq!(domain.snapshot(), before);
  assert_eq!(tenant.snapshot().unwrap(), tenant_before);
}

#[test]
fn async_control_rejection_returns_future_and_rolls_back_both_ledgers() {
  let (domain, tenant, resources) = bound_resources();
  let runtime = AsyncRuntime::with_resources(
    AsyncConfig {
      workers: 1,
      max_outstanding: 2,
      max_scopes: 2,
    },
    resources,
  )
  .unwrap_or_else(|error| panic!("async runtime setup failed: {error}"));
  let handle = runtime.handle();
  close_control_admission(&domain, &tenant);
  let before = domain.snapshot();
  let tenant_before = tenant
    .snapshot()
    .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"));
  let polls = Arc::new(AtomicUsize::new(0));
  let rejected = handle
    .spawn(TaggedFuture {
      value: 73,
      polls: Arc::clone(&polls),
      payload: [0xa5; 128],
    })
    .unwrap_err();
  assert_eq!(
    rejected.kind,
    AsyncError::ResourceDomain(DomainError::Exhausted(DomainResource::Control))
  );
  let returned = rejected.into_future();
  assert_eq!(returned.value, 73);
  assert_eq!(returned.payload[0], 0xa5);
  assert_eq!(polls.load(Ordering::SeqCst), 0);
  assert_eq!(domain.snapshot(), before);
  assert_eq!(tenant.snapshot().unwrap(), tenant_before);

  drop(returned);
  runtime
    .shutdown(AsyncShutdown::CancelPending)
    .unwrap_or_else(|error| panic!("async runtime shutdown failed: {error}"));
}

#[test]
fn async_task_waker_control_failure_finishes_without_polling_future() {
  let (domain, tenant, resources) = bound_resources();
  let (entered_tx, entered_rx) = mpsc::sync_channel(1);
  let (release_tx, release_rx) = mpsc::sync_channel(1);
  let release_rx = Arc::new(Mutex::new(release_rx));
  let hook_release_rx = Arc::clone(&release_rx);
  let options = AsyncThreadOptions::new().on_thread_start(move |_| {
    entered_tx.send(()).unwrap();
    hook_release_rx
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .recv()
      .unwrap();
  });
  let runtime = AsyncRuntime::with_resources_and_thread_options(
    AsyncConfig {
      workers: 1,
      max_outstanding: 2,
      max_scopes: 2,
    },
    resources,
    options,
  )
  .unwrap_or_else(|error| panic!("async runtime setup failed: {error}"));
  entered_rx
    .recv_timeout(Duration::from_secs(2))
    .unwrap_or_else(|error| panic!("worker did not reach its gate: {error}"));
  let handle = runtime.handle();
  let polls = Arc::new(AtomicUsize::new(0));
  let job = handle
    .spawn(TaggedFuture {
      value: 19,
      polls: Arc::clone(&polls),
      payload: [0x6d; 128],
    })
    .unwrap_or_else(|error| panic!("task admission failed: {}", error.kind));
  close_control_admission(&domain, &tenant);
  release_tx
    .send(())
    .unwrap_or_else(|error| panic!("worker release failed: {error}"));

  let mut job = Box::pin(job);
  let mut context = Context::from_waker(Waker::noop());
  let deadline = Instant::now() + Duration::from_secs(2);
  let outcome = loop {
    if let Poll::Ready(outcome) = job.as_mut().poll(&mut context) {
      break outcome;
    }
    assert!(
      Instant::now() < deadline,
      "async task did not publish a result"
    );
    thread::yield_now();
  };
  assert!(matches!(
    outcome,
    Err(
      crate::runtime::asynchronous::AsyncJoinError::ResourceDomain(DomainError::Exhausted(
        DomainResource::Control
      ))
    )
  ));
  assert_eq!(polls.load(Ordering::SeqCst), 0);
  assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 0);
  drop(job);
  runtime
    .shutdown(AsyncShutdown::CancelPending)
    .unwrap_or_else(|error| panic!("async runtime shutdown failed: {error}"));
}

#[test]
fn async_abort_metrics_and_child_scope_keep_control_until_final_owner_drop() {
  let (domain, tenant, resources) = bound_resources();
  let domain_baseline = control_used(domain.snapshot());
  let runtime = AsyncRuntime::with_resources(
    AsyncConfig {
      workers: 1,
      max_outstanding: 2,
      max_scopes: 2,
    },
    resources.clone(),
  )
  .unwrap_or_else(|error| panic!("async runtime setup failed: {error}"));
  let metrics = runtime.metrics();
  let handle = runtime.handle();
  let saved_waker = Arc::new(Mutex::new(None));
  let task = handle
    .spawn(RetainWaker(Arc::clone(&saved_waker)))
    .unwrap_or_else(|error| panic!("task admission failed: {}", error.kind));
  let abort = task.abort_handle();
  assert_eq!(
    handle
      .block_on(task)
      .unwrap_or_else(|error| panic!("root block_on failed: {error}"))
      .unwrap_or_else(|error| panic!("task failed: {error}")),
    41
  );
  assert!(abort.is_finished());
  wait_until(|| metrics.num_alive_tasks() == 0);
  assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 0);

  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("async runtime shutdown failed: {error}"));
  let retained_with_abort = control_used(domain.snapshot());
  assert!(retained_with_abort > domain_baseline);
  drop(abort);
  wait_until(|| control_used(domain.snapshot()) < retained_with_abort);

  let retained_with_metrics = control_used(domain.snapshot());
  drop(handle);
  wait_until(|| control_used(domain.snapshot()) < retained_with_metrics);
  assert!(control_used(domain.snapshot()) > domain_baseline);
  drop(metrics);
  let retained_by_waker = control_used(domain.snapshot());
  assert!(retained_by_waker > domain_baseline);
  let retained_waker = saved_waker
    .lock()
    .unwrap_or_else(std::sync::PoisonError::into_inner)
    .take();
  drop(retained_waker);
  wait_until(|| control_used(domain.snapshot()) == domain_baseline);

  // A closed child scope leaves its Control owner with the last public handle.
  let runtime = AsyncRuntime::with_resources(
    AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 2,
    },
    resources,
  )
  .unwrap_or_else(|error| panic!("async runtime setup failed: {error}"));
  let root = runtime.handle();
  let before_scope = control_used(domain.snapshot());
  let tenant_before_scope = tenant_control_used(&tenant);
  let scope = runtime
    .scope()
    .unwrap_or_else(|error| panic!("scope creation failed: {error}"));
  let child_handle = scope.handle();
  assert!(control_used(domain.snapshot()) > before_scope);
  root
    .block_on(scope.close())
    .unwrap_or_else(|error| panic!("scope close failed: {error}"));
  assert!(control_used(domain.snapshot()) > before_scope);
  assert!(tenant_control_used(&tenant) > tenant_before_scope);
  drop(child_handle);
  wait_until(|| control_used(domain.snapshot()) == before_scope);
  assert_eq!(tenant_control_used(&tenant), tenant_before_scope);
  runtime
    .shutdown(AsyncShutdown::CancelPending)
    .unwrap_or_else(|error| panic!("async runtime shutdown failed: {error}"));
}

#[test]
fn local_control_rejection_preserves_future_and_scope_handle_owns_control() {
  let (domain, tenant, resources) = bound_resources();
  close_control_admission(&domain, &tenant);
  let before = domain.snapshot();
  let tenant_before = tenant
    .snapshot()
    .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"));
  let build_error = LocalRuntime::with_resources(
    LocalConfig {
      max_outstanding: 2,
      max_scopes: 2,
    },
    resources,
  )
  .err()
  .unwrap_or_else(|| panic!("local Control exhaustion was ignored"));
  assert_eq!(
    build_error,
    LocalError::ResourceDomain(DomainError::Exhausted(DomainResource::Control))
  );
  assert_eq!(domain.snapshot(), before);
  assert_eq!(tenant.snapshot().unwrap(), tenant_before);

  let (domain, tenant, resources) = bound_resources();
  let runtime = LocalRuntime::with_resources(
    LocalConfig {
      max_outstanding: 2,
      max_scopes: 2,
    },
    resources,
  )
  .unwrap_or_else(|error| panic!("local runtime setup failed: {error}"));
  let handle = runtime.handle();
  close_control_admission(&domain, &tenant);
  let before = domain.snapshot();
  let tenant_before = tenant
    .snapshot()
    .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"));
  let polls = Arc::new(AtomicUsize::new(0));
  let rejected = handle
    .spawn_local(TaggedFuture {
      value: 29,
      polls: Arc::clone(&polls),
      payload: [0x3c; 128],
    })
    .unwrap_err();
  assert_eq!(
    rejected.kind,
    LocalError::ResourceDomain(DomainError::Exhausted(DomainResource::Control))
  );
  let returned = rejected.into_future();
  assert_eq!(returned.value, 29);
  assert_eq!(returned.payload[0], 0x3c);
  assert_eq!(polls.load(Ordering::SeqCst), 0);
  assert_eq!(domain.snapshot(), before);
  assert_eq!(tenant.snapshot().unwrap(), tenant_before);
  drop(returned);
  drop(handle);
  drop(runtime);

  let (domain, _tenant, resources) = bound_resources();
  let runtime = LocalRuntime::with_resources(
    LocalConfig {
      max_outstanding: 1,
      max_scopes: 2,
    },
    resources,
  )
  .unwrap_or_else(|error| panic!("local runtime setup failed: {error}"));
  let before_scope = control_used(domain.snapshot());
  let scope = runtime
    .scope()
    .unwrap_or_else(|error| panic!("local scope creation failed: {error}"));
  let child_handle = scope.handle();
  assert!(control_used(domain.snapshot()) > before_scope);
  drop(scope.close());
  assert!(control_used(domain.snapshot()) > before_scope);
  drop(child_handle);
  assert_eq!(control_used(domain.snapshot()), before_scope);

  let (domain, tenant, resources) = bound_resources();
  let mut runtime = LocalRuntime::with_resources(
    LocalConfig {
      max_outstanding: 2,
      max_scopes: 2,
    },
    resources,
  )
  .unwrap_or_else(|error| panic!("local runtime setup failed: {error}"));
  let handle = runtime.handle();
  let polls = Arc::new(AtomicUsize::new(0));
  let job = handle
    .spawn_local(TaggedFuture {
      value: 11,
      polls: Arc::clone(&polls),
      payload: [0xc7; 128],
    })
    .unwrap_or_else(|error| panic!("local task admission failed: {}", error.kind));
  let root = ClampAndJoin {
    job,
    domain: &domain,
    tenant: &tenant,
    clamped: false,
  };
  assert!(matches!(
    runtime
      .block_on(root)
      .unwrap_or_else(|error| panic!("local block_on failed: {error}")),
    Err(AsyncJoinError::ResourceDomain(DomainError::Exhausted(
      DomainResource::Control
    )))
  ));
  assert_eq!(polls.load(Ordering::SeqCst), 0);
  assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 0);

  let (domain, _tenant, resources) = bound_resources();
  let domain_baseline = control_used(domain.snapshot());
  let mut runtime = LocalRuntime::with_resources(
    LocalConfig {
      max_outstanding: 1,
      max_scopes: 1,
    },
    resources,
  )
  .unwrap_or_else(|error| panic!("local runtime setup failed: {error}"));
  let saved_root_waker = Arc::new(Mutex::new(None));
  assert_eq!(
    runtime
      .block_on(RetainWaker(Arc::clone(&saved_root_waker)))
      .unwrap_or_else(|error| panic!("local root poll failed: {error}")),
    41
  );
  drop(runtime);
  let retained_by_waker = control_used(domain.snapshot());
  assert!(retained_by_waker > domain_baseline);
  let retained_root_waker = saved_root_waker
    .lock()
    .unwrap_or_else(std::sync::PoisonError::into_inner)
    .take();
  drop(retained_root_waker);
  wait_until(|| control_used(domain.snapshot()) < retained_by_waker);
  assert_eq!(control_used(domain.snapshot()), domain_baseline);
}

#[test]
fn blocking_control_exhaustion_is_typed_and_keeps_the_original_closure() {
  struct DropMark(Arc<AtomicUsize>);

  impl Drop for DropMark {
    fn drop(&mut self) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  let (domain, tenant, resources) = bound_resources();
  let runtime = Runtime::with_resources(
    Config {
      workers: 1,
      max_outstanding: 2,
      capacity: Resources::ZERO,
    },
    resources,
  )
  .unwrap_or_else(|error| panic!("blocking runtime setup failed: {error}"));
  let handle = runtime.handle();
  close_control_admission(&domain, &tenant);
  let before = domain.snapshot();
  let ran = Arc::new(AtomicBool::new(false));
  let drops = Arc::new(AtomicUsize::new(0));
  let run_flag = Arc::clone(&ran);
  let marker = DropMark(Arc::clone(&drops));
  let rejected = runtime
    .try_spawn(Resources::ZERO, move |_| {
      run_flag.store(true, Ordering::SeqCst);
      drop(marker);
    })
    .unwrap_err();
  assert_eq!(
    rejected.kind,
    SubmitErrorKind::ResourceDomain(DomainError::Exhausted(DomainResource::Control))
  );
  assert_eq!(domain.snapshot(), before);
  assert!(!ran.load(Ordering::SeqCst));
  assert_eq!(drops.load(Ordering::SeqCst), 0);
  let closure = rejected.into_job();
  assert!(!ran.load(Ordering::SeqCst));
  assert_eq!(drops.load(Ordering::SeqCst), 0);
  drop(closure);
  assert_eq!(drops.load(Ordering::SeqCst), 1);

  drop(handle);
  drop(runtime);
}

#[test]
fn blocking_job_result_and_handle_control_last_until_job_drop() {
  let (domain, _tenant, resources) = bound_resources();
  let mut runtime = Runtime::with_resources(
    Config {
      workers: 1,
      max_outstanding: 2,
      capacity: Resources::ZERO,
    },
    resources,
  )
  .unwrap_or_else(|error| panic!("blocking runtime setup failed: {error}"));
  let base = control_used(domain.snapshot());
  let job = runtime
    .try_spawn(Resources::ZERO, |_| [0x5a; 256])
    .unwrap_or_else(|error| panic!("job admission failed: {}", error.kind));
  wait_until(|| job.is_finished());
  assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 0);
  assert!(control_used(domain.snapshot()) > base);
  assert_eq!(
    job
      .join()
      .unwrap_or_else(|error| panic!("job failed: {error}"))[0],
    0x5a
  );
  let retained = control_used(domain.snapshot());
  assert!(retained > base);
  drop(job);
  wait_until(|| control_used(domain.snapshot()) < retained);
  runtime
    .shutdown(ShutdownMode::Drain)
    .unwrap_or_else(|error| panic!("blocking shutdown failed: {error}"));
}

#[test]
fn blocking_control_exhaustion_fails_before_worker_start() {
  let (domain, tenant, resources) = bound_resources();
  close_control_admission(&domain, &tenant);
  let before = domain.snapshot();
  let tenant_before = tenant
    .snapshot()
    .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"));
  let result = Runtime::with_resources(
    Config {
      workers: 2,
      max_outstanding: 2,
      capacity: Resources::ZERO,
    },
    resources,
  );
  let error = result
    .err()
    .unwrap_or_else(|| panic!("Control exhaustion was ignored"));
  assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
  assert_eq!(
    error
      .get_ref()
      .and_then(|cause| cause.downcast_ref::<DomainError>()),
    Some(&DomainError::Exhausted(DomainResource::Control))
  );
  assert_eq!(domain.snapshot(), before);
  assert_eq!(tenant.snapshot().unwrap(), tenant_before);
}
