use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use super::asynchronous::{
  AsyncConfig, AsyncError, AsyncRuntime, HandoffConfig, LocalConfig, LocalError, LocalRuntime,
};
use super::blocking::{Config as BlockingConfig, Runtime as BlockingRuntime};
use super::error::JoinError;
use super::managed::{ResourceLimits, ResourceScope};
use super::resource_domain::{DomainError, DomainResource, DomainResources, ResourceDomain};
use super::resources::Resources;

fn ceiling(cpu: usize, tasks: usize) -> DomainResources {
  DomainResources::ZERO
    .with(DomainResource::Cpu, cpu)
    .with(DomainResource::Tasks, tasks)
    .with(DomainResource::Control, 1 << 18)
}

fn resource_scope(tenant: super::resource_domain::TenantDomain) -> ResourceScope {
  ResourceScope::from_tenant(ResourceLimits::default(), tenant)
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
  let deadline = Instant::now() + Duration::from_secs(3);
  while !predicate() {
    assert!(
      Instant::now() < deadline,
      "runtime state did not make progress"
    );
    thread::sleep(Duration::from_millis(1));
  }
}

struct HoldPoll {
  entered: Option<Sender<()>>,
  release: Receiver<()>,
}

impl Future for HoldPoll {
  type Output = ();

  fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if let Some(entered) = this.entered.take() {
      entered.send(()).unwrap();
      this.release.recv().unwrap();
    }
    Poll::Ready(())
  }
}

struct CountPoll(Arc<AtomicUsize>);

impl Future for CountPoll {
  type Output = ();

  fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
    self.0.fetch_add(1, Ordering::SeqCst);
    Poll::Ready(())
  }
}

#[test]
fn async_task_admission_precedes_queue_publication_and_releases_after_cleanup() {
  let limits = ceiling(1, 1);
  let domain = ResourceDomain::with_waiters(limits, 1, 3).unwrap();
  let tenant = domain.tenant(limits).unwrap();
  let runtime = AsyncRuntime::with_resources(
    AsyncConfig {
      workers: 1,
      max_outstanding: 2,
      max_scopes: 1,
    },
    resource_scope(tenant),
  )
  .unwrap();
  let handle = runtime.handle();
  let (dropped_tx, dropped_rx) = mpsc::channel();
  let first = handle
    .spawn(PendingDrop {
      dropped: Some(dropped_tx),
    })
    .unwrap();
  let rejected = handle.spawn(async { 7usize }).unwrap_err();
  assert_eq!(
    rejected.kind,
    AsyncError::ResourceDomain(DomainError::Exhausted(DomainResource::Tasks))
  );
  drop(rejected.into_future());
  first.abort();
  dropped_rx.recv_timeout(Duration::from_secs(3)).unwrap();
  wait_until(|| domain.snapshot().used.get(DomainResource::Tasks) == 0);
  assert!(matches!(
    runtime.block_on(first).unwrap(),
    Err(super::asynchronous::AsyncJoinError::Cancelled)
  ));
  let (accepted_tx, accepted_rx) = mpsc::channel();
  let accepted = handle
    .spawn(async move {
      accepted_tx.send(9usize).unwrap();
    })
    .unwrap();
  assert_eq!(accepted_rx.recv_timeout(Duration::from_secs(3)).unwrap(), 9);
  drop(accepted);
  wait_until(|| domain.snapshot().used.get(DomainResource::Tasks) == 0);
}

struct PendingDrop {
  dropped: Option<Sender<()>>,
}

impl Future for PendingDrop {
  type Output = ();

  fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
    Poll::Pending
  }
}

impl Drop for PendingDrop {
  fn drop(&mut self) {
    if let Some(dropped) = self.dropped.take() {
      let _ = dropped.send(());
    }
  }
}

#[test]
fn borrowed_async_root_holds_cpu_while_its_future_is_being_polled() {
  let limits = ceiling(1, 3);
  let domain = ResourceDomain::with_waiters(limits, 1, 2).unwrap();
  let tenant = domain.tenant(limits).unwrap();
  let runtime = AsyncRuntime::with_resources(
    AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 1,
    },
    resource_scope(tenant),
  )
  .unwrap();
  let handle = runtime.handle();
  let (entered_tx, entered_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let root = thread::spawn(move || {
    handle.block_on(HoldPoll {
      entered: Some(entered_tx),
      release: release_rx,
    })
  });
  entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();

  let polls = Arc::new(AtomicUsize::new(0));
  let job = runtime
    .handle()
    .spawn(CountPoll(Arc::clone(&polls)))
    .unwrap();
  thread::sleep(Duration::from_millis(25));
  assert_eq!(polls.load(Ordering::SeqCst), 0);

  release_tx.send(()).unwrap();
  assert!(root.join().unwrap().is_ok());
  assert_eq!(runtime.block_on(job).unwrap().unwrap(), ());
  assert_eq!(polls.load(Ordering::SeqCst), 1);
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
}

#[test]
fn local_task_and_async_worker_share_cpu_tickets() {
  let limits = ceiling(1, 4);
  let domain = ResourceDomain::with_waiters(limits, 1, 4).unwrap();
  let tenant = domain.tenant(limits).unwrap();
  let resources = resource_scope(tenant);
  let async_runtime = AsyncRuntime::with_resources(
    AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 1,
    },
    resources.clone(),
  )
  .unwrap();
  let (entered_tx, entered_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let local_resources = resources.clone();
  let local = thread::spawn(move || {
    let mut runtime = LocalRuntime::with_resources(
      LocalConfig {
        max_outstanding: 1,
        max_scopes: 1,
      },
      local_resources,
    )
    .unwrap();
    let job = runtime
      .handle()
      .spawn_local(HoldPoll {
        entered: Some(entered_tx),
        release: release_rx,
      })
      .unwrap();
    runtime.block_on(job)
  });
  entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();

  let polls = Arc::new(AtomicUsize::new(0));
  let job = async_runtime
    .handle()
    .spawn(CountPoll(Arc::clone(&polls)))
    .unwrap();
  thread::sleep(Duration::from_millis(25));
  assert_eq!(polls.load(Ordering::SeqCst), 0);

  release_tx.send(()).unwrap();
  assert!(local.join().unwrap().unwrap().is_ok());
  assert!(async_runtime.block_on(job).unwrap().is_ok());
  assert_eq!(polls.load(Ordering::SeqCst), 1);
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
}

#[test]
fn blocking_cpu_wait_is_cancellable_without_running_the_queued_closure() {
  let limits = ceiling(1, 2);
  let domain = ResourceDomain::with_waiters(limits, 1, 2).unwrap();
  let tenant = domain.tenant(limits).unwrap();
  let runtime = BlockingRuntime::with_resources(
    BlockingConfig {
      workers: 2,
      max_outstanding: 2,
      capacity: Resources::ZERO,
    },
    resource_scope(tenant),
  )
  .unwrap();
  let (entered_tx, entered_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let first = runtime
    .try_spawn(Resources::ZERO, move |_| {
      entered_tx.send(()).unwrap();
      release_rx.recv().unwrap();
    })
    .unwrap();
  entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();

  let called = Arc::new(AtomicUsize::new(0));
  let closure_called = Arc::clone(&called);
  let second = runtime
    .try_spawn(Resources::ZERO, move |_| {
      closure_called.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap();
  wait_until(|| runtime.snapshot().running == 2);
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 1);
  second.cancel();
  assert!(matches!(second.join(), Err(JoinError::Cancelled)));
  assert_eq!(called.load(Ordering::SeqCst), 0);
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 1);
  assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 1);

  release_tx.send(()).unwrap();
  first.join().unwrap();
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
  assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 0);
}

#[test]
fn bound_runtime_startup_reserves_its_disjoint_waiter_share() {
  let limits = ceiling(1, 4);
  let domain = ResourceDomain::with_waiters(limits, 1, 2).unwrap();
  let tenant = domain.tenant(limits).unwrap();
  let error = AsyncRuntime::with_resources(
    AsyncConfig {
      workers: 1,
      max_outstanding: 2,
      max_scopes: 1,
    },
    resource_scope(tenant.clone()),
  )
  .unwrap_err();
  assert_eq!(error, AsyncError::ResourceDomain(DomainError::WaitersFull));
  let _left = tenant.reserve_waiters(1).unwrap();
  assert_eq!(
    tenant.reserve_waiters(2).unwrap_err(),
    DomainError::WaitersFull
  );
}

#[test]
fn async_child_scopes_inherit_the_domain_and_only_select_same_domain_tenants() {
  let global_limits = ceiling(1, 2);
  let tenant_limits = ceiling(1, 1);
  let domain = ResourceDomain::with_waiters(global_limits, 2, 3).unwrap();
  let root_tenant = domain.tenant(tenant_limits).unwrap();
  let child_tenant = domain.tenant(tenant_limits).unwrap();
  let other_limits = ceiling(1, 2);
  let other_domain = ResourceDomain::new(other_limits, 1).unwrap();
  let other_tenant = other_domain.tenant(other_limits).unwrap();
  let runtime = AsyncRuntime::with_resources(
    AsyncConfig {
      workers: 1,
      max_outstanding: 2,
      max_scopes: 3,
    },
    resource_scope(root_tenant),
  )
  .unwrap();
  let handle = runtime.handle();

  let unbound = runtime.scope_with_resources(&ResourceScope::new(ResourceLimits::default()));
  assert!(matches!(
    unbound,
    Err(AsyncError::ResourceDomain(DomainError::Invalid))
  ));
  let foreign = runtime.scope_with_resources(&resource_scope(other_tenant));
  assert!(matches!(
    foreign,
    Err(AsyncError::ResourceDomain(DomainError::Invalid))
  ));

  let inherited = runtime.scope().unwrap();
  let first = inherited
    .handle()
    .spawn(std::future::pending::<()>())
    .unwrap();
  assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 1);
  let root_rejected = handle.spawn(async {}).unwrap_err();
  assert_eq!(
    root_rejected.kind,
    AsyncError::ResourceDomain(DomainError::Exhausted(DomainResource::Tasks))
  );
  drop(root_rejected.into_future());

  let selected = runtime
    .scope_with_resources(&resource_scope(child_tenant))
    .unwrap();
  let second = selected
    .handle()
    .spawn(std::future::pending::<()>())
    .unwrap();
  assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 2);
  first.abort();
  second.abort();
  wait_until(|| domain.snapshot().used.get(DomainResource::Tasks) == 0);
  drop(inherited);
  drop(selected);
}

#[test]
fn local_child_scopes_cannot_detach_from_a_bound_domain() {
  let global_limits = ceiling(1, 2);
  let tenant_limits = ceiling(1, 1);
  let domain = ResourceDomain::with_waiters(global_limits, 2, 3).unwrap();
  let root_tenant = domain.tenant(tenant_limits).unwrap();
  let child_tenant = domain.tenant(tenant_limits).unwrap();
  let other_limits = ceiling(1, 1);
  let other_domain = ResourceDomain::new(other_limits, 1).unwrap();
  let other_tenant = other_domain.tenant(other_limits).unwrap();
  let runtime = LocalRuntime::with_resources(
    LocalConfig {
      max_outstanding: 2,
      max_scopes: 3,
    },
    resource_scope(root_tenant),
  )
  .unwrap();
  assert!(matches!(
    runtime.scope_with_resources(&ResourceScope::new(ResourceLimits::default())),
    Err(super::asynchronous::LocalError::ResourceDomain(
      DomainError::Invalid
    ))
  ));
  assert!(matches!(
    runtime.scope_with_resources(&resource_scope(other_tenant)),
    Err(super::asynchronous::LocalError::ResourceDomain(
      DomainError::Invalid
    ))
  ));

  let inherited = runtime.scope().unwrap();
  let first = inherited
    .handle()
    .spawn_local(std::future::pending::<()>())
    .unwrap();
  assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 1);
  let root_rejected = runtime
    .handle()
    .spawn_local(std::future::ready(()))
    .unwrap_err();
  assert_eq!(
    root_rejected.kind,
    super::asynchronous::LocalError::ResourceDomain(DomainError::Exhausted(DomainResource::Tasks))
  );
  drop(root_rejected.into_future());

  let selected = runtime
    .scope_with_resources(&resource_scope(child_tenant))
    .unwrap();
  let second = selected
    .handle()
    .spawn_local(std::future::pending::<()>())
    .unwrap();
  assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 2);
  first.abort();
  second.abort();
  drop(inherited);
  drop(selected);
  drop(runtime);
  assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 0);
}

#[test]
fn blocking_closure_reentrant_async_root_fails_fast_while_retaining_its_cpu_ticket() {
  let limits = ceiling(1, 2);
  let domain = ResourceDomain::with_waiters(limits, 1, 3).unwrap();
  let tenant = domain.tenant(limits).unwrap();
  let resources = resource_scope(tenant);
  let async_runtime = AsyncRuntime::with_resources(
    AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 1,
    },
    resources.clone(),
  )
  .unwrap();
  let async_handle = async_runtime.handle();
  let polls = Arc::new(AtomicUsize::new(0));
  let nested_polls = Arc::clone(&polls);
  let (finished_tx, finished_rx) = mpsc::channel();
  let mut blocking = BlockingRuntime::with_resources(
    BlockingConfig {
      workers: 1,
      max_outstanding: 1,
      capacity: Resources::ZERO,
    },
    resources,
  )
  .unwrap();
  let job = blocking
    .try_spawn(Resources::ZERO, move |_| {
      let result = async_handle.block_on(CountPoll(nested_polls));
      finished_tx.send(result).unwrap();
    })
    .unwrap();
  drop(job);

  assert_eq!(
    finished_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
    Err(AsyncError::ResourceDomain(DomainError::Exhausted(
      DomainResource::Cpu
    )))
  );
  assert_eq!(polls.load(Ordering::SeqCst), 0);
  wait_until(|| domain.snapshot().used.get(DomainResource::Tasks) == 0);
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
  blocking
    .shutdown(super::blocking::ShutdownMode::Drain)
    .unwrap();
}

#[test]
fn handed_off_original_thread_rejects_a_local_root_that_cannot_get_another_cpu_ticket() {
  let limits = ceiling(1, 2);
  let domain = ResourceDomain::with_waiters(limits, 1, 4).unwrap();
  let tenant = domain.tenant(limits).unwrap();
  let resources = resource_scope(tenant);
  let runtime = AsyncRuntime::with_resources_and_handoffs(
    AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 1,
    },
    HandoffConfig { max_handoffs: 1 },
    resources.clone(),
  )
  .unwrap();
  let polls = Arc::new(AtomicUsize::new(0));
  let nested_polls = Arc::clone(&polls);
  let (finished_tx, finished_rx) = mpsc::channel();
  let task = runtime
    .handle()
    .spawn(async move {
      let result = super::asynchronous::try_block_in_place(move || {
        let mut local = LocalRuntime::with_resources(
          LocalConfig {
            max_outstanding: 1,
            max_scopes: 1,
          },
          resources,
        )
        .unwrap();
        local.block_on(CountPoll(nested_polls))
      });
      let rejected = matches!(
        result,
        Ok(Err(LocalError::ResourceDomain(DomainError::Exhausted(
          DomainResource::Cpu
        ))))
      );
      finished_tx.send(rejected).unwrap();
    })
    .unwrap();
  drop(task);

  assert!(finished_rx.recv_timeout(Duration::from_secs(3)).unwrap());
  assert_eq!(polls.load(Ordering::SeqCst), 0);
  wait_until(|| domain.snapshot().used.get(DomainResource::Tasks) == 0);
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
  runtime
    .shutdown(super::asynchronous::AsyncShutdown::Drain)
    .unwrap();
}

#[test]
fn blocking_join_across_pools_sharing_cpu_fails_fast_and_preserves_the_job() {
  let limits = ceiling(1, 8);
  let domain = ResourceDomain::with_waiters(limits, 1, 2).unwrap();
  let tenant = domain.tenant(limits).unwrap();
  let resources = resource_scope(tenant);
  let mut first = BlockingRuntime::with_resources(
    BlockingConfig {
      workers: 1,
      max_outstanding: 1,
      capacity: Resources::ZERO,
    },
    resources.clone(),
  )
  .unwrap();
  let second = BlockingRuntime::with_resources(
    BlockingConfig {
      workers: 1,
      max_outstanding: 1,
      capacity: Resources::ZERO,
    },
    resources,
  )
  .unwrap();
  let second_handle = second.handle();
  let ran = Arc::new(AtomicBool::new(false));
  let first_ran = Arc::clone(&ran);
  let (submitted_tx, submitted_rx) = mpsc::channel();
  let (join_now_tx, join_now_rx) = mpsc::channel();
  let (joined_tx, joined_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let a_job = first
    .try_spawn(Resources::ZERO, move |_| {
      let b_ran = Arc::clone(&first_ran);
      let b_job = second_handle
        .try_spawn(Resources::ZERO, move |_| {
          b_ran.store(true, Ordering::SeqCst);
        })
        .unwrap();
      submitted_tx.send(()).unwrap();
      join_now_rx.recv_timeout(Duration::from_secs(3)).unwrap();
      let joined = b_job.join();
      joined_tx.send((joined, b_job)).unwrap();
      release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    })
    .unwrap();

  submitted_rx.recv_timeout(Duration::from_secs(3)).unwrap();
  wait_until(|| second.snapshot().running == 1);
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 1);
  assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 2);
  join_now_tx.send(()).unwrap();

  let (joined, b_job) = joined_rx.recv_timeout(Duration::from_secs(3)).unwrap();
  assert!(matches!(joined, Err(JoinError::WouldDeadlock)));
  assert!(!b_job.is_finished());
  assert!(!ran.load(Ordering::SeqCst));
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 1);

  release_tx.send(()).unwrap();
  a_job.join().unwrap();
  b_job.join().unwrap();
  assert!(ran.load(Ordering::SeqCst));
  wait_until(|| domain.snapshot().used.get(DomainResource::Tasks) == 0);
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);

  let ready_job = second.try_spawn(Resources::ZERO, move |_| 42usize).unwrap();
  wait_until(|| ready_job.is_finished());
  let (ready_tx, ready_rx) = mpsc::channel();
  let join_ready = first
    .try_spawn(Resources::ZERO, move |_| {
      ready_tx.send(ready_job.join()).unwrap();
    })
    .unwrap();
  join_ready.join().unwrap();
  assert!(matches!(
    ready_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
    Ok(42)
  ));
  wait_until(|| domain.snapshot().used.get(DomainResource::Tasks) == 0);
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);

  first
    .shutdown(super::blocking::ShutdownMode::Drain)
    .unwrap();
  let mut second = second;
  second
    .shutdown(super::blocking::ShutdownMode::Drain)
    .unwrap();
}

#[test]
fn handed_off_blocking_join_detects_the_retained_original_cpu_ticket() {
  let limits = ceiling(1, 8);
  let domain = ResourceDomain::with_waiters(limits, 1, 3).unwrap();
  let tenant = domain.tenant(limits).unwrap();
  let resources = resource_scope(tenant);
  let async_runtime = AsyncRuntime::with_resources_and_handoffs(
    AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 1,
    },
    HandoffConfig { max_handoffs: 1 },
    resources.clone(),
  )
  .unwrap();
  let mut blocking = BlockingRuntime::with_resources(
    BlockingConfig {
      workers: 1,
      max_outstanding: 1,
      capacity: Resources::ZERO,
    },
    resources,
  )
  .unwrap();
  let blocking_handle = blocking.handle();
  let ran = Arc::new(AtomicBool::new(false));
  let task_ran = Arc::clone(&ran);
  let (submitted_tx, submitted_rx) = mpsc::channel();
  let (join_now_tx, join_now_rx) = mpsc::channel();
  let (joined_tx, joined_rx) = mpsc::channel();
  let (release_handoff_tx, release_handoff_rx) = mpsc::channel();
  let task = async_runtime
    .handle()
    .spawn(async move {
      let handoff = super::asynchronous::try_block_in_place(|| {
        let b_ran = Arc::clone(&task_ran);
        let b_job = blocking_handle
          .try_spawn(Resources::ZERO, move |_| {
            b_ran.store(true, Ordering::SeqCst);
          })
          .unwrap();
        submitted_tx.send(()).unwrap();
        join_now_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let joined = b_job.join();
        joined_tx.send((joined, b_job)).unwrap();
        release_handoff_rx
          .recv_timeout(Duration::from_secs(3))
          .unwrap();
      });
      assert!(handoff.is_ok());
    })
    .unwrap();
  let async_handle = async_runtime.handle();
  let (completed_tx, completed_rx) = mpsc::channel();
  let root = thread::spawn(move || {
    let completed = async_handle.block_on(task);
    let _ = completed_tx.send(completed);
  });

  submitted_rx.recv_timeout(Duration::from_secs(3)).unwrap();
  wait_until(|| blocking.snapshot().running == 1);
  join_now_tx.send(()).unwrap();
  let (joined, b_job) = joined_rx.recv_timeout(Duration::from_secs(3)).unwrap();
  assert!(matches!(joined, Err(JoinError::WouldDeadlock)));
  assert!(!b_job.is_finished());
  assert!(!ran.load(Ordering::SeqCst));
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 1);

  release_handoff_tx.send(()).unwrap();
  assert!(
    completed_rx
      .recv_timeout(Duration::from_secs(3))
      .unwrap()
      .unwrap()
      .is_ok()
  );
  root.join().unwrap();
  b_job.join().unwrap();
  assert!(ran.load(Ordering::SeqCst));
  wait_until(|| domain.snapshot().used.get(DomainResource::Tasks) == 0);
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
  blocking
    .shutdown(super::blocking::ShutdownMode::Drain)
    .unwrap();
  async_runtime
    .shutdown(super::asynchronous::AsyncShutdown::Drain)
    .unwrap();
}
