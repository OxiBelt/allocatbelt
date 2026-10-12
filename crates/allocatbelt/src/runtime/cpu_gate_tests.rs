use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

use super::{CpuGate, CpuGateInner, CpuGated, RunState, ThreadWake};
use crate::runtime::blocking::{Config, Runtime, ShutdownMode};
use crate::runtime::error::JoinError;
use crate::runtime::managed::{ResourceLimits, ResourceScope};
use crate::runtime::resource_domain::{
  DomainError, DomainResource, DomainResources, DomainWaitPool, ResourceDomain, TenantDomain,
};
use crate::runtime::resources::Resources;

const CONTROL: usize = 1 << 20;

fn domain(cpu: usize, waiter_slots: usize) -> (ResourceDomain, TenantDomain) {
  let ceiling = DomainResources::ZERO
    .with(DomainResource::Cpu, cpu)
    .with(DomainResource::Tasks, 16)
    .with(DomainResource::Control, CONTROL);
  let domain = ResourceDomain::with_waiters(ceiling, 2, waiter_slots)
    .unwrap_or_else(|error| panic!("resource domain setup failed: {error}"));
  let tenant = domain
    .tenant(ceiling)
    .unwrap_or_else(|error| panic!("tenant setup failed: {error}"));
  (domain, tenant)
}

fn cpu_ticket(tenant: &TenantDomain) -> crate::runtime::resource_domain::DomainReservation {
  tenant
    .try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 1))
    .unwrap_or_else(|error| panic!("CPU ticket acquisition failed: {error}"))
}

fn control(snapshot: crate::runtime::resource_domain::DomainSnapshot) -> usize {
  snapshot.used.get(DomainResource::Control)
}

fn tenant_control(tenant: &TenantDomain) -> usize {
  tenant
    .snapshot()
    .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"))
    .used
    .get(DomainResource::Control)
}

fn blocking_run_control_bytes<F>(_: &F) -> usize {
  std::mem::size_of::<RunState<F>>() + std::mem::size_of::<ThreadWake>()
}

struct CountingWake {
  wakes: Arc<AtomicUsize>,
  drops: Option<Arc<AtomicUsize>>,
}

impl Wake for CountingWake {
  fn wake(self: Arc<Self>) {
    self.wakes.fetch_add(1, Ordering::SeqCst);
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.wakes.fetch_add(1, Ordering::SeqCst);
  }
}

impl Drop for CountingWake {
  fn drop(&mut self) {
    if let Some(drops) = &self.drops {
      drops.fetch_add(1, Ordering::SeqCst);
    }
  }
}

struct ReentrantRunDropWake {
  gate: CpuGate,
  domain: ResourceDomain,
  wakes: Arc<AtomicUsize>,
  started: mpsc::SyncSender<()>,
  result: mpsc::SyncSender<(usize, DomainError)>,
}

impl Wake for ReentrantRunDropWake {
  fn wake(self: Arc<Self>) {
    self.wakes.fetch_add(1, Ordering::SeqCst);
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.wakes.fetch_add(1, Ordering::SeqCst);
  }
}

impl Drop for ReentrantRunDropWake {
  fn drop(&mut self) {
    let _ = self.started.send(());
    let cpu_used = self.domain.snapshot().used.get(DomainResource::Cpu);
    let kind = match self.gate.run(|| ()) {
      Ok(()) => DomainError::Invalid,
      Err(error) => error.kind,
    };
    let _ = self.result.send((cpu_used, kind));
  }
}

fn counting_waker(drops: Option<Arc<AtomicUsize>>) -> (Waker, Arc<AtomicUsize>, Arc<CountingWake>) {
  let wakes = Arc::new(AtomicUsize::new(0));
  let wake = Arc::new(CountingWake {
    wakes: Arc::clone(&wakes),
    drops,
  });
  (Waker::from(Arc::clone(&wake)), wakes, wake)
}

fn context(waker: &Waker) -> Context<'_> {
  Context::from_waker(waker)
}

fn wait_until(mut condition: impl FnMut() -> bool, description: &str) {
  let deadline = Instant::now() + Duration::from_secs(3);
  while !condition() {
    assert!(
      Instant::now() < deadline,
      "timed out waiting for {description}"
    );
    thread::yield_now();
  }
}

#[test]
fn gate_and_future_control_charges_match_declared_payload_and_last_clone() {
  let (domain, tenant) = domain(1, 4);
  let domain_before = control(domain.snapshot());
  let tenant_before = tenant_control(&tenant);
  let gate = CpuGate::new(tenant.clone(), 2)
    .unwrap_or_else(|error| panic!("CPU gate setup failed: {error}"));
  let gate_bytes = std::mem::size_of::<CpuGateInner>() + DomainWaitPool::control_payload_bytes();
  assert_eq!(control(domain.snapshot()) - domain_before, gate_bytes);
  assert_eq!(tenant_control(&tenant) - tenant_before, gate_bytes);

  let clone = gate.clone();
  drop(gate);
  assert_eq!(control(domain.snapshot()) - domain_before, gate_bytes);
  assert_eq!(tenant_control(&tenant) - tenant_before, gate_bytes);

  type ReadyUnit = std::future::Ready<()>;
  let wrapper = clone
    .wrap(std::future::ready(()))
    .unwrap_or_else(|error| panic!("future wrapping failed: {error}"));
  let future_bytes = std::mem::size_of::<CpuGated<ReadyUnit>>() + std::mem::size_of::<ReadyUnit>();
  assert_eq!(
    control(domain.snapshot()) - domain_before,
    gate_bytes + future_bytes
  );
  assert_eq!(
    tenant_control(&tenant) - tenant_before,
    gate_bytes + future_bytes
  );
  drop(wrapper);
  assert_eq!(control(domain.snapshot()) - domain_before, gate_bytes);
  drop(clone);
  assert_eq!(control(domain.snapshot()), domain_before);
  assert_eq!(tenant_control(&tenant), tenant_before);
}

#[test]
fn async_waiter_registers_real_waker_and_resumes_after_shared_cpu_release() {
  let (domain, tenant) = domain(1, 4);
  let gate = CpuGate::new(tenant.clone(), 2)
    .unwrap_or_else(|error| panic!("CPU gate setup failed: {error}"));
  type ReadyInt = std::future::Ready<i32>;
  let control_before = control(domain.snapshot());
  let ticket = cpu_ticket(&tenant);
  let mut future = Box::pin(
    gate
      .wrap(std::future::ready(19))
      .unwrap_or_else(|error| panic!("future wrapping failed: {error}")),
  );
  let full_control = std::mem::size_of::<CpuGated<ReadyInt>>() + std::mem::size_of::<ReadyInt>();
  assert_eq!(control(domain.snapshot()) - control_before, full_control);
  let (waker, wakes, _wake) = counting_waker(None);
  let mut context = context(&waker);
  assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 1);
  assert_eq!(wakes.load(Ordering::SeqCst), 0);

  drop(ticket);
  assert!(wakes.load(Ordering::SeqCst) > 0);
  assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(Ok(19)));
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
  assert_eq!(
    control(domain.snapshot()) - control_before,
    std::mem::size_of::<CpuGated<ReadyInt>>()
  );
  drop(future);
  assert_eq!(control(domain.snapshot()), control_before);
}

#[test]
fn cpu_reservation_marks_identity_before_dropping_the_stored_waker() {
  let (domain, tenant) = domain(2, 6);
  let initial_global = domain.snapshot();
  domain
    .set_limits(initial_global.limit.with(DomainResource::Cpu, 1))
    .unwrap_or_else(|error| panic!("global CPU limit update failed: {error}"));
  let initial_tenant = tenant
    .snapshot()
    .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"));
  tenant
    .set_limits(initial_tenant.limit.with(DomainResource::Cpu, 1))
    .unwrap_or_else(|error| panic!("tenant CPU limit update failed: {error}"));
  let other_tenant = domain
    .tenant(initial_tenant.ceiling)
    .unwrap_or_else(|error| panic!("second tenant setup failed: {error}"));
  let other_snapshot = other_tenant
    .snapshot()
    .unwrap_or_else(|error| panic!("second tenant snapshot failed: {error}"));
  other_tenant
    .set_limits(other_snapshot.limit.with(DomainResource::Cpu, 0))
    .unwrap_or_else(|error| panic!("second tenant CPU limit update failed: {error}"));
  let gate = CpuGate::new(tenant.clone(), 3)
    .unwrap_or_else(|error| panic!("CPU gate setup failed: {error}"));
  let future = gate
    .wrap(std::future::ready(7))
    .unwrap_or_else(|error| panic!("future wrapping failed: {error}"));
  let waiter = future
    .waiter
    .as_ref()
    .unwrap_or_else(|| panic!("future did not retain its waiter lease"));
  let (started_tx, started_rx) = mpsc::sync_channel(1);
  let (result_tx, result_rx) = mpsc::sync_channel(1);
  let wake_count = Arc::new(AtomicUsize::new(0));
  {
    let wake = Arc::new(ReentrantRunDropWake {
      gate: gate.clone(),
      domain: domain.clone(),
      wakes: Arc::clone(&wake_count),
      started: started_tx,
      result: result_tx,
    });
    let waker = Waker::from(Arc::clone(&wake));
    assert!(
      waiter
        .try_acquire_or_register(&other_tenant, &waker)
        .unwrap_or_else(|error| panic!("waiter registration failed: {error}"))
        .is_none()
    );
  }

  // Make the stored Waker ineligible for domain wake selection, while this
  // gate tenant still has an available CPU unit. Its next poll therefore
  // reserves CPU and drops that prior Waker in try_acquire_or_register.
  let (poll_tx, poll_rx) = mpsc::sync_channel(1);
  let poller = thread::spawn(move || {
    let mut future = Box::pin(future);
    let mut context = context(Waker::noop());
    poll_tx.send(future.as_mut().poll(&mut context))
  });
  started_rx
    .recv_timeout(Duration::from_secs(2))
    .unwrap_or_else(|error| panic!("stored waker Drop did not reenter: {error}"));

  let (cpu_used_during_waker_drop, reentrant) =
    match result_rx.recv_timeout(Duration::from_millis(500)) {
      Ok(result) => result,
      Err(mpsc::RecvTimeoutError::Timeout) => {
        // Watchdog escape for a regression: if run parks behind the ticket
        // reserved by the outer poll, raise the soft limits so that it can
        // finish and the test reports the unexpected success instead of hang.
        let current = domain.snapshot();
        domain
          .set_limits(current.limit.with(DomainResource::Cpu, 2))
          .unwrap_or_else(|error| panic!("watchdog global CPU update failed: {error}"));
        let current_tenant = tenant
          .snapshot()
          .unwrap_or_else(|error| panic!("watchdog tenant snapshot failed: {error}"));
        tenant
          .set_limits(current_tenant.limit.with(DomainResource::Cpu, 2))
          .unwrap_or_else(|error| panic!("watchdog tenant CPU update failed: {error}"));
        result_rx
          .recv_timeout(Duration::from_secs(2))
          .unwrap_or_else(|error| panic!("reentrant run did not leave its wait: {error}"))
      }
      Err(error) => panic!("reentrant waker result channel failed: {error}"),
    };
  assert_eq!(cpu_used_during_waker_drop, 1);
  assert_eq!(wake_count.load(Ordering::SeqCst), 0);
  assert_eq!(reentrant, DomainError::Exhausted(DomainResource::Cpu));
  assert_eq!(
    poll_rx
      .recv_timeout(Duration::from_secs(2))
      .unwrap_or_else(|error| panic!("outer CPU gate poll did not complete: {error}")),
    Poll::Ready(Ok(7))
  );
  poller
    .join()
    .unwrap_or_else(|_| panic!("outer CPU gate poller panicked"))
    .unwrap_or_else(|error| panic!("outer CPU gate poll result was abandoned: {error}"));
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
}

#[test]
fn dropping_a_pending_future_clears_its_waker_and_releases_its_waiter_slot() {
  let (_domain, tenant) = domain(1, 1);
  let gate = CpuGate::new(tenant.clone(), 1)
    .unwrap_or_else(|error| panic!("CPU gate setup failed: {error}"));
  let ticket = cpu_ticket(&tenant);
  let drops = Arc::new(AtomicUsize::new(0));
  let mut pending = Box::pin(
    gate
      .wrap(std::future::ready(1))
      .unwrap_or_else(|error| panic!("first waiter lease failed: {error}")),
  );
  let (waker, _, wake) = counting_waker(Some(Arc::clone(&drops)));
  let mut context = context(&waker);
  assert!(matches!(pending.as_mut().poll(&mut context), Poll::Pending));
  drop(pending);
  drop(waker);
  drop(wake);
  assert_eq!(drops.load(Ordering::SeqCst), 1);

  let second = gate.wrap(std::future::ready(2));
  assert!(
    second.is_ok(),
    "dropping a pending future must release its slot"
  );
  drop(second);
  drop(ticket);
}

#[test]
fn wrap_refusal_returns_the_unchanged_future_when_all_leases_are_used() {
  let (_domain, tenant) = domain(1, 2);
  let gate =
    CpuGate::new(tenant, 1).unwrap_or_else(|error| panic!("CPU gate setup failed: {error}"));
  let first = gate
    .wrap(std::future::pending::<usize>())
    .unwrap_or_else(|error| panic!("first waiter lease failed: {error}"));
  let rejected = gate
    .wrap(std::future::ready(73))
    .err()
    .unwrap_or_else(|| panic!("second waiter unexpectedly acquired a bounded lease"));
  assert_eq!(rejected.kind, DomainError::WaitersFull);
  let mut original = Box::pin(rejected.into_future());
  let waker = Waker::noop();
  let mut context = context(waker);
  assert_eq!(original.as_mut().poll(&mut context), Poll::Ready(73));
  drop(first);
}

struct NestedTryRun {
  gate: CpuGate,
}

impl Future for NestedTryRun {
  type Output = bool;

  fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
    let result = self.gate.try_run(|| 1_usize);
    Poll::Ready(matches!(
      result,
      Err(error) if error.kind == DomainError::Exhausted(DomainResource::Cpu)
    ))
  }
}

#[test]
fn async_inner_poll_carries_domain_execution_identity_and_releases_per_poll() {
  let (domain, tenant) = domain(1, 4);
  let gate =
    CpuGate::new(tenant, 3).unwrap_or_else(|error| panic!("CPU gate setup failed: {error}"));
  let mut future = Box::pin(
    gate
      .wrap(NestedTryRun { gate: gate.clone() })
      .unwrap_or_else(|error| panic!("future wrapping failed: {error}")),
  );
  let mut context = context(Waker::noop());
  assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(Ok(true)));
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
}

struct PollTwice {
  domain: ResourceDomain,
  polls: usize,
}

impl Future for PollTwice {
  type Output = usize;

  fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.as_mut().get_mut();
    this.polls += 1;
    assert_eq!(this.domain.snapshot().used.get(DomainResource::Cpu), 1);
    if this.polls == 1 {
      context.waker().wake_by_ref();
      Poll::Pending
    } else {
      Poll::Ready(this.polls)
    }
  }
}

#[test]
fn inner_pending_poll_releases_cpu_ticket_before_next_poll() {
  let (domain, tenant) = domain(1, 2);
  let gate =
    CpuGate::new(tenant, 1).unwrap_or_else(|error| panic!("CPU gate setup failed: {error}"));
  let mut future = Box::pin(
    gate
      .wrap(PollTwice {
        domain: domain.clone(),
        polls: 0,
      })
      .unwrap_or_else(|error| panic!("future wrapping failed: {error}")),
  );
  let (waker, wakes, _wake) = counting_waker(None);
  let mut context = context(&waker);
  assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
  assert_eq!(wakes.load(Ordering::SeqCst), 1);
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
  assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(Ok(2)));
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
}

#[test]
fn blocking_and_async_paths_share_cpu_admission_and_real_wakeups() {
  let (domain, tenant) = domain(1, 4);
  let gate = CpuGate::new(tenant.clone(), 2)
    .unwrap_or_else(|error| panic!("CPU gate setup failed: {error}"));
  let (entered_tx, entered_rx) = mpsc::sync_channel(1);
  let (release_tx, release_rx) = mpsc::channel();
  let blocking_gate = gate.clone();
  let blocker = thread::spawn(move || {
    blocking_gate.run(move || {
      let _ = entered_tx.send(());
      let _ = release_rx.recv_timeout(Duration::from_secs(3));
      41
    })
  });
  entered_rx
    .recv_timeout(Duration::from_secs(2))
    .unwrap_or_else(|error| panic!("blocking closure did not acquire CPU: {error}"));
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 1);

  let mut future = Box::pin(
    gate
      .wrap(std::future::ready(73))
      .unwrap_or_else(|error| panic!("future wrapping failed: {error}")),
  );
  let (waker, wakes, _wake) = counting_waker(None);
  let mut context = context(&waker);
  assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
  assert_eq!(wakes.load(Ordering::SeqCst), 0);

  release_tx
    .send(())
    .unwrap_or_else(|error| panic!("blocking closure release failed: {error}"));
  assert_eq!(
    blocker
      .join()
      .unwrap_or_else(|_| panic!("blocking gate worker panicked"))
      .unwrap_or_else(|error| panic!("blocking gate admission failed: {error}")),
    41
  );
  assert!(wakes.load(Ordering::SeqCst) > 0);
  assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(Ok(73)));
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
}

#[test]
fn blocking_run_parks_then_resumes_and_nested_same_domain_run_fails_fast() {
  let (domain, tenant) = domain(1, 5);
  let gate = CpuGate::new(tenant.clone(), 3)
    .unwrap_or_else(|error| panic!("CPU gate setup failed: {error}"));
  let ticket = cpu_ticket(&tenant);
  let waiting_gate = gate.clone();
  let (entered_tx, entered_rx) = mpsc::sync_channel(1);
  let worker = thread::spawn(move || {
    waiting_gate
      .run(|| entered_tx.send(()))
      .map_err(|error| error.kind)
  });
  thread::sleep(Duration::from_millis(20));
  assert!(entered_rx.try_recv().is_err());
  drop(ticket);
  entered_rx
    .recv_timeout(Duration::from_secs(2))
    .unwrap_or_else(|error| panic!("parked blocking closure did not resume: {error}"));
  assert!(
    worker
      .join()
      .unwrap_or_else(|_| panic!("blocking gate waiter panicked"))
      .is_ok()
  );

  let nested_gate = gate.clone();
  let nested = gate
    .run(move || nested_gate.run(|| 11_usize))
    .unwrap_or_else(|error| panic!("outer blocking admission failed: {error}"));
  let error = match nested {
    Ok(_) => panic!("nested run unexpectedly executed"),
    Err(error) => error,
  };
  assert_eq!(error.kind, DomainError::Exhausted(DomainResource::Cpu));
  assert_eq!(error.into_function()(), 11);
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
}

#[test]
fn gated_cpu_execution_makes_cross_runtime_job_join_fail_fast() {
  let (domain, tenant) = domain(1, 6);
  let gate = CpuGate::new(tenant.clone(), 2)
    .unwrap_or_else(|error| panic!("CPU gate setup failed: {error}"));
  let resources = ResourceScope::from_tenant(ResourceLimits::default(), tenant);
  let mut runtime = Runtime::with_resources(
    Config {
      workers: 1,
      max_outstanding: 2,
      capacity: Resources {
        cpu: 1,
        ..Resources::ZERO
      },
    },
    resources,
  )
  .unwrap_or_else(|error| panic!("blocking runtime setup failed: {error}"));
  let job = runtime
    .try_spawn(
      Resources {
        cpu: 1,
        ..Resources::ZERO
      },
      |_| 29,
    )
    .unwrap_or_else(|error| panic!("blocking task admission failed: {}", error.kind));

  let joined = gate
    .run(|| {
      wait_until(|| runtime.snapshot().running == 1, "blocking job CPU wait");
      matches!(job.join(), Err(JoinError::WouldDeadlock))
    })
    .unwrap_or_else(|error| panic!("CPU gate closure admission failed: {error}"));
  assert!(joined);
  assert!(matches!(job.join(), Ok(29)));
  runtime
    .shutdown(ShutdownMode::Drain)
    .unwrap_or_else(|error| panic!("blocking runtime shutdown failed: {error}"));
  assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
}

#[test]
fn control_exhaustion_recovers_the_unpolled_future_and_closure() {
  let (domain, tenant) = domain(1, 3);
  let gate = CpuGate::new(tenant.clone(), 2)
    .unwrap_or_else(|error| panic!("CPU gate setup failed: {error}"));
  let snapshot = domain.snapshot();
  domain
    .set_limits(
      snapshot
        .limit
        .with(DomainResource::Control, control(snapshot)),
    )
    .unwrap_or_else(|error| panic!("global Control limit update failed: {error}"));
  let tenant_snapshot = tenant
    .snapshot()
    .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"));
  tenant
    .set_limits(
      tenant_snapshot
        .limit
        .with(DomainResource::Control, tenant_control(&tenant)),
    )
    .unwrap_or_else(|error| panic!("tenant Control limit update failed: {error}"));

  let future = gate.wrap(std::future::ready(53));
  let rejected = future
    .err()
    .unwrap_or_else(|| panic!("future Control limit was ignored"));
  assert_eq!(
    rejected.kind,
    DomainError::Exhausted(DomainResource::Control)
  );
  let mut future = Box::pin(rejected.into_future());
  let mut context = context(Waker::noop());
  assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(53));

  let closure = gate.try_run(|| 61_usize);
  let rejected = closure
    .err()
    .unwrap_or_else(|| panic!("closure Control limit was ignored"));
  assert_eq!(
    rejected.kind,
    DomainError::Exhausted(DomainResource::Control)
  );
  assert_eq!(rejected.into_function()(), 61);
}

#[test]
fn stack_lease_and_thread_wake_fees_are_released_after_run() {
  let (domain, tenant) = domain(1, 3);
  let gate = CpuGate::new(tenant.clone(), 2)
    .unwrap_or_else(|error| panic!("CPU gate setup failed: {error}"));
  let baseline_global = control(domain.snapshot());
  let baseline_tenant = tenant_control(&tenant);
  let expected = Arc::new(AtomicUsize::new(0));
  let expected_in_run = Arc::clone(&expected);
  let domain_in_run = domain.clone();
  let tenant_in_run = tenant.clone();
  let captured = [0x5a_u8; 47];
  let function = move || {
    let expected = expected_in_run.load(Ordering::SeqCst);
    assert_eq!(
      control(domain_in_run.snapshot()) - baseline_global,
      expected
    );
    assert_eq!(tenant_control(&tenant_in_run) - baseline_tenant, expected);
    assert_eq!(captured[0], 0x5a);
    67
  };
  expected.store(blocking_run_control_bytes(&function), Ordering::SeqCst);
  assert_eq!(
    gate
      .run(function)
      .unwrap_or_else(|error| panic!("blocking gate admission failed: {error}")),
    67
  );
  assert_eq!(control(domain.snapshot()), baseline_global);
  assert_eq!(tenant_control(&tenant), baseline_tenant);
}

#[test]
fn unbounded_cpu_gate_is_not_constructible_without_domain_cpu_ticket_capacity() {
  let ceiling = DomainResources::ZERO.with(DomainResource::Control, CONTROL);
  let domain = ResourceDomain::with_waiters(ceiling, 1, 2)
    .unwrap_or_else(|error| panic!("resource domain setup failed: {error}"));
  let tenant = domain
    .tenant(ceiling)
    .unwrap_or_else(|error| panic!("tenant setup failed: {error}"));
  assert_eq!(
    CpuGate::new(tenant, 1).err(),
    Some(DomainError::AboveCeiling(DomainResource::Cpu))
  );
}
