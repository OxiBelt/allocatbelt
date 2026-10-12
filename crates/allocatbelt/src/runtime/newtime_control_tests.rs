use super::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};

fn controlled_tenant() -> (ResourceDomain, TenantDomain) {
  let limits = DomainResources::ZERO.with(DomainResource::Control, 1 << 20);
  let domain = ResourceDomain::with_waiters(limits, 1, 0).expect("timer test domain");
  let tenant = domain.tenant(limits).expect("timer test tenant");
  (domain, tenant)
}

fn used_control(tenant: &TenantDomain) -> usize {
  tenant
    .snapshot()
    .expect("timer tenant snapshot")
    .used
    .get(DomainResource::Control)
}

fn limit_control(tenant: &TenantDomain, limit: usize) {
  tenant
    .set_limits(DomainResources::ZERO.with(DomainResource::Control, limit))
    .expect("lower timer tenant Control limit");
}

fn wait_for_control(tenant: &TenantDomain, expected: usize, timeout: Duration) {
  let deadline = Instant::now() + timeout;
  while used_control(tenant) != expected {
    assert!(
      Instant::now() < deadline,
      "timer metadata charge did not release"
    );
    std::thread::yield_now();
  }
}

struct DropWitness(Arc<AtomicUsize>);

impl Future for DropWitness {
  type Output = ();

  fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
    Poll::Pending
  }
}

impl Drop for DropWitness {
  fn drop(&mut self) {
    self.0.fetch_add(1, Ordering::SeqCst);
  }
}

#[test]
fn timer_constructor_rolls_back_partial_control_admission_before_starting_threads() {
  let (_domain, tenant) = controlled_tenant();
  let baseline = used_control(&tenant);
  // `new_in_tenant` first charges its private coordinator. Leave exactly
  // enough tenant headroom for that object, then refuse Shared/table startup.
  limit_control(&tenant, baseline + std::mem::size_of::<IdleCoordinator>());

  assert!(matches!(
    TimerDriver::new_in_tenant(8, &tenant),
    Err(TimerError::Domain(DomainError::Exhausted(
      DomainResource::Control
    )))
  ));
  assert_eq!(used_control(&tenant), baseline);
}

#[test]
fn timer_shared_and_slot_charges_follow_their_last_handles() {
  let (_domain, tenant) = controlled_tenant();
  let baseline = used_control(&tenant);
  let driver = TimerDriver::new_in_tenant(2, &tenant).expect("controlled timer");
  let actual_queue_bytes = lock(&driver.shared.state)
    .queue
    .actual_storage_bytes()
    .expect("actual queue capacity bytes");
  let service_attempt_capacity = driver._service_thread_name.clone().capacity();
  let close_attempt_capacity = driver.close_thread_name.clone().capacity();
  assert_eq!(
    driver.shared._control.bytes(),
    TimerDriver::shared_control_bytes(actual_queue_bytes).expect("Shared Control payload")
  );
  let panic_capacity = driver.lock_panic_payloads().capacity();
  let panic_bytes =
    crate::runtime::resource_domain::payload_bytes::<Box<dyn std::any::Any + Send>>(panic_capacity)
      .expect("panic payload Vec capacity bytes");
  let name_bytes = driver._service_thread_name.capacity()
    + driver.close_thread_name.capacity()
    + service_attempt_capacity
    + close_attempt_capacity;
  let builder_bytes = std::mem::size_of::<std::thread::Builder>() * 2;
  let owner_bytes = std::mem::size_of::<TimerDriver>() + panic_bytes + name_bytes + builder_bytes;
  assert_eq!(
    driver._owner_control.bytes(),
    owner_bytes,
    "TimerDriver Control includes its inline payload and external capacities"
  );
  let prepared = driver
    .prepared_joins
    .as_ref()
    .expect("embedded prepared join set");
  let prepared_vec_bytes =
    crate::runtime::resource_domain::payload_bytes::<PreparedJoin>(prepared.entries_capacity())
      .expect("PreparedJoin Vec capacity bytes");
  assert_eq!(prepared.control_bytes(), prepared_vec_bytes);
  let completion_bytes = driver
    .thread
    .as_ref()
    .expect("service completion owner")
    .control_bytes()
    + prepared
      .prepared_shared_control_bytes()
      .expect("close completion owner bytes");
  let expected_total = owner_bytes
    + prepared_vec_bytes
    + completion_bytes
    + driver.shared._control.bytes()
    + driver.shared.coordinator._control.bytes();
  assert_eq!(
    used_control(&tenant) - baseline,
    expected_total,
    "aggregate timer metadata omits the embedded PreparedJoins inline payload"
  );
  let handle = driver.handle();
  let before_sleep = used_control(&tenant);
  let cancelled = handle
    .sleep(Duration::from_secs(60))
    .expect("cancelled controlled slot");
  assert_eq!(
    used_control(&tenant),
    before_sleep + std::mem::size_of::<Slot>()
  );
  drop(cancelled);
  assert_eq!(handle.registered(), 0);
  assert_eq!(used_control(&tenant), before_sleep);

  let sleep = handle
    .sleep(Duration::from_secs(60))
    .expect("controlled slot");
  assert_eq!(
    used_control(&tenant),
    before_sleep + std::mem::size_of::<Slot>()
  );
  assert_eq!(handle.registered(), 1);

  driver.shutdown().expect("close controlled timer");
  assert!(handle.is_closed());
  assert!(used_control(&tenant) > baseline);

  let mut sleep = Box::pin(sleep);
  let mut context = Context::from_waker(Waker::noop());
  assert!(matches!(
    sleep.as_mut().poll(&mut context),
    Poll::Ready(Err(TimerError::Closed))
  ));
  drop(sleep);
  assert!(
    used_control(&tenant) > baseline,
    "the handle retains Shared"
  );
  drop(handle);
  wait_for_control(&tenant, baseline, Duration::from_secs(3));
}

#[test]
fn slot_admission_fails_before_arming_and_timeout_drops_its_future_once() {
  let (_domain, tenant) = controlled_tenant();
  let baseline = used_control(&tenant);
  let driver = TimerDriver::new_in_tenant(1, &tenant).expect("controlled timer");
  let handle = driver.handle();
  let used = used_control(&tenant);
  limit_control(&tenant, used);

  assert_eq!(
    handle.sleep(Duration::from_secs(1)).err(),
    Some(TimerError::Domain(DomainError::Exhausted(
      DomainResource::Control
    )))
  );
  assert_eq!(handle.registered(), 0);

  let drops = Arc::new(AtomicUsize::new(0));
  assert!(matches!(
    handle.timeout(Duration::from_secs(1), DropWitness(Arc::clone(&drops))),
    Err(TimerError::Domain(DomainError::Exhausted(
      DomainResource::Control
    )))
  ));
  assert_eq!(drops.load(Ordering::SeqCst), 1);
  assert_eq!(used_control(&tenant), used);

  driver.shutdown().expect("close timer after refusal");
  drop(handle);
  assert_eq!(used_control(&tenant), baseline);
}

#[test]
fn fixed_real_tenant_timer_keeps_its_immutable_clock_contract() {
  let (_domain, tenant) = controlled_tenant();
  let baseline = used_control(&tenant);
  let driver =
    TimerDriver::new_realtime_in_tenant(2, &tenant).expect("fixed real-time controlled timer");
  let handle = driver.handle();
  assert!(handle.is_realtime());
  assert_eq!(
    handle.set_mode(ClockMode::PausedManual),
    Err(TimerError::FixedRealClock)
  );
  driver.shutdown().expect("close fixed real timer");
  drop(handle);
  assert_eq!(used_control(&tenant), baseline);
}

#[test]
fn prepared_timer_completion_owner_survives_monitor_refusal_and_retry() {
  let (_domain, tenant) = controlled_tenant();
  let baseline = used_control(&tenant);
  let mut driver = TimerDriver::new_in_tenant(1, &tenant).expect("controlled timer");
  let handle = driver.handle();
  driver
    .request_shutdown()
    .expect("start prepared close worker");

  crate::runtime::thread_completion::fail_next_monitor_for_test();
  assert_eq!(driver.poll_shutdown(), Err(TimerError::JoinMonitorSpawn));
  assert!(used_control(&tenant) > baseline);

  let deadline = std::time::Instant::now() + Duration::from_secs(3);
  loop {
    match driver.poll_shutdown() {
      Ok(true) => break,
      Ok(false) => {
        assert!(
          std::time::Instant::now() < deadline,
          "timer completion monitor did not publish"
        );
        std::thread::yield_now();
      }
      Err(TimerError::JoinMonitorSpawn) => std::thread::yield_now(),
      Err(error) => panic!("timer completion failed: {error}"),
    }
  }
  assert!(handle.is_closed());
  drop(driver);
  assert!(
    used_control(&tenant) > baseline,
    "the handle retains Shared"
  );
  drop(handle);
  wait_for_control(&tenant, baseline, Duration::from_secs(3));
}

#[test]
fn idle_signal_and_coordinator_control_charges_follow_final_arcs() {
  let (_domain, tenant) = controlled_tenant();
  let baseline = used_control(&tenant);
  let signal_bytes = std::mem::size_of::<IdleSignal>();
  let signal =
    IdleSignal::new_in_tenant(std::thread::current(), &tenant).expect("controlled idle signal");
  assert_eq!(used_control(&tenant), baseline + signal_bytes);
  let signal_clone = Arc::clone(&signal);
  drop(signal);
  assert_eq!(used_control(&tenant), baseline + signal_bytes);
  drop(signal_clone);
  assert_eq!(used_control(&tenant), baseline);

  let coordinator_bytes = std::mem::size_of::<IdleCoordinator>();
  let coordinator =
    IdleCoordinator::new_in_tenant(None, &tenant).expect("controlled idle coordinator");
  assert_eq!(used_control(&tenant), baseline + coordinator_bytes);
  let clone = Arc::clone(&coordinator);
  drop(coordinator);
  assert_eq!(used_control(&tenant), baseline + coordinator_bytes);
  drop(clone);
  assert_eq!(used_control(&tenant), baseline);

  limit_control(&tenant, baseline);
  assert_eq!(
    IdleSignal::new_in_tenant(std::thread::current(), &tenant).map(drop),
    Err(DomainError::Exhausted(DomainResource::Control))
  );
  assert_eq!(
    IdleCoordinator::new_in_tenant(None, &tenant).map(drop),
    Err(DomainError::Exhausted(DomainResource::Control))
  );
  assert_eq!(used_control(&tenant), baseline);
}
