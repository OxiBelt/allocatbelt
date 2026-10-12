use super::*;

#[test]
fn task_role_leases_are_charged_to_the_shared_tenant_until_drop() {
  let domain = ApplicationDomain::new(Workload::Cpu, 2).expect("application domain");
  let bindings = domain.for_tokio().expect("Tokio run bindings");
  let before = bindings
    .snapshots()
    .expect("domain snapshots")
    .1
    .used
    .get(DomainResource::Tasks);
  let task = bindings.reserve_task().expect("task reservation");
  assert_eq!(
    bindings
      .snapshots()
      .expect("task snapshots")
      .1
      .used
      .get(DomainResource::Tasks),
    before + 1
  );
  drop(task);
  assert_eq!(
    bindings
      .snapshots()
      .expect("released snapshots")
      .1
      .used
      .get(DomainResource::Tasks),
    before
  );
  let (global, tenant, resources) = bindings.snapshots().expect("final snapshots");
  assert_eq!(global.ceiling, domain.domain_limits());
  assert_eq!(tenant.ceiling, domain.domain_limits());
  assert_eq!(resources.limits, domain.local_limits());
  assert_eq!(resources.managed_memory, 0);
  assert_eq!(resources.disk_ops, 0);
  assert_eq!(resources.network_ops, 0);
  assert_eq!(bindings.io().fixed_rate_parameters(), fixed_rate_config());
  let mut bindings = bindings;
  bindings
    .shutdown_auxiliary_timer()
    .expect("fixed rate timer shutdown");
}

#[test]
fn fixed_domain_bounds_cpu_waiters_tasks_and_managed_resources() {
  let domain = ApplicationDomain::new(Workload::Mixed, 4).expect("mixed application domain");
  let task = domain.domain_limits().get(DomainResource::Tasks);
  assert_eq!(task, APPLICATION_TASK_CEILING);
  assert_eq!(domain.domain_limits().get(DomainResource::Cpu), 4);
  assert!(domain.domain_limits().get(DomainResource::Control) > 0);
  assert_eq!(domain.local_limits().network_concurrent_ops, 16);
  assert_eq!(domain.local_limits().disk_concurrent_ops, 8);
}

#[test]
fn managed_payload_is_admitted_and_released_in_global_tenant_and_scope_ledgers() {
  let domain = ApplicationDomain::new(Workload::Memory, 2).expect("memory application domain");
  let mut bindings = domain.for_tokio().expect("Tokio memory bindings");
  let scope = bindings.resources();
  let bytes = scope.limits().managed_memory;
  let payload = scope.try_alloc_zeroed(bytes).expect("bounded payload");
  let (global, tenant, local) = bindings.snapshots().expect("live payload snapshots");
  assert_eq!(global.used.get(DomainResource::Memory), bytes);
  assert_eq!(tenant.used.get(DomainResource::Memory), bytes);
  assert_eq!(local.managed_memory, bytes);
  assert!(scope.try_alloc_zeroed(1).is_err());
  drop(payload);
  let (global, tenant, local) = bindings.snapshots().expect("released payload snapshots");
  assert_eq!(global.used.get(DomainResource::Memory), 0);
  assert_eq!(tenant.used.get(DomainResource::Memory), 0);
  assert_eq!(local.managed_memory, 0);
  bindings
    .shutdown_auxiliary_timer()
    .expect("fixed rate timer shutdown");
}

#[test]
fn native_driver_and_application_scope_share_one_tenant_domain() {
  let domain = ApplicationDomain::new(Workload::Cpu, 2).expect("native application domain");
  let readback_domain = domain.readback_domain();
  let fixed_control_baseline = domain.fixed_global_control_baseline();
  let rate = domain.rate_config();
  let mut driver = allocatbelt::runtime::MultiThreadBuilder::new(
    allocatbelt::runtime::asynchronous::AsyncConfig {
      workers: 2,
      max_outstanding: 8,
      max_scopes: 2,
    },
  )
  .resources(domain.local_limits())
  .resource_domain(domain.tenant())
  .rate_timer_registrations(256)
  .disk_rate(rate)
  .upload_rate(rate)
  .download_rate(rate)
  .build()
  .expect("native owning driver");
  let bindings = domain.for_native(&driver).expect("native run bindings");
  let application_scope = bindings.resources();
  let tenant = application_scope
    .tenant_domain()
    .expect("scope should retain its tenant");
  assert_eq!(
    tenant.snapshot().expect("tenant snapshot").ceiling,
    domain.domain_limits()
  );
  assert_eq!(bindings.io().fixed_rate_parameters(), rate);
  assert_eq!(
    bindings
      .snapshots()
      .expect("native snapshots")
      .2
      .managed_memory,
    0
  );

  let scope = driver.scope().expect("native test scope");
  driver
    .block_on(scope.close())
    .expect("native scope close future");
  driver
    .request_shutdown(allocatbelt::runtime::MultiShutdown {
      tasks: allocatbelt::runtime::asynchronous::AsyncShutdown::Drain,
      blocking: allocatbelt::runtime::ShutdownMode::Drain,
      processes: allocatbelt::runtime::process::ProcessShutdownMode::Wait,
    })
    .expect("native shutdown request");
  let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
  loop {
    match driver
      .drive_shutdown_step()
      .expect("native shutdown progress")
    {
      allocatbelt::runtime::ShutdownProgress::Complete => break,
      allocatbelt::runtime::ShutdownProgress::Pending => {
        assert!(
          std::time::Instant::now() < deadline,
          "native driver shutdown timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
      }
    }
  }
  drop(bindings);
  drop(application_scope);
  drop(driver);
  assert_eq!(
    domain.domain_limits().get(DomainResource::Tasks),
    APPLICATION_TASK_CEILING
  );
  drop(domain);
  let released = readback_domain.snapshot();
  assert_eq!(
    released.used.get(DomainResource::Control),
    fixed_control_baseline
  );
  assert_eq!(released.live_tenants, 0);
}

#[test]
fn native_driver_with_equal_limits_but_a_different_tenant_is_rejected() {
  let domain = ApplicationDomain::new(Workload::Cpu, 2).expect("selected application domain");
  let wrong_domain = ResourceDomain::with_waiters(domain.domain_limits(), 1, 256)
    .expect("wrong global domain with equal ceilings");
  let wrong_tenant = wrong_domain
    .tenant(domain.domain_limits())
    .expect("wrong tenant with equal ceilings");
  let rate = domain.rate_config();
  let mut wrong_driver = allocatbelt::runtime::MultiThreadBuilder::new(
    allocatbelt::runtime::asynchronous::AsyncConfig {
      workers: 2,
      max_outstanding: 8,
      max_scopes: 2,
    },
  )
  .resources(domain.local_limits())
  .resource_domain(wrong_tenant)
  .rate_timer_registrations(256)
  .disk_rate(rate)
  .upload_rate(rate)
  .download_rate(rate)
  .build()
  .expect("wrong-tenant native driver");

  let error = match domain.for_native(&wrong_driver) {
    Ok(_) => panic!("equal limits must not disguise a different tenant account"),
    Err(error) => error,
  };
  assert!(error.contains("different tenant account"));
  wrong_driver
    .request_shutdown(allocatbelt::runtime::MultiShutdown {
      tasks: allocatbelt::runtime::asynchronous::AsyncShutdown::Drain,
      blocking: allocatbelt::runtime::ShutdownMode::Drain,
      processes: allocatbelt::runtime::process::ProcessShutdownMode::Wait,
    })
    .expect("wrong driver shutdown request");
  let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
  loop {
    match wrong_driver
      .drive_shutdown_step()
      .expect("wrong driver shutdown progress")
    {
      allocatbelt::runtime::ShutdownProgress::Complete => break,
      allocatbelt::runtime::ShutdownProgress::Pending => {
        assert!(
          std::time::Instant::now() < deadline,
          "wrong driver shutdown timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
      }
    }
  }
}
