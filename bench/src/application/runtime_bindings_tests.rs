use super::*;

#[cfg(feature = "resource-feedback")]
fn feedback_startup_domain(workload: Workload) -> ApplicationDomain {
  ApplicationDomain::new_with_calibrations(
    workload,
    2,
    ApplicationMode::ExternalPressure,
    FeedbackCalibrations::default(),
  )
  .expect("external-pressure startup domain")
}

#[cfg(feature = "resource-feedback")]
fn feedback_startup_window(bindings: &ApplicationRunBindings) -> (Instant, Instant) {
  let sample_at = bindings
    .wait_for_feedback_startup_observation()
    .expect("accepted fresh dense CPU startup sample");
  let production_start = Instant::now();
  assert!(sample_at < production_start);
  assert!(
    bindings
      .validate_feedback_startup_observation(
        sample_at,
        production_start,
        Some((100, 131)),
        Some((130, 200)),
      )
      .is_err(),
    "overlapping clock uncertainty must not be tolerated"
  );
  (sample_at, production_start)
}

#[cfg(feature = "resource-feedback")]
fn wait_for_feedback_sample_after_drain(bindings: &ApplicationRunBindings) {
  let anchor = Instant::now()
    .checked_sub(Duration::from_secs(60))
    .expect("test clock anchor fits the monotonic clock range");
  let drain_end = Instant::now();
  let drain_upper = drain_end
    .checked_duration_since(anchor)
    .expect("drain marker follows test clock anchor")
    .as_nanos();
  let sample_at = bindings
    .wait_for_feedback_observation_after(drain_upper, |at| {
      let sample_ns = at
        .checked_duration_since(anchor)
        .ok_or_else(|| "sample predates test clock anchor".to_owned())?
        .as_nanos();
      Ok((sample_ns, sample_ns))
    })
    .expect("accepted fresh CPU sample after drain");
  let sample_ns = sample_at
    .checked_duration_since(anchor)
    .expect("accepted sample follows test clock anchor")
    .as_nanos();
  assert!(sample_ns >= drain_upper);
}

#[cfg(feature = "resource-feedback")]
#[test]
fn startup_barrier_waits_for_accepted_fresh_cpu_in_both_binding_paths() {
  let tokio_domain = feedback_startup_domain(Workload::Cpu);
  let tokio_baseline = tokio_domain.fixed_global_control_baseline();
  let tokio_readback = tokio_domain.readback_domain();
  let mut tokio_bindings = tokio_domain.for_tokio().expect("Tokio pressure bindings");
  let (tokio_sample, tokio_production) = feedback_startup_window(&tokio_bindings);
  wait_for_feedback_sample_after_drain(&tokio_bindings);
  tokio_bindings
    .shutdown_feedback(Duration::from_secs(5))
    .expect("Tokio feedback shutdown");
  tokio_bindings
    .validate_feedback_startup_observation(tokio_sample, tokio_production, None, None)
    .expect("post-run validation uses the captured startup sample, not later metrics");
  tokio_bindings
    .shutdown_auxiliary_timer()
    .expect("Tokio auxiliary timer shutdown");
  drop(tokio_bindings);
  drop(tokio_domain);
  assert_eq!(
    tokio_readback.snapshot().used.get(DomainResource::Control),
    tokio_baseline
  );

  let native_domain = feedback_startup_domain(Workload::Cpu);
  let native_baseline = native_domain.fixed_global_control_baseline();
  let factory = native_domain
    .feedback_factory()
    .expect("native pressure factory")
    .expect("external workload factory");
  let rates = native_domain.rate_configs();
  let mut driver = allocatbelt::runtime::MultiThreadBuilder::new(
    allocatbelt::runtime::asynchronous::AsyncConfig {
      workers: 2,
      max_outstanding: 8,
      max_scopes: 2,
    },
  )
  .resources(native_domain.local_limits())
  .resource_domain(native_domain.tenant())
  .timer(2)
  .rate_timer_registrations(256)
  .disk_rate(rates.disk)
  .upload_rate(rates.upload)
  .download_rate(rates.download)
  .feedback_sources(factory)
  .build()
  .expect("native pressure driver");
  let mut native_bindings = native_domain
    .for_native(&driver)
    .expect("native pressure bindings");
  let (native_sample, native_production) = feedback_startup_window(&native_bindings);
  wait_for_feedback_sample_after_drain(&native_bindings);
  driver
    .request_shutdown(allocatbelt::runtime::MultiShutdown {
      tasks: allocatbelt::runtime::asynchronous::AsyncShutdown::Drain,
      blocking: allocatbelt::runtime::ShutdownMode::Drain,
      processes: allocatbelt::runtime::process::ProcessShutdownMode::Wait,
    })
    .expect("native driver shutdown request");
  let deadline = Instant::now() + Duration::from_secs(5);
  loop {
    match driver
      .drive_shutdown_step()
      .expect("native shutdown progress")
    {
      allocatbelt::runtime::ShutdownProgress::Complete => break,
      allocatbelt::runtime::ShutdownProgress::Pending => {
        assert!(
          Instant::now() < deadline,
          "native driver shutdown timed out"
        );
        std::thread::sleep(Duration::from_millis(1));
      }
    }
  }
  native_bindings
    .shutdown_feedback(Duration::from_secs(5))
    .expect("native feedback service joined with its owning driver");
  native_bindings
    .validate_feedback_startup_observation(native_sample, native_production, None, None)
    .expect("post-run validation uses the captured startup sample, not later metrics");
  drop(native_bindings);
  drop(driver);
  let native_readback = native_domain.readback_domain();
  drop(native_domain);
  assert_eq!(
    native_readback.snapshot().used.get(DomainResource::Control),
    native_baseline
  );
}

#[cfg(feature = "resource-feedback")]
#[test]
fn post_drain_feedback_wait_does_not_accept_a_sample_after_its_deadline() {
  let domain = feedback_startup_domain(Workload::Cpu);
  let baseline = domain.fixed_global_control_baseline();
  let readback = domain.readback_domain();
  let mut bindings = domain.for_tokio().expect("Tokio pressure bindings");
  let anchor = Instant::now()
    .checked_sub(Duration::from_secs(60))
    .expect("test clock anchor fits the monotonic clock range");
  let drain_end = Instant::now();
  let drain_upper = drain_end
    .checked_duration_since(anchor)
    .expect("drain marker follows test clock anchor")
    .as_nanos();
  let bounds = |at: Instant| {
    let timestamp = at
      .checked_duration_since(anchor)
      .ok_or_else(|| "sample predates test clock anchor".to_owned())?
      .as_nanos();
    Ok((timestamp, timestamp))
  };
  bindings
    .wait_for_feedback_observation_after(drain_upper, &bounds)
    .expect("a fresh post-drain sample is accepted within the bounded wait");
  let error = bindings
    .wait_for_feedback_observation_after(drain_upper, |sample_at| {
      std::thread::sleep(SAMPLE_INTERVAL + MAX_DENSE_SAMPLE_GAP + Duration::from_millis(50));
      bounds(sample_at)
    })
    .expect_err("mapping that consumes the deadline must not admit a late sample");
  assert!(error.contains("deadline"));
  bindings
    .shutdown_feedback(Duration::from_secs(5))
    .expect("Tokio feedback shutdown");
  bindings
    .shutdown_auxiliary_timer()
    .expect("Tokio auxiliary timer shutdown");
  drop(bindings);
  drop(domain);
  assert_eq!(
    readback.snapshot().used.get(DomainResource::Control),
    baseline
  );
}

#[test]
fn comparison_family_defaults_fixed_and_pressure_requires_the_feature() {
  assert_eq!(
    ApplicationMode::from_comparison_family(None).expect("fixed default"),
    ApplicationMode::Fixed
  );
  assert_eq!(
    ApplicationMode::from_comparison_family(Some("fixed_policy")).expect("explicit fixed"),
    ApplicationMode::Fixed
  );
  if cfg!(feature = "resource-feedback") {
    assert_eq!(
      ApplicationMode::from_comparison_family(Some("external_pressure"))
        .expect("compiled pressure support"),
      ApplicationMode::ExternalPressure
    );
  } else {
    assert!(ApplicationMode::from_comparison_family(Some("external_pressure")).is_err());
  }
  assert!(ApplicationMode::from_comparison_family(Some("unknown")).is_err());
}

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

#[cfg(feature = "resource-feedback")]
fn calibrated_mixed_application_domain() -> ApplicationDomain {
  let source_sha256 = "a".repeat(64);
  let bytes = String::from_utf8(capacity_artifact(
    "1250000000",
    APPLICATION_BYTE_CALIBRATION_UNITS,
  ))
  .expect("capacity artifact is UTF-8")
  .replace("profile\tsteady", "profile\tmixed")
  .replace("workload\tdisk", "workload\tmixed")
  .replace(
    "disk.bytes_per_second\t1000000",
    "disk.bytes_per_second\t750000000",
  )
  .into_bytes();
  let sha256 = capacity_artifact_hash::sha256_hex(&bytes);
  let path = write_calibration_test_file(&bytes);
  let domain = ApplicationDomain::new_for_feedback_probe(
    Workload::Mixed,
    4,
    "mixed",
    CapacityCalibrationProbeInput {
      path: &path,
      sha256: &sha256,
      host_id: "agent-9700x",
      source_sha256: &source_sha256,
      capacity_floor_policy_id: None,
    },
  );
  std::fs::remove_file(path).expect("remove temporary calibration input after loading");
  domain.expect("calibrated mixed application domain")
}

#[cfg(feature = "resource-feedback")]
fn assert_calibrated_directional_bindings(bindings: &ApplicationRunBindings) {
  let rates = bindings
    .io()
    .readback_rows()
    .into_iter()
    .collect::<std::collections::HashMap<_, _>>();
  let upload_rate = APPLICATION_RATE_CEILING_BYTES_PER_SECOND.to_string();
  for (direction, expected) in [
    ("disk", "750000000"),
    ("download", "1250000000"),
    ("upload", upload_rate.as_str()),
  ] {
    assert_eq!(
      rates[&format!("{direction}_bytes_per_second")].as_str(),
      expected
    );
    assert_eq!(
      rates[&format!("{direction}_ceiling_bytes_per_second")].as_str(),
      expected,
    );
  }
  let policy = bindings
    .policy_rows()
    .into_iter()
    .collect::<std::collections::HashMap<_, _>>();
  for (name, expected) in [
    ("disk.initial", "750000000"),
    ("disk.ceiling", "750000000"),
    ("download.initial", "1250000000"),
    ("download.ceiling", "1250000000"),
  ] {
    assert_eq!(
      policy[&format!("feedback.policy.{name}")].as_str(),
      expected
    );
  }
}

#[cfg(feature = "resource-feedback")]
fn assert_application_domain_released(readback: &ResourceDomain, baseline: usize) {
  let snapshot = readback.snapshot();
  after_release_global_snapshot_rows(&snapshot, baseline)
    .expect("all application owners return to the constructor baseline");
  assert_eq!(snapshot.live_tenants, 0);
  assert_eq!(snapshot.used.get(DomainResource::Control), baseline);
  for resource in [
    DomainResource::Cpu,
    DomainResource::Memory,
    DomainResource::Disk,
    DomainResource::Network,
    DomainResource::Tasks,
  ] {
    assert_eq!(snapshot.used.get(resource), 0);
  }
}

#[cfg(feature = "resource-feedback")]
#[test]
fn calibrated_native_and_tokio_bindings_match_directional_buckets_receipts_and_cleanup() {
  let tokio_domain = calibrated_mixed_application_domain();
  let tokio_baseline = tokio_domain.fixed_global_control_baseline();
  let tokio_readback = tokio_domain.readback_domain();
  let mut tokio_bindings = tokio_domain
    .for_tokio()
    .expect("calibrated Tokio feedback bindings");
  assert!(tokio_bindings.feedback_started());
  assert_calibrated_directional_bindings(&tokio_bindings);
  tokio_bindings
    .shutdown_feedback(Duration::from_secs(5))
    .expect("calibrated Tokio feedback shutdown");
  tokio_bindings
    .shutdown_auxiliary_timer()
    .expect("calibrated Tokio rate timer shutdown");
  drop(tokio_bindings);
  drop(tokio_domain);
  assert_application_domain_released(&tokio_readback, tokio_baseline);

  let native_domain = calibrated_mixed_application_domain();
  let native_baseline = native_domain.fixed_global_control_baseline();
  let native_readback = native_domain.readback_domain();
  let factory = native_domain
    .feedback_factory()
    .expect("calibrated native feedback factory")
    .expect("mixed workload starts feedback");
  let rates = native_domain.rate_configs();
  let mut driver = allocatbelt::runtime::MultiThreadBuilder::new(
    allocatbelt::runtime::asynchronous::AsyncConfig {
      workers: 4,
      max_outstanding: 8,
      max_scopes: 2,
    },
  )
  .resources(native_domain.local_limits())
  .resource_domain(native_domain.tenant())
  .rate_timer_registrations(256)
  .disk_rate(rates.disk)
  .upload_rate(rates.upload)
  .download_rate(rates.download)
  .blocking(allocatbelt::runtime::Config {
    workers: 4,
    max_outstanding: 8,
    capacity: allocatbelt::runtime::Resources {
      disk: 8,
      ..allocatbelt::runtime::Resources::ZERO
    },
  })
  .filesystem()
  .feedback_sources(factory)
  .build()
  .expect("calibrated native feedback driver");
  let mut native_bindings = native_domain
    .for_native(&driver)
    .expect("calibrated native run bindings");
  assert!(native_bindings.feedback_started());
  assert_calibrated_directional_bindings(&native_bindings);
  driver
    .request_shutdown(allocatbelt::runtime::MultiShutdown {
      tasks: allocatbelt::runtime::asynchronous::AsyncShutdown::Drain,
      blocking: allocatbelt::runtime::ShutdownMode::Drain,
      processes: allocatbelt::runtime::process::ProcessShutdownMode::Wait,
    })
    .expect("calibrated native shutdown request");
  let deadline = Instant::now() + Duration::from_secs(5);
  loop {
    match driver
      .drive_shutdown_step()
      .expect("calibrated native shutdown progress")
    {
      allocatbelt::runtime::ShutdownProgress::Complete => break,
      allocatbelt::runtime::ShutdownProgress::Pending => {
        assert!(
          Instant::now() < deadline,
          "calibrated native driver shutdown timed out"
        );
        std::thread::sleep(Duration::from_millis(1));
      }
    }
  }
  native_bindings
    .shutdown_feedback(Duration::from_secs(5))
    .expect("calibrated native feedback shutdown");
  drop(native_bindings);
  drop(driver);
  drop(native_domain);
  assert_application_domain_released(&native_readback, native_baseline);
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
fn after_release_global_snapshot_rows_report_actual_application_dimensions() {
  assert_eq!(
    RUNTIME_BINDING_RECEIPT_SCHEMA_V2,
    "allocatbelt.application-runtime-binding.v2"
  );
  let domain = ApplicationDomain::new(Workload::Memory, 2).expect("application domain");
  let readback_domain = domain.readback_domain();
  let baseline = domain.fixed_global_control_baseline();
  let tenant = domain.tenant();
  let memory_charge = tenant
    .try_acquire(DomainResources::ZERO.with(DomainResource::Memory, 1))
    .expect("memory resource charge");
  let live = readback_domain.snapshot();
  assert_eq!(live.used.get(DomainResource::Memory), 1);
  assert!(
    after_release_global_snapshot_rows(&live, baseline)
      .expect_err("live memory cannot be a final snapshot")
      .contains("global memory usage: 1")
  );
  drop(memory_charge);
  drop(tenant);
  drop(domain);

  let released = readback_domain.snapshot();
  let rows = after_release_global_snapshot_rows(&released, baseline)
    .expect("captured final global snapshot");
  assert_eq!(rows.len(), 9);
  for (name, resource) in [
    ("cpu", DomainResource::Cpu),
    ("memory", DomainResource::Memory),
    ("disk", DomainResource::Disk),
    ("network", DomainResource::Network),
    ("tasks", DomainResource::Tasks),
  ] {
    let key = format!("after_release.global.used.{name}");
    let value = rows
      .iter()
      .find(|(candidate, _)| candidate == &key)
      .map(|(_, value)| value.as_str())
      .expect("final application resource dimension");
    assert_eq!(value, released.used.get(resource).to_string());
    assert_eq!(value, "0");
  }
  assert_eq!(released.live_tenants, 0);
  assert_eq!(
    rows
      .iter()
      .find(|(key, _)| key == "after_release.global.live_tenants")
      .map(|(_, value)| value.as_str()),
    Some("0")
  );
  assert_eq!(
    rows
      .iter()
      .find(|(key, _)| key == "after_release.global.used.control")
      .map(|(_, value)| value.clone())
      .expect("actual final Control snapshot"),
    released.used.get(DomainResource::Control).to_string()
  );
  assert_eq!(
    rows
      .iter()
      .find(|(key, _)| key == "after_release.expected_global_control_baseline")
      .map(|(_, value)| value.clone())
      .expect("expected final Control baseline"),
    baseline.to_string()
  );
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
  let rates = domain.rate_configs();
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
  .disk_rate(rates.disk)
  .upload_rate(rates.upload)
  .download_rate(rates.download)
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
  assert_eq!(bindings.io().fixed_rate_parameters(), rates.disk);
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
  let rates = domain.rate_configs();
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
  .disk_rate(rates.disk)
  .upload_rate(rates.upload)
  .download_rate(rates.download)
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

#[cfg(feature = "resource-feedback")]
fn capacity_artifact(download_capacity: &str, download_units: &str) -> Vec<u8> {
  format!(
    "schema\t{CAPACITY_CALIBRATION_SCHEMA}\ncalibration_id\tcal-17\nhost_id\tagent-9700x\nprofile\tsteady\nworkload\tdisk\nsource_sha256\t{}\ndisk.bytes_per_second\t1000000\ndisk.units\t{APPLICATION_BYTE_CALIBRATION_UNITS}\ndisk.provenance\tlocal-device-read-write-pilot\ndownload.bytes_per_second\t{download_capacity}\ndownload.units\t{download_units}\ndownload.provenance\tno-independent-download-calibration\n",
    "a".repeat(64)
  )
  .into_bytes()
}

#[cfg(feature = "resource-feedback")]
fn capacity_test_identity<'a>(
  profile: &'a str,
  source_sha256: &'a str,
  pressure_qualification: bool,
) -> CalibrationRunIdentity<'a> {
  CalibrationRunIdentity {
    host_id: "agent-9700x",
    profile,
    workload: "disk",
    source_sha256,
    pressure_qualification,
  }
}

#[cfg(feature = "resource-feedback")]
fn load_capacity_test_file(
  tenant: &TenantDomain,
  path: &std::path::Path,
  hash: &str,
  profile: &str,
  source_sha256: &str,
  pressure_qualification: bool,
) -> Result<FeedbackCalibrations, String> {
  let identity = capacity_test_identity(profile, source_sha256, pressure_qualification);
  FeedbackCalibrations::from_file(tenant, path, hash, &identity)
}

#[cfg(feature = "resource-feedback")]
#[test]
fn capacity_artifact_binds_candidate_host_context_and_rejects_profile_mismatch() {
  let bytes = capacity_artifact("missing", "missing");
  let source_sha = "a".repeat(64);
  let identity = capacity_test_identity("steady", &source_sha, false);
  let parsed = parse_capacity_calibration(&bytes, &identity).expect("valid capacity artifact");
  let text = std::str::from_utf8(&bytes).expect("UTF-8 test artifact");
  assert_eq!(&text[parsed.calibration_id], "cal-17");
  assert_eq!(parsed.disk.bytes_per_second, NonZeroU64::new(1_000_000));
  assert_eq!(parsed.download.bytes_per_second, None);
  let other_host = CalibrationRunIdentity {
    host_id: "different-host",
    ..identity
  };
  assert!(parse_capacity_calibration(&bytes, &other_host).is_err());
  let other_profile = CalibrationRunIdentity {
    profile: "burst",
    ..identity
  };
  assert!(parse_capacity_calibration(&bytes, &other_profile).is_err());
  let other_source = "b".repeat(64);
  let other_source_identity = capacity_test_identity("steady", &other_source, false);
  assert!(parse_capacity_calibration(&bytes, &other_source_identity).is_err());
}

#[cfg(feature = "resource-feedback")]
#[test]
fn capacity_artifact_hash_covers_exact_bytes_and_qualification_requires_applicable_sources() {
  let bytes = capacity_artifact("5000000", APPLICATION_BYTE_CALIBRATION_UNITS);
  let hash = capacity_artifact_hash::sha256_hex(&bytes);
  let path = write_calibration_test_file(&bytes);
  let control_limits = DomainResources::ZERO.with(DomainResource::Control, 64 * 1024);
  let domain = ResourceDomain::new(
    DomainResources::ZERO.with(DomainResource::Control, 1024 * 1024),
    1,
  )
  .expect("calibration test domain");
  let tenant = domain
    .tenant(control_limits)
    .expect("calibration test tenant");
  let baseline = domain.snapshot().used.get(DomainResource::Control);
  let source_sha = "a".repeat(64);
  let loaded = load_capacity_test_file(&tenant, &path, &hash, "steady", &source_sha, true)
    .expect("fully calibrated pressure qualification");
  assert!(loaded.pressure_qualification);
  assert_eq!(loaded.download_capacity(), NonZeroU64::new(5_000_000));
  assert_eq!(loaded.disk_capacity(), NonZeroU64::new(1_000_000));
  let artifact = loaded.artifact.as_ref().expect("retained calibration");
  assert_eq!(
    String::from_utf8_lossy(&artifact.artifact_sha256),
    hash.as_str()
  );
  assert!(
    domain.snapshot().used.get(DomainResource::Control)
      >= baseline + CALIBRATION_ARTIFACT_CONTROL_CHARGE
  );
  let retained = loaded.clone();
  drop(loaded);
  assert!(
    domain.snapshot().used.get(DomainResource::Control)
      >= baseline + CALIBRATION_ARTIFACT_CONTROL_CHARGE
  );
  drop(retained);
  assert_eq!(
    domain.snapshot().used.get(DomainResource::Control),
    baseline
  );

  let mismatched_profile =
    load_capacity_test_file(&tenant, &path, &hash, "burst", &source_sha, false);
  assert!(mismatched_profile.is_err());
  assert_eq!(
    domain.snapshot().used.get(DomainResource::Control),
    baseline
  );

  let tampered = String::from_utf8(bytes.clone())
    .expect("artifact UTF-8")
    .replace(
      "disk.bytes_per_second\t1000000",
      "disk.bytes_per_second\t1000001",
    )
    .into_bytes();
  let tampered_path = write_calibration_test_file(&tampered);
  assert!(
    load_capacity_test_file(&tenant, &tampered_path, &hash, "steady", &source_sha, false,).is_err()
  );

  let missing_download = capacity_artifact("missing", "missing");
  let missing_hash = capacity_artifact_hash::sha256_hex(&missing_download);
  let missing_path = write_calibration_test_file(&missing_download);
  let before_missing = domain.snapshot().used.get(DomainResource::Control);
  let disk_only = load_capacity_test_file(
    &tenant,
    &missing_path,
    &missing_hash,
    "steady",
    &source_sha,
    true,
  )
  .expect("disk workload does not require a download denominator");
  assert_eq!(disk_only.download_capacity(), None);
  drop(disk_only);
  assert_eq!(
    domain.snapshot().used.get(DomainResource::Control),
    before_missing
  );
  drop(tenant);
  drop(domain);
  for artifact_path in [path, tampered_path, missing_path] {
    std::fs::remove_file(artifact_path).expect("remove calibration test artifact");
  }
}

#[cfg(feature = "resource-feedback")]
#[test]
fn pressure_capacity_requirements_follow_the_actual_workload() {
  let control = DomainResources::ZERO.with(DomainResource::Control, 1024 * 1024);
  let domain = ResourceDomain::new(control, 1).expect("calibration domain");
  let tenant = domain.tenant(control).expect("calibration tenant");
  let source = "a".repeat(64);
  for (workload, disk, download, expected) in [
    ("cpu", false, false, true),
    ("memory", false, false, true),
    ("disk", true, false, true),
    ("http", false, true, true),
    ("mixed", true, true, true),
    ("disk", false, true, false),
    ("http", true, false, false),
    ("mixed", true, false, false),
    ("mixed", false, true, false),
  ] {
    let mut text = String::from_utf8(capacity_artifact(
      if download { "5000000" } else { "missing" },
      if download {
        APPLICATION_BYTE_CALIBRATION_UNITS
      } else {
        "missing"
      },
    ))
    .expect("artifact UTF-8")
    .replace("workload\tdisk", &format!("workload\t{workload}"));
    if !disk {
      text = text
        .replace(
          "disk.bytes_per_second\t1000000",
          "disk.bytes_per_second\tmissing",
        )
        .replace(
          &format!("disk.units\t{APPLICATION_BYTE_CALIBRATION_UNITS}"),
          "disk.units\tmissing",
        );
    }
    let bytes = text.into_bytes();
    let hash = capacity_artifact_hash::sha256_hex(&bytes);
    let identity = CalibrationRunIdentity {
      workload,
      ..capacity_test_identity("steady", &source, true)
    };
    let baseline = tenant
      .snapshot()
      .expect("baseline")
      .used
      .get(DomainResource::Control);
    let charge = tenant
      .try_acquire(
        DomainResources::ZERO.with(DomainResource::Control, CALIBRATION_ARTIFACT_CONTROL_CHARGE),
      )
      .expect("calibration charge");
    let result = FeedbackCalibrations::from_bytes_with_charge(bytes, &hash, &identity, charge);
    assert_eq!(
      result.is_ok(),
      expected,
      "workload={workload} disk={disk} download={download}"
    );
    drop(result);
    assert_eq!(
      tenant
        .snapshot()
        .expect("released")
        .used
        .get(DomainResource::Control),
      baseline
    );
  }
}

#[cfg(feature = "resource-feedback")]
fn loaded_test_calibrations(
  workload: &str,
  disk_capacity: &str,
  download_capacity: &str,
) -> (ResourceDomain, FeedbackCalibrations) {
  let download_units = if download_capacity == "missing" {
    "missing"
  } else {
    APPLICATION_BYTE_CALIBRATION_UNITS
  };
  let mut text = String::from_utf8(capacity_artifact(download_capacity, download_units))
    .expect("capacity artifact is UTF-8")
    .replace("workload\tdisk", &format!("workload\t{workload}"))
    .replace(
      "disk.bytes_per_second\t1000000",
      &format!("disk.bytes_per_second\t{disk_capacity}"),
    );
  if disk_capacity == "missing" {
    text = text.replace(
      &format!("disk.units\t{APPLICATION_BYTE_CALIBRATION_UNITS}"),
      "disk.units\tmissing",
    );
  }
  let bytes = text.into_bytes();
  let hash = capacity_artifact_hash::sha256_hex(&bytes);
  let source_sha = "a".repeat(64);
  let control = DomainResources::ZERO.with(DomainResource::Control, 1024 * 1024);
  let domain = ResourceDomain::new(control, 1).expect("test calibration domain");
  let tenant = domain.tenant(control).expect("test calibration tenant");
  let identity = CalibrationRunIdentity {
    host_id: "agent-9700x",
    profile: "steady",
    workload,
    source_sha256: &source_sha,
    pressure_qualification: false,
  };
  let charge = tenant
    .try_acquire(
      DomainResources::ZERO.with(DomainResource::Control, CALIBRATION_ARTIFACT_CONTROL_CHARGE),
    )
    .expect("test calibration charge");
  let calibrations = FeedbackCalibrations::from_bytes_with_charge(bytes, &hash, &identity, charge)
    .expect("test calibration artifact loads");
  drop(tenant);
  (domain, calibrations)
}

#[cfg(feature = "resource-feedback")]
#[test]
fn calibrated_feedback_resolves_directional_buckets_and_preserves_cpu_quantization() {
  for workers in [2, 4] {
    let (_domain, calibrations) = loaded_test_calibrations("mixed", "750000000", "1250000000");
    let resolved = resolve_application_feedback(Workload::Mixed, workers, &calibrations)
      .expect("both application byte sources resolve");
    let frozen = feedback_policy(workers);
    assert_eq!(resolved.policy.cpu_concurrency, frozen.cpu_concurrency);
    assert_eq!(resolved.policy.cpu_concurrency.initial, workers as u64);
    assert_eq!(resolved.policy.cpu_concurrency.ceiling, workers as u64);
    assert_eq!(resolved.policy.cpu_concurrency.floor, 1);
    assert_eq!(resolved.policy.cpu_concurrency.initial / 10, 0);
    assert_eq!(resolved.policy.disk_rate.floor, frozen.disk_rate.floor);
    assert_eq!(
      resolved.policy.disk_rate.low_utilization_basis_points,
      frozen.disk_rate.low_utilization_basis_points
    );
    assert_eq!(
      resolved.policy.disk_rate.high_utilization_basis_points,
      frozen.disk_rate.high_utilization_basis_points
    );
    assert_eq!(resolved.policy.disk_rate.initial, 750_000_000);
    assert_eq!(resolved.policy.disk_rate.ceiling, 750_000_000);
    assert_eq!(resolved.policy.network_rate.initial, 1_250_000_000);
    assert_eq!(resolved.policy.network_rate.ceiling, 1_250_000_000);
    assert_eq!(resolved.rates.disk.bytes_per_second, 750_000_000);
    assert_eq!(resolved.rates.download.bytes_per_second, 1_250_000_000);
    assert_eq!(resolved.rates.upload, fixed_rate_config());
    assert_eq!(calibrations.disk_capacity(), NonZeroU64::new(750_000_000));
    assert_eq!(
      calibrations.download_capacity(),
      NonZeroU64::new(1_250_000_000)
    );
    let rows = feedback_policy_rows(
      workers,
      &calibrations,
      resolved,
      "owning_FsRate_application_bytes",
    );
    for (key, expected) in [
      ("feedback.policy.disk.initial", "750000000"),
      ("feedback.policy.disk.ceiling", "750000000"),
      ("feedback.policy.download.initial", "1250000000"),
      ("feedback.policy.download.ceiling", "1250000000"),
    ] {
      assert_eq!(
        rows
          .iter()
          .find(|(row, _)| row == key)
          .map(|(_, value)| value.as_str()),
        Some(expected),
        "{key} must report the resolved constructor policy"
      );
    }
  }
}

#[cfg(feature = "resource-feedback")]
#[test]
fn calibrated_feedback_clips_bucket_roofs_but_keeps_raw_sensor_denominators() {
  let raw_disk = 32 * APPLICATION_RATE_CEILING_BYTES_PER_SECOND;
  let raw_download = 33 * APPLICATION_RATE_CEILING_BYTES_PER_SECOND;
  let (_domain, calibrations) =
    loaded_test_calibrations("mixed", &raw_disk.to_string(), &raw_download.to_string());
  let resolved = resolve_application_feedback(Workload::Mixed, 4, &calibrations)
    .expect("above-roof capacities clip to the existing rate roof");
  assert_eq!(
    resolved.policy.disk_rate.initial,
    APPLICATION_RATE_CEILING_BYTES_PER_SECOND
  );
  assert_eq!(
    resolved.policy.disk_rate.ceiling,
    APPLICATION_RATE_CEILING_BYTES_PER_SECOND
  );
  assert_eq!(
    resolved.rates.disk.bytes_per_second,
    APPLICATION_RATE_CEILING_BYTES_PER_SECOND
  );
  assert_eq!(
    resolved.policy.network_rate.initial,
    APPLICATION_RATE_CEILING_BYTES_PER_SECOND
  );
  assert_eq!(
    resolved.policy.network_rate.ceiling,
    APPLICATION_RATE_CEILING_BYTES_PER_SECOND
  );
  assert_eq!(
    calibrations.disk_capacity().map(NonZeroU64::get),
    Some(raw_disk)
  );
  assert_eq!(
    calibrations.download_capacity().map(NonZeroU64::get),
    Some(raw_download)
  );
}

#[cfg(feature = "resource-feedback")]
#[test]
fn capacity_relative_floor_uses_checked_floor_rounding_and_preserves_the_static_default() {
  for (capacity, expected) in [
    (1, 1),
    (9, 1),
    (10, 1),
    (19, 1),
    (20, 2),
    (4_617_956, 461_795),
    (
      APPLICATION_RATE_CEILING_BYTES_PER_SECOND * 2,
      FEEDBACK_RATE_FLOOR,
    ),
  ] {
    assert_eq!(
      capacity_relative_floor(FEEDBACK_RATE_FLOOR, capacity)
        .expect("checked capacity-relative floor"),
      expected,
    );
  }

  let (_domain, mut calibrated) = loaded_test_calibrations("mixed", "4617956", "4617956");
  calibrated.capacity_floor_policy = CapacityFloorPolicy::CapacityRelativeTenth;
  let resolved = resolve_application_feedback(Workload::Mixed, 4, &calibrated)
    .expect("explicit relative policy resolves an independently measured capacity");
  assert_eq!(
    resolved.capacity_floor_policy_id,
    Some(CAPACITY_FLOOR_POLICY_ID)
  );
  assert_eq!(resolved.policy.disk_rate.floor, 461_795);
  assert_eq!(resolved.policy.network_rate.floor, 461_795);
  assert_eq!(resolved.policy.disk_rate.initial, 4_617_956);
  assert_eq!(resolved.policy.disk_rate.ceiling, 4_617_956);
  assert_eq!(resolved.policy.network_rate.initial, 4_617_956);
  assert_eq!(resolved.policy.network_rate.ceiling, 4_617_956);
  assert_eq!(resolved.rates.disk.burst_bytes, RATE_BURST_BYTES);
  assert_eq!(resolved.rates.download.burst_bytes, RATE_BURST_BYTES);
  assert_eq!(resolved.rates.disk.max_reservations, RATE_RESERVATIONS);
  assert_eq!(resolved.rates.download.max_reservations, RATE_RESERVATIONS);

  let (_domain, static_default) = loaded_test_calibrations("mixed", "4617956", "4617956");
  assert_eq!(
    static_default.capacity_floor_policy,
    CapacityFloorPolicy::StaticDefault
  );
  assert!(resolve_application_feedback(Workload::Mixed, 4, &static_default).is_err());
  assert_eq!(feedback_policy(4).disk_rate.floor, FEEDBACK_RATE_FLOOR);
}

#[cfg(feature = "resource-feedback")]
#[test]
fn capacity_relative_floor_activation_requires_pressure_and_a_validated_artifact() {
  let relative = CapacityFloorPolicy::CapacityRelativeTenth;
  assert!(validate_capacity_floor_activation(relative, false, Some(true)).is_err());
  assert!(validate_capacity_floor_activation(relative, true, Some(false)).is_err());
  assert!(validate_capacity_floor_activation(relative, true, None).is_ok());
  assert!(validate_capacity_floor_activation(relative, true, Some(true)).is_ok());
  assert!(
    validate_capacity_floor_activation(CapacityFloorPolicy::StaticDefault, false, Some(false))
      .is_ok()
  );
}

#[cfg(feature = "resource-feedback")]
#[test]
fn calibrated_feedback_rejects_relevant_missing_and_below_floor_sources() {
  let (_domain, missing_disk) = loaded_test_calibrations("disk", "missing", "missing");
  assert!(resolve_application_feedback(Workload::Disk, 2, &missing_disk).is_err());

  let (_domain, missing_download) = loaded_test_calibrations("http", "missing", "missing");
  assert!(resolve_application_feedback(Workload::Http, 2, &missing_download).is_err());

  let (_domain, disk_below_floor) = loaded_test_calibrations("disk", "1000000", "missing");
  assert!(resolve_application_feedback(Workload::Disk, 2, &disk_below_floor).is_err());

  let (_domain, download_below_floor) = loaded_test_calibrations("http", "missing", "1000000");
  assert!(resolve_application_feedback(Workload::Http, 2, &download_below_floor).is_err());

  let (_domain, measured_download_below_default) =
    loaded_test_calibrations("http", "missing", "4617956");
  assert!(
    resolve_application_feedback(Workload::Http, 2, &measured_download_below_default).is_err()
  );

  let (_domain, missing_mixed_download) = loaded_test_calibrations("mixed", "750000000", "missing");
  assert!(resolve_application_feedback(Workload::Mixed, 4, &missing_mixed_download).is_err());

  let (_domain, missing_mixed_disk) = loaded_test_calibrations("mixed", "missing", "1250000000");
  assert!(resolve_application_feedback(Workload::Mixed, 4, &missing_mixed_disk).is_err());
}

#[cfg(feature = "resource-feedback")]
#[test]
fn uncalibrated_and_zero_io_directions_keep_the_static_policy_and_buckets() {
  for workload in [Workload::Cpu, Workload::Memory] {
    let resolved = resolve_application_feedback(workload, 2, &FeedbackCalibrations::default())
      .expect("uncalibrated constructor keeps the frozen defaults");
    assert_eq!(resolved.policy, feedback_policy(2));
    assert_eq!(resolved.rates, ApplicationRateConfigs::fixed());
  }

  let (_domain, cpu_calibration) = loaded_test_calibrations("cpu", "missing", "missing");
  let cpu = resolve_application_feedback(Workload::Cpu, 2, &cpu_calibration)
    .expect("missing non-applicable byte sources do not create controls");
  assert_eq!(cpu.policy, feedback_policy(2));
  assert_eq!(cpu.rates, ApplicationRateConfigs::fixed());

  let (_domain, disk_calibration) = loaded_test_calibrations("disk", "750000000", "missing");
  let disk = resolve_application_feedback(Workload::Disk, 4, &disk_calibration)
    .expect("missing download is irrelevant to disk-only work");
  assert_eq!(disk.policy.network_rate, feedback_policy(4).network_rate);
  assert_eq!(disk.rates.download, fixed_rate_config());

  let (_domain, http_calibration) = loaded_test_calibrations("http", "missing", "1250000000");
  let http = resolve_application_feedback(Workload::Http, 4, &http_calibration)
    .expect("missing disk is irrelevant to HTTP-only work");
  assert_eq!(http.policy.disk_rate, feedback_policy(4).disk_rate);
  assert_eq!(http.rates.disk, fixed_rate_config());
  assert_eq!(http.policy.network_rate.initial, 1_250_000_000);
}

#[cfg(feature = "resource-feedback")]
#[test]
fn feedback_rate_validation_checks_initial_rate_and_construction_ceiling() {
  let resolved = resolve_application_feedback(Workload::Mixed, 2, &FeedbackCalibrations::default())
    .expect("default resolved policy");
  let disk = ByteRateLimit::new(resolved.rates.disk).expect("matching disk bucket");
  let download = ByteRateLimit::new(resolved.rates.download).expect("matching download bucket");
  assert!(validate_initial_feedback_rates(&disk, &download, resolved).is_ok());

  disk
    .set_limits(FEEDBACK_RATE_FLOOR, resolved.rates.disk.burst_bytes)
    .expect("valid reduced initial rate");
  assert!(validate_initial_feedback_rates(&disk, &download, resolved).is_err());

  let larger_ceiling = ByteRateConfig {
    bytes_per_second: resolved.policy.network_rate.ceiling + 1,
    ..resolved.rates.download
  };
  let wrong_ceiling = ByteRateLimit::new(larger_ceiling).expect("valid larger bucket ceiling");
  wrong_ceiling
    .set_limits(
      resolved.policy.network_rate.initial,
      resolved.rates.download.burst_bytes,
    )
    .expect("initial rate remains below the test ceiling");
  assert!(
    validate_initial_feedback_rates(
      &ByteRateLimit::new(resolved.rates.disk).expect("matching disk bucket"),
      &wrong_ceiling,
      resolved,
    )
    .is_err()
  );
}

#[cfg(feature = "resource-feedback")]
fn write_calibration_test_file(bytes: &[u8]) -> std::path::PathBuf {
  use std::sync::atomic::{AtomicU64, Ordering};
  static NEXT_FILE: AtomicU64 = AtomicU64::new(1);
  let path = std::env::temp_dir().join(format!(
    "allocatbelt-calibration-owner-{}-{}.tsv",
    std::process::id(),
    NEXT_FILE.fetch_add(1, Ordering::Relaxed),
  ));
  std::fs::write(&path, bytes).expect("write calibration test artifact");
  path
}

#[cfg(feature = "resource-feedback")]
#[test]
fn capacity_artifact_control_ceiling_refusal_is_transactional_before_file_read() {
  let tenant_limit = CALIBRATION_ARTIFACT_CONTROL_CHARGE - 1;
  let domain = ResourceDomain::new(
    DomainResources::ZERO.with(DomainResource::Control, 1024 * 1024),
    1,
  )
  .expect("calibration refusal domain");
  let tenant_limits = DomainResources::ZERO.with(DomainResource::Control, tenant_limit);
  let tenant = domain
    .tenant(tenant_limits)
    .expect("calibration refusal tenant");
  let baseline = domain.snapshot();
  let filler = tenant
    .try_acquire(DomainResources::ZERO.with(DomainResource::Control, tenant_limit))
    .expect("fill tenant Control ceiling");
  let before = domain.snapshot();
  let source_sha = "a".repeat(64);
  let error = load_capacity_test_file(
    &tenant,
    std::path::Path::new("/path/must/not/be/opened-before-charge"),
    &"0".repeat(64),
    "steady",
    &source_sha,
    false,
  )
  .expect_err("calibration owner exceeds the Control ceiling");
  assert!(error.contains("Control charge failed"));
  assert_eq!(domain.snapshot(), before);
  drop(filler);
  assert_eq!(domain.snapshot(), baseline);
}

#[cfg(feature = "resource-feedback")]
#[test]
fn capacity_artifact_rejects_duplicate_unknown_and_zero_capacity_fields() {
  let valid = capacity_artifact("missing", "missing");
  let source_sha = "a".repeat(64);
  let identity = capacity_test_identity("steady", &source_sha, false);
  let duplicate = [
    valid.clone(),
    b"disk.units\tapplication_bytes_per_second\n".to_vec(),
  ]
  .concat();
  assert!(parse_capacity_calibration(&duplicate, &identity).is_err());
  let unknown = [valid.clone(), b"other\tvalue\n".to_vec()].concat();
  assert!(parse_capacity_calibration(&unknown, &identity).is_err());
  let zero = String::from_utf8(valid)
    .expect("valid artifact UTF-8")
    .replace("disk.bytes_per_second\t1000000", "disk.bytes_per_second\t0")
    .into_bytes();
  assert!(parse_capacity_calibration(&zero, &identity).is_err());
}

#[cfg(feature = "resource-feedback")]
#[test]
fn capacity_artifact_read_rejects_symlinks_and_oversized_files() {
  use std::os::unix::fs::symlink;
  use std::sync::atomic::{AtomicU64, Ordering};

  static NEXT_DIR: AtomicU64 = AtomicU64::new(1);
  let directory = std::env::temp_dir().join(format!(
    "allocatbelt-calibration-test-{}-{}",
    std::process::id(),
    NEXT_DIR.fetch_add(1, Ordering::Relaxed),
  ));
  std::fs::create_dir(&directory).expect("create calibration test directory");
  let regular = directory.join("regular.tsv");
  std::fs::write(&regular, b"bounded calibration bytes\n").expect("write calibration artifact");
  assert_eq!(
    read_capacity_calibration(&regular).expect("read regular artifact"),
    b"bounded calibration bytes\n"
  );
  let link = directory.join("linked.tsv");
  symlink(&regular, &link).expect("create symlink fixture");
  assert!(read_capacity_calibration(&link).is_err());
  let oversized = directory.join("oversized.tsv");
  std::fs::write(
    &oversized,
    vec![b'x'; MAX_CAPACITY_CALIBRATION_BYTES as usize + 1],
  )
  .expect("write oversized artifact");
  assert!(read_capacity_calibration(&oversized).is_err());
  std::fs::remove_dir_all(directory).expect("remove calibration test directory");
}
