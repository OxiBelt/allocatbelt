use super::*;

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
fn capacity_artifact_hash_covers_exact_bytes_and_qualification_requires_both_directions() {
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
  assert!(
    load_capacity_test_file(
      &tenant,
      &missing_path,
      &missing_hash,
      "steady",
      &source_sha,
      true,
    )
    .is_err()
  );
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
