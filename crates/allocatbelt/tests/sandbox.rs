//! Sandbox and virtualization qualification (directive Phase E, §8, §17):
//! the allocator needs no extra privilege, optional capabilities that a
//! sandbox denies fall back (or fail cleanly under `Require`), and only what
//! the current process sees counts.
//!
//! Most tests here assert the behaviour of one environment, which
//! `scripts/check-sandbox.sh` sets up (a hardened Docker container with a
//! given seccomp profile, or a qemu-user CPU model) and names in
//! `ALLOCATBELT_SANDBOX`; elsewhere they return at once. The script runs
//! each in a process of its own (`--exact`), because a process starts the
//! maintenance thread only once. `no_hidden_host_probes` runs everywhere.

use allocatbelt::Allocatbelt;

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

/// Whether the script set up environment `name` for this process.
fn in_sandbox(name: &str) -> bool {
  let set = std::env::var("ALLOCATBELT_SANDBOX").ok();
  if set.as_deref() != Some(name) {
    eprintln!("not in sandbox {name:?} ({set:?}): nothing to check");
    return false;
  }
  true
}

/// The scenarios that start the maintenance thread.
#[cfg(feature = "maintenance")]
mod maintenance {
  use std::time::{Duration, Instant};

  use allocatbelt::{Availability, Policy};
  #[cfg(any(feature = "io-uring", feature = "scheduler"))]
  use allocatbelt::{Capability, FeaturePolicy, PolicyError};

  use super::{GLOBAL, in_sandbox};

  fn wait_for(done: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
      if Instant::now() > deadline {
        return false;
      }
      std::thread::sleep(Duration::from_millis(5));
    }
    true
  }

  /// Churns 48 MiB through the allocator and checks that the maintenance
  /// thread returns it: the allocator works whatever the backend.
  fn churn_and_purge() {
    let bufs: Vec<Vec<u8>> = (0..48).map(|i| vec![i as u8 | 1; 1 << 20]).collect();
    assert!(bufs.iter().all(|b| b.iter().all(|&x| x == b[0])));
    drop(bufs);
    GLOBAL.request_purge();
    assert!(
      wait_for(|| GLOBAL.dirty_bytes() == 0),
      "memory not returned"
    );
  }

  /// Starts the maintenance thread with `policy`, expecting it to fail with
  /// `expected`; checks that no thread was left and the policy stays open.
  #[cfg(any(feature = "io-uring", feature = "scheduler"))]
  fn start_fails(policy: Policy, expected: &PolicyError) {
    GLOBAL.configure(policy).unwrap();
    let err = GLOBAL.start_maintenance_thread().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported, "{err}");
    let got = err.get_ref().and_then(|e| e.downcast_ref::<PolicyError>());
    assert_eq!(got, Some(expected), "{err}");
    let e = GLOBAL.effective_profile();
    assert!(!e.maintenance && !e.frozen, "{e:?}");
    assert_eq!(e.purge_backend, allocatbelt::PurgeBackend::NotStarted);
  }

  /// A hardened container: unprivileged user, every capability dropped,
  /// read-only root, `no-new-privileges`, no network, Docker's default
  /// seccomp profile. The allocator, the maintenance thread and `SCHED_BATCH`
  /// (which lowers priority and needs no capability) work unchanged.
  #[test]
  fn hardened_container_needs_no_privilege() {
    if !in_sandbox("hardened") {
      return;
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    for line in status.lines() {
      if line.starts_with("CapEff:") || line.starts_with("CapPrm:") {
        assert!(
          line.ends_with("0000000000000000"),
          "{line}: not unprivileged"
        );
      }
      if line.starts_with("NoNewPrivs:") {
        assert!(line.ends_with('1'), "{line}");
      }
    }
    assert!(GLOBAL.start_maintenance_thread().unwrap());
    let d = GLOBAL.detected_capabilities();
    eprintln!("{}", GLOBAL.report());
    assert_eq!(d.maintenance, Availability::Available);
    if GLOBAL.compiled_capabilities().scheduler {
      assert_eq!(d.scheduler, Availability::Available);
      assert!(GLOBAL.maintenance_is_batch());
    }
    // `Auto` never tries the ring.
    assert!(matches!(
      d.io_uring,
      Availability::NotTried | Availability::NotCompiled
    ));
    churn_and_purge();
  }

  /// Docker's default seccomp profile denies io_uring with `EPERM`: `Require`
  /// fails cleanly, `Prefer` falls back to `madvise` and says why.
  #[test]
  #[cfg(feature = "io-uring")]
  fn io_uring_denied_falls_back() {
    if !in_sandbox("hardened") {
      return;
    }
    let mut p = Policy::DEFAULT;
    p.io_uring = FeaturePolicy::Require;
    start_fails(
      p,
      &PolicyError::Unavailable {
        capability: Capability::IoUring,
        step: "setup",
        errno: 1,
      },
    );
    p.io_uring = FeaturePolicy::Prefer;
    GLOBAL.configure(p).unwrap();
    assert!(GLOBAL.start_maintenance_thread().unwrap());
    eprintln!("{}", GLOBAL.report());
    assert_eq!(
      GLOBAL.detected_capabilities().io_uring,
      Availability::Unavailable {
        step: "setup",
        errno: 1
      }
    );
    assert!(wait_for(
      || GLOBAL.purge_backend() == allocatbelt::PurgeBackend::Madvise
    ));
    let e = GLOBAL.io_uring_error().unwrap();
    assert_eq!((e.step, e.errno), ("setup", 1));
    churn_and_purge();
  }

  /// A seccomp profile that allows io_uring (`io-uring-allowed.json`):
  /// `Require` gets the restricted ring.
  #[test]
  #[cfg(feature = "io-uring")]
  fn io_uring_allowed_is_used() {
    if !in_sandbox("io-uring-allowed") {
      return;
    }
    let mut p = Policy::DEFAULT;
    p.io_uring = FeaturePolicy::Require;
    GLOBAL.configure(p).unwrap();
    assert!(GLOBAL.start_maintenance_thread().unwrap());
    eprintln!("{}", GLOBAL.report());
    assert_eq!(
      GLOBAL.detected_capabilities().io_uring,
      Availability::Available
    );
    assert!(wait_for(|| matches!(
      GLOBAL.purge_backend(),
      allocatbelt::PurgeBackend::IoUring { .. }
    )));
    churn_and_purge();
  }

  /// A seccomp profile that kills the process on `io_uring_setup`
  /// (`io-uring-kill.json`): `Disable` must never call it, and neither must
  /// `Auto`, the default.
  #[test]
  #[cfg(feature = "io-uring")]
  fn io_uring_disabled_never_calls_setup() {
    if !in_sandbox("io-uring-kill") {
      return;
    }
    let mut p = Policy::DEFAULT;
    p.io_uring = FeaturePolicy::Disable;
    GLOBAL.configure(p).unwrap();
    assert!(GLOBAL.start_maintenance_thread().unwrap());
    assert_eq!(
      GLOBAL.detected_capabilities().io_uring,
      Availability::NotTried
    );
    churn_and_purge();
  }

  /// As [`io_uring_disabled_never_calls_setup`], with the default policy.
  #[test]
  fn io_uring_auto_never_calls_setup() {
    if !in_sandbox("io-uring-kill") {
      return;
    }
    assert_eq!(GLOBAL.policy(), Policy::DEFAULT);
    assert!(GLOBAL.start_maintenance_thread().unwrap());
    churn_and_purge();
  }

  /// A seccomp profile that refuses `sched_setscheduler` with `EPERM`
  /// (`no-sched.json`): `Require` fails cleanly, `Auto` keeps the default
  /// scheduling policy and says why.
  #[test]
  #[cfg(feature = "scheduler")]
  fn scheduler_denied_falls_back() {
    if !in_sandbox("no-sched") {
      return;
    }
    let mut p = Policy::DEFAULT;
    p.scheduler = FeaturePolicy::Require;
    start_fails(
      p,
      &PolicyError::Unavailable {
        capability: Capability::Scheduler,
        step: "sched_setscheduler",
        errno: 1,
      },
    );
    GLOBAL.configure(Policy::DEFAULT).unwrap();
    assert!(GLOBAL.start_maintenance_thread().unwrap());
    eprintln!("{}", GLOBAL.report());
    assert!(!GLOBAL.maintenance_is_batch());
    assert_eq!(
      GLOBAL.detected_capabilities().scheduler,
      Availability::Unavailable {
        step: "sched_setscheduler",
        errno: 1
      }
    );
    churn_and_purge();
  }
}

/// Under a qemu-user CPU model that exposes less than the host (a guest
/// view): only the exposed ISA is detected. `ALLOCATBELT_EXPECT_CPU` lists
/// feature names that must be present (`+name`) or absent (`-name`).
#[test]
fn only_the_visible_isa_is_detected() {
  if !in_sandbox("visible-isa") {
    return;
  }
  let expect = std::env::var("ALLOCATBELT_EXPECT_CPU").unwrap();
  let seen = format!("{:?}", GLOBAL.cpu_features());
  eprintln!("cpu_features under emulation: {seen}");
  for item in expect.split(',').filter(|s| !s.is_empty()) {
    let (want, name) = item.split_at(1);
    let has = seen.contains(&format!("\"{name}\""));
    assert_eq!(has, want == "+", "{name}: expected {want}, saw {seen}");
  }
  // No kernel is dispatched on detection alone.
  assert_eq!(GLOBAL.kernel_set(), allocatbelt::KernelSet::Baseline);
}

/// Nothing in the allocator looks past the current process: no hypervisor
/// identity, no host topology files, no CPU count to size structures by.
/// Checked on the sources, which the package ships.
#[test]
fn no_hidden_host_probes() {
  let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
  let forbidden = [
    "/proc/cpuinfo",
    "/sys/devices",
    "/sys/hypervisor",
    "/sys/class/dmi",
    "0x4000_0000",
    "0x40000000",
    "sched_getaffinity",
    "_SC_NPROCESSORS",
    "num_cpus",
  ];
  let mut files = 0;
  let mut dirs = vec![src];
  while let Some(dir) = dirs.pop() {
    for entry in std::fs::read_dir(&dir).unwrap() {
      let path = entry.unwrap().path();
      if path.is_dir() {
        dirs.push(path);
        continue;
      }
      let text = std::fs::read_to_string(&path).unwrap();
      files += 1;
      for f in forbidden {
        assert!(!text.contains(f), "{} mentions {f}", path.display());
      }
      // CPU counts only in benchmarks and tests of the core, which are
      // compiled by allocatbelt-core-check, not into the allocator.
      if text.contains("available_parallelism") {
        assert!(path.ends_with("core/lock.rs"), "{}", path.display());
        let first = text.find("available_parallelism").unwrap();
        let tests = text.find("#[cfg(all(test").unwrap_or(usize::MAX);
        assert!(first > tests, "available_parallelism outside tests");
      }
    }
  }
  assert!(files > 20, "only {files} source files found");
}
