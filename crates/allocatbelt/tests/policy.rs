//! The run-time policy (directive Phase D): `Require` of what is not
//! compiled in fails, the maintenance thread applies `scheduler` and
//! `io_uring` and freezes them, a failed `Require` leaves no thread and the
//! policy changeable, and the report shows compiled, detected and
//! effective capabilities. A separate test binary, because it starts the
//! maintenance thread.

use std::time::{Duration, Instant};

use allocatbelt::{
  Allocatbelt, Availability, Capability, FeaturePolicy, Policy, PolicyError, PurgeBackend,
};

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

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

#[test]
fn policy_is_applied_within_the_compiled_capabilities() {
  // Early allocations ran under the default policy.
  let early = vec![7u8; 1 << 16];
  assert_eq!(GLOBAL.policy(), Policy::DEFAULT);
  let e = GLOBAL.effective_profile();
  assert!(!e.frozen && !e.maintenance && !e.scheduler && !e.rseq);
  assert_eq!(e.purge_backend, PurgeBackend::NotStarted);

  // `Require` of a capability this build lacks fails and changes nothing.
  let compiled = GLOBAL.compiled_capabilities();
  for (capability, has, set) in [
    (
      Capability::Scheduler,
      compiled.scheduler,
      (|p: &mut Policy| p.scheduler = FeaturePolicy::Require) as fn(&mut Policy),
    ),
    (Capability::IoUring, compiled.io_uring, |p| {
      p.io_uring = FeaturePolicy::Require
    }),
    (Capability::Rseq, compiled.rseq, |p| {
      p.rseq = FeaturePolicy::Require
    }),
  ] {
    let mut p = Policy::DEFAULT;
    set(&mut p);
    let r = GLOBAL.configure(p);
    if !has {
      assert_eq!(r, Err(PolicyError::NotCompiled { capability }));
    }
    GLOBAL.configure(Policy::DEFAULT).unwrap();
  }
  assert_eq!(GLOBAL.policy(), Policy::DEFAULT);

  // Scheduler off; the ring required where it is compiled in.
  let mut p = Policy::DEFAULT;
  p.scheduler = FeaturePolicy::Disable;
  if compiled.io_uring {
    p.io_uring = FeaturePolicy::Require;
  }
  GLOBAL.configure(p).unwrap();
  let started = GLOBAL.start_maintenance_thread();
  let d = GLOBAL.detected_capabilities();
  eprintln!("{}", GLOBAL.report());
  match started {
    Ok(true) => {
      if compiled.io_uring {
        assert_eq!(d.io_uring, Availability::Available);
        assert!(wait_for(|| matches!(
          GLOBAL.purge_backend(),
          PurgeBackend::IoUring { .. }
        )));
      }
    }
    Err(err) => {
      // Only the required ring can fail here (qemu-user, seccomp,
      // `kernel.io_uring_disabled`): no thread, the policy still open.
      assert!(compiled.io_uring);
      assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
      let pe = err.get_ref().and_then(|e| e.downcast_ref::<PolicyError>());
      let Some(&PolicyError::Unavailable {
        capability: Capability::IoUring,
        step,
        errno,
      }) = pe
      else {
        panic!("unexpected error {err:?}");
      };
      assert_eq!(d.io_uring, Availability::Unavailable { step, errno });
      let e = GLOBAL.effective_profile();
      assert!(!e.frozen && !e.maintenance);
      p.io_uring = FeaturePolicy::Prefer;
      GLOBAL.configure(p).unwrap();
      assert!(GLOBAL.start_maintenance_thread().unwrap());
      assert!(wait_for(|| GLOBAL.purge_backend() == PurgeBackend::Madvise));
    }
    Ok(false) => panic!("the thread was already running"),
  }
  assert!(!GLOBAL.start_maintenance_thread().unwrap(), "started twice");

  // Built from the policy, and frozen.
  let e = GLOBAL.effective_profile();
  assert!(e.frozen && e.maintenance);
  assert!(
    !e.scheduler && !GLOBAL.maintenance_is_batch(),
    "scheduler disabled"
  );
  assert_eq!(
    GLOBAL.detected_capabilities().scheduler,
    if compiled.scheduler {
      Availability::NotTried
    } else {
      Availability::NotCompiled
    }
  );
  let mut q = GLOBAL.policy();
  q.scheduler = FeaturePolicy::Prefer;
  assert_eq!(
    GLOBAL.configure(q),
    Err(PolicyError::Frozen {
      capability: Capability::Scheduler
    })
  );
  assert_eq!(GLOBAL.policy().scheduler, FeaturePolicy::Disable);
  #[cfg(feature = "io-uring")]
  assert!(GLOBAL.set_io_uring(false).is_err());

  // `rseq` stays switchable.
  let mut q = GLOBAL.policy();
  q.rseq = FeaturePolicy::Disable;
  GLOBAL.configure(q).unwrap();
  assert_eq!(GLOBAL.policy().rseq, FeaturePolicy::Disable);

  let text = GLOBAL.report().to_string();
  for line in [
    "allocator: allocatbelt",
    "maintenance: compiled=true",
    "scheduler: compiled=",
    "io_uring: compiled=",
    "rseq: compiled=",
    "policy_frozen: true",
  ] {
    assert!(text.contains(line), "{line:?} missing in\n{text}");
  }
  assert!(text.contains("scheduler: compiled=") && text.contains("policy=disable"));
  assert!(early.iter().all(|&b| b == 7));
}
