//! The start-up probe of the platform contract (docs/platform.md).

use allocatbelt::Allocatbelt;

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

#[test]
fn probe_ran_before_the_first_allocation() {
  let v = vec![1u8; 4096];
  let caps = GLOBAL
    .platform()
    .expect("the allocator initialised without its arena");
  assert!(
    caps.kernel.is_some(),
    "unparseable kernel release: {caps:?}"
  );
  assert_eq!(v.iter().map(|&b| usize::from(b)).sum::<usize>(), 4096);
}

#[test]
fn dispatch_is_initialised_with_the_arena() {
  let v: Vec<u64> = (0..16).collect();
  assert_eq!(GLOBAL.kernel_set(), allocatbelt::KernelSet::Baseline);
  let features = GLOBAL.cpu_features();
  #[cfg(target_arch = "x86_64")]
  assert!(
    features.contains(allocatbelt::CpuFeatures::X86_64_V3),
    "{features:?}"
  );
  #[cfg(target_arch = "aarch64")]
  assert!(
    features.contains(allocatbelt::CpuFeatures::ASIMD),
    "{features:?}"
  );
  #[cfg(target_arch = "riscv64")]
  let _ = features;
  assert_eq!(v.len(), 16);
}

#[test]
fn compiled_capabilities_follow_the_features() {
  let c = GLOBAL.compiled_capabilities();
  assert_eq!(c.runtime, cfg!(feature = "runtime"));
  assert_eq!(c.runtime_io_uring, cfg!(feature = "runtime-io-uring"));
  assert_eq!(c, allocatbelt::CompiledCapabilities::CURRENT);
  assert_eq!(c.maintenance, cfg!(feature = "maintenance"));
  assert_eq!(c.scheduler, cfg!(feature = "scheduler"));
  assert_eq!(c.io_uring, cfg!(feature = "io-uring"));
  assert_eq!(c.rseq, cfg!(feature = "experimental-rseq"));
  // ISA backends count only on their architecture.
  let aarch64 = cfg!(target_arch = "aarch64");
  assert_eq!(
    c.experimental_aarch64_sve,
    aarch64 && cfg!(feature = "experimental-aarch64-sve")
  );
  assert_eq!(
    c.experimental_aarch64_sve2,
    aarch64 && cfg!(feature = "experimental-aarch64-sve2")
  );
  assert_eq!(
    c.experimental_riscv_rvv,
    cfg!(all(
      target_arch = "riscv64",
      feature = "experimental-riscv-rvv"
    ))
  );
  // Features that imply others.
  assert!(!c.scheduler || c.maintenance);
  assert!(!c.io_uring || c.maintenance);
  assert!(!c.runtime_io_uring || c.runtime);
  assert!(!c.experimental_aarch64_sve2 || c.experimental_aarch64_sve);
}

#[test]
fn policy_moves_only_within_the_build() {
  let c = GLOBAL.compiled_capabilities();
  assert_eq!(c.runtime, cfg!(feature = "runtime"));
  let mut p = allocatbelt::Policy::DEFAULT;
  p.io_uring = allocatbelt::FeaturePolicy::Require;
  let r = GLOBAL.configure(p);
  if c.io_uring {
    assert_eq!(r, Ok(()));
  } else {
    assert_eq!(
      r,
      Err(allocatbelt::PolicyError::NotCompiled {
        capability: allocatbelt::Capability::IoUring
      })
    );
  }
  GLOBAL.configure(allocatbelt::Policy::DEFAULT).unwrap();
  let d = GLOBAL.detected_capabilities();
  if !c.maintenance {
    assert_eq!(d.maintenance, allocatbelt::Availability::NotCompiled);
  }
  let text = GLOBAL.report().to_string();
  assert!(text.contains("policy_frozen: false"), "{text}");
}
