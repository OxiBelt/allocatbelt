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
  assert_eq!(c, allocatbelt::CompiledCapabilities::CURRENT);
  assert_eq!(c.maintenance, cfg!(feature = "maintenance"));
  assert_eq!(c.scheduler, cfg!(feature = "scheduler"));
  assert_eq!(c.io_uring, cfg!(feature = "io-uring"));
  assert_eq!(c.rseq, cfg!(feature = "experimental-rseq"));
  // Features that imply others.
  assert!(!c.scheduler || c.maintenance);
  assert!(!c.io_uring || c.maintenance);
}
