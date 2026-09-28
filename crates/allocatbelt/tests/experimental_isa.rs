//! The experimental ISA policy (directive Phase F): an experimental kernel
//! set is selected only when it is compiled in, the CPU exposes its
//! extension, and the policy asks for it; the allocator behaves the same
//! with it.
//!
//! `ALLOCATBELT_EXPECT_KERNEL` (`Baseline`, `Sve` or `Sve2`), set by
//! `scripts/check-experimental-isa.sh` for each emulated CPU, names the set
//! `Prefer` must select, so that a detection failure cannot make these
//! checks pass by selecting nothing.

use std::time::{Duration, Instant};

use allocatbelt::{
  Allocatbelt, Availability, Capability, CpuFeatures, FeaturePolicy, KernelSet, Policy, PolicyError,
};

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

/// The set `Prefer` selects here, from what is compiled and detected.
fn selectable() -> KernelSet {
  let c = GLOBAL.compiled_capabilities();
  let f = GLOBAL.cpu_features();
  let sve = f.contains(CpuFeatures::SVE);
  if c.experimental_aarch64_sve2 && sve && f.contains(CpuFeatures::SVE2) {
    KernelSet::Sve2
  } else if c.experimental_aarch64_sve && sve {
    KernelSet::Sve
  } else {
    KernelSet::Baseline
  }
}

fn with(experimental_isa: FeaturePolicy) -> Policy {
  let mut p = Policy::DEFAULT;
  p.experimental_isa = experimental_isa;
  p
}

/// Frees 8 MiB of page runs and waits until decay passes (not the dirty
/// budget, which is larger) have returned them: the decay pass's age scan
/// runs on the selected kernel set.
fn decay_returns_memory() {
  GLOBAL.set_purge_delay(Duration::from_secs(3600));
  let blocks: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8 | 1; 1 << 20]).collect();
  assert!(blocks.iter().all(|b| b.iter().all(|&x| x == b[0])));
  drop(blocks);
  assert!(GLOBAL.dirty_bytes() >= 8 << 20);
  GLOBAL.set_purge_delay(Duration::from_millis(20));
  let deadline = Instant::now() + Duration::from_secs(10);
  // At most the churn below stays dirty.
  while GLOBAL.dirty_bytes() > 1 << 20 {
    assert!(
      Instant::now() < deadline,
      "decay did not return the memory: {} bytes dirty",
      GLOBAL.dirty_bytes()
    );
    // Page-run allocations are slow-path operations, which run due decay
    // passes when no maintenance thread does.
    std::hint::black_box(vec![1u8; 256 << 10]);
    std::thread::sleep(Duration::from_millis(2));
  }
  GLOBAL.set_purge_delay(Duration::from_secs(1));
}

/// One test, so that no other test changes the policy meanwhile.
#[test]
fn experimental_kernels_need_compile_time_cpu_and_policy() {
  let v = vec![0u64; 64];
  let expected = selectable();
  if let Ok(name) = std::env::var("ALLOCATBELT_EXPECT_KERNEL") {
    assert_eq!(format!("{expected:?}"), name, "{:?}", GLOBAL.cpu_features());
  }

  // `Auto` (the default) and `Disable` keep the baseline.
  assert_eq!(GLOBAL.policy(), Policy::DEFAULT);
  assert_eq!(GLOBAL.kernel_set(), KernelSet::Baseline);
  GLOBAL.configure(with(FeaturePolicy::Disable)).unwrap();
  assert_eq!(GLOBAL.kernel_set(), KernelSet::Baseline);

  // `Prefer` takes what is there, falling back to the baseline.
  GLOBAL.configure(with(FeaturePolicy::Prefer)).unwrap();
  assert_eq!(GLOBAL.kernel_set(), expected);
  assert_eq!(GLOBAL.effective_profile().kernel_set, expected);
  let report = GLOBAL.report();
  assert_eq!(
    report.detected.experimental_isa,
    match expected {
      _ if !report.compiled.experimental_aarch64_sve => Availability::NotCompiled,
      KernelSet::Baseline => Availability::Unavailable {
        step: "cpu features",
        errno: 0,
      },
      _ => Availability::Available,
    }
  );
  let text = report.to_string();
  eprintln!("{text}");
  assert!(
    text.contains(&format!("kernel_set: {expected:?}")),
    "{text}"
  );
  assert!(text.contains("experimental_isa: compiled="), "{text}");
  decay_returns_memory();

  // `Require` selects it, or fails and changes nothing.
  GLOBAL.configure(Policy::DEFAULT).unwrap();
  match GLOBAL.configure(with(FeaturePolicy::Require)) {
    Ok(()) => {
      assert_ne!(expected, KernelSet::Baseline);
      assert_eq!(GLOBAL.kernel_set(), expected);
      decay_returns_memory();
    }
    Err(e) => {
      assert_eq!(expected, KernelSet::Baseline);
      let capability = Capability::ExperimentalIsa;
      if report.compiled.experimental_aarch64_sve {
        assert_eq!(
          e,
          PolicyError::Unavailable {
            capability,
            step: "cpu features",
            errno: 0,
          }
        );
      } else {
        assert_eq!(e, PolicyError::NotCompiled { capability });
      }
      assert_eq!(GLOBAL.policy(), Policy::DEFAULT);
    }
  }

  // Back to the baseline at any time, also with the maintenance thread
  // running: the kernels compute the same results.
  #[cfg(feature = "maintenance")]
  assert!(GLOBAL.start_maintenance_thread().unwrap());
  GLOBAL.configure(with(FeaturePolicy::Prefer)).unwrap();
  assert_eq!(GLOBAL.kernel_set(), expected);
  decay_returns_memory();
  GLOBAL.configure(Policy::DEFAULT).unwrap();
  assert_eq!(GLOBAL.kernel_set(), KernelSet::Baseline);
  decay_returns_memory();
  assert_eq!(v.len(), 64);
}
