//! CPU feature discovery and architecture kernel dispatch for allocatbelt.
//!
//! This module is the architecture boundary of the allocator: it finds out,
//! without allocating, which ISA extensions the running CPU and kernel
//! support, and publishes which set of architecture kernels the allocator
//! may use. The `core` module stays `#![forbid(unsafe_code)]` and never sees
//! vector types; the few `unsafe` operations detection needs live here and
//! are listed in `docs/unsafe-boundary.md`.
//!
//! ```text
//! allocations before initialize_dispatch()  -> KernelSet::Baseline
//! initialize_dispatch()                     -> probe once
//! afterwards                                -> kernel_set(): Baseline, or
//!                                              an experimental set if the
//!                                              policy asks for one
//! ```
//!
//! A detected feature does not mean an optimized kernel exists for it. A
//! kernel becomes a default only with benchmark evidence that it speeds up
//! a measured allocator cost, and none has (plan phase 5, see
//! `docs/research/simd-benchmarks.md`), so the default is always
//! [`KernelSet::Baseline`]. The experimental sets (directive Phase F) are
//! compiled only with their Cargo feature and selected only when
//! [`crate::Policy::experimental_isa`] is `Prefer` or `Require` and the
//! process sees the extension:
//!
//! ```text
//! compiled ∩ detected ∩ experimental policy = selectable
//! ```
//!
//! Every set computes the same results ([`crate::core::aged_pages`]), so
//! the selection may change at any time.

#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::FeaturePolicy;
use crate::core::AgeKernel;

mod features;

#[cfg(test)]
mod allocation_free;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(all(target_arch = "aarch64", feature = "experimental-aarch64-sve"))]
mod sve;
#[cfg(target_arch = "x86_64")]
mod x86_64;

pub use features::CpuFeatures;

/// The set of architecture kernels the allocator dispatches to.
///
/// Every variant exists in every build, so that matching on it does not
/// depend on the features another crate turns on; a set whose feature is
/// not compiled in is never reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KernelSet {
  /// Portable scalar code only. Always correct, the default, and what
  /// every allocation uses before [`initialize_dispatch`] has run.
  Baseline,
  /// Experimental (feature `experimental-aarch64-sve`): the decay pass's
  /// age scan compiled for SVE. Not measured.
  Sve,
  /// Experimental (feature `experimental-aarch64-sve2`): as `Sve`, compiled
  /// for SVE2. Not measured.
  Sve2,
}

/// Detection result, with [`DETECTED`] set once it is valid.
static FEATURES: AtomicU32 = AtomicU32::new(0);
const DETECTED: u32 = 1 << 31;

/// Set by [`initialize_dispatch`]: kernels other than the baseline may be
/// selected from then on.
static DISPATCH: AtomicBool = AtomicBool::new(false);

/// The features of the running CPU and kernel, probed on first use and
/// cached. Allocation-free, and never probes again once cached; concurrent
/// first calls may each probe, and store the same result.
#[must_use]
pub fn detected_features() -> CpuFeatures {
  let cached = FEATURES.load(Ordering::Acquire);
  if cached & DETECTED != 0 {
    return CpuFeatures::from_bits(cached);
  }
  let features = detect();
  FEATURES.store(features.bits() | DETECTED, Ordering::Release);
  features
}

/// Probes the CPU (once) and lets [`kernel_set`] select kernels from now
/// on. Allocation-free and idempotent; call it before worker threads
/// start. Allocations that happen earlier use the baseline.
pub fn initialize_dispatch() -> KernelSet {
  let _ = detected_features();
  DISPATCH.store(true, Ordering::Release);
  kernel_set()
}

/// The kernel set in use: [`KernelSet::Baseline`] before
/// [`initialize_dispatch`], and afterwards unless the experimental ISA
/// policy selects one. Two atomic loads; never probes.
#[must_use]
pub fn kernel_set() -> KernelSet {
  if !DISPATCH.load(Ordering::Acquire) {
    return KernelSet::Baseline;
  }
  select(detected_features(), crate::policy::experimental_isa())
}

/// The kernel set that `policy` selects on a CPU with `features`.
fn select(features: CpuFeatures, policy: FeaturePolicy) -> KernelSet {
  match policy {
    FeaturePolicy::Prefer | FeaturePolicy::Require => {
      experimental(features).unwrap_or(KernelSet::Baseline)
    }
    _ => KernelSet::Baseline,
  }
}

/// The best experimental kernel set that is compiled in and runs on a CPU
/// with `features`, if any.
pub(crate) fn experimental(features: CpuFeatures) -> Option<KernelSet> {
  #[cfg(all(target_arch = "aarch64", feature = "experimental-aarch64-sve2"))]
  if features.contains(CpuFeatures::SVE) && features.contains(CpuFeatures::SVE2) {
    return Some(KernelSet::Sve2);
  }
  #[cfg(all(target_arch = "aarch64", feature = "experimental-aarch64-sve"))]
  if features.contains(CpuFeatures::SVE) {
    return Some(KernelSet::Sve);
  }
  let _ = features;
  None
}

/// Whether an experimental kernel set is compiled into this build for this
/// architecture.
pub(crate) const EXPERIMENTAL_COMPILED: bool = cfg!(all(
  target_arch = "aarch64",
  feature = "experimental-aarch64-sve"
));

/// The age kernel of the kernel set in use, if it has one (see
/// `Os::age_kernel`).
pub(crate) fn age_kernel() -> Option<AgeKernel> {
  #[cfg(all(target_arch = "aarch64", feature = "experimental-aarch64-sve"))]
  return sve::age_kernel();
  #[cfg(not(all(target_arch = "aarch64", feature = "experimental-aarch64-sve")))]
  None
}

#[cfg(target_arch = "x86_64")]
fn detect() -> CpuFeatures {
  x86_64::detect()
}

#[cfg(target_arch = "aarch64")]
fn detect() -> CpuFeatures {
  aarch64::detect()
}

#[cfg(target_arch = "riscv64")]
fn detect() -> CpuFeatures {
  riscv64::detect()
}

/// Other architectures are rejected by the `sys` module; report nothing.
#[cfg(not(any(
  target_arch = "x86_64",
  target_arch = "aarch64",
  target_arch = "riscv64"
)))]
fn detect() -> CpuFeatures {
  CpuFeatures::empty()
}

#[cfg(test)]
mod tests {
  use super::{
    CpuFeatures, FeaturePolicy, KernelSet, detected_features, experimental, initialize_dispatch,
    kernel_set, select,
  };

  #[test]
  fn dispatch_is_baseline_by_default_and_idempotent() {
    assert_eq!(initialize_dispatch(), KernelSet::Baseline);
    assert_eq!(initialize_dispatch(), KernelSet::Baseline);
    assert_eq!(kernel_set(), KernelSet::Baseline);
  }

  #[test]
  fn detection_is_cached() {
    assert_eq!(detected_features(), detected_features());
  }

  /// Only `Prefer` and `Require` select an experimental set, and only one
  /// that is compiled in and detected.
  #[test]
  fn only_an_experimental_policy_selects_experimental_kernels() {
    let all = [
      CpuFeatures::empty(),
      CpuFeatures::empty().with_if(CpuFeatures::SVE, true),
      CpuFeatures::empty()
        .with_if(CpuFeatures::SVE, true)
        .with_if(CpuFeatures::SVE2, true),
      CpuFeatures::empty().with_if(CpuFeatures::SVE2, true),
    ];
    for f in all {
      for p in [FeaturePolicy::Auto, FeaturePolicy::Disable] {
        assert_eq!(select(f, p), KernelSet::Baseline);
      }
      for p in [FeaturePolicy::Prefer, FeaturePolicy::Require] {
        assert_eq!(select(f, p), experimental(f).unwrap_or(KernelSet::Baseline));
      }
    }
    let sve = cfg!(all(
      target_arch = "aarch64",
      feature = "experimental-aarch64-sve"
    ));
    let sve2 = cfg!(all(
      target_arch = "aarch64",
      feature = "experimental-aarch64-sve2"
    ));
    assert_eq!(experimental(all[0]), None);
    assert_eq!(experimental(all[1]), sve.then_some(KernelSet::Sve));
    assert_eq!(
      experimental(all[2]),
      if sve2 {
        Some(KernelSet::Sve2)
      } else {
        sve.then_some(KernelSet::Sve)
      }
    );
    // SVE2 without SVE is not a state Linux reports; nothing is selected.
    assert_eq!(experimental(all[3]), None);
  }
}
