//! Experimental SVE and SVE2 kernels (features `experimental-aarch64-sve`
//! and `experimental-aarch64-sve2`, directive Phase F).
//!
//! SVE intrinsics are not stable in Rust, so each kernel is the portable
//! loop ([`aged_pages`]) compiled inside a `#[target_feature]` function,
//! which lets LLVM use SVE's scalable vectors for it: the technique of the
//! `sve-autovec` candidates in `bench/simd`, on stable Rust. The kernels
//! compute the same results as the portable loop; they have not been
//! measured and are never selected by default.

use crate::arch::KernelSet;
use crate::core::{AgeKernel, PAGES_PER_SEGMENT, aged_pages};

/// The age kernel of the kernel set in use. [`super::kernel_set`] reports
/// `Sve` or `Sve2` only when the CPU and kernel expose that extension
/// (`AT_HWCAP`), which is what makes calling these kernels sound.
pub(super) fn age_kernel() -> Option<AgeKernel> {
  match super::kernel_set() {
    KernelSet::Sve => Some(aged_pages_sve),
    #[cfg(feature = "experimental-aarch64-sve2")]
    KernelSet::Sve2 => Some(aged_pages_sve2),
    _ => None,
  }
}

/// [`aged_pages`] compiled for SVE. Only reached through [`age_kernel`].
fn aged_pages_sve(since: &[u64; PAGES_PER_SEGMENT], cutoff: u64) -> u64 {
  // SAFETY: `age_kernel` returns this kernel only for `KernelSet::Sve`,
  // which is selected only when the auxiliary vector reports SVE
  // (`HWCAP_SVE`), so the CPU and kernel run SVE instructions.
  #[expect(unsafe_code, reason = "calling an SVE target-feature function")]
  unsafe {
    aged_pages_sve_body(since, cutoff)
  }
}

#[target_feature(enable = "sve")]
fn aged_pages_sve_body(since: &[u64; PAGES_PER_SEGMENT], cutoff: u64) -> u64 {
  aged_pages(since, cutoff)
}

/// [`aged_pages`] compiled for SVE2. Only reached through [`age_kernel`].
#[cfg(feature = "experimental-aarch64-sve2")]
fn aged_pages_sve2(since: &[u64; PAGES_PER_SEGMENT], cutoff: u64) -> u64 {
  // SAFETY: `age_kernel` returns this kernel only for `KernelSet::Sve2`,
  // which is selected only when the auxiliary vector reports SVE and SVE2
  // (`HWCAP_SVE`, `HWCAP2_SVE2`).
  #[expect(unsafe_code, reason = "calling an SVE2 target-feature function")]
  unsafe {
    aged_pages_sve2_body(since, cutoff)
  }
}

#[cfg(feature = "experimental-aarch64-sve2")]
#[target_feature(enable = "sve2")]
fn aged_pages_sve2_body(since: &[u64; PAGES_PER_SEGMENT], cutoff: u64) -> u64 {
  aged_pages(since, cutoff)
}

#[cfg(test)]
mod tests {
  use crate::arch::CpuFeatures;
  use crate::arch::kernel_tests::check;

  #[test]
  fn sve_kernel_matches_the_portable_loop() {
    if !crate::arch::detected_features().contains(CpuFeatures::SVE) {
      eprintln!("SVE not exposed to this process: nothing to check");
      return;
    }
    check("sve", super::aged_pages_sve);
  }

  #[test]
  #[cfg(feature = "experimental-aarch64-sve2")]
  fn sve2_kernel_matches_the_portable_loop() {
    let f = crate::arch::detected_features();
    if !(f.contains(CpuFeatures::SVE) && f.contains(CpuFeatures::SVE2)) {
      eprintln!("SVE2 not exposed to this process: nothing to check");
      return;
    }
    check("sve2", super::aged_pages_sve2);
  }
}
