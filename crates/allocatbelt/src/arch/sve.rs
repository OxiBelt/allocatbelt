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
  use crate::core::{AgeKernel, PAGES_PER_SEGMENT, aged_pages};

  /// Checks `kernel` against the portable loop: every cutoff around each
  /// age of a few layouts, including the extremes.
  fn check(name: &str, kernel: AgeKernel) {
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let mut layouts: Vec<[u64; PAGES_PER_SEGMENT]> = vec![
      [0; PAGES_PER_SEGMENT],
      [u64::MAX; PAGES_PER_SEGMENT],
      core::array::from_fn(|i| i as u64),
      core::array::from_fn(|i| (PAGES_PER_SEGMENT - i) as u64),
      core::array::from_fn(|i| if i % 2 == 0 { 0 } else { u64::MAX }),
      core::array::from_fn(|i| 1 << (i % 64)),
    ];
    for _ in 0..64 {
      layouts.push(core::array::from_fn(|_| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        // Mostly small epochs, as a decay counter has, with some extremes.
        match x % 16 {
          0 => u64::MAX,
          1 => 0,
          _ => x % 40,
        }
      }));
    }
    for since in &layouts {
      let mut cutoffs = vec![0, 1, u64::MAX - 1, u64::MAX];
      for &t in since {
        cutoffs.extend([t.saturating_sub(1), t, t.saturating_add(1)]);
      }
      for cutoff in cutoffs {
        assert_eq!(
          kernel(since, cutoff),
          aged_pages(since, cutoff),
          "{name}: cutoff {cutoff}, ages {since:?}"
        );
      }
    }
  }

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
