//! Experimental RISC-V V kernel (feature `experimental-riscv-rvv`,
//! directive Phase G).
//!
//! The portable loop ([`aged_pages`]) compiled inside a
//! `#[target_feature(enable = "v")]` function, which LLVM vectorizes with
//! RVV's length-agnostic loops. Only this function may contain V
//! instructions: the rest of the binary stays on the RV64GC baseline, so it
//! runs on CPUs without V until run-time dispatch selects the kernel. The
//! `v` target feature is unstable in Rust 1.98, so this module needs nightly
//! (`riscv_target_feature`, enabled in `lib.rs` only for this feature on
//! riscv64). Not measured, and never selected by default.

use crate::arch::KernelSet;
use crate::core::{AgeKernel, PAGES_PER_SEGMENT, aged_pages};

/// The age kernel of the kernel set in use. [`super::kernel_set`] reports
/// `Rvv` only when `riscv_hwprobe` reports V on every online CPU and the
/// kernel lets this thread use it, which is what makes calling the kernel
/// sound.
pub(super) fn age_kernel() -> Option<AgeKernel> {
  match super::kernel_set() {
    KernelSet::Rvv => Some(aged_pages_rvv),
    _ => None,
  }
}

/// [`aged_pages`] compiled for V. Only reached through [`age_kernel`].
fn aged_pages_rvv(since: &[u64; PAGES_PER_SEGMENT], cutoff: u64) -> u64 {
  // SAFETY: `age_kernel` returns this kernel only for `KernelSet::Rvv`,
  // which is selected only when `riscv_hwprobe` reports V for all online
  // CPUs and `PR_RISCV_V_GET_CONTROL` does not report it turned off for
  // this thread, so V instructions execute.
  #[expect(unsafe_code, reason = "calling a V target-feature function")]
  unsafe {
    aged_pages_rvv_body(since, cutoff)
  }
}

#[target_feature(enable = "v")]
fn aged_pages_rvv_body(since: &[u64; PAGES_PER_SEGMENT], cutoff: u64) -> u64 {
  aged_pages(since, cutoff)
}

#[cfg(test)]
mod tests {
  use crate::arch::CpuFeatures;

  #[test]
  fn rvv_kernel_matches_the_portable_loop() {
    if !crate::arch::detected_features().contains(CpuFeatures::RVV) {
      eprintln!("V not usable by this process: nothing to check");
      return;
    }
    crate::arch::kernel_tests::check("rvv", super::aged_pages_rvv);
  }
}
