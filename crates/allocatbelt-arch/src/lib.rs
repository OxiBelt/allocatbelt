//! CPU feature discovery and architecture kernel dispatch for allocatbelt.
//!
//! This crate is the architecture boundary of the allocator: it finds out,
//! without allocating, which ISA extensions the running CPU and kernel
//! support, and publishes which set of architecture kernels the allocator
//! may use. `allocatbelt-core` stays `#![forbid(unsafe_code)]` and never sees
//! vector types; the few `unsafe` operations detection needs live here and
//! are listed in `docs/unsafe-boundary.md`.
//!
//! ```text
//! allocations before initialize_dispatch()  -> KernelSet::Baseline
//! initialize_dispatch()                     -> probe once, publish atomically
//! allocations afterwards                    -> the published KernelSet
//! ```
//!
//! A detected feature does not mean an optimized kernel exists for it. No
//! architecture kernel has been admitted yet (each needs benchmark evidence,
//! see `docs/research/README.md` §5), so [`initialize_dispatch`] always
//! publishes [`KernelSet::Baseline`] for now.

#![no_std]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

#[cfg(test)]
extern crate std;

use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

mod features;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

pub use features::CpuFeatures;

/// The set of architecture kernels the allocator dispatches to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KernelSet {
  /// Portable scalar code only. Always correct, and what every allocation
  /// uses before [`initialize_dispatch`] has run.
  Baseline,
}

/// Detection result, with [`DETECTED`] set once it is valid.
static FEATURES: AtomicU32 = AtomicU32::new(0);
const DETECTED: u32 = 1 << 31;

/// The published [`KernelSet`]; `0` is [`KernelSet::Baseline`].
static DISPATCH: AtomicU8 = AtomicU8::new(0);

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

/// Probes the CPU (once), chooses the kernel set and publishes it for
/// [`kernel_set`]. Allocation-free and idempotent; call it before worker
/// threads start. Allocations that happen earlier use the baseline.
pub fn initialize_dispatch() -> KernelSet {
  let _ = detected_features();
  // No architecture kernel has passed its benchmark gate yet.
  let set = KernelSet::Baseline;
  DISPATCH.store(set as u8, Ordering::Release);
  set
}

/// The kernel set published by [`initialize_dispatch`], or
/// [`KernelSet::Baseline`] before it has run.
#[must_use]
pub fn kernel_set() -> KernelSet {
  // Only `Baseline` exists so far; later sets decode the stored value here.
  let _published = DISPATCH.load(Ordering::Acquire);
  KernelSet::Baseline
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

/// Other architectures are rejected by `allocatbelt-sys`; report nothing.
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
  use super::{KernelSet, detected_features, initialize_dispatch, kernel_set};

  #[test]
  fn dispatch_is_baseline_and_idempotent() {
    assert_eq!(initialize_dispatch(), KernelSet::Baseline);
    assert_eq!(initialize_dispatch(), KernelSet::Baseline);
    assert_eq!(kernel_set(), KernelSet::Baseline);
  }

  #[test]
  fn detection_is_cached() {
    assert_eq!(detected_features(), detected_features());
  }
}
