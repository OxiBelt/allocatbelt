//! Candidate kernels, one family per allocator operation (plan §7.2, §14).
//!
//! Every family has a scalar baseline, a compiler auto-vectorized version
//! and, where the architecture has them, hand-written vector versions. A
//! [`Variant`] is only handed out when the running CPU supports it, which is
//! what makes calling its function sound.
//!
//! All inputs are plain local values: a snapshot the maintenance pass would
//! first take with individual atomic loads (§7.1), or thread-owned bytes. No
//! kernel reads shared `AtomicU64` metadata.

use allocatbelt::CpuFeatures;

mod portable;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

/// `out` gets bit `i % 64` of word `i / 64` set iff `words[i] != 0`
/// (`find_nonzero_local_words`: which segments of a `seg_used` snapshot are
/// in use, which pages of a dirty snapshot are dirty). `out` has
/// `words.len().div_ceil(64)` words.
pub type NonzeroFn = fn(&[u64], &mut [u64]);

/// The total of `count_ones` over `words` (`reduce_local_masks`: dirty or
/// free pages over a snapshot of several segments).
pub type PopcountFn = fn(&[u64]) -> u64;

/// The bits `i` of `candidates` whose `since[i] <= cutoff`: the pages of one
/// segment that have been dirty long enough to purge
/// (`Heap::purge_segment`).
pub type AgeFn = fn(&[u64; 64], u64, u64) -> u64;

/// Fills the buffer with zeroes (`alloc_zeroed` when the block is not known
/// to be zero).
pub type ZeroFn = fn(&mut [u8]);

/// Copies `src` into `dst`, which has the same length (`realloc` moving a
/// block).
pub type CopyFn = fn(&mut [u8], &[u8]);

/// How a variant was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
  /// Scalar code, one element at a time, with vectorization prevented.
  Scalar,
  /// The plain loop the allocator would write, vectorized (or not) by the
  /// compiler for the build's target features.
  Autovec,
  /// Platform library routine (`memset`/`memcpy` through `core::ptr`).
  Library,
  /// Hand-written intrinsics.
  Handwritten,
  /// Experimental: compiler output in a function built for an optional
  /// feature (SVE), not a production candidate without native evidence.
  Experimental,
}

impl Tier {
  /// Short label for reports.
  #[must_use]
  pub const fn label(self) -> &'static str {
    match self {
      Self::Scalar => "scalar",
      Self::Autovec => "autovec",
      Self::Library => "library",
      Self::Handwritten => "handwritten",
      Self::Experimental => "experimental",
    }
  }
}

/// One implementation of a kernel family.
#[derive(Debug, Clone, Copy)]
pub struct Variant<F> {
  name: &'static str,
  tier: Tier,
  f: F,
}

impl<F: Copy> Variant<F> {
  const fn new(name: &'static str, tier: Tier, f: F) -> Self {
    Self { name, tier, f }
  }

  /// Variant name, such as `avx2`.
  #[must_use]
  pub const fn name(&self) -> &'static str {
    self.name
  }

  /// How the variant was produced.
  #[must_use]
  pub const fn tier(&self) -> Tier {
    self.tier
  }

  /// The kernel. Only obtainable for a CPU that supports it.
  #[must_use]
  pub const fn get(&self) -> F {
    self.f
  }
}

/// The variants of each family that the running CPU supports, scalar first.
#[derive(Debug, Clone, Default)]
pub struct Families {
  /// `find_nonzero_local_words`.
  pub nonzero: Vec<Variant<NonzeroFn>>,
  /// `reduce_local_masks`.
  pub popcount: Vec<Variant<PopcountFn>>,
  /// Purge-age classification.
  pub age: Vec<Variant<AgeFn>>,
  /// Bulk zeroing.
  pub zero: Vec<Variant<ZeroFn>>,
  /// Bulk copy.
  pub copy: Vec<Variant<CopyFn>>,
}

impl Families {
  /// The variants usable with `features`, which must be what the running
  /// CPU supports: listing a variant is what makes calling it sound.
  fn for_features(features: CpuFeatures) -> Self {
    #[cfg_attr(
      target_arch = "riscv64",
      expect(unused_mut, reason = "no hand-written kernels")
    )]
    let mut f = portable::families();
    #[cfg(target_arch = "x86_64")]
    x86_64::add(&mut f, features);
    #[cfg(target_arch = "aarch64")]
    aarch64::add(&mut f, features);
    let _ = features;
    f
  }

  /// The variants usable on this CPU.
  #[must_use]
  pub fn detected() -> Self {
    Self::for_features(allocatbelt::Allocatbelt.cpu_features())
  }
}

#[cfg(test)]
mod tests;
