//! Scalar baselines, compiler auto-vectorized versions and library calls.

use core::hint::black_box;

use super::{Families, Tier, Variant};

pub(super) fn families() -> Families {
  Families {
    nonzero: vec![
      Variant::new("scalar", Tier::Scalar, nonzero_scalar),
      Variant::new(autovec_name(), Tier::Autovec, nonzero_autovec),
    ],
    popcount: vec![
      Variant::new("scalar", Tier::Scalar, popcount_scalar),
      Variant::new(autovec_name(), Tier::Autovec, popcount_autovec),
    ],
    age: vec![
      Variant::new("scalar-sparse", Tier::Scalar, age_sparse),
      Variant::new("scalar-dense", Tier::Scalar, age_scalar),
      Variant::new(autovec_name(), Tier::Autovec, age_autovec),
    ],
    zero: vec![Variant::new("memset", Tier::Library, zero_library)],
    copy: vec![Variant::new("memcpy", Tier::Library, copy_library)],
  }
}

/// On riscv64 built with `-C target-feature=+v` the auto-vectorized
/// variants are the experimental RVV path (`core::arch::riscv64` and the `v`
/// target feature are unstable, so this is the stable way to get RVV code;
/// `build.rs` sets `allocatbelt_rvv` from the flags).
const fn autovec_name() -> &'static str {
  if cfg!(allocatbelt_rvv) {
    "autovec(+v)"
  } else {
    "autovec"
  }
}

// `black_box` on each element keeps LLVM from vectorizing the scalar
// baselines, at the cost of a compiler barrier per element, so they
// slightly overstate what a naturally scalar loop costs.

fn nonzero_scalar(words: &[u64], out: &mut [u64]) {
  out.fill(0);
  for (i, &w) in words.iter().enumerate() {
    if black_box(w) != 0 {
      out[i / 64] |= 1 << (i % 64);
    }
  }
}

pub(super) fn nonzero_autovec(words: &[u64], out: &mut [u64]) {
  nonzero_body(words, out);
}

/// Branchless, one output word per 64 inputs: the shape LLVM vectorizes.
#[inline(always)]
pub(super) fn nonzero_body(words: &[u64], out: &mut [u64]) {
  for (o, chunk) in out.iter_mut().zip(words.chunks(64)) {
    let mut m = 0u64;
    for (i, &w) in chunk.iter().enumerate() {
      m |= u64::from(w != 0) << i;
    }
    *o = m;
  }
}

fn popcount_scalar(words: &[u64]) -> u64 {
  words
    .iter()
    .map(|&w| u64::from(black_box(w).count_ones()))
    .sum()
}

pub(super) fn popcount_autovec(words: &[u64]) -> u64 {
  popcount_body(words)
}

#[inline(always)]
pub(super) fn popcount_body(words: &[u64]) -> u64 {
  words.iter().map(|&w| u64::from(w.count_ones())).sum()
}

/// What `Heap::purge_segment` does today: visit only the candidate pages.
fn age_sparse(since: &[u64; 64], candidates: u64, cutoff: u64) -> u64 {
  let mut eligible = 0;
  let mut d = candidates;
  while d != 0 {
    let i = d.trailing_zeros() as usize;
    d &= d - 1;
    if since[i] <= cutoff {
      eligible |= 1 << i;
    }
  }
  eligible
}

fn age_scalar(since: &[u64; 64], candidates: u64, cutoff: u64) -> u64 {
  let mut m = 0u64;
  for (i, &t) in since.iter().enumerate() {
    m |= u64::from(black_box(t) <= cutoff) << i;
  }
  m & candidates
}

pub(super) fn age_autovec(since: &[u64; 64], candidates: u64, cutoff: u64) -> u64 {
  age_body(since, candidates, cutoff)
}

#[inline(always)]
pub(super) fn age_body(since: &[u64; 64], candidates: u64, cutoff: u64) -> u64 {
  let mut m = 0u64;
  for (i, &t) in since.iter().enumerate() {
    m |= u64::from(t <= cutoff) << i;
  }
  m & candidates
}

fn zero_library(buf: &mut [u8]) {
  buf.fill(0);
}

fn copy_library(dst: &mut [u8], src: &[u8]) {
  dst.copy_from_slice(src);
}
