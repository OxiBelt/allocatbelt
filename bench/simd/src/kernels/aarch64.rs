//! Hand-written Advanced SIMD (NEON) candidates and the experimental SVE
//! path.
//!
//! Each kernel is a `#[target_feature]` function behind a plain wrapper that
//! is only listed when the feature was detected. SVE intrinsics are not stable in Rust, so the SVE
//! variants are the portable loops compiled inside `#[target_feature(enable
//! = "sve")]` functions, listed only when SVE was detected (plan §4.2).

#![allow(
  unsafe_code,
  reason = "benchmark-only SIMD candidates; see docs/unsafe-boundary.md"
)]

use core::arch::aarch64::{
  uint8x16x4_t, vaddlvq_u8, vcgtq_u64, vcntq_u8, vdupq_n_u8, vdupq_n_u64, vgetq_lane_u64,
  vld1q_u8_x4, vld1q_u64, vreinterpretq_u8_u64, vst1q_u8_x4, vtstq_u64,
};

use allocatbelt_arch::CpuFeatures;

use super::{Families, Tier, Variant, portable};

pub(super) fn add(f: &mut Families, features: CpuFeatures) {
  if features.contains(CpuFeatures::ASIMD) {
    f.nonzero
      .push(Variant::new("neon", Tier::Handwritten, nonzero_neon));
    f.popcount
      .push(Variant::new("neon", Tier::Handwritten, popcount_neon));
    f.age
      .push(Variant::new("neon", Tier::Handwritten, age_neon));
    f.zero
      .push(Variant::new("neon", Tier::Handwritten, zero_neon));
    f.copy
      .push(Variant::new("neon", Tier::Handwritten, copy_neon));
  }
  if features.contains(CpuFeatures::SVE) {
    f.nonzero
      .push(Variant::new("sve-autovec", Tier::Experimental, nonzero_sve));
    f.popcount.push(Variant::new(
      "sve-autovec",
      Tier::Experimental,
      popcount_sve,
    ));
    f.age
      .push(Variant::new("sve-autovec", Tier::Experimental, age_sve));
  }
}

// ---- find_nonzero_local_words ----

fn nonzero_neon(words: &[u64], out: &mut [u64]) {
  // SAFETY: listed only when Advanced SIMD was detected.
  unsafe { nonzero_neon_imp(words, out) }
}

#[target_feature(enable = "neon")]
fn nonzero_neon_imp(words: &[u64], out: &mut [u64]) {
  for (o, block) in out.iter_mut().zip(words.chunks(64)) {
    let mut m = 0u64;
    let mut pairs = block.chunks_exact(2);
    for (q, c) in pairs.by_ref().enumerate() {
      let v = load2(c);
      // All-ones lanes where the word has any bit set.
      let t = vtstq_u64(v, v);
      let bits = (vgetq_lane_u64::<0>(t) & 1) | (vgetq_lane_u64::<1>(t) & 2);
      m |= bits << (2 * q);
    }
    let done = block.len() - pairs.remainder().len();
    for (i, &w) in pairs.remainder().iter().enumerate() {
      m |= u64::from(w != 0) << (done + i);
    }
    *o = m;
  }
}

// ---- reduce_local_masks ----

fn popcount_neon(words: &[u64]) -> u64 {
  // SAFETY: listed only when Advanced SIMD was detected.
  unsafe { popcount_neon_imp(words) }
}

#[target_feature(enable = "neon")]
fn popcount_neon_imp(words: &[u64]) -> u64 {
  let mut total = 0u64;
  let mut pairs = words.chunks_exact(2);
  for c in pairs.by_ref() {
    let bytes = vcntq_u8(vreinterpretq_u8_u64(load2(c)));
    total += u64::from(vaddlvq_u8(bytes));
  }
  total
    + pairs
      .remainder()
      .iter()
      .map(|&w| u64::from(w.count_ones()))
      .sum::<u64>()
}

// ---- purge-age classification ----

fn age_neon(since: &[u64; 64], candidates: u64, cutoff: u64) -> u64 {
  // SAFETY: listed only when Advanced SIMD was detected.
  unsafe { age_neon_imp(since, candidates, cutoff) }
}

#[target_feature(enable = "neon")]
fn age_neon_imp(since: &[u64; 64], candidates: u64, cutoff: u64) -> u64 {
  let c = vdupq_n_u64(cutoff);
  let mut later = 0u64;
  for (q, chunk) in since.chunks_exact(2).enumerate() {
    let gt = vcgtq_u64(load2(chunk), c);
    let bits = (vgetq_lane_u64::<0>(gt) & 1) | (vgetq_lane_u64::<1>(gt) & 2);
    later |= bits << (2 * q);
  }
  !later & candidates
}

// ---- bulk zeroing and copy ----

fn zero_neon(buf: &mut [u8]) {
  // SAFETY: listed only when Advanced SIMD was detected.
  unsafe { zero_neon_imp(buf) }
}

#[target_feature(enable = "neon")]
fn zero_neon_imp(buf: &mut [u8]) {
  let z = vdupq_n_u8(0);
  let zeros = uint8x16x4_t(z, z, z, z);
  let mut chunks = buf.chunks_exact_mut(64);
  for c in chunks.by_ref() {
    // SAFETY: `c` is 64 writable bytes; `st1` has no alignment
    // requirement.
    unsafe { vst1q_u8_x4(c.as_mut_ptr(), zeros) };
  }
  chunks.into_remainder().fill(0);
}

fn copy_neon(dst: &mut [u8], src: &[u8]) {
  // SAFETY: listed only when Advanced SIMD was detected.
  unsafe { copy_neon_imp(dst, src) }
}

#[target_feature(enable = "neon")]
fn copy_neon_imp(dst: &mut [u8], src: &[u8]) {
  assert_eq!(dst.len(), src.len());
  let mut d = dst.chunks_exact_mut(64);
  let mut s = src.chunks_exact(64);
  for (dc, sc) in d.by_ref().zip(s.by_ref()) {
    // SAFETY: `sc` is 64 readable bytes; `ld1` has no alignment
    // requirement.
    let v = unsafe { vld1q_u8_x4(sc.as_ptr()) };
    // SAFETY: `dc` is 64 writable bytes, disjoint from `sc` (`&mut`).
    unsafe { vst1q_u8_x4(dc.as_mut_ptr(), v) };
  }
  d.into_remainder().copy_from_slice(s.remainder());
}

// ---- experimental SVE (compiler output only) ----

fn nonzero_sve(words: &[u64], out: &mut [u64]) {
  // SAFETY: listed only when SVE was detected.
  unsafe { nonzero_sve_imp(words, out) }
}

#[target_feature(enable = "sve")]
fn nonzero_sve_imp(words: &[u64], out: &mut [u64]) {
  portable::nonzero_body(words, out);
}

fn popcount_sve(words: &[u64]) -> u64 {
  // SAFETY: listed only when SVE was detected.
  unsafe { popcount_sve_imp(words) }
}

#[target_feature(enable = "sve")]
fn popcount_sve_imp(words: &[u64]) -> u64 {
  portable::popcount_body(words)
}

fn age_sve(since: &[u64; 64], candidates: u64, cutoff: u64) -> u64 {
  // SAFETY: listed only when SVE was detected.
  unsafe { age_sve_imp(since, candidates, cutoff) }
}

#[target_feature(enable = "sve")]
fn age_sve_imp(since: &[u64; 64], candidates: u64, cutoff: u64) -> u64 {
  portable::age_body(since, candidates, cutoff)
}

// ---- helpers ----

/// Two words as a vector.
#[inline]
#[target_feature(enable = "neon")]
fn load2(c: &[u64]) -> core::arch::aarch64::uint64x2_t {
  let pair: &[u64; 2] = c.first_chunk().unwrap_or(&[0, 0]);
  // SAFETY: `pair` is two readable, 8-aligned `u64`s.
  unsafe { vld1q_u64(pair.as_ptr()) }
}
