//! Hand-written AVX2 and AVX-512 candidates.
//!
//! Each kernel is a `#[target_feature]` function behind a plain wrapper, and
//! a wrapper is only listed when `allocatbelt-arch` detected the features
//! its kernel is compiled for (AVX2 always holds at the x86-64-v3 floor).

#![allow(
  unsafe_code,
  reason = "benchmark-only SIMD candidates; see docs/unsafe-boundary.md"
)]

use core::arch::x86_64::{
  __m256i, __m512i, _mm_sfence, _mm256_add_epi8, _mm256_add_epi64, _mm256_and_si256,
  _mm256_castsi256_pd, _mm256_cmpeq_epi64, _mm256_cmpgt_epi64, _mm256_extract_epi64,
  _mm256_loadu_si256, _mm256_movemask_pd, _mm256_sad_epu8, _mm256_set_epi64x, _mm256_set1_epi8,
  _mm256_set1_epi64x, _mm256_setr_epi8, _mm256_setzero_si256, _mm256_shuffle_epi8,
  _mm256_srli_epi16, _mm256_storeu_si256, _mm256_stream_si256, _mm256_xor_si256, _mm512_add_epi64,
  _mm512_cmple_epu64_mask, _mm512_loadu_si512, _mm512_popcnt_epi64, _mm512_reduce_add_epi64,
  _mm512_set_epi64, _mm512_set1_epi64, _mm512_setzero_si512, _mm512_storeu_si512,
  _mm512_test_epi64_mask,
};

use allocatbelt_arch::CpuFeatures;

use super::{Families, Tier, Variant};

pub(super) fn add(f: &mut Families, features: CpuFeatures) {
  if !features.contains(CpuFeatures::AVX2) {
    return;
  }
  f.nonzero
    .push(Variant::new("avx2", Tier::Handwritten, nonzero_avx2));
  f.popcount
    .push(Variant::new("avx2", Tier::Handwritten, popcount_avx2));
  f.age
    .push(Variant::new("avx2", Tier::Handwritten, age_avx2));
  f.zero
    .push(Variant::new("avx2", Tier::Handwritten, zero_avx2));
  f.zero
    .push(Variant::new("avx2-nt", Tier::Handwritten, zero_avx2_nt));
  f.copy
    .push(Variant::new("avx2", Tier::Handwritten, copy_avx2));
  if features.contains(CpuFeatures::AVX512F) {
    f.nonzero
      .push(Variant::new("avx512", Tier::Handwritten, nonzero_avx512));
    f.age
      .push(Variant::new("avx512", Tier::Handwritten, age_avx512));
    f.zero
      .push(Variant::new("avx512", Tier::Handwritten, zero_avx512));
    f.copy
      .push(Variant::new("avx512", Tier::Handwritten, copy_avx512));
  }
  if features.contains(CpuFeatures::AVX512F | CpuFeatures::AVX512VPOPCNTDQ) {
    f.popcount
      .push(Variant::new("avx512", Tier::Handwritten, popcount_avx512));
  }
}

// ---- find_nonzero_local_words ----

fn nonzero_avx2(words: &[u64], out: &mut [u64]) {
  // SAFETY: listed only when AVX2 was detected (always, at the x86-64-v3
  // floor).
  unsafe { nonzero_avx2_imp(words, out) }
}

#[target_feature(enable = "avx2")]
fn nonzero_avx2_imp(words: &[u64], out: &mut [u64]) {
  let zero = _mm256_setzero_si256();
  for (o, block) in out.iter_mut().zip(words.chunks(64)) {
    let mut m = 0u64;
    let mut quads = block.chunks_exact(4);
    for (q, c) in quads.by_ref().enumerate() {
      let v = set4(c);
      let eq = _mm256_movemask_pd(_mm256_castsi256_pd(_mm256_cmpeq_epi64(v, zero)));
      m |= u64::from(!eq as u8 & 0xf) << (4 * q);
    }
    let done = block.len() - quads.remainder().len();
    for (i, &w) in quads.remainder().iter().enumerate() {
      m |= u64::from(w != 0) << (done + i);
    }
    *o = m;
  }
}

fn nonzero_avx512(words: &[u64], out: &mut [u64]) {
  // SAFETY: listed only when AVX-512F was detected.
  unsafe { nonzero_avx512_imp(words, out) }
}

#[target_feature(enable = "avx512f")]
fn nonzero_avx512_imp(words: &[u64], out: &mut [u64]) {
  for (o, block) in out.iter_mut().zip(words.chunks(64)) {
    let mut m = 0u64;
    let mut octs = block.chunks_exact(8);
    for (q, c) in octs.by_ref().enumerate() {
      let v = set8(c);
      m |= u64::from(_mm512_test_epi64_mask(v, v)) << (8 * q);
    }
    let done = block.len() - octs.remainder().len();
    for (i, &w) in octs.remainder().iter().enumerate() {
      m |= u64::from(w != 0) << (done + i);
    }
    *o = m;
  }
}

// ---- reduce_local_masks ----

fn popcount_avx2(words: &[u64]) -> u64 {
  // SAFETY: listed only when AVX2 was detected (always, at the x86-64-v3
  // floor).
  unsafe { popcount_avx2_imp(words) }
}

#[target_feature(enable = "avx2")]
fn popcount_avx2_imp(words: &[u64]) -> u64 {
  // Nibble lookup (Muła's method): popcount of each byte, summed with SAD.
  let lut = _mm256_setr_epi8(
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
  );
  let low = _mm256_set1_epi8(0x0f);
  let zero = _mm256_setzero_si256();
  let mut acc = zero;
  let mut quads = words.chunks_exact(4);
  for c in quads.by_ref() {
    let v = set4(c);
    let lo = _mm256_and_si256(v, low);
    let hi = _mm256_and_si256(_mm256_srli_epi16::<4>(v), low);
    let bytes = _mm256_add_epi8(_mm256_shuffle_epi8(lut, lo), _mm256_shuffle_epi8(lut, hi));
    acc = _mm256_add_epi64(acc, _mm256_sad_epu8(bytes, zero));
  }
  let lanes = [
    _mm256_extract_epi64::<0>(acc),
    _mm256_extract_epi64::<1>(acc),
    _mm256_extract_epi64::<2>(acc),
    _mm256_extract_epi64::<3>(acc),
  ];
  let vec: u64 = lanes.iter().map(|&l| l as u64).sum();
  vec
    + quads
      .remainder()
      .iter()
      .map(|&w| u64::from(w.count_ones()))
      .sum::<u64>()
}

fn popcount_avx512(words: &[u64]) -> u64 {
  // SAFETY: listed only when AVX-512F and AVX-512 VPOPCNTDQ were detected.
  unsafe { popcount_avx512_imp(words) }
}

#[target_feature(enable = "avx512f,avx512vpopcntdq")]
fn popcount_avx512_imp(words: &[u64]) -> u64 {
  let mut acc = _mm512_setzero_si512();
  let mut octs = words.chunks_exact(8);
  for c in octs.by_ref() {
    acc = _mm512_add_epi64(acc, _mm512_popcnt_epi64(set8(c)));
  }
  _mm512_reduce_add_epi64(acc) as u64
    + octs
      .remainder()
      .iter()
      .map(|&w| u64::from(w.count_ones()))
      .sum::<u64>()
}

// ---- purge-age classification ----

fn age_avx2(since: &[u64; 64], candidates: u64, cutoff: u64) -> u64 {
  // SAFETY: listed only when AVX2 was detected (always, at the x86-64-v3
  // floor).
  unsafe { age_avx2_imp(since, candidates, cutoff) }
}

#[target_feature(enable = "avx2")]
fn age_avx2_imp(since: &[u64; 64], candidates: u64, cutoff: u64) -> u64 {
  // AVX2 compares signed 64-bit lanes; flipping the sign bit of both sides
  // turns that into the unsigned `since > cutoff`.
  let sign = _mm256_set1_epi64x(i64::MIN);
  let c = _mm256_xor_si256(_mm256_set1_epi64x(cutoff as i64), sign);
  let mut later = 0u64;
  for (q, chunk) in since.chunks_exact(4).enumerate() {
    let v = _mm256_xor_si256(set4(chunk), sign);
    let gt = _mm256_movemask_pd(_mm256_castsi256_pd(_mm256_cmpgt_epi64(v, c)));
    later |= u64::from(gt as u8 & 0xf) << (4 * q);
  }
  !later & candidates
}

fn age_avx512(since: &[u64; 64], candidates: u64, cutoff: u64) -> u64 {
  // SAFETY: listed only when AVX-512F was detected.
  unsafe { age_avx512_imp(since, candidates, cutoff) }
}

#[target_feature(enable = "avx512f")]
fn age_avx512_imp(since: &[u64; 64], candidates: u64, cutoff: u64) -> u64 {
  let c = _mm512_set1_epi64(cutoff as i64);
  let mut m = 0u64;
  for (q, chunk) in since.chunks_exact(8).enumerate() {
    m |= u64::from(_mm512_cmple_epu64_mask(set8(chunk), c)) << (8 * q);
  }
  m & candidates
}

// ---- bulk zeroing ----

fn zero_avx2(buf: &mut [u8]) {
  // SAFETY: listed only when AVX2 was detected (always, at the x86-64-v3
  // floor).
  unsafe { zero_avx2_imp(buf) }
}

#[target_feature(enable = "avx2")]
fn zero_avx2_imp(buf: &mut [u8]) {
  let z = _mm256_setzero_si256();
  let mut chunks = buf.chunks_exact_mut(32);
  for c in chunks.by_ref() {
    // SAFETY: `c` is 32 writable bytes; `storeu` has no alignment
    // requirement.
    unsafe { _mm256_storeu_si256(c.as_mut_ptr().cast::<__m256i>(), z) };
  }
  chunks.into_remainder().fill(0);
}

/// Non-temporal stores bypass the cache; the plan asks whether that helps
/// for large blocks and hurts for small ones.
fn zero_avx2_nt(buf: &mut [u8]) {
  // SAFETY: listed only when AVX2 was detected (always, at the x86-64-v3
  // floor).
  unsafe { zero_avx2_nt_imp(buf) }
}

#[target_feature(enable = "avx2")]
fn zero_avx2_nt_imp(buf: &mut [u8]) {
  let head = buf.as_ptr().align_offset(32).min(buf.len());
  let (head, body) = buf.split_at_mut(head);
  head.fill(0);
  let z = _mm256_setzero_si256();
  let mut chunks = body.chunks_exact_mut(32);
  for c in chunks.by_ref() {
    // SAFETY: `c` is 32 writable bytes starting 32-byte aligned (`body`
    // starts aligned and the chunks are 32 bytes), as `stream` requires.
    unsafe { _mm256_stream_si256(c.as_mut_ptr().cast::<__m256i>(), z) };
  }
  chunks.into_remainder().fill(0);
  // Orders the streaming stores before anything the caller does next.
  _mm_sfence();
}

fn zero_avx512(buf: &mut [u8]) {
  // SAFETY: listed only when AVX-512F was detected.
  unsafe { zero_avx512_imp(buf) }
}

#[target_feature(enable = "avx512f")]
fn zero_avx512_imp(buf: &mut [u8]) {
  let z = _mm512_setzero_si512();
  let mut chunks = buf.chunks_exact_mut(64);
  for c in chunks.by_ref() {
    // SAFETY: `c` is 64 writable bytes; `storeu` has no alignment
    // requirement.
    unsafe { _mm512_storeu_si512(c.as_mut_ptr().cast::<__m512i>(), z) };
  }
  chunks.into_remainder().fill(0);
}

// ---- bulk copy ----

fn copy_avx2(dst: &mut [u8], src: &[u8]) {
  // SAFETY: listed only when AVX2 was detected (always, at the x86-64-v3
  // floor).
  unsafe { copy_avx2_imp(dst, src) }
}

#[target_feature(enable = "avx2")]
fn copy_avx2_imp(dst: &mut [u8], src: &[u8]) {
  assert_eq!(dst.len(), src.len());
  let mut d = dst.chunks_exact_mut(32);
  let mut s = src.chunks_exact(32);
  for (dc, sc) in d.by_ref().zip(s.by_ref()) {
    // SAFETY: `sc` is 32 readable bytes; `loadu` has no alignment
    // requirement.
    let v = unsafe { _mm256_loadu_si256(sc.as_ptr().cast::<__m256i>()) };
    // SAFETY: `dc` is 32 writable bytes, disjoint from `sc` (`&mut`).
    unsafe { _mm256_storeu_si256(dc.as_mut_ptr().cast::<__m256i>(), v) };
  }
  d.into_remainder().copy_from_slice(s.remainder());
}

fn copy_avx512(dst: &mut [u8], src: &[u8]) {
  assert_eq!(dst.len(), src.len());
  // SAFETY: listed only when AVX-512F was detected.
  unsafe { copy_avx512_imp(dst, src) }
}

#[target_feature(enable = "avx512f")]
fn copy_avx512_imp(dst: &mut [u8], src: &[u8]) {
  let mut d = dst.chunks_exact_mut(64);
  let mut s = src.chunks_exact(64);
  for (dc, sc) in d.by_ref().zip(s.by_ref()) {
    // SAFETY: `sc` is 64 readable bytes; `loadu` has no alignment
    // requirement.
    let v = unsafe { _mm512_loadu_si512(sc.as_ptr().cast::<__m512i>()) };
    // SAFETY: `dc` is 64 writable bytes, disjoint from `sc` (`&mut`).
    unsafe { _mm512_storeu_si512(dc.as_mut_ptr().cast::<__m512i>(), v) };
  }
  d.into_remainder().copy_from_slice(s.remainder());
}

// ---- helpers ----

/// Four words as a vector; LLVM folds this into one unaligned load.
#[inline]
#[target_feature(enable = "avx2")]
fn set4(c: &[u64]) -> __m256i {
  _mm256_set_epi64x(c[3] as i64, c[2] as i64, c[1] as i64, c[0] as i64)
}

/// Eight words as a vector; LLVM folds this into one unaligned load.
#[inline]
#[target_feature(enable = "avx512f")]
fn set8(c: &[u64]) -> __m512i {
  _mm512_set_epi64(
    c[7] as i64,
    c[6] as i64,
    c[5] as i64,
    c[4] as i64,
    c[3] as i64,
    c[2] as i64,
    c[1] as i64,
    c[0] as i64,
  )
}
