//! Experimental hand-written assembly for the thread cache's block list
//! (feature `experimental-asm-kernels`).
//!
//! Four leaf operations of the cached allocation paths have a kernel here,
//! one implementation per ISA level, chosen at compile time from the
//! build's target features (there is no run-time dispatch: the kernels are
//! inlined into the paths that use them):
//!
//! | Kernel | Path | Portable form |
//! |---|---|---|
//! | [`list_holds`] | every free into the word the thread has claimed (`Heap::dealloc_cached`) | [`crate::core::list_holds`] |
//! | [`unpack_blocks`] | every refill of a thread cache (`Heap::refill`) | [`crate::core::unpack_blocks`] |
//! | [`nonzero_words`] | every claim of a bitmap word, under the shard's lock (`Heap::claim_class`) | [`crate::core::nonzero_words`] |
//! | [`pack_blocks`] | every return of a claimed word (`Heap::flush`) | [`crate::core::pack_blocks`] |
//!
//! | Build | Implementation |
//! |---|---|
//! | x86_64 with AVX-512F/BW/CD/DQ/VL (x86-64-v4) | `x86_64_v4.rs` |
//! | other x86_64 (x86-64-v3, the floor) | `x86_64_v3.rs` |
//! | aarch64 (Advanced SIMD, the baseline) | `aarch64.rs` |
//! | riscv64 (V, the floor) | `riscv64.rs` |
//!
//! Each kernel only reads or writes the 64 entries of one list, which
//! belong to the calling thread, and must return exactly what its portable
//! form returns; the tests compare them over every length and position.

use core::cell::Cell;
use core::sync::atomic::AtomicU64;

#[cfg(all(
  target_arch = "x86_64",
  target_feature = "avx512f",
  target_feature = "avx512bw",
  target_feature = "avx512cd",
  target_feature = "avx512dq",
  target_feature = "avx512vl"
))]
#[path = "asm_kernels/x86_64_v4.rs"]
mod imp;

#[cfg(all(
  target_arch = "x86_64",
  not(all(
    target_feature = "avx512f",
    target_feature = "avx512bw",
    target_feature = "avx512cd",
    target_feature = "avx512dq",
    target_feature = "avx512vl"
  ))
))]
#[path = "asm_kernels/x86_64_v3.rs"]
mod imp;

#[cfg(target_arch = "aarch64")]
#[path = "asm_kernels/aarch64.rs"]
mod imp;

#[cfg(target_arch = "riscv64")]
#[path = "asm_kernels/riscv64.rs"]
mod imp;

/// Whether block number `i` (below 64) is among the first `len` (at most
/// 64) entries of `blocks`; see [`crate::core::list_holds`].
#[inline(always)]
pub(crate) fn list_holds(blocks: &[Cell<u8>; 64], len: u8, i: u8) -> bool {
  imp::list_holds(blocks, len, i)
}

/// Writes the numbers of the set bits of `bits` to `blocks`, highest
/// first, and returns their count; see [`crate::core::unpack_blocks`].
#[inline(always)]
pub(crate) fn unpack_blocks(bits: u64, blocks: &[Cell<u8>; 64]) -> u8 {
  imp::unpack_blocks(bits, blocks)
}

/// Which of `words` (at most 64) are non-zero, as a mask; see
/// [`crate::core::nonzero_words`]. The caller holds the lock under which
/// the words change.
#[inline(always)]
pub(crate) fn nonzero_words(words: &[AtomicU64]) -> u64 {
  imp::nonzero_words(words)
}

/// The mask of the block numbers in the first `len` (at most 64) entries of
/// `blocks`; see [`crate::core::pack_blocks`].
#[inline(always)]
pub(crate) fn pack_blocks(blocks: &[Cell<u8>; 64], len: u8) -> u64 {
  imp::pack_blocks(blocks, len)
}

/// The name of the implementation compiled into this build.
#[cfg(test)]
pub(crate) const IMPLEMENTATION: &str = imp::NAME;

#[cfg(test)]
mod tests;
