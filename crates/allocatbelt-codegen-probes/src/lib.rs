//! Probes for the scalar ISA check (`scripts/check-scalar-isa.sh`).
//!
//! The allocator's bit scans are small functions that LLVM inlines into
//! their callers, so they have no symbol of their own to disassemble. Each
//! probe here is an out-of-line wrapper around one of them, built with the
//! same flags as the allocator, so the script can check which instructions
//! the hot operations lower to: `tzcnt`/`popcnt`/`lzcnt` on x86-64-v3 and
//! `ctz`/`cpop`/`clz` on riscv64 with Zbb.
//!
//! The probes are not part of the allocator and nothing calls them.

#![no_std]
#![forbid(unsafe_code)]

use allocatbelt_core_check::core::{bits, class};

/// `trailing_zeros`: the first aligned run of `n` free blocks in a bitmap
/// word. (`bits::find_run` is compiled out of line in the core
/// itself, so wrapping it would only show a call; `find_run_aligned` is
/// `#[inline]` and shares its `trailing_zeros` step.)
#[inline(never)]
#[must_use]
pub fn probe_find_run(free: u64, n: u32, step: u32) -> Option<u32> {
  bits::find_run_aligned(free, n, step)
}

/// `trailing_zeros` after a rotation: the randomized pick of a set bit.
#[inline(never)]
#[must_use]
pub fn probe_pick_bit(m: u64, r: u32) -> u32 {
  bits::pick_bit(m, r)
}

/// `leading_zeros`: the size class of a request.
#[inline(never)]
#[must_use]
pub fn probe_class_of(size: usize) -> usize {
  class::class_of(size)
}

/// `count_ones` on a bitmap word, as the free counters in `proto.rs` and
/// the dirty-page accounting in `heap.rs` use it. Those call sites are
/// private and inlined, so this probe checks the operation itself.
#[inline(never)]
#[must_use]
pub fn probe_count_ones(word: u64) -> u32 {
  word.count_ones()
}

#[cfg(test)]
mod tests {
  #[test]
  fn probes_forward() {
    assert_eq!(super::probe_find_run(0b1110_0000, 3, 1), Some(5));
    assert_eq!(super::probe_find_run(0b1111_0000, 2, 4), Some(4));
    assert_eq!(super::probe_pick_bit(0b1000, 0), 3);
    assert_eq!(super::probe_count_ones(0xff00), 8);
    assert_eq!(super::probe_class_of(16), super::class::class_of(16));
  }
}
