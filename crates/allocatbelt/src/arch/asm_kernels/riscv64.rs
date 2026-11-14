//! PLACEHOLDER for the riscv64 kernels: portable loops, to be replaced by
//! hand-written assembly. Self-contained: no `crate::` paths, so the
//! benchmark crate can include this file too.

use core::cell::Cell;

/// Reported by the tests and the benchmark.
pub(crate) const NAME: &str = "riscv64 (placeholder, portable)";

#[inline(always)]
pub(crate) fn list_holds(blocks: &[Cell<u8>; 64], len: u8, i: u8) -> bool {
  let mut hit = false;
  for (k, b) in blocks.iter().enumerate() {
    hit |= b.get() == i && k < usize::from(len);
  }
  hit
}

#[inline(always)]
pub(crate) fn unpack_blocks(bits: u64, blocks: &[Cell<u8>; 64]) -> u8 {
  let mut rest = bits;
  let mut n = 0;
  while rest != 0 {
    let i = 63 - rest.leading_zeros();
    blocks[n].set(i as u8);
    n += 1;
    rest &= !(1 << i);
  }
  n as u8
}
