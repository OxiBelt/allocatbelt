//! Bit-twiddling helpers. They compile to `tzcnt`/`popcnt`/`lzcnt` where the
//! target supports them (e.g. `-C target-feature=+bmi1,+popcnt,+lzcnt` or
//! `-C target-cpu=x86-64-v3`) and stay entirely in safe Rust.

/// Index of the first run of `n` consecutive set bits in `free`, if any.
#[must_use]
pub const fn find_run(free: u64, n: u32) -> Option<u32> {
  first(run_starts(free, n))
}

/// Index of the first run of `n` consecutive set bits in `free` that starts
/// at a multiple of `step` (a power of two in `1..=64`), if any.
#[must_use]
#[inline]
pub const fn find_run_aligned(free: u64, n: u32, step: u32) -> Option<u32> {
  first(run_starts(free, n) & stride_mask(step))
}

const fn first(m: u64) -> Option<u32> {
  if m == 0 {
    None
  } else {
    Some(m.trailing_zeros())
  }
}

/// Bit `i` is set iff bits `i..i + n` of `free` are all set.
///
/// Uses the doubling trick: after each step bit `i` of `m` is set iff bits
/// `i..i + k` of `free` are all set, so it needs only `O(log n)` shifts.
const fn run_starts(free: u64, n: u32) -> u64 {
  if n == 0 || n > 64 {
    return 0;
  }
  if n == 64 {
    return if free == u64::MAX { 1 } else { 0 };
  }
  let mut m = free;
  let mut k = 1;
  while k < n {
    let s = if k < n - k { k } else { n - k };
    m &= m >> s;
    k += s;
  }
  m
}

/// Bits `0, step, 2 * step, ...` (`step` a power of two in `1..=64`). A
/// table lookup: this sits on the page-claim path.
const fn stride_mask(step: u32) -> u64 {
  const MASKS: [u64; 7] = [
    u64::MAX,
    0x5555_5555_5555_5555,
    0x1111_1111_1111_1111,
    0x0101_0101_0101_0101,
    0x0001_0001_0001_0001,
    0x0000_0001_0000_0001,
    1,
  ];
  MASKS[step.trailing_zeros() as usize]
}

/// Mask with bits `start..start + n` set (`n` in `1..=64`).
#[must_use]
pub const fn run_mask(start: u32, n: u32) -> u64 {
  let ones = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
  ones << start
}

#[cfg(test)]
mod tests;
