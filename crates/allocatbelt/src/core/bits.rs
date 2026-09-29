//! Bit-twiddling helpers. They compile to `tzcnt`/`popcnt`/`lzcnt` where the
//! target supports them (e.g. `-C target-feature=+bmi1,+popcnt,+lzcnt` or
//! `-C target-cpu=x86-64-v3`) and stay entirely in safe Rust. On riscv64 the
//! baseline `gc` target has no bit-manipulation instructions, so these fall
//! back to multi-instruction sequences; `-C target-feature=+zbb` (part of
//! RVA22) turns them into `ctz`/`cpop`/`clz`.

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

/// A set bit of `m` (non-zero) chosen by `r`: the set bits are ranked from
/// the lowest, and `r`, read as a fraction of 2^32, picks the rank
/// (`rank = r * m.count_ones() / 2^32`). `r = 0` gives the lowest set bit;
/// a uniformly random `r` gives every set bit the same chance, whatever
/// the gaps between them.
///
/// The pick is a rank selection, not a scan from a random position: a scan
/// from a random start favours set bits that follow long runs of zeros,
/// and the rank is where randomization belongs.
#[must_use]
#[inline]
pub const fn pick_bit(m: u64, r: u32) -> u32 {
  let rank = ((r as u64 * m.count_ones() as u64) >> 32) as u32;
  select_bit(m, rank)
}

/// Index of the set bit of `m` with `rank` set bits below it; `rank` must be
/// below `m.count_ones()`. Halves the word six times by population count,
/// so it takes the same steps for every input.
#[must_use]
#[inline]
pub const fn select_bit(m: u64, rank: u32) -> u32 {
  let mut m = m;
  let mut rank = rank;
  let mut index = 0;
  let mut width = 32;
  while width != 0 {
    let below = (m & ((1u64 << width) - 1)).count_ones();
    if rank >= below {
      rank -= below;
      m >>= width;
      index += width;
    }
    width /= 2;
  }
  index
}

/// Mask with bits `start..start + n` set (`n` in `1..=64`).
#[must_use]
pub const fn run_mask(start: u32, n: u32) -> u64 {
  let ones = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
  ones << start
}

#[cfg(all(test, allocatbelt_core_check))]
mod tests;
