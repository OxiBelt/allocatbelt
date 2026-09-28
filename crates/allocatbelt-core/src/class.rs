//! Small-object size classes: 16-byte steps up to 128 bytes, then four
//! classes per power of two up to [`SMALL_MAX`]. Every power of two is a
//! class, so a power-of-two class block is naturally aligned to its size
//! inside a page-aligned page.

use crate::PAGE_SIZE;

/// Number of small size classes.
pub const NUM_CLASSES: usize = 32;
/// Largest request served from a small size class.
pub const SMALL_MAX: usize = 8192;
/// Minimum block size and default alignment of small blocks.
pub const MIN_ALIGN: usize = 16;
/// Bitmap words a page needs for the smallest class.
pub const MAX_BITMAP_WORDS: usize = PAGE_SIZE / MIN_ALIGN / 64;

const fn compute_size(c: usize) -> usize {
  if c < 8 {
    MIN_ALIGN * (c + 1)
  } else {
    let g = (c - 8) / 4;
    let sub = (c - 8) % 4;
    let base = 128 << g;
    base + (sub + 1) * (base / 4)
  }
}

const SIZES: [usize; NUM_CLASSES] = {
  let mut t = [0; NUM_CLASSES];
  let mut c = 0;
  while c < NUM_CLASSES {
    t[c] = compute_size(c);
    c += 1;
  }
  t
};

const CAPACITY: [u16; NUM_CLASSES] = {
  let mut t = [0; NUM_CLASSES];
  let mut c = 0;
  while c < NUM_CLASSES {
    t[c] = (PAGE_SIZE / SIZES[c]) as u16;
    c += 1;
  }
  t
};

/// `ceil(2^32 / size)`: `(offset * RECIP[c]) >> 32` is `offset / size` for
/// every in-page offset (below 2^16), since `offset * size < 2^32`.
const RECIP: [u64; NUM_CLASSES] = {
  let mut t = [0; NUM_CLASSES];
  let mut c = 0;
  while c < NUM_CLASSES {
    t[c] = (1u64 << 32).div_ceil(SIZES[c] as u64);
    c += 1;
  }
  t
};

/// Block size of class `c`.
#[must_use]
#[inline]
pub const fn size(c: usize) -> usize {
  SIZES[c]
}

/// Blocks per page for class `c`.
#[must_use]
#[inline]
pub const fn capacity(c: usize) -> usize {
  CAPACITY[c] as usize
}

/// Bitmap words in use for class `c`.
#[must_use]
#[inline]
pub const fn bitmap_words(c: usize) -> usize {
  capacity(c).div_ceil(64)
}

/// Index of the class-`c` block that starts `in_page` bytes into its page,
/// or `None` if no block starts there. Uses a multiplication instead of a
/// division: this sits on the free path.
#[must_use]
#[inline]
pub const fn block_index(c: usize, in_page: usize) -> Option<usize> {
  let idx = ((in_page as u64 * RECIP[c]) >> 32) as usize;
  if idx * SIZES[c] == in_page && idx < capacity(c) {
    Some(idx)
  } else {
    None
  }
}

/// Smallest class whose blocks hold `size` bytes (`size` in `0..=SMALL_MAX`).
#[must_use]
pub const fn class_of(size: usize) -> usize {
  let s = if size == 0 { 1 } else { size };
  if s <= 128 {
    return s.div_ceil(MIN_ALIGN) - 1;
  }
  let s1 = s - 1;
  // floor(log2(s1)); `leading_zeros` lowers to `lzcnt` where available.
  let b = (usize::BITS - 1 - s1.leading_zeros()) as usize;
  let sub = (s1 >> (b - 2)) & 3;
  8 + (b - 7) * 4 + sub
}

/// Smallest class whose blocks hold `size` bytes and are all aligned to
/// `align` (a power of two), if any. A block is aligned to `align` when its
/// size is a multiple of it and `align` does not exceed the page alignment.
#[must_use]
pub const fn class_for(size: usize, align: usize) -> Option<usize> {
  if align > PAGE_SIZE || size > SMALL_MAX {
    return None;
  }
  let mut c = class_of(if size < align { align } else { size });
  while c < NUM_CLASSES {
    if SIZES[c].is_multiple_of(align) {
      return Some(c);
    }
    c += 1;
  }
  None
}

#[cfg(test)]
mod tests;
