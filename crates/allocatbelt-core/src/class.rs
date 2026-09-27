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

/// Block size of class `c`.
#[must_use]
pub const fn size(c: usize) -> usize {
    SIZES[c]
}

/// Blocks per page for class `c`.
#[must_use]
pub const fn capacity(c: usize) -> usize {
    PAGE_SIZE / SIZES[c]
}

/// Bitmap words in use for class `c`.
#[must_use]
pub const fn bitmap_words(c: usize) -> usize {
    capacity(c).div_ceil(64)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_shape() {
        assert_eq!(size(0), 16);
        assert_eq!(size(7), 128);
        assert_eq!(size(8), 160);
        assert_eq!(size(NUM_CLASSES - 1), SMALL_MAX);
        for c in 1..NUM_CLASSES {
            assert!(size(c) > size(c - 1));
            assert_eq!(size(c) % MIN_ALIGN, 0);
            assert!(bitmap_words(c) <= MAX_BITMAP_WORDS);
        }
        for k in 4..=13 {
            let p = 1usize << k;
            assert_eq!(size(class_of(p)), p, "power of two {p} must be a class");
        }
    }

    #[test]
    fn class_of_is_tight() {
        for s in 0..=SMALL_MAX {
            let c = class_of(s);
            assert!(size(c) >= s.max(1), "size {s}");
            if c > 0 {
                assert!(size(c - 1) < s, "size {s} not in smallest class");
            }
        }
    }
}
