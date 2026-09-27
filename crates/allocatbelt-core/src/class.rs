//! Size classes: 16-byte steps up to 128 bytes, then four classes per power
//! of two up to [`SMALL_MAX`], so rounding up wastes at most 25%.
//!
//! Blocks of a class are carved from a *span* of [`span`] contiguous pages
//! (one page for classes up to 32 KiB). A block's offset from the page-aligned
//! span start is a multiple of its size, so a block is aligned to the largest
//! power of two dividing its size, capped at [`PAGE_SIZE`].

use crate::PAGE_SIZE;

/// Number of size classes.
pub const NUM_CLASSES: usize = 52;
/// Largest request served from a size class (256 KiB). Beyond it, page runs
/// round up by less than one 64 KiB page, again at most 25%.
pub const SMALL_MAX: usize = 256 * 1024;
/// Largest span in pages.
pub const MAX_SPAN: usize = 8;
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

/// Smallest span that holds at least two blocks and wastes at most 1/8.
const fn compute_span(c: usize) -> usize {
    let size = SIZES[c];
    let mut s = 1;
    while s < MAX_SPAN {
        let bytes = s * PAGE_SIZE;
        if bytes / size >= 2 && bytes % size <= bytes / 8 {
            break;
        }
        s += 1;
    }
    s
}

const SPANS: [usize; NUM_CLASSES] = {
    let mut t = [0; NUM_CLASSES];
    let mut c = 0;
    while c < NUM_CLASSES {
        t[c] = compute_span(c);
        c += 1;
    }
    t
};

/// Pages in a span of class `c`.
#[must_use]
pub const fn span(c: usize) -> usize {
    SPANS[c]
}

/// Blocks per span for class `c`.
#[must_use]
pub const fn capacity(c: usize) -> usize {
    SPANS[c] * PAGE_SIZE / SIZES[c]
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
        for c in 0..NUM_CLASSES {
            if c > 0 {
                assert!(size(c) > size(c - 1));
            }
            assert_eq!(size(c) % MIN_ALIGN, 0);
            assert!(bitmap_words(c) <= MAX_BITMAP_WORDS);
            assert!(capacity(c) >= 2, "class {c}");
            assert!(span(c) <= MAX_SPAN);
            // Waste from carving the span into blocks stays within 1/8.
            let bytes = span(c) * PAGE_SIZE;
            assert!(bytes - capacity(c) * size(c) <= bytes / 8, "class {c}");
            if size(c) <= 8192 {
                assert_eq!(span(c), 1, "small classes keep one-page spans");
            }
        }
        for k in 4..=18 {
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
