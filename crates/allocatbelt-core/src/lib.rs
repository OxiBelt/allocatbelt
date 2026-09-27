//! Allocation logic for allocatbelt, written without `unsafe`.
//!
//! The core never dereferences memory. Every allocation is an *offset* into a
//! virtual arena owned by an [`Os`] implementation, and all bookkeeping lives
//! out-of-band in atomic metadata words that the [`Os`] hands out. Free blocks
//! are tracked with per-page bitmaps rather than intrusive free lists, so a
//! use-after-free write in user memory cannot corrupt allocator state, and a
//! double free is detected when the block's bit is already set.
//!
//! Converting offsets to pointers, committing memory and returning it to the
//! kernel are the responsibility of the embedding crate (see `allocatbelt-sys`).

#![no_std]
#![forbid(unsafe_code)]

#[cfg(not(all(target_pointer_width = "64", target_has_atomic = "64")))]
compile_error!(
    "allocatbelt needs a 64-bit target with 64-bit atomics (e.g. x86_64, aarch64, riscv64)"
);

#[cfg(test)]
extern crate std;

pub mod bits;
pub mod class;
pub mod heap;
mod lock;

pub use heap::{Block, Heap, Os};

/// log2 of [`PAGE_SIZE`].
pub const PAGE_SHIFT: u32 = 16;
/// Pages are the unit a size class is assigned to (64 KiB).
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
/// log2 of [`SEGMENT_SIZE`].
pub const SEGMENT_SHIFT: u32 = 22;
/// Segments are the unit of commit and of shard ownership (4 MiB).
pub const SEGMENT_SIZE: usize = 1 << SEGMENT_SHIFT;
/// Pages per segment; one `u64` tracks page occupancy of a segment.
pub const PAGES_PER_SEGMENT: usize = SEGMENT_SIZE / PAGE_SIZE;
/// Segments in the arena (64 GiB of address space).
pub const MAX_SEGMENTS: usize = 16 * 1024;
/// Size of the reserved virtual arena in bytes.
pub const ARENA_SIZE: usize = MAX_SEGMENTS * SEGMENT_SIZE;
/// Number of independently locked heaps threads are spread over.
pub const SHARDS: usize = 64;
/// Largest alignment the heap can satisfy (segment alignment).
pub const MAX_ALIGN: usize = SEGMENT_SIZE;

/// Words of per-page metadata: 4 header words and a 64-word free bitmap.
pub const PAGE_META_WORDS: usize = 4 + class::MAX_BITMAP_WORDS;
/// Words of segment header metadata that precede the page records.
pub const SEGMENT_HEADER_WORDS: usize = 4;
/// Metadata words the [`Os`] must provide for every segment.
pub const META_WORDS: usize = SEGMENT_HEADER_WORDS + PAGES_PER_SEGMENT * PAGE_META_WORDS;

const _: () = assert!(PAGES_PER_SEGMENT == 64);

#[cfg(test)]
mod tests;
