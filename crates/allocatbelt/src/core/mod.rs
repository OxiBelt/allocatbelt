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
//! kernel are the responsibility of the embedding code (the `sys` module and
//! the adapter in `global.rs`).
//!
//! This module is safe Rust only (`forbid(unsafe_code)` below cannot be
//! lifted by any item inside it) and uses only `core`, never `std`, outside
//! test and model code. The development package `allocatbelt-core-check`
//! compiles this same source as its own `#![no_std]` crate, so a `std`
//! dependency fails to build there, and runs the core's model, property and
//! loom tests.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]
// The core's API serves the adapter here and, in allocatbelt-core-check (where
// it is public, and where unused private items still warn), the tests, the
// fuzz target and the probes; the adapter alone does not use all of it.
#![cfg_attr(
  not(allocatbelt_core_check),
  allow(dead_code, unused_imports, reason = "used by allocatbelt-core-check")
)]

#[cfg(not(all(target_pointer_width = "64", target_has_atomic = "64")))]
compile_error!(
  "allocatbelt needs a 64-bit target with 64-bit atomics (e.g. x86_64, aarch64, riscv64)"
);

pub mod bits;
pub mod class;
#[cfg(not(loom))]
pub mod heap;
#[cfg_attr(loom, allow(dead_code))]
mod lock;
#[cfg(all(any(all(test, allocatbelt_core_check), allocatbelt_model), not(loom)))]
pub mod model;
#[cfg_attr(loom, allow(dead_code))]
mod proto;
mod sync;

#[cfg(not(loom))]
pub use heap::{
  AgeKernel, Block, CacheStats, DIRTY_HARD_LIMIT_PAGES, Heap, HeapUsage, MaintenanceStats, Os,
  PURGE_BATCH, Purger, SearchStats, SyncPurger, Task, ThreadCache, aged_pages,
};

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
/// Words of segment header metadata that precede the page records: eight
/// words of segment state, then two bitmaps per size class.
pub const SEGMENT_HEADER_WORDS: usize = 8 + 2 * class::NUM_CLASSES;
/// Metadata words the [`Os`] must provide for every segment.
pub const META_WORDS: usize = SEGMENT_HEADER_WORDS + PAGES_PER_SEGMENT * PAGE_META_WORDS;

const _: () = assert!(PAGES_PER_SEGMENT == 64);

#[cfg(all(test, allocatbelt_core_check, not(loom)))]
mod tests;
