//! Bookkeeping of explicit-lifetime regions (theory-driven plan, Stage E):
//! checked bump arithmetic, chunk sizing and the retention rule, on
//! addresses held as integers.
//!
//! A region hands out consecutive, aligned pieces of chunks it takes from
//! the heap and gives the chunks back when it is reset or dropped; it never
//! frees one piece. Everything here is arithmetic that can fail: it returns
//! `None` instead of wrapping, so the adapter (`crate::region`), which owns
//! the chunks and builds the pointers, only ever computes addresses inside a
//! chunk it holds.

/// Every chunk is aligned to at least this, so small alignments cost no
/// padding at the start of a chunk.
pub const MIN_CHUNK_ALIGN: usize = 16;
/// Smallest standard chunk a region accepts.
pub const MIN_CHUNK: usize = 256;
/// Largest standard chunk a region accepts (one segment); larger requests
/// get chunks of their own.
pub const MAX_CHUNK: usize = super::SEGMENT_SIZE;
/// Standard chunk size by default: one allocator page (64 KiB).
pub const DEFAULT_CHUNK: usize = super::PAGE_SIZE;
/// Capacity a reset keeps by default (1 MiB).
pub const DEFAULT_RETAIN: usize = 1 << 20;

/// `addr` rounded up to a multiple of `align`, a power of two; `None` on
/// overflow or if `align` is not a power of two.
#[must_use]
pub const fn align_up(addr: usize, align: usize) -> Option<usize> {
  if !align.is_power_of_two() {
    return None;
  }
  match addr.checked_add(align - 1) {
    Some(a) => Some(a & !(align - 1)),
    None => None,
  }
}

/// Places `size` bytes aligned to `align` at or after `cursor` and ending
/// at or before `end`. Returns the start of the piece and the new cursor
/// (its end), or `None` if it does not fit or the arithmetic overflows.
#[must_use]
pub const fn bump(cursor: usize, end: usize, size: usize, align: usize) -> Option<(usize, usize)> {
  let Some(start) = align_up(cursor, align) else {
    return None;
  };
  match start.checked_add(size) {
    Some(next) if next <= end => Some((start, next)),
    _ => None,
  }
}

/// The standard chunk size a region uses for `requested` bytes: clamped to
/// [`MIN_CHUNK`]..=[`MAX_CHUNK`] and rounded up to [`MIN_CHUNK_ALIGN`].
#[must_use]
pub const fn standard_chunk(requested: usize) -> usize {
  let c = if requested < MIN_CHUNK {
    MIN_CHUNK
  } else if requested > MAX_CHUNK {
    MAX_CHUNK
  } else {
    requested
  };
  // Cannot overflow: `c <= MAX_CHUNK`.
  (c + MIN_CHUNK_ALIGN - 1) & !(MIN_CHUNK_ALIGN - 1)
}

/// Whether a request of `size` bytes aligned to `align` fits an empty
/// standard chunk of `chunk` bytes (aligned to [`MIN_CHUNK_ALIGN`]) at
/// every base address such a chunk can have. Otherwise it gets a chunk of
/// its own.
#[must_use]
pub const fn fits_standard(size: usize, align: usize, chunk: usize) -> bool {
  match size.checked_add(align.saturating_sub(MIN_CHUNK_ALIGN)) {
    Some(n) => n <= chunk,
    None => false,
  }
}

/// Size and alignment of a chunk of its own for a request of `size` bytes
/// aligned to `align`: the request starts at the chunk's base. `None` if
/// the size cannot be rounded up without overflow.
#[must_use]
pub const fn own_chunk(size: usize, align: usize) -> Option<(usize, usize)> {
  let a = if align > MIN_CHUNK_ALIGN {
    align
  } else {
    MIN_CHUNK_ALIGN
  };
  let s = if size == 0 { a } else { size };
  match align_up(s, MIN_CHUNK_ALIGN) {
    Some(s) => Some((s, a)),
    None => None,
  }
}

/// The retention rule of a reset, chunk by chunk in the order the region
/// took them: a standard chunk of `capacity` bytes is kept if the chunks
/// kept before it (`kept` bytes) and it stay within `retain` bytes. Chunks
/// of their own (larger requests) are never kept, so one unusually large
/// request does not stay resident after the reset.
#[must_use]
pub const fn keep_on_reset(standard: bool, capacity: usize, kept: usize, retain: usize) -> bool {
  if !standard {
    return false;
  }
  match kept.checked_add(capacity) {
    Some(total) => total <= retain,
    None => false,
  }
}

/// Whether taking a chunk of `capacity` bytes keeps the region's chunks
/// (`held` bytes now) within its `limit`.
#[must_use]
pub const fn within_limit(held: usize, capacity: usize, limit: usize) -> bool {
  match held.checked_add(capacity) {
    Some(total) => total <= limit,
    None => false,
  }
}

#[cfg(all(test, allocatbelt_core_check))]
mod tests;
