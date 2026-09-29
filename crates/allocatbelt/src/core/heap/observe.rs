//! Observations of what the heap does and holds, for diagnostics and for
//! deterministic tests of its work (Stage A of the theory-driven plan).
//!
//! Three kinds, each counted where it costs nothing on the fast paths:
//!
//! * **Search** ([`SearchStats`]): how refills and page-run allocations
//!   find memory. Counted per shard, under the shard lock that the counted
//!   work already holds, with a plain load and store (no read-modify-write,
//!   no shared cache line between shards). Read by summing the shards.
//! * **Free buffering** ([`CacheStats`]): what a thread's cache holds and
//!   how its buffered frees are flushed. Plain `Cell`s of the cache,
//!   updated when a buffered word is flushed, never on a free that is only
//!   buffered; read by the owning thread.
//! * **Memory** ([`HeapUsage`]): a walk over the owned segments that tells
//!   apart memory handed out, free blocks, dirty pages and clean pages.
//!
//! Purge work is in [`MaintenanceStats`](super::MaintenanceStats).
//!
//! Counters only grow and wrap modulo 2^64. A read while other threads work
//! is a set of individually atomic reads, not one consistent snapshot:
//! counters of different shards, or a counter and the state it describes,
//! can be one operation apart.

use super::*;

/// Search counters of one shard, updated under its lock.
#[derive(Clone, Copy)]
pub(super) enum SearchStat {
  Refill,
  CursorClaim,
  CursorRetired,
  PageSearch,
  PageSearchSegment,
  Candidate,
  StaleHint,
  NewPage,
  CursorInvalidation,
  RunSearch,
  RunSearchSegment,
  NewSegment,
  DirtyReuse,
}

/// Number of [`SearchStat`]s.
pub(super) const SEARCH_STATS: usize = 13;

impl Shard {
  /// Adds `n` to a search counter. Caller holds the shard lock, so a load
  /// and a store suffice.
  pub(super) fn bump(&self, stat: SearchStat, n: u64) {
    let a = &self.stats[stat as usize];
    a.store(a.load(Relaxed).wrapping_add(n), Relaxed);
  }
}

/// How the shards found memory for small-block refills and page runs,
/// summed over all shards. Read with `Allocatbelt::search_stats`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SearchStats {
  /// Bitmap words claimed for a size class (cache refills and uncached
  /// small allocations).
  pub refills: u64,
  /// Of those, words found on the shard's current page for the class (its
  /// cursor), without a search.
  pub cursor_claims: u64,
  /// Current pages that had no free block left and were dropped from the
  /// class's availability word.
  pub cursor_retired: u64,
  /// Searches for another page of the class with free blocks.
  pub page_searches: u64,
  /// Segments those searches visited (the shard's segment list, in order).
  pub page_search_segments: u64,
  /// Candidate pages (availability bits) those searches inspected.
  pub candidates: u64,
  /// Of those, availability bits that were stale (the page had no free
  /// block) and were dropped.
  pub stale_hints: u64,
  /// Pages set up for a size class because no page of it had free blocks.
  pub new_pages: u64,
  /// Current pages forgotten by trimming (see `release_empty_pages`), so
  /// the next refill of the class searches again.
  pub cursor_invalidations: u64,
  /// Searches for a free page run (large blocks and new small pages).
  pub run_searches: u64,
  /// Segments those searches visited.
  pub run_search_segments: u64,
  /// Segments taken from the arena because no owned segment had room.
  pub new_segments: u64,
  /// Dirty pages handed out again by page-run claims before a purge
  /// returned them: reuse the retention of freed pages paid for (the
  /// signal of [`Retention::Adaptive`](super::Retention::Adaptive)).
  pub dirty_reused_pages: u64,
}

/// What one thread's cache holds and how it flushed its buffered frees.
/// Read with `Allocatbelt::thread_cache_stats`. Counters cover the cache's
/// life; a cache that is retired keeps them, and they end with the thread.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
  /// Whether the cache is attached (caching); a detached or retired cache
  /// holds nothing.
  pub attached: bool,
  /// Free blocks of the claimed bitmap words, one word per size class at
  /// most: taken from the shared bitmaps, not handed out yet.
  pub claimed_blocks: u64,
  /// Freed blocks buffered and not yet returned to the shared bitmaps.
  pub buffered_blocks: u64,
  /// Bitmap words those buffered blocks belong to (occupied slots).
  pub buffered_words: u64,
  /// Buffered words returned to the shared bitmaps, each with one atomic
  /// read-modify-write.
  pub flushes: u64,
  /// Blocks returned by those flushes. `flushed_blocks / flushes` is the
  /// batch a shared update actually carried.
  pub flushed_blocks: u64,
  /// Flushes by the number of blocks they carried: 1, 2-3, 4-7, 8-15,
  /// 16-31, 32-63 and 64 (bucket `floor(log2(n))`).
  pub flush_sizes: [u64; 7],
  /// Flushes forced because a free of another word needed a slot and both
  /// ways of the word's set were taken (the buffer is 32 sets of 2 ways).
  pub evictions: u64,
  /// Flushes of a class's buffered frees before a refill of that class
  /// would have taken a new page.
  pub refill_flushes: u64,
  /// Times the cache drained itself for a cache-return request
  /// (`Allocatbelt::request_cache_return`), seen at one of its sampled
  /// slow paths.
  pub pressure_returns: u64,
}

/// A walk over the heap's segments that tells apart what the memory it
/// took from the arena is used for. Read with `Allocatbelt::heap_usage`.
///
/// Approximate while other threads allocate and free: each segment is read
/// word by word, and per-page free counts may lag a free by an instant.
/// None of these is the process's resident set size (RSS), which the OS
/// decides: pages never touched are not resident, purged pages are
/// resident again once written, and the allocator's metadata and thread
/// caches' own state are outside them.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeapUsage {
  /// Segments owned by shards (small blocks and page runs).
  pub owned_segments: usize,
  /// Segments of huge blocks (a block of `k` segments counts `k`).
  pub huge_segments: usize,
  /// Pages of owned segments that are in use (small pages and page runs;
  /// also pages a purge has claimed for the moment), guard pages excluded.
  pub pages_in_use: usize,
  /// Of those, pages of small blocks.
  pub small_pages: usize,
  /// Bytes of small blocks that are allocated or held by thread caches
  /// (claimed or buffered): capacity minus the free blocks in the shared
  /// bitmaps. Which of them are live is known only to the caches' owners
  /// (`Allocatbelt::thread_cache_stats`).
  pub small_bytes_out: usize,
  /// Bytes of free small blocks in the shared bitmaps, available to any
  /// thread: returned to the heap, not to the OS.
  pub small_bytes_free: usize,
  /// Free pages of owned segments marked dirty: freed, not purged yet
  /// (the pages the dirty budget counts), recounted from the marks.
  pub dirty_pages: usize,
  /// Free pages of owned segments that read as zero (never used, or
  /// purged).
  pub clean_pages: usize,
}

impl<O: Os> Heap<O> {
  /// The search counters of all shards, summed. Allocation-free; reads 13
  /// words per shard.
  pub fn search_stats(&self) -> SearchStats {
    let mut t = [0u64; SEARCH_STATS];
    for sh in &self.shards {
      for (t, a) in t.iter_mut().zip(&sh.stats) {
        *t = t.wrapping_add(a.load(Relaxed));
      }
    }
    let s = |stat: SearchStat| t[stat as usize];
    SearchStats {
      refills: s(SearchStat::Refill),
      cursor_claims: s(SearchStat::CursorClaim),
      cursor_retired: s(SearchStat::CursorRetired),
      page_searches: s(SearchStat::PageSearch),
      page_search_segments: s(SearchStat::PageSearchSegment),
      candidates: s(SearchStat::Candidate),
      stale_hints: s(SearchStat::StaleHint),
      new_pages: s(SearchStat::NewPage),
      cursor_invalidations: s(SearchStat::CursorInvalidation),
      run_searches: s(SearchStat::RunSearch),
      run_search_segments: s(SearchStat::RunSearchSegment),
      new_segments: s(SearchStat::NewSegment),
      dirty_reused_pages: s(SearchStat::DirtyReuse),
    }
  }

  /// Walks the segments taken from the arena and reports what their memory
  /// is used for (see [`HeapUsage`]). Allocation-free and lock-free; costs
  /// one read per segment header word and one per small page, so it is
  /// linear in the segments in use: for diagnostics, not for a hot path.
  pub fn usage(&self) -> HeapUsage {
    let mut u = HeapUsage::default();
    for (wi, word) in self.seg_used.iter().enumerate() {
      let mut used_segs = word.load(Relaxed);
      while used_segs != 0 {
        let seg = wi * 64 + used_segs.trailing_zeros() as usize;
        used_segs &= used_segs - 1;
        let Some(m) = self.os.meta(seg) else {
          continue;
        };
        match m[SEG_HDR].load(Acquire) & 0xFF {
          SEG_OWNED => {}
          SEG_HUGE | SEG_HUGE_TAIL => {
            u.huge_segments += 1;
            continue;
          }
          _ => continue,
        }
        u.owned_segments += 1;
        let pages = m[SEG_PAGES].load(Acquire) & !GUARD_BIT;
        let dirty = m[SEG_DIRTY].load(Acquire) & !pages & !GUARD_BIT;
        u.pages_in_use += pages.count_ones() as usize;
        u.dirty_pages += dirty.count_ones() as usize;
        u.clean_pages += (!pages & !dirty & !GUARD_BIT).count_ones() as usize;
        for c in 0..NUM_CLASSES {
          let mut small = m[SEG_CLS + c].load(Relaxed);
          u.small_pages += small.count_ones() as usize;
          while small != 0 {
            let i = small.trailing_zeros() as usize;
            small &= small - 1;
            let cap = class::capacity(c);
            let free = (PageMeta::new(m, i).free().load(Relaxed) as usize).min(cap);
            u.small_bytes_out += (cap - free) * class::size(c);
            u.small_bytes_free += free * class::size(c);
          }
        }
      }
    }
    u
  }
}

#[cfg(all(test, allocatbelt_core_check))]
impl<O: Os> Heap<O> {
  /// Runs `f` while shard `s` is locked, as by an allocating thread.
  pub(crate) fn with_shard_held<R>(&self, s: usize, f: impl FnOnce() -> R) -> R {
    let _g = self.shards[s].lock.lock(&self.os);
    f()
  }

  /// Runs `f` while the purge lock is held, as by a running pass.
  pub(crate) fn with_purge_lock_held<R>(&self, f: impl FnOnce() -> R) -> R {
    let _g = self.purge_lock.lock(&self.os);
    f()
  }
}
