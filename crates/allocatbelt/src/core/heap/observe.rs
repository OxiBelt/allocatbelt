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
  PageInspected,
  FullPagePassed,
  NewPage,
  RunSearch,
  RunSearchSegment,
  NewSegment,
  DirtyReuse,
}

/// Number of [`SearchStat`]s.
pub(super) const SEARCH_STATS: usize = 8;

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
  /// Claims for a size class: a bitmap word for a cache refill, a single
  /// block for an uncached small allocation. Each searches the shard's
  /// segments by address for the lowest page of the class with free blocks
  /// or free page, from the class's and the shard's lower bounds.
  pub refills: u64,
  /// Pages those searches looked at: pages of the class whose free count
  /// they read, and the free page they stopped at.
  pub pages_inspected: u64,
  /// Of those, pages of the class with no free block, passed over.
  pub full_pages_passed: u64,
  /// Free pages set up for a size class because they were the lowest
  /// candidates, or pages of new segments because there was none.
  pub new_pages: u64,
  /// Searches for a free page run (large blocks).
  pub run_searches: u64,
  /// Segments those searches visited.
  pub run_search_segments: u64,
  /// Segments taken from the arena because no owned segment had room (for
  /// a page run or a small page).
  pub new_segments: u64,
  /// Dirty pages handed out again (as page runs or new small pages) before a purge
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
  /// The shard (0 to 63) the cache prefers when the environment gives no
  /// hint: the one it was attached to, or the one set with
  /// `Allocatbelt::set_thread_shard`.
  pub shard: usize,
  /// Free blocks of the claimed bitmap words, one word per size class at
  /// most: taken from the shared bitmaps, not handed out yet.
  pub claimed_blocks: u64,
  /// Freed blocks buffered and not yet returned to the shared bitmaps.
  pub buffered_blocks: u64,
  /// Bitmap words those buffered blocks belong to (occupied slots).
  pub buffered_words: u64,
  /// Buffered words returned to the shared bitmaps, each in one update
  /// under the lock of the shard that owns the word's page.
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
  /// The search counters of all shards, summed. Allocation-free; reads 8
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
      pages_inspected: s(SearchStat::PageInspected),
      full_pages_passed: s(SearchStat::FullPagePassed),
      new_pages: s(SearchStat::NewPage),
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
            // Read without the owner's lock: may be one update behind.
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

#[cfg(any(all(test, allocatbelt_core_check), allocatbelt_model))]
impl<O: Os> Heap<O> {
  /// Checks the search bounds against the metadata, while no operation is
  /// running: every shard's segments are its own and listed in address
  /// order, no page of a class with free blocks lies below the class's
  /// bound and no free page below the shard's, every small page's free
  /// counter is the number of its free bits, and every small page whose
  /// blocks are all free is an empty-page candidate of its segment.
  pub fn check_indexes(&self) {
    for (s, sh) in self.shards.iter().enumerate() {
      let mut segs = std::vec::Vec::new();
      let mut cur = sh.segs.load(Relaxed);
      while cur != 0 {
        let seg = cur as usize - 1;
        let m = self.seg_meta(seg);
        let hdr = m[SEG_HDR].load(Acquire);
        assert_eq!(
          (hdr & 0xFF, (hdr >> 8) & 0xFF),
          (SEG_OWNED, s as u64),
          "segment {seg} on the list of shard {s}"
        );
        assert!(
          segs.last().is_none_or(|&last| last < seg),
          "shard {s} lists segment {seg} out of address order"
        );
        segs.push(seg);
        cur = m[SEG_NEXT].load(Relaxed) as u32;
      }
      let free_low = sh.free_low.load(Relaxed);
      for &seg in &segs {
        let m = self.seg_meta(seg);
        let first = seg * PAGES_PER_SEGMENT;
        let free = !m[SEG_PAGES].load(Relaxed);
        if free != 0 {
          let lowest = (first + free.trailing_zeros() as usize) as u64;
          assert!(
            lowest >= free_low,
            "free page {lowest} below the bound {free_low} of shard {s}"
          );
        }
        let empty = m[SEG_EMPTY].load(Relaxed);
        for (c, cs) in sh.classes.iter().enumerate() {
          let low = cs.low.load(Relaxed);
          let mut small = m[SEG_CLS + c].load(Relaxed);
          while small != 0 {
            let i = small.trailing_zeros() as usize;
            small &= small - 1;
            let pm = PageMeta::new(m, i);
            assert_eq!(
              pm.info().load(Acquire),
              PAGE_SMALL | (c as u64) << 8,
              "page {i} of segment {seg} is marked as class {c}"
            );
            let bits: u64 = pm
              .bitmaps()
              .iter()
              .map(|w| u64::from(w.load(Relaxed).count_ones()))
              .sum();
            assert_eq!(
              pm.free().load(Relaxed),
              bits,
              "page {i} of segment {seg} (class {c}): counter and bitmap disagree"
            );
            if bits > 0 {
              assert!(
                (first + i) as u64 >= low,
                "page {i} of segment {seg} (class {c}) has free blocks below the bound {low}"
              );
            }
            if proto::all_free(pm.free(), class::capacity(c) as u64) {
              assert_ne!(
                empty & 1 << i,
                0,
                "fully free page {i} of segment {seg} (class {c}) is not a candidate"
              );
            }
          }
        }
      }
    }
  }
}

#[cfg(all(test, allocatbelt_core_check))]
impl<O: Os> Heap<O> {
  /// Runs `f` while shard `s` is locked, as by an allocating thread.
  pub(crate) fn with_shard_held<R>(&self, s: usize, f: impl FnOnce() -> R) -> R {
    let _g = self.shards[s].lock.lock(&self.os);
    f()
  }

  /// Drops every empty-page candidate, as a lost publication would.
  pub(crate) fn forget_empty_candidates(&self) {
    for seg in 0..MAX_SEGMENTS {
      if let Some(m) = self.os.meta(seg) {
        m[SEG_EMPTY].store(0, Relaxed);
      }
    }
  }

  /// Runs `f` while the purge lock is held, as by a running pass.
  pub(crate) fn with_purge_lock_held<R>(&self, f: impl FnOnce() -> R) -> R {
    let _g = self.purge_lock.lock(&self.os);
    f()
  }
}
