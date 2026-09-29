//! The heap: segment allocation, page runs, small-object bitmaps, per-thread
//! caches and frees.
//!
//! Metadata layout (all `AtomicU64`, one slice of [`META_WORDS`] per segment):
//!
//! ```text
//! [0] SEG_HDR    kind | shard << 8 | segment count << 16
//! [1] SEG_PAGES  occupancy bitmap of the 64 pages (1 = in use)
//! [2] SEG_NEXT   next segment of the owning shard (index + 1, 0 = end)
//! [3] SEG_DIRTY  free pages whose memory has not been purged yet; while
//!                the segment is not owned, non-zero if its memory may hold
//!                non-zero bytes
//! [4..8]         reserved
//! [SEG_CLS + c]    small pages of class c (changed under the shard lock)
//! [SEG_AVAIL + c]  pages of class c that may have free blocks
//! then per page (PAGE_META_WORDS each):
//!   [0] P_INFO     kind | class << 8 | run length << 16
//!   [1] P_FREE     number of set bits in the bitmap (may transiently lag)
//!   [2] P_SUMMARY  small pages: bitmap words that may be non-zero
//!   [3] P_SINCE    free pages: decay epoch in which the page was last
//!                  marked dirty
//!   [4..68]        free bitmap (1 = free block)
//! ```
//!
//! Small objects: a thread allocates from a [`ThreadCache`] that holds one
//! claimed bitmap word per size class, so the fast path is a bit pop on
//! thread-local `Cell`s with no atomics and no lock. When the word runs out,
//! the thread takes its shard's lock and claims the next word of the shard's
//! current page for that class. Finding that word and page goes through two
//! levels of summaries (page summary word, then the segment's per-class
//! availability word), each a `trailing_zeros`, rather than a scan of pages.
//! The protocols that keep the summaries exact in the face of racing frees
//! are in [`crate::core::proto`].
//!
//! Frees never take a lock. A thread with a cache buffers the freed bit in a
//! small direct-mapped table keyed by (page, bitmap word); the buffer is
//! flushed with one `fetch_or` per word, so a burst of frees into the same
//! word costs one read-modify-write. Every free, buffered or not, reaches the
//! shared bitmap through `fetch_or` before its block can be handed out again,
//! and the bit value returned there detects double frees. A large free is a
//! compare-exchange on the page header and a `fetch_and` on the segment's
//! page bitmap. Only the owning shard (under its lock) hands out bits, and
//! only it recycles a page, which it does solely when every block of the page
//! is free.
//!
//! Purging is deferred: freed page runs are only marked dirty. Once more than
//! [`DIRTY_BUDGET_PAGES`] pages are dirty, the freeing thread claims the dirty
//! free pages of every segment (as if allocating them), `madvise`s them and
//! releases them again. Purging on every free costs an `mmap_lock` round trip
//! and a TLB shootdown per call, which dominated multi-threaded profiles.
//! The same pass returns segments whose pages have all been free since the
//! previous pass to the arena, keeping one empty segment per shard; both
//! damp the decommit/recommit churn of a workload that empties and refills
//! segments.
//!
//! Zero tracking: memory that was never handed out, or that was purged or
//! decommitted successfully, reads as zero. Free pages that are not dirty are
//! such memory, so a page run or segment run claimed without dirty pages is
//! reported as zeroed ([`Block::zeroed`]) and `calloc` can skip the memset.

use core::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::core::bits::{pick_bit, run_mask};
use crate::core::class::{self, MIN_ALIGN, NUM_CLASSES, SMALL_MAX};
use crate::core::lock::{Lock, Park};
use crate::core::proto;
use crate::core::{
  ARENA_SIZE, MAX_ALIGN, MAX_SEGMENTS, PAGE_META_WORDS, PAGE_SHIFT, PAGE_SIZE, PAGES_PER_SEGMENT,
  SEGMENT_HEADER_WORDS, SEGMENT_SHIFT, SEGMENT_SIZE, SHARDS,
};

use Ordering::{AcqRel, Acquire, Relaxed, Release};

mod cache;
mod fork;
mod maint;
mod observe;
mod purge;

pub use cache::ThreadCache;
pub use maint::{DIRTY_HARD_LIMIT_PAGES, MaintenanceStats, Task};
pub use observe::{CacheStats, HeapUsage, SearchStats};
use observe::{SEARCH_STATS, SearchStat};
use purge::Pass;
pub use purge::{PURGE_BATCH, Purger, SyncPurger};

/// The age scan of a decay pass over one segment: see [`aged_pages`].
pub type AgeKernel = fn(&[u64; PAGES_PER_SEGMENT], u64) -> u64;

const _: () = assert!(PAGES_PER_SEGMENT == 64);

/// Which pages of a segment are old enough to purge: bit `i` is set if page
/// `i` was last marked dirty in decay epoch `since[i]` or earlier
/// (`since[i] <= cutoff`). The portable [`AgeKernel`] and the definition
/// every architecture kernel must match. Inlined into each kernel, so that
/// the kernel's target features apply to the loop.
#[inline(always)]
#[must_use]
pub fn aged_pages(since: &[u64; PAGES_PER_SEGMENT], cutoff: u64) -> u64 {
  let mut aged = 0u64;
  for (i, &t) in since.iter().enumerate() {
    aged |= u64::from(t <= cutoff) << i;
  }
  aged
}

/// Services the heap needs from its environment.
///
/// Offsets are relative to the start of a [`ARENA_SIZE`]-byte arena whose base
/// is aligned to [`SEGMENT_SIZE`]. The heap guarantees that it only calls
/// [`Os::decommit`] and [`Os::purge`] on ranges that contain no live
/// allocation, and that it never hands out an offset that has not been
/// committed.
///
/// The heap relies on arena memory reading as zero until it is first handed
/// out, and again after a [`Os::purge`] or [`Os::decommit`] that returned
/// `true`, and reports such blocks as [`Block::zeroed`].
pub trait Os: Sync {
  /// Makes `offset..offset + len` readable and writable. Returns `false` if
  /// the memory cannot be provided. Never changes the contents.
  fn commit(&self, offset: usize, len: usize) -> bool;
  /// Returns the physical memory of the range to the OS and makes it
  /// inaccessible. Returns `true` if the range will read as zero once it is
  /// committed again.
  fn decommit(&self, offset: usize, len: usize) -> bool;
  /// Returns the physical memory of the range to the OS but keeps it
  /// accessible. Returns `true` if the range now reads as zero.
  fn purge(&self, offset: usize, len: usize) -> bool;
  /// Commits (once) and returns the [`crate::core::META_WORDS`] metadata words of
  /// `segment`. Words are zero the first time they are returned.
  fn commit_meta(&self, segment: usize) -> Option<&[AtomicU64]>;
  /// Metadata words of `segment` if [`Os::commit_meta`] succeeded before.
  fn meta(&self, segment: usize) -> Option<&[AtomicU64]>;
  /// Makes `offset..offset + len` fault on any access, discarding its
  /// contents. Returns whether a guard is in place. The heap only guards
  /// ranges that hold no live allocation, never hands them out while
  /// guarded, and calls [`Os::unguard`] before the range can be committed
  /// for other use. The default installs no guard.
  fn guard(&self, offset: usize, len: usize) -> bool {
    let _ = (offset, len);
    false
  }
  /// Removes a guard installed by [`Os::guard`]. The range need not become
  /// accessible until it is committed again.
  fn unguard(&self, offset: usize, len: usize) {
    let _ = (offset, len);
  }
  /// Blocks the calling thread while `word` holds `expected`, for at most
  /// `timeout_ms` if given: a `FUTEX_WAIT`. Used by a heap lock that stayed
  /// held after a short spin (no timeout) and by an idle maintenance thread
  /// ([`Heap::maintain`]). Checking the value and going to sleep must be
  /// atomic with respect to [`Os::futex_wake`]. May return early or
  /// spuriously. The default returns at once, which makes contended locks
  /// spin.
  fn futex_wait(&self, word: &AtomicU32, expected: u32, timeout_ms: Option<u64>) {
    let _ = (word, expected, timeout_ms);
    core::hint::spin_loop();
  }
  /// Wakes one thread blocked in [`Os::futex_wait`] on `word`: a
  /// `FUTEX_WAKE`. Called when an unlock finds a thread may be parked, and
  /// when work for the maintenance thread is recorded.
  fn futex_wake(&self, word: &AtomicU32) {
    let _ = word;
  }
  /// Milliseconds on a monotonic clock, for delaying purges (see
  /// [`Heap::decay`]). A clock that never advances, like this default,
  /// leaves purging to the dirty budget and explicit [`Heap::purge`] calls.
  fn now_ms(&self) -> u64 {
    0
  }
  /// The shard the calling thread should prefer right now, in place of the
  /// one its cache was given when attached; `None` keeps that one. Asked
  /// on cache refills and other uncached allocations, never on the cached
  /// fast path. Only a preference: the shard is locked either way, so a
  /// hint that is stale by the time it is used (the thread moved to
  /// another CPU) costs locality, never correctness. The default returns
  /// `None`.
  fn shard_hint(&self) -> Option<usize> {
    None
  }
  /// An architecture kernel for the age scan of decay passes, or `None`
  /// for the portable loop over the candidate pages. Asked once per decay
  /// pass. A kernel must return exactly what [`aged_pages`] returns, and
  /// only sees a private snapshot of the pages' ages, never the shared
  /// metadata. The default returns `None`.
  fn age_kernel(&self) -> Option<AgeKernel> {
    None
  }
  /// Reports heap corruption or misuse (invalid or double free). Must not
  /// return.
  fn fatal(&self, msg: &'static str) -> !;
}

/// Heap locks park through the [`Os`].
impl<O: Os> Park for O {
  fn wait(&self, word: &AtomicU32, expected: u32) {
    self.futex_wait(word, expected, None);
  }
  fn wake(&self, word: &AtomicU32) {
    self.futex_wake(word);
  }
}

const SEG_HDR: usize = 0;
const SEG_PAGES: usize = 1;
const SEG_NEXT: usize = 2;
const SEG_DIRTY: usize = 3;
/// Decay epoch (+ 1) in which a purge pass first found the owned segment
/// empty, or 0.
const SEG_IDLE: usize = 4;
const SEG_CLS: usize = 8;
const SEG_AVAIL: usize = SEG_CLS + NUM_CLASSES;

const _: () = assert!(SEG_AVAIL + NUM_CLASSES == SEGMENT_HEADER_WORDS);

const SEG_FREE: u64 = 0;
const SEG_OWNED: u64 = 1;
const SEG_HUGE: u64 = 2;
const SEG_HUGE_TAIL: u64 = 3;

const P_INFO: usize = 0;
const P_FREE: usize = 1;
const P_SUMMARY: usize = 2;
/// Free pages: the decay epoch in which the page was last marked dirty.
const P_SINCE: usize = 3;
const P_BITMAP: usize = 4;

const PAGE_FREE: u64 = 0;
const PAGE_SMALL: u64 = 1;
const PAGE_LARGE: u64 = 2;
const PAGE_LARGE_TAIL: u64 = 3;

/// The last page of every owned segment is a guard page: never handed out
/// and, where the [`Os`] supports it, faulting on access, so that a linear
/// overflow out of one segment's last block cannot run into the next
/// segment's memory.
const GUARD_PAGE: usize = PAGES_PER_SEGMENT - 1;
const GUARD_BIT: u64 = 1 << GUARD_PAGE;
/// Longest page run inside a segment; longer blocks take whole segments.
pub const MAX_RUN_PAGES: usize = PAGES_PER_SEGMENT - 1;

/// Dirty (freed, unpurged) pages tolerated before a purge pass (32 MiB).
/// A bound on the pages the heap tracks as dirty, not on the process's
/// RSS: live and cached blocks, metadata, and memory the OS keeps resident
/// after a purge are outside it (see [`HeapUsage`]).
pub const DIRTY_BUDGET_PAGES: isize = 512;
/// How long freed pages stay resident, and empty segments stay owned,
/// before a decay pass returns them (see [`Heap::set_purge_delay_ms`]).
pub const DEFAULT_PURGE_DELAY_MS: u64 = 1000;
/// Shards tried with `try_lock` before blocking on the preferred one.
const SHARD_PROBES: usize = 4;

const INVALID_FREE: &str = "allocatbelt: invalid or double free (pointer is not allocated)";
const DOUBLE_FREE: &str = "allocatbelt: double free detected";

#[derive(Debug)]
struct ClassState {
  /// Page (+ 1) this shard currently claims words of this class from; 0
  /// when there is none.
  cursor: AtomicU64,
}

impl ClassState {
  const fn new() -> Self {
    Self {
      cursor: AtomicU64::new(0),
    }
  }
}

#[derive(Debug)]
#[repr(align(128))]
struct Shard {
  lock: Lock,
  /// Head of the list of segments owned by this shard (segment + 1).
  segs: AtomicU32,
  /// Random state for placement decisions, stepped under the lock; 0 while
  /// randomization is off.
  rng: AtomicU64,
  classes: [ClassState; NUM_CLASSES],
  /// [`SearchStats`] of this shard, indexed by [`SearchStat`], changed
  /// under the lock.
  stats: [AtomicU64; SEARCH_STATS],
}

impl Shard {
  const fn new() -> Self {
    Self {
      lock: Lock::new(),
      segs: AtomicU32::new(0),
      rng: AtomicU64::new(0),
      classes: [const { ClassState::new() }; NUM_CLASSES],
      stats: [const { AtomicU64::new(0) }; SEARCH_STATS],
    }
  }

  /// Next random number, or 0 if randomization is off. Caller holds the
  /// lock.
  fn random(&self) -> u32 {
    let x = self.rng.load(Relaxed);
    if x == 0 {
      return 0;
    }
    let x = xorshift(x);
    self.rng.store(x, Relaxed);
    (x >> 32) as u32
  }
}

/// One step of xorshift64 (never maps a non-zero state to zero).
const fn xorshift(mut x: u64) -> u64 {
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  x
}

/// splitmix64: spreads a seed into an independent non-zero state.
const fn splitmix(seed: u64) -> u64 {
  let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
  z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
  z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
  z ^= z >> 31;
  if z == 0 { 1 } else { z }
}

// ---- blocks and metadata views -------------------------------------------

/// A fresh allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block {
  /// Arena offset of the first byte.
  pub offset: usize,
  /// The whole block already reads as zero.
  pub zeroed: bool,
}

impl Block {
  const fn new(offset: usize, zeroed: bool) -> Self {
    Self { offset, zeroed }
  }
}

/// How a request is served.
enum Kind {
  /// A block of size class `c`.
  Small(usize),
  /// A run of `n` pages starting at a multiple of `step` pages.
  Run(usize, usize),
  /// A run of `k` whole segments.
  Huge(usize),
}

/// What an allocated offset refers to.
enum Target<'a> {
  /// A class block `in_page` bytes into `page`.
  Small {
    in_page: usize,
    page: usize,
    c: usize,
  },
  /// A page run starting at `page`.
  Large {
    page: usize,
    m: &'a [AtomicU64],
    pm: PageMeta<'a>,
    info: u64,
  },
  /// A run of segments starting at `seg`.
  Huge {
    seg: usize,
    m: &'a [AtomicU64],
    hdr: u64,
  },
}

/// View of one page's metadata words.
#[derive(Clone, Copy)]
struct PageMeta<'a>(&'a [AtomicU64]);

impl<'a> PageMeta<'a> {
  fn new(seg_meta: &'a [AtomicU64], page_in_seg: usize) -> Self {
    let base = SEGMENT_HEADER_WORDS + page_in_seg * PAGE_META_WORDS;
    Self(&seg_meta[base..base + PAGE_META_WORDS])
  }
  fn info(self) -> &'a AtomicU64 {
    &self.0[P_INFO]
  }
  fn free(self) -> &'a AtomicU64 {
    &self.0[P_FREE]
  }
  fn summary(self) -> &'a AtomicU64 {
    &self.0[P_SUMMARY]
  }
  fn since(self) -> &'a AtomicU64 {
    &self.0[P_SINCE]
  }
  fn bitmap(self, w: usize) -> &'a AtomicU64 {
    &self.0[P_BITMAP + w]
  }
  fn bitmaps(self) -> &'a [AtomicU64] {
    &self.0[P_BITMAP..]
  }
}

/// A sharded heap handing out offsets into the arena managed by `O`.
#[derive(Debug)]
pub struct Heap<O> {
  os: O,
  seg_lock: Lock,
  seg_used: [AtomicU64; MAX_SEGMENTS / 64],
  /// Pages marked dirty and not yet purged or reused (may transiently lag).
  dirty_pages: AtomicIsize,
  purge_lock: Lock,
  purge_delay_ms: AtomicU64,
  /// Clock reading of the last decay pass.
  last_decay_ms: AtomicU64,
  /// Decay passes so far. Freed pages and empty segments are stamped with
  /// it, so freeing never reads the clock.
  epoch: AtomicU64,
  /// Allocation slow paths run decay passes when they are due (unless a
  /// background thread does, see [`Heap::set_auto_decay`]).
  auto_decay: AtomicBool,
  /// A thread runs [`Heap::maintain`] (see [`maint`]).
  maint_attached: AtomicBool,
  /// Work recorded for the maintenance thread, which sleeps on this word.
  maint_work: AtomicU32,
  /// [`MaintenanceStats`], indexed by `maint::Stat`.
  maint_stats: [AtomicU64; maint::STATS],
  /// Round-robin shard assignment for attached thread caches.
  next_shard: AtomicUsize,
  /// Secret for randomized placement; 0 turns randomization off.
  seed: AtomicU64,
  shards: [Shard; SHARDS],
}

impl<O: Os> Heap<O> {
  /// Creates an empty heap. No memory is touched until the first allocation.
  pub const fn new(os: O) -> Self {
    Self {
      os,
      seg_lock: Lock::new(),
      seg_used: [const { AtomicU64::new(0) }; MAX_SEGMENTS / 64],
      dirty_pages: AtomicIsize::new(0),
      purge_lock: Lock::new(),
      purge_delay_ms: AtomicU64::new(DEFAULT_PURGE_DELAY_MS),
      last_decay_ms: AtomicU64::new(0),
      epoch: AtomicU64::new(0),
      auto_decay: AtomicBool::new(true),
      maint_attached: AtomicBool::new(false),
      maint_work: AtomicU32::new(0),
      maint_stats: [const { AtomicU64::new(0) }; maint::STATS],
      next_shard: AtomicUsize::new(0),
      seed: AtomicU64::new(0),
      shards: [const { Shard::new() }; SHARDS],
    }
  }

  /// The environment this heap runs on.
  pub const fn os(&self) -> &O {
    &self.os
  }

  /// Seeds randomized placement: the bitmap word a refill claims, the order
  /// a thread hands out the blocks of a word, and where new segments go in
  /// the arena. The embedder passes a secret from the OS (e.g.
  /// `getrandom`), so that heap layout is hard to predict; 0 (the default)
  /// turns randomization off. Threads attached earlier keep their state.
  pub fn set_seed(&self, seed: u64) {
    self.seed.store(seed, Relaxed);
    for (i, sh) in self.shards.iter().enumerate() {
      let x = if seed == 0 {
        0
      } else {
        splitmix(seed ^ ((i as u64) << 32))
      };
      sh.rng.store(x, Relaxed);
    }
  }

  fn kind(size: usize, align: usize) -> Option<Kind> {
    if !align.is_power_of_two() || align > MAX_ALIGN || size > ARENA_SIZE / 2 {
      return None;
    }
    if align <= MIN_ALIGN && size <= SMALL_MAX {
      return Some(Kind::Small(class::class_of(size)));
    }
    if let Some(c) = class::class_for(size, align) {
      return Some(Kind::Small(c));
    }
    let n = size.div_ceil(PAGE_SIZE).max(1);
    if n <= MAX_RUN_PAGES {
      // Alignments above a page place the run at a multiple of
      // `align / PAGE_SIZE` pages; the segment itself is aligned.
      return Some(Kind::Run(n, (align / PAGE_SIZE).max(1)));
    }
    Some(Kind::Huge(size.div_ceil(SEGMENT_SIZE).max(1)))
  }

  /// Allocates `size` bytes aligned to `align` and returns the arena offset.
  ///
  /// `shard_hint` selects the preferred shard (typically a per-thread
  /// value). Returns `None` when out of memory or when `align` is not a
  /// power of two no larger than [`MAX_ALIGN`].
  pub fn alloc(&self, shard_hint: usize, size: usize, align: usize) -> Option<usize> {
    self.alloc_block(shard_hint, size, align).map(|b| b.offset)
  }

  /// As [`Heap::alloc`], but also reports whether the block is known to
  /// read as zero, so a zeroing allocation can skip clearing it.
  ///
  /// This is the uncached path: a small allocation claims a bitmap word
  /// under the shard lock and returns the blocks it does not use.
  pub fn alloc_block(&self, shard_hint: usize, size: usize, align: usize) -> Option<Block> {
    match Self::kind(size, align)? {
      Kind::Small(c) => self
        .alloc_small(shard_hint, c)
        .map(|o| Block::new(o, false)),
      Kind::Run(n, step) => self.alloc_large(shard_hint, n, step),
      Kind::Huge(k) => self.alloc_huge(k),
    }
  }

  /// Frees the allocation at `offset`. Invalid and double frees are reported
  /// through [`Os::fatal`].
  pub fn dealloc(&self, offset: usize) {
    match self.block(offset, INVALID_FREE) {
      Target::Small { in_page, page, c } => {
        let (w, bit) = self.block_bit(in_page, c);
        self.free_bits(page, c, w, bit);
      }
      Target::Large { page, m, pm, info } => self.free_large(page, m, pm, info),
      Target::Huge { seg, m, hdr } => self.free_huge(seg, m, hdr),
    }
  }

  /// Bytes usable at `offset`, which must be a live allocation.
  pub fn usable_size(&self, offset: usize) -> usize {
    match self.block(
      offset,
      "allocatbelt: size query for a pointer that is not allocated",
    ) {
      Target::Small { c, .. } => class::size(c),
      Target::Large { info, .. } => ((info >> 16) & 0xFF) as usize * PAGE_SIZE,
      Target::Huge { hdr, .. } => (hdr >> 16) as usize * SEGMENT_SIZE,
    }
  }

  /// Tries to make the live block at `offset` hold `new_size` bytes without
  /// moving it. Returns `false` when the caller should move it instead
  /// (allocate, copy, free).
  ///
  /// A block is kept when it still fits and would not waste more than half
  /// of itself. Page and segment runs also grow into free neighbours and
  /// hand their unused tail back, so they only move when the neighbours are
  /// taken or when a size class would fit the new size much better.
  pub fn resize_in_place(&self, offset: usize, new_size: usize) -> bool {
    match self.block(
      offset,
      "allocatbelt: realloc of a pointer that is not allocated",
    ) {
      Target::Small { c, .. } => {
        let size = class::size(c);
        new_size <= size && new_size >= size / 2
      }
      Target::Large { page, m, pm, info } => {
        let n = ((info >> 16) & 0xFF) as usize;
        let n2 = new_size.div_ceil(PAGE_SIZE).max(1);
        if n2 > MAX_RUN_PAGES {
          return false;
        }
        if n2 > n {
          return self.grow_large(page, m, pm, n, n2);
        }
        if new_size <= SMALL_MAX && new_size < n * PAGE_SIZE / 2 {
          return false;
        }
        if n2 < n {
          self.shrink_large(page, m, pm, n, n2);
        }
        true
      }
      Target::Huge { seg, m, hdr } => {
        let k = (hdr >> 16) as usize;
        let k2 = new_size.div_ceil(SEGMENT_SIZE).max(1);
        if k2 > k {
          return self.grow_huge(seg, m, k, k2);
        }
        if new_size <= SEGMENT_SIZE && new_size < k * SEGMENT_SIZE / 2 {
          return false;
        }
        if k2 < k {
          self.shrink_huge(seg, m, k, k2);
        }
        true
      }
    }
  }

  /// Resolves `offset` to the block it starts, or reports `bad` if it does
  /// not start an allocated block. Inlined so that the free path matches
  /// on the page kind directly instead of returning a `Target`.
  #[inline(always)]
  fn block(&self, offset: usize, bad: &'static str) -> Target<'_> {
    let (seg, m, hdr) = self.lookup(offset);
    match hdr & 0xFF {
      SEG_OWNED => {
        let page = offset >> PAGE_SHIFT;
        let in_seg = page % PAGES_PER_SEGMENT;
        let pm = PageMeta::new(m, in_seg);
        let info = pm.info().load(Acquire);
        match info & 0xFF {
          PAGE_SMALL => Target::Small {
            in_page: offset % PAGE_SIZE,
            page,
            c: ((info >> 8) & 0xFF) as usize,
          },
          PAGE_LARGE if offset.is_multiple_of(PAGE_SIZE) => Target::Large { page, m, pm, info },
          _ => self.os.fatal(bad),
        }
      }
      SEG_HUGE if offset.is_multiple_of(SEGMENT_SIZE) => Target::Huge { seg, m, hdr },
      _ => self.os.fatal(bad),
    }
  }

  /// Pages freed but not yet purged or reused.
  pub fn dirty_pages(&self) -> usize {
    self.dirty_pages.load(Relaxed).max(0) as usize
  }

  /// Number of segments currently taken from the arena.
  pub fn segments_in_use(&self) -> usize {
    self
      .seg_used
      .iter()
      .map(|w| w.load(Relaxed).count_ones() as usize)
      .sum()
  }

  fn lookup(&self, offset: usize) -> (usize, &[AtomicU64], u64) {
    if offset >= ARENA_SIZE {
      self.os.fatal("allocatbelt: pointer outside the arena");
    }
    let seg = offset >> SEGMENT_SHIFT;
    let Some(m) = self.os.meta(seg) else {
      self.os.fatal("allocatbelt: pointer into an unused segment");
    };
    let hdr = m[SEG_HDR].load(Acquire);
    (seg, m, hdr)
  }

  fn seg_meta(&self, seg: usize) -> &[AtomicU64] {
    match self.os.meta(seg) {
      Some(m) => m,
      None => self
        .os
        .fatal("allocatbelt: metadata missing for an owned segment"),
    }
  }

  /// Runs `f` with a locked shard, preferring `hint` and probing a few
  /// neighbours before blocking so that threads sharing a shard rarely spin.
  fn with_shard<R>(&self, hint: usize, f: impl FnOnce(usize, &Shard) -> R) -> R {
    for i in 0..SHARD_PROBES {
      let s = (hint + i) % SHARDS;
      if let Some(_g) = self.shards[s].lock.try_lock(&self.os) {
        return f(s, &self.shards[s]);
      }
    }
    let s = hint % SHARDS;
    let _g = self.shards[s].lock.lock(&self.os);
    f(s, &self.shards[s])
  }

  // ---- small objects -------------------------------------------------

  /// Uncached small allocation: claims a word, keeps one block and gives
  /// the rest back.
  fn alloc_small(&self, hint: usize, c: usize) -> Option<usize> {
    let (page, w, bits) =
      self.with_shard(hint, |s, sh| self.claim_class_word(s, sh, c, true))??;
    let i = bits.trailing_zeros() as usize;
    let rest = bits & (bits - 1);
    if rest != 0 {
      self.free_bits(page, c, w as usize, rest);
    }
    Some((page << PAGE_SHIFT) + (w as usize * 64 + i) * class::size(c))
  }

  /// Claims the free blocks of one bitmap word of class `c`: from the
  /// shard's current page, else from another page of the class that has
  /// free blocks, else, if `grow`, from a new page. Returns `Some(None)`
  /// when a new page would be needed but `grow` is false, and `None` when
  /// out of memory. Caller holds the shard lock.
  fn claim_class_word(
    &self,
    s: usize,
    sh: &Shard,
    c: usize,
    grow: bool,
  ) -> Option<Option<(usize, u32, u64)>> {
    let cs = &sh.classes[c];
    sh.bump(SearchStat::Refill, 1);
    // A page just set up for the class must have blocks to claim; if not,
    // the metadata is corrupt, and retrying would take pages forever.
    let mut fresh = false;
    let mut searched = false;
    loop {
      let cur = cs.cursor.load(Relaxed);
      if cur != 0 {
        let page = cur as usize - 1;
        let (m, in_seg) = (
          self.seg_meta(page / PAGES_PER_SEGMENT),
          page % PAGES_PER_SEGMENT,
        );
        let pm = PageMeta::new(m, in_seg);
        let words = &pm.bitmaps()[..class::bitmap_words(c)];
        if let Some((w, bits)) = proto::claim_word(pm.summary(), words, sh.random()) {
          pm.free().fetch_sub(u64::from(bits.count_ones()), Relaxed);
          if !searched {
            sh.bump(SearchStat::CursorClaim, 1);
          }
          return Some(Some((page, w, bits)));
        }
        if fresh {
          self
            .os
            .fatal("allocatbelt: a new small page has no free blocks");
        }
        if !proto::retire_page(&m[SEG_AVAIL + c], 1 << in_seg, pm.summary()) {
          continue;
        }
        sh.bump(SearchStat::CursorRetired, 1);
        cs.cursor.store(0, Relaxed);
      }
      searched = true;
      let page = match self.find_page(sh, c) {
        Some(p) => p,
        None if !grow => return Some(None),
        None => {
          fresh = true;
          self.new_small_page(s, sh, c)?
        }
      };
      cs.cursor.store(page as u64 + 1, Relaxed);
    }
  }

  /// Finds a page of class `c` with free blocks among the shard's
  /// segments, through their availability words. Caller holds the lock.
  fn find_page(&self, sh: &Shard, c: usize) -> Option<usize> {
    // Counted locally and added once: the search holds the lock anyway.
    let (mut segs, mut cands, mut stale) = (0, 0, 0);
    let mut found = None;
    let mut cur = sh.segs.load(Relaxed);
    'segs: while cur != 0 {
      let seg = cur as usize - 1;
      segs += 1;
      let m = self.seg_meta(seg);
      let mut cand = m[SEG_AVAIL + c].load(Acquire) & m[SEG_CLS + c].load(Relaxed);
      while cand != 0 {
        let i = cand.trailing_zeros() as usize;
        cand &= cand - 1;
        cands += 1;
        let summary = PageMeta::new(m, i).summary();
        // A stale availability bit is dropped here, unless a free
        // refills the page meanwhile.
        if summary.load(Acquire) != 0 || !proto::retire_page(&m[SEG_AVAIL + c], 1 << i, summary) {
          found = Some(seg * PAGES_PER_SEGMENT + i);
          break 'segs;
        }
        stale += 1;
      }
      cur = m[SEG_NEXT].load(Relaxed) as u32;
    }
    sh.bump(SearchStat::PageSearch, 1);
    sh.bump(SearchStat::PageSearchSegment, segs);
    sh.bump(SearchStat::Candidate, cands);
    sh.bump(SearchStat::StaleHint, stale);
    found
  }

  fn new_small_page(&self, s: usize, sh: &Shard, c: usize) -> Option<usize> {
    let (p, _) = self.alloc_pages(s, sh, 1, 1)?;
    sh.bump(SearchStat::NewPage, 1);
    let (m, in_seg) = (self.seg_meta(p / PAGES_PER_SEGMENT), p % PAGES_PER_SEGMENT);
    let pm = PageMeta::new(m, in_seg);
    let cap = class::capacity(c);
    let words = class::bitmap_words(c);
    // Words past the class's range are zeroed too: a free of the page's
    // previous life may still set a stale summary bit for one of them.
    for w in 0..class::MAX_BITMAP_WORDS {
      let v = if (w + 1) * 64 <= cap {
        u64::MAX
      } else if w * 64 < cap {
        (1u64 << (cap - w * 64)) - 1
      } else {
        0
      };
      pm.bitmap(w).store(v, Relaxed);
    }
    pm.free().store(cap as u64, Relaxed);
    pm.summary().store(run_mask(0, words as u32), Relaxed);
    pm.info().store(PAGE_SMALL | (c as u64) << 8, Release);
    m[SEG_CLS + c].fetch_or(1 << in_seg, Relaxed);
    m[SEG_AVAIL + c].fetch_or(1 << in_seg, AcqRel);
    Some(p)
  }

  /// Returns a small page whose blocks are all free to its segment. Caller
  /// holds the owning shard's lock.
  fn release_small_page(&self, page: usize, m: &[AtomicU64], c: usize) {
    let in_seg = page % PAGES_PER_SEGMENT;
    m[SEG_CLS + c].fetch_and(!(1 << in_seg), Relaxed);
    m[SEG_AVAIL + c].fetch_and(!(1 << in_seg), AcqRel);
    PageMeta::new(m, in_seg).info().store(PAGE_FREE, Release);
    self.release_pages(page, 1);
  }

  /// Bitmap word and bit of the class-`c` block `in_page` bytes into its
  /// page, or a fatal error if no block starts there.
  fn block_bit(&self, in_page: usize, c: usize) -> (usize, u64) {
    match class::block_index(c, in_page) {
      Some(idx) => (idx / 64, 1u64 << (idx % 64)),
      None => self
        .os
        .fatal("allocatbelt: free of a misaligned small pointer"),
    }
  }

  /// Returns the blocks `mask` of bitmap word `w` of small page `page`
  /// (class `c`) to the shared bitmap.
  fn free_bits(&self, page: usize, c: usize, w: usize, mask: u64) {
    let (m, in_seg) = (
      self.seg_meta(page / PAGES_PER_SEGMENT),
      page % PAGES_PER_SEGMENT,
    );
    let pm = PageMeta::new(m, in_seg);
    if !proto::release_blocks(
      pm.bitmap(w),
      pm.free(),
      pm.summary(),
      &m[SEG_AVAIL + c],
      w as u32,
      1 << in_seg,
      mask,
    ) {
      self.os.fatal(DOUBLE_FREE);
    }
  }

  // ---- page runs -----------------------------------------------------

  fn alloc_large(&self, hint: usize, n: usize, step: usize) -> Option<Block> {
    self.with_shard(hint, |s, sh| {
      let (p, zeroed) = self.alloc_pages(s, sh, n, step)?;
      let m = self.seg_meta(p / PAGES_PER_SEGMENT);
      for t in 1..n {
        PageMeta::new(m, p % PAGES_PER_SEGMENT + t)
          .info()
          .store(PAGE_LARGE_TAIL, Relaxed);
      }
      PageMeta::new(m, p % PAGES_PER_SEGMENT)
        .info()
        .store(PAGE_LARGE | (n as u64) << 16, Release);
      Some(Block::new(p << PAGE_SHIFT, zeroed))
    })
  }

  fn free_large(&self, page: usize, m: &[AtomicU64], pm: PageMeta<'_>, info: u64) {
    if pm
      .info()
      .compare_exchange(info, PAGE_FREE, AcqRel, Relaxed)
      .is_err()
    {
      self.os.fatal(DOUBLE_FREE);
    }
    let n = ((info >> 16) & 0xFF) as usize;
    for t in 1..n {
      PageMeta::new(m, page % PAGES_PER_SEGMENT + t)
        .info()
        .store(PAGE_FREE, Relaxed);
    }
    self.release_pages(page, n);
  }

  /// Extends the live run of `n` pages at `page` to `n2` pages if the pages
  /// after it are free. Any thread may do this for a block it owns: the
  /// claim is a compare-exchange like every other page claim.
  fn grow_large(
    &self,
    page: usize,
    m: &[AtomicU64],
    pm: PageMeta<'_>,
    n: usize,
    n2: usize,
  ) -> bool {
    let in_seg = page % PAGES_PER_SEGMENT;
    if in_seg + n2 > PAGES_PER_SEGMENT {
      return false;
    }
    let mask = run_mask((in_seg + n) as u32, (n2 - n) as u32);
    let Some(was_dirty) = proto::claim_exact(&m[SEG_PAGES], &m[SEG_DIRTY], mask) else {
      return false;
    };
    if was_dirty != 0 {
      self
        .dirty_pages
        .fetch_sub(was_dirty.count_ones() as isize, Relaxed);
    }
    for t in n..n2 {
      PageMeta::new(m, in_seg + t)
        .info()
        .store(PAGE_LARGE_TAIL, Relaxed);
    }
    pm.info().store(PAGE_LARGE | (n2 as u64) << 16, Release);
    true
  }

  /// Cuts the live run of `n` pages at `page` down to `n2` pages.
  fn shrink_large(&self, page: usize, m: &[AtomicU64], pm: PageMeta<'_>, n: usize, n2: usize) {
    pm.info().store(PAGE_LARGE | (n2 as u64) << 16, Release);
    for t in n2..n {
      PageMeta::new(m, page % PAGES_PER_SEGMENT + t)
        .info()
        .store(PAGE_FREE, Relaxed);
    }
    self.release_pages(page + n2, n - n2);
  }

  /// Claims `n` contiguous pages starting at a multiple of `step` pages from
  /// a segment owned by shard `s`. Also returns whether the pages read as
  /// zero.
  fn alloc_pages(&self, s: usize, sh: &Shard, n: usize, step: usize) -> Option<(usize, bool)> {
    sh.bump(SearchStat::RunSearch, 1);
    let mut segs = 0;
    let mut cur = sh.segs.load(Relaxed);
    while cur != 0 {
      let seg = cur as usize - 1;
      segs += 1;
      let m = self.seg_meta(seg);
      if let Some((start, zeroed)) = self.claim_run(m, n, step) {
        sh.bump(SearchStat::RunSearchSegment, segs);
        return Some((seg * PAGES_PER_SEGMENT + start, zeroed));
      }
      cur = m[SEG_NEXT].load(Relaxed) as u32;
    }
    sh.bump(SearchStat::RunSearchSegment, segs);
    let seg = self.alloc_segments(1, sh.random())?;
    sh.bump(SearchStat::NewSegment, 1);
    let m = self.seg_meta(seg);
    // A segment whose memory may hold stale bytes starts fully dirty, so
    // it is neither reported as zeroed nor kept resident forever. Dirty
    // is written before the pages are opened up so a concurrent purge
    // pass never sees clean-looking free pages.
    if m[SEG_DIRTY].load(Relaxed) != 0 {
      m[SEG_DIRTY].store(!GUARD_BIT, Relaxed);
      self.dirty_pages.fetch_add(MAX_RUN_PAGES as isize, Relaxed);
    }
    // The guard page stays claimed for as long as the shard owns the
    // segment, so nothing hands it out, purges it or marks it dirty.
    let _ = self.os.guard(
      (seg * PAGES_PER_SEGMENT + GUARD_PAGE) << PAGE_SHIFT,
      PAGE_SIZE,
    );
    // Late frees of a previous owner may have left hints behind.
    for c in 0..NUM_CLASSES {
      m[SEG_CLS + c].store(0, Relaxed);
      m[SEG_AVAIL + c].store(0, Relaxed);
    }
    m[SEG_IDLE].store(0, Relaxed);
    m[SEG_PAGES].store(GUARD_BIT, Release);
    m[SEG_NEXT].store(u64::from(sh.segs.load(Relaxed)), Relaxed);
    m[SEG_HDR].store(SEG_OWNED | (s as u64) << 8 | 1 << 16, Release);
    sh.segs.store(seg as u32 + 1, Relaxed);
    self
      .claim_run(m, n, step)
      .map(|(start, zeroed)| (seg * PAGES_PER_SEGMENT + start, zeroed))
  }

  /// Atomically claims a run of `n` free pages starting at a multiple of
  /// `step` in a segment and reports whether it reads as zero. Reusing dirty
  /// pages is free: they simply stop being dirty (and are not zero).
  fn claim_run(&self, m: &[AtomicU64], n: usize, step: usize) -> Option<(usize, bool)> {
    let (start, was_dirty) = proto::claim_run(&m[SEG_PAGES], &m[SEG_DIRTY], n as u32, step as u32)?;
    if was_dirty != 0 {
      self
        .dirty_pages
        .fetch_sub(was_dirty.count_ones() as isize, Relaxed);
    }
    Some((start as usize, was_dirty == 0))
  }

  /// Marks `n` pages dirty and returns them to their segment.
  fn release_pages(&self, page: usize, n: usize) {
    let m = self.seg_meta(page / PAGES_PER_SEGMENT);
    let in_seg = page % PAGES_PER_SEGMENT;
    // Stamped before the pages are marked dirty, so a purge pass that sees
    // the mark also sees the stamp (or a later one, if the pages are reused
    // and freed again meanwhile).
    let epoch = self.epoch.load(Relaxed);
    for t in in_seg..in_seg + n {
      PageMeta::new(m, t).since().store(epoch, Relaxed);
    }
    proto::release_run(
      &m[SEG_PAGES],
      &m[SEG_DIRTY],
      run_mask(in_seg as u32, n as u32),
    );
    let dirty = self.dirty_pages.fetch_add(n as isize, Relaxed) + n as isize;
    if dirty > DIRTY_BUDGET_PAGES {
      self.over_budget(dirty);
    }
  }

  // ---- segments ------------------------------------------------------

  fn alloc_huge(&self, k: usize) -> Option<Block> {
    let first = self.alloc_segments(k, 0)?;
    let mut zeroed = true;
    for i in (0..k).rev() {
      let hdr = if i == 0 {
        SEG_HUGE | (k as u64) << 16
      } else {
        SEG_HUGE_TAIL
      };
      let m = self.seg_meta(first + i);
      zeroed &= m[SEG_DIRTY].load(Relaxed) == 0;
      m[SEG_HDR].store(hdr, Release);
    }
    Some(Block::new(first << SEGMENT_SHIFT, zeroed))
  }

  fn free_huge(&self, seg: usize, m: &[AtomicU64], hdr: u64) {
    if m[SEG_HDR]
      .compare_exchange(hdr, SEG_FREE, AcqRel, Relaxed)
      .is_err()
    {
      self.os.fatal(DOUBLE_FREE);
    }
    let k = (hdr >> 16) as usize;
    for i in 1..k {
      self.seg_meta(seg + i)[SEG_HDR].store(SEG_FREE, Relaxed);
    }
    self.free_segments(seg, k);
  }

  /// Extends the huge block of `k` segments at `seg` to `k2` segments if
  /// the segments after it are free.
  fn grow_huge(&self, seg: usize, m: &[AtomicU64], k: usize, k2: usize) -> bool {
    let (first, extra) = (seg + k, k2 - k);
    if seg + k2 > MAX_SEGMENTS {
      return false;
    }
    {
      let _g = self.seg_lock.lock(&self.os);
      let free =
        (first..first + extra).all(|s| self.seg_used[s / 64].load(Relaxed) & 1 << (s % 64) == 0);
      if !free {
        return false;
      }
      self.mark_segments(first, extra, true);
    }
    if !self.commit_segments(first, extra) {
      return false;
    }
    for s in first..first + extra {
      let t = self.seg_meta(s);
      t[SEG_PAGES].store(u64::MAX, Relaxed);
      t[SEG_HDR].store(SEG_HUGE_TAIL, Release);
    }
    m[SEG_HDR].store(SEG_HUGE | (k2 as u64) << 16, Release);
    true
  }

  /// Cuts the huge block of `k` segments at `seg` down to `k2` segments.
  fn shrink_huge(&self, seg: usize, m: &[AtomicU64], k: usize, k2: usize) {
    m[SEG_HDR].store(SEG_HUGE | (k2 as u64) << 16, Release);
    for s in seg + k2..seg + k {
      self.seg_meta(s)[SEG_HDR].store(SEG_FREE, Relaxed);
    }
    self.free_segments(seg + k2, k - k2);
  }

  /// Takes `k` contiguous segments from the arena, commits their metadata
  /// and memory, and returns the first index. The segments' `SEG_DIRTY`
  /// word tells whether their memory may hold non-zero bytes. `r` randomizes
  /// the placement of single segments (see `find_free_segments`).
  fn alloc_segments(&self, k: usize, r: u32) -> Option<usize> {
    if k == 0 || k > MAX_SEGMENTS {
      return None;
    }
    let first = {
      let _g = self.seg_lock.lock(&self.os);
      let first = self.find_free_segments(k, r)?;
      self.mark_segments(first, k, true);
      first
    };
    self.commit_segments(first, k).then_some(first)
  }

  /// Commits metadata and memory of `k` segments marked used by the
  /// caller. On failure the segments are returned to the arena.
  fn commit_segments(&self, first: usize, k: usize) -> bool {
    // Metadata first: until it exists, nothing records whether the
    // memory is zero, so the memory must not be touched before.
    if !(first..first + k).all(|s| self.os.commit_meta(s).is_some()) {
      let _g = self.seg_lock.lock(&self.os);
      self.mark_segments(first, k, false);
      return false;
    }
    if !self.os.commit(first << SEGMENT_SHIFT, k << SEGMENT_SHIFT) {
      self.free_segments(first, k);
      return false;
    }
    true
  }

  /// Decommits `k` segments and returns them to the arena, recording
  /// whether their memory reads as zero. No page of them may be claimable.
  fn free_segments(&self, first: usize, k: usize) {
    let zeroed = self.os.decommit(first << SEGMENT_SHIFT, k << SEGMENT_SHIFT);
    for s in first..first + k {
      let m = self.seg_meta(s);
      // All pages "used": a stale purge pass cannot claim any of them.
      m[SEG_PAGES].store(u64::MAX, Relaxed);
      m[SEG_DIRTY].store(if zeroed { 0 } else { u64::MAX }, Relaxed);
    }
    let _g = self.seg_lock.lock(&self.os);
    self.mark_segments(first, k, false);
  }

  /// First-fit search for `k` free segments. Caller holds `seg_lock`.
  ///
  /// With a non-zero `r`, a single segment is instead picked at random
  /// among the free ones of the first 64-segment group that has any, which
  /// makes addresses hard to predict while keeping the arena compact (the
  /// metadata of a segment that was ever used stays committed).
  fn find_free_segments(&self, k: usize, r: u32) -> Option<usize> {
    if k == 1 && r != 0 {
      return self.seg_used.iter().enumerate().find_map(|(wi, w)| {
        let free = !w.load(Relaxed);
        (free != 0).then(|| wi * 64 + pick_bit(free, r) as usize)
      });
    }
    let mut run = 0;
    let mut i = 0;
    while i < MAX_SEGMENTS {
      let w = self.seg_used[i / 64].load(Relaxed);
      let bit = i % 64;
      if bit == 0 && w == u64::MAX {
        run = 0;
        i += 64;
        continue;
      }
      if bit == 0 && w == 0 && run + 64 < k {
        run += 64;
        i += 64;
        continue;
      }
      if (w >> bit) & 1 == 1 {
        run = 0;
      } else {
        run += 1;
        if run == k {
          return Some(i + 1 - k);
        }
      }
      i += 1;
    }
    None
  }

  fn mark_segments(&self, first: usize, k: usize, used: bool) {
    for s in first..first + k {
      let bit = 1u64 << (s % 64);
      if used {
        self.seg_used[s / 64].fetch_or(bit, Relaxed);
      } else {
        self.seg_used[s / 64].fetch_and(!bit, Relaxed);
      }
    }
  }
}
