//! Per-thread caches: claimed bitmap words for allocation, and a buffer of
//! frees returned to the shared bitmaps one word at a time.
//!
//! **Free buffer.** [`FREE_SLOTS`] slots (128) in sets of [`FREE_WAYS`]
//! ways (2). A free of a block goes to the set its bitmap word hashes to:
//! into the way that already holds the word, else an empty way, else it
//! evicts the oldest way (per-set round robin), whose frees go back to the
//! shared bitmap in one update. A word lives in at
//! most one slot, so a duplicate free is caught in either way. Two words
//! whose frees interleave share a set without evicting each other, which a
//! direct-mapped buffer could not do: the shared update per free is
//! amortized over the batch a slot actually collects.
//!
//! **Cache return.** Blocks a cache holds (claimed words, buffered frees)
//! are unavailable to other threads until it flushes. Its owner flushes it
//! explicitly ([`Heap::flush`]) or cooperatively: [`Heap::request_cache_return`]
//! bumps a generation, and each attached cache drains itself completely
//! when it next sees a new value at a sampled point of its own slow paths:
//! a refill, a page-run or huge allocation or free, and a free that needs a
//! new slot. A thread that only frees reaches the last within 8192 frees
//! (a slot takes at most 64 frees of its word before a free must start a
//! new one, and there are 128 slots). A drain is bounded: 128 slots and one
//! claimed word per class, one shared update each. Only the owner mutates
//! its cache; a thread that sleeps or blocks sees nothing and keeps what it
//! holds, so the embedder flushes before parking.

use core::cell::Cell;

use super::*;

/// Slots of buffered frees per thread: [`FREE_SETS`] sets of [`FREE_WAYS`]
/// ways. Slot `i` is way `i % FREE_WAYS` of set `i / FREE_WAYS`. A fixed
/// constant, not a setting (`docs/design-constraints.md`, cache capacity);
/// `docs/thread-caches.md` gives the bounds it sets.
const FREE_SLOTS: usize = 128;
const FREE_WAYS: usize = 2;
const FREE_SETS: usize = FREE_SLOTS / FREE_WAYS;
/// `u64` words of a per-class mask of slots (`ThreadCache::pending`).
const SLOT_WORDS: usize = FREE_SLOTS / 64;

const DETACHED: u8 = 0;
const ATTACHING: u8 = 1;
const ATTACHED: u8 = 2;
const RETIRED: u8 = 3;

/// Free blocks of one bitmap word, claimed by a thread, kept as a list of
/// block numbers rather than as the word's bits: a refill unpacks the bits
/// it claimed, and the thread hands blocks out from the list.
#[derive(Debug)]
struct CachedBlocks {
  /// Arena offset of the word's first block.
  base: Cell<usize>,
  /// Block numbers (block `i` is at `base + i * size`); the first `len`
  /// are free, the last of them is handed out next.
  blocks: [Cell<u8>; 64],
  len: Cell<u8>,
}

impl CachedBlocks {
  /// Whether block `i` of the word is in the list (see [`list_holds`]).
  #[cfg(test)]
  fn holds(&self, i: u32) -> bool {
    list_holds(&self.blocks, self.len.get(), i as u8)
  }
}

/// The mask of the block numbers (each below 64) in the first `len` (at
/// most 64) entries of `blocks`: the portable form of [`Os::pack_blocks`],
/// which every kernel must match.
#[must_use]
#[inline]
pub fn pack_blocks(blocks: &[Cell<u8>; 64], len: u8) -> u64 {
  blocks[..usize::from(len)]
    .iter()
    .fold(0, |m, b| m | 1 << b.get())
}

/// Whether block number `i` (below 64) is among the first `len` entries of
/// `blocks`: the portable form of [`Os::list_holds`], which every kernel
/// must match.
///
/// Compares all 64 entries with `i` and keeps the matches among the first
/// `len`; the entries past `len` are stale and do not count. Without an
/// early exit and with byte-wide lanes, this lowers to two 32-byte
/// compares on x86-64-v3 and four 16-byte compares on AArch64, where a
/// search of the live entries took up to 64 compare-and-branch steps on
/// every free into the claimed word. A base RV64GC core, without vector
/// instructions, runs it as a loop of 64 scalar steps.
#[must_use]
#[inline]
pub fn list_holds(blocks: &[Cell<u8>; 64], len: u8, i: u8) -> bool {
  // A block number is below 64, so it fits the entries' byte.
  debug_assert!(i < 64);
  let mut hit = 0u8;
  for (b, k) in blocks.iter().zip(&POSITIONS) {
    hit |= u8::from(b.get() == i) & u8::from(*k < len);
  }
  hit != 0
}

/// Writes the numbers of the set bits of `bits` to `blocks`, highest
/// first, and returns how many there are: the portable form of
/// [`Os::unpack_blocks`]. A kernel must write the same first entries and
/// return the same count; it may leave any value in the entries past the
/// count, which no reader looks at.
#[inline]
pub fn unpack_blocks(bits: u64, blocks: &[Cell<u8>; 64]) -> u8 {
  let mut rest = bits;
  let mut n = 0;
  while rest != 0 {
    let i = 63 - rest.leading_zeros();
    blocks[n].set(i as u8);
    n += 1;
    rest &= !(1 << i);
  }
  n as u8
}

/// `POSITIONS[k] == k`: the positions of a list's entries, as bytes, so a
/// compare with its length stays byte-wide (see [`list_holds`]).
const POSITIONS: [u8; 64] = {
  let mut t = [0; 64];
  let mut k = 0;
  while k < 64 {
    t[k] = k as u8;
    k += 1;
  }
  t
};

/// Freed blocks of one bitmap word, not yet returned to the bitmap.
#[derive(Debug)]
struct FreeSlot {
  /// [`slot_key`] of the word, or 0 when the slot is empty.
  key: Cell<u64>,
  mask: Cell<u64>,
}

/// Packs a (page, bitmap word, class) triple; never zero.
const fn slot_key(page: usize, w: usize, c: usize) -> u64 {
  1 << 63 | (page as u64) << 11 | (w as u64) << 5 | c as u64
}

const fn unpack_key(key: u64) -> (usize, usize, usize) {
  (
    ((key >> 11) & ((1 << 52) - 1)) as usize,
    ((key >> 5) & 63) as usize,
    (key & 31) as usize,
  )
}

const _: () = assert!(NUM_CLASSES <= 32);

/// The set of the free buffer that frees of word `w` of `page` go to: the
/// top bits of a multiplicative hash, as many as the sets need.
#[inline]
const fn set_index(page: usize, w: usize) -> usize {
  ((((page << 6) | w) as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
    >> (64 - FREE_SETS.trailing_zeros())) as usize
}

// Sets are a power of two (the hash takes their bits), slots fill whole
// `u64` words of the per-class `pending` masks, and a way number fits the
// per-set `u8` victim.
const _: () = assert!(
  FREE_SETS.is_power_of_two()
    && FREE_SETS >= 2
    && FREE_WAYS >= 2
    && FREE_WAYS <= u8::MAX as usize
    && FREE_SLOTS.is_multiple_of(64)
);

/// The size class of a request for `size` bytes aligned to `align`, when
/// `align` is a power of two and a small class holds `size` in blocks
/// aligned to it: the class of `size` rounded up to a multiple of `align`
/// (at least `align`). It is the class [`class::class_for`] finds by
/// search, without the search. Up to 128 bytes every multiple of 16 is a
/// class size. Above, the classes between powers of two `b` and `2b` step
/// by `b / 4`: an alignment up to `b / 4` divides all of them, and the
/// multiples of a larger one in that range, `3b / 2` and `2b`, are class
/// sizes too. So no smaller class holds the request aligned.
#[inline]
const fn aligned_class(size: usize, align: usize) -> Option<usize> {
  if !align.is_power_of_two() || align > SMALL_MAX || size > SMALL_MAX {
    return None;
  }
  // Both are at most `SMALL_MAX`, so this cannot overflow.
  let rounded = (size + align - 1) & !(align - 1);
  let rounded = if rounded < align { align } else { rounded };
  if rounded > SMALL_MAX {
    None
  } else {
    Some(class::class_of(rounded))
  }
}

/// A thread's private allocation state: one claimed bitmap word per size
/// class, and a small buffer of frees not yet returned to the bitmaps.
///
/// It is built from `Cell`s, so it is `!Sync` and needs no `unsafe`: the
/// embedder keeps one per thread (a `const`-initialised thread local without
/// `Drop`) and passes it to [`Heap::alloc_cached`] and
/// [`Heap::dealloc_cached`]. Blocks held in a cache are unavailable to other
/// threads, so the embedder must hand the cache back with [`Heap::retire`]
/// when the thread exits.
///
/// A new cache is *detached* and every call through it takes the shared
/// (uncached) paths. [`Heap::attach`] enables caching; the embedder calls
/// [`ThreadCache::begin_attach`] first, so allocations made while it
/// registers its thread-exit hook bypass the cache too.
#[derive(Debug)]
pub struct ThreadCache {
  words: [CachedBlocks; NUM_CLASSES],
  frees: [FreeSlot; FREE_SLOTS],
  /// Occupied free slots per class (bit `i % 64` of word `i / 64` =
  /// `frees[i]`).
  pending: [[Cell<u64>; SLOT_WORDS]; NUM_CLASSES],
  /// Way to evict next, per set.
  victims: [Cell<u8>; FREE_SETS],
  /// Last cache-return generation this cache drained for.
  pressure_seen: Cell<u32>,
  /// [`CacheStats::pressure_returns`].
  pressure_returns: Cell<u64>,
  shard: Cell<usize>,
  state: Cell<u8>,
  /// Refills so far, to sample the clock.
  ticks: Cell<u32>,
  /// Random state for the order blocks are handed out; 0 while
  /// randomization is off.
  rng: Cell<u64>,
  /// [`CacheStats::flush_sizes`], counted when a slot is flushed.
  flush_sizes: [Cell<u64>; 7],
  /// [`CacheStats::flushed_blocks`].
  flushed_blocks: Cell<u64>,
  /// [`CacheStats::evictions`].
  evictions: Cell<u64>,
  /// [`CacheStats::refill_flushes`].
  refill_flushes: Cell<u64>,
}

impl ThreadCache {
  /// A detached, empty cache.
  #[must_use]
  pub const fn new() -> Self {
    Self {
      words: [const {
        CachedBlocks {
          base: Cell::new(0),
          blocks: [const { Cell::new(0) }; 64],
          len: Cell::new(0),
        }
      }; NUM_CLASSES],
      frees: [const {
        FreeSlot {
          key: Cell::new(0),
          mask: Cell::new(0),
        }
      }; FREE_SLOTS],
      pending: [const { [const { Cell::new(0) }; SLOT_WORDS] }; NUM_CLASSES],
      victims: [const { Cell::new(0) }; FREE_SETS],
      pressure_seen: Cell::new(0),
      pressure_returns: Cell::new(0),
      shard: Cell::new(0),
      state: Cell::new(DETACHED),
      ticks: Cell::new(0),
      rng: Cell::new(0),
      flush_sizes: [const { Cell::new(0) }; 7],
      flushed_blocks: Cell::new(0),
      evictions: Cell::new(0),
      refill_flushes: Cell::new(0),
    }
  }

  /// Whether the cache still has to be attached (see [`Heap::attach`]).
  #[must_use]
  pub fn is_detached(&self) -> bool {
    self.state.get() == DETACHED
  }

  /// Marks the cache as being attached. Until [`Heap::attach`], calls
  /// through it take the uncached paths, so the embedder may allocate while
  /// it sets up the thread-exit hook.
  pub fn begin_attach(&self) {
    if self.state.get() == DETACHED {
      self.state.set(ATTACHING);
    }
  }

  fn is_attached(&self) -> bool {
    self.state.get() == ATTACHED
  }
}

impl Default for ThreadCache {
  fn default() -> Self {
    Self::new()
  }
}

impl<O: Os> Heap<O> {
  /// Allocates through the calling thread's cache. Small blocks come from
  /// the cache without atomics; everything else, and every call through a
  /// cache that is not attached, behaves like [`Heap::alloc_block`].
  #[inline]
  pub fn alloc_cached(&self, tc: &ThreadCache, size: usize, align: usize) -> Option<Block> {
    if align <= MIN_ALIGN && size <= SMALL_MAX && tc.is_attached() {
      let c = class::class_of(size);
      if let Some(o) = Self::pop(tc, c) {
        return Some(Block::new(o, false));
      }
      return self.refill(tc, c).map(|o| Block::new(o, false));
    }
    // An alignment above the default that a small class satisfies takes
    // the same cached path, without the general size and alignment check.
    if align > MIN_ALIGN
      && let Some(c) = aligned_class(size, align)
      && tc.is_attached()
    {
      return Self::pop(tc, c)
        .or_else(|| self.refill(tc, c))
        .map(|o| Block::new(o, false));
    }
    self.alloc_cached_slow(tc, size, align)
  }

  fn alloc_cached_slow(&self, tc: &ThreadCache, size: usize, align: usize) -> Option<Block> {
    if !tc.is_attached() {
      return self.alloc_block(self.shard_of(tc), size, align);
    }
    match Self::kind(size, align)? {
      Kind::Small(c) => Self::pop(tc, c)
        .or_else(|| self.refill(tc, c))
        .map(|o| Block::new(o, false)),
      Kind::Run(n, step) => {
        self.observe_pressure(tc);
        self.tick(tc);
        self.alloc_large(self.shard_of(tc), n, step)
      }
      Kind::Huge(k) => {
        self.observe_pressure(tc);
        self.tick(tc);
        self.alloc_huge(k)
      }
    }
  }

  /// Takes a free block of class `c` from the thread's claimed word.
  #[inline(always)]
  fn pop(tc: &ThreadCache, c: usize) -> Option<usize> {
    let cw = &tc.words[c];
    let n = usize::from(cw.len.get());
    if n == 0 {
      return None;
    }
    // Randomized, consecutive allocations are not adjacent in memory: a
    // uniformly chosen entry trades places with the last one. In order
    // otherwise (the list is filled highest block first).
    let x = tc.rng.get();
    let j = if x == 0 {
      n - 1
    } else {
      let x = xorshift(x);
      tc.rng.set(x);
      (((x >> 32) * n as u64) >> 32) as usize
    };
    let i = cw.blocks[j].get();
    cw.blocks[j].set(cw.blocks[n - 1].get());
    cw.len.set(n as u8 - 1);
    Some(cw.base.get() + usize::from(i) * class::size(c))
  }

  /// Claims a new word of class `c` for the thread and pops from it.
  #[inline(never)]
  fn refill(&self, tc: &ThreadCache, c: usize) -> Option<usize> {
    self.observe_pressure(tc);
    // Frees the thread has buffered stay buffered (and keep batching)
    // while the class has free blocks elsewhere; before a new page is
    // taken for the class, they go back so the claim can reuse them.
    let grow = tc.pending[c].iter().all(|w| w.get() == 0);
    let hint = self.shard_of(tc);
    let (page, w, bits) =
      match self.with_shard(hint, |s, sh| self.claim_class(s, sh, c, grow, false))? {
        Some(claim) => claim,
        None => {
          bump(&tc.refill_flushes, 1);
          self.flush_class(tc, c);
          self.with_shard(hint, |s, sh| self.claim_class(s, sh, c, true, false))??
        }
      };
    // A block of the claimed word that this thread still holds as freed in
    // its buffer cannot be free in the shared bitmap as well.
    let key = slot_key(page, w as usize, c);
    let first = set_index(page, w as usize) * FREE_WAYS;
    if tc.frees[first..first + FREE_WAYS]
      .iter()
      .any(|slot| slot.key.get() == key && slot.mask.get() & bits != 0)
    {
      self.os.fatal(DOUBLE_FREE);
    }
    let cw = &tc.words[c];
    cw.base
      .set((page << PAGE_SHIFT) + w as usize * 64 * class::size(c));
    // Highest block first, so an unrandomized cache hands them out from
    // the lowest.
    cw.len.set(self.os.unpack_blocks(bits, &cw.blocks));
    self.tick(tc);
    Self::pop(tc, c)
  }

  /// The shard the thread prefers: the environment's current hint (see
  /// [`Os::shard_hint`]), else the one given when its cache was attached.
  #[inline]
  fn shard_of(&self, tc: &ThreadCache) -> usize {
    self.os.shard_hint().unwrap_or_else(|| tc.shard.get())
  }

  /// Counts a slow-path operation of the thread and, every 16th, runs a
  /// decay pass if one is due: reading the clock on every one would cost
  /// more than the operation itself.
  #[inline]
  fn tick(&self, tc: &ThreadCache) {
    let ticks = tc.ticks.get().wrapping_add(1);
    tc.ticks.set(ticks);
    if ticks.is_multiple_of(16) {
      self.maybe_housekeep();
    }
  }

  /// Enables caching for `tc`. The embedder must arrange for
  /// [`Heap::retire`] to run when the thread exits, before calling this.
  /// Does nothing to a cache that is attached or retired.
  pub fn attach(&self, tc: &ThreadCache) {
    // Retired for good; or attached already (a reentrant call), which
    // keeps the cache's shard, random state and cache-return obligation.
    if matches!(tc.state.get(), RETIRED | ATTACHED) {
      return;
    }
    // Consecutive caches get consecutive shards. A plain load and store,
    // not a read-modify-write: two threads attaching at once may get the
    // same shard, which costs them some lock sharing and nothing else, as
    // the shard is only a first choice (see `with_shard`). The random seed
    // below still differs, as it mixes in the cache's own address.
    let n = self.next_shard.load(Relaxed);
    self.next_shard.store(n.wrapping_add(1), Relaxed);
    tc.shard.set(n % SHARDS);
    let seed = self.seed.load(Relaxed);
    tc.rng.set(if seed == 0 {
      0
    } else {
      let at = core::ptr::from_ref(tc).addr() as u64;
      splitmix(seed ^ (n as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ at.rotate_left(32))
    });
    // A new cache owes nothing for requests made before it existed.
    tc.pressure_seen.set(self.cache_pressure.load(Relaxed));
    tc.state.set(ATTACHED);
  }

  /// Makes `shard % SHARDS` the shard `tc` prefers from now on, in place
  /// of the one [`Heap::attach`] gave it: for an embedder that numbers its
  /// threads, such as an async runtime's workers. The environment's
  /// [`Os::shard_hint`], when it gives one, still comes first. Only a
  /// preference, as in `attach`: the shard is locked either way. A later
  /// `attach` of a detached cache gives it a shard again.
  pub fn set_preferred_shard(&self, tc: &ThreadCache, shard: usize) {
    tc.shard.set(shard % SHARDS);
  }

  /// Returns every block held by `tc` (claimed or freed) to the shared
  /// bitmaps: at most 64 buffered words and one claimed word per class, one
  /// update each under the lock of the shard that owns the word's page.
  /// The cache stays usable (and attached, if it was).
  /// Only the thread that owns `tc` can call it; not async-signal-safe.
  pub fn flush(&self, tc: &ThreadCache) {
    for i in 0..FREE_SLOTS {
      self.flush_slot(tc, i);
    }
    for (c, cw) in tc.words.iter().enumerate() {
      // The listed blocks as a mask of the word, emptying the list.
      let bits = self.os.pack_blocks(&cw.blocks, cw.len.replace(0));
      if bits != 0 {
        let base = cw.base.get();
        let w = base % PAGE_SIZE / (64 * class::size(c));
        self.free_bits(base >> PAGE_SHIFT, c, w, bits);
      }
    }
  }

  /// Flushes `tc` and stops caching in it for good: later calls through it
  /// take the uncached paths. For thread exit, where thread-local
  /// destructors that run afterwards may still allocate and free.
  pub fn retire(&self, tc: &ThreadCache) {
    tc.state.set(RETIRED);
    self.flush(tc);
  }

  /// Frees the allocation at `offset` through the calling thread's cache:
  /// small blocks are buffered and returned in batches.
  #[inline]
  pub fn dealloc_cached(&self, tc: &ThreadCache, offset: usize) {
    // Fast path: a small block freed into an attached cache.
    if offset < ARENA_SIZE
      && tc.is_attached()
      && let Some(m) = self.os.meta(offset >> SEGMENT_SHIFT)
      && m[SEG_HDR].load(Acquire) & 0xFF == SEG_OWNED
    {
      let page = offset >> PAGE_SHIFT;
      let pm = &m[SEGMENT_HEADER_WORDS + page % PAGES_PER_SEGMENT * PAGE_META_WORDS..];
      let info = pm[P_INFO].load(Acquire);
      if info & 0xFF == PAGE_SMALL {
        let c = ((info >> 8) & 0xFF) as usize;
        if let Some(idx) = class::block_index(c, offset % PAGE_SIZE) {
          let w = idx / 64;
          self.buffer_free(tc, page, c, w, 1 << (idx % 64), &pm[P_BITMAP + w]);
          return;
        }
      }
    }
    self.dealloc_cached_slow(tc, offset);
  }

  #[inline(never)]
  fn dealloc_cached_slow(&self, tc: &ThreadCache, offset: usize) {
    match self.block(offset, INVALID_FREE) {
      Target::Small { in_page, page, c } => {
        let (w, bit) = self.block_bit(in_page, c);
        if tc.is_attached() {
          let m = self.seg_meta(page / PAGES_PER_SEGMENT);
          let word = PageMeta::new(m, page % PAGES_PER_SEGMENT).bitmap(w);
          self.buffer_free(tc, page, c, w, bit, word);
        } else {
          self.free_bits(page, c, w, bit);
        }
      }
      Target::Large { page, m, pm, info } => {
        self.free_large(page, m, pm, info);
        self.observe_pressure(tc);
        self.tick(tc);
      }
      Target::Huge { seg, m, hdr } => {
        self.free_huge(seg, m, hdr);
        self.observe_pressure(tc);
        self.tick(tc);
      }
    }
  }

  /// Records a small free in the thread's buffer. `word` is the block's
  /// word of the page's shared bitmap.
  #[inline(always)]
  fn buffer_free(
    &self,
    tc: &ThreadCache,
    page: usize,
    c: usize,
    w: usize,
    bit: u64,
    word: &AtomicU64,
  ) {
    // A block that the shared bitmap shows as free is not allocated, so
    // this is a second free of it. One plain load without the lock, never a
    // read-modify-write; aborting is its only effect, and the value is not
    // kept. A clear bit decides nothing: the free is buffered, and its
    // write-back is checked under the lock. A free is ordered after the
    // allocation of its block (one that is not is a data race on the block),
    // so the claim that handed the block out, which cleared its bit under
    // the owner's lock, happened before this load; only a write-back of a
    // free of the block sets the bit again, so the check never reports a
    // legitimate free.
    if word.load(Relaxed) & bit != 0 {
      self.os.fatal(DOUBLE_FREE);
    }
    let cw = &tc.words[c];
    // A block the thread claimed but has not handed out cannot be freed.
    if cw.base.get() == (page << PAGE_SHIFT) + w * 64 * class::size(c)
      && self
        .os
        .list_holds(&cw.blocks, cw.len.get(), bit.trailing_zeros() as u8)
    {
      self.os.fatal(DOUBLE_FREE);
    }
    let key = slot_key(page, w, c);
    let set = set_index(page, w);
    let first = set * FREE_WAYS;
    // The word lives in at most one way of its set.
    let Some(slot) = tc.frees[first..first + FREE_WAYS]
      .iter()
      .find(|slot| slot.key.get() == key)
    else {
      return self.insert_slot(tc, set, key, c, bit);
    };
    let m = slot.mask.get();
    if m & bit != 0 {
      self.os.fatal(DOUBLE_FREE);
    }
    slot.mask.set(m | bit);
  }

  /// Makes a way of `set` hold `bit` of the word `key`, which no way of the
  /// set holds: an empty way, else the set's victim, flushed first. Also a
  /// sampled point where the cache sees cache-return requests.
  #[inline(never)]
  fn insert_slot(&self, tc: &ThreadCache, set: usize, key: u64, c: usize, bit: u64) {
    self.observe_pressure(tc);
    let first = set * FREE_WAYS;
    let way = match tc.frees[first..first + FREE_WAYS]
      .iter()
      .position(|slot| slot.key.get() == 0)
    {
      Some(way) => way,
      None => {
        bump(&tc.evictions, 1);
        let way = usize::from(tc.victims[set].get());
        self.flush_slot(tc, first + way);
        way
      }
    };
    // The next way is now the oldest: the next to go.
    tc.victims[set].set(((way + 1) % FREE_WAYS) as u8);
    let i = first + way;
    let slot = &tc.frees[i];
    slot.key.set(key);
    slot.mask.set(bit);
    let pending = &tc.pending[c][i / 64];
    pending.set(pending.get() | 1 << (i % 64));
  }

  /// Drains `tc` if a cache return was requested since it last looked (see
  /// the module docs). One relaxed load when nothing is requested.
  #[inline]
  fn observe_pressure(&self, tc: &ThreadCache) {
    let g = self.cache_pressure.load(Relaxed);
    if g != tc.pressure_seen.get() {
      self.return_cache(tc, g);
    }
  }

  /// Flushes `tc` for cache-return generation `g`, and records that it did.
  #[cold]
  #[inline(never)]
  fn return_cache(&self, tc: &ThreadCache, g: u32) {
    // A detached or retired cache holds nothing and owes nothing.
    if !tc.is_attached() {
      return;
    }
    self.flush(tc);
    tc.pressure_seen.set(g);
    bump(&tc.pressure_returns, 1);
  }

  /// Asks every attached thread cache to return what it holds to the
  /// shared bitmaps. Returns at once; each cache drains itself, on its own
  /// thread, at its next sampled slow path (see the module docs). A thread
  /// that never calls the allocator again, or is asleep, does not drain.
  /// Lock-free and allocation-free.
  pub fn request_cache_return(&self) {
    self.cache_pressure.fetch_add(1, Relaxed);
  }

  /// The cache-return generation: how many requests were made (modulo
  /// 2^32).
  pub fn cache_return_generation(&self) -> u32 {
    self.cache_pressure.load(Relaxed)
  }

  /// Returns the frees buffered in slot `i` to the bitmap.
  fn flush_slot(&self, tc: &ThreadCache, i: usize) {
    let slot = &tc.frees[i];
    let key = slot.key.replace(0);
    if key == 0 {
      return;
    }
    let (page, w, c) = unpack_key(key);
    let pending = &tc.pending[c][i / 64];
    pending.set(pending.get() & !(1 << (i % 64)));
    let mask = slot.mask.get();
    let n = mask.count_ones();
    bump(&tc.flushed_blocks, u64::from(n));
    // A slot holds at least one block: bucket floor(log2(n)), 0..=6.
    bump(
      &tc.flush_sizes[(u32::BITS - 1 - n.leading_zeros()) as usize],
      1,
    );
    self.free_bits(page, c, w, mask);
  }

  /// Returns the buffered frees of class `c`.
  fn flush_class(&self, tc: &ThreadCache, c: usize) {
    for (n, word) in tc.pending[c].iter().enumerate() {
      let mut pending = word.get();
      while pending != 0 {
        self.flush_slot(tc, n * 64 + pending.trailing_zeros() as usize);
        pending &= pending - 1;
      }
    }
  }

  /// What `tc` holds now and how it flushed its buffered frees so far (see
  /// [`CacheStats`]). Only the thread that owns `tc` can call it; it reads
  /// the cache's `Cell`s and nothing shared.
  pub fn cache_stats(&self, tc: &ThreadCache) -> CacheStats {
    let (mut buffered_blocks, mut buffered_words) = (0, 0);
    for slot in &tc.frees {
      if slot.key.get() != 0 {
        buffered_words += 1;
        buffered_blocks += u64::from(slot.mask.get().count_ones());
      }
    }
    let flush_sizes = core::array::from_fn(|i| tc.flush_sizes[i].get());
    CacheStats {
      attached: tc.is_attached(),
      shard: tc.shard.get(),
      claimed_blocks: tc.words.iter().map(|w| u64::from(w.len.get())).sum(),
      buffered_blocks,
      buffered_words,
      flushes: flush_sizes.iter().fold(0u64, |a, &n| a.wrapping_add(n)),
      flushed_blocks: tc.flushed_blocks.get(),
      flush_sizes,
      evictions: tc.evictions.get(),
      refill_flushes: tc.refill_flushes.get(),
      pressure_returns: tc.pressure_returns.get(),
    }
  }

  /// The set of the free buffer that a free at `offset` (a small block)
  /// goes to, for tests that build collisions.
  #[cfg(all(test, allocatbelt_core_check))]
  pub(crate) fn free_set_of(offset: usize, c: usize) -> usize {
    let page = offset >> PAGE_SHIFT;
    let idx = class::block_index(c, offset % PAGE_SIZE).unwrap_or(0);
    set_index(page, idx / 64)
  }

  /// The occupied slots of class `c` (bit `i` = slot `i`), for tests of
  /// the pending masks.
  #[cfg(all(test, allocatbelt_core_check))]
  pub(crate) fn pending_slots(tc: &ThreadCache, c: usize) -> u128 {
    const { assert!(FREE_SLOTS <= 128) };
    tc.pending[c]
      .iter()
      .enumerate()
      .fold(0, |m, (n, w)| m | u128::from(w.get()) << (n * 64))
  }

  /// The words the free buffer holds, as `(page, word, class)`, and the
  /// mask of each, for tests of its bounds.
  #[cfg(all(test, allocatbelt_core_check))]
  pub(crate) fn buffered_words(tc: &ThreadCache) -> std::vec::Vec<((usize, usize, usize), u64)> {
    tc.frees
      .iter()
      .filter(|slot| slot.key.get() != 0)
      .map(|slot| (unpack_key(slot.key.get()), slot.mask.get()))
      .collect()
  }

  /// Slots of the free buffer, for tests of its bounds.
  #[cfg(all(test, allocatbelt_core_check))]
  pub(crate) const FREE_SLOTS: usize = FREE_SLOTS;

  /// Ways of a set of the free buffer, for tests that fill one set.
  #[cfg(all(test, allocatbelt_core_check))]
  pub(crate) const FREE_WAYS: usize = FREE_WAYS;

  /// Checks that every class's pending mask names exactly the occupied
  /// slots of that class, and that no word is in two slots.
  #[cfg(all(any(all(test, allocatbelt_core_check), allocatbelt_model), not(loom)))]
  pub(crate) fn check_free_buffer(tc: &ThreadCache) {
    let mut seen = [[0u64; SLOT_WORDS]; NUM_CLASSES];
    for (i, slot) in tc.frees.iter().enumerate() {
      let key = slot.key.get();
      if key == 0 {
        continue;
      }
      assert_ne!(slot.mask.get(), 0, "slot {i} holds no block");
      let (page, w, c) = unpack_key(key);
      assert_eq!(
        set_index(page, w),
        i / FREE_WAYS,
        "slot {i} in the wrong set"
      );
      seen[c][i / 64] |= 1 << (i % 64);
      for (j, other) in tc.frees.iter().enumerate() {
        assert!(
          j == i || other.key.get() != key,
          "word in slots {i} and {j}"
        );
      }
    }
    for (c, p) in tc.pending.iter().enumerate() {
      assert_eq!(
        core::array::from_fn::<u64, SLOT_WORDS, _>(|n| p[n].get()),
        seen[c],
        "pending mask of class {c}"
      );
    }
    for (set, victim) in tc.victims.iter().enumerate() {
      assert!(usize::from(victim.get()) < FREE_WAYS, "victim of set {set}");
    }
  }

  /// Sets the cache-return generation, for tests of its wrap-around.
  #[cfg(all(test, allocatbelt_core_check))]
  pub(crate) fn set_cache_return_generation(&self, g: u32) {
    self.cache_pressure.store(g, Relaxed);
  }
}

/// Adds `n` to a diagnostic counter of the cache (wrapping).
#[inline]
fn bump(counter: &Cell<u64>, n: u64) {
  counter.set(counter.get().wrapping_add(n));
}

#[cfg(all(test, allocatbelt_core_check))]
mod tests;
