//! Per-thread caches: claimed bitmap words for allocation, and a buffer of
//! frees returned to the shared bitmaps one word at a time.

use core::cell::Cell;

use super::*;

/// Direct-mapped slots of buffered frees per thread.
const FREE_SLOTS: usize = 64;

const DETACHED: u8 = 0;
const ATTACHING: u8 = 1;
const ATTACHED: u8 = 2;
const RETIRED: u8 = 3;

/// Free blocks of one bitmap word, claimed by a thread.
#[derive(Debug)]
struct CachedWord {
  /// Arena offset of the word's first block.
  base: Cell<usize>,
  /// Claimed free blocks (bit `i` is block `base + i * size`).
  bits: Cell<u64>,
}

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

#[inline]
const fn slot_index(page: usize, w: usize) -> usize {
  ((((page << 6) | w) as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 58) as usize
}

const _: () = assert!(FREE_SLOTS == 64);

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
  words: [CachedWord; NUM_CLASSES],
  frees: [FreeSlot; FREE_SLOTS],
  /// Occupied free slots per class (bit `i` = `frees[i]`).
  pending: [Cell<u64>; NUM_CLASSES],
  shard: Cell<usize>,
  state: Cell<u8>,
}

impl ThreadCache {
  /// A detached, empty cache.
  #[must_use]
  pub const fn new() -> Self {
    Self {
      words: [const {
        CachedWord {
          base: Cell::new(0),
          bits: Cell::new(0),
        }
      }; NUM_CLASSES],
      frees: [const {
        FreeSlot {
          key: Cell::new(0),
          mask: Cell::new(0),
        }
      }; FREE_SLOTS],
      pending: [const { Cell::new(0) }; NUM_CLASSES],
      shard: Cell::new(0),
      state: Cell::new(DETACHED),
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
    self.alloc_cached_slow(tc, size, align)
  }

  fn alloc_cached_slow(&self, tc: &ThreadCache, size: usize, align: usize) -> Option<Block> {
    if !tc.is_attached() {
      return self.alloc_block(tc.shard.get(), size, align);
    }
    match Self::kind(size, align)? {
      Kind::Small(c) => Self::pop(tc, c)
        .or_else(|| self.refill(tc, c))
        .map(|o| Block::new(o, false)),
      Kind::Run(n, step) => self.alloc_large(tc.shard.get(), n, step),
      Kind::Huge(k) => self.alloc_huge(k),
    }
  }

  /// Takes a free block of class `c` from the thread's claimed word.
  #[inline(always)]
  fn pop(tc: &ThreadCache, c: usize) -> Option<usize> {
    let cw = &tc.words[c];
    let bits = cw.bits.get();
    if bits == 0 {
      return None;
    }
    let i = bits.trailing_zeros();
    cw.bits.set(bits & (bits - 1));
    Some(cw.base.get() + i as usize * class::size(c))
  }

  /// Claims a new word of class `c` for the thread and pops from it.
  #[inline(never)]
  fn refill(&self, tc: &ThreadCache, c: usize) -> Option<usize> {
    // Frees the thread has buffered stay buffered (and keep batching)
    // while the class has free blocks elsewhere; before a new page is
    // taken for the class, they go back so the claim can reuse them.
    let grow = tc.pending[c].get() == 0;
    let hint = tc.shard.get();
    let (page, w, bits) =
      match self.with_shard(hint, |s, sh| self.claim_class_word(s, sh, c, grow))? {
        Some(claim) => claim,
        None => {
          self.flush_class(tc, c);
          self.with_shard(hint, |s, sh| self.claim_class_word(s, sh, c, true))??
        }
      };
    let cw = &tc.words[c];
    cw.base
      .set((page << PAGE_SHIFT) + w as usize * 64 * class::size(c));
    cw.bits.set(bits);
    Self::pop(tc, c)
  }

  /// Enables caching for `tc`. The embedder must arrange for
  /// [`Heap::retire`] to run when the thread exits, before calling this.
  pub fn attach(&self, tc: &ThreadCache) {
    if tc.state.get() == RETIRED {
      return;
    }
    tc.shard.set(self.next_shard.fetch_add(1, Relaxed) % SHARDS);
    tc.state.set(ATTACHED);
  }

  /// Returns every block held by `tc` (claimed or freed) to the shared
  /// bitmaps. The cache stays usable.
  pub fn flush(&self, tc: &ThreadCache) {
    for i in 0..FREE_SLOTS {
      self.flush_slot(tc, i);
    }
    for (c, cw) in tc.words.iter().enumerate() {
      let bits = cw.bits.replace(0);
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
      let info =
        m[SEGMENT_HEADER_WORDS + page % PAGES_PER_SEGMENT * PAGE_META_WORDS + P_INFO].load(Acquire);
      if info & 0xFF == PAGE_SMALL {
        let c = ((info >> 8) & 0xFF) as usize;
        if let Some(idx) = class::block_index(c, offset % PAGE_SIZE) {
          self.buffer_free(tc, page, c, idx / 64, 1 << (idx % 64));
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
          self.buffer_free(tc, page, c, w, bit);
        } else {
          self.free_bits(page, c, w, bit);
        }
      }
      Target::Large { page, m, pm, info } => self.free_large(page, m, pm, info),
      Target::Huge { seg, m, hdr } => self.free_huge(seg, m, hdr),
    }
  }

  /// Records a small free in the thread's buffer.
  #[inline(always)]
  fn buffer_free(&self, tc: &ThreadCache, page: usize, c: usize, w: usize, bit: u64) {
    let cw = &tc.words[c];
    // A block the thread claimed but has not handed out cannot be freed.
    if cw.bits.get() & bit != 0 && cw.base.get() == (page << PAGE_SHIFT) + w * 64 * class::size(c) {
      self.os.fatal(DOUBLE_FREE);
    }
    let key = slot_key(page, w, c);
    let i = slot_index(page, w);
    let slot = &tc.frees[i];
    if slot.key.get() == key {
      let m = slot.mask.get();
      if m & bit != 0 {
        self.os.fatal(DOUBLE_FREE);
      }
      slot.mask.set(m | bit);
    } else {
      self.replace_slot(tc, i, key, c, bit);
    }
  }

  /// Flushes slot `i` and makes it hold `bit` of the word `key`.
  #[inline(never)]
  fn replace_slot(&self, tc: &ThreadCache, i: usize, key: u64, c: usize, bit: u64) {
    self.flush_slot(tc, i);
    let slot = &tc.frees[i];
    slot.key.set(key);
    slot.mask.set(bit);
    tc.pending[c].set(tc.pending[c].get() | 1 << i);
  }

  /// Returns the frees buffered in slot `i` to the bitmap.
  fn flush_slot(&self, tc: &ThreadCache, i: usize) {
    let slot = &tc.frees[i];
    let key = slot.key.replace(0);
    if key == 0 {
      return;
    }
    let (page, w, c) = unpack_key(key);
    tc.pending[c].set(tc.pending[c].get() & !(1 << i));
    self.free_bits(page, c, w, slot.mask.get());
  }

  /// Returns the buffered frees of class `c`.
  fn flush_class(&self, tc: &ThreadCache, c: usize) {
    let mut pending = tc.pending[c].get();
    while pending != 0 {
      self.flush_slot(tc, pending.trailing_zeros() as usize);
      pending &= pending - 1;
    }
  }
}
