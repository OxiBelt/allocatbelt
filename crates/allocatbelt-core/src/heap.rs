//! The heap: segment allocation, page runs, small-object bitmaps and frees.
//!
//! Metadata layout (all `AtomicU64`, one slice of [`META_WORDS`] per segment):
//!
//! ```text
//! [0] SEG_HDR    kind | shard << 8 | segment count << 16
//! [1] SEG_PAGES  occupancy bitmap of the 64 pages (1 = in use)
//! [2] SEG_NEXT   next segment of the owning shard (index + 1, 0 = end)
//! [3] SEG_DIRTY  free pages whose memory has not been purged yet
//! then per page (PAGE_META_WORDS each):
//!   [0] P_INFO   kind | class << 8 | run length << 16
//!   [1] P_FREE   number of set bits in the bitmap (may transiently lag)
//!   [2] P_NEXT   next page of the same class in the shard (index + 1)
//!   [3] reserved
//!   [4..68]      free bitmap (1 = free block)
//! ```
//!
//! Locking: each shard has a spin lock that serialises *allocation* from its
//! pages. Frees never take a lock: a small free is one `fetch_or` on the
//! bitmap plus a `fetch_add` on the page's free counter, and a large free is a
//! compare-exchange on the page header and a `fetch_and` on the segment's page
//! bitmap. Only the owning shard (under its lock) hands out bits, and only it
//! recycles a page, which it does solely when every block of the page is free.
//!
//! Purging is deferred: freed page runs are only marked dirty. Once more than
//! [`DIRTY_BUDGET_PAGES`] pages are dirty, the freeing thread claims the dirty
//! free pages of every segment (as if allocating them), `madvise`s them and
//! releases them again. Purging on every free costs an `mmap_lock` round trip
//! and a TLB shootdown per call, which dominated multi-threaded profiles.

use core::sync::atomic::{AtomicIsize, AtomicU32, AtomicU64, Ordering};

use crate::bits::{find_run, run_mask};
use crate::class::{self, MIN_ALIGN, NUM_CLASSES, SMALL_MAX};
use crate::lock::SpinLock;
use crate::{
    ARENA_SIZE, MAX_ALIGN, MAX_SEGMENTS, PAGE_META_WORDS, PAGE_SHIFT, PAGE_SIZE, PAGES_PER_SEGMENT,
    SEGMENT_HEADER_WORDS, SEGMENT_SHIFT, SEGMENT_SIZE, SHARDS,
};

use Ordering::{AcqRel, Acquire, Relaxed, Release};

/// Services the heap needs from its environment.
///
/// Offsets are relative to the start of a [`ARENA_SIZE`]-byte arena whose base
/// is aligned to [`SEGMENT_SIZE`]. The heap guarantees that it only calls
/// [`Os::decommit`] and [`Os::purge`] on ranges that contain no live
/// allocation, and that it never hands out an offset that has not been
/// committed.
pub trait Os: Sync {
    /// Makes `offset..offset + len` readable and writable. Returns `false` if
    /// the memory cannot be provided.
    fn commit(&self, offset: usize, len: usize) -> bool;
    /// Returns the physical memory of the range to the OS and makes it
    /// inaccessible.
    fn decommit(&self, offset: usize, len: usize);
    /// Returns the physical memory of the range to the OS but keeps it
    /// accessible.
    fn purge(&self, offset: usize, len: usize);
    /// Commits (once) and returns the [`crate::META_WORDS`] metadata words of
    /// `segment`. Words are zero the first time they are returned.
    fn commit_meta(&self, segment: usize) -> Option<&[AtomicU64]>;
    /// Metadata words of `segment` if [`Os::commit_meta`] succeeded before.
    fn meta(&self, segment: usize) -> Option<&[AtomicU64]>;
    /// Called while spinning on a contended lock.
    fn yield_now(&self) {}
    /// Reports heap corruption or misuse (invalid or double free). Must not
    /// return.
    fn fatal(&self, msg: &'static str) -> !;
}

const SEG_HDR: usize = 0;
const SEG_PAGES: usize = 1;
const SEG_NEXT: usize = 2;
const SEG_DIRTY: usize = 3;

const SEG_FREE: u64 = 0;
const SEG_OWNED: u64 = 1;
const SEG_HUGE: u64 = 2;
const SEG_HUGE_TAIL: u64 = 3;

const P_INFO: usize = 0;
const P_FREE: usize = 1;
const P_NEXT: usize = 2;
const P_BITMAP: usize = 4;

const PAGE_FREE: u64 = 0;
const PAGE_SMALL: u64 = 1;
const PAGE_LARGE: u64 = 2;
const PAGE_LARGE_TAIL: u64 = 3;

/// Dirty (freed, unpurged) pages tolerated before a purge pass (32 MiB).
pub const DIRTY_BUDGET_PAGES: isize = 512;
/// Shards tried with `try_lock` before blocking on the preferred one.
const SHARD_PROBES: usize = 4;

#[derive(Debug)]
struct ClassState {
    /// `(page + 1) << 32 | next bitmap word to scan`; 0 when there is no page.
    cursor: AtomicU64,
    /// Free blocks claimed from bitmap word `next - 1` of the cursor page.
    bits: AtomicU64,
    /// Head of this shard's list of pages of this class (page + 1).
    head: AtomicU32,
}

impl ClassState {
    const fn new() -> Self {
        Self {
            cursor: AtomicU64::new(0),
            bits: AtomicU64::new(0),
            head: AtomicU32::new(0),
        }
    }
}

#[derive(Debug)]
#[repr(align(128))]
struct Shard {
    lock: SpinLock,
    /// Head of the list of segments owned by this shard (segment + 1).
    segs: AtomicU32,
    classes: [ClassState; NUM_CLASSES],
}

impl Shard {
    const fn new() -> Self {
        Self {
            lock: SpinLock::new(),
            segs: AtomicU32::new(0),
            classes: [const { ClassState::new() }; NUM_CLASSES],
        }
    }
}

const fn pack(page: usize, next: usize) -> u64 {
    ((page as u64 + 1) << 32) | next as u64
}

const fn unpack(cursor: u64) -> (usize, usize) {
    (
        ((cursor >> 32) - 1) as usize,
        (cursor & 0xFFFF_FFFF) as usize,
    )
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
    fn next(self) -> &'a AtomicU64 {
        &self.0[P_NEXT]
    }
    fn bitmap(self, w: usize) -> &'a AtomicU64 {
        &self.0[P_BITMAP + w]
    }
}

/// A sharded heap handing out offsets into the arena managed by `O`.
#[derive(Debug)]
pub struct Heap<O> {
    os: O,
    seg_lock: SpinLock,
    seg_used: [AtomicU64; MAX_SEGMENTS / 64],
    /// Pages marked dirty and not yet purged or reused (may transiently lag).
    dirty_pages: AtomicIsize,
    purge_lock: SpinLock,
    shards: [Shard; SHARDS],
}

impl<O: Os> Heap<O> {
    /// Creates an empty heap. No memory is touched until the first allocation.
    pub const fn new(os: O) -> Self {
        Self {
            os,
            seg_lock: SpinLock::new(),
            seg_used: [const { AtomicU64::new(0) }; MAX_SEGMENTS / 64],
            dirty_pages: AtomicIsize::new(0),
            purge_lock: SpinLock::new(),
            shards: [const { Shard::new() }; SHARDS],
        }
    }

    /// The environment this heap runs on.
    pub const fn os(&self) -> &O {
        &self.os
    }

    /// Allocates `size` bytes aligned to `align` and returns the arena offset.
    ///
    /// `shard_hint` selects the preferred shard (typically a per-thread
    /// value). Returns `None` when out of memory or when `align` is not a
    /// power of two no larger than [`MAX_ALIGN`].
    pub fn alloc(&self, shard_hint: usize, size: usize, align: usize) -> Option<usize> {
        if !align.is_power_of_two() || align > MAX_ALIGN || size > ARENA_SIZE / 2 {
            return None;
        }
        if align <= MIN_ALIGN && size <= SMALL_MAX {
            return self.alloc_small(shard_hint, class::class_of(size));
        }
        if align > MIN_ALIGN && align <= SMALL_MAX {
            // Power-of-two classes are aligned to their own size.
            let p = size.max(align).next_power_of_two();
            if p <= SMALL_MAX {
                return self.alloc_small(shard_hint, class::class_of(p));
            }
        }
        if align <= PAGE_SIZE && size <= SEGMENT_SIZE {
            return self.alloc_large(shard_hint, size.div_ceil(PAGE_SIZE).max(1));
        }
        self.alloc_huge(size.div_ceil(SEGMENT_SIZE).max(1))
    }

    /// Frees the allocation at `offset`. Invalid and double frees are reported
    /// through [`Os::fatal`].
    pub fn dealloc(&self, offset: usize) {
        let (seg, m, hdr) = self.lookup(offset);
        match hdr & 0xFF {
            SEG_OWNED => {
                let page = offset >> PAGE_SHIFT;
                let pm = PageMeta::new(m, page % PAGES_PER_SEGMENT);
                let info = pm.info().load(Acquire);
                match info & 0xFF {
                    PAGE_SMALL => self.free_small(offset, pm, ((info >> 8) & 0xFF) as usize),
                    PAGE_LARGE if offset.is_multiple_of(PAGE_SIZE) => {
                        self.free_large(page, m, pm, info)
                    }
                    _ => self
                        .os
                        .fatal("allocatbelt: invalid or double free (pointer is not allocated)"),
                }
            }
            SEG_HUGE if offset.is_multiple_of(SEGMENT_SIZE) => self.free_huge(seg, m, hdr),
            _ => self
                .os
                .fatal("allocatbelt: invalid or double free (pointer is not allocated)"),
        }
    }

    /// Bytes usable at `offset`, which must be a live allocation.
    pub fn usable_size(&self, offset: usize) -> usize {
        let (_, m, hdr) = self.lookup(offset);
        match hdr & 0xFF {
            SEG_OWNED => {
                let info = PageMeta::new(m, (offset >> PAGE_SHIFT) % PAGES_PER_SEGMENT)
                    .info()
                    .load(Acquire);
                match info & 0xFF {
                    PAGE_SMALL => class::size(((info >> 8) & 0xFF) as usize),
                    PAGE_LARGE => ((info >> 16) & 0xFF) as usize * PAGE_SIZE,
                    _ => self
                        .os
                        .fatal("allocatbelt: size query for a pointer that is not allocated"),
                }
            }
            SEG_HUGE => (hdr >> 16) as usize * SEGMENT_SIZE,
            _ => self
                .os
                .fatal("allocatbelt: size query for a pointer that is not allocated"),
        }
    }

    /// Pages freed but not yet purged or reused.
    pub fn dirty_pages(&self) -> usize {
        self.dirty_pages.load(Relaxed).max(0) as usize
    }

    /// Number of segments currently taken from the arena.
    pub fn segments_in_use(&self) -> usize {
        self.seg_used
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

    fn page_meta(&self, page: usize) -> PageMeta<'_> {
        PageMeta::new(
            self.seg_meta(page / PAGES_PER_SEGMENT),
            page % PAGES_PER_SEGMENT,
        )
    }

    /// Runs `f` with a locked shard, preferring `hint` and probing a few
    /// neighbours before blocking so that threads sharing a shard rarely spin.
    fn with_shard<R>(&self, hint: usize, f: impl FnOnce(usize, &Shard) -> R) -> R {
        for i in 0..SHARD_PROBES {
            let s = (hint + i) % SHARDS;
            if let Some(_g) = self.shards[s].lock.try_lock() {
                return f(s, &self.shards[s]);
            }
        }
        let s = hint % SHARDS;
        let _g = self.shards[s].lock.lock(|| self.os.yield_now());
        f(s, &self.shards[s])
    }

    // ---- small objects -------------------------------------------------

    fn alloc_small(&self, hint: usize, c: usize) -> Option<usize> {
        self.with_shard(hint, |s, sh| self.alloc_small_locked(s, sh, c))
    }

    fn alloc_small_locked(&self, s: usize, sh: &Shard, c: usize) -> Option<usize> {
        let cs = &sh.classes[c];
        let size = class::size(c);
        'refill: loop {
            let bits = cs.bits.load(Relaxed);
            let cursor = cs.cursor.load(Relaxed);
            if bits != 0 {
                cs.bits.store(bits & (bits - 1), Relaxed);
                let (page, next) = unpack(cursor);
                let idx = (next - 1) * 64 + bits.trailing_zeros() as usize;
                return Some((page << PAGE_SHIFT) + idx * size);
            }
            if cursor != 0 {
                let (page, mut next) = unpack(cursor);
                let pm = self.page_meta(page);
                while next < class::bitmap_words(c) {
                    // Claim a whole word: later pops need no atomics.
                    let b = pm.bitmap(next).swap(0, Acquire);
                    next += 1;
                    if b != 0 {
                        pm.free().fetch_sub(u64::from(b.count_ones()), Relaxed);
                        cs.cursor.store(pack(page, next), Relaxed);
                        cs.bits.store(b, Relaxed);
                        continue 'refill;
                    }
                }
                cs.cursor.store(0, Relaxed);
            }
            let page = match self.find_page(cs, c) {
                Some(p) => p,
                None => self.new_small_page(s, sh, cs, c)?,
            };
            cs.cursor.store(pack(page, 0), Relaxed);
        }
    }

    /// Finds a page of class `c` with free blocks and recycles surplus pages
    /// whose blocks are all free.
    fn find_page(&self, cs: &ClassState, c: usize) -> Option<usize> {
        let cap = class::capacity(c) as i64;
        let mut prev: Option<usize> = None;
        let mut cur = cs.head.load(Relaxed);
        let mut found = None;
        while cur != 0 {
            let p = cur as usize - 1;
            let pm = self.page_meta(p);
            let next = pm.next().load(Relaxed) as u32;
            // Frees set the bit before bumping the counter, so the counter
            // never overstates the set bits once our own claims are
            // subtracted. It can transiently read low (even negative).
            let free = pm.free().load(Acquire) as i64;
            if free >= cap && found.is_some() {
                match prev {
                    None => cs.head.store(next, Relaxed),
                    Some(q) => self.page_meta(q).next().store(u64::from(next), Relaxed),
                }
                self.release_small_page(p, pm);
                cur = next;
                continue;
            }
            if free > 0 && found.is_none() {
                found = Some(p);
            }
            prev = Some(p);
            cur = next;
        }
        found
    }

    fn new_small_page(&self, s: usize, sh: &Shard, cs: &ClassState, c: usize) -> Option<usize> {
        let p = self.alloc_pages(s, sh, 1)?;
        let pm = self.page_meta(p);
        let cap = class::capacity(c);
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
        pm.next().store(u64::from(cs.head.load(Relaxed)), Relaxed);
        pm.info().store(PAGE_SMALL | (c as u64) << 8, Release);
        cs.head.store(p as u32 + 1, Relaxed);
        Some(p)
    }

    fn release_small_page(&self, page: usize, pm: PageMeta<'_>) {
        pm.info().store(PAGE_FREE, Release);
        self.release_pages(page, 1);
    }

    fn free_small(&self, offset: usize, pm: PageMeta<'_>, c: usize) {
        let size = class::size(c);
        let in_page = offset % PAGE_SIZE;
        let idx = in_page / size;
        if !in_page.is_multiple_of(size) || idx >= class::capacity(c) {
            self.os
                .fatal("allocatbelt: free of a misaligned small pointer");
        }
        let bit = 1u64 << (idx % 64);
        if pm.bitmap(idx / 64).fetch_or(bit, Release) & bit != 0 {
            self.os.fatal("allocatbelt: double free detected");
        }
        pm.free().fetch_add(1, Release);
    }

    // ---- page runs -----------------------------------------------------

    fn alloc_large(&self, hint: usize, n: usize) -> Option<usize> {
        self.with_shard(hint, |s, sh| {
            let p = self.alloc_pages(s, sh, n)?;
            let m = self.seg_meta(p / PAGES_PER_SEGMENT);
            for t in 1..n {
                PageMeta::new(m, p % PAGES_PER_SEGMENT + t)
                    .info()
                    .store(PAGE_LARGE_TAIL, Relaxed);
            }
            PageMeta::new(m, p % PAGES_PER_SEGMENT)
                .info()
                .store(PAGE_LARGE | (n as u64) << 16, Release);
            Some(p << PAGE_SHIFT)
        })
    }

    fn free_large(&self, page: usize, m: &[AtomicU64], pm: PageMeta<'_>, info: u64) {
        if pm
            .info()
            .compare_exchange(info, PAGE_FREE, AcqRel, Relaxed)
            .is_err()
        {
            self.os.fatal("allocatbelt: double free detected");
        }
        let n = ((info >> 16) & 0xFF) as usize;
        for t in 1..n {
            PageMeta::new(m, page % PAGES_PER_SEGMENT + t)
                .info()
                .store(PAGE_FREE, Relaxed);
        }
        self.release_pages(page, n);
    }

    /// Claims `n` contiguous pages from a segment owned by shard `s`.
    fn alloc_pages(&self, s: usize, sh: &Shard, n: usize) -> Option<usize> {
        let mut cur = sh.segs.load(Relaxed);
        while cur != 0 {
            let seg = cur as usize - 1;
            let m = self.seg_meta(seg);
            if let Some(start) = self.claim_run(m, n) {
                return Some(seg * PAGES_PER_SEGMENT + start);
            }
            cur = m[SEG_NEXT].load(Relaxed) as u32;
        }
        let seg = self.alloc_segments(1)?;
        let m = self.seg_meta(seg);
        m[SEG_PAGES].store(0, Relaxed);
        m[SEG_DIRTY].store(0, Relaxed);
        m[SEG_NEXT].store(u64::from(sh.segs.load(Relaxed)), Relaxed);
        m[SEG_HDR].store(SEG_OWNED | (s as u64) << 8 | 1 << 16, Release);
        sh.segs.store(seg as u32 + 1, Relaxed);
        self.claim_run(m, n)
            .map(|start| seg * PAGES_PER_SEGMENT + start)
    }

    /// Atomically claims a run of `n` free pages in a segment. Reusing dirty
    /// pages is free: they simply stop being dirty.
    fn claim_run(&self, m: &[AtomicU64], n: usize) -> Option<usize> {
        let mut used = m[SEG_PAGES].load(Acquire);
        loop {
            let start = find_run(!used, n as u32)?;
            let mask = run_mask(start, n as u32);
            match m[SEG_PAGES].compare_exchange_weak(used, used | mask, AcqRel, Acquire) {
                Ok(_) => {
                    let was_dirty = m[SEG_DIRTY].fetch_and(!mask, AcqRel) & mask;
                    if was_dirty != 0 {
                        self.dirty_pages
                            .fetch_sub(was_dirty.count_ones() as isize, Relaxed);
                    }
                    return Some(start as usize);
                }
                Err(now) => used = now,
            }
        }
    }

    /// Marks `n` pages dirty and returns them to their segment.
    fn release_pages(&self, page: usize, n: usize) {
        let m = self.seg_meta(page / PAGES_PER_SEGMENT);
        let mask = run_mask((page % PAGES_PER_SEGMENT) as u32, n as u32);
        // Dirty first, so a claimer that grabs the pages clears the mark.
        m[SEG_DIRTY].fetch_or(mask, Release);
        m[SEG_PAGES].fetch_and(!mask, Release);
        let dirty = self.dirty_pages.fetch_add(n as isize, Relaxed) + n as isize;
        if dirty > DIRTY_BUDGET_PAGES
            && let Some(_g) = self.purge_lock.try_lock()
        {
            self.purge_segments();
        }
    }

    /// Returns the memory of every free, dirty page to the OS.
    ///
    /// Embedders may call this from a maintenance task (e.g. when idle); it is
    /// also run automatically once the dirty budget is exceeded.
    pub fn purge(&self) {
        let _g = self.purge_lock.lock(|| self.os.yield_now());
        self.purge_segments();
    }

    fn purge_segments(&self) {
        for (wi, word) in self.seg_used.iter().enumerate() {
            let mut used_segs = word.load(Relaxed);
            while used_segs != 0 {
                let seg = wi * 64 + used_segs.trailing_zeros() as usize;
                used_segs &= used_segs - 1;
                if let Some(m) = self.os.meta(seg)
                    && m[SEG_HDR].load(Acquire) & 0xFF == SEG_OWNED
                {
                    self.purge_segment(seg, m);
                }
            }
        }
    }

    fn purge_segment(&self, seg: usize, m: &[AtomicU64]) {
        let mut used = m[SEG_PAGES].load(Acquire);
        let dirty = loop {
            let d = m[SEG_DIRTY].load(Acquire) & !used;
            if d == 0 {
                return;
            }
            // Claim the dirty free pages like an allocation would, so nobody
            // can hand them out while their contents are being discarded.
            match m[SEG_PAGES].compare_exchange_weak(used, used | d, AcqRel, Acquire) {
                Ok(_) => break d,
                Err(now) => used = now,
            }
        };
        let mut rest = dirty;
        while rest != 0 {
            let start = rest.trailing_zeros();
            let len = (rest >> start).trailing_ones();
            let page = seg * PAGES_PER_SEGMENT + start as usize;
            self.os.purge(page << PAGE_SHIFT, len as usize * PAGE_SIZE);
            rest &= !run_mask(start, len);
        }
        let cleared = m[SEG_DIRTY].fetch_and(!dirty, AcqRel) & dirty;
        self.dirty_pages
            .fetch_sub(cleared.count_ones() as isize, Relaxed);
        m[SEG_PAGES].fetch_and(!dirty, Release);
    }

    // ---- segments ------------------------------------------------------

    fn alloc_huge(&self, k: usize) -> Option<usize> {
        let first = self.alloc_segments(k)?;
        for i in (0..k).rev() {
            let hdr = if i == 0 {
                SEG_HUGE | (k as u64) << 16
            } else {
                SEG_HUGE_TAIL
            };
            self.seg_meta(first + i)[SEG_HDR].store(hdr, Release);
        }
        Some(first << SEGMENT_SHIFT)
    }

    fn free_huge(&self, seg: usize, m: &[AtomicU64], hdr: u64) {
        if m[SEG_HDR]
            .compare_exchange(hdr, SEG_FREE, AcqRel, Relaxed)
            .is_err()
        {
            self.os.fatal("allocatbelt: double free detected");
        }
        let k = (hdr >> 16) as usize;
        for i in 1..k {
            self.seg_meta(seg + i)[SEG_HDR].store(SEG_FREE, Relaxed);
        }
        self.free_segments(seg, k);
    }

    /// Takes `k` contiguous segments from the arena, commits their memory and
    /// metadata, and returns the first index.
    fn alloc_segments(&self, k: usize) -> Option<usize> {
        if k == 0 || k > MAX_SEGMENTS {
            return None;
        }
        let first = {
            let _g = self.seg_lock.lock(|| self.os.yield_now());
            let first = self.find_free_segments(k)?;
            self.mark_segments(first, k, true);
            first
        };
        let committed = self.os.commit(first << SEGMENT_SHIFT, k << SEGMENT_SHIFT)
            && (first..first + k).all(|s| self.os.commit_meta(s).is_some());
        if !committed {
            self.free_segments(first, k);
            return None;
        }
        Some(first)
    }

    fn free_segments(&self, first: usize, k: usize) {
        self.os.decommit(first << SEGMENT_SHIFT, k << SEGMENT_SHIFT);
        let _g = self.seg_lock.lock(|| self.os.yield_now());
        self.mark_segments(first, k, false);
    }

    /// First-fit search for `k` free segments. Caller holds `seg_lock`.
    fn find_free_segments(&self, k: usize) -> Option<usize> {
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
