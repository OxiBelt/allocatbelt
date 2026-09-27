//! Model tests: the heap runs on a mock [`Os`] that never backs user memory
//! but checks the heap's promises (offsets are committed, purged ranges hold
//! no live allocation, blocks reported as zeroed were not written since they
//! were last purged) against shadow maps.

use std::boxed::Box;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

use crate::{ARENA_SIZE, Block, Heap, MAX_SEGMENTS, META_WORDS, Os, PAGE_SIZE, SEGMENT_SIZE};

struct MockOs {
    meta: Vec<OnceLock<&'static [AtomicU64]>>,
    committed: Vec<AtomicBool>,
    live: Mutex<BTreeMap<usize, usize>>,
    /// Pages the "program" wrote to since they were last purged.
    written: Mutex<BTreeSet<usize>>,
    /// Bytes handed back to the OS by `purge` or `decommit`.
    purged: AtomicUsize,
    /// Makes `purge` and `decommit` report failure, as `madvise` does on
    /// `mlock`ed memory.
    purge_fails: AtomicBool,
}

impl MockOs {
    fn new() -> Self {
        Self {
            meta: (0..MAX_SEGMENTS).map(|_| OnceLock::new()).collect(),
            committed: (0..MAX_SEGMENTS).map(|_| AtomicBool::new(false)).collect(),
            live: Mutex::new(BTreeMap::new()),
            written: Mutex::new(BTreeSet::new()),
            purged: AtomicUsize::new(0),
            purge_fails: AtomicBool::new(false),
        }
    }

    /// Clears the written marks of the range unless purging fails.
    fn zero(&self, offset: usize, len: usize) -> bool {
        if self.purge_fails.load(Ordering::Relaxed) {
            return false;
        }
        let mut w = self.written.lock().unwrap();
        let pages: Vec<_> = w
            .range(offset / PAGE_SIZE..(offset + len).div_ceil(PAGE_SIZE))
            .copied()
            .collect();
        for p in pages {
            w.remove(&p);
        }
        true
    }

    fn assert_no_live(&self, offset: usize, len: usize, what: &str) {
        let live = self.live.lock().unwrap();
        if let Some((&s, &e)) = live.range(..offset + len).next_back() {
            assert!(
                e <= offset,
                "{what} of {offset:#x}+{len:#x} overlaps live {s:#x}..{e:#x}"
            );
        }
    }
}

impl Os for MockOs {
    fn commit(&self, offset: usize, len: usize) -> bool {
        assert_eq!(offset % SEGMENT_SIZE, 0);
        for s in offset / SEGMENT_SIZE..(offset + len) / SEGMENT_SIZE {
            self.committed[s].store(true, Ordering::Relaxed);
        }
        true
    }
    fn decommit(&self, offset: usize, len: usize) -> bool {
        self.assert_no_live(offset, len, "decommit");
        for s in offset / SEGMENT_SIZE..(offset + len) / SEGMENT_SIZE {
            self.committed[s].store(false, Ordering::Relaxed);
        }
        self.purged.fetch_add(len, Ordering::Relaxed);
        self.zero(offset, len)
    }
    fn purge(&self, offset: usize, len: usize) -> bool {
        self.assert_no_live(offset, len, "purge");
        self.purged.fetch_add(len, Ordering::Relaxed);
        self.zero(offset, len)
    }
    fn commit_meta(&self, segment: usize) -> Option<&[AtomicU64]> {
        Some(self.meta[segment].get_or_init(|| {
            Box::leak(
                (0..META_WORDS)
                    .map(|_| AtomicU64::new(0))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            )
        }))
    }
    fn meta(&self, segment: usize) -> Option<&[AtomicU64]> {
        self.meta[segment].get().copied()
    }
    fn yield_now(&self) {
        std::thread::yield_now();
    }
    fn fatal(&self, msg: &'static str) -> ! {
        panic!("{msg}")
    }
}

fn heap() -> &'static Heap<MockOs> {
    Box::leak(Box::new(Heap::new(MockOs::new())))
}

/// Allocates and records the block in the shadow map, checking the
/// allocator's post-conditions.
fn alloc(h: &Heap<MockOs>, shard: usize, size: usize, align: usize) -> usize {
    alloc_block(h, shard, size, align).offset
}

/// As [`alloc`], returning the whole [`Block`]. The block is then treated as
/// written, like a program would.
fn alloc_block(h: &Heap<MockOs>, shard: usize, size: usize, align: usize) -> Block {
    let b = h.alloc_block(shard, size, align).expect("out of memory");
    let off = b.offset;
    {
        let mut w = h.os().written.lock().unwrap();
        let pages = off / PAGE_SIZE..(off + size.max(1)).div_ceil(PAGE_SIZE);
        if b.zeroed {
            let dirty = w.range(pages.clone()).next();
            assert!(
                dirty.is_none(),
                "{b:?} claims zero but page {dirty:?} was written"
            );
        }
        w.extend(pages);
    }
    assert_eq!(off % align, 0, "size {size} align {align} -> {off:#x}");
    assert!(off + size <= ARENA_SIZE);
    let usable = h.usable_size(off);
    assert!(usable >= size, "usable {usable} < {size}");
    let end = off + size.max(1);
    for s in off / SEGMENT_SIZE..end.div_ceil(SEGMENT_SIZE) {
        assert!(
            h.os().committed[s].load(Ordering::Relaxed),
            "segment {s} not committed"
        );
    }
    let mut live = h.os().live.lock().unwrap();
    if let Some((&s, &e)) = live.range(..end).next_back() {
        assert!(
            e <= off,
            "new {off:#x}..{end:#x} overlaps live {s:#x}..{e:#x}"
        );
    }
    live.insert(off, end);
    b
}

/// Resizes in place, updating the shadow maps and checking that a grown
/// block stays committed and overlaps nothing.
fn resize(h: &Heap<MockOs>, off: usize, new_size: usize) -> bool {
    // While shrinking, only the first `new_size` bytes must stay intact.
    let old_end = h.os().live.lock().unwrap()[&off];
    h.os()
        .live
        .lock()
        .unwrap()
        .insert(off, old_end.min(off + new_size));
    if !h.resize_in_place(off, new_size) {
        h.os().live.lock().unwrap().insert(off, old_end);
        return false;
    }
    assert!(h.usable_size(off) >= new_size);
    let end = off + new_size;
    for s in off / SEGMENT_SIZE..end.div_ceil(SEGMENT_SIZE) {
        assert!(
            h.os().committed[s].load(Ordering::Relaxed),
            "segment {s} not committed"
        );
    }
    let mut live = h.os().live.lock().unwrap();
    live.remove(&off);
    if let Some((&s, &e)) = live.range(..end).next_back() {
        assert!(
            e <= off,
            "resized {off:#x}..{end:#x} overlaps live {s:#x}..{e:#x}"
        );
    }
    live.insert(off, end);
    h.os()
        .written
        .lock()
        .unwrap()
        .extend(off / PAGE_SIZE..end.div_ceil(PAGE_SIZE));
    true
}

fn free(h: &Heap<MockOs>, off: usize) {
    h.os().live.lock().unwrap().remove(&off);
    h.dealloc(off);
}

const SIZES: &[usize] = &[
    1,
    8,
    16,
    17,
    24,
    100,
    128,
    129,
    500,
    1000,
    4096,
    8192,
    8193,
    20_000,
    40_000,
    65_536,
    100_000,
    200_000,
    262_144,
    262_145,
    300_000,
    1 << 21,
    (1 << 22) - 1,
    1 << 22,
    (1 << 22) + 1,
    10 << 20,
];

#[test]
fn every_size_round_trips() {
    let h = heap();
    for &size in SIZES {
        let offs: Vec<_> = (0..if size > PAGE_SIZE { 3 } else { 200 })
            .map(|_| alloc(h, 0, size, 8))
            .collect();
        for o in offs {
            free(h, o);
        }
    }
}

#[test]
fn alignments() {
    let h = heap();
    let mut offs = Vec::new();
    for shift in 0..=22 {
        let align = 1usize << shift;
        for &size in &[1, 24, align, align + 1, 3 * align] {
            offs.push(alloc(h, 1, size, align));
        }
    }
    for o in offs {
        free(h, o);
    }
    assert!(h.alloc(0, 8, 1 << 23).is_none());
    assert!(h.alloc(0, 8, 3).is_none());
}

#[test]
fn freed_small_blocks_are_reused() {
    let h = heap();
    let a = alloc(h, 0, 32, 8);
    free(h, a);
    // Churn through a full page worth of blocks; the freed slot must come back.
    let offs: Vec<_> = (0..PAGE_SIZE / 32 + 1)
        .map(|_| alloc(h, 0, 32, 8))
        .collect();
    assert!(offs.contains(&a));
    for o in offs {
        free(h, o);
    }
}

#[test]
fn huge_segments_are_returned() {
    let h = heap();
    let base = h.segments_in_use();
    let a = alloc(h, 0, 20 << 20, 8);
    assert_eq!(h.segments_in_use(), base + 5);
    free(h, a);
    assert_eq!(h.segments_in_use(), base);
}

#[test]
fn empty_pages_are_recycled_across_classes() {
    let h = heap();
    // Fill several pages of one class, free everything, then allocate a
    // different class: its pages must come from the recycled ones rather
    // than a new segment.
    let offs: Vec<_> = (0..PAGE_SIZE / 64 * 8)
        .map(|_| alloc(h, 3, 64, 8))
        .collect();
    let segs = h.segments_in_use();
    for o in offs {
        free(h, o);
    }
    let _ = alloc(h, 3, 64, 8); // triggers the scan that recycles empty pages
    let more: Vec<_> = (0..PAGE_SIZE / 1024 * 6)
        .map(|_| alloc(h, 3, 1024, 8))
        .collect();
    assert_eq!(h.segments_in_use(), segs);
    for o in more {
        free(h, o);
    }
}

#[test]
fn purging_is_deferred_until_budget() {
    let h = heap();
    const RUN: usize = 5;
    let n = crate::heap::DIRTY_BUDGET_PAGES as usize / 4 + 8;
    let big: Vec<_> = (0..n).map(|_| alloc(h, 0, RUN * PAGE_SIZE, 8)).collect();
    // The newest segment is searched first, so free runs from it.
    let (rest, last) = big.split_at(n - 4);
    for &o in last {
        free(h, o);
    }
    assert_eq!(
        h.os().purged.load(Ordering::Relaxed),
        0,
        "small frees must not purge"
    );
    assert_eq!(h.dirty_pages(), 4 * RUN);
    // Dirty pages are reused without a purge.
    let again: Vec<_> = (0..4).map(|_| alloc(h, 0, RUN * PAGE_SIZE, 8)).collect();
    assert_eq!(h.dirty_pages(), 0);
    for &o in rest.iter().chain(&again) {
        free(h, o);
    }
    // Crossing the budget purged everything that was dirty at that point
    // (or returned whole empty segments).
    assert!(
        h.os().purged.load(Ordering::Relaxed)
            >= crate::heap::DIRTY_BUDGET_PAGES as usize * PAGE_SIZE
    );
    h.purge();
    assert_eq!(h.dirty_pages(), 0);
}

#[test]
#[should_panic(expected = "double free")]
fn double_free_small() {
    let h = heap();
    let a = h.alloc(0, 48, 8).unwrap();
    let _b = h.alloc(0, 48, 8).unwrap();
    h.dealloc(a);
    h.dealloc(a);
}

#[test]
#[should_panic(expected = "double free")]
fn double_free_large() {
    let h = heap();
    let a = h.alloc(0, 300_000, 8).unwrap();
    h.dealloc(a);
    h.dealloc(a);
}

#[test]
#[should_panic(expected = "invalid or double free")]
fn interior_pointer_free() {
    let h = heap();
    let a = h.alloc(0, 300_000, 8).unwrap();
    h.dealloc(a + PAGE_SIZE);
}

#[test]
#[should_panic(expected = "misaligned")]
fn misaligned_small_free() {
    let h = heap();
    let a = h.alloc(0, 64, 8).unwrap();
    h.dealloc(a + 8);
}

#[test]
fn cross_thread_frees() {
    let h = heap();
    let threads = if cfg!(miri) { 2 } else { 8 };
    let rounds = if cfg!(miri) { 50 } else { 20_000 };
    let (tx, rx) = std::sync::mpsc::channel::<Vec<usize>>();
    let rx = std::sync::Arc::new(Mutex::new(rx));
    let done = AtomicBool::new(false);
    std::thread::scope(|sc| {
        // Purge passes (and segment trimming) race the allocating threads.
        let done = &done;
        sc.spawn(move || {
            while !done.load(Ordering::Relaxed) {
                h.purge();
                std::thread::yield_now();
            }
        });
        let mut workers = Vec::new();
        for t in 0..threads {
            let tx = tx.clone();
            let rx = rx.clone();
            workers.push(sc.spawn(move || {
                let mut batch = Vec::new();
                for i in 0..rounds {
                    let size = SIZES[(i * 7 + t) % 12];
                    batch.push(alloc(h, t, size, 8));
                    if batch.len() == 32 {
                        tx.send(std::mem::take(&mut batch)).unwrap();
                        // Free a batch produced by (probably) another thread.
                        let theirs = rx.lock().unwrap().try_recv();
                        if let Ok(v) = theirs {
                            for o in v {
                                free(h, o);
                            }
                        }
                    }
                }
                for o in batch {
                    free(h, o);
                }
            }));
        }
        for w in workers {
            w.join().unwrap();
        }
        done.store(true, Ordering::Relaxed);
    });
    drop(tx);
    for v in rx.lock().unwrap().iter() {
        for o in v {
            free(h, o);
        }
    }
    assert!(h.os().live.lock().unwrap().is_empty());
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(if cfg!(miri) { 2 } else { 64 }))]
    #[test]
    fn random_sequences(ops in proptest::collection::vec((0usize..40_000, 0u32..8, 0u8..3), 1..300)) {
        let h = heap();
        let mut live = Vec::new();
        for (size, align_shift, op) in ops {
            if op == 1 && !live.is_empty() {
                let o = live.swap_remove(size % live.len());
                free(h, o);
            } else if op == 2 && !live.is_empty() {
                // Resize a live block to a size spanning all block kinds.
                let o = live[size % live.len()];
                let new_size = size * (1 << (align_shift * 2)) / 4 + 1;
                resize(h, o, new_size);
            } else {
                live.push(alloc(h, size % 3, size, 1 << (align_shift * 2)));
            }
        }
        for o in live {
            free(h, o);
        }
    }
}

#[test]
fn zeroed_blocks_are_reported() {
    let h = heap();
    // Fresh memory reads as zero.
    let big = alloc_block(h, 0, 10 << 20, 8);
    assert!(big.zeroed);
    let run = alloc_block(h, 0, 5 * PAGE_SIZE, 8);
    assert!(run.zeroed);
    // Class blocks are recycled without tracking, so never claimed zero.
    let small = alloc_block(h, 0, 64, 8);
    assert!(!small.zeroed);
    free(h, run.offset);
    // Dirty pages are reused as they are: not zero.
    let again = alloc_block(h, 0, 5 * PAGE_SIZE, 8);
    assert_eq!(again.offset, run.offset);
    assert!(!again.zeroed);
    free(h, again.offset);
    h.purge();
    assert!(alloc_block(h, 0, 5 * PAGE_SIZE, 8).zeroed);
    // Huge segments are decommitted on free, so they come back zeroed.
    free(h, big.offset);
    assert!(alloc_block(h, 0, 10 << 20, 8).zeroed);
}

#[test]
fn failed_purges_are_not_zeroed() {
    let h = heap();
    h.os().purge_fails.store(true, Ordering::Relaxed);
    let big = alloc(h, 0, 10 << 20, 8);
    free(h, big);
    let huge = alloc_block(h, 0, 10 << 20, 8);
    assert!(!huge.zeroed);
    let run = alloc(h, 0, 5 * PAGE_SIZE, 8);
    free(h, run);
    h.purge();
    // The pages stay dirty and are reported as such.
    assert_eq!(h.dirty_pages(), 5);
    let again = alloc_block(h, 0, 5 * PAGE_SIZE, 8);
    assert_eq!(again.offset, run);
    assert!(!again.zeroed);
    // A segment whose decommit failed starts fully dirty when a shard takes
    // it (first fit picks the lowest segment, freed here).
    assert_eq!(huge.offset, 0);
    free(h, huge.offset);
    let owned = alloc_block(h, 1, 5 * PAGE_SIZE, 8);
    assert!(owned.offset < SEGMENT_SIZE && !owned.zeroed);
    assert_eq!(h.dirty_pages(), 64 - 5);
    // Once purging works again, the pages are clean and reported zeroed.
    h.os().purge_fails.store(false, Ordering::Relaxed);
    h.purge();
    assert_eq!(h.dirty_pages(), 0);
    assert!(alloc_block(h, 1, 5 * PAGE_SIZE, 8).zeroed);
}

#[test]
fn page_aligned_runs_stay_inside_segments() {
    let h = heap();
    let base = h.segments_in_use();
    // Up to segment alignment, over-aligned blocks are page runs placed at an
    // aligned page, not whole segments.
    let offs: Vec<_> = [17, 18, 19, 20, 21]
        .iter()
        .map(|&shift| {
            let o = alloc(h, 0, 100, 1 << shift);
            assert_eq!(h.usable_size(o), PAGE_SIZE);
            o
        })
        .collect();
    assert_eq!(h.segments_in_use(), base + 1);
    let whole = alloc(h, 0, SEGMENT_SIZE, SEGMENT_SIZE);
    assert_eq!(h.usable_size(whole), SEGMENT_SIZE);
    for o in offs.into_iter().chain([whole]) {
        free(h, o);
    }
}

#[test]
fn aligned_requests_use_the_tightest_class() {
    let h = heap();
    // 5120 is a multiple of 32, so it serves 5000 bytes aligned to 32
    // (rounding to a power of two would take 8192).
    let a = alloc(h, 0, 5000, 32);
    assert_eq!(h.usable_size(a), 5120);
    let b = alloc(h, 0, 3000, 1024);
    assert_eq!(h.usable_size(b), 3072);
    free(h, a);
    free(h, b);
}

#[test]
fn empty_segments_are_returned() {
    let h = heap();
    let base = h.segments_in_use();
    // Twelve five-page runs per segment: 60 runs fill five segments.
    let runs: Vec<_> = (0..60).map(|_| alloc(h, 4, 5 * PAGE_SIZE, 8)).collect();
    assert_eq!(h.segments_in_use(), base + 5);
    for o in runs {
        free(h, o);
    }
    h.purge();
    // One empty segment stays with the shard as a cache.
    assert_eq!(h.segments_in_use(), base + 1);
    assert_eq!(h.dirty_pages(), 0);
    // Returned segments are reused, by shards and by huge blocks alike.
    let big = alloc_block(h, 0, 12 << 20, 8);
    assert!(big.zeroed);
    let again: Vec<_> = (0..24).map(|_| alloc(h, 4, 5 * PAGE_SIZE, 8)).collect();
    assert_eq!(h.segments_in_use(), base + 1 + 3 + 1);
    for o in again.into_iter().chain([big.offset]) {
        free(h, o);
    }
    h.purge();
    assert_eq!(h.segments_in_use(), base + 1);
}

#[test]
fn resizing_in_place() {
    let h = heap();
    // Class blocks stay while the new size uses at least half of them.
    let small = alloc(h, 5, 64, 8);
    assert!(resize(h, small, 40));
    assert!(!resize(h, small, 16));
    assert!(!resize(h, small, 65));
    free(h, small);

    // A page run at the end of what its segment uses grows into free pages.
    let run = alloc(h, 6, 5 * PAGE_SIZE, 8);
    assert!(resize(h, run, 8 * PAGE_SIZE - 1));
    assert_eq!(h.usable_size(run), 8 * PAGE_SIZE);
    // Once a neighbour follows it, it cannot.
    let next = alloc(h, 6, 5 * PAGE_SIZE, 8);
    assert_eq!(next, run + 8 * PAGE_SIZE);
    assert!(!resize(h, run, 9 * PAGE_SIZE));
    // Shrinking hands the tail back as dirty pages, which are then reused.
    let dirty = h.dirty_pages();
    assert!(resize(h, run, 6 * PAGE_SIZE));
    assert_eq!(h.usable_size(run), 6 * PAGE_SIZE);
    assert_eq!(h.dirty_pages(), dirty + 2);
    // Down to class sizes it moves instead.
    assert!(!resize(h, run, 1000));
    free(h, run);
    free(h, next);

    // Huge blocks grow into free segments and give back their tail.
    let base = h.segments_in_use();
    let huge = alloc(h, 0, 5 << 20, 8);
    assert_eq!(h.segments_in_use(), base + 2);
    assert!(resize(h, huge, 11 << 20));
    assert_eq!(h.usable_size(huge), 3 * SEGMENT_SIZE);
    assert_eq!(h.segments_in_use(), base + 3);
    assert!(resize(h, huge, 5 << 20));
    assert_eq!(h.segments_in_use(), base + 2);
    assert!(!resize(h, huge, 1 << 20));
    // A block right after it stops growth.
    let wall = alloc(h, 0, 5 << 20, 8);
    assert_eq!(wall, huge + 2 * SEGMENT_SIZE);
    assert!(!resize(h, huge, 9 << 20));
    free(h, huge);
    free(h, wall);
    assert_eq!(h.segments_in_use(), base);
}

#[test]
#[should_panic(expected = "realloc of a pointer that is not allocated")]
fn resize_of_freed_block() {
    let h = heap();
    let a = h.alloc(0, 300_000, 8).unwrap();
    h.dealloc(a);
    h.resize_in_place(a, 400_000);
}
