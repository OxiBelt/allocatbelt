//! Model tests: the heap runs on a mock [`Os`] that never backs user memory
//! but checks the heap's promises (offsets are committed, purged ranges hold
//! no live allocation) against a shadow map of live allocations.

use std::boxed::Box;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

use crate::{ARENA_SIZE, Heap, MAX_SEGMENTS, META_WORDS, Os, PAGE_SIZE, SEGMENT_SIZE};

struct MockOs {
    meta: Vec<OnceLock<&'static [AtomicU64]>>,
    committed: Vec<AtomicBool>,
    live: Mutex<BTreeMap<usize, usize>>,
    purged: AtomicUsize,
}

impl MockOs {
    fn new() -> Self {
        Self {
            meta: (0..MAX_SEGMENTS).map(|_| OnceLock::new()).collect(),
            committed: (0..MAX_SEGMENTS).map(|_| AtomicBool::new(false)).collect(),
            live: Mutex::new(BTreeMap::new()),
            purged: AtomicUsize::new(0),
        }
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
    fn decommit(&self, offset: usize, len: usize) {
        self.assert_no_live(offset, len, "decommit");
        for s in offset / SEGMENT_SIZE..(offset + len) / SEGMENT_SIZE {
            self.committed[s].store(false, Ordering::Relaxed);
        }
    }
    fn purge(&self, offset: usize, len: usize) {
        self.assert_no_live(offset, len, "purge");
        self.purged.fetch_add(len, Ordering::Relaxed);
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
    let off = h.alloc(shard, size, align).expect("out of memory");
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
    off
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
    65_536,
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
    let n = crate::heap::DIRTY_BUDGET_PAGES as usize / 4 + 8;
    let big: Vec<_> = (0..n).map(|_| alloc(h, 0, 4 * PAGE_SIZE, 8)).collect();
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
    assert_eq!(h.dirty_pages(), 16);
    // Dirty pages are reused without a purge.
    let again: Vec<_> = (0..4).map(|_| alloc(h, 0, 4 * PAGE_SIZE, 8)).collect();
    assert_eq!(h.dirty_pages(), 0);
    for &o in rest.iter().chain(&again) {
        free(h, o);
    }
    // Crossing the budget purged everything that was dirty at that point.
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
    let a = h.alloc(0, 100_000, 8).unwrap();
    h.dealloc(a);
    h.dealloc(a);
}

#[test]
#[should_panic(expected = "invalid or double free")]
fn interior_pointer_free() {
    let h = heap();
    let a = h.alloc(0, 200_000, 8).unwrap();
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
    std::thread::scope(|sc| {
        for t in 0..threads {
            let tx = tx.clone();
            let rx = rx.clone();
            sc.spawn(move || {
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
            });
        }
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
    fn random_sequences(ops in proptest::collection::vec((0usize..40_000, 0u32..8, proptest::bool::ANY), 1..300)) {
        let h = heap();
        let mut live = Vec::new();
        for (size, align_shift, do_free) in ops {
            if do_free && !live.is_empty() {
                let o = live.swap_remove(size % live.len());
                free(h, o);
            } else {
                live.push(alloc(h, size % 3, size, 1 << (align_shift * 2)));
            }
        }
        for o in live {
            free(h, o);
        }
    }
}
