//! Model tests: the heap runs on the checking [`MockOs`] of
//! [`crate::core::model`], which never backs user memory but checks the heap's
//! promises against shadow maps.

use std::boxed::Box;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::vec::Vec;

use crate::core::heap::DIRTY_BUDGET_PAGES;
use crate::core::heap::MAX_RUN_PAGES;
use crate::core::heap::Os;
use crate::core::model::{
  MockOs, MockPurger, alloc, alloc_block, alloc_c, cache, free, free_c, resize,
};
use crate::core::{
  Block, DIRTY_HARD_LIMIT_PAGES, Heap, PAGE_SIZE, PURGE_BATCH, SEGMENT_SIZE, Task, ThreadCache,
};

// Keep intentional mock heaps reachable so Miri can still report other leaks.
#[cfg(miri)]
static MIRI_HEAP_ROOTS: Mutex<Vec<&'static Heap<MockOs>>> = Mutex::new(Vec::new());

fn heap() -> &'static Heap<MockOs> {
  let heap = Box::leak(Box::new(Heap::new(MockOs::new())));
  #[cfg(miri)]
  MIRI_HEAP_ROOTS.lock().unwrap().push(heap);
  heap
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
    let count = if cfg!(miri) || size > PAGE_SIZE {
      3
    } else {
      200
    };
    let offs: Vec<_> = (0..count).map(|_| alloc(h, 0, size, 8)).collect();
    if cfg!(miri) {
      assert_eq!(offs.iter().copied().collect::<BTreeSet<_>>().len(), count);
    }
    for o in offs {
      free(h, o);
    }
    if cfg!(miri) {
      assert!(h.os().live.lock().unwrap().is_empty(), "size {size}");
      let usage = h.usage();
      assert_eq!(usage.small_bytes_out, 0, "size {size}: {usage:?}");
      h.check_indexes();
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
  // The native stress path keeps its original request size and count. Under
  // Miri, 512-byte blocks still occupy two bitmap words per 64 KiB page but
  // reach the reuse check with 129 allocations instead of 2,049 tiny ones.
  let size = if cfg!(miri) { 512 } else { 32 };
  assert!(size <= crate::core::class::SMALL_MAX);
  let blocks_per_page = PAGE_SIZE / size;
  let allocation_count = if cfg!(miri) {
    blocks_per_page + 1
  } else {
    PAGE_SIZE / 32 + 1
  };
  assert!(allocation_count <= PAGE_SIZE / 32 + 1);
  if cfg!(miri) {
    assert_eq!(blocks_per_page, 128);
    assert_eq!(allocation_count, 129);
  }
  let a = alloc(h, 0, size, 8);
  free(h, a);
  // Churn past a full page worth of blocks; the freed slot must come back.
  let offs: Vec<_> = (0..allocation_count)
    .map(|_| alloc(h, 0, size, 8))
    .collect();
  assert!(offs.contains(&a));
  let unique_offsets: BTreeSet<_> = offs.iter().copied().collect();
  assert_eq!(unique_offsets.len(), allocation_count);

  if cfg!(miri) {
    let pages: BTreeSet<_> = offs.iter().map(|offset| offset / PAGE_SIZE).collect();
    assert_eq!(pages.len(), 2);
    let mut occupancy: Vec<_> = pages
      .iter()
      .map(|page| {
        offs
          .iter()
          .filter(|offset| **offset / PAGE_SIZE == *page)
          .count()
      })
      .collect();
    occupancy.sort_unstable();
    assert_eq!(occupancy, [1, blocks_per_page]);

    let full_page = pages
      .iter()
      .copied()
      .find(|page| {
        offs
          .iter()
          .filter(|offset| **offset / PAGE_SIZE == *page)
          .count()
          == blocks_per_page
      })
      .unwrap();
    let full_page_words: BTreeSet<_> = offs
      .iter()
      .filter(|offset| **offset / PAGE_SIZE == full_page)
      .map(|offset| offset % PAGE_SIZE / (64 * size))
      .collect();
    assert_eq!(full_page_words, BTreeSet::from([0, 1]));
  }

  h.check_indexes();
  for o in offs {
    free(h, o);
  }
  assert!(h.os().live.lock().unwrap().is_empty());
  h.check_indexes();
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
  // Miri retains eight completely filled source pages and six destination
  // pages of a different class, with the same kept-newest exclusion. Larger
  // small classes avoid repeating 8,192 tiny allocations under interpretation;
  // the separate multiword fixture covers bitmap-word boundaries.
  let source_size = if cfg!(miri) { 8192 } else { 64 };
  let destination_size = if cfg!(miri) { 4096 } else { 1024 };
  assert!(source_size <= crate::core::class::SMALL_MAX);
  assert!(destination_size <= crate::core::class::SMALL_MAX);
  assert_ne!(
    crate::core::class::class_of(source_size),
    crate::core::class::class_of(destination_size)
  );
  let offs: Vec<_> = (0..PAGE_SIZE / source_size * 8)
    .map(|_| alloc(h, 3, source_size, 8))
    .collect();
  let source_pages: BTreeSet<_> = offs.iter().map(|offset| offset / PAGE_SIZE).collect();
  assert_eq!(source_pages.len(), 8);
  let kept_newest_page = offs.last().copied().expect("eight full source pages") / PAGE_SIZE;
  let segs = h.segments_in_use();
  for o in offs {
    free(h, o);
  }
  // Explicitly recycle candidates: merely reusing the source class can find
  // a free block before any trim, so unchanged segment count alone would also
  // pass if the next class used previously untouched pages of the segment.
  h.purge();
  assert_eq!(h.maintenance_stats().released_pages, 7);
  let trigger = alloc(h, 3, source_size, 8);
  let more: Vec<_> = (0..PAGE_SIZE / destination_size * 6)
    .map(|_| alloc(h, 3, destination_size, 8))
    .collect();
  let destination_pages: BTreeSet<_> = more.iter().map(|offset| offset / PAGE_SIZE).collect();
  assert_eq!(destination_pages.len(), 6);
  assert!(destination_pages.is_subset(&source_pages));
  assert!(!destination_pages.contains(&kept_newest_page));
  assert!(!destination_pages.contains(&(trigger / PAGE_SIZE)));
  assert_eq!(h.segments_in_use(), segs);
  for o in more {
    free(h, o);
  }
}

#[test]
fn purging_is_deferred_until_budget() {
  let h = heap();
  const RUN: usize = 5;
  let n = crate::core::heap::DIRTY_BUDGET_PAGES as usize / 4 + 8;
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
      >= crate::core::heap::DIRTY_BUDGET_PAGES as usize * PAGE_SIZE
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

/// Sets the flag when dropped.
struct SetOnDrop<'a>(&'a AtomicBool);

impl Drop for SetOnDrop<'_> {
  fn drop(&mut self) {
    self.0.store(true, Ordering::Relaxed);
  }
}

/// Decrements a live worker-batch count without panicking during unwind.
struct ActiveCountOnDrop<'a>(&'a AtomicUsize);

impl Drop for ActiveCountOnDrop<'_> {
  fn drop(&mut self) {
    self.0.fetch_sub(1, Ordering::SeqCst);
  }
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
    // Stops the purger even when a worker panics, so a failure ends the
    // test instead of leaving the scope waiting on the purge loop.
    let _stop = SetOnDrop(done);
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
  // (All pages but the guard page start dirty.)
  assert_eq!(h.dirty_pages(), MAX_RUN_PAGES - 5);
  // Once purging works again, the pages are clean and reported zeroed.
  h.os().purge_fails.store(false, Ordering::Relaxed);
  h.purge();
  assert_eq!(h.dirty_pages(), 0);
  assert!(alloc_block(h, 1, 5 * PAGE_SIZE, 8).zeroed);
}

/// Free pages are taken first fit by position, whatever their history: a
/// page that was used and freed (and still holds its bytes) is not
/// preferred to one that was never handed out, nor the other way round.
#[test]
fn free_page_choice_ignores_page_history() {
  let h = heap();
  let first = alloc(h, 0, PAGE_SIZE, 8);
  assert_eq!(first % SEGMENT_SIZE, 0);
  // Pages 1 to 3 are skipped by the alignment and never handed out.
  let used = alloc(h, 0, PAGE_SIZE, 4 * PAGE_SIZE);
  assert_eq!(used, first + 4 * PAGE_SIZE);
  free(h, used);
  assert_eq!(h.dirty_pages(), 1);
  // The never-used page 1 comes first; the freed page 4 waits its turn.
  let next = alloc_block(h, 0, PAGE_SIZE, 8);
  assert_eq!(next.offset, first + PAGE_SIZE);
  assert!(next.zeroed);
  assert_eq!(h.dirty_pages(), 1);
  // A purged page is taken where it lies too, before later dirty ones.
  let (a, b) = (alloc(h, 0, PAGE_SIZE, 8), alloc(h, 0, PAGE_SIZE, 8));
  assert_eq!((a, b), (first + 2 * PAGE_SIZE, first + 3 * PAGE_SIZE));
  free(h, a);
  h.purge();
  free(h, b);
  let again = alloc_block(h, 0, PAGE_SIZE, 8);
  assert_eq!(again.offset, a);
  assert!(again.zeroed);
  for o in [first, next.offset, again.offset] {
    free(h, o);
  }
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
  // An explicit purge returns them right away, but for one that stays with
  // the shard as a cache.
  h.purge();
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

#[test]
fn freed_small_pages_leave_their_segments() {
  let h = heap();
  let base = h.segments_in_use();
  // Enough 16-byte blocks for three segments (all pages but the guard
  // pages), then free them all. Under Miri the same three-segment topology
  // uses the largest small class, avoiding hundreds of thousands of tiny
  // modeled allocations while preserving every page and trim transition.
  let size = if cfg!(miri) { 8192 } else { 16 };
  let n = 3 * MAX_RUN_PAGES * PAGE_SIZE / size;
  let offs: Vec<_> = (0..n).map(|_| h.alloc(6, size, 8).unwrap()).collect();
  assert_eq!(h.segments_in_use(), base + 3);
  // Keep the last block so its page stays behind. It is on the class's
  // newest page, which trimming keeps anyway.
  let last = offs[n - 1];
  for &o in &offs[..n - 1] {
    h.dealloc(o);
  }
  // Pages go back on the first pass, segments on the second. What stays:
  // the survivor's segment and one empty segment the shard keeps.
  h.purge();
  h.purge();
  assert_eq!(h.segments_in_use(), base + 2);
  // The survivor is intact and the class keeps working.
  assert_eq!(h.usable_size(last), size);
  // The reuse phase checks that the retained class still allocates. Miri
  // uses two pages rather than adding another thousand large-class calls;
  // the native stress count remains unchanged. Multiword small-class claims
  // are checked separately below.
  let reuse_count = if cfg!(miri) { 16 } else { 1000 };
  let again: Vec<_> = (0..reuse_count)
    .map(|_| h.alloc(6, size, 8).unwrap())
    .collect();
  for o in again.into_iter().chain([last]) {
    h.dealloc(o);
  }
}

// ---- thread caches and page search ------------------------------------------

#[test]
fn cached_round_trip_and_reuse() {
  let h = heap();
  let tc = cache(h);
  let offs: Vec<_> = (0..500).map(|i| alloc_c(h, &tc, 16 + i % 200, 8)).collect();
  for &o in &offs {
    free_c(h, &tc, o);
  }
  // Buffered frees are returned before the next claim of their class, so
  // the same memory comes back instead of new pages.
  let segs = h.segments_in_use();
  let again: Vec<_> = (0..500).map(|i| alloc_c(h, &tc, 16 + i % 200, 8)).collect();
  assert_eq!(h.segments_in_use(), segs);
  for o in again {
    free_c(h, &tc, o);
  }
  h.retire(&tc);
  // Once everything is returned, a purge pass releases every small page.
  h.purge();
  h.purge();
  assert_eq!(h.dirty_pages(), 0);
}

#[test]
fn caches_free_each_others_blocks() {
  let h = heap();
  let (a, b) = (cache(h), cache(h));
  if cfg!(miri) {
    let max_class = crate::core::class::class_of(3007);
    let mut bounds = Vec::new();
    bounds.resize(max_class + 1, (None, None));
    for size in 8..=3007 {
      let c = crate::core::class::class_of(size);
      let bound = &mut bounds[c];
      if bound.0.is_none() {
        bound.0 = Some(size);
      }
      bound.1 = Some(size);
    }
    let represented: BTreeSet<_> = (8..=3007).map(crate::core::class::class_of).collect();
    assert_eq!(represented, (0..=max_class).collect());

    // Keep one request from every size class in the native request range,
    // including its endpoints in the first and last classes. Then extend the
    // smallest class across three bitmap words and add 70 full pages of the
    // largest small class. Those pages provide more than 64 distinct free
    // keys and exercise free-buffer evictions without repeating all 3,000
    // native requests. The class-31 helper is additional topology, not part
    // of the native request distribution.
    let mut requests = Vec::new();
    for (c, bound) in bounds.iter().enumerate() {
      let (Some(lower), Some(upper)) = *bound else {
        panic!("represented class {c} has no request bound");
      };
      requests.push(if c == max_class { upper } else { lower });
    }
    assert_eq!(crate::core::class::class_of(requests[0]), 0);
    assert_eq!(requests[0], 8);
    assert!(requests.contains(&3007));

    let class_zero = crate::core::class::class_of(8);
    let class_zero_count = 129;
    requests.extend(core::iter::repeat_n(8, class_zero_count - 1));
    assert_eq!(
      requests
        .iter()
        .filter(|&&size| crate::core::class::class_of(size) == class_zero)
        .count(),
      class_zero_count
    );

    let helper_class = crate::core::class::NUM_CLASSES - 1;
    let helper_size = crate::core::class::size(helper_class);
    let helper_pages = 70;
    let helper_blocks = helper_pages * crate::core::class::capacity(helper_class);
    assert_eq!(crate::core::class::class_of(helper_size), helper_class);
    requests.extend(core::iter::repeat_n(helper_size, helper_blocks));
    assert_eq!(requests.len(), 714);

    let from_a: Vec<_> = requests
      .iter()
      .map(|&size| alloc_c(h, &a, size, 8))
      .collect();
    let offsets: BTreeSet<_> = from_a.iter().copied().collect();
    assert_eq!(
      offsets.len(),
      from_a.len(),
      "live allocations must be unique"
    );
    assert!(h.usage().small_bytes_out > 0);

    let pages: BTreeSet<_> = from_a.iter().map(|offset| offset / PAGE_SIZE).collect();
    assert_eq!(pages.len(), represented.len() + helper_pages);
    assert_eq!(h.segments_in_use(), 2);

    let mut keys = BTreeSet::new();
    let mut keys_by_set: Vec<BTreeSet<_>> = (0..32).map(|_| BTreeSet::new()).collect();
    for (&offset, &size) in from_a.iter().zip(&requests) {
      let c = crate::core::class::class_of(size);
      let page = offset / PAGE_SIZE;
      let word = offset % PAGE_SIZE / (64 * crate::core::class::size(c));
      let key = (page, word, c);
      keys.insert(key);
      let set = Heap::<MockOs>::free_set_of(offset, c);
      keys_by_set[set].insert(key);
    }
    let mut expected_classes = represented.clone();
    expected_classes.insert(helper_class);
    assert_eq!(
      keys.iter().map(|key| key.2).collect::<BTreeSet<_>>(),
      expected_classes
    );
    assert!(keys.len() > 64, "{} keys: {keys:?}", keys.len());
    assert!(
      keys.len() >= represented.len() + helper_pages + 2,
      "{keys:?}"
    );
    assert!(
      keys_by_set.iter().any(|set| set.len() >= 3),
      "the fixture should observe three distinct keys in one set: {keys_by_set:?}"
    );

    for &o in &from_a {
      free_c(h, &b, o);
    }
    let buffered = h.cache_stats(&b);
    assert!(buffered.evictions > 0, "{buffered:?}");
    assert_eq!(
      buffered.flushed_blocks + buffered.buffered_blocks,
      from_a.len() as u64
    );
    h.flush(&b);
    let flushed = h.cache_stats(&b);
    assert_eq!((flushed.buffered_blocks, flushed.buffered_words), (0, 0));
    Heap::<MockOs>::check_free_buffer(&b);
    for c in 0..crate::core::class::NUM_CLASSES {
      assert_eq!(Heap::<MockOs>::pending_slots(&b, c), 0);
    }

    // Every block freed through `b` is available to `a` again. Use the exact
    // same request multiset, and ensure no new segment was needed.
    let before = h.segments_in_use();
    let again: Vec<_> = requests
      .iter()
      .map(|&size| alloc_c(h, &a, size, 8))
      .collect();
    assert_eq!(h.segments_in_use(), before);
    assert_eq!(
      again.iter().copied().collect::<BTreeSet<_>>().len(),
      again.len()
    );
    for o in again {
      free_c(h, &a, o);
    }
    h.retire(&a);
    h.retire(&b);
    let (a_stats, b_stats) = (h.cache_stats(&a), h.cache_stats(&b));
    assert_eq!((a_stats.claimed_blocks, a_stats.buffered_blocks), (0, 0));
    assert_eq!((b_stats.claimed_blocks, b_stats.buffered_blocks), (0, 0));
    Heap::<MockOs>::check_free_buffer(&a);
    Heap::<MockOs>::check_free_buffer(&b);
    for c in 0..crate::core::class::NUM_CLASSES {
      assert_eq!(Heap::<MockOs>::pending_slots(&a, c), 0);
      assert_eq!(Heap::<MockOs>::pending_slots(&b, c), 0);
    }
    assert_eq!(h.usage().small_bytes_out, 0);
    h.check_indexes();
  } else {
    let from_a: Vec<_> = (0..3000).map(|i| alloc_c(h, &a, 8 + i % 3000, 8)).collect();
    for &o in &from_a {
      free_c(h, &b, o);
    }
    h.flush(&b);
    // Every block freed through `b` is available to `a` again.
    let before = h.segments_in_use();
    let again: Vec<_> = (0..3000).map(|i| alloc_c(h, &a, 8 + i % 3000, 8)).collect();
    assert_eq!(h.segments_in_use(), before);
    for o in again {
      free_c(h, &a, o);
    }
    h.retire(&a);
    h.retire(&b);
  }
}

#[test]
fn detached_and_retired_caches_are_bypassed() {
  let h = heap();
  let tc = ThreadCache::new();
  assert!(tc.is_detached());
  let o = alloc_c(h, &tc, 64, 8);
  free_c(h, &tc, o);
  let tc = cache(h);
  let o = alloc_c(h, &tc, 64, 8);
  h.retire(&tc);
  free_c(h, &tc, o);
  // Retired caches stay retired.
  h.attach(&tc);
  let o = alloc_c(h, &tc, 64, 8);
  free_c(h, &tc, o);
  h.flush(&tc);
}

#[test]
#[should_panic(expected = "double free")]
fn double_free_in_buffer() {
  let h = heap();
  let tc = cache(h);
  let a = h.alloc_cached(&tc, 48, 8).unwrap().offset;
  let _b = h.alloc_cached(&tc, 48, 8).unwrap();
  h.dealloc_cached(&tc, a);
  h.dealloc_cached(&tc, a);
}

#[test]
#[should_panic(expected = "double free")]
fn double_free_across_caches() {
  let h = heap();
  let (a, b) = (cache(h), cache(h));
  let x = h.alloc_cached(&a, 48, 8).unwrap().offset;
  h.dealloc_cached(&a, x);
  h.dealloc_cached(&b, x);
  h.flush(&a);
  h.flush(&b);
}

#[test]
#[should_panic(expected = "double free")]
fn free_of_a_claimed_block() {
  let h = heap();
  let tc = cache(h);
  let a = h.alloc_cached(&tc, 48, 8).unwrap().offset;
  // The next block of the word is claimed by the cache but not handed out.
  h.dealloc_cached(&tc, a + 48);
}

#[test]
fn a_seeded_cache_hands_out_each_claimed_block_once() {
  let h = heap();
  h.set_seed(0x9E37_79B9_7F4A_7C15);
  let tc = cache(h);
  let first = alloc_c(h, &tc, 16, 8);
  // One refill claimed the rest of a 64-block word; the cache lists them
  // and hands each out exactly once, in a shuffled order.
  let claimed = h.cache_stats(&tc).claimed_blocks;
  let mut got: Vec<_> = (0..claimed).map(|_| alloc_c(h, &tc, 16, 8)).collect();
  assert_eq!(h.cache_stats(&tc).claimed_blocks, 0);
  let in_order = got.windows(2).all(|w| w[1] > w[0]);
  got.push(first);
  got.sort_unstable();
  got.dedup();
  assert_eq!(got.len() as u64, claimed + 1);
  let base = got[0] / (64 * 16) * (64 * 16);
  assert!(got.iter().all(|&o| (base..base + 64 * 16).contains(&o)));
  assert!(!in_order, "a seeded cache handed its blocks out in order");
}

#[test]
fn refill_finds_freed_page_without_scanning() {
  let h = heap();
  // Fill 40 pages of one class, then free one block in an early page. Under
  // Miri, use the largest small class so the same page-search topology takes
  // 320 allocations instead of tens of thousands.
  let size = if cfg!(miri) { 8192 } else { 32 };
  let per_page = PAGE_SIZE / size;
  let offs: Vec<_> = (0..per_page * 40).map(|_| alloc(h, 7, size, 8)).collect();
  let segs = h.segments_in_use();
  // The free lowers the class's search bound to that page (under the
  // owner's lock).
  free(h, offs[5]);
  h.check_indexes();
  // The next allocation of the class takes the freed block from that page,
  // the lowest with a free block, rather than a new page.
  let before = h.search_stats();
  let again = alloc(h, 7, size, 8);
  let after = h.search_stats();
  assert_eq!(again, offs[5]);
  assert_eq!(h.segments_in_use(), segs);
  // It is the first page the search looks at.
  assert_eq!(
    (
      after.pages_inspected - before.pages_inspected,
      after.new_pages - before.new_pages
    ),
    (1, 0)
  );
  for o in offs.into_iter().filter(|&o| o != again).chain([again]) {
    free(h, o);
  }
}

#[test]
fn cached_threads_with_cross_frees() {
  let h = heap();
  let threads = if cfg!(miri) { 2 } else { 8 };
  let rounds = if cfg!(miri) { 50 } else { 20_000 };
  let (tx, rx) = std::sync::mpsc::channel::<Vec<usize>>();
  let rx = std::sync::Arc::new(Mutex::new(rx));
  let done = AtomicBool::new(false);
  std::thread::scope(|sc| {
    let done = &done;
    sc.spawn(move || {
      while !done.load(Ordering::Relaxed) {
        h.purge();
        std::thread::yield_now();
      }
    });
    // Stops the purger even when a worker panics, so a failure ends the
    // test instead of leaving the scope waiting on the purge loop.
    let _stop = SetOnDrop(done);
    let mut workers = Vec::new();
    for t in 0..threads {
      let tx = tx.clone();
      let rx = rx.clone();
      workers.push(sc.spawn(move || {
        let tc = cache(h);
        let mut batch = Vec::new();
        for i in 0..rounds {
          let size = SIZES[(i * 7 + t) % 12];
          batch.push(alloc_c(h, &tc, size, 8));
          if batch.len() == 32 {
            tx.send(std::mem::take(&mut batch)).unwrap();
            let theirs = rx.lock().unwrap().try_recv();
            if let Ok(v) = theirs {
              for o in v {
                free_c(h, &tc, o);
              }
            }
          }
        }
        for o in batch {
          free_c(h, &tc, o);
        }
        h.retire(&tc);
      }));
    }
    for w in workers {
      w.join().unwrap();
    }
  });
  drop(tx);
  for v in rx.lock().unwrap().iter() {
    for o in v {
      free(h, o);
    }
  }
  assert!(h.os().live.lock().unwrap().is_empty());
  // Everything went back: two passes return all pages and segments but
  // the one each shard keeps.
  h.purge();
  h.purge();
  assert_eq!(h.dirty_pages(), 0);
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(if cfg!(miri) { 2 } else { 64 }))]
    #[test]
    fn random_cached_sequences(
        ops in proptest::collection::vec((0usize..20_000, 0u32..6, 0u8..5, 0usize..3), 1..400),
        seed in proptest::prop_oneof![proptest::strategy::Just(0u64), proptest::prelude::any::<u64>()],
    ) {
        let h = heap();
        // Randomized placement must keep every invariant too.
        h.set_seed(seed);
        let caches = [cache(h), cache(h), ThreadCache::new()];
        let mut live = Vec::new();
        for (size, align_shift, op, t) in ops {
            let tc = &caches[t];
            match op {
                1 | 2 if !live.is_empty() => {
                    let o = live.swap_remove(size % live.len());
                    free_c(h, tc, o);
                }
                3 => h.flush(tc),
                4 if size % 50 == 0 => h.purge(),
                _ => live.push(alloc_c(h, tc, size % (1 << (align_shift * 3)), 1 << align_shift)),
            }
        }
        for o in live {
            free(h, o);
        }
        for tc in &caches {
            h.retire(tc);
        }
    }
}

// ---- time-based purging ------------------------------------------------------

/// Decay passes a page waits before a decay pass purges it (with a delay).
const DECAY_AGE: usize = 5;

#[test]
fn decay_waits_for_the_purge_delay() {
  let h = heap();
  let runs: Vec<_> = (0..8).map(|_| alloc(h, 2, 5 * PAGE_SIZE, 8)).collect();
  for &o in &runs[..4] {
    free(h, o);
  }
  // Freshly freed pages stay resident for the delay (in decay passes).
  for _ in 0..2 {
    h.decay();
  }
  // Pages freed later are purged later.
  for &o in &runs[4..] {
    free(h, o);
  }
  for _ in 2..DECAY_AGE - 1 {
    h.decay();
  }
  assert_eq!(h.dirty_pages(), 40);
  assert_eq!(h.os().purged.load(Ordering::Relaxed), 0);
  h.decay();
  assert_eq!(h.dirty_pages(), 20, "only the first four runs expired");
  assert_eq!(h.os().purged.load(Ordering::Relaxed), 20 * PAGE_SIZE);
  h.decay();
  assert_eq!(h.dirty_pages(), 20);
  h.decay();
  assert_eq!(h.dirty_pages(), 0);
}

/// The definition every age kernel is checked against, on the edges.
#[test]
fn aged_pages_compares_each_page() {
  let mut since = [0u64; 64];
  for (i, t) in since.iter_mut().enumerate() {
    *t = i as u64;
  }
  assert_eq!(crate::core::aged_pages(&since, 0), 1);
  assert_eq!(crate::core::aged_pages(&since, 31), u64::from(u32::MAX));
  assert_eq!(crate::core::aged_pages(&since, 63), u64::MAX);
  since[63] = u64::MAX;
  assert_eq!(crate::core::aged_pages(&since, u64::MAX - 1), u64::MAX >> 1);
  assert_eq!(crate::core::aged_pages(&since, u64::MAX), u64::MAX);
  assert_eq!(crate::core::aged_pages(&[u64::MAX; 64], 0), 0);
}

/// Decay passes that compare ages on a snapshot, as architecture kernels
/// do ([`crate::core::Os::age_kernel`]), purge exactly what the portable
/// scan purges, step by step.
#[test]
fn decay_with_an_age_kernel_purges_the_same_pages() {
  let plain = heap();
  let kernel = heap();
  kernel.os().age_kernel.store(true, Ordering::Relaxed);
  let mut held: [Vec<usize>; 2] = [Vec::new(), Vec::new()];
  let mut x = 0x9E37_79B9_7F4A_7C15u64;
  // The deterministic Miri prefix exercises all 24 page-count/shard pairs,
  // every branch, and repeated purge epochs while preserving every-step
  // comparison. Native runs retain the full 3000-step stress walk.
  let steps = if cfg!(miri) { 192 } else { 3000 };
  let mut allocations = [[false; 4]; 6];
  let mut branches = [false; 8];
  let mut decay_steps = 0;
  let mut frees = 0;
  for step in 0..steps {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    branches[(x % 8) as usize] = true;
    for (side, (h, held)) in [plain, kernel].into_iter().zip(held.iter_mut()).enumerate() {
      match x % 8 {
        0..=3 => {
          let pages = 1 + (x >> 8) as usize % 6;
          let shard = (x >> 16) as usize % 4;
          allocations[pages - 1][shard] = true;
          held.push(alloc(h, shard, pages * PAGE_SIZE, 8));
        }
        4..=6 if !held.is_empty() => {
          let o = held.swap_remove((x >> 24) as usize % held.len());
          free(h, o);
          if side == 0 {
            frees += 1;
          }
        }
        _ => {
          if side == 0 {
            decay_steps += 1;
          }
          h.os().advance(h.decay_interval_ms());
          h.decay();
        }
      }
    }
    assert_eq!(held[0], held[1], "placement differs at step {step}");
    assert_eq!(plain.dirty_pages(), kernel.dirty_pages(), "step {step}");
    assert_eq!(
      plain.os().purged.load(Ordering::Relaxed),
      kernel.os().purged.load(Ordering::Relaxed),
      "step {step}"
    );
    assert_eq!(plain.segments_in_use(), kernel.segments_in_use());
  }
  assert!(allocations.iter().flatten().all(|&seen| seen));
  assert!(branches.into_iter().all(|seen| seen));
  assert!(frees >= 60);
  assert!(decay_steps >= 30);
  assert!(kernel.os().purged.load(Ordering::Relaxed) > 0);
  assert_eq!(kernel.dirty_pages(), kernel.dirty_pages_recounted());
}

#[test]
fn empty_segments_decay_after_the_delay() {
  let h = heap();
  let base = h.segments_in_use();
  let runs: Vec<_> = (0..36).map(|_| alloc(h, 5, 5 * PAGE_SIZE, 8)).collect();
  assert_eq!(h.segments_in_use(), base + 3);
  for o in runs {
    free(h, o);
  }
  // The first pass notes that the segments are empty ...
  for _ in 0..DECAY_AGE {
    h.decay();
    assert_eq!(h.segments_in_use(), base + 3);
  }
  // ... and they go back once they have been empty for the delay, but for
  // the one the shard keeps.
  h.decay();
  assert_eq!(h.segments_in_use(), base + 1);
  assert_eq!(h.dirty_pages(), 0);
  // Reuse resets the idle time.
  let a = alloc(h, 5, 5 * PAGE_SIZE, 8);
  for _ in 0..DECAY_AGE + 2 {
    h.decay();
  }
  assert_eq!(h.segments_in_use(), base + 1);
  free(h, a);
}

#[test]
fn allocation_runs_due_decay_passes() {
  let h = heap();
  // With no delay, a pass purges everything dirty; passes are due every
  // millisecond.
  h.set_purge_delay_ms(0);
  assert_eq!(h.decay_interval_ms(), 1);
  let tc = cache(h);
  let run = alloc_c(h, &tc, 5 * PAGE_SIZE, 8);
  free_c(h, &tc, run);
  let purged = h.os().purged.load(Ordering::Relaxed);
  // Page-run allocations and frees are slow paths that check for a due
  // pass (sampling the clock every 16th time) ...
  let churn = |n| {
    for _ in 0..n {
      let o = alloc_c(h, &tc, 3 * PAGE_SIZE, 8);
      free_c(h, &tc, o);
    }
  };
  churn(8);
  assert_eq!(
    h.os().purged.load(Ordering::Relaxed),
    purged,
    "no pass is due yet"
  );
  h.os().advance(1);
  churn(8);
  assert!(h.os().purged.load(Ordering::Relaxed) > purged);
  // ... unless automatic decay is off (a background thread's job).
  h.set_auto_decay(false);
  h.os().advance(1);
  let purged = h.os().purged.load(Ordering::Relaxed);
  churn(16);
  assert_eq!(h.os().purged.load(Ordering::Relaxed), purged);
  h.retire(&tc);
}

#[test]
fn small_refills_run_due_decay_passes() {
  let h = heap();
  h.set_purge_delay_ms(0);
  let tc = cache(h);
  let run = alloc_c(h, &tc, 5 * PAGE_SIZE, 8);
  free_c(h, &tc, run);
  h.os().advance(1);
  // Enough 16-byte refills (64 blocks each) to sample the clock.
  let blocks: Vec<_> = (0..64 * 40).map(|_| alloc_c(h, &tc, 16, 8)).collect();
  assert_eq!(h.dirty_pages(), 0);
  for o in blocks {
    free_c(h, &tc, o);
  }
  h.retire(&tc);
}

#[test]
fn budget_passes_purge_everything_dirty() {
  let h = heap();
  h.os().advance(10_000);
  const RUN: usize = 8;
  let n = crate::core::heap::DIRTY_BUDGET_PAGES as usize / RUN + 2;
  let runs: Vec<_> = (0..n).map(|_| alloc(h, 3, RUN * PAGE_SIZE, 8)).collect();
  let segs = h.segments_in_use();
  for o in runs {
    free(h, o);
  }
  // Crossing the budget purged the dirty pages without waiting for the
  // delay, but kept the (just emptied) segments.
  assert!(h.dirty_pages() < crate::core::heap::DIRTY_BUDGET_PAGES as usize);
  assert_eq!(h.segments_in_use(), segs);
}

// ---- maintenance engine -----------------------------------------------------------

/// Page runs of `RUN` pages whose frees take the dirty count to `pages`
/// (a multiple of `RUN`), in shard 3.
const RUN: usize = 8;

fn dirty_runs(h: &Heap<MockOs>, pages: usize) -> Vec<usize> {
  (0..pages / RUN)
    .map(|_| alloc(h, 3, RUN * PAGE_SIZE, 8))
    .collect()
}

#[test]
fn maintenance_takes_budget_passes_off_frees() {
  let h = heap();
  h.attach_maintenance();
  let budget = DIRTY_BUDGET_PAGES as usize;
  let runs = dirty_runs(h, budget + 2 * RUN);
  let wakes = h.os().wakes.load(Ordering::Relaxed);
  for o in runs {
    free(h, o);
  }
  // The frees only recorded the work and woke the thread, once.
  assert_eq!(h.dirty_pages(), budget + 2 * RUN);
  assert_eq!(h.os().purged.load(Ordering::Relaxed), 0);
  assert_eq!(h.os().wakes.load(Ordering::Relaxed), wakes + 1);
  let stats = h.maintenance_stats();
  assert_eq!((stats.wakeups, stats.inline_budget_passes), (1, 0));
  assert_eq!(h.next_task(0), Some(Task::Budget));
  // The maintenance thread's round runs the pass.
  assert_eq!(h.maintain(), Some(Task::Budget));
  assert_eq!(h.dirty_pages(), 0);
  assert_eq!(h.maintenance_stats().budget_passes, 1);
  assert_eq!(h.next_task(0), None);
}

#[test]
fn frees_purge_inline_past_the_hard_limit() {
  let h = heap();
  h.attach_maintenance();
  let runs = dirty_runs(h, DIRTY_HARD_LIMIT_PAGES as usize + RUN);
  for o in runs {
    free(h, o);
  }
  // The thread never ran; the free past the hard limit purged itself.
  let stats = h.maintenance_stats();
  assert_eq!(stats.inline_budget_passes, 1);
  assert_eq!(stats.budget_passes, 0);
  assert!(h.dirty_pages() <= RUN);
}

#[test]
fn without_maintenance_frees_purge_inline() {
  let h = heap();
  let runs = dirty_runs(h, DIRTY_BUDGET_PAGES as usize + RUN);
  for o in runs {
    free(h, o);
  }
  assert_eq!(h.maintenance_stats().inline_budget_passes, 1);
  assert_eq!(h.maintenance_stats().wakeups, 0);
  assert!(h.dirty_pages() <= RUN);
}

#[test]
fn maintenance_runs_work_by_priority() {
  let h = heap();
  h.attach_maintenance();
  let budget = DIRTY_BUDGET_PAGES as usize;
  let runs = dirty_runs(h, budget + RUN);
  for o in runs {
    free(h, o);
  }
  h.os().advance(10_000);
  // Budget (P1) and decay (P2) are due; a force request (P0) goes first.
  h.request_purge();
  assert_eq!(
    h.dirty_pages(),
    budget + RUN,
    "requests do not purge inline"
  );
  assert_eq!(h.maintain(), Some(Task::Force));
  assert_eq!(h.dirty_pages(), 0);
  // The budget request is still recorded; its pass finds nothing to do.
  assert_eq!(h.maintain(), Some(Task::Budget));
  assert_eq!(h.maintenance_stats().budget_passes, 0);
  assert_eq!(h.maintain(), Some(Task::Decay));
  assert_eq!(h.maintain(), None);
  let stats = h.maintenance_stats();
  assert_eq!((stats.force_passes, stats.decay_passes), (1, 1));
}

#[test]
fn idle_maintenance_sleeps_until_decay_is_due() {
  let h = heap();
  h.attach_maintenance();
  h.os().advance(1000);
  assert_eq!(h.maintain(), Some(Task::Decay));
  h.os().advance(100);
  // Passes are due every quarter of the 1 s delay.
  assert_eq!(h.maintain(), None);
  assert_eq!(h.os().last_wait_ms.load(Ordering::Relaxed), 150);
  // A shorter delay wakes the thread to recompute its deadline: passes
  // every 50 ms, so the next one is overdue.
  let wakes = h.os().wakes.load(Ordering::Relaxed);
  h.set_purge_delay_ms(200);
  assert_eq!(h.os().wakes.load(Ordering::Relaxed), wakes + 1);
  assert_eq!(h.maintain(), Some(Task::Decay));
  assert_eq!(h.maintain(), None);
  assert_eq!(h.os().last_wait_ms.load(Ordering::Relaxed), 50);
}

#[test]
fn maintenance_stops_allocation_driven_decay() {
  let h = heap();
  h.set_purge_delay_ms(0);
  h.attach_maintenance();
  let tc = cache(h);
  h.os().advance(1);
  for _ in 0..32 {
    let o = alloc_c(h, &tc, 3 * PAGE_SIZE, 8);
    free_c(h, &tc, o);
  }
  assert_eq!(h.maintenance_stats().inline_decay_passes, 0);
  assert!(h.dirty_pages() > 0);
  assert_eq!(h.maintain(), Some(Task::Decay));
  assert_eq!(h.dirty_pages(), 0);
  h.retire(&tc);
}

#[test]
fn request_purge_without_maintenance_purges_inline() {
  let h = heap();
  let o = alloc(h, 0, 5 * PAGE_SIZE, 8);
  free(h, o);
  assert_eq!(h.dirty_pages(), 5);
  h.request_purge();
  assert_eq!(h.dirty_pages(), 0);
}

#[test]
fn forked_child_takes_housekeeping_back() {
  let h = heap();
  h.attach_maintenance();
  h.request_purge();
  h.fork_prepare();
  h.fork_child();
  assert!(!h.maintenance_attached());
  assert_eq!(h.next_task(0), None, "the parent's requests are dropped");
  let runs = dirty_runs(h, DIRTY_BUDGET_PAGES as usize + RUN);
  for o in runs {
    free(h, o);
  }
  assert_eq!(h.maintenance_stats().inline_budget_passes, 1);
}

// ---- hardening -----------------------------------------------------------------

// ---- batched (asynchronous) purges -------------------------------------------------

/// Shards whose segments [`dirty_everywhere`] uses.
const SPREAD: usize = 8;

/// Separate dirty runs in `SPREAD` segments, under the dirty budget: in
/// each, six runs of `RUN` pages, every other one freed. Returns the dirty
/// pages and the runs still held.
fn dirty_everywhere(h: &Heap<MockOs>) -> (usize, Vec<usize>) {
  let mut held = Vec::new();
  let mut dirty = 0;
  for shard in 0..SPREAD {
    let runs: Vec<usize> = (0..6)
      .map(|_| alloc(h, shard, RUN * PAGE_SIZE, 8))
      .collect();
    for (i, o) in runs.into_iter().enumerate() {
      if i % 2 == 0 {
        free(h, o);
        dirty += RUN;
      } else {
        held.push(o);
      }
    }
  }
  assert!(dirty < DIRTY_BUDGET_PAGES as usize);
  (dirty, held)
}

#[test]
fn batched_purges_complete_and_clean() {
  let h = heap();
  h.attach_maintenance();
  let (dirty, _held) = dirty_everywhere(h);
  assert_eq!(h.dirty_pages(), dirty);
  assert_eq!(h.dirty_pages(), h.dirty_pages_recounted());
  h.request_purge();
  let mut p = MockPurger::new(h.os(), PURGE_BATCH);
  assert_eq!(h.maintain_with(&mut p), Some(Task::Force));
  assert_eq!(h.dirty_pages(), 0);
  assert_eq!(h.dirty_pages_recounted(), 0);
  // One call for the runs of every segment.
  assert_eq!(p.runs, dirty / RUN);
  assert!(p.batches == 1, "{} batches for {} runs", p.batches, p.runs);
  let stats = h.maintenance_stats();
  assert_eq!(stats.purged_runs, p.runs as u64);
  assert_eq!(stats.purge_batches, p.batches as u64);
  // Everything purged reads as zero again.
  let o = alloc_block(h, 0, RUN * PAGE_SIZE, 8);
  assert!(o.zeroed);
}

#[test]
fn failed_runs_in_a_batch_stay_dirty() {
  let h = heap();
  h.attach_maintenance();
  let (_, held) = dirty_everywhere(h);
  h.request_purge();
  let mut p = MockPurger::new(h.os(), PURGE_BATCH);
  p.fail_every = 3;
  h.maintain_with(&mut p);
  // A partial failure: some runs are clean, the failed ones stay dirty and
  // are counted.
  let left = h.dirty_pages();
  assert!(left > 0);
  assert_eq!(left, h.dirty_pages_recounted());
  // Their pages are handed out as not zero (the model checks every
  // `zeroed` claim against what was written), then purged by the next
  // pass once freed.
  let reused: Vec<Block> = (0..SPREAD * 3)
    .map(|i| alloc_block(h, i % SPREAD, RUN * PAGE_SIZE, 8))
    .collect();
  assert!(reused.iter().any(|b| !b.zeroed));
  for o in reused.iter().map(|b| b.offset).chain(held) {
    free(h, o);
  }
  h.request_purge();
  h.maintain_with(&mut MockPurger::new(h.os(), PURGE_BATCH));
  assert_eq!(h.dirty_pages(), 0);
  assert_eq!(h.dirty_pages_recounted(), 0);
}

/// Other threads allocate, grow and free while a batch is in flight; none of
/// them may get a page whose purge is pending ([`MockPurger`] checks the
/// ranges again at completion, and the model checks every allocation).
#[test]
fn allocations_during_a_batch_never_get_its_pages() {
  let h = heap();
  h.attach_maintenance();
  let (_, before) = dirty_everywhere(h);
  let tc = cache(h);
  let held = Mutex::new(before);
  let during = || {
    let mut held = held.lock().unwrap();
    for i in 0..SPREAD * 2 {
      held.push(alloc(h, i, RUN * PAGE_SIZE, 8));
      held.push(alloc(h, i, 3 * PAGE_SIZE, 8));
      held.push(alloc_c(h, &tc, 100, 8));
    }
    // Frees during the batch make new dirty pages, left for a later pass.
    for o in held.drain(..SPREAD * 3) {
      free(h, o);
    }
  };
  h.request_purge();
  let mut p = MockPurger::new(h.os(), PURGE_BATCH);
  p.during = Some(&during);
  h.maintain_with(&mut p);
  assert!(p.batches > 0);
  assert_eq!(h.dirty_pages(), h.dirty_pages_recounted());
  for o in held.into_inner().unwrap() {
    free(h, o);
  }
  h.retire(&tc);
  h.purge();
  assert_eq!(h.dirty_pages(), 0);
}

/// A decay pass through a batching purger returns only aged pages.
#[test]
fn batched_decay_purges_only_aged_pages() {
  let h = heap();
  h.attach_maintenance();
  let (old, mut held) = dirty_everywhere(h);
  let mut p = MockPurger::new(h.os(), 16);
  // Age the first runs past the purge delay with decay rounds.
  for _ in 0..6 {
    h.os().advance(h.decay_interval_ms());
    assert_eq!(h.maintain_with(&mut p), Some(Task::Decay));
  }
  assert_eq!(h.dirty_pages(), 0, "{old} old pages");
  // Freed now: too young for the next decay pass.
  let young = held.len() * RUN;
  for o in held.drain(..) {
    free(h, o);
  }
  h.os().advance(h.decay_interval_ms());
  assert_eq!(h.maintain_with(&mut p), Some(Task::Decay));
  assert_eq!(h.dirty_pages(), young);
  assert_eq!(h.dirty_pages(), h.dirty_pages_recounted());
}

#[test]
fn owned_segments_end_in_a_guard_page() {
  let h = heap();
  // The longest page run fits beside the guard page; one page more takes a
  // whole segment.
  let run = alloc(h, 0, MAX_RUN_PAGES * PAGE_SIZE, 8);
  assert_eq!(h.usable_size(run), MAX_RUN_PAGES * PAGE_SIZE);
  let whole = alloc(h, 0, MAX_RUN_PAGES * PAGE_SIZE + 1, 8);
  assert_eq!(h.usable_size(whole), SEGMENT_SIZE);
  assert_eq!(h.os().guarded.lock().unwrap().len(), 1);
  // A run does not grow into the guard page.
  assert!(!resize(h, run, MAX_RUN_PAGES * PAGE_SIZE + 1));
  // A second owned segment gets its own guard.
  let more = alloc(h, 0, 2 * PAGE_SIZE, 8);
  assert_eq!(h.os().guarded.lock().unwrap().len(), 2);
  for o in [run, whole, more] {
    free(h, o);
  }
  // Returning a segment removes its guard (the mock `commit` checks that
  // nothing guarded is committed again, e.g. for this huge block).
  h.purge();
  assert_eq!(h.os().guarded.lock().unwrap().len(), 1);
  let huge = alloc(h, 0, 3 * SEGMENT_SIZE, 8);
  free(h, huge);
}

#[test]
fn seeded_placement_is_randomized() {
  let first = |seed: u64| {
    let h = heap();
    h.set_seed(seed);
    let tc = cache(h);
    let blocks: Vec<_> = (0..4).map(|_| alloc_c(h, &tc, 64, 8)).collect();
    (blocks[0] / SEGMENT_SIZE, blocks)
  };
  // Unseeded heaps are deterministic: first segment, consecutive blocks.
  let (seg, blocks) = first(0);
  assert_eq!(seg, 0);
  assert!(blocks.windows(2).all(|w| w[1] == w[0] + 64));
  assert_eq!(first(0).1, blocks);
  // Seeded ones vary the segment, the word and the order within a word.
  let runs: Vec<_> = (1..=16u64)
    .map(|i| first(i.wrapping_mul(0x9E37_79B9_7F4A_7C15)))
    .collect();
  let segs: BTreeSet<_> = runs.iter().map(|r| r.0).collect();
  let offsets: BTreeSet<_> = runs.iter().map(|r| r.1[0] % SEGMENT_SIZE).collect();
  assert!(segs.len() > 8, "segments barely vary: {segs:?}");
  assert!(offsets.len() > 8, "offsets barely vary: {offsets:?}");
  let adjacent = runs
    .iter()
    .flat_map(|r| r.1.windows(2).map(|w| w[1] == w[0] + 64))
    .filter(|&a| a)
    .count();
  assert!(
    adjacent < 16,
    "{adjacent} of 48 consecutive blocks were adjacent"
  );
}

// ---- fuzz programs -------------------------------------------------------------

proptest::proptest! {
  #![proptest_config(proptest::prelude::ProptestConfig::with_cases(if cfg!(miri) { 2 } else { 256 }))]
  /// The fuzz target's interpreter (see `fuzz/`), on random programs.
  #[test]
  fn fuzz_programs(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..3000)) {
    #[cfg(miri)]
    {
      crate::core::model::run(&bounded_miri_program(&data));
    }
    #[cfg(not(miri))]
    {
      crate::core::model::run(&data);
    }
  }
}

#[cfg(miri)]
fn bounded_miri_program(seed_bytes: &[u8]) -> Vec<u8> {
  struct Program {
    bytes: Vec<u8>,
    live: Vec<(usize, u8)>,
    page_credit: usize,
    instructions: usize,
    maintenance_attached: bool,
  }

  impl Program {
    fn instruction(&mut self, op: u8) {
      assert!(self.instructions < 96, "program exceeded instruction bound");
      self.instructions += 1;
      self.bytes.push(op);
    }

    fn alloc(&mut self, route: u8, size: usize, align_shift: u8) {
      let (kind, value) = if size <= 256 {
        (0u8, size)
      } else if size <= 8192 {
        (1, size)
      } else if size <= 65_520 && size.is_multiple_of(16) {
        (2, size / 16)
      } else {
        assert!(size.is_multiple_of(1024), "unsupported encoded size {size}");
        (3, size / 1024)
      };
      assert!(value <= 0x3fff, "size encoding overflow: {size}");
      let hi = (kind << 6) | ((value >> 8) as u8 & 0x3f);
      let lo = value as u8;
      let align_shift = align_shift.min(16);
      let decoded = match kind {
        0 => value % 257,
        1 => value % 8193,
        2 => value * 16,
        _ => value * 1024,
      };
      assert_eq!(decoded, size);
      self.page_credit += size
        .max(1)
        .saturating_add((1usize << align_shift) - 1)
        .div_ceil(PAGE_SIZE);
      assert!(self.page_credit <= 256, "page-credit bound exceeded");
      self.instruction((route << 5) | 0);
      self.bytes.extend([hi, lo, align_shift]);
      self.live.push((route as usize, align_shift));
    }

    fn free(&mut self, route: u8, index: usize) {
      assert!(!self.live.is_empty());
      self.instruction((route << 5) | 12);
      let index = index % self.live.len();
      self.bytes.push(index as u8);
      self.live.swap_remove(index);
    }

    fn resize(&mut self, route: u8, index: usize, size: usize) {
      assert!(!self.live.is_empty());
      let (kind, value) = if size <= 256 {
        (0u8, size)
      } else if size <= 8192 {
        (1, size)
      } else if size <= 65_520 && size.is_multiple_of(16) {
        (2, size / 16)
      } else {
        assert!(size.is_multiple_of(1024), "unsupported encoded size {size}");
        (3, size / 1024)
      };
      assert!(value <= 0x3fff, "size encoding overflow: {size}");
      let hi = (kind << 6) | ((value >> 8) as u8 & 0x3f);
      let lo = value as u8;
      let decoded = match kind {
        0 => value % 257,
        1 => value % 8193,
        2 => value * 16,
        _ => value * 1024,
      };
      assert_eq!(decoded, size);
      let align_shift = self.live[index % self.live.len()].1;
      self.page_credit += size
        .max(1)
        .saturating_add((1usize << align_shift) - 1)
        .div_ceil(PAGE_SIZE);
      assert!(self.page_credit <= 256, "page-credit bound exceeded");
      self.instruction((route << 5) | 20);
      self
        .bytes
        .extend([index as u8 % self.live.len() as u8, hi, lo]);
    }

    fn op(&mut self, route: u8, op: u8) {
      self.instruction((route << 5) | op);
    }

    fn configured(&mut self, route: u8, selector: u8) {
      self.op(route, 26);
      self.bytes.push(selector);
      match selector % 4 {
        0 | 1 => self.bytes.push(selector.wrapping_mul(7)),
        2 => self.bytes.extend([16, 32, 64]),
        _ => self.bytes.extend([8, 2]),
      }
    }
  }

  let mut program = Program {
    bytes: std::vec![seed_bytes.iter().fold(0u8, |a, b| a.rotate_left(1) ^ b)],
    live: Vec::new(),
    page_credit: 0,
    instructions: 0,
    maintenance_attached: false,
  };

  // Exercise all four allocator routes, then cross-route free and resize.
  for (route, size) in [1, 8192, 65_536, 131_072].into_iter().enumerate() {
    program.alloc(route as u8, size, route as u8);
  }
  program.free(1, 0);
  program.resize(2, 1, 4096);
  program.op(1, 22); // flush the cross-route free through an attached cache
  program.op(0, 23); // purge
  program.op(1, 24); // decay
  program.op(2, 25);
  program.bytes.push(7);
  program.configured(0, 0); // purge delay
  program.configured(3, 1); // alternate purge-delay mode
  program.configured(1, 2); // reclaim thresholds
  program.configured(2, 3); // slicing and retention
  program.op(2, 27); // retire the detached cache
  program.op(0, 28); // attach maintenance
  program.maintenance_attached = true;
  program.op(1, 30); // request purge

  // A representable >4 MiB request is released before randomized work begins.
  program.alloc(3, (4 << 20) + 1024, 10);
  let last = program.live.len() - 1;
  program.free(0, last);
  program.alloc(3, 200_704, 8);
  let dirty_run = program.live.len() - 1;
  program.free(3, dirty_run);
  program.op(3, 31); // batched purge with configured failures
  program.bytes.extend([4, 1]);
  program.op(2, 29); // maintenance round
  program.op(0, 28); // detach maintenance
  program.maintenance_attached = false;
  let random_start = program.bytes.len();

  let mut random = seed_bytes.iter().fold(0xA341_316Cu32, |state, byte| {
    state.rotate_left(5) ^ u32::from(*byte).wrapping_add(0x9E37_79B9)
  });
  let mut next = || {
    random ^= random << 13;
    random ^= random >> 17;
    random ^= random << 5;
    random as u8
  };
  let random_sizes = [
    1,
    16,
    256,
    512,
    4096,
    8192,
    8192 + 16,
    65_520,
    65_536,
    131_072,
  ];
  for _ in 0..32 {
    match next() % 8 {
      0..=2 => {
        let size = random_sizes[usize::from(next()) % random_sizes.len()];
        program.alloc(next() % 4, size, next() % 17);
      }
      3 if !program.live.is_empty() => {
        program.free(next() % 4, usize::from(next()));
      }
      4 if !program.live.is_empty() => {
        let size = random_sizes[usize::from(next()) % random_sizes.len()];
        program.resize(next() % 4, usize::from(next()), size);
      }
      5 => program.configured(next() % 4, next()),
      6 => {
        let route = next() % 4;
        program.op(route, 22 + next() % 4);
        if program.bytes.last().is_some_and(|op| op & 0x1f == 25) {
          program.bytes.push(next());
        }
      }
      _ => {
        let route = next() % 4;
        if program.maintenance_attached {
          program.op(route, 29 + next() % 3);
          if program.bytes.last().is_some_and(|op| op & 0x1f == 31) {
            program.bytes.extend([next(), next()]);
          }
        } else {
          program.op(route, 28);
          program.maintenance_attached = true;
        }
      }
    }
  }
  assert!(program.instructions <= 96);
  assert!(program.page_credit <= 256);
  validate_bounded_miri_program(&program.bytes, random_start);
  program.bytes
}

#[cfg(miri)]
fn validate_bounded_miri_program(bytes: &[u8], random_start: usize) {
  fn take(bytes: &[u8], cursor: &mut usize) -> u8 {
    let byte = *bytes.get(*cursor).expect("truncated bounded program");
    *cursor += 1;
    byte
  }

  fn decoded_size(hi: u8, lo: u8) -> usize {
    let value = usize::from(hi & 0x3f) << 8 | usize::from(lo);
    match hi >> 6 {
      0 => value % 257,
      1 => value % 8193,
      2 => value * 16,
      _ => value * 1024,
    }
  }

  assert!(random_start <= bytes.len());
  let mut cursor = 1; // model::run consumes the first byte as its seed
  let mut live: Vec<(u8, bool, usize)> = Vec::new();
  let mut instructions = 0usize;
  let mut prefix_instructions = 0usize;
  let mut suffix_instructions = 0usize;
  let mut page_credit = 0usize;
  let mut prefix_routes = [false; 4];
  let mut cross_route_free = false;
  let mut saw_resize = false;
  let mut saw_flush = false;
  let mut saw_purge = false;
  let mut saw_decay = false;
  let mut saw_clock = false;
  let mut config_kinds = [false; 4];
  let mut saw_retire = false;
  let mut attached = false;
  let mut saw_attach = false;
  let mut saw_detach = false;
  let mut saw_request = false;
  let mut saw_failing_batch = false;
  let mut saw_large = false;
  let mut saw_dirty_run_free = false;
  let mut saw_successful_resize_shape = false;

  while cursor < bytes.len() {
    let in_prefix = cursor < random_start;
    let op = take(bytes, &mut cursor);
    let route = op >> 5;
    let operation = op & 0x1f;
    instructions += 1;
    if in_prefix {
      prefix_instructions += 1;
    } else {
      suffix_instructions += 1;
    }

    match operation {
      0..=11 => {
        let size = decoded_size(take(bytes, &mut cursor), take(bytes, &mut cursor));
        let align_shift = take(bytes, &mut cursor);
        assert!(align_shift <= 16, "alignment shift {align_shift}");
        if !in_prefix {
          assert!(size <= 2 * PAGE_SIZE, "random allocation too large: {size}");
        }
        page_credit += size
          .max(1)
          .saturating_add((1usize << align_shift) - 1)
          .div_ceil(PAGE_SIZE);
        if in_prefix {
          prefix_routes[usize::from(route)] = true;
          if size > 4 << 20 {
            saw_large = true;
          }
          live.push((route, size > 4 << 20, size));
        } else {
          live.push((route, false, size));
        }
      }
      12..=19 if !live.is_empty() => {
        let index = usize::from(take(bytes, &mut cursor)) % live.len();
        let (allocation_route, was_large, allocation_size) = live.swap_remove(index);
        if in_prefix && route != allocation_route {
          cross_route_free = true;
        }
        if in_prefix && allocation_size > PAGE_SIZE && allocation_size <= 4 << 20 {
          saw_dirty_run_free = true;
        }
        if was_large {
          assert!(in_prefix, "large request crossed into randomized suffix");
        }
      }
      20 | 21 if !live.is_empty() => {
        let index = usize::from(take(bytes, &mut cursor)) % live.len();
        let size = decoded_size(take(bytes, &mut cursor), take(bytes, &mut cursor));
        if !in_prefix {
          assert!(size <= 2 * PAGE_SIZE, "random resize too large: {size}");
        }
        if in_prefix && live[index].2 == 8192 && size == 4096 {
          saw_successful_resize_shape = true;
        }
        page_credit += size
          .max(1)
          .saturating_add((1usize << 16) - 1)
          .div_ceil(PAGE_SIZE);
        let _ = index;
        saw_resize |= in_prefix;
      }
      22 => saw_flush |= in_prefix,
      23 => saw_purge |= in_prefix,
      24 => saw_decay |= in_prefix,
      25 => {
        let _ = take(bytes, &mut cursor);
        saw_clock |= in_prefix;
      }
      26 => {
        let selector = take(bytes, &mut cursor);
        let kind = usize::from(selector % 4);
        config_kinds[kind] |= in_prefix;
        let operand_count = match kind {
          0 | 1 => 1,
          2 => 3,
          _ => 2,
        };
        for _ in 0..operand_count {
          let _ = take(bytes, &mut cursor);
        }
      }
      27 => saw_retire |= in_prefix,
      28 => {
        attached = !attached;
        if in_prefix {
          if attached {
            saw_attach = true;
          } else {
            saw_detach = true;
          }
        }
      }
      30 => saw_request |= in_prefix,
      31 => {
        let batch_size = take(bytes, &mut cursor);
        let fail_every = take(bytes, &mut cursor);
        saw_failing_batch |= in_prefix && batch_size == 4 && fail_every % 4 == 1;
      }
      _ => {}
    }
    if in_prefix {
      assert!(
        cursor <= random_start,
        "prefix operand crossed suffix boundary"
      );
      if cursor == random_start {
        assert!(saw_large && live.iter().all(|(_, large, _)| !large));
      }
    }
    assert!(page_credit <= 256, "decoded page-credit bound exceeded");
    assert!(instructions <= 96, "decoded instruction bound exceeded");
  }

  assert_eq!(cursor, bytes.len());
  assert!(prefix_routes.into_iter().all(|seen| seen));
  assert!(
    cross_route_free && saw_resize && saw_successful_resize_shape,
    "cross-route free={cross_route_free}, resize={saw_resize}, successful resize shape={saw_successful_resize_shape}"
  );
  assert!(saw_flush && saw_purge && saw_decay && saw_clock);
  assert!(config_kinds.into_iter().all(|seen| seen));
  assert!(saw_retire && saw_attach && saw_detach && saw_request && saw_failing_batch);
  assert!(saw_large && saw_dirty_run_free && live.iter().all(|(_, large, _)| !large));
  assert!(prefix_instructions <= 64);
  assert!(suffix_instructions <= 32);
}

#[cfg(miri)]
#[test]
fn bounded_program_resize_witness_succeeds() {
  let h = heap();
  let offset = alloc(h, 1, 8192, 8);
  assert!(resize(h, offset, 4096));
  free(h, offset);
}

#[cfg(miri)]
#[test]
fn bounded_program_batch_witness_fails_a_dirty_run() {
  let h = heap();
  h.attach_maintenance();
  h.request_purge();
  let offset = alloc(h, 0, 200_704, 8);
  free(h, offset);
  let dirty_before = h.dirty_pages();
  assert!(dirty_before > 0);

  let mut purger = MockPurger::new(h.os(), 4);
  purger.fail_every = 1;
  let _ = h.maintain_with(&mut purger);
  assert!(purger.batches > 0);
  assert!(purger.runs > 0);
  assert_eq!(h.dirty_pages(), dirty_before);

  h.detach_maintenance();
  h.purge();
}

#[test]
fn fuzz_program_edge_cases() {
  crate::core::model::run(&[]);
  crate::core::model::run(&[1]);
  // Allocate the largest sizes of each kind through every path, then free
  // them crosswise, with randomization on.
  let mut p = std::vec![1u8];
  for who in 0..4u8 {
    for hi in [0x00, 0x7F, 0xBF, 0xFF] {
      p.extend([who << 5, hi, 0xFF, 22]);
    }
  }
  for who in 0..4u8 {
    for _ in 0..4 {
      p.extend([(who << 5) | 12, 0]);
    }
  }
  p.extend([23, 24, 25, 255, 26, 0, 24, 27, 0x20 | 27]);
  crate::core::model::run(&p);
}

#[test]
fn shard_hints_override_the_attached_shard() {
  let h = heap();
  // Two caches, attached to two different shards.
  let (a, b) = (cache(h), cache(h));
  let seg = |o: usize| o / SEGMENT_SIZE;
  let run = 4 * PAGE_SIZE;
  assert_ne!(seg(alloc_c(h, &a, run, 8)), seg(alloc_c(h, &b, run, 8)));
  // With a hint, both allocate from the hinted shard's segment: its runs
  // and its small pages alike.
  h.os().hint.store(7, Ordering::Relaxed);
  let (x, y) = (alloc_c(h, &a, run, 8), alloc_c(h, &b, run, 8));
  assert_eq!(seg(x), seg(y));
  let (x, y) = (alloc_c(h, &a, 48, 8), alloc_c(h, &b, 48, 8));
  assert_eq!(seg(x), seg(y));
  // Without one again, each cache is back on its own shard.
  h.os().hint.store(usize::MAX, Ordering::Relaxed);
  assert_ne!(seg(alloc_c(h, &a, run, 8)), seg(alloc_c(h, &b, run, 8)));
}

#[test]
fn preferred_shards_replace_the_attached_one() {
  let h = heap();
  let (a, b) = (cache(h), cache(h));
  let seg = |o: usize| o / SEGMENT_SIZE;
  let run = 4 * PAGE_SIZE;
  assert_ne!(h.cache_stats(&a).shard, h.cache_stats(&b).shard);
  assert_ne!(seg(alloc_c(h, &a, run, 8)), seg(alloc_c(h, &b, run, 8)));
  // Both prefer shard 5 (given modulo the shard count): they share its
  // segments, for runs and small pages alike.
  h.set_preferred_shard(&a, 5);
  h.set_preferred_shard(&b, 5 + crate::core::SHARDS);
  assert_eq!((h.cache_stats(&a).shard, h.cache_stats(&b).shard), (5, 5));
  assert_eq!(seg(alloc_c(h, &a, run, 8)), seg(alloc_c(h, &b, run, 8)));
  assert_eq!(seg(alloc_c(h, &a, 48, 8)), seg(alloc_c(h, &b, 48, 8)));
  // An environment hint still comes first.
  h.set_preferred_shard(&b, 6);
  h.os().hint.store(9, Ordering::Relaxed);
  assert_eq!(seg(alloc_c(h, &a, run, 8)), seg(alloc_c(h, &b, run, 8)));
  h.os().hint.store(usize::MAX, Ordering::Relaxed);
  assert_ne!(seg(alloc_c(h, &a, run, 8)), seg(alloc_c(h, &b, run, 8)));
}

/// More threads than shards, each "migrating" on every slow-path call:
/// shard hints change under them (as an rseq `mm_cid` does), so blocks
/// cached, freed and flushed by one thread come from shards the others
/// are using. The hints are only preferences; the heap stays consistent.
#[test]
fn migrating_threads_keep_the_heap_consistent() {
  let h = heap();
  h.os().hint.store(0, Ordering::Relaxed);
  h.os().migrate.store(true, Ordering::Relaxed);
  let threads = if cfg!(miri) {
    2
  } else {
    crate::core::SHARDS + 8
  };
  let rounds = if cfg!(miri) { 50 } else { 2_000 };
  let shared = Mutex::new(Vec::<usize>::new());
  std::thread::scope(|sc| {
    for t in 0..threads {
      let shared = &shared;
      sc.spawn(move || {
        let tc = cache(h);
        let mut mine = Vec::new();
        for i in 0..rounds {
          mine.push(alloc_c(h, &tc, SIZES[(i * 5 + t) % 16], 8));
          if mine.len() == 16 {
            // Half go to other threads, half are freed here.
            let mut s = shared.lock().unwrap();
            s.extend(mine.drain(..8));
            let n = s.len().min(8);
            let theirs: Vec<usize> = s.drain(..n).collect();
            drop(s);
            for o in theirs.into_iter().chain(mine.drain(..)) {
              free_c(h, &tc, o);
            }
          }
        }
        for o in mine {
          free_c(h, &tc, o);
        }
        h.retire(&tc);
      });
    }
  });
  for o in shared.into_inner().unwrap() {
    free(h, o);
  }
  assert!(h.os().live.lock().unwrap().is_empty());
  assert_eq!(h.dirty_pages(), h.dirty_pages_recounted());
  h.purge();
  assert_eq!(h.dirty_pages(), 0);
}

// ---- observations (theory-driven plan, Stage A) -------------------------------

/// The counters of `after` minus those of `before`.
fn work_since(
  before: crate::core::MaintenanceStats,
  after: crate::core::MaintenanceStats,
) -> [u64; 12] {
  let f = |m: crate::core::MaintenanceStats| {
    [
      m.purge_batches,
      m.purged_runs,
      m.failed_runs,
      m.purged_pages,
      m.segments_inspected,
      m.trimmed_shards,
      m.busy_shards,
      m.trim_pages_inspected,
      m.released_pages,
      m.returned_segments,
      m.skipped_passes,
      m.hard_limit_slices,
    ]
  };
  let (b, a) = (f(before), f(after));
  core::array::from_fn(|i| a[i] - b[i])
}

const BATCHES: usize = 0;
const RUNS: usize = 1;
const FAILED: usize = 2;
const PURGED_PAGES: usize = 3;
const SEGS_INSPECTED: usize = 4;
const TRIMMED: usize = 5;
const BUSY: usize = 6;
const RELEASED: usize = 8;
const SKIPPED: usize = 10;
const HARD_LIMIT: usize = 11;

/// Four runs of 8 pages freed in one segment of shard 3: 32 dirty pages in
/// one contiguous run (placement is not randomized).
fn one_dirty_run(h: &Heap<MockOs>) {
  let runs: Vec<_> = (0..4).map(|_| alloc(h, 3, 8 * PAGE_SIZE, 8)).collect();
  for o in runs {
    free(h, o);
  }
  assert_eq!(h.dirty_pages(), 32);
}

#[test]
fn purge_work_is_counted() {
  let h = heap();
  one_dirty_run(h);
  let u = h.usage();
  assert_eq!(
    (
      u.owned_segments,
      u.pages_in_use,
      u.dirty_pages,
      u.clean_pages
    ),
    (1, 0, 32, 31)
  );
  let before = h.maintenance_stats();
  h.purge();
  let w = work_since(before, h.maintenance_stats());
  // One segment inspected, one run claimed and purged in one batch: the
  // operation counts of a force pass over this heap, not a timing.
  assert_eq!(w[SEGS_INSPECTED], 1);
  assert_eq!(
    (w[BATCHES], w[RUNS], w[FAILED], w[PURGED_PAGES]),
    (1, 1, 0, 32)
  );
  assert_eq!((w[TRIMMED], w[BUSY]), (crate::core::SHARDS as u64, 0));
  let u = h.usage();
  assert_eq!((u.dirty_pages, u.clean_pages), (0, 63));
}

#[test]
fn failed_purges_are_counted_and_stay_dirty() {
  let h = heap();
  one_dirty_run(h);
  h.os().purge_fails.store(true, Ordering::Relaxed);
  for _ in 0..3 {
    let before = h.maintenance_stats();
    h.purge();
    let w = work_since(before, h.maintenance_stats());
    // Each pass tries the run once, however often it failed before: the
    // attempts of a pass are bounded by what is dirty, not by success.
    assert_eq!((w[RUNS], w[FAILED], w[PURGED_PAGES]), (1, 1, 0));
    assert_eq!(h.dirty_pages(), 32);
  }
  h.os().purge_fails.store(false, Ordering::Relaxed);
  let before = h.maintenance_stats();
  h.purge();
  let w = work_since(before, h.maintenance_stats());
  assert_eq!((w[RUNS], w[FAILED], w[PURGED_PAGES]), (1, 0, 32));
  assert_eq!(h.dirty_pages(), 0);
}

#[test]
fn busy_shards_are_skipped_and_counted() {
  let h = heap();
  let before = h.maintenance_stats();
  h.with_shard_held(5, || h.purge());
  let w = work_since(before, h.maintenance_stats());
  assert_eq!((w[TRIMMED], w[BUSY]), (crate::core::SHARDS as u64 - 1, 1));
}

#[test]
fn contended_inline_passes_are_counted_as_skipped() {
  let h = heap();
  let runs = dirty_runs(h, DIRTY_BUDGET_PAGES as usize + 2 * RUN);
  let before = h.maintenance_stats();
  h.with_purge_lock_held(|| {
    for o in runs {
      free(h, o);
    }
  });
  let w = work_since(before, h.maintenance_stats());
  // The two frees past the budget found the purge lock taken.
  assert_eq!(w[SKIPPED], 2);
  assert_eq!(
    h.maintenance_stats().inline_budget_passes,
    before.inline_budget_passes
  );
  assert_eq!(h.dirty_pages(), DIRTY_BUDGET_PAGES as usize + 2 * RUN);
}

#[test]
fn hard_limit_interventions_are_counted() {
  let h = heap();
  h.attach_maintenance();
  let runs = dirty_runs(h, DIRTY_HARD_LIMIT_PAGES as usize + RUN);
  let before = h.maintenance_stats();
  for o in runs {
    free(h, o);
  }
  let after = h.maintenance_stats();
  let w = work_since(before, after);
  assert_eq!(w[HARD_LIMIT], 1);
  assert_eq!(after.inline_budget_passes - before.inline_budget_passes, 1);
}

#[test]
fn trimming_counts_released_pages() {
  let h = heap();
  let size = 1000;
  let n = 2 * PAGE_SIZE / size;
  let offs: Vec<_> = (0..n).map(|_| alloc(h, 0, size, 8)).collect();
  let pages = h.usage().small_pages;
  assert!(pages >= 2);
  for o in offs {
    free(h, o);
  }
  let before = h.maintenance_stats();
  h.purge();
  let after = h.maintenance_stats();
  let w = work_since(before, after);
  // All but the class's newest page, which trimming keeps.
  assert_eq!(w[RELEASED], pages as u64 - 1);
  assert_eq!(after.kept_newest_pages - before.kept_newest_pages, 1);
  assert_eq!(h.usage().small_pages, 1);
}

#[test]
fn a_kept_page_is_purged_once_it_has_been_kept_for_the_delay() {
  let h = heap();
  h.set_reconcile_epochs(0);
  let a = alloc(h, 0, 1000, 8);
  free(h, a);
  let purged = || h.os().purged.load(Ordering::Relaxed);
  // The first decay sweep finds the page fully free and keeps it, the
  // newest of its class; every sweep checks it again, and the one that
  // comes a purge delay later purges its memory.
  for _ in 0..DECAY_AGE {
    assert_eq!(decay_trim(h), (1, 0, 0, 0, 1));
    assert_eq!(purged(), 0);
  }
  assert_eq!(decay_trim(h), (1, 0, 0, 0, 1));
  assert_eq!(purged(), PAGE_SIZE);
  // Purged, it is no candidate any more: later sweeps leave it alone.
  assert_eq!(decay_trim(h), (0, 0, 0, 0, 0));
  assert_eq!(h.usage().small_pages, 1);
  // A block claimed from it makes it an ordinary page again. Freed, it is
  // kept anew, and a force purge purges it at once, only once.
  let b = alloc(h, 0, 1000, 8);
  assert_eq!(b / PAGE_SIZE, a / PAGE_SIZE);
  free(h, b);
  h.purge();
  assert_eq!(purged(), 2 * PAGE_SIZE);
  h.purge();
  assert_eq!(purged(), 2 * PAGE_SIZE);
  h.check_indexes();
}

#[test]
fn trimming_keeps_the_newest_page_of_a_class() {
  let h = heap();
  // A class size, so that the blocks fill whole pages.
  let size = 1024;
  let per_page = PAGE_SIZE / size;
  // Two pages of the class: the lower one first, then the newest.
  let offs: Vec<_> = (0..2 * per_page).map(|_| alloc(h, 0, size, 8)).collect();
  let (low, newest) = (offs[0] / PAGE_SIZE, offs[2 * per_page - 1] / PAGE_SIZE);
  assert!(low < newest);
  for o in offs {
    free(h, o);
  }
  let trim = || {
    let before = h.maintenance_stats();
    h.purge();
    h.check_indexes();
    let after = h.maintenance_stats();
    (
      after.released_pages - before.released_pages,
      after.kept_newest_pages - before.kept_newest_pages,
    )
  };
  assert_eq!(trim(), (1, 1));
  assert_eq!((h.usage().small_pages, h.newest_pages()), (1, 1));
  // The kept page still serves its class, but the lower page, now free,
  // comes first and becomes the newest page of the class.
  let x = alloc(h, 0, size, 8);
  assert_eq!(x / PAGE_SIZE, low);
  // The page that was the newest is released on the next pass, without
  // another free to make it a candidate.
  assert_eq!(trim(), (1, 0));
  assert_eq!(h.usage().small_pages, 1);
  // The newest page is kept once its last block is freed.
  free(h, x);
  assert_eq!(trim(), (0, 1));
  assert_eq!(h.usage().small_pages, 1);
}

#[test]
fn a_full_word_is_flushed_in_one_update() {
  let h = heap();
  let tc = cache(h);
  // One claimed word of the 16-byte class holds 64 blocks.
  let offs: Vec<_> = (0..64).map(|_| alloc_c(h, &tc, 16, 8)).collect();
  assert_eq!(h.cache_stats(&tc).claimed_blocks, 0);
  for o in offs {
    free_c(h, &tc, o);
  }
  let s = h.cache_stats(&tc);
  assert_eq!((s.buffered_blocks, s.buffered_words, s.flushes), (64, 1, 0));
  h.flush(&tc);
  let s = h.cache_stats(&tc);
  assert_eq!((s.buffered_blocks, s.flushes, s.flushed_blocks), (0, 1, 64));
  assert_eq!(s.flush_sizes, [0, 0, 0, 0, 0, 0, 1]);
  assert_eq!((s.evictions, s.refill_flushes), (0, 0));
}

#[test]
fn small_classes_claim_across_bitmap_word_boundaries() {
  let h = heap();
  for size in [16, 32] {
    let tc = cache(h);
    // 129 blocks cross both 64-bit bitmap-word boundaries while remaining
    // small enough to stay within one page for either class.
    let offs: Vec<_> = (0..129).map(|_| alloc_c(h, &tc, size, 8)).collect();
    assert_eq!(
      offs.iter().copied().collect::<BTreeSet<_>>().len(),
      offs.len()
    );
    let pages: BTreeSet<_> = offs.iter().map(|o| o / PAGE_SIZE).collect();
    let mut words = std::collections::BTreeMap::<usize, usize>::new();
    for o in &offs {
      *words.entry(o % PAGE_SIZE / (64 * size)).or_default() += 1;
    }
    let mut word_counts: Vec<_> = words.values().copied().collect();
    word_counts.sort_unstable();
    assert_eq!(pages.len(), 1);
    assert_eq!(word_counts, [1, 64, 64]);
    for o in offs {
      free_c(h, &tc, o);
    }
    h.retire(&tc);
    h.check_indexes();
  }
  assert_eq!(h.usage().small_bytes_out, 0);
}

/// Allocated bitmap words of which `k` share a free-buffer set: `k` distinct
/// words, in the order they were claimed. Under Miri, use full pages of the
/// largest small class so the same 70-word pigeonhole topology needs 560
/// allocations instead of 4,480; the separate 129-block fixture covers the
/// small-class word boundaries.
fn words_in_one_set(h: &Heap<MockOs>, tc: &ThreadCache, k: usize) -> (Vec<usize>, Vec<Vec<usize>>) {
  let c = if cfg!(miri) {
    crate::core::class::NUM_CLASSES - 1
  } else {
    crate::core::class::class_of(16)
  };
  let size = crate::core::class::size(c);
  let blocks_per_word = crate::core::class::capacity(c).min(64);
  // Seventy words in 32 sets: some set gets at least three.
  let offs: Vec<_> = (0..blocks_per_word * 70)
    .map(|_| alloc_c(h, tc, size, 8))
    .collect();
  let pages: BTreeSet<_> = offs.iter().map(|offset| offset / PAGE_SIZE).collect();
  if cfg!(miri) {
    assert_eq!(size, 8192);
    assert_eq!(pages.len(), 70);
    assert_eq!(blocks_per_word, crate::core::class::capacity(c));
  }
  let mut by_set: std::collections::BTreeMap<usize, Vec<Vec<usize>>> = Default::default();
  let mut distinct_words = BTreeSet::new();
  for w in offs.chunks(blocks_per_word) {
    assert_eq!(w.len(), blocks_per_word);
    let page = w[0] / PAGE_SIZE;
    let word = w[0] % PAGE_SIZE / (64 * size);
    assert!(
      w.iter()
        .all(|offset| { offset / PAGE_SIZE == page && offset % PAGE_SIZE / (64 * size) == word })
    );
    assert!(distinct_words.insert((page, word)));
    by_set
      .entry(Heap::<MockOs>::free_set_of(w[0], c))
      .or_default()
      .push(w.to_vec());
  }
  assert_eq!(distinct_words.len(), 70);
  let words = by_set
    .into_values()
    .find(|v| v.len() >= k)
    .expect("70 distinct words in 32 sets of two")
    .into_iter()
    .take(k)
    .collect();
  (offs, words)
}

/// Frees through `tc` every block of `offs` not in `freed`, then retires
/// `tc`, so the heap ends empty.
fn free_rest(h: &Heap<MockOs>, tc: &ThreadCache, offs: &[usize], freed: &[usize]) {
  for &o in offs.iter().filter(|o| !freed.contains(o)) {
    free_c(h, tc, o);
  }
  h.retire(tc);
}

#[test]
fn a_third_word_in_a_set_evicts_the_older_way() {
  let h = heap();
  let tc = cache(h);
  let (offs, w) = words_in_one_set(h, &tc, 3);
  let (a, b, c) = (&w[0], &w[1], &w[2]);
  // Interleaved frees of two words of one set: both ways, no eviction.
  for o in [a[0], b[0], a[1], b[1]] {
    free_c(h, &tc, o);
  }
  let s = h.cache_stats(&tc);
  assert_eq!((s.evictions, s.flushes), (0, 0));
  assert_eq!((s.buffered_blocks, s.buffered_words), (4, 2));
  // A third word evicts the older way (a's two blocks, in one update).
  free_c(h, &tc, c[0]);
  let s = h.cache_stats(&tc);
  assert_eq!((s.evictions, s.flushes, s.flushed_blocks), (1, 1, 2));
  assert_eq!(s.flush_sizes[1], 1);
  // b is still buffered, in the other way.
  free_c(h, &tc, b[2]);
  assert_eq!(h.cache_stats(&tc).evictions, 1);
  // a again: now b is the older way (round robin), with three blocks.
  free_c(h, &tc, a[2]);
  let t = h.cache_stats(&tc);
  assert_eq!((t.evictions, t.flushed_blocks), (2, 5));
  assert_eq!(t.flush_sizes[1], 2);
  assert_eq!((t.buffered_blocks, t.buffered_words), (2, 2));
  Heap::<MockOs>::check_free_buffer(&tc);
  free_rest(h, &tc, &offs, &[a[0], a[1], a[2], b[0], b[1], b[2], c[0]]);
}

#[test]
fn refills_count_their_search() {
  let h = heap();
  let tc = cache(h);
  let before = h.search_stats();
  let first = alloc_c(h, &tc, 16, 8);
  let s = h.search_stats();
  // A fresh heap: the refill finds no page (the shard has no segment),
  // takes a new segment and sets up its first page for the class.
  assert_eq!(
    (
      s.refills - before.refills,
      s.pages_inspected - before.pages_inspected,
      s.full_pages_passed - before.full_pages_passed,
      s.new_pages - before.new_pages,
      s.run_searches - before.run_searches,
      s.new_segments - before.new_segments,
    ),
    (1, 0, 0, 1, 0, 1)
  );
  // The next 64 allocations empty the claimed word and claim the next word
  // of the same page, the first the search looks at.
  let rest: Vec<_> = (0..64).map(|_| alloc_c(h, &tc, 16, 8)).collect();
  let t = h.search_stats();
  assert_eq!(
    (
      t.refills - s.refills,
      t.pages_inspected - s.pages_inspected,
      t.full_pages_passed - s.full_pages_passed,
      t.new_pages - s.new_pages
    ),
    (1, 1, 0, 0)
  );
  for o in rest.into_iter().chain([first]) {
    free_c(h, &tc, o);
  }
  h.retire(&tc);
}

#[test]
fn usage_tells_memory_apart() {
  let h = heap();
  let small = alloc(h, 0, 16, 8);
  let run = alloc(h, 0, 8 * PAGE_SIZE, 8);
  let huge = alloc(h, 0, 20 << 20, 8);
  let u = h.usage();
  let cap = crate::core::class::capacity(crate::core::class::class_of(16));
  assert_eq!((u.owned_segments, u.huge_segments), (1, 5));
  assert_eq!((u.pages_in_use, u.small_pages), (9, 1));
  assert_eq!(
    (u.small_bytes_out, u.small_bytes_free),
    (16, (cap - 1) * 16)
  );
  assert_eq!((u.dirty_pages, u.clean_pages), (0, 54));
  free(h, run);
  free(h, huge);
  let u = h.usage();
  assert_eq!(
    (
      u.huge_segments,
      u.pages_in_use,
      u.dirty_pages,
      u.clean_pages
    ),
    (0, 1, 8, 54)
  );
  assert_eq!(u.dirty_pages, h.dirty_pages());
  h.purge();
  let u = h.usage();
  assert_eq!((u.pages_in_use, u.dirty_pages, u.clean_pages), (1, 0, 62));
  free(h, small);
  h.purge();
  // The small page, the newest of its class, stays, with nothing out.
  let u = h.usage();
  assert_eq!(
    (u.pages_in_use, u.small_pages, u.small_bytes_out),
    (1, 1, 0)
  );
  assert_eq!(u.dirty_pages, h.dirty_pages());
}

// ---- bounded, resumable reclamation (theory-driven plan, Stage B) -----------

use crate::core::{ReclaimTargets, ReclaimTargetsError, Retention};

/// Runs maintenance rounds until nothing is pending (at most `max`), and
/// returns how many ran.
fn maintain_until_idle(h: &Heap<MockOs>, max: usize) -> usize {
  for n in 0..max {
    if h.next_task(crate::core::Os::now_ms(h.os())).is_none() {
      return n;
    }
    let _ = h.maintain();
  }
  panic!(
    "maintenance still busy after {max} rounds: {:?}",
    h.reclaim_status()
  );
}

#[test]
fn reclaim_targets_are_validated() {
  let d = ReclaimTargets::DEFAULT;
  assert_eq!(
    (d.low_pages(), d.trigger_pages(), d.emergency_pages()),
    (
      0,
      DIRTY_BUDGET_PAGES as usize,
      DIRTY_HARD_LIMIT_PAGES as usize
    )
  );
  assert_eq!(
    ReclaimTargets::new(0, 0, 10),
    Err(ReclaimTargetsError::ZeroTrigger)
  );
  assert_eq!(
    ReclaimTargets::new(10, 10, 20),
    Err(ReclaimTargetsError::Order)
  );
  assert_eq!(
    ReclaimTargets::new(0, 21, 20),
    Err(ReclaimTargetsError::Order)
  );
  assert_eq!(
    ReclaimTargets::new(0, 1, 1 << 21),
    Err(ReclaimTargetsError::TooLarge)
  );
  let max = crate::core::MAX_SEGMENTS * crate::core::PAGES_PER_SEGMENT;
  assert!(ReclaimTargets::new(max - 2, max - 1, max).is_ok());
  // Bytes round down to whole pages.
  let t = ReclaimTargets::from_bytes(PAGE_SIZE + 1, 3 * PAGE_SIZE - 1, 4 * PAGE_SIZE).unwrap();
  assert_eq!(
    (t.low_pages(), t.trigger_pages(), t.emergency_pages()),
    (1, 2, 4)
  );
  assert_eq!(
    ReclaimTargets::from_bytes(0, PAGE_SIZE - 1, PAGE_SIZE),
    Err(ReclaimTargetsError::ZeroTrigger)
  );
  let h = heap();
  h.set_reclaim_targets(t);
  assert_eq!(h.reclaim_targets(), t);
  assert_eq!(h.reclaim_status().targets, t);
}

/// Nine 8-page runs in shard 3: seven fill one segment (56 pages), two go
/// to a second one. Freeing them all leaves 72 dirty pages.
fn nine_runs(h: &Heap<MockOs>) -> Vec<usize> {
  (0..9).map(|_| alloc(h, 3, 8 * PAGE_SIZE, 8)).collect()
}

#[test]
fn budget_cycles_purge_down_to_the_low_target() {
  let h = heap();
  h.set_reclaim_targets(ReclaimTargets::new(16, 64, 1024).unwrap());
  let runs = nine_runs(h);
  for (i, o) in runs.into_iter().enumerate() {
    free(h, o);
    // Up to the trigger, frees only mark pages dirty.
    if i < 8 {
      assert_eq!(h.dirty_pages(), 8 * (i + 1));
    }
  }
  // The free that crossed the trigger ran the cycle's slice inline: it
  // purged the first segment (56 pages) and stopped at the low target,
  // keeping the second segment's 16 pages for reuse.
  assert_eq!(h.dirty_pages(), 16);
  let s = h.reclaim_status();
  assert!(!s.budget_pending && s.sweep.is_none(), "{s:?}");
  let m = h.maintenance_stats();
  assert_eq!((m.inline_budget_passes, m.inline_slices), (1, 1));
  // With the default targets, the same frees purge everything, as the
  // budget pass did.
  let h = heap();
  for o in nine_runs(h) {
    free(h, o);
  }
  assert!(h.dirty_pages() <= crate::core::heap::DIRTY_BUDGET_PAGES as usize);
}

#[test]
fn cycles_continue_below_the_trigger_until_the_low_target() {
  let h = heap();
  h.attach_maintenance();
  h.set_reclaim_targets(ReclaimTargets::new(8, 64, 1024).unwrap());
  // Slices small enough that the cycle takes many of them.
  h.set_slice_work(1);
  for o in nine_runs(h) {
    free(h, o);
  }
  assert_eq!(h.dirty_pages(), 72);
  assert!(h.reclaim_status().budget_pending);
  let mut below_trigger = 0;
  let mut slices = 0;
  while h.reclaim_status().budget_pending {
    assert_eq!(h.maintain(), Some(Task::Budget));
    slices += 1;
    let d = h.dirty_pages();
    if (8..=64).contains(&d) && h.reclaim_status().budget_pending {
      // Below the trigger, above the low target: still pending.
      below_trigger += 1;
      assert_eq!(h.next_task(0), Some(Task::Budget));
    }
    assert!(slices < 1000);
  }
  assert!(slices > 1 && below_trigger > 0, "{slices} {below_trigger}");
  assert!(h.dirty_pages() <= 8);
  assert_eq!(h.maintenance_stats().budget_passes, 1);
  assert_eq!(h.maintenance_stats().slices, slices);
}

#[test]
fn slices_bound_attempted_work_when_every_purge_fails() {
  let h = heap();
  h.attach_maintenance();
  let work = 64;
  h.set_slice_work(work);
  // 96 runs of 8 pages over 14 segments: 768 dirty pages.
  let runs = dirty_runs(h, 96 * RUN);
  h.os().purge_fails.store(true, Ordering::Relaxed);
  for o in runs {
    free(h, o);
  }
  let dirty = h.dirty_pages();
  assert_eq!(dirty, 96 * RUN);
  let mut rounds = 0;
  loop {
    let before = h.maintenance_stats();
    match h.maintain() {
      Some(Task::Budget) => {}
      Some(t) => panic!("unexpected {t:?}"),
      None => break,
    }
    let after = h.maintenance_stats();
    // Each slice attempts a bounded number of runs, all refused: at most
    // the limit, plus the runs of the one segment that crossed it.
    assert!(after.purged_runs - before.purged_runs <= work + 32);
    assert_eq!(
      after.failed_runs - before.failed_runs,
      after.purged_runs - before.purged_runs
    );
    rounds += 1;
    assert!(rounds < 1000, "the cycle never gave up");
  }
  // One full sweep without progress stalls the cycle: nothing purged, the
  // obligation visible, and no more budget work until the next epoch.
  let s = h.reclaim_status();
  assert!(s.budget_deferred && !s.budget_pending, "{s:?}");
  assert_eq!(h.maintenance_stats().stalled_cycles, 1);
  assert_eq!(h.dirty_pages(), dirty);
  assert_eq!(h.next_task(0), None);
  // The thread went to sleep on the deferred request instead of spinning.
  assert_eq!(h.maintain(), None);
  // The next decay epoch lifts the deferral, and purges work again.
  h.os().purge_fails.store(false, Ordering::Relaxed);
  h.os().advance(h.decay_interval_ms());
  maintain_until_idle(h, 1000);
  assert_eq!(h.dirty_pages(), 0);
}

#[test]
fn stalled_cycles_leave_frees_alone_until_the_emergency_threshold() {
  let h = heap();
  h.set_slice_work(64);
  h.os().purge_fails.store(true, Ordering::Relaxed);
  let budget = DIRTY_BUDGET_PAGES as usize;
  // Allocated up front: allocations would reuse the dirty pages.
  let mut runs = dirty_runs(h, DIRTY_HARD_LIMIT_PAGES as usize + 8 * RUN).into_iter();
  // Up to the trigger and past it: the crossing free starts a cycle and
  // later frees continue it until a full sweep stalls.
  for o in runs.by_ref().take(budget / RUN + 20) {
    free(h, o);
  }
  assert!(
    h.reclaim_status().budget_deferred,
    "{:?}",
    h.reclaim_status()
  );
  let slices = h.maintenance_stats().slices;
  // More frees below the emergency threshold run no slice ...
  for o in runs.by_ref().take(20) {
    free(h, o);
  }
  assert_eq!(h.maintenance_stats().slices, slices);
  // ... past it, every free runs a bounded emergency slice.
  for o in runs {
    free(h, o);
  }
  let m = h.maintenance_stats();
  assert!(m.emergency_slices > 0 && m.hard_limit_slices == 0, "{m:?}");
  h.os().purge_fails.store(false, Ordering::Relaxed);
  h.purge();
  assert_eq!(h.dirty_pages(), 0);
}

#[test]
fn partial_batch_success_finishes_every_claim() {
  let h = heap();
  h.attach_maintenance();
  let runs = dirty_runs(h, DIRTY_BUDGET_PAGES as usize + 8 * RUN);
  for o in runs {
    free(h, o);
  }
  let mut p = MockPurger::new(h.os(), 4);
  p.fail_every = 3;
  while h.next_task(0) == Some(Task::Budget) {
    let _ = h.maintain_with(&mut p);
  }
  // Every third run failed and stays dirty; the others are clean, and no
  // page is left claimed by the purge.
  let m = h.maintenance_stats();
  assert!(m.failed_runs > 0 && m.failed_runs < m.purged_runs, "{m:?}");
  assert!(h.dirty_pages() > 0);
  assert_eq!(h.dirty_pages(), h.dirty_pages_recounted());
  let u = h.usage();
  assert_eq!((u.pages_in_use, u.dirty_pages), (0, h.dirty_pages()));
}

#[test]
fn wrapped_batches_credit_each_segment_its_own_runs() {
  let h = heap();
  h.attach_maintenance();
  h.set_reclaim_targets(ReclaimTargets::new(8, 40, 1024).unwrap());
  // Segment x holds runs 0..7, segment y runs 7 and 8 (see `nine_runs`);
  // the last run of each stays live so that trimming returns neither.
  let runs = nine_runs(h);
  let (x, y) = (runs[0] / SEGMENT_SIZE, runs[7] / SEGMENT_SIZE);
  assert!(x < y && runs[6] / SEGMENT_SIZE == x && runs[8] / SEGMENT_SIZE == y);
  for &o in runs[..6].iter().chain(&runs[7..8]) {
    free(h, o);
  }
  assert_eq!(h.dirty_pages(), 56);
  // A budget cycle claims x, reaches the low target on paper and stops:
  // the next sweep starts after x. Every purge fails, so nothing changes.
  let mut p = MockPurger::new(h.os(), PURGE_BATCH);
  p.fail_every = 1;
  assert_eq!(h.maintain_with(&mut p), Some(Task::Budget));
  assert_eq!(h.dirty_pages(), 56);
  // A force sweep from there visits y, wraps round the arena and ends with
  // x, all in one batch: y's run fails, x's succeeds.
  h.request_purge();
  let mut p = MockPurger::new(h.os(), PURGE_BATCH);
  p.fail_every = 2;
  p.runs = 1;
  while h.next_task(0) == Some(Task::Force) {
    let _ = h.maintain_with(&mut p);
  }
  assert_eq!(p.batches, 1);
  // y's 8 pages stay dirty and x's are clean, not the other way round.
  assert_eq!(h.dirty_pages(), 8);
  assert_eq!(h.dirty_pages(), h.dirty_pages_recounted());
  // Handing y's pages out again does not claim they are zero.
  free(h, runs[6]);
  free(h, runs[8]);
  h.detach_maintenance();
  let again = alloc(h, 3, 8 * PAGE_SIZE, 8);
  free(h, again);
}

#[test]
fn busy_shards_do_not_hold_up_later_ones() {
  let h = heap();
  h.set_slice_work(4);
  // A fully free small page in shard 40, followed by the newest page of
  // its class, which trimming keeps.
  let offs: Vec<_> = (0..2 * PAGE_SIZE / 1024)
    .map(|_| alloc(h, 40, 1024, 8))
    .collect();
  for o in offs {
    free(h, o);
  }
  let before = h.maintenance_stats();
  // Shard 5 stays locked for a whole force purge of many small slices.
  h.with_shard_held(5, || h.purge());
  let w = work_since(before, h.maintenance_stats());
  assert_eq!((w[BUSY], w[RELEASED]), (1, 1));
  assert_eq!(h.usage().small_pages, 1);
}

#[test]
fn resumed_sweeps_survive_segment_reuse() {
  let h = heap();
  h.attach_maintenance();
  h.set_slice_work(3);
  // Dirty pages and empty segments in several shards.
  let mut runs = Vec::new();
  for s in 0..6 {
    runs.extend((0..10).map(|_| alloc(h, s, 6 * PAGE_SIZE, 8)));
  }
  for o in runs.drain(..) {
    free(h, o);
  }
  h.request_purge();
  let mut held: Vec<usize> = Vec::new();
  let mut rounds = 0;
  while h.next_task(0) == Some(Task::Force) {
    let _ = h.maintain();
    // Between slices, other threads take segments the sweep returned or is
    // about to visit: huge blocks, runs in the shards being trimmed (new
    // segments linked ahead of the sweep's position), and frees.
    match rounds % 4 {
      0 => held.push(alloc(h, 0, 5 << 20, 8)),
      1 => held.push(alloc(h, rounds % 6, 20 * PAGE_SIZE, 8)),
      2 if !held.is_empty() => free(h, held.swap_remove(0)),
      _ => held.push(alloc(h, 7, 100, 8)),
    }
    rounds += 1;
    assert!(rounds < 10_000);
  }
  assert!(rounds > 10, "the sweep should take many slices");
  assert_eq!(h.dirty_pages(), h.dirty_pages_recounted());
  crate::core::model::check_observations(h, &[]);
  for o in held {
    free(h, o);
  }
  h.detach_maintenance();
  h.purge();
  assert_eq!(h.dirty_pages(), 0);
}

#[test]
fn many_slices_do_not_age_pages_faster() {
  // `decay_waits_for_the_purge_delay`, with slices of one work unit: a
  // decay pass takes hundreds of slices, and ages still move one epoch
  // per pass.
  let h = heap();
  h.set_slice_work(1);
  let runs: Vec<_> = (0..8).map(|_| alloc(h, 2, 5 * PAGE_SIZE, 8)).collect();
  for &o in &runs[..4] {
    free(h, o);
  }
  let slices = h.maintenance_stats().slices;
  for _ in 0..2 {
    h.decay();
  }
  assert!(h.maintenance_stats().slices - slices > 100);
  for &o in &runs[4..] {
    free(h, o);
  }
  for _ in 2..DECAY_AGE - 1 {
    h.decay();
  }
  assert_eq!(h.dirty_pages(), 40);
  h.decay();
  assert_eq!(h.dirty_pages(), 20, "only the first four runs expired");
  h.decay();
  assert_eq!(h.dirty_pages(), 20);
  h.decay();
  assert_eq!(h.dirty_pages(), 0);
}

#[test]
fn target_changes_apply_to_the_cycle_in_progress() {
  let h = heap();
  h.attach_maintenance();
  h.set_reclaim_targets(ReclaimTargets::new(0, 64, 1024).unwrap());
  h.set_slice_work(2);
  for o in nine_runs(h) {
    free(h, o);
  }
  assert_eq!(h.maintain(), Some(Task::Budget));
  assert_eq!(h.reclaim_status().sweep, Some(Task::Budget));
  // A low target above the dirty count ends the cycle at its next slice,
  // with nothing more purged.
  h.set_reclaim_targets(ReclaimTargets::new(100, 200, 1024).unwrap());
  assert_eq!(h.maintain(), Some(Task::Budget));
  let s = h.reclaim_status();
  assert!(s.sweep.is_none() && !s.budget_pending, "{s:?}");
  assert_eq!(h.dirty_pages(), 72);
  assert_eq!(h.next_task(0), None);
}

#[test]
fn purge_delay_changes_leave_the_sweep_in_progress_alone() {
  let h = heap();
  h.attach_maintenance();
  h.set_slice_work(1);
  let runs: Vec<_> = (0..4).map(|_| alloc(h, 2, 5 * PAGE_SIZE, 8)).collect();
  for o in runs {
    free(h, o);
  }
  // A decay sweep starts with the 1 s delay: nothing is old enough.
  h.os().advance(1000);
  assert_eq!(h.maintain(), Some(Task::Decay));
  assert_eq!(h.reclaim_status().sweep, Some(Task::Decay));
  // A zero delay applies from the next sweep on, not to this one.
  h.set_purge_delay_ms(0);
  while h.reclaim_status().sweep == Some(Task::Decay) {
    let _ = h.maintain();
  }
  assert_eq!(h.dirty_pages(), 20);
  h.os().advance(1);
  maintain_until_idle(h, 10_000);
  assert_eq!(h.dirty_pages(), 0);
}

#[test]
fn detached_maintenance_leaves_the_cycle_to_frees_and_allocations() {
  let h = heap();
  h.attach_maintenance();
  h.set_reclaim_targets(ReclaimTargets::new(0, 64, 1024).unwrap());
  h.set_slice_work(2);
  for o in nine_runs(h) {
    free(h, o);
  }
  // The thread ran one slice, then went away (a fork, say).
  assert_eq!(h.maintain(), Some(Task::Budget));
  h.detach_maintenance();
  assert!(h.reclaim_status().budget_pending);
  // Allocation slow paths (cached page-run allocations and frees, every
  // 16th of which checks) finish the cycle.
  let tc = cache(h);
  let mut ops = 0;
  while h.reclaim_status().budget_pending {
    let o = alloc_c(h, &tc, 3 * PAGE_SIZE, 8);
    free_c(h, &tc, o);
    ops += 1;
    assert!(ops < 100_000, "{:?}", h.reclaim_status());
  }
  assert!(h.dirty_pages() <= 8, "{}", h.dirty_pages());
  h.retire(&tc);
}

#[test]
fn without_a_worker_page_run_frees_resume_the_cycle() {
  let h = heap();
  h.set_reclaim_targets(ReclaimTargets::new(0, 64, 1024).unwrap());
  h.set_slice_work(2);
  for o in nine_runs(h) {
    free(h, o);
  }
  // The crossing free ran one small slice; the cycle is pending.
  assert!(h.reclaim_status().budget_pending);
  assert_eq!(h.maintenance_stats().inline_slices, 1);
  let mut frees = 0;
  while h.reclaim_status().budget_pending {
    let o = alloc(h, 9, PAGE_SIZE * 2, 8);
    free(h, o);
    frees += 1;
    assert!(frees < 100_000);
  }
  assert!(h.maintenance_stats().inline_slices > 1);
  assert!(h.dirty_pages() <= 8, "{}", h.dirty_pages());
}

#[test]
fn force_purges_preempt_a_budget_cycle() {
  let h = heap();
  h.attach_maintenance();
  h.set_reclaim_targets(ReclaimTargets::new(0, 64, 1024).unwrap());
  h.set_slice_work(2);
  for o in nine_runs(h) {
    free(h, o);
  }
  assert_eq!(h.maintain(), Some(Task::Budget));
  assert_eq!(h.reclaim_status().sweep, Some(Task::Budget));
  // A request goes ahead of the cycle in progress ...
  h.request_purge();
  assert_eq!(h.next_task(0), Some(Task::Force));
  assert_eq!(h.maintain(), Some(Task::Force));
  assert_eq!(h.reclaim_status().sweep, Some(Task::Force));
  // ... and an explicit purge replaces whatever runs and finishes.
  h.purge();
  let s = h.reclaim_status();
  assert_eq!(h.dirty_pages(), 0);
  assert!(s.sweep.is_none(), "{s:?}");
  // The cycle, now below its low target, ended with it.
  maintain_until_idle(h, 1000);
  assert!(!h.reclaim_status().budget_pending);
}

#[test]
fn emergency_slices_are_larger_but_bounded() {
  let h = heap();
  h.attach_maintenance();
  h.set_slice_work(16);
  let runs = dirty_runs(h, DIRTY_HARD_LIMIT_PAGES as usize + 16 * RUN);
  let mut worst = 0;
  for o in runs {
    let before = h.maintenance_stats().purged_runs;
    free(h, o);
    worst = worst.max(h.maintenance_stats().purged_runs - before);
  }
  let m = h.maintenance_stats();
  assert!(
    m.emergency_slices > 0 && m.hard_limit_slices == m.emergency_slices,
    "{m:?}"
  );
  // Four ordinary slices' worth of runs, plus one segment's.
  assert!(worst > 0 && worst <= 4 * 16 + 32, "{worst}");
  assert!(h.dirty_pages() <= DIRTY_HARD_LIMIT_PAGES as usize + RUN);
}

#[test]
fn adaptive_retention_follows_reuse_and_idleness() {
  let h = heap();
  assert_eq!(h.reclaim_status().retention, 1);
  h.set_retention(Retention::Adaptive);
  // Epochs in which freed page runs are reused before any purge: the
  // retention grows, one step per delay (four epochs) at most.
  let mut last = 1;
  for epoch in 0..40 {
    let o = alloc(h, 1, 4 * PAGE_SIZE, 8);
    free(h, o);
    h.decay();
    let r = h.reclaim_status().retention;
    assert!(r >= last && r <= last + 1, "epoch {epoch}: {last} -> {r}");
    last = r;
  }
  assert_eq!(last, crate::core::MAX_RETENTION);
  // Pages now wait four times the delay (in epochs) before decay purges
  // them.
  let o = alloc(h, 1, 4 * PAGE_SIZE, 8);
  free(h, o);
  for _ in 0..DECAY_AGE {
    h.decay();
  }
  assert_eq!(h.dirty_pages(), 4, "kept past one delay");
  // Idle epochs bring it back down, step by step.
  for _ in 0..80 {
    h.decay();
  }
  assert_eq!(h.reclaim_status().retention, 1);
  assert_eq!(h.dirty_pages(), 0);
  // Explicit pressure resets it at once, and the fixed mode pins it.
  for _ in 0..40 {
    let o = alloc(h, 1, 4 * PAGE_SIZE, 8);
    free(h, o);
    h.decay();
  }
  assert!(h.reclaim_status().retention > 1);
  h.request_purge();
  assert_eq!(h.reclaim_status().retention, 1);
  h.set_retention(Retention::Fixed);
  assert_eq!(h.reclaim_status().retention_mode, Retention::Fixed);
}

// ---- thread caches: 2-way free buffer and cache return (Stage C) ----------

#[test]
fn interleaved_frees_of_one_set_batch_without_evictions() {
  let h = heap();
  let tc = cache(h);
  let (offs, w) = words_in_one_set(h, &tc, 2);
  let (a, b) = (&w[0], &w[1]);
  assert_eq!(a.len(), b.len());
  let blocks_per_word = a.len();
  // Every block of two words of one set, alternately. A direct-mapped buffer
  // would flush on every free after the first; two ways keep both words.
  for i in 0..blocks_per_word {
    free_c(h, &tc, a[i]);
    free_c(h, &tc, b[i]);
  }
  let s = h.cache_stats(&tc);
  assert_eq!((s.evictions, s.flushes), (0, 0));
  assert_eq!(
    (s.buffered_blocks, s.buffered_words),
    (2 * blocks_per_word as u64, 2)
  );
  h.flush(&tc);
  let s = h.cache_stats(&tc);
  // Two shared updates, one for each complete bitmap word.
  assert_eq!(
    (s.flushes, s.flushed_blocks),
    (2, 2 * blocks_per_word as u64)
  );
  let bucket = (usize::BITS - 1 - blocks_per_word.leading_zeros()) as usize;
  let mut expected_flush_sizes = [0; 7];
  expected_flush_sizes[bucket] = 2;
  assert_eq!(s.flush_sizes, expected_flush_sizes);
  let freed: Vec<usize> = a.iter().chain(b).copied().collect();
  free_rest(h, &tc, &offs, &freed);
}

#[test]
#[should_panic(expected = "double free")]
fn duplicate_free_in_the_first_way() {
  let h = heap();
  let tc = cache(h);
  let (_, w) = words_in_one_set(h, &tc, 2);
  for o in [w[0][0], w[1][0], w[0][0]] {
    h.dealloc_cached(&tc, o);
  }
}

#[test]
#[should_panic(expected = "double free")]
fn duplicate_free_in_the_second_way() {
  let h = heap();
  let tc = cache(h);
  let (_, w) = words_in_one_set(h, &tc, 2);
  for o in [w[0][0], w[1][0], w[1][0]] {
    h.dealloc_cached(&tc, o);
  }
}

#[test]
fn pending_masks_follow_evictions_across_classes() {
  let h = heap();
  let tc = cache(h);
  // Blocks of three classes, freed in an order that fills sets and evicts
  // across classes; the masks must name exactly each class's slots.
  //
  // Native stress keeps 2,560 blocks of each of three tiny classes and frees
  // all 7,680 in one seeded shuffle. Miri uses 24 full one-word pages of each
  // of three large small classes (816 blocks, all live together). Page runs
  // above `SMALL_MAX` never reach the free buffer. A fixed prefix frees one
  // block of every page, interleaving the classes, and must evict a word of
  // another class; the rest follow the same seeded shuffle. The separate
  // bitmap-word boundary tests keep multiword and 64-block flush coverage.
  let (sizes, counts) = if cfg!(miri) {
    ([4096, 6144, 8192], [24 * 16, 24 * 10, 24 * 8])
  } else {
    ([16, 48, 256], [64 * 40; 3])
  };
  let classes = sizes.map(crate::core::class::class_of);
  if cfg!(miri) {
    assert!(
      sizes
        .iter()
        .all(|&size| size <= crate::core::class::SMALL_MAX)
    );
    assert_eq!(classes.iter().collect::<BTreeSet<_>>().len(), 3);
    assert_eq!(classes.map(crate::core::class::size), sizes);
    assert_eq!(classes.map(crate::core::class::capacity), [16, 10, 8]);
    assert_eq!(classes.map(crate::core::class::bitmap_words), [1; 3]);
  }
  let mut offs: Vec<usize> = Vec::new();
  // The position in `sizes` of each allocation's class.
  let mut kinds: Vec<usize> = Vec::new();
  for (k, (&size, &count)) in sizes.iter().zip(&counts).enumerate() {
    offs.extend((0..count).map(|_| alloc_c(h, &tc, size, 8)));
    kinds.resize(offs.len(), k);
  }
  // Miri: a fixed prefix of one block per page, by page ordinal and then
  // class, so that sets fill with words of all three classes.
  let mut prefix: Vec<usize> = Vec::new();
  let mut cross_class_evictions = 0;
  let mut freed = std::vec![false; offs.len()];
  if cfg!(miri) {
    assert_eq!(offs.len(), 816);
    assert_eq!(offs.iter().collect::<BTreeSet<_>>().len(), offs.len());
    // Every claimed word was exhausted: nothing is left in the cache.
    assert_eq!(h.cache_stats(&tc).claimed_blocks, 0);
    let mut pages: [std::collections::BTreeMap<usize, Vec<usize>>; 3] = Default::default();
    let mut keys = BTreeSet::new();
    for (i, (&o, &k)) in offs.iter().zip(&kinds).enumerate() {
      let (page, word) = (o / PAGE_SIZE, o % PAGE_SIZE / (64 * sizes[k]));
      assert_eq!(word, 0);
      keys.insert((page, word, classes[k]));
      pages[k].entry(page).or_default().push(i);
    }
    assert_eq!(keys.len(), 72);
    for (k, by_page) in pages.iter().enumerate() {
      assert_eq!(keys.iter().filter(|key| key.2 == classes[k]).count(), 24);
      assert_eq!(by_page.len(), 24);
      let capacity = crate::core::class::capacity(classes[k]);
      assert!(by_page.values().all(|blocks| blocks.len() == capacity));
    }
    // `BTreeMap` order: each class's pages by address.
    let firsts = pages.map(|by_page| {
      by_page
        .into_values()
        .map(|blocks| blocks[0])
        .collect::<Vec<_>>()
    });
    for ordinal in 0..24 {
      prefix.extend(firsts.iter().map(|class_firsts| class_firsts[ordinal]));
    }
    assert_eq!(prefix.iter().collect::<BTreeSet<_>>().len(), 72);
    let pending = || classes.map(|c| Heap::<MockOs>::pending_slots(&tc, c));
    for &i in &prefix {
      let k = kinds[i];
      let (before, evictions) = (pending(), h.cache_stats(&tc).evictions);
      free_c(h, &tc, offs[i]);
      assert!(!std::mem::replace(&mut freed[i], true));
      let (after, s) = (pending(), h.cache_stats(&tc));
      assert_ne!(after[k], 0, "{s:?}");
      // Nothing but this free changes the buffer: other classes can only
      // lose a slot, and only to an eviction.
      let mut other_lost = false;
      for (j, (b, a)) in before.iter().zip(&after).enumerate() {
        if j != k {
          assert_eq!(a & !b, 0, "class {j} gained a slot: {s:?}");
          other_lost |= b & !a != 0;
        }
      }
      if s.evictions == evictions {
        assert!(!other_lost, "{s:?}");
      } else {
        assert_eq!(s.evictions, evictions + 1, "{s:?}");
        if other_lost {
          cross_class_evictions += 1;
        }
      }
    }
    Heap::<MockOs>::check_free_buffer(&tc);
    let s = h.cache_stats(&tc);
    assert!(cross_class_evictions > 0, "{s:?}");
    assert!(s.evictions > 0 && s.flushes > 0, "{s:?}");
    // Partial-word flushes: no word holds more than 16 blocks here.
    assert!(s.flush_sizes[..6].iter().any(|&n| n > 0), "{s:?}");
    assert_eq!(s.flush_sizes[6], 0, "{s:?}");
  }
  let mut in_prefix = std::vec![false; offs.len()];
  for &i in &prefix {
    in_prefix[i] = true;
  }
  let mut x = 0x9E37_79B9u64;
  let mut order: Vec<usize> = (0..offs.len()).collect();
  for i in (1..order.len()).rev() {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    order.swap(i, (x % (i as u64 + 1)) as usize);
  }
  // Native has no prefix, so this is the whole shuffled order.
  for (n, &i) in order.iter().filter(|&&i| !in_prefix[i]).enumerate() {
    free_c(h, &tc, offs[i]);
    if cfg!(miri) {
      assert!(!std::mem::replace(&mut freed[i], true));
    }
    if n % 97 == 0 {
      Heap::<MockOs>::check_free_buffer(&tc);
    }
  }
  Heap::<MockOs>::check_free_buffer(&tc);
  let s = h.cache_stats(&tc);
  assert!(s.evictions > 0, "{s:?}");
  // Everything freed is either flushed or still buffered, once.
  assert_eq!(
    s.flushed_blocks + s.buffered_blocks,
    offs.len() as u64,
    "{s:?}"
  );
  if cfg!(miri) {
    assert!(freed.iter().all(|&f| f));
    assert!(cross_class_evictions > 0, "{s:?}");
    assert_eq!(s.flush_sizes[6], 0, "{s:?}");
    assert!(h.os().live.lock().unwrap().is_empty());
  }
  h.retire(&tc);
  for c in 0..crate::core::class::NUM_CLASSES {
    assert_eq!(Heap::<MockOs>::pending_slots(&tc, c), 0);
  }
  assert_eq!(h.usage().small_bytes_out, 0);
  if cfg!(miri) {
    let s = h.cache_stats(&tc);
    assert_eq!((s.claimed_blocks, s.buffered_blocks), (0, 0), "{s:?}");
    Heap::<MockOs>::check_free_buffer(&tc);
    h.check_indexes();
  }
}

#[test]
fn a_refill_flushes_only_its_class_and_flush_the_rest() {
  let h = heap();
  let tc = cache(h);
  // Miri exhausts the same page topology using two bitmap words rather
  // than interpreting a 4096-allocation small-class page. Native stress
  // retains the 16-byte class and its full allocation count.
  let size = if cfg!(miri) { 512 } else { 16 };
  let c = crate::core::class::class_of(size);
  assert_eq!(crate::core::class::size(c), size);
  assert_ne!(c, crate::core::class::class_of(48));
  let y = alloc_c(h, &tc, 48, 8);
  // One whole page of the selected class, all handed out.
  let n = crate::core::class::capacity(c);
  assert_eq!(n, if cfg!(miri) { 128 } else { 4096 });
  assert!(n / u64::BITS as usize >= 2);
  let offs: Vec<_> = (0..n).map(|_| alloc_c(h, &tc, size, 8)).collect();
  assert_eq!(
    offs
      .iter()
      .map(|o| o / PAGE_SIZE)
      .collect::<BTreeSet<_>>()
      .len(),
    1
  );
  let x = offs[100];
  free_c(h, &tc, x);
  free_c(h, &tc, y);
  // The class has no free block but the buffered one: the refill returns
  // the class's buffered frees (not the other class's) and takes x again,
  // instead of a new page.
  let again = alloc_c(h, &tc, size, 8);
  assert_eq!(again, x);
  let s = h.cache_stats(&tc);
  assert_eq!((s.refill_flushes, s.flushes), (1, 1));
  assert_eq!((s.buffered_blocks, s.buffered_words), (1, 1));
  h.flush(&tc);
  let s = h.cache_stats(&tc);
  assert_eq!((s.buffered_blocks, s.claimed_blocks, s.flushes), (0, 0, 2));
  free_rest(h, &tc, &offs, &[]);
  assert_eq!(h.usage().small_bytes_out, 0);
}

#[test]
fn producer_consumer_frees_are_all_accounted_for() {
  let h = heap();
  let (p, c) = (cache(h), cache(h));
  let offs: Vec<_> = (0..1000)
    .map(|i| alloc_c(h, &p, 16 + i % 5 * 16, 8))
    .collect();
  // The consumer frees what the producer allocated.
  for &o in &offs {
    free_c(h, &c, o);
  }
  let (ps, cs) = (h.cache_stats(&p), h.cache_stats(&c));
  assert_eq!(cs.flushed_blocks + cs.buffered_blocks, 1000);
  // Out of the shared bitmaps: the producer's claimed blocks and the
  // consumer's buffered frees.
  let u = h.usage();
  assert!(u.small_bytes_out > 0 && ps.claimed_blocks > 0);
  h.flush(&c);
  // The producer allocates again from what the consumer returned.
  let again: Vec<_> = (0..1000)
    .map(|i| alloc_c(h, &p, 16 + i % 5 * 16, 8))
    .collect();
  for o in again {
    free_c(h, &p, o);
  }
  h.retire(&p);
  h.retire(&c);
  let (ps, cs) = (h.cache_stats(&p), h.cache_stats(&c));
  assert_eq!(
    (ps.claimed_blocks, ps.buffered_blocks, ps.attached),
    (0, 0, false)
  );
  assert_eq!(
    (cs.claimed_blocks, cs.buffered_blocks, cs.attached),
    (0, 0, false)
  );
  assert_eq!(h.usage().small_bytes_out, 0);
}

#[test]
fn free_only_threads_see_cache_return_requests() {
  let h = heap();
  let (p, c) = (cache(h), cache(h));
  let w: Vec<_> = (0..128).map(|_| alloc_c(h, &p, 16, 8)).collect();
  // The consumer only frees: two blocks of one word, then a request.
  free_c(h, &c, w[0]);
  h.request_cache_return();
  free_c(h, &c, w[1]);
  // A free into a word already buffered is the fast path: nothing seen.
  let s = h.cache_stats(&c);
  assert_eq!((s.pressure_returns, s.buffered_blocks), (0, 2));
  // The next free that needs a slot sees the request: the cache drains
  // (two blocks, one update), then buffers the new free.
  free_c(h, &c, w[64]);
  let s = h.cache_stats(&c);
  assert_eq!((s.pressure_returns, s.flushes, s.flushed_blocks), (1, 1, 2));
  assert_eq!((s.buffered_blocks, s.buffered_words), (1, 1));
  // Seen once: later frees do not drain again.
  free_c(h, &c, w[2]);
  assert_eq!(h.cache_stats(&c).pressure_returns, 1);
  free_rest(h, &c, &w, &[w[0], w[1], w[2], w[64]]);
  h.retire(&p);
}

#[test]
fn allocations_see_cache_return_requests() {
  let h = heap();
  let tc = cache(h);
  let a = alloc_c(h, &tc, 16, 8);
  // The cache holds the rest of a's word.
  assert_eq!(h.cache_stats(&tc).claimed_blocks, 63);
  h.request_cache_return();
  // Allocations from the claimed word see nothing ...
  let b = alloc_c(h, &tc, 16, 8);
  assert_eq!(h.cache_stats(&tc).pressure_returns, 0);
  // ... a refill (another class) does, and returns the 16-byte word first.
  let c = alloc_c(h, &tc, 48, 8);
  let s = h.cache_stats(&tc);
  assert_eq!((s.pressure_returns, s.claimed_blocks), (1, 63));
  assert_eq!(h.usage().small_bytes_out, 2 * 16 + 64 * 48);
  // A page run is a sampled point too.
  h.request_cache_return();
  let big = alloc_c(h, &tc, 100_000, 8);
  let s = h.cache_stats(&tc);
  assert_eq!((s.pressure_returns, s.claimed_blocks), (2, 0));
  for o in [a, b, c, big] {
    free_c(h, &tc, o);
  }
  h.retire(&tc);
}

#[test]
fn cache_return_generations_wrap() {
  let h = heap();
  h.set_cache_return_generation(u32::MAX);
  let tc = cache(h);
  let a = alloc_c(h, &tc, 16, 8);
  h.request_cache_return();
  assert_eq!(h.cache_return_generation(), 0);
  let b = alloc_c(h, &tc, 48, 8);
  let s = h.cache_stats(&tc);
  assert_eq!((s.pressure_returns, s.claimed_blocks), (1, 63));
  for o in [a, b] {
    free_c(h, &tc, o);
  }
  h.retire(&tc);
}

#[test]
fn caches_owe_only_requests_made_while_attached() {
  let h = heap();
  for _ in 0..3 {
    h.request_cache_return();
  }
  // A new cache owes nothing for earlier requests.
  let tc = cache(h);
  let a = alloc_c(h, &tc, 16, 8);
  let b = alloc_c(h, &tc, 48, 8);
  assert_eq!(h.cache_stats(&tc).pressure_returns, 0);
  // A reentrant attach keeps what the cache holds and what it owes.
  h.request_cache_return();
  h.attach(&tc);
  assert_eq!(h.cache_stats(&tc).claimed_blocks, 126);
  let c = alloc_c(h, &tc, 256, 8);
  assert_eq!(h.cache_stats(&tc).pressure_returns, 1);
  // A cache being attached, or retired, takes the uncached paths and is
  // never asked to drain.
  let attaching = ThreadCache::new();
  attaching.begin_attach();
  h.retire(&tc);
  h.request_cache_return();
  for t in [&tc, &attaching] {
    let big = alloc_c(h, t, 100_000, 8);
    free_c(h, t, big);
    let s = h.cache_stats(t);
    assert!(!s.attached && s.claimed_blocks == 0 && s.buffered_blocks == 0);
  }
  assert_eq!(h.cache_stats(&tc).pressure_returns, 1);
  assert_eq!(h.cache_stats(&attaching).pressure_returns, 0);
  for o in [a, b, c] {
    free(h, o);
  }
  assert_eq!(h.usage().small_bytes_out, 0);
}

/// A worker thread that allocates, frees and parks (waits on a channel),
/// flushing its cache before parking if `flush`. Returns the worker, the
/// channel that wakes it, and its live block.
fn parked_worker(
  h: &'static Heap<MockOs>,
  flush: bool,
) -> (
  std::thread::JoinHandle<crate::core::CacheStats>,
  std::sync::mpsc::Sender<()>,
  usize,
) {
  let (parked_tx, parked) = std::sync::mpsc::channel();
  let (wake, wake_rx) = std::sync::mpsc::channel::<()>();
  let worker = std::thread::spawn(move || {
    let tc = cache(h);
    let live = alloc_c(h, &tc, 16, 8);
    let x = alloc_c(h, &tc, 48, 8);
    free_c(h, &tc, x);
    if flush {
      // The integration contract: flush before parking.
      h.flush(&tc);
    }
    parked_tx.send(live).unwrap();
    wake_rx.recv().unwrap();
    // Woken: its next slow path sees any request made meanwhile.
    let big = alloc_c(h, &tc, 100_000, 8);
    free_c(h, &tc, big);
    let s = h.cache_stats(&tc);
    h.retire(&tc);
    s
  });
  let live = parked.recv().unwrap();
  (worker, wake, live)
}

#[test]
fn parked_workers_that_flush_hold_nothing() {
  let h = heap();
  let (worker, wake, live) = parked_worker(h, true);
  // Only the live block is out of the shared bitmaps.
  assert_eq!(h.usage().small_bytes_out, 16);
  wake.send(()).unwrap();
  assert_eq!(worker.join().unwrap().pressure_returns, 0);
  free(h, live);
  assert_eq!(h.usage().small_bytes_out, 0);
}

#[test]
fn parked_workers_keep_their_cache_until_they_run() {
  let h = heap();
  let (worker, wake, live) = parked_worker(h, false);
  let held = h.usage().small_bytes_out;
  // The rest of two claimed words and a buffered free.
  assert_eq!(held, 64 * 16 + 64 * 48);
  // A request reaches no sleeping thread: nothing changes.
  h.request_cache_return();
  assert_eq!(h.usage().small_bytes_out, held);
  // Woken, the worker drains at its first slow path.
  wake.send(()).unwrap();
  assert_eq!(worker.join().unwrap().pressure_returns, 1);
  free(h, live);
  assert_eq!(h.usage().small_bytes_out, 0);
}

#[test]
fn fork_children_do_not_wait_for_vanished_caches() {
  let h = heap();
  let (mine, theirs) = (cache(h), cache(h));
  let a = alloc_c(h, &mine, 16, 8);
  let b = alloc_c(h, &theirs, 48, 8);
  h.attach_maintenance();
  // `fork` from this thread: `theirs` belongs to a thread the child does
  // not have, and the maintenance thread is gone too.
  h.fork_prepare();
  h.fork_child();
  assert!(!h.maintenance_attached());
  // Requests and flushes return at once; the vanished cache keeps its
  // blocks (lost to the child, a bounded amount), ours drains.
  h.request_cache_return();
  let c = alloc_c(h, &mine, 256, 8);
  assert_eq!(h.cache_stats(&mine).pressure_returns, 1);
  h.flush(&mine);
  assert_eq!(h.usage().small_bytes_out, 16 + 256 + 64 * 48);
  for o in [a, c] {
    free_c(h, &mine, o);
  }
  h.retire(&mine);
  free_c(h, &theirs, b);
  h.retire(&theirs);
  assert_eq!(h.usage().small_bytes_out, 0);
}

// ---- search indexes (theory-driven plan, Stage D) -----------------------------

/// The trimming counters of `after` minus those of `before`: pages
/// inspected, released, stale candidates and reconciled pages.
fn trim_since(
  before: crate::core::MaintenanceStats,
  after: crate::core::MaintenanceStats,
) -> (u64, u64, u64, u64, u64) {
  (
    after.trim_pages_inspected - before.trim_pages_inspected,
    after.released_pages - before.released_pages,
    after.stale_empty_candidates - before.stale_empty_candidates,
    after.reconciled_pages - before.reconciled_pages,
    after.kept_newest_pages - before.kept_newest_pages,
  )
}

/// Runs a decay sweep and returns its trimming counters.
fn decay_trim(h: &Heap<MockOs>) -> (u64, u64, u64, u64, u64) {
  let before = h.maintenance_stats();
  h.decay();
  h.check_indexes();
  trim_since(before, h.maintenance_stats())
}

/// Blocks of the 1000-byte class per page.
fn cap_1000() -> usize {
  crate::core::class::capacity(crate::core::class::class_of(1000))
}

#[test]
fn trimming_leaves_a_page_it_does_not_release_first_in_line() {
  let h = heap();
  let tc = cache(h);
  // Two words of the 16-byte class, from one page.
  let offs: Vec<_> = (0..65).map(|_| alloc_c(h, &tc, 16, 8)).collect();
  h.purge();
  let t = h.search_stats();
  h.check_indexes();
  // The next refill still claims from that page, the first it looks at.
  let more: Vec<_> = (0..64).map(|_| alloc_c(h, &tc, 16, 8)).collect();
  let u = h.search_stats();
  assert_eq!(
    (
      u.refills - t.refills,
      u.pages_inspected - t.pages_inspected,
      u.new_pages - t.new_pages
    ),
    (1, 1, 0)
  );
  assert_eq!(more[0] / PAGE_SIZE, offs[0] / PAGE_SIZE);
  for o in offs.into_iter().chain(more) {
    free_c(h, &tc, o);
  }
  h.retire(&tc);
}

#[test]
fn the_lowest_page_is_taken_whether_free_or_partly_used() {
  let h = heap();
  // Pages 0 and 2 of the segment for the primary class, page 1 for the
  // secondary class; page 3 stays an untouched free page above them. Native
  // keeps the 1000-byte (64 per page) and 48-byte (1,365 per page) classes.
  // Miri keeps the same four-page topology and event order with the
  // 8192-byte (8 per page) and 4096-byte (16 per page) classes: 27
  // allocation calls instead of 1,432. Both Miri classes fit one bitmap
  // word; only native covers a multiword secondary page.
  let primary_size = if cfg!(miri) { 8192 } else { 1000 };
  let secondary_size = if cfg!(miri) { 4096 } else { 48 };
  assert!(primary_size <= crate::core::class::SMALL_MAX);
  assert!(secondary_size <= crate::core::class::SMALL_MAX);
  let primary_class = crate::core::class::class_of(primary_size);
  let secondary_class = crate::core::class::class_of(secondary_size);
  assert_ne!(primary_class, secondary_class);
  let primary_cap = crate::core::class::capacity(primary_class);
  let cap = crate::core::class::capacity(secondary_class);
  assert!(primary_cap >= 2 && cap >= 2);
  if cfg!(miri) {
    assert_eq!(
      (
        crate::core::class::size(primary_class),
        crate::core::class::size(secondary_class)
      ),
      (8192, 4096)
    );
    assert_eq!((primary_cap, cap), (8, 16));
  } else {
    assert_eq!(primary_cap, cap_1000());
  }
  let a: Vec<_> = (0..primary_cap)
    .map(|_| alloc(h, 0, primary_size, 8))
    .collect();
  let page = a[0] / PAGE_SIZE;
  assert!(a.iter().all(|&o| o / PAGE_SIZE == page));
  assert_eq!(
    a.iter().copied().collect::<BTreeSet<_>>().len(),
    primary_cap
  );
  let b = alloc(h, 0, secondary_size, 8);
  let a2 = alloc(h, 0, primary_size, 8);
  assert_eq!((b / PAGE_SIZE, a2 / PAGE_SIZE), (page + 1, page + 2));
  for o in a.into_iter().chain([a2]) {
    free(h, o);
  }
  let before = h.maintenance_stats();
  h.purge();
  let (_, released, _, _, kept_newest) = trim_since(before, h.maintenance_stats());
  // Page 0 is released; page 2, the newest page of its class, is kept.
  assert_eq!((released, kept_newest), (1, 1));
  assert_eq!(h.usage().small_pages, 2);
  h.check_indexes();
  // Page 0 is free again and lies below the partly used page 1: the
  // secondary class takes it.
  let s = h.search_stats();
  let b2 = alloc(h, 0, secondary_size, 8);
  let t = h.search_stats();
  assert_eq!(b2 / PAGE_SIZE, page);
  assert_eq!(
    (
      t.pages_inspected - s.pages_inspected,
      t.new_pages - s.new_pages
    ),
    (1, 1)
  );
  assert_eq!(h.usage().small_pages, 3);
  // Now page 0 is the class's lowest page with free blocks: taken first.
  let b3 = alloc(h, 0, secondary_size, 8);
  assert_eq!(b3 / PAGE_SIZE, page);
  // A free page above a partly used one waits: page 3 is free, and the
  // class keeps claiming from page 1 once page 0 is full.
  let fill: Vec<_> = (0..cap - 2)
    .map(|_| alloc(h, 0, secondary_size, 8))
    .collect();
  assert!(fill.iter().all(|&o| o / PAGE_SIZE == page));
  let s = h.search_stats();
  let next = alloc(h, 0, secondary_size, 8);
  let t = h.search_stats();
  assert_eq!(next / PAGE_SIZE, b / PAGE_SIZE);
  assert_eq!(
    (
      t.refills - s.refills,
      t.pages_inspected - s.pages_inspected,
      t.new_pages - s.new_pages
    ),
    (1, 1, 0)
  );
  assert_eq!(h.usage().small_pages, 3);
  h.check_indexes();
  // Every simultaneously live secondary block is distinct: page 0's
  // `cap` blocks plus `b` and `next` on page 1.
  let live: Vec<_> = fill.into_iter().chain([b, b2, b3, next]).collect();
  assert_eq!(live.iter().copied().collect::<BTreeSet<_>>().len(), cap + 2);
  for o in live {
    free(h, o);
  }
  assert!(h.os().live.lock().unwrap().is_empty());
  h.check_indexes();
}

#[test]
fn a_released_page_reused_at_the_same_offset_is_not_claimed_from() {
  let h = heap();
  // A full page of the class and the class's newest page after it.
  let offs: Vec<_> = (0..=cap_1000()).map(|_| alloc(h, 0, 1000, 8)).collect();
  let page = offs[0] / PAGE_SIZE;
  for o in offs {
    free(h, o);
  }
  h.purge();
  // The first page is released, the newest kept.
  assert_eq!(h.usage().small_pages, 1);
  h.check_indexes();
  // The page's next life is a one-page run at the same offset; the class
  // claims from its kept page.
  let run = alloc(h, 0, PAGE_SIZE, 8);
  assert_eq!(run / PAGE_SIZE, page);
  let b = alloc(h, 0, 1000, 8);
  assert_ne!(b / PAGE_SIZE, page);
  h.check_indexes();
  free(h, run);
  free(h, b);
  h.purge();
  // And then a page of another class, again at the same offset.
  let c = alloc(h, 0, 16, 8);
  assert_eq!(c / PAGE_SIZE, page);
  let d = alloc(h, 0, 1000, 8);
  assert_ne!(d / PAGE_SIZE, page);
  h.check_indexes();
  free(h, c);
  free(h, d);
  h.purge();
  // Only the newest page of each of the two classes stays.
  assert_eq!((h.usage().small_pages, h.newest_pages()), (2, 2));
}

#[test]
fn a_returned_and_reacquired_segment_is_searched_again() {
  let h = heap();
  h.set_purge_delay_ms(0);
  // Shard 0's first two segments are full of one run each; the small page
  // goes to a third segment.
  let run = alloc(h, 0, MAX_RUN_PAGES * PAGE_SIZE, 8);
  let run2 = alloc(h, 0, MAX_RUN_PAGES * PAGE_SIZE, 8);
  let fill: Vec<_> = (0..cap_1000()).map(|_| alloc(h, 0, 1000, 8)).collect();
  let seg = fill[0] / SEGMENT_SIZE;
  assert!(seg != run / SEGMENT_SIZE && seg != run2 / SEGMENT_SIZE);
  // The class's next page, its newest, which trimming keeps, goes to the
  // first segment once its run is freed.
  free(h, run);
  let a = alloc(h, 0, 1000, 8);
  assert_eq!(a / SEGMENT_SIZE, run / SEGMENT_SIZE);
  for o in fill {
    free(h, o);
  }
  free(h, run2);
  let before = h.maintenance_stats();
  // Two segments are empty: one is returned, one kept for the shard.
  h.purge();
  h.purge();
  assert_eq!(
    h.maintenance_stats().returned_segments - before.returned_segments,
    1
  );
  assert_eq!(h.usage().small_pages, 1);
  h.check_indexes();
  // The returned segment comes back, whole, as a huge block, then the
  // class fills its page and takes a new one.
  let huge = alloc(h, 0, SEGMENT_SIZE, 8);
  let b: Vec<_> = (0..cap_1000()).map(|_| alloc(h, 0, 1000, 8)).collect();
  h.check_indexes();
  free(h, huge);
  for o in b.into_iter().chain([a]) {
    free(h, o);
  }
  h.purge();
  h.check_indexes();
}

#[test]
fn the_last_free_of_a_page_makes_it_a_candidate() {
  let h = heap();
  h.set_reconcile_epochs(0);
  let cap = cap_1000();
  // Eight full pages of the class, one block kept live on each.
  let offs: Vec<_> = (0..8 * cap).map(|_| alloc(h, 0, 1000, 8)).collect();
  let pages: BTreeSet<_> = offs.iter().map(|o| o / PAGE_SIZE).collect();
  assert_eq!(pages.len(), 8);
  for (i, &o) in offs.iter().enumerate() {
    if i % cap != 0 {
      free(h, o);
    }
  }
  // No page is fully free: no candidate, nothing inspected.
  assert_eq!(decay_trim(h), (0, 0, 0, 0, 0));
  // Freeing the last block of one page publishes it, and trimming checks
  // that page only.
  free(h, offs[3 * cap]);
  assert_eq!(decay_trim(h), (1, 1, 0, 0, 0));
  assert_eq!(h.usage().small_pages, 7);
  // A reconciling sweep checks every small page and finds nothing more.
  let before = h.maintenance_stats();
  h.purge();
  assert_eq!(trim_since(before, h.maintenance_stats()), (7, 0, 0, 0, 0));
  for p in (0..8).filter(|&p| p != 3) {
    free(h, offs[p * cap]);
  }
  // All are released but the last, the newest page of the class.
  assert_eq!(decay_trim(h), (7, 6, 0, 0, 1));
  assert_eq!(h.usage().small_pages, 1);
}

#[test]
fn stale_candidates_are_checked_and_dropped() {
  let h = heap();
  h.set_reconcile_epochs(0);
  let cap = cap_1000();
  let offs: Vec<_> = (0..cap).map(|_| alloc(h, 0, 1000, 8)).collect();
  let page = offs[0] / PAGE_SIZE;
  assert!(offs.iter().all(|o| o / PAGE_SIZE == page));
  // The class's newest page, above it, stays in use.
  let newer = alloc(h, 0, 1000, 8);
  assert_eq!(newer / PAGE_SIZE, page + 1);
  for &o in &offs {
    free(h, o);
  }
  // The page is claimed from again: its candidate is stale.
  let again = alloc(h, 0, 1000, 8);
  assert_eq!(again / PAGE_SIZE, page);
  assert_eq!(decay_trim(h), (1, 0, 1, 0, 0));
  assert_eq!(h.usage().small_pages, 2);
  // Its last free publishes it again.
  free(h, again);
  assert_eq!(decay_trim(h), (1, 1, 0, 0, 0));
  assert_eq!(h.usage().small_pages, 1);
  // The newest page is checked, and kept, once it is fully free.
  free(h, newer);
  assert_eq!(decay_trim(h), (1, 0, 0, 0, 1));
  assert_eq!(h.usage().small_pages, 1);
}

#[test]
fn cache_flushes_and_retirement_publish_candidates() {
  let h = heap();
  h.set_reconcile_epochs(0);
  // Kept pages are purged at the pass that keeps them, so they stop being
  // candidates there.
  h.set_purge_delay_ms(0);
  let tc = cache(h);
  let a = alloc_c(h, &tc, 16, 8);
  let b = alloc_c(h, &tc, 1000, 8);
  free_c(h, &tc, a);
  free_c(h, &tc, b);
  // Buffered frees and claimed words keep both pages: no candidate.
  assert_eq!(decay_trim(h), (0, 0, 0, 0, 0));
  assert_eq!(h.usage().small_pages, 2);
  // A flush returns them, and the last of each page publishes it. Each is
  // the newest page of its class, so trimming checks it and keeps it.
  h.flush(&tc);
  assert_eq!(decay_trim(h), (2, 0, 0, 0, 2));
  // Again through retirement.
  let c = alloc_c(h, &tc, 48, 8);
  free_c(h, &tc, c);
  assert_eq!(decay_trim(h), (0, 0, 0, 0, 0));
  h.retire(&tc);
  assert_eq!(decay_trim(h), (1, 0, 0, 0, 1));
  assert_eq!(h.usage().small_pages, 3);
}

#[test]
fn reconciling_sweeps_recover_lost_candidates() {
  let h = heap();
  h.set_reconcile_epochs(0);
  assert_eq!(cap_1000(), 64);
  for reconcile in [Some(1), None] {
    // Keep the original two-page 1000-byte-class topology in both builds.
    let offs: Vec<_> = (0..=cap_1000()).map(|_| alloc(h, 0, 1000, 8)).collect();
    assert_eq!(offs.len(), 65);
    assert_eq!(
      offs.iter().copied().collect::<BTreeSet<_>>().len(),
      offs.len()
    );
    let segment = offs[0] / SEGMENT_SIZE;
    assert!(offs.iter().all(|offset| offset / SEGMENT_SIZE == segment));
    let mut blocks_per_page = BTreeMap::new();
    let mut page_indices = BTreeSet::new();
    for &offset in &offs {
      let page = (offset % SEGMENT_SIZE) / PAGE_SIZE;
      assert!(page < 64);
      page_indices.insert(page);
      *blocks_per_page.entry(page).or_insert(0usize) += 1;
    }
    let mut page_occupancy: Vec<_> = blocks_per_page.values().copied().collect();
    page_occupancy.sort_unstable();
    assert_eq!(page_occupancy, [1, cap_1000()]);
    assert_eq!(page_indices.len(), 2);
    let usage = h.usage();
    assert_eq!(h.segments_in_use(), 1);
    assert_eq!(usage.owned_segments, 1);
    assert_eq!(usage.huge_segments, 0);
    assert_eq!(usage.small_pages, 2);
    for o in offs {
      free(h, o);
    }
    assert!(h.os().live.lock().unwrap().is_empty());
    let usage = h.usage();
    assert_eq!(usage.owned_segments, 1);
    assert_eq!(usage.huge_segments, 0);
    assert_eq!(usage.small_pages, 2);
    assert_eq!(usage.small_bytes_out, 0);
    // The sole owned segment contains exactly the two empty pages. Witness
    // their publications before injecting the same lost-candidate state.
    let mut candidate_pages = 0u64;
    for page in page_indices {
      candidate_pages |= 1u64 << page;
    }
    assert_eq!(candidate_pages.count_ones(), 2);
    // SEG_EMPTY is metadata slot 5 in heap.rs. The direct Miri path below
    // changes only this owned segment; native keeps the original global scan.
    const SEG_EMPTY_METADATA_SLOT: usize = 5;
    let meta = h.os().meta(segment).expect("owned segment metadata");
    assert_eq!(
      meta[SEG_EMPTY_METADATA_SLOT].load(Ordering::Relaxed),
      candidate_pages
    );
    #[cfg(miri)]
    meta[SEG_EMPTY_METADATA_SLOT].store(0, Ordering::Relaxed);
    #[cfg(not(miri))]
    h.forget_empty_candidates();
    // (`check_indexes` would catch the lost candidates.)
    let before = h.maintenance_stats();
    h.decay();
    assert_eq!(trim_since(before, h.maintenance_stats()), (0, 0, 0, 0, 0));
    assert_eq!(h.usage().small_pages, 2);
    let before = h.maintenance_stats();
    match reconcile {
      // A decay sweep on a reconciling epoch...
      Some(every) => {
        h.set_reconcile_epochs(every);
        h.decay();
        h.set_reconcile_epochs(0);
      }
      // ...or a force purge.
      None => h.purge(),
    }
    assert_eq!(trim_since(before, h.maintenance_stats()), (2, 1, 0, 1, 1));
    assert_eq!(h.usage().small_pages, 1);
    h.check_indexes();
  }
}

#[test]
fn concurrent_frees_and_trims_lose_no_candidate() {
  let h = heap();
  h.set_reconcile_epochs(0);
  h.set_purge_delay_ms(0);
  let done = AtomicBool::new(false);
  let active_batches = AtomicUsize::new(0);
  let trimmer_passes = AtomicUsize::new(0);
  let overlapping_passes = AtomicUsize::new(0);
  let requested_passes = AtomicUsize::new(0);
  let completed_passes = AtomicUsize::new(0);
  let workers_count = 4;
  let start = std::sync::Barrier::new(workers_count + 1);
  let rounds = if cfg!(miri) { 4 } else { 40 };
  let blocks_per_batch = if cfg!(miri) { 129 } else { 300 };
  std::thread::scope(|s| {
    // Stops the trimmer even when a worker panics (the join below then
    // panics too), so a failure does not hang the scope.
    let _done = SetOnDrop(&done);
    // The trimmer: decay sweeps (all trimming, delay 0) until the workers
    // are done.
    let start = &start;
    let done_ref = &done;
    let active_batches = &active_batches;
    let trimmer_passes = &trimmer_passes;
    let overlapping_passes = &overlapping_passes;
    let requested_passes = &requested_passes;
    let completed_passes = &completed_passes;
    s.spawn(move || {
      // If an assertion or sweep panics, release workers waiting on tickets.
      let _trimmer_done = SetOnDrop(done_ref);
      start.wait();
      if cfg!(miri) {
        while !done_ref.load(Ordering::Relaxed) {
          let completed = completed_passes.load(Ordering::SeqCst);
          let requested = requested_passes.load(Ordering::SeqCst);
          if completed < requested && active_batches.load(Ordering::SeqCst) != 0 {
            let active_before = active_batches.load(Ordering::SeqCst);
            assert!(
              active_before > 0,
              "a requested sweep must have an active batch"
            );
            h.decay();
            let active_after = active_batches.load(Ordering::SeqCst);
            trimmer_passes.fetch_add(1, Ordering::SeqCst);
            assert!(
              active_after > 0,
              "ticket owner must remain active until acknowledgement"
            );
            overlapping_passes.fetch_add(1, Ordering::SeqCst);
            // A sweep acknowledges exactly one worker ticket only after the
            // real decay operation and its overlap witness have completed.
            completed_passes.fetch_add(1, Ordering::SeqCst);
          } else {
            std::thread::yield_now();
          }
        }
      } else {
        while !done_ref.load(Ordering::Relaxed) {
          h.decay();
          if active_batches.load(Ordering::SeqCst) != 0 {
            overlapping_passes.fetch_add(1, Ordering::SeqCst);
          }
          trimmer_passes.fetch_add(1, Ordering::SeqCst);
        }
      }
    });
    let workers: Vec<_> = (0..workers_count)
      .map(|t| {
        s.spawn(move || {
          start.wait();
          let tc = cache(h);
          for round in 0..rounds {
            let size = [16, 48, 1000, 4000][(t + round) % 4];
            let offs: Vec<_> = (0..blocks_per_batch)
              .map(|_| alloc_c(h, &tc, size, 8))
              .collect();
            if cfg!(miri) && round == 0 {
              active_batches.fetch_add(1, Ordering::SeqCst);
              let _active_batch = ActiveCountOnDrop(active_batches);
              let mut remaining = offs.into_iter();
              free_c(h, &tc, remaining.next().expect("nonempty batch"));
              let ticket = requested_passes.fetch_add(1, Ordering::SeqCst);
              loop {
                if completed_passes.load(Ordering::SeqCst) > ticket {
                  break;
                }
                if done_ref.load(Ordering::Relaxed) {
                  if completed_passes.load(Ordering::SeqCst) > ticket {
                    break;
                  }
                  panic!("trimmer abandoned a requested overlap ticket");
                }
                std::thread::yield_now();
              }
              for o in remaining {
                free_c(h, &tc, o);
              }
            } else {
              for o in offs {
                free_c(h, &tc, o);
              }
            }
            let flush = if cfg!(miri) {
              round == 0 || round == 3
            } else {
              round % 3 == 0
            };
            if flush {
              h.flush(&tc);
            }
          }
          h.retire(&tc);
        })
      })
      .collect();
    for w in workers {
      w.join().unwrap();
    }
  });
  if cfg!(miri) {
    assert_eq!(requested_passes.load(Ordering::SeqCst), workers_count);
    assert_eq!(completed_passes.load(Ordering::SeqCst), workers_count);
    assert_eq!(trimmer_passes.load(Ordering::SeqCst), workers_count);
    assert_eq!(
      overlapping_passes.load(Ordering::SeqCst),
      workers_count,
      "each ticketed decay must overlap a live worker batch"
    );
    assert_eq!(active_batches.load(Ordering::SeqCst), 0);
  }
  h.check_indexes();
  // Without reconciling, the candidates alone find every fully free page
  // but the newest of each shard and class, which trimming keeps.
  let (_, _, _, reconciled, _) = decay_trim(h);
  assert_eq!(reconciled, 0);
  assert_eq!(h.usage().small_pages, h.newest_pages());
  assert!(h.os().live.lock().unwrap().is_empty());
}
