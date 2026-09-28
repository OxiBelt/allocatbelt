//! Model tests: the heap runs on the checking [`MockOs`] of
//! [`crate::core::model`], which never backs user memory but checks the heap's
//! promises against shadow maps.

use std::boxed::Box;
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::vec::Vec;

use crate::core::heap::DIRTY_BUDGET_PAGES;
use crate::core::heap::MAX_RUN_PAGES;
use crate::core::model::{
  MockOs, MockPurger, alloc, alloc_block, alloc_c, cache, free, free_c, resize,
};
use crate::core::{
  Block, DIRTY_HARD_LIMIT_PAGES, Heap, PAGE_SIZE, PURGE_BATCH, SEGMENT_SIZE, Task, ThreadCache,
};

fn heap() -> &'static Heap<MockOs> {
  Box::leak(Box::new(Heap::new(MockOs::new())))
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
  // pages), then free them all.
  let n = 3 * MAX_RUN_PAGES * PAGE_SIZE / 16;
  let offs: Vec<_> = (0..n).map(|_| h.alloc(6, 16, 8).unwrap()).collect();
  assert_eq!(h.segments_in_use(), base + 3);
  // Keep one block so its page stays behind.
  for &o in &offs[1..] {
    h.dealloc(o);
  }
  // Pages go back on the first pass, segments on the second. What stays:
  // the survivor's segment and one empty segment the shard keeps.
  h.purge();
  h.purge();
  assert_eq!(h.segments_in_use(), base + 2);
  // The survivor is intact and the class keeps working.
  assert_eq!(h.usable_size(offs[0]), 16);
  let again: Vec<_> = (0..1000).map(|_| h.alloc(6, 16, 8).unwrap()).collect();
  for o in again.into_iter().chain([offs[0]]) {
    h.dealloc(o);
  }
}

// ---- thread caches and summaries -------------------------------------------

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
fn refill_finds_freed_page_without_scanning() {
  let h = heap();
  // Fill many pages of one class, then free one block in an early page.
  let per_page = PAGE_SIZE / 32;
  let offs: Vec<_> = (0..per_page * 40).map(|_| alloc(h, 7, 32, 8)).collect();
  let segs = h.segments_in_use();
  free(h, offs[5]);
  // The next allocation of the class takes the freed block from that page
  // (found through the availability words) rather than a new page.
  let again = alloc(h, 7, 32, 8);
  assert_eq!(again, offs[5]);
  assert_eq!(h.segments_in_use(), segs);
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
  for step in 0..3000 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    for (h, held) in [plain, kernel].into_iter().zip(held.iter_mut()) {
      match x % 8 {
        0..=3 => {
          let pages = 1 + (x >> 8) as usize % 6;
          let shard = (x >> 16) as usize % 4;
          held.push(alloc(h, shard, pages * PAGE_SIZE, 8));
        }
        4..=6 if !held.is_empty() => {
          let o = held.swap_remove((x >> 24) as usize % held.len());
          free(h, o);
        }
        _ => {
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
    crate::core::model::run(&data);
  }
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
