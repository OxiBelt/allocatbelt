//! Runs std collections and threads with allocatbelt as the global allocator.

#![allow(unsafe_code, reason = "tests exercise the raw GlobalAlloc API")]

use std::alloc::{GlobalAlloc, Layout};
use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc;

use allocatbelt::Allocatbelt;

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

#[test]
fn collections() {
  let mut v: Vec<u64> = (0..100_000).collect();
  v.extend(0..1_000_000);
  assert_eq!(
    v.iter().sum::<u64>(),
    (0..100_000u64).sum::<u64>() + (0..1_000_000u64).sum::<u64>()
  );
  let m: HashMap<String, Vec<u8>> = (0..10_000)
    .map(|i| (format!("key-{i}"), vec![i as u8; i % 300]))
    .collect();
  assert_eq!(m["key-299"].len(), 299);
  let b: BTreeMap<u32, Box<[u8]>> = (0..5_000)
    .map(|i| (i, vec![1; 100].into_boxed_slice()))
    .collect();
  assert_eq!(b.len(), 5_000);
  let big = vec![7u8; 64 << 20];
  assert!(big.iter().all(|&x| x == 7));
}

#[test]
fn zeroed_and_realloc() {
  for &size in &[1usize, 100, 8192, 70_000, 5 << 20] {
    let layout = Layout::from_size_align(size, 8).unwrap();
    // SAFETY: non-zero layout; the block is freed below with the same layout.
    let p = unsafe { GLOBAL.alloc_zeroed(layout) };
    assert!(!p.is_null());
    // SAFETY: `p` is valid for `size` bytes.
    let s = unsafe { std::slice::from_raw_parts_mut(p, size) };
    assert!(s.iter().all(|&x| x == 0));
    s.fill(0xAB);
    // SAFETY: `p` came from `alloc_zeroed` with `layout`.
    let q = unsafe { GLOBAL.realloc(p, layout, size * 3) };
    assert!(!q.is_null());
    // SAFETY: the first `size` bytes were preserved by realloc.
    let s = unsafe { std::slice::from_raw_parts(q, size) };
    assert!(s.iter().all(|&x| x == 0xAB));
    // SAFETY: `q` is live with size `size * 3`.
    unsafe { GLOBAL.dealloc(q, Layout::from_size_align(size * 3, 8).unwrap()) };
  }
}

#[test]
fn over_aligned() {
  for shift in 4..=22 {
    let layout = Layout::from_size_align(24, 1 << shift).unwrap();
    let p = GLOBAL.allocate(layout).expect("alloc");
    assert_eq!(p.as_ptr().addr() % (1 << shift), 0);
    // SAFETY: allocated above with this layout.
    unsafe { GLOBAL.dealloc(p.as_ptr(), layout) };
  }
}

#[test]
fn producer_consumer_threads() {
  let (tx, rx) = mpsc::sync_channel::<Vec<Box<[u8]>>>(64);
  let producers: Vec<_> = (0..8)
    .map(|t| {
      let tx = tx.clone();
      std::thread::spawn(move || {
        for i in 0..2_000 {
          let batch = (0..16)
            .map(|j| vec![t as u8; (i * 31 + j * 17) % 3000 + 1].into_boxed_slice())
            .collect();
          tx.send(batch).unwrap();
        }
      })
    })
    .collect();
  drop(tx);
  let mut total = 0usize;
  for batch in rx {
    total += batch.iter().map(|b| b.len()).sum::<usize>();
  }
  for p in producers {
    p.join().unwrap();
  }
  assert!(total > 0);
}

#[test]
fn reused_memory_is_zeroed() {
  // Huge blocks are decommitted on free and page runs are purged, after
  // which `alloc_zeroed` skips the memset; the memory must really be zero.
  for &size in &[300_000usize, 5 << 20, 20 << 20] {
    let layout = Layout::from_size_align(size, 8).unwrap();
    for _ in 0..3 {
      // SAFETY: non-zero layout; freed below with the same layout.
      let p = unsafe { GLOBAL.alloc_zeroed(layout) };
      assert!(!p.is_null());
      // SAFETY: `p` is valid for `size` bytes.
      let s = unsafe { std::slice::from_raw_parts_mut(p, size) };
      assert!(s.iter().all(|&x| x == 0), "size {size}");
      s.fill(0xCD);
      // SAFETY: `p` came from `alloc_zeroed` with `layout`.
      unsafe { GLOBAL.dealloc(p, layout) };
      GLOBAL.purge();
    }
  }
}

#[test]
fn realloc_grows_and_shrinks() {
  // Page runs and huge blocks resize in place where they can; either way
  // the contents must survive.
  let mut layout = Layout::from_size_align(100_000, 8).unwrap();
  // SAFETY: non-zero layout.
  let mut p = unsafe { GLOBAL.alloc(layout) };
  assert!(!p.is_null());
  // SAFETY: `p` is valid for `layout.size()` bytes.
  unsafe { p.write_bytes(0x5A, layout.size()) };
  for &size in &[
    300_000usize,
    1 << 20,
    6 << 20,
    40 << 20,
    9 << 20,
    500_000,
    20_000,
  ] {
    let keep = layout.size().min(size);
    // SAFETY: `p` is live with `layout`; `size` is non-zero.
    p = unsafe { GLOBAL.realloc(p, layout, size) };
    assert!(!p.is_null());
    // SAFETY: the first `keep` bytes were preserved.
    let s = unsafe { std::slice::from_raw_parts_mut(p, size) };
    assert!(s[..keep].iter().all(|&x| x == 0x5A), "size {size}");
    s.fill(0x5A);
    layout = Layout::from_size_align(size, 8).unwrap();
  }
  // SAFETY: `p` is live with `layout`.
  unsafe { GLOBAL.dealloc(p, layout) };
}

#[test]
fn exiting_threads_return_their_caches() {
  // Many short-lived threads, each leaving blocks in its cache at exit:
  // retiring the caches must let the pages go back, so repeated rounds do
  // not accumulate segments.
  let round = || {
    let handles: Vec<_> = (0..16)
      .map(|t| {
        std::thread::spawn(move || {
          let v: Vec<Box<[u8]>> = (0..20_000)
            .map(|i| vec![t as u8; 16 + (i * 13) % 2000].into_boxed_slice())
            .collect();
          // Free half now (buffered in this thread's cache) and
          // half at thread exit.
          let (keep, drop_now): (Vec<_>, Vec<_>) =
            v.into_iter().enumerate().partition(|(i, _)| i % 2 == 0);
          drop(drop_now);
          keep.len()
        })
      })
      .collect();
    for h in handles {
      assert_eq!(h.join().unwrap(), 10_000);
    }
    GLOBAL.purge();
    GLOBAL.purge();
    GLOBAL.segments_in_use()
  };
  // Threads are spread over the 64 shards round-robin, and each shard keeps
  // one empty (purged) segment; warm them all up before measuring.
  for _ in 0..4 {
    round();
  }
  let first = round();
  let mut last = first;
  for _ in 0..6 {
    last = round();
  }
  // Other tests allocate concurrently, so allow a little noise.
  assert!(last <= first + 8, "segments grew from {first} to {last}");
}

#[test]
fn thread_local_destructors_may_free_after_retire() {
  #[allow(clippy::vec_box, reason = "each box is a separate small allocation")]
  struct Holder(Vec<Box<[u8; 100]>>);
  impl Drop for Holder {
    fn drop(&mut self) {
      // Runs during thread exit, possibly after the cache was retired;
      // frees and allocations must keep working.
      self.0.clear();
      let v = vec![1u8; 1000];
      assert_eq!(v.len(), 1000);
    }
  }
  std::thread_local! {
      static HOLDER: std::cell::RefCell<Option<Holder>> = const { std::cell::RefCell::new(None) };
  }
  let handles: Vec<_> = (0..8)
    .map(|_| {
      std::thread::spawn(|| {
        let v = (0..1000).map(|_| Box::new([7u8; 100])).collect();
        HOLDER.with(|h| *h.borrow_mut() = Some(Holder(v)));
        // A second allocation after the holder, so our retire hook
        // may be registered before or after it.
        let _ = vec![0u8; 64];
      })
    })
    .collect();
  for h in handles {
    h.join().unwrap();
  }
}

#[test]
fn diagnostics_are_readable_through_the_adapter() {
  // A thread of its own, so its cache holds only what this test does.
  std::thread::spawn(|| {
    let blocks: Vec<Box<[u8; 32]>> = (0..1000).map(|i| Box::new([i as u8; 32])).collect();
    let usage = GLOBAL.heap_usage();
    assert!(usage.owned_segments >= 1 && usage.small_bytes_out >= 32 * 1000);
    assert!(GLOBAL.search_stats().refills > 0);
    let before = GLOBAL.thread_cache_stats().expect("cache");
    assert!(before.attached);
    drop(blocks);
    let after = GLOBAL.thread_cache_stats().expect("cache");
    // Every free is either still buffered or was flushed in a batch.
    let returned = |s: allocatbelt::CacheStats| s.buffered_blocks + s.flushed_blocks;
    assert!(
      returned(after) - returned(before) >= 1000,
      "{before:?} {after:?}"
    );
    assert_eq!(after.flushes, after.flush_sizes.iter().sum::<u64>());
  })
  .join()
  .unwrap();
}

#[test]
fn reclamation_is_configurable_through_the_adapter() {
  use allocatbelt::{ReclaimTargets, ReclaimTargetsError, Retention};
  assert_eq!(GLOBAL.reclaim_targets(), ReclaimTargets::DEFAULT);
  assert_eq!(
    ReclaimTargets::from_bytes(64 << 20, 32 << 20, 128 << 20),
    Err(ReclaimTargetsError::Order)
  );
  // Setting the defaults again changes nothing for the other tests.
  GLOBAL.set_reclaim_targets(ReclaimTargets::DEFAULT);
  GLOBAL.set_retention(Retention::Fixed);
  let s = GLOBAL.reclaim_status();
  assert_eq!(
    (s.targets, s.retention_mode, s.retention),
    (ReclaimTargets::DEFAULT, Retention::Fixed, 1)
  );
}
