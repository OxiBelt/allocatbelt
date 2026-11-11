//! Heap-backed regions (theory-driven plan, Stage E): data integrity across
//! many chunks, alignment, zero-sized requests, the limit and allocation
//! failure, chunk ownership, reset and retention, a long-lived region moved
//! between threads, and one region per thread.
//!
//! The process's global allocator is the system one here: a region takes
//! its chunks from the allocatbelt heap whatever the global allocator is.

use std::sync::{Mutex, MutexGuard};

use allocatbelt::{Allocatbelt, Region, RegionError, RegionOptions, RegionStats};

/// Tests that count heap segments run one at a time.
static SEGMENTS: Mutex<()> = Mutex::new(());

fn segments_lock() -> MutexGuard<'static, ()> {
  SEGMENTS
    .lock()
    .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A small pseudo-random sequence, so the test needs no dependency.
struct Rng(u64);

impl Rng {
  fn next(&mut self) -> u64 {
    self.0 ^= self.0 << 13;
    self.0 ^= self.0 >> 7;
    self.0 ^= self.0 << 17;
    self.0
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(64))]
struct Line([u8; 64]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(4096))]
struct Page4k([u8; 4096]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(65536))]
struct Page64k([u8; 65536]);

/// Never built: only its alignment (8 MiB) matters.
#[derive(Clone, Copy)]
#[repr(C, align(8388608))]
struct Over([u8; 8388608]);

fn addr<T: ?Sized>(r: &T) -> usize {
  std::ptr::from_ref(r).cast::<u8>().addr()
}

#[test]
fn many_pieces_keep_their_contents_across_chunks() {
  let region = Region::with_options(RegionOptions::new().with_chunk_size(4096));
  let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
  let mut pieces: Vec<(&mut [u32], u32)> = Vec::new();
  for i in 0..20_000u32 {
    let len = (rng.next() % 300) as usize;
    pieces.push((region.alloc_slice_fill(len, i).unwrap(), i));
  }
  // Rewrite every other piece, then check them all.
  for (p, v) in pieces.iter_mut().step_by(2) {
    *v = !*v;
    p.fill(*v);
  }
  for (p, v) in &pieces {
    assert!(p.iter().all(|x| x == v));
  }
  let s = region.stats();
  assert!(s.chunks > 100, "{s:?}");
  assert!(s.used <= s.capacity);
}

#[test]
fn pieces_are_aligned_for_their_types() {
  let region = Region::new();
  for _ in 0..3 {
    let b = region.alloc_copy(1u8).unwrap();
    let l = region.alloc_copy(Line([2; 64])).unwrap();
    let p = region.alloc_copy(Page4k([3; 4096])).unwrap();
    let q = region.alloc_slice_copy(&[Page64k([4; 65536])]).unwrap();
    assert_eq!(addr(l) % 64, 0);
    assert_eq!(addr(p) % 4096, 0);
    assert_eq!(addr(&*q) % 65536, 0);
    assert_eq!((*b, l.0[63], p.0[4095], q[0].0[65535]), (1, 2, 3, 4));
  }
  // The 64 KiB piece does not fit a standard chunk with its padding.
  assert_eq!(region.stats().own_chunks, 3);
  // An alignment above the heap's largest is refused, even for no values.
  assert_eq!(
    region.alloc_slice_copy::<Over>(&[]).map(|s| s.len()),
    Err(RegionError::Layout)
  );
}

#[test]
fn zero_sized_requests_take_no_chunk() {
  let region = Region::new();
  assert_eq!(*region.alloc_copy(()).unwrap(), ());
  assert!(region.alloc_zeroed_bytes(0).unwrap().is_empty());
  assert!(region.alloc_str("").unwrap().is_empty());
  assert_eq!(region.alloc_slice_fill(1 << 40, ()).unwrap().len(), 1 << 40);
  assert_eq!(
    addr(&*region.alloc_slice_copy::<Line>(&[]).unwrap()) % 64,
    0
  );
  assert_eq!(region.stats(), RegionStats::default());
}

#[test]
fn the_limit_and_allocation_failure_leave_the_region_usable() {
  let region = Region::with_options(
    RegionOptions::new()
      .with_chunk_size(1024)
      .with_limit_bytes(4096),
  );
  let kept: Vec<&mut [u8]> = (0..4)
    .map(|i| region.alloc_slice_fill(1000, i).unwrap())
    .collect();
  assert_eq!(region.alloc_zeroed_bytes(1000), Err(RegionError::Limit));
  assert_eq!(region.alloc_zeroed_bytes(100_000), Err(RegionError::Limit));
  // Still fits the current chunk.
  assert_eq!(region.alloc_zeroed_bytes(24).unwrap().len(), 24);
  assert_eq!(region.stats().capacity, 4096);
  for (i, k) in kept.iter().enumerate() {
    assert!(k.iter().all(|&x| usize::from(x) == i));
  }

  // More than the heap's arena: the heap refuses the chunk.
  let unlimited = Region::new();
  assert_eq!(
    unlimited.alloc_zeroed_bytes(1 << 40),
    Err(RegionError::OutOfMemory)
  );
  assert_eq!(
    unlimited.alloc_zeroed_bytes(usize::MAX),
    Err(RegionError::Layout)
  );
  assert_eq!(unlimited.stats(), RegionStats::default());
  assert_eq!(*unlimited.alloc_copy(5u16).unwrap(), 5);
}

#[test]
fn chunks_come_from_the_heap_and_go_back_to_it() {
  let _lock = segments_lock();
  let huge = || Allocatbelt.heap_usage().huge_segments;
  let before = huge();
  let mut region = Region::new();
  // 24 MiB: a chunk of its own, which the heap serves as a huge block of
  // six 4 MiB segments.
  let big = region.alloc_zeroed_bytes(24 << 20).unwrap();
  big[(24 << 20) - 1] = 1;
  assert!(huge() >= before + 6);
  // A reset never keeps a chunk of its own.
  region.reset();
  assert_eq!(huge(), before);
  let _ = region.alloc_zeroed_bytes(24 << 20).unwrap();
  assert!(huge() >= before + 6);
  drop(region);
  assert_eq!(huge(), before);
}

#[test]
fn resets_keep_the_retained_chunks_and_reuse_them() {
  let mut region = Region::with_options(
    RegionOptions::new()
      .with_chunk_size(4096)
      .with_retain_bytes(3 * 4096),
  );
  let chunk_addrs = |r: &Region| {
    let mut v: Vec<usize> = (0..3)
      .map(|_| addr(&*r.alloc_zeroed_bytes(4096).unwrap()))
      .collect();
    v.sort_unstable();
    v
  };
  let first = chunk_addrs(&region);
  for _ in 0..10 {
    region.alloc_zeroed_bytes(4096).unwrap();
  }
  assert_eq!(region.stats().chunks, 13);
  region.reset();
  let s = region.stats();
  assert_eq!(
    (s.chunks, s.capacity, s.used, s.resets),
    (3, 3 * 4096, 0, 1)
  );
  // The same three chunks serve the next round.
  assert_eq!(chunk_addrs(&region), first);
  assert_eq!(region.stats().chunks, 3);
  region.release();
  assert_eq!(region.stats().chunks, 0);
}

#[test]
fn scopes_reset_the_region_after_each_task() {
  let mut region = Region::with_options(RegionOptions::new().with_retain_bytes(1 << 16));
  for task in 0..100u64 {
    let sum = region.scope(|r| {
      let xs = r.alloc_slice_fill(1000, task).unwrap();
      let ys = r.alloc_slice_copy(xs).unwrap();
      ys.iter().sum::<u64>()
    });
    assert_eq!(sum, 1000 * task);
  }
  let s = region.stats();
  assert_eq!((s.chunks, s.used, s.resets), (1, 0, 100));
}

#[test]
fn a_long_lived_region_moves_between_threads() {
  let region = Region::with_options(RegionOptions::new().with_chunk_size(1024));
  let (mut region, first) = std::thread::spawn(move || {
    let first = region.alloc_str("first").unwrap().len();
    (region, first)
  })
  .join()
  .unwrap();
  assert_eq!(first, 5);
  // The chunks taken on the other thread stay valid and are returned from
  // this one.
  let s = region.alloc_str("second").unwrap();
  assert_eq!(&*s, "second");
  let mut region = std::thread::spawn(move || {
    for i in 0..10_000u32 {
      assert_eq!(*region.alloc_copy(i).unwrap(), i);
    }
    region.reset();
    region
  })
  .join()
  .unwrap();
  assert!(region.stats().chunks > 1);
  region.release();
}

#[test]
fn one_region_per_thread() {
  std::thread::scope(|s| {
    for t in 0..8u64 {
      s.spawn(move || {
        let mut region = Region::with_options(RegionOptions::new().with_chunk_size(2048));
        for round in 0..20 {
          let pieces: Vec<&mut [u64]> = (0..200)
            .map(|i| region.alloc_slice_fill(i % 37, t * 1000 + round).unwrap())
            .collect();
          assert!(
            pieces
              .iter()
              .all(|p| p.iter().all(|&x| x == t * 1000 + round))
          );
          region.reset();
        }
      });
    }
  });
}
