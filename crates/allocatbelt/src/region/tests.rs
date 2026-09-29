//! Region tests over the system allocator (so that Miri can run them; the
//! heap needs `mmap`), and over a source that fails on request. The
//! integration tests in `tests/region.rs` cover the heap-backed `Region`.

use std::alloc::System;
use std::cell::Cell;
use std::vec::Vec;

use super::*;

/// The system allocator, counting live chunks and failing when told to.
#[derive(Default)]
struct Source {
  live: Cell<usize>,
  taken: Cell<usize>,
  fail: Cell<bool>,
}

impl ChunkSource for &Source {
  fn allocate(&self, layout: Layout) -> Option<NonNull<u8>> {
    if self.fail.get() {
      return None;
    }
    // SAFETY: regions only ask for chunks of non-zero size.
    #[expect(unsafe_code, reason = "test chunk source")]
    let p = NonNull::new(unsafe { System.alloc(layout) })?;
    self.live.set(self.live.get() + 1);
    self.taken.set(self.taken.get() + 1);
    Some(p)
  }

  #[expect(unsafe_code, reason = "test chunk source")]
  unsafe fn release(&self, ptr: NonNull<u8>, layout: Layout) {
    self.live.set(self.live.get() - 1);
    // SAFETY: `ptr` came from `System.alloc(layout)` above (the contract).
    unsafe { System.dealloc(ptr.as_ptr(), layout) }
  }
}

fn region(source: &Source, options: RegionOptions) -> RawRegion<&Source> {
  RawRegion::new(source, options)
}

fn small() -> RegionOptions {
  RegionOptions::new()
    .with_chunk_size(256)
    .with_retain_bytes(512)
}

#[test]
fn values_keep_their_contents_and_alignment() {
  let src = Source::default();
  let r = region(&src, small());
  let a = r.alloc_copy(0x1122_3344_5566_7788u64).unwrap();
  let b = r.alloc_copy(7u8).unwrap();
  let c = r.alloc_copy([1u128, 2]).unwrap();
  let s = r.alloc_str("héllo").unwrap();
  let v = r.alloc_slice_copy(&[1u16, 2, 3]).unwrap();
  let z = r.alloc_zeroed_bytes(40).unwrap();
  // Every piece is live at once and writable.
  *a += 1;
  *b += 1;
  c[1] = 9;
  v[2] = 30;
  z[39] = 1;
  s.make_ascii_uppercase();
  assert_eq!(*a, 0x1122_3344_5566_7789);
  assert_eq!(*b, 8);
  assert_eq!(*c, [1, 9]);
  assert_eq!(v, &[1, 2, 30]);
  assert_eq!(&*s, "HéLLO");
  assert!(z[..39].iter().all(|&x| x == 0));
  assert_eq!(std::ptr::from_ref(a).addr() % align_of::<u64>(), 0);
  assert_eq!(std::ptr::from_ref(c).addr() % align_of::<[u128; 2]>(), 0);
}

#[test]
fn alignments_up_to_beyond_a_chunk() {
  let src = Source::default();
  let r = region(&src, small());
  for shift in 0..=12 {
    let align = 1usize << shift;
    let p = r.piece(3, align).unwrap();
    assert_eq!(p.as_ptr().addr() % align, 0, "align {align}");
  }
  // Alignment beyond the standard chunk: a chunk of its own.
  let before = r.stats().own_chunks;
  let p = r.piece(8, 4096).unwrap();
  assert_eq!(p.as_ptr().addr() % 4096, 0);
  assert!(r.stats().own_chunks > before);
  assert_eq!(r.piece(1, 3), Err(RegionError::Layout));
  assert_eq!(r.piece(1, MAX_ALIGN * 2), Err(RegionError::Layout));
}

#[test]
fn zero_sized_requests_take_no_memory() {
  let src = Source::default();
  let r = region(&src, small());
  let unit = r.alloc_copy(()).unwrap();
  let empty = r.alloc_slice_copy::<u64>(&[]).unwrap();
  let none = r.alloc_zeroed_bytes(0).unwrap();
  let zst = r.alloc_slice_fill(1000, ()).unwrap();
  assert_eq!(*unit, ());
  assert!(empty.is_empty() && none.is_empty());
  assert_eq!(zst.len(), 1000);
  assert_eq!(empty.as_ptr().addr() % align_of::<u64>(), 0);
  assert_eq!((r.stats().chunks, src.taken.get()), (0, 0));
}

#[test]
fn pieces_fill_chunks_then_take_new_ones() {
  let src = Source::default();
  let r = region(&src, small());
  let mut pieces = Vec::new();
  for i in 0..100u32 {
    pieces.push(r.alloc_slice_fill(7, i).unwrap());
  }
  // 28 bytes each, aligned to 4: 9 per 256-byte chunk.
  assert_eq!(r.stats().chunks, 12);
  for (i, p) in pieces.iter().enumerate() {
    assert!(
      p.iter().all(|&x| x as usize == i),
      "piece {i} was overwritten"
    );
  }
}

#[test]
fn large_requests_get_chunks_of_their_own() {
  let src = Source::default();
  let r = region(&src, small());
  let a = r.alloc_copy(1u64).unwrap();
  let big = r.alloc_slice_fill(1000, 5u32).unwrap();
  // The standard chunk goes on after the large request.
  let b = r.alloc_copy(2u64).unwrap();
  let s = r.stats();
  assert_eq!((s.chunks, s.own_chunks), (2, 1));
  assert_eq!(
    std::ptr::from_ref(b).addr() - std::ptr::from_ref(a).addr(),
    8
  );
  assert!(big.iter().all(|&x| x == 5));
}

#[test]
fn resets_keep_standard_chunks_up_to_the_retain_bytes() {
  let src = Source::default();
  let mut r = region(&src, small());
  for i in 0..40u64 {
    r.alloc_slice_fill(8, i).unwrap();
  }
  r.alloc_slice_fill(10_000, 0u8).unwrap();
  let before = r.stats();
  assert!(before.chunks > 3 && before.own_chunks == 1);
  r.reset();
  // Two 256-byte chunks fit 512 retained bytes; the large one goes.
  let s = r.stats();
  assert_eq!(
    (s.chunks, s.own_chunks, s.capacity, s.used, s.resets),
    (2, 0, 512, 0, 1)
  );
  assert_eq!(src.live.get(), 2);
  // The retained chunks are reused before a new one is taken.
  let taken = src.taken.get();
  for i in 0..8u64 {
    r.alloc_slice_fill(8, i).unwrap();
  }
  assert_eq!(src.taken.get(), taken);
  r.alloc_slice_fill(8, 0u64).unwrap();
  assert_eq!(src.taken.get(), taken + 1);
  r.release();
  assert_eq!(
    (r.stats().chunks, r.stats().capacity, src.live.get()),
    (0, 0, 0)
  );
  // Still usable after a release.
  assert_eq!(*r.alloc_copy(3u8).unwrap(), 3);
}

#[test]
fn a_retain_of_zero_returns_every_chunk() {
  let src = Source::default();
  let mut r = region(&src, small().with_retain_bytes(0));
  r.alloc_zeroed_bytes(100).unwrap();
  r.reset();
  assert_eq!((r.stats().chunks, src.live.get()), (0, 0));
  r.alloc_zeroed_bytes(100).unwrap();
  assert_eq!(src.live.get(), 1);
}

#[test]
fn failures_leave_the_region_and_its_pieces_intact() {
  let src = Source::default();
  let r = region(&src, small().with_limit_bytes(512));
  let a = r.alloc_slice_fill(60, 1u32).unwrap();
  let b = r.alloc_slice_fill(60, 2u32).unwrap();
  // A third chunk would pass the limit.
  assert_eq!(r.alloc_slice_fill(60, 3u32), Err(RegionError::Limit));
  assert_eq!(r.alloc_slice_fill(1000, 3u32), Err(RegionError::Limit));
  // What still fits the current chunk is served.
  let c = r.alloc_copy(4u32).unwrap();
  src.fail.set(true);
  let r2 = region(&src, small());
  assert_eq!(r2.alloc_copy(1u8), Err(RegionError::OutOfMemory));
  assert_eq!(r2.stats(), RegionStats::default());
  src.fail.set(false);
  assert!(a.iter().all(|&x| x == 1) && b.iter().all(|&x| x == 2) && *c == 4);
  assert_eq!(r.stats().capacity, 512);
  // Overflowing sizes are refused before any chunk is taken.
  assert_eq!(
    r2.alloc_slice_fill(usize::MAX, 0u64),
    Err(RegionError::Layout)
  );
  assert_eq!(
    r2.alloc_slice_fill(isize::MAX as usize, 0u16),
    Err(RegionError::Layout)
  );
}

#[test]
fn dropping_returns_every_chunk() {
  let src = Source::default();
  {
    let r = region(&src, small());
    r.alloc_zeroed_bytes(10).unwrap();
    r.alloc_zeroed_bytes(5000).unwrap();
    assert_eq!(src.live.get(), 2);
  }
  assert_eq!(src.live.get(), 0);
}

#[test]
fn many_resets_reuse_the_same_chunks() {
  let src = Source::default();
  let mut r = region(&src, small());
  for round in 0..50u32 {
    let xs = r.alloc_slice_fill(20, round).unwrap();
    let ys = r.alloc_slice_copy(xs).unwrap();
    assert!(ys.iter().all(|&y| y == round));
    r.reset();
  }
  assert_eq!(src.taken.get(), 1);
  assert_eq!(r.stats().resets, 50);
}

#[test]
#[cfg_attr(miri, ignore = "the heap needs mmap")]
fn heap_chunks_serve_every_alignment_up_to_the_largest() {
  let r = RawRegion::new(HeapChunks, RegionOptions::new());
  for shift in 0..=MAX_ALIGN.trailing_zeros() {
    let align = 1usize << shift;
    let p = r.piece(24, align).unwrap();
    assert_eq!(p.as_ptr().addr() % align, 0, "align {align}");
    // SAFETY: the piece is 24 bytes, writable, and not otherwise used.
    #[expect(unsafe_code, reason = "writing to a fresh piece")]
    unsafe {
      p.as_ptr().wrapping_add(23).write(1);
    }
  }
  assert!(r.stats().own_chunks >= 2);
}
