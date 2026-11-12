use std::vec;
use std::vec::Vec;

use super::*;

/// A claimed word listing `fill` in order, of which the first `len` are live.
fn list(fill: &[u8; 64], len: u8) -> CachedBlocks {
  let cw = CachedBlocks {
    base: Cell::new(0),
    blocks: [const { Cell::new(0) }; 64],
    len: Cell::new(len),
  };
  for (b, &v) in cw.blocks.iter().zip(fill) {
    b.set(v);
  }
  cw
}

/// What [`CachedBlocks::holds`] answers: a search of the live entries.
fn listed(cw: &CachedBlocks, i: u32) -> bool {
  cw.blocks[..usize::from(cw.len.get())]
    .iter()
    .any(|b| u32::from(b.get()) == i)
}

fn xorshift64(x: &mut u64) -> u64 {
  *x ^= *x << 13;
  *x ^= *x >> 7;
  *x ^= *x << 17;
  *x
}

/// Lists to check membership on: in order, reversed, one block repeated,
/// halves that repeat each other (so a stale entry repeats a live one),
/// and shuffled orders like those a seeded cache leaves.
fn fills() -> Vec<[u8; 64]> {
  let ascending: [u8; 64] = core::array::from_fn(|k| k as u8);
  let mut fills = vec![
    ascending,
    core::array::from_fn(|k| 63 - k as u8),
    [0; 64],
    [63; 64],
    core::array::from_fn(|k| (k % 32) as u8),
    core::array::from_fn(|k| (k % 7) as u8 * 9),
  ];
  let mut x = 0x9E37_79B9_7F4A_7C15;
  for _ in 0..if cfg!(miri) { 2 } else { 16 } {
    let mut f = ascending;
    for k in (1..64).rev() {
      f.swap(k, (xorshift64(&mut x) % (k as u64 + 1)) as usize);
    }
    fills.push(f);
  }
  fills
}

#[test]
fn holds_answers_for_the_live_entries_only() {
  for fill in fills() {
    for len in 0..=64 {
      let cw = list(&fill, len);
      for i in 0..64 {
        assert_eq!(
          cw.holds(i),
          listed(&cw, i),
          "block {i}, length {len}, list {fill:?}"
        );
      }
    }
  }
}

#[test]
fn holds_at_the_ends_of_the_list() {
  let ascending: [u8; 64] = core::array::from_fn(|k| k as u8);
  // An empty list holds nothing, though its entries still name blocks.
  assert!((0..64).all(|i| !list(&ascending, 0).holds(i)));
  // The first and the last of 64 live entries, and the one live entry of
  // a list whose other entries are stale.
  let full = list(&ascending, 64);
  assert!(full.holds(0) && full.holds(63));
  let one = list(&ascending, 1);
  assert!(one.holds(0));
  assert!((1..64).all(|i| !one.holds(i)));
  // The entry just past the end is stale.
  let most = list(&ascending, 63);
  assert!(most.holds(62) && !most.holds(63));
}

/// Sizes at and around every class boundary, and the ends of the range.
fn boundary_sizes() -> Vec<usize> {
  let mut sizes = vec![0, 1, 15, 16, 17, SMALL_MAX, SMALL_MAX + 1];
  for c in 0..NUM_CLASSES {
    let s = class::size(c);
    sizes.extend([s - 1, s, s + 1]);
  }
  sizes
}

#[test]
fn aligned_class_is_the_class_that_class_for_finds() {
  let sizes: Vec<usize> = if cfg!(miri) {
    boundary_sizes()
  } else {
    (0..=SMALL_MAX + 1).collect()
  };
  for shift in 0..=17 {
    let align = 1usize << shift;
    for &size in &sizes {
      assert_eq!(
        aligned_class(size, align),
        class::class_for(size, align),
        "size {size} align {align}"
      );
    }
  }
  for size in [SMALL_MAX + 2, 1 << 20, usize::MAX] {
    assert_eq!(aligned_class(size, 32), None, "size {size}");
  }
}

#[test]
fn aligned_class_refuses_alignments_that_are_not_powers_of_two() {
  // `Heap::kind` refuses them too, so the request fails as before.
  for align in [0, 3, 24, 48, 96, 3 << 10, usize::MAX] {
    for size in [0, 1, 48, 4096] {
      assert_eq!(
        aligned_class(size, align),
        None,
        "size {size} align {align}"
      );
    }
  }
}
