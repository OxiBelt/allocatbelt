//! The compiled kernels against their portable forms.

use core::cell::Cell;

use super::{IMPLEMENTATION, list_holds, unpack_blocks};
use crate::core::{list_holds as portable_holds, unpack_blocks as portable_unpack};

/// A deterministic generator (splitmix64), so failures reproduce.
struct Rng(u64);

impl Rng {
  fn next(&mut self) -> u64 {
    self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = self.0;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
  }
}

fn cells(bytes: [u8; 64]) -> [Cell<u8>; 64] {
  bytes.map(Cell::new)
}

fn bytes(cells: &[Cell<u8>; 64]) -> [u8; 64] {
  core::array::from_fn(|k| cells[k].get())
}

/// Lists a cache can hold (distinct block numbers in some order) and lists
/// it cannot (repeats, constants), which a kernel must still answer for.
fn fills() -> Vec<[u8; 64]> {
  let mut rng = Rng(0x00A1_10CA_7BE1_7000);
  let mut fills = vec![
    core::array::from_fn(|k| k as u8),
    core::array::from_fn(|k| 63 - k as u8),
    [0; 64],
    [63; 64],
    core::array::from_fn(|k| (k as u8) & 1),
  ];
  for _ in 0..40 {
    let mut permutation: [u8; 64] = core::array::from_fn(|k| k as u8);
    for k in (1..64).rev() {
      permutation.swap(k, (rng.next() % (k as u64 + 1)) as usize);
    }
    fills.push(permutation);
    fills.push(core::array::from_fn(|_| (rng.next() & 63) as u8));
  }
  fills
}

#[test]
fn list_holds_matches_the_portable_loop_for_every_length_and_block() {
  eprintln!("asm kernels: {IMPLEMENTATION}");
  for fill in fills() {
    let list = cells(fill);
    for len in 0..=64u8 {
      for i in 0..64u8 {
        assert_eq!(
          list_holds(&list, len, i),
          portable_holds(&list, len, i),
          "block {i}, length {len}, list {fill:?}"
        );
      }
    }
    assert_eq!(bytes(&list), fill, "list_holds must not write");
  }
}

fn masks() -> Vec<u64> {
  let mut rng = Rng(0xB17_5EED);
  let mut masks = vec![
    0,
    u64::MAX,
    1,
    1 << 63,
    0x5555_5555_5555_5555,
    !0x5555_5555_5555_5555,
  ];
  for b in 0..64 {
    masks.push(1 << b);
    masks.push(!(1 << b));
    masks.push(u64::MAX << b);
    masks.push(u64::MAX >> b);
    masks.push(0xFF << (b & 56));
  }
  for round in 0..4000 {
    // Sparse, dense and uniform words.
    let x = rng.next();
    masks.push(match round % 4 {
      0 => x,
      1 => x & rng.next() & rng.next(),
      2 => x | rng.next() | rng.next(),
      _ => x & (u64::MAX >> (rng.next() & 63)),
    });
  }
  masks
}

#[test]
fn unpack_blocks_matches_the_portable_loop() {
  for bits in masks() {
    // Stale entries a kernel may overwrite, but must not report.
    let got = cells([0xA5; 64]);
    let want = cells([0xA5; 64]);
    let n = unpack_blocks(bits, &got);
    assert_eq!(n, portable_unpack(bits, &want), "count of {bits:#018x}");
    assert_eq!(u32::from(n), bits.count_ones());
    let n = usize::from(n);
    assert_eq!(
      bytes(&got)[..n],
      bytes(&want)[..n],
      "entries of {bits:#018x}"
    );
  }
}

/// An anonymous mapping of three 64 KiB granules whose first and last are
/// inaccessible, so a read or write outside a list placed at either end of
/// the middle one faults.
struct Guarded {
  base: *mut u8,
}

const GRANULE: usize = 64 * 1024;

impl Guarded {
  fn new() -> Self {
    // SAFETY: an anonymous private mapping with a null hint is a fresh
    // range; `Drop` unmaps it.
    let base = unsafe {
      libc::mmap(
        core::ptr::null_mut(),
        3 * GRANULE,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
      )
    };
    assert_ne!(base, libc::MAP_FAILED);
    let base = base.cast::<u8>();
    for granule in [0, 2] {
      // SAFETY: a granule of the mapping above, which nothing refers to.
      let r = unsafe {
        libc::mprotect(
          base.wrapping_add(granule * GRANULE).cast(),
          GRANULE,
          libc::PROT_NONE,
        )
      };
      assert_eq!(r, 0);
    }
    Self { base }
  }

  /// The list that starts `at` bytes into the accessible granule.
  fn list(&self, at: usize) -> &[Cell<u8>; 64] {
    assert!(at <= GRANULE - 64);
    let p = self
      .base
      .wrapping_add(GRANULE + at)
      .cast::<[Cell<u8>; 64]>();
    // SAFETY: 64 bytes inside the accessible, zero-filled granule; `Cell<u8>`
    // has the layout of `u8`, and this test's thread alone uses the mapping.
    unsafe { &*p }
  }
}

impl Drop for Guarded {
  fn drop(&mut self) {
    // SAFETY: the mapping made in `new`, unmapped once.
    assert_eq!(unsafe { libc::munmap(self.base.cast(), 3 * GRANULE) }, 0);
  }
}

#[test]
fn kernels_touch_only_the_64_entries() {
  let guarded = Guarded::new();
  let mut rng = Rng(0x6A2D);
  // Flush against the inaccessible granule below, against the one above,
  // and at every alignment in between the two.
  let mut places = vec![0, GRANULE - 64];
  places.extend((1..64).map(|k| GRANULE - 64 - k));
  places.extend(1..64);
  for at in places {
    let list = guarded.list(at);
    for round in 0..64 {
      let bits = match round {
        0 => 0,
        1 => u64::MAX,
        _ => rng.next() & rng.next(),
      };
      let want = cells([0; 64]);
      let n = unpack_blocks(bits, list);
      assert_eq!(n, portable_unpack(bits, &want));
      assert_eq!(
        bytes(list)[..usize::from(n)],
        bytes(&want)[..usize::from(n)]
      );
      for len in [0, 1, n / 2, n, 64] {
        for i in [0, 1, 31, 32, 62, 63, (rng.next() & 63) as u8] {
          assert_eq!(list_holds(list, len, i), portable_holds(list, len, i));
        }
      }
    }
  }
}
