//! Checks shared by the experimental kernels' tests.

use crate::core::{AgeKernel, PAGES_PER_SEGMENT, aged_pages};

/// Checks `kernel` against the portable loop: every cutoff around each
/// age of a few layouts, including the extremes.
pub(super) fn check(name: &str, kernel: AgeKernel) {
  let mut x = 0x2545_F491_4F6C_DD1Du64;
  let mut layouts: Vec<[u64; PAGES_PER_SEGMENT]> = vec![
    [0; PAGES_PER_SEGMENT],
    [u64::MAX; PAGES_PER_SEGMENT],
    core::array::from_fn(|i| i as u64),
    core::array::from_fn(|i| (PAGES_PER_SEGMENT - i) as u64),
    core::array::from_fn(|i| if i % 2 == 0 { 0 } else { u64::MAX }),
    core::array::from_fn(|i| 1 << (i % 64)),
  ];
  for _ in 0..64 {
    layouts.push(core::array::from_fn(|_| {
      x ^= x << 13;
      x ^= x >> 7;
      x ^= x << 17;
      // Mostly small epochs, as a decay counter has, with some extremes.
      match x % 16 {
        0 => u64::MAX,
        1 => 0,
        _ => x % 40,
      }
    }));
  }
  for since in &layouts {
    let mut cutoffs = vec![0, 1, u64::MAX - 1, u64::MAX];
    for &t in since {
      cutoffs.extend([t.saturating_sub(1), t, t.saturating_add(1)]);
    }
    for cutoff in cutoffs {
      assert_eq!(
        kernel(since, cutoff),
        aged_pages(since, cutoff),
        "{name}: cutoff {cutoff}, ages {since:?}"
      );
    }
  }
}
