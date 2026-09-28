//! One segment's metadata words, laid out as in allocatbelt's core, so that
//! a kernel can be measured on the data the allocator would really read.
//!
//! The `age` family runs its kernels on a contiguous `[u64; 64]`. In the
//! heap, the epoch in which a free page was marked dirty is word `P_SINCE`
//! of that page's metadata record, so the 64 epochs of a segment are
//! `PAGE_META_WORDS` words (544 bytes) apart, and they are `AtomicU64`s that
//! frees store to while a purge pass reads them. A dense kernel therefore
//! first copies them into a local snapshot with one atomic load each (plan
//! §7.1, §8), touching one cache line per page, where `Heap::purge_segment`
//! loads only the candidates' epochs.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering::Relaxed;

use allocatbelt_core_check::core::{
  META_WORDS, PAGE_META_WORDS, PAGES_PER_SEGMENT, SEGMENT_HEADER_WORDS,
};

/// Word of a page record that holds the page's dirty epoch. Mirrors the
/// private `P_SINCE` of the core's heap.
const P_SINCE: usize = 3;

/// The metadata words of one segment; only the dirty epochs are set.
#[derive(Debug)]
pub struct SegmentMeta(Box<[AtomicU64]>);

impl SegmentMeta {
  /// Metadata in which page `i` was marked dirty in epoch `since[i]`.
  #[must_use]
  pub fn new(since: &[u64; PAGES_PER_SEGMENT]) -> Self {
    let words: Box<[AtomicU64]> = (0..META_WORDS).map(|_| AtomicU64::new(0)).collect();
    for (page, &epoch) in since.iter().enumerate() {
      words[Self::since_index(page)].store(epoch, Relaxed);
    }
    Self(words)
  }

  const fn since_index(page: usize) -> usize {
    SEGMENT_HEADER_WORDS + page * PAGE_META_WORDS + P_SINCE
  }

  fn since(&self, page: usize) -> &AtomicU64 {
    &self.0[Self::since_index(page)]
  }

  /// The bits `i` of `candidates` whose page has been dirty since epoch
  /// `cutoff` or earlier, one atomic load per candidate: the loop of
  /// `Heap::purge_segment`.
  #[must_use]
  pub fn age_sparse(&self, candidates: u64, cutoff: u64) -> u64 {
    let mut eligible = 0;
    let mut d = candidates;
    while d != 0 {
      let i = d.trailing_zeros() as usize;
      d &= d - 1;
      if self.since(i).load(Relaxed) <= cutoff {
        eligible |= 1 << i;
      }
    }
    eligible
  }

  /// [`SegmentMeta::age_sparse`] without the data-dependent branch, so the
  /// candidates' loads do not wait for mispredicted comparisons.
  #[must_use]
  pub fn age_sparse_branchless(&self, candidates: u64, cutoff: u64) -> u64 {
    let mut eligible = 0;
    let mut d = candidates;
    while d != 0 {
      let i = d.trailing_zeros();
      d &= d - 1;
      eligible |= u64::from(self.since(i as usize).load(Relaxed) <= cutoff) << i;
    }
    eligible
  }

  /// The 64 dirty epochs, one atomic load each: the local snapshot a dense
  /// kernel works on.
  #[must_use]
  pub fn snapshot(&self) -> [u64; PAGES_PER_SEGMENT] {
    core::array::from_fn(|page| self.since(page).load(Relaxed))
  }
}

#[cfg(test)]
mod tests {
  use super::SegmentMeta;
  use crate::kernels::Families;

  #[test]
  fn snapshot_reads_every_epoch() {
    let since: [u64; 64] = core::array::from_fn(|i| i as u64 * 3 + 1);
    assert_eq!(SegmentMeta::new(&since).snapshot(), since);
  }

  #[test]
  fn sparse_and_snapshot_kernels_agree_with_the_age_baseline() {
    let f = Families::detected();
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
      x ^= x << 13;
      x ^= x >> 7;
      x ^= x << 17;
      x
    };
    for _ in 0..100 {
      let since: [u64; 64] = core::array::from_fn(|_| next() % 16);
      let seg = SegmentMeta::new(&since);
      let snap = seg.snapshot();
      for candidates in [0, 1, 1 << 63, u64::MAX, next()] {
        for cutoff in [0, 7, u64::MAX, next() % 16] {
          let want = (f.age[0].get())(&since, candidates, cutoff);
          assert_eq!(seg.age_sparse(candidates, cutoff), want);
          assert_eq!(seg.age_sparse_branchless(candidates, cutoff), want);
          for v in &f.age {
            assert_eq!((v.get())(&snap, candidates, cutoff), want, "{}", v.name());
          }
        }
      }
    }
  }
}
