//! Purge passes: releasing empty small pages, returning dirty pages' memory
//! to the OS and empty segments to the arena.

use super::*;

impl<O: Os> Heap<O> {
  /// Returns the memory of every free, dirty page to the OS, and empty
  /// segments (beyond one per shard) to the arena.
  ///
  /// Embedders may call this from a maintenance task (e.g. when idle); it is
  /// also run automatically once the dirty budget is exceeded. Shards that
  /// are allocating at that moment keep their empty segments until the next
  /// pass. Blocks held in thread caches stay allocated; flush the calling
  /// thread's cache first with [`Heap::flush`].
  pub fn purge(&self) {
    let _g = self.purge_lock.lock(|| self.os.yield_now());
    self.purge_segments();
  }

  /// Caller holds `purge_lock`.
  pub(super) fn purge_segments(&self) {
    self.trim_shards();
    for (wi, word) in self.seg_used.iter().enumerate() {
      let mut used_segs = word.load(Relaxed);
      while used_segs != 0 {
        let seg = wi * 64 + used_segs.trailing_zeros() as usize;
        used_segs &= used_segs - 1;
        if let Some(m) = self.os.meta(seg)
          && m[SEG_HDR].load(Acquire) & 0xFF == SEG_OWNED
        {
          self.purge_segment(seg, m);
        }
      }
    }
  }

  /// Releases the fully free small pages of each idle shard, then unlinks
  /// and frees its empty segments, except the first, that were already
  /// empty at the previous pass. Caller holds `purge_lock`, so no purge
  /// pass races the claim.
  fn trim_shards(&self) {
    for sh in &self.shards {
      let Some(_g) = sh.lock.try_lock() else {
        continue;
      };
      for c in 0..NUM_CLASSES {
        self.release_empty_pages(sh, c);
      }
      let mut kept_empty = false;
      let mut prev: Option<&[AtomicU64]> = None;
      let mut cur = sh.segs.load(Relaxed);
      while cur != 0 {
        let seg = cur as usize - 1;
        let m = self.seg_meta(seg);
        let next = m[SEG_NEXT].load(Relaxed);
        let empty = m[SEG_PAGES].load(Acquire) == 0;
        let (idle, bit) = (&self.seg_idle[seg / 64], 1u64 << (seg % 64));
        let was_idle = if empty && kept_empty {
          idle.fetch_or(bit, Relaxed) & bit != 0
        } else {
          idle.fetch_and(!bit, Relaxed);
          false
        };
        // Claiming every page shuts out the only other claimers:
        // in-place growth, which needs a live block in the segment.
        if was_idle
          && m[SEG_PAGES]
            .compare_exchange(0, u64::MAX, AcqRel, Relaxed)
            .is_ok()
        {
          idle.fetch_and(!bit, Relaxed);
          match prev {
            None => sh.segs.store(next as u32, Relaxed),
            Some(p) => p[SEG_NEXT].store(next, Relaxed),
          }
          self.free_owned_segment(seg, m);
        } else {
          kept_empty |= empty;
          prev = Some(m);
        }
        cur = next as u32;
      }
    }
  }

  /// Returns an unlinked owned segment whose pages have all been claimed
  /// by the caller to the arena.
  fn free_owned_segment(&self, seg: usize, m: &[AtomicU64]) {
    m[SEG_HDR].store(SEG_FREE, Release);
    let dirty = m[SEG_DIRTY].swap(0, AcqRel);
    self
      .dirty_pages
      .fetch_sub(dirty.count_ones() as isize, Relaxed);
    self.free_segments(seg, 1);
  }

  fn purge_segment(&self, seg: usize, m: &[AtomicU64]) {
    // Claim the dirty free pages like an allocation would, so nobody can
    // hand them out while their contents are being discarded.
    let dirty = proto::claim_dirty(&m[SEG_PAGES], &m[SEG_DIRTY], u64::MAX);
    if dirty == 0 {
      return;
    }
    let mut rest = dirty;
    let mut purged = 0;
    while rest != 0 {
      let start = rest.trailing_zeros();
      let len = (rest >> start).trailing_ones();
      let page = seg * PAGES_PER_SEGMENT + start as usize;
      let run = run_mask(start, len);
      // Pages that could not be purged keep their dirty mark: they are
      // not known to be zero.
      if self.os.purge(page << PAGE_SHIFT, len as usize * PAGE_SIZE) {
        purged |= run;
      }
      rest &= !run;
    }
    let cleared = proto::finish_purge(&m[SEG_PAGES], &m[SEG_DIRTY], dirty, purged);
    self
      .dirty_pages
      .fetch_sub(cleared.count_ones() as isize, Relaxed);
  }

  /// Releases every page of class `c` whose blocks are all free. Caller
  /// holds the shard lock.
  fn release_empty_pages(&self, sh: &Shard, c: usize) {
    // The cursor is only a scan position; dropping it makes the next
    // claim start from the availability words.
    sh.classes[c].cursor.store(0, Relaxed);
    let cap = class::capacity(c) as i64;
    let mut cur = sh.segs.load(Relaxed);
    while cur != 0 {
      let seg = cur as usize - 1;
      let m = self.seg_meta(seg);
      let mut pages = m[SEG_CLS + c].load(Relaxed);
      while pages != 0 {
        let i = pages.trailing_zeros() as usize;
        pages &= pages - 1;
        // Frees set bits before bumping the counter, and our own
        // claims are subtracted under this lock, so the counter never
        // overstates the free blocks here.
        if PageMeta::new(m, i).free().load(Acquire) as i64 >= cap {
          self.release_small_page(seg * PAGES_PER_SEGMENT + i, m, c);
        }
      }
      cur = m[SEG_NEXT].load(Relaxed) as u32;
    }
  }
}
