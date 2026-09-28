//! Purge passes: releasing empty small pages, returning dirty pages' memory
//! to the OS and empty segments to the arena.
//!
//! Freed page runs are only marked dirty and stay resident, so that a
//! workload that frees and reallocates reuses them without a syscall. Three
//! kinds of pass return memory:
//!
//! * a **decay** pass purges the pages that have been dirty for the purge
//!   delay, and returns segments that have been empty that long. Decay
//!   passes are due every quarter delay; allocation slow paths run one when
//!   it is due, or a background thread calls [`Heap::decay`] instead. Ages
//!   are counted in decay passes (epochs) rather than read from the clock,
//!   so freeing never reads it: a page freed in epoch `e` is purged by the
//!   pass that starts epoch `e + 5`, one to one and a quarter delays later
//!   when passes are regular, later when they are not;
//! * a **budget** pass runs when more than [`DIRTY_BUDGET_PAGES`] pages are
//!   dirty and purges all of them at once, bounding RSS under churn;
//! * an explicit [`Heap::purge`] returns everything it can right away.
//!
//! Every pass also releases small pages whose blocks are all free, turning
//! them into dirty free pages that the time rule then handles. Each shard
//! keeps one empty segment, so a shard that drains and refills does not
//! decommit and recommit a segment every time.

use super::*;

/// Decay passes per purge delay.
const DECAY_STEPS: u64 = 4;

/// What a pass returns.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Pass {
  /// Pages dirty for the purge delay; segments empty for the purge delay.
  Decay,
  /// All dirty pages; segments empty for the purge delay.
  Budget,
  /// All dirty pages and all empty segments (but one per shard).
  Force,
}

impl<O: Os> Heap<O> {
  /// Returns the memory of every free, dirty page to the OS, and empty
  /// segments (beyond one per shard) to the arena, without waiting for the
  /// purge delay.
  ///
  /// Embedders may call this from a maintenance task (e.g. when idle).
  /// Shards that are allocating at that moment keep their empty segments
  /// until the next pass. Blocks held in thread caches stay allocated; flush
  /// the calling thread's cache first with [`Heap::flush`].
  pub fn purge(&self) {
    let _g = self.purge_lock.lock(|| self.os.yield_now());
    self.pass(Pass::Force);
  }

  /// Runs a decay pass: purges the pages that have been dirty for the purge
  /// delay and returns segments that have been empty that long. For a
  /// background thread that calls it every [`Heap::decay_interval_ms`]; see
  /// [`Heap::set_auto_decay`].
  pub fn decay(&self) {
    let _g = self.purge_lock.lock(|| self.os.yield_now());
    self.last_decay_ms.store(self.os.now_ms(), Relaxed);
    self.pass(Pass::Decay);
  }

  /// Sets how long freed pages stay resident and empty segments stay owned
  /// before a decay pass returns them ([`DEFAULT_PURGE_DELAY_MS`] by
  /// default). 0 returns them at the next pass.
  pub fn set_purge_delay_ms(&self, ms: u64) {
    self.purge_delay_ms.store(ms, Relaxed);
  }

  /// The current purge delay in milliseconds.
  pub fn purge_delay_ms(&self) -> u64 {
    self.purge_delay_ms.load(Relaxed)
  }

  /// How often decay passes are due: a quarter of the purge delay, at least
  /// 1 ms.
  pub fn decay_interval_ms(&self) -> u64 {
    (self.purge_delay_ms() / DECAY_STEPS).max(1)
  }

  /// Decay passes a page stays dirty (a segment stays empty) before a decay
  /// pass returns it: one more than the passes per delay, since the first
  /// may follow the free immediately.
  fn decay_age(&self) -> u64 {
    if self.purge_delay_ms() == 0 {
      0
    } else {
      DECAY_STEPS + 1
    }
  }

  /// Whether allocation slow paths run decay passes when they are due (the
  /// default). An embedder that calls [`Heap::decay`] from a background
  /// thread turns this off, which keeps the passes off allocating threads.
  pub fn set_auto_decay(&self, on: bool) {
    self.auto_decay.store(on, Relaxed);
  }

  /// Runs a decay pass if one is due and nobody else is running a pass.
  /// Called from allocation slow paths (sampled, as it reads the clock),
  /// never with a shard lock held.
  pub(super) fn maybe_decay(&self) {
    if !self.auto_decay.load(Relaxed) {
      return;
    }
    let now = self.os.now_ms();
    let due = self
      .last_decay_ms
      .load(Relaxed)
      .saturating_add(self.decay_interval_ms());
    if now < due {
      return;
    }
    if let Some(_g) = self.purge_lock.try_lock() {
      self.last_decay_ms.store(now, Relaxed);
      self.pass(Pass::Decay);
    }
  }

  /// Caller holds `purge_lock`.
  pub(super) fn pass(&self, kind: Pass) {
    // Only decay passes age pages and segments.
    let epoch = if kind == Pass::Decay {
      self.epoch.fetch_add(1, Relaxed) + 1
    } else {
      self.epoch.load(Relaxed)
    };
    let age = self.decay_age();
    self.trim_shards(epoch, age, kind == Pass::Force);
    // Pages dirty since epoch `cutoff` or earlier are purged.
    let cutoff = match kind {
      Pass::Decay => epoch.checked_sub(age),
      Pass::Budget | Pass::Force => Some(u64::MAX),
    };
    let Some(cutoff) = cutoff else {
      return;
    };
    for (wi, word) in self.seg_used.iter().enumerate() {
      let mut used_segs = word.load(Relaxed);
      while used_segs != 0 {
        let seg = wi * 64 + used_segs.trailing_zeros() as usize;
        used_segs &= used_segs - 1;
        if let Some(m) = self.os.meta(seg)
          && m[SEG_HDR].load(Acquire) & 0xFF == SEG_OWNED
        {
          self.purge_segment(seg, m, cutoff);
        }
      }
    }
  }

  /// Releases the fully free small pages of each idle shard, then unlinks
  /// and frees its empty segments, except the first, once they have been
  /// empty for `age` epochs (or right away if `force`). Caller holds
  /// `purge_lock`, so no purge pass races the claim.
  fn trim_shards(&self, epoch: u64, age: u64, force: bool) {
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
        let expired = if empty && kept_empty {
          // Idle since epoch `since - 1`; stamped by the first pass that
          // saw it.
          let since = m[SEG_IDLE].load(Relaxed);
          if since == 0 {
            m[SEG_IDLE].store(epoch + 1, Relaxed);
          }
          force || (since != 0 && (since - 1).saturating_add(age) <= epoch)
        } else {
          m[SEG_IDLE].store(0, Relaxed);
          false
        };
        // Claiming every page shuts out the only other claimers:
        // in-place growth, which needs a live block in the segment.
        if expired
          && m[SEG_PAGES]
            .compare_exchange(0, u64::MAX, AcqRel, Relaxed)
            .is_ok()
        {
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
    m[SEG_IDLE].store(0, Relaxed);
    let dirty = m[SEG_DIRTY].swap(0, AcqRel);
    self
      .dirty_pages
      .fetch_sub(dirty.count_ones() as isize, Relaxed);
    self.free_segments(seg, 1);
  }

  /// Purges the free pages of a segment that have been dirty since epoch
  /// `cutoff` or earlier.
  fn purge_segment(&self, seg: usize, m: &[AtomicU64], cutoff: u64) {
    let mut eligible = u64::MAX;
    if cutoff != u64::MAX {
      let mut d = m[SEG_DIRTY].load(Acquire) & !m[SEG_PAGES].load(Acquire);
      if d == 0 {
        return;
      }
      eligible = 0;
      while d != 0 {
        let i = d.trailing_zeros() as usize;
        d &= d - 1;
        if PageMeta::new(m, i).since().load(Relaxed) <= cutoff {
          eligible |= 1 << i;
        }
      }
    }
    // Claim the dirty free pages like an allocation would, so nobody can
    // hand them out while their contents are being discarded.
    let dirty = proto::claim_dirty(&m[SEG_PAGES], &m[SEG_DIRTY], eligible);
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
