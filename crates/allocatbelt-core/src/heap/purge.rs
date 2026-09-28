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
//!
//! A pass hands the dirty page runs it claims to a [`Purger`] in batches.
//! Passes on allocating threads use [`SyncPurger`], one [`Os::purge`] per
//! run as it is claimed; a maintenance thread may batch them instead
//! ([`Heap::maintain_with`]), e.g. through io_uring. The claim is what makes
//! that safe: from `proto::claim_dirty` until `proto::finish_purge`, the
//! claimed pages are allocated as far as every other thread can tell, so
//! nothing hands them out while their purge is in flight, however long the
//! batch takes. A run the purger reports as failed stays dirty and is not
//! reported as zero.

use super::*;

/// Decay passes per purge delay.
const DECAY_STEPS: u64 = 4;

/// The most page runs one [`Purger::purge_batch`] call carries.
pub const PURGE_BATCH: usize = 64;

/// Returns the memory of batches of dirty page runs for purge passes.
///
/// The heap's side of the contract is that of [`Os::purge`]: every range
/// holds only free pages, which the pass has claimed, so no live allocation
/// is in them and none of their pages is handed out until
/// [`Purger::purge_batch`] returns.
pub trait Purger {
  /// Runs worth collecting before a call, at most [`PURGE_BATCH`]. A call
  /// follows the segment that reaches it, so it may carry a few more.
  fn batch_size(&self) -> usize;
  /// Purges each range (byte offset and length, as [`Os::purge`]) and sets
  /// `purged[i]` to whether range `i` now reads as zero. Must not return
  /// before every purge has completed: the heap hands the pages out again
  /// right afterwards. `purged` has the length of `ranges`.
  fn purge_batch(&mut self, ranges: &[(usize, usize)], purged: &mut [bool]);
}

/// Purges run by run through [`Os::purge`], as each segment's runs are
/// claimed: the purger of passes on allocating threads.
pub struct SyncPurger<'a, O>(pub &'a O);

impl<O: Os> Purger for SyncPurger<'_, O> {
  fn batch_size(&self) -> usize {
    1
  }
  fn purge_batch(&mut self, ranges: &[(usize, usize)], purged: &mut [bool]) {
    for (&(offset, len), p) in ranges.iter().zip(purged) {
      *p = self.0.purge(offset, len);
    }
  }
}

/// Runs claimed by a pass and not yet purged.
struct Batch {
  ranges: [(usize, usize); PURGE_BATCH],
  purged: [bool; PURGE_BATCH],
  len: usize,
  /// Per segment in the batch: its index and the pages claimed in it.
  segs: [(usize, u64); PURGE_BATCH],
  nsegs: usize,
}

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
    let _g = self.purge_lock.lock(&self.os);
    self.pass(Pass::Force, &mut SyncPurger(&self.os));
  }

  /// Runs a decay pass: purges the pages that have been dirty for the purge
  /// delay and returns segments that have been empty that long. For a
  /// background thread that calls it every [`Heap::decay_interval_ms`]; see
  /// [`Heap::set_auto_decay`].
  pub fn decay(&self) {
    let _g = self.purge_lock.lock(&self.os);
    self.last_decay_ms.store(self.os.now_ms(), Relaxed);
    self.pass(Pass::Decay, &mut SyncPurger(&self.os));
  }

  /// Sets how long freed pages stay resident and empty segments stay owned
  /// before a decay pass returns them ([`DEFAULT_PURGE_DELAY_MS`] by
  /// default). 0 returns them at the next pass.
  pub fn set_purge_delay_ms(&self, ms: u64) {
    self.purge_delay_ms.store(ms, Relaxed);
    self.poke_maintenance();
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
    if let Some(_g) = self.purge_lock.try_lock(&self.os) {
      self.last_decay_ms.store(now, Relaxed);
      self.pass(Pass::Decay, &mut SyncPurger(&self.os));
      self.count(maint::Stat::InlineDecay);
    }
  }

  /// Caller holds `purge_lock`.
  pub(super) fn pass<P: Purger>(&self, kind: Pass, purger: &mut P) {
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
    let mut batch = Batch {
      ranges: [(0, 0); PURGE_BATCH],
      purged: [false; PURGE_BATCH],
      len: 0,
      segs: [(0, 0); PURGE_BATCH],
      nsegs: 0,
    };
    let batch_size = purger.batch_size().clamp(1, PURGE_BATCH);
    for (wi, word) in self.seg_used.iter().enumerate() {
      let mut used_segs = word.load(Relaxed);
      while used_segs != 0 {
        let seg = wi * 64 + used_segs.trailing_zeros() as usize;
        used_segs &= used_segs - 1;
        if let Some(m) = self.os.meta(seg)
          && m[SEG_HDR].load(Acquire) & 0xFF == SEG_OWNED
        {
          self.claim_segment(seg, m, cutoff, &mut batch, purger);
          if batch.len >= batch_size {
            self.purge_claimed(&mut batch, purger);
          }
        }
      }
    }
    self.purge_claimed(&mut batch, purger);
  }

  /// Releases the fully free small pages of each idle shard, then unlinks
  /// and frees its empty segments, except the first, once they have been
  /// empty for `age` epochs (or right away if `force`). Caller holds
  /// `purge_lock`, so no purge pass races the claim.
  fn trim_shards(&self, epoch: u64, age: u64, force: bool) {
    for sh in &self.shards {
      let Some(_g) = sh.lock.try_lock(&self.os) else {
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
        let empty = m[SEG_PAGES].load(Acquire) == GUARD_BIT;
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
            .compare_exchange(GUARD_BIT, u64::MAX, AcqRel, Relaxed)
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
    // The segment may next be committed whole (e.g. for a huge block).
    self.os.unguard(
      (seg * PAGES_PER_SEGMENT + GUARD_PAGE) << PAGE_SHIFT,
      PAGE_SIZE,
    );
    self.free_segments(seg, 1);
  }

  /// The dirty page count recomputed from the segments' dirty marks, which
  /// must equal [`Heap::dirty_pages`] whenever no pass or free is running.
  #[cfg(any(test, feature = "model"))]
  pub fn dirty_pages_recounted(&self) -> usize {
    let mut n = 0;
    for (wi, word) in self.seg_used.iter().enumerate() {
      let mut used_segs = word.load(Relaxed);
      while used_segs != 0 {
        let seg = wi * 64 + used_segs.trailing_zeros() as usize;
        used_segs &= used_segs - 1;
        if let Some(m) = self.os.meta(seg)
          && m[SEG_HDR].load(Acquire) & 0xFF == SEG_OWNED
        {
          n += m[SEG_DIRTY].load(Relaxed).count_ones() as usize;
        }
      }
    }
    n
  }

  /// Claims the free pages of a segment that have been dirty since epoch
  /// `cutoff` or earlier and adds their runs to `batch`, purging it first
  /// if they do not fit.
  fn claim_segment<P: Purger>(
    &self,
    seg: usize,
    m: &[AtomicU64],
    cutoff: u64,
    batch: &mut Batch,
    purger: &mut P,
  ) {
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
    // A segment has at most 32 runs (63 pages), so they fit an empty batch.
    let runs = (dirty & !(dirty << 1)).count_ones() as usize;
    if batch.len + runs > PURGE_BATCH {
      self.purge_claimed(batch, purger);
    }
    let mut rest = dirty;
    while rest != 0 {
      let start = rest.trailing_zeros();
      let len = (rest >> start).trailing_ones();
      let page = seg * PAGES_PER_SEGMENT + start as usize;
      batch.ranges[batch.len] = (page << PAGE_SHIFT, len as usize * PAGE_SIZE);
      batch.len += 1;
      rest &= !run_mask(start, len);
    }
    batch.segs[batch.nsegs] = (seg, dirty);
    batch.nsegs += 1;
  }

  /// Purges the runs in `batch` and ends the claims on their segments.
  /// Pages that could not be purged keep their dirty mark: they are not
  /// known to be zero.
  fn purge_claimed<P: Purger>(&self, batch: &mut Batch, purger: &mut P) {
    if batch.len == 0 {
      return;
    }
    let (ranges, purged) = (&batch.ranges[..batch.len], &mut batch.purged[..batch.len]);
    purged.fill(false);
    purger.purge_batch(ranges, purged);
    self.count(maint::Stat::Batch);
    self.count_n(maint::Stat::Run, batch.len as u64);
    // Ranges are in segment order, so each segment's are contiguous.
    let mut r = 0;
    for &(seg, claimed) in &batch.segs[..batch.nsegs] {
      let mut done = 0;
      while r < batch.len && batch.ranges[r].0 >> PAGE_SHIFT < (seg + 1) * PAGES_PER_SEGMENT {
        let (offset, len) = batch.ranges[r];
        if batch.purged[r] {
          let start = ((offset >> PAGE_SHIFT) % PAGES_PER_SEGMENT) as u32;
          done |= run_mask(start, (len / PAGE_SIZE) as u32);
        }
        r += 1;
      }
      let m = self.seg_meta(seg);
      let cleared = proto::finish_purge(&m[SEG_PAGES], &m[SEG_DIRTY], claimed, done);
      self
        .dirty_pages
        .fetch_sub(cleared.count_ones() as isize, Relaxed);
    }
    batch.len = 0;
    batch.nsegs = 0;
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
