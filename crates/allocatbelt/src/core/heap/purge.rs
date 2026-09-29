//! Purge passes: releasing empty small pages, returning dirty pages' memory
//! to the OS and empty segments to the arena.
//!
//! Freed page runs are only marked dirty and stay resident, so that a
//! workload that frees and reallocates reuses them without a syscall. Three
//! kinds of pass (sweeps, run in bounded slices, see [`super::reclaim`])
//! return memory:
//!
//! * a **decay** pass purges the pages that have been dirty for the purge
//!   delay, and returns segments that have been empty that long. Decay
//!   epochs are due every quarter delay; allocation slow paths start one
//!   when it is due, or a background thread calls [`Heap::decay`] instead.
//!   Ages are counted in decay epochs rather than read from the clock, so
//!   freeing never reads it: a page freed in epoch `e` is purged by the
//!   pass that starts epoch `e + 5`, one to one and a quarter delays later
//!   when passes are regular, later when they are not (and later still
//!   with [`Retention::Adaptive`](super::Retention::Adaptive));
//! * a **budget** cycle runs when more than the trigger
//!   ([`ReclaimTargets`](super::ReclaimTargets), 512 pages by default) are
//!   dirty and purges regardless of age down to the low target, bounding
//!   the tracked dirty pages under churn (not the process's RSS: live
//!   blocks, blocks held in thread caches, metadata and pages the OS has
//!   not reclaimed yet are outside it);
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

use super::maint::PassWork;
use super::reclaim::Want;
use super::*;

/// Decay epochs per purge delay.
pub(super) const DECAY_STEPS: u64 = 4;

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

/// Runs claimed by a slice and not yet purged.
pub(super) struct Batch {
  ranges: [(usize, usize); PURGE_BATCH],
  purged: [bool; PURGE_BATCH],
  pub(super) len: usize,
  /// Per segment in the batch: its index and the pages claimed in it.
  segs: [(usize, u64); PURGE_BATCH],
  nsegs: usize,
  /// The work of the slice so far.
  pub(super) work: PassWork,
}

impl Batch {
  pub(super) const fn new() -> Self {
    Self {
      ranges: [(0, 0); PURGE_BATCH],
      purged: [false; PURGE_BATCH],
      len: 0,
      segs: [(0, 0); PURGE_BATCH],
      nsegs: 0,
      work: PassWork::new(),
    }
  }

  /// Pages claimed and not purged yet.
  pub(super) fn claimed_pages(&self) -> u64 {
    self.segs[..self.nsegs]
      .iter()
      .map(|&(_, claimed)| u64::from(claimed.count_ones()))
      .sum()
  }
}

impl<O: Os> Heap<O> {
  /// Returns the memory of every free, dirty page to the OS, and empty
  /// segments (beyond one per shard) to the arena, without waiting for the
  /// purge delay: a force sweep, run to its end here in slices (replacing
  /// any other sweep in progress; a budget cycle continues afterwards if
  /// still needed).
  ///
  /// Embedders may call this from a maintenance task (e.g. when idle).
  /// Shards that are allocating at that moment keep their empty segments
  /// until the next pass. Blocks held in thread caches stay allocated; flush
  /// the calling thread's cache first with [`Heap::flush`]. Pages freed
  /// while it runs may stay dirty: it does not chase concurrent frees.
  pub fn purge(&self) {
    let _g = self.purge_lock.lock(&self.os);
    self.reset_retention();
    self.run_sweep(Want::NewForce, &mut SyncPurger(&self.os));
  }

  /// Runs a decay pass: advances the decay epoch, then purges the pages
  /// that have been dirty for the purge delay and returns segments that
  /// have been empty that long, to the end of the sweep. A sweep of
  /// another kind in progress is finished first. For a background thread
  /// that calls it every [`Heap::decay_interval_ms`]; see
  /// [`Heap::set_auto_decay`].
  pub fn decay(&self) {
    let _g = self.purge_lock.lock(&self.os);
    self.decay_tick(self.os.now_ms());
    self.run_sweep(Want::Decay, &mut SyncPurger(&self.os));
  }

  /// Sets how long freed pages stay resident and empty segments stay owned
  /// before a decay pass returns them ([`DEFAULT_PURGE_DELAY_MS`] by
  /// default). 0 returns them at the next pass. A sweep in progress keeps
  /// the delay it started with.
  pub fn set_purge_delay_ms(&self, ms: u64) {
    self.purge_delay_ms.store(ms, Relaxed);
    if ms == 0 {
      self.reset_retention();
    }
    self.poke_maintenance();
  }

  /// The current purge delay in milliseconds.
  pub fn purge_delay_ms(&self) -> u64 {
    self.purge_delay_ms.load(Relaxed)
  }

  /// How often decay epochs are due: a quarter of the purge delay, at least
  /// 1 ms.
  pub fn decay_interval_ms(&self) -> u64 {
    (self.purge_delay_ms() / DECAY_STEPS).max(1)
  }

  /// Whether allocation slow paths run decay passes when they are due (the
  /// default). An embedder that calls [`Heap::decay`] from a background
  /// thread turns this off, which keeps the passes off allocating threads.
  pub fn set_auto_decay(&self, on: bool) {
    self.auto_decay.store(on, Relaxed);
  }

  /// Returns an unlinked owned segment whose pages have all been claimed
  /// by the caller to the arena.
  pub(super) fn free_owned_segment(&self, seg: usize, m: &[AtomicU64]) {
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
  #[cfg(any(all(test, allocatbelt_core_check), allocatbelt_model))]
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
  /// if they do not fit. `kernel` compares the ages if given.
  pub(super) fn claim_segment<P: Purger>(
    &self,
    seg: usize,
    m: &[AtomicU64],
    cutoff: u64,
    kernel: Option<AgeKernel>,
    batch: &mut Batch,
    purger: &mut P,
  ) {
    let mut eligible = u64::MAX;
    if cutoff != u64::MAX {
      let candidates = m[SEG_DIRTY].load(Acquire) & !m[SEG_PAGES].load(Acquire);
      if candidates == 0 {
        return;
      }
      eligible = match kernel {
        None => {
          let mut d = candidates;
          let mut aged = 0;
          while d != 0 {
            let i = d.trailing_zeros() as usize;
            d &= d - 1;
            if PageMeta::new(m, i).since().load(Relaxed) <= cutoff {
              aged |= 1 << i;
            }
          }
          aged
        }
        Some(kernel) => {
          // A snapshot taken with one atomic load per page: the kernel
          // works on this private copy, never with vector loads of the
          // shared words. Ages of pages that are not candidates are
          // masked off.
          let mut since = [0; PAGES_PER_SEGMENT];
          for (i, t) in since.iter_mut().enumerate() {
            *t = PageMeta::new(m, i).since().load(Relaxed);
          }
          kernel(&since, cutoff) & candidates
        }
      };
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
  pub(super) fn purge_claimed<P: Purger>(&self, batch: &mut Batch, purger: &mut P) {
    if batch.len == 0 {
      return;
    }
    let (ranges, purged) = (&batch.ranges[..batch.len], &mut batch.purged[..batch.len]);
    purged.fill(false);
    purger.purge_batch(ranges, purged);
    batch.work.batches += 1;
    batch.work.runs += batch.len as u64;
    batch.work.failed_runs += purged.iter().filter(|&&p| !p).count() as u64;
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
      batch.work.purged_pages += u64::from(cleared.count_ones());
    }
    batch.len = 0;
    batch.nsegs = 0;
  }

  /// Releases every small page of segment `seg` whose blocks are all free
  /// and returns the number of small pages it checked. Caller holds the
  /// lock of the shard that owns the segment.
  pub(super) fn release_empty_pages(
    &self,
    seg: usize,
    m: &[AtomicU64],
    work: &mut PassWork,
  ) -> u64 {
    let mut inspected = 0;
    for c in 0..NUM_CLASSES {
      let cap = class::capacity(c) as i64;
      let mut pages = m[SEG_CLS + c].load(Relaxed);
      while pages != 0 {
        let i = pages.trailing_zeros() as usize;
        pages &= pages - 1;
        // Frees set bits before bumping the counter, and our own
        // claims are subtracted under this lock, so the counter never
        // overstates the free blocks here.
        inspected += 1;
        if PageMeta::new(m, i).free().load(Acquire) as i64 >= cap {
          self.release_small_page(seg * PAGES_PER_SEGMENT + i, m, c);
          work.released_pages += 1;
        }
      }
    }
    work.trim_pages_inspected += inspected;
    inspected
  }
}
