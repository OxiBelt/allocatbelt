//! Reclamation policy and resumable sweeps (Stage B of the theory-driven
//! plan).
//!
//! **Policy.** Three thresholds on the tracked dirty pages
//! ([`ReclaimTargets`]): a free that takes the count above the *trigger*
//! starts a budget cycle, the cycle purges until the count is at or below
//! the *low target*, and above the *emergency* threshold a freeing thread
//! reclaims itself even when a maintenance thread is attached. The
//! mechanism below does not know how the thresholds were chosen; the
//! optional adaptive retention ([`Retention::Adaptive`]) changes only how
//! long decay keeps pages, never the thresholds.
//!
//! **Sweeps.** Every pass (decay, budget cycle, force purge) is a *sweep*:
//! trimming every shard, then claiming and purging the dirty pages of every
//! owned segment. A sweep runs in *slices*, each bounded by a work limit
//! that counts what it inspects and attempts (shards, segments, small
//! pages, bitmap words, submitted runs), not only what succeeds. Between
//! slices the sweep's position is kept in [`Sweep`]; all of it is changed
//! only under `purge_lock`. A slice finishes every purge it submitted
//! before it returns, so no page stays claimed between slices. Resuming is
//! safe because:
//!
//! * the purge phase keeps only a segment index and re-reads the segment's
//!   header, so a segment returned or reused meanwhile is skipped or
//!   handled as what it is now;
//! * the trim phase keeps the last segment it kept linked in the current
//!   shard's list. Only trimming unlinks segments, trimming only runs
//!   inside a sweep, and a new sweep starts its trim afresh, so that
//!   segment is still linked when the sweep resumes (checked, and the
//!   shard restarted from its head if not). New segments are linked at the
//!   head, before it, and wait for the next sweep.
//!
//! A sweep keeps the epoch, age and cutoff it started with, so a sweep that
//! takes many slices does not age pages faster; decay epochs advance on the
//! schedule only ([`Heap::decay_tick`]).
//!
//! **Priority.** A force purge replaces any other sweep. A budget cycle
//! continues a budget or force sweep, and turns a decay sweep into a budget
//! sweep from where it is (widening its cutoff purges more, never less). A
//! decay sweep starts only when no sweep is in progress; a decay epoch that
//! falls due meanwhile still advances and is owed, so budget work cannot
//! stall decay's bookkeeping.
//!
//! **Cycles.** A budget cycle ends when the dirty count is at or below the
//! low target (checked after each purged segment), or when a full sweep
//! has been made. Dropping below the trigger does not end it. After a full
//! sweep the cycle starts again only if the count is still above the
//! trigger, so frees that race the sweep are not chased below it. A full
//! sweep that made no progress while above the low target (purges refused,
//! nothing to release) *stalls* the cycle: new cycles wait for the next
//! decay epoch, except past the emergency threshold, where freeing threads
//! still run bounded emergency slices. Dirty memory can exceed every
//! threshold when the process frees faster than slices reclaim or the OS
//! refuses purges.

use core::sync::atomic::AtomicBool;

use super::maint::{PassWork, Stat};
use super::purge::{Batch, DECAY_STEPS};
use super::*;

/// Work units a slice may spend (see [`Heap::slice`]). A slice stops at the
/// first unit boundary past it; the largest step (one segment) adds at
/// most a few hundred units.
pub(super) const SLICE_WORK: u64 = 4096;
/// An emergency slice may spend this many times [`SLICE_WORK`].
const EMERGENCY_FACTOR: u64 = 4;

/// Pages of the arena; every threshold must fit.
const ARENA_PAGES: usize = MAX_SEGMENTS * PAGES_PER_SEGMENT;
/// Bits per threshold in the packed word (`ARENA_PAGES` fits).
const TARGET_BITS: u32 = 21;
const _: () = assert!(ARENA_PAGES < 1 << TARGET_BITS);

/// Thresholds on the dirty pages the heap tracks (freed, not purged yet),
/// in allocator pages (64 KiB):
/// `low <= trigger - 1`, `trigger <= emergency`.
///
/// A bound on tracked dirty pages, not on the process's RSS: live and
/// cached blocks, metadata and memory the OS keeps resident are outside
/// it. The defaults ([`ReclaimTargets::DEFAULT`]) are a trigger of 512
/// pages (32 MiB), an emergency threshold of 1024 pages (64 MiB) and a low
/// target of 0, so a budget cycle purges everything it can, as the budget
/// pass did before these thresholds existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReclaimTargets {
  low: usize,
  trigger: usize,
  emergency: usize,
}

/// Why [`ReclaimTargets::new`] refused a set of thresholds.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimTargetsError {
  /// The trigger is zero: every free would start a cycle.
  ZeroTrigger,
  /// Not `low < trigger <= emergency`.
  Order,
  /// A threshold is larger than the arena (2^20 pages, 64 GiB).
  TooLarge,
}

impl core::fmt::Display for ReclaimTargetsError {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(match self {
      Self::ZeroTrigger => "the trigger must be at least one page",
      Self::Order => "the thresholds must satisfy low < trigger <= emergency",
      Self::TooLarge => "a threshold is larger than the arena",
    })
  }
}

impl ReclaimTargets {
  /// A low target of 0, a trigger of 512 pages (32 MiB) and an emergency
  /// threshold of 1024 pages (64 MiB).
  pub const DEFAULT: Self = Self {
    low: 0,
    trigger: DIRTY_BUDGET_PAGES as usize,
    emergency: maint::DIRTY_HARD_LIMIT_PAGES as usize,
  };

  /// Thresholds in allocator pages (64 KiB each).
  ///
  /// # Errors
  ///
  /// If the trigger is 0, if not `low < trigger <= emergency`, or if the
  /// emergency threshold is larger than the arena.
  pub const fn new(
    low: usize,
    trigger: usize,
    emergency: usize,
  ) -> Result<Self, ReclaimTargetsError> {
    if trigger == 0 {
      Err(ReclaimTargetsError::ZeroTrigger)
    } else if low >= trigger || trigger > emergency {
      Err(ReclaimTargetsError::Order)
    } else if emergency > ARENA_PAGES {
      Err(ReclaimTargetsError::TooLarge)
    } else {
      Ok(Self {
        low,
        trigger,
        emergency,
      })
    }
  }

  /// Thresholds in bytes, each rounded down to whole pages.
  ///
  /// # Errors
  ///
  /// As [`ReclaimTargets::new`], after rounding (so a trigger below one
  /// page is [`ReclaimTargetsError::ZeroTrigger`]).
  pub const fn from_bytes(
    low: usize,
    trigger: usize,
    emergency: usize,
  ) -> Result<Self, ReclaimTargetsError> {
    Self::new(low / PAGE_SIZE, trigger / PAGE_SIZE, emergency / PAGE_SIZE)
  }

  /// The low target: a budget cycle purges until at most this many pages
  /// are dirty.
  #[must_use]
  pub const fn low_pages(self) -> usize {
    self.low
  }

  /// The trigger: a free that takes the dirty pages above it starts a
  /// budget cycle.
  #[must_use]
  pub const fn trigger_pages(self) -> usize {
    self.trigger
  }

  /// The emergency threshold: above it a freeing thread reclaims itself,
  /// in slices several times as large, even with a maintenance thread.
  #[must_use]
  pub const fn emergency_pages(self) -> usize {
    self.emergency
  }

  const fn pack(self) -> u64 {
    (self.low as u64)
      | (self.trigger as u64) << TARGET_BITS
      | (self.emergency as u64) << (2 * TARGET_BITS)
  }

  const fn unpack(w: u64) -> Self {
    let mask = (1 << TARGET_BITS) - 1;
    Self {
      low: (w & mask) as usize,
      trigger: ((w >> TARGET_BITS) & mask) as usize,
      emergency: ((w >> (2 * TARGET_BITS)) & mask) as usize,
    }
  }
}

impl Default for ReclaimTargets {
  fn default() -> Self {
    Self::DEFAULT
  }
}

/// How long decay passes keep freed pages (and empty segments) before they
/// return them.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Retention {
  /// Exactly the purge delay (the default).
  #[default]
  Fixed,
  /// Opt-in: between the purge delay and [`MAX_RETENTION`] times it,
  /// adjusted once per decay epoch from how often dirty pages were reused
  /// before a purge versus purged (see [`ReclaimStatus::retention`]). An
  /// allocator-level estimate: it counts reused pages, not page faults.
  /// A purge delay of 0, a force purge and a purge request reset it to the
  /// delay.
  Adaptive,
}

/// Most multiples of the purge delay [`Retention::Adaptive`] keeps pages.
pub const MAX_RETENTION: u32 = 4;

/// Where reclamation stands, for diagnostics and tests. A set of separate
/// reads, like the counters (see `docs/observability.md`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReclaimStatus {
  /// The thresholds in force.
  pub targets: ReclaimTargets,
  /// Pages the heap tracks as dirty.
  pub dirty_pages: usize,
  /// A budget cycle is pending (started and not finished).
  pub budget_pending: bool,
  /// The sweep in progress, if any, by kind.
  pub sweep: Option<Task>,
  /// The last budget cycle stalled (a full sweep made no progress) and new
  /// ones wait for the next decay epoch, except past the emergency
  /// threshold.
  pub budget_deferred: bool,
  /// A decay epoch fell due while another sweep was in progress; a decay
  /// sweep runs when it ends.
  pub decay_owed: bool,
  /// The retention mode.
  pub retention_mode: Retention,
  /// Multiples of the purge delay that decay keeps pages now: 1 with
  /// [`Retention::Fixed`], 1 to [`MAX_RETENTION`] with
  /// [`Retention::Adaptive`].
  pub retention: u32,
}

/// Kinds of sweep, by priority. Stored in [`Sweep::kind`].
const NONE: u64 = 0;
const DECAY: u64 = 1;
const BUDGET: u64 = 2;
const FORCE: u64 = 3;

/// The purge phase is skipped (a decay sweep before any page is old
/// enough).
const NO_CUTOFF: u64 = u64::MAX - 1;

/// What the caller of a slice wants done.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Want {
  /// A new force purge, replacing any sweep in progress ([`Heap::purge`]).
  NewForce,
  /// A force purge: start one unless one is in progress.
  Force,
  /// A budget cycle: start or continue one if the dirty count calls for
  /// it.
  Budget,
  /// A decay sweep: start one if one is owed and nothing is in progress,
  /// else continue what is.
  Decay,
  /// Continue the sweep in progress, if any.
  Continue,
}

/// Who runs a slice, for the counters.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Actor {
  /// The maintenance thread ([`Heap::maintain`]).
  Maintenance,
  /// An allocating or freeing thread.
  Inline,
  /// [`Heap::purge`] and [`Heap::decay`]: not counted as passes.
  Explicit,
}

/// What a slice did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum SliceEnd {
  /// Nothing was wanted or in progress.
  Idle,
  /// Work remains in the sweep.
  More,
  /// A sweep ended (completed, or a budget cycle reached its target).
  Done,
}

/// A sweep's position and parameters, read into a plain value at the start
/// of a slice and written back at its end, under `purge_lock`.
#[derive(Clone, Copy)]
struct SweepState {
  kind: u64,
  /// 0: trim, 1: purge.
  phase: u64,
  epoch: u64,
  age: u64,
  cutoff: u64,
  /// Trim: shards finished, from `trim_start`.
  shards_done: u64,
  /// Trim: last segment (+ 1) kept linked in the current shard, 0 at its
  /// head.
  prev: u64,
  /// Trim: the current shard kept an empty segment already.
  kept_empty: bool,
  /// Purge: segment indices covered, from `purge_start`.
  purge_off: u64,
  /// Pages purged or released and segments returned by this sweep.
  progress: u64,
  trim_start: u64,
  purge_start: u64,
}

/// The persistent state of reclamation, part of the [`Heap`].
#[derive(Debug)]
pub(super) struct Sweep {
  kind: AtomicU64,
  phase: AtomicU64,
  epoch: AtomicU64,
  age: AtomicU64,
  cutoff: AtomicU64,
  shards_done: AtomicU64,
  prev: AtomicU64,
  kept_empty: AtomicBool,
  purge_off: AtomicU64,
  progress: AtomicU64,
  /// Where the next sweep's trim starts (rotates by one per sweep).
  trim_start: AtomicU64,
  /// Where the next sweep's purge phase starts: after the segment where
  /// the last budget sweep reached its target, so the same segments are
  /// not always purged first.
  purge_start: AtomicU64,
  /// [`ReclaimTargets`], packed, so they are read in one load.
  targets: AtomicU64,
  /// A budget cycle is pending. Set by frees without a lock; read by frees
  /// and allocation slow paths as a hint.
  pub(super) budget_pending: AtomicBool,
  /// Epoch in which the last budget cycle stalled, or `u64::MAX`.
  stall_epoch: AtomicU64,
  /// A decay epoch fell due during another sweep.
  decay_owed: AtomicBool,
  /// Work units per slice ([`SLICE_WORK`]; tests lower it).
  slice_work: AtomicU64,
  /// [`Retention`]: 0 fixed, 1 adaptive.
  adaptive: AtomicBool,
  /// Current multiple of the delay decay keeps pages (1..=MAX_RETENTION).
  retention: AtomicU64,
  /// Adaptive: smoothed share of reused pages, in 1/65536.
  reuse_ewma: AtomicU64,
  /// Adaptive: reused and purged pages seen at the last epoch.
  seen_reused: AtomicU64,
  seen_purged: AtomicU64,
  /// Adaptive: epoch of the last change of `retention`.
  last_step: AtomicU64,
}

impl Sweep {
  pub(super) const fn new() -> Self {
    Self {
      kind: AtomicU64::new(NONE),
      phase: AtomicU64::new(0),
      epoch: AtomicU64::new(0),
      age: AtomicU64::new(0),
      cutoff: AtomicU64::new(0),
      shards_done: AtomicU64::new(0),
      prev: AtomicU64::new(0),
      kept_empty: AtomicBool::new(false),
      purge_off: AtomicU64::new(0),
      progress: AtomicU64::new(0),
      trim_start: AtomicU64::new(0),
      purge_start: AtomicU64::new(0),
      targets: AtomicU64::new(ReclaimTargets::DEFAULT.pack()),
      budget_pending: AtomicBool::new(false),
      stall_epoch: AtomicU64::new(u64::MAX),
      decay_owed: AtomicBool::new(false),
      slice_work: AtomicU64::new(SLICE_WORK),
      adaptive: AtomicBool::new(false),
      retention: AtomicU64::new(1),
      reuse_ewma: AtomicU64::new(0),
      seen_reused: AtomicU64::new(0),
      seen_purged: AtomicU64::new(0),
      last_step: AtomicU64::new(0),
    }
  }

  fn load(&self) -> SweepState {
    SweepState {
      kind: self.kind.load(Relaxed),
      phase: self.phase.load(Relaxed),
      epoch: self.epoch.load(Relaxed),
      age: self.age.load(Relaxed),
      cutoff: self.cutoff.load(Relaxed),
      shards_done: self.shards_done.load(Relaxed),
      prev: self.prev.load(Relaxed),
      kept_empty: self.kept_empty.load(Relaxed),
      purge_off: self.purge_off.load(Relaxed),
      progress: self.progress.load(Relaxed),
      trim_start: self.trim_start.load(Relaxed),
      purge_start: self.purge_start.load(Relaxed),
    }
  }

  fn store(&self, s: &SweepState) {
    self.kind.store(s.kind, Relaxed);
    self.phase.store(s.phase, Relaxed);
    self.epoch.store(s.epoch, Relaxed);
    self.age.store(s.age, Relaxed);
    self.cutoff.store(s.cutoff, Relaxed);
    self.shards_done.store(s.shards_done, Relaxed);
    self.prev.store(s.prev, Relaxed);
    self.kept_empty.store(s.kept_empty, Relaxed);
    self.purge_off.store(s.purge_off, Relaxed);
    self.progress.store(s.progress, Relaxed);
    self.trim_start.store(s.trim_start, Relaxed);
    self.purge_start.store(s.purge_start, Relaxed);
  }

  pub(super) fn targets(&self) -> ReclaimTargets {
    ReclaimTargets::unpack(self.targets.load(Relaxed))
  }

  /// The kind of sweep in progress (a hint without `purge_lock`).
  pub(super) fn active(&self) -> Option<Task> {
    match self.kind.load(Relaxed) {
      DECAY => Some(Task::Decay),
      BUDGET => Some(Task::Budget),
      FORCE => Some(Task::Force),
      _ => None,
    }
  }
}

impl<O: Os> Heap<O> {
  /// Sets the dirty-page thresholds. Takes effect at the next free or
  /// slice; a cycle in progress continues toward the new low target.
  pub fn set_reclaim_targets(&self, t: ReclaimTargets) {
    self.sweep.targets.store(t.pack(), Relaxed);
    self.poke_maintenance();
  }

  /// The dirty-page thresholds in force.
  pub fn reclaim_targets(&self) -> ReclaimTargets {
    self.sweep.targets()
  }

  /// Sets the retention mode. Switching to [`Retention::Fixed`] goes back
  /// to exactly the purge delay at once.
  pub fn set_retention(&self, r: Retention) {
    let adaptive = r == Retention::Adaptive;
    self.sweep.adaptive.store(adaptive, Relaxed);
    if !adaptive {
      self.sweep.retention.store(1, Relaxed);
      self.sweep.reuse_ewma.store(0, Relaxed);
    }
  }

  /// Where reclamation stands (see [`ReclaimStatus`]).
  pub fn reclaim_status(&self) -> ReclaimStatus {
    ReclaimStatus {
      targets: self.sweep.targets(),
      dirty_pages: self.dirty_pages(),
      budget_pending: self.sweep.budget_pending.load(Relaxed),
      sweep: self.sweep.active(),
      budget_deferred: self.budget_deferred(),
      decay_owed: self.sweep.decay_owed.load(Relaxed),
      retention_mode: if self.sweep.adaptive.load(Relaxed) {
        Retention::Adaptive
      } else {
        Retention::Fixed
      },
      retention: self.sweep.retention.load(Relaxed) as u32,
    }
  }

  /// Lowers the work limit of slices, for tests of slicing.
  #[cfg(any(all(test, allocatbelt_core_check), allocatbelt_model))]
  pub fn set_slice_work(&self, units: u64) {
    self.sweep.slice_work.store(units.max(1), Relaxed);
  }

  /// Work units of an ordinary or an emergency slice.
  pub(super) fn slice_limit(&self, emergency: bool) -> u64 {
    let base = self.sweep.slice_work.load(Relaxed);
    if emergency {
      base.saturating_mul(EMERGENCY_FACTOR)
    } else {
      base
    }
  }

  /// Whether new budget cycles wait: the last one stalled in the current
  /// epoch.
  pub(super) fn budget_deferred(&self) -> bool {
    self.sweep.stall_epoch.load(Relaxed) == self.epoch.load(Relaxed)
  }

  /// Whether a budget cycle is wanted now: above the trigger (and not
  /// deferred, unless past the emergency threshold), or pending and above
  /// the low target.
  fn budget_wanted(&self, t: ReclaimTargets) -> bool {
    let dirty = self.dirty_pages.load(Relaxed);
    let pending = self.sweep.budget_pending.load(Relaxed);
    (dirty > t.trigger as isize && !self.budget_deferred())
      || dirty > t.emergency as isize
      || (pending && dirty > t.low as isize)
  }

  /// Called by a free that took the dirty count to `dirty`: records a
  /// budget cycle and runs or requests a slice of it (see the module
  /// docs). Never with a shard lock held.
  #[inline]
  pub(super) fn after_release(&self, dirty: isize) {
    let t = self.sweep.targets();
    if dirty > t.trigger as isize || self.sweep.budget_pending.load(Relaxed) {
      self.budget_opportunity(dirty, t);
    }
  }

  #[inline(never)]
  fn budget_opportunity(&self, dirty: isize, t: ReclaimTargets) {
    let above = dirty > t.trigger as isize;
    let emergency = dirty > t.emergency as isize;
    let mut pending = self.sweep.budget_pending.load(Relaxed);
    if above && !pending && !self.budget_deferred() {
      self.sweep.budget_pending.store(true, Relaxed);
      pending = true;
    }
    let attached = self.maintenance_attached();
    if attached && !emergency {
      if above && pending {
        self.request(maint::WORK_BUDGET);
      }
      return;
    }
    if !pending && !emergency {
      return;
    }
    let Some(_g) = self.purge_lock.try_lock(&self.os) else {
      self.count(Stat::SkippedPass);
      return;
    };
    let limit = self.slice_limit(emergency);
    let end = self.slice(
      Want::Budget,
      limit,
      Actor::Inline,
      &mut SyncPurger(&self.os),
    );
    if emergency && end != SliceEnd::Idle {
      self.count(Stat::EmergencySlice);
      if attached {
        self.count(Stat::HardLimit);
      }
    }
  }

  /// Housekeeping on allocation slow paths (sampled, as it reads the
  /// clock), never with a shard lock held: a decay epoch that is due, and,
  /// without a maintenance thread, a slice of the sweep or budget cycle in
  /// progress. The only opportunities besides frees: a process that stops
  /// calling the allocator stops reclaiming too.
  pub(super) fn maybe_housekeep(&self) {
    let auto = self.auto_decay.load(Relaxed);
    let inline = !self.maintenance_attached();
    let now = self.os.now_ms();
    let due = auto && now >= self.decay_due_ms();
    let busy = inline && (self.sweep.budget_pending.load(Relaxed) || self.sweep.active().is_some());
    if !due && !busy {
      return;
    }
    let Some(_g) = self.purge_lock.try_lock(&self.os) else {
      self.count(Stat::SkippedPass);
      return;
    };
    let want = if due {
      self.decay_tick(now);
      Want::Decay
    } else if self.sweep.budget_pending.load(Relaxed) {
      Want::Budget
    } else {
      Want::Continue
    };
    self.slice(
      want,
      self.slice_limit(false),
      Actor::Inline,
      &mut SyncPurger(&self.os),
    );
  }

  /// Advances the decay epoch (the schedule's tick, never per slice),
  /// records the clock, owes a decay sweep and updates adaptive retention.
  /// Caller holds `purge_lock`.
  pub(super) fn decay_tick(&self, now: u64) {
    self.last_decay_ms.store(now, Relaxed);
    let epoch = self.epoch.fetch_add(1, Relaxed).wrapping_add(1);
    self.sweep.decay_owed.store(true, Relaxed);
    if self.sweep.adaptive.load(Relaxed) {
      self.adapt_retention(epoch);
    }
  }

  /// One step of the adaptive retention controller, once per decay epoch:
  /// the share of dirty pages that were reused rather than purged since the
  /// last epoch, smoothed (1/4 weight per epoch), moves the retention
  /// multiple up above 3/4 and down below 1/4, one step per delay at most.
  /// An epoch without reuse or purges counts as idle (share 0).
  fn adapt_retention(&self, epoch: u64) {
    let s = &self.sweep;
    let reused = self.search_stats().dirty_reused_pages;
    let purged = self.maintenance_stats().purged_pages;
    let dr = reused.wrapping_sub(s.seen_reused.swap(reused, Relaxed));
    let dp = purged.wrapping_sub(s.seen_purged.swap(purged, Relaxed));
    let sample = if dr + dp == 0 {
      0
    } else {
      (dr.min(1 << 32) << 16) / (dr.min(1 << 32) + dp.min(1 << 32))
    };
    let old = s.reuse_ewma.load(Relaxed);
    let ewma = if sample >= old {
      old + (sample - old) / 4
    } else {
      old - (old - sample) / 4
    };
    s.reuse_ewma.store(ewma, Relaxed);
    let r = s.retention.load(Relaxed);
    if epoch.wrapping_sub(s.last_step.load(Relaxed)) < DECAY_STEPS {
      return;
    }
    let next = if ewma > 3 << 14 {
      (r + 1).min(u64::from(MAX_RETENTION))
    } else if ewma < 1 << 14 {
      r.saturating_sub(1).max(1)
    } else {
      r
    };
    if next != r {
      s.retention.store(next, Relaxed);
      s.last_step.store(epoch, Relaxed);
    }
  }

  /// Explicit memory pressure (a force purge or a purge request): adaptive
  /// retention goes back to the delay.
  pub(super) fn reset_retention(&self) {
    self.sweep.retention.store(1, Relaxed);
    self.sweep.reuse_ewma.store(0, Relaxed);
  }

  /// Decay epochs a page stays dirty (a segment stays empty) before a decay
  /// sweep returns it: one more than the epochs per delay, since the first
  /// may follow the free immediately, times the retention multiple; 0 with
  /// no delay.
  pub(super) fn decay_age(&self) -> u64 {
    if self.purge_delay_ms() == 0 {
      0
    } else {
      (DECAY_STEPS + 1) * self.sweep.retention.load(Relaxed).max(1)
    }
  }

  /// Runs slices until the sweep that `want` selects has ended, then, for
  /// [`Want::Decay`], an owed decay sweep too. For [`Heap::purge`] and
  /// [`Heap::decay`]. Caller holds `purge_lock`.
  pub(super) fn run_sweep<P: Purger>(&self, want: Want, purger: &mut P) {
    let limit = self.slice_limit(false);
    let mut next = want;
    loop {
      match self.slice(next, limit, Actor::Explicit, purger) {
        SliceEnd::More => next = Want::Continue,
        // A sweep of another kind was in progress: the decay owed runs
        // after it.
        SliceEnd::Done if want == Want::Decay && self.sweep.decay_owed.load(Relaxed) => {
          next = Want::Decay;
        }
        SliceEnd::Done | SliceEnd::Idle => return,
      }
    }
  }

  /// Runs one slice of reclamation: at most `limit` work units of the
  /// sweep `want` selects (see the module docs). Caller holds `purge_lock`.
  pub(super) fn slice<P: Purger>(
    &self,
    want: Want,
    limit: u64,
    actor: Actor,
    purger: &mut P,
  ) -> SliceEnd {
    let t = self.sweep.targets();
    let mut st = self.sweep.load();
    match (want, st.kind) {
      (Want::NewForce, _) => self.start(&mut st, FORCE),
      (Want::Force, k) if k != FORCE => self.start(&mut st, FORCE),
      (Want::Budget, NONE) => {
        if !self.budget_wanted(t) {
          self.sweep.budget_pending.store(false, Relaxed);
          return SliceEnd::Idle;
        }
        self.sweep.budget_pending.store(true, Relaxed);
        self.start(&mut st, BUDGET);
      }
      (Want::Budget, DECAY) => {
        // Widening the cutoff purges more of the rest of the sweep.
        self.sweep.budget_pending.store(true, Relaxed);
        st.kind = BUDGET;
        st.cutoff = u64::MAX;
      }
      (Want::Decay, NONE) if self.sweep.decay_owed.load(Relaxed) => self.start(&mut st, DECAY),
      (_, NONE) => return SliceEnd::Idle,
      _ => {}
    }
    self.count(Stat::Slice);
    if actor == Actor::Inline {
      self.count(Stat::InlineSlice);
    }
    let mut batch = Batch::new();
    let mut work = 0;
    let mut end = self.dirty_pages.load(Relaxed) <= t.low as isize && st.kind == BUDGET;
    if !end && st.phase == 0 {
      self.trim_step(&mut st, limit, &mut work, &mut batch.work);
      if st.shards_done >= SHARDS as u64 {
        st.phase = 1;
      }
    }
    let mut full = false;
    if !end && st.phase == 1 {
      if st.cutoff == NO_CUTOFF {
        full = true;
      } else {
        let low = (st.kind == BUDGET).then_some(t.low as isize);
        let (done, reached) = self.purge_step(&mut st, limit, &mut work, low, &mut batch, purger);
        full = done;
        end = reached;
      }
    }
    // Every claim this slice submitted is finished before it returns.
    self.purge_claimed(&mut batch, purger);
    st.progress +=
      batch.work.purged_pages + batch.work.released_pages + batch.work.returned_segments;
    self.count_work(&batch.work);
    if !(full || end) {
      self.sweep.store(&st);
      return SliceEnd::More;
    }
    self.finish_sweep(&mut st, full, actor, t);
    self.sweep.store(&st);
    SliceEnd::Done
  }

  /// Sets up a new sweep of `kind` in `st`, replacing any other.
  fn start(&self, st: &mut SweepState, kind: u64) {
    let epoch = self.epoch.load(Relaxed);
    let age = self.decay_age();
    st.kind = kind;
    st.phase = 0;
    st.epoch = epoch;
    st.age = age;
    // Pages dirty since epoch `cutoff` or earlier are purged.
    st.cutoff = match kind {
      DECAY => match epoch.checked_sub(age) {
        Some(c) => c.min(NO_CUTOFF - 1),
        None => NO_CUTOFF,
      },
      _ => u64::MAX,
    };
    if kind == DECAY {
      // This sweep does the decay owed; one that falls due while it runs
      // is owed again.
      self.sweep.decay_owed.store(false, Relaxed);
    }
    st.shards_done = 0;
    st.prev = 0;
    st.kept_empty = false;
    st.purge_off = 0;
    st.progress = 0;
    st.trim_start = (st.trim_start + 1) % SHARDS as u64;
  }

  /// Counts a finished sweep and ends a budget cycle with it: see the
  /// module docs.
  fn finish_sweep(&self, st: &mut SweepState, full: bool, actor: Actor, t: ReclaimTargets) {
    let kind = st.kind;
    let stat = match (kind, actor) {
      (FORCE, Actor::Maintenance) => Some(Stat::Force),
      (BUDGET, Actor::Maintenance) => Some(Stat::Budget),
      (DECAY, Actor::Maintenance) => Some(Stat::Decay),
      (BUDGET, Actor::Inline) => Some(Stat::InlineBudget),
      (DECAY, Actor::Inline) => Some(Stat::InlineDecay),
      _ => None,
    };
    if let Some(stat) = stat {
      self.count(stat);
    }
    let dirty = self.dirty_pages.load(Relaxed);
    if kind == BUDGET || self.sweep.budget_pending.load(Relaxed) && dirty <= t.low as isize {
      self.sweep.budget_pending.store(false, Relaxed);
      if kind == BUDGET && full && st.progress == 0 && dirty > t.low as isize {
        self
          .sweep
          .stall_epoch
          .store(self.epoch.load(Relaxed), Relaxed);
        self.count(Stat::StalledCycle);
      }
    }
    st.kind = NONE;
  }

  /// The trim phase of a slice: shards from where the sweep is, until the
  /// work limit.
  fn trim_step(&self, st: &mut SweepState, limit: u64, work: &mut u64, pw: &mut PassWork) {
    let force = st.kind == FORCE;
    while st.shards_done < SHARDS as u64 && *work < limit {
      let s = ((st.trim_start + st.shards_done) % SHARDS as u64) as usize;
      let sh = &self.shards[s];
      *work += 1;
      let Some(_g) = sh.lock.try_lock(&self.os) else {
        pw.busy_shards += 1;
        st.shards_done += 1;
        st.prev = 0;
        st.kept_empty = false;
        continue;
      };
      if st.prev == 0 {
        pw.trimmed_shards += 1;
      }
      // The cursors are only scan positions; dropping them makes the next
      // claims start from the availability words, and no cursor is left
      // on a page released below.
      for cs in &sh.classes {
        if cs.cursor.swap(0, Relaxed) != 0 {
          sh.bump(SearchStat::CursorInvalidation, 1);
        }
      }
      let mut prev: Option<(usize, &[AtomicU64])> = None;
      let mut cur = sh.segs.load(Relaxed) as u64;
      if st.prev != 0 {
        let seg = st.prev as usize - 1;
        let m = self.seg_meta(seg);
        let hdr = m[SEG_HDR].load(Acquire);
        if hdr & 0xFF == SEG_OWNED && (hdr >> 8) & 0xFF == s as u64 {
          prev = Some((seg, m));
          cur = m[SEG_NEXT].load(Relaxed);
        } else {
          // Not ours any more (never expected): start the shard over.
          st.kept_empty = false;
        }
      }
      // At least one segment per visit, so every slice makes progress.
      let mut first = true;
      while cur != 0 && (first || *work < limit) {
        first = false;
        let seg = cur as usize - 1;
        let m = self.seg_meta(seg);
        let next = m[SEG_NEXT].load(Relaxed);
        *work += 1 + self.release_empty_pages(seg, m, pw);
        let empty = m[SEG_PAGES].load(Acquire) == GUARD_BIT;
        let expired = if empty && st.kept_empty {
          // Idle since epoch `since - 1`; stamped by the first sweep that
          // saw it.
          let since = m[SEG_IDLE].load(Relaxed);
          if since == 0 {
            m[SEG_IDLE].store(st.epoch + 1, Relaxed);
          }
          force || (since != 0 && (since - 1).saturating_add(st.age) <= st.epoch)
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
            Some((_, p)) => p[SEG_NEXT].store(next, Relaxed),
          }
          self.free_owned_segment(seg, m);
          pw.returned_segments += 1;
        } else {
          st.kept_empty |= empty;
          prev = Some((seg, m));
        }
        cur = next;
      }
      if cur == 0 {
        st.shards_done += 1;
        st.prev = 0;
        st.kept_empty = false;
      } else {
        st.prev = prev.map_or(0, |(seg, _)| seg as u64 + 1);
      }
    }
  }

  /// The purge phase of a slice: owned segments from where the sweep is,
  /// round the arena from `purge_start`, until the work limit. With `low`
  /// (a budget sweep), stops once the dirty count is at or below it.
  /// Returns whether the phase covered the arena and whether it stopped at
  /// the target.
  fn purge_step<P: Purger>(
    &self,
    st: &mut SweepState,
    limit: u64,
    work: &mut u64,
    low: Option<isize>,
    batch: &mut Batch,
    purger: &mut P,
  ) -> (bool, bool) {
    // Only decay sweeps compare ages.
    let kernel = if st.cutoff == u64::MAX {
      None
    } else {
      self.os.age_kernel()
    };
    let batch_size = purger.batch_size().clamp(1, PURGE_BATCH);
    let total = MAX_SEGMENTS as u64;
    while st.purge_off < total && *work < limit {
      let pos = ((st.purge_start + st.purge_off) % total) as usize;
      // The rest of this bitmap word, not past the end of the round.
      let span = (64 - pos % 64).min((total - st.purge_off) as usize);
      let mask = if span == 64 {
        u64::MAX
      } else {
        ((1u64 << span) - 1) << (pos % 64)
      };
      let mut used = self.seg_used[pos / 64].load(Relaxed) & mask;
      *work += 1;
      let mut covered = span as u64;
      while used != 0 {
        let seg = (pos / 64) * 64 + used.trailing_zeros() as usize;
        used &= used - 1;
        if let Some(m) = self.os.meta(seg)
          && m[SEG_HDR].load(Acquire) & 0xFF == SEG_OWNED
        {
          batch.work.segments_inspected += 1;
          let runs = batch.work.runs + batch.len as u64;
          self.claim_segment(seg, m, st.cutoff, kernel, batch, purger);
          if batch.len >= batch_size {
            self.purge_claimed(batch, purger);
          }
          *work += 1 + (batch.work.runs + batch.len as u64 - runs);
        }
        // Claims not purged yet count as purged here; if the target is
        // reached, they are purged before the sweep stops.
        let stop_target = low.is_some_and(|low| {
          self.dirty_pages.load(Relaxed) - batch.claimed_pages() as isize <= low
        });
        if stop_target || *work >= limit {
          covered = (seg - pos) as u64 + 1;
          if stop_target {
            self.purge_claimed(batch, purger);
            st.purge_off += covered;
            // The next budget sweep starts after this segment.
            st.purge_start = (st.purge_start + st.purge_off) % total;
            return (false, true);
          }
          break;
        }
      }
      st.purge_off += covered;
    }
    (st.purge_off >= total, false)
  }
}
