//! The maintenance engine: allocator housekeeping as prioritized work that
//! one maintenance thread runs (plan §9, Phase 7).
//!
//! Without the engine, the allocating threads do all housekeeping inline,
//! one bounded slice at a time (see [`super::reclaim`]): the free that
//! pushes the dirty count over the trigger starts a budget cycle and runs
//! its first slice, later page-run frees and allocation slow paths run
//! further slices while it is pending, and allocation slow paths start
//! decay sweeps when they are due. Once an embedder dedicates a thread to
//! [`Heap::maintain`], they only record work in an atomic word and wake
//! that thread on the transition; the thread runs one slice per round, of
//! the most urgent work:
//!
//! | Priority | Work | Requested by |
//! |---|---|---|
//! | P0 | force purge: every dirty page, every empty segment but one per shard | [`Heap::request_purge`] |
//! | P1 | budget cycle: dirty pages regardless of age, down to the low target | a free that takes the dirty count over the trigger ([`ReclaimTargets`]) |
//! | P2 | decay sweep: pages dirty, segments empty, for the purge delay | the clock (a deadline, not a request) |
//! | P3 | empty-segment retirement | part of every sweep above (trimming) |
//! | P4 | statistics | [`Heap::maintenance_stats`], kept by the slices |
//!
//! Each slice takes `purge_lock`, so frees and inline slices can run
//! between two slices of a long sweep. The thread may bring its own
//! [`Purger`] ([`Heap::maintain_with`]), such as the adapter's io_uring
//! ring, which purges a slice's page runs in batches; slices on allocating
//! threads purge through [`Os::purge`] ([`SyncPurger`]). Returning
//! segments ([`Os::decommit`]) stays synchronous. Two safety valves keep
//! memory bounded if the thread falls behind (it runs as a batch task, see
//! the adapter): a free that finds more dirty pages than the emergency
//! threshold (64 MiB by default) runs an emergency slice inline (a
//! foreground intervention, [`MaintenanceStats::hard_limit_slices`]), and
//! a forked child, which has no maintenance thread, goes back to inline
//! housekeeping.
//!
//! A budget cycle that stalls (a full sweep without progress, e.g. every
//! purge refused) is deferred until the next decay epoch: the thread then
//! sleeps with the budget request still recorded, and wakes for anything
//! else (`proto::idle_word`), so refused purges cannot make it spin.

use super::reclaim::{Actor, Want};
use super::*;

/// P0: a force purge was requested.
const WORK_FORCE: u32 = 1 << 0;
/// P1: the dirty trigger was exceeded.
pub(super) const WORK_BUDGET: u32 = 1 << 1;

/// The default emergency threshold: dirty pages beyond which a free runs
/// an emergency slice itself even when a maintenance thread is attached
/// (64 MiB; see [`ReclaimTargets`]): the thread is behind, and the dirty
/// pages it has not purged must not grow without bound. A bound on tracked
/// dirty pages, not on the process's RSS (see [`DIRTY_BUDGET_PAGES`]).
pub const DIRTY_HARD_LIMIT_PAGES: isize = 2 * DIRTY_BUDGET_PAGES;

/// Housekeeping work, in priority order; also the kind of a sweep
/// ([`ReclaimStatus::sweep`](super::ReclaimStatus::sweep)).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task {
  /// P0: return every dirty page and every empty segment but one per
  /// shard (`request_purge`).
  Force,
  /// P1: return every dirty page; the dirty budget was exceeded.
  Budget,
  /// P2: return pages dirty, and segments empty, for the purge delay.
  Decay,
}

/// Counters of the housekeeping passes (P4), for diagnostics and tests.
///
/// A *pass* is a sweep (see `docs/reclamation.md`), which runs in one or more
/// bounded *slices*; the pass counters count sweeps when they end, by the
/// thread that ran their last slice.
///
/// Each counter only grows, and wraps modulo 2^64 (which no process
/// reaches). A snapshot reads the counters one by one while slices may be
/// running, so two counters of one snapshot can disagree by the work of a
/// slice in progress; each slice adds its work when it ends, so counters of
/// one slice (inspected, attempted, purged, failed) appear together.
/// Counting costs a few atomic additions per slice, none per allocation or
/// free.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaintenanceStats {
  /// Force passes ended by the maintenance thread.
  pub force_passes: u64,
  /// Budget passes (sweeps of a budget cycle) ended by the maintenance
  /// thread.
  pub budget_passes: u64,
  /// Decay passes ended by the maintenance thread.
  pub decay_passes: u64,
  /// Budget passes ended inline by a freeing or allocating thread: no
  /// maintenance thread, or the dirty count passed the emergency
  /// threshold.
  pub inline_budget_passes: u64,
  /// Decay passes ended inline by allocating threads.
  pub inline_decay_passes: u64,
  /// Times a freeing thread woke the maintenance thread.
  pub wakeups: u64,
  /// Purge batches, by any pass (one per segment for `madvise` purges).
  pub purge_batches: u64,
  /// Page runs purged (or attempted) by those batches.
  pub purged_runs: u64,
  /// Of [`MaintenanceStats::purged_runs`], the runs the OS refused (or
  /// whose completion failed): their pages stay dirty and are tried again
  /// by a later pass.
  pub failed_runs: u64,
  /// Pages whose purge succeeded: memory handed back to the OS. Not the
  /// same as a drop in the process's RSS, which the OS decides. Includes
  /// kept small pages (see [`MaintenanceStats::kept_newest_pages`]) whose
  /// memory trimming purged.
  pub purged_pages: u64,
  /// Owned segments whose dirty free pages a pass inspected.
  pub segments_inspected: u64,
  /// Shards a pass trimmed (released their fully free small pages and
  /// checked their empty segments).
  pub trimmed_shards: u64,
  /// Shards a pass skipped because another thread held their lock; their
  /// pages and segments wait for a later pass.
  pub busy_shards: u64,
  /// Small pages whose free count trimming checked: empty-page candidates
  /// (published by the free that made a page fully free), and in
  /// reconciling sweeps every small page.
  pub trim_pages_inspected: u64,
  /// Small pages trimming found fully free and turned into dirty free
  /// pages. Returning a page to its segment does not return memory to the
  /// OS; a purge does, later.
  pub released_pages: u64,
  /// Empty segments trimming returned to the arena (decommitted).
  pub returned_segments: u64,
  /// Empty-page candidates trimming checked and did not release: the page
  /// was claimed from again, released or reused since its last block was
  /// freed.
  pub stale_empty_candidates: u64,
  /// Pages a reconciling sweep (force, and every `RECONCILE_EPOCHS`-th
  /// decay sweep) released without a candidate. 0 unless a candidate was
  /// lost, or a free published it while the sweep ran.
  pub reconciled_pages: u64,
  /// Fully free small pages trimming checked and kept because each was
  /// the page its shard set up last for its class: at most one page per
  /// shard and class stays until a newer one is set up. A kept page is
  /// checked by every sweep until its memory is purged, after the purge
  /// delay.
  pub kept_newest_pages: u64,
  /// Passes an allocating or freeing thread would have run but skipped,
  /// because another thread held the purge lock.
  pub skipped_passes: u64,
  /// Slices run, by any thread (the maintenance thread, inline, and
  /// explicit `purge` and `decay` calls).
  pub slices: u64,
  /// Of those, slices run inline by allocating or freeing threads.
  pub inline_slices: u64,
  /// Of those, emergency slices (larger, run by a free past the emergency
  /// threshold).
  pub emergency_slices: u64,
  /// Of those, emergency slices a freeing thread ran although a
  /// maintenance thread was attached: foreground intervention.
  pub hard_limit_slices: u64,
  /// Budget cycles that stalled: a full sweep made no progress (no page
  /// purged or released, no segment returned) while more than the low
  /// target stayed dirty. New cycles then wait for the next decay epoch.
  pub stalled_cycles: u64,
}

/// Indices into `Heap::maint_stats`.
#[derive(Clone, Copy)]
pub(super) enum Stat {
  Force,
  Budget,
  Decay,
  InlineBudget,
  InlineDecay,
  Wakeup,
  Batch,
  Run,
  FailedRun,
  PurgedPage,
  SegmentInspected,
  TrimmedShard,
  BusyShard,
  TrimPageInspected,
  ReleasedPage,
  ReturnedSegment,
  SkippedPass,
  HardLimit,
  Slice,
  InlineSlice,
  EmergencySlice,
  StalledCycle,
  StaleEmptyCandidate,
  ReconciledPage,
  KeptNewestPage,
}

/// Number of [`Stat`]s.
pub(super) const STATS: usize = 25;

/// The work of one slice, counted in private and added to the shared
/// counters once when the slice ends.
#[derive(Default)]
pub(super) struct PassWork {
  pub(super) batches: u64,
  pub(super) runs: u64,
  pub(super) failed_runs: u64,
  pub(super) purged_pages: u64,
  pub(super) segments_inspected: u64,
  pub(super) trimmed_shards: u64,
  pub(super) busy_shards: u64,
  pub(super) trim_pages_inspected: u64,
  pub(super) released_pages: u64,
  pub(super) returned_segments: u64,
  pub(super) stale_empty_candidates: u64,
  pub(super) reconciled_pages: u64,
  pub(super) kept_newest_pages: u64,
}

impl PassWork {
  pub(super) const fn new() -> Self {
    Self {
      batches: 0,
      runs: 0,
      failed_runs: 0,
      purged_pages: 0,
      segments_inspected: 0,
      trimmed_shards: 0,
      busy_shards: 0,
      trim_pages_inspected: 0,
      released_pages: 0,
      returned_segments: 0,
      stale_empty_candidates: 0,
      reconciled_pages: 0,
      kept_newest_pages: 0,
    }
  }
}

impl<O: Os> Heap<O> {
  /// Hands housekeeping to the calling thread, which must then call
  /// [`Heap::maintain`] in a loop for the life of the process. Allocating
  /// threads stop running budget and decay passes (up to the hard limit).
  pub fn attach_maintenance(&self) {
    self.set_auto_decay(false);
    self.maint_attached.store(true, Release);
  }

  /// Whether a maintenance thread is attached.
  pub fn maintenance_attached(&self) -> bool {
    self.maint_attached.load(Acquire)
  }

  /// Gives housekeeping back to the allocating threads: in a forked child,
  /// where the maintenance thread does not exist, and when the thread could
  /// not be started after [`Heap::attach_maintenance`].
  pub fn detach_maintenance(&self) {
    self.maint_attached.store(false, Release);
    self.maint_work.store(0, Relaxed);
    self.set_auto_decay(true);
  }

  /// One round of the maintenance thread: runs one slice of the most
  /// urgent pending work, or, with none, sleeps until the next decay epoch
  /// is due or a request wakes it. Returns what it ran. Purges through
  /// [`Os::purge`].
  pub fn maintain(&self) -> Option<Task> {
    self.maintain_with(&mut SyncPurger(&self.os))
  }

  /// [`Heap::maintain`], with the slices purging through `purger`.
  pub fn maintain_with<P: Purger>(&self, purger: &mut P) -> Option<Task> {
    let now = self.os.now_ms();
    match self.next_task(now) {
      Some(task) => {
        self.run_task(task, now, purger);
        Some(task)
      }
      None => {
        let due = self.decay_due_ms();
        // Sleeps only while no work is recorded but a deferred budget
        // request; anything else that lands meanwhile changes the word or
        // wakes it.
        let deferred = if self.budget_deferred() {
          WORK_BUDGET
        } else {
          0
        };
        if let Some(word) = proto::idle_word(&self.maint_work, deferred) {
          self
            .os
            .futex_wait(&self.maint_work, word, Some(due.saturating_sub(now).max(1)));
        }
        None
      }
    }
  }

  /// The most urgent pending work at `now`, if any: a force purge
  /// requested or in progress; a budget cycle requested, pending, in
  /// progress, or called for by the dirty count (unless deferred after a
  /// stall, below the emergency threshold); a decay sweep in progress,
  /// owed or due.
  pub fn next_task(&self, now: u64) -> Option<Task> {
    let work = self.maint_work.load(Acquire);
    let active = self.sweep.active();
    if work & WORK_FORCE != 0 || active == Some(Task::Force) {
      return Some(Task::Force);
    }
    let t = self.sweep.targets();
    let dirty = self.dirty_pages.load(Relaxed);
    let wanted = work & WORK_BUDGET != 0
      || self.sweep.budget_pending.load(Relaxed)
      || dirty > t.trigger_pages() as isize;
    if active == Some(Task::Budget)
      || wanted && (!self.budget_deferred() || dirty > t.emergency_pages() as isize)
    {
      Some(Task::Budget)
    } else if active == Some(Task::Decay)
      || self.reclaim_status().decay_owed
      || now >= self.decay_due_ms()
    {
      Some(Task::Decay)
    } else {
      None
    }
  }

  fn run_task<P: Purger>(&self, task: Task, now: u64, purger: &mut P) {
    let _g = self.purge_lock.lock(&self.os);
    // The decay schedule advances whatever runs, so budget work cannot
    // hold the epoch back; the decay owed runs when the sweep in progress
    // ends.
    if now >= self.decay_due_ms() {
      self.decay_tick(now);
    }
    let active = self.sweep.active();
    // Requests are taken before the slice reads what caused them, so one
    // that arrives during it is served by this cycle or by another one
    // (`proto::take_work`). A request for work already in progress stays
    // recorded until that sweep ends.
    let want = match task {
      Task::Force => {
        if active != Some(Task::Force) {
          proto::take_work(&self.maint_work, WORK_FORCE);
        }
        Want::Force
      }
      Task::Budget => {
        if !matches!(active, Some(Task::Budget | Task::Force)) {
          proto::take_work(&self.maint_work, WORK_BUDGET);
        }
        Want::Budget
      }
      Task::Decay => Want::Decay,
    };
    self.slice(want, self.slice_limit(false), Actor::Maintenance, purger);
  }

  /// Asks the maintenance thread for a force purge (P0) and returns at
  /// once; without one attached, purges inline like [`Heap::purge`]. For
  /// memory-pressure notifications, which should not block the notifier.
  pub fn request_purge(&self) {
    self.reset_retention();
    if self.maintenance_attached() {
      self.request(WORK_FORCE);
    } else {
      self.purge();
    }
  }

  /// Records `bit` and wakes the maintenance thread if it was not
  /// recorded yet: a fence and one read while it is, one
  /// read-modify-write and one `FUTEX_WAKE` per request.
  pub(super) fn request(&self, bit: u32) {
    if proto::post_work(&self.maint_work, bit) {
      self.os.futex_wake(&self.maint_work);
      self.count(Stat::Wakeup);
    }
  }

  /// Wakes the maintenance thread so that it recomputes its deadline, e.g.
  /// after the purge delay changed.
  pub(super) fn poke_maintenance(&self) {
    if self.maintenance_attached() {
      self.os.futex_wake(&self.maint_work);
    }
  }

  /// When the next decay epoch is due, in [`Os::now_ms`] time.
  pub(super) fn decay_due_ms(&self) -> u64 {
    self
      .last_decay_ms
      .load(Relaxed)
      .saturating_add(self.decay_interval_ms())
  }

  pub(super) fn count(&self, stat: Stat) {
    self.count_n(stat, 1);
  }

  pub(super) fn count_n(&self, stat: Stat, n: u64) {
    if n != 0 {
      self.maint_stats[stat as usize].fetch_add(n, Relaxed);
    }
  }

  /// Adds the work of a pass that just ended to the counters.
  pub(super) fn count_work(&self, w: &PassWork) {
    self.count_n(Stat::Batch, w.batches);
    self.count_n(Stat::Run, w.runs);
    self.count_n(Stat::FailedRun, w.failed_runs);
    self.count_n(Stat::PurgedPage, w.purged_pages);
    self.count_n(Stat::SegmentInspected, w.segments_inspected);
    self.count_n(Stat::TrimmedShard, w.trimmed_shards);
    self.count_n(Stat::BusyShard, w.busy_shards);
    self.count_n(Stat::TrimPageInspected, w.trim_pages_inspected);
    self.count_n(Stat::ReleasedPage, w.released_pages);
    self.count_n(Stat::ReturnedSegment, w.returned_segments);
    self.count_n(Stat::StaleEmptyCandidate, w.stale_empty_candidates);
    self.count_n(Stat::ReconciledPage, w.reconciled_pages);
    self.count_n(Stat::KeptNewestPage, w.kept_newest_pages);
  }

  /// The housekeeping counters so far.
  pub fn maintenance_stats(&self) -> MaintenanceStats {
    let s = |stat: Stat| self.maint_stats[stat as usize].load(Relaxed);
    MaintenanceStats {
      force_passes: s(Stat::Force),
      budget_passes: s(Stat::Budget),
      decay_passes: s(Stat::Decay),
      inline_budget_passes: s(Stat::InlineBudget),
      inline_decay_passes: s(Stat::InlineDecay),
      wakeups: s(Stat::Wakeup),
      purge_batches: s(Stat::Batch),
      purged_runs: s(Stat::Run),
      failed_runs: s(Stat::FailedRun),
      purged_pages: s(Stat::PurgedPage),
      segments_inspected: s(Stat::SegmentInspected),
      trimmed_shards: s(Stat::TrimmedShard),
      busy_shards: s(Stat::BusyShard),
      trim_pages_inspected: s(Stat::TrimPageInspected),
      released_pages: s(Stat::ReleasedPage),
      returned_segments: s(Stat::ReturnedSegment),
      stale_empty_candidates: s(Stat::StaleEmptyCandidate),
      reconciled_pages: s(Stat::ReconciledPage),
      kept_newest_pages: s(Stat::KeptNewestPage),
      skipped_passes: s(Stat::SkippedPass),
      slices: s(Stat::Slice),
      inline_slices: s(Stat::InlineSlice),
      emergency_slices: s(Stat::EmergencySlice),
      hard_limit_slices: s(Stat::HardLimit),
      stalled_cycles: s(Stat::StalledCycle),
    }
  }
}
