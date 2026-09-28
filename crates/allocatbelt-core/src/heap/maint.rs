//! The maintenance engine: allocator housekeeping as prioritized work that
//! one maintenance thread runs (plan §9, Phase 7).
//!
//! Without the engine, the allocating threads do all housekeeping inline:
//! the free that pushes the dirty count over the budget runs the budget
//! pass itself, and allocation slow paths run decay passes when they are
//! due. Once an embedder dedicates a thread to [`Heap::maintain`], they
//! only record work in an atomic word and wake that thread on the
//! transition; the thread runs the work in priority order:
//!
//! | Priority | Work | Requested by |
//! |---|---|---|
//! | P0 | force purge: every dirty page, every empty segment but one per shard | [`Heap::request_purge`] |
//! | P1 | budget pass: every dirty page | a free that takes the dirty count over [`DIRTY_BUDGET_PAGES`] |
//! | P2 | decay pass: pages dirty, segments empty, for the purge delay | the clock (a deadline, not a request) |
//! | P3 | empty-segment retirement | part of every pass above (`trim_shards`) |
//! | P4 | statistics | [`Heap::maintenance_stats`], kept by the passes |
//!
//! The engine uses the existing synchronous backend: each pass takes
//! `purge_lock` and calls [`Os::purge`] and [`Os::decommit`] as before,
//! so the protocols the passes rely on are unchanged; only who runs them
//! and when differs. Two safety valves keep memory bounded if the thread
//! falls behind (it runs as a batch task, see the adapter): a free that
//! finds more than [`DIRTY_HARD_LIMIT_PAGES`] dirty pages runs the budget
//! pass inline as before, and a forked child, which has no maintenance
//! thread, goes back to inline housekeeping.

use super::*;

/// P0: a force purge was requested.
const WORK_FORCE: u32 = 1 << 0;
/// P1: the dirty budget was exceeded.
const WORK_BUDGET: u32 = 1 << 1;

/// Dirty pages beyond which a free runs the budget pass itself even when a
/// maintenance thread is attached (64 MiB): the thread is behind, and RSS
/// must stay bounded.
pub const DIRTY_HARD_LIMIT_PAGES: isize = 2 * DIRTY_BUDGET_PAGES;

/// Housekeeping work, in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task {
  /// P0: return every dirty page and every empty segment but one per
  /// shard ([`Heap::request_purge`]).
  Force,
  /// P1: return every dirty page; the dirty budget was exceeded.
  Budget,
  /// P2: return pages dirty, and segments empty, for the purge delay.
  Decay,
}

/// Counters of the housekeeping passes (P4), for diagnostics and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaintenanceStats {
  /// Force passes run by the maintenance thread.
  pub force_passes: u64,
  /// Budget passes run by the maintenance thread.
  pub budget_passes: u64,
  /// Decay passes run by the maintenance thread.
  pub decay_passes: u64,
  /// Budget passes run inline by a freeing thread: no maintenance thread,
  /// or the dirty count passed [`DIRTY_HARD_LIMIT_PAGES`].
  pub inline_budget_passes: u64,
  /// Decay passes run inline by allocating threads.
  pub inline_decay_passes: u64,
  /// Times a freeing thread woke the maintenance thread.
  pub wakeups: u64,
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
}

/// Number of [`Stat`]s.
pub(super) const STATS: usize = 6;

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

  /// One round of the maintenance thread: runs the most urgent pending
  /// work, or, with none, sleeps until the next decay pass is due or a
  /// request wakes it. Returns what it ran.
  pub fn maintain(&self) -> Option<Task> {
    let now = self.os.now_ms();
    match self.next_task(now) {
      Some(task) => {
        self.run_task(task, now);
        Some(task)
      }
      None => {
        let due = self.decay_due_ms();
        // Sleeps only while no work is recorded (the word is 0); a request
        // that lands meanwhile changes the word or wakes it.
        self
          .os
          .futex_wait(&self.maint_work, 0, Some(due.saturating_sub(now).max(1)));
        None
      }
    }
  }

  /// The most urgent pending work at `now`, if any.
  pub fn next_task(&self, now: u64) -> Option<Task> {
    let work = self.maint_work.load(Acquire);
    if work & WORK_FORCE != 0 {
      Some(Task::Force)
    } else if work & WORK_BUDGET != 0 || self.dirty_pages.load(Relaxed) > DIRTY_BUDGET_PAGES {
      Some(Task::Budget)
    } else if now >= self.decay_due_ms() {
      Some(Task::Decay)
    } else {
      None
    }
  }

  fn run_task(&self, task: Task, now: u64) {
    // Requests are taken before the pass reads what caused them, so one
    // that arrives during it is served by this pass or by another one
    // (`proto::take_work`).
    match task {
      Task::Force => {
        proto::take_work(&self.maint_work, WORK_FORCE);
        let _g = self.purge_lock.lock(&self.os);
        self.pass(Pass::Force);
        self.count(Stat::Force);
      }
      Task::Budget => {
        proto::take_work(&self.maint_work, WORK_BUDGET);
        let _g = self.purge_lock.lock(&self.os);
        // An inline pass (hard limit) may have done it meanwhile.
        if self.dirty_pages.load(Relaxed) > DIRTY_BUDGET_PAGES {
          self.pass(Pass::Budget);
          self.count(Stat::Budget);
        }
      }
      Task::Decay => {
        let _g = self.purge_lock.lock(&self.os);
        self.last_decay_ms.store(now, Relaxed);
        self.pass(Pass::Decay);
        self.count(Stat::Decay);
      }
    }
  }

  /// Asks the maintenance thread for a force purge (P0) and returns at
  /// once; without one attached, purges inline like [`Heap::purge`]. For
  /// memory-pressure notifications, which should not block the notifier.
  pub fn request_purge(&self) {
    if self.maintenance_attached() {
      self.request(WORK_FORCE);
    } else {
      self.purge();
    }
  }

  /// Called by a free that took the dirty count to `dirty`, over the
  /// budget.
  pub(super) fn over_budget(&self, dirty: isize) {
    if self.maintenance_attached() && dirty <= DIRTY_HARD_LIMIT_PAGES {
      self.request(WORK_BUDGET);
    } else if let Some(_g) = self.purge_lock.try_lock(&self.os) {
      self.pass(Pass::Budget);
      self.count(Stat::InlineBudget);
    }
  }

  /// Records `bit` and wakes the maintenance thread if it was not
  /// recorded yet: a fence and one read while it is, one
  /// read-modify-write and one `FUTEX_WAKE` per request.
  fn request(&self, bit: u32) {
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

  /// When the next decay pass is due, in [`Os::now_ms`] time.
  fn decay_due_ms(&self) -> u64 {
    self
      .last_decay_ms
      .load(Relaxed)
      .saturating_add(self.decay_interval_ms())
  }

  pub(super) fn count(&self, stat: Stat) {
    self.maint_stats[stat as usize].fetch_add(1, Relaxed);
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
    }
  }
}
