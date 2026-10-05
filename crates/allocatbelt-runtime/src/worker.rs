//! A worker thread: takes jobs in FIFO order, runs or drops them outside
//! the scheduler lock, and returns its allocator cache before it parks and
//! before it exits.

use std::cell::Cell;
use std::collections::VecDeque;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::cache;
use crate::resources::Resources;
use crate::scheduler::{Entry, Shared};
use crate::task::Release;

// Both cells are const-initialized and have no `Drop`, so they stay
// readable while the thread's other thread-locals are destroyed.
thread_local! {
  /// The id of the runtime this thread is a worker of, 0 for none. Set when
  /// the worker starts and never cleared, so it covers jobs, every `Drop`
  /// the worker runs and the thread-local destructors as it exits.
  static WORKER_OF: Cell<u64> = const { Cell::new(0) };
  /// This thread's token for [`Ident::cleaner`], 0 until first needed.
  static THREAD: Cell<u64> = const { Cell::new(0) };
}

static NEXT_THREAD: AtomicU64 = AtomicU64::new(1);

/// The token of every thread that started after the tokens ran out. Such
/// threads share it, so a join on a runtime cleaned by one of them fails
/// as `WouldDeadlock` on all of them: a spurious error, never a missed
/// deadlock. Unreachable in practice (2^64 - 2 threads).
const EXHAUSTED: u64 = u64::MAX;

/// Takes the next id from `next`, never wrapping: `None` once `u64::MAX`
/// would be reached, so no id is reused while its holder may be alive and
/// no id equals 0 (none) or `u64::MAX`.
pub(crate) fn next_id(next: &AtomicU64) -> Option<u64> {
  next
    .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
      id.checked_add(1).filter(|&after| after != EXHAUSTED)
    })
    .ok()
}

/// A token unique to the calling thread for the life of the process, or
/// [`EXHAUSTED`].
fn thread_token() -> u64 {
  let mut token = THREAD.get();
  if token == 0 {
    token = next_id(&NEXT_THREAD).unwrap_or(EXHAUSTED);
    THREAD.set(token);
  }
  token
}

/// A runtime's identity for the deadlock guard, shared by its scheduler
/// and every job's control. Each runtime records its own cleaner, so a
/// thread cleaning several runtimes at once (one runtime's capture
/// dropping another runtime) is recognised by each of them.
pub(crate) struct Ident {
  pub(crate) id: u64,
  /// The token of the thread abandoning the runtime's taken queue (a
  /// cancelling shutdown or the runtime's drop), 0 for none.
  cleaner: AtomicU64,
}

impl Ident {
  pub(crate) fn new(id: u64) -> Arc<Self> {
    Arc::new(Self {
      id,
      cleaner: AtomicU64::new(0),
    })
  }
}

/// Whether the calling thread is a worker of the runtime `id`.
pub(crate) fn is_worker_of(id: u64) -> bool {
  WORKER_OF.get() == id
}

/// Whether a blocking join of an unfinished job of `runtime` from this
/// thread could wait on work only this thread can finish.
pub(crate) fn would_deadlock(runtime: &Ident) -> bool {
  // `cleaner` equals this thread's token only if this thread stored it,
  // and a thread always reads its own latest store: `Relaxed` suffices.
  WORKER_OF.get() == runtime.id || runtime.cleaner.load(Ordering::Relaxed) == thread_token()
}

/// Marks the thread as abandoning `runtime`'s jobs until dropped, and
/// restores the previous cleaner when dropped, unwinding included.
pub(crate) struct Cleaning<'a> {
  runtime: &'a Ident,
  previous: u64,
}

impl<'a> Cleaning<'a> {
  pub(crate) fn enter(runtime: &'a Ident) -> Self {
    let previous = runtime.cleaner.swap(thread_token(), Ordering::Relaxed);
    Self { runtime, previous }
  }
}

impl Drop for Cleaning<'_> {
  fn drop(&mut self) {
    self.runtime.cleaner.store(self.previous, Ordering::Relaxed);
  }
}

enum Next {
  Run(Entry),
  Abandon(Entry),
  Exit,
}

#[derive(Clone, Copy)]
enum Phase {
  /// Started by worker `index`.
  Running(usize),
  Cancelling,
}

/// A job's admission, released once.
struct Admitted<'a> {
  shared: &'a Shared,
  request: Resources,
  phase: Phase,
  done: bool,
}

impl Release for Admitted<'_> {
  fn release(&mut self) {
    if !self.done {
      self.done = true;
      let mut state = self.shared.lock();
      let control = match self.phase {
        Phase::Running(index) => {
          state.running_count = state.running_count.saturating_sub(1);
          state.running.get_mut(index).and_then(Option::take)
        }
        Phase::Cancelling => {
          state.cancelling = state.cancelling.saturating_sub(1);
          None
        }
      };
      state.admission.release(&self.request);
      drop(state);
      // Holds no user data; dropped outside the lock all the same.
      drop(control);
    }
  }
}

/// Drops a job taken off the queue unstarted, then releases its admission,
/// then publishes `Cancelled`. Runs outside the lock; the caller counted it
/// as cancelling.
pub(crate) fn abandon(shared: &Shared, entry: Entry) {
  let mut admitted = Admitted {
    shared,
    request: entry.request,
    phase: Phase::Cancelling,
    done: false,
  };
  let task = entry.task;
  let _ = panic::catch_unwind(AssertUnwindSafe(|| task.abandon(&mut admitted)));
  admitted.release();
}

/// [`abandon`] for every job a cancelling close took, on a thread that is
/// marked as cleaning the runtime meanwhile.
pub(crate) fn abandon_all(shared: &Shared, pending: VecDeque<Entry>) {
  if pending.is_empty() {
    return;
  }
  let _cleaning = Cleaning::enter(&shared.ident);
  for entry in pending {
    abandon(shared, entry);
  }
}

pub(crate) fn run(shared: &Arc<Shared>, index: usize) {
  WORKER_OF.set(shared.ident.id);
  cache::set_shard(index);
  loop {
    match next(shared, index) {
      Next::Run(entry) => {
        let mut admitted = Admitted {
          shared,
          request: entry.request,
          phase: Phase::Running(index),
          done: false,
        };
        let task = entry.task;
        // `run` contains the closure's panic; this only catches one from
        // dropping what nobody takes, and still releases.
        let _ = panic::catch_unwind(AssertUnwindSafe(|| task.run(&mut admitted)));
        admitted.release();
      }
      Next::Abandon(entry) => abandon(shared, entry),
      Next::Exit => break,
    }
  }
  // `WORKER_OF` stays set: the thread's thread-local destructors still run
  // after this, and a join from one of them is a worker's join.
  cache::flush();
}

/// Waits for the next job. A job that lost its start transition to a
/// cancellation stays admitted, counted as cancelling, and is handed back
/// to be dropped outside the lock. Exits once closed with an empty queue:
/// a draining shutdown runs everything queued first.
fn next(shared: &Shared, index: usize) -> Next {
  let mut flushed = false;
  let mut state = shared.lock();
  loop {
    if let Some(entry) = state.queue.pop_front() {
      if entry.task.control().start.try_start() {
        state.running_count += 1;
        if let Some(slot) = state.running.get_mut(index) {
          *slot = Some(Arc::clone(entry.task.control()));
        }
        return Next::Run(entry);
      }
      state.cancelling += 1;
      return Next::Abandon(entry);
    }
    if state.closed {
      return Next::Exit;
    }
    if !flushed {
      drop(state);
      cache::flush();
      #[cfg(test)]
      if let Some(hook) = &shared.park_hook {
        hook();
      }
      flushed = true;
      state = shared.lock();
      continue;
    }
    state.idle += 1;
    state = shared
      .work
      .wait(state)
      .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.idle = state.idle.saturating_sub(1);
  }
}
