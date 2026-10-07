//! Bounded original-thread `block_in_place`. A blocking closure always runs on
//! its caller's thread. On an owned executor thread it first loans one of the
//! runtime's handoff slots, so a prestarted helper can take over dispatching
//! while the closure blocks; see [`try_block_in_place`].

use std::cell::RefCell;
use std::fmt;
use std::sync::Arc;

use super::entry::{self, ClosureContextGuard};
use super::handoff_protocol::{DispatchTurn, HandoffLoan};
use super::scheduler::Shared;
use crate::runtime::cache;

/// Handoff limits for [`AsyncRuntime::new_with_handoffs`](super::AsyncRuntime::new_with_handoffs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoffConfig {
  /// Maximum number of owned turns that may be handed off to a
  /// [`try_block_in_place`] closure at once; nested inline calls do not
  /// count. This many helper threads are started with the runtime. Must be
  /// nonzero, and `workers + max_handoffs` must not overflow.
  pub max_handoffs: usize,
}

/// Why [`try_block_in_place`] did not call its closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockInPlaceErrorKind {
  /// The calling task runs on a runtime built without handoffs
  /// ([`AsyncRuntime::new`](super::AsyncRuntime::new)).
  Disabled,
  /// Every handoff slot of the calling task's runtime is loaned.
  Full,
  /// The caller is being polled or cleaned up by a
  /// [`LocalRuntime`](super::LocalRuntime), whose single thread has no
  /// helper to take over.
  LocalExecutor,
}

impl fmt::Display for BlockInPlaceErrorKind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Disabled => "the runtime was built without block_in_place handoffs",
      Self::Full => "every block_in_place handoff slot is in use",
      Self::LocalExecutor => "block_in_place is not supported on a local executor",
    })
  }
}

/// A rejected [`try_block_in_place`] call together with its uncalled closure.
pub struct BlockInPlaceError<F> {
  /// Why the closure was not called.
  pub kind: BlockInPlaceErrorKind,
  closure: F,
}

impl<F> BlockInPlaceError<F> {
  fn new(kind: BlockInPlaceErrorKind, closure: F) -> Self {
    Self { kind, closure }
  }

  /// Returns the unchanged closure, which has not been called.
  #[must_use]
  pub fn into_closure(self) -> F {
    self.closure
  }
}

impl<F> fmt::Debug for BlockInPlaceError<F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BlockInPlaceError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl<F> fmt::Display for BlockInPlaceError<F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "block_in_place rejected: {}", self.kind)
  }
}

impl<F> std::error::Error for BlockInPlaceError<F> {}

/// Runs a blocking closure on the calling thread and returns its result.
///
/// Neither the closure nor its result needs to be `Send` or `'static`: the
/// closure runs on the caller's own stack and thread, so it may borrow from
/// and return thread-affine values to the caller.
///
/// # On an owned executor thread
///
/// When called during an owned [`AsyncRuntime`](super::AsyncRuntime) task's
/// poll, cancellation cleanup or result publication, the call first reserves
/// one of the runtime's [`HandoffConfig::max_handoffs`] slots and only then
/// releases the thread's dispatcher permit, so a prestarted helper thread can
/// dispatch other owned work while the closure runs. At most `workers`
/// threads dispatch at once and at most `max_handoffs` closures are handed
/// off at once. After the closure returns or panics, the thread waits for a
/// dispatcher permit, ahead of any new scheduler work, and keeps its slot
/// until it has one; restoration also proceeds after admission has closed.
/// A panic in the closure resumes once the permit is held again.
///
/// The calling task stays admitted and running throughout. In particular:
///
/// - Its scope's active-poll slot stays reserved through the whole
///   `Future::poll`, closure included. A closure that waits for another task
///   of the same scope can deadlock once that scope's `max_active_polls` is
///   exhausted and the dependency needs another poll: with a limit of 1,
///   a still-pending same-scope dependency cannot progress. The implicit root
///   scope's
///   limit equals the worker count, so with one worker a handed-off root
///   task holds back every other root task until its closure returns.
///   Dependencies inside one scope need an explicit
///   [`AsyncScopeConfig`](super::AsyncScopeConfig) limit above the number of
///   its tasks that may wait at once.
/// - Abort and cancelling shutdown take effect only after the poll returns;
///   they never drop the task while its closure runs.
/// - The runtime-worker identity stays set, so
///   [`AsyncRuntime::shutdown`](super::AsyncRuntime::shutdown) called from
///   the closure returns [`AsyncError::WouldDeadlock`](super::AsyncError::WouldDeadlock).
///   Explicit shutdown from another thread joins every worker and helper and
///   therefore waits for blocked closures without a time limit; dropping the
///   runtime does not wait.
///
/// Inside the closure, the task identity, entered runtime contexts and
/// task-local values remain those of the calling task, and the thread may run
/// a nested [`AsyncHandle::block_on`](super::AsyncHandle::block_on), whose
/// root has no task identity; the executor-worker marker, task identity and
/// cooperative budget are restored afterwards, on return or unwind. A nested
/// `try_block_in_place` on the same thread runs inline. Helper threads may
/// hand off too, under the same bound.
///
/// # Elsewhere
///
/// Outside an owned executor turn, including inside the root future of
/// [`AsyncHandle::block_on`](super::AsyncHandle::block_on), the closure runs
/// inline. The borrowed root's reentrancy marker and cooperative budget are
/// saved so that the closure may call `block_on` again, and are restored on
/// return or unwind.
///
/// This is not a CPU-time quota and preempts nothing: the closure runs to
/// completion on its thread for as long as it takes.
///
/// # Errors
///
/// Returns the uncalled closure in a [`BlockInPlaceError`]:
/// [`Disabled`](BlockInPlaceErrorKind::Disabled) on an owned executor turn of
/// a runtime without handoffs, [`Full`](BlockInPlaceErrorKind::Full) when
/// every slot is loaned (the calling turn keeps its permit), and
/// [`LocalExecutor`](BlockInPlaceErrorKind::LocalExecutor) during actual
/// [`LocalRuntime`](super::LocalRuntime) execution. Entering a
/// [`LocalHandle`](super::LocalHandle) context alone is not local execution.
pub fn try_block_in_place<F, R>(f: F) -> Result<R, BlockInPlaceError<F>>
where
  F: FnOnce() -> R,
{
  if entry::local_execution_active() {
    return Err(BlockInPlaceError::new(
      BlockInPlaceErrorKind::LocalExecutor,
      f,
    ));
  }
  match take_turn() {
    Placement::Inline => {
      let _context = ClosureContextGuard::suspend(false);
      Ok(f())
    }
    Placement::Disabled => Err(BlockInPlaceError::new(BlockInPlaceErrorKind::Disabled, f)),
    Placement::HandOff(shared, turn) => match shared.hand_off(turn) {
      Err(turn) => {
        restore_phase(turn);
        Err(BlockInPlaceError::new(BlockInPlaceErrorKind::Full, f))
      }
      Ok(loan) => {
        let restore = Restore {
          shared,
          loan: Some(loan),
          _context: ClosureContextGuard::suspend(true),
        };
        cache::flush();
        let output = f();
        drop(restore);
        Ok(output)
      }
    },
  }
}

/// Reacquires the dispatcher permit when the closure returns or unwinds,
/// then restores the suspended markers.
struct Restore {
  shared: Arc<Shared>,
  loan: Option<HandoffLoan>,
  _context: ClosureContextGuard,
}

impl Drop for Restore {
  fn drop(&mut self) {
    if let Some(loan) = self.loan.take() {
      let turn = self.shared.restore(loan);
      restore_phase(turn);
    }
  }
}

enum Phase {
  /// Between turns.
  Idle,
  /// Holding a dispatcher permit for an owned poll, cleanup or publication.
  Dispatching(DispatchTurn),
  /// Running a handed-off closure; the permit is released.
  HandedOff,
}

struct DispatcherThread {
  shared: Arc<Shared>,
  phase: Phase,
}

thread_local! {
  static DISPATCHER: RefCell<Option<DispatcherThread>> = const { RefCell::new(None) };
}

enum Placement {
  Inline,
  Disabled,
  HandOff(Arc<Shared>, DispatchTurn),
}

fn take_turn() -> Placement {
  DISPATCHER
    .try_with(|slot| {
      let mut slot = slot.borrow_mut();
      let Some(thread) = slot.as_mut() else {
        return Placement::Inline;
      };
      match std::mem::replace(&mut thread.phase, Phase::HandedOff) {
        Phase::Dispatching(turn) if thread.shared.handoffs_enabled() => {
          Placement::HandOff(Arc::clone(&thread.shared), turn)
        }
        Phase::Dispatching(turn) => {
          thread.phase = Phase::Dispatching(turn);
          Placement::Disabled
        }
        other => {
          thread.phase = other;
          Placement::Inline
        }
      }
    })
    .unwrap_or(Placement::Inline)
}

fn restore_phase(turn: DispatchTurn) {
  let _ = DISPATCHER.try_with(|slot| {
    if let Some(thread) = slot.borrow_mut().as_mut() {
      thread.phase = Phase::Dispatching(turn);
    }
  });
}

/// Starts an owned turn on this executor thread.
pub(super) fn enter_turn(turn: DispatchTurn) {
  restore_phase(turn);
}

/// Ends this thread's owned turn and returns its permit for release under
/// the scheduler lock.
pub(super) fn leave_turn() -> Option<DispatchTurn> {
  DISPATCHER
    .try_with(|slot| {
      let mut slot = slot.borrow_mut();
      let thread = slot.as_mut()?;
      match std::mem::replace(&mut thread.phase, Phase::Idle) {
        Phase::Dispatching(turn) => Some(turn),
        other => {
          debug_assert!(matches!(other, Phase::Idle));
          thread.phase = other;
          None
        }
      }
    })
    .ok()
    .flatten()
}

/// Registers the current thread as one of a runtime's executor threads for
/// its lifetime. If the thread unwinds out of a turn, dropping the guard
/// releases that turn's permit.
pub(super) struct DispatcherGuard(());

impl DispatcherGuard {
  pub(super) fn install(shared: &Arc<Shared>) -> Self {
    let replaced = DISPATCHER
      .try_with(|slot| {
        slot.borrow_mut().replace(DispatcherThread {
          shared: Arc::clone(shared),
          phase: Phase::Idle,
        })
      })
      .ok()
      .flatten();
    drop(replaced);
    Self(())
  }
}

impl Drop for DispatcherGuard {
  fn drop(&mut self) {
    let removed = DISPATCHER
      .try_with(|slot| slot.borrow_mut().take())
      .ok()
      .flatten();
    if let Some(DispatcherThread {
      shared,
      phase: Phase::Dispatching(turn),
    }) = removed
    {
      shared.abandon_turn(turn);
    }
  }
}
