//! The type-erased queued job: runs its closure, or drops it unstarted.

use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;

use crate::error::JoinError;
use crate::job::{CancellationToken, Control, Packet};

/// Returns a job's admission. The worker calls it again after the job if
/// the job did not, so it releases exactly once.
pub(crate) trait Release {
  fn release(&mut self);
}

/// A queued job with its result type erased.
pub(crate) trait Runnable: Send {
  /// The job's flags and start state (see [`crate::state`]).
  fn control(&self) -> &Arc<Control>;

  /// Runs a started job: calls the closure, releases the admission once the
  /// closure returned (or unwound) and its captures were dropped, publishes
  /// the outcome and drops what nobody will take. Called without any
  /// scheduler lock.
  fn run(self: Box<Self>, release: &mut dyn Release);

  /// Finishes a job that will not start: drops the closure (a panic of its
  /// `Drop` contained), then releases the admission, then publishes
  /// `Cancelled`. Called without any scheduler lock.
  fn abandon(self: Box<Self>, release: &mut dyn Release);
}

pub(crate) struct Task<F, T> {
  pub(crate) f: F,
  control: Arc<Control>,
  packet: Arc<Packet<T>>,
}

impl<F, T> Task<F, T> {
  pub(crate) fn new(f: F, control: Arc<Control>, packet: Arc<Packet<T>>) -> Self {
    Self { f, control, packet }
  }
}

/// Drops `value`, containing a panic of its `Drop`. A panic payload whose
/// own drop panics is leaked rather than unwinding into the worker.
pub(crate) fn drop_contained<V>(value: V) {
  if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(move || drop(value)))
    && let Err(again) = panic::catch_unwind(AssertUnwindSafe(move || drop(payload)))
  {
    std::mem::forget(again);
  }
}

impl<F, T> Runnable for Task<F, T>
where
  F: FnOnce(CancellationToken) -> T + Send,
  T: Send,
{
  fn control(&self) -> &Arc<Control> {
    &self.control
  }

  fn run(self: Box<Self>, release: &mut dyn Release) {
    let Self { f, control, packet } = *self;
    let token = CancellationToken::new(control);
    let outcome =
      panic::catch_unwind(AssertUnwindSafe(move || f(token))).map_err(JoinError::Panicked);
    release.release();
    if let Some(unclaimed) = packet.publish(outcome) {
      drop_contained(unclaimed);
    }
  }

  fn abandon(self: Box<Self>, release: &mut dyn Release) {
    let Self { f, control, packet } = *self;
    // A shutdown's take: the job may never start, whatever won before.
    let _ = control.start.try_cancel();
    drop_contained(f);
    release.release();
    // `Cancelled` holds nothing of the user's, so this drops nothing.
    let _ = packet.publish(Err(JoinError::Cancelled));
  }
}
