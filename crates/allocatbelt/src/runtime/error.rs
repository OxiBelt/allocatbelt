//! Submission and join errors.

use std::any::Any;
use std::fmt;

/// Why a submission was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubmitErrorKind {
  /// The runtime is shut down or shutting down, or was dropped.
  Closed,
  /// `max_outstanding` jobs are queued or running.
  Full,
  /// The request fits the capacity but not what is free now.
  InsufficientResources,
  /// The request exceeds the capacity in some component and can never be
  /// admitted.
  InvalidRequest,
}

impl fmt::Display for SubmitErrorKind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Closed => "runtime is closed",
      Self::Full => "outstanding job bound reached",
      Self::InsufficientResources => "not enough free resources",
      Self::InvalidRequest => "request exceeds the runtime's capacity",
    })
  }
}

impl std::error::Error for SubmitErrorKind {}

/// A rejected submission. Owns the closure that was not admitted: take it
/// back with [`SubmitError::into_job`] or the public field.
pub struct SubmitError<F> {
  /// Why it was rejected.
  pub kind: SubmitErrorKind,
  /// The closure that was not admitted, unchanged.
  pub job: F,
}

impl<F> SubmitError<F> {
  /// Why it was rejected.
  #[must_use]
  pub const fn kind(&self) -> SubmitErrorKind {
    self.kind
  }

  /// The closure that was not admitted.
  #[must_use]
  pub fn into_job(self) -> F {
    self.job
  }
}

impl<F> fmt::Debug for SubmitError<F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("SubmitError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl<F> fmt::Display for SubmitError<F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "job rejected: {}", self.kind)
  }
}

impl<F> std::error::Error for SubmitError<F> {}

/// Why [`Job::join`](crate::runtime::Job::join) has no result.
#[non_exhaustive]
pub enum JoinError {
  /// The job was cancelled before it started, or dropped unstarted by a
  /// cancelling shutdown or the runtime's drop. Its closure has been
  /// dropped and its admission released. A job that started and saw its
  /// token cancelled returns whatever its closure returned instead.
  Cancelled,
  /// The closure panicked; the payload is the panic's.
  Panicked(Box<dyn Any + Send + 'static>),
  /// The outcome was not ready, and the join was called from one of the
  /// job's runtime's workers or from the thread dropping its queued jobs.
  /// Waiting there could deadlock (see [`Job::join`](crate::runtime::Job::join)).
  /// The job is unaffected; its result is lost because the handle was
  /// consumed.
  WouldDeadlock,
}

impl fmt::Debug for JoinError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Cancelled => f.write_str("Cancelled"),
      Self::Panicked(_) => f.write_str("Panicked(..)"),
      Self::WouldDeadlock => f.write_str("WouldDeadlock"),
    }
  }
}

impl fmt::Display for JoinError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Cancelled => "job was cancelled before it started",
      Self::Panicked(_) => "job panicked",
      Self::WouldDeadlock => "join from the job's own runtime would deadlock",
    })
  }
}

impl std::error::Error for JoinError {}

#[cfg(test)]
mod tests {
  use super::{JoinError, SubmitError, SubmitErrorKind};

  struct NotDebug(u32);

  #[test]
  fn errors_format_without_debug_payloads() {
    let e = SubmitError {
      kind: SubmitErrorKind::Full,
      job: NotDebug(7),
    };
    assert_eq!(e.to_string(), "job rejected: outstanding job bound reached");
    assert!(format!("{e:?}").contains("Full"));
    let boxed: Box<dyn std::error::Error> = Box::new(SubmitError {
      kind: SubmitErrorKind::Closed,
      job: NotDebug(1),
    });
    assert_eq!(boxed.to_string(), "job rejected: runtime is closed");
    assert_eq!(e.kind(), SubmitErrorKind::Full);
    assert_eq!(e.into_job().0, 7);
    assert_eq!(
      format!("{:?}", JoinError::Panicked(Box::new(3))),
      "Panicked(..)"
    );
  }
}
