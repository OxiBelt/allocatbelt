//! Bounded process-wide signal subscriptions.
//!
//! The first published bridge fixes the process-wide listener ceiling. Drivers share
//! one dispatcher and permanently installed handlers; dropping subscriptions
//! does not restore a signal's default disposition. Events coalesce to one
//! unseen notification per listener. Cancellation removes only the registered
//! waker, preserving an unseen event.
//!
//! The handler only marks a lock-free pending bit and writes to a permanent
//! nonblocking descriptor. User callbacks run on the ordinary dispatcher
//! thread, outside the listener lock. This module forbids unsafe code; the
//! signal registration boundary lives in `sys`.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

mod protocol;
#[cfg(all(test, not(loom)))]
mod protocol_tests;
#[cfg(not(loom))]
mod system;

use std::fmt;

pub use protocol::{Signal, SignalRecv};
#[cfg(not(loom))]
pub use system::SignalDriver;

/// A supported Linux signal number on this library's three architectures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalKind(i32);

impl SignalKind {
  /// Validates a signal without installing a handler. The registry's
  /// forbidden set (illegal instruction, floating-point fault, segmentation
  /// fault, kill and stop) and libc-reserved signals are excluded.
  pub const fn from_raw(signal: i32) -> Result<Self, SignalError> {
    match signal {
      1..=64 if !matches!(signal, 4 | 8 | 9 | 11 | 19 | 32 | 33) => Ok(Self(signal)),
      _ => Err(SignalError::InvalidKind),
    }
  }

  /// Interrupt (`SIGINT`), commonly delivered by Ctrl-C.
  pub const fn interrupt() -> Self {
    Self(2)
  }

  /// Termination request (`SIGTERM`).
  pub const fn terminate() -> Self {
    Self(15)
  }

  /// Hangup (`SIGHUP`).
  pub const fn hangup() -> Self {
    Self(1)
  }

  /// Child status notification (`SIGCHLD`).
  pub const fn child() -> Self {
    Self(17)
  }

  /// The first user-defined signal (`SIGUSR1`).
  pub const fn user_defined1() -> Self {
    Self(10)
  }

  /// The second user-defined signal (`SIGUSR2`).
  pub const fn user_defined2() -> Self {
    Self(12)
  }

  /// The validated kernel signal number.
  pub const fn as_raw(self) -> i32 {
    self.0
  }

  pub(crate) const fn mask(self) -> u64 {
    1u64 << (self.0 - 1)
  }
}

/// Signal construction, admission or receive failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalError {
  /// Signal number is unsupported, reserved, uncatchable or a fault signal.
  InvalidKind,
  /// The listener ceiling is zero or cannot be represented.
  InvalidCapacity,
  /// Reserving the fixed listener table failed.
  AllocationFailed,
  /// A later driver requested a different process-wide ceiling.
  ConfigurationMismatch,
  /// The listener table has no available slot.
  Full,
  /// Bridge construction or dispatcher startup failed.
  Bridge(std::io::ErrorKind),
  /// Registration failed. The registry may already have changed disposition;
  /// the bridge remains valid and the failed attempt is never repeated.
  Registration(std::io::ErrorKind),
  /// The listener is no longer registered.
  Closed,
  /// A custom raw waker panicked while being cloned.
  WakerPanicked,
  /// This future was polled after completion.
  Completed,
}

impl fmt::Display for SignalError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::InvalidKind => "unsupported signal kind",
      Self::InvalidCapacity => "invalid signal listener capacity",
      Self::AllocationFailed => "signal listener table allocation failed",
      Self::ConfigurationMismatch => "process signal listener capacity is already fixed",
      Self::Full => "signal listener table is full",
      Self::Bridge(_) => "process signal bridge failed to start",
      Self::Registration(_) => "signal handler registration failed",
      Self::Closed => "signal listener is closed",
      Self::WakerPanicked => "signal waker clone panicked",
      Self::Completed => "signal receive future already completed",
    })
  }
}

impl std::error::Error for SignalError {}
