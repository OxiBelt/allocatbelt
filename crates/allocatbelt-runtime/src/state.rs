//! The start/cancel transition of a queued job.
//!
//! A job is created `QUEUED` and leaves that state exactly once, by one
//! compare-and-swap: a worker moving it to `RUNNING` (it will call the
//! closure) or a cancellation moving it to `CANCELLED` (the closure is never
//! called). That swap is the linearization point; whichever loses sees the
//! other's state and does nothing.

use crate::sync::{AtomicU8, Ordering};

const QUEUED: u8 = 0;
const RUNNING: u8 = 1;
const CANCELLED: u8 = 2;

#[derive(Debug)]
pub(crate) struct StartState(AtomicU8);

impl StartState {
  pub(crate) fn new() -> Self {
    Self(AtomicU8::new(QUEUED))
  }

  /// `QUEUED` to `RUNNING`: the caller may call the closure.
  pub(crate) fn try_start(&self) -> bool {
    self.swap_from_queued(RUNNING)
  }

  /// `QUEUED` to `CANCELLED`: the caller publishes the cancellation and
  /// the closure is never called.
  pub(crate) fn try_cancel(&self) -> bool {
    self.swap_from_queued(CANCELLED)
  }

  fn swap_from_queued(&self, to: u8) -> bool {
    self
      .0
      .compare_exchange(QUEUED, to, Ordering::AcqRel, Ordering::Acquire)
      .is_ok()
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::StartState;

  #[test]
  fn the_first_transition_wins() {
    let s = StartState::new();
    assert!(s.try_start());
    assert!(!s.try_cancel());
    assert!(!s.try_start());
    let c = StartState::new();
    assert!(c.try_cancel());
    assert!(!c.try_start());
    assert!(!c.try_cancel());
  }
}
