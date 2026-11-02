//! Construction-time dispatcher search configuration: pre-park spin, the
//! searcher cap and concurrent spinner slots.

#![forbid(unsafe_code)]

/// Spin policy used before a distributed dispatcher attempts to park.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParkSpin {
  /// Check ready-depth hints for at most this many rounds, without locks.
  /// The round limit is fixed at construction. Zero disables spinning.
  /// The default is 128 rounds. Closing and handoff yield hints stop early.
  /// See [`super::AsyncRuntimeOptions::max_spinning_dispatchers`] for the
  /// construction-time cap on simultaneous spinners. Loom omits spinning.
  /// Each round reads every dispatcher's depth hint, so very large values
  /// keep idle dispatchers busy for a long time before they park.
  #[non_exhaustive]
  Fixed { rounds: u32 },
}

impl ParkSpin {
  /// Spins for at most `rounds` rounds before parking; zero disables spinning.
  #[must_use]
  pub const fn fixed(rounds: u32) -> Self {
    Self::Fixed { rounds }
  }
}

impl Default for ParkSpin {
  fn default() -> Self {
    Self::fixed(128)
  }
}

// Configuration is accepted but ignored when Loom compiles spinning out.
#[cfg_attr(loom, allow(dead_code))]
#[derive(Clone, Copy, Debug)]
pub(super) struct Policy {
  pub(super) rounds: u32,
  pub(super) max_spinners: Option<usize>,
  /// Search admission cap; `None` uses half the workers, rounded up.
  pub(super) max_searchers: Option<usize>,
}

impl Default for Policy {
  fn default() -> Self {
    let ParkSpin::Fixed { rounds } = ParkSpin::default();
    Self {
      rounds,
      max_spinners: None,
      max_searchers: None,
    }
  }
}

#[cfg(not(loom))]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(not(loom))]
pub(super) struct SpinnerSlots {
  current: AtomicUsize,
  max: usize,
  #[cfg(test)]
  acquisitions: AtomicUsize,
}

#[cfg(not(loom))]
impl SpinnerSlots {
  pub(super) fn new(max: usize) -> Self {
    Self {
      current: AtomicUsize::new(0),
      max,
      #[cfg(test)]
      acquisitions: AtomicUsize::new(0),
    }
  }

  pub(super) fn try_acquire(&self) -> Option<SpinnerGuard<'_>> {
    // This counter grants slots only; it publishes no queue or task state.
    self
      .current
      .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        (current < self.max).then(|| current + 1)
      })
      .ok()
      .map(|_| {
        #[cfg(test)]
        self.acquisitions.fetch_add(1, Ordering::Relaxed);
        SpinnerGuard(self)
      })
  }

  #[cfg(test)]
  pub(super) fn acquisitions(&self) -> usize {
    self.acquisitions.load(Ordering::Relaxed)
  }

  #[cfg(test)]
  pub(super) fn current(&self) -> usize {
    self.current.load(Ordering::Relaxed)
  }
}

#[cfg(not(loom))]
pub(super) struct SpinnerGuard<'a>(&'a SpinnerSlots);

#[cfg(not(loom))]
impl Drop for SpinnerGuard<'_> {
  fn drop(&mut self) {
    self.0.current.fetch_sub(1, Ordering::Relaxed);
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;

  #[test]
  fn spinner_slot_is_released_during_unwind() {
    let slots = SpinnerSlots::new(1);
    assert!(
      std::panic::catch_unwind(|| {
        let _guard = slots.try_acquire().unwrap();
        assert_eq!(slots.current(), 1);
        assert!(slots.try_acquire().is_none());
        panic!("injected spin unwind");
      })
      .is_err()
    );
    assert_eq!(slots.current(), 0);
    assert!(slots.try_acquire().is_some());
  }
}
