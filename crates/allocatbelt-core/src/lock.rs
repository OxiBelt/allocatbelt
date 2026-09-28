//! A test-and-test-and-set spin lock built only from atomics.
//!
//! Data guarded by it is itself stored in atomics accessed with `Relaxed`
//! ordering; the `Acquire`/`Release` pair here orders those accesses, which
//! avoids `UnsafeCell` (and therefore `unsafe`) entirely.

use crate::sync::{AtomicBool, Ordering, spin_loop};

#[derive(Debug)]
pub(crate) struct SpinLock(AtomicBool);

impl SpinLock {
  #[cfg(not(loom))]
  pub(crate) const fn new() -> Self {
    Self(AtomicBool::new(false))
  }

  #[cfg(loom)]
  pub(crate) fn new() -> Self {
    Self(AtomicBool::new(false))
  }

  pub(crate) fn try_lock(&self) -> Option<Guard<'_>> {
    if self.0.load(Ordering::Relaxed) {
      return None;
    }
    self
      .0
      .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
      .ok()
      .map(|_| Guard(self))
  }

  pub(crate) fn lock(&self, yield_now: impl Fn()) -> Guard<'_> {
    self.acquire(yield_now);
    Guard(self)
  }

  /// Takes the lock without a guard; [`SpinLock::release`] gives it back.
  /// Only for `fork` handlers, which lock and unlock in separate calls.
  pub(crate) fn acquire(&self, yield_now: impl Fn()) {
    let mut spins = 0u32;
    loop {
      if let Some(g) = self.try_lock() {
        core::mem::forget(g);
        return;
      }
      if spins < 64 {
        spins += 1;
        spin_loop();
      } else {
        yield_now();
      }
    }
  }

  /// Releases a lock taken with [`SpinLock::acquire`] (or, in a forked
  /// child, by a thread that no longer exists).
  pub(crate) fn release(&self) {
    self.0.store(false, Ordering::Release);
  }
}

pub(crate) struct Guard<'a>(&'a SpinLock);

impl Drop for Guard<'_> {
  fn drop(&mut self) {
    self.0.release();
  }
}
