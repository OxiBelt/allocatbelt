//! A test-and-test-and-set spin lock built only from atomics.
//!
//! Data guarded by it is itself stored in atomics accessed with `Relaxed`
//! ordering; the `Acquire`/`Release` pair here orders those accesses, which
//! avoids `UnsafeCell` (and therefore `unsafe`) entirely.

use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
pub(crate) struct SpinLock(AtomicBool);

impl SpinLock {
  pub(crate) const fn new() -> Self {
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
    let mut spins = 0u32;
    loop {
      if let Some(g) = self.try_lock() {
        return g;
      }
      if spins < 64 {
        spins += 1;
        core::hint::spin_loop();
      } else {
        yield_now();
      }
    }
  }
}

pub(crate) struct Guard<'a>(&'a SpinLock);

impl Drop for Guard<'_> {
  fn drop(&mut self) {
    self.0.0.store(false, Ordering::Release);
  }
}
