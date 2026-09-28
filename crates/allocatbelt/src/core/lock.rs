//! An adaptive lock built only from atomics: it spins briefly, then parks
//! the thread through [`Park`] (a futex on Linux) until the holder wakes it.
//!
//! Data guarded by it is itself stored in atomics accessed with `Relaxed`
//! ordering; the `Acquire`/`Release` pair here orders those accesses, which
//! avoids `UnsafeCell` (and therefore `unsafe`) entirely.
//!
//! The state word follows the classic three-state futex mutex (Drepper,
//! "Futexes Are Tricky", mutex 2; also Rust's `std` futex mutex):
//! [`UNLOCKED`], [`LOCKED`] with no thread parked, and [`CONTENDED`] when a
//! thread may be parked. An uncontended lock and unlock is one
//! compare-and-swap and one swap, with no system call; only an unlock that
//! finds [`CONTENDED`] wakes a thread.

use crate::core::sync::{AtomicU32, Ordering, spin_loop};

const UNLOCKED: u32 = 0;
const LOCKED: u32 = 1;
const CONTENDED: u32 = 2;

/// Iterations to spin on a held lock before parking. Holders are usually
/// done within a few hundred cycles (a bitmap claim or a list update), so
/// spinning first avoids a system call in the common case; a holder that
/// is in a system call itself (`mprotect`, `madvise`) or was preempted is
/// waited out asleep instead. loom spins once, to keep its search small.
const SPINS: u32 = if cfg!(loom) { 1 } else { 100 };

/// How a thread sleeps on a contended lock.
pub(crate) trait Park {
  /// Blocks while `word` holds `expected`, or returns at once if it does
  /// not; may also return spuriously. Checking the value and going to
  /// sleep must be atomic with respect to [`Park::wake`] (`FUTEX_WAIT`).
  fn wait(&self, word: &AtomicU32, expected: u32);
  /// Wakes one thread blocked in [`Park::wait`] on `word`, if any
  /// (`FUTEX_WAKE`).
  fn wake(&self, word: &AtomicU32);
}

#[derive(Debug)]
pub(crate) struct Lock(AtomicU32);

impl Lock {
  #[cfg(not(loom))]
  pub(crate) const fn new() -> Self {
    Self(AtomicU32::new(UNLOCKED))
  }

  #[cfg(loom)]
  pub(crate) fn new() -> Self {
    Self(AtomicU32::new(UNLOCKED))
  }

  pub(crate) fn try_lock<'a, P: Park>(&'a self, park: &'a P) -> Option<Guard<'a, P>> {
    // `then`, not `then_some`: a `Guard` built eagerly would be dropped on
    // failure and release the lock its holder still owns.
    self.try_acquire().then(|| Guard(self, park))
  }

  pub(crate) fn lock<'a, P: Park>(&'a self, park: &'a P) -> Guard<'a, P> {
    self.acquire(park);
    Guard(self, park)
  }

  fn try_acquire(&self) -> bool {
    self.0.load(Ordering::Relaxed) == UNLOCKED
      && self
        .0
        .compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
  }

  /// Takes the lock without a guard; [`Lock::release`] gives it back.
  /// Only for `fork` handlers, which lock and unlock in separate calls.
  pub(crate) fn acquire(&self, park: &impl Park) {
    if self
      .0
      .compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
      .is_err()
    {
      self.acquire_contended(park);
    }
  }

  #[cold]
  fn acquire_contended(&self, park: &impl Park) {
    let mut state = self.spin();
    if state == UNLOCKED
      && self
        .0
        .compare_exchange(UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
      return;
    }
    loop {
      // Taking the lock as CONTENDED rather than LOCKED is conservative:
      // other threads may still be parked, so our unlock must wake one.
      if state != CONTENDED && self.0.swap(CONTENDED, Ordering::Acquire) == UNLOCKED {
        return;
      }
      park.wait(&self.0, CONTENDED);
      state = self.spin();
    }
  }

  /// Spins while the lock is held by a thread nobody waits for, and
  /// returns the last state seen.
  fn spin(&self) -> u32 {
    let mut left = SPINS;
    loop {
      let state = self.0.load(Ordering::Relaxed);
      if state != LOCKED || left == 0 {
        return state;
      }
      spin_loop();
      left -= 1;
    }
  }

  /// Releases a lock taken with [`Lock::acquire`] (or, in a forked child,
  /// by a thread that no longer exists), waking a parked thread if there
  /// may be one.
  pub(crate) fn release(&self, park: &impl Park) {
    if self.0.swap(UNLOCKED, Ordering::Release) == CONTENDED {
      park.wake(&self.0);
    }
  }
}

pub(crate) struct Guard<'a, P: Park>(&'a Lock, &'a P);

impl<P: Park> Drop for Guard<'_, P> {
  fn drop(&mut self) {
    self.0.release(self.1);
  }
}

#[cfg(all(test, allocatbelt_core_check, not(loom)))]
mod tests {
  use std::sync::atomic::AtomicBool;
  use std::time::{Duration, Instant};
  use std::vec::Vec;
  use std::{println, thread};

  use rustix::thread::futex;
  use rustix::time::{ClockId, clock_gettime};

  use super::{AtomicU32, Lock, Ordering, Park, spin_loop};

  struct Spin;

  impl Park for Spin {
    fn wait(&self, _: &AtomicU32, _: u32) {}
    fn wake(&self, _: &AtomicU32) {}
  }

  #[test]
  fn failed_try_lock_keeps_the_lock() {
    let lock = Lock::new();
    let g = lock.lock(&Spin);
    assert!(lock.try_lock(&Spin).is_none());
    assert!(
      lock.try_lock(&Spin).is_none(),
      "a failed try_lock released it"
    );
    drop(g);
    assert!(lock.try_lock(&Spin).is_some());
  }

  /// The lock this module replaced: test-and-test-and-set, 64 spins, then
  /// `sched_yield` in a loop. The baseline of [`contention_benchmark`].
  struct YieldLock(AtomicBool);

  impl YieldLock {
    fn lock(&self) {
      let mut spins = 0u32;
      loop {
        if !self.0.load(Ordering::Relaxed)
          && self
            .0
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
          return;
        }
        if spins < 64 {
          spins += 1;
          spin_loop();
        } else {
          thread::yield_now();
        }
      }
    }
    fn unlock(&self) {
      self.0.store(false, Ordering::Release);
    }
  }

  /// What the adapter does (`sys::futex_wait`/`futex_wake`).
  struct Futex;

  impl Park for Futex {
    fn wait(&self, word: &AtomicU32, expected: u32) {
      let _ = futex::wait(word, futex::Flags::PRIVATE, expected, None);
    }
    fn wake(&self, word: &AtomicU32) {
      let _ = futex::wake(word, futex::Flags::PRIVATE, 1);
    }
  }

  fn busy(iters: u32) {
    for i in 0..iters {
      core::hint::black_box(i);
    }
  }

  fn cpu_ns() -> u128 {
    let t = clock_gettime(ClockId::ProcessCPUTime);
    t.tv_sec as u128 * 1_000_000_000 + t.tv_nsec as u128
  }

  /// `threads` threads take one lock `ops` times each. Inside, they spin
  /// for `inside` iterations, and every `block_every`-th time also sleep
  /// 20 µs, as a holder in `mprotect`/`madvise` or preempted would; outside
  /// they spin for `outside`. Returns wall and process CPU time.
  fn run(
    futex_lock: bool,
    threads: usize,
    ops: u32,
    inside: u32,
    outside: u32,
    block_every: u32,
  ) -> (Duration, Duration) {
    let (lock, old) = (Lock::new(), YieldLock(AtomicBool::new(false)));
    let (wall, cpu) = (Instant::now(), cpu_ns());
    thread::scope(|s| {
      for _ in 0..threads {
        s.spawn(|| {
          for i in 0..ops {
            let g = futex_lock.then(|| lock.lock(&Futex));
            if !futex_lock {
              old.lock();
            }
            busy(inside);
            if block_every != 0 && i % block_every == 0 {
              thread::sleep(Duration::from_micros(20));
            }
            drop(g);
            if !futex_lock {
              old.unlock();
            }
            busy(outside);
          }
        });
      }
    });
    let cpu = Duration::from_nanos((cpu_ns() - cpu) as u64);
    (wall.elapsed(), cpu)
  }

  /// The Phase 6 qualification: the futex lock against the `sched_yield`
  /// lock it replaced, on lock-heavy patterns. Prints a markdown table;
  /// `cargo test --release -p allocatbelt-core-check --lib contention_benchmark
  /// -- --ignored --nocapture`. See docs/research/benchmarks.md.
  #[test]
  #[ignore = "benchmark; prints timings"]
  fn contention_benchmark() {
    let cpus = thread::available_parallelism().map_or(4, |n| n.get());
    let scenarios = [
      ("short hold", cpus, 100_000, 50, 200, 0),
      ("short hold, 4x threads", 4 * cpus, 25_000, 50, 200, 0),
      ("holder blocks 1/64", cpus, 20_000, 50, 200, 64),
      (
        "holder blocks 1/64, 4x threads",
        4 * cpus,
        5_000,
        50,
        200,
        64,
      ),
    ];
    println!("| scenario | threads | lock | wall ms | CPU ms | CPU / wall |");
    println!("|---|---:|---|---:|---:|---:|");
    for (name, threads, ops, inside, outside, block) in scenarios {
      for futex_lock in [false, true] {
        let mut runs: Vec<(Duration, Duration)> = (0..7)
          .map(|_| run(futex_lock, threads, ops, inside, outside, block))
          .collect();
        runs.sort();
        let (wall, cpu) = runs[runs.len() / 2];
        println!(
          "| {name} | {threads} | {} | {:.1} | {:.1} | {:.2} |",
          if futex_lock { "futex" } else { "yield" },
          wall.as_secs_f64() * 1e3,
          cpu.as_secs_f64() * 1e3,
          cpu.as_secs_f64() / wall.as_secs_f64()
        );
      }
    }
  }
}
