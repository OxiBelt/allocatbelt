//! The maintenance thread's decay passes decommit retained huge blocks
//! once the purge delay has passed. A separate test binary, because it
//! starts the maintenance thread (feature `maintenance`).

#![allow(unsafe_code, reason = "the test queries the kernel for page faults")]

use std::time::{Duration, Instant};

use allocatbelt::Allocatbelt;

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

/// Two segments: well above the longest page run, below the dirty budget.
const SIZE: usize = 8 << 20;

/// Minor page faults of this process so far.
fn minor_faults() -> i64 {
  // SAFETY: `rusage` is plain data for which all-zero bytes are valid.
  let mut r: libc::rusage = unsafe { std::mem::zeroed() };
  // SAFETY: `getrusage` writes the usage of this process to `r`, a valid
  // out pointer.
  assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &raw mut r) }, 0);
  r.ru_minflt
}

/// Allocates a block of `SIZE`, writes one byte per 4 KiB page and frees
/// it; returns the minor faults that cost.
fn fill_and_free() -> i64 {
  let before = minor_faults();
  let mut v = Vec::<u8>::with_capacity(SIZE);
  v.resize(SIZE, 1);
  for i in (0..SIZE).step_by(4096) {
    v[i] = i as u8;
  }
  std::hint::black_box(&v);
  drop(v);
  minor_faults() - before
}

/// Waits up to 10 s for `done`.
fn wait_for(done: impl Fn() -> bool) -> bool {
  let deadline = Instant::now() + Duration::from_secs(10);
  while !done() {
    if Instant::now() > deadline {
      return false;
    }
    std::thread::sleep(Duration::from_millis(5));
  }
  true
}

#[test]
fn the_maintenance_thread_decays_retained_huge_blocks() {
  GLOBAL.set_purge_delay(Duration::from_secs(3600));
  fill_and_free();
  assert_eq!(GLOBAL.heap_usage().retained_segments, 2);
  // Retained: reused without a fault per page.
  let faults = fill_and_free();
  assert!(faults < 256, "{faults} faults refilling a retained block");
  assert_eq!(GLOBAL.heap_usage().retained_segments, 2);

  // Once the purge delay has passed, the thread's decay pass decommits
  // them, with no allocation from this thread.
  GLOBAL.set_purge_delay(Duration::from_millis(20));
  assert!(GLOBAL.start_maintenance_thread().unwrap());
  assert!(
    wait_for(|| GLOBAL.heap_usage().retained_segments == 0),
    "{:?}",
    GLOBAL.heap_usage()
  );
  assert!(GLOBAL.maintenance_stats().retained_segments_purged >= 2);
  // Decommitted, a new block of the size faults again on every page.
  GLOBAL.set_purge_delay(Duration::from_secs(3600));
  let faults = fill_and_free();
  assert!(
    faults >= 1024,
    "only {faults} faults filling a decommitted block"
  );
}
