//! Freed huge blocks stay resident but inaccessible until a pass decommits
//! them: seen from a real process, in every feature combination. No test
//! here starts the maintenance thread, so decay passes run inline on
//! allocation slow paths; `huge_retention_maintenance.rs` covers the thread.
//!
//! One test runs the cases in order. A thread's first allocations take a
//! segment for its shard, and a shard's new segment may be any free one, a
//! retained one included (randomized placement does not look at
//! retention); a second test thread starting while a case holds retained
//! segments could take one and upset the counts. A separate test binary,
//! so that no other test allocates meanwhile.

#![allow(
  unsafe_code,
  reason = "the tests fork, read a freed block on purpose and query the kernel"
)]

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

/// Writes one byte per 4 KiB page of `v`'s whole capacity.
fn touch(v: &mut Vec<u8>) {
  v.resize(v.capacity(), 1);
  for i in (0..v.len()).step_by(4096) {
    v[i] = i as u8;
  }
  std::hint::black_box(&v);
}

/// Allocates and fills a block of `SIZE`, returning it and the minor faults
/// that cost.
fn filled() -> (Vec<u8>, i64) {
  let before = minor_faults();
  let mut v = Vec::<u8>::with_capacity(SIZE);
  touch(&mut v);
  (v, minor_faults() - before)
}

/// Retained segments are reused without a fault per page until an
/// explicit purge decommits them.
fn reused_without_faults_until_purged() {
  // No decay pass gets in the way.
  GLOBAL.set_purge_delay(Duration::from_secs(3600));
  let (v, _) = filled();
  let first = v.as_ptr();
  drop(v);
  let u = GLOBAL.heap_usage();
  assert_eq!((u.huge_segments, u.retained_segments), (0, 2), "{u:?}");

  // First fit by address takes the same segments, still resident: filling
  // the block again faults far less than once per page (2048 pages).
  let (v, faults) = filled();
  assert_eq!(v.as_ptr(), first);
  assert!(faults < 256, "{faults} faults refilling a retained block");
  assert_eq!(GLOBAL.heap_usage().retained_segments, 0);
  drop(v);
  assert_eq!(GLOBAL.heap_usage().retained_segments, 2);

  // An explicit purge decommits them regardless of age; a new block of
  // the size then faults on every page again.
  let purged = GLOBAL.maintenance_stats().retained_segments_purged;
  GLOBAL.purge();
  assert_eq!(GLOBAL.heap_usage().retained_segments, 0);
  assert_eq!(
    GLOBAL.maintenance_stats().retained_segments_purged - purged,
    2
  );
  let (v, faults) = filled();
  assert!(
    faults >= 1024,
    "only {faults} faults filling a decommitted block"
  );
  drop(v);
  GLOBAL.purge();
}

/// Without a maintenance thread, the decay passes that allocation slow
/// paths run decommit retained segments once the delay has passed.
fn inline_decay_decommits_them() {
  GLOBAL.set_purge_delay(Duration::from_millis(20));
  let purged = || GLOBAL.maintenance_stats().retained_segments_purged;
  let before = purged();
  let (v, _) = filled();
  drop(v);
  assert_eq!(GLOBAL.heap_usage().retained_segments, 2);
  // Without a maintenance thread, allocation slow paths run the decay
  // passes once they are due (sampled every 16th slow path): allocate and
  // free page runs, which take the slow path, until a pass has decommitted
  // the retained segments. The passes run on this thread and add their
  // work to the counters before the allocation that ran them returns.
  let deadline = Instant::now() + Duration::from_secs(10);
  while GLOBAL.heap_usage().retained_segments != 0 {
    assert!(Instant::now() < deadline, "{:?}", GLOBAL.heap_usage());
    for _ in 0..16 {
      std::hint::black_box(Vec::<u8>::with_capacity(256 << 10));
    }
    std::thread::sleep(Duration::from_millis(2));
  }
  assert_eq!(purged() - before, 2);
  GLOBAL.set_purge_delay(Duration::from_secs(3600));
}

/// What the child does: read a freed huge block, which must fault.
fn read_after_free() -> ! {
  // SAFETY: `alarm` only arms a timer; its default action kills the child
  // if it hangs instead of faulting.
  unsafe { libc::alarm(10) };
  GLOBAL.set_purge_delay(Duration::from_secs(3600));
  let (v, _) = filled();
  let p = v.as_ptr().wrapping_add(SIZE / 2);
  drop(v);
  // Retained, not decommitted: the memory is still there, but the
  // segments are inaccessible. (At least these two: the parent's state is
  // forked too.)
  assert!(GLOBAL.heap_usage().retained_segments >= 2);
  // SAFETY: none; this is the use after free under test, in a child
  // process that must die of `SIGSEGV` here.
  let _ = unsafe { p.read_volatile() };
  // SAFETY: `_exit` ends the child without running the parent's atexit
  // handlers or flushing its stdio buffers twice.
  unsafe { libc::_exit(0) }
}

/// A read of a freed huge block faults (in a forked child).
fn reading_a_retained_block_faults() {
  // SAFETY: the child only calls async-signal-safe functions and the
  // allocator (which supports use after `fork`) before it faults or exits.
  let pid = unsafe { libc::fork() };
  assert!(pid >= 0, "fork failed");
  if pid == 0 {
    read_after_free();
  }
  let mut status = 0;
  // SAFETY: waits for the child just created; `status` is a valid out
  // pointer.
  let r = unsafe { libc::waitpid(pid, &raw mut status, 0) };
  assert_eq!(r, pid);
  assert!(
    libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSEGV,
    "child ended with status {status:#x}, not SIGSEGV (a SIGALRM kill means it hung, \
     an abort that an assertion failed)"
  );
}

#[test]
fn freed_huge_blocks_are_retained_inaccessible_and_decommitted_later() {
  // This thread's shard takes its segment now, before any is retained.
  std::hint::black_box(Vec::<u8>::with_capacity(256 << 10));
  reused_without_faults_until_purged();
  inline_decay_decommits_them();
  reading_a_retained_block_faults();
}
