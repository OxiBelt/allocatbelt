//! The maintenance thread takes budget passes off the freeing threads,
//! serves purge requests, and runs as `SCHED_BATCH` (feature `scheduler`).
//! A separate test binary, so that no other test allocates meanwhile.

use std::time::{Duration, Instant};

use allocatbelt::{Allocatbelt, PurgeBackend};

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

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

/// The scheduling policy of the thread named `name` (`/proc/<pid>/task/
/// <tid>/stat` field 41). Thread names are at most 15 bytes there.
fn policy_of(name: &str) -> Option<u32> {
  for task in std::fs::read_dir("/proc/self/task").ok()? {
    let dir = task.ok()?.path();
    if std::fs::read_to_string(dir.join("comm")).ok()?.trim() != name {
      continue;
    }
    let stat = std::fs::read_to_string(dir.join("stat")).ok()?;
    // Fields after the parenthesised command name start at field 3.
    let rest = &stat[stat.rfind(')')? + 2..];
    return rest.split(' ').nth(41 - 3)?.parse().ok();
  }
  None
}

#[test]
fn maintenance_thread_does_the_housekeeping() {
  // No decay pass gets in the way of the counts below.
  GLOBAL.set_purge_delay(Duration::from_secs(3600));
  // Opt-in (off by default); falls back to `madvise` where io_uring is
  // unavailable.
  #[cfg(feature = "io-uring")]
  GLOBAL.set_io_uring(true);
  assert!(GLOBAL.start_maintenance_thread().unwrap());
  assert!(!GLOBAL.start_purge_thread().unwrap(), "started twice");
  assert!(wait_for(
    || GLOBAL.purge_backend() != PurgeBackend::NotStarted
  ));
  if cfg!(feature = "scheduler") {
    assert!(wait_for(|| GLOBAL.maintenance_is_batch()));
    assert_eq!(policy_of("allocatbelt-mnt"), Some(3), "SCHED_BATCH");
  } else {
    assert!(!GLOBAL.maintenance_is_batch());
    assert_eq!(policy_of("allocatbelt-mnt"), Some(0), "SCHED_OTHER");
  }
  // io_uring where the kernel allows it; `madvise` otherwise (qemu-user,
  // seccomp, `kernel.io_uring_disabled`), with the reason.
  let backend = GLOBAL.purge_backend();
  #[cfg(feature = "io-uring")]
  {
    eprintln!("purge backend: {backend:?} ({:?})", GLOBAL.io_uring_error());
    assert_eq!(
      backend == PurgeBackend::Madvise,
      GLOBAL.io_uring_error().is_some()
    );
  }
  #[cfg(not(feature = "io-uring"))]
  assert_eq!(backend, PurgeBackend::Madvise);

  // 40 MiB of page runs: freeing them passes the 32 MiB budget but not
  // the 64 MiB hard limit, so the frees only record the work.
  let bufs: Vec<Vec<u8>> = (0..40).map(|i| vec![i as u8 | 1; 1 << 20]).collect();
  let before = GLOBAL.maintenance_stats();
  drop(bufs);
  // A pass lowers the dirty count batch by batch and is counted once it
  // ends, so the count can drop below the budget before the pass shows.
  assert!(wait_for(|| {
    GLOBAL.dirty_bytes() < 32 << 20
      && GLOBAL.maintenance_stats().budget_passes > before.budget_passes
  }));
  let after = GLOBAL.maintenance_stats();
  assert_eq!(after.inline_budget_passes, before.inline_budget_passes);
  assert!(after.wakeups > before.wakeups);
  assert!(after.purged_runs > before.purged_runs);
  if matches!(backend, PurgeBackend::IoUring { .. }) {
    // The page runs of many segments went to the kernel together.
    assert!(
      after.purged_runs - before.purged_runs > after.purge_batches - before.purge_batches,
      "{before:?} {after:?}"
    );
  }

  // A purge request returns at once; the thread purges the rest.
  let bufs: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8 | 1; 1 << 20]).collect();
  drop(bufs);
  assert!(GLOBAL.dirty_bytes() >= 7 << 20);
  GLOBAL.request_purge();
  assert!(wait_for(|| {
    GLOBAL.dirty_bytes() == 0 && GLOBAL.maintenance_stats().force_passes > after.force_passes
  }));
}
