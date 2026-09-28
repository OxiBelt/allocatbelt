//! `fork` while other threads allocate: the child must be able to use the
//! allocator, although the threads that held its locks do not exist there.

#![allow(unsafe_code, reason = "the test calls fork, alarm, _exit and waitpid")]

use std::sync::atomic::{AtomicBool, Ordering};

use allocatbelt::Allocatbelt;

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

/// What a child does: allocations of every kind (new segments take the
/// global segment lock), a purge (the purge lock), then exit.
fn child() -> ! {
  // SAFETY: `alarm` only arms a timer; its default action kills the child
  // if the allocator deadlocks.
  unsafe { libc::alarm(10) };
  let small: Vec<Box<[u8]>> = (0..2000).map(|i| vec![1; 16 + i % 500].into()).collect();
  let runs: Vec<Vec<u8>> = (0..8).map(|i| vec![2; (i + 1) * 70_000]).collect();
  let huge = vec![3u8; 20 << 20];
  let ok = small.iter().all(|b| b[0] == 1) && runs.iter().all(|r| r[0] == 2) && huge[1] == 3;
  drop((small, runs, huge));
  GLOBAL.purge();
  // SAFETY: `_exit` ends the child without running the parent's atexit
  // handlers or flushing its stdio buffers twice.
  unsafe { libc::_exit(if ok { 0 } else { 1 }) }
}

/// Sets the flag when dropped, so the busy threads stop even when an
/// assertion fails.
struct SetOnDrop<'a>(&'a AtomicBool);

impl Drop for SetOnDrop<'_> {
  fn drop(&mut self) {
    self.0.store(true, Ordering::Relaxed);
  }
}

#[test]
fn children_of_busy_parents_can_allocate() {
  let stop = AtomicBool::new(false);
  std::thread::scope(|s| {
    let _stop = SetOnDrop(&stop);
    for t in 0..4 {
      let stop = &stop;
      s.spawn(move || {
        while !stop.load(Ordering::Relaxed) {
          // Huge blocks go through the segment lock, purges through the
          // purge lock; small ones through the shard locks.
          let v: Vec<Vec<u8>> = (0..16).map(|i| vec![t; 16 << (i % 16)]).collect();
          drop(v);
          let big = vec![t; 5 << 20];
          drop(big);
          GLOBAL.purge();
        }
      });
    }
    for _ in 0..200 {
      // SAFETY: the child only calls async-signal-safe functions and the
      // allocator (the point of the test) before `_exit`.
      let pid = unsafe { libc::fork() };
      assert!(pid >= 0, "fork failed");
      if pid == 0 {
        child();
      }
      let mut status = 0;
      // SAFETY: waits for the child just created; `status` is a valid out
      // pointer.
      let r = unsafe { libc::waitpid(pid, &raw mut status, 0) };
      assert_eq!(r, pid);
      assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child failed (status {status:#x}; a SIGALRM kill means it deadlocked)"
      );
    }
  });
}
