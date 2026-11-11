//! `fork` after the maintenance thread started (directive §17): the child
//! has no maintenance thread, keeps the policy, and can start its own,
//! which tries its capabilities (and, with `Prefer`, its own io_uring)
//! again. A separate test binary, because it starts the maintenance thread.

#![allow(unsafe_code, reason = "the test calls fork, alarm, _exit and waitpid")]

use allocatbelt::{Allocatbelt, FeaturePolicy, Policy, PurgeBackend};

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

fn child(parent_backend: PurgeBackend) -> ! {
  // SAFETY: `alarm` only arms a timer; its default action kills the child
  // if it hangs.
  unsafe { libc::alarm(10) };
  let e = GLOBAL.effective_profile();
  let mut ok = !e.maintenance && !e.frozen && e.purge_backend == PurgeBackend::NotStarted;
  ok &= GLOBAL.policy().io_uring == FeaturePolicy::Prefer;
  ok &= GLOBAL.start_maintenance_thread().unwrap_or(false);
  let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
  while GLOBAL.purge_backend() == PurgeBackend::NotStarted && std::time::Instant::now() < deadline {
    std::thread::yield_now();
  }
  // The child's own thread chose as the parent's did.
  ok &= GLOBAL.purge_backend() == parent_backend;
  let v = vec![5u8; 40 << 20];
  ok &= v[v.len() - 1] == 5;
  drop(v);
  // Cache return in the child: nothing waits for the parent's threads.
  GLOBAL.request_cache_return();
  GLOBAL.flush_thread_cache();
  let small = Box::new([3u8; 48]);
  ok &= small[0] == 3;
  drop(small);
  GLOBAL.request_purge();
  // SAFETY: `_exit` ends the child without running the parent's atexit
  // handlers.
  unsafe { libc::_exit(if ok { 0 } else { 1 }) }
}

#[test]
fn fork_child_starts_its_own_maintenance_thread() {
  let mut p = Policy::DEFAULT;
  p.io_uring = FeaturePolicy::Prefer;
  GLOBAL.configure(p).unwrap();
  assert!(GLOBAL.start_maintenance_thread().unwrap());
  while GLOBAL.purge_backend() == PurgeBackend::NotStarted {
    std::thread::yield_now();
  }
  let backend = GLOBAL.purge_backend();
  eprintln!("{}", GLOBAL.report());
  // SAFETY: the child uses only the allocator and async-signal-safe calls
  // before `_exit`, and starts one thread of its own.
  let pid = unsafe { libc::fork() };
  assert!(pid >= 0, "fork failed");
  if pid == 0 {
    child(backend);
  }
  let mut status = 0;
  // SAFETY: waits for the child just created; `status` is a valid out
  // pointer.
  let r = unsafe { libc::waitpid(pid, &raw mut status, 0) };
  assert_eq!(r, pid);
  assert!(
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
    "child failed (status {status:#x})"
  );
  // The parent's thread is unaffected.
  assert!(GLOBAL.effective_profile().maintenance);
  assert_eq!(GLOBAL.purge_backend(), backend);
}
