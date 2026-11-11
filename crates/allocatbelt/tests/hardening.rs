//! Hardening seen from a real process: the guard page at the end of every
//! owned segment faults.

#![allow(
  unsafe_code,
  reason = "the test forks, overflows a buffer on purpose and waits"
)]

use allocatbelt::Allocatbelt;

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

/// Pages in the longest run a segment holds: all but its guard page.
const RUN: usize = 63 * 64 * 1024;

/// What the child does: overflow a run by one byte, which must fault.
fn child() -> ! {
  // SAFETY: `alarm` only arms a timer; its default action kills the child
  // if it hangs instead of faulting.
  unsafe { libc::alarm(10) };
  // A run this long only fits in an empty segment, where it ends right
  // before the guard page; one byte past it must fault.
  let v = vec![1u8; RUN];
  let end = v.as_ptr().wrapping_add(RUN).cast_mut();
  // SAFETY: none; this is the out-of-bounds write under test, in a child
  // process that must die of `SIGSEGV` here.
  unsafe { end.write_volatile(2) };
  // SAFETY: `_exit` ends the child without running the parent's atexit
  // handlers or flushing its stdio buffers twice.
  unsafe { libc::_exit(0) }
}

// `fork`, not a re-exec of the test binary: under qemu-user (the riscv64 CI
// job) the host cannot exec a guest binary without binfmt_misc, and the
// child of the emulated `posix_spawn` then exits with 127.
#[test]
fn overflow_past_a_segment_faults() {
  // SAFETY: the child only calls async-signal-safe functions and the
  // allocator (which supports use after `fork`) before it faults or exits.
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
    libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSEGV,
    "child ended with status {status:#x}, not SIGSEGV (a SIGALRM kill means it hung)"
  );
}
