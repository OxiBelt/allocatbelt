//! Hardening seen from a real process: the guard page at the end of every
//! owned segment faults.

#![allow(unsafe_code, reason = "the test overflows a buffer on purpose")]

use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use allocatbelt::Allocatbelt;

#[global_allocator]
static GLOBAL: Allocatbelt = Allocatbelt;

/// Pages in the longest run a segment holds: all but its guard page.
const RUN: usize = 63 * 64 * 1024;

#[test]
fn overflow_past_a_segment_faults() {
  if std::env::var_os("ALLOCATBELT_GUARD_CHILD").is_some() {
    // A run this long only fits in an empty segment, where it ends right
    // before the guard page; one byte past it must fault.
    let v = vec![1u8; RUN];
    let end = v.as_ptr().wrapping_add(RUN).cast_mut();
    // SAFETY: none; this is the out-of-bounds write under test, in a child
    // process that must die of `SIGSEGV` here.
    unsafe { end.write_volatile(2) };
    std::process::exit(0);
  }
  let status = Command::new(std::env::current_exe().unwrap())
    .args([
      "--exact",
      "overflow_past_a_segment_faults",
      "--test-threads=1",
    ])
    .env("ALLOCATBELT_GUARD_CHILD", "1")
    .output()
    .unwrap()
    .status;
  assert_eq!(
    status.signal(),
    Some(11),
    "child ended with {status:?}, not SIGSEGV"
  );
}
