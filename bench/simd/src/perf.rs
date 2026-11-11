//! Hardware counters through `perf_event_open(2)`, for user-space code of
//! the calling thread only.
//!
//! The ABI (`struct perf_event_attr` up to `PERF_ATTR_SIZE_VER0`, the
//! hardware event ids, `PERF_FORMAT_GROUP` and the ioctl numbers) is from
//! Linux `include/uapi/linux/perf_event.h`, checked against v7.0; the `libc`
//! crate has no binding for it. Counters are optional: in containers and
//! under `perf_event_paranoid >= 3` the syscall fails, and the report says
//! so instead of printing zeroes.

#![allow(
  unsafe_code,
  reason = "perf_event_open syscall; see docs/unsafe-boundary.md"
)]

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _};

/// The events of one group, in this order.
pub const EVENTS: [(&str, u64); 5] = [
  ("cycles", 0),        // PERF_COUNT_HW_CPU_CYCLES
  ("instructions", 1),  // PERF_COUNT_HW_INSTRUCTIONS
  ("branches", 4),      // PERF_COUNT_HW_BRANCH_INSTRUCTIONS
  ("branch-misses", 5), // PERF_COUNT_HW_BRANCH_MISSES
  ("cache-misses", 3),  // PERF_COUNT_HW_CACHE_MISSES
];

const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_ATTR_SIZE_VER0: u32 = 64;
const PERF_FORMAT_GROUP: u64 = 1 << 3;
const FLAG_DISABLED: u64 = 1 << 0;
const FLAG_EXCLUDE_KERNEL: u64 = 1 << 5;
const FLAG_EXCLUDE_HV: u64 = 1 << 6;
/// `_IO('$', n)`.
const IOC_ENABLE: u64 = 0x2400;
const IOC_DISABLE: u64 = 0x2401;
const IOC_RESET: u64 = 0x2403;
const IOC_FLAG_GROUP: u64 = 1;

/// The first published layout of `struct perf_event_attr`
/// (`PERF_ATTR_SIZE_VER0`); the kernel accepts it and zero-extends it.
#[repr(C)]
#[derive(Default)]
struct Attr {
  kind: u32,
  size: u32,
  config: u64,
  sample_period: u64,
  sample_type: u64,
  read_format: u64,
  flags: u64,
  wakeup_events: u32,
  bp_type: u32,
  config1: u64,
}

const _: () = assert!(size_of::<Attr>() == PERF_ATTR_SIZE_VER0 as usize);

/// An open counter group; the first file is the group leader.
pub struct Counters {
  files: Vec<File>,
}

impl Counters {
  /// Opens the group for the calling thread, or explains why not.
  ///
  /// # Errors
  ///
  /// The `errno` of the first event the kernel refused.
  pub fn open() -> std::io::Result<Self> {
    let mut files: Vec<File> = Vec::with_capacity(EVENTS.len());
    for &(_, config) in &EVENTS {
      let attr = Attr {
        kind: PERF_TYPE_HARDWARE,
        size: PERF_ATTR_SIZE_VER0,
        config,
        read_format: PERF_FORMAT_GROUP,
        flags: FLAG_DISABLED | FLAG_EXCLUDE_KERNEL | FLAG_EXCLUDE_HV,
        ..Attr::default()
      };
      let leader = files.first().map_or(-1, |f| f.as_raw_fd());
      // SAFETY: `perf_event_open(attr, pid = 0 (this thread), cpu = -1
      // (any), group_fd, flags = 0)` only reads `attr`, a live
      // `PERF_ATTR_SIZE_VER0`-byte struct, and returns a new descriptor.
      let fd = unsafe {
        libc::syscall(
          libc::SYS_perf_event_open,
          &raw const attr,
          0 as libc::pid_t,
          -1 as libc::c_int,
          leader,
          0 as libc::c_ulong,
        )
      };
      if fd < 0 {
        return Err(std::io::Error::last_os_error());
      }
      let fd = libc::c_int::try_from(fd).map_err(|_| std::io::Error::other("bad fd"))?;
      // SAFETY: `fd` was just returned by the kernel and is owned by no one
      // else, so the `File` may close it.
      files.push(unsafe { File::from_raw_fd(fd) });
    }
    Ok(Self { files })
  }

  fn group_ioctl(&self, request: u64) {
    let leader = self.files[0].as_raw_fd();
    // SAFETY: a perf ioctl without an argument pointer on a perf
    // descriptor we own; errors only mean the counts are unusable.
    let _ = unsafe { libc::ioctl(leader, request as _, IOC_FLAG_GROUP) };
  }

  /// Zeroes and starts every counter of the group.
  pub fn start(&self) {
    self.group_ioctl(IOC_RESET);
    self.group_ioctl(IOC_ENABLE);
  }

  /// Stops the group and returns one count per entry of [`EVENTS`].
  ///
  /// # Errors
  ///
  /// When the group cannot be read back.
  pub fn stop(&mut self) -> std::io::Result<[u64; EVENTS.len()]> {
    self.group_ioctl(IOC_DISABLE);
    // PERF_FORMAT_GROUP: `nr`, then one value per event.
    let mut buf = [0u8; 8 * (1 + EVENTS.len())];
    self.files[0].read_exact(&mut buf)?;
    let mut values = [0u64; EVENTS.len()];
    for (v, raw) in values.iter_mut().zip(buf[8..].chunks_exact(8)) {
      *v = u64::from_ne_bytes(raw.try_into().map_err(std::io::Error::other)?);
    }
    Ok(values)
  }
}
