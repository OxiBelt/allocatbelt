//! The calling thread's rseq `mm_cid`, read from the area glibc registered
//! for it (Phase 9 research, feature `experimental-rseq`).
//!
//! `mm_cid` is a concurrency id the kernel keeps dense per process: threads
//! running at the same moment have different ids, all below the number of
//! CPUs the process may use (and below its thread count). The kernel
//! stores it in each thread's `struct rseq` whenever the thread returns to
//! user space.
//!
//! Read-only: allocatbelt registers no rseq area of its own (glibc owns
//! the registration, and a thread can hold only one) and runs no rseq
//! critical section, so there is nothing to abort or restart. A value read
//! here can be stale the moment it is read (the thread migrates); callers
//! use it only as a preference.

use core::sync::atomic::{AtomicU32, Ordering};

/// Why `mm_cid` cannot be read.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RseqUnavailable {
  /// Not built against glibc, the only C library whose rseq area is read.
  /// (musl registers none; allocatbelt does not register one either.)
  NotGlibc,
  /// glibc registered no rseq area: the kernel lacks rseq, a seccomp filter
  /// or an emulator (qemu-user) refused it, or `GLIBC_TUNABLES` set
  /// `glibc.pthread.rseq=0`.
  NotRegistered,
  /// The kernel's rseq area has no `mm_cid` (before Linux 6.3).
  NoMmCid,
}

impl RseqUnavailable {
  /// The reason as a short step name, for reports.
  #[must_use]
  pub const fn step(self) -> &'static str {
    match self {
      Self::NotGlibc => "not glibc",
      Self::NotRegistered => "not registered",
      Self::NoMmCid => "no mm_cid",
    }
  }
}

/// Offset of `cpu_id` in `struct rseq` (`uapi/linux/rseq.h`).
const CPU_ID: isize = 4;
/// Offset of `mm_cid` in `struct rseq`.
const MM_CID: isize = 24;
/// `AT_RSEQ_FEATURE_SIZE`: how much of `struct rseq` the kernel fills in.
#[cfg(target_env = "gnu")]
const AT_RSEQ_FEATURE_SIZE: libc::c_ulong = 27;
/// End of `mm_cid` in `struct rseq`.
#[cfg(target_env = "gnu")]
const MM_CID_END: libc::c_ulong = 28;

#[cfg(target_env = "gnu")]
#[expect(unsafe_code, reason = "glibc's rseq ABI symbols")]
unsafe extern "C" {
  /// Offset of each thread's rseq area from its thread pointer.
  static __rseq_offset: isize;
  /// Size of the registered area; 0 if glibc registered none.
  static __rseq_size: u32;
}

/// Reads the calling thread's `mm_cid`.
#[derive(Clone, Copy, Debug)]
pub struct MmCid {
  /// `__rseq_offset`.
  offset: isize,
}

impl MmCid {
  /// Checks that glibc registered rseq areas and that the kernel fills in
  /// `mm_cid`. Does not allocate.
  ///
  /// # Errors
  ///
  /// Why `mm_cid` cannot be read.
  #[cfg(target_env = "gnu")]
  pub fn probe() -> Result<Self, RseqUnavailable> {
    // SAFETY: a constant glibc sets before any user code runs.
    #[expect(unsafe_code, reason = "reading glibc's __rseq_size")]
    let size = unsafe { __rseq_size };
    if size == 0 {
      return Err(RseqUnavailable::NotRegistered);
    }
    // SAFETY: `getauxval` reads the auxiliary vector; any key is valid.
    #[expect(unsafe_code, reason = "getauxval")]
    let feature_size = unsafe { libc::getauxval(AT_RSEQ_FEATURE_SIZE) };
    if feature_size < MM_CID_END {
      return Err(RseqUnavailable::NoMmCid);
    }
    Ok(Self {
      // SAFETY: as for `__rseq_size`.
      #[expect(unsafe_code, reason = "reading glibc's __rseq_offset")]
      offset: unsafe { __rseq_offset },
    })
  }

  /// As on glibc, but always unavailable.
  ///
  /// # Errors
  ///
  /// Always [`RseqUnavailable::NotGlibc`].
  #[cfg(not(target_env = "gnu"))]
  pub fn probe() -> Result<Self, RseqUnavailable> {
    Err(RseqUnavailable::NotGlibc)
  }

  /// The calling thread's `mm_cid`, or `None` if its rseq registration
  /// failed (glibc then leaves `cpu_id` negative). Two loads from the
  /// thread's own TCB; no syscall.
  #[inline]
  #[must_use]
  pub fn current(self) -> Option<u32> {
    let area = thread_pointer().wrapping_offset(self.offset);
    // Negative `cpu_id`: RSEQ_CPU_ID_UNINITIALIZED or _REGISTRATION_FAILED.
    if field(area, CPU_ID).load(Ordering::Relaxed) >= 1 << 31 {
      return None;
    }
    Some(field(area, MM_CID).load(Ordering::Relaxed))
  }
}

/// The `u32` at `offset` in the rseq area `area` of the calling thread.
#[inline]
fn field(area: *const u8, offset: isize) -> &'static AtomicU32 {
  // SAFETY: glibc places every thread's rseq area (32 bytes, 32-aligned,
  // in its TCB) at the thread pointer plus `__rseq_offset`, whether or not
  // its registration succeeded, and keeps it for the thread's lifetime;
  // `offset` names an aligned `u32` in it. Only the kernel writes it, and
  // only while this thread is in the kernel, so the loads never race. The
  // reference does not outlive the caller's load on this thread.
  #[expect(unsafe_code, reason = "a u32 of the thread's rseq area")]
  unsafe {
    &*area.wrapping_offset(offset).cast::<AtomicU32>()
  }
}

/// The thread pointer that glibc's `__rseq_offset` is relative to
/// (`__builtin_thread_pointer`).
#[inline(always)]
fn thread_pointer() -> *const u8 {
  let tp: *const u8;
  // SAFETY: reads the TCB's self pointer at `%fs:0`, which the x86_64 TLS
  // ABI requires to equal the thread pointer; no other effect.
  #[cfg(target_arch = "x86_64")]
  #[expect(unsafe_code, reason = "reading the thread pointer")]
  unsafe {
    core::arch::asm!("mov {}, qword ptr fs:[0]", out(reg) tp, options(nostack, readonly, preserves_flags));
  }
  // SAFETY: reads the thread pointer register; no other effect.
  #[cfg(target_arch = "aarch64")]
  #[expect(unsafe_code, reason = "reading the thread pointer")]
  unsafe {
    core::arch::asm!("mrs {}, tpidr_el0", out(reg) tp, options(nomem, nostack, preserves_flags));
  }
  // SAFETY: copies the thread pointer register; no other effect.
  #[cfg(target_arch = "riscv64")]
  #[expect(unsafe_code, reason = "reading the thread pointer")]
  unsafe {
    core::arch::asm!("mv {}, tp", out(reg) tp, options(nomem, nostack, preserves_flags));
  }
  tp
}

#[cfg(test)]
mod tests {

  use super::*;

  #[test]
  fn mm_cids_are_dense_and_distinct_while_running() {
    let cid = match MmCid::probe() {
      Ok(cid) => cid,
      Err(e) => return std::eprintln!("mm_cid unavailable: {e:?}"),
    };
    let Some(mine) = cid.current() else {
      return std::eprintln!("this thread's rseq registration failed");
    };
    // Dense: below the number of threads using the process's memory
    // (the test harness runs a few at once) and the CPUs.
    assert!(mine < 4096, "{mine}");
    // Threads that all run at once (they wait for each other) hold
    // different ids.
    let n = 4;
    let barrier = std::sync::Barrier::new(n);
    let ids: std::vec::Vec<u32> = std::thread::scope(|s| {
      let hs: std::vec::Vec<_> = (0..n)
        .map(|_| {
          s.spawn(|| {
            barrier.wait();
            let a = cid.current();
            barrier.wait();
            (a, cid.current())
          })
        })
        .collect();
      hs.into_iter()
        .filter_map(|h| match h.join().unwrap() {
          // Only when the thread kept its id across the second barrier
          // (it may have been preempted and moved).
          (Some(a), Some(b)) if a == b => Some(a),
          _ => None,
        })
        .collect()
    });
    std::eprintln!("mm_cid of main {mine}, of running threads {ids:?}");
    assert!(ids.iter().all(|&i| i < 4096));
  }
}
