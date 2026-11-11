//! A small io_uring that only purges: batched `MADV_DONTNEED` through
//! `IORING_OP_MADVISE` (plan §10, Phase 8).
//!
//! The ring exists so that the maintenance thread can hand the kernel a
//! batch of purges in one `io_uring_enter` instead of one `madvise` per
//! page run. It is deliberately narrow:
//!
//! * **Restricted.** It is created disabled (`IORING_SETUP_R_DISABLED`),
//!   then allowed exactly one operation, `IORING_OP_MADVISE`, with no SQE
//!   flags and no further `io_uring_register` calls, and only then enabled.
//!   It registers no files and no buffers; allocator memory is never pinned.
//! * **One issuer.** `IORING_SETUP_SINGLE_ISSUER` and
//!   `IORING_SETUP_DEFER_TASKRUN`: the thread that creates it is the only
//!   one that submits, and completions are posted only while it waits for
//!   them. [`PurgeRing`] is not `Send`.
//! * **No SQ array, rewinding on Linux 7.0.** `IORING_SETUP_NO_SQARRAY`, and
//!   `IORING_SETUP_SQ_REWIND` where the kernel has it: every batch is
//!   written to the start of the SQE array, so the same few cache lines are
//!   reused. Without `SQ_REWIND` the ring uses the SQ tail as usual.
//! * **Not SQPOLL.** Purges come in bursts; a polling kernel thread would
//!   spin between them (plan §10.3).
//!
//! [`PurgeRing::purge`] submits a batch and waits for every completion
//! before it returns, so no purge is in flight once it has. A completion
//! with a result of 0 means `madvise` succeeded, so the range reads as zero;
//! anything else leaves the range dirty. Any submission the kernel does not
//! fully accept retires the ring: the unsubmitted ranges and every later
//! batch are purged with plain `madvise`, and nothing is submitted again.
//! The ring never allocates.

use core::ffi::c_void;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU32, Ordering};

use rustix::fd::OwnedFd;
use rustix::io::Errno;
use rustix::io_uring::{
  IoringEnterFlags, IoringFeatureFlags, IoringRegisterOp, IoringSetupFlags, io_uring_enter,
  io_uring_params, io_uring_register, io_uring_setup,
};
use rustix::mm::{self, MapFlags, ProtFlags};

use crate::sys::Region;

// UAPI values from `include/uapi/linux/io_uring.h` that rustix 1.1 does
// not name, or names in types this module does not use.
/// `IORING_SETUP_SQ_REWIND` (Linux 7.0).
const SETUP_SQ_REWIND: u32 = 1 << 20;
const IORING_OFF_SQ_RING: u64 = 0;
const IORING_OFF_SQES: u64 = 0x1000_0000;
const IORING_OP_MADVISE: u8 = 25;
const IORING_RESTRICTION_REGISTER_OP: u16 = 0;
const IORING_RESTRICTION_SQE_OP: u16 = 1;
const IORING_REGISTER_ENABLE_RINGS: u8 = 12;
const IO_URING_OP_SUPPORTED: u16 = 1 << 0;
const MADV_DONTNEED: u32 = 4;

/// `struct io_uring_sqe`, with only the fields a madvise uses named.
#[repr(C)]
#[derive(Default)]
struct Sqe {
  opcode: u8,
  flags: u8,
  ioprio: u16,
  fd: i32,
  off: u64,
  addr: u64,
  len: u32,
  /// `fadvise_advice`: the `madvise` advice.
  advice: u32,
  user_data: u64,
  rest: [u64; 3],
}

/// `struct io_uring_cqe` (16 bytes; the ring does not use `CQE32`).
#[repr(C)]
#[derive(Clone, Copy)]
struct Cqe {
  user_data: u64,
  res: i32,
  flags: u32,
}

/// `struct io_uring_restriction`.
#[repr(C)]
struct Restriction {
  opcode: u16,
  /// `sqe_op` for `IORING_RESTRICTION_SQE_OP`.
  arg: u8,
  resv: u8,
  resv2: [u32; 3],
}

/// `struct io_uring_probe` with room for 256 `struct io_uring_probe_op`s.
#[repr(C)]
struct Probe {
  last_op: u8,
  ops_len: u8,
  resv: u16,
  resv2: [u32; 3],
  /// `struct io_uring_probe_op`: `op: u8, resv: u8, flags: u16, resv2: u32`.
  ops: [[u16; 4]; 256],
}

const _: () = {
  assert!(size_of::<Sqe>() == 64);
  assert!(size_of::<Cqe>() == 16);
  assert!(size_of::<Restriction>() == 16);
  assert!(size_of::<Probe>() == 16 + 8 * 256);
};

/// Why a ring could not be set up, for diagnostics.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingError {
  /// The step that failed.
  pub step: &'static str,
  /// The kernel's error code (0 when the kernel returned success but the
  /// result was unusable).
  pub errno: i32,
}

impl RingError {
  fn new(step: &'static str, e: Errno) -> Self {
    Self {
      step,
      errno: e.raw_os_error(),
    }
  }
}

/// A completion wait failed for a reason other than a signal: the
/// submitted purges may still run, so their ranges must never be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompletionLost(pub i32);

/// A restricted io_uring for batched `MADV_DONTNEED` (see the module docs).
pub struct PurgeRing {
  fd: OwnedFd,
  /// The SQ and CQ rings (one mapping, `IORING_FEAT_SINGLE_MMAP`).
  rings: NonNull<c_void>,
  rings_len: usize,
  sqes: NonNull<Sqe>,
  sqes_len: usize,
  entries: u32,
  sq_tail: u32,
  cq_head: u32,
  cq_tail: u32,
  cq_mask: u32,
  cqes: u32,
  rewind: bool,
  /// A submission went wrong; everything is purged with `madvise` now.
  retired: bool,
}

impl PurgeRing {
  /// Sets up a ring of `entries` submission slots (a power of two, at most
  /// 4096) whose kernel workers run at most `max_workers` purges at once,
  /// and makes the calling thread its only submitter. With `sq_rewind`,
  /// tries `IORING_SETUP_SQ_REWIND` first and falls back to a plain
  /// `NO_SQARRAY` ring on kernels before 7.0.
  ///
  /// # Errors
  ///
  /// The step that failed: io_uring disabled (`kernel.io_uring_disabled`,
  /// seccomp, ENOSYS under emulators), no `IORING_OP_MADVISE`, or a
  /// restriction the kernel refused. The caller purges synchronously then.
  pub fn new(entries: u32, max_workers: u32, sq_rewind: bool) -> Result<Self, RingError> {
    let base = IoringSetupFlags::R_DISABLED
      | IoringSetupFlags::SINGLE_ISSUER
      | IoringSetupFlags::DEFER_TASKRUN
      | IoringSetupFlags::NO_SQARRAY;
    let rewind = IoringSetupFlags::from_bits_retain(SETUP_SQ_REWIND);
    let first = if sq_rewind { base | rewind } else { base };
    let (fd, p) = match setup(entries, first) {
      Ok(r) => r,
      Err(Errno::INVAL) if sq_rewind => {
        setup(entries, base).map_err(|e| RingError::new("setup", e))?
      }
      Err(e) => return Err(RingError::new("setup", e)),
    };
    if !p.features.contains(IoringFeatureFlags::SINGLE_MMAP) {
      return Err(RingError {
        step: "features",
        errno: 0,
      });
    }
    let rings_len = p.cq_off.cqes as usize + p.cq_entries as usize * size_of::<Cqe>();
    let rings = map(&fd, rings_len, IORING_OFF_SQ_RING).map_err(|e| RingError::new("mmap", e))?;
    let sqes_len = p.sq_entries as usize * size_of::<Sqe>();
    let sqes = match map(&fd, sqes_len, IORING_OFF_SQES) {
      Ok(s) => s.cast(),
      Err(e) => {
        unmap(rings, rings_len);
        return Err(RingError::new("mmap", e));
      }
    };
    // From here on, dropping `ring` unmaps both.
    let mut ring = Self {
      fd,
      rings,
      rings_len,
      sqes,
      sqes_len,
      entries: p.sq_entries,
      sq_tail: p.sq_off.tail,
      cq_head: p.cq_off.head,
      cq_tail: p.cq_off.tail,
      cq_mask: 0,
      cqes: p.cq_off.cqes,
      rewind: p.flags.contains(rewind),
      retired: false,
    };
    ring.cq_mask = ring.word(p.cq_off.ring_mask).load(Ordering::Relaxed);
    ring.restrict(max_workers)?;
    Ok(ring)
  }

  /// Whether the kernel took `IORING_SETUP_SQ_REWIND` (Linux 7.0+).
  #[must_use]
  pub fn sq_rewind(&self) -> bool {
    self.rewind
  }

  /// Whether a failed submission retired the ring (later purges use
  /// `madvise`).
  #[must_use]
  pub fn retired(&self) -> bool {
    self.retired
  }

  /// Checks for `IORING_OP_MADVISE`, caps the kernel workers, allows only
  /// that operation, and enables the ring for the calling thread.
  fn restrict(&mut self, max_workers: u32) -> Result<(), RingError> {
    let mut probe = Probe {
      last_op: 0,
      ops_len: 0,
      resv: 0,
      resv2: [0; 3],
      ops: [[0; 4]; 256],
    };
    self
      .register(
        IoringRegisterOp::RegisterProbe,
        (&raw mut probe).cast(),
        256,
      )
      .map_err(|e| RingError::new("probe", e))?;
    let op = usize::from(IORING_OP_MADVISE);
    if op >= usize::from(probe.ops_len) || probe.ops[op][1] & IO_URING_OP_SUPPORTED == 0 {
      return Err(RingError {
        step: "probe",
        errno: 0,
      });
    }
    // Bounded and unbounded workers; madvise work is bounded.
    let mut workers = [max_workers.max(1), 1];
    self
      .register(
        IoringRegisterOp::RegisterIowqMaxWorkers,
        (&raw mut workers).cast(),
        2,
      )
      .map_err(|e| RingError::new("max workers", e))?;
    // Newer kernels restrict `io_uring_register` only once a register
    // opcode is listed, so one is: `ENABLE_RINGS`, which fails on an
    // enabled ring anyway. Older kernels restrict both from the start.
    let allow = [
      Restriction {
        opcode: IORING_RESTRICTION_SQE_OP,
        arg: IORING_OP_MADVISE,
        resv: 0,
        resv2: [0; 3],
      },
      Restriction {
        opcode: IORING_RESTRICTION_REGISTER_OP,
        arg: IORING_REGISTER_ENABLE_RINGS,
        resv: 0,
        resv2: [0; 3],
      },
    ];
    self
      .register(
        IoringRegisterOp::RegisterRestrictions,
        (&raw const allow).cast_mut().cast(),
        2,
      )
      .map_err(|e| RingError::new("restrict", e))?;
    self
      .register(IoringRegisterOp::RegisterEnableRings, ptr::null_mut(), 0)
      .map_err(|e| RingError::new("enable", e))?;
    Ok(())
  }

  /// Purges `ranges` (byte offsets and lengths into `region`) and sets
  /// `purged[i]` to whether range `i` now reads as zero, like
  /// [`Region::purge`] for each. Submits them in batches of at most
  /// [`PurgeRing::entries`] and returns only when every submitted purge has
  /// completed. A range outside `region` or not granule-aligned is left
  /// alone (`false`).
  ///
  /// # Safety
  ///
  /// As for [`Region::purge`], for every range: nothing may reference or
  /// access it until this returns.
  ///
  /// # Errors
  ///
  /// [`CompletionLost`] if waiting for completions failed with anything but
  /// `EINTR`: purges may then still be running, and the caller must never
  /// hand the ranges out again (the allocator aborts).
  ///
  /// # Panics
  ///
  /// If `purged` is shorter than `ranges`.
  #[expect(unsafe_code, reason = "contract: caller owns the ranges")]
  pub unsafe fn purge(
    &mut self,
    region: &Region,
    ranges: &[(usize, usize)],
    purged: &mut [bool],
  ) -> Result<(), CompletionLost> {
    let purged = &mut purged[..ranges.len()];
    for (chunk, done) in ranges
      .chunks(self.entries as usize)
      .zip(purged.chunks_mut(self.entries as usize))
    {
      if self.retired {
        for (&(offset, len), done) in chunk.iter().zip(done.iter_mut()) {
          // SAFETY: forwarded caller contract.
          #[expect(unsafe_code, reason = "purge contract is identical")]
          let z = unsafe { region.purge(offset, len) };
          *done = z;
        }
      } else {
        self.purge_chunk(region, chunk, done)?;
      }
    }
    Ok(())
  }

  /// One submission of at most `entries` ranges. Caller contract as
  /// [`PurgeRing::purge`].
  fn purge_chunk(
    &mut self,
    region: &Region,
    ranges: &[(usize, usize)],
    purged: &mut [bool],
  ) -> Result<(), CompletionLost> {
    purged.fill(false);
    let tail = if self.rewind {
      0
    } else {
      self.word(self.sq_tail).load(Ordering::Relaxed)
    };
    let mut n = 0u32;
    for (i, &(offset, len)) in ranges.iter().enumerate() {
      let (Some(addr), Ok(len)) = (region.range(offset, len), u32::try_from(len)) else {
        continue;
      };
      let slot = if self.rewind {
        n
      } else {
        tail.wrapping_add(n) & (self.entries - 1)
      };
      let sqe = Sqe {
        opcode: IORING_OP_MADVISE,
        addr: addr as u64,
        len,
        advice: MADV_DONTNEED,
        user_data: i as u64,
        ..Sqe::default()
      };
      // SAFETY: `slot < entries`, the length of the SQE mapping, which only
      // this thread writes; the kernel reads a slot only after the tail
      // store below (or, rewinding, during the `io_uring_enter` below).
      #[expect(unsafe_code, reason = "write to the shared SQE array")]
      unsafe {
        self.sqes.as_ptr().wrapping_add(slot as usize).write(sqe);
      }
      n += 1;
    }
    if n == 0 {
      return Ok(());
    }
    if !self.rewind {
      self
        .word(self.sq_tail)
        .store(tail.wrapping_add(n), Ordering::Release);
    }
    let submitted = match self.enter(n, n) {
      Ok(k) => k.min(n),
      Err(_) => 0,
    };
    if submitted < n {
      // The kernel stopped early (e.g. it could not allocate a request).
      // Without SQ_REWIND the rest would still sit in the SQ, so nothing
      // is ever submitted again; the ranges not yet completed and not
      // submitted are purged synchronously below.
      self.retired = true;
    }
    // Ranges whose completion arrived (at most 4096 slots).
    let mut seen = [0u64; 64];
    let mut completed = 0;
    while completed < submitted {
      completed += self.reap(purged, &mut seen);
      if completed < submitted {
        match self.enter(0, submitted - completed) {
          Ok(_) | Err(Errno::INTR | Errno::AGAIN | Errno::BUSY | Errno::TIME) => {}
          Err(e) => return Err(CompletionLost(e.raw_os_error())),
        }
      }
    }
    if submitted < n {
      for (i, &(offset, len)) in ranges.iter().enumerate() {
        if seen[i / 64] >> (i % 64) & 1 == 0 && region.range(offset, len).is_some() {
          // SAFETY: forwarded caller contract; this range was never
          // submitted (every submitted one has completed).
          #[expect(unsafe_code, reason = "purge contract is identical")]
          let z = unsafe { region.purge(offset, len) };
          purged[i] = z;
        }
      }
    }
    Ok(())
  }

  /// Takes the available completions, marking each range in `seen` and
  /// its result in `purged`. Returns how many there were.
  fn reap(&self, purged: &mut [bool], seen: &mut [u64; 64]) -> u32 {
    let head = self.word(self.cq_head).load(Ordering::Relaxed);
    let tail = self.word(self.cq_tail).load(Ordering::Acquire);
    let mut i = head;
    while i != tail {
      let at = self.cqes as usize + (i & self.cq_mask) as usize * size_of::<Cqe>();
      // SAFETY: `at` is a CQE slot inside the ring mapping (the mask
      // bounds it by `cq_entries`); the kernel wrote it before publishing
      // `tail`, which the Acquire load above observed, and does not reuse
      // it until `head` moves past it below.
      #[expect(unsafe_code, reason = "read from the shared CQE array")]
      let cqe = unsafe {
        self
          .rings
          .as_ptr()
          .wrapping_byte_add(at)
          .cast::<Cqe>()
          .read()
      };
      let r = cqe.user_data as usize;
      if let Some(p) = purged.get_mut(r) {
        *p = cqe.res == 0;
        seen[r / 64] |= 1 << (r % 64);
      }
      i = i.wrapping_add(1);
    }
    self.word(self.cq_head).store(tail, Ordering::Release);
    tail.wrapping_sub(head)
  }

  /// The ring's `u32` at byte offset `off` (a head, tail or mask).
  fn word(&self, off: u32) -> &AtomicU32 {
    debug_assert!(off as usize + 4 <= self.rings_len && off.is_multiple_of(4));
    // SAFETY: the kernel's offsets point at aligned `u32`s inside the ring
    // mapping, which lives as long as `self`; both sides access them
    // atomically (the kernel with `READ_ONCE`/`smp_store_release`).
    #[expect(unsafe_code, reason = "shared ring word")]
    unsafe {
      &*self
        .rings
        .as_ptr()
        .wrapping_byte_add(off as usize)
        .cast::<AtomicU32>()
    }
  }

  fn register(&self, op: IoringRegisterOp, arg: *mut c_void, nr: u32) -> Result<(), Errno> {
    // SAFETY: `op` is one of the four registrations above, and `arg`
    // points at a live value of the type and count (`nr`) that `op`
    // expects (or is null for `RegisterEnableRings`, which takes none);
    // the kernel reads or fills only that.
    #[expect(unsafe_code, reason = "io_uring_register syscall")]
    let r = unsafe { io_uring_register(&self.fd, op, arg.cast_const(), nr) };
    r.map(drop)
  }

  /// Submits `to_submit` SQEs and waits for `min_complete` completions
  /// (`IORING_ENTER_GETEVENTS`, which also runs the deferred task work).
  fn enter(&self, to_submit: u32, min_complete: u32) -> Result<u32, Errno> {
    // SAFETY: a plain `io_uring_enter` without an argument pointer. The
    // SQEs it submits were written by `purge_chunk` and describe `madvise`
    // of ranges the caller of `purge` owns.
    #[expect(unsafe_code, reason = "io_uring_enter syscall")]
    let r = unsafe {
      io_uring_enter(
        &self.fd,
        to_submit,
        min_complete,
        IoringEnterFlags::GETEVENTS,
      )
    };
    r
  }
}

impl Drop for PurgeRing {
  fn drop(&mut self) {
    // Nothing is in flight: `purge` waits for every completion. Closing the
    // descriptor (after this) tears the ring down.
    unmap(self.sqes.cast(), self.sqes_len);
    unmap(self.rings, self.rings_len);
  }
}

/// `io_uring_setup(entries, params)` with `flags`.
fn setup(entries: u32, flags: IoringSetupFlags) -> Result<(OwnedFd, io_uring_params), Errno> {
  let mut p = io_uring_params::default();
  p.flags = flags;
  // SAFETY: the flags ask for no SQPOLL thread and no attached work queue
  // (`wq_fd` unused), so the kernel only reads and fills `p` and returns a
  // new descriptor.
  #[expect(unsafe_code, reason = "io_uring_setup syscall")]
  let fd = unsafe { io_uring_setup(entries, &mut p) }?;
  Ok((fd, p))
}

/// Maps `len` bytes of the ring at `offset` (`IORING_OFF_*`).
fn map(fd: &OwnedFd, len: usize, offset: u64) -> Result<NonNull<c_void>, Errno> {
  // SAFETY: a fresh shared mapping of the ring's own memory at an address
  // the kernel picks; it aliases nothing in this process.
  #[expect(unsafe_code, reason = "mmap of the ring")]
  let p = unsafe {
    mm::mmap(
      ptr::null_mut(),
      len,
      ProtFlags::READ | ProtFlags::WRITE,
      MapFlags::SHARED | MapFlags::POPULATE,
      fd,
      offset,
    )
  }?;
  NonNull::new(p).ok_or(Errno::NOMEM)
}

fn unmap(p: NonNull<c_void>, len: usize) {
  // SAFETY: `p..p + len` is a ring mapping created by `map` and referenced
  // only by the ring being dropped.
  #[expect(unsafe_code, reason = "munmap of the ring")]
  let _ = unsafe { mm::munmap(p.as_ptr(), len) };
}

#[cfg(test)]
mod tests {
  #![allow(clippy::unwrap_used, reason = "tests")]

  use super::*;
  use crate::sys::GRANULE;

  /// io_uring can be missing (qemu-user, seccomp, the sysctl); these tests
  /// then check only that setup fails cleanly.
  fn ring() -> Option<PurgeRing> {
    match PurgeRing::new(8, 2, true) {
      Ok(r) => Some(r),
      Err(e) => {
        std::eprintln!("no io_uring purge ring, test skipped: {e:?}");
        None
      }
    }
  }

  fn touched(region: &Region, pages: usize) {
    assert!(region.commit(0, pages * GRANULE));
    for i in 0..pages * GRANULE / 4096 {
      // SAFETY: committed read/write above; only this test uses it.
      #[expect(unsafe_code, reason = "test writes")]
      unsafe {
        region
          .base
          .as_ptr()
          .wrapping_add(i * 4096)
          .write_volatile(1);
      }
    }
  }

  fn byte(region: &Region, offset: usize) -> u8 {
    // SAFETY: committed read/write; only this test uses it.
    #[expect(unsafe_code, reason = "test reads")]
    unsafe {
      region.base.as_ptr().wrapping_add(offset).read_volatile()
    }
  }

  #[test]
  fn purges_in_batches_and_zeroes() {
    let Some(mut ring) = ring() else { return };
    let region = Region::reserve(64 * GRANULE, GRANULE).unwrap();
    touched(&region, 20);
    // 20 ranges through 8 slots: three submissions.
    let ranges: [(usize, usize); 20] = core::array::from_fn(|i| (i * GRANULE, GRANULE));
    let mut purged = [false; 20];
    // SAFETY: nothing references the region.
    #[expect(unsafe_code, reason = "test purge")]
    unsafe { ring.purge(&region, &ranges, &mut purged) }.unwrap();
    assert!(purged.iter().all(|&p| p), "{purged:?}");
    for i in 0..20 {
      assert_eq!(byte(&region, i * GRANULE), 0);
    }
    assert!(!ring.retired());
  }

  #[test]
  fn failed_purges_stay_dirty() {
    let Some(mut ring) = ring() else { return };
    let region = Region::reserve(64 * GRANULE, GRANULE).unwrap();
    touched(&region, 2);
    // A range the kernel refuses: `MADV_DONTNEED` of locked memory fails
    // with EINVAL (if this process may lock memory at all). A range outside
    // the region is skipped.
    // SAFETY: locking only pins pages of this test's own mapping.
    #[expect(unsafe_code, reason = "test mlock")]
    let locked = unsafe { mm::mlock(region.base.as_ptr().cast(), GRANULE) }.is_ok();
    let ranges = [
      (0, GRANULE),
      (GRANULE, GRANULE),
      (63 * GRANULE, 2 * GRANULE),
    ];
    let mut purged = [true; 3];
    // SAFETY: nothing references the region.
    #[expect(unsafe_code, reason = "test purge")]
    unsafe { ring.purge(&region, &ranges, &mut purged) }.unwrap();
    assert!(!purged[2], "out of range");
    assert!(purged[1]);
    assert_eq!(byte(&region, GRANULE), 0);
    if locked {
      assert!(!purged[0], "purging locked memory must fail");
      assert_eq!(byte(&region, 0), 1, "a failed purge keeps the contents");
    }
  }

  #[test]
  fn only_madvise_is_allowed() {
    let Some(mut ring) = ring() else { return };
    // Registrations after enabling are refused by the restrictions.
    let mut workers = [1u32, 1];
    assert_eq!(
      ring.register(
        IoringRegisterOp::RegisterIowqMaxWorkers,
        (&raw mut workers).cast(),
        2
      ),
      Err(Errno::ACCESS)
    );
    // So is any operation but madvise: a NOP completes with -EACCES.
    let slot = if ring.rewind {
      0
    } else {
      ring.word(ring.sq_tail).load(Ordering::Relaxed) & (ring.entries - 1)
    };
    // SAFETY: as in `purge_chunk`: a slot of the SQE mapping.
    #[expect(unsafe_code, reason = "test SQE")]
    unsafe {
      ring.sqes.as_ptr().wrapping_add(slot as usize).write(Sqe {
        user_data: 0,
        ..Sqe::default()
      });
    }
    if !ring.rewind {
      let t = ring.word(ring.sq_tail).load(Ordering::Relaxed);
      ring
        .word(ring.sq_tail)
        .store(t.wrapping_add(1), Ordering::Release);
    }
    assert_eq!(ring.enter(1, 1), Ok(1));
    let mut res = [true];
    let mut seen = [0u64; 64];
    // `reap` reports result 0 as purged; read the CQE's result instead.
    let head = ring.word(ring.cq_head).load(Ordering::Relaxed);
    let at = ring.cqes as usize + (head & ring.cq_mask) as usize * size_of::<Cqe>();
    // SAFETY: as in `reap`: a published CQE slot of the ring mapping.
    #[expect(unsafe_code, reason = "test CQE")]
    let cqe = unsafe {
      ring
        .rings
        .as_ptr()
        .wrapping_byte_add(at)
        .cast::<Cqe>()
        .read()
    };
    assert_eq!(cqe.res, -Errno::ACCESS.raw_os_error());
    assert_eq!(ring.reap(&mut res, &mut seen), 1);
    assert!(!res[0]);
    ring.retired = false;
  }

  /// Batched `MADV_DONTNEED` through the ring against one `madvise` per
  /// run: `cargo test --release -p allocatbelt --lib ring_benchmark --
  /// --ignored --nocapture`. Each round touches 64 runs of `pages` 64 KiB
  /// pages and purges them; prints the median round time.
  #[test]
  #[ignore = "benchmark"]
  fn ring_benchmark() {
    use std::time::Instant;
    use std::vec::Vec;

    const RUNS: usize = 64;
    const ROUNDS: usize = 41;
    let median = |mut v: Vec<f64>| {
      v.sort_by(f64::total_cmp);
      v[v.len() / 2]
    };
    let region = Region::reserve(RUNS * 16 * 2 * GRANULE, GRANULE).unwrap();
    assert!(region.commit(0, RUNS * 16 * 2 * GRANULE));
    let touch = |pages: usize| {
      for r in 0..RUNS {
        for i in 0..pages * GRANULE / 4096 {
          // SAFETY: committed read/write; only this test uses it.
          #[expect(unsafe_code, reason = "benchmark writes")]
          unsafe {
            region
              .base
              .as_ptr()
              .wrapping_add(r * 2 * pages * GRANULE + i * 4096)
              .write_volatile(1);
          }
        }
      }
    };
    std::println!("pages/run  backend                     us/round  us/run");
    for pages in [1usize, 4, 16] {
      // Every other run, so they stay separate ranges.
      let ranges: Vec<(usize, usize)> = (0..RUNS)
        .map(|r| (r * 2 * pages * GRANULE, pages * GRANULE))
        .collect();
      let mut purged = [false; RUNS];
      let report = |name: &str, times: Vec<f64>| {
        let m = median(times);
        std::println!("{pages:>9}  {name:<26}  {m:>8.1}  {:>6.2}", m / RUNS as f64);
      };
      let times = (0..ROUNDS)
        .map(|_| {
          touch(pages);
          let t = Instant::now();
          for &(o, l) in &ranges {
            // SAFETY: nothing references the region.
            #[expect(unsafe_code, reason = "benchmark purge")]
            let _ = unsafe { region.purge(o, l) };
          }
          t.elapsed().as_secs_f64() * 1e6
        })
        .collect();
      report("madvise per run", times);
      let setups = [
        (64, 1, false),
        (64, 1, true),
        (64, 2, true),
        (64, 4, true),
        (32, 1, true),
        (128, 1, true),
      ];
      for (entries, workers, rewind) in setups {
        let Ok(mut ring) = PurgeRing::new(entries, workers, rewind) else {
          std::println!("no io_uring");
          return;
        };
        let times = (0..ROUNDS)
          .map(|_| {
            touch(pages);
            let t = Instant::now();
            // SAFETY: nothing references the region.
            #[expect(unsafe_code, reason = "benchmark purge")]
            unsafe { ring.purge(&region, &ranges, &mut purged) }.unwrap();
            t.elapsed().as_secs_f64() * 1e6
          })
          .collect();
        assert!(purged.iter().all(|&p| p));
        let rw = if ring.sq_rewind() { "rewind" } else { "tail" };
        report(
          &std::format!("ring {entries}x, {workers} workers, {rw}"),
          times,
        );
      }
    }
  }
}
