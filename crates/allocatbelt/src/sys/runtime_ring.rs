//! An owned-buffer io_uring for the optional runtime: positioned reads and
//! writes of regular files into [`ManagedBuf`] storage (feature
//! `runtime-io-uring`).
//!
//! This ring is independent of the allocator's purge ring (`sys/ring.rs`,
//! feature `io-uring`): it shares no state, flag or descriptor with it and
//! never runs inside `GlobalAlloc`. Its only allocation is the fixed
//! in-flight table, reserved fallibly by [`RuntimeRing::new`].
//!
//! # Ownership
//!
//! [`RuntimeRing::publish`] either returns the whole [`RingOperation`] in
//! [`NotPublished`], in which case no SQE or kernel-visible pointer for it
//! was ever written, or takes ownership of its descriptor and buffer until
//! the kernel posts the operation's one completion. While the ring owns
//! them they live in a private slot of the in-flight table; the ring reads
//! only their metadata (the descriptor number and the length recorded at
//! publication) and never forms a slice of, resizes or formats the buffer
//! contents. The storage pointer is taken once, through
//! [`ManagedBuf::get_mut`] on a uniquely owned buffer, before the SQE that
//! carries it is published with the Release store of the SQ tail. Moving
//! the `ManagedBuf` (an `Arc` handle) never moves its storage, and its
//! scope charge stays held until the buffer is returned in a
//! [`RingCompletion`] and finally dropped by the caller.
//!
//! The ring holds the descriptor's number, not the open file description:
//! a `dup` or another process may share the description. Aliases must not
//! change its status flags (`O_APPEND`, `O_DIRECT`) while an operation is
//! in flight; `publish` checks them once, before publication.
//!
//! # Fail-stop
//!
//! There is no cancellation and no fallback. Once an SQE may have been
//! published, the only way its owners leave the ring is its own completion.
//! The process aborts (`std::process::abort`) instead of guessing whenever
//! that cannot be established: an `io_uring_enter` failure other than a
//! retryable one while SQEs are exposed, a completion with an unknown,
//! stale or duplicate key, unexpected flags or a malformed result, more
//! completions than operations, a moved or corrupt queue counter, a CQ
//! overflow or dropped entry, an unwind through a section where ownership
//! is being transferred, use from a forked child, and dropping the ring
//! while any operation is in flight. Closing the ring descriptor is not a
//! barrier: Linux queues ring teardown asynchronously
//! (`io_uring_release`), so neither closing it nor closing the file proves
//! that the kernel stopped using a buffer.
//!
//! # Ring shape
//!
//! `IORING_SETUP_SINGLE_ISSUER | DEFER_TASKRUN | R_DISABLED | NO_SQARRAY`:
//! no SQPOLL thread, no attached work queue, no SQ rewinding. Before the
//! ring is enabled it probes `IORING_OP_READ` and `IORING_OP_WRITE`, caps
//! both io-wq worker classes at the ring depth, and restricts the ring to
//! those two operations without SQE flags and to no `io_uring_register`
//! call but `ENABLE_RINGS`. No files or buffers are registered. Completions
//! are posted only while the creating thread enters the kernel
//! (`DEFER_TASKRUN`), so [`RuntimeRing::poll_completion`] enters it without
//! waiting when the completion queue is empty. The io-wq limit belongs to
//! the issuing thread's io_uring context, which other rings created by the
//! same thread share. Setup requires the `SINGLE_MMAP`, `EXT_ARG`, `NODROP`
//! and `SUBMIT_STABLE` features. The latter guarantees the kernel has
//! finished reading an SQE once it advances the SQ head, before this issuer
//! may reuse that array entry.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::mem;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU32, Ordering};
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

use rustix::fs::{FileType, OFlags};
use rustix::io::Errno;
use rustix::io_uring::{
  IoringEnterFlags, IoringFeatureFlags, IoringRegisterOp, IoringSetupFlags, Timespec,
  io_uring_enter, io_uring_enter_arg, io_uring_getevents_arg, io_uring_params, io_uring_ptr,
  io_uring_register, io_uring_setup,
};
use rustix::mm::{self, MapFlags, ProtFlags};
use rustix::process::{Pid, getpid};

use crate::runtime::managed::ManagedBuf;

/// The largest ring depth: the in-flight table and the SQ have this many
/// entries at most.
pub(crate) const MAX_DEPTH: u32 = 1024;

// UAPI values from `include/uapi/linux/io_uring.h` (checked against the
// Linux 7.0 header) that rustix 1.1 does not name, or names in types this
// module does not use.
const IORING_OP_READ: u8 = 22;
const IORING_OP_WRITE: u8 = 23;
const IORING_OFF_SQ_RING: u64 = 0;
const IORING_OFF_SQES: u64 = 0x1000_0000;
const IORING_RESTRICTION_REGISTER_OP: u16 = 0;
const IORING_RESTRICTION_SQE_OP: u16 = 1;
const IORING_REGISTER_ENABLE_RINGS: u8 = 12;
const IO_URING_OP_SUPPORTED: u16 = 1 << 0;
const IORING_SQ_CQ_OVERFLOW: u32 = 1 << 1;
/// The kernel's `IORING_MAX_CQ_ENTRIES`.
const MAX_CQ_ENTRIES: u32 = 2 * 32768;
/// The largest errno a negative result may carry (`MAX_ERRNO`).
const MAX_ERRNO: i32 = 4095;
/// Low bits of a kernel `user_data` key that hold the slot index; the rest
/// is the slot's generation.
const SLOT_BITS: u32 = 16;
const SLOT_MASK: u64 = (1 << SLOT_BITS) - 1;
const MAX_GENERATION: u64 = (1 << (64 - SLOT_BITS)) - 1;

const _: () = {
  assert!(cfg!(target_endian = "little") && usize::BITS == 64);
  assert!(MAX_DEPTH.is_power_of_two() && MAX_DEPTH as u64 <= SLOT_MASK + 1);
};

/// `struct io_uring_sqe`, with the fields a read or write uses named.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Sqe {
  opcode: u8,
  flags: u8,
  ioprio: u16,
  fd: i32,
  off: u64,
  addr: u64,
  len: u32,
  rw_flags: u32,
  user_data: u64,
  /// `buf_index`, `personality`, `file_index`, `addr3` and padding: zero.
  rest: [u64; 3],
}

/// `struct io_uring_cqe` (16 bytes; the ring does not use `CQE32`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cqe {
  user_data: u64,
  res: i32,
  flags: u32,
}

/// `struct io_uring_restriction`.
#[repr(C)]
struct Restriction {
  opcode: u16,
  /// `register_op` or `sqe_op`.
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
  assert!(size_of::<Sqe>() == 64 && align_of::<Sqe>() == 8);
  assert!(mem::offset_of!(Sqe, fd) == 4);
  assert!(mem::offset_of!(Sqe, off) == 8);
  assert!(mem::offset_of!(Sqe, addr) == 16);
  assert!(mem::offset_of!(Sqe, len) == 24);
  assert!(mem::offset_of!(Sqe, rw_flags) == 28);
  assert!(mem::offset_of!(Sqe, user_data) == 32);
  assert!(mem::offset_of!(Sqe, rest) == 40);
  assert!(size_of::<Cqe>() == 16 && align_of::<Cqe>() == 8);
  assert!(mem::offset_of!(Cqe, res) == 8 && mem::offset_of!(Cqe, flags) == 12);
  assert!(size_of::<Restriction>() == 16);
  assert!(size_of::<Probe>() == 16 + 8 * 256);
  assert!(size_of::<io_uring_params>() == 120);
  assert!(size_of::<io_uring_getevents_arg>() == 24);
  assert!(mem::offset_of!(io_uring_getevents_arg, ts) == 16);
  // `struct __kernel_timespec`.
  assert!(size_of::<Timespec>() == 16);
};

/// A positioned transfer between a regular file and a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationKind {
  /// `pread`: the kernel writes up to the buffer's length into it.
  ReadAt,
  /// `pwrite`: the kernel reads the buffer's bytes.
  WriteAt,
}

/// An operation offered to [`RuntimeRing::publish`].
#[derive(Debug)]
pub(crate) struct RingOperation {
  /// The caller's key, returned in the completion; unique among the ring's
  /// operations in flight.
  pub user_data: u64,
  /// A regular file opened for the operation's direction.
  pub fd: OwnedFd,
  /// Uniquely owned storage; its whole length is transferred.
  pub buffer: ManagedBuf,
  /// File offset; `offset + buffer.len()` must not exceed `i64::MAX`.
  pub offset: u64,
  /// Read or write.
  pub kind: OperationKind,
}

/// The completion of a published operation, returning its owners.
#[derive(Debug)]
pub(crate) struct RingCompletion {
  /// The operation's [`RingOperation::user_data`].
  pub user_data: u64,
  /// The operation's descriptor.
  pub fd: OwnedFd,
  /// The operation's buffer, with its charge still held.
  pub buffer: ManagedBuf,
  /// Bytes transferred (at most the buffer's length), or the kernel's error.
  pub result: io::Result<usize>,
}

/// An operation that was never exposed to the kernel, returned whole.
#[derive(Debug)]
pub(crate) struct NotPublished {
  /// The operation as offered.
  pub operation: RingOperation,
  /// Why it was refused: `InvalidInput` (not a regular file, `O_PATH`,
  /// `O_APPEND` for a write, an extent beyond `u32` or `i64::MAX`),
  /// `Unsupported` (`O_DIRECT`), `EBADF` (wrong access mode),
  /// `AlreadyExists` (duplicate `user_data`), `WouldBlock` (the ring is
  /// full), `ResourceBusy` (the buffer has clones), or the `fstat`/`fcntl`
  /// error.
  pub error: io::Error,
}

/// Why [`RuntimeRing::new`] failed. No operation was published, and every
/// resource it acquired has been released.
#[derive(Debug)]
pub(crate) struct RingStartError {
  /// The setup step that failed.
  pub phase: &'static str,
  /// The error; `Unsupported` or `InvalidData` for a kernel result this
  /// ring does not accept.
  pub error: io::Error,
}

impl RingStartError {
  fn new(phase: &'static str, error: impl Into<io::Error>) -> Self {
    Self {
      phase,
      error: error.into(),
    }
  }
}

impl fmt::Display for RingStartError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "runtime io_uring {} failed: {}", self.phase, self.error)
  }
}

impl std::error::Error for RingStartError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.error)
  }
}

/// Aborts the process. Used wherever the ring cannot prove who owns a
/// buffer or descriptor the kernel may still use.
#[cold]
fn fail_stop(reason: &'static str) -> ! {
  use std::io::Write as _;
  let _ = writeln!(
    std::io::stderr(),
    "allocatbelt runtime io_uring fail-stop: {reason}"
  );
  std::process::abort()
}

/// Aborts if dropped: held across sections in which an unwind could
/// separate kernel-visible state from its owners. Forgotten on success.
struct UnwindGuard(&'static str);

impl Drop for UnwindGuard {
  fn drop(&mut self) {
    fail_stop(self.0)
  }
}

/// Checks a requested depth: a power of two in `1..=MAX_DEPTH`.
fn check_depth(depth: u32) -> Result<(), io::ErrorKind> {
  if depth == 0 || depth > MAX_DEPTH || !depth.is_power_of_two() {
    return Err(io::ErrorKind::InvalidInput);
  }
  Ok(())
}

/// The SQE length for a buffer of `len` bytes at `offset`: at most
/// `u32::MAX`, and the end must be a valid non-negative `loff_t` (which
/// also excludes `-1`, "the current file position").
fn check_extent(len: usize, offset: u64) -> Result<u32, io::ErrorKind> {
  let len32 = u32::try_from(len).map_err(|_| io::ErrorKind::InvalidInput)?;
  let end = offset
    .checked_add(u64::from(len32))
    .ok_or(io::ErrorKind::InvalidInput)?;
  if end > i64::MAX.unsigned_abs() {
    return Err(io::ErrorKind::InvalidInput);
  }
  Ok(len32)
}

/// Checks the descriptor before publication: a regular file, open for the
/// operation's direction, not `O_PATH` or `O_DIRECT`, and not `O_APPEND`
/// for a write (which would ignore the offset).
fn check_file(fd: &OwnedFd, kind: OperationKind) -> io::Result<()> {
  let stat = rustix::fs::fstat(fd)?;
  if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
    return Err(io::ErrorKind::InvalidInput.into());
  }
  let flags = rustix::fs::fcntl_getfl(fd)?;
  if flags.contains(OFlags::PATH) {
    return Err(io::ErrorKind::InvalidInput.into());
  }
  let mode = flags & OFlags::RWMODE;
  let permitted = match kind {
    OperationKind::ReadAt => mode == OFlags::RDONLY || mode == OFlags::RDWR,
    OperationKind::WriteAt => mode == OFlags::WRONLY || mode == OFlags::RDWR,
  };
  if !permitted {
    return Err(Errno::BADF.into());
  }
  if kind == OperationKind::WriteAt && flags.contains(OFlags::APPEND) {
    return Err(io::ErrorKind::InvalidInput.into());
  }
  if flags.contains(OFlags::DIRECT) {
    return Err(io::ErrorKind::Unsupported.into());
  }
  Ok(())
}

/// A CQE result for a transfer of at most `len` bytes: a count up to `len`,
/// or a negated errno in `1..=MAX_ERRNO`. `None` for anything else.
fn decode_result(res: i32, len: u32) -> Option<io::Result<usize>> {
  if let Ok(count) = u32::try_from(res) {
    return (count <= len).then_some(Ok(count as usize));
  }
  let errno = res.checked_neg()?;
  (errno <= MAX_ERRNO).then(|| Err(io::Error::from_raw_os_error(errno)))
}

/// Entries between a consumer counter `from` and a producer counter `to`,
/// if at most `limit`.
fn distance(from: u32, to: u32, limit: u32) -> Option<u32> {
  let n = to.wrapping_sub(from);
  (n <= limit).then_some(n)
}

/// The kernel `user_data` of slot `index` in `generation`.
fn key(index: usize, generation: u64) -> u64 {
  generation << SLOT_BITS | index as u64 & SLOT_MASK
}

/// `timeout` as a relative `__kernel_timespec`, saturating the seconds.
fn timespec(timeout: Duration) -> Timespec {
  Timespec {
    tv_sec: i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX),
    tv_nsec: timeout.subsec_nanos().into(),
  }
}

/// The ring's mapped layout, checked before any reference into it exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layout {
  sq_entries: u32,
  cq_entries: u32,
  rings_len: usize,
  sqes_len: usize,
  sq_head: u32,
  sq_tail: u32,
  sq_mask: u32,
  sq_ring_entries: u32,
  sq_flags: u32,
  sq_dropped: u32,
  cq_head: u32,
  cq_tail: u32,
  cq_mask: u32,
  cq_ring_entries: u32,
  cq_overflow: u32,
  cqes: u32,
}

impl Layout {
  /// Checks what `io_uring_setup` returned for a ring of `depth` entries:
  /// `depth` SQ entries, a power-of-two CQ of at least `depth`, no SQ
  /// array, and eleven distinct aligned `u32` header words that lie before
  /// the CQE array, whose end must not overflow (`cq_off.flags` is not
  /// used).
  fn from_params(p: &io_uring_params, depth: u32) -> Result<Self, &'static str> {
    if p.sq_entries != depth {
      return Err("SQ entries differ from the requested depth");
    }
    let cq_entries = p.cq_entries;
    if cq_entries < depth || cq_entries > MAX_CQ_ENTRIES || !cq_entries.is_power_of_two() {
      return Err("unexpected CQ entries");
    }
    if p.sq_off.array != 0 {
      return Err("SQ array present despite NO_SQARRAY");
    }
    let cqes = p.cq_off.cqes;
    if !(cqes as usize).is_multiple_of(align_of::<Cqe>()) {
      return Err("misaligned CQE array");
    }
    let rings_len = (cq_entries as usize)
      .checked_mul(size_of::<Cqe>())
      .and_then(|n| n.checked_add(cqes as usize))
      .ok_or("ring size overflows")?;
    let sqes_len = (depth as usize)
      .checked_mul(size_of::<Sqe>())
      .ok_or("SQE array size overflows")?;
    let layout = Self {
      sq_entries: depth,
      cq_entries,
      rings_len,
      sqes_len,
      sq_head: p.sq_off.head,
      sq_tail: p.sq_off.tail,
      sq_mask: p.sq_off.ring_mask,
      sq_ring_entries: p.sq_off.ring_entries,
      sq_flags: p.sq_off.flags,
      sq_dropped: p.sq_off.dropped,
      cq_head: p.cq_off.head,
      cq_tail: p.cq_off.tail,
      cq_mask: p.cq_off.ring_mask,
      cq_ring_entries: p.cq_off.ring_entries,
      cq_overflow: p.cq_off.overflow,
      cqes,
    };
    let words = layout.words();
    for (i, &off) in words.iter().enumerate() {
      let end = off.checked_add(4).ok_or("header word overflows")?;
      if !off.is_multiple_of(4) || end > cqes {
        return Err("header word misaligned or outside the ring header");
      }
      if words[..i].contains(&off) {
        return Err("header words overlap");
      }
    }
    Ok(layout)
  }

  /// The header words this ring reads or writes.
  const fn words(&self) -> [u32; 11] {
    [
      self.sq_head,
      self.sq_tail,
      self.sq_mask,
      self.sq_ring_entries,
      self.sq_flags,
      self.sq_dropped,
      self.cq_head,
      self.cq_tail,
      self.cq_mask,
      self.cq_ring_entries,
      self.cq_overflow,
    ]
  }
}

/// The owners of an operation that may be kernel-visible.
struct Owner {
  user_data: u64,
  fd: OwnedFd,
  buffer: ManagedBuf,
  /// The transfer length published in the SQE.
  len: u32,
  /// The SQ tail value at which its SQE was published.
  position: u32,
}

struct Slot {
  generation: u64,
  owner: Option<Owner>,
}

/// The fixed in-flight table: one slot per SQ entry, never grown.
struct Table {
  slots: Vec<Slot>,
  live: usize,
}

impl Table {
  /// A table of `depth` empty slots, reserved fallibly.
  fn new(depth: u32) -> Result<Self, io::Error> {
    let depth = depth as usize;
    let mut slots = Vec::new();
    slots
      .try_reserve_exact(depth)
      .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    slots.extend((0..depth).map(|_| Slot {
      generation: 0,
      owner: None,
    }));
    Ok(Self { slots, live: 0 })
  }

  /// A free slot for an operation keyed `user_data`.
  fn vacancy(&self, user_data: u64) -> Result<usize, io::ErrorKind> {
    let mut free = None;
    for (i, slot) in self.slots.iter().enumerate() {
      match &slot.owner {
        Some(owner) if owner.user_data == user_data => return Err(io::ErrorKind::AlreadyExists),
        Some(_) => {}
        None => {
          if free.is_none() {
            free = Some(i);
          }
        }
      }
    }
    let i = free.ok_or(io::ErrorKind::WouldBlock)?;
    match self.slots.get(i) {
      Some(slot) if slot.generation < MAX_GENERATION => Ok(i),
      _ => Err(io::ErrorKind::Other),
    }
  }

  /// Stores `owner` in slot `index` (from [`Table::vacancy`]) under a new
  /// generation and returns its kernel key.
  fn occupy(&mut self, index: usize, owner: Owner) -> u64 {
    let Some(slot) = self.slots.get_mut(index) else {
      fail_stop("in-flight slot out of range");
    };
    if slot.owner.is_some() || slot.generation >= MAX_GENERATION {
      fail_stop("in-flight slot not vacant");
    }
    slot.generation += 1;
    slot.owner = Some(owner);
    self.live += 1;
    key(index, slot.generation)
  }

  /// Takes the owners of the operation `cqe` completes after checking the
  /// whole CQE. `consumed` says whether the SQE published at a position
  /// has been consumed by the kernel. On an error nothing changes.
  fn release(
    &mut self,
    cqe: Cqe,
    consumed: impl FnOnce(u32) -> bool,
  ) -> Result<RingCompletion, &'static str> {
    let index = usize::try_from(cqe.user_data & SLOT_MASK).map_err(|_| "unknown CQE key")?;
    let generation = cqe.user_data >> SLOT_BITS;
    let slot = self
      .slots
      .get_mut(index)
      .ok_or("CQE key outside the table")?;
    let owner = slot
      .owner
      .as_ref()
      .ok_or("CQE for an idle slot (unknown or duplicate completion)")?;
    if slot.generation != generation {
      return Err("CQE with a stale generation (duplicate completion)");
    }
    if !consumed(owner.position) {
      return Err("CQE for an SQE the kernel has not consumed");
    }
    if cqe.flags != 0 {
      return Err("unexpected CQE flags");
    }
    let result = decode_result(cqe.res, owner.len).ok_or("malformed CQE result")?;
    let owner = slot.owner.take().ok_or("in-flight slot emptied")?;
    self.live -= 1;
    Ok(RingCompletion {
      user_data: owner.user_data,
      fd: owner.fd,
      buffer: owner.buffer,
      result,
    })
  }
}

/// A shared mapping of ring memory, unmapped when dropped.
struct Mapping {
  ptr: NonNull<c_void>,
  len: usize,
}

impl Mapping {
  /// Maps `len` bytes of `fd` at `offset` (`IORING_OFF_*`).
  fn new(fd: &OwnedFd, len: usize, offset: u64) -> Result<Self, Errno> {
    // SAFETY: a fresh shared mapping of the ring's own memory at an address
    // the kernel picks; it aliases nothing in this process. `len` was
    // computed with checked arithmetic from the kernel's layout.
    #[expect(unsafe_code, reason = "mmap of the runtime ring")]
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
    let ptr = NonNull::new(p).ok_or(Errno::NOMEM)?;
    Ok(Self { ptr, len })
  }
}

impl Drop for Mapping {
  fn drop(&mut self) {
    // SAFETY: `ptr..ptr + len` is a mapping created by `Mapping::new` and
    // used only through its owner, which is being dropped; the ring that
    // holds it has no operation in flight (or never had one).
    #[expect(unsafe_code, reason = "munmap of the runtime ring")]
    let _ = unsafe { mm::munmap(self.ptr.as_ptr(), self.len) };
  }
}

/// An `io_uring_enter` outcome once SQEs may be exposed. In every case but
/// `Done` the SQEs the kernel did not consume stay in the SQ, unchanged,
/// for a later enter; none is rewritten or published again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entered {
  Done,
  /// `EINTR`: a signal; the wait may be repeated.
  Interrupted,
  /// `EAGAIN` or `ENOMEM`: the kernel deferred the submission.
  Deferred,
  /// `ETIME`: the wait's timeout passed.
  TimedOut,
}

/// Classifies `result`; any other error aborts with `reason`, because the
/// exposed SQEs can then be neither proven consumed nor taken back.
fn entered(result: Result<u32, Errno>, reason: &'static str) -> Entered {
  match result {
    Ok(_) => Entered::Done,
    Err(Errno::INTR) => Entered::Interrupted,
    Err(Errno::AGAIN | Errno::NOMEM) => Entered::Deferred,
    Err(Errno::TIME) => Entered::TimedOut,
    Err(_) => fail_stop(reason),
  }
}

/// Test-only fault injection; compiled out of the library.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
  PanicAfterOccupy,
  PanicAfterTail,
  /// The next publication's submission fails with this errno without
  /// entering the kernel.
  SubmitError(Errno),
  /// The next publication submits at most this many SQEs.
  SubmitLimit(u32),
  /// The next SQE gets this opcode and these flags.
  Sqe(u8, u8),
}

#[cfg(test)]
std::thread_local! {
  static FAULT: core::cell::Cell<Option<Fault>> = const { core::cell::Cell::new(None) };
}

#[cfg(test)]
fn injected(matches: fn(Fault) -> bool) -> Option<Fault> {
  FAULT.with(|cell| match cell.get() {
    Some(fault) if matches(fault) => {
      cell.set(None);
      Some(fault)
    }
    _ => None,
  })
}

/// A restricted io_uring for owned-buffer reads and writes of regular
/// files (see the module docs). Only the creating thread may use it: it is
/// neither `Send` nor `Sync`.
pub(crate) struct RuntimeRing {
  // Dropped in this order: the (empty) table, the mappings, the ring.
  table: Table,
  sqes: Mapping,
  rings: Mapping,
  fd: OwnedFd,
  layout: Layout,
  /// The SQ tail; only this ring writes it.
  sq_tail: u32,
  /// The CQ head; only this ring writes it.
  cq_head: u32,
  pid: Pid,
  _issuer: PhantomData<*mut ()>,
}

impl RuntimeRing {
  /// Sets up a ring of `depth` entries (a power of two, at most
  /// [`MAX_DEPTH`]) issued by the calling thread.
  ///
  /// # Errors
  ///
  /// The step that failed: the depth, the in-flight table, io_uring
  /// unavailable or denied (`kernel.io_uring_disabled`, seccomp, ENOSYS
  /// under emulators), a missing feature or operation, or a layout this
  /// ring does not accept. Nothing has been published.
  pub(crate) fn new(depth: u32) -> Result<Self, RingStartError> {
    check_depth(depth).map_err(|kind| RingStartError::new("depth", kind))?;
    let table = Table::new(depth).map_err(|e| RingStartError::new("in-flight table", e))?;
    let pid = getpid();
    let flags = IoringSetupFlags::SINGLE_ISSUER
      | IoringSetupFlags::DEFER_TASKRUN
      | IoringSetupFlags::R_DISABLED
      | IoringSetupFlags::NO_SQARRAY;
    let mut p = io_uring_params::default();
    p.flags = flags;
    // SAFETY: the flags ask for no SQPOLL thread and no attached work
    // queue (`wq_fd` is unused), so the kernel only reads and fills `p`, a
    // live exclusive `io_uring_params`, and returns a new descriptor.
    #[expect(unsafe_code, reason = "io_uring_setup syscall")]
    let fd =
      unsafe { io_uring_setup(depth, &mut p) }.map_err(|e| RingStartError::new("setup", e))?;
    let required = IoringFeatureFlags::SINGLE_MMAP
      | IoringFeatureFlags::EXT_ARG
      | IoringFeatureFlags::NODROP
      | IoringFeatureFlags::SUBMIT_STABLE;
    if !p.features.contains(required) {
      return Err(RingStartError::new("features", io::ErrorKind::Unsupported));
    }
    if p.flags != flags {
      return Err(RingStartError::new("flags", io::ErrorKind::InvalidData));
    }
    let layout = Layout::from_params(&p, depth)
      .map_err(|_| RingStartError::new("layout", io::ErrorKind::InvalidData))?;
    let rings = Mapping::new(&fd, layout.rings_len, IORING_OFF_SQ_RING)
      .map_err(|e| RingStartError::new("map rings", e))?;
    let sqes = Mapping::new(&fd, layout.sqes_len, IORING_OFF_SQES)
      .map_err(|e| RingStartError::new("map SQEs", e))?;
    // From here on, dropping `ring` unmaps both and closes the descriptor.
    let mut ring = Self {
      table,
      sqes,
      rings,
      fd,
      layout,
      sq_tail: 0,
      cq_head: 0,
      pid,
      _issuer: PhantomData,
    };
    ring.check_header()?;
    ring.restrict(depth)?;
    Ok(ring)
  }

  /// Checks the mapped header against the layout: masks and entry counts,
  /// empty queues and zero overflow, drop and flag words.
  fn check_header(&mut self) -> Result<(), RingStartError> {
    let l = self.layout;
    let read = |off| self.word(off).load(Ordering::Acquire);
    let sq_head = read(l.sq_head);
    let cq_tail = read(l.cq_tail);
    let consistent = read(l.sq_mask) == l.sq_entries - 1
      && read(l.sq_ring_entries) == l.sq_entries
      && read(l.cq_mask) == l.cq_entries - 1
      && read(l.cq_ring_entries) == l.cq_entries
      && read(l.sq_tail) == sq_head
      && read(l.cq_head) == cq_tail
      && read(l.sq_dropped) == 0
      && read(l.cq_overflow) == 0
      && read(l.sq_flags) & IORING_SQ_CQ_OVERFLOW == 0;
    if !consistent {
      return Err(RingStartError::new(
        "ring header",
        io::ErrorKind::InvalidData,
      ));
    }
    self.sq_tail = sq_head;
    self.cq_head = cq_tail;
    Ok(())
  }

  /// Probes the two operations, caps the io-wq workers, allows only reads
  /// and writes, and enables the ring for the calling thread.
  fn restrict(&mut self, depth: u32) -> Result<(), RingStartError> {
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
      .map_err(|e| RingStartError::new("probe", e))?;
    for op in [IORING_OP_READ, IORING_OP_WRITE] {
      let i = usize::from(op);
      let supported = i < usize::from(probe.ops_len)
        && probe
          .ops
          .get(i)
          .is_some_and(|o| o[1] & IO_URING_OP_SUPPORTED != 0);
      if !supported {
        return Err(RingStartError::new("probe", io::ErrorKind::Unsupported));
      }
    }
    // Bounded (regular files) and unbounded workers, both at the depth.
    let mut workers = [depth, depth];
    self
      .register(
        IoringRegisterOp::RegisterIowqMaxWorkers,
        (&raw mut workers).cast(),
        2,
      )
      .map_err(|e| RingStartError::new("max workers", e))?;
    let allow = |opcode, arg| Restriction {
      opcode,
      arg,
      resv: 0,
      resv2: [0; 3],
    };
    // No `IORING_RESTRICTION_SQE_FLAGS_*` entry, so every SQE flag is
    // refused. `ENABLE_RINGS` is listed because newer kernels restrict
    // `io_uring_register` only once a register opcode is; it fails on an
    // enabled ring anyway.
    let mut rules = [
      allow(IORING_RESTRICTION_SQE_OP, IORING_OP_READ),
      allow(IORING_RESTRICTION_SQE_OP, IORING_OP_WRITE),
      allow(IORING_RESTRICTION_REGISTER_OP, IORING_REGISTER_ENABLE_RINGS),
    ];
    self
      .register(
        IoringRegisterOp::RegisterRestrictions,
        (&raw mut rules).cast(),
        3,
      )
      .map_err(|e| RingStartError::new("restrict", e))?;
    self
      .register(IoringRegisterOp::RegisterEnableRings, ptr::null_mut(), 0)
      .map_err(|e| RingStartError::new("enable", e))?;
    Ok(())
  }

  /// Publishes `op` and submits it.
  ///
  /// `Ok` transfers the descriptor and buffer to the ring until the
  /// operation's completion returns them; a submission the kernel defers
  /// (`EINTR`, `EAGAIN`, `ENOMEM`) is retried, unchanged, by the next
  /// [`RuntimeRing::poll_completion`] or [`RuntimeRing::wait_with_timeout`].
  /// A zero-length buffer is published like any other and completes with
  /// the kernel's result for a zero-length transfer.
  ///
  /// # Errors
  ///
  /// [`NotPublished`], returning `op` unchanged, when it fails a check
  /// (see [`NotPublished::error`]); nothing about it was exposed.
  pub(crate) fn publish(&mut self, op: RingOperation) -> Result<(), NotPublished> {
    self.check_process();
    let refuse = |operation, error| Err(NotPublished { operation, error });
    if let Err(error) = check_file(&op.fd, op.kind) {
      return refuse(op, error);
    }
    let len = match check_extent(op.buffer.len(), op.offset) {
      Ok(len) => len,
      Err(kind) => return refuse(op, kind.into()),
    };
    let index = match self.table.vacancy(op.user_data) {
      Ok(index) => index,
      Err(kind) => return refuse(op, kind.into()),
    };
    // The table bounds the outstanding SQEs below the SQ size, so position
    // `sq_tail` holds a consumed entry; a corrupt head aborts here.
    if self.outstanding() >= self.layout.sq_entries {
      return refuse(op, io::ErrorKind::WouldBlock.into());
    }
    let RingOperation {
      user_data,
      fd,
      mut buffer,
      offset,
      kind,
    } = op;
    // The one storage pointer, taken while the buffer is provably unique.
    // The `&mut [u8]` ends here; the storage is not touched again until the
    // completion returns the buffer.
    let addr = match buffer.get_mut() {
      Some(bytes) => bytes.as_mut_ptr(),
      None => {
        let operation = RingOperation {
          user_data,
          fd,
          buffer,
          offset,
          kind,
        };
        return refuse(operation, io::ErrorKind::ResourceBusy.into());
      }
    };
    let opcode = match kind {
      OperationKind::ReadAt => IORING_OP_READ,
      OperationKind::WriteAt => IORING_OP_WRITE,
    };
    #[cfg(test)]
    let (opcode, flags) = match injected(|f| matches!(f, Fault::Sqe(..))) {
      Some(Fault::Sqe(opcode, flags)) => (opcode, flags),
      _ => (opcode, 0),
    };
    #[cfg(not(test))]
    let flags = 0;
    let raw_fd = fd.as_raw_fd();
    let position = self.sq_tail;
    // From here until the submission returns, an unwind would leave owners
    // and kernel-visible state out of step.
    let guard = UnwindGuard("unwind while publishing a runtime io_uring operation");
    // The owners enter the table before anything kernel-visible names them.
    let user_key = self.table.occupy(
      index,
      Owner {
        user_data,
        fd,
        buffer,
        len,
        position,
      },
    );
    #[cfg(test)]
    if injected(|f| f == Fault::PanicAfterOccupy).is_some() {
      panic!("injected panic after occupying an in-flight slot");
    }
    self.write_sqe(
      position,
      Sqe {
        opcode,
        flags,
        fd: raw_fd,
        off: offset,
        addr: addr.expose_provenance() as u64,
        len,
        user_data: user_key,
        ..Sqe::default()
      },
    );
    self.sq_tail = position.wrapping_add(1);
    self
      .word(self.layout.sq_tail)
      .store(self.sq_tail, Ordering::Release);
    #[cfg(test)]
    if injected(|f| f == Fault::PanicAfterTail).is_some() {
      panic!("injected panic after publishing the SQ tail");
    }
    self.submit();
    mem::forget(guard);
    Ok(())
  }

  /// Submits the SQEs the kernel has not consumed, without waiting.
  fn submit(&mut self) {
    let to_submit = self.outstanding();
    if to_submit == 0 {
      return;
    }
    #[cfg(test)]
    let to_submit = match injected(|f| matches!(f, Fault::SubmitError(_) | Fault::SubmitLimit(_))) {
      Some(Fault::SubmitError(e)) => {
        entered(Err(e), "injected fatal submission error");
        return;
      }
      Some(Fault::SubmitLimit(n)) => to_submit.min(n),
      _ => to_submit,
    };
    let result = self.enter(to_submit, IoringEnterFlags::empty());
    entered(result, "io_uring_enter failed with SQEs exposed");
    self.outstanding();
  }

  /// The next completion, if one is available, without blocking. With
  /// operations in flight and none posted, enters the kernel once to submit
  /// what is outstanding and run deferred completions.
  pub(crate) fn poll_completion(&mut self) -> Option<RingCompletion> {
    self.check_process();
    if let Some(completion) = self.take_completion() {
      return Some(completion);
    }
    if self.table.live == 0 {
      return None;
    }
    let to_submit = self.outstanding();
    let result = self.enter(to_submit, IoringEnterFlags::GETEVENTS);
    entered(result, "io_uring_enter failed with operations in flight");
    self.take_completion()
  }

  /// The next completion, waiting up to `timeout` for one. `None` when the
  /// time passed, when nothing is in flight, or when the kernel deferred an
  /// outstanding submission (the caller may retry).
  pub(crate) fn wait_with_timeout(&mut self, timeout: Duration) -> Option<RingCompletion> {
    self.check_process();
    if let Some(completion) = self.take_completion() {
      return Some(completion);
    }
    if self.table.live == 0 {
      return None;
    }
    let deadline = Instant::now().checked_add(timeout);
    let mut remaining = timeout;
    loop {
      let to_submit = self.outstanding();
      let result = self.enter_wait(to_submit, remaining);
      let outcome = entered(result, "io_uring wait failed with operations in flight");
      if let Some(completion) = self.take_completion() {
        return Some(completion);
      }
      // A short submission skips the wait; one that made no progress is
      // left to the caller rather than spun on.
      let stalled = to_submit != 0 && self.outstanding() == to_submit;
      if matches!(outcome, Entered::TimedOut | Entered::Deferred) || stalled {
        return None;
      }
      if let Some(deadline) = deadline {
        remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
          return None;
        }
      }
    }
  }

  /// Takes one posted completion, after checking the queues and the CQE.
  fn take_completion(&mut self) -> Option<RingCompletion> {
    self.check_health();
    let tail = self.word(self.layout.cq_tail).load(Ordering::Acquire);
    let ready = distance(self.cq_head, tail, self.layout.cq_entries)
      .unwrap_or_else(|| fail_stop("CQ tail outside the ring"));
    if ready == 0 {
      return None;
    }
    if ready as usize > self.table.live {
      fail_stop("more CQEs than operations in flight");
    }
    let cqe = self.read_cqe(self.cq_head);
    let completion = self.accept(cqe);
    self.cq_head = self.cq_head.wrapping_add(1);
    self
      .word(self.layout.cq_head)
      .store(self.cq_head, Ordering::Release);
    Some(completion)
  }

  /// Returns the owners `cqe` completes, or aborts.
  fn accept(&mut self, cqe: Cqe) -> RingCompletion {
    let guard = UnwindGuard("unwind while accepting a runtime io_uring completion");
    let tail = self.sq_tail;
    let pending = tail.wrapping_sub(self.sq_head());
    let completion = self
      .table
      .release(cqe, |position| tail.wrapping_sub(position) > pending)
      .unwrap_or_else(|reason| fail_stop(reason));
    mem::forget(guard);
    completion
  }

  /// SQEs published but not consumed, checked against the ring and table.
  fn outstanding(&self) -> u32 {
    match distance(self.sq_head(), self.sq_tail, self.layout.sq_entries) {
      Some(n) if n as usize <= self.table.live => n,
      _ => fail_stop("SQ head outside the published range"),
    }
  }

  fn sq_head(&self) -> u32 {
    self.word(self.layout.sq_head).load(Ordering::Acquire)
  }

  /// Aborts on a CQ overflow or a dropped SQE: some completion may be lost.
  fn check_health(&self) {
    let l = self.layout;
    if self.word(l.sq_flags).load(Ordering::Acquire) & IORING_SQ_CQ_OVERFLOW != 0
      || self.word(l.cq_overflow).load(Ordering::Acquire) != 0
      || self.word(l.sq_dropped).load(Ordering::Acquire) != 0
    {
      fail_stop("io_uring CQ overflow or dropped SQE");
    }
  }

  /// Aborts in a forked child: the ring's mappings are shared with the
  /// parent, whose kernel context would run anything published here.
  fn check_process(&self) {
    if getpid() != self.pid {
      fail_stop("runtime io_uring used outside the process that created it");
    }
  }

  /// The header word at byte offset `off`, one of the layout's words.
  fn word(&self, off: u32) -> &AtomicU32 {
    let p = self
      .rings
      .ptr
      .as_ptr()
      .wrapping_byte_add(off as usize)
      .cast::<AtomicU32>();
    // SAFETY: `Layout::from_params` checked that `off` is 4-aligned and that
    // `off + 4` lies before the CQE array, inside the rings mapping (which
    // is page-aligned and lives as long as `self`). The kernel accesses
    // these words with `READ_ONCE`/`WRITE_ONCE` and acquire/release, and
    // this module only atomically.
    #[expect(unsafe_code, reason = "shared ring header word")]
    unsafe {
      &*p
    }
  }

  /// Writes the SQE for SQ position `position`.
  fn write_sqe(&mut self, position: u32, sqe: Sqe) {
    let index = (position & (self.layout.sq_entries - 1)) as usize;
    let p = self.sqes.ptr.cast::<Sqe>().as_ptr().wrapping_add(index);
    // SAFETY: `index < sq_entries`, so the slot is inside the SQE mapping
    // (`sq_entries * 64` bytes, page-aligned). Only this thread writes SQEs,
    // and it writes position `tail` only while fewer than `sq_entries` SQEs
    // are outstanding, so the kernel has consumed (and, with
    // `IORING_FEAT_SUBMIT_STABLE`, no longer reads) the entry it replaces.
    // The kernel reads it only after the Release tail store that follows.
    #[expect(unsafe_code, reason = "write to the shared SQE array")]
    unsafe {
      p.write(sqe);
    }
  }

  /// Reads the CQE at CQ position `position`.
  fn read_cqe(&self, position: u32) -> Cqe {
    let index = (position & (self.layout.cq_entries - 1)) as usize;
    let p = self
      .rings
      .ptr
      .as_ptr()
      .wrapping_byte_add(self.layout.cqes as usize)
      .cast::<Cqe>()
      .wrapping_add(index);
    // SAFETY: `index < cq_entries` and the CQE array of `cq_entries`
    // 8-aligned entries ends at `rings_len`, the mapping's length. The
    // kernel wrote the entry before the CQ tail store the Acquire load in
    // `take_completion` observed, and does not reuse it until the head
    // moves past it.
    #[expect(unsafe_code, reason = "read from the shared CQE array")]
    unsafe {
      p.read()
    }
  }

  fn register(&self, op: IoringRegisterOp, arg: *mut c_void, nr: u32) -> Result<(), Errno> {
    // SAFETY: `op` is one of the setup registrations, and `arg` points at a
    // live exclusive value of the type and count (`nr`) `op` expects (or is
    // null for `RegisterEnableRings`, which takes none); the kernel reads or
    // fills only that.
    #[expect(unsafe_code, reason = "io_uring_register syscall")]
    let r = unsafe { io_uring_register(&self.fd, op, arg.cast_const(), nr) };
    r.map(drop)
  }

  /// `io_uring_enter` without an argument and without waiting.
  fn enter(&self, to_submit: u32, flags: IoringEnterFlags) -> Result<u32, Errno> {
    // SAFETY: no argument pointer. The SQEs it may submit were written by
    // `publish`; their descriptors and buffers stay in the in-flight table
    // until their completions, so each buffer pointer stays valid for
    // `len` bytes, and nothing else accesses those bytes meanwhile.
    #[expect(unsafe_code, reason = "io_uring_enter syscall")]
    let r = unsafe { io_uring_enter(&self.fd, to_submit, 0, flags) };
    r
  }

  /// `io_uring_enter` waiting up to `timeout` for one completion.
  fn enter_wait(&self, to_submit: u32, timeout: Duration) -> Result<u32, Errno> {
    let ts = timespec(timeout);
    let arg = io_uring_getevents_arg {
      sigmask: io_uring_ptr::null(),
      sigmask_sz: 0,
      min_wait_usec: 0,
      ts: io_uring_ptr::new((&raw const ts).cast_mut().cast()),
    };
    // SAFETY: as `enter`; additionally `arg` and the `ts` it points to are
    // live locals for the whole call, the kernel only reads them, and the
    // null sigmask leaves the signal mask alone.
    #[expect(unsafe_code, reason = "io_uring_enter syscall")]
    let r = unsafe {
      io_uring_enter_arg(
        &self.fd,
        to_submit,
        1,
        IoringEnterFlags::GETEVENTS | IoringEnterFlags::EXT_ARG,
        Some(&arg),
      )
    };
    r
  }
}

impl Drop for RuntimeRing {
  fn drop(&mut self) {
    // Owners may still be kernel-owned, and closing the ring is not a
    // barrier: abort before any field (buffer, descriptor, mapping) drops.
    if self.table.live != 0 {
      fail_stop("runtime io_uring dropped with operations in flight");
    }
  }
}

impl fmt::Debug for RuntimeRing {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("RuntimeRing")
      .field("depth", &self.layout.sq_entries)
      .field("cq_entries", &self.layout.cq_entries)
      .field("in_flight", &self.table.live)
      .finish_non_exhaustive()
  }
}

#[cfg(test)]
mod tests {
  #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

  use std::fs::{File, OpenOptions};
  use std::io::{Read as _, Write as _};
  use std::os::unix::fs::OpenOptionsExt;
  use std::os::unix::process::ExitStatusExt;
  use std::path::{Path, PathBuf};
  use std::process::{Command, Stdio};
  use std::string::String;
  use std::sync::atomic::AtomicUsize;
  use std::vec::Vec;

  use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

  use super::*;
  use crate::runtime::managed::{ResourceLimits, ResourceScope};

  const CHILD_ENV: &str = "ALLOCATBELT_RUNTIME_RING_CHILD";
  const CHILD_FILE_ENV: &str = "ALLOCATBELT_RUNTIME_RING_CHILD_FILE";
  /// Set to make an unavailable io_uring fail the kernel tests instead of
  /// recording them as not run.
  const REQUIRE_ENV: &str = "ALLOCATBELT_REQUIRE_IO_URING";
  /// A child's exit code when io_uring is unavailable to it.
  const UNAVAILABLE: i32 = 77;
  const IOSQE_ASYNC: u8 = 1 << 4;
  const IORING_OP_NOP: u8 = 0;

  /// Whether setup failed because the environment denies io_uring, as
  /// opposed to this ring rejecting what the kernel returned.
  fn denied(e: &RingStartError) -> bool {
    e.phase == "setup"
      && [Errno::PERM, Errno::ACCESS, Errno::NOSYS]
        .iter()
        .any(|errno| e.error.raw_os_error() == Some(errno.raw_os_error()))
  }

  fn not_run(what: &str, why: &dyn fmt::Display) {
    assert!(
      std::env::var_os(REQUIRE_ENV).is_none(),
      "{REQUIRE_ENV} is set but io_uring is unavailable: {why}"
    );
    std::eprintln!("ENVIRONMENT-NOT-PASS: {what} not run, io_uring unavailable: {why}");
  }

  /// A kernel ring, or `None` (recorded as not run) when io_uring is denied.
  fn ring(depth: u32) -> Option<RuntimeRing> {
    match RuntimeRing::new(depth) {
      Ok(ring) => Some(ring),
      Err(e) if denied(&e) => {
        not_run("kernel ring test", &e);
        None
      }
      Err(e) => panic!("ring setup rejected: {e}"),
    }
  }

  fn inject(fault: Fault) {
    FAULT.with(|cell| cell.set(Some(fault)));
  }

  /// A file under the temporary directory, removed when dropped.
  struct TempFile(PathBuf);

  impl TempFile {
    fn new(contents: &[u8]) -> Self {
      static NEXT: AtomicUsize = AtomicUsize::new(0);
      let n = NEXT.fetch_add(1, Ordering::Relaxed);
      let path = std::env::temp_dir().join(std::format!(
        "allocatbelt-runtime-ring-{}-{n}",
        std::process::id()
      ));
      // Never truncate a stale path from another test-process lifetime.
      let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
      let owned = Self(path);
      file.write_all(contents).unwrap();
      drop(file);
      owned
    }

    fn open(&self, options: &mut OpenOptions) -> OwnedFd {
      options.open(&self.0).unwrap().into()
    }

    fn read_write(&self) -> OwnedFd {
      open_read_write(&self.0)
    }

    fn contents(&self) -> Vec<u8> {
      let mut v = Vec::new();
      File::open(&self.0).unwrap().read_to_end(&mut v).unwrap();
      v
    }
  }

  impl Drop for TempFile {
    fn drop(&mut self) {
      let _ = std::fs::remove_file(&self.0);
    }
  }

  fn open_read_write(path: &Path) -> OwnedFd {
    OpenOptions::new()
      .read(true)
      .write(true)
      .open(path)
      .unwrap()
      .into()
  }

  fn assert_temp_file_absent(path: &Path) {
    match std::fs::symlink_metadata(path) {
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
      Ok(_) => panic!("parent-owned abort fixture remained after its guard dropped"),
      Err(error) => panic!("could not verify abort fixture cleanup: {error}"),
    }
  }

  fn scope(bytes: usize) -> ResourceScope {
    ResourceScope::new(ResourceLimits {
      managed_memory: bytes,
      ..ResourceLimits::default()
    })
  }

  fn buffer(scope: &ResourceScope, contents: &[u8]) -> ManagedBuf {
    let mut buf = scope.try_alloc_zeroed(contents.len()).unwrap();
    buf.get_mut().unwrap().copy_from_slice(contents);
    buf
  }

  fn op(
    user_data: u64,
    fd: OwnedFd,
    buffer: ManagedBuf,
    offset: u64,
    kind: OperationKind,
  ) -> RingOperation {
    RingOperation {
      user_data,
      fd,
      buffer,
      offset,
      kind,
    }
  }

  fn complete(ring: &mut RuntimeRing) -> RingCompletion {
    for _ in 0..100 {
      if let Some(c) = ring.wait_with_timeout(Duration::from_millis(100)) {
        return c;
      }
    }
    panic!("no completion within 10 s");
  }

  fn refused(ring: &mut RuntimeRing, operation: RingOperation) -> NotPublished {
    let tail = ring.sq_tail;
    let live = ring.table.live;
    let (user_data, raw, storage, offset, kind) = (
      operation.user_data,
      operation.fd.as_raw_fd(),
      operation.buffer.as_ptr(),
      operation.offset,
      operation.kind,
    );
    let e = ring.publish(operation).unwrap_err();
    // Nothing was exposed and the operation came back whole.
    assert_eq!(ring.sq_tail, tail);
    assert_eq!(ring.word(ring.layout.sq_tail).load(Ordering::Acquire), tail);
    assert_eq!(ring.table.live, live);
    let o = &e.operation;
    assert_eq!(
      (
        o.user_data,
        o.fd.as_raw_fd(),
        o.buffer.as_ptr(),
        o.offset,
        o.kind
      ),
      (user_data, raw, storage, offset, kind)
    );
    e
  }

  impl RuntimeRing {
    /// The SQE at SQ position `position` (test only).
    fn sqe_at(&self, position: u32) -> Sqe {
      let index = (position & (self.layout.sq_entries - 1)) as usize;
      let p = self.sqes.ptr.cast::<Sqe>().as_ptr().wrapping_add(index);
      // SAFETY: as in `write_sqe`, a slot inside the SQE mapping; the kernel
      // only reads SQEs, so this read cannot race with a write.
      #[expect(unsafe_code, reason = "test read of the shared SQE array")]
      unsafe {
        p.read()
      }
    }

    /// The kernel key of the in-flight operation `user_data`.
    fn key_of(&self, user_data: u64) -> u64 {
      let (i, slot) = self
        .table
        .slots
        .iter()
        .enumerate()
        .find(|(_, s)| s.owner.as_ref().is_some_and(|o| o.user_data == user_data))
        .unwrap();
      key(i, slot.generation)
    }

    /// Submits and waits until a CQE is posted, without taking it.
    fn wait_posted(&mut self) -> Cqe {
      for _ in 0..1000 {
        let to_submit = self.outstanding();
        let _ = self.enter_wait(to_submit, Duration::from_millis(10));
        let tail = self.word(self.layout.cq_tail).load(Ordering::Acquire);
        if tail != self.cq_head {
          return self.read_cqe(self.cq_head);
        }
      }
      panic!("no CQE posted");
    }
  }

  // Pure checks.

  #[test]
  fn depth_must_be_a_bounded_power_of_two() {
    for depth in [0, 3, 6, 1000, MAX_DEPTH + 1, 2048, u32::MAX] {
      assert_eq!(check_depth(depth), Err(io::ErrorKind::InvalidInput));
      let e = RuntimeRing::new(depth).unwrap_err();
      assert_eq!(e.phase, "depth");
      assert_eq!(e.error.kind(), io::ErrorKind::InvalidInput);
    }
    for depth in [1, 2, 64, 512, MAX_DEPTH] {
      assert_eq!(check_depth(depth), Ok(()));
    }
  }

  #[test]
  fn extents_fit_u32_and_loff_t() {
    let max = i64::MAX.unsigned_abs();
    let invalid = Err(io::ErrorKind::InvalidInput);
    assert_eq!(check_extent(0, 0), Ok(0));
    assert_eq!(check_extent(u32::MAX as usize, 0), Ok(u32::MAX));
    assert_eq!(check_extent(u32::MAX as usize + 1, 0), invalid);
    assert_eq!(check_extent(0, max), Ok(0));
    assert_eq!(check_extent(10, max - 10), Ok(10));
    assert_eq!(check_extent(11, max - 10), invalid);
    assert_eq!(check_extent(1, max), invalid);
    // `-1` (the current position) and other negative offsets.
    assert_eq!(check_extent(0, u64::MAX), invalid);
    assert_eq!(check_extent(0, max + 1), invalid);
    assert_eq!(check_extent(1, u64::MAX), invalid);
  }

  #[test]
  fn results_are_counts_up_to_the_length_or_errnos() {
    let count = |res, len| decode_result(res, len).map(|r| r.map_err(|e| e.raw_os_error()));
    assert_eq!(count(0, 0), Some(Ok(0)));
    assert_eq!(count(7, 8), Some(Ok(7)));
    assert_eq!(count(8, 8), Some(Ok(8)));
    assert_eq!(count(9, 8), None);
    assert_eq!(count(1, 0), None);
    assert_eq!(count(i32::MAX, u32::MAX), Some(Ok(i32::MAX as usize)));
    assert_eq!(count(-1, 8), Some(Err(Some(1))));
    assert_eq!(count(-4095, 8), Some(Err(Some(4095))));
    assert_eq!(count(-4096, 8), None);
    assert_eq!(count(i32::MIN, 8), None);
    assert_eq!(count(i32::MIN + 1, 8), None);
  }

  #[test]
  fn counter_distances_wrap_and_are_bounded() {
    assert_eq!(distance(0, 0, 4), Some(0));
    assert_eq!(distance(3, 7, 4), Some(4));
    assert_eq!(distance(3, 8, 4), None);
    assert_eq!(distance(u32::MAX, 1, 4), Some(2));
    // A consumer ahead of its producer.
    assert_eq!(distance(5, 3, 4), None);
  }

  #[test]
  fn timeouts_saturate() {
    let t = timespec(Duration::new(1, 500_000_000));
    assert_eq!((t.tv_sec, t.tv_nsec), (1, 500_000_000));
    let t = timespec(Duration::MAX);
    assert_eq!((t.tv_sec, t.tv_nsec), (i64::MAX, 999_999_999));
    let t = timespec(Duration::ZERO);
    assert_eq!((t.tv_sec, t.tv_nsec), (0, 0));
  }

  /// Offsets shaped like Linux 7.0's `struct io_rings`.
  fn params(depth: u32) -> io_uring_params {
    let mut p = io_uring_params::default();
    p.sq_entries = depth;
    p.cq_entries = 2 * depth;
    p.sq_off.head = 0;
    p.sq_off.tail = 4;
    p.sq_off.ring_mask = 128;
    p.sq_off.ring_entries = 136;
    p.sq_off.flags = 148;
    p.sq_off.dropped = 144;
    p.cq_off.head = 64;
    p.cq_off.tail = 68;
    p.cq_off.ring_mask = 132;
    p.cq_off.ring_entries = 140;
    p.cq_off.overflow = 156;
    p.cq_off.flags = 152;
    p.cq_off.cqes = 192;
    p
  }

  #[test]
  fn layouts_are_checked_before_mapping() {
    let l = Layout::from_params(&params(8), 8).unwrap();
    assert_eq!((l.rings_len, l.sqes_len), (192 + 16 * 16, 8 * 64));
    type Corrupt = fn(&mut io_uring_params);
    let cases: [(&str, Corrupt); 13] = [
      ("sq entries", |p| p.sq_entries = 16),
      ("cq below depth", |p| p.cq_entries = 4),
      ("cq not a power of two", |p| p.cq_entries = 24),
      ("cq too large", |p| p.cq_entries = MAX_CQ_ENTRIES * 2),
      ("sq array", |p| p.sq_off.array = 512),
      ("cqes misaligned", |p| p.cq_off.cqes = 196),
      ("word misaligned", |p| p.sq_off.tail = 6),
      ("word in cqes", |p| p.cq_off.overflow = 192),
      ("word past end", |p| p.sq_off.dropped = u32::MAX - 3),
      ("word overflows", |p| p.cq_off.head = u32::MAX),
      ("words overlap", |p| p.cq_off.head = p.sq_off.tail),
      ("mask overlaps tail", |p| p.cq_off.ring_mask = p.cq_off.tail),
      ("cqes before header", |p| p.cq_off.cqes = 8),
    ];
    for (what, corrupt) in cases {
      let mut p = params(8);
      corrupt(&mut p);
      assert!(Layout::from_params(&p, 8).is_err(), "{what}");
    }
    // The largest accepted values cannot overflow the arithmetic.
    let mut p = params(MAX_DEPTH);
    p.cq_entries = MAX_CQ_ENTRIES;
    p.cq_off.cqes = u32::MAX - 7;
    let l = Layout::from_params(&p, MAX_DEPTH).unwrap();
    assert_eq!(
      l.rings_len,
      (u32::MAX - 7) as usize + 16 * MAX_CQ_ENTRIES as usize
    );
  }

  fn owner(scope: &ResourceScope, user_data: u64, len: usize, position: u32) -> Owner {
    Owner {
      user_data,
      fd: File::open("/dev/null").unwrap().into(),
      buffer: scope.try_alloc_zeroed(len).unwrap(),
      len: u32::try_from(len).unwrap(),
      position,
    }
  }

  #[test]
  fn the_table_checks_every_completion_before_releasing_owners() {
    let scope = scope(64);
    let mut table = Table::new(2).unwrap();
    assert_eq!(table.vacancy(1), Ok(0));
    let first = owner(&scope, 1, 8, 0);
    let (raw, storage) = (first.fd.as_raw_fd(), first.buffer.as_ptr());
    let k = table.occupy(0, first);
    assert_eq!(k, key(0, 1));
    assert_eq!(table.vacancy(1), Err(io::ErrorKind::AlreadyExists));
    assert_eq!(table.vacancy(2), Ok(1));
    table.occupy(1, owner(&scope, 2, 8, 1));
    assert_eq!(table.vacancy(3), Err(io::ErrorKind::WouldBlock));
    assert_eq!(scope.snapshot().managed_memory, 16);

    let cqe = |user_data, res, flags| Cqe {
      user_data,
      res,
      flags,
    };
    let consumed = |_| true;
    let bad = [
      (cqe(key(5, 1), 0, 0), consumed as fn(u32) -> bool),
      (cqe(key(SLOT_MASK as usize, 1), 0, 0), consumed),
      (cqe(key(0, 2), 0, 0), consumed),
      (cqe(key(0, 0), 0, 0), consumed),
      (cqe(k, 0, 1), consumed),
      (cqe(k, 0, 1 << 15), consumed),
      (cqe(k, 9, 0), consumed),
      (cqe(k, -4096, 0), consumed),
      (cqe(k, i32::MIN, 0), consumed),
      (cqe(k, 0, 0), |_| false),
    ];
    for (c, consumed) in bad {
      assert!(table.release(c, consumed).is_err(), "{c:?}");
      assert_eq!(table.live, 2);
      assert!(table.slots[0].owner.is_some());
    }
    let done = table.release(cqe(k, 5, 0), consumed).unwrap();
    assert_eq!(done.user_data, 1);
    assert_eq!(*done.result.as_ref().unwrap(), 5);
    assert_eq!((done.fd.as_raw_fd(), done.buffer.as_ptr()), (raw, storage));
    assert_eq!(table.live, 1);
    // The same key again: the slot is idle now.
    assert!(table.release(cqe(k, 5, 0), consumed).is_err());
    // A reused slot gets a new generation; the old key is stale.
    assert_eq!(table.vacancy(1), Ok(0));
    let k2 = table.occupy(0, owner(&scope, 1, 8, 2));
    assert_eq!(k2, key(0, 2));
    assert!(table.release(cqe(k, 0, 0), consumed).is_err());
    let e = table.release(cqe(k2, -5, 0), consumed).unwrap();
    assert_eq!(e.result.as_ref().unwrap_err().raw_os_error(), Some(5));
    // The buffers keep their charge until dropped.
    assert_eq!(scope.snapshot().managed_memory, 24);
    drop((done, e));
    assert_eq!(scope.snapshot().managed_memory, 8);
  }

  #[test]
  fn start_errors_name_the_phase() {
    let e = RingStartError::new("probe", io::ErrorKind::Unsupported);
    assert!(e.to_string().starts_with("runtime io_uring probe failed: "));
    assert!(std::error::Error::source(&e).is_some());
  }

  // Kernel tests: skipped and recorded when io_uring is unavailable.

  #[test]
  fn reads_and_writes_return_their_owners() {
    let Some(mut ring) = ring(4) else { return };
    assert!(std::format!("{ring:?}").contains("in_flight: 0"));
    let file = TempFile::new(b"");
    let scope = scope(64);
    let data = buffer(&scope, b"hello world");
    let fd = file.read_write();
    let (raw, storage) = (fd.as_raw_fd(), data.as_ptr());
    ring
      .publish(op(1, fd, data, 0, OperationKind::WriteAt))
      .unwrap();
    // The ring holds the buffer and its charge.
    assert_eq!(ring.table.live, 1);
    assert_eq!(scope.snapshot().managed_memory, 11);
    let c = complete(&mut ring);
    assert_eq!((c.user_data, c.result.as_ref().ok()), (1, Some(&11)));
    assert_eq!((c.fd.as_raw_fd(), c.buffer.as_ptr()), (raw, storage));
    assert_eq!(c.buffer.charged_bytes(), 11);
    assert_eq!(file.contents(), b"hello world");
    let fd = c.fd;

    // Full, partial, end-of-file and zero-length reads, all in flight at once.
    let reads = [
      (10, 0, 5, 5),
      (11, 6, 8, 5),
      (12, 11, 4, 0),
      (13, 100, 4, 0),
    ];
    for (user_data, offset, len, _) in reads {
      let buf = scope.try_alloc_zeroed(len).unwrap();
      ring
        .publish(op(
          user_data,
          fd.try_clone().unwrap(),
          buf,
          offset,
          OperationKind::ReadAt,
        ))
        .unwrap();
    }
    assert_eq!(ring.table.live, 4);
    assert_eq!(scope.snapshot().managed_memory, 11 + 21);
    let mut seen = Vec::new();
    for _ in 0..4 {
      let c = complete(&mut ring);
      let (_, offset, len, n) = reads.iter().find(|r| r.0 == c.user_data).copied().unwrap();
      assert_eq!(c.result.unwrap(), n, "read {}", c.user_data);
      assert_eq!(c.buffer.len(), len);
      let offset = usize::try_from(offset).unwrap();
      if n > 0 {
        assert_eq!(&c.buffer[..n], &b"hello world"[offset..offset + n]);
      }
      seen.push(c.user_data);
    }
    seen.sort_unstable();
    assert_eq!(seen, [10, 11, 12, 13]);
    let empty = scope.try_alloc_zeroed(0).unwrap();
    ring
      .publish(op(14, fd, empty, 3, OperationKind::ReadAt))
      .unwrap();
    let c = complete(&mut ring);
    assert_eq!((c.user_data, *c.result.as_ref().unwrap()), (14, 0));
    assert!(ring.poll_completion().is_none());
    assert_eq!((ring.table.live, ring.outstanding()), (0, 0));
    drop(ring);
    assert_eq!(scope.snapshot().managed_memory, 11);
    drop(c);
  }

  #[test]
  fn only_flagless_reads_and_writes_run() {
    let Some(mut ring) = ring(2) else { return };
    let file = TempFile::new(b"abcd");
    let scope = scope(8);
    // An SQE flag, and an operation other than read or write, complete with
    // EACCES without touching the buffer.
    for (user_data, fault) in [
      (1, Fault::Sqe(IORING_OP_READ, IOSQE_ASYNC)),
      (2, Fault::Sqe(IORING_OP_NOP, 0)),
    ] {
      let buf = scope.try_alloc_zeroed(4).unwrap();
      let fd = file.read_write();
      let (raw, storage) = (fd.as_raw_fd(), buf.as_ptr());
      inject(fault);
      ring
        .publish(op(user_data, fd, buf, 0, OperationKind::ReadAt))
        .unwrap();
      let c = complete(&mut ring);
      assert_eq!(c.user_data, user_data);
      assert_eq!(
        c.result.unwrap_err().raw_os_error(),
        Some(Errno::ACCESS.raw_os_error())
      );
      assert_eq!((c.fd.as_raw_fd(), c.buffer.as_ptr()), (raw, storage));
      assert_eq!(&c.buffer[..], &[0; 4]);
    }
    // No registration but `ENABLE_RINGS`, which an enabled ring refuses.
    let mut workers = [1u32, 1];
    assert_eq!(
      ring.register(
        IoringRegisterOp::RegisterIowqMaxWorkers,
        (&raw mut workers).cast(),
        2
      ),
      Err(Errno::ACCESS)
    );
    assert!(
      ring
        .register(IoringRegisterOp::RegisterEnableRings, ptr::null_mut(), 0)
        .is_err()
    );
  }

  #[test]
  fn refused_operations_are_never_exposed() {
    let Some(mut ring) = ring(1) else { return };
    let file = TempFile::new(b"abcdefgh");
    let scope = scope(64);
    let read = OperationKind::ReadAt;
    let write = OperationKind::WriteAt;
    let fresh = || scope.try_alloc_zeroed(4).unwrap();
    // The refused operation, with its buffer, is dropped at once.
    let mut error = |operation| refused(&mut ring, operation).error;
    let kind = |e: io::Error| e.kind();
    let errno = |e: io::Error| e.raw_os_error();

    let dir: OwnedFd = File::open(std::env::temp_dir()).unwrap().into();
    assert_eq!(
      kind(error(op(1, dir, fresh(), 0, read))),
      io::ErrorKind::InvalidInput
    );
    let null: OwnedFd = File::open("/dev/null").unwrap().into();
    assert_eq!(
      kind(error(op(1, null, fresh(), 0, read))),
      io::ErrorKind::InvalidInput
    );
    let path = file.open(OpenOptions::new().read(true).custom_flags(libc::O_PATH));
    assert_eq!(
      kind(error(op(1, path, fresh(), 0, read))),
      io::ErrorKind::InvalidInput
    );
    let read_only = file.open(OpenOptions::new().read(true));
    let badf = Some(Errno::BADF.raw_os_error());
    assert_eq!(errno(error(op(1, read_only, fresh(), 0, write))), badf);
    let write_only = file.open(OpenOptions::new().write(true));
    assert_eq!(errno(error(op(1, write_only, fresh(), 0, read))), badf);
    let append = file.open(OpenOptions::new().read(true).append(true));
    assert_eq!(
      kind(error(op(1, append, fresh(), 0, write))),
      io::ErrorKind::InvalidInput
    );
    match OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_DIRECT)
      .open(&file.0)
    {
      Ok(direct) => {
        let e = error(op(1, direct.into(), fresh(), 0, read));
        assert_eq!(kind(e), io::ErrorKind::Unsupported);
      }
      Err(e) => std::eprintln!("O_DIRECT check not run: {e}"),
    }
    let far = i64::MAX.unsigned_abs();
    let e = error(op(1, file.read_write(), fresh(), far, read));
    assert_eq!(kind(e), io::ErrorKind::InvalidInput);
    assert_eq!(scope.snapshot().managed_memory, 0);
    let shared = fresh();
    let clone = shared.clone();
    let e = refused(&mut ring, op(1, file.read_write(), shared, 0, read));
    assert_eq!(e.error.kind(), io::ErrorKind::ResourceBusy);
    drop(clone);
    // A refused operation can be published once fixed.
    let NotPublished { mut operation, .. } = e;
    operation.user_data = 7;
    ring.publish(operation).unwrap();
    // Duplicate key and full ring, while 7 is in flight.
    let e = refused(&mut ring, op(7, file.read_write(), fresh(), 0, read));
    assert_eq!(e.error.kind(), io::ErrorKind::AlreadyExists);
    drop(e);
    let e = refused(&mut ring, op(8, file.read_write(), fresh(), 0, read));
    assert_eq!(e.error.kind(), io::ErrorKind::WouldBlock);
    drop(e);
    // The ring holds the charge of the buffer in flight.
    assert_eq!(scope.snapshot().managed_memory, 4);
    let c = complete(&mut ring);
    assert_eq!((c.user_data, *c.result.as_ref().unwrap()), (7, 4));
    assert_eq!(&c.buffer[..], b"abcd");
    assert_eq!(scope.snapshot().managed_memory, 4);
    drop(c);
    assert_eq!(scope.snapshot().managed_memory, 0);
  }

  #[test]
  fn deferred_submissions_are_retried_without_rewriting() {
    let Some(mut ring) = ring(4) else { return };
    let file = TempFile::new(b"abcdefgh");
    let scope = scope(64);
    let read = |user_data, offset| {
      op(
        user_data,
        file.read_write(),
        scope.try_alloc_zeroed(4).unwrap(),
        offset,
        OperationKind::ReadAt,
      )
    };
    // The kernel defers the first submission: A stays in the SQ.
    let a = ring.sq_tail;
    inject(Fault::SubmitError(Errno::AGAIN));
    ring.publish(read(1, 0)).unwrap();
    assert_eq!(ring.outstanding(), 1);
    let sqe_a = ring.sqe_at(a);
    assert_eq!(sqe_a.user_data, ring.key_of(1));
    assert_eq!(
      (sqe_a.opcode, sqe_a.flags, sqe_a.len),
      (IORING_OP_READ, 0, 4)
    );
    // B's submission is short: the kernel takes A, the oldest, only.
    let b = ring.sq_tail;
    inject(Fault::SubmitLimit(1));
    ring.publish(read(2, 4)).unwrap();
    assert_eq!(ring.outstanding(), 1);
    assert_eq!(ring.sqe_at(a), sqe_a, "a consumed SQE is not rewritten");
    let sqe_b = ring.sqe_at(b);
    assert_eq!(sqe_b.user_data, ring.key_of(2));
    // Completions retry B's submission unchanged; each completes once.
    let mut results = Vec::new();
    for _ in 0..2 {
      if ring.outstanding() == 1 {
        assert_eq!(ring.sqe_at(b), sqe_b, "an outstanding SQE is not rewritten");
      }
      let c = complete(&mut ring);
      results.push((c.user_data, c.result.unwrap(), c.buffer.to_vec()));
    }
    results.sort_unstable();
    assert_eq!(
      results,
      [(1, 4, b"abcd".to_vec()), (2, 4, b"efgh".to_vec())]
    );
    assert_eq!((ring.sq_tail, ring.sq_head()), (b + 1, b + 1));
    assert!(ring.poll_completion().is_none());
    assert!(ring.wait_with_timeout(Duration::from_millis(10)).is_none());
  }

  #[test]
  fn waits_return_at_once_when_idle() {
    let Some(mut ring) = ring(2) else { return };
    let t = Instant::now();
    assert!(ring.wait_with_timeout(Duration::from_secs(30)).is_none());
    assert!(ring.poll_completion().is_none());
    assert!(t.elapsed() < Duration::from_secs(5));
  }

  #[test]
  fn kernel_layout_is_accepted_as_reported() {
    let Some(ring) = ring(MAX_DEPTH) else { return };
    let l = ring.layout;
    assert_eq!(l.sq_entries, MAX_DEPTH);
    assert!(l.cq_entries >= MAX_DEPTH);
    assert_eq!(l.sqes_len, MAX_DEPTH as usize * 64);
  }

  // Fail-stop paths run in child processes, which must abort.

  /// Runs `mode` in a child and expects it to abort with `message`.
  fn expect_abort(mode: &str, message: &str) {
    // The parent owns the fixture because SIGABRT skips child destructors.
    let file = TempFile::new(b"abcdefgh");
    let file_path = file.0.clone();
    let test = module_path!()
      .strip_prefix("allocatbelt::")
      .unwrap_or(module_path!());
    let mut child = Command::new(std::env::current_exe().unwrap())
      .args([
        "--exact",
        &std::format!("{test}::child_helper_entrypoint"),
        "--nocapture",
        "--test-threads=1",
      ])
      .env(CHILD_ENV, mode)
      .env(CHILD_FILE_ENV, &file.0)
      .stdout(Stdio::null())
      .stderr(Stdio::piped())
      .spawn()
      .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
      if let Some(status) = child.try_wait().unwrap() {
        break status;
      }
      if Instant::now() > deadline {
        let _ = child.kill();
        let _ = child.wait();
        panic!("{mode}: child did not finish");
      }
      std::thread::sleep(Duration::from_millis(10));
    };
    let mut stderr = String::new();
    child
      .stderr
      .take()
      .unwrap()
      .read_to_string(&mut stderr)
      .unwrap();
    if status.code() == Some(UNAVAILABLE) {
      not_run(&std::format!("fail-stop child {mode}"), &stderr.trim());
      drop(file);
      assert_temp_file_absent(&file_path);
      return;
    }
    assert_eq!(
      status.signal(),
      Some(libc::SIGABRT),
      "{mode}: {status}\n{stderr}"
    );
    assert!(!status.core_dumped(), "{mode}: core dumps are disabled");
    assert!(
      stderr.contains(&std::format!("fail-stop: {message}")),
      "{mode}: {stderr}"
    );
    drop(file);
    assert_temp_file_absent(&file_path);
  }

  /// The child side of [`expect_abort`]; a no-op unless `CHILD_ENV` is set.
  #[test]
  fn child_helper_entrypoint() {
    let Ok(mode) = std::env::var(CHILD_ENV) else {
      return;
    };
    // No core dump: a zero limit, and not dumpable at all, because a piped
    // `core_pattern` (systemd-coredump) ignores the limit.
    let no_core = Rlimit {
      current: Some(0),
      maximum: Some(0),
    };
    setrlimit(Resource::Core, no_core).unwrap();
    set_dumpable_behavior(DumpableBehavior::NotDumpable).unwrap();
    let mut ring = match RuntimeRing::new(2) {
      Ok(ring) => ring,
      Err(e) => {
        std::eprintln!("{e}");
        std::process::exit(if denied(&e) { UNAVAILABLE } else { 1 });
      }
    };
    // This borrowed pathname must not install a child-side unlink guard.
    let file_path = PathBuf::from(
      std::env::var_os(CHILD_FILE_ENV).expect("parent abort harness must supply its file path"),
    );
    let scope = scope(64);
    let read = |user_data| {
      op(
        user_data,
        open_read_write(&file_path),
        scope.try_alloc_zeroed(4).unwrap(),
        0,
        OperationKind::ReadAt,
      )
    };
    let forged = |user_data, res, flags| Cqe {
      user_data,
      res,
      flags,
    };
    match mode.as_str() {
      "pending-drop" => {
        ring.publish(read(1)).unwrap();
        drop(ring);
      }
      "unwind-after-occupy" => {
        inject(Fault::PanicAfterOccupy);
        let _ = ring.publish(read(1));
      }
      "unwind-after-tail" => {
        inject(Fault::PanicAfterTail);
        let _ = ring.publish(read(1));
      }
      "unwind-holding-ring" => {
        ring.publish(read(1)).unwrap();
        panic!("unwinding with an operation in flight");
      }
      "fatal-submit" => {
        inject(Fault::SubmitError(Errno::INVAL));
        let _ = ring.publish(read(1));
      }
      "unknown-cqe" => {
        ring.accept(forged(key(1, 3), 0, 0));
      }
      "duplicate-cqe" => {
        ring.publish(read(1)).unwrap();
        // The kernel has posted its CQE, so the forged copy only returns
        // owners the kernel no longer uses; the real one is then extra.
        let real = ring.wait_posted();
        let copy = ring.accept(real);
        assert_eq!(copy.result.unwrap(), 4);
        let _ = ring.poll_completion();
      }
      "duplicate-cqe-reused-slot" => {
        ring.publish(read(1)).unwrap();
        let real = ring.wait_posted();
        ring.accept(real);
        // The slot is reused by an operation the kernel has not consumed,
        // so the real CQE is the only one and carries the old generation.
        inject(Fault::SubmitError(Errno::AGAIN));
        ring.publish(read(2)).unwrap();
        let _ = ring.poll_completion();
      }
      "stale-cqe" => {
        ring.publish(read(1)).unwrap();
        let old = ring.key_of(1);
        complete(&mut ring);
        ring.publish(read(2)).unwrap();
        ring.wait_posted();
        ring.accept(forged(old, 0, 0));
      }
      "unconsumed-cqe" => {
        inject(Fault::SubmitError(Errno::AGAIN));
        ring.publish(read(1)).unwrap();
        let k = ring.key_of(1);
        ring.accept(forged(k, 0, 0));
      }
      "long-result" | "errno-out-of-range" | "minimum-result" | "cqe-flags" => {
        ring.publish(read(1)).unwrap();
        ring.wait_posted();
        let k = ring.key_of(1);
        let (res, flags) = match mode.as_str() {
          "long-result" => (5, 0),
          "errno-out-of-range" => (-4096, 0),
          "minimum-result" => (i32::MIN, 0),
          _ => (4, 1),
        };
        ring.accept(forged(k, res, flags));
      }
      "cq-overflow" => {
        ring.publish(read(1)).unwrap();
        ring.wait_posted();
        ring
          .word(ring.layout.cq_overflow)
          .store(1, Ordering::Release);
        let _ = ring.poll_completion();
      }
      "sq-dropped" => {
        ring
          .word(ring.layout.sq_dropped)
          .store(1, Ordering::Release);
        let _ = ring.poll_completion();
      }
      "extra-cqe" => {
        // Nothing was ever published, so no kernel write can follow.
        let tail = ring.word(ring.layout.cq_tail);
        tail.store(
          tail.load(Ordering::Acquire).wrapping_add(1),
          Ordering::Release,
        );
        let _ = ring.wait_with_timeout(Duration::ZERO);
      }
      "sq-head-ahead" => {
        let head = ring.word(ring.layout.sq_head);
        head.store(
          head.load(Ordering::Acquire).wrapping_add(1),
          Ordering::Release,
        );
        let _ = ring.publish(read(1));
      }
      "forked-use" => {
        ring.pid = Pid::from_raw(1).unwrap();
        let _ = ring.poll_completion();
      }
      other => panic!("unknown child mode {other}"),
    }
    std::eprintln!("child mode {mode} did not abort");
    std::process::exit(2);
  }

  #[test]
  fn dropping_a_ring_in_flight_aborts() {
    expect_abort(
      "pending-drop",
      "runtime io_uring dropped with operations in flight",
    );
  }

  #[test]
  fn unwinding_through_publication_aborts() {
    let msg = "unwind while publishing a runtime io_uring operation";
    expect_abort("unwind-after-occupy", msg);
    expect_abort("unwind-after-tail", msg);
    expect_abort(
      "unwind-holding-ring",
      "runtime io_uring dropped with operations in flight",
    );
  }

  #[test]
  fn an_unretryable_submission_error_aborts() {
    expect_abort("fatal-submit", "injected fatal submission error");
  }

  #[test]
  fn unknown_duplicate_and_stale_completions_abort() {
    let stale = "CQE with a stale generation (duplicate completion)";
    expect_abort(
      "unknown-cqe",
      "CQE for an idle slot (unknown or duplicate completion)",
    );
    expect_abort("duplicate-cqe", "more CQEs than operations in flight");
    expect_abort("duplicate-cqe-reused-slot", stale);
    expect_abort("stale-cqe", stale);
    expect_abort(
      "unconsumed-cqe",
      "CQE for an SQE the kernel has not consumed",
    );
  }

  #[test]
  fn malformed_completions_abort() {
    for mode in ["long-result", "errno-out-of-range", "minimum-result"] {
      expect_abort(mode, "malformed CQE result");
    }
    expect_abort("cqe-flags", "unexpected CQE flags");
  }

  #[test]
  fn queue_anomalies_abort() {
    let lost = "io_uring CQ overflow or dropped SQE";
    expect_abort("cq-overflow", lost);
    expect_abort("sq-dropped", lost);
    expect_abort("extra-cqe", "more CQEs than operations in flight");
    expect_abort("sq-head-ahead", "SQ head outside the published range");
  }

  #[test]
  fn use_from_another_process_aborts() {
    expect_abort(
      "forked-use",
      "runtime io_uring used outside the process that created it",
    );
  }
}
