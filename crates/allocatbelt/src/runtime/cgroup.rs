//! Explicit controls for a caller-supplied delegated Linux cgroup v2 group.
//!
//! This module accepts an already-open group-directory descriptor as its
//! capability. It never discovers, mounts, or changes a host cgroup root, and
//! it never attaches a process. The caller is responsible for supplying an
//! isolated group delegated for these controls. The kernel decides whether
//! the descriptor has permission to open and write each control.
//!
//! Every control name is fixed and opened relative to the supplied directory
//! with `O_NOFOLLOW | O_CLOEXEC`. Requests are checked against caller-provided
//! finite ceilings before any write. Each setter is a separate kernel side
//! effect followed by bounded readback. The controls are not transactional:
//! if a later write or readback fails, earlier writes remain applied and the
//! typed error reports progress plus any state that could be read. This
//! module does not automatically restore earlier values.
//!
//! Control data and descriptors are kernel/caller resources, outside the
//! [`ManagedBuf`](crate::runtime::managed::ManagedBuf) ledger. No cgroup
//! controls are changed by the parser and validation tests.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt::{self, Write as _};
use std::io;
use std::num::NonZeroU64;

use rustix::fd::OwnedFd;
use rustix::fs::{FileType, OFlags, fstat, fstatfs, openat};
use rustix::io::{read, write};

const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
/// Maximum number of distinct device entries retained from `io.max`.
pub const MAX_IO_DEVICES: usize = 16;
/// Maximum bytes read from any cgroup control file.
pub const MAX_CONTROL_BYTES: usize = 4096;
const MAX_IO_LINE: usize = 256;
const IO_RETRIES: usize = 64;
const MIN_CPU_QUOTA_US: u64 = 1_000;
const MAX_CPU_QUOTA_US: u64 = (1 << 44) - 1;
const MIN_CPU_PERIOD_US: u64 = 1_000;
const MAX_CPU_PERIOD_US: u64 = 1_000_000;
const MAX_DEVICE_MAJOR: u32 = (1 << 12) - 1;
const MAX_DEVICE_MINOR: u32 = (1 << 20) - 1;

/// A finite CPU quota and period for `cpu.max`, in microseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuMax {
  quota_us: NonZeroU64,
  period_us: NonZeroU64,
}

impl CpuMax {
  /// Creates a quota/period pair. The pair remains inert until used as a
  /// ceiling or applied; those paths reject values outside Linux v7.0's
  /// finite quota and period ranges before any control write.
  pub const fn new(quota_us: NonZeroU64, period_us: NonZeroU64) -> Self {
    Self {
      quota_us,
      period_us,
    }
  }

  /// The finite quota in microseconds.
  #[must_use]
  pub const fn quota_us(self) -> u64 {
    self.quota_us.get()
  }

  /// The nonzero period in microseconds.
  #[must_use]
  pub const fn period_us(self) -> u64 {
    self.period_us.get()
  }

  fn within(self, ceiling: Self) -> bool {
    u128::from(self.quota_us.get()) * u128::from(ceiling.period_us.get())
      <= u128::from(ceiling.quota_us.get()) * u128::from(self.period_us.get())
  }
}

/// Why a finite `cpu.max` quota/period pair is outside Linux v7.0 limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuLimitError {
  /// The quota is below the kernel minimum.
  QuotaTooLow,
  /// The quota exceeds the kernel maximum.
  QuotaTooHigh,
  /// `u64::MAX` is the kernel's unlimited quota sentinel.
  UnlimitedQuota,
  /// The period is below the kernel minimum.
  PeriodTooShort,
  /// The period exceeds the kernel maximum.
  PeriodTooLong,
}

fn validate_cpu_max(value: CpuMax) -> Result<(), CpuLimitError> {
  let quota = value.quota_us();
  if quota == u64::MAX {
    return Err(CpuLimitError::UnlimitedQuota);
  }
  if quota < MIN_CPU_QUOTA_US {
    return Err(CpuLimitError::QuotaTooLow);
  }
  if quota > MAX_CPU_QUOTA_US {
    return Err(CpuLimitError::QuotaTooHigh);
  }
  let period = value.period_us();
  if period < MIN_CPU_PERIOD_US {
    return Err(CpuLimitError::PeriodTooShort);
  }
  if period > MAX_CPU_PERIOD_US {
    return Err(CpuLimitError::PeriodTooLong);
  }
  Ok(())
}

/// A block-device identity used by cgroup v2 `io.max`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DeviceId {
  /// Linux block-device major number.
  pub major: u32,
  /// Linux block-device minor number.
  pub minor: u32,
}

/// Why a block-device identity cannot be represented without `MKDEV` aliasing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceIdError {
  /// Major exceeds the 12-bit Linux `dev_t` major field.
  MajorOutOfRange,
  /// Minor exceeds the 20-bit Linux `dev_t` minor field.
  MinorOutOfRange,
}

fn validate_device_id(device: DeviceId) -> Result<(), DeviceIdError> {
  if device.major > MAX_DEVICE_MAJOR {
    Err(DeviceIdError::MajorOutOfRange)
  } else if device.minor > MAX_DEVICE_MINOR {
    Err(DeviceIdError::MinorOutOfRange)
  } else {
    Ok(())
  }
}

/// Four finite per-device I/O limits for `io.max`.
///
/// Zero and numeric values reserved by the kernel for unlimited (`u64::MAX`
/// for byte rates and `u32::MAX` or greater for operation rates) are rejected
/// by [`CgroupCeilings::add_io_device`] and [`CgroupV2::set_io_max`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoMax {
  /// Device to which this record applies.
  pub device: DeviceId,
  /// Maximum bytes read per second.
  pub read_bytes_per_second: u64,
  /// Maximum bytes written per second.
  pub write_bytes_per_second: u64,
  /// Maximum read operations per second.
  pub read_ios_per_second: u64,
  /// Maximum write operations per second.
  pub write_ios_per_second: u64,
}

fn invalid_io_limit(item: IoMax) -> Option<(IoRateField, IoLimitError)> {
  [
    (
      IoRateField::ReadBytesPerSecond,
      item.read_bytes_per_second,
      u64::MAX,
    ),
    (
      IoRateField::WriteBytesPerSecond,
      item.write_bytes_per_second,
      u64::MAX,
    ),
    (
      IoRateField::ReadIosPerSecond,
      item.read_ios_per_second,
      u64::from(u32::MAX),
    ),
    (
      IoRateField::WriteIosPerSecond,
      item.write_ios_per_second,
      u64::from(u32::MAX),
    ),
  ]
  .into_iter()
  .find_map(|(field, value, sentinel)| {
    if value == 0 {
      Some((field, IoLimitError::Zero))
    } else if value >= sentinel {
      Some((field, IoLimitError::UnlimitedSentinel))
    } else {
      None
    }
  })
}

fn memory_limit_aligned(bytes: u64) -> bool {
  let page_size = rustix::param::page_size() as u64;
  bytes.is_multiple_of(page_size)
}

fn memory_unlimited_sentinel() -> u64 {
  let page_size = rustix::param::page_size() as u64;
  let page_counter_max = if usize::BITS == 32 {
    isize::MAX as u64
  } else {
    isize::MAX as u64 / page_size
  };
  page_counter_max * page_size
}

fn memory_limit_error(bytes: u64) -> Option<MemoryLimitError> {
  if !memory_limit_aligned(bytes) {
    Some(MemoryLimitError::Unaligned)
  } else if bytes >= memory_unlimited_sentinel() {
    Some(MemoryLimitError::UnlimitedSentinel)
  } else {
    None
  }
}

/// Fixed caller ceilings for all accepted controls.
///
/// CPU ceilings compare quota/period as a rational value, so lowering a
/// request's period cannot accidentally exceed the permitted CPU fraction.
/// I/O ceilings contain at most [`MAX_IO_DEVICES`] distinct device records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CgroupCeilings {
  cpu_max: CpuMax,
  memory_high_bytes: u64,
  memory_max_bytes: u64,
  io_max: [Option<IoMax>; MAX_IO_DEVICES],
  io_max_len: usize,
}

impl CgroupCeilings {
  /// Creates ceilings for CPU and memory. I/O ceilings may be added with
  /// [`CgroupCeilings::add_io_device`].
  #[must_use]
  pub const fn new(cpu_max: CpuMax, memory_high_bytes: u64, memory_max_bytes: u64) -> Self {
    Self {
      cpu_max,
      memory_high_bytes,
      memory_max_bytes,
      io_max: [None; MAX_IO_DEVICES],
      io_max_len: 0,
    }
  }

  /// Adds one finite device ceiling. Duplicate devices and excess entries
  /// are rejected without changing this value.
  pub fn add_io_device(&mut self, ceiling: IoMax) -> Result<(), CeilingError> {
    if let Err(error) = validate_device_id(ceiling.device) {
      return Err(CeilingError::InvalidDevice(ceiling.device, error));
    }
    if let Some((field, error)) = invalid_io_limit(ceiling) {
      return Err(CeilingError::InvalidIoLimit(field, error));
    }
    if self.io_max[..self.io_max_len]
      .iter()
      .flatten()
      .any(|existing| existing.device == ceiling.device)
    {
      return Err(CeilingError::DuplicateDevice(ceiling.device));
    }
    if self.io_max_len == MAX_IO_DEVICES {
      return Err(CeilingError::TooManyDevices);
    }
    self.io_max[self.io_max_len] = Some(ceiling);
    self.io_max_len += 1;
    Ok(())
  }

  fn io_ceiling(&self, device: DeviceId) -> Option<IoMax> {
    self.io_max[..self.io_max_len]
      .iter()
      .flatten()
      .find(|entry| entry.device == device)
      .copied()
  }
}

/// Why a fixed I/O ceiling table rejected an entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeilingError {
  /// The finite CPU ceiling is outside the supported kernel range.
  InvalidCpuLimit(CpuLimitError),
  /// A memory ceiling is unaligned or maps to the kernel unlimited sentinel.
  InvalidMemoryLimit(MemoryField, MemoryLimitError),
  /// The configured I/O device identity exceeds the kernel's `dev_t` fields.
  InvalidDevice(DeviceId, DeviceIdError),
  /// The device already has a ceiling.
  DuplicateDevice(DeviceId),
  /// The fixed table has no free entry.
  TooManyDevices,
  /// A purported finite I/O ceiling is zero or uses a kernel unlimited sentinel.
  InvalidIoLimit(IoRateField, IoLimitError),
}

impl fmt::Display for CeilingError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::DuplicateDevice(device) => {
        write!(
          f,
          "duplicate I/O ceiling for {}:{}",
          device.major, device.minor
        )
      }
      Self::TooManyDevices => f.write_str("too many I/O device ceilings"),
      Self::InvalidCpuLimit(error) => write!(f, "invalid finite CPU ceiling: {error:?}"),
      Self::InvalidMemoryLimit(field, error) => {
        write!(f, "invalid finite {field:?} memory ceiling: {error:?}")
      }
      Self::InvalidDevice(device, error) => write!(
        f,
        "invalid I/O ceiling device {}:{}: {error:?}",
        device.major, device.minor
      ),
      Self::InvalidIoLimit(field, error) => {
        write!(f, "invalid finite {field:?} ceiling: {error:?}")
      }
    }
  }
}

impl std::error::Error for CeilingError {}

/// Why the supplied directory descriptor could not be accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CgroupOpenErrorKind {
  /// The descriptor does not refer to a directory.
  NotDirectory,
  /// The descriptor is not on a cgroup v2 filesystem.
  WrongFilesystem,
  /// `fstat` or `fstatfs` failed.
  Stat(CgroupIoError),
  /// The caller-supplied finite CPU ceiling is outside the supported range.
  InvalidCeiling(CeilingError),
}

/// Rejection of a cgroup directory, retaining the caller's descriptor.
pub struct CgroupOpenError {
  kind: CgroupOpenErrorKind,
  directory: OwnedFd,
}

impl CgroupOpenError {
  /// Returns the reason the directory was rejected.
  #[must_use]
  pub const fn kind(&self) -> CgroupOpenErrorKind {
    self.kind
  }

  /// Returns the original descriptor.
  #[must_use]
  pub fn into_directory(self) -> OwnedFd {
    self.directory
  }
}

impl fmt::Debug for CgroupOpenError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("CgroupOpenError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl fmt::Display for CgroupOpenError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self.kind {
      CgroupOpenErrorKind::NotDirectory => "cgroup descriptor is not a directory",
      CgroupOpenErrorKind::WrongFilesystem => "directory is not on cgroup v2",
      CgroupOpenErrorKind::Stat(_) => "could not inspect cgroup directory descriptor",
      CgroupOpenErrorKind::InvalidCeiling(_) => "cgroup ceiling is outside the supported range",
    })
  }
}

impl std::error::Error for CgroupOpenError {}

/// A finite or kernel-reported unlimited cgroup value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Limit {
  /// A finite kernel value.
  Value(u64),
  /// The kernel reports `max`.
  Max,
}

/// Kernel-reported CPU quota and period.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuMaxReadback {
  /// Finite quota, or [`Limit::Max`].
  pub quota_us: Limit,
  /// Kernel-reported nonzero period.
  pub period_us: u64,
}

/// Kernel-reported `io.max` entry. The kernel may report an individual rate
/// as [`Limit::Max`] even though setters accept only finite values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoMaxReadback {
  /// Device identity.
  pub device: DeviceId,
  /// Maximum read bytes per second or unlimited.
  pub read_bytes_per_second: Limit,
  /// Maximum write bytes per second or unlimited.
  pub write_bytes_per_second: Limit,
  /// Maximum read operations per second or unlimited.
  pub read_ios_per_second: Limit,
  /// Maximum write operations per second or unlimited.
  pub write_ios_per_second: Limit,
}

/// Bounded readback of supported cgroup controls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CgroupSnapshot {
  /// Current CPU quota and period.
  pub cpu_max: CpuMaxReadback,
  /// Current `memory.high`, including an unlimited kernel default.
  pub memory_high: Limit,
  /// Current `memory.max`, including an unlimited kernel default.
  pub memory_max: Limit,
  /// Fixed table of all parsed `io.max` device entries.
  pub io_max: [Option<IoMaxReadback>; MAX_IO_DEVICES],
  /// Number of populated `io_max` entries.
  pub io_max_len: usize,
}

/// Which fixed cgroup control failed to read or verify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
  /// `cpu.max`.
  CpuMax,
  /// `memory.high`.
  MemoryHigh,
  /// `memory.max`.
  MemoryMax,
  /// `io.max`.
  IoMax,
}

/// A portable summary of an operating-system I/O error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CgroupIoError {
  /// Standard error category.
  pub kind: io::ErrorKind,
  /// Raw Linux error number when available.
  pub raw_os_error: Option<i32>,
}

impl From<io::Error> for CgroupIoError {
  fn from(error: io::Error) -> Self {
    Self {
      kind: error.kind(),
      raw_os_error: error.raw_os_error(),
    }
  }
}

/// Why bounded readback failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadFailure {
  /// Opening or reading a fixed control failed.
  Io(CgroupIoError),
  /// A control exceeded [`MAX_CONTROL_BYTES`].
  TooLarge,
  /// A control contained invalid UTF-8, syntax, number, or unsupported key.
  InvalidFormat,
  /// An `io.max` file had a duplicate device or too many entries.
  InvalidDevices,
}

/// A failed read of a fixed cgroup control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CgroupReadError {
  /// Control being read when parsing or I/O failed.
  pub control: Control,
  /// Bounded failure reason.
  pub failure: ReadFailure,
}

impl fmt::Display for CgroupReadError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "could not read {:?}: {:?}", self.control, self.failure)
  }
}

impl std::error::Error for CgroupReadError {}

/// Why a cgroup write or readback verification failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyFailure {
  /// Opening or writing the control failed, often because the kernel denied
  /// delegated permission or rejected the numeric range.
  Io(CgroupIoError),
  /// The control accepted only part of the single fixed write.
  ShortWrite,
  /// Bounded post-write readback failed.
  Readback(CgroupReadError),
  /// The kernel's parsed value differed from the finite request.
  Mismatch,
  /// A request exceeded its caller-provided ceiling, named an unknown device,
  /// or repeated a device. This is rejected before changing the kernel.
  Rejected(RejectReason),
  /// Existing plus requested `io.max` devices exceed the fixed table bound.
  TooManyDevices,
}

/// Why a request was rejected before a kernel write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
  /// Requested finite values exceeded the caller's configured ceiling.
  AboveCeiling,
  /// An I/O device did not have a configured caller ceiling.
  UnknownDevice,
  /// An I/O request repeated a device in the same call.
  DuplicateDevice,
  /// Memory values must be aligned to the host kernel page size.
  UnalignedMemory,
  /// Finite I/O limit was zero, which the kernel rejects with ERANGE.
  ZeroIoLimit(IoRateField),
  /// Value aliases the kernel's unlimited `io.max` sentinel.
  IoUnlimitedSentinel(IoRateField),
  /// A CPU request is outside the supported finite range.
  InvalidCpuLimit(CpuLimitError),
  /// The configured CPU ceiling is outside the supported finite range.
  InvalidCpuCeiling(CpuLimitError),
  /// A memory request is unaligned or maps to the kernel unlimited sentinel.
  InvalidMemoryLimit(MemoryLimitError),
  /// A configured memory ceiling is unaligned or maps to the unlimited sentinel.
  InvalidMemoryCeiling(MemoryField, MemoryLimitError),
  /// An I/O device identity exceeds the kernel's `dev_t` fields.
  InvalidDevice(DeviceId, DeviceIdError),
}

/// One finite numeric field in a cgroup v2 `io.max` record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoRateField {
  /// `rbps`.
  ReadBytesPerSecond,
  /// `wbps`.
  WriteBytesPerSecond,
  /// `riops`.
  ReadIosPerSecond,
  /// `wiops`.
  WriteIosPerSecond,
}

/// Why an `io.max` rate cannot represent a finite limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoLimitError {
  /// The kernel rejects zero rates.
  Zero,
  /// The kernel interprets this numeric value as unlimited.
  UnlimitedSentinel,
}

/// Which finite memory control is being configured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryField {
  /// `memory.high`.
  High,
  /// `memory.max`.
  Max,
}

/// Why a finite memory limit cannot be represented without kernel rounding or
/// becoming the kernel's unlimited page-counter sentinel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryLimitError {
  /// Memory controls accept whole host pages only for this finite API.
  Unaligned,
  /// The value saturates to `PAGE_COUNTER_MAX`, which is reported as `max`.
  UnlimitedSentinel,
}

/// Fixed-size copy of the request associated with a failed application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CgroupRequest {
  /// Requested finite CPU quota and period, for a CPU update.
  pub cpu_max: Option<CpuMax>,
  /// Requested finite memory bytes, for a memory update.
  pub memory_bytes: Option<u64>,
  /// First bounded set of requested I/O entries.
  pub io_max: [Option<IoMax>; MAX_IO_DEVICES],
  /// Number of entries copied into `io_max`.
  pub io_copied: usize,
  /// Number of entries in the original I/O request.
  pub io_requested: usize,
}

impl CgroupRequest {
  fn cpu(value: CpuMax) -> Self {
    Self {
      cpu_max: Some(value),
      memory_bytes: None,
      io_max: [None; MAX_IO_DEVICES],
      io_copied: 0,
      io_requested: 0,
    }
  }

  fn memory(value: u64) -> Self {
    Self {
      cpu_max: None,
      memory_bytes: Some(value),
      io_max: [None; MAX_IO_DEVICES],
      io_copied: 0,
      io_requested: 0,
    }
  }

  fn io(entries: &[IoMax]) -> Self {
    let mut io_max = [None; MAX_IO_DEVICES];
    let io_copied = entries.len().min(MAX_IO_DEVICES);
    for (destination, source) in io_max.iter_mut().zip(entries.iter()).take(io_copied) {
      *destination = Some(*source);
    }
    Self {
      cpu_max: None,
      memory_bytes: None,
      io_max,
      io_copied,
      io_requested: entries.len(),
    }
  }
}

/// A nontransactional failed control update with exact accepted-entry
/// progress and any post-failure state that could be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CgroupApplyError {
  /// Control being applied.
  pub control: Control,
  /// Fixed-size metadata for the original request.
  pub requested: CgroupRequest,
  /// Failure category.
  pub failure: ApplyFailure,
  /// Number of `io.max` records whose writes completed before failure.
  pub io_entries_written: usize,
  /// Snapshot read after a write failure or mismatch, if bounded readback
  /// succeeded. `None` means the state is unknown, not rolled back.
  pub observed: Option<CgroupSnapshot>,
}

impl fmt::Display for CgroupApplyError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "failed to apply {:?}: {:?}", self.control, self.failure)
  }
}

impl std::error::Error for CgroupApplyError {}

/// Caller-owned capability for a delegated cgroup v2 group directory.
pub struct CgroupV2 {
  directory: OwnedFd,
  ceilings: CgroupCeilings,
}

impl fmt::Debug for CgroupV2 {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("CgroupV2")
      .field("ceilings", &self.ceilings)
      .finish_non_exhaustive()
  }
}

impl CgroupV2 {
  /// Takes and validates an already-open cgroup v2 group directory.
  ///
  /// This checks directory type, filesystem magic, and configured finite
  /// ceiling ranges. It cannot prove that the group is isolated or delegated
  /// for every requested control; the caller supplies that authority, and the
  /// kernel validates permission when a control is opened or written. On
  /// rejection, the original descriptor is returned.
  pub fn open(directory: OwnedFd, ceilings: CgroupCeilings) -> Result<Self, CgroupOpenError> {
    if let Err(error) = validate_cpu_max(ceilings.cpu_max) {
      return Err(CgroupOpenError {
        kind: CgroupOpenErrorKind::InvalidCeiling(CeilingError::InvalidCpuLimit(error)),
        directory,
      });
    }
    for (field, bytes) in [
      (MemoryField::High, ceilings.memory_high_bytes),
      (MemoryField::Max, ceilings.memory_max_bytes),
    ] {
      if let Some(error) = memory_limit_error(bytes) {
        return Err(CgroupOpenError {
          kind: CgroupOpenErrorKind::InvalidCeiling(CeilingError::InvalidMemoryLimit(field, error)),
          directory,
        });
      }
    }
    let metadata = match fstat(&directory) {
      Ok(metadata) => metadata,
      Err(error) => {
        return Err(CgroupOpenError {
          kind: CgroupOpenErrorKind::Stat(io::Error::from(error).into()),
          directory,
        });
      }
    };
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
      return Err(CgroupOpenError {
        kind: CgroupOpenErrorKind::NotDirectory,
        directory,
      });
    }
    let filesystem = match fstatfs(&directory) {
      Ok(filesystem) => filesystem,
      Err(error) => {
        return Err(CgroupOpenError {
          kind: CgroupOpenErrorKind::Stat(io::Error::from(error).into()),
          directory,
        });
      }
    };
    if filesystem.f_type as u64 != CGROUP2_SUPER_MAGIC {
      return Err(CgroupOpenError {
        kind: CgroupOpenErrorKind::WrongFilesystem,
        directory,
      });
    }
    Ok(Self {
      directory,
      ceilings,
    })
  }

  /// Returns the fixed caller ceilings.
  #[must_use]
  pub const fn ceilings(&self) -> &CgroupCeilings {
    &self.ceilings
  }

  /// Reads all supported controls into fixed bounded storage.
  pub fn readback(&self) -> Result<CgroupSnapshot, CgroupReadError> {
    let cpu = read_control(&self.directory, "cpu.max", Control::CpuMax)?;
    let memory_high = read_control(&self.directory, "memory.high", Control::MemoryHigh)?;
    let memory_max = read_control(&self.directory, "memory.max", Control::MemoryMax)?;
    let io_max = read_control(&self.directory, "io.max", Control::IoMax)?;
    let cpu_max = parse_cpu_max(&cpu).map_err(|failure| CgroupReadError {
      control: Control::CpuMax,
      failure,
    })?;
    let memory_high = parse_limit(&memory_high).map_err(|failure| CgroupReadError {
      control: Control::MemoryHigh,
      failure,
    })?;
    let memory_max = parse_limit(&memory_max).map_err(|failure| CgroupReadError {
      control: Control::MemoryMax,
      failure,
    })?;
    let (io_max, io_max_len) = parse_io_max(&io_max).map_err(|failure| CgroupReadError {
      control: Control::IoMax,
      failure,
    })?;
    Ok(CgroupSnapshot {
      cpu_max,
      memory_high,
      memory_max,
      io_max,
      io_max_len,
    })
  }

  /// Applies a finite CPU quota within the fixed rational CPU ceiling.
  pub fn set_cpu_max(&self, requested: CpuMax) -> Result<CgroupSnapshot, CgroupApplyError> {
    let request = CgroupRequest::cpu(requested);
    if let Err(error) = validate_cpu_max(self.ceilings.cpu_max) {
      return Err(rejected(
        Control::CpuMax,
        request,
        RejectReason::InvalidCpuCeiling(error),
      ));
    }
    if let Err(error) = validate_cpu_max(requested) {
      return Err(rejected(
        Control::CpuMax,
        request,
        RejectReason::InvalidCpuLimit(error),
      ));
    }
    if !requested.within(self.ceilings.cpu_max) {
      return Err(rejected(
        Control::CpuMax,
        request,
        RejectReason::AboveCeiling,
      ));
    }
    let mut text = [0u8; 64];
    let mut writer = FixedWriter::new(&mut text);
    let _ = writeln!(writer, "{} {}", requested.quota_us(), requested.period_us());
    self.apply_one(
      Control::CpuMax,
      request,
      "cpu.max",
      writer.as_bytes(),
      |snapshot| {
        snapshot.cpu_max
          == CpuMaxReadback {
            quota_us: Limit::Value(requested.quota_us()),
            period_us: requested.period_us(),
          }
      },
    )
  }

  /// Applies finite, host-page-aligned `memory.high` within its caller ceiling.
  pub fn set_memory_high(&self, requested: u64) -> Result<CgroupSnapshot, CgroupApplyError> {
    if let Some(error) = memory_limit_error(self.ceilings.memory_high_bytes) {
      return Err(rejected(
        Control::MemoryHigh,
        CgroupRequest::memory(requested),
        RejectReason::InvalidMemoryCeiling(MemoryField::High, error),
      ));
    }
    if let Some(error) = memory_limit_error(requested) {
      return Err(rejected(
        Control::MemoryHigh,
        CgroupRequest::memory(requested),
        RejectReason::InvalidMemoryLimit(error),
      ));
    }
    if requested > self.ceilings.memory_high_bytes {
      return Err(rejected(
        Control::MemoryHigh,
        CgroupRequest::memory(requested),
        RejectReason::AboveCeiling,
      ));
    }
    self.apply_memory(Control::MemoryHigh, "memory.high", requested)
  }

  /// Applies finite, host-page-aligned `memory.max` within its caller ceiling.
  pub fn set_memory_max(&self, requested: u64) -> Result<CgroupSnapshot, CgroupApplyError> {
    if let Some(error) = memory_limit_error(self.ceilings.memory_max_bytes) {
      return Err(rejected(
        Control::MemoryMax,
        CgroupRequest::memory(requested),
        RejectReason::InvalidMemoryCeiling(MemoryField::Max, error),
      ));
    }
    if let Some(error) = memory_limit_error(requested) {
      return Err(rejected(
        Control::MemoryMax,
        CgroupRequest::memory(requested),
        RejectReason::InvalidMemoryLimit(error),
      ));
    }
    if requested > self.ceilings.memory_max_bytes {
      return Err(rejected(
        Control::MemoryMax,
        CgroupRequest::memory(requested),
        RejectReason::AboveCeiling,
      ));
    }
    self.apply_memory(Control::MemoryMax, "memory.max", requested)
  }

  fn apply_memory(
    &self,
    control: Control,
    name: &'static str,
    requested: u64,
  ) -> Result<CgroupSnapshot, CgroupApplyError> {
    let request = match control {
      Control::MemoryHigh | Control::MemoryMax => CgroupRequest::memory(requested),
      _ => {
        return Err(rejected(
          control,
          CgroupRequest::memory(requested),
          RejectReason::AboveCeiling,
        ));
      }
    };
    let mut text = [0u8; 32];
    let mut writer = FixedWriter::new(&mut text);
    let _ = writeln!(writer, "{requested}");
    self.apply_one(control, request, name, writer.as_bytes(), |snapshot| {
      (if control == Control::MemoryHigh {
        snapshot.memory_high
      } else {
        snapshot.memory_max
      }) == Limit::Value(requested)
    })
  }

  /// Applies finite limits to known devices. Unmentioned existing device
  /// entries remain unchanged. Duplicate, unknown, or over-ceiling requests
  /// are rejected before the first write. Each line is a separate kernel
  /// operation; errors report the number of completed line writes.
  pub fn set_io_max(&self, requested: &[IoMax]) -> Result<CgroupSnapshot, CgroupApplyError> {
    let request = CgroupRequest::io(requested);
    if requested.len() > MAX_IO_DEVICES {
      return Err(CgroupApplyError {
        control: Control::IoMax,
        requested: request,
        failure: ApplyFailure::TooManyDevices,
        io_entries_written: 0,
        observed: None,
      });
    }
    for (index, item) in requested.iter().enumerate() {
      if let Err(error) = validate_device_id(item.device) {
        return Err(rejected(
          Control::IoMax,
          request,
          RejectReason::InvalidDevice(item.device, error),
        ));
      }
      if requested[..index]
        .iter()
        .any(|previous| previous.device == item.device)
      {
        return Err(rejected(
          Control::IoMax,
          request,
          RejectReason::DuplicateDevice,
        ));
      }
      let Some(ceiling) = self.ceilings.io_ceiling(item.device) else {
        return Err(rejected(
          Control::IoMax,
          request,
          RejectReason::UnknownDevice,
        ));
      };
      if let Some((field, error)) = invalid_io_limit(*item) {
        let reason = match error {
          IoLimitError::Zero => RejectReason::ZeroIoLimit(field),
          IoLimitError::UnlimitedSentinel => RejectReason::IoUnlimitedSentinel(field),
        };
        return Err(rejected(Control::IoMax, request, reason));
      }
      if item.read_bytes_per_second > ceiling.read_bytes_per_second
        || item.write_bytes_per_second > ceiling.write_bytes_per_second
        || item.read_ios_per_second > ceiling.read_ios_per_second
        || item.write_ios_per_second > ceiling.write_ios_per_second
      {
        return Err(rejected(
          Control::IoMax,
          request,
          RejectReason::AboveCeiling,
        ));
      }
    }

    // Parse first so existing unmentioned records are known and retained, and
    // reject a request whose union cannot fit the fixed readback table before
    // modifying the kernel.
    let before = match self.readback() {
      Ok(snapshot) => snapshot,
      Err(error) => {
        return Err(CgroupApplyError {
          control: Control::IoMax,
          requested: request,
          failure: ApplyFailure::Readback(error),
          io_entries_written: 0,
          observed: None,
        });
      }
    };
    let mut union_count = before.io_max_len;
    for item in requested {
      if before.io_max[..before.io_max_len]
        .iter()
        .flatten()
        .all(|existing| existing.device != item.device)
      {
        union_count += 1;
      }
    }
    if union_count > MAX_IO_DEVICES {
      return Err(CgroupApplyError {
        control: Control::IoMax,
        requested: request,
        failure: ApplyFailure::TooManyDevices,
        io_entries_written: 0,
        observed: Some(before),
      });
    }

    let mut written = 0usize;
    for item in requested {
      let mut text = [0u8; MAX_IO_LINE];
      let mut writer = FixedWriter::new(&mut text);
      let _ = writeln!(
        writer,
        "{}:{} rbps={} wbps={} riops={} wiops={}",
        item.device.major,
        item.device.minor,
        item.read_bytes_per_second,
        item.write_bytes_per_second,
        item.read_ios_per_second,
        item.write_ios_per_second
      );
      match self.write_one("io.max", writer.as_bytes()) {
        Ok(()) => written += 1,
        Err(failure) => {
          return Err(CgroupApplyError {
            control: Control::IoMax,
            requested: request,
            failure,
            io_entries_written: written,
            observed: self.readback().ok(),
          });
        }
      }
    }

    let observed = match self.readback() {
      Ok(snapshot) => snapshot,
      Err(error) => {
        return Err(CgroupApplyError {
          control: Control::IoMax,
          requested: request,
          failure: ApplyFailure::Readback(error),
          io_entries_written: written,
          observed: None,
        });
      }
    };
    let all_match = requested.iter().all(|request| {
      observed.io_max[..observed.io_max_len]
        .iter()
        .flatten()
        .any(|value| *value == io_readback(*request))
    });
    if !all_match {
      return Err(CgroupApplyError {
        control: Control::IoMax,
        requested: request,
        failure: ApplyFailure::Mismatch,
        io_entries_written: written,
        observed: Some(observed),
      });
    }
    Ok(observed)
  }

  fn apply_one(
    &self,
    control: Control,
    requested: CgroupRequest,
    name: &'static str,
    text: &[u8],
    verify: impl FnOnce(&CgroupSnapshot) -> bool,
  ) -> Result<CgroupSnapshot, CgroupApplyError> {
    if let Err(failure) = self.write_one(name, text) {
      return Err(CgroupApplyError {
        control,
        requested,
        failure,
        io_entries_written: 0,
        observed: self.readback().ok(),
      });
    }
    let observed = match self.readback() {
      Ok(snapshot) => snapshot,
      Err(error) => {
        return Err(CgroupApplyError {
          control,
          requested,
          failure: ApplyFailure::Readback(error),
          io_entries_written: 0,
          observed: None,
        });
      }
    };
    if !verify(&observed) {
      return Err(CgroupApplyError {
        control,
        requested,
        failure: ApplyFailure::Mismatch,
        io_entries_written: 0,
        observed: Some(observed),
      });
    }
    Ok(observed)
  }

  fn write_one(&self, name: &'static str, text: &[u8]) -> Result<(), ApplyFailure> {
    let fd = openat(
      &self.directory,
      name,
      OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
      rustix::fs::Mode::empty(),
    )
    .map_err(|error| ApplyFailure::Io(io::Error::from(error).into()))?;
    for _ in 0..IO_RETRIES {
      match write(&fd, text) {
        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
        Err(error) => return Err(ApplyFailure::Io(io::Error::from(error).into())),
        Ok(count) if count == text.len() => return Ok(()),
        Ok(_) => return Err(ApplyFailure::ShortWrite),
      }
    }
    Err(ApplyFailure::Io(CgroupIoError {
      kind: io::ErrorKind::Interrupted,
      raw_os_error: None,
    }))
  }
}

fn rejected(control: Control, requested: CgroupRequest, reason: RejectReason) -> CgroupApplyError {
  CgroupApplyError {
    control,
    requested,
    failure: ApplyFailure::Rejected(reason),
    io_entries_written: 0,
    observed: None,
  }
}

fn io_readback(request: IoMax) -> IoMaxReadback {
  IoMaxReadback {
    device: request.device,
    read_bytes_per_second: Limit::Value(request.read_bytes_per_second),
    write_bytes_per_second: Limit::Value(request.write_bytes_per_second),
    read_ios_per_second: Limit::Value(request.read_ios_per_second),
    write_ios_per_second: Limit::Value(request.write_ios_per_second),
  }
}

fn read_control(
  directory: &OwnedFd,
  name: &'static str,
  control: Control,
) -> Result<ControlText, CgroupReadError> {
  let fd = openat(
    directory,
    name,
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
    rustix::fs::Mode::empty(),
  )
  .map_err(|error| CgroupReadError {
    control,
    failure: ReadFailure::Io(io::Error::from(error).into()),
  })?;
  let mut bytes = [0u8; MAX_CONTROL_BYTES];
  let mut length = 0usize;
  loop {
    if length == bytes.len() {
      let mut extra = [0u8; 1];
      let count =
        read_bounded(&fd, &mut extra).map_err(|failure| CgroupReadError { control, failure })?;
      if count != 0 {
        return Err(CgroupReadError {
          control,
          failure: ReadFailure::TooLarge,
        });
      }
      break;
    }
    let count = read_bounded(&fd, &mut bytes[length..])
      .map_err(|failure| CgroupReadError { control, failure })?;
    if count == 0 {
      break;
    }
    length += count;
  }
  Ok(ControlText { bytes, length })
}

fn read_bounded(fd: &OwnedFd, buffer: &mut [u8]) -> Result<usize, ReadFailure> {
  for _ in 0..IO_RETRIES {
    match read(fd, &mut *buffer) {
      Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
      Err(error) => return Err(ReadFailure::Io(io::Error::from(error).into())),
      Ok(count) => return Ok(count),
    }
  }
  Err(ReadFailure::Io(CgroupIoError {
    kind: io::ErrorKind::Interrupted,
    raw_os_error: None,
  }))
}

#[derive(Clone, Copy)]
struct ControlText {
  bytes: [u8; MAX_CONTROL_BYTES],
  length: usize,
}

impl ControlText {
  #[cfg(test)]
  fn from_slice(bytes: &[u8]) -> Result<Self, ReadFailure> {
    if bytes.len() > MAX_CONTROL_BYTES {
      return Err(ReadFailure::TooLarge);
    }
    let mut storage = [0u8; MAX_CONTROL_BYTES];
    storage[..bytes.len()].copy_from_slice(bytes);
    Ok(Self {
      bytes: storage,
      length: bytes.len(),
    })
  }

  fn as_str(&self) -> Result<&str, ReadFailure> {
    std::str::from_utf8(&self.bytes[..self.length]).map_err(|_| ReadFailure::InvalidFormat)
  }
}

fn parse_cpu_max(text: &ControlText) -> Result<CpuMaxReadback, ReadFailure> {
  let mut fields = text.as_str()?.split_ascii_whitespace();
  let quota = parse_limit_token(fields.next().ok_or(ReadFailure::InvalidFormat)?)?;
  let period = parse_u64(fields.next().ok_or(ReadFailure::InvalidFormat)?)?;
  if period == 0 || fields.next().is_some() {
    return Err(ReadFailure::InvalidFormat);
  }
  Ok(CpuMaxReadback {
    quota_us: quota,
    period_us: period,
  })
}

fn parse_limit(text: &ControlText) -> Result<Limit, ReadFailure> {
  let mut fields = text.as_str()?.split_ascii_whitespace();
  let value = parse_limit_token(fields.next().ok_or(ReadFailure::InvalidFormat)?)?;
  if fields.next().is_some() {
    return Err(ReadFailure::InvalidFormat);
  }
  Ok(value)
}

fn parse_limit_token(token: &str) -> Result<Limit, ReadFailure> {
  if token == "max" {
    Ok(Limit::Max)
  } else {
    parse_u64(token).map(Limit::Value)
  }
}

fn parse_u64(token: &str) -> Result<u64, ReadFailure> {
  token.parse().map_err(|_| ReadFailure::InvalidFormat)
}

fn parse_io_max(
  text: &ControlText,
) -> Result<([Option<IoMaxReadback>; MAX_IO_DEVICES], usize), ReadFailure> {
  let mut entries = [None; MAX_IO_DEVICES];
  let mut length = 0usize;
  for line in text.as_str()?.lines() {
    let mut fields = line.split_ascii_whitespace();
    let Some(device) = fields.next() else {
      continue;
    };
    if length == MAX_IO_DEVICES || line.len() > MAX_IO_LINE {
      return Err(ReadFailure::InvalidDevices);
    }
    let device = parse_device(device)?;
    if entries[..length]
      .iter()
      .flatten()
      .any(|entry: &IoMaxReadback| entry.device == device)
    {
      return Err(ReadFailure::InvalidDevices);
    }
    let mut values = [None; 4];
    for field in fields {
      let (key, value) = field.split_once('=').ok_or(ReadFailure::InvalidFormat)?;
      let index = match key {
        "rbps" => 0,
        "wbps" => 1,
        "riops" => 2,
        "wiops" => 3,
        _ => return Err(ReadFailure::InvalidFormat),
      };
      if values[index].is_some() {
        return Err(ReadFailure::InvalidFormat);
      }
      values[index] = Some(parse_limit_token(value)?);
    }
    let [
      Some(read_bytes_per_second),
      Some(write_bytes_per_second),
      Some(read_ios_per_second),
      Some(write_ios_per_second),
    ] = values
    else {
      return Err(ReadFailure::InvalidFormat);
    };
    entries[length] = Some(IoMaxReadback {
      device,
      read_bytes_per_second,
      write_bytes_per_second,
      read_ios_per_second,
      write_ios_per_second,
    });
    length += 1;
  }
  Ok((entries, length))
}

fn parse_device(token: &str) -> Result<DeviceId, ReadFailure> {
  let (major, minor) = token.split_once(':').ok_or(ReadFailure::InvalidFormat)?;
  if minor.contains(':') {
    return Err(ReadFailure::InvalidFormat);
  }
  let device = DeviceId {
    major: major.parse().map_err(|_| ReadFailure::InvalidFormat)?,
    minor: minor.parse().map_err(|_| ReadFailure::InvalidFormat)?,
  };
  validate_device_id(device).map_err(|_| ReadFailure::InvalidDevices)?;
  Ok(device)
}

struct FixedWriter<'a> {
  output: &'a mut [u8],
  length: usize,
}

impl<'a> FixedWriter<'a> {
  fn new(output: &'a mut [u8]) -> Self {
    Self { output, length: 0 }
  }

  fn as_bytes(&self) -> &[u8] {
    &self.output[..self.length]
  }
}

impl fmt::Write for FixedWriter<'_> {
  fn write_str(&mut self, text: &str) -> fmt::Result {
    let Some(end) = self.length.checked_add(text.len()) else {
      return Err(fmt::Error);
    };
    let Some(destination) = self.output.get_mut(self.length..end) else {
      return Err(fmt::Error);
    };
    destination.copy_from_slice(text.as_bytes());
    self.length = end;
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs::File;
  use std::num::NonZeroU64;
  use std::os::fd::OwnedFd as StdOwnedFd;

  fn nonzero(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap()
  }

  fn control(text: &[u8]) -> ControlText {
    ControlText::from_slice(text).unwrap()
  }

  #[test]
  fn cpu_ceiling_compares_quota_period_ratios() {
    let ceiling = CpuMax::new(nonzero(50_000), nonzero(100_000));
    assert!(CpuMax::new(nonzero(25_000), nonzero(100_000)).within(ceiling));
    assert!(CpuMax::new(nonzero(25_000), nonzero(50_000)).within(ceiling));
    assert!(!CpuMax::new(nonzero(50_000), nonzero(50_000)).within(ceiling));
  }

  #[test]
  fn cpu_limits_validate_linux_v70_boundaries_and_unlimited_sentinel() {
    let max_quota = (1 << 44) - 1;
    assert_eq!(
      validate_cpu_max(CpuMax::new(nonzero(1_000), nonzero(1_000))),
      Ok(())
    );
    assert_eq!(
      validate_cpu_max(CpuMax::new(nonzero(max_quota), nonzero(1_000_000))),
      Ok(())
    );
    assert_eq!(
      validate_cpu_max(CpuMax::new(nonzero(999), nonzero(1_000))),
      Err(CpuLimitError::QuotaTooLow)
    );
    assert_eq!(
      validate_cpu_max(CpuMax::new(nonzero(max_quota + 1), nonzero(1_000))),
      Err(CpuLimitError::QuotaTooHigh)
    );
    assert_eq!(
      validate_cpu_max(CpuMax::new(nonzero(u64::MAX), nonzero(100_000))),
      Err(CpuLimitError::UnlimitedQuota)
    );
    assert_eq!(
      validate_cpu_max(CpuMax::new(nonzero(1_000), nonzero(999))),
      Err(CpuLimitError::PeriodTooShort)
    );
    assert_eq!(
      validate_cpu_max(CpuMax::new(nonzero(1_000), nonzero(1_000_001))),
      Err(CpuLimitError::PeriodTooLong)
    );
  }

  #[test]
  fn device_ids_must_fit_kernel_major_minor_fields() {
    assert_eq!(
      validate_device_id(DeviceId {
        major: MAX_DEVICE_MAJOR,
        minor: MAX_DEVICE_MINOR
      }),
      Ok(())
    );
    assert_eq!(
      validate_device_id(DeviceId {
        major: MAX_DEVICE_MAJOR + 1,
        minor: 0
      }),
      Err(DeviceIdError::MajorOutOfRange)
    );
    assert_eq!(
      validate_device_id(DeviceId {
        major: 4_104,
        minor: 0
      }),
      Err(DeviceIdError::MajorOutOfRange)
    );
    assert_eq!(
      validate_device_id(DeviceId {
        major: 8,
        minor: MAX_DEVICE_MINOR + 1
      }),
      Err(DeviceIdError::MinorOutOfRange)
    );

    let valid = IoMax {
      device: DeviceId {
        major: MAX_DEVICE_MAJOR + 1,
        minor: 0,
      },
      read_bytes_per_second: 1,
      write_bytes_per_second: 1,
      read_ios_per_second: 1,
      write_ios_per_second: 1,
    };
    let mut ceilings = CgroupCeilings::new(
      CpuMax::new(nonzero(100_000), nonzero(100_000)),
      1 << 30,
      1 << 31,
    );
    assert!(matches!(
      ceilings.add_io_device(valid),
      Err(CeilingError::InvalidDevice(
        _,
        DeviceIdError::MajorOutOfRange
      ))
    ));
  }

  #[test]
  fn parses_finite_and_unlimited_cpu_and_memory_readbacks() {
    assert_eq!(
      parse_cpu_max(&control(b"max 100000\n")).unwrap(),
      CpuMaxReadback {
        quota_us: Limit::Max,
        period_us: 100_000,
      }
    );
    assert_eq!(
      parse_limit(&control(b"9223372036854771712\n")).unwrap(),
      Limit::Value(9_223_372_036_854_771_712)
    );
    assert_eq!(parse_limit(&control(b"max\n")).unwrap(), Limit::Max);
  }

  #[test]
  fn io_parser_retains_unmentioned_devices_and_rejects_bad_or_excess_data() {
    let parsed = parse_io_max(&control(
      b"8:0 rbps=100 wbps=max riops=2 wiops=3\n259:1 rbps=max wbps=200 riops=max wiops=4\n",
    ))
    .unwrap();
    assert_eq!(parsed.1, 2);
    assert_eq!(parsed.0[0].unwrap().device, DeviceId { major: 8, minor: 0 });
    assert_eq!(parsed.0[0].unwrap().write_bytes_per_second, Limit::Max);
    assert_eq!(
      parsed.0[1].unwrap().device,
      DeviceId {
        major: 259,
        minor: 1
      }
    );

    assert_eq!(
      parse_io_max(&control(
        b"8:0 rbps=1 wbps=2 riops=3 wiops=4\n8:0 rbps=1 wbps=2 riops=3 wiops=4\n"
      )),
      Err(ReadFailure::InvalidDevices)
    );
    assert_eq!(
      parse_io_max(&control(b"8:0 rbps=1 wbps=2 riops=3 unknown=4\n")),
      Err(ReadFailure::InvalidFormat)
    );
  }

  #[test]
  fn finite_memory_and_io_limits_reject_kernel_rounding_and_sentinels() {
    assert!(memory_limit_aligned(0));
    let page = rustix::param::page_size() as u64;
    assert!(memory_limit_aligned(page));
    assert!(!memory_limit_aligned(page + 1));
    let memory_sentinel = memory_unlimited_sentinel();
    assert_eq!(
      memory_limit_error(memory_sentinel - page),
      None,
      "the last finite page remains representable"
    );
    assert_eq!(
      memory_limit_error(memory_sentinel),
      Some(MemoryLimitError::UnlimitedSentinel)
    );
    assert_eq!(
      memory_limit_error(memory_sentinel + page),
      Some(MemoryLimitError::UnlimitedSentinel)
    );
    assert_eq!(
      memory_limit_error(memory_sentinel + 1),
      Some(MemoryLimitError::Unaligned)
    );

    let valid = IoMax {
      device: DeviceId { major: 8, minor: 0 },
      read_bytes_per_second: 1,
      write_bytes_per_second: 1,
      read_ios_per_second: 1,
      write_ios_per_second: 1,
    };
    assert_eq!(invalid_io_limit(valid), None);
    assert_eq!(
      invalid_io_limit(IoMax {
        read_bytes_per_second: 0,
        ..valid
      }),
      Some((IoRateField::ReadBytesPerSecond, IoLimitError::Zero))
    );
    assert_eq!(
      invalid_io_limit(IoMax {
        write_bytes_per_second: u64::MAX,
        ..valid
      }),
      Some((
        IoRateField::WriteBytesPerSecond,
        IoLimitError::UnlimitedSentinel
      ))
    );
    assert_eq!(
      invalid_io_limit(IoMax {
        read_ios_per_second: u64::from(u32::MAX) - 1,
        ..valid
      }),
      None
    );
    assert_eq!(
      invalid_io_limit(IoMax {
        read_ios_per_second: u64::from(u32::MAX),
        ..valid
      }),
      Some((
        IoRateField::ReadIosPerSecond,
        IoLimitError::UnlimitedSentinel
      ))
    );
    assert_eq!(
      invalid_io_limit(IoMax {
        write_ios_per_second: u64::from(u32::MAX) + 1,
        ..valid
      }),
      Some((
        IoRateField::WriteIosPerSecond,
        IoLimitError::UnlimitedSentinel
      ))
    );

    let mut ceilings = CgroupCeilings::new(CpuMax::new(nonzero(1), nonzero(1)), page, page);
    assert!(matches!(
      ceilings.add_io_device(IoMax {
        read_ios_per_second: u64::from(u32::MAX),
        ..valid
      }),
      Err(CeilingError::InvalidIoLimit(
        IoRateField::ReadIosPerSecond,
        IoLimitError::UnlimitedSentinel
      ))
    ));
    assert!(ceilings.add_io_device(valid).is_ok());
  }

  #[test]
  fn io_parser_enforces_device_fields_numbers_and_control_byte_bound() {
    let mut seventeen = String::new();
    for index in 0..=MAX_IO_DEVICES {
      use std::fmt::Write as _;
      writeln!(seventeen, "8:{index} rbps=1 wbps=2 riops=3 wiops=4").unwrap();
    }
    assert_eq!(
      parse_io_max(&control(seventeen.as_bytes())),
      Err(ReadFailure::InvalidDevices)
    );
    assert_eq!(
      parse_io_max(&control(b"8:0 rbps=1 wbps=2 riops=3\n")),
      Err(ReadFailure::InvalidFormat)
    );
    assert_eq!(
      parse_io_max(&control(
        b"8:0 rbps=18446744073709551616 wbps=2 riops=3 wiops=4\n"
      )),
      Err(ReadFailure::InvalidFormat)
    );
    assert_eq!(
      parse_io_max(&control(b"4294967296:0 rbps=1 wbps=2 riops=3 wiops=4\n")),
      Err(ReadFailure::InvalidFormat)
    );
    assert_eq!(
      parse_io_max(&control(b"4104:0 rbps=1 wbps=2 riops=3 wiops=4\n")),
      Err(ReadFailure::InvalidDevices)
    );
    assert_eq!(
      parse_io_max(&control(b"8:1048576 rbps=1 wbps=2 riops=3 wiops=4\n")),
      Err(ReadFailure::InvalidDevices)
    );

    let at_limit = vec![b' '; MAX_CONTROL_BYTES];
    assert_eq!(parse_io_max(&control(&at_limit)).unwrap().1, 0);
    let over_limit = vec![b' '; MAX_CONTROL_BYTES + 1];
    assert!(matches!(
      ControlText::from_slice(&over_limit),
      Err(ReadFailure::TooLarge)
    ));
  }

  #[test]
  fn rejects_regular_filesystem_and_returns_original_directory() {
    let directory: StdOwnedFd = File::open(std::env::temp_dir()).unwrap().into();
    let ceilings = CgroupCeilings::new(
      CpuMax::new(nonzero(100_000), nonzero(100_000)),
      1 << 30,
      1 << 31,
    );
    let error = CgroupV2::open(directory, ceilings).unwrap_err();
    assert_eq!(error.kind(), CgroupOpenErrorKind::WrongFilesystem);
    let returned = error.into_directory();
    assert!(fstat(&returned).is_ok());
  }

  #[test]
  fn rejects_invalid_cpu_ceiling_and_returns_original_directory() {
    let directory: StdOwnedFd = File::open(std::env::temp_dir()).unwrap().into();
    let ceilings = CgroupCeilings::new(
      CpuMax::new(nonzero(u64::MAX), nonzero(100_000)),
      1 << 30,
      1 << 31,
    );
    let error = CgroupV2::open(directory, ceilings).unwrap_err();
    assert_eq!(
      error.kind(),
      CgroupOpenErrorKind::InvalidCeiling(CeilingError::InvalidCpuLimit(
        CpuLimitError::UnlimitedQuota
      ))
    );
    assert!(fstat(error.into_directory()).is_ok());
  }

  #[test]
  fn rejects_memory_unlimited_sentinel_ceiling_and_returns_original_directory() {
    let directory: StdOwnedFd = File::open(std::env::temp_dir()).unwrap().into();
    let ceilings = CgroupCeilings::new(
      CpuMax::new(nonzero(100_000), nonzero(100_000)),
      memory_unlimited_sentinel(),
      memory_unlimited_sentinel() - rustix::param::page_size() as u64,
    );
    let error = CgroupV2::open(directory, ceilings).unwrap_err();
    assert_eq!(
      error.kind(),
      CgroupOpenErrorKind::InvalidCeiling(CeilingError::InvalidMemoryLimit(
        MemoryField::High,
        MemoryLimitError::UnlimitedSentinel
      ))
    );
    assert!(fstat(error.into_directory()).is_ok());
  }
}
