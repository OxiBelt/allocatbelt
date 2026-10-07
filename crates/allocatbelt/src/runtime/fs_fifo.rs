//! Blocking-pool operations for named Unix FIFOs.

use std::fmt;
use std::io;
use std::path::PathBuf;

use rustix::fs::{CWD, Mode, OFlags, mkfifoat, open};

use super::super::job::Job;
use super::super::reactor::ReactorHandle;
use super::super::unix_pipe::{OwnedPipeError, PipeReader, PipeWriter};
use super::{FsHandle, FsSubmissionError, FsSubmissionErrorKind};

#[cfg(all(test, not(loom)))]
#[path = "fs_fifo_tests.rs"]
mod tests;

/// Options shared by named FIFO reader and writer opens.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FifoOpenOptions {
  read_write: bool,
}

impl FifoOpenOptions {
  /// Creates options with the portable read-only/read-only-or-write-only modes.
  #[must_use]
  pub const fn new() -> Self {
    Self { read_write: false }
  }

  /// Opens with `O_RDWR` instead of the direction-specific access mode.
  ///
  /// Linux supports read-write FIFO opens as an extension. Such a descriptor
  /// keeps a self-peer open: a reader will not observe ordinary EOF while the
  /// descriptor remains open, and a writer does not get `ENXIO` merely because
  /// no other reader is open. The option is therefore useful only when these
  /// changed peer and EOF semantics are intended.
  #[must_use]
  pub const fn read_write(mut self, enabled: bool) -> Self {
    self.read_write = enabled;
    self
  }

  const fn is_read_write(self) -> bool {
    self.read_write
  }
}

/// A FIFO open error after the blocking job was admitted.
#[derive(Debug)]
pub enum FifoOpenError {
  /// Opening the pathname failed. The open syscall was attempted; no replay or
  /// pathname rollback is performed.
  Open(io::Error),
  /// The opened descriptor could not be validated or registered. It remains
  /// available through the contained error.
  Import(OwnedPipeError),
}

impl fmt::Display for FifoOpenError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Open(error) => write!(f, "opening named FIFO failed: {error}"),
      Self::Import(error) => write!(f, "registering opened FIFO failed: {error}"),
    }
  }
}

impl std::error::Error for FifoOpenError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(match self {
      Self::Open(error) => error,
      Self::Import(error) => error,
    })
  }
}

/// An admitted named FIFO receiver open job.
pub type FifoReceiverJob = Job<Result<PipeReader, FifoOpenError>>;

/// An admitted named FIFO sender open job.
pub type FifoSenderJob = Job<Result<PipeWriter, FifoOpenError>>;

/// A refused named FIFO open with its original path and options.
pub type FifoOpenSubmissionError = FsSubmissionError<(PathBuf, FifoOpenOptions)>;

impl FsHandle {
  /// Creates a named FIFO using an explicit permission mode.
  ///
  /// Mode bits outside `0o7777` are rejected before admission and returned
  /// with the path. The process umask may remove requested permission bits,
  /// and the kernel may ignore special bits. This operation creates no parent
  /// directories and never unlinks a path on failure. Path resolution follows
  /// ordinary kernel behavior; this is not a confinement or race-free path
  /// API. The disk-operation permit remains held until the syscall completes.
  pub fn create_fifo(
    &self,
    path: PathBuf,
    mode: u32,
  ) -> Result<Job<io::Result<()>>, FsSubmissionError<(PathBuf, u32)>> {
    if mode & !0o7777 != 0 {
      return Err(FsSubmissionError {
        kind: FsSubmissionErrorKind::InvalidInput,
        input: (path, mode),
      });
    }

    self.submit((path, mode), |(path, mode), _token| {
      mkfifoat(CWD, path, Mode::from_raw_mode(mode)).map_err(io::Error::from)
    })
  }

  /// Opens a FIFO reader on the existing blocking pool and registers it with
  /// `reactor` before publishing the job result.
  ///
  /// The open uses `O_NONBLOCK | O_CLOEXEC | O_NOCTTY`; a default read-only
  /// open does not wait for a writer. A direct raw read on the nonblocking
  /// descriptor can return EOF before the first writer opens. The wrapper's
  /// [`AsyncRead`](crate::runtime::io::AsyncRead) adapter waits for reactor readiness, and
  /// Linux does not report the initial no-writer state as readiness, so that
  /// future can remain pending until writer activity. The descriptor remains
  /// usable when a writer later arrives. It is checked as a FIFO after
  /// opening, so symlinks and path replacement use ordinary kernel path
  /// resolution rather than confinement.
  /// If opening succeeds but import/registration fails, the error retains the
  /// descriptor. Dropping this job while its syscall is already running does
  /// not cancel the syscall; retained resources are released only after it
  /// completes.
  pub fn open_fifo_receiver(
    &self,
    path: PathBuf,
    options: FifoOpenOptions,
    reactor: &ReactorHandle,
  ) -> Result<FifoReceiverJob, FifoOpenSubmissionError> {
    let reactor = reactor.clone();
    self.submit((path, options), move |(path, options), _token| {
      let flags = fifo_flags(options, PipeAccess::Reader);
      let fd = open(path, flags, Mode::empty())
        .map_err(|error| FifoOpenError::Open(io::Error::from(error)))?;
      PipeReader::from_owned_fd(fd, &reactor).map_err(FifoOpenError::Import)
    })
  }

  /// Opens a FIFO writer on the existing blocking pool and registers it with
  /// `reactor` before publishing the job result.
  ///
  /// Without `read_write(true)`, opening with no reader returns the operating
  /// system's `ENXIO` error. The open uses `O_NONBLOCK | O_CLOEXEC | O_NOCTTY`;
  /// after opening, the descriptor is checked as a FIFO. If registration
  /// fails, the error retains the opened descriptor. Cancellation before a
  /// queued job starts prevents the open; once the syscall starts it is not
  /// replayed or rolled back.
  pub fn open_fifo_sender(
    &self,
    path: PathBuf,
    options: FifoOpenOptions,
    reactor: &ReactorHandle,
  ) -> Result<FifoSenderJob, FifoOpenSubmissionError> {
    let reactor = reactor.clone();
    self.submit((path, options), move |(path, options), _token| {
      let flags = fifo_flags(options, PipeAccess::Writer);
      let fd = open(path, flags, Mode::empty())
        .map_err(|error| FifoOpenError::Open(io::Error::from(error)))?;
      PipeWriter::from_owned_fd(fd, &reactor).map_err(FifoOpenError::Import)
    })
  }
}

#[derive(Clone, Copy)]
enum PipeAccess {
  Reader,
  Writer,
}

fn fifo_flags(options: FifoOpenOptions, access: PipeAccess) -> OFlags {
  let access = if options.is_read_write() {
    OFlags::RDWR
  } else {
    match access {
      PipeAccess::Reader => OFlags::RDONLY,
      PipeAccess::Writer => OFlags::WRONLY,
    }
  };
  access | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOCTTY
}
