//! Bounded reactor-backed anonymous Unix pipes.
//!
//! [`pipe`] creates a kernel pipe with close-on-exec and nonblocking flags,
//! then registers both endpoints with the supplied reactor. Imported
//! endpoints are checked as FIFOs with a compatible access mode before any
//! flag change or reactor registration. Registration and readiness waiters
//! use the reactor's fixed bounds. The kernel pipe buffer is outside the
//! managed-memory ledger; these wrappers allocate no userspace payload
//! storage.
//!
//! Importing a descriptor can affect aliases of its open file description.
//! The endpoint sets `O_NONBLOCK`, so callers must coordinate every alias for
//! the endpoint's entire lifetime and must not change its status flags or
//! packet mode while it is registered. If registration fails after a flag
//! change, restoring the original flags is best-effort and any restoration
//! error is returned with the original descriptor. A named FIFO's path can
//! also be replaced between opening it and importing its descriptor; this is
//! not a path-confinement API.
//! On Linux, packet mode is reflected in the writer descriptor's status
//! flags; a read descriptor cannot reveal whether its peer enabled packet
//! mode. Callers importing only a reader must therefore ensure its peer is an
//! ordinary byte-stream writer.
//!
//! Writes to a pipe with no readers follow the process's current `SIGPIPE`
//! disposition; this module does not change process-wide signal handling.
//! Shutting down or dropping a [`PipeWriter`] closes only that owned writer
//! descriptor. Readers observe EOF only after every writer descriptor and
//! alias has closed. This endpoint shutdown is not a higher-level transport
//! half-close.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustix::fs::{FileType, OFlags, fcntl_getfl, fstat};
use rustix::pipe::{PipeFlags, pipe_with};

use super::asynchronous::poll_cooperative;
use super::io::{AsyncRead, AsyncWrite};
use super::process::pipe::{ChildPipeReader, ChildPipeWriter, PipeRegistrationError};
use super::reactor::ReactorHandle;

#[cfg(all(test, not(loom)))]
#[path = "unix_pipe_tests.rs"]
mod tests;

/// A refused imported pipe descriptor, retaining its original ownership.
pub struct OwnedPipeError {
  fd: OwnedFd,
  error: io::Error,
  restoration_error: Option<io::Error>,
}

impl OwnedPipeError {
  fn validation(fd: OwnedFd, error: io::Error) -> Self {
    Self {
      fd,
      error,
      restoration_error: None,
    }
  }

  fn registration(error: PipeRegistrationError<OwnedFd>) -> Self {
    let (fd, error, restoration_error) = error.into_parts();
    Self {
      fd,
      error,
      restoration_error,
    }
  }

  /// The validation, flag-change, or registration error.
  #[must_use]
  pub const fn error(&self) -> &io::Error {
    &self.error
  }

  /// A failure to restore the original status flags after registration failed.
  #[must_use]
  pub const fn restoration_error(&self) -> Option<&io::Error> {
    self.restoration_error.as_ref()
  }

  /// Borrows the original descriptor returned by this error.
  #[must_use]
  pub const fn get_ref(&self) -> &OwnedFd {
    &self.fd
  }

  /// Returns the original descriptor and both errors.
  #[must_use]
  pub fn into_parts(self) -> (OwnedFd, io::Error, Option<io::Error>) {
    (self.fd, self.error, self.restoration_error)
  }

  /// Returns the original descriptor.
  #[must_use]
  pub fn into_fd(self) -> OwnedFd {
    self.fd
  }
}

impl fmt::Debug for OwnedPipeError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("OwnedPipeError")
      .field("error", &self.error)
      .field("restoration_error", &self.restoration_error)
      .finish_non_exhaustive()
  }
}

impl fmt::Display for OwnedPipeError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "owned pipe descriptor refused: {}", self.error)?;
    if let Some(error) = &self.restoration_error {
      write!(f, "; restoring file status flags also failed: {error}")?;
    }
    Ok(())
  }
}

impl std::error::Error for OwnedPipeError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.error)
  }
}

/// An owned, nonblocking pipe reader registered with a reactor.
pub struct PipeReader {
  inner: ChildPipeReader<OwnedFd>,
}

impl PipeReader {
  /// Imports a pipe or FIFO reader descriptor.
  ///
  /// The descriptor must refer to a FIFO/pipe and be opened read-only or
  /// read-write. `O_PATH` and Linux packet-mode `O_DIRECT` descriptors are
  /// rejected before changing flags. On every rejection, the original
  /// descriptor is returned. Successful registration enables `O_NONBLOCK`;
  /// aliases of its open file description must remain coordinated while this
  /// endpoint is alive. Linux does not expose peer packet-mode state on the
  /// imported read descriptor, so callers must ensure its peer did not enable
  /// packet mode.
  pub fn from_owned_fd(fd: OwnedFd, reactor: &ReactorHandle) -> Result<Self, OwnedPipeError> {
    if let Err(error) = validate_pipe_fd(&fd, PipeDirection::Reader) {
      return Err(OwnedPipeError::validation(fd, error));
    }
    ChildPipeReader::from_std(fd, reactor)
      .map(|inner| Self { inner })
      .map_err(OwnedPipeError::registration)
  }

  /// Borrows the registered descriptor.
  #[must_use]
  pub fn get_ref(&self) -> &OwnedFd {
    self.inner.get_ref()
  }

  /// Releases a readiness waiter retained after a dropped pending read.
  /// Call after dropping any future borrowing this endpoint.
  pub fn cancel_io_waits(&mut self) {
    self.inner.cancel_io_waits();
  }
}

/// An owned, nonblocking pipe writer registered with a reactor.
pub struct PipeWriter {
  inner: ChildPipeWriter<OwnedFd>,
}

impl PipeWriter {
  /// Imports a pipe or FIFO writer descriptor.
  ///
  /// The descriptor must refer to a FIFO/pipe and be opened write-only or
  /// read-write. `O_PATH` and Linux packet-mode `O_DIRECT` descriptors are
  /// rejected before changing flags. On every rejection, the original
  /// descriptor is returned. Successful registration enables `O_NONBLOCK`;
  /// aliases of its open file description must remain coordinated while this
  /// endpoint is alive.
  pub fn from_owned_fd(fd: OwnedFd, reactor: &ReactorHandle) -> Result<Self, OwnedPipeError> {
    if let Err(error) = validate_pipe_fd(&fd, PipeDirection::Writer) {
      return Err(OwnedPipeError::validation(fd, error));
    }
    ChildPipeWriter::from_owned_pipe(fd, reactor)
      .map(|inner| Self { inner })
      .map_err(OwnedPipeError::registration)
  }

  /// Borrows the registered descriptor while it remains open.
  #[must_use]
  pub fn get_ref(&self) -> Option<&OwnedFd> {
    self.inner.get_ref()
  }

  /// Releases a readiness waiter retained after a dropped pending write.
  /// Call after dropping any future borrowing this endpoint.
  pub fn cancel_io_waits(&mut self) {
    self.inner.cancel_io_waits();
  }
}

/// Creates and registers a close-on-exec, nonblocking anonymous pipe pair.
///
/// If either registration fails, all new descriptors are closed and any
/// registration already completed by this call is reclaimed. The returned
/// error is the creation or registration error; no original user descriptor
/// is involved in this constructor.
pub fn pipe(reactor: &ReactorHandle) -> io::Result<(PipeReader, PipeWriter)> {
  let (read_fd, write_fd) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
  let reader = match PipeReader::from_owned_fd(read_fd, reactor) {
    Ok(reader) => reader,
    Err(error) => {
      let (_, error, _) = error.into_parts();
      drop(write_fd);
      return Err(error);
    }
  };
  match PipeWriter::from_owned_fd(write_fd, reactor) {
    Ok(writer) => Ok((reader, writer)),
    Err(error) => {
      let (_, error, _) = error.into_parts();
      drop(reader);
      Err(error)
    }
  }
}

#[derive(Clone, Copy)]
enum PipeDirection {
  Reader,
  Writer,
}

fn validate_pipe_fd(fd: &OwnedFd, direction: PipeDirection) -> io::Result<()> {
  let stat = fstat(fd).map_err(io::Error::from)?;
  if FileType::from_raw_mode(stat.st_mode) != FileType::Fifo {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "descriptor is not a FIFO or pipe",
    ));
  }
  let flags = fcntl_getfl(fd).map_err(io::Error::from)?;
  if flags.contains(OFlags::PATH) {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "path-only descriptors cannot be registered as pipes",
    ));
  }
  if flags.contains(OFlags::DIRECT) {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "packet-mode pipes are not byte-stream endpoints",
    ));
  }
  let access = flags & OFlags::ACCMODE;
  let allowed = match direction {
    PipeDirection::Reader => access == OFlags::RDONLY || access == OFlags::RDWR,
    PipeDirection::Writer => access == OFlags::WRONLY || access == OFlags::RDWR,
  };
  if !allowed {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      match direction {
        PipeDirection::Reader => "pipe descriptor is not readable",
        PipeDirection::Writer => "pipe descriptor is not writable",
      },
    ));
  }
  Ok(())
}

impl AsyncRead for PipeReader {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    poll_cooperative(cx, |cx| Pin::new(&mut this.inner).poll_read(cx, buf))
  }

  fn poll_read_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &mut [IoSliceMut<'_>],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    poll_cooperative(cx, |cx| {
      Pin::new(&mut this.inner).poll_read_vectored(cx, bufs)
    })
  }
}

impl AsyncWrite for PipeWriter {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    poll_cooperative(cx, |cx| Pin::new(&mut this.inner).poll_write(cx, buf))
  }

  fn poll_write_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    poll_cooperative(cx, |cx| {
      Pin::new(&mut this.inner).poll_write_vectored(cx, bufs)
    })
  }

  fn is_write_vectored(&self) -> bool {
    self.inner.is_write_vectored()
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.as_mut().get_mut();
    poll_cooperative(cx, |cx| Pin::new(&mut this.inner).poll_flush(cx))
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.as_mut().get_mut();
    poll_cooperative(cx, |cx| Pin::new(&mut this.inner).poll_shutdown(cx))
  }
}
