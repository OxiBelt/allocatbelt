//! Bounded reactor-backed child pipe endpoints.
//!
//! These wrappers make the standard child stdin, stdout, and stderr pipes
//! nonblocking and register them with a caller-owned reactor. They use the
//! runtime's initialized-buffer I/O traits and allocate no read or write
//! storage. A pipe registration failure returns the original owned handle
//! and reports whether its original file status flags were restored.
//!
//! Pipe endpoints retain one readiness future per direction when a trait
//! poll returns `Pending`. Dropping that poll does not release the waiter;
//! another terminal read or write poll, an empty-buffer poll,
//! writer shutdown, [`ChildPipeReader::cancel_io_waits`],
//! [`ChildPipeWriter::cancel_io_waits`], or dropping the endpoint releases
//! it. The reactor's configured registration and waiter bounds are the pipe
//! endpoints' bounds.
//!
//! The writer has no userspace buffer: flush is immediately ready, and
//! shutdown closes the child stdin handle to deliver EOF. Dropping a stdout
//! or stderr endpoint closes that read handle; it does not stop or wait for
//! the process. Callers must drain piped output concurrently when a child can
//! write enough data to fill its kernel pipe buffers.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::AsFd;
use std::pin::Pin;
use std::process::ChildStdout as StdChildStdout;
use std::process::{ChildStderr as StdChildStderr, ChildStdin as StdChildStdin};
use std::task::{Context, Poll};

use rustix::fd::OwnedFd;
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::io::{read, readv, write, writev};

use super::super::io::{AsyncRead, AsyncWrite};
use super::super::reactor::{AsyncFd, OwnedReadiness, ReactorHandle};

const IO_BUDGET: usize = 64;

/// A refused pipe registration, retaining its original owned handle.
pub struct PipeRegistrationError<T> {
  handle: T,
  error: io::Error,
  restoration_error: Option<io::Error>,
}

impl<T> PipeRegistrationError<T> {
  /// The reactor or file-control error that refused registration.
  #[must_use]
  pub const fn error(&self) -> &io::Error {
    &self.error
  }

  /// An error while restoring the original flags after registration failed.
  ///
  /// When this is `Some`, the returned handle is still owned by this error,
  /// but its open-file-description flags may remain nonblocking.
  #[must_use]
  pub const fn restoration_error(&self) -> Option<&io::Error> {
    self.restoration_error.as_ref()
  }

  /// Borrows the original handle.
  #[must_use]
  pub const fn get_ref(&self) -> &T {
    &self.handle
  }

  /// Returns the original handle and both registration outcomes.
  #[must_use]
  pub fn into_parts(self) -> (T, io::Error, Option<io::Error>) {
    (self.handle, self.error, self.restoration_error)
  }

  /// Returns the original handle.
  #[must_use]
  pub fn into_inner(self) -> T {
    self.handle
  }
}

impl<T> fmt::Debug for PipeRegistrationError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("PipeRegistrationError")
      .field("error", &self.error)
      .field("restoration_error", &self.restoration_error)
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Display for PipeRegistrationError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "child pipe registration failed: {}", self.error)?;
    if let Some(error) = &self.restoration_error {
      write!(f, "; restoring file status flags also failed: {error}")?;
    }
    Ok(())
  }
}

impl<T: 'static> std::error::Error for PipeRegistrationError<T> {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.error)
  }
}

/// A registered child stdout or stderr reader.
pub struct ChildPipeReader<T> {
  fd: AsyncFd<T>,
  waiter: Option<OwnedReadiness<T>>,
}

/// A registered child stdin writer.
pub struct ChildPipeWriter<T> {
  fd: Option<AsyncFd<T>>,
  waiter: Option<OwnedReadiness<T>>,
}

/// Async wrapper for [`std::process::ChildStdout`].
pub type AsyncChildStdout = ChildPipeReader<StdChildStdout>;
/// Async wrapper for [`std::process::ChildStderr`].
pub type AsyncChildStderr = ChildPipeReader<StdChildStderr>;
/// Async wrapper for [`std::process::ChildStdin`].
pub type AsyncChildStdin = ChildPipeWriter<StdChildStdin>;

/// Generic reader over an owned, reactor-compatible child pipe.
impl<T> ChildPipeReader<T>
where
  T: AsFd + Send + Sync + 'static,
{
  /// Sets nonblocking mode and registers an owned child pipe.
  ///
  /// On failure, the error owns and returns `handle`. If registration fails
  /// after the flag change, construction attempts to restore all original
  /// file status flags and records a restoration failure separately.
  pub fn from_std(handle: T, reactor: &ReactorHandle) -> Result<Self, PipeRegistrationError<T>> {
    register(handle, reactor).map(|fd| Self { fd, waiter: None })
  }

  /// The underlying registered standard pipe.
  #[must_use]
  pub fn get_ref(&self) -> &T {
    self.fd.get_ref()
  }

  /// Cancels a readiness waiter retained after a dropped pending poll.
  /// Call after dropping any future borrowing this endpoint.
  pub fn cancel_io_waits(&mut self) {
    self.waiter = None;
  }
}

impl ChildPipeWriter<StdChildStdin> {
  /// Sets nonblocking mode and registers an owned child pipe.
  ///
  /// On failure, the error owns and returns `handle`. If registration fails
  /// after the flag change, construction attempts to restore all original
  /// file status flags and records a restoration failure separately.
  pub fn from_std(
    handle: StdChildStdin,
    reactor: &ReactorHandle,
  ) -> Result<Self, PipeRegistrationError<StdChildStdin>> {
    register(handle, reactor).map(|fd| Self {
      fd: Some(fd),
      waiter: None,
    })
  }
}

impl ChildPipeWriter<OwnedFd> {
  /// Registers an already-validated owned anonymous pipe writer.
  pub(crate) fn from_owned_pipe(
    handle: OwnedFd,
    reactor: &ReactorHandle,
  ) -> Result<Self, PipeRegistrationError<OwnedFd>> {
    register(handle, reactor).map(|fd| Self {
      fd: Some(fd),
      waiter: None,
    })
  }
}

impl<T> ChildPipeWriter<T> {
  /// The underlying registered standard pipe, if it has not been shut down.
  #[must_use]
  pub fn get_ref(&self) -> Option<&T> {
    self.fd.as_ref().map(AsyncFd::get_ref)
  }

  /// Cancels a readiness waiter retained after a dropped pending poll.
  /// Call after dropping any future borrowing this endpoint.
  pub fn cancel_io_waits(&mut self) {
    self.waiter = None;
  }
}

fn register<T>(handle: T, reactor: &ReactorHandle) -> Result<AsyncFd<T>, PipeRegistrationError<T>>
where
  T: AsFd + Send + Sync + 'static,
{
  let original_flags = match fcntl_getfl(handle.as_fd()) {
    Ok(flags) => flags,
    Err(error) => {
      return Err(PipeRegistrationError {
        handle,
        error: error.into(),
        restoration_error: None,
      });
    }
  };
  if !original_flags.contains(OFlags::NONBLOCK)
    && let Err(error) = fcntl_setfl(handle.as_fd(), original_flags | OFlags::NONBLOCK)
  {
    return Err(PipeRegistrationError {
      handle,
      error: error.into(),
      restoration_error: None,
    });
  }

  match reactor.register(handle) {
    Ok(fd) => Ok(fd),
    Err(rejected) => {
      let (handle, error) = rejected.into_parts();
      let restoration_error = if original_flags.contains(OFlags::NONBLOCK) {
        None
      } else {
        fcntl_setfl(handle.as_fd(), original_flags)
          .err()
          .map(io::Error::from)
      };
      Err(PipeRegistrationError {
        handle,
        error,
        restoration_error,
      })
    }
  }
}

fn read_len(bufs: &[IoSliceMut<'_>]) -> io::Result<usize> {
  bufs.iter().try_fold(0_usize, |sum, buf| {
    sum
      .checked_add(buf.len())
      .ok_or_else(|| io::ErrorKind::InvalidInput.into())
  })
}

fn write_len(bufs: &[IoSlice<'_>]) -> io::Result<usize> {
  bufs.iter().try_fold(0_usize, |sum, buf| {
    sum
      .checked_add(buf.len())
      .ok_or_else(|| io::ErrorKind::InvalidInput.into())
  })
}

fn check_count(count: usize, offered: usize) -> io::Result<usize> {
  if count <= offered {
    Ok(count)
  } else {
    Err(io::ErrorKind::InvalidData.into())
  }
}

impl<T> AsyncRead for ChildPipeReader<T>
where
  T: AsFd + Send + Sync + 'static,
{
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    if buf.is_empty() {
      this.waiter = None;
      return Poll::Ready(Ok(0));
    }

    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
      if this.waiter.is_none() {
        this.waiter = Some(this.fd.readable_owned());
      }
      let readiness = match this.waiter.as_mut() {
        Some(waiter) => Pin::new(waiter).poll(cx),
        None => unreachable!("read waiter was just created"),
      };
      match readiness {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => {
          this.waiter = None;
          return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(guard)) => {
          this.waiter = None;
          attempts += 1;
          match guard.try_io(|pipe| read(pipe, &mut *buf).map_err(io::Error::from)) {
            Err(error)
              if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
              ) => {}
            Ok(count) => return Poll::Ready(check_count(count, buf.len())),
            Err(error) => return Poll::Ready(Err(error)),
          }
        }
      }
    }
  }

  fn poll_read_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &mut [IoSliceMut<'_>],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    let offered = match read_len(bufs) {
      Ok(len) => len,
      Err(error) => {
        this.waiter = None;
        return Poll::Ready(Err(error));
      }
    };
    if offered == 0 {
      this.waiter = None;
      return Poll::Ready(Ok(0));
    }

    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
      if this.waiter.is_none() {
        this.waiter = Some(this.fd.readable_owned());
      }
      let readiness = match this.waiter.as_mut() {
        Some(waiter) => Pin::new(waiter).poll(cx),
        None => unreachable!("read waiter was just created"),
      };
      match readiness {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => {
          this.waiter = None;
          return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(guard)) => {
          this.waiter = None;
          attempts += 1;
          match guard.try_io(|pipe| readv(pipe, bufs).map_err(io::Error::from)) {
            Err(error)
              if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
              ) => {}
            Ok(count) => return Poll::Ready(check_count(count, offered)),
            Err(error) => return Poll::Ready(Err(error)),
          }
        }
      }
    }
  }
}

impl<T> AsyncWrite for ChildPipeWriter<T>
where
  T: AsFd + Send + Sync + 'static,
{
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    let Some(fd) = this.fd.as_ref() else {
      return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
    };
    if buf.is_empty() {
      this.waiter = None;
      return Poll::Ready(Ok(0));
    }

    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
      if this.waiter.is_none() {
        this.waiter = Some(fd.writable_owned());
      }
      let readiness = match this.waiter.as_mut() {
        Some(waiter) => Pin::new(waiter).poll(cx),
        None => unreachable!("write waiter was just created"),
      };
      match readiness {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => {
          this.waiter = None;
          return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(guard)) => {
          this.waiter = None;
          attempts += 1;
          match guard.try_io(|pipe| write(pipe, buf).map_err(io::Error::from)) {
            Err(error)
              if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
              ) => {}
            Ok(count) => return Poll::Ready(check_count(count, buf.len())),
            Err(error) => return Poll::Ready(Err(error)),
          }
        }
      }
    }
  }

  fn poll_write_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    let Some(fd) = this.fd.as_ref() else {
      return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
    };
    let offered = match write_len(bufs) {
      Ok(len) => len,
      Err(error) => {
        this.waiter = None;
        return Poll::Ready(Err(error));
      }
    };
    if offered == 0 {
      this.waiter = None;
      return Poll::Ready(Ok(0));
    }

    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
      if this.waiter.is_none() {
        this.waiter = Some(fd.writable_owned());
      }
      let readiness = match this.waiter.as_mut() {
        Some(waiter) => Pin::new(waiter).poll(cx),
        None => unreachable!("write waiter was just created"),
      };
      match readiness {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => {
          this.waiter = None;
          return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(guard)) => {
          this.waiter = None;
          attempts += 1;
          match guard.try_io(|pipe| writev(pipe, bufs).map_err(io::Error::from)) {
            Err(error)
              if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
              ) => {}
            Ok(count) => return Poll::Ready(check_count(count, offered)),
            Err(error) => return Poll::Ready(Err(error)),
          }
        }
      }
    }
  }

  fn is_write_vectored(&self) -> bool {
    true
  }

  fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.as_mut().get_mut();
    this.waiter = None;
    this.fd = None;
    Poll::Ready(Ok(()))
  }
}

impl<T> fmt::Debug for ChildPipeReader<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ChildPipeReader")
      .field("waiting", &self.waiter.is_some())
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Debug for ChildPipeWriter<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ChildPipeWriter")
      .field("open", &self.fd.is_some())
      .field("waiting", &self.waiter.is_some())
      .finish_non_exhaustive()
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::{AsyncChildStderr, AsyncChildStdin, AsyncChildStdout, ChildPipeReader};
  use crate::runtime::io::{AsyncRead, AsyncWrite};
  use crate::runtime::reactor::{Reactor, ReactorConfig};
  use std::future::{Future, poll_fn};
  use std::io::{self, IoSlice, IoSliceMut};
  use std::os::fd::AsFd;
  use std::pin::Pin;
  use std::process::{Child, Command, Stdio};
  use std::sync::Arc;
  use std::task::{Context, Poll, Wake, Waker};
  use std::thread;
  use std::time::Duration;

  struct ThreadWake(thread::Thread);

  impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
      self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.0.unpark();
    }
  }

  fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
      match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => return output,
        Poll::Pending => thread::park_timeout(Duration::from_secs(1)),
      }
    }
  }

  fn reactor(
    registrations: usize,
    waiters: usize,
  ) -> (Reactor, super::super::super::reactor::ReactorHandle) {
    let reactor = Reactor::new(ReactorConfig {
      max_registrations: registrations,
      max_waiters: waiters,
    })
    .unwrap();
    let handle = reactor.handle();
    (reactor, handle)
  }

  fn helper(mode: &str) -> Command {
    let script = match mode {
      "burst" => {
        "block=$(printf '%8192s' ''); block=${block// /o}; \
         for ((i=0; i<128; i++)); do printf '%s' \"$block\"; done; \
         block=${block//o/e}; \
         for ((i=0; i<128; i++)); do printf '%s' \"$block\" >&2; done"
      }
      "vectors" => "printf '%s' 'vector-read'",
      "hold" => "sleep 20",
      _ => "exit 2",
    };
    let mut command = Command::new("/bin/bash");
    command
      .args(["-c", script])
      .stdout(Stdio::piped())
      .stderr(Stdio::piped());
    command
  }

  fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
  }

  fn read_to_end<R: AsyncRead + Unpin>(mut reader: R) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
      let count = block_on(poll_fn(|cx| {
        Pin::new(&mut reader).poll_read(cx, &mut buffer)
      }))?;
      if count == 0 {
        return Ok(output);
      }
      output.extend_from_slice(&buffer[..count]);
    }
  }

  #[test]
  fn simultaneously_drains_stdout_and_stderr_beyond_pipe_capacity() {
    let (reactor, handle) = reactor(2, 2);
    let mut child = helper("burst").spawn().unwrap();
    let stdout = AsyncChildStdout::from_std(child.stdout.take().unwrap(), &handle).unwrap();
    let stderr = AsyncChildStderr::from_std(child.stderr.take().unwrap(), &handle).unwrap();
    let stdout_reader = thread::spawn(move || read_to_end(stdout).unwrap());
    let stderr_reader = thread::spawn(move || read_to_end(stderr).unwrap());
    let stdout = stdout_reader.join().unwrap();
    let stderr = stderr_reader.join().unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(stdout.len(), 128 * 8192);
    assert!(stdout.iter().all(|byte| *byte == b'o'));
    assert_eq!(stderr.len(), 128 * 8192);
    assert!(stderr.iter().all(|byte| *byte == b'e'));
    reactor.shutdown().unwrap();
  }

  #[test]
  fn vectored_partial_read_and_eof_are_preserved() {
    let (reactor, handle) = reactor(1, 1);
    let mut child = helper("vectors").spawn().unwrap();
    let mut stdout = AsyncChildStdout::from_std(child.stdout.take().unwrap(), &handle).unwrap();
    let mut first = [0_u8; 3];
    let mut second = [0_u8; 2];
    let read = block_on(poll_fn(|cx| {
      let mut buffers = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
      Pin::new(&mut stdout).poll_read_vectored(cx, &mut buffers)
    }))
    .unwrap();
    assert_eq!(read, 5);
    assert_eq!(&first, b"vec");
    assert_eq!(&second, b"to");

    let remainder = read_to_end(stdout).unwrap();
    assert_eq!(remainder, b"r-read");
    assert!(child.wait().unwrap().success());
    reactor.shutdown().unwrap();
  }

  #[test]
  fn vectored_stdin_shutdown_delivers_eof_and_later_write_fails() {
    let (reactor, handle) = reactor(2, 2);
    let mut child = Command::new("/bin/cat")
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .spawn()
      .unwrap();
    let mut stdin = AsyncChildStdin::from_std(child.stdin.take().unwrap(), &handle).unwrap();
    let stdout = AsyncChildStdout::from_std(child.stdout.take().unwrap(), &handle).unwrap();
    let buffers = [IoSlice::new(b"from-"), IoSlice::new(b"stdin")];
    let written = block_on(poll_fn(|cx| {
      Pin::new(&mut stdin).poll_write_vectored(cx, &buffers)
    }))
    .unwrap();
    assert_eq!(written, 10);
    block_on(poll_fn(|cx| Pin::new(&mut stdin).poll_flush(cx))).unwrap();
    block_on(poll_fn(|cx| Pin::new(&mut stdin).poll_shutdown(cx))).unwrap();
    let error = block_on(poll_fn(|cx| Pin::new(&mut stdin).poll_write(cx, b"closed"))).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(read_to_end(stdout).unwrap(), b"from-stdin");
    assert!(child.wait().unwrap().success());
    reactor.shutdown().unwrap();
  }

  #[test]
  fn canceled_pending_poll_releases_bounded_waiter_for_another_pipe() {
    let (reactor, handle) = reactor(2, 1);
    let mut first_child = helper("hold").spawn().unwrap();
    let mut first =
      AsyncChildStdout::from_std(first_child.stdout.take().unwrap(), &handle).unwrap();
    let mut context = Context::from_waker(Waker::noop());
    let mut byte = [0_u8; 1];
    assert!(
      Pin::new(&mut first)
        .poll_read(&mut context, &mut byte)
        .is_pending()
    );
    assert_eq!(handle.waiters(), 1);
    first.cancel_io_waits();
    assert_eq!(handle.waiters(), 0);

    let mut second_child = helper("vectors").spawn().unwrap();
    let second = AsyncChildStdout::from_std(second_child.stdout.take().unwrap(), &handle).unwrap();
    assert_eq!(read_to_end(second).unwrap(), b"vector-read");
    assert!(second_child.wait().unwrap().success());
    drop(first);
    stop(&mut first_child);
    reactor.shutdown().unwrap();
  }

  #[test]
  fn full_reactor_returns_pipe_and_restores_file_status_flags() {
    let (reactor, handle) = reactor(1, 1);
    let mut first_child = helper("hold").spawn().unwrap();
    let first = AsyncChildStdout::from_std(first_child.stdout.take().unwrap(), &handle).unwrap();
    let mut second_child = helper("hold").spawn().unwrap();
    let original = second_child.stdout.take().unwrap();
    let before = rustix::fs::fcntl_getfl(original.as_fd()).unwrap();
    let error = match ChildPipeReader::from_std(original, &handle) {
      Ok(_) => panic!("registration exceeded the reactor bound"),
      Err(error) => error,
    };
    assert_eq!(error.error().kind(), io::ErrorKind::Other);
    assert!(error.restoration_error().is_none());
    let (returned, _, restore) = error.into_parts();
    assert!(restore.is_none());
    assert_eq!(rustix::fs::fcntl_getfl(returned.as_fd()).unwrap(), before);
    drop(first);
    stop(&mut first_child);
    stop(&mut second_child);
    reactor.shutdown().unwrap();
  }
}
