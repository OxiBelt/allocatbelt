//! Bounded readiness driven network endpoints.
//!
//! This first network layer owns nonblocking sockets registered with an
//! explicitly supplied [`ReactorHandle`]. Its named async methods wait for
//! readiness and then make one standard-library syscall through the
//! readiness guard. They do not start a runtime or a blocking pool.
//!
//! Standard endpoint creation and binding are synchronous. `NetHandle::connect`
//! uses its explicitly supplied blocking runtime; the named nonblocking TCP
//! connect methods register before initiating one connect syscall and wait on
//! the explicit reactor. `from_std` takes ownership only on success; a
//! rejected socket is returned intact. Registering sets `O_NONBLOCK` on the
//! shared open file description, which also affects other descriptors sharing
//! it.
//!
//! The async methods preserve partial byte counts and retry `Interrupted`
//! and stale-readiness `WouldBlock`. They make at most 64 endpoint calls per
//! poll before yielding. Readiness waits do not count as endpoint calls.
//! Dropping a named async-method future releases its readiness waiter; bytes
//! already transferred remain transferred. `TcpStream` and Unix `UnixStream`
//! also implement [`AsyncRead`] and [`AsyncWrite`]. Their pending waiter is
//! retained by the endpoint when the caller drops a poll future; it is freed
//! when a later read or write poll in that direction completes (including an
//! empty-buffer poll), by [`TcpStream::cancel_io_waits`] or
//! [`UnixStream::cancel_io_waits`], or when the endpoint is dropped. Flush and
//! shutdown polls do not clear read or write waiters.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::future::poll_fn;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::{
  Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener as StdTcpListener,
  TcpStream as StdTcpStream, ToSocketAddrs, UdpSocket as StdUdpSocket,
};
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use rustix::fs::{self as rfs, OFlags};
use rustix::io::{Errno, FdFlags};
use rustix::net::{self as rnet, AddressFamily, SocketFlags, SocketType};

use super::blocking::Handle as BlockingHandle;
use super::error::{JoinError, SubmitErrorKind};
use super::io::{AsyncRead, AsyncWrite};
use super::managed::{ManagedBuf, OperationPermit, OperationRequest, ResourceError, ResourceScope};
use super::reactor::{AsyncFd, OwnedReadiness, ReactorHandle, RegisterError};
use super::resources::Resources;

const IO_BUDGET: usize = 64;
const ADDRESS_RECORD_BYTES: usize = 27;

#[cfg(all(test, not(loom)))]
#[path = "net_tests.rs"]
mod tests;

/// A refused socket registration, retaining the original socket.
pub struct FromStdError<T> {
  /// Why the reactor refused the descriptor.
  pub error: io::Error,
  /// The unchanged socket returned by the reactor.
  pub socket: T,
}

impl<T> FromStdError<T> {
  fn from_register(error: RegisterError<T>) -> Self {
    let (socket, error) = error.into_parts();
    Self { error, socket }
  }
}

impl<T> fmt::Debug for FromStdError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("FromStdError")
      .field("error", &self.error)
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Display for FromStdError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "socket registration refused: {}", self.error)
  }
}

impl<T: 'static> std::error::Error for FromStdError<T> {}

/// An owned, nonblocking IP TCP socket that is not registered with a reactor.
///
/// New sockets are created with `SOCK_NONBLOCK | SOCK_CLOEXEC`. Importing an
/// existing descriptor requires those flags, an IPv4 or IPv6 TCP stream
/// socket, and a socket that is not listening or currently connected. The
/// import checks cannot detect another descriptor alias that has an earlier
/// connect in progress, changes `O_NONBLOCK`, or consumes `SO_ERROR`; callers
/// must coordinate such aliases for the duration of a connect operation.
#[derive(Debug)]
pub struct TcpSocket {
  fd: OwnedFd,
  family: AddressFamily,
}

impl TcpSocket {
  /// Creates an unbound, nonblocking IPv4 TCP socket.
  pub fn new_v4() -> io::Result<Self> {
    Self::new(AddressFamily::INET)
  }

  /// Creates an unbound, nonblocking IPv6 TCP socket.
  pub fn new_v6() -> io::Result<Self> {
    Self::new(AddressFamily::INET6)
  }

  fn new(family: AddressFamily) -> io::Result<Self> {
    let fd = rnet::socket_with(
      family,
      SocketType::STREAM,
      SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
      Some(rnet::ipproto::TCP),
    )?;
    Ok(Self { fd, family })
  }

  /// Imports an owned descriptor after checking its family, type, protocol,
  /// nonblocking and close-on-exec flags, and listening/connected state.
  ///
  /// On every rejection, the exact original descriptor is returned. Import
  /// does not alter shared open-file-description flags.
  pub fn from_owned_fd(fd: OwnedFd) -> Result<Self, TcpSocketImportError> {
    let family = match rnet::sockopt::socket_domain(&fd) {
      Ok(family @ (AddressFamily::INET | AddressFamily::INET6)) => family,
      Ok(_) => return Err(TcpSocketImportError::new(invalid_tcp_socket(), fd)),
      Err(error) => return Err(TcpSocketImportError::new(error.into(), fd)),
    };
    let reject = |error, fd| TcpSocketImportError::new(error, fd);
    let socket_type = match rnet::sockopt::socket_type(&fd) {
      Ok(socket_type) => socket_type,
      Err(error) => return Err(reject(error.into(), fd)),
    };
    if socket_type != SocketType::STREAM {
      return Err(reject(invalid_tcp_socket(), fd));
    }
    let protocol = match rnet::sockopt::socket_protocol(&fd) {
      Ok(protocol) => protocol,
      Err(error) => return Err(reject(error.into(), fd)),
    };
    if protocol != Some(rnet::ipproto::TCP) {
      return Err(reject(invalid_tcp_socket(), fd));
    }
    let listening = match rnet::sockopt::socket_acceptconn(&fd) {
      Ok(listening) => listening,
      Err(error) => return Err(reject(error.into(), fd)),
    };
    if listening {
      return Err(reject(invalid_tcp_socket(), fd));
    }
    let connected = match rnet::getpeername(&fd) {
      Ok(peer) => peer.is_some(),
      Err(Errno::NOTCONN) => false,
      Err(error) => return Err(reject(error.into(), fd)),
    };
    if connected {
      return Err(reject(invalid_tcp_socket(), fd));
    }
    let status_flags = match rfs::fcntl_getfl(&fd) {
      Ok(flags) => flags,
      Err(error) => return Err(reject(error.into(), fd)),
    };
    let descriptor_flags = match rustix::io::fcntl_getfd(&fd) {
      Ok(flags) => flags,
      Err(error) => return Err(reject(error.into(), fd)),
    };
    if !status_flags.contains(OFlags::NONBLOCK) || !descriptor_flags.contains(FdFlags::CLOEXEC) {
      return Err(reject(
        io::Error::new(
          io::ErrorKind::InvalidInput,
          "imported TCP socket must be nonblocking and close-on-exec",
        ),
        fd,
      ));
    }
    Ok(Self { fd, family })
  }

  /// Binds this socket to an address of its family.
  pub fn bind(&self, address: SocketAddr) -> io::Result<()> {
    if address_family(address) != self.family {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "TCP socket and bind address families differ",
      ));
    }
    rnet::bind(&self.fd, &address).map_err(Into::into)
  }

  /// Returns the current local address, including an assigned ephemeral port.
  pub fn local_addr(&self) -> io::Result<SocketAddr> {
    SocketAddr::try_from(rnet::getsockname(&self.fd)?).map_err(|_| {
      io::Error::new(
        io::ErrorKind::InvalidData,
        "TCP socket returned a non-IP address",
      )
    })
  }

  /// Recovers the original descriptor before submitting a connect operation.
  #[must_use]
  pub fn into_owned_fd(self) -> OwnedFd {
    self.fd
  }

  fn into_stream(self) -> StdTcpStream {
    self.fd.into()
  }
}

fn address_family(address: SocketAddr) -> AddressFamily {
  match address {
    SocketAddr::V4(_) => AddressFamily::INET,
    SocketAddr::V6(_) => AddressFamily::INET6,
  }
}

fn invalid_tcp_socket() -> io::Error {
  io::Error::new(
    io::ErrorKind::InvalidInput,
    "descriptor is not an unconnected IPv4 or IPv6 TCP stream socket",
  )
}

/// A rejected descriptor import, retaining the unchanged owned descriptor.
pub struct TcpSocketImportError {
  /// Why the descriptor did not satisfy the TCP socket requirements.
  pub error: io::Error,
  /// The descriptor returned unchanged for recovery or another use.
  pub socket: OwnedFd,
}

impl TcpSocketImportError {
  fn new(error: io::Error, socket: OwnedFd) -> Self {
    Self { error, socket }
  }
}

impl fmt::Debug for TcpSocketImportError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("TcpSocketImportError")
      .field("error", &self.error)
      .finish_non_exhaustive()
  }
}

impl fmt::Display for TcpSocketImportError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TCP socket import rejected: {}", self.error)
  }
}

impl std::error::Error for TcpSocketImportError {}

/// A registered nonblocking TCP stream.
pub struct TcpStream {
  fd: AsyncFd<StdTcpStream>,
  read_waiter: Option<OwnedReadiness<StdTcpStream>>,
  write_waiter: Option<OwnedReadiness<StdTcpStream>>,
}

impl TcpStream {
  /// Registers an existing stream. Registration sets nonblocking mode.
  pub fn from_std(
    stream: StdTcpStream,
    reactor: &ReactorHandle,
  ) -> Result<Self, FromStdError<StdTcpStream>> {
    reactor
      .register(stream)
      .map(|fd| Self {
        fd,
        read_waiter: None,
        write_waiter: None,
      })
      .map_err(FromStdError::from_register)
  }

  /// The underlying standard stream.
  #[must_use]
  pub fn get_ref(&self) -> &StdTcpStream {
    self.fd.get_ref()
  }

  /// Reads once after readable readiness, preserving the standard stream's
  /// EOF (`Ok(0)`) and partial-read behavior.
  pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
    if buf.is_empty() {
      return Ok(0);
    }
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        yield_once().await;
        attempts = 0;
      }
      let guard = self.fd.readable().await?;
      attempts += 1;
      match guard.try_io(|stream| (&*stream).read(buf)) {
        Err(error)
          if matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
          ) => {}
        result => return result,
      }
    }
  }

  /// Reads once into initialized buffers after readable readiness.
  pub async fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
    stream_read_vectored(&self.fd, bufs).await
  }

  /// Writes once after writable readiness, preserving partial-write counts.
  pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
    if buf.is_empty() {
      return Ok(0);
    }
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        yield_once().await;
        attempts = 0;
      }
      let guard = self.fd.writable().await?;
      attempts += 1;
      match guard.try_io(|stream| (&*stream).write(buf)) {
        Err(error)
          if matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
          ) => {}
        result => return result,
      }
    }
  }

  /// Writes once from initialized buffers after writable readiness.
  pub async fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
    stream_write_vectored(&self.fd, bufs).await
  }

  /// TCP flush is a no-op because writes go directly to the socket.
  pub async fn flush(&self) -> io::Result<()> {
    Ok(())
  }

  /// Shuts down the local write half. The read half remains usable.
  pub async fn shutdown(&self) -> io::Result<()> {
    self.get_ref().shutdown(std::net::Shutdown::Write)
  }

  /// Cancels readiness waits retained by [`AsyncRead`] or [`AsyncWrite`]
  /// after their poll futures were dropped. Call after dropping those
  /// futures; named async methods cancel their waits when dropped.
  pub fn cancel_io_waits(&mut self) {
    self.read_waiter = None;
    self.write_waiter = None;
  }
}

impl AsyncRead for TcpStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    if buf.is_empty() {
      this.read_waiter = None;
      return Poll::Ready(Ok(0));
    }
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
      if this.read_waiter.is_none() {
        this.read_waiter = Some(this.fd.readable_owned());
      }
      let readiness = match this.read_waiter.as_mut() {
        Some(readiness) => Pin::new(readiness).poll(cx),
        None => unreachable!("read waiter was just created"),
      };
      match readiness {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => {
          this.read_waiter = None;
          return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(guard)) => {
          this.read_waiter = None;
          attempts += 1;
          match guard.try_io(|stream| (&*stream).read(buf)) {
            Err(error)
              if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
              ) => {}
            result => return Poll::Ready(result),
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
    let offered = match read_vectored_len(bufs) {
      Ok(len) => len,
      Err(error) => {
        this.read_waiter = None;
        return Poll::Ready(Err(error));
      }
    };
    if offered == 0 {
      this.read_waiter = None;
      return Poll::Ready(Ok(0));
    }
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
      if this.read_waiter.is_none() {
        this.read_waiter = Some(this.fd.readable_owned());
      }
      let readiness = match this.read_waiter.as_mut() {
        Some(readiness) => Pin::new(readiness).poll(cx),
        None => unreachable!("read waiter was just created"),
      };
      match readiness {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => {
          this.read_waiter = None;
          return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(guard)) => {
          this.read_waiter = None;
          attempts += 1;
          match guard.try_io(|stream| {
            let mut stream = stream;
            stream.read_vectored(bufs)
          }) {
            Err(error)
              if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
              ) => {}
            Ok(count) if count > offered => {
              return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            result => return Poll::Ready(result),
          }
        }
      }
    }
  }
}

impl AsyncWrite for TcpStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    if buf.is_empty() {
      this.write_waiter = None;
      return Poll::Ready(Ok(0));
    }
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
      if this.write_waiter.is_none() {
        this.write_waiter = Some(this.fd.writable_owned());
      }
      let readiness = match this.write_waiter.as_mut() {
        Some(readiness) => Pin::new(readiness).poll(cx),
        None => unreachable!("write waiter was just created"),
      };
      match readiness {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => {
          this.write_waiter = None;
          return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(guard)) => {
          this.write_waiter = None;
          attempts += 1;
          match guard.try_io(|stream| (&*stream).write(buf)) {
            Err(error)
              if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
              ) => {}
            result => return Poll::Ready(result),
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
    let offered = match write_vectored_len(bufs) {
      Ok(len) => len,
      Err(error) => {
        this.write_waiter = None;
        return Poll::Ready(Err(error));
      }
    };
    if offered == 0 {
      this.write_waiter = None;
      return Poll::Ready(Ok(0));
    }
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
      if this.write_waiter.is_none() {
        this.write_waiter = Some(this.fd.writable_owned());
      }
      let readiness = match this.write_waiter.as_mut() {
        Some(readiness) => Pin::new(readiness).poll(cx),
        None => unreachable!("write waiter was just created"),
      };
      match readiness {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => {
          this.write_waiter = None;
          return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(guard)) => {
          this.write_waiter = None;
          attempts += 1;
          match guard.try_io(|stream| {
            let mut stream = stream;
            stream.write_vectored(bufs)
          }) {
            Err(error)
              if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
              ) => {}
            Ok(count) if count > offered => {
              return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            result => return Poll::Ready(result),
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

  fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(self.get_mut().get_ref().shutdown(std::net::Shutdown::Write))
  }
}

impl fmt::Debug for TcpStream {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("TcpStream").finish_non_exhaustive()
  }
}

/// A registered nonblocking TCP listener.
pub struct TcpListener {
  fd: AsyncFd<StdTcpListener>,
  reactor: ReactorHandle,
}

impl TcpListener {
  /// Registers an existing listener. Registration sets nonblocking mode.
  pub fn from_std(
    listener: StdTcpListener,
    reactor: &ReactorHandle,
  ) -> Result<Self, FromStdError<StdTcpListener>> {
    reactor
      .register(listener)
      .map(|fd| Self {
        fd,
        reactor: reactor.clone(),
      })
      .map_err(FromStdError::from_register)
  }

  /// The underlying standard listener.
  #[must_use]
  pub fn get_ref(&self) -> &StdTcpListener {
    self.fd.get_ref()
  }

  /// Accepts one connection. If the accepted socket cannot be registered,
  /// [`AcceptError::Registration`] returns that accepted socket to the
  /// caller; the connection has already been consumed from the listen queue.
  pub async fn accept(&self) -> Result<(TcpStream, SocketAddr), AcceptError> {
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        yield_once().await;
        attempts = 0;
      }
      let guard = self.fd.readable().await.map_err(AcceptError::Io)?;
      attempts += 1;
      match guard.try_io(|listener| listener.accept()) {
        Err(error)
          if matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
          ) => {}
        Err(error) => return Err(AcceptError::Io(error)),
        Ok((stream, address)) => match TcpStream::from_std(stream, &self.reactor) {
          Ok(stream) => return Ok((stream, address)),
          Err(error) => return Err(AcceptError::Registration(error)),
        },
      }
    }
  }
}

impl fmt::Debug for TcpListener {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("TcpListener").finish_non_exhaustive()
  }
}

/// Failure to accept or register an accepted connection.
#[derive(Debug)]
pub enum AcceptError {
  /// The accept syscall or readiness wait failed.
  Io(io::Error),
  /// Registration failed and the accepted socket remains available.
  Registration(FromStdError<StdTcpStream>),
}

impl fmt::Display for AcceptError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Io(error) => error.fmt(f),
      Self::Registration(error) => error.fmt(f),
    }
  }
}

impl std::error::Error for AcceptError {}

/// A network operation that uses the explicitly supplied blocking runtime and
/// scope. The operation slot is held by its worker closure until the blocking
/// syscall (including resolver iteration) has actually stopped.
#[derive(Clone)]
pub struct NetHandle {
  blocking: BlockingHandle,
  scope: ResourceScope,
  reactor: ReactorHandle,
  max_dns_addresses: usize,
}

/// Submission, execution, or operation failure from [`NetHandle`].
#[derive(Debug)]
#[non_exhaustive]
pub enum NetworkError {
  /// The scope refused the network operation slot.
  Resource(ResourceError),
  /// The blocking runtime refused the job.
  Runtime(SubmitErrorKind),
  /// The job was cancelled before it started or panicked.
  Join(JoinError),
  /// A network endpoint syscall or resolver operation failed.
  Io(io::Error),
  /// The connected socket could not be registered; ownership is retained.
  Registration(FromStdError<StdTcpStream>),
  /// Resolver yielded more than the configured maximum. The observed
  /// addresses remain charged to their scope and include one overflow item.
  TooManyAddresses(ResolvedAddresses),
}

impl fmt::Display for NetworkError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Resource(error) => error.fmt(f),
      Self::Runtime(error) => write!(f, "network operation refused: {error}"),
      Self::Join(error) => error.fmt(f),
      Self::Io(error) => error.fmt(f),
      Self::Registration(error) => error.fmt(f),
      Self::TooManyAddresses(addresses) => write!(
        f,
        "resolver exceeded address limit (observed {})",
        addresses.len()
      ),
    }
  }
}

impl std::error::Error for NetworkError {}

/// A pre-connect rejection or an error from a nonblocking TCP connect.
#[derive(Debug)]
#[non_exhaustive]
pub enum TcpConnectError {
  /// Admission or reactor registration rejected a supplied socket before the
  /// connect syscall. The socket is returned unchanged.
  Submission(TcpConnectSubmissionError),
  /// Socket creation or a connect operation failed after admission.
  Operation(NetworkError),
}

impl fmt::Display for TcpConnectError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Submission(error) => error.fmt(f),
      Self::Operation(error) => error.fmt(f),
    }
  }
}

impl std::error::Error for TcpConnectError {}

/// The reason a supplied socket was rejected before connect was attempted.
#[derive(Debug)]
#[non_exhaustive]
pub enum TcpConnectRejectKind {
  /// The scope had no network operation slot available.
  Resource(ResourceError),
  /// The supplied socket and destination address are incompatible.
  Socket(io::Error),
  /// The reactor refused registration before connect began.
  Registration(io::Error),
}

/// A pre-connect rejection that retains the caller's supplied socket.
pub struct TcpConnectSubmissionError {
  /// Why admission or registration was rejected.
  pub kind: TcpConnectRejectKind,
  /// The original socket, still available to the caller.
  pub socket: TcpSocket,
}

impl fmt::Debug for TcpConnectSubmissionError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("TcpConnectSubmissionError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl fmt::Display for TcpConnectSubmissionError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TCP connect rejected before connect: {:?}", self.kind)
  }
}

impl std::error::Error for TcpConnectSubmissionError {}

/// A DNS request rejected before the blocking worker accepts ownership.
/// The original hostname and port are returned unchanged for retry.
#[derive(Debug)]
pub struct ResolveSubmissionError {
  /// Why resolution could not be submitted.
  pub kind: ResolveSubmissionKind,
  /// The hostname supplied by the caller.
  pub host: String,
  /// The requested port.
  pub port: u16,
}

/// Resource or runtime admission failure for DNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolveSubmissionKind {
  /// The scope could not reserve output memory or a network operation slot.
  Resource(ResourceError),
  /// The blocking runtime rejected the request.
  Runtime(SubmitErrorKind),
}

impl fmt::Display for ResolveSubmissionError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "DNS request refused: {:?}", self.kind)
  }
}

impl std::error::Error for ResolveSubmissionError {}

/// A DNS failure before submission, or an operation failure after admission.
#[derive(Debug)]
#[non_exhaustive]
pub enum ResolveError {
  /// Submission failed and the caller's original hostname is available.
  Submission(ResolveSubmissionError),
  /// The submitted resolver operation failed or exceeded its bound.
  Operation(NetworkError),
}

impl fmt::Display for ResolveError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Submission(error) => error.fmt(f),
      Self::Operation(error) => error.fmt(f),
    }
  }
}

impl std::error::Error for ResolveError {}

/// A bounded DNS result backed by storage charged to its [`ResourceScope`].
/// Clones share the bytes and their single memory charge until the last clone
/// is dropped. This record buffer charges its full reserved capacity, even if
/// the resolver returns fewer than the configured maximum.
#[derive(Clone)]
pub struct ResolvedAddresses {
  storage: ManagedBuf,
  len: usize,
}

impl ResolvedAddresses {
  /// Number of returned addresses.
  #[must_use]
  pub const fn len(&self) -> usize {
    self.len
  }

  /// Whether the resolver returned no addresses.
  #[must_use]
  pub const fn is_empty(&self) -> bool {
    self.len == 0
  }

  /// Managed storage capacity held by this result, including unused slots.
  #[must_use]
  pub fn charged_bytes(&self) -> usize {
    self.storage.charged_bytes()
  }

  /// The address at `index`, if it is in the result.
  #[must_use]
  pub fn get(&self, index: usize) -> Option<SocketAddr> {
    if index >= self.len {
      return None;
    }
    decode_address(
      &self.storage.as_slice()[index * ADDRESS_RECORD_BYTES..(index + 1) * ADDRESS_RECORD_BYTES],
    )
  }

  /// Iterates over the bounded result without allocating.
  pub fn iter(&self) -> ResolvedAddressesIter<'_> {
    ResolvedAddressesIter {
      addresses: self,
      index: 0,
    }
  }
}

impl fmt::Debug for ResolvedAddresses {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ResolvedAddresses")
      .field("len", &self.len)
      .field("charged_bytes", &self.charged_bytes())
      .finish_non_exhaustive()
  }
}

/// Iterator over a [`ResolvedAddresses`] value.
pub struct ResolvedAddressesIter<'a> {
  addresses: &'a ResolvedAddresses,
  index: usize,
}

impl Iterator for ResolvedAddressesIter<'_> {
  type Item = SocketAddr;

  fn next(&mut self) -> Option<Self::Item> {
    let address = self.addresses.get(self.index)?;
    self.index += 1;
    Some(address)
  }

  fn size_hint(&self) -> (usize, Option<usize>) {
    let remaining = self.addresses.len - self.index;
    (remaining, Some(remaining))
  }
}

impl ExactSizeIterator for ResolvedAddressesIter<'_> {}

impl NetHandle {
  /// Uses an existing blocking pool, resource scope, and reactor. DNS output
  /// is capped at `max_dns_addresses`; one additional observed address is
  /// retained on the explicit overflow error. The bounded result records use
  /// managed storage. The standard resolver's own internal allocations are
  /// platform-controlled and are not accounted here.
  pub fn new(
    blocking: BlockingHandle,
    scope: ResourceScope,
    reactor: ReactorHandle,
    max_dns_addresses: usize,
  ) -> io::Result<Self> {
    let capacity = max_dns_addresses
      .checked_add(1)
      .and_then(|count| count.checked_mul(ADDRESS_RECORD_BYTES));
    if max_dns_addresses == 0 || !matches!(capacity, Some(bytes) if bytes <= isize::MAX as usize) {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "DNS address bound cannot be represented as managed output storage",
      ));
    }
    Ok(Self {
      blocking,
      scope,
      reactor,
      max_dns_addresses,
    })
  }

  /// Opens a TCP connection on the supplied blocking pool, then registers it
  /// with this handle's reactor. Dropping this future detaches the job; the
  /// network permit remains held until the blocking connect has completed.
  pub async fn connect(&self, address: SocketAddr) -> Result<TcpStream, NetworkError> {
    let permit = self.acquire()?;
    let reactor = self.reactor.clone();
    let job = self
      .blocking
      .try_spawn(Resources::ZERO, move |_token| {
        let _permit = permit;
        let stream = StdTcpStream::connect(address)?;
        TcpStream::from_std(stream, &reactor).map_err(|error| {
          let (socket, error) = (error.socket, error.error);
          ConnectWorkerError::Registration(FromStdError { socket, error })
        })
      })
      .map_err(|error| {
        drop(error.job);
        NetworkError::Runtime(error.kind)
      })?;
    match job.await.map_err(NetworkError::Join)? {
      Ok(stream) => Ok(stream),
      Err(ConnectWorkerError::Io(error)) => Err(NetworkError::Io(error)),
      Err(ConnectWorkerError::Registration(error)) => Err(NetworkError::Registration(error)),
    }
  }

  /// Connects to one address using a newly created nonblocking socket and
  /// this handle's reactor. No DNS or address retry is performed. Cancellation
  /// drops the local socket and waiter; it does not undo a handshake already
  /// observed by the remote peer.
  pub async fn connect_nonblocking(
    &self,
    address: SocketAddr,
  ) -> Result<TcpStream, TcpConnectError> {
    let permit = self.acquire().map_err(TcpConnectError::Operation)?;
    let socket = match address_family(address) {
      AddressFamily::INET => TcpSocket::new_v4(),
      AddressFamily::INET6 => TcpSocket::new_v6(),
      _ => unreachable!("IP socket address has an IP family"),
    }
    .map_err(|error| TcpConnectError::Operation(NetworkError::Io(error)))?;
    self.connect_with_permit(socket, address, permit).await
  }

  /// Connects one supplied unregistered socket to one address.
  ///
  /// The scope slot and reactor registration are acquired before the single
  /// connect syscall. A rejection at either step returns the same socket in
  /// [`TcpConnectError::Submission`]. Once connect has been attempted, an
  /// error closes the socket; the operation is never replayed. Dropping this
  /// future closes its waiter and registered descriptor before releasing the
  /// network operation slot. The caller must prevent descriptor aliases from
  /// mutating connection state or flags, or consuming `SO_ERROR` while the
  /// operation is active.
  pub async fn connect_socket(
    &self,
    socket: TcpSocket,
    address: SocketAddr,
  ) -> Result<TcpStream, TcpConnectError> {
    if socket.family != address_family(address) {
      return Err(TcpConnectError::Submission(TcpConnectSubmissionError {
        kind: TcpConnectRejectKind::Socket(io::Error::new(
          io::ErrorKind::InvalidInput,
          "TCP socket and connect address families differ",
        )),
        socket,
      }));
    }
    let permit = match self.acquire() {
      Ok(permit) => permit,
      Err(NetworkError::Resource(error)) => {
        return Err(TcpConnectError::Submission(TcpConnectSubmissionError {
          kind: TcpConnectRejectKind::Resource(error),
          socket,
        }));
      }
      Err(error) => return Err(TcpConnectError::Operation(error)),
    };
    self.connect_with_permit(socket, address, permit).await
  }

  async fn connect_with_permit(
    &self,
    socket: TcpSocket,
    address: SocketAddr,
    permit: OperationPermit,
  ) -> Result<TcpStream, TcpConnectError> {
    let family = socket.family;
    let stream = match TcpStream::from_std(socket.into_stream(), &self.reactor) {
      Ok(stream) => stream,
      Err(error) => {
        let (stream, error) = (error.socket, error.error);
        return Err(TcpConnectError::Submission(TcpConnectSubmissionError {
          kind: TcpConnectRejectKind::Registration(error),
          socket: TcpSocket {
            fd: stream.into(),
            family,
          },
        }));
      }
    };
    let mut attempt = ConnectAttempt::new(stream, permit);
    let pending = match initiate_tcp_connect(attempt.stream_ref(), &address, |stream, address| {
      rnet::connect(stream, address)
    }) {
      Ok(pending) => pending,
      Err(error) => {
        return Err(TcpConnectError::Operation(NetworkError::Io(error)));
      }
    };
    if !pending {
      return Ok(attempt.finish());
    }

    wait_for_tcp_connect(&mut attempt, 1)
      .await
      .map_err(|error| TcpConnectError::Operation(NetworkError::Io(error)))?;
    Ok(attempt.finish())
  }

  /// Resolves `(host, port)` on the supplied blocking pool and collects no
  /// more than the configured cap plus one address into memory charged to the
  /// resource scope. If rejected before the worker accepts it, the original
  /// hostname and port are returned inside [`ResolveError::Submission`]. The
  /// resolver's own internal allocations are controlled by the platform and
  /// are not measured by this runtime.
  pub async fn resolve(&self, host: String, port: u16) -> Result<ResolvedAddresses, ResolveError> {
    let permit = match self.scope.try_acquire(OperationRequest {
      disk: 0,
      network: 1,
    }) {
      Ok(permit) => permit,
      Err(kind) => {
        return Err(ResolveError::Submission(ResolveSubmissionError {
          kind: ResolveSubmissionKind::Resource(kind),
          host,
          port,
        }));
      }
    };
    let capacity = (self.max_dns_addresses + 1) * ADDRESS_RECORD_BYTES;
    let storage = match self.scope.try_alloc_zeroed(capacity) {
      Ok(storage) => storage,
      Err(error) => {
        drop(permit);
        return Err(ResolveError::Submission(ResolveSubmissionError {
          kind: ResolveSubmissionKind::Resource(error),
          host,
          port,
        }));
      }
    };
    let maximum = self.max_dns_addresses;
    let request = Arc::new(Mutex::new(Some(ResolveRequest {
      host,
      port,
      storage,
      permit,
    })));
    let worker_request = Arc::clone(&request);
    let job = match self.blocking.try_spawn(Resources::ZERO, move |_token| {
      let ResolveRequest {
        host,
        port,
        storage,
        permit,
      } = take_resolve_request(&worker_request);
      let result = resolve_bounded(host.as_str(), port, maximum, storage);
      drop(host);
      drop(permit);
      result
    }) {
      Ok(job) => {
        drop(request);
        job
      }
      Err(error) => {
        let kind = error.kind;
        drop(error.job);
        let ResolveRequest {
          host,
          port,
          storage,
          permit,
        } = take_resolve_request(&request);
        drop(storage);
        drop(permit);
        return Err(ResolveError::Submission(ResolveSubmissionError {
          kind: ResolveSubmissionKind::Runtime(kind),
          host,
          port,
        }));
      }
    };
    match job
      .await
      .map_err(|error| ResolveError::Operation(NetworkError::Join(error)))?
    {
      Ok(addresses) => Ok(addresses),
      Err(error) => Err(ResolveError::Operation(error)),
    }
  }

  fn acquire(&self) -> Result<OperationPermit, NetworkError> {
    self
      .scope
      .try_acquire(OperationRequest {
        disk: 0,
        network: 1,
      })
      .map_err(NetworkError::Resource)
  }
}

/// Owns the local socket and permit through cancellation and completion.
/// The waiter is dropped first so its registration clone is gone before the
/// original stream closes; the permit is released last.
struct ConnectAttempt {
  waiter: Option<OwnedReadiness<StdTcpStream>>,
  stream: Option<TcpStream>,
  permit: Option<OperationPermit>,
}

impl ConnectAttempt {
  fn new(stream: TcpStream, permit: OperationPermit) -> Self {
    Self {
      waiter: None,
      stream: Some(stream),
      permit: Some(permit),
    }
  }

  fn stream_ref(&self) -> &StdTcpStream {
    match self.stream.as_ref() {
      Some(stream) => stream.get_ref(),
      None => unreachable!("connect attempt stream was already transferred"),
    }
  }

  fn stream_fd(&self) -> &AsyncFd<StdTcpStream> {
    match self.stream.as_ref() {
      Some(stream) => &stream.fd,
      None => unreachable!("connect attempt stream was already transferred"),
    }
  }

  fn finish(mut self) -> TcpStream {
    drop(self.waiter.take());
    let stream = match self.stream.take() {
      Some(stream) => stream,
      None => unreachable!("connect attempt stream was already transferred"),
    };
    drop(self.permit.take());
    stream
  }
}

impl Drop for ConnectAttempt {
  fn drop(&mut self) {
    drop(self.waiter.take());
    drop(self.stream.take());
    drop(self.permit.take());
  }
}

fn classify_connect_start(result: Result<(), Errno>) -> io::Result<bool> {
  match result {
    Ok(()) => Ok(false),
    Err(Errno::INPROGRESS) => Ok(true),
    Err(error) => Err(error.into()),
  }
}

fn initiate_tcp_connect(
  stream: &StdTcpStream,
  address: &SocketAddr,
  connect: impl FnOnce(&StdTcpStream, &SocketAddr) -> Result<(), Errno>,
) -> io::Result<bool> {
  classify_connect_start(connect(stream, address))
}

#[derive(Debug)]
enum ConnectProbeResult {
  Connected,
  SocketError(io::Error),
}

fn classify_connect_probe(
  socket_error: Result<(), Errno>,
  peer_address: impl FnOnce() -> io::Result<SocketAddr>,
) -> io::Result<ConnectProbeResult> {
  if let Err(error) = socket_error {
    return Ok(ConnectProbeResult::SocketError(error.into()));
  }
  match peer_address() {
    Ok(_) => Ok(ConnectProbeResult::Connected),
    Err(error) if error.kind() == io::ErrorKind::NotConnected => Err(io::Error::new(
      io::ErrorKind::WouldBlock,
      "TCP peer address is not available yet",
    )),
    Err(error) => Err(error),
  }
}

fn finish_connect_probe(probe: io::Result<ConnectProbeResult>) -> io::Result<bool> {
  match probe {
    Ok(ConnectProbeResult::Connected) => Ok(true),
    Ok(ConnectProbeResult::SocketError(error)) => Err(error),
    Err(error)
      if matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
      ) =>
    {
      Ok(false)
    }
    Err(error) => Err(error),
  }
}

async fn wait_for_tcp_connect(
  attempt: &mut ConnectAttempt,
  mut endpoint_calls: usize,
) -> io::Result<()> {
  loop {
    if endpoint_calls + 2 > IO_BUDGET {
      yield_once().await;
      endpoint_calls = 0;
    }
    let guard = poll_fn(|cx| {
      if attempt.waiter.is_none() {
        attempt.waiter = Some(attempt.stream_fd().writable_owned());
      }
      let waiter = match attempt.waiter.as_mut() {
        Some(waiter) => waiter,
        None => unreachable!("connect readiness waiter was just created"),
      };
      match Pin::new(waiter).poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(error)) => {
          drop(attempt.waiter.take());
          Poll::Ready(Err(error))
        }
        Poll::Ready(Ok(guard)) => {
          drop(attempt.waiter.take());
          Poll::Ready(Ok(guard))
        }
      }
    })
    .await?;
    let connected = finish_connect_probe(guard.try_io(|stream| {
      let socket_error = rnet::sockopt::socket_error(stream)?;
      classify_connect_probe(socket_error, || stream.peer_addr())
    }));
    match connected {
      Ok(true) => return Ok(()),
      Ok(false) => {
        endpoint_calls += 2;
      }
      Err(error) => return Err(error),
    }
  }
}

enum ConnectWorkerError {
  Io(io::Error),
  Registration(FromStdError<StdTcpStream>),
}

impl From<io::Error> for ConnectWorkerError {
  fn from(error: io::Error) -> Self {
    Self::Io(error)
  }
}

struct ResolveRequest {
  host: String,
  port: u16,
  storage: ManagedBuf,
  permit: OperationPermit,
}

fn take_resolve_request(request: &Mutex<Option<ResolveRequest>>) -> ResolveRequest {
  lock(request)
    .take()
    .unwrap_or_else(|| panic!("DNS request was consumed before worker start"))
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn resolve_bounded(
  host: &str,
  port: u16,
  maximum: usize,
  storage: ManagedBuf,
) -> Result<ResolvedAddresses, NetworkError> {
  collect_bounded(
    (host, port).to_socket_addrs().map_err(NetworkError::Io)?,
    maximum,
    storage,
    0,
  )
}

fn collect_bounded(
  addresses: impl Iterator<Item = SocketAddr>,
  maximum: usize,
  mut storage: ManagedBuf,
  mut len: usize,
) -> Result<ResolvedAddresses, NetworkError> {
  for address in addresses {
    if len == maximum + 1 {
      return Err(NetworkError::TooManyAddresses(ResolvedAddresses {
        storage,
        len,
      }));
    }
    let start = len * ADDRESS_RECORD_BYTES;
    let end = start + ADDRESS_RECORD_BYTES;
    let Some(bytes) = storage.get_mut() else {
      return Err(NetworkError::Resource(ResourceError::Shared));
    };
    encode_address(address, &mut bytes[start..end]);
    len += 1;
    if len == maximum + 1 {
      return Err(NetworkError::TooManyAddresses(ResolvedAddresses {
        storage,
        len,
      }));
    }
  }
  Ok(ResolvedAddresses { storage, len })
}

fn encode_address(address: SocketAddr, record: &mut [u8]) {
  debug_assert_eq!(record.len(), ADDRESS_RECORD_BYTES);
  record[1..3].copy_from_slice(&address.port().to_be_bytes());
  match address {
    SocketAddr::V4(address) => {
      record[0] = 4;
      record[3..7].copy_from_slice(&address.ip().octets());
    }
    SocketAddr::V6(address) => {
      record[0] = 6;
      record[3..19].copy_from_slice(&address.ip().octets());
      record[19..23].copy_from_slice(&address.flowinfo().to_be_bytes());
      record[23..27].copy_from_slice(&address.scope_id().to_be_bytes());
    }
  }
}

fn decode_address(record: &[u8]) -> Option<SocketAddr> {
  if record.len() != ADDRESS_RECORD_BYTES {
    return None;
  }
  let port = u16::from_be_bytes(record[1..3].try_into().ok()?);
  match record[0] {
    4 => {
      let octets: [u8; 4] = record[3..7].try_into().ok()?;
      Some(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::from(octets),
        port,
      )))
    }
    6 => {
      let octets: [u8; 16] = record[3..19].try_into().ok()?;
      let flowinfo = u32::from_be_bytes(record[19..23].try_into().ok()?);
      let scope_id = u32::from_be_bytes(record[23..27].try_into().ok()?);
      Some(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(octets),
        port,
        flowinfo,
        scope_id,
      )))
    }
    _ => None,
  }
}

/// A registered nonblocking UDP socket.
pub struct UdpSocket {
  fd: AsyncFd<StdUdpSocket>,
}

impl UdpSocket {
  /// Registers an existing datagram socket. Registration sets nonblocking mode.
  pub fn from_std(
    socket: StdUdpSocket,
    reactor: &ReactorHandle,
  ) -> Result<Self, FromStdError<StdUdpSocket>> {
    reactor
      .register(socket)
      .map(|fd| Self { fd })
      .map_err(FromStdError::from_register)
  }

  /// The underlying standard socket.
  #[must_use]
  pub fn get_ref(&self) -> &StdUdpSocket {
    self.fd.get_ref()
  }

  /// Sends one datagram to the peer selected by the standard socket's
  /// `connect`. Empty buffers still send a zero-length datagram. Peer
  /// selection is explicit; this method performs no DNS or connection retry.
  pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        yield_once().await;
        attempts = 0;
      }
      let guard = self.fd.writable().await?;
      attempts += 1;
      match guard.try_io(|socket| socket.send(buf)) {
        Err(error)
          if matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
          ) => {}
        result => return result,
      }
    }
  }

  /// Receives one datagram, using the kernel's connected-peer filtering when
  /// the underlying socket is connected. Excess bytes are discarded; an
  /// empty buffer consumes a datagram, rather than returning early.
  pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
    self.readable_operation(|socket| socket.recv(buf)).await
  }

  /// Inspects a datagram without consuming it. The returned count is capped
  /// by the buffer, including zero; a subsequent receive still sees the
  /// complete original datagram, subject to competing descriptor aliases.
  pub async fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
    self.readable_operation(|socket| socket.peek(buf)).await
  }

  /// Inspects a datagram and its source without consuming it. Connected
  /// sockets retain kernel peer filtering. Cancellation releases this
  /// future's readiness waiter without dequeuing the datagram.
  pub async fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    self
      .readable_operation(|socket| socket.peek_from(buf))
      .await
  }

  async fn readable_operation<T>(
    &self,
    mut operation: impl FnMut(&StdUdpSocket) -> io::Result<T>,
  ) -> io::Result<T> {
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        yield_once().await;
        attempts = 0;
      }
      let guard = self.fd.readable().await?;
      attempts += 1;
      match guard.try_io(&mut operation) {
        Err(error)
          if matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
          ) => {}
        result => return result,
      }
    }
  }

  /// Sends one complete datagram in one syscall. A short successful count is
  /// returned as reported by the operating system.
  pub async fn send_to(&self, buf: &[u8], address: SocketAddr) -> io::Result<usize> {
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        yield_once().await;
        attempts = 0;
      }
      let guard = self.fd.writable().await?;
      attempts += 1;
      match guard.try_io(|socket| socket.send_to(buf, address)) {
        Err(error)
          if matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
          ) => {}
        result => return result,
      }
    }
  }

  /// Receives one datagram into the initialized buffer and returns its source.
  /// A datagram larger than `buf` is truncated by the operating system.
  pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        yield_once().await;
        attempts = 0;
      }
      let guard = self.fd.readable().await?;
      attempts += 1;
      match guard.try_io(|socket| socket.recv_from(buf)) {
        Err(error)
          if matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
          ) => {}
        result => return result,
      }
    }
  }
}

impl fmt::Debug for UdpSocket {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("UdpSocket").finish_non_exhaustive()
  }
}

#[cfg(unix)]
mod unix {
  use super::*;
  use std::os::unix::net::{
    UnixDatagram as StdUnixDatagram, UnixListener as StdUnixListener, UnixStream as StdUnixStream,
  };

  /// Registered nonblocking Unix stream.
  pub struct UnixStream {
    pub(super) fd: AsyncFd<StdUnixStream>,
    read_waiter: Option<OwnedReadiness<StdUnixStream>>,
    write_waiter: Option<OwnedReadiness<StdUnixStream>>,
  }

  impl UnixStream {
    /// Registers an existing stream and enables nonblocking mode.
    pub fn from_std(
      stream: StdUnixStream,
      reactor: &ReactorHandle,
    ) -> Result<Self, FromStdError<StdUnixStream>> {
      reactor
        .register(stream)
        .map(|fd| Self {
          fd,
          read_waiter: None,
          write_waiter: None,
        })
        .map_err(FromStdError::from_register)
    }
    /// The underlying standard stream.
    #[must_use]
    pub fn get_ref(&self) -> &StdUnixStream {
      self.fd.get_ref()
    }
    /// Reads once after readable readiness.
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
      stream_read(&self.fd, buf).await
    }
    /// Reads once into initialized buffers after readable readiness.
    pub async fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
      stream_read_vectored(&self.fd, bufs).await
    }
    /// Writes once after writable readiness.
    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
      stream_write(&self.fd, buf).await
    }
    /// Writes once from initialized buffers after writable readiness.
    pub async fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
      stream_write_vectored(&self.fd, bufs).await
    }
    /// Flushes the direct socket writer.
    pub async fn flush(&self) -> io::Result<()> {
      Ok(())
    }
    /// Shuts down the local write half.
    pub async fn shutdown(&self) -> io::Result<()> {
      self.get_ref().shutdown(std::net::Shutdown::Write)
    }

    /// Cancels readiness waits retained by [`AsyncRead`] or [`AsyncWrite`]
    /// after their poll futures were dropped. Call after dropping those
    /// futures; named async methods cancel their waits when dropped.
    pub fn cancel_io_waits(&mut self) {
      self.read_waiter = None;
      self.write_waiter = None;
    }
  }

  impl AsyncRead for UnixStream {
    fn poll_read(
      mut self: Pin<&mut Self>,
      cx: &mut Context<'_>,
      buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
      let this = self.as_mut().get_mut();
      if buf.is_empty() {
        this.read_waiter = None;
        return Poll::Ready(Ok(0));
      }
      let mut attempts = 0;
      loop {
        if attempts == IO_BUDGET {
          cx.waker().wake_by_ref();
          return Poll::Pending;
        }
        if this.read_waiter.is_none() {
          this.read_waiter = Some(this.fd.readable_owned());
        }
        let readiness = match this.read_waiter.as_mut() {
          Some(readiness) => Pin::new(readiness).poll(cx),
          None => unreachable!("read waiter was just created"),
        };
        match readiness {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Err(error)) => {
            this.read_waiter = None;
            return Poll::Ready(Err(error));
          }
          Poll::Ready(Ok(guard)) => {
            this.read_waiter = None;
            attempts += 1;
            match guard.try_io(|stream| (&*stream).read(buf)) {
              Err(error)
                if matches!(
                  error.kind(),
                  io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
              result => return Poll::Ready(result),
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
      let offered = match read_vectored_len(bufs) {
        Ok(len) => len,
        Err(error) => {
          this.read_waiter = None;
          return Poll::Ready(Err(error));
        }
      };
      if offered == 0 {
        this.read_waiter = None;
        return Poll::Ready(Ok(0));
      }
      let mut attempts = 0;
      loop {
        if attempts == IO_BUDGET {
          cx.waker().wake_by_ref();
          return Poll::Pending;
        }
        if this.read_waiter.is_none() {
          this.read_waiter = Some(this.fd.readable_owned());
        }
        let readiness = match this.read_waiter.as_mut() {
          Some(readiness) => Pin::new(readiness).poll(cx),
          None => unreachable!("read waiter was just created"),
        };
        match readiness {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Err(error)) => {
            this.read_waiter = None;
            return Poll::Ready(Err(error));
          }
          Poll::Ready(Ok(guard)) => {
            this.read_waiter = None;
            attempts += 1;
            match guard.try_io(|stream| {
              let mut stream = stream;
              stream.read_vectored(bufs)
            }) {
              Err(error)
                if matches!(
                  error.kind(),
                  io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
              Ok(count) if count > offered => {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
              }
              result => return Poll::Ready(result),
            }
          }
        }
      }
    }
  }

  impl AsyncWrite for UnixStream {
    fn poll_write(
      mut self: Pin<&mut Self>,
      cx: &mut Context<'_>,
      buf: &[u8],
    ) -> Poll<io::Result<usize>> {
      let this = self.as_mut().get_mut();
      if buf.is_empty() {
        this.write_waiter = None;
        return Poll::Ready(Ok(0));
      }
      let mut attempts = 0;
      loop {
        if attempts == IO_BUDGET {
          cx.waker().wake_by_ref();
          return Poll::Pending;
        }
        if this.write_waiter.is_none() {
          this.write_waiter = Some(this.fd.writable_owned());
        }
        let readiness = match this.write_waiter.as_mut() {
          Some(readiness) => Pin::new(readiness).poll(cx),
          None => unreachable!("write waiter was just created"),
        };
        match readiness {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Err(error)) => {
            this.write_waiter = None;
            return Poll::Ready(Err(error));
          }
          Poll::Ready(Ok(guard)) => {
            this.write_waiter = None;
            attempts += 1;
            match guard.try_io(|stream| (&*stream).write(buf)) {
              Err(error)
                if matches!(
                  error.kind(),
                  io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
              result => return Poll::Ready(result),
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
      let offered = match write_vectored_len(bufs) {
        Ok(len) => len,
        Err(error) => {
          this.write_waiter = None;
          return Poll::Ready(Err(error));
        }
      };
      if offered == 0 {
        this.write_waiter = None;
        return Poll::Ready(Ok(0));
      }
      let mut attempts = 0;
      loop {
        if attempts == IO_BUDGET {
          cx.waker().wake_by_ref();
          return Poll::Pending;
        }
        if this.write_waiter.is_none() {
          this.write_waiter = Some(this.fd.writable_owned());
        }
        let readiness = match this.write_waiter.as_mut() {
          Some(readiness) => Pin::new(readiness).poll(cx),
          None => unreachable!("write waiter was just created"),
        };
        match readiness {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Err(error)) => {
            this.write_waiter = None;
            return Poll::Ready(Err(error));
          }
          Poll::Ready(Ok(guard)) => {
            this.write_waiter = None;
            attempts += 1;
            match guard.try_io(|stream| {
              let mut stream = stream;
              stream.write_vectored(bufs)
            }) {
              Err(error)
                if matches!(
                  error.kind(),
                  io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
              Ok(count) if count > offered => {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
              }
              result => return Poll::Ready(result),
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

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      Poll::Ready(self.get_mut().get_ref().shutdown(std::net::Shutdown::Write))
    }
  }
  impl fmt::Debug for UnixStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.debug_struct("UnixStream").finish_non_exhaustive()
    }
  }

  /// Registered nonblocking Unix listener.
  pub struct UnixListener {
    pub(super) fd: AsyncFd<StdUnixListener>,
    reactor: ReactorHandle,
  }
  impl UnixListener {
    /// Registers an existing listener and enables nonblocking mode.
    pub fn from_std(
      listener: StdUnixListener,
      reactor: &ReactorHandle,
    ) -> Result<Self, FromStdError<StdUnixListener>> {
      reactor
        .register(listener)
        .map(|fd| Self {
          fd,
          reactor: reactor.clone(),
        })
        .map_err(FromStdError::from_register)
    }
    /// Accepts one connection; registration failure returns the accepted socket.
    pub async fn accept(
      &self,
    ) -> Result<(UnixStream, std::os::unix::net::SocketAddr), UnixAcceptError> {
      let mut attempts = 0;
      loop {
        if attempts == IO_BUDGET {
          yield_once().await;
          attempts = 0;
        }
        let guard = self.fd.readable().await.map_err(UnixAcceptError::Io)?;
        attempts += 1;
        match guard.try_io(|listener| listener.accept()) {
          Err(error)
            if matches!(
              error.kind(),
              io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) => {}
          Err(error) => return Err(UnixAcceptError::Io(error)),
          Ok((stream, address)) => match UnixStream::from_std(stream, &self.reactor) {
            Ok(stream) => return Ok((stream, address)),
            Err(error) => return Err(UnixAcceptError::Registration(error)),
          },
        }
      }
    }
  }
  impl fmt::Debug for UnixListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.debug_struct("UnixListener").finish_non_exhaustive()
    }
  }
  #[derive(Debug)]
  pub enum UnixAcceptError {
    Io(io::Error),
    Registration(FromStdError<StdUnixStream>),
  }
  impl fmt::Display for UnixAcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
        Self::Io(e) => e.fmt(f),
        Self::Registration(e) => e.fmt(f),
      }
    }
  }
  impl std::error::Error for UnixAcceptError {}

  /// Registered nonblocking Unix datagram socket.
  pub struct UnixDatagram {
    pub(super) fd: AsyncFd<StdUnixDatagram>,
  }
  impl UnixDatagram {
    /// Registers an existing datagram socket and enables nonblocking mode.
    pub fn from_std(
      socket: StdUnixDatagram,
      reactor: &ReactorHandle,
    ) -> Result<Self, FromStdError<StdUnixDatagram>> {
      reactor
        .register(socket)
        .map(|fd| Self { fd })
        .map_err(FromStdError::from_register)
    }
    /// The underlying standard datagram socket.
    #[must_use]
    pub fn get_ref(&self) -> &StdUnixDatagram {
      self.fd.get_ref()
    }
    /// Sends one datagram in one syscall.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
      datagram_send(&self.fd, buf).await
    }
    /// Sends one datagram to a filesystem Unix socket path.
    pub async fn send_to(&self, buf: &[u8], path: &std::path::Path) -> io::Result<usize> {
      let mut attempts = 0;
      loop {
        if attempts == IO_BUDGET {
          yield_once().await;
          attempts = 0;
        }
        let guard = self.fd.writable().await?;
        attempts += 1;
        match guard.try_io(|socket| socket.send_to(buf, path)) {
          Err(error)
            if matches!(
              error.kind(),
              io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) => {}
          result => return result,
        }
      }
    }
    /// Receives one datagram in one syscall.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
      datagram_recv(&self.fd, buf).await
    }
    /// Receives one datagram and returns its source address.
    pub async fn recv_from(
      &self,
      buf: &mut [u8],
    ) -> io::Result<(usize, std::os::unix::net::SocketAddr)> {
      let mut attempts = 0;
      loop {
        if attempts == IO_BUDGET {
          yield_once().await;
          attempts = 0;
        }
        let guard = self.fd.readable().await?;
        attempts += 1;
        match guard.try_io(|socket| socket.recv_from(buf)) {
          Err(error)
            if matches!(
              error.kind(),
              io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) => {}
          result => return result,
        }
      }
    }
  }
  impl fmt::Debug for UnixDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.debug_struct("UnixDatagram").finish_non_exhaustive()
    }
  }

  async fn stream_read(fd: &AsyncFd<StdUnixStream>, buf: &mut [u8]) -> io::Result<usize> {
    if buf.is_empty() {
      return Ok(0);
    }
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        yield_once().await;
        attempts = 0;
      }
      let g = fd.readable().await?;
      attempts += 1;
      match g.try_io(|s| (&*s).read(buf)) {
        Err(e)
          if matches!(
            e.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
          ) => {}
        r => return r,
      }
    }
  }
  async fn stream_write(fd: &AsyncFd<StdUnixStream>, buf: &[u8]) -> io::Result<usize> {
    if buf.is_empty() {
      return Ok(0);
    }
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        yield_once().await;
        attempts = 0;
      }
      let g = fd.writable().await?;
      attempts += 1;
      match g.try_io(|s| (&*s).write(buf)) {
        Err(e)
          if matches!(
            e.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
          ) => {}
        r => return r,
      }
    }
  }
  async fn datagram_send(fd: &AsyncFd<StdUnixDatagram>, buf: &[u8]) -> io::Result<usize> {
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        yield_once().await;
        attempts = 0;
      }
      let g = fd.writable().await?;
      attempts += 1;
      match g.try_io(|s| s.send(buf)) {
        Err(e)
          if matches!(
            e.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
          ) => {}
        r => return r,
      }
    }
  }
  async fn datagram_recv(fd: &AsyncFd<StdUnixDatagram>, buf: &mut [u8]) -> io::Result<usize> {
    let mut attempts = 0;
    loop {
      if attempts == IO_BUDGET {
        yield_once().await;
        attempts = 0;
      }
      let g = fd.readable().await?;
      attempts += 1;
      match g.try_io(|s| s.recv(buf)) {
        Err(e)
          if matches!(
            e.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
          ) => {}
        r => return r,
      }
    }
  }

  pub use self::UnixAcceptError as PublicUnixAcceptError;
  pub use self::UnixDatagram as PublicUnixDatagram;
  pub use self::UnixListener as PublicUnixListener;
  pub use self::UnixStream as PublicUnixStream;
}

#[cfg(unix)]
pub use unix::{
  PublicUnixAcceptError as UnixAcceptError, PublicUnixDatagram as UnixDatagram,
  PublicUnixListener as UnixListener, PublicUnixStream as UnixStream,
};

/// Yields after a bounded run of interrupted syscalls.
async fn yield_once() {
  let mut yielded = false;
  std::future::poll_fn(|cx| {
    if yielded {
      Poll::Ready(())
    } else {
      yielded = true;
      cx.waker().wake_by_ref();
      Poll::Pending
    }
  })
  .await
}

fn read_vectored_len(bufs: &[IoSliceMut<'_>]) -> io::Result<usize> {
  bufs.iter().try_fold(0_usize, |total, buf| {
    total
      .checked_add(buf.len())
      .ok_or_else(|| io::ErrorKind::InvalidInput.into())
  })
}

fn write_vectored_len(bufs: &[IoSlice<'_>]) -> io::Result<usize> {
  bufs.iter().try_fold(0_usize, |total, buf| {
    total
      .checked_add(buf.len())
      .ok_or_else(|| io::ErrorKind::InvalidInput.into())
  })
}

fn checked_vectored_count(count: usize, offered: usize) -> io::Result<usize> {
  if count <= offered {
    Ok(count)
  } else {
    Err(io::ErrorKind::InvalidData.into())
  }
}

async fn stream_read_vectored<T>(fd: &AsyncFd<T>, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize>
where
  for<'a> &'a T: Read,
{
  let offered = read_vectored_len(bufs)?;
  if offered == 0 {
    return Ok(0);
  }
  let mut attempts = 0;
  loop {
    if attempts == IO_BUDGET {
      yield_once().await;
      attempts = 0;
    }
    let guard = fd.readable().await?;
    attempts += 1;
    match guard.try_io(|stream| {
      let mut stream = stream;
      stream.read_vectored(bufs)
    }) {
      Err(error)
        if matches!(
          error.kind(),
          io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ) => {}
      Ok(count) => return checked_vectored_count(count, offered),
      Err(error) => return Err(error),
    }
  }
}

async fn stream_write_vectored<T>(fd: &AsyncFd<T>, bufs: &[IoSlice<'_>]) -> io::Result<usize>
where
  for<'a> &'a T: Write,
{
  let offered = write_vectored_len(bufs)?;
  if offered == 0 {
    return Ok(0);
  }
  let mut attempts = 0;
  loop {
    if attempts == IO_BUDGET {
      yield_once().await;
      attempts = 0;
    }
    let guard = fd.writable().await?;
    attempts += 1;
    match guard.try_io(|stream| {
      let mut stream = stream;
      stream.write_vectored(bufs)
    }) {
      Err(error)
        if matches!(
          error.kind(),
          io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ) => {}
      Ok(count) => return checked_vectored_count(count, offered),
      Err(error) => return Err(error),
    }
  }
}

#[cfg(all(test, not(loom)))]
mod vectored_tests {
  use std::future::Future;
  use std::io::{IoSlice, IoSliceMut, Read, Write};
  use std::net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream};
  use std::pin::pin;
  use std::task::{Context, Poll, Waker};
  use std::thread;
  use std::time::{Duration, Instant};

  use super::*;
  use crate::runtime::io::{AsyncReadExt, AsyncWriteExt};
  use crate::runtime::reactor::{Reactor, ReactorConfig};

  const TIMEOUT: Duration = Duration::from_secs(5);

  fn reactor() -> Reactor {
    Reactor::new(ReactorConfig {
      max_registrations: 2,
      max_waiters: 8,
    })
    .unwrap()
  }

  fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    let deadline = Instant::now() + TIMEOUT;
    loop {
      match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => return output,
        Poll::Pending => {
          assert!(
            Instant::now() < deadline,
            "vectored network operation timed out"
          );
          thread::sleep(Duration::from_millis(1));
        }
      }
    }
  }

  #[test]
  fn tcp_trait_vectored_io_uses_scatter_gather_readiness_paths() {
    let reactor = reactor();
    let handle = reactor.handle();
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let peer_address = listener.local_addr().unwrap();
    let mut stream =
      TcpStream::from_std(StdTcpStream::connect(peer_address).unwrap(), &handle).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(TIMEOUT)).unwrap();
    peer.set_write_timeout(Some(TIMEOUT)).unwrap();

    let outgoing = [IoSlice::new(b"tcp-"), IoSlice::new(b"vectors")];
    assert!(stream.is_write_vectored());
    assert_eq!(
      block_on(AsyncWriteExt::write_vectored(&mut stream, &outgoing)).unwrap(),
      11
    );
    let mut received = [0_u8; 11];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"tcp-vectors");

    let mut first = [0_u8; 7];
    let mut second = [0_u8; 5];
    let mut incoming = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
    {
      let mut waiting = Box::pin(AsyncReadExt::read_vectored(&mut stream, &mut incoming));
      let mut cx = Context::from_waker(Waker::noop());
      assert!(waiting.as_mut().poll(&mut cx).is_pending());
    }
    assert!(stream.read_waiter.is_some());
    stream.cancel_io_waits();
    assert!(stream.read_waiter.is_none());

    peer.write_all(b"scatter-read").unwrap();
    assert_eq!(
      block_on(AsyncReadExt::read_vectored(&mut stream, &mut incoming)).unwrap(),
      12
    );
    assert_eq!(&incoming[0][..], b"scatter");
    assert_eq!(&incoming[1][..], b"-read");
  }

  #[cfg(unix)]
  #[test]
  fn unix_inherent_vectored_io_uses_scatter_gather_readiness_paths() {
    use std::os::unix::net::UnixStream as StdUnixStream;

    let reactor = reactor();
    let handle = reactor.handle();
    let (registered, mut peer) = StdUnixStream::pair().unwrap();
    peer.set_read_timeout(Some(TIMEOUT)).unwrap();
    peer.set_write_timeout(Some(TIMEOUT)).unwrap();
    let stream = UnixStream::from_std(registered, &handle).unwrap();

    let outgoing = [IoSlice::new(b"unix"), IoSlice::new(b"-vectors")];
    assert!(stream.is_write_vectored());
    assert_eq!(block_on(stream.write_vectored(&outgoing)).unwrap(), 12);
    let mut received = [0_u8; 12];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"unix-vectors");

    peer.write_all(b"unix-scatter").unwrap();
    let mut first = [0_u8; 4];
    let mut second = [0_u8; 8];
    let mut incoming = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
    assert_eq!(block_on(stream.read_vectored(&mut incoming)).unwrap(), 12);
    assert_eq!(&incoming[0][..], b"unix");
    assert_eq!(&incoming[1][..], b"-scatter");
  }
}
