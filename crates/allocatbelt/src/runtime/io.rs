//! Runtime-neutral asynchronous I/O over initialized byte buffers: the
//! [`AsyncRead`], [`AsyncWrite`] and [`AsyncSeek`] traits, the futures their
//! extension traits return, bounded [`copy_with_buffer`] and
//! [`copy_bidirectional_with_buffers`] copies, and endpoints over borrowed
//! slices. The [`pipes`] module also provides bounded endpoints over
//! caller-owned managed buffers. Like the rest of the runtime this is an experimental
//! research foundation. It provides the capabilities the runtime's tasks
//! need, not Tokio's API, and it implements no files, sockets or other
//! operating-system endpoints.
//!
//! ```
//! use std::future::Future;
//! use std::pin::pin;
//! use std::task::{Context, Poll, Waker};
//!
//! use allocatbelt::runtime::io::{
//!   AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, SliceReader, SliceWriter,
//!   copy_with_buffer,
//! };
//!
//! // A ported `async fn`: generic over the traits, borrowing every buffer.
//! async fn relay<R, W>(
//!   reader: &mut R,
//!   writer: &mut W,
//!   scratch: &mut [u8],
//! ) -> std::io::Result<u64>
//! where
//!   R: AsyncRead + Unpin,
//!   W: AsyncWrite + Unpin,
//! {
//!   let mut header = [0u8; 4];
//!   reader.read_exact(&mut header).await?;
//!   writer.write_all(&header).await?;
//!   copy_with_buffer(reader, writer, scratch).await
//! }
//!
//! let mut reader = SliceReader::new(b"HEADpayload");
//! let mut out = [0u8; 16];
//! let mut writer = SliceWriter::new(&mut out);
//! // Any initialized slice works, such as `ManagedBuf::get_mut` storage.
//! let mut scratch = [0u8; 4];
//!
//! // Not an executor: slice endpoints are always ready, so a bounded loop
//! // with a no-op waker is enough here.
//! let copied = {
//!   let mut future = pin!(relay(&mut reader, &mut writer, &mut scratch));
//!   let mut cx = Context::from_waker(Waker::noop());
//!   let mut copied = None;
//!   for _ in 0..8 {
//!     if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
//!       copied = Some(result?);
//!       break;
//!     }
//!   }
//!   copied
//! };
//! assert_eq!(copied, Some(7));
//! assert_eq!(writer.written(), b"HEADpayload");
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! # Buffers and counts
//!
//! Every buffer is an initialized `&mut [u8]` or `&[u8]`; there is no
//! uninitialized read buffer. An endpoint reports how many bytes it read into
//! or wrote from the front of the buffer it was offered. The futures here
//! check that count against the buffer before slicing, and a count larger
//! than the buffer fails with `InvalidData` instead of panicking. Nothing here
//! allocates: the futures borrow the endpoint and the caller's buffer, and
//! the errors they create carry only an [`ErrorKind`]. [`copy_with_buffer`]
//! uses only the buffer it is given, which may be borrowed from managed
//! storage, such as the slice
//! [`ManagedBuf::get_mut`](crate::runtime::managed::ManagedBuf::get_mut)
//! returns for a uniquely owned buffer.
//!
//! # Runtime neutrality
//!
//! Nothing here reads a current-runtime handle or a timer. A future makes
//! progress only when it is polled, and relies on its endpoint to wake the
//! task after returning `Pending`. Because the futures borrow, they can run in
//! a root future driven on the caller's thread or inside an owned spawned
//! task that owns the endpoint and the buffer; spawning itself still takes an
//! owned future.
//!
//! # Fairness
//!
//! The looping futures ([`ReadExact`], [`WriteAll`], [`CopyWithBuffer`],
//! [`CopyBidirectional`], [`ReadToEndBounded`], [`ReadUntilBounded`]) poll their endpoints at most
//! [`POLL_BUDGET`] times per poll. When the budget runs out with work left,
//! they wake their own task and return `Pending`. These loops retry
//! `ErrorKind::Interrupted`, counting each attempt against the budget.
//! [`ReadVectored`] and [`WriteVectored`] also retry interruptions within
//! that budget; scalar single-operation futures return them. This is local
//! loop bounding, not automatic runtime cooperation for arbitrary I/O polls.
//!
//! # Cancellation and partial progress
//!
//! Dropping any future here is safe for ownership: it holds only borrows, so
//! the endpoint and the buffer go back to the caller intact. It is not
//! transactional. Progress already made stays where it happened: bytes a
//! [`ReadExact`] read are in the front of the caller's buffer and gone from
//! the stream, bytes a [`WriteAll`] wrote are in the stream, and bytes a
//! [`CopyWithBuffer`] read but has not written are in its buffer and gone from
//! the reader. A future created again after cancellation starts from the
//! beginning of whatever buffer it is given, so the exact offset of the
//! operation is lost unless the caller read it from the old future first
//! ([`ReadExact::filled`], [`WriteAll::written`],
//! [`CopyWithBuffer::transferred`], [`CopyWithBuffer::unwritten`],
//! [`CopyBidirectional::transferred`], [`CopyBidirectional::unwritten`]).
//! A bidirectional copy also keeps any flush or write-side shutdown it
//! completed. Bounded
//! read futures expose [`filled`](ReadToEndBounded::filled) while pending or
//! before cancellation; their result and [`BoundedReadError`] also carry the
//! count after completion. Bytes consumed by delimiter reads stay consumed,
//! while any unconsumed buffered suffix remains available to the endpoint.
//! A panicking endpoint can leave its own state partially changed; callers
//! must not assume that polling the operation again replays safely.
//!
//! # Limitations
//!
//! [`AsyncReadExt::take`] caps reads without consuming bytes past the limit;
//! [`AsyncReadExt::chain`] advances to a second reader after a nonempty first
//! read reports EOF. Both adapters own their endpoints and require `Unpin`
//! endpoints when polled, and both implement
//! [`AsyncBufRead`](crate::runtime::buffered_io::AsyncBufRead). [`empty`]
//! implements buffered reading, writing and seeking as a stateless ready
//! endpoint; [`sink`] and [`repeat`] provide the separate write-only and
//! repeating-read behaviors. The repeating reader has no EOF; cap it when
//! copying or reading a whole stream. Their vectored reads use the scalar
//! fallback. These adapters neither allocate nor reserve managed storage.
//!
//! Bounded delimiter, line and whole-stream reads use caller-owned initialized
//! slices and report capacity separately from EOF. These reads never grow a
//! `Vec` or `String`; UTF-8 ports validate the bytes left in the slice. A full
//! destination is not probed for an additional byte. Endpoint splitting is
//! available separately through [`split_io::split`](crate::runtime::split_io::split).
//! [`AsyncSeek`] is a single `poll_seek` that is polled again with the same
//! position after `Pending`, instead of a separate start and completion.
//! Managed buffered readers and writers live in
//! [`buffered_io`](crate::runtime::buffered_io).

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::future::Future;
use std::io::{self, ErrorKind, IoSlice, IoSliceMut, SeekFrom};
use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll};

#[path = "io_bidirectional.rs"]
mod bidirectional;
pub use bidirectional::{CopyBidirectional, copy_bidirectional_with_buffers};

#[path = "io_pipes.rs"]
mod io_pipes;
pub use io_pipes::pipes;

#[path = "io_adapters.rs"]
mod adapters;
pub use adapters::{Chain, Empty, Repeat, Sink, Take, empty, repeat, sink};

#[path = "io_bounded.rs"]
mod bounded;
pub use bounded::AsyncBufReadExt;
pub use bounded::{
  BoundedRead, BoundedReadError, BoundedReadStop, ReadLineBounded, ReadToEndBounded,
  ReadToStringBounded, ReadUntilBounded,
};

#[cfg(test)]
#[path = "io_bounded_tests.rs"]
mod bounded_tests;

/// Endpoint operations a looping future ([`ReadExact`], [`WriteAll`],
/// [`CopyWithBuffer`], [`CopyBidirectional`]) performs in one poll before it wakes its own task and
/// returns `Pending`.
pub const POLL_BUDGET: usize = 64;

/// Reads bytes into an initialized buffer.
pub trait AsyncRead {
  /// Attempts to read into `buf`, returning how many bytes were read into its
  /// front.
  ///
  /// `Ok(0)` for a non-empty `buf` means end of stream; for an empty `buf`
  /// it should be returned without blocking. `Pending` must arrange for the
  /// task to be woken when a read can make progress. The count must not
  /// exceed `buf.len()`; the futures here reject a larger count with
  /// `InvalidData`.
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>>;

  /// Attempts to read into a list of initialized buffers in order.
  ///
  /// The default forwards to the first nonempty buffer, or an empty buffer if
  /// none exists. An empty list or list of empty buffers therefore preserves
  /// the endpoint's ordinary empty-read behavior. Implementations may
  /// override this with scatter I/O. A successful count must not exceed the
  /// combined offered length; the extension future validates it.
  fn poll_read_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &mut [IoSliceMut<'_>],
  ) -> Poll<io::Result<usize>> {
    if let Some(buf) = bufs.iter_mut().find(|buf| !buf.is_empty()) {
      let offered = buf.len();
      self
        .poll_read(cx, buf)
        .map(|result| result.and_then(|count| checked_count(count, offered)))
    } else {
      self
        .poll_read(cx, &mut [])
        .map(|result| result.and_then(|count| checked_count(count, 0)))
    }
  }
}

/// Writes bytes from a buffer, and flushes and shuts down the write side.
pub trait AsyncWrite {
  /// Attempts to write from `buf`, returning how many bytes from its front
  /// were accepted.
  ///
  /// `Ok(0)` for a non-empty `buf` means the endpoint cannot accept bytes;
  /// [`AsyncWriteExt::write_all`] reports it as `WriteZero`. `Pending` must
  /// arrange for the task to be woken when a write can make progress. The
  /// count must not exceed `buf.len()`; the futures here reject a larger
  /// count with `InvalidData`.
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>>;

  /// Attempts to write from a list of buffers in order.
  ///
  /// The default forwards to the first nonempty buffer, or an empty buffer if
  /// none exists. Implementations may override this with gather I/O. A
  /// successful count must not exceed the combined offered length; the
  /// extension future validates it.
  fn poll_write_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    let buf = bufs
      .iter()
      .find(|buf| !buf.is_empty())
      .map_or(&[][..], |buf| &**buf);
    self
      .poll_write(cx, buf)
      .map(|result| result.and_then(|count| checked_count(count, buf.len())))
  }

  /// Whether `poll_write_vectored` uses an efficient scatter/gather path.
  /// Defaults to false when the implementation only forwards one buffer.
  fn is_write_vectored(&self) -> bool {
    false
  }

  /// Attempts to deliver every accepted byte the endpoint still buffers.
  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

  /// Attempts to shut down the write side once buffered bytes are delivered.
  /// What a write after a successful shutdown does is up to the endpoint.
  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

/// Moves a stream's position.
pub trait AsyncSeek {
  /// Attempts to move to `pos`, returning the new position from the start.
  ///
  /// After `Pending`, the caller polls again with the same `pos`, so an
  /// implementation may keep a seek it has started; [`AsyncSeekExt::seek`]
  /// does so.
  fn poll_seek(self: Pin<&mut Self>, cx: &mut Context<'_>, pos: SeekFrom) -> Poll<io::Result<u64>>;
}

impl<T: AsyncRead + Unpin + ?Sized> AsyncRead for &mut T {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut **self.get_mut()).poll_read(cx, buf)
  }

  fn poll_read_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &mut [IoSliceMut<'_>],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut **self.get_mut()).poll_read_vectored(cx, bufs)
  }
}

impl<T: AsyncWrite + Unpin + ?Sized> AsyncWrite for &mut T {
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
    Pin::new(&mut **self.get_mut()).poll_write(cx, buf)
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut **self.get_mut()).poll_write_vectored(cx, bufs)
  }

  fn is_write_vectored(&self) -> bool {
    (**self).is_write_vectored()
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut **self.get_mut()).poll_flush(cx)
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut **self.get_mut()).poll_shutdown(cx)
  }
}

impl<T: AsyncSeek + Unpin + ?Sized> AsyncSeek for &mut T {
  fn poll_seek(self: Pin<&mut Self>, cx: &mut Context<'_>, pos: SeekFrom) -> Poll<io::Result<u64>> {
    Pin::new(&mut **self.get_mut()).poll_seek(cx, pos)
  }
}

/// `count` when an endpoint offered `len` bytes reported at most that many,
/// else `InvalidData`.
fn checked_count(count: usize, len: usize) -> io::Result<usize> {
  if count <= len {
    Ok(count)
  } else {
    Err(ErrorKind::InvalidData.into())
  }
}

/// Requests another poll after yielding; another task's turn is not guaranteed.
fn yield_now<T>(cx: &Context<'_>) -> Poll<T> {
  cx.waker().wake_by_ref();
  Poll::Pending
}

/// Futures over [`AsyncRead`]; implemented for every reader.
pub trait AsyncReadExt: AsyncRead {
  /// Limits reads to `limit` bytes without allocating or consuming bytes
  /// beyond that boundary. Use [`Take::into_inner`] to recover the reader.
  fn take(self, limit: u64) -> Take<Self>
  where
    Self: Sized,
  {
    Take::new(self, limit)
  }

  /// Reads this endpoint to EOF before reading `next`. An empty read does
  /// not advance from the first endpoint; see [`Chain`].
  fn chain<R: AsyncRead>(self, next: R) -> Chain<Self, R>
  where
    Self: Sized,
  {
    Chain::new(self, next)
  }

  /// Reads into fixed caller-owned storage until EOF or the slice fills.
  ///
  /// A full slice stops immediately with `Capacity`; the endpoint is not
  /// probed for EOF and no additional byte is consumed. Progress is available
  /// from the future while pending or before cancellation and from the
  /// returned result or error after completion.
  fn read_to_end_bounded<'a>(&'a mut self, buffer: &'a mut [u8]) -> ReadToEndBounded<'a, Self>
  where
    Self: Unpin,
  {
    ReadToEndBounded::new(self, buffer)
  }

  /// Reads to EOF or capacity and validates the bytes as UTF-8.
  ///
  /// The destination remains an initialized byte slice; no `String` is grown.
  /// Invalid UTF-8 returns `InvalidData` with the byte count while preserving
  /// the bytes in the caller's slice.
  fn read_to_string_bounded<'a>(&'a mut self, buffer: &'a mut [u8]) -> ReadToStringBounded<'a, Self>
  where
    Self: Unpin,
  {
    ReadToStringBounded::new(self, buffer)
  }

  /// Reads once into `buf`, completing with the count; `0` for a non-empty
  /// buffer means end of stream. An empty buffer completes with `0` without
  /// polling the reader.
  fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> Read<'a, Self>
  where
    Self: Unpin,
  {
    Read { reader: self, buf }
  }

  /// Reads into initialized buffers in order, returning the total byte count.
  ///
  /// An empty list, or a list containing only empty buffers, completes with
  /// zero without polling the reader. `Interrupted` is retried up to
  /// [`POLL_BUDGET`] times per poll; other errors, including `WouldBlock`, are
  /// returned. A count beyond the combined buffer lengths fails with
  /// `InvalidData`.
  fn read_vectored<'a, 'b>(
    &'a mut self,
    bufs: &'a mut [IoSliceMut<'b>],
  ) -> ReadVectored<'a, 'b, Self>
  where
    Self: Unpin,
  {
    ReadVectored { reader: self, bufs }
  }

  /// Reads until `buf` is full, completing with its length. End of stream
  /// first fails with `UnexpectedEof`. An empty buffer completes at once
  /// without polling the reader. See the module documentation for partial
  /// progress on error or cancellation.
  fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> ReadExact<'a, Self>
  where
    Self: Unpin,
  {
    ReadExact {
      reader: self,
      buf,
      filled: 0,
    }
  }
}

impl<R: AsyncRead + ?Sized> AsyncReadExt for R {}

/// Futures over [`AsyncWrite`]; implemented for every writer.
pub trait AsyncWriteExt: AsyncWrite {
  /// Writes once from `buf`, completing with the count accepted. An empty
  /// buffer completes with `0` without polling the writer.
  fn write<'a>(&'a mut self, buf: &'a [u8]) -> Write<'a, Self>
  where
    Self: Unpin,
  {
    Write { writer: self, buf }
  }

  /// Writes from buffers in order, returning the total accepted byte count.
  ///
  /// An empty list, or a list containing only empty buffers, completes with
  /// zero without polling the writer. `Interrupted` is retried up to
  /// [`POLL_BUDGET`] times per poll; other errors, including `WouldBlock`, are
  /// returned. A count beyond the combined buffer lengths fails with
  /// `InvalidData`.
  fn write_vectored<'a, 'b>(&'a mut self, bufs: &'a [IoSlice<'b>]) -> WriteVectored<'a, 'b, Self>
  where
    Self: Unpin,
  {
    WriteVectored { writer: self, bufs }
  }

  /// Writes until every byte of `buf` is accepted. A write accepting none
  /// fails with `WriteZero`. An empty buffer completes at once without
  /// polling the writer. This does not flush. See the module documentation
  /// for partial progress on error or cancellation.
  fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> WriteAll<'a, Self>
  where
    Self: Unpin,
  {
    WriteAll {
      writer: self,
      buf,
      written: 0,
    }
  }

  /// Flushes the writer.
  fn flush(&mut self) -> Flush<'_, Self>
  where
    Self: Unpin,
  {
    Flush { writer: self }
  }

  /// Shuts down the write side.
  fn shutdown(&mut self) -> Shutdown<'_, Self>
  where
    Self: Unpin,
  {
    Shutdown { writer: self }
  }
}

impl<W: AsyncWrite + ?Sized> AsyncWriteExt for W {}

/// One vectored read; see [`AsyncReadExt::read_vectored`].
#[must_use = "futures do nothing unless polled"]
pub struct ReadVectored<'a, 'b, R: ?Sized> {
  reader: &'a mut R,
  bufs: &'a mut [IoSliceMut<'b>],
}

impl<R: ?Sized> fmt::Debug for ReadVectored<'_, '_, R> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ReadVectored")
      .field("buffers", &self.bufs.len())
      .finish_non_exhaustive()
  }
}

impl<R: AsyncRead + Unpin + ?Sized> Future for ReadVectored<'_, '_, R> {
  type Output = io::Result<usize>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    let offered = match read_vectored_len(this.bufs) {
      Ok(len) => len,
      Err(error) => return Poll::Ready(Err(error)),
    };
    if offered == 0 {
      return Poll::Ready(Ok(0));
    }
    for _ in 0..POLL_BUDGET {
      match Pin::new(&mut *this.reader).poll_read_vectored(cx, this.bufs) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Ok(count)) => return Poll::Ready(checked_count(count, offered)),
        Poll::Ready(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
      }
    }
    yield_now(cx)
  }
}

/// One vectored write; see [`AsyncWriteExt::write_vectored`].
#[must_use = "futures do nothing unless polled"]
pub struct WriteVectored<'a, 'b, W: ?Sized> {
  writer: &'a mut W,
  bufs: &'a [IoSlice<'b>],
}

impl<W: ?Sized> fmt::Debug for WriteVectored<'_, '_, W> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("WriteVectored")
      .field("buffers", &self.bufs.len())
      .finish_non_exhaustive()
  }
}

impl<W: AsyncWrite + Unpin + ?Sized> Future for WriteVectored<'_, '_, W> {
  type Output = io::Result<usize>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    let offered = match write_vectored_len(this.bufs) {
      Ok(len) => len,
      Err(error) => return Poll::Ready(Err(error)),
    };
    if offered == 0 {
      return Poll::Ready(Ok(0));
    }
    for _ in 0..POLL_BUDGET {
      match Pin::new(&mut *this.writer).poll_write_vectored(cx, this.bufs) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Ok(count)) => return Poll::Ready(checked_count(count, offered)),
        Poll::Ready(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
      }
    }
    yield_now(cx)
  }
}

fn read_vectored_len(bufs: &[IoSliceMut<'_>]) -> io::Result<usize> {
  bufs.iter().try_fold(0_usize, |total, buf| {
    total
      .checked_add(buf.len())
      .ok_or_else(|| ErrorKind::InvalidInput.into())
  })
}

fn write_vectored_len(bufs: &[IoSlice<'_>]) -> io::Result<usize> {
  bufs.iter().try_fold(0_usize, |total, buf| {
    total
      .checked_add(buf.len())
      .ok_or_else(|| ErrorKind::InvalidInput.into())
  })
}

/// Futures over [`AsyncSeek`]; implemented for every seekable stream.
pub trait AsyncSeekExt: AsyncSeek {
  /// Moves to `pos`, completing with the new position from the start.
  fn seek(&mut self, pos: SeekFrom) -> Seek<'_, Self>
  where
    Self: Unpin,
  {
    Seek { seeker: self, pos }
  }
}

impl<S: AsyncSeek + ?Sized> AsyncSeekExt for S {}

/// One read; see [`AsyncReadExt::read`].
#[must_use = "futures do nothing unless polled"]
pub struct Read<'a, R: ?Sized> {
  reader: &'a mut R,
  buf: &'a mut [u8],
}

impl<R: AsyncRead + Unpin + ?Sized> Future for Read<'_, R> {
  type Output = io::Result<usize>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.buf.is_empty() {
      return Poll::Ready(Ok(0));
    }
    match Pin::new(&mut *this.reader).poll_read(cx, this.buf) {
      Poll::Ready(Ok(count)) => Poll::Ready(checked_count(count, this.buf.len())),
      other => other,
    }
  }
}

impl<R: ?Sized> fmt::Debug for Read<'_, R> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Read")
      .field("len", &self.buf.len())
      .finish_non_exhaustive()
  }
}

/// Fills a buffer; see [`AsyncReadExt::read_exact`].
#[must_use = "futures do nothing unless polled"]
pub struct ReadExact<'a, R: ?Sized> {
  reader: &'a mut R,
  buf: &'a mut [u8],
  /// `buf[..filled]` holds bytes read; never above `buf.len()`.
  filled: usize,
}

impl<R: ?Sized> ReadExact<'_, R> {
  /// Bytes read so far into the front of the buffer, including before an
  /// error or a `Pending` the caller may abandon.
  #[must_use]
  pub const fn filled(&self) -> usize {
    self.filled
  }
}

impl<R: AsyncRead + Unpin + ?Sized> Future for ReadExact<'_, R> {
  type Output = io::Result<usize>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    let mut budget = POLL_BUDGET;
    while this.filled < this.buf.len() {
      if budget == 0 {
        return yield_now(cx);
      }
      budget -= 1;
      let rest = &mut this.buf[this.filled..];
      let len = rest.len();
      match Pin::new(&mut *this.reader).poll_read(cx, rest) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Ok(0)) => return Poll::Ready(Err(ErrorKind::UnexpectedEof.into())),
        Poll::Ready(Ok(count)) => this.filled += checked_count(count, len)?,
        Poll::Ready(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
      }
    }
    Poll::Ready(Ok(this.filled))
  }
}

impl<R: ?Sized> fmt::Debug for ReadExact<'_, R> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ReadExact")
      .field("len", &self.buf.len())
      .field("filled", &self.filled)
      .finish_non_exhaustive()
  }
}

/// One write; see [`AsyncWriteExt::write`].
#[must_use = "futures do nothing unless polled"]
pub struct Write<'a, W: ?Sized> {
  writer: &'a mut W,
  buf: &'a [u8],
}

impl<W: AsyncWrite + Unpin + ?Sized> Future for Write<'_, W> {
  type Output = io::Result<usize>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.buf.is_empty() {
      return Poll::Ready(Ok(0));
    }
    match Pin::new(&mut *this.writer).poll_write(cx, this.buf) {
      Poll::Ready(Ok(count)) => Poll::Ready(checked_count(count, this.buf.len())),
      other => other,
    }
  }
}

impl<W: ?Sized> fmt::Debug for Write<'_, W> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Write")
      .field("len", &self.buf.len())
      .finish_non_exhaustive()
  }
}

/// Writes a whole buffer; see [`AsyncWriteExt::write_all`].
#[must_use = "futures do nothing unless polled"]
pub struct WriteAll<'a, W: ?Sized> {
  writer: &'a mut W,
  buf: &'a [u8],
  /// `buf[..written]` was accepted; never above `buf.len()`.
  written: usize,
}

impl<W: ?Sized> WriteAll<'_, W> {
  /// Bytes from the front of the buffer the writer has accepted so far,
  /// including before an error or a `Pending` the caller may abandon.
  #[must_use]
  pub const fn written(&self) -> usize {
    self.written
  }
}

impl<W: AsyncWrite + Unpin + ?Sized> Future for WriteAll<'_, W> {
  type Output = io::Result<()>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    let mut budget = POLL_BUDGET;
    while this.written < this.buf.len() {
      if budget == 0 {
        return yield_now(cx);
      }
      budget -= 1;
      let rest = &this.buf[this.written..];
      match Pin::new(&mut *this.writer).poll_write(cx, rest) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Ok(0)) => return Poll::Ready(Err(ErrorKind::WriteZero.into())),
        Poll::Ready(Ok(count)) => this.written += checked_count(count, rest.len())?,
        Poll::Ready(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
      }
    }
    Poll::Ready(Ok(()))
  }
}

impl<W: ?Sized> fmt::Debug for WriteAll<'_, W> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("WriteAll")
      .field("len", &self.buf.len())
      .field("written", &self.written)
      .finish_non_exhaustive()
  }
}

/// A flush; see [`AsyncWriteExt::flush`].
#[must_use = "futures do nothing unless polled"]
pub struct Flush<'a, W: ?Sized> {
  writer: &'a mut W,
}

impl<W: AsyncWrite + Unpin + ?Sized> Future for Flush<'_, W> {
  type Output = io::Result<()>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    Pin::new(&mut *self.get_mut().writer).poll_flush(cx)
  }
}

impl<W: ?Sized> fmt::Debug for Flush<'_, W> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Flush").finish_non_exhaustive()
  }
}

/// A write-side shutdown; see [`AsyncWriteExt::shutdown`].
#[must_use = "futures do nothing unless polled"]
pub struct Shutdown<'a, W: ?Sized> {
  writer: &'a mut W,
}

impl<W: AsyncWrite + Unpin + ?Sized> Future for Shutdown<'_, W> {
  type Output = io::Result<()>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    Pin::new(&mut *self.get_mut().writer).poll_shutdown(cx)
  }
}

impl<W: ?Sized> fmt::Debug for Shutdown<'_, W> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Shutdown").finish_non_exhaustive()
  }
}

/// A seek; see [`AsyncSeekExt::seek`].
#[must_use = "futures do nothing unless polled"]
pub struct Seek<'a, S: ?Sized> {
  seeker: &'a mut S,
  pos: SeekFrom,
}

impl<S: AsyncSeek + Unpin + ?Sized> Future for Seek<'_, S> {
  type Output = io::Result<u64>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    Pin::new(&mut *this.seeker).poll_seek(cx, this.pos)
  }
}

impl<S: ?Sized> fmt::Debug for Seek<'_, S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Seek")
      .field("pos", &self.pos)
      .finish_non_exhaustive()
  }
}

/// Copies everything `reader` yields to `writer` through the caller's `buf`,
/// then flushes `writer`, completing with the number of bytes the writer
/// accepted, saturating at `u64::MAX`.
///
/// The copy reads into `buf` only after the writer has accepted every byte
/// of the previous read. When the reader reports end of stream and nothing is
/// left in `buf`, it flushes the writer and completes only once that flush
/// succeeds; it never shuts the writer down. When the reader returns
/// `Pending` after bytes were written since the last flush, it also polls a
/// flush once before returning `Pending`, so a buffering writer is not left
/// holding bytes the reader's peer may be waiting for.
///
/// # Errors
///
/// `InvalidInput` for an empty `buf`, before either endpoint is polled;
/// `WriteZero` when the writer accepts no bytes; `InvalidData` when either
/// endpoint reports more bytes than it was offered; otherwise the first
/// error from the reader, the writer or a flush (`Interrupted` is retried).
/// The error does not carry the count already transferred: read it, and the
/// bytes still in `buf`, from [`CopyWithBuffer::transferred`] and
/// [`CopyWithBuffer::unwritten`] before dropping the future.
pub fn copy_with_buffer<'a, R, W>(
  reader: &'a mut R,
  writer: &'a mut W,
  buf: &'a mut [u8],
) -> CopyWithBuffer<'a, R, W>
where
  R: AsyncRead + Unpin + ?Sized,
  W: AsyncWrite + Unpin + ?Sized,
{
  CopyWithBuffer {
    reader,
    writer,
    buf,
    start: 0,
    end: 0,
    read_done: false,
    need_flush: false,
    transferred: 0,
  }
}

/// A bounded copy; see [`copy_with_buffer`].
#[must_use = "futures do nothing unless polled"]
pub struct CopyWithBuffer<'a, R: ?Sized, W: ?Sized> {
  reader: &'a mut R,
  writer: &'a mut W,
  buf: &'a mut [u8],
  /// `buf[start..end]` was read and not yet written; both are zero when it
  /// is empty, and `end` never exceeds `buf.len()`.
  start: usize,
  end: usize,
  /// The reader reported end of stream.
  read_done: bool,
  /// Bytes were written since the last successful flush.
  need_flush: bool,
  transferred: u64,
}

impl<R: ?Sized, W: ?Sized> CopyWithBuffer<'_, R, W> {
  /// Bytes the writer has accepted so far, including before an error or a
  /// `Pending` the caller may abandon, saturating at `u64::MAX`.
  #[must_use]
  pub const fn transferred(&self) -> u64 {
    self.transferred
  }

  /// The range of the caller's buffer holding bytes taken from the reader
  /// and not yet accepted by the writer; empty when there are none. Bytes
  /// in it are lost to the stream if the caller drops the copy without
  /// writing them itself.
  #[must_use]
  pub const fn unwritten(&self) -> Range<usize> {
    self.start..self.end
  }
}

impl<R, W> Future for CopyWithBuffer<'_, R, W>
where
  R: AsyncRead + Unpin + ?Sized,
  W: AsyncWrite + Unpin + ?Sized,
{
  type Output = io::Result<u64>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.buf.is_empty() {
      return Poll::Ready(Err(ErrorKind::InvalidInput.into()));
    }
    let mut budget = POLL_BUDGET;
    loop {
      if budget == 0 {
        return yield_now(cx);
      }
      budget -= 1;
      if this.start < this.end {
        let unwritten = &this.buf[this.start..this.end];
        match Pin::new(&mut *this.writer).poll_write(cx, unwritten) {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Ok(0)) => return Poll::Ready(Err(ErrorKind::WriteZero.into())),
          Poll::Ready(Ok(count)) => {
            this.start += checked_count(count, unwritten.len())?;
            // `usize` is 64 bits on every supported target.
            this.transferred = this.transferred.saturating_add(count as u64);
            this.need_flush = true;
            if this.start == this.end {
              this.start = 0;
              this.end = 0;
            }
          }
          Poll::Ready(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        }
      } else if !this.read_done {
        match Pin::new(&mut *this.reader).poll_read(cx, this.buf) {
          Poll::Pending => {
            // A buffering writer may hold what the reader's peer waits for.
            if this.need_flush {
              if budget == 0 {
                return yield_now(cx);
              }
              // This branch makes a second endpoint call. Count it too.
              budget -= 1;
              match Pin::new(&mut *this.writer).poll_flush(cx) {
                Poll::Ready(Ok(())) => this.need_flush = false,
                Poll::Ready(Err(error)) if error.kind() != ErrorKind::Interrupted => {
                  return Poll::Ready(Err(error));
                }
                Poll::Ready(Err(_)) => {
                  // Interrupted flushes need an explicit retry: the reader
                  // may remain pending until these bytes reach its peer.
                  if budget == 0 {
                    return yield_now(cx);
                  }
                  continue;
                }
                Poll::Pending => {}
              }
            }
            return Poll::Pending;
          }
          Poll::Ready(Ok(0)) => this.read_done = true,
          Poll::Ready(Ok(count)) => this.end = checked_count(count, this.buf.len())?,
          Poll::Ready(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        }
      } else {
        match Pin::new(&mut *this.writer).poll_flush(cx) {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Ok(())) => {
            this.need_flush = false;
            return Poll::Ready(Ok(this.transferred));
          }
          Poll::Ready(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        }
      }
    }
  }
}

impl<R: ?Sized, W: ?Sized> fmt::Debug for CopyWithBuffer<'_, R, W> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("CopyWithBuffer")
      .field("len", &self.buf.len())
      .field("unwritten", &self.unwritten())
      .field("read_done", &self.read_done)
      .field("transferred", &self.transferred)
      .finish_non_exhaustive()
  }
}

/// An always-ready reader over a borrowed slice, with a position in
/// `0..=len`. Reads copy from the position and advance it; at the end they
/// return `0`.
#[derive(Debug, Clone)]
pub struct SliceReader<'a> {
  data: &'a [u8],
  pos: usize,
}

impl<'a> SliceReader<'a> {
  /// A reader at the start of `data`.
  #[must_use]
  pub const fn new(data: &'a [u8]) -> Self {
    Self { data, pos: 0 }
  }

  /// The offset of the next byte to read.
  #[must_use]
  pub const fn position(&self) -> usize {
    self.pos
  }

  /// The bytes not yet read.
  #[must_use]
  pub fn remaining(&self) -> &'a [u8] {
    &self.data[self.pos..]
  }

  /// The whole slice, read or not.
  #[must_use]
  pub const fn get_ref(&self) -> &'a [u8] {
    self.data
  }
}

impl AsyncRead for SliceReader<'_> {
  fn poll_read(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    let rest = this.remaining();
    let count = rest.len().min(buf.len());
    buf[..count].copy_from_slice(&rest[..count]);
    this.pos += count;
    Poll::Ready(Ok(count))
  }

  fn poll_read_vectored(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    bufs: &mut [IoSliceMut<'_>],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    let mut copied = 0;
    for buf in bufs {
      let remaining = this.remaining();
      let count = remaining.len().min(buf.len());
      (**buf)[..count].copy_from_slice(&remaining[..count]);
      this.pos += count;
      copied += count;
      if count < buf.len() {
        break;
      }
    }
    Poll::Ready(Ok(copied))
  }
}

/// Seeks only within `0..=len`: a target outside the slice, or one that
/// overflows, fails with `InvalidInput` and leaves the position unchanged.
impl AsyncSeek for SliceReader<'_> {
  fn poll_seek(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    pos: SeekFrom,
  ) -> Poll<io::Result<u64>> {
    let this = self.get_mut();
    this.pos = seek_in_slice(this.pos, this.data.len(), pos)?;
    // `usize` is 64 bits on every supported target.
    Poll::Ready(Ok(this.pos as u64))
  }
}

/// The position `target` selects in a slice of `len` bytes read up to
/// `position`, or `InvalidInput` when it is outside `0..=len` or overflows.
fn seek_in_slice(position: usize, len: usize, target: SeekFrom) -> io::Result<usize> {
  let selected = match target {
    SeekFrom::Start(offset) => usize::try_from(offset).ok(),
    SeekFrom::End(offset) => offset_from(len, offset),
    SeekFrom::Current(offset) => offset_from(position, offset),
  };
  selected
    .filter(|&at| at <= len)
    .ok_or_else(|| ErrorKind::InvalidInput.into())
}

/// `base` moved by `offset`, or `None` when that is not a `usize`.
fn offset_from(base: usize, offset: i64) -> Option<usize> {
  base.checked_add_signed(isize::try_from(offset).ok()?)
}

/// An always-ready writer into a borrowed slice that never grows. Writes
/// copy to the position and advance it; once the slice is full a non-empty
/// write returns `0`, which [`AsyncWriteExt::write_all`] reports as
/// `WriteZero`. Flush and shutdown do nothing and succeed, and writes after
/// a shutdown are still accepted.
#[derive(Debug)]
pub struct SliceWriter<'a> {
  data: &'a mut [u8],
  pos: usize,
}

impl<'a> SliceWriter<'a> {
  /// A writer at the start of `data`.
  #[must_use]
  pub const fn new(data: &'a mut [u8]) -> Self {
    Self { data, pos: 0 }
  }

  /// The offset of the next byte to write, which is the count written.
  #[must_use]
  pub const fn position(&self) -> usize {
    self.pos
  }

  /// The bytes written so far.
  #[must_use]
  pub fn written(&self) -> &[u8] {
    &self.data[..self.pos]
  }

  /// How many more bytes fit.
  #[must_use]
  pub fn spare_len(&self) -> usize {
    self.data.len() - self.pos
  }

  /// The whole slice, written or not.
  #[must_use]
  pub fn get_ref(&self) -> &[u8] {
    self.data
  }

  /// Gives the whole slice back.
  #[must_use]
  pub fn into_inner(self) -> &'a mut [u8] {
    self.data
  }
}

impl AsyncWrite for SliceWriter<'_> {
  fn poll_write(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    let spare = &mut this.data[this.pos..];
    let count = spare.len().min(buf.len());
    spare[..count].copy_from_slice(&buf[..count]);
    this.pos += count;
    Poll::Ready(Ok(count))
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    let mut copied = 0;
    for buf in bufs {
      let spare = &mut this.data[this.pos..];
      let count = spare.len().min(buf.len());
      spare[..count].copy_from_slice(&buf[..count]);
      this.pos += count;
      copied += count;
      if count < buf.len() {
        break;
      }
    }
    Poll::Ready(Ok(copied))
  }

  fn is_write_vectored(&self) -> bool {
    true
  }

  fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use std::collections::VecDeque;
  use std::iter;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::{Wake, Waker};

  use super::*;

  /// Counts wakes, so a test can tell a self-wake from an endpoint `Pending`.
  #[derive(Default)]
  struct CountingWake(AtomicUsize);

  impl CountingWake {
    fn count(&self) -> usize {
      self.0.load(Ordering::Relaxed)
    }
  }

  impl Wake for CountingWake {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.0.fetch_add(1, Ordering::Relaxed);
    }
  }

  fn counting_waker() -> (Arc<CountingWake>, Waker) {
    let wake = Arc::new(CountingWake::default());
    (Arc::clone(&wake), Waker::from(wake))
  }

  #[test]
  fn interrupted_flush_while_reader_waits_retries_with_a_bounded_self_wake() {
    let steps =
      iter::once(ReadStep::Bytes(b"x")).chain(iter::repeat_n(ReadStep::Pending, POLL_BUDGET));
    let mut reader = ScriptReader::new(steps);
    let mut writer = ScriptWriter {
      flush_steps: iter::repeat_n(FlushStep::Fail(ErrorKind::Interrupted), POLL_BUDGET).collect(),
      ..ScriptWriter::default()
    };
    let mut buffer = [0u8; 1];
    let mut copy = copy_with_buffer(&mut reader, &mut writer, &mut buffer);
    let (wake, waker) = counting_waker();
    assert!(poll(&mut copy, &waker).is_pending());
    assert_eq!(wake.count(), 1);
    assert!(copy.writer.flushes > 1);
    assert_eq!(
      copy.reader.polls + copy.writer.polls + copy.writer.flushes,
      POLL_BUDGET
    );
  }

  #[test]
  fn a_reader_pending_at_the_budget_edge_does_not_add_an_extra_flush_call() {
    let steps = iter::once(ReadStep::Fail(ErrorKind::Interrupted))
      .chain(iter::repeat_n(ReadStep::Bytes(b"x"), 31))
      .chain(iter::once(ReadStep::Pending));
    let mut reader = ScriptReader::new(steps);
    let mut writer = ScriptWriter::default();
    let mut buffer = [0u8; 1];
    let mut copy = copy_with_buffer(&mut reader, &mut writer, &mut buffer);
    let (wake, waker) = counting_waker();
    assert!(poll(&mut copy, &waker).is_pending());
    assert_eq!(wake.count(), 1);
    assert_eq!(copy.writer.flushes, 0);
    assert_eq!(copy.reader.polls + copy.writer.polls, POLL_BUDGET);
  }

  fn poll<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(waker))
  }

  /// Polls `future` with a no-op waker until it completes, failing the test
  /// after `limit` polls.
  fn run<F: Future + Unpin>(mut future: F, limit: usize) -> F::Output {
    for _ in 0..limit {
      if let Poll::Ready(output) = poll(&mut future, Waker::noop()) {
        return output;
      }
    }
    panic!("still pending after {limit} polls");
  }

  fn kind<T>(result: io::Result<T>) -> Result<T, ErrorKind> {
    result.map_err(|error| error.kind())
  }

  fn kinds<T>(poll: Poll<io::Result<T>>) -> Poll<Result<T, ErrorKind>> {
    poll.map(kind)
  }

  #[derive(Debug, Clone)]
  enum ReadStep {
    /// Delivers these bytes, keeping what does not fit for the next read.
    Bytes(&'static [u8]),
    /// Returns `Pending` without waking.
    Pending,
    Fail(ErrorKind),
    /// Reports this count without touching the buffer.
    Claim(usize),
  }

  /// Follows its script, then reports end of stream.
  struct ScriptReader {
    steps: VecDeque<ReadStep>,
    polls: usize,
  }

  impl ScriptReader {
    fn new(steps: impl IntoIterator<Item = ReadStep>) -> Self {
      Self {
        steps: steps.into_iter().collect(),
        polls: 0,
      }
    }
  }

  impl AsyncRead for ScriptReader {
    fn poll_read(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
      let this = self.get_mut();
      this.polls += 1;
      match this.steps.pop_front() {
        None => Poll::Ready(Ok(0)),
        Some(ReadStep::Bytes(bytes)) => {
          let count = bytes.len().min(buf.len());
          buf[..count].copy_from_slice(&bytes[..count]);
          if count < bytes.len() {
            this.steps.push_front(ReadStep::Bytes(&bytes[count..]));
          }
          Poll::Ready(Ok(count))
        }
        Some(ReadStep::Pending) => Poll::Pending,
        Some(ReadStep::Fail(kind)) => Poll::Ready(Err(kind.into())),
        Some(ReadStep::Claim(count)) => Poll::Ready(Ok(count)),
      }
    }
  }

  #[derive(Debug, Clone)]
  enum WriteStep {
    /// Accepts up to this many bytes.
    Accept(usize),
    /// Returns `Pending` without waking.
    Pending,
    Fail(ErrorKind),
    /// Reports this count without taking any bytes.
    Claim(usize),
  }

  #[derive(Debug, Clone)]
  enum FlushStep {
    Pending,
    Fail(ErrorKind),
  }

  /// Follows its scripts, then accepts every write and flush.
  #[derive(Default)]
  struct ScriptWriter {
    steps: VecDeque<WriteStep>,
    flush_steps: VecDeque<FlushStep>,
    data: Vec<u8>,
    polls: usize,
    flushes: usize,
    /// `data.len()` at each successful flush.
    flushed_at: Vec<usize>,
    shutdowns: usize,
  }

  impl ScriptWriter {
    fn new(steps: impl IntoIterator<Item = WriteStep>) -> Self {
      Self {
        steps: steps.into_iter().collect(),
        ..Self::default()
      }
    }

    fn with_flushes(mut self, steps: impl IntoIterator<Item = FlushStep>) -> Self {
      self.flush_steps = steps.into_iter().collect();
      self
    }
  }

  impl AsyncWrite for ScriptWriter {
    fn poll_write(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      buf: &[u8],
    ) -> Poll<io::Result<usize>> {
      let this = self.get_mut();
      this.polls += 1;
      match this.steps.pop_front() {
        None => {
          this.data.extend_from_slice(buf);
          Poll::Ready(Ok(buf.len()))
        }
        Some(WriteStep::Accept(limit)) => {
          let count = limit.min(buf.len());
          this.data.extend_from_slice(&buf[..count]);
          Poll::Ready(Ok(count))
        }
        Some(WriteStep::Pending) => Poll::Pending,
        Some(WriteStep::Fail(kind)) => Poll::Ready(Err(kind.into())),
        Some(WriteStep::Claim(count)) => Poll::Ready(Ok(count)),
      }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      let this = self.get_mut();
      this.flushes += 1;
      match this.flush_steps.pop_front() {
        None => {
          this.flushed_at.push(this.data.len());
          Poll::Ready(Ok(()))
        }
        Some(FlushStep::Pending) => Poll::Pending,
        Some(FlushStep::Fail(kind)) => Poll::Ready(Err(kind.into())),
      }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      self.get_mut().shutdowns += 1;
      Poll::Ready(Ok(()))
    }
  }

  #[test]
  fn futures_are_unpin() {
    fn assert_unpin<T: Unpin>() {}
    assert_unpin::<Read<'static, dyn AsyncRead>>();
    assert_unpin::<ReadVectored<'static, 'static, dyn AsyncRead>>();
    assert_unpin::<ReadExact<'static, dyn AsyncRead>>();
    assert_unpin::<Write<'static, dyn AsyncWrite>>();
    assert_unpin::<WriteVectored<'static, 'static, dyn AsyncWrite>>();
    assert_unpin::<WriteAll<'static, dyn AsyncWrite>>();
    assert_unpin::<Flush<'static, dyn AsyncWrite>>();
    assert_unpin::<Shutdown<'static, dyn AsyncWrite>>();
    assert_unpin::<Seek<'static, dyn AsyncSeek>>();
    assert_unpin::<CopyWithBuffer<'static, dyn AsyncRead, dyn AsyncWrite>>();
  }

  #[test]
  fn read_returns_one_checked_count() {
    let mut reader = ScriptReader::new([ReadStep::Bytes(b"abc"), ReadStep::Claim(5)]);
    let mut buf = [0u8; 2];
    assert_eq!(kind(run(reader.read(&mut buf), 1)), Ok(2));
    assert_eq!(&buf, b"ab");
    assert_eq!(kind(run(reader.read(&mut buf), 1)), Ok(1));
    assert_eq!(buf[0], b'c');
    let result = run(reader.read(&mut buf), 1);
    assert_eq!(kind(result), Err(ErrorKind::InvalidData));
    assert_eq!(kind(run(reader.read(&mut buf), 1)), Ok(0));
  }

  #[test]
  fn vectored_trait_defaults_select_first_nonempty_and_keep_empty_reads_ready() {
    let mut reader = ScriptReader::new([ReadStep::Bytes(b"ab")]);
    let mut empty = [];
    let mut first = [0_u8; 0];
    let mut second = [0_u8; 2];
    let mut third = [0_u8; 3];
    let mut buffers = [
      IoSliceMut::new(&mut first),
      IoSliceMut::new(&mut second),
      IoSliceMut::new(&mut third),
    ];
    assert_eq!(kind(run(reader.read_vectored(&mut empty), 1)), Ok(0));
    assert_eq!(kind(run(reader.read_vectored(&mut buffers), 1)), Ok(2));
    assert_eq!(&buffers[1][..], b"ab");
    assert_eq!(reader.polls, 1);

    let mut writer = ScriptWriter::default();
    assert!(!writer.is_write_vectored());
    let buffers = [
      IoSlice::new(b""),
      IoSlice::new(b"first"),
      IoSlice::new(b"second"),
    ];
    assert_eq!(kind(run(writer.write_vectored(&buffers), 1)), Ok(5));
    assert_eq!(writer.data, b"first");
    assert_eq!(writer.polls, 1);
  }

  #[test]
  fn slice_endpoints_scatter_and_gather_across_empty_and_partial_buffers() {
    let mut reader = SliceReader::new(b"abcdef");
    let mut empty = [];
    let mut first = [0_u8; 0];
    let mut second = [0_u8; 2];
    let mut third = [0_u8; 3];
    let mut fourth = [0_u8; 4];
    let mut buffers = [
      IoSliceMut::new(&mut first),
      IoSliceMut::new(&mut second),
      IoSliceMut::new(&mut third),
      IoSliceMut::new(&mut fourth),
    ];
    assert_eq!(kind(run(reader.read_vectored(&mut empty), 1)), Ok(0));
    assert_eq!(kind(run(reader.read_vectored(&mut buffers), 1)), Ok(6));
    assert_eq!(&buffers[1][..], b"ab");
    assert_eq!(&buffers[2][..], b"cde");
    assert_eq!(&buffers[3][..1], b"f");

    let mut output = [0_u8; 5];
    let mut writer = SliceWriter::new(&mut output);
    assert!(writer.is_write_vectored());
    let buffers = [
      IoSlice::new(b""),
      IoSlice::new(b"ab"),
      IoSlice::new(b"cdef"),
      IoSlice::new(b"ignored"),
    ];
    assert_eq!(kind(run(writer.write_vectored(&buffers), 1)), Ok(5));
    assert_eq!(writer.written(), b"abcde");
  }

  #[test]
  fn vectored_helpers_reject_overreported_counts_and_propagate_would_block() {
    struct Overreport;
    impl AsyncRead for Overreport {
      fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut [u8],
      ) -> Poll<io::Result<usize>> {
        unreachable!()
      }
      fn poll_read_vectored(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut [IoSliceMut<'_>],
      ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(4))
      }
    }
    let mut reader = Overreport;
    let mut first = [0_u8; 1];
    let mut second = [0_u8; 2];
    let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
    assert_eq!(
      kind(run(reader.read_vectored(&mut bufs), 1)),
      Err(ErrorKind::InvalidData)
    );

    struct Overwrite;
    impl AsyncWrite for Overwrite {
      fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
      ) -> Poll<io::Result<usize>> {
        unreachable!()
      }
      fn poll_write_vectored(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[IoSlice<'_>],
      ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(4))
      }
      fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        unreachable!()
      }
      fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        unreachable!()
      }
    }
    let mut writer = Overwrite;
    let bufs = [IoSlice::new(b"a"), IoSlice::new(b"bc")];
    assert_eq!(
      kind(run(writer.write_vectored(&bufs), 1)),
      Err(ErrorKind::InvalidData)
    );

    let mut reader = ScriptReader::new([ReadStep::Fail(ErrorKind::WouldBlock)]);
    let mut read_buf = [0_u8; 1];
    let mut bufs = [IoSliceMut::new(&mut read_buf)];
    assert_eq!(
      kind(run(reader.read_vectored(&mut bufs), 1)),
      Err(ErrorKind::WouldBlock)
    );
    let mut writer = ScriptWriter::new([WriteStep::Fail(ErrorKind::WouldBlock)]);
    let bufs = [IoSlice::new(b"x")];
    assert_eq!(
      kind(run(writer.write_vectored(&bufs), 1)),
      Err(ErrorKind::WouldBlock)
    );
  }

  #[test]
  fn vectored_defaults_validate_the_actual_forwarded_slice() {
    let mut first = [0_u8; 1];
    let mut later = [0_u8; 2];
    let mut bufs = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut later)];
    let mut reader = ScriptReader::new([ReadStep::Claim(2)]);
    assert_eq!(
      kind(run(reader.read_vectored(&mut bufs), 1)),
      Err(ErrorKind::InvalidData)
    );
    let bufs = [IoSlice::new(b"a"), IoSlice::new(b"bc")];
    let mut writer = ScriptWriter::new([WriteStep::Claim(2)]);
    assert_eq!(
      kind(run(writer.write_vectored(&bufs), 1)),
      Err(ErrorKind::InvalidData)
    );

    let mut cx = Context::from_waker(Waker::noop());
    let mut reader = ScriptReader::new([ReadStep::Claim(1)]);
    assert_eq!(
      kinds(Pin::new(&mut reader).poll_read_vectored(&mut cx, &mut [])),
      Poll::Ready(Err(ErrorKind::InvalidData))
    );
    let mut writer = ScriptWriter::new([WriteStep::Claim(1)]);
    assert_eq!(
      kinds(Pin::new(&mut writer).poll_write_vectored(&mut cx, &[])),
      Poll::Ready(Err(ErrorKind::InvalidData))
    );
  }

  #[test]
  fn vectored_helpers_retry_interrupted_with_a_bounded_budget() {
    let steps = iter::repeat_n(ReadStep::Fail(ErrorKind::Interrupted), POLL_BUDGET);
    let mut reader = ScriptReader::new(steps);
    let mut bytes = [0_u8; 1];
    let mut bufs = [IoSliceMut::new(&mut bytes)];
    let (wake, waker) = counting_waker();
    assert_eq!(
      kinds(poll(&mut reader.read_vectored(&mut bufs), &waker)),
      Poll::Pending
    );
    assert_eq!((reader.polls, wake.count()), (POLL_BUDGET, 1));
    assert_eq!(kind(run(reader.read_vectored(&mut bufs), 1)), Ok(0));

    let steps = iter::repeat_n(WriteStep::Fail(ErrorKind::Interrupted), POLL_BUDGET);
    let mut writer = ScriptWriter::new(steps);
    let bufs = [IoSlice::new(b"x")];
    let (wake, waker) = counting_waker();
    assert_eq!(
      kinds(poll(&mut writer.write_vectored(&bufs), &waker)),
      Poll::Pending
    );
    assert_eq!((writer.polls, wake.count()), (POLL_BUDGET, 1));
    assert_eq!(kind(run(writer.write_vectored(&bufs), 1)), Ok(1));
  }

  #[test]
  fn empty_reads_and_writes_complete_without_polling() {
    let mut reader = ScriptReader::new([ReadStep::Pending]);
    let mut writer = ScriptWriter::new([WriteStep::Pending]);
    let (wake, waker) = counting_waker();
    let mut empty = [0u8; 0];
    let read = poll(&mut reader.read(&mut empty), &waker);
    assert_eq!(kinds(read), Poll::Ready(Ok(0)));
    let read_exact = poll(&mut reader.read_exact(&mut empty), &waker);
    assert_eq!(kinds(read_exact), Poll::Ready(Ok(0)));
    let write = poll(&mut writer.write(&[]), &waker);
    assert_eq!(kinds(write), Poll::Ready(Ok(0)));
    let write_all = poll(&mut writer.write_all(&[]), &waker);
    assert_eq!(kinds(write_all), Poll::Ready(Ok(())));
    assert_eq!((reader.polls, writer.polls, wake.count()), (0, 0, 0));
  }

  #[test]
  fn read_exact_keeps_its_position_across_pending() {
    let mut reader = ScriptReader::new([
      ReadStep::Bytes(b"ab"),
      ReadStep::Pending,
      ReadStep::Bytes(b"c"),
      ReadStep::Bytes(b"d"),
    ]);
    let mut buf = [0u8; 4];
    let (wake, waker) = counting_waker();
    {
      let mut future = reader.read_exact(&mut buf);
      assert_eq!(kinds(poll(&mut future, &waker)), Poll::Pending);
      assert_eq!(future.filled(), 2);
      assert_eq!(kinds(poll(&mut future, &waker)), Poll::Ready(Ok(4)));
    }
    // The `Pending` came from the reader, which registers its own wake-up.
    assert_eq!(wake.count(), 0);
    assert_eq!(&buf, b"abcd");
    assert_eq!(reader.polls, 4);
  }

  #[test]
  fn read_exact_reports_early_end_of_stream() {
    let mut reader = ScriptReader::new([ReadStep::Bytes(b"ab")]);
    let mut buf = [0u8; 4];
    let mut future = reader.read_exact(&mut buf);
    assert_eq!(kind(run(&mut future, 1)), Err(ErrorKind::UnexpectedEof));
    assert_eq!(future.filled(), 2);
    drop(future);
    assert_eq!(&buf[..2], b"ab");
  }

  #[test]
  fn read_exact_retries_interrupted_and_keeps_progress_on_error() {
    let mut reader = ScriptReader::new([
      ReadStep::Bytes(b"a"),
      ReadStep::Fail(ErrorKind::Interrupted),
      ReadStep::Bytes(b"b"),
      ReadStep::Fail(ErrorKind::ConnectionReset),
    ]);
    let mut buf = [0u8; 4];
    let mut future = reader.read_exact(&mut buf);
    assert_eq!(kind(run(&mut future, 1)), Err(ErrorKind::ConnectionReset));
    assert_eq!(future.filled(), 2);
    drop(future);
    assert_eq!(&buf[..2], b"ab");
    assert_eq!(reader.polls, 4);
  }

  #[test]
  fn read_exact_rejects_a_count_beyond_the_rest_of_the_buffer() {
    let mut reader = ScriptReader::new([ReadStep::Bytes(b"ab"), ReadStep::Claim(3)]);
    let mut buf = [0u8; 4];
    let mut future = reader.read_exact(&mut buf);
    assert_eq!(kind(run(&mut future, 1)), Err(ErrorKind::InvalidData));
    assert_eq!(future.filled(), 2);
  }

  #[test]
  fn read_exact_yields_after_its_budget() {
    let mut reader = ScriptReader::new(iter::repeat_n(ReadStep::Bytes(b"x"), 200));
    let mut buf = [0u8; 200];
    let (wake, waker) = counting_waker();
    let mut future = reader.read_exact(&mut buf);
    assert_eq!(kinds(poll(&mut future, &waker)), Poll::Pending);
    assert_eq!((future.filled(), wake.count()), (POLL_BUDGET, 1));
    assert_eq!(kinds(poll(&mut future, &waker)), Poll::Pending);
    assert_eq!(kinds(poll(&mut future, &waker)), Poll::Pending);
    assert_eq!(kinds(poll(&mut future, &waker)), Poll::Ready(Ok(200)));
    assert_eq!(wake.count(), 3);
  }

  #[test]
  fn read_exact_resumes_after_cancellation_only_from_the_recorded_offset() {
    let mut reader = ScriptReader::new([
      ReadStep::Bytes(b"ab"),
      ReadStep::Pending,
      ReadStep::Bytes(b"cd"),
    ]);
    let mut buf = [0u8; 4];
    let filled = {
      let mut future = reader.read_exact(&mut buf);
      assert_eq!(kinds(poll(&mut future, Waker::noop())), Poll::Pending);
      future.filled()
    };
    assert_eq!((filled, &buf[..filled]), (2, &b"ab"[..]));
    assert_eq!(kind(run(reader.read_exact(&mut buf[filled..]), 2)), Ok(2));
    assert_eq!(&buf, b"abcd");
  }

  #[test]
  fn write_returns_one_checked_count() {
    let mut writer = ScriptWriter::new([WriteStep::Accept(2), WriteStep::Claim(9)]);
    assert_eq!(kind(run(writer.write(b"abc"), 1)), Ok(2));
    let result = run(writer.write(b"abc"), 1);
    assert_eq!(kind(result), Err(ErrorKind::InvalidData));
    assert_eq!(writer.data, b"ab");
  }

  #[test]
  fn write_all_keeps_its_position_across_pending() {
    let mut writer = ScriptWriter::new([
      WriteStep::Accept(2),
      WriteStep::Pending,
      WriteStep::Accept(1),
    ]);
    let (wake, waker) = counting_waker();
    {
      let mut future = writer.write_all(b"abcdef");
      assert_eq!(kinds(poll(&mut future, &waker)), Poll::Pending);
      assert_eq!(future.written(), 2);
      assert_eq!(kinds(poll(&mut future, &waker)), Poll::Ready(Ok(())));
    }
    assert_eq!(wake.count(), 0);
    assert_eq!(writer.data, b"abcdef");
    assert_eq!(writer.flushes, 0);
  }

  #[test]
  fn write_all_reports_write_zero_and_invalid_counts() {
    let mut writer = ScriptWriter::new([WriteStep::Accept(2), WriteStep::Accept(0)]);
    let mut future = writer.write_all(b"abcd");
    assert_eq!(kind(run(&mut future, 1)), Err(ErrorKind::WriteZero));
    assert_eq!(future.written(), 2);

    let mut writer = ScriptWriter::new([WriteStep::Accept(1), WriteStep::Claim(4)]);
    let mut future = writer.write_all(b"abcd");
    assert_eq!(kind(run(&mut future, 1)), Err(ErrorKind::InvalidData));
    assert_eq!(future.written(), 1);
  }

  #[test]
  fn write_all_retries_interrupted_and_keeps_progress_on_error() {
    let mut writer = ScriptWriter::new([
      WriteStep::Accept(1),
      WriteStep::Fail(ErrorKind::Interrupted),
      WriteStep::Fail(ErrorKind::BrokenPipe),
    ]);
    let mut future = writer.write_all(b"abcd");
    assert_eq!(kind(run(&mut future, 1)), Err(ErrorKind::BrokenPipe));
    assert_eq!(future.written(), 1);
    drop(future);
    assert_eq!(writer.polls, 3);
  }

  #[test]
  fn write_all_yields_after_its_budget() {
    let mut writer = ScriptWriter::new(iter::repeat_n(WriteStep::Accept(1), 100));
    let (wake, waker) = counting_waker();
    let data = [7u8; 100];
    let mut future = writer.write_all(&data);
    assert_eq!(kinds(poll(&mut future, &waker)), Poll::Pending);
    assert_eq!((future.written(), wake.count()), (POLL_BUDGET, 1));
    assert_eq!(kinds(poll(&mut future, &waker)), Poll::Ready(Ok(())));
    assert_eq!(wake.count(), 1);
    drop(future);
    assert_eq!(writer.data, data);
  }

  #[test]
  fn flush_and_shutdown_forward_to_the_writer() {
    let mut writer = ScriptWriter::default().with_flushes([FlushStep::Pending]);
    assert_eq!(kind(run(writer.flush(), 2)), Ok(()));
    assert_eq!(kind(run(writer.shutdown(), 1)), Ok(()));
    assert_eq!((writer.flushes, writer.shutdowns), (2, 1));
  }

  #[test]
  fn seek_polls_again_with_the_same_position() {
    struct PendingOnce(Vec<SeekFrom>);

    impl AsyncSeek for PendingOnce {
      fn poll_seek(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        pos: SeekFrom,
      ) -> Poll<io::Result<u64>> {
        let seen = &mut self.get_mut().0;
        seen.push(pos);
        if seen.len() == 1 {
          Poll::Pending
        } else {
          Poll::Ready(Ok(9))
        }
      }
    }

    let mut seeker = PendingOnce(Vec::new());
    assert_eq!(kind(run(seeker.seek(SeekFrom::Current(4)), 2)), Ok(9));
    assert_eq!(seeker.0, [SeekFrom::Current(4), SeekFrom::Current(4)]);
  }

  #[test]
  fn forwarding_through_mutable_references_and_trait_objects() {
    fn read_two<R: AsyncRead + Unpin>(mut reader: R) -> io::Result<usize> {
      let mut buf = [0u8; 2];
      run(reader.read_exact(&mut buf), 1)
    }

    let mut reader = SliceReader::new(b"abcd");
    assert_eq!(kind(read_two(&mut reader)), Ok(2));
    assert_eq!(kind(read_two(&mut &mut reader)), Ok(2));
    assert_eq!(reader.position(), 4);
    // `Self` is `&mut SliceReader`, so this goes through the forwarding impl.
    let mut seeker = &mut reader;
    let result = run(AsyncSeekExt::seek(&mut seeker, SeekFrom::Start(1)), 1);
    assert_eq!(kind(result), Ok(1));
    assert_eq!(reader.position(), 1);

    let mut out = [0u8; 2];
    let mut writer = SliceWriter::new(&mut out);
    let object: &mut (dyn AsyncWrite + Unpin) = &mut writer;
    assert_eq!(kind(run(object.write_all(b"xy"), 1)), Ok(()));
    assert_eq!(kind(run(object.flush(), 1)), Ok(()));
    assert_eq!(writer.written(), b"xy");
  }

  #[test]
  fn copy_flushes_when_the_reader_waits_and_at_the_end() {
    let mut reader = ScriptReader::new([
      ReadStep::Bytes(b"hello "),
      ReadStep::Pending,
      ReadStep::Bytes(b"world"),
    ]);
    let mut writer = ScriptWriter::new([WriteStep::Accept(2), WriteStep::Pending]);
    let mut buf = [0u8; 4];
    let (wake, waker) = counting_waker();
    let mut future = copy_with_buffer(&mut reader, &mut writer, &mut buf);
    // Writer `Pending` with "ll" still in the buffer.
    assert_eq!(kinds(poll(&mut future, &waker)), Poll::Pending);
    assert_eq!((future.transferred(), future.unwritten()), (2, 2..4));
    // Reader `Pending` after "llo " was written: one flush.
    assert_eq!(kinds(poll(&mut future, &waker)), Poll::Pending);
    assert_eq!(kinds(poll(&mut future, &waker)), Poll::Ready(Ok(11)));
    assert_eq!(wake.count(), 0);
    drop(future);
    assert_eq!(writer.data, b"hello world");
    assert_eq!(writer.flushed_at, [6, 11]);
    assert_eq!(writer.shutdowns, 0);
  }

  #[test]
  fn copy_completes_only_after_the_final_flush() {
    let mut reader = ScriptReader::new([ReadStep::Bytes(b"abc")]);
    let flushes = [FlushStep::Pending, FlushStep::Fail(ErrorKind::BrokenPipe)];
    let mut writer = ScriptWriter::default().with_flushes(flushes);
    let mut buf = [0u8; 8];
    let mut future = copy_with_buffer(&mut reader, &mut writer, &mut buf);
    assert_eq!(kinds(poll(&mut future, Waker::noop())), Poll::Pending);
    assert_eq!(
      kinds(poll(&mut future, Waker::noop())),
      Poll::Ready(Err(ErrorKind::BrokenPipe))
    );
    assert_eq!(future.transferred(), 3);
    drop(future);
    assert_eq!(writer.data, b"abc");
    assert!(writer.flushed_at.is_empty());
  }

  #[test]
  fn copy_rejects_an_empty_buffer_before_polling() {
    let mut reader = ScriptReader::new([ReadStep::Bytes(b"a")]);
    let mut writer = ScriptWriter::default();
    let mut empty = [0u8; 0];
    let result = run(copy_with_buffer(&mut reader, &mut writer, &mut empty), 1);
    assert_eq!(kind(result), Err(ErrorKind::InvalidInput));
    assert_eq!((reader.polls, writer.polls, writer.flushes), (0, 0, 0));
  }

  #[test]
  fn copy_reports_write_zero_with_its_progress() {
    let mut reader = ScriptReader::new([ReadStep::Bytes(b"abcd")]);
    let mut writer = ScriptWriter::new([WriteStep::Accept(3), WriteStep::Accept(0)]);
    let mut buf = [0u8; 8];
    let mut future = copy_with_buffer(&mut reader, &mut writer, &mut buf);
    assert_eq!(kind(run(&mut future, 1)), Err(ErrorKind::WriteZero));
    assert_eq!((future.transferred(), future.unwritten()), (3, 3..4));
  }

  #[test]
  fn copy_keeps_its_count_on_a_reader_error() {
    let mut reader = ScriptReader::new([
      ReadStep::Bytes(b"ab"),
      ReadStep::Fail(ErrorKind::Interrupted),
      ReadStep::Fail(ErrorKind::ConnectionReset),
    ]);
    let mut writer = ScriptWriter::default();
    let mut buf = [0u8; 8];
    let mut future = copy_with_buffer(&mut reader, &mut writer, &mut buf);
    assert_eq!(kind(run(&mut future, 1)), Err(ErrorKind::ConnectionReset));
    assert_eq!((future.transferred(), future.unwritten()), (2, 0..0));
    drop(future);
    assert_eq!(reader.polls, 3);
    assert_eq!(writer.flushes, 0);
  }

  #[test]
  fn copy_rejects_counts_beyond_the_buffer() {
    let mut reader = ScriptReader::new([ReadStep::Claim(9)]);
    let mut writer = ScriptWriter::default();
    let mut buf = [0u8; 8];
    let result = run(copy_with_buffer(&mut reader, &mut writer, &mut buf), 1);
    assert_eq!(kind(result), Err(ErrorKind::InvalidData));
    assert_eq!(writer.polls, 0);

    let mut reader = ScriptReader::new([ReadStep::Bytes(b"abc")]);
    let mut writer = ScriptWriter::new([WriteStep::Claim(5)]);
    let mut future = copy_with_buffer(&mut reader, &mut writer, &mut buf);
    assert_eq!(kind(run(&mut future, 1)), Err(ErrorKind::InvalidData));
    assert_eq!((future.transferred(), future.unwritten()), (0, 0..3));
  }

  #[test]
  fn copy_yields_after_its_budget() {
    let mut reader = ScriptReader::new(iter::repeat_n(ReadStep::Bytes(b"x"), 100));
    let mut writer = ScriptWriter::default();
    let mut buf = [0u8; 8];
    let (wake, waker) = counting_waker();
    let mut future = copy_with_buffer(&mut reader, &mut writer, &mut buf);
    // One read and one write per byte.
    assert_eq!(kinds(poll(&mut future, &waker)), Poll::Pending);
    assert_eq!((future.transferred(), wake.count()), (32, 1));
    assert_eq!(kinds(poll(&mut future, &waker)), Poll::Pending);
    assert_eq!(kinds(poll(&mut future, &waker)), Poll::Pending);
    assert_eq!(kinds(poll(&mut future, &waker)), Poll::Ready(Ok(100)));
    assert_eq!(wake.count(), 3);
    drop(future);
    assert_eq!(writer.data.len(), 100);
    assert_eq!(writer.flushed_at, [100]);
  }

  #[test]
  fn copy_resumes_after_cancellation_from_its_unwritten_range() {
    let mut reader = ScriptReader::new([ReadStep::Bytes(b"abcdef")]);
    let mut writer = ScriptWriter::new([WriteStep::Accept(2), WriteStep::Pending]);
    let mut buf = [0u8; 4];
    let unwritten = {
      let mut future = copy_with_buffer(&mut reader, &mut writer, &mut buf);
      assert_eq!(kinds(poll(&mut future, Waker::noop())), Poll::Pending);
      future.unwritten()
    };
    assert_eq!(&buf[unwritten.clone()], b"cd");
    assert_eq!(kind(run(writer.write_all(&buf[unwritten]), 1)), Ok(()));
    let result = run(copy_with_buffer(&mut reader, &mut writer, &mut buf), 1);
    assert_eq!(kind(result), Ok(2));
    assert_eq!(writer.data, b"abcdef");
  }

  #[test]
  fn slice_reader_reads_in_order_then_reports_end() {
    let mut reader = SliceReader::new(b"abcde");
    let mut buf = [0u8; 3];
    assert_eq!(kind(run(reader.read(&mut buf), 1)), Ok(3));
    assert_eq!((&buf, reader.position()), (b"abc", 3));
    assert_eq!(reader.remaining(), b"de");
    assert_eq!(kind(run(reader.read(&mut buf), 1)), Ok(2));
    assert_eq!(&buf[..2], b"de");
    assert_eq!(kind(run(reader.read(&mut buf), 1)), Ok(0));
    let result = run(reader.read_exact(&mut buf), 1);
    assert_eq!(kind(result), Err(ErrorKind::UnexpectedEof));
    assert_eq!(reader.get_ref(), b"abcde");
    assert!(reader.remaining().is_empty());
  }

  #[test]
  fn slice_reader_seeks_only_within_the_slice() {
    let mut reader = SliceReader::new(b"hello");
    assert_eq!(kind(run(reader.seek(SeekFrom::End(-2)), 1)), Ok(3));
    assert_eq!(reader.remaining(), b"lo");
    assert_eq!(kind(run(reader.seek(SeekFrom::Current(-3)), 1)), Ok(0));
    for target in [
      SeekFrom::Start(6),
      SeekFrom::Start(u64::MAX),
      SeekFrom::End(1),
      SeekFrom::Current(-1),
      SeekFrom::Current(i64::MIN),
    ] {
      let result = run(reader.seek(target), 1);
      assert_eq!(kind(result), Err(ErrorKind::InvalidInput));
      assert_eq!(reader.position(), 0);
    }
    assert_eq!(kind(run(reader.seek(SeekFrom::End(0)), 1)), Ok(5));
    assert_eq!(kind(run(reader.seek(SeekFrom::Start(5)), 1)), Ok(5));
  }

  #[test]
  fn slice_writer_never_grows() {
    let mut out = [0u8; 4];
    let mut writer = SliceWriter::new(&mut out);
    assert_eq!(kind(run(writer.write(b"ab"), 1)), Ok(2));
    let result = run(writer.write_all(b"cde"), 1);
    assert_eq!(kind(result), Err(ErrorKind::WriteZero));
    assert_eq!((writer.position(), writer.spare_len()), (4, 0));
    assert_eq!(kind(run(writer.write(b"f"), 1)), Ok(0));
    assert_eq!(kind(run(writer.shutdown(), 1)), Ok(()));
    assert_eq!(writer.written(), b"abcd");
    assert_eq!(writer.get_ref(), b"abcd");
    assert_eq!(writer.into_inner(), b"abcd");
  }

  #[test]
  fn copy_between_slices_stops_when_the_writer_is_full() {
    let mut reader = SliceReader::new(b"abcdef");
    let mut out = [0u8; 4];
    let mut writer = SliceWriter::new(&mut out);
    let mut buf = [0u8; 3];
    let mut future = copy_with_buffer(&mut reader, &mut writer, &mut buf);
    assert_eq!(kind(run(&mut future, 1)), Err(ErrorKind::WriteZero));
    assert_eq!((future.transferred(), future.unwritten()), (4, 1..3));
    drop(future);
    assert_eq!(reader.position(), 6);
    assert_eq!(writer.written(), b"abcd");
  }
}
