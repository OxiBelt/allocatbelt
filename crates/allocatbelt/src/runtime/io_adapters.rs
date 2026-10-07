//! Allocation-free stream composition and ready endpoints.

use std::io::{self, IoSlice, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::runtime::buffered_io::AsyncBufRead;

use super::{AsyncRead, AsyncSeek, AsyncWrite, checked_count};

fn saturating_usize(value: u64) -> usize {
  usize::try_from(value).unwrap_or(usize::MAX)
}

/// A reader capped at a remaining byte count.
///
/// A zero limit or empty buffer returns zero without polling the inner
/// reader. Pending and errors leave the limit unchanged. EOF does not
/// consume the limit. Vectored reads use the trait's scalar fallback.
/// Its [`AsyncBufRead`] implementation limits the exposed slice and clamps
/// `consume` to the last exposed bytes and the remaining allowance.
/// Direct access through `get_mut` can bypass the cap; it is a logical read
/// limit, not an ownership or security boundary.
#[derive(Debug)]
pub struct Take<R> {
  inner: R,
  remaining: u64,
  buffered: usize,
}

impl<R> Take<R> {
  pub(super) fn new(inner: R, limit: u64) -> Self {
    Self {
      inner,
      remaining: limit,
      buffered: 0,
    }
  }

  /// Remaining bytes allowed through this adapter.
  #[must_use]
  pub const fn limit(&self) -> u64 {
    self.remaining
  }

  /// Replaces the remaining read allowance, including after EOF.
  pub fn set_limit(&mut self, limit: u64) {
    self.remaining = limit;
    self.buffered = self.buffered.min(saturating_usize(limit));
  }

  /// Borrows the inner endpoint.
  #[must_use]
  pub const fn get_ref(&self) -> &R {
    &self.inner
  }

  /// Borrows the inner endpoint, allowing the caller to bypass the cap.
  pub const fn get_mut(&mut self) -> &mut R {
    self.buffered = 0;
    &mut self.inner
  }

  /// Recovers the inner endpoint without reading or dropping it.
  #[must_use]
  pub fn into_inner(self) -> R {
    self.inner
  }
}

impl<R: AsyncRead + Unpin> AsyncRead for Take<R> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    this.buffered = 0;
    let offered = this.remaining.min(buf.len() as u64) as usize;
    if offered == 0 {
      return Poll::Ready(Ok(0));
    }
    match Pin::new(&mut this.inner).poll_read(cx, &mut buf[..offered]) {
      Poll::Ready(Ok(count)) => match checked_count(count, offered) {
        Ok(count) => {
          this.remaining -= count as u64;
          Poll::Ready(Ok(count))
        }
        Err(error) => Poll::Ready(Err(error)),
      },
      other => other,
    }
  }
}

impl<R: AsyncBufRead + Unpin> AsyncBufRead for Take<R> {
  fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
    let this = self.get_mut();
    if this.remaining == 0 {
      this.buffered = 0;
      return Poll::Ready(Ok(&[]));
    }
    match Pin::new(&mut this.inner).poll_fill_buf(cx) {
      Poll::Pending => {
        this.buffered = 0;
        Poll::Pending
      }
      Poll::Ready(Err(error)) => {
        this.buffered = 0;
        Poll::Ready(Err(error))
      }
      Poll::Ready(Ok(bytes)) => {
        let count = bytes.len().min(saturating_usize(this.remaining));
        this.buffered = count;
        Poll::Ready(Ok(&bytes[..count]))
      }
    }
  }

  fn consume(self: Pin<&mut Self>, amount: usize) {
    let this = self.get_mut();
    let consumed = amount.min(this.buffered);
    Pin::new(&mut this.inner).consume(consumed);
    this.remaining -= consumed as u64;
    this.buffered -= consumed;
  }
}

/// Reads the first endpoint until a nonempty read reports EOF, then reads
/// the second. Empty reads poll neither endpoint and never switch sides.
///
/// Errors and Pending on the first endpoint do not switch sides. Once EOF
/// is observed, the first endpoint is no longer polled, including if callers
/// alter it through `get_mut`. Both endpoints remain owned until recovery or
/// drop. Dropping a read future does not undo bytes already read or a completed
/// switch to the second endpoint. The [`AsyncBufRead`] implementation follows
/// the same switch rule and consumes only the currently exposed bytes.
/// Vectored reads use the scalar fallback.
#[derive(Debug)]
pub struct Chain<A, B> {
  first: A,
  second: B,
  first_done: bool,
  buffered: usize,
}

impl<A, B> Chain<A, B> {
  pub(super) fn new(first: A, second: B) -> Self {
    Self {
      first,
      second,
      first_done: false,
      buffered: 0,
    }
  }

  /// Borrows both endpoints in read order.
  #[must_use]
  pub const fn get_ref(&self) -> (&A, &B) {
    (&self.first, &self.second)
  }

  /// Mutably borrows both endpoints; an observed first EOF stays sticky.
  pub const fn get_mut(&mut self) -> (&mut A, &mut B) {
    self.buffered = 0;
    (&mut self.first, &mut self.second)
  }

  /// Recovers both endpoints in read order.
  #[must_use]
  pub fn into_inner(self) -> (A, B) {
    (self.first, self.second)
  }
}

impl<A: AsyncRead + Unpin, B: AsyncRead + Unpin> AsyncRead for Chain<A, B> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    this.buffered = 0;
    if buf.is_empty() {
      return Poll::Ready(Ok(0));
    }
    if !this.first_done {
      match Pin::new(&mut this.first).poll_read(cx, buf) {
        Poll::Ready(Ok(0)) => this.first_done = true,
        Poll::Ready(Ok(count)) => return Poll::Ready(checked_count(count, buf.len())),
        other => return other,
      }
    }
    Pin::new(&mut this.second)
      .poll_read(cx, buf)
      .map(|result| result.and_then(|count| checked_count(count, buf.len())))
  }
}

impl<A: AsyncBufRead + Unpin, B: AsyncBufRead + Unpin> AsyncBufRead for Chain<A, B> {
  fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
    let this = self.get_mut();
    this.buffered = 0;
    if !this.first_done {
      match Pin::new(&mut this.first).poll_fill_buf(cx) {
        Poll::Ready(Ok([])) => this.first_done = true,
        Poll::Ready(Ok(bytes)) => {
          this.buffered = bytes.len();
          return Poll::Ready(Ok(bytes));
        }
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
      }
    }
    match Pin::new(&mut this.second).poll_fill_buf(cx) {
      Poll::Ready(Ok(bytes)) => {
        this.buffered = bytes.len();
        Poll::Ready(Ok(bytes))
      }
      other => other,
    }
  }

  fn consume(self: Pin<&mut Self>, amount: usize) {
    let this = self.get_mut();
    let consumed = amount.min(this.buffered);
    if this.first_done {
      Pin::new(&mut this.second).consume(consumed);
    } else {
      Pin::new(&mut this.first).consume(consumed);
    }
    this.buffered -= consumed;
  }
}

/// An always-ready EOF reader, discarding writer and zero-position seeker.
#[derive(Clone, Copy, Debug, Default)]
pub struct Empty;

/// Creates an allocation-free EOF reader.
#[must_use]
pub const fn empty() -> Empty {
  Empty
}

impl AsyncRead for Empty {
  fn poll_read(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    _buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    Poll::Ready(Ok(0))
  }
}

impl AsyncBufRead for Empty {
  fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
    Poll::Ready(Ok(&[]))
  }

  fn consume(self: Pin<&mut Self>, _amount: usize) {}
}

impl AsyncWrite for Empty {
  fn poll_write(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    Poll::Ready(Ok(buf.len()))
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    let count = bufs
      .iter()
      .try_fold(0usize, |sum, buf| sum.checked_add(buf.len()));
    Poll::Ready(count.ok_or_else(|| io::ErrorKind::InvalidInput.into()))
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

impl AsyncSeek for Empty {
  fn poll_seek(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    _pos: SeekFrom,
  ) -> Poll<io::Result<u64>> {
    Poll::Ready(Ok(0))
  }
}

/// An always-ready reader that fills initialized buffers with one byte.
/// Bound whole-stream reads with [`Take`] because this endpoint has no EOF.
#[derive(Clone, Copy, Debug)]
pub struct Repeat(u8);

/// Creates an allocation-free repeating-byte reader.
#[must_use]
pub const fn repeat(byte: u8) -> Repeat {
  Repeat(byte)
}

impl AsyncRead for Repeat {
  fn poll_read(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    buf.fill(self.0);
    Poll::Ready(Ok(buf.len()))
  }
}

/// An always-ready writer that discards bytes, accepting their whole count.
/// Flush and write shutdown succeed without I/O. Shutdown does not revoke
/// later writes, matching a stateless sink rather than a socket endpoint.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sink;

/// Creates an allocation-free discarding writer.
#[must_use]
pub const fn sink() -> Sink {
  Sink
}

impl AsyncWrite for Sink {
  fn poll_write(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    Poll::Ready(Ok(buf.len()))
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    let count = bufs
      .iter()
      .try_fold(0usize, |sum, buf| sum.checked_add(buf.len()));
    Poll::Ready(count.ok_or_else(|| io::ErrorKind::InvalidInput.into()))
  }

  fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }
}

#[cfg(all(test, not(loom)))]
#[path = "io_adapters_tests.rs"]
mod tests;
