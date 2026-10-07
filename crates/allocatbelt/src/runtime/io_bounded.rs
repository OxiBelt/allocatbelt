//! Bounded delimiter and whole-stream reads over caller-owned initialized slices.
//!
//! These futures never grow a `Vec` or `String`; UTF-8 methods validate bytes
//! already written into the caller's slice. A full slice, including a
//! zero-length slice, ends immediately as `Capacity`, without probing the
//! endpoint or consuming a buffered tail. `filled()` exposes progress while a
//! future is pending or before it is canceled. Cancellation does not roll back
//! copied or consumed bytes. An endpoint that panics may have changed its own
//! state and must not be assumed safe to replay.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::runtime::buffered_io::AsyncBufRead;

use super::{AsyncRead, POLL_BUDGET, yield_now};

/// Why a bounded read stopped successfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedReadStop {
  /// The requested delimiter was copied, including the delimiter byte.
  Delimiter,
  /// The endpoint reported EOF before the destination filled.
  Eof,
  /// The destination filled; no extra endpoint poll was made to distinguish
  /// exact-fit EOF from additional input.
  Capacity,
}

/// Progress and termination reason for a successful bounded read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedRead {
  /// Number of initialized bytes written at the front of the caller's slice.
  pub filled: usize,
  /// The event that ended the read.
  pub stop: BoundedReadStop,
}

/// An I/O or UTF-8 error with the count of bytes already written.
#[derive(Debug)]
pub struct BoundedReadError {
  source: io::Error,
  filled: usize,
}

impl BoundedReadError {
  fn new(source: io::Error, filled: usize) -> Self {
    Self { source, filled }
  }

  /// Number of bytes already written to the caller's slice.
  #[must_use]
  pub const fn filled(&self) -> usize {
    self.filled
  }

  /// The underlying I/O error kind.
  #[must_use]
  pub fn kind(&self) -> ErrorKind {
    self.source.kind()
  }

  /// Recovers the underlying I/O error.
  #[must_use]
  pub fn into_io_error(self) -> io::Error {
    self.source
  }
}

impl fmt::Display for BoundedReadError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "bounded read failed after {} bytes: {}",
      self.filled, self.source
    )
  }
}

impl Error for BoundedReadError {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    Some(&self.source)
  }
}

fn invalid_data(filled: usize) -> BoundedReadError {
  BoundedReadError::new(ErrorKind::InvalidData.into(), filled)
}

fn validate_utf8(bytes: &[u8], read: BoundedRead) -> Result<BoundedRead, BoundedReadError> {
  if std::str::from_utf8(&bytes[..read.filled]).is_ok() {
    Ok(read)
  } else {
    Err(invalid_data(read.filled))
  }
}

/// A future that reads an `AsyncRead` endpoint into a fixed initialized slice
/// until EOF or capacity. It never polls after filling the destination.
pub struct ReadToEndBounded<'a, R: ?Sized> {
  reader: &'a mut R,
  buffer: &'a mut [u8],
  filled: usize,
}

impl<'a, R: ?Sized> ReadToEndBounded<'a, R> {
  pub(super) fn new(reader: &'a mut R, buffer: &'a mut [u8]) -> Self {
    Self {
      reader,
      buffer,
      filled: 0,
    }
  }

  /// Bytes written so far, including while pending or before cancellation.
  #[must_use]
  pub const fn filled(&self) -> usize {
    self.filled
  }
}

impl<R: AsyncRead + Unpin + ?Sized> Future for ReadToEndBounded<'_, R> {
  type Output = Result<BoundedRead, BoundedReadError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.filled == this.buffer.len() {
      return Poll::Ready(Ok(BoundedRead {
        filled: this.filled,
        stop: BoundedReadStop::Capacity,
      }));
    }

    let mut calls = 0;
    loop {
      if calls == POLL_BUDGET {
        return yield_now(cx);
      }
      calls += 1;
      let remaining = this.buffer.len() - this.filled;
      match Pin::new(&mut *this.reader).poll_read(cx, &mut this.buffer[this.filled..]) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
        Poll::Ready(Err(error)) => {
          return Poll::Ready(Err(BoundedReadError::new(error, this.filled)));
        }
        Poll::Ready(Ok(count)) if count > remaining => {
          return Poll::Ready(Err(invalid_data(this.filled)));
        }
        Poll::Ready(Ok(0)) => {
          return Poll::Ready(Ok(BoundedRead {
            filled: this.filled,
            stop: BoundedReadStop::Eof,
          }));
        }
        Poll::Ready(Ok(count)) => {
          this.filled += count;
          if this.filled == this.buffer.len() {
            return Poll::Ready(Ok(BoundedRead {
              filled: this.filled,
              stop: BoundedReadStop::Capacity,
            }));
          }
        }
      }
    }
  }
}

/// A future that reads a buffered endpoint through a delimiter, EOF, or the
/// fixed destination capacity. It consumes only copied bytes, preserving any
/// unread buffered suffix.
pub struct ReadUntilBounded<'a, R: ?Sized> {
  reader: &'a mut R,
  buffer: &'a mut [u8],
  delimiter: u8,
  filled: usize,
}

impl<'a, R: ?Sized> ReadUntilBounded<'a, R> {
  pub(super) fn new(reader: &'a mut R, delimiter: u8, buffer: &'a mut [u8]) -> Self {
    Self {
      reader,
      buffer,
      delimiter,
      filled: 0,
    }
  }

  /// Bytes copied so far, including while pending or before cancellation.
  #[must_use]
  pub const fn filled(&self) -> usize {
    self.filled
  }
}

impl<R: AsyncBufRead + Unpin + ?Sized> Future for ReadUntilBounded<'_, R> {
  type Output = Result<BoundedRead, BoundedReadError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.filled == this.buffer.len() {
      return Poll::Ready(Ok(BoundedRead {
        filled: this.filled,
        stop: BoundedReadStop::Capacity,
      }));
    }

    let mut calls = 0;
    loop {
      if calls == POLL_BUDGET {
        return yield_now(cx);
      }
      calls += 1;
      match Pin::new(&mut *this.reader).poll_fill_buf(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
        Poll::Ready(Err(error)) => {
          return Poll::Ready(Err(BoundedReadError::new(error, this.filled)));
        }
        Poll::Ready(Ok([])) => {
          return Poll::Ready(Ok(BoundedRead {
            filled: this.filled,
            stop: BoundedReadStop::Eof,
          }));
        }
        Poll::Ready(Ok(bytes)) => {
          let room = this.buffer.len() - this.filled;
          let offered = bytes.len().min(room);
          let found = bytes[..offered]
            .iter()
            .position(|byte| *byte == this.delimiter);
          let count = found.map_or(offered, |index| index + 1);
          this.buffer[this.filled..this.filled + count].copy_from_slice(&bytes[..count]);
          this.filled += count;
          Pin::new(&mut *this.reader).consume(count);
          if found.is_some() {
            return Poll::Ready(Ok(BoundedRead {
              filled: this.filled,
              stop: BoundedReadStop::Delimiter,
            }));
          }
          if this.filled == this.buffer.len() {
            return Poll::Ready(Ok(BoundedRead {
              filled: this.filled,
              stop: BoundedReadStop::Capacity,
            }));
          }
        }
      }
    }
  }
}

/// A line read that includes `\n` when present and validates the completed
/// bytes as UTF-8.
pub struct ReadLineBounded<'a, R: ?Sized> {
  inner: ReadUntilBounded<'a, R>,
}

impl<R: ?Sized> ReadLineBounded<'_, R> {
  /// Bytes copied so far, including while pending or before cancellation.
  #[must_use]
  pub const fn filled(&self) -> usize {
    self.inner.filled
  }
}

impl<R: AsyncBufRead + Unpin + ?Sized> Future for ReadLineBounded<'_, R> {
  type Output = Result<BoundedRead, BoundedReadError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    match Pin::new(&mut this.inner).poll(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Ready(Ok(read)) => Poll::Ready(validate_utf8(&this.inner.buffer[..read.filled], read)),
    }
  }
}

/// A whole-stream read that validates the completed bytes as UTF-8 without
/// growing a `String`.
pub struct ReadToStringBounded<'a, R: ?Sized> {
  inner: ReadToEndBounded<'a, R>,
}

impl<R: ?Sized> ReadToStringBounded<'_, R> {
  /// Bytes written so far, including while pending or before cancellation.
  #[must_use]
  pub const fn filled(&self) -> usize {
    self.inner.filled
  }
}

impl<'a, R: ?Sized> ReadToStringBounded<'a, R> {
  pub(super) fn new(reader: &'a mut R, buffer: &'a mut [u8]) -> Self {
    Self {
      inner: ReadToEndBounded::new(reader, buffer),
    }
  }
}

impl<R: AsyncRead + Unpin + ?Sized> Future for ReadToStringBounded<'_, R> {
  type Output = Result<BoundedRead, BoundedReadError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    match Pin::new(&mut this.inner).poll(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Ready(Ok(read)) => Poll::Ready(validate_utf8(&this.inner.buffer[..read.filled], read)),
    }
  }
}

/// Bounded buffered-read operations over [`AsyncBufRead`].
pub trait AsyncBufReadExt: AsyncBufRead {
  /// Copies bytes through `delimiter`, including it when found, or stops at
  /// EOF or capacity. Reaching capacity does not poll or consume another byte.
  fn read_until_bounded<'a>(
    &'a mut self,
    delimiter: u8,
    buffer: &'a mut [u8],
  ) -> ReadUntilBounded<'a, Self>
  where
    Self: Unpin,
  {
    ReadUntilBounded::new(self, delimiter, buffer)
  }

  /// Reads one UTF-8 line, including `\n` when present, into fixed storage.
  fn read_line_bounded<'a>(&'a mut self, buffer: &'a mut [u8]) -> ReadLineBounded<'a, Self>
  where
    Self: Unpin,
  {
    ReadLineBounded {
      inner: ReadUntilBounded::new(self, b'\n', buffer),
    }
  }
}

impl<R: AsyncBufRead + ?Sized> AsyncBufReadExt for R {}
