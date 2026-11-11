//! Buffered asynchronous I/O backed by caller-supplied [`ManagedBuf`] storage.
//!
//! The wrappers do not allocate their own byte vectors. Their constructors
//! require nonempty, uniquely owned managed storage and return the original
//! endpoint and buffer when that contract is not met. A reader treats the
//! buffer's full length as writable initialized storage; a writer uses it to
//! retain bytes accepted from callers until the wrapped endpoint accepts them.
//!
//! Each poll makes at most [`POLL_BUDGET`] calls to the wrapped endpoint,
//! including calls made while flushing or shutting down. Runtime-owned outer
//! polls also charge each buffered operation through the shared cooperative
//! budget; manual polls and polls by another executor do not. `Interrupted` is
//! retried within the local bound. Other errors, including `WouldBlock`, are
//! returned to the caller. A pending writer retains its unwritten range, which
//! remains available from [`BufferedWriter::into_parts`] after cancellation.
//! Dropping a writer does not flush it.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::io::{self, ErrorKind};
use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::runtime::io::{AsyncRead, AsyncWrite, POLL_BUDGET};
use crate::runtime::managed::ManagedBuf;

/// The reason a buffered endpoint constructor rejected its storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferInitErrorKind {
  /// A zero-length buffer cannot provide useful buffered I/O.
  Empty,
  /// Another [`ManagedBuf`] clone still shares the storage.
  Shared,
}

/// A constructor rejection that preserves both supplied values.
pub struct BufferInitError<T> {
  /// The endpoint passed to the constructor.
  pub inner: T,
  /// The buffer passed to the constructor.
  pub buffer: ManagedBuf,
  /// Why the buffer could not be used.
  pub kind: BufferInitErrorKind,
}

impl<T> fmt::Debug for BufferInitError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BufferInitError")
      .field("kind", &self.kind)
      .field("buffer", &self.buffer)
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Display for BufferInitError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self.kind {
      BufferInitErrorKind::Empty => "buffered I/O requires a nonempty buffer",
      BufferInitErrorKind::Shared => "buffered I/O requires uniquely owned storage",
    })
  }
}

impl<T: fmt::Debug> std::error::Error for BufferInitError<T> {}

fn validate<T>(inner: T, mut buffer: ManagedBuf) -> Result<(T, ManagedBuf), BufferInitError<T>> {
  let kind = if buffer.is_empty() {
    Some(BufferInitErrorKind::Empty)
  } else if buffer.get_mut().is_none() {
    Some(BufferInitErrorKind::Shared)
  } else {
    None
  };
  match kind {
    Some(kind) => Err(BufferInitError {
      inner,
      buffer,
      kind,
    }),
    None => Ok((inner, buffer)),
  }
}

/// A reader whose internal byte storage is a caller-supplied managed buffer.
pub struct BufferedReader<R> {
  inner: R,
  buffer: ManagedBuf,
  start: usize,
  end: usize,
}

impl<R> BufferedReader<R> {
  /// Creates a reader over `inner` using the uniquely owned `buffer`.
  ///
  /// The buffer must be nonempty. On rejection, the error contains both
  /// original values so the caller can recover them.
  pub fn new(inner: R, buffer: ManagedBuf) -> Result<Self, BufferInitError<R>> {
    let (inner, buffer) = validate(inner, buffer)?;
    Ok(Self {
      inner,
      buffer,
      start: 0,
      end: 0,
    })
  }

  /// The wrapped reader.
  #[must_use]
  pub const fn get_ref(&self) -> &R {
    &self.inner
  }

  /// The unread bytes currently held in the buffer.
  #[must_use]
  pub fn buffered(&self) -> &[u8] {
    &self.buffer.as_slice()[self.start..self.end]
  }

  /// Returns the wrapped reader, its managed storage and the unread range.
  #[must_use]
  pub fn into_parts(self) -> (R, ManagedBuf, Range<usize>) {
    let Self {
      inner,
      buffer,
      start,
      end,
      ..
    } = self;
    (inner, buffer, start..end)
  }
}

impl<R: fmt::Debug> fmt::Debug for BufferedReader<R> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BufferedReader")
      .field("inner", &self.inner)
      .field("buffer_len", &self.buffer.len())
      .field("buffered", &self.buffered().len())
      .finish()
  }
}

/// A buffered reader whose returned slice remains valid until `consume` or
/// another mutable operation on the reader.
pub trait AsyncBufRead: AsyncRead {
  /// Returns the currently buffered bytes, filling the buffer if it is empty.
  fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>>;

  /// Consumes up to `amount` bytes from the current buffered slice.
  ///
  /// Amounts larger than the available data are clamped to the available
  /// length, matching the behavior expected of buffered readers.
  fn consume(self: Pin<&mut Self>, amount: usize);
}

impl<R: AsyncRead + Unpin> AsyncBufRead for BufferedReader<R> {
  fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
    let this = self.get_mut();
    let result =
      crate::runtime::asynchronous::poll_cooperative_composed(cx, |cx| this.poll_fill_range(cx));
    match result {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Ready(Ok(range)) => Poll::Ready(Ok(&this.buffer.as_slice()[range])),
    }
  }

  fn consume(self: Pin<&mut Self>, amount: usize) {
    let this = self.get_mut();
    let available = this.end - this.start;
    this.start += amount.min(available);
  }
}

impl<R: AsyncRead + Unpin> BufferedReader<R> {
  fn poll_fill_range(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Range<usize>>> {
    if self.start < self.end {
      return Poll::Ready(Ok(self.start..self.end));
    }

    self.start = 0;
    self.end = 0;
    let mut calls = 0;
    loop {
      if calls == POLL_BUDGET {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
      calls += 1;
      let storage = match self.buffer.get_mut() {
        Some(storage) => storage,
        None => unreachable!("buffer storage stays uniquely owned"),
      };
      match Pin::new(&mut self.inner).poll_read(cx, storage) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Ok(count)) if count > storage.len() => {
          return Poll::Ready(Err(ErrorKind::InvalidData.into()));
        }
        Poll::Ready(Ok(count)) => {
          self.end = count;
          return Poll::Ready(Ok(0..count));
        }
        Poll::Ready(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
      }
    }
  }
}

impl<R: AsyncRead + Unpin> AsyncRead for BufferedReader<R> {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    output: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    if output.is_empty() {
      return crate::runtime::asynchronous::poll_cooperative_composed(cx, |_| Poll::Ready(Ok(0)));
    }
    match self.as_mut().poll_fill_buf(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Ready(Ok(bytes)) => {
        let count = bytes.len().min(output.len());
        output[..count].copy_from_slice(&bytes[..count]);
        self.consume(count);
        Poll::Ready(Ok(count))
      }
    }
  }
}

/// A writer that retains accepted but not yet written bytes in a managed
/// buffer. Dropping it never writes or flushes implicitly.
pub struct BufferedWriter<W> {
  inner: W,
  buffer: ManagedBuf,
  start: usize,
  end: usize,
  shutdown_flushed: bool,
  shutdown_complete: bool,
}

impl<W> BufferedWriter<W> {
  /// Creates a writer over `inner` using the uniquely owned `buffer`.
  ///
  /// The buffer must be nonempty. On rejection, the error contains both
  /// original values so the caller can recover them.
  pub fn new(inner: W, buffer: ManagedBuf) -> Result<Self, BufferInitError<W>> {
    let (inner, buffer) = validate(inner, buffer)?;
    Ok(Self {
      inner,
      buffer,
      start: 0,
      end: 0,
      shutdown_flushed: false,
      shutdown_complete: false,
    })
  }

  /// The wrapped writer.
  #[must_use]
  pub const fn get_ref(&self) -> &W {
    &self.inner
  }

  /// The bytes accepted from callers and not yet accepted by the endpoint.
  #[must_use]
  pub fn unwritten(&self) -> &[u8] {
    &self.buffer.as_slice()[self.start..self.end]
  }

  /// Returns the wrapped writer, its managed storage and the exact unwritten
  /// range. Use this after cancellation or an error to recover queued bytes.
  #[must_use]
  pub fn into_parts(self) -> (W, ManagedBuf, Range<usize>) {
    let Self {
      inner,
      buffer,
      start,
      end,
      ..
    } = self;
    (inner, buffer, start..end)
  }

  fn compact(&mut self) {
    if self.start != 0 && self.start < self.end {
      let pending = self.end - self.start;
      let storage = match self.buffer.get_mut() {
        Some(storage) => storage,
        None => unreachable!("buffer storage stays uniquely owned"),
      };
      storage.copy_within(self.start..self.end, 0);
      self.start = 0;
      self.end = pending;
    } else if self.start == self.end {
      self.start = 0;
      self.end = 0;
    }
  }

  fn poll_flush_pending(&mut self, cx: &mut Context<'_>, calls: &mut usize) -> Poll<io::Result<()>>
  where
    W: AsyncWrite + Unpin,
  {
    while self.start < self.end {
      if *calls == POLL_BUDGET {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
      *calls += 1;
      let len = self.end - self.start;
      match Pin::new(&mut self.inner).poll_write(cx, &self.buffer.as_slice()[self.start..self.end])
      {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Ok(0)) => return Poll::Ready(Err(ErrorKind::WriteZero.into())),
        Poll::Ready(Ok(count)) if count > len => {
          return Poll::Ready(Err(ErrorKind::InvalidData.into()));
        }
        Poll::Ready(Ok(count)) => self.start += count,
        Poll::Ready(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
      }
    }
    self.start = 0;
    self.end = 0;

    loop {
      if *calls == POLL_BUDGET {
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
      *calls += 1;
      match Pin::new(&mut self.inner).poll_flush(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
        Poll::Ready(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
      }
    }
  }
}

impl<W: fmt::Debug> fmt::Debug for BufferedWriter<W> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BufferedWriter")
      .field("inner", &self.inner)
      .field("buffer_len", &self.buffer.len())
      .field("unwritten", &self.unwritten().len())
      .finish()
  }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for BufferedWriter<W> {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    input: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    crate::runtime::asynchronous::poll_cooperative_composed(cx, |cx| {
      if input.is_empty() {
        return Poll::Ready(Ok(0));
      }
      if this.end == this.buffer.len() {
        this.compact();
      }
      if this.end == this.buffer.len() {
        let mut calls = 0;
        match this.poll_flush_pending(cx, &mut calls) {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
          Poll::Ready(Ok(())) => {}
        }
      }
      let available = this.buffer.len() - this.end;
      let count = available.min(input.len());
      let storage = match this.buffer.get_mut() {
        Some(storage) => storage,
        None => unreachable!("buffer storage stays uniquely owned"),
      };
      storage[this.end..this.end + count].copy_from_slice(&input[..count]);
      this.end += count;
      if count != 0 {
        this.shutdown_flushed = false;
        this.shutdown_complete = false;
      }
      Poll::Ready(Ok(count))
    })
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.as_mut().get_mut();
    crate::runtime::asynchronous::poll_cooperative_composed(cx, |cx| {
      let mut calls = 0;
      this.poll_flush_pending(cx, &mut calls)
    })
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.as_mut().get_mut();
    crate::runtime::asynchronous::poll_cooperative_composed(cx, |cx| {
      if this.shutdown_complete {
        return Poll::Ready(Ok(()));
      }
      let mut calls = 0;
      if !this.shutdown_flushed {
        match this.poll_flush_pending(cx, &mut calls) {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
          Poll::Ready(Ok(())) => this.shutdown_flushed = true,
        }
      }
      loop {
        if calls == POLL_BUDGET {
          cx.waker().wake_by_ref();
          return Poll::Pending;
        }
        calls += 1;
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Ok(())) => {
            this.shutdown_complete = true;
            return Poll::Ready(Ok(()));
          }
          Poll::Ready(Err(error)) if error.kind() == ErrorKind::Interrupted => {}
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        }
      }
    })
  }
}

#[cfg(test)]
mod tests {
  use std::collections::VecDeque;
  use std::io::{self, ErrorKind};
  use std::pin::Pin;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::{Context, Poll, Wake, Waker};

  use super::{AsyncBufRead, BufferInitErrorKind, BufferedReader, BufferedWriter};
  use crate::runtime::io::{AsyncRead, AsyncWrite};
  use crate::runtime::managed::{ResourceLimits, ResourceScope};

  fn buffer(len: usize) -> crate::runtime::managed::ManagedBuf {
    ResourceScope::new(ResourceLimits {
      managed_memory: len,
      ..ResourceLimits::default()
    })
    .try_alloc_zeroed(len)
    .unwrap()
  }

  fn context() -> Context<'static> {
    Context::from_waker(Waker::noop())
  }

  #[derive(Debug, Default)]
  struct Reader {
    steps: VecDeque<io::Result<Vec<u8>>>,
    calls: usize,
    interrupts_forever: bool,
    reported_count: Option<usize>,
  }

  impl AsyncRead for Reader {
    fn poll_read(
      mut self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
      self.calls += 1;
      if self.interrupts_forever {
        return Poll::Ready(Err(ErrorKind::Interrupted.into()));
      }
      if let Some(count) = self.reported_count {
        return Poll::Ready(Ok(count));
      }
      let step = self.steps.pop_front().unwrap_or_else(|| Ok(Vec::new()));
      Poll::Ready(step.map(|bytes| {
        let count = bytes.len().min(output.len());
        output[..count].copy_from_slice(&bytes[..count]);
        count
      }))
    }
  }

  #[derive(Debug, Clone, Copy)]
  enum WriteStep {
    Accept(usize),
    Error(ErrorKind),
    Pending,
  }

  #[derive(Debug, Default)]
  struct Writer {
    writes: VecDeque<WriteStep>,
    flushes: VecDeque<WriteStep>,
    shutdowns: VecDeque<WriteStep>,
    output: Vec<u8>,
    write_calls: usize,
    flush_calls: usize,
    shutdown_calls: usize,
  }

  impl AsyncWrite for Writer {
    fn poll_write(
      mut self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      input: &[u8],
    ) -> Poll<io::Result<usize>> {
      self.write_calls += 1;
      match self
        .writes
        .pop_front()
        .unwrap_or(WriteStep::Accept(input.len()))
      {
        WriteStep::Accept(count) => {
          if count <= input.len() {
            self.output.extend_from_slice(&input[..count]);
          }
          Poll::Ready(Ok(count))
        }
        WriteStep::Error(kind) => Poll::Ready(Err(kind.into())),
        WriteStep::Pending => Poll::Pending,
      }
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      self.flush_calls += 1;
      match self.flushes.pop_front().unwrap_or(WriteStep::Accept(0)) {
        WriteStep::Accept(_) => Poll::Ready(Ok(())),
        WriteStep::Error(kind) => Poll::Ready(Err(kind.into())),
        WriteStep::Pending => Poll::Pending,
      }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      self.shutdown_calls += 1;
      match self.shutdowns.pop_front().unwrap_or(WriteStep::Accept(0)) {
        WriteStep::Accept(_) => Poll::Ready(Ok(())),
        WriteStep::Error(kind) => Poll::Ready(Err(kind.into())),
        WriteStep::Pending => Poll::Pending,
      }
    }
  }

  #[derive(Default)]
  struct Counter(AtomicUsize);

  impl Wake for Counter {
    fn wake(self: Arc<Self>) {
      self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.0.fetch_add(1, Ordering::Relaxed);
    }
  }

  #[test]
  fn constructors_recover_empty_and_shared_storage() {
    let empty = BufferedReader::new(Reader::default(), buffer(0)).unwrap_err();
    assert_eq!(empty.kind, BufferInitErrorKind::Empty);
    assert_eq!(empty.buffer.len(), 0);

    let shared = buffer(4);
    let clone = shared.clone();
    let rejected = BufferedWriter::new(Writer::default(), shared).unwrap_err();
    assert_eq!(rejected.kind, BufferInitErrorKind::Shared);
    assert_eq!(rejected.buffer.len(), 4);
    drop(clone);
  }

  #[test]
  fn reader_fills_and_clamps_consume_to_available_data() {
    let mut inner = Reader::default();
    inner.steps.push_back(Ok(b"abc".to_vec()));
    inner.steps.push_back(Ok(b"z".to_vec()));
    let mut reader = BufferedReader::new(inner, buffer(4)).unwrap();
    let mut cx = context();

    let filled = match Pin::new(&mut reader).poll_fill_buf(&mut cx) {
      Poll::Ready(Ok(bytes)) => bytes.to_vec(),
      other => panic!("unexpected fill result: {other:?}"),
    };
    assert_eq!(filled, b"abc");
    Pin::new(&mut reader).consume(usize::MAX);
    let filled_again = match Pin::new(&mut reader).poll_fill_buf(&mut cx) {
      Poll::Ready(Ok(bytes)) => bytes.to_vec(),
      other => panic!("unexpected second fill result: {other:?}"),
    };
    assert_eq!(filled_again, b"z");
  }

  #[test]
  fn reader_propagates_would_block_and_yields_after_interrupt_budget() {
    let mut blocked = Reader::default();
    blocked
      .steps
      .push_back(Err(io::Error::from(ErrorKind::WouldBlock)));
    let mut reader = BufferedReader::new(blocked, buffer(4)).unwrap();
    let mut cx = context();
    assert!(matches!(
      Pin::new(&mut reader).poll_fill_buf(&mut cx),
      Poll::Ready(Err(error)) if error.kind() == ErrorKind::WouldBlock
    ));

    let counter = Arc::new(Counter::default());
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    let mut inner = Reader {
      interrupts_forever: true,
      ..Reader::default()
    };
    // `get_ref` exposes the call count after the bounded poll.
    let mut reader = BufferedReader::new(&mut inner, buffer(4)).unwrap();
    assert!(Pin::new(&mut reader).poll_fill_buf(&mut cx).is_pending());
    assert_eq!(reader.get_ref().calls, 64);
    assert_eq!(counter.0.load(Ordering::Relaxed), 1);

    let mut inner = Reader {
      reported_count: Some(5),
      ..Reader::default()
    };
    let mut reader = BufferedReader::new(&mut inner, buffer(4)).unwrap();
    assert!(matches!(
      Pin::new(&mut reader).poll_fill_buf(&mut cx),
      Poll::Ready(Err(error)) if error.kind() == ErrorKind::InvalidData
    ));
  }

  #[test]
  fn writer_retains_exact_suffix_after_partial_progress_and_would_block() {
    let mut inner = Writer::default();
    inner.writes.extend([
      WriteStep::Accept(2),
      WriteStep::Error(ErrorKind::WouldBlock),
    ]);
    let mut writer = BufferedWriter::new(inner, buffer(8)).unwrap();
    let mut cx = context();
    assert!(matches!(
      Pin::new(&mut writer).poll_write(&mut cx, b"abcd"),
      Poll::Ready(Ok(4))
    ));
    assert!(matches!(
      Pin::new(&mut writer).poll_flush(&mut cx),
      Poll::Ready(Err(error)) if error.kind() == ErrorKind::WouldBlock
    ));
    assert_eq!(writer.unwritten(), b"cd");
    let (inner, buffer, range) = writer.into_parts();
    assert_eq!(&buffer.as_slice()[range], b"cd");
    assert_eq!(inner.output, b"ab");
  }

  #[test]
  fn cancelling_pending_flush_preserves_only_the_unwritten_suffix() {
    let mut inner = Writer::default();
    inner
      .writes
      .extend([WriteStep::Accept(2), WriteStep::Pending]);
    let mut writer = BufferedWriter::new(inner, buffer(8)).unwrap();
    let mut cx = context();
    assert!(matches!(
      Pin::new(&mut writer).poll_write(&mut cx, b"abcd"),
      Poll::Ready(Ok(4))
    ));
    {
      let mut flush = std::pin::pin!(std::future::poll_fn(|cx| {
        Pin::new(&mut writer).poll_flush(cx)
      }));
      assert!(flush.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(writer.unwritten(), b"cd");
    let (inner, buffer, range) = writer.into_parts();
    assert_eq!(&buffer.as_slice()[range], b"cd");
    assert_eq!(inner.output, b"ab");
  }

  #[test]
  fn writer_rejects_write_zero_and_oversized_counts_without_losing_bytes() {
    for (step, expected) in [
      (WriteStep::Accept(0), ErrorKind::WriteZero),
      (WriteStep::Accept(9), ErrorKind::InvalidData),
    ] {
      let mut inner = Writer::default();
      inner.writes.push_back(step);
      let mut writer = BufferedWriter::new(inner, buffer(8)).unwrap();
      let mut cx = context();
      assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut cx, b"four"),
        Poll::Ready(Ok(4))
      ));
      assert!(matches!(
        Pin::new(&mut writer).poll_flush(&mut cx),
        Poll::Ready(Err(error)) if error.kind() == expected
      ));
      assert_eq!(writer.unwritten(), b"four");
    }
  }

  #[test]
  fn into_parts_keeps_managed_charge_until_returned_buffer_is_dropped() {
    let scope = ResourceScope::new(ResourceLimits {
      managed_memory: 8,
      ..ResourceLimits::default()
    });
    let buffer = scope.try_alloc_zeroed(8).unwrap();
    let mut writer = BufferedWriter::new(Writer::default(), buffer).unwrap();
    let mut cx = context();
    assert!(matches!(
      Pin::new(&mut writer).poll_write(&mut cx, b"bytes"),
      Poll::Ready(Ok(5))
    ));
    assert_eq!(scope.snapshot().managed_memory, 8);
    let (_, returned_buffer, range) = writer.into_parts();
    assert_eq!(&returned_buffer.as_slice()[range], b"bytes");
    assert_eq!(scope.snapshot().managed_memory, 8);
    drop(returned_buffer);
    assert_eq!(scope.snapshot().managed_memory, 0);
  }

  #[test]
  fn shutdown_budget_includes_write_flush_and_shutdown_calls() {
    let inner = Writer {
      flushes: std::iter::repeat_n(WriteStep::Error(ErrorKind::Interrupted), 62)
        .chain([WriteStep::Accept(0)])
        .collect(),
      ..Writer::default()
    };
    let mut writer = BufferedWriter::new(inner, buffer(8)).unwrap();
    let mut cx = context();
    assert!(matches!(
      Pin::new(&mut writer).poll_write(&mut cx, b"data"),
      Poll::Ready(Ok(4))
    ));
    assert!(Pin::new(&mut writer).poll_shutdown(&mut cx).is_pending());
    assert!(matches!(
      Pin::new(&mut writer).poll_shutdown(&mut cx),
      Poll::Ready(Ok(()))
    ));
    let (inner, _, range) = writer.into_parts();
    assert_eq!(
      inner.write_calls + inner.flush_calls + inner.shutdown_calls,
      65
    );
    assert_eq!(inner.write_calls, 1);
    assert_eq!(inner.flush_calls, 63);
    assert_eq!(inner.shutdown_calls, 1);
    assert!(range.is_empty());
  }
}
