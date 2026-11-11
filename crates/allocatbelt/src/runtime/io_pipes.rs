//! Fixed-capacity in-memory byte pipes backed by caller-owned managed buffers.
//!
//! Each ring owns exactly one initialized
//! [`ManagedBuf`](crate::runtime::managed::ManagedBuf). Pipe operations
//! copy bytes into that storage; they never grow a queue or allocate payload
//! storage. Only the supplied buffers are charged to a
//! [`ResourceScope`](crate::runtime::managed::ResourceScope);
//! endpoint `Arc` and mutex metadata uses ordinary Rust allocations. A duplex
//! pair owns two independent rings, one per direction.
//! During runtime-owned task polls, each ready endpoint poll participates in
//! the shared cooperative budget. Manual polls and polls by other executors
//! bypass that accounting. The runtime does not preempt arbitrary caller loops.
//! Dropping a borrowing I/O future does not roll back accepted bytes; an
//! endpoint may retain its one direction waiter until it is polled again,
//! explicitly canceled, or dropped.
//! These endpoints use scalar I/O and the traits' default vectored fallback.
//! They do not implement [`AsyncBufRead`](crate::runtime::buffered_io::AsyncBufRead):
//! a ring slice cannot be borrowed safely after releasing its state lock.

pub mod pipes {
  use std::io;
  use std::panic::{self, AssertUnwindSafe};
  use std::task::{Context, Poll, Waker};

  #[cfg(loom)]
  use loom::sync::{Arc, Mutex, MutexGuard};
  #[cfg(not(loom))]
  use std::sync::{Arc, Mutex, MutexGuard};

  use crate::runtime::asynchronous::poll_cooperative;
  use crate::runtime::io::{AsyncRead, AsyncWrite};
  use crate::runtime::managed::ManagedBuf;

  /// The reason a pipe buffer could not be accepted.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum PipeInitErrorKind {
    /// A ring must have nonzero capacity.
    Empty,
    /// A ring buffer must not have any other [`ManagedBuf`] handles.
    Shared,
  }

  /// A pipe-construction error that returns every supplied buffer unchanged.
  #[derive(Debug)]
  pub struct PipeInitError<B> {
    /// Why construction failed.
    pub kind: PipeInitErrorKind,
    /// Every original input buffer.
    pub buffers: B,
  }

  impl<B> std::fmt::Display for PipeInitError<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      match self.kind {
        PipeInitErrorKind::Empty => f.write_str("pipe buffer must not be empty"),
        PipeInitErrorKind::Shared => f.write_str("pipe buffer must be uniquely owned"),
      }
    }
  }

  impl<B: std::fmt::Debug> std::error::Error for PipeInitError<B> {}

  /// A bounded simplex byte pipe's reading endpoint.
  pub struct PipeReader {
    ring: Arc<Ring>,
  }

  /// A bounded simplex byte pipe's writing endpoint.
  ///
  /// Flush completes immediately because writes are already visible to the
  /// paired reader; it provides no durability guarantee.
  pub struct PipeWriter {
    ring: Arc<Ring>,
    shutdown: bool,
  }

  /// One endpoint of a bounded duplex byte pipe.
  ///
  /// Each endpoint reads the ring written by its peer and writes the ring
  /// read by its peer. Endpoints are unique and must not be duplicated.
  /// Flush completes immediately because writes are already visible to the
  /// peer; it provides no durability guarantee.
  pub struct DuplexEnd {
    incoming: Arc<Ring>,
    outgoing: Arc<Ring>,
    shutdown: bool,
  }

  impl std::fmt::Debug for PipeReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.debug_struct("PipeReader").finish_non_exhaustive()
    }
  }

  impl std::fmt::Debug for PipeWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.debug_struct("PipeWriter")
        .field("shutdown", &self.shutdown)
        .finish_non_exhaustive()
    }
  }

  impl std::fmt::Debug for DuplexEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      f.debug_struct("DuplexEnd")
        .field("shutdown", &self.shutdown)
        .finish_non_exhaustive()
    }
  }

  /// Creates a simplex pipe with `buffer.len()` bytes of capacity.
  ///
  /// The buffer must be nonempty and uniquely owned. If validation fails,
  /// the returned error contains the original buffer. The ring retains its
  /// managed charge until both endpoints have been dropped. Dropping a
  /// writer closes its direction; the reader drains accepted bytes and then
  /// sees EOF. Dropping a reader discards buffered bytes and makes later
  /// writes fail with `BrokenPipe`.
  pub fn pipe(
    mut buffer: ManagedBuf,
  ) -> Result<(PipeReader, PipeWriter), PipeInitError<ManagedBuf>> {
    if let Err(kind) = validate_buffer(&mut buffer) {
      return Err(PipeInitError {
        kind,
        buffers: buffer,
      });
    }
    let ring = Arc::new(Ring::new(buffer));
    Ok((
      PipeReader { ring: ring.clone() },
      PipeWriter {
        ring,
        shutdown: false,
      },
    ))
  }

  /// Creates a duplex pair. `a_to_b` is written by the first endpoint and
  /// read by the second; `b_to_a` carries the opposite direction.
  ///
  /// Both buffers must be nonempty and uniquely owned. On failure, both
  /// original buffers are returned. Each direction retains its buffer charge
  /// until both endpoints are dropped. Shutting down one endpoint closes only
  /// its outgoing direction; its incoming direction remains usable. Dropping
  /// the endpoint closes its outgoing and incoming directions independently.
  pub fn duplex(
    mut a_to_b: ManagedBuf,
    mut b_to_a: ManagedBuf,
  ) -> Result<(DuplexEnd, DuplexEnd), PipeInitError<(ManagedBuf, ManagedBuf)>> {
    let first = validate_buffer(&mut a_to_b);
    let second = validate_buffer(&mut b_to_a);
    if let Some(kind) = first.err().or_else(|| second.err()) {
      return Err(PipeInitError {
        kind,
        buffers: (a_to_b, b_to_a),
      });
    }

    let a_to_b = Arc::new(Ring::new(a_to_b));
    let b_to_a = Arc::new(Ring::new(b_to_a));
    Ok((
      DuplexEnd {
        incoming: b_to_a.clone(),
        outgoing: a_to_b.clone(),
        shutdown: false,
      },
      DuplexEnd {
        incoming: a_to_b,
        outgoing: b_to_a,
        shutdown: false,
      },
    ))
  }

  fn validate_buffer(buffer: &mut ManagedBuf) -> Result<(), PipeInitErrorKind> {
    if buffer.is_empty() {
      return Err(PipeInitErrorKind::Empty);
    }
    if buffer.get_mut().is_none() {
      return Err(PipeInitErrorKind::Shared);
    }
    Ok(())
  }

  struct Ring {
    state: Mutex<RingState>,
  }

  struct RingState {
    buffer: ManagedBuf,
    head: usize,
    len: usize,
    reader_closed: bool,
    writer_closed: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
  }

  impl Ring {
    fn new(buffer: ManagedBuf) -> Self {
      Self {
        state: Mutex::new(RingState {
          buffer,
          head: 0,
          len: 0,
          reader_closed: false,
          writer_closed: false,
          read_waker: None,
          write_waker: None,
        }),
      }
    }

    fn lock(&self) -> MutexGuard<'_, RingState> {
      self
        .state
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
    }

    fn poll_read(&self, output: &mut [u8], cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
      poll_cooperative(cx, |cx| {
        if output.is_empty() {
          self.cancel_read_wait();
          Poll::Ready(Ok(0))
        } else {
          self.poll_read_inner(output, cx)
        }
      })
    }

    fn poll_read_inner(&self, output: &mut [u8], cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
      {
        let mut state = self.lock();
        match state.read(output) {
          ReadAttempt::Ready(count) => {
            let old = state.read_waker.take();
            let wake = state.write_waker.take();
            drop(state);
            drop_contained(old);
            wake_contained(wake);
            return Poll::Ready(Ok(count));
          }
          ReadAttempt::Pending => {}
        }
      }

      let waker = match clone_waker(cx.waker()) {
        Ok(waker) => waker,
        Err(error) => {
          self.cancel_read_wait();
          return Poll::Ready(Err(error));
        }
      };
      let mut state = self.lock();
      match state.read(output) {
        ReadAttempt::Ready(count) => {
          let old = state.read_waker.take();
          let write_waker = state.write_waker.take();
          drop(state);
          drop_contained(old);
          drop_contained(Some(waker));
          wake_contained(write_waker);
          Poll::Ready(Ok(count))
        }
        ReadAttempt::Pending => {
          let old = state.read_waker.replace(waker);
          drop(state);
          drop_contained(old);
          Poll::Pending
        }
      }
    }

    fn poll_write(
      &self,
      input: &[u8],
      cx: &mut Context<'_>,
      own_shutdown: bool,
    ) -> Poll<io::Result<usize>> {
      poll_cooperative(cx, |cx| {
        if input.is_empty() {
          self.cancel_write_wait();
          Poll::Ready(Ok(0))
        } else {
          self.poll_write_inner(input, cx, own_shutdown)
        }
      })
    }

    fn poll_write_inner(
      &self,
      input: &[u8],
      cx: &mut Context<'_>,
      own_shutdown: bool,
    ) -> Poll<io::Result<usize>> {
      {
        let mut state = self.lock();
        match state.write(input, own_shutdown) {
          WriteAttempt::Ready(result) => {
            let old = state.write_waker.take();
            let wake = if result.as_ref().is_ok_and(|count| *count > 0) {
              state.read_waker.take()
            } else {
              None
            };
            drop(state);
            drop_contained(old);
            wake_contained(wake);
            return Poll::Ready(result);
          }
          WriteAttempt::Pending => {}
        }
      }

      let waker = match clone_waker(cx.waker()) {
        Ok(waker) => waker,
        Err(error) => {
          self.cancel_write_wait();
          return Poll::Ready(Err(error));
        }
      };
      let mut state = self.lock();
      match state.write(input, own_shutdown) {
        WriteAttempt::Ready(result) => {
          let old = state.write_waker.take();
          let read_waker = if result.as_ref().is_ok_and(|count| *count > 0) {
            state.read_waker.take()
          } else {
            None
          };
          drop(state);
          drop_contained(old);
          drop_contained(Some(waker));
          wake_contained(read_waker);
          Poll::Ready(result)
        }
        WriteAttempt::Pending => {
          let old = state.write_waker.replace(waker);
          drop(state);
          drop_contained(old);
          Poll::Pending
        }
      }
    }

    fn set_reader_closed(&self) {
      let (read, write) = {
        let mut state = self.lock();
        if !state.reader_closed {
          state.reader_closed = true;
          state.head = 0;
          state.len = 0;
        }
        (state.read_waker.take(), state.write_waker.take())
      };
      drop_contained(read);
      wake_contained(write);
    }

    fn set_writer_closed(&self) {
      let (read, write) = {
        let mut state = self.lock();
        state.writer_closed = true;
        (state.read_waker.take(), state.write_waker.take())
      };
      wake_contained(read);
      drop_contained(write);
    }

    fn cancel_read_wait(&self) {
      let waker = self.lock().read_waker.take();
      drop_contained(waker);
    }

    fn cancel_write_wait(&self) {
      let waker = self.lock().write_waker.take();
      drop_contained(waker);
    }
  }

  enum ReadAttempt {
    Pending,
    Ready(usize),
  }

  enum WriteAttempt {
    Pending,
    Ready(io::Result<usize>),
  }

  impl RingState {
    fn assert_valid(&self) {
      let capacity = self.buffer.len();
      debug_assert!(capacity > 0);
      debug_assert!(self.head < capacity);
      debug_assert!(self.len <= capacity);
    }

    fn read(&mut self, output: &mut [u8]) -> ReadAttempt {
      self.assert_valid();
      if self.len == 0 {
        return if self.writer_closed || self.reader_closed {
          ReadAttempt::Ready(0)
        } else {
          ReadAttempt::Pending
        };
      }

      let count = output.len().min(self.len);
      let capacity = self.buffer.len();
      let first = count.min(capacity - self.head);
      output[..first].copy_from_slice(&self.buffer.as_slice()[self.head..self.head + first]);
      if first < count {
        output[first..count].copy_from_slice(&self.buffer.as_slice()[..count - first]);
      }
      self.head = advance(self.head, count, capacity);
      self.len -= count;
      if self.len == 0 {
        self.head = 0;
      }
      self.assert_valid();
      ReadAttempt::Ready(count)
    }

    fn write(&mut self, input: &[u8], own_shutdown: bool) -> WriteAttempt {
      self.assert_valid();
      if self.reader_closed || self.writer_closed || own_shutdown {
        return WriteAttempt::Ready(Err(io::Error::new(
          io::ErrorKind::BrokenPipe,
          "pipe is closed",
        )));
      }
      let capacity = self.buffer.len();
      let available = capacity - self.len;
      if available == 0 {
        return WriteAttempt::Pending;
      }
      let count = input.len().min(available);
      let tail = advance(self.head, self.len, capacity);
      let first = count.min(capacity - tail);
      let Some(buffer) = self.buffer.get_mut() else {
        return WriteAttempt::Ready(Err(io::Error::other(
          "pipe ring lost unique managed-buffer ownership",
        )));
      };
      buffer[tail..tail + first].copy_from_slice(&input[..first]);
      if first < count {
        buffer[..count - first].copy_from_slice(&input[first..count]);
      }
      self.len += count;
      self.assert_valid();
      WriteAttempt::Ready(Ok(count))
    }
  }

  fn advance(index: usize, count: usize, capacity: usize) -> usize {
    debug_assert!(capacity > 0 && index < capacity && count <= capacity);
    let until_wrap = capacity - index;
    if count >= until_wrap {
      count - until_wrap
    } else {
      index + count
    }
  }

  fn clone_waker(waker: &Waker) -> io::Result<Waker> {
    match panic::catch_unwind(AssertUnwindSafe(|| waker.clone())) {
      Ok(waker) => Ok(waker),
      Err(payload) => {
        contain_payload(payload);
        Err(io::Error::other("pipe waker clone panicked"))
      }
    }
  }

  fn wake_contained(waker: Option<Waker>) {
    if let Some(waker) = waker
      && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
    {
      contain_payload(payload);
    }
  }

  fn drop_contained(value: Option<Waker>) {
    if let Some(value) = value
      && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(value)))
    {
      contain_payload(payload);
    }
  }

  fn contain_payload(payload: Box<dyn std::any::Any + Send>) {
    if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(payload))) {
      // A panic payload with a panicking destructor cannot be safely dropped
      // during containment. Leak the secondary payload rather than beginning
      // a second unwind.
      std::mem::forget(payload);
    }
  }

  impl PipeReader {
    /// Clears the one stored read waiter, if any. A canceled borrowing future
    /// otherwise leaves its bounded waiter here until the next read, explicit
    /// cancellation, or endpoint drop.
    pub fn cancel_io_waits(&mut self) {
      self.ring.cancel_read_wait();
    }
  }

  impl PipeWriter {
    /// Clears the one stored write waiter, if any.
    pub fn cancel_io_waits(&mut self) {
      self.ring.cancel_write_wait();
    }
  }

  impl DuplexEnd {
    /// Clears this endpoint's one incoming read and outgoing write waiter.
    pub fn cancel_io_waits(&mut self) {
      self.incoming.cancel_read_wait();
      self.outgoing.cancel_write_wait();
    }
  }

  impl AsyncRead for PipeReader {
    fn poll_read(
      self: std::pin::Pin<&mut Self>,
      cx: &mut Context<'_>,
      output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
      self.get_mut().ring.poll_read(output, cx)
    }
  }

  impl AsyncWrite for PipeWriter {
    fn poll_write(
      self: std::pin::Pin<&mut Self>,
      cx: &mut Context<'_>,
      input: &[u8],
    ) -> Poll<io::Result<usize>> {
      let this = self.get_mut();
      this.ring.poll_write(input, cx, this.shutdown)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      poll_cooperative(_cx, |_| Poll::Ready(Ok(())))
    }

    fn poll_shutdown(
      self: std::pin::Pin<&mut Self>,
      _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
      let this = self.get_mut();
      poll_cooperative(_cx, |_| {
        if !this.shutdown {
          this.shutdown = true;
          this.ring.set_writer_closed();
        }
        Poll::Ready(Ok(()))
      })
    }
  }

  impl AsyncRead for DuplexEnd {
    fn poll_read(
      self: std::pin::Pin<&mut Self>,
      cx: &mut Context<'_>,
      output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
      self.get_mut().incoming.poll_read(output, cx)
    }
  }

  impl AsyncWrite for DuplexEnd {
    fn poll_write(
      self: std::pin::Pin<&mut Self>,
      cx: &mut Context<'_>,
      input: &[u8],
    ) -> Poll<io::Result<usize>> {
      let this = self.get_mut();
      this.outgoing.poll_write(input, cx, this.shutdown)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      poll_cooperative(_cx, |_| Poll::Ready(Ok(())))
    }

    fn poll_shutdown(
      self: std::pin::Pin<&mut Self>,
      _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
      let this = self.get_mut();
      poll_cooperative(_cx, |_| {
        if !this.shutdown {
          this.shutdown = true;
          this.outgoing.set_writer_closed();
        }
        Poll::Ready(Ok(()))
      })
    }
  }

  impl Drop for PipeReader {
    fn drop(&mut self) {
      self.ring.set_reader_closed();
    }
  }

  impl Drop for PipeWriter {
    fn drop(&mut self) {
      self.ring.set_writer_closed();
    }
  }

  impl Drop for DuplexEnd {
    fn drop(&mut self) {
      // Each ring is locked separately. Any callback is invoked only after
      // the corresponding transition has released its lock.
      self.outgoing.set_writer_closed();
      self.incoming.set_reader_closed();
    }
  }

  #[cfg(all(test, not(loom)))]
  mod tests {
    use super::{DuplexEnd, PipeInitErrorKind, duplex, pipe};
    use crate::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};
    use crate::runtime::channel;
    use crate::runtime::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use crate::runtime::managed::{ResourceLimits, ResourceScope};
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Weak;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    fn scope() -> ResourceScope {
      ResourceScope::new(ResourceLimits {
        managed_memory: 128,
        disk_concurrent_ops: 0,
        network_concurrent_ops: 0,
      })
    }

    fn buffer(scope: &ResourceScope, size: usize) -> crate::runtime::managed::ManagedBuf {
      scope.try_alloc_zeroed(size).unwrap()
    }

    fn context() -> Context<'static> {
      Context::from_waker(Waker::noop())
    }

    fn read(reader: &mut (impl AsyncRead + Unpin), output: &mut [u8]) -> Poll<io::Result<usize>> {
      let mut cx = context();
      Pin::new(reader).poll_read(&mut cx, output)
    }

    fn write(writer: &mut (impl AsyncWrite + Unpin), input: &[u8]) -> Poll<io::Result<usize>> {
      let mut cx = context();
      Pin::new(writer).poll_write(&mut cx, input)
    }

    fn shutdown(writer: &mut (impl AsyncWrite + Unpin)) -> Poll<io::Result<()>> {
      let mut cx = context();
      Pin::new(writer).poll_shutdown(&mut cx)
    }

    fn count(result: Poll<io::Result<usize>>) -> usize {
      match result {
        Poll::Ready(Ok(count)) => count,
        other => panic!("expected ready byte count, got {other:?}"),
      }
    }

    #[test]
    fn constructor_rejection_returns_empty_and_shared_inputs() {
      let scope = scope();
      let empty = buffer(&scope, 0);
      let err = pipe(empty).unwrap_err();
      assert_eq!(err.kind, PipeInitErrorKind::Empty);
      assert!(err.buffers.is_empty());

      let shared = buffer(&scope, 8);
      let other = shared.clone();
      let err = pipe(shared).unwrap_err();
      assert_eq!(err.kind, PipeInitErrorKind::Shared);
      assert_eq!(err.buffers.len(), 8);
      drop(other);
      let mut returned = err.buffers;
      assert!(returned.get_mut().is_some());

      let first = buffer(&scope, 4);
      let second = buffer(&scope, 0);
      let err = duplex(first, second).unwrap_err();
      assert_eq!(err.kind, PipeInitErrorKind::Empty);
      assert_eq!(err.buffers.0.len(), 4);
      assert!(err.buffers.1.is_empty());
      let (mut returned_first, returned_second) = err.buffers;
      assert!(returned_first.get_mut().is_some());
      assert!(returned_second.is_empty());
    }

    #[test]
    fn simplex_partial_progress_backpressure_and_wraparound() {
      let scope = scope();
      let (mut reader, mut writer) = pipe(buffer(&scope, 4)).unwrap();
      assert_eq!(count(write(&mut writer, b"abcd")), 4);
      assert!(write(&mut writer, b"x").is_pending());

      let mut first = [0; 3];
      assert_eq!(count(read(&mut reader, &mut first)), 3);
      assert_eq!(&first, b"abc");
      assert_eq!(count(write(&mut writer, b"xy")), 2);
      let mut tail = [0; 3];
      assert_eq!(count(read(&mut reader, &mut tail)), 3);
      assert_eq!(&tail, b"dxy");
    }

    #[test]
    fn canceling_write_all_keeps_accepted_bytes_and_allows_progress_to_resume() {
      let scope = scope();
      let (mut reader, mut writer) = pipe(buffer(&scope, 2)).unwrap();
      {
        let mut future = std::pin::pin!(writer.write_all(b"abc"));
        let mut cx = context();
        assert!(future.as_mut().poll(&mut cx).is_pending());
      }

      let mut accepted = [0; 2];
      assert_eq!(count(read(&mut reader, &mut accepted)), 2);
      assert_eq!(&accepted, b"ab");
      writer.cancel_io_waits();
      assert_eq!(count(write(&mut writer, b"c")), 1);
      let mut final_byte = [0];
      assert_eq!(count(read(&mut reader, &mut final_byte)), 1);
      assert_eq!(&final_byte, b"c");
    }

    #[test]
    fn shutdown_is_idempotent_positive_writes_fail_and_reads_drain_to_eof() {
      let scope = scope();
      let (mut reader, mut writer) = pipe(buffer(&scope, 4)).unwrap();
      assert_eq!(count(write(&mut writer, b"abc")), 3);
      assert!(shutdown(&mut writer).is_ready());
      assert!(shutdown(&mut writer).is_ready());
      assert_eq!(
        write(&mut writer, b"x").unwrap_ready().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
      );
      assert_eq!(count(write(&mut writer, b"")), 0);
      let mut output = [0; 4];
      assert_eq!(count(read(&mut reader, &mut output)), 3);
      assert_eq!(&output[..3], b"abc");
      assert_eq!(count(read(&mut reader, &mut output)), 0);
      assert_eq!(count(read(&mut reader, &mut output)), 0);
    }

    #[test]
    fn dropping_reader_makes_blocked_writer_fail_and_charge_lives_to_last_owner() {
      let scope = scope();
      let (reader, mut writer) = pipe(buffer(&scope, 3)).unwrap();
      assert_eq!(scope.snapshot().managed_memory, 3);
      assert_eq!(count(write(&mut writer, b"abc")), 3);
      assert!(write(&mut writer, b"d").is_pending());
      drop(reader);
      assert_eq!(
        write(&mut writer, b"d").unwrap_ready().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
      );
      assert_eq!(scope.snapshot().managed_memory, 3);
      drop(writer);
      assert_eq!(scope.snapshot().managed_memory, 0);
    }

    #[test]
    fn duplex_directions_close_independently_and_both_charges_release_last() {
      let scope = scope();
      let (mut a, mut b): (DuplexEnd, DuplexEnd) =
        duplex(buffer(&scope, 4), buffer(&scope, 2)).unwrap();
      assert_eq!(scope.snapshot().managed_memory, 6);
      assert_eq!(count(write(&mut a, b"hello")), 4);
      let mut received = [0; 4];
      assert_eq!(count(read(&mut b, &mut received)), 4);
      assert_eq!(&received, b"hell");

      assert!(shutdown(&mut a).is_ready());
      assert_eq!(
        write(&mut a, b"x").unwrap_ready().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
      );
      assert_eq!(count(read(&mut b, &mut received)), 0);
      assert_eq!(count(write(&mut b, b"ok")), 2);
      assert_eq!(count(read(&mut a, &mut received)), 2);
      assert_eq!(&received[..2], b"ok");

      drop(a);
      assert_eq!(scope.snapshot().managed_memory, 6);
      drop(b);
      assert_eq!(scope.snapshot().managed_memory, 0);
    }

    #[test]
    fn duplex_echo_uses_runtime_neutral_read_write_futures() {
      let scope = scope();
      let (a, b) = duplex(buffer(&scope, 8), buffer(&scope, 8)).unwrap();
      let runtime = AsyncRuntime::new(AsyncConfig {
        workers: 1,
        max_outstanding: 4,
        max_scopes: 2,
      })
      .unwrap();
      let echoed = runtime
        .block_on(async move {
          let (mut a, mut b) = (a, b);
          let mut request = [0; 4];
          let mut response = [0; 4];
          a.write_all(b"ping").await?;
          b.read_exact(&mut request).await?;
          b.write_all(&request).await?;
          b.shutdown().await?;
          a.read_exact(&mut response).await?;
          Ok::<_, io::Error>(response)
        })
        .unwrap()
        .unwrap();
      assert_eq!(&echoed, b"ping");
      runtime.shutdown(AsyncShutdown::Drain).unwrap();
    }

    #[test]
    fn exhausted_runtime_budget_preserves_ready_pipe_data_for_the_next_poll() {
      let scope = scope();
      let (mut reader, mut writer) = pipe(buffer(&scope, 1)).unwrap();
      assert_eq!(count(write(&mut writer, b"x")), 1);
      let runtime = AsyncRuntime::new(AsyncConfig {
        workers: 1,
        max_outstanding: 4,
        max_scopes: 2,
      })
      .unwrap();
      let job = runtime
        .handle()
        .spawn(async move {
          let report = std::future::poll_fn(|cx| {
            for _ in 0..64 {
              assert!(matches!(
                Pin::new(&mut reader).poll_read(cx, &mut []),
                Poll::Ready(Ok(0))
              ));
            }
            let mut byte = [0];
            let poll = Pin::new(&mut reader).poll_read(cx, &mut byte);
            Poll::Ready((poll.is_pending(), byte))
          })
          .await;
          (report.0, report.1, reader)
        })
        .unwrap();
      let (was_budget_blocked, output, mut reader) = runtime.block_on(job).unwrap().unwrap();
      assert!(was_budget_blocked);
      assert_eq!(output, [0]);
      assert_eq!(count(read(&mut reader, &mut [0])), 1);
      runtime.shutdown(AsyncShutdown::Drain).unwrap();
    }

    #[test]
    fn runtime_pipe_ready_loop_yields_to_another_admitted_task() {
      let scope = scope();
      let (reader, _writer) = pipe(buffer(&scope, 1)).unwrap();
      let runtime = AsyncRuntime::new(AsyncConfig {
        workers: 1,
        max_outstanding: 4,
        max_scopes: 2,
      })
      .unwrap();
      let (start_sender, mut start_receiver) = channel::channel::<()>(1, 2).unwrap();
      let (ready_sender, mut ready_receiver) = channel::channel::<()>(1, 2).unwrap();
      let reads = Arc::new(AtomicUsize::new(0));
      let hot_reads = reads.clone();

      let hot = runtime
        .handle()
        .spawn(async move {
          let mut reader = reader;
          let _ = start_receiver.recv().await;
          ready_sender.send(()).await.unwrap();
          for _ in 0..1_000 {
            std::future::poll_fn(|cx| match Pin::new(&mut reader).poll_read(cx, &mut []) {
              Poll::Ready(Ok(0)) => Poll::Ready(()),
              Poll::Ready(Ok(_)) | Poll::Ready(Err(_)) => panic!("empty pipe read changed state"),
              Poll::Pending => Poll::Pending,
            })
            .await;
            hot_reads.fetch_add(1, Ordering::SeqCst);
          }
          hot_reads.load(Ordering::SeqCst)
        })
        .unwrap();

      let observer = runtime
        .handle()
        .spawn(async move {
          let _ = ready_receiver.recv().await;
          reads.load(Ordering::SeqCst)
        })
        .unwrap();

      runtime.block_on(start_sender.send(())).unwrap().unwrap();
      let observed = runtime.block_on(observer).unwrap().unwrap();
      // One ready channel receive and one send can spend budget too, but the
      // direct pipe loop must yield before exhausting its 1,000 iterations.
      assert!(observed > 0 && observed <= 64);
      runtime.block_on(hot).unwrap().unwrap();
      runtime.shutdown(AsyncShutdown::Drain).unwrap();
    }

    #[test]
    fn empty_io_does_not_close_or_consume_any_state() {
      let scope = scope();
      let (mut reader, mut writer) = pipe(buffer(&scope, 2)).unwrap();
      assert_eq!(count(read(&mut reader, &mut [])), 0);
      assert_eq!(count(write(&mut writer, &[])), 0);
      assert_eq!(count(write(&mut writer, b"ok")), 2);
      let mut out = [0; 2];
      assert_eq!(count(read(&mut reader, &mut out)), 2);
      assert_eq!(&out, b"ok");
    }

    struct DropWake {
      drops: Arc<AtomicUsize>,
      wakes: Arc<AtomicUsize>,
    }

    impl Wake for DropWake {
      fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
      }
      fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
      }
    }

    impl Drop for DropWake {
      fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
      }
    }

    #[test]
    fn explicit_cancel_drops_the_bounded_stored_waiter() {
      let scope = scope();
      let (_reader, mut writer) = pipe(buffer(&scope, 1)).unwrap();
      assert_eq!(count(write(&mut writer, b"x")), 1);
      let drops = Arc::new(AtomicUsize::new(0));
      let wakes = Arc::new(AtomicUsize::new(0));
      let waker = Waker::from(Arc::new(DropWake {
        drops: drops.clone(),
        wakes: wakes.clone(),
      }));
      {
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut writer).poll_write(&mut cx, b"y").is_pending());
      }
      drop(waker);
      assert_eq!(drops.load(Ordering::SeqCst), 0);
      writer.cancel_io_waits();
      assert_eq!(drops.load(Ordering::SeqCst), 1);
      assert_eq!(wakes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ready_empty_operations_clear_only_their_retained_waiters() {
      let scope = scope();
      let (mut reader, mut writer) = pipe(buffer(&scope, 1)).unwrap();

      let read_drops = Arc::new(AtomicUsize::new(0));
      let read_wakes = Arc::new(AtomicUsize::new(0));
      let read_probe = Arc::new(DropWake {
        drops: read_drops.clone(),
        wakes: read_wakes.clone(),
      });
      let read_waker = Waker::from(read_probe.clone());
      {
        let mut cx = Context::from_waker(&read_waker);
        assert!(
          Pin::new(&mut reader)
            .poll_read(&mut cx, &mut [0])
            .is_pending()
        );
      }
      drop(read_waker);
      drop(read_probe);
      assert_eq!(read_drops.load(Ordering::SeqCst), 0);
      assert_eq!(count(read(&mut reader, &mut [])), 0);
      assert_eq!(read_drops.load(Ordering::SeqCst), 1);
      assert_eq!(read_wakes.load(Ordering::SeqCst), 0);

      assert_eq!(count(write(&mut writer, b"x")), 1);
      let write_drops = Arc::new(AtomicUsize::new(0));
      let write_wakes = Arc::new(AtomicUsize::new(0));
      let write_probe = Arc::new(DropWake {
        drops: write_drops.clone(),
        wakes: write_wakes.clone(),
      });
      let write_waker = Waker::from(write_probe.clone());
      {
        let mut cx = Context::from_waker(&write_waker);
        assert!(Pin::new(&mut writer).poll_write(&mut cx, b"y").is_pending());
      }
      drop(write_waker);
      drop(write_probe);
      assert_eq!(write_drops.load(Ordering::SeqCst), 0);
      assert_eq!(count(write(&mut writer, &[])), 0);
      assert_eq!(write_drops.load(Ordering::SeqCst), 1);
      assert_eq!(write_wakes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn exhausted_budget_keeps_empty_poll_waiter_until_explicit_cancel() {
      let scope = scope();
      let (mut reader, mut writer) = pipe(buffer(&scope, 1)).unwrap();
      assert_eq!(count(write(&mut writer, b"x")), 1);
      let drops = Arc::new(AtomicUsize::new(0));
      let wakes = Arc::new(AtomicUsize::new(0));
      let probe = Arc::new(DropWake {
        drops: drops.clone(),
        wakes: wakes.clone(),
      });
      let waker = Waker::from(probe.clone());
      {
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut writer).poll_write(&mut cx, b"y").is_pending());
      }
      drop(waker);
      drop(probe);
      assert_eq!(drops.load(Ordering::SeqCst), 0);

      let runtime = AsyncRuntime::new(AsyncConfig {
        workers: 1,
        max_outstanding: 4,
        max_scopes: 2,
      })
      .unwrap();
      let job = runtime
        .handle()
        .spawn(async move {
          let was_budget_blocked = std::future::poll_fn(|cx| {
            for _ in 0..64 {
              assert!(matches!(
                Pin::new(&mut reader).poll_read(cx, &mut []),
                Poll::Ready(Ok(0))
              ));
            }
            let empty_write = Pin::new(&mut writer).poll_write(cx, &[]);
            Poll::Ready(empty_write.is_pending())
          })
          .await;
          (was_budget_blocked, reader, writer)
        })
        .unwrap();
      let (was_budget_blocked, _reader, mut writer) = runtime.block_on(job).unwrap().unwrap();
      assert!(was_budget_blocked);
      assert_eq!(drops.load(Ordering::SeqCst), 0);
      writer.cancel_io_waits();
      assert_eq!(drops.load(Ordering::SeqCst), 1);
      assert_eq!(wakes.load(Ordering::SeqCst), 0);
      runtime.shutdown(AsyncShutdown::Drain).unwrap();
    }

    #[test]
    fn duplex_pending_write_waiter_is_released_when_reader_drops() {
      let scope = scope();
      let (a_to_b, b_to_a) = (buffer(&scope, 1), buffer(&scope, 1));
      let (mut a, b) = duplex(a_to_b, b_to_a).unwrap();
      assert_eq!(count(write(&mut a, b"x")), 1);
      let wake_count = Arc::new(AtomicUsize::new(0));
      let waker = Waker::from(Arc::new(CountWake(wake_count.clone())));
      let mut cx = Context::from_waker(&waker);
      assert!(Pin::new(&mut a).poll_write(&mut cx, b"y").is_pending());
      drop(b);
      assert!(wake_count.load(Ordering::SeqCst) > 0);
      assert_eq!(
        Pin::new(&mut a)
          .poll_write(&mut cx, b"y")
          .unwrap_ready()
          .unwrap_err()
          .kind(),
        io::ErrorKind::BrokenPipe
      );
    }

    struct ReentrantWake {
      ring: Weak<super::Ring>,
      lock_was_free: Arc<AtomicUsize>,
      panic_on_wake: bool,
    }

    impl Wake for ReentrantWake {
      fn wake(self: Arc<Self>) {
        self.check_and_maybe_panic();
      }
      fn wake_by_ref(self: &Arc<Self>) {
        self.check_and_maybe_panic();
      }
    }

    impl ReentrantWake {
      fn check_and_maybe_panic(&self) {
        let lock_was_free = self
          .ring
          .upgrade()
          .is_some_and(|ring| ring.state.try_lock().is_ok());
        if lock_was_free {
          self.lock_was_free.fetch_add(1, Ordering::SeqCst);
        }
        assert!(!self.panic_on_wake, "injected reentrant pipe wake panic");
      }
    }

    #[test]
    fn waking_and_dropping_waiters_happen_after_ring_unlock() {
      let scope = scope();
      let (mut reader, mut writer) = pipe(buffer(&scope, 1)).unwrap();
      let wake_count = Arc::new(AtomicUsize::new(0));
      let waker = Waker::from(Arc::new(ReentrantWake {
        ring: Arc::downgrade(&reader.ring),
        lock_was_free: wake_count.clone(),
        panic_on_wake: false,
      }));
      let mut cx = Context::from_waker(&waker);
      assert!(
        Pin::new(&mut reader)
          .poll_read(&mut cx, &mut [0])
          .is_pending()
      );
      assert_eq!(count(write(&mut writer, b"x")), 1);
      assert_eq!(wake_count.load(Ordering::SeqCst), 1);
      assert_eq!(count(read(&mut reader, &mut [0])), 1);

      let drop_probe = Arc::new(DropReentrant {
        ring: Arc::downgrade(&reader.ring),
        lock_was_free: Arc::new(AtomicUsize::new(0)),
      });
      let dropped_outside_lock = drop_probe.lock_was_free.clone();
      let first = Waker::from(drop_probe.clone());
      {
        let mut first_cx = Context::from_waker(&first);
        assert!(
          Pin::new(&mut reader)
            .poll_read(&mut first_cx, &mut [0])
            .is_pending()
        );
      }
      drop(first);
      drop(drop_probe);

      let second = Waker::from(Arc::new(CountWake(wake_count.clone())));
      let mut second_cx = Context::from_waker(&second);
      assert!(
        Pin::new(&mut reader)
          .poll_read(&mut second_cx, &mut [0])
          .is_pending()
      );
      // The previous read waiter was removed while its ring mutex was free.
      assert_eq!(dropped_outside_lock.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn panicking_wake_is_contained_after_state_commit() {
      let scope = scope();
      let (reader, mut writer) = pipe(buffer(&scope, 1)).unwrap();
      let panic_probe = Arc::new(AtomicUsize::new(0));
      let waker = Waker::from(Arc::new(ReentrantWake {
        ring: Arc::downgrade(&reader.ring),
        lock_was_free: panic_probe.clone(),
        panic_on_wake: true,
      }));
      let mut cx = Context::from_waker(&waker);
      let mut reader = reader;
      assert!(
        Pin::new(&mut reader)
          .poll_read(&mut cx, &mut [0])
          .is_pending()
      );
      assert_eq!(count(write(&mut writer, b"x")), 1);
      let mut output = [0];
      assert_eq!(count(read(&mut reader, &mut output)), 1);
      assert_eq!(&output, b"x");
    }

    struct PanicDropWake(Arc<AtomicUsize>);

    impl Wake for PanicDropWake {
      fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
      fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }

    impl Drop for PanicDropWake {
      fn drop(&mut self) {
        panic!("injected pipe waker-drop panic");
      }
    }

    #[test]
    fn panicking_waker_drop_is_contained_outside_ring_lock() {
      let scope = scope();
      let (mut reader, mut writer) = pipe(buffer(&scope, 1)).unwrap();
      let wake_count = Arc::new(AtomicUsize::new(0));
      let probe = Arc::new(PanicDropWake(wake_count));
      let first = Waker::from(probe.clone());
      {
        let mut cx = Context::from_waker(&first);
        assert!(
          Pin::new(&mut reader)
            .poll_read(&mut cx, &mut [0])
            .is_pending()
        );
      }
      drop(first);
      drop(probe);

      let second = Waker::from(Arc::new(CountWake(Arc::new(AtomicUsize::new(0)))));
      let mut cx = Context::from_waker(&second);
      assert!(
        Pin::new(&mut reader)
          .poll_read(&mut cx, &mut [0])
          .is_pending()
      );
      assert_eq!(count(write(&mut writer, b"x")), 1);
      let mut output = [0];
      assert_eq!(count(read(&mut reader, &mut output)), 1);
      assert_eq!(&output, b"x");
    }

    struct CountWake(Arc<AtomicUsize>);

    struct DropReentrant {
      ring: Weak<super::Ring>,
      lock_was_free: Arc<AtomicUsize>,
    }

    impl Wake for DropReentrant {
      fn wake(self: Arc<Self>) {
        self.lock_was_free.fetch_add(1, Ordering::SeqCst);
      }
      fn wake_by_ref(self: &Arc<Self>) {
        self.lock_was_free.fetch_add(1, Ordering::SeqCst);
      }
    }

    impl Drop for DropReentrant {
      fn drop(&mut self) {
        if self
          .ring
          .upgrade()
          .is_some_and(|ring| ring.state.try_lock().is_ok())
        {
          self.lock_was_free.fetch_add(1, Ordering::SeqCst);
        }
      }
    }

    impl Wake for CountWake {
      fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
      fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }

    trait UnwrapReady<T> {
      fn unwrap_ready(self) -> T;
    }

    impl<T> UnwrapReady<T> for Poll<T> {
      fn unwrap_ready(self) -> T {
        match self {
          Poll::Ready(value) => value,
          Poll::Pending => panic!("poll unexpectedly pending"),
        }
      }
    }
  }

  #[cfg(all(test, loom))]
  mod loom_models {
    use super::{ReadAttempt, Ring, WriteAttempt};
    use crate::runtime::managed::{ResourceLimits, ResourceScope};
    use loom::sync::Arc;
    use loom::thread;
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    fn ring(capacity: usize) -> Arc<Ring> {
      let scope = ResourceScope::new(ResourceLimits {
        managed_memory: capacity,
        disk_concurrent_ops: 0,
        network_concurrent_ops: 0,
      });
      Arc::new(Ring::new(scope.try_alloc_zeroed(capacity).unwrap()))
    }

    #[test]
    fn concurrent_ring_write_and_read_preserve_each_byte_once() {
      loom::model(|| {
        let ring = ring(2);
        let writer_ring = ring.clone();
        let writer = thread::spawn(move || {
          let mut state = writer_ring.lock();
          match state.write(b"xy", false) {
            WriteAttempt::Ready(Ok(2)) => true,
            WriteAttempt::Ready(Ok(_)) | WriteAttempt::Pending => false,
            WriteAttempt::Ready(Err(_)) => panic!("open ring rejected write"),
          }
        });

        let reader_ring = ring.clone();
        let reader = thread::spawn(move || {
          let mut bytes = [0; 2];
          let mut state = reader_ring.lock();
          let read = match state.read(&mut bytes) {
            ReadAttempt::Ready(count) => count,
            ReadAttempt::Pending => 0,
          };
          (read, bytes)
        });

        let wrote = writer.join().unwrap();
        let (read, bytes) = reader.join().unwrap();
        let mut state = ring.lock();
        state.assert_valid();
        assert!(wrote);
        if read == 2 {
          assert_eq!(&bytes, b"xy");
          assert_eq!(state.len, 0);
        } else {
          assert_eq!(read, 0);
          assert_eq!(state.len, 2);
          let mut rest = [0; 2];
          assert!(matches!(state.read(&mut rest), ReadAttempt::Ready(2)));
          assert_eq!(&rest, b"xy");
        }
      });
    }

    #[test]
    fn reader_close_racing_a_write_never_leaves_buffered_bytes() {
      loom::model(|| {
        let ring = ring(1);
        let writer_ring = ring.clone();
        let writer = thread::spawn(move || {
          let mut state = writer_ring.lock();
          state.write(b"x", false)
        });

        let close_ring = ring.clone();
        let closer = thread::spawn(move || close_ring.set_reader_closed());

        let outcome = writer.join().unwrap();
        closer.join().unwrap();
        let state = ring.lock();
        state.assert_valid();
        assert!(state.reader_closed);
        match outcome {
          WriteAttempt::Ready(Ok(1)) | WriteAttempt::Ready(Err(_)) => {}
          WriteAttempt::Ready(Ok(_)) | WriteAttempt::Pending => {
            panic!("unexpected ring write result")
          }
        }
        assert_eq!(state.len, 0);
      });
    }

    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
      fn wake(self: StdArc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
      fn wake_by_ref(self: &StdArc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }

    #[test]
    fn concurrent_poll_registration_and_write_cannot_lose_wakeup() {
      loom::model(|| {
        let ring = ring(1);
        let wakes = StdArc::new(WakeCount(AtomicUsize::new(0)));
        let reader_ring = ring.clone();
        let reader_wakes = wakes.clone();
        let reader = thread::spawn(move || {
          let waker = Waker::from(reader_wakes);
          let mut cx = Context::from_waker(&waker);
          let mut output = [0];
          (reader_ring.poll_read(&mut output, &mut cx), output)
        });

        let writer_ring = ring.clone();
        let writer = thread::spawn(move || {
          let mut cx = Context::from_waker(Waker::noop());
          writer_ring.poll_write(b"x", &mut cx, false)
        });

        let (read, output) = reader.join().unwrap();
        assert!(matches!(writer.join().unwrap(), Poll::Ready(Ok(1))));
        match read {
          Poll::Ready(Ok(1)) => assert_eq!(&output, b"x"),
          Poll::Pending => assert!(wakes.0.load(Ordering::SeqCst) > 0),
          Poll::Ready(Ok(_)) | Poll::Ready(Err(_)) => panic!("unexpected read result"),
        }
        let mut state = ring.lock();
        state.assert_valid();
        if state.len == 1 {
          let mut output = [0];
          assert!(matches!(state.read(&mut output), ReadAttempt::Ready(1)));
          assert_eq!(&output, b"x");
        } else {
          assert_eq!(state.len, 0);
        }
      });
    }
  }
}
