//! Bounded asynchronous adapters over owned blocking [`Read`] and [`Write`]
//! streams.
//!
//! Each endpoint owns one nonempty, uniquely owned [`ManagedBuf`] for its
//! fixed staging storage and submits at most one operation at a time to an
//! existing blocking [`Handle`]. There is no private worker or per-endpoint
//! queue. The caller declares the [`Resources`] reserved by each submitted
//! operation; those declarations are runtime accounting, not measurements or
//! enforcement. The staging buffer is charged independently by its
//! [`ResourceScope`](crate::runtime::managed::ResourceScope).
//!
//! A dropped borrowing I/O future does not cancel an admitted blocking job or
//! discard its progress. The adapter keeps the job and its read-ahead or
//! accepted write suffix for a later poll. Dropping the endpoint detaches the
//! job; its stream and buffer remain owned until the blocking call and result
//! cleanup finish. A queued job cancelled by `ShutdownMode::CancelPending`
//! loses its captured stream and buffer before it starts, so that endpoint
//! becomes terminal. A started `Read` or `Write` call cannot be interrupted;
//! draining shutdown can wait indefinitely for a blocking stream.
//!
//! Admission and resource-capacity rejection is reported as `WouldBlock`.
//! The endpoint restores its stream and buffer, and a rejected write accepts
//! no bytes. Because the blocking handle has no asynchronous capacity
//! notification, the caller must retry after capacity becomes available.
//!
//! Each worker job calls the underlying `read` or `write` at most once, with a
//! small fixed retry bound for `Interrupted`. Partial writes advance the
//! retained suffix exactly by the returned count. An I/O error preserves the
//! remaining suffix, but standard `Write` errors cannot promise that an
//! external stream had no side effects; the adapter never replays byte ranges
//! the writer reported as written. Flush is a separate job after accepted
//! bytes are written. Shutdown
//! flushes and logically closes the writer, but does not close the underlying
//! stream. In particular, standard output and error handles remain open.
//!
//! The standard-stream helpers wrap `std::io`'s process-global handles. Their
//! internal locking and buffering are standard-library behavior and are not
//! separately charged. A pool whose workers all block on stdin cannot run
//! queued work until those reads return, so choose the pool size and task
//! topology with that blocking behavior in mind.
//!
//! Boxed stream metadata and runtime job metadata use ordinary Rust
//! allocations; only the caller's `ManagedBuf` storage is managed-memory
//! charged. This module does not implement `AsyncBufRead`, does not create an
//! executor, and does not close global standard descriptors.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use crate::runtime::asynchronous::poll_cooperative;
use crate::runtime::error::{JoinError, SubmitErrorKind};
use crate::runtime::io::{AsyncRead, AsyncWrite};
use crate::runtime::job::Job;
use crate::runtime::managed::ManagedBuf;
use crate::runtime::{Handle, Resources};

const INTERRUPTED_RETRIES: usize = 4;

/// Why a blocking stream adapter constructor rejected its inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockingIoInitErrorKind {
  /// Staging storage must be nonempty.
  EmptyBuffer,
  /// Staging storage must have no other `ManagedBuf` clones.
  SharedBuffer,
}

impl fmt::Display for BlockingIoInitErrorKind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::EmptyBuffer => "blocking I/O staging buffer is empty",
      Self::SharedBuffer => "blocking I/O staging buffer is shared",
    })
  }
}

/// A constructor error that returns the original stream and managed buffer.
pub struct BlockingIoInitError<S> {
  /// Why construction failed.
  pub kind: BlockingIoInitErrorKind,
  stream: S,
  buffer: ManagedBuf,
}

impl<S> BlockingIoInitError<S> {
  fn new(kind: BlockingIoInitErrorKind, stream: S, buffer: ManagedBuf) -> Self {
    Self {
      kind,
      stream,
      buffer,
    }
  }

  /// Returns the unchanged inputs rejected by the constructor.
  #[must_use]
  pub fn into_parts(self) -> (S, ManagedBuf) {
    (self.stream, self.buffer)
  }
}

impl<S> fmt::Debug for BlockingIoInitError<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BlockingIoInitError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl<S> fmt::Display for BlockingIoInitError<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt::Display::fmt(&self.kind, f)
  }
}

impl<S: 'static> std::error::Error for BlockingIoInitError<S> {}

/// The typed cause carried by a blocking I/O adapter's `io::Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockingIoErrorKind {
  /// The existing blocking runtime refused admission.
  Submission(SubmitErrorKind),
  /// A queued operation was cancelled before it started.
  Cancelled,
  /// The operation closure panicked and lost its owned stream.
  Panicked,
  /// Joining would deadlock from this blocking worker.
  WouldDeadlock,
}

/// A typed blocking I/O service or admission failure stored as an `io::Error`
/// source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockingIoError {
  kind: BlockingIoErrorKind,
}

impl BlockingIoError {
  /// The underlying service failure.
  #[must_use]
  pub const fn kind(&self) -> BlockingIoErrorKind {
    self.kind
  }
}

impl fmt::Display for BlockingIoError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self.kind {
      BlockingIoErrorKind::Submission(kind) => {
        write!(f, "blocking I/O submission refused: {kind}")
      }
      BlockingIoErrorKind::Cancelled => {
        f.write_str("blocking I/O job was cancelled before it started")
      }
      BlockingIoErrorKind::Panicked => f.write_str("blocking I/O job panicked"),
      BlockingIoErrorKind::WouldDeadlock => {
        f.write_str("blocking I/O job could not be joined from this worker")
      }
    }
  }
}

impl std::error::Error for BlockingIoError {}

fn validate_buffer<S>(
  stream: S,
  mut buffer: ManagedBuf,
) -> Result<(S, ManagedBuf), BlockingIoInitError<S>> {
  if buffer.is_empty() {
    return Err(BlockingIoInitError::new(
      BlockingIoInitErrorKind::EmptyBuffer,
      stream,
      buffer,
    ));
  }
  if buffer.get_mut().is_none() {
    return Err(BlockingIoInitError::new(
      BlockingIoInitErrorKind::SharedBuffer,
      stream,
      buffer,
    ));
  }
  Ok((stream, buffer))
}

/// An owned blocking reader exposed through the runtime-neutral `AsyncRead`
/// trait.
pub struct BlockingReader<R> {
  handle: Handle,
  resources: Resources,
  reader: Option<Box<R>>,
  buffer: Option<ManagedBuf>,
  job: Option<Job<ReadOutput<R>>>,
  read_pos: usize,
  read_len: usize,
  terminal: bool,
}

struct ReadInput<R> {
  reader: Box<R>,
  buffer: ManagedBuf,
}

struct ReadOutput<R> {
  reader: Box<R>,
  buffer: ManagedBuf,
  result: io::Result<usize>,
}

/// Creates an owned reader. `resources` is the blocking runtime's declared
/// request for each actual blocking read. Buffer storage remains managed
/// charged independently.
pub fn reader<R: Read + Send + 'static>(
  handle: Handle,
  resources: Resources,
  stream: R,
  buffer: ManagedBuf,
) -> Result<BlockingReader<R>, BlockingIoInitError<R>> {
  let (stream, buffer) = validate_buffer(stream, buffer)?;
  Ok(BlockingReader {
    handle,
    resources,
    reader: Some(Box::new(stream)),
    buffer: Some(buffer),
    job: None,
    read_pos: 0,
    read_len: 0,
    terminal: false,
  })
}

impl<R: Read + Send + 'static> BlockingReader<R> {
  fn submit_read(&mut self) -> Result<(), io::Error> {
    let Some(reader) = self.reader.take() else {
      self.terminal = true;
      return Err(terminal_error());
    };
    let Some(buffer) = self.buffer.take() else {
      self.reader = Some(reader);
      self.terminal = true;
      return Err(terminal_error());
    };
    let input = ReadInput { reader, buffer };
    let request = Arc::new(Mutex::new(Some(input)));
    let worker_request = Arc::clone(&request);
    match self.handle.try_spawn(self.resources, move |_| {
      let mut input = take_input(&worker_request);
      let operation = panic::catch_unwind(AssertUnwindSafe(|| {
        let result = match input.buffer.get_mut() {
          Some(bytes) => read_retry(&mut *input.reader, bytes),
          None => Err(io::Error::new(
            ErrorKind::InvalidData,
            "blocking reader staging buffer is shared",
          )),
        };
        result.and_then(|count| {
          if count <= input.buffer.len() {
            Ok(count)
          } else {
            Err(io::Error::new(
              ErrorKind::InvalidData,
              "blocking reader returned a count larger than its staging buffer",
            ))
          }
        })
      }));
      let result = match operation {
        Ok(result) => result,
        Err(payload) => {
          discard_after_primary_panic(input.reader);
          discard_after_primary_panic(input.buffer);
          panic::resume_unwind(payload);
        }
      };
      ReadOutput {
        reader: input.reader,
        buffer: input.buffer,
        result,
      }
    }) {
      Ok(job) => {
        self.job = Some(job);
        drop(request);
        Ok(())
      }
      Err(rejected) => {
        let kind = rejected.kind;
        drop(rejected.job);
        let input = take_input(&request);
        self.reader = Some(input.reader);
        self.buffer = Some(input.buffer);
        Err(submission_error(kind))
      }
    }
  }

  fn poll_read_job(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
    let Some(job) = self.job.as_mut() else {
      return Poll::Ready(Err(io::Error::other("blocking read job is missing")));
    };
    let result = match Pin::new(job).poll(cx) {
      Poll::Pending => return Poll::Pending,
      Poll::Ready(result) => result,
    };
    drop(self.job.take());
    match result {
      Ok(output) => {
        self.reader = Some(output.reader);
        self.buffer = Some(output.buffer);
        match output.result {
          Ok(count) => {
            self.read_pos = 0;
            self.read_len = count;
            Poll::Ready(Ok(count))
          }
          Err(error) => Poll::Ready(Err(error)),
        }
      }
      Err(error) => {
        self.terminal = true;
        Poll::Ready(Err(job_error(error)))
      }
    }
  }
}

impl<R: Read + Send + 'static> AsyncRead for BlockingReader<R> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    output: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    poll_cooperative(cx, |cx| {
      if output.is_empty() {
        return Poll::Ready(Ok(0));
      }
      if this.terminal {
        return Poll::Ready(Err(io::Error::new(
          ErrorKind::BrokenPipe,
          "blocking reader lost its stream after job cancellation or panic",
        )));
      }
      if this.read_pos < this.read_len {
        let Some(buffer) = this.buffer.as_ref() else {
          return Poll::Ready(Err(io::Error::other("blocking reader buffer is missing")));
        };
        let count = output.len().min(this.read_len - this.read_pos);
        let end = this.read_pos + count;
        output[..count].copy_from_slice(&buffer.as_slice()[this.read_pos..end]);
        this.read_pos = end;
        if this.read_pos == this.read_len {
          this.read_pos = 0;
          this.read_len = 0;
        }
        return Poll::Ready(Ok(count));
      }

      if this.job.is_none()
        && let Err(error) = this.submit_read()
      {
        return Poll::Ready(Err(error));
      }
      match this.poll_read_job(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
        Poll::Ready(Ok(_)) => {
          let Some(buffer) = this.buffer.as_ref() else {
            return Poll::Ready(Err(io::Error::other("blocking reader buffer is missing")));
          };
          let count = output.len().min(this.read_len);
          output[..count].copy_from_slice(&buffer.as_slice()[..count]);
          this.read_pos = count;
          if this.read_pos == this.read_len {
            this.read_pos = 0;
            this.read_len = 0;
          }
          Poll::Ready(Ok(count))
        }
      }
    })
  }
}

/// An owned blocking writer exposed through the runtime-neutral `AsyncWrite`
/// trait.
pub struct BlockingWriter<W> {
  handle: Handle,
  resources: Resources,
  writer: Option<Box<W>>,
  buffer: Option<ManagedBuf>,
  job: Option<Job<WriteOutput<W>>>,
  write_pos: usize,
  write_len: usize,
  shutdown_requested: bool,
  shutdown_complete: bool,
  terminal: bool,
}

#[derive(Clone, Copy)]
enum WriteOperation {
  Write,
  Flush,
}

enum WriteResult {
  Wrote(io::Result<usize>),
  Flushed(io::Result<()>),
}

struct WriteInput<W> {
  writer: Box<W>,
  buffer: ManagedBuf,
  write_pos: usize,
  write_len: usize,
  operation: WriteOperation,
}

struct WriteOutput<W> {
  writer: Box<W>,
  buffer: ManagedBuf,
  write_pos: usize,
  write_len: usize,
  operation: WriteOperation,
  result: WriteResult,
}

/// Creates an owned writer. `resources` is the blocking runtime's declared
/// request for each write or flush operation. Buffer storage remains managed
/// charged independently.
pub fn writer<W: Write + Send + 'static>(
  handle: Handle,
  resources: Resources,
  stream: W,
  buffer: ManagedBuf,
) -> Result<BlockingWriter<W>, BlockingIoInitError<W>> {
  let (stream, buffer) = validate_buffer(stream, buffer)?;
  Ok(BlockingWriter {
    handle,
    resources,
    writer: Some(Box::new(stream)),
    buffer: Some(buffer),
    job: None,
    write_pos: 0,
    write_len: 0,
    shutdown_requested: false,
    shutdown_complete: false,
    terminal: false,
  })
}

impl<W: Write + Send + 'static> BlockingWriter<W> {
  fn submit(&mut self, operation: WriteOperation) -> Result<(), io::Error> {
    let Some(writer) = self.writer.take() else {
      self.terminal = true;
      return Err(terminal_error());
    };
    let Some(buffer) = self.buffer.take() else {
      self.writer = Some(writer);
      self.terminal = true;
      return Err(terminal_error());
    };
    let input = WriteInput {
      writer,
      buffer,
      write_pos: self.write_pos,
      write_len: self.write_len,
      operation,
    };
    let request = Arc::new(Mutex::new(Some(input)));
    let worker_request = Arc::clone(&request);
    match self.handle.try_spawn(self.resources, move |_| {
      let mut input = take_input(&worker_request);
      let operation = panic::catch_unwind(AssertUnwindSafe(|| match input.operation {
        WriteOperation::Write => {
          let end = input.write_pos.checked_add(input.write_len);
          match end.and_then(|end| input.buffer.as_slice().get(input.write_pos..end)) {
            Some(bytes) => WriteResult::Wrote(write_retry(&mut *input.writer, bytes)),
            None => WriteResult::Wrote(Err(io::Error::new(
              ErrorKind::InvalidData,
              "blocking writer staging range is invalid",
            ))),
          }
        }
        WriteOperation::Flush => WriteResult::Flushed(flush_retry(&mut *input.writer)),
      }));
      let result = match operation {
        Ok(result) => result,
        Err(payload) => {
          discard_after_primary_panic(input.writer);
          discard_after_primary_panic(input.buffer);
          panic::resume_unwind(payload);
        }
      };
      match result {
        WriteResult::Wrote(Ok(count)) if count > input.write_len => WriteOutput {
          writer: input.writer,
          buffer: input.buffer,
          write_pos: input.write_pos,
          write_len: input.write_len,
          operation: input.operation,
          result: WriteResult::Wrote(Err(io::Error::new(
            ErrorKind::InvalidData,
            "blocking writer returned a count larger than its input",
          ))),
        },
        WriteResult::Wrote(Ok(0)) if input.write_len > 0 => WriteOutput {
          writer: input.writer,
          buffer: input.buffer,
          write_pos: input.write_pos,
          write_len: input.write_len,
          operation: input.operation,
          result: WriteResult::Wrote(Err(io::Error::new(
            ErrorKind::WriteZero,
            "blocking writer accepted no bytes",
          ))),
        },
        WriteResult::Wrote(Ok(count)) => {
          input.write_pos += count;
          input.write_len -= count;
          if input.write_len == 0 {
            input.write_pos = 0;
          }
          WriteOutput {
            writer: input.writer,
            buffer: input.buffer,
            write_pos: input.write_pos,
            write_len: input.write_len,
            operation: input.operation,
            result: WriteResult::Wrote(Ok(count)),
          }
        }
        other => WriteOutput {
          writer: input.writer,
          buffer: input.buffer,
          write_pos: input.write_pos,
          write_len: input.write_len,
          operation: input.operation,
          result: other,
        },
      }
    }) {
      Ok(job) => {
        self.job = Some(job);
        drop(request);
        Ok(())
      }
      Err(rejected) => {
        let kind = rejected.kind;
        drop(rejected.job);
        let input = take_input(&request);
        self.restore_input(input);
        Err(submission_error(kind))
      }
    }
  }

  fn restore_input(&mut self, input: WriteInput<W>) {
    self.writer = Some(input.writer);
    self.buffer = Some(input.buffer);
    self.write_pos = input.write_pos;
    self.write_len = input.write_len;
  }

  fn poll_job(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<WriteOperation>> {
    let Some(job) = self.job.as_mut() else {
      return Poll::Ready(Err(io::Error::other("blocking write job is missing")));
    };
    let result = match Pin::new(job).poll(cx) {
      Poll::Pending => return Poll::Pending,
      Poll::Ready(result) => result,
    };
    drop(self.job.take());
    let output = match result {
      Ok(output) => output,
      Err(error) => {
        self.terminal = true;
        return Poll::Ready(Err(job_error(error)));
      }
    };
    self.writer = Some(output.writer);
    self.buffer = Some(output.buffer);
    self.write_pos = output.write_pos;
    self.write_len = output.write_len;
    match output.result {
      WriteResult::Wrote(Ok(_)) => Poll::Ready(Ok(output.operation)),
      WriteResult::Wrote(Err(error)) | WriteResult::Flushed(Err(error)) => Poll::Ready(Err(error)),
      WriteResult::Flushed(Ok(())) => {
        if self.shutdown_requested {
          self.shutdown_complete = true;
        }
        Poll::Ready(Ok(output.operation))
      }
    }
  }

  fn poll_flush_or_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    if self.terminal {
      return Poll::Ready(Err(terminal_error()));
    }
    if self.shutdown_complete {
      return Poll::Ready(Ok(()));
    }
    if self.job.is_some() {
      match self.poll_job(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        Poll::Ready(Ok(WriteOperation::Flush)) => return Poll::Ready(Ok(())),
        Poll::Ready(Ok(WriteOperation::Write)) => {}
      }
    }
    if self.write_len > 0 {
      if let Err(kind) = self.submit(WriteOperation::Write) {
        return Poll::Ready(Err(kind));
      }
      match self.poll_job(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        Poll::Ready(Ok(WriteOperation::Flush)) => return Poll::Ready(Ok(())),
        Poll::Ready(Ok(WriteOperation::Write)) => {
          if self.write_len > 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
          }
        }
      }
    }
    if let Err(kind) = self.submit(WriteOperation::Flush) {
      return Poll::Ready(Err(kind));
    }
    match self.poll_job(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(result) => {
        result.map_or_else(|error| Poll::Ready(Err(error)), |_| Poll::Ready(Ok(())))
      }
    }
  }
}

impl<W: Write + Send + 'static> AsyncWrite for BlockingWriter<W> {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    input: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    poll_cooperative(cx, |cx| {
      if input.is_empty() {
        return Poll::Ready(Ok(0));
      }
      if this.terminal || this.shutdown_requested {
        return Poll::Ready(Err(terminal_error()));
      }
      if this.job.is_some() {
        match this.poll_job(cx) {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
          Poll::Ready(Ok(WriteOperation::Flush)) => {}
          Poll::Ready(Ok(WriteOperation::Write)) => {
            if this.write_len > 0 {
              if let Err(error) = this.submit(WriteOperation::Write) {
                return Poll::Ready(Err(error));
              }
              match this.poll_job(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) if this.write_len > 0 => {
                  cx.waker().wake_by_ref();
                  return Poll::Pending;
                }
                Poll::Ready(Ok(_)) => {
                  cx.waker().wake_by_ref();
                  return Poll::Pending;
                }
              }
            }
          }
        }
      } else if this.write_len > 0 {
        if let Err(error) = this.submit(WriteOperation::Write) {
          return Poll::Ready(Err(error));
        }
        match this.poll_job(cx) {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
          Poll::Ready(Ok(_)) if this.write_len > 0 => {
            cx.waker().wake_by_ref();
            return Poll::Pending;
          }
          Poll::Ready(Ok(_)) => {
            cx.waker().wake_by_ref();
            return Poll::Pending;
          }
        }
      }

      let Some(buffer) = this.buffer.as_mut() else {
        return Poll::Ready(Err(terminal_error()));
      };
      let capacity = buffer.len();
      let count = input.len().min(capacity);
      let Some(staging) = buffer.get_mut() else {
        return Poll::Ready(Err(io::Error::other("blocking writer buffer is shared")));
      };
      staging[..count].copy_from_slice(&input[..count]);
      this.write_pos = 0;
      this.write_len = count;
      if let Err(error) = this.submit(WriteOperation::Write) {
        this.write_pos = 0;
        this.write_len = 0;
        return Poll::Ready(Err(error));
      }
      Poll::Ready(Ok(count))
    })
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    poll_cooperative(cx, |cx| this.poll_flush_or_shutdown(cx))
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    poll_cooperative(cx, |cx| {
      this.shutdown_requested = true;
      this.poll_flush_or_shutdown(cx)
    })
  }
}

/// Reader adapter over `std::io::stdin()`.
pub type StdinReader = BlockingReader<std::io::Stdin>;

/// Writer adapter over `std::io::stdout()`.
pub type StdoutWriter = BlockingWriter<std::io::Stdout>;

/// Writer adapter over `std::io::stderr()`.
pub type StderrWriter = BlockingWriter<std::io::Stderr>;

/// Creates a managed-buffered adapter over the process-global stdin handle.
pub fn stdin_reader(
  handle: Handle,
  resources: Resources,
  buffer: ManagedBuf,
) -> Result<StdinReader, BlockingIoInitError<std::io::Stdin>> {
  reader(handle, resources, std::io::stdin(), buffer)
}

/// Creates a managed-buffered adapter over the process-global stdout handle.
pub fn stdout_writer(
  handle: Handle,
  resources: Resources,
  buffer: ManagedBuf,
) -> Result<StdoutWriter, BlockingIoInitError<std::io::Stdout>> {
  writer(handle, resources, std::io::stdout(), buffer)
}

/// Creates a managed-buffered adapter over the process-global stderr handle.
pub fn stderr_writer(
  handle: Handle,
  resources: Resources,
  buffer: ManagedBuf,
) -> Result<StderrWriter, BlockingIoInitError<std::io::Stderr>> {
  writer(handle, resources, std::io::stderr(), buffer)
}

fn read_retry<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
  let mut retries = 0;
  loop {
    match reader.read(buffer) {
      Err(error) if error.kind() == ErrorKind::Interrupted && retries < INTERRUPTED_RETRIES => {
        retries += 1;
      }
      result => return result,
    }
  }
}

fn write_retry<W: Write>(writer: &mut W, buffer: &[u8]) -> io::Result<usize> {
  let mut retries = 0;
  loop {
    match writer.write(buffer) {
      Err(error) if error.kind() == ErrorKind::Interrupted && retries < INTERRUPTED_RETRIES => {
        retries += 1;
      }
      result => return result,
    }
  }
}

fn flush_retry<W: Write>(writer: &mut W) -> io::Result<()> {
  let mut retries = 0;
  loop {
    match writer.flush() {
      Err(error) if error.kind() == ErrorKind::Interrupted && retries < INTERRUPTED_RETRIES => {
        retries += 1;
      }
      result => return result,
    }
  }
}

fn take_input<T>(input: &Mutex<Option<T>>) -> T {
  match lock(input).take() {
    Some(input) => input,
    None => panic!("blocking I/O request was consumed before its worker started"),
  }
}

/// Drops retained operation inputs without allowing a user destructor panic
/// to replace the primary stream-operation panic.
fn discard_after_primary_panic<T>(value: T) {
  crate::runtime::task::drop_contained(value);
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn submission_error(kind: SubmitErrorKind) -> io::Error {
  io::Error::new(
    ErrorKind::WouldBlock,
    BlockingIoError {
      kind: BlockingIoErrorKind::Submission(kind),
    },
  )
}

fn job_error(error: JoinError) -> io::Error {
  let kind = match error {
    JoinError::Cancelled => BlockingIoErrorKind::Cancelled,
    JoinError::Panicked(payload) => {
      crate::runtime::task::drop_contained(payload);
      BlockingIoErrorKind::Panicked
    }
    JoinError::WouldDeadlock => BlockingIoErrorKind::WouldDeadlock,
  };
  io::Error::new(ErrorKind::BrokenPipe, BlockingIoError { kind })
}

fn terminal_error() -> io::Error {
  io::Error::new(
    ErrorKind::BrokenPipe,
    "blocking I/O endpoint is terminal after losing its stream",
  )
}

#[cfg(all(test, not(loom)))]
#[path = "blocking_io_tests.rs"]
mod tests;
