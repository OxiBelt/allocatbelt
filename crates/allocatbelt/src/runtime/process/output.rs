//! Bounded, owned collection of a managed child's stdout and stderr.
//!
//! [`OutputFuture`] concurrently drains both registered pipes into caller
//! supplied [`ManagedBuf`] storage and waits for the process reaper to publish
//! its cached status. It never grows either buffer. Once a buffer is full, a
//! fixed one-byte probe distinguishes EOF at the exact limit from actual
//! overflow. The probe byte is preserved in the returned parts.
//!
//! [`OutputLimitPolicy::KillAndWait`] requests child termination at the first
//! overflow and continues draining into fixed stack scratch storage until
//! both streams reach EOF and the reaper publishes completion. It can wait
//! indefinitely if a descendant retains an inherited pipe or the process
//! cannot be terminated. [`OutputLimitPolicy::ReturnPartial`] returns as soon
//! as it observes an overflow byte, preserving the child, both endpoints,
//! buffers, and that byte so the caller can continue or clean up explicitly.
//!
//! Dropping a pending future cancels only its completion waiter and drops its
//! owned child handle. The child's `kill_on_drop` setting still controls
//! whether the reaper receives a kill request; the reaper retains the process
//! admission slot until it actually observes termination. Buffer allocations
//! are supplied by the caller and remain charged while returned output owns
//! them. The one-byte probes and fixed drain scratch are ordinary stack
//! storage outside the managed-memory ledger.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::process::ExitStatus;
use std::task::{Context, Poll};

use crate::runtime::io::AsyncRead;
use crate::runtime::managed::ManagedBuf;

use super::ProcessChild;
use super::completion::{Registration, WaitError};
use super::drop_contained;
use super::pipe::{AsyncChildStderr, AsyncChildStdout};

const IO_BUDGET: usize = 64;
const DRAIN_SCRATCH: usize = 1024;

enum ReadStep {
  Bytes(usize),
  Discarded(usize),
  Overflow(u8),
  Eof,
}

/// Which action to take when either output buffer cannot hold another byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputLimitPolicy {
  /// Request termination and keep draining excess bytes into fixed stack
  /// storage until both pipes reach EOF and the child is reaped.
  KillAndWait,
  /// Return ownership as soon as an overflow byte is observed.
  ReturnPartial,
}

/// Identifies a child output stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputStream {
  /// The child's standard output.
  Stdout,
  /// The child's standard error.
  Stderr,
}

/// Inputs consumed by output collection, returned unchanged on construction
/// rejection.
pub struct OutputInputs {
  /// Managed child handle.
  pub child: ProcessChild,
  /// Registered stdout pipe.
  pub stdout: AsyncChildStdout,
  /// Registered stderr pipe.
  pub stderr: AsyncChildStderr,
  /// Fixed output storage for stdout.
  pub stdout_buffer: ManagedBuf,
  /// Fixed output storage for stderr.
  pub stderr_buffer: ManagedBuf,
}

/// Why output collection could not start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputStartErrorKind {
  /// At least one buffer has a shared backing and therefore cannot be filled
  /// without mutating another owner.
  SharedBuffer,
}

/// A rejected output-collection request retaining every original input.
pub struct OutputStartError {
  kind: OutputStartErrorKind,
  inputs: OutputInputs,
}

impl OutputStartError {
  /// Returns the rejection reason.
  #[must_use]
  pub const fn kind(&self) -> OutputStartErrorKind {
    self.kind
  }

  /// Returns every input without changing child stdin or pipe state.
  #[must_use]
  pub fn into_inputs(self) -> OutputInputs {
    self.inputs
  }
}

impl fmt::Debug for OutputStartError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("OutputStartError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl fmt::Display for OutputStartError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("child output buffers must be uniquely owned")
  }
}

impl std::error::Error for OutputStartError {}

/// The child and all caller-owned output storage and endpoints.
///
/// The counts describe initialized output bytes in each fixed-capacity
/// buffer. `overflow_byte` preserves the first byte observed beyond either
/// buffer's capacity under either limit policy.
pub struct OutputParts {
  /// Managed child handle. Dropping it follows its `kill_on_drop` setting.
  pub child: ProcessChild,
  /// Registered stdout endpoint, possibly already at EOF.
  pub stdout: AsyncChildStdout,
  /// Registered stderr endpoint, possibly already at EOF.
  pub stderr: AsyncChildStderr,
  /// Fixed stdout storage, retaining its managed-memory charge.
  pub stdout_buffer: ManagedBuf,
  /// Fixed stderr storage, retaining its managed-memory charge.
  pub stderr_buffer: ManagedBuf,
  /// Number of stdout bytes in `stdout_buffer`.
  pub stdout_len: usize,
  /// Number of stderr bytes in `stderr_buffer`.
  pub stderr_len: usize,
  /// Whether stdout contained discarded bytes after its retained prefix.
  pub stdout_truncated: bool,
  /// Whether stderr contained discarded bytes after its retained prefix.
  pub stderr_truncated: bool,
  /// Whether stdout has reached EOF.
  pub stdout_eof: bool,
  /// Whether stderr has reached EOF.
  pub stderr_eof: bool,
  /// The first byte read past a full buffer, preserved under either limit
  /// policy.
  pub overflow_byte: Option<(OutputStream, u8)>,
}

/// Fully drained child output and the process's cached exit status.
pub struct CollectedOutput {
  /// Child, pipe endpoints, and managed buffers returned to the caller.
  pub parts: OutputParts,
  /// Cached status published by the independent reaper.
  pub status: ExitStatus,
}

impl fmt::Debug for CollectedOutput {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("CollectedOutput")
      .field("status", &self.status)
      .field("stdout_len", &self.parts.stdout_len)
      .field("stderr_len", &self.parts.stderr_len)
      .field("stdout_truncated", &self.parts.stdout_truncated)
      .field("stderr_truncated", &self.parts.stderr_truncated)
      .finish_non_exhaustive()
  }
}

/// Why a collection operation returned before normal EOF and exit completion.
#[derive(Debug)]
pub enum OutputFailureKind {
  /// A byte exceeded one buffer under `ReturnPartial`; it is preserved in
  /// `OutputParts::overflow_byte`.
  LimitReached(OutputStream),
  /// A pipe read failed; all current state remains available in `parts`.
  Io(OutputStream, io::Error),
  /// The process wait ledger returned a terminal error.
  Wait(WaitError),
  /// The kill request failed after an overflow under `KillAndWait`.
  Kill(io::Error),
  /// The output future was polled after it returned a terminal result. In
  /// this case `OutputFailure::parts` is `None` because ownership was already
  /// transferred by the first result.
  AlreadyCompleted,
}

impl fmt::Display for OutputFailureKind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::LimitReached(stream) => write!(f, "child {stream:?} exceeded its output limit"),
      Self::Io(stream, error) => write!(f, "child {stream:?} read failed: {error}"),
      Self::Wait(error) => write!(f, "child wait failed: {error}"),
      Self::Kill(error) => write!(f, "child termination request failed: {error}"),
      Self::AlreadyCompleted => f.write_str("child output future was already completed"),
    }
  }
}

/// An output failure together with any ownership that has not already been
/// transferred to the caller.
pub struct OutputFailure {
  /// Failure reason.
  pub kind: OutputFailureKind,
  /// Recoverable child, endpoints, and buffers; absent only on repoll after
  /// the first terminal result.
  pub parts: Option<OutputParts>,
}

impl fmt::Debug for OutputFailure {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("OutputFailure")
      .field("kind", &self.kind)
      .field("has_parts", &self.parts.is_some())
      .finish()
  }
}

impl fmt::Display for OutputFailure {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.kind.fmt(f)
  }
}

impl std::error::Error for OutputFailure {}

/// A bounded, cancellation-safe owner of one child's output collection.
pub struct OutputFuture {
  parts: Option<OutputParts>,
  policy: OutputLimitPolicy,
  waiter: Option<u64>,
  status: Option<ExitStatus>,
  stdout_eof: bool,
  stderr_eof: bool,
  completed: bool,
  next_stream: OutputStream,
}

impl fmt::Debug for OutputFuture {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("OutputFuture")
      .field("policy", &self.policy)
      .field("stdout_eof", &self.stdout_eof)
      .field("stderr_eof", &self.stderr_eof)
      .field("completed", &self.completed)
      .finish_non_exhaustive()
  }
}

impl OutputFuture {
  /// Starts collecting the two already-registered child pipes.
  ///
  /// Both managed buffers must be uniquely owned. Validation happens before
  /// stdin is closed or any pipe is polled. A zero-length buffer is valid and
  /// uses the same one-byte EOF/overflow probe as a full nonempty buffer.
  pub fn new(
    mut inputs: OutputInputs,
    policy: OutputLimitPolicy,
  ) -> Result<Self, OutputStartError> {
    if inputs.stdout_buffer.get_mut().is_none() || inputs.stderr_buffer.get_mut().is_none() {
      return Err(OutputStartError {
        kind: OutputStartErrorKind::SharedBuffer,
        inputs,
      });
    }

    // Match ProcessChild::wait: the collector owns completion and closes any
    // still-owned stdin before it can wait on the child.
    drop_contained(inputs.child.take_stdin());

    Ok(Self {
      parts: Some(OutputParts {
        child: inputs.child,
        stdout: inputs.stdout,
        stderr: inputs.stderr,
        stdout_buffer: inputs.stdout_buffer,
        stderr_buffer: inputs.stderr_buffer,
        stdout_len: 0,
        stderr_len: 0,
        stdout_truncated: false,
        stderr_truncated: false,
        stdout_eof: false,
        stderr_eof: false,
        overflow_byte: None,
      }),
      policy,
      waiter: None,
      status: None,
      stdout_eof: false,
      stderr_eof: false,
      completed: false,
      next_stream: OutputStream::Stdout,
    })
  }

  fn fail(&mut self, kind: OutputFailureKind) -> Poll<Result<CollectedOutput, OutputFailure>> {
    self.completed = true;
    if let Some(parts) = self.parts.as_ref() {
      parts.child.completion.cancel_waiter(&mut self.waiter);
    }
    Poll::Ready(Err(OutputFailure {
      kind,
      parts: self.parts.take(),
    }))
  }

  fn finish(&mut self) -> Poll<Result<CollectedOutput, OutputFailure>> {
    self.completed = true;
    let _ = self
      .parts
      .as_ref()
      .map(|parts| parts.child.completion.cancel_waiter(&mut self.waiter));
    match (self.parts.take(), self.status.take()) {
      (Some(parts), Some(status)) => Poll::Ready(Ok(CollectedOutput { parts, status })),
      (Some(parts), None) => Poll::Ready(Err(OutputFailure {
        kind: OutputFailureKind::Wait(WaitError::AlreadyCompleted),
        parts: Some(parts),
      })),
      (None, _) => Poll::Ready(Err(OutputFailure {
        kind: OutputFailureKind::AlreadyCompleted,
        parts: None,
      })),
    }
  }

  fn poll_status(&mut self, cx: &mut Context<'_>) -> Result<(), WaitError> {
    let Some(parts) = self.parts.as_ref() else {
      return Err(WaitError::AlreadyCompleted);
    };
    match parts
      .child
      .completion
      .poll_register(&mut self.waiter, cx.waker())?
    {
      Registration::Ready(Ok(status)) => {
        parts.child.completion.cancel_waiter(&mut self.waiter);
        self.status = Some(status);
      }
      Registration::Ready(Err(error)) => {
        parts.child.completion.cancel_waiter(&mut self.waiter);
        return Err(error);
      }
      Registration::Pending => {}
    }
    Ok(())
  }

  fn poll_one_stream(
    &mut self,
    stream: OutputStream,
    cx: &mut Context<'_>,
  ) -> Poll<io::Result<ReadStep>> {
    let Some(parts) = self.parts.as_mut() else {
      return Poll::Ready(Err(io::Error::other("output future has no parts")));
    };
    match stream {
      OutputStream::Stdout => poll_endpoint(
        &mut parts.stdout,
        &mut parts.stdout_buffer,
        parts.stdout_len,
        parts.stdout_truncated,
        cx,
      ),
      OutputStream::Stderr => poll_endpoint(
        &mut parts.stderr,
        &mut parts.stderr_buffer,
        parts.stderr_len,
        parts.stderr_truncated,
        cx,
      ),
    }
  }
}

fn poll_endpoint<R: AsyncRead + Unpin>(
  reader: &mut R,
  buffer: &mut ManagedBuf,
  length: usize,
  truncated: bool,
  cx: &mut Context<'_>,
) -> Poll<io::Result<ReadStep>> {
  if truncated {
    let mut scratch = [0u8; DRAIN_SCRATCH];
    return Pin::new(reader).poll_read(cx, &mut scratch).map(|result| {
      result.map(|count| {
        if count == 0 {
          ReadStep::Eof
        } else {
          ReadStep::Discarded(count)
        }
      })
    });
  }

  let Some(storage) = buffer.get_mut() else {
    return Poll::Ready(Err(io::Error::other("output buffer became shared")));
  };
  if length < storage.len() {
    let destination = &mut storage[length..];
    Pin::new(reader).poll_read(cx, destination).map(|result| {
      result.map(|count| {
        if count == 0 {
          ReadStep::Eof
        } else {
          ReadStep::Bytes(count)
        }
      })
    })
  } else {
    let mut probe = [0u8; 1];
    Pin::new(reader).poll_read(cx, &mut probe).map(|result| {
      result.map(|count| {
        if count == 0 {
          ReadStep::Eof
        } else {
          ReadStep::Overflow(probe[0])
        }
      })
    })
  }
}

impl Future for OutputFuture {
  type Output = Result<CollectedOutput, OutputFailure>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.completed {
      return Poll::Ready(Err(OutputFailure {
        kind: OutputFailureKind::AlreadyCompleted,
        parts: None,
      }));
    }

    if let Err(error) = this.poll_status(cx) {
      return this.fail(OutputFailureKind::Wait(error));
    }

    let mut pending_stdout = false;
    let mut pending_stderr = false;
    let mut quiescent = false;
    for _ in 0..IO_BUDGET {
      let stream = this.next_stream;
      this.next_stream = match stream {
        OutputStream::Stdout => OutputStream::Stderr,
        OutputStream::Stderr => OutputStream::Stdout,
      };
      if (stream == OutputStream::Stdout && (this.stdout_eof || pending_stdout))
        || (stream == OutputStream::Stderr && (this.stderr_eof || pending_stderr))
      {
        if (this.stdout_eof || pending_stdout) && (this.stderr_eof || pending_stderr) {
          quiescent = true;
          break;
        }
        continue;
      }

      match this.poll_one_stream(stream, cx) {
        Poll::Pending => match stream {
          OutputStream::Stdout => pending_stdout = true,
          OutputStream::Stderr => pending_stderr = true,
        },
        Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
          // Count each interruption against the same finite poll budget.
        }
        Poll::Ready(Err(error)) => return this.fail(OutputFailureKind::Io(stream, error)),
        Poll::Ready(Ok(ReadStep::Eof)) => {
          if let Some(parts) = this.parts.as_mut() {
            match stream {
              OutputStream::Stdout => parts.stdout_eof = true,
              OutputStream::Stderr => parts.stderr_eof = true,
            }
          }
          match stream {
            OutputStream::Stdout => this.stdout_eof = true,
            OutputStream::Stderr => this.stderr_eof = true,
          }
        }
        Poll::Ready(Ok(ReadStep::Bytes(count))) => {
          let Some(parts) = this.parts.as_mut() else {
            return this.fail(OutputFailureKind::AlreadyCompleted);
          };
          let (length, capacity) = match stream {
            OutputStream::Stdout => (&mut parts.stdout_len, parts.stdout_buffer.len()),
            OutputStream::Stderr => (&mut parts.stderr_len, parts.stderr_buffer.len()),
          };
          if *length < capacity {
            *length = length.saturating_add(count).min(capacity);
          }
        }
        Poll::Ready(Ok(ReadStep::Discarded(_count))) => {}
        Poll::Ready(Ok(ReadStep::Overflow(byte))) => {
          if let Some(parts) = this.parts.as_mut() {
            parts.overflow_byte.get_or_insert((stream, byte));
            match stream {
              OutputStream::Stdout => parts.stdout_truncated = true,
              OutputStream::Stderr => parts.stderr_truncated = true,
            }
          }
          match this.policy {
            OutputLimitPolicy::ReturnPartial => {
              return this.fail(OutputFailureKind::LimitReached(stream));
            }
            OutputLimitPolicy::KillAndWait => {
              let Some(parts) = this.parts.as_mut() else {
                return this.fail(OutputFailureKind::AlreadyCompleted);
              };
              if let Err(error) = parts.child.start_kill() {
                return this.fail(OutputFailureKind::Kill(error));
              }
            }
          }
        }
      }
    }

    if this.stdout_eof && this.stderr_eof && this.status.is_some() {
      return this.finish();
    }
    if quiescent {
      return Poll::Pending;
    }
    cx.waker().wake_by_ref();
    Poll::Pending
  }
}

impl Drop for OutputFuture {
  fn drop(&mut self) {
    if let Some(parts) = self.parts.as_ref() {
      parts.child.completion.cancel_waiter(&mut self.waiter);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::managed::{ResourceLimits, ResourceScope};
  use crate::runtime::process::ProcessDriver;
  use crate::runtime::reactor::{Reactor, ReactorConfig};
  use std::future::Future;
  use std::process::{Command, Stdio};
  use std::sync::Arc;
  use std::task::{Wake, Waker};
  use std::thread;
  use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
      if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
        return output;
      }
      thread::park_timeout(Duration::from_secs(1));
    }
  }

  fn setup(
    mut command: Command,
    stdout_capacity: usize,
    stderr_capacity: usize,
    policy: OutputLimitPolicy,
  ) -> (ProcessDriver, Reactor, ResourceScope, OutputFuture) {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let driver = ProcessDriver::new(1).unwrap();
    let mut child = driver.spawn(command).unwrap();
    let stdout = child.take_stdout().unwrap();
    let stderr = child.take_stderr().unwrap();
    let reactor = Reactor::new(ReactorConfig {
      max_registrations: 2,
      max_waiters: 2,
    })
    .unwrap();
    let handle = reactor.handle();
    let stdout = AsyncChildStdout::from_std(stdout, &handle).unwrap();
    let stderr = AsyncChildStderr::from_std(stderr, &handle).unwrap();
    let scope = ResourceScope::new(ResourceLimits {
      managed_memory: stdout_capacity + stderr_capacity,
      ..ResourceLimits::default()
    });
    let stdout_buffer = scope.try_alloc_zeroed(stdout_capacity).unwrap();
    let stderr_buffer = scope.try_alloc_zeroed(stderr_capacity).unwrap();
    let future = OutputFuture::new(
      OutputInputs {
        child,
        stdout,
        stderr,
        stdout_buffer,
        stderr_buffer,
      },
      policy,
    )
    .unwrap();
    (driver, reactor, scope, future)
  }

  fn shell(script: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", script]);
    command
  }

  #[test]
  fn drains_both_streams_beyond_pipe_capacity_and_retains_buffer_charges() {
    let command = shell("printf '%065536d' 0; printf '%065536d' 0 >&2");
    let (mut driver, _reactor, scope, future) =
      setup(command, 65_536, 65_536, OutputLimitPolicy::KillAndWait);
    let output = block_on(future).unwrap();
    assert!(output.status.success());
    assert_eq!(output.parts.stdout_len, 65_536);
    assert_eq!(output.parts.stderr_len, 65_536);
    assert!(!output.parts.stdout_truncated);
    assert!(!output.parts.stderr_truncated);
    assert!(
      output
        .parts
        .stdout_buffer
        .as_slice()
        .iter()
        .all(|byte| *byte == b'0')
    );
    assert!(
      output
        .parts
        .stderr_buffer
        .as_slice()
        .iter()
        .all(|byte| *byte == b'0')
    );
    assert_eq!(scope.snapshot().managed_memory, 131_072);

    let OutputParts {
      child,
      stdout,
      stderr,
      stdout_buffer,
      stderr_buffer,
      ..
    } = output.parts;
    drop((child, stdout, stderr));
    assert_eq!(scope.snapshot().managed_memory, 131_072);
    drop((stdout_buffer, stderr_buffer));
    assert_eq!(scope.snapshot().managed_memory, 0);
    driver
      .shutdown(super::super::ProcessShutdownMode::Wait)
      .unwrap();
  }

  #[test]
  fn both_stream_overflows_preserve_the_first_probe() {
    let (mut driver, _reactor, _scope, mut future) = setup(
      shell("printf a; printf b >&2"),
      0,
      0,
      OutputLimitPolicy::KillAndWait,
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while future
      .parts
      .as_mut()
      .unwrap()
      .child
      .try_wait()
      .unwrap()
      .is_none()
    {
      assert!(std::time::Instant::now() < deadline);
      thread::sleep(Duration::from_millis(5));
    }
    let output = block_on(future).unwrap();
    assert!(output.parts.stdout_truncated);
    assert!(output.parts.stderr_truncated);
    assert_eq!(
      output.parts.overflow_byte,
      Some((OutputStream::Stdout, b'a'))
    );
    driver
      .shutdown(super::super::ProcessShutdownMode::Wait)
      .unwrap();
  }

  #[test]
  fn exact_capacity_is_eof_but_overflow_returns_the_probe_byte() {
    let (mut driver, _reactor, _scope, future) =
      setup(shell("printf abc"), 3, 0, OutputLimitPolicy::ReturnPartial);
    let output = block_on(future).unwrap();
    assert_eq!(output.parts.stdout_len, 3);
    assert_eq!(&output.parts.stdout_buffer.as_slice()[..3], b"abc");
    assert!(!output.parts.stdout_truncated);
    driver
      .shutdown(super::super::ProcessShutdownMode::Wait)
      .unwrap();

    let (mut driver, _reactor, _scope, future) =
      setup(shell("printf abcd"), 3, 3, OutputLimitPolicy::ReturnPartial);
    let failure = block_on(future).unwrap_err();
    assert!(matches!(
      failure.kind,
      OutputFailureKind::LimitReached(OutputStream::Stdout)
    ));
    let parts = failure.parts.unwrap();
    assert_eq!(parts.stdout_len, 3);
    assert_eq!(&parts.stdout_buffer.as_slice()[..3], b"abc");
    assert_eq!(parts.overflow_byte, Some((OutputStream::Stdout, b'd')));
    assert!(parts.stdout_truncated);
    drop(parts);
    driver
      .shutdown(super::super::ProcessShutdownMode::Wait)
      .unwrap();
  }

  #[test]
  fn zero_capacity_distinguishes_empty_output_from_one_overflow_byte() {
    let (mut driver, _reactor, _scope, future) =
      setup(shell(":"), 0, 0, OutputLimitPolicy::ReturnPartial);
    let output = block_on(future).unwrap();
    assert_eq!(output.parts.stdout_len, 0);
    assert_eq!(output.parts.stderr_len, 0);
    driver
      .shutdown(super::super::ProcessShutdownMode::Wait)
      .unwrap();

    let (mut driver, _reactor, _scope, future) =
      setup(shell("printf x"), 0, 0, OutputLimitPolicy::ReturnPartial);
    let failure = block_on(future).unwrap_err();
    let parts = failure.parts.unwrap();
    assert_eq!(parts.overflow_byte, Some((OutputStream::Stdout, b'x')));
    assert_eq!(parts.stdout_len, 0);
    drop(parts);
    driver
      .shutdown(super::super::ProcessShutdownMode::Wait)
      .unwrap();
  }

  #[test]
  fn kill_policy_preserves_prefix_and_drains_after_overflow() {
    let (mut driver, _reactor, _scope, future) =
      setup(shell("exec yes x"), 16, 16, OutputLimitPolicy::KillAndWait);
    let started = Instant::now();
    let output = block_on(future).unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(output.parts.stdout_truncated);
    assert!(output.parts.overflow_byte.is_some());
    assert_eq!(output.parts.stdout_len, 16);
    assert!(output.status.code().is_none() || output.status.code() != Some(0));
    driver
      .shutdown(super::super::ProcessShutdownMode::Wait)
      .unwrap();
  }

  #[test]
  fn dropping_pending_collection_detaches_child_until_reaper_finishes() {
    let unique = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_nanos();
    let path = std::env::temp_dir().join(format!("allocatbelt-output-{unique}"));
    let script = format!("sleep 0.1; printf done > '{}'", path.display());
    let (mut driver, _reactor, _scope, mut future) =
      setup(shell(&script), 16, 16, OutputLimitPolicy::KillAndWait);
    let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut context = Context::from_waker(&waker);
    assert!(Pin::new(&mut future).poll(&mut context).is_pending());
    drop(future);
    assert_eq!(driver.active_children(), 1);
    driver
      .shutdown(super::super::ProcessShutdownMode::Wait)
      .unwrap();
    assert_eq!(driver.active_children(), 0);
    assert_eq!(std::fs::read(&path).unwrap(), b"done");
    let _ = std::fs::remove_file(path);
  }

  #[test]
  fn shared_buffer_rejection_returns_every_input_without_starting_collection() {
    let command = shell("sleep 0.1");
    let (mut driver, reactor, scope, future) =
      setup(command, 8, 8, OutputLimitPolicy::ReturnPartial);
    drop((future, reactor, scope));
    driver
      .shutdown(super::super::ProcessShutdownMode::Wait)
      .unwrap();

    let command = shell("sleep 0.1");
    let mut command = command;
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut driver = ProcessDriver::new(1).unwrap();
    let mut child = driver.spawn(command).unwrap();
    let stdout = child.take_stdout().unwrap();
    let stderr = child.take_stderr().unwrap();
    let reactor = Reactor::new(ReactorConfig {
      max_registrations: 2,
      max_waiters: 2,
    })
    .unwrap();
    let handle = reactor.handle();
    let stdout = AsyncChildStdout::from_std(stdout, &handle).unwrap();
    let stderr = AsyncChildStderr::from_std(stderr, &handle).unwrap();
    let scope = ResourceScope::new(ResourceLimits {
      managed_memory: 8,
      ..ResourceLimits::default()
    });
    let stdout_buffer = scope.try_alloc_zeroed(4).unwrap();
    let stderr_buffer = scope.try_alloc_zeroed(4).unwrap();
    let shared_clone = stdout_buffer.clone();
    let error = OutputFuture::new(
      OutputInputs {
        child,
        stdout,
        stderr,
        stdout_buffer,
        stderr_buffer,
      },
      OutputLimitPolicy::ReturnPartial,
    )
    .unwrap_err();
    assert_eq!(error.kind(), OutputStartErrorKind::SharedBuffer);
    let inputs = error.into_inputs();
    assert_eq!(inputs.stdout_buffer.len(), 4);
    drop((inputs, shared_clone, reactor));
    driver
      .shutdown(super::super::ProcessShutdownMode::Wait)
      .unwrap();
  }

  #[test]
  fn reactor_io_failure_returns_child_endpoints_and_buffers() {
    let command = shell("sleep 0.1");
    let (mut driver, reactor, scope, mut future) =
      setup(command, 8, 8, OutputLimitPolicy::ReturnPartial);
    reactor.shutdown().unwrap();

    let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut context = Context::from_waker(&waker);
    let failure = match Pin::new(&mut future).poll(&mut context) {
      Poll::Ready(Err(failure)) => failure,
      other => panic!("closed reactor should fail a child-pipe read: {other:?}"),
    };
    assert!(matches!(
      failure.kind,
      OutputFailureKind::Io(OutputStream::Stdout, _)
    ));
    let parts = failure.parts.unwrap();
    assert_eq!(parts.stdout_len, 0);
    assert_eq!(parts.stderr_len, 0);
    assert_eq!(parts.stdout_buffer.len(), 8);
    assert_eq!(parts.stderr_buffer.len(), 8);
    drop(parts);
    assert_eq!(scope.snapshot().managed_memory, 0);
    driver
      .shutdown(super::super::ProcessShutdownMode::Wait)
      .unwrap();
  }

  #[test]
  fn repeated_pending_polls_keep_only_bounded_waker_state() {
    let (mut driver, _reactor, _scope, mut future) =
      setup(shell("sleep 20"), 8, 8, OutputLimitPolicy::ReturnPartial);
    let wake = Arc::new(ThreadWake(thread::current()));
    let waker = Waker::from(Arc::clone(&wake));
    let mut context = Context::from_waker(&waker);
    assert!(Pin::new(&mut future).poll(&mut context).is_pending());
    let retained = Arc::strong_count(&wake);
    for _ in 0..32 {
      assert!(Pin::new(&mut future).poll(&mut context).is_pending());
      assert_eq!(Arc::strong_count(&wake), retained);
    }
    drop(future);
    driver
      .shutdown(super::super::ProcessShutdownMode::KillAndWait)
      .unwrap();
  }
}
