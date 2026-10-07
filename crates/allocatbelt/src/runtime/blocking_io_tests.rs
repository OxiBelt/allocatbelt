use super::*;
use crate::runtime::blocking::{Config, Runtime, ShutdownMode};
use crate::runtime::io::{AsyncReadExt, AsyncWriteExt};
use crate::runtime::managed::{ResourceLimits, ResourceScope};
use std::cell::Cell;
use std::future::Future;
use std::io::{Cursor, Read, Write};
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

fn runtime(workers: usize, max_outstanding: usize) -> Runtime {
  Runtime::new(Config {
    workers,
    max_outstanding,
    capacity: Resources {
      cpu: 4,
      memory: 1 << 20,
      disk: 4,
      network: 4,
    },
  })
  .unwrap()
}

fn resource_scope(bytes: usize) -> ResourceScope {
  ResourceScope::new(ResourceLimits {
    managed_memory: bytes,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  })
}

fn managed(scope: &ResourceScope, bytes: usize) -> ManagedBuf {
  scope.try_alloc_zeroed(bytes).unwrap()
}

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
  let deadline = Instant::now() + Duration::from_secs(10);
  loop {
    match future.as_mut().poll(&mut context) {
      Poll::Ready(output) => return output,
      Poll::Pending => {
        assert!(Instant::now() < deadline, "blocking I/O future timed out");
        thread::park_timeout(Duration::from_millis(10));
      }
    }
  }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
  let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
  let mut context = Context::from_waker(&waker);
  future.poll(&mut context)
}

#[derive(Default)]
struct Gate {
  state: Mutex<bool>,
  ready: Condvar,
}

impl Gate {
  fn wait(&self) {
    let mut released = self.state.lock().unwrap();
    while !*released {
      released = self.ready.wait(released).unwrap();
    }
  }

  fn release(&self) {
    *self.state.lock().unwrap() = true;
    self.ready.notify_all();
  }
}

struct ReleaseGate(Arc<Gate>);

impl Drop for ReleaseGate {
  fn drop(&mut self) {
    self.0.release();
  }
}

fn block_worker(runtime: &Runtime) -> (Job<()>, Receiver<()>, Arc<Gate>, ReleaseGate) {
  let gate = Arc::new(Gate::default());
  let (started_tx, started_rx) = mpsc::channel();
  let worker_gate = Arc::clone(&gate);
  let job = runtime
    .try_spawn(Resources::ZERO, move |_| {
      started_tx.send(()).unwrap();
      worker_gate.wait();
    })
    .unwrap();
  let release = ReleaseGate(Arc::clone(&gate));
  (job, started_rx, gate, release)
}

fn started(receiver: &Receiver<()>) {
  receiver
    .recv_timeout(Duration::from_secs(5))
    .expect("worker did not start");
}

struct GateReader {
  gate: Arc<Gate>,
  started: Option<Sender<()>>,
  inner: Cursor<&'static [u8]>,
}

impl Read for GateReader {
  fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
    if let Some(started) = self.started.take() {
      started.send(()).unwrap();
      self.gate.wait();
    }
    self.inner.read(output)
  }
}

#[derive(Default)]
struct WriterState {
  bytes: Vec<u8>,
  calls: usize,
  flushes: usize,
  max_per_call: usize,
  interruptions: usize,
  fail_call: Option<usize>,
}

#[derive(Clone)]
struct ScriptWriter(Arc<Mutex<WriterState>>);

impl Write for ScriptWriter {
  fn write(&mut self, input: &[u8]) -> io::Result<usize> {
    let mut state = self.0.lock().unwrap();
    state.calls += 1;
    if state.interruptions > 0 {
      state.interruptions -= 1;
      return Err(io::Error::from(ErrorKind::Interrupted));
    }
    if state.fail_call == Some(state.calls) {
      state.fail_call = None;
      return Err(io::Error::other("scripted write failure"));
    }
    let limit = if state.max_per_call == 0 {
      input.len()
    } else {
      state.max_per_call
    };
    let count = input.len().min(limit);
    state.bytes.extend_from_slice(&input[..count]);
    Ok(count)
  }

  fn flush(&mut self) -> io::Result<()> {
    self.0.lock().unwrap().flushes += 1;
    Ok(())
  }
}

struct GateWriter {
  gate: Arc<Gate>,
  started: Option<Sender<()>>,
  inner: ScriptWriter,
}

impl Write for GateWriter {
  fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
    if let Some(started) = self.started.take() {
      started.send(()).unwrap();
      self.gate.wait();
    }
    self.inner.write(bytes)
  }

  fn flush(&mut self) -> io::Result<()> {
    self.inner.flush()
  }
}

struct PinnedReader {
  _cell: Cell<()>,
  _pin: PhantomPinned,
}

impl Read for PinnedReader {
  fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
    let bytes = b"pinned";
    let count = output.len().min(bytes.len());
    output[..count].copy_from_slice(&bytes[..count]);
    Ok(count)
  }
}

#[test]
fn read_ahead_survives_cancelled_borrow_and_later_buffer_size() {
  let mut runtime = runtime(1, 4);
  let scope = resource_scope(4);
  let gate = Arc::new(Gate::default());
  let (started_tx, started_rx) = mpsc::channel();
  let mut reader = reader(
    runtime.handle(),
    Resources::ZERO,
    GateReader {
      gate: Arc::clone(&gate),
      started: Some(started_tx),
      inner: Cursor::new(b"abcdef"),
    },
    managed(&scope, 4),
  )
  .unwrap();
  let _release = ReleaseGate(Arc::clone(&gate));

  let mut first = [0; 1];
  let mut future = Box::pin(AsyncReadExt::read(&mut reader, &mut first));
  assert!(poll_once(future.as_mut()).is_pending());
  started(&started_rx);
  drop(future);
  assert_eq!(scope.snapshot().managed_memory, 4);
  gate.release();

  let mut next = [0; 3];
  assert_eq!(
    block_on(AsyncReadExt::read(&mut reader, &mut next)).unwrap(),
    3
  );
  assert_eq!(&next, b"abc");
  let mut tail = [0; 2];
  assert_eq!(
    block_on(AsyncReadExt::read(&mut reader, &mut tail)).unwrap(),
    1
  );
  assert_eq!(&tail[..1], b"d");
  let mut final_byte = [0; 1];
  assert_eq!(
    block_on(AsyncReadExt::read(&mut reader, &mut final_byte)).unwrap(),
    1
  );
  assert_eq!(&final_byte, b"e");
  assert_eq!(scope.snapshot().managed_memory, 4);
  drop(reader);
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn reader_supports_send_non_sync_non_unpin_streams() {
  let mut runtime = runtime(1, 2);
  let scope = resource_scope(6);
  let mut reader = reader(
    runtime.handle(),
    Resources::ZERO,
    PinnedReader {
      _cell: Cell::new(()),
      _pin: PhantomPinned,
    },
    managed(&scope, 6),
  )
  .unwrap();
  let mut output = [0; 6];
  assert_eq!(
    block_on(AsyncReadExt::read(&mut reader, &mut output)).unwrap(),
    6
  );
  assert_eq!(&output, b"pinned");
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn constructor_rejection_returns_original_stream_and_buffer() {
  let mut runtime = runtime(1, 2);
  let scope = resource_scope(8);
  let empty = managed(&scope, 0);
  let rejected = match reader(
    runtime.handle(),
    Resources::ZERO,
    Cursor::new(b"same"),
    empty,
  ) {
    Ok(_) => panic!("empty buffer was accepted"),
    Err(error) => error,
  };
  assert_eq!(rejected.kind, BlockingIoInitErrorKind::EmptyBuffer);
  let (stream, buffer) = rejected.into_parts();
  assert_eq!(stream.into_inner(), b"same");
  assert!(buffer.is_empty());

  let shared = managed(&scope, 8);
  let other = shared.clone();
  let rejected = match writer(
    runtime.handle(),
    Resources::ZERO,
    ScriptWriter(Arc::new(Mutex::new(WriterState::default()))),
    shared,
  ) {
    Ok(_) => panic!("shared buffer was accepted"),
    Err(error) => error,
  };
  assert_eq!(rejected.kind, BlockingIoInitErrorKind::SharedBuffer);
  let (_writer, returned) = rejected.into_parts();
  assert_eq!(returned.len(), 8);
  drop(other);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn writer_retries_interrupted_and_drains_partial_suffix_before_flush() {
  let mut runtime = runtime(1, 8);
  let scope = resource_scope(4);
  let state = Arc::new(Mutex::new(WriterState {
    max_per_call: 2,
    interruptions: 2,
    ..WriterState::default()
  }));
  let mut writer = writer(
    runtime.handle(),
    Resources {
      cpu: 1,
      ..Resources::ZERO
    },
    ScriptWriter(Arc::clone(&state)),
    managed(&scope, 4),
  )
  .unwrap();
  block_on(AsyncWriteExt::write_all(&mut writer, b"abcdef")).unwrap();
  block_on(AsyncWriteExt::flush(&mut writer)).unwrap();
  assert_eq!(state.lock().unwrap().bytes, b"abcdef");
  assert!(state.lock().unwrap().calls >= 5);
  assert_eq!(state.lock().unwrap().flushes, 1);
  block_on(AsyncWriteExt::shutdown(&mut writer)).unwrap();
  assert_eq!(state.lock().unwrap().flushes, 2);
  assert_eq!(
    block_on(AsyncWriteExt::write(&mut writer, b"x"))
      .unwrap_err()
      .kind(),
    ErrorKind::BrokenPipe
  );
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn partial_write_error_preserves_suffix_without_replaying_committed_bytes() {
  let mut runtime = runtime(1, 8);
  let scope = resource_scope(4);
  let state = Arc::new(Mutex::new(WriterState {
    max_per_call: 2,
    fail_call: Some(2),
    ..WriterState::default()
  }));
  let mut writer = writer(
    runtime.handle(),
    Resources::ZERO,
    ScriptWriter(Arc::clone(&state)),
    managed(&scope, 4),
  )
  .unwrap();
  block_on(AsyncWriteExt::write_all(&mut writer, b"abcd")).unwrap();
  let error = block_on(AsyncWriteExt::flush(&mut writer)).unwrap_err();
  assert_eq!(error.kind(), ErrorKind::Other);
  assert_eq!(state.lock().unwrap().bytes, b"ab");
  block_on(AsyncWriteExt::flush(&mut writer)).unwrap();
  assert_eq!(state.lock().unwrap().bytes, b"abcd");
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn admission_rejection_accepts_no_write_bytes_and_can_be_retried() {
  let mut runtime = runtime(1, 1);
  let (blocker, blocker_started, gate, _release) = block_worker(&runtime);
  started(&blocker_started);
  let scope = resource_scope(4);
  let state = Arc::new(Mutex::new(WriterState::default()));
  let mut writer = writer(
    runtime.handle(),
    Resources::ZERO,
    ScriptWriter(Arc::clone(&state)),
    managed(&scope, 4),
  )
  .unwrap();
  let error = block_on(AsyncWriteExt::write(&mut writer, b"data")).unwrap_err();
  assert_eq!(error.kind(), ErrorKind::WouldBlock);
  assert!(state.lock().unwrap().bytes.is_empty());
  assert_eq!(scope.snapshot().managed_memory, 4);
  gate.release();
  blocker.join().unwrap();
  assert_eq!(
    block_on(AsyncWriteExt::write_all(&mut writer, b"data")).unwrap(),
    ()
  );
  block_on(AsyncWriteExt::flush(&mut writer)).unwrap();
  assert_eq!(state.lock().unwrap().bytes, b"data");
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn cancelled_borrow_does_not_credit_an_old_write_to_new_input() {
  let mut runtime = runtime(1, 6);
  let gate = Arc::new(Gate::default());
  let (started_tx, started_rx) = mpsc::channel();
  let state = Arc::new(Mutex::new(WriterState::default()));
  let mut writer = writer(
    runtime.handle(),
    Resources::ZERO,
    GateWriter {
      gate: Arc::clone(&gate),
      started: Some(started_tx),
      inner: ScriptWriter(Arc::clone(&state)),
    },
    managed(&resource_scope(1), 1),
  )
  .unwrap();
  let _release = ReleaseGate(Arc::clone(&gate));

  assert_eq!(
    block_on(AsyncWriteExt::write(&mut writer, b"a")).unwrap(),
    1
  );
  started(&started_rx);
  let mut cancelled = Box::pin(AsyncWriteExt::write_all(&mut writer, b"b"));
  assert!(poll_once(cancelled.as_mut()).is_pending());
  drop(cancelled);
  gate.release();

  block_on(AsyncWriteExt::write_all(&mut writer, b"c")).unwrap();
  block_on(AsyncWriteExt::flush(&mut writer)).unwrap();
  assert_eq!(state.lock().unwrap().bytes, b"ac");
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn queued_cancel_pending_makes_endpoint_terminal_and_releases_buffer() {
  let mut runtime = runtime(1, 3);
  let (blocker, blocker_started, gate, _release) = block_worker(&runtime);
  started(&blocker_started);
  let scope = resource_scope(4);
  let state = Arc::new(Mutex::new(WriterState::default()));
  let mut writer = writer(
    runtime.handle(),
    Resources::ZERO,
    ScriptWriter(Arc::clone(&state)),
    managed(&scope, 4),
  )
  .unwrap();
  assert_eq!(
    block_on(AsyncWriteExt::write(&mut writer, b"data")).unwrap(),
    4
  );
  assert_eq!(scope.snapshot().managed_memory, 4);

  let handle = runtime.handle();
  let shutdown = thread::spawn(move || runtime.shutdown(ShutdownMode::CancelPending));
  let deadline = Instant::now() + Duration::from_secs(5);
  while !handle.snapshot().closed {
    assert!(Instant::now() < deadline, "runtime did not begin shutdown");
    thread::sleep(Duration::from_millis(5));
  }
  while scope.snapshot().managed_memory != 0 {
    assert!(
      Instant::now() < deadline,
      "queued adapter input was not cancelled"
    );
    thread::sleep(Duration::from_millis(5));
  }
  gate.release();
  shutdown.join().unwrap().unwrap();
  assert_eq!(blocker.join().unwrap(), ());
  assert_eq!(scope.snapshot().managed_memory, 0);
  assert_eq!(
    block_on(AsyncWriteExt::flush(&mut writer))
      .unwrap_err()
      .kind(),
    ErrorKind::BrokenPipe
  );
  assert!(state.lock().unwrap().bytes.is_empty());
}

#[test]
fn dropping_endpoint_retains_managed_buffer_until_running_call_finishes() {
  let mut runtime = runtime(1, 3);
  let gate = Arc::new(Gate::default());
  let (started_tx, started_rx) = mpsc::channel();
  let scope = resource_scope(1);
  let state = Arc::new(Mutex::new(WriterState::default()));
  let mut writer = writer(
    runtime.handle(),
    Resources::ZERO,
    GateWriter {
      gate: Arc::clone(&gate),
      started: Some(started_tx),
      inner: ScriptWriter(Arc::clone(&state)),
    },
    managed(&scope, 1),
  )
  .unwrap();
  let _release = ReleaseGate(Arc::clone(&gate));
  assert_eq!(
    block_on(AsyncWriteExt::write(&mut writer, b"x")).unwrap(),
    1
  );
  started(&started_rx);
  drop(writer);
  assert_eq!(scope.snapshot().managed_memory, 1);
  gate.release();
  let deadline = Instant::now() + Duration::from_secs(5);
  while scope.snapshot().managed_memory != 0 {
    assert!(Instant::now() < deadline, "managed buffer charge leaked");
    thread::sleep(Duration::from_millis(5));
  }
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn stdio_constructors_wrap_global_handles_without_reading_stdin() {
  let mut runtime = runtime(1, 3);
  let scope = resource_scope(3);
  let input = stdin_reader(runtime.handle(), Resources::ZERO, managed(&scope, 1)).unwrap();
  let output = stdout_writer(runtime.handle(), Resources::ZERO, managed(&scope, 1)).unwrap();
  let error = stderr_writer(runtime.handle(), Resources::ZERO, managed(&scope, 1)).unwrap();
  drop((input, output, error));
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn reader_retries_only_the_bounded_interrupted_budget() {
  struct InterruptedReader(Arc<AtomicUsize>);
  impl Read for InterruptedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
      let count = self.0.fetch_add(1, Ordering::SeqCst);
      if count < INTERRUPTED_RETRIES + 1 {
        return Err(io::Error::from(ErrorKind::Interrupted));
      }
      output[0] = b'z';
      Ok(1)
    }
  }

  let mut runtime = runtime(1, 2);
  let scope = resource_scope(1);
  let calls = Arc::new(AtomicUsize::new(0));
  let mut reader = reader(
    runtime.handle(),
    Resources::ZERO,
    InterruptedReader(Arc::clone(&calls)),
    managed(&scope, 1),
  )
  .unwrap();
  let mut output = [0];
  assert_eq!(
    block_on(AsyncReadExt::read(&mut reader, &mut output))
      .unwrap_err()
      .kind(),
    ErrorKind::Interrupted
  );
  assert_eq!(calls.load(Ordering::SeqCst), INTERRUPTED_RETRIES + 1);
  assert_eq!(
    block_on(AsyncReadExt::read(&mut reader, &mut output)).unwrap(),
    1
  );
  assert_eq!(output, [b'z']);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn exhausted_runtime_coop_budget_does_not_accept_or_submit_a_write() {
  use crate::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown, consume_budget};

  let mut blocking = runtime(1, 4);
  let blocking_handle = blocking.handle();
  let scope = resource_scope(1);
  let state = Arc::new(Mutex::new(WriterState::default()));
  let writer = writer(
    blocking_handle.clone(),
    Resources::ZERO,
    ScriptWriter(Arc::clone(&state)),
    managed(&scope, 1),
  )
  .unwrap();
  let asynchronous = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let observed_state = Arc::clone(&state);
  let task = asynchronous
    .handle()
    .spawn(async move {
      let mut writer = writer;
      for _ in 0..64 {
        consume_budget().await;
      }
      let mut first = true;
      let accepted = std::future::poll_fn(|cx| {
        let result = Pin::new(&mut writer).poll_write(cx, b"x");
        if first {
          first = false;
          assert!(result.is_pending());
          assert_eq!(blocking_handle.snapshot().outstanding, 0);
          assert!(observed_state.lock().unwrap().bytes.is_empty());
        }
        result
      })
      .await?;
      assert_eq!(accepted, 1);
      AsyncWriteExt::flush(&mut writer).await?;
      Ok::<_, io::Error>(())
    })
    .unwrap();
  asynchronous.block_on(task).unwrap().unwrap().unwrap();
  assert_eq!(state.lock().unwrap().bytes, b"x");
  asynchronous.shutdown(AsyncShutdown::Drain).unwrap();
  blocking.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn invalid_stream_counts_become_errors_and_preserve_writer_suffix() {
  struct TooMuchReader;
  impl Read for TooMuchReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
      Ok(output.len() + 1)
    }
  }

  struct TooMuchWriter;
  impl Write for TooMuchWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
      Ok(input.len() + 1)
    }

    fn flush(&mut self) -> io::Result<()> {
      Ok(())
    }
  }

  let mut runtime = runtime(1, 4);
  let read_scope = resource_scope(2);
  let mut reader = reader(
    runtime.handle(),
    Resources::ZERO,
    TooMuchReader,
    managed(&read_scope, 2),
  )
  .unwrap();
  let mut destination = [0; 2];
  assert_eq!(
    block_on(AsyncReadExt::read(&mut reader, &mut destination))
      .unwrap_err()
      .kind(),
    ErrorKind::InvalidData
  );

  let write_scope = resource_scope(2);
  let mut writer = writer(
    runtime.handle(),
    Resources::ZERO,
    TooMuchWriter,
    managed(&write_scope, 2),
  )
  .unwrap();
  assert_eq!(
    block_on(AsyncWriteExt::write(&mut writer, b"xy")).unwrap(),
    2
  );
  assert_eq!(
    block_on(AsyncWriteExt::flush(&mut writer))
      .unwrap_err()
      .kind(),
    ErrorKind::InvalidData
  );
  assert_eq!(write_scope.snapshot().managed_memory, 2);
  drop((reader, writer));
  assert_eq!(read_scope.snapshot().managed_memory, 0);
  assert_eq!(write_scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn panicking_stream_job_becomes_terminal_and_releases_managed_buffer() {
  struct PanicWriter;
  impl Write for PanicWriter {
    fn write(&mut self, _input: &[u8]) -> io::Result<usize> {
      panic!("scripted writer panic");
    }

    fn flush(&mut self) -> io::Result<()> {
      Ok(())
    }
  }

  let mut runtime = runtime(1, 3);
  let scope = resource_scope(2);
  let mut writer = writer(
    runtime.handle(),
    Resources::ZERO,
    PanicWriter,
    managed(&scope, 2),
  )
  .unwrap();
  assert_eq!(
    block_on(AsyncWriteExt::write(&mut writer, b"xy")).unwrap(),
    2
  );
  assert_eq!(scope.snapshot().managed_memory, 2);
  assert_eq!(
    block_on(AsyncWriteExt::flush(&mut writer))
      .unwrap_err()
      .kind(),
    ErrorKind::BrokenPipe
  );
  assert_eq!(scope.snapshot().managed_memory, 0);
  assert_eq!(
    block_on(AsyncWriteExt::flush(&mut writer))
      .unwrap_err()
      .kind(),
    ErrorKind::BrokenPipe
  );
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn operation_panic_survives_panicking_stream_drop() {
  struct PanicOnDrop;
  impl Drop for PanicOnDrop {
    fn drop(&mut self) {
      std::panic::panic_any(PanicOnDrop);
    }
  }

  struct PanicAndDropWriter(Arc<AtomicBool>);
  impl Write for PanicAndDropWriter {
    fn write(&mut self, _input: &[u8]) -> io::Result<usize> {
      panic!("primary stream operation panic");
    }

    fn flush(&mut self) -> io::Result<()> {
      Ok(())
    }
  }
  impl Drop for PanicAndDropWriter {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
      std::panic::panic_any(PanicOnDrop);
    }
  }

  let mut runtime = runtime(1, 3);
  let scope = resource_scope(2);
  let dropped = Arc::new(AtomicBool::new(false));
  let mut writer = writer(
    runtime.handle(),
    Resources::ZERO,
    PanicAndDropWriter(Arc::clone(&dropped)),
    managed(&scope, 2),
  )
  .unwrap();

  assert_eq!(
    block_on(AsyncWriteExt::write(&mut writer, b"xy")).unwrap(),
    2
  );
  let error = block_on(AsyncWriteExt::flush(&mut writer)).unwrap_err();
  let kind = error
    .get_ref()
    .and_then(|source| source.downcast_ref::<BlockingIoError>())
    .map(|error| error.kind());
  assert_eq!(kind, Some(BlockingIoErrorKind::Panicked));
  assert!(dropped.load(Ordering::SeqCst));
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn invalid_declared_resources_reject_before_write_acceptance() {
  let mut runtime = runtime(1, 2);
  let scope = resource_scope(2);
  let state = Arc::new(Mutex::new(WriterState::default()));
  let mut writer = writer(
    runtime.handle(),
    Resources {
      cpu: 5,
      ..Resources::ZERO
    },
    ScriptWriter(Arc::clone(&state)),
    managed(&scope, 2),
  )
  .unwrap();
  let error = block_on(AsyncWriteExt::write(&mut writer, b"no")).unwrap_err();
  assert_eq!(error.kind(), ErrorKind::WouldBlock);
  let Some(failure) = error
    .get_ref()
    .and_then(|cause| cause.downcast_ref::<BlockingIoError>())
  else {
    panic!("submission source was not preserved");
  };
  assert_eq!(
    failure.kind(),
    BlockingIoErrorKind::Submission(SubmitErrorKind::InvalidRequest)
  );
  assert!(state.lock().unwrap().bytes.is_empty());
  assert_eq!(scope.snapshot().managed_memory, 2);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn unix_stream_peer_receives_only_flushed_accepted_bytes() {
  use std::io::Read as _;
  use std::os::unix::net::UnixStream;

  let mut runtime = runtime(1, 4);
  let scope = resource_scope(8);
  let (stream, mut peer) = UnixStream::pair().unwrap();
  let mut writer = writer(
    runtime.handle(),
    Resources::ZERO,
    stream,
    managed(&scope, 8),
  )
  .unwrap();
  block_on(AsyncWriteExt::write_all(&mut writer, b"pipe-data")).unwrap();
  block_on(AsyncWriteExt::flush(&mut writer)).unwrap();
  let mut received = [0; 9];
  peer.read_exact(&mut received).unwrap();
  assert_eq!(&received, b"pipe-data");
  drop(writer);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}
