#![cfg(target_os = "linux")]

use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender, TryRecvError};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

use allocatbelt::runtime::blocking_io::{self, BlockingWriter};
use allocatbelt::runtime::buffered_io::{BufferedReader, BufferedWriter};
use allocatbelt::runtime::fs::{FifoOpenError, FifoOpenOptions, FsHandle, FsSubmissionErrorKind};
use allocatbelt::runtime::io::{
  AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BoundedReadStop,
};
use allocatbelt::runtime::managed::{ManagedBuf, ResourceLimits, ResourceScope};
use allocatbelt::runtime::reactor::{Reactor, ReactorConfig, ReactorHandle};
use allocatbelt::runtime::unix_pipe::{PipeReader, PipeWriter};
use allocatbelt::runtime::{Config, Resources, Runtime, ShutdownMode};

const WAIT: Duration = Duration::from_secs(15);
const BLOCKING_GATE_WAIT: Duration = Duration::from_secs(10);
const PIPE_FILL_LIMIT: usize = 1024 * 1024;
const PIPE_WRITER_BYTES: usize = 1024 * 1024;
const PIPE_READ_CHUNK: usize = 64 * 1024;
const MAX_DRAIN_ROUNDS: usize = 1024;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);

impl Scratch {
  fn new() -> Self {
    let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-fifo-pipeline-{}-{id}",
      std::process::id()
    ));
    std::fs::DirBuilder::new()
      .mode(0o700)
      .create(&path)
      .expect("fresh private test directory should be created");
    Self(path)
  }

  fn child(&self, name: &str) -> PathBuf {
    self.0.join(name)
  }

  /// Explicit success-path cleanup; Drop remains best-effort for unwinding.
  fn remove(self) {
    std::fs::remove_dir_all(&self.0)
      .expect("scratch directory should be removed after its owners drop");
    assert_eq!(
      std::fs::symlink_metadata(&self.0)
        .expect_err("removed scratch directory must not remain")
        .kind(),
      io::ErrorKind::NotFound
    );
  }
}

impl Drop for Scratch {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.0);
  }
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
  let deadline = Instant::now() + WAIT;
  loop {
    match future.as_mut().poll(&mut context) {
      Poll::Ready(output) => return output,
      Poll::Pending => {
        assert!(
          Instant::now() < deadline,
          "FIFO pipeline operation exceeded its local wait bound"
        );
        thread::park_timeout(Duration::from_millis(2));
      }
    }
  }
}

fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
  let mut context = Context::from_waker(Waker::noop());
  future.as_mut().poll(&mut context)
}

fn managed(scope: &ResourceScope, bytes: usize) -> ManagedBuf {
  scope
    .try_alloc_zeroed(bytes)
    .expect("fixture buffer should fit the caller's managed-memory limit")
}

fn resource_scope(memory: usize, disk: usize) -> ResourceScope {
  ResourceScope::new(ResourceLimits {
    managed_memory: memory,
    disk_concurrent_ops: disk,
    network_concurrent_ops: 0,
  })
}

fn blocking_runtime(workers: usize, capacity: Resources) -> Runtime {
  Runtime::new(Config {
    workers,
    max_outstanding: 8,
    capacity,
  })
  .expect("bounded blocking runtime should start")
}

fn reactor(max_registrations: usize) -> (Reactor, ReactorHandle) {
  let reactor = Reactor::new(ReactorConfig {
    max_registrations,
    max_waiters: 8,
  })
  .expect("bounded reactor should start");
  let handle = reactor.handle();
  (reactor, handle)
}

fn make_fifo(filesystem: &FsHandle, path: &Path) {
  filesystem
    .create_fifo(path.to_path_buf(), 0o600)
    .expect("FIFO creation should be admitted")
    .join()
    .expect("FIFO creation job should complete")
    .expect("FIFO creation syscall should succeed");
  assert!(
    std::fs::symlink_metadata(path)
      .expect("created FIFO metadata should be available")
      .file_type()
      .is_fifo()
  );
}

#[test]
fn fifo_admission_rejection_enxio_late_data_and_self_peer_are_explicit() {
  let scratch = Scratch::new();
  let mut runtime = blocking_runtime(2, Resources::ZERO);
  let resources = resource_scope(0, 8);
  let filesystem = FsHandle::new(runtime.handle(), resources.clone());
  let exhausted = FsHandle::new(runtime.handle(), resource_scope(0, 0));
  let (_reactor, reactor) = reactor(8);

  let late_path = scratch.child("late-writer");
  make_fifo(&filesystem, &late_path);
  let options = FifoOpenOptions::new();
  let rejected = match exhausted.open_fifo_sender(late_path.clone(), options, &reactor) {
    Err(error) => error,
    Ok(_) => panic!("zero disk permits must refuse FIFO sender admission"),
  };
  assert!(matches!(rejected.kind, FsSubmissionErrorKind::Resource(_)));
  let (recovered_path, recovered_options) = rejected.into_input();
  assert_eq!(recovered_path, late_path);
  assert_eq!(recovered_options, options);

  let mut reader = filesystem
    .open_fifo_receiver(late_path.clone(), options, &reactor)
    .expect("FIFO receiver open should be admitted")
    .join()
    .expect("FIFO receiver open job should complete")
    .expect("FIFO receiver should open");
  let mut raw_reader = std::fs::File::from(
    reader
      .get_ref()
      .try_clone()
      .expect("reader alias should preserve the original descriptor"),
  );
  let mut first = [0_u8; 1];
  assert_eq!(
    raw_reader
      .read(&mut first)
      .expect("initial Linux FIFO read should succeed"),
    0,
    "a default reader observes initial EOF before the first writer opens"
  );
  drop(raw_reader);

  let mut writer = filesystem
    .open_fifo_sender(late_path, options, &reactor)
    .expect("FIFO sender open should be admitted")
    .join()
    .expect("FIFO sender open job should complete")
    .expect("sender should open after the reader exists");
  block_on(writer.write_all(b"late-data")).expect("later FIFO data should be written");
  let mut late_data = [0_u8; 16];
  read_exact_async(&mut reader, &mut late_data[..b"late-data".len()]);
  assert_eq!(&late_data[..b"late-data".len()], b"late-data");
  block_on(writer.shutdown()).expect("closing the FIFO writer should succeed");
  assert_eq!(
    block_on(reader.read(&mut late_data)).expect("closed FIFO should report EOF"),
    0
  );
  drop(writer);
  drop(reader);

  let no_reader_path = scratch.child("no-reader");
  make_fifo(&filesystem, &no_reader_path);
  let error = match filesystem
    .open_fifo_sender(no_reader_path.clone(), options, &reactor)
    .expect("sender syscall should be admitted")
    .join()
    .expect("sender open job should complete")
  {
    Err(error) => error,
    Ok(_) => panic!("a default FIFO sender without a reader must fail"),
  };
  match error {
    FifoOpenError::Open(error) => {
      assert_eq!(error.raw_os_error(), Some(6), "Linux ENXIO is preserved");
    }
    FifoOpenError::Import(_) => panic!("an open failure must not be reported as import failure"),
  }
  assert!(
    std::fs::symlink_metadata(&no_reader_path)
      .expect("failed sender open must retain the FIFO path")
      .file_type()
      .is_fifo()
  );

  let self_path = scratch.child("self-peer");
  make_fifo(&filesystem, &self_path);
  let mut self_reader = filesystem
    .open_fifo_receiver(self_path, FifoOpenOptions::new().read_write(true), &reactor)
    .expect("read-write FIFO open should be admitted")
    .join()
    .expect("read-write FIFO open job should complete")
    .expect("Linux read-write FIFO should self-peer");
  let mut self_peer = std::fs::File::from(
    self_reader
      .get_ref()
      .try_clone()
      .expect("self-peer descriptor alias should be retained"),
  );
  self_peer
    .write_all(b"self-peer")
    .expect("self-peer FIFO should accept a finite write");
  let mut self_data = [0_u8; 16];
  read_exact_async(&mut self_reader, &mut self_data[..b"self-peer".len()]);
  assert_eq!(&self_data[..b"self-peer".len()], b"self-peer");
  assert_eq!(
    self_peer
      .read(&mut first)
      .expect_err("the self-peer keeps a nonblocking writer peer open")
      .kind(),
    io::ErrorKind::WouldBlock
  );
  drop(self_peer);
  drop(self_reader);

  assert_eq!(reactor.registrations(), 0);
  assert_eq!(reactor.waiters(), 0);
  assert_eq!(resources.snapshot().disk_ops, 0);
  drop(filesystem);
  drop(exhausted);
  runtime
    .shutdown(ShutdownMode::Drain)
    .expect("all FIFO-open workers should have finished");
  _reactor
    .shutdown()
    .expect("all FIFO registrations should be closed");
  scratch.remove();
}

#[test]
fn buffered_fifo_line_resumes_split_utf8_and_capacity_without_replay() {
  let scratch = Scratch::new();
  let mut runtime = blocking_runtime(2, Resources::ZERO);
  let resources = resource_scope(32, 4);
  let filesystem = FsHandle::new(runtime.handle(), resources.clone());
  let (_reactor, reactor) = reactor(4);
  let path = scratch.child("split-line");
  make_fifo(&filesystem, &path);

  let reader = filesystem
    .open_fifo_receiver(path.clone(), FifoOpenOptions::new(), &reactor)
    .expect("FIFO reader open should be admitted")
    .join()
    .expect("FIFO reader job should complete")
    .expect("FIFO reader should open");
  let mut writer = filesystem
    .open_fifo_sender(path, FifoOpenOptions::new(), &reactor)
    .expect("FIFO writer open should be admitted")
    .join()
    .expect("FIFO writer job should complete")
    .expect("FIFO writer should open");
  let mut buffered = BufferedReader::new(reader, managed(&resources, 4))
    .expect("four-byte managed reader buffer should initialize");

  // The euro sign's third byte arrives only after the bounded line read has
  // actually consumed the first fragment and returned Pending.
  block_on(writer.write_all(b"head:\xe2"))
    .expect("the first split-line fragment should be accepted");
  let mut first_line = [0_u8; 8];
  let mut pending_line = Box::pin(buffered.read_line_bounded(&mut first_line));
  let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
  let mut context = Context::from_waker(&waker);
  let deadline = Instant::now() + WAIT;
  loop {
    match pending_line.as_mut().poll(&mut context) {
      Poll::Ready(_) => panic!("the partial UTF-8 line must wait for its remaining bytes"),
      Poll::Pending if pending_line.as_ref().get_ref().filled() == 6 => break,
      Poll::Pending => {
        assert!(
          Instant::now() < deadline,
          "first FIFO fragment was not observed in time"
        );
        thread::park_timeout(Duration::from_millis(2));
      }
    }
  }
  assert_eq!(pending_line.as_ref().get_ref().filled(), 6);
  block_on(writer.write_all(b"\x82\xac-tail\nrest\n"))
    .expect("the second split-line fragment should be accepted");
  let first_result =
    block_on(pending_line).expect("the completed UTF-8 line prefix should be valid");
  assert_eq!(first_result.filled, 8);
  assert_eq!(first_result.stop, BoundedReadStop::Capacity);
  assert_eq!(first_line.as_slice(), "head:€".as_bytes());

  let expected_tail = b"-tail\nrest\n";
  let buffered_before_resume = buffered.buffered().to_vec();
  assert!(
    expected_tail.starts_with(&buffered_before_resume),
    "the unread buffer is an exact prefix of the unconsumed stream suffix"
  );
  let mut tail = [0_u8; 32];
  let tail_result = block_on(buffered.read_line_bounded(&mut tail))
    .expect("resuming after destination capacity should preserve UTF-8 and suffix bytes");
  assert_eq!(tail_result.filled, b"-tail\n".len());
  assert_eq!(tail_result.stop, BoundedReadStop::Delimiter);
  assert_eq!(&tail[..tail_result.filled], b"-tail\n");
  let rest_result = block_on(buffered.read_line_bounded(&mut tail))
    .expect("the next line should follow without replay");
  assert_eq!(rest_result.filled, b"rest\n".len());
  assert_eq!(rest_result.stop, BoundedReadStop::Delimiter);
  assert_eq!(&tail[..rest_result.filled], b"rest\n");
  block_on(writer.shutdown()).expect("FIFO write side should close after both lines");
  let eof = block_on(buffered.read_line_bounded(&mut tail))
    .expect("the final bounded read should observe EOF");
  assert_eq!(eof.filled, 0);
  assert_eq!(eof.stop, BoundedReadStop::Eof);

  let (inner, buffer, unread) = buffered.into_parts();
  assert!(
    unread.is_empty(),
    "all delivered bytes were consumed exactly once"
  );
  assert_eq!(unread, 0..0);
  drop(inner);
  assert_eq!(resources.snapshot().managed_memory, 4);
  drop(buffer);
  assert_eq!(resources.snapshot().managed_memory, 0);
  drop(writer);
  drop(filesystem);
  assert_eq!(reactor.registrations(), 0);
  assert_eq!(reactor.waiters(), 0);
  runtime
    .shutdown(ShutdownMode::Drain)
    .expect("FIFO-open workers should be idle");
  _reactor
    .shutdown()
    .expect("reader and writer registrations should be gone");
  scratch.remove();
}

#[derive(Debug, Default)]
struct WriterObservation {
  accepted: usize,
  flush_at: Vec<usize>,
  shutdown_at: Vec<usize>,
  events: Vec<WriterEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterEvent {
  Write { offered: usize, accepted: usize },
  Flush(usize),
  Shutdown(usize),
}

struct CountedPipeWriter {
  inner: PipeWriter,
  observation: Arc<Mutex<WriterObservation>>,
}

impl AsyncWrite for CountedPipeWriter {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bytes: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    let offered = bytes.len();
    match Pin::new(&mut this.inner).poll_write(cx, bytes) {
      Poll::Ready(Ok(count)) => {
        let mut observation = this
          .observation
          .lock()
          .expect("write observation lock is healthy");
        observation.accepted += count;
        observation.events.push(WriterEvent::Write {
          offered,
          accepted: count,
        });
        Poll::Ready(Ok(count))
      }
      other => other,
    }
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    match Pin::new(&mut this.inner).poll_flush(cx) {
      Poll::Ready(Ok(())) => {
        let mut observation = this
          .observation
          .lock()
          .expect("write observation lock is healthy");
        let accepted = observation.accepted;
        observation.flush_at.push(accepted);
        observation.events.push(WriterEvent::Flush(accepted));
        Poll::Ready(Ok(()))
      }
      other => other,
    }
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    match Pin::new(&mut this.inner).poll_shutdown(cx) {
      Poll::Ready(Ok(())) => {
        let mut observation = this
          .observation
          .lock()
          .expect("write observation lock is healthy");
        let accepted = observation.accepted;
        observation.shutdown_at.push(accepted);
        observation.events.push(WriterEvent::Shutdown(accepted));
        Poll::Ready(Ok(()))
      }
      other => other,
    }
  }

  fn is_write_vectored(&self) -> bool {
    self.inner.is_write_vectored()
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlushStep {
  PendingAfterProgress(usize),
  Complete(usize),
}

async fn flush_until_progress<W: AsyncWrite + Unpin>(
  writer: &mut W,
  observation: &Arc<Mutex<WriterObservation>>,
  previous: usize,
) -> io::Result<FlushStep> {
  let mut flush = Box::pin(writer.flush());
  poll_fn(|cx| match flush.as_mut().poll(cx) {
    Poll::Ready(Ok(())) => {
      let accepted = observation
        .lock()
        .expect("write observation lock is healthy")
        .accepted;
      Poll::Ready(Ok(FlushStep::Complete(accepted)))
    }
    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
    Poll::Pending => {
      let accepted = observation
        .lock()
        .expect("write observation lock is healthy")
        .accepted;
      if accepted > previous {
        Poll::Ready(Ok(FlushStep::PendingAfterProgress(accepted)))
      } else {
        Poll::Pending
      }
    }
  })
  .await
}

fn accepted(observation: &Arc<Mutex<WriterObservation>>) -> usize {
  observation
    .lock()
    .expect("write observation lock is healthy")
    .accepted
}

fn read_exact_async<R: AsyncRead + Unpin>(reader: &mut R, output: &mut [u8]) {
  let read = block_on(reader.read_exact(output)).expect("known pipe bytes should be readable");
  assert_eq!(read, output.len());
}

#[test]
fn buffered_pipe_writer_observes_kernel_would_block_partial_progress_and_suffix_recovery() {
  let resources = resource_scope(PIPE_WRITER_BYTES, 0);
  let buffer = managed(&resources, PIPE_WRITER_BYTES);
  let (reactor, reactor_handle) = reactor(2);
  let (raw_reader, mut raw_writer) =
    std::io::pipe().expect("anonymous Linux pipe should be created");
  let mut registered_reader = PipeReader::from_owned_fd(
    raw_reader
      .as_fd()
      .try_clone_to_owned()
      .expect("reader fd clone should be owned"),
    &reactor_handle,
  )
  .expect("anonymous pipe reader should register");
  let pipe_writer = PipeWriter::from_owned_fd(
    raw_writer
      .as_fd()
      .try_clone_to_owned()
      .expect("writer fd clone should be owned"),
    &reactor_handle,
  )
  .expect("anonymous pipe writer should register");
  drop(raw_reader);
  let observation = Arc::new(Mutex::new(WriterObservation::default()));
  let counted = CountedPipeWriter {
    inner: pipe_writer,
    observation: Arc::clone(&observation),
  };
  let mut writer = BufferedWriter::new(counted, buffer)
    .expect("managed buffer should initialize the bounded writer");

  let mut filled = 0;
  let mut saw_would_block = false;
  for _ in 0..PIPE_FILL_LIMIT {
    match raw_writer.write(b"f") {
      Ok(1) => filled += 1,
      Ok(_) => panic!("one-byte pipe writes must make exactly one byte of progress"),
      Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
        saw_would_block = true;
        break;
      }
      Err(error) => panic!("bounded raw pipe fill failed: {error}"),
    }
  }
  assert!(
    saw_would_block,
    "the finite one-byte fill must witness actual EAGAIN"
  );
  assert!(filled > 0 && filled < PIPE_FILL_LIMIT);
  drop(raw_writer);

  let payload: Vec<u8> = (0..PIPE_WRITER_BYTES)
    .map(|index| u8::try_from(index % 251).expect("remainder fits in one byte"))
    .collect();
  block_on(writer.write_all(&payload)).expect("buffered writer should retain the full payload");
  assert_eq!(writer.unwritten(), payload.as_slice());
  assert_eq!(resources.snapshot().managed_memory, PIPE_WRITER_BYTES);

  let mut full_flush = Box::pin(writer.flush());
  assert!(poll_once(full_flush.as_mut()).is_pending());
  drop(full_flush);
  assert_eq!(accepted(&observation), 0);
  assert_eq!(writer.unwritten(), payload.as_slice());
  assert!(
    reactor_handle.waiters() > 0,
    "full pipe must retain a write waiter"
  );

  // Drain all bytes whose occupancy was witnessed by the one-byte fill. A
  // half-drain can leave a Linux pipe slot unavailable and keep the writer
  // asleep, so the first payload-progress wait starts only after the complete
  // filler prefix has been consumed in finite chunks.
  let mut filler_remaining = filled;
  while filler_remaining > 0 {
    let chunk_len = filler_remaining.min(PIPE_READ_CHUNK);
    let mut filler_chunk = vec![0_u8; chunk_len];
    read_exact_async(&mut registered_reader, &mut filler_chunk);
    assert!(filler_chunk.iter().all(|byte| *byte == b'f'));
    filler_remaining -= chunk_len;
  }

  let progress = match block_on(flush_until_progress(&mut writer, &observation, 0))
    .expect("writer should resume after the bounded complete filler drain")
  {
    FlushStep::PendingAfterProgress(accepted) => accepted,
    FlushStep::Complete(_) => panic!("less than a pipe buffer of drain cannot flush 1 MiB"),
  };
  assert!(progress > 0 && progress < payload.len());
  assert!(
    observation
      .lock()
      .expect("write observation lock is healthy")
      .events
      .iter()
      .any(|event| {
        matches!(
          event,
          WriterEvent::Write { offered, accepted }
            if *accepted > 0 && *accepted < *offered
        )
      }),
    "the real nonblocking endpoint must report partial write progress"
  );

  let (inner, buffer, unwritten) = writer.into_parts();
  assert_eq!(unwritten, progress..payload.len());
  let recovered_suffix = buffer.as_slice()[unwritten.clone()].to_vec();
  assert_eq!(recovered_suffix.as_slice(), &payload[progress..]);
  assert_eq!(buffer.charged_bytes(), PIPE_WRITER_BYTES);
  let mut writer = BufferedWriter::new(inner, buffer)
    .expect("returned endpoint and managed buffer should be recoverable");
  block_on(writer.write_all(&recovered_suffix))
    .expect("only the returned suffix should be resubmitted after cancellation");
  assert_eq!(writer.unwritten(), recovered_suffix.as_slice());

  let mut first_written = vec![0_u8; progress];
  read_exact_async(&mut registered_reader, &mut first_written);
  assert_eq!(first_written.as_slice(), &payload[..progress]);

  let mut sent = progress;
  for _ in 0..MAX_DRAIN_ROUNDS {
    let before = accepted(&observation);
    assert_eq!(
      before, sent,
      "accepted output and drained offset must agree"
    );
    match block_on(flush_until_progress(&mut writer, &observation, before))
      .expect("writer should keep progressing as the peer drains")
    {
      FlushStep::PendingAfterProgress(after) => {
        assert!(after > before && after < payload.len());
        let mut chunk = vec![0_u8; after - sent];
        read_exact_async(&mut registered_reader, &mut chunk);
        assert_eq!(chunk.as_slice(), &payload[sent..after]);
        sent = after;
      }
      FlushStep::Complete(after) => {
        assert_eq!(after, payload.len());
        if after > sent {
          let mut chunk = vec![0_u8; after - sent];
          read_exact_async(&mut registered_reader, &mut chunk);
          assert_eq!(chunk.as_slice(), &payload[sent..after]);
        }
        sent = after;
        break;
      }
    }
  }
  assert_eq!(
    sent,
    payload.len(),
    "finite peer drains must finish the recovered suffix"
  );
  assert!(writer.unwritten().is_empty());
  block_on(writer.shutdown()).expect("flush must precede write-side shutdown");
  let observation = observation
    .lock()
    .expect("write observation lock is healthy");
  assert!(observation.events.iter().all(|event| match event {
    WriterEvent::Write { accepted, .. } => *accepted > 0,
    WriterEvent::Flush(_) | WriterEvent::Shutdown(_) => true,
  }));
  assert!(observation.flush_at.len() >= 2);
  assert!(
    observation
      .flush_at
      .iter()
      .all(|accepted| *accepted == payload.len())
  );
  assert_eq!(observation.shutdown_at, [payload.len()]);
  assert!(observation.events.ends_with(&[
    WriterEvent::Flush(payload.len()),
    WriterEvent::Shutdown(payload.len()),
  ]));
  drop(observation);

  let mut eof = [0_u8; 1];
  assert_eq!(
    block_on(registered_reader.read(&mut eof)).expect("closed writer should produce EOF"),
    0
  );
  assert_eq!(resources.snapshot().managed_memory, PIPE_WRITER_BYTES);
  drop(writer);
  assert_eq!(resources.snapshot().managed_memory, 0);
  drop(registered_reader);
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(reactor_handle.waiters(), 0);
  reactor
    .shutdown()
    .expect("pipe registrations should be released");
}

#[derive(Default)]
struct GateState {
  released: bool,
}

struct Gate {
  state: Mutex<GateState>,
  changed: Condvar,
}

impl Gate {
  fn new() -> Self {
    Self {
      state: Mutex::new(GateState::default()),
      changed: Condvar::new(),
    }
  }

  fn release(&self) {
    let mut state = self.state.lock().expect("gate mutex is healthy");
    state.released = true;
    self.changed.notify_all();
  }

  fn wait(&self) -> io::Result<()> {
    let deadline = Instant::now() + BLOCKING_GATE_WAIT;
    let mut state = self.state.lock().expect("gate mutex is healthy");
    while !state.released {
      let now = Instant::now();
      if now >= deadline {
        return Err(io::Error::new(
          io::ErrorKind::TimedOut,
          "blocking writer gate expired",
        ));
      }
      let (next, timeout) = self
        .changed
        .wait_timeout(state, deadline.saturating_duration_since(now))
        .expect("gate condition variable is healthy");
      state = next;
      if timeout.timed_out() && !state.released {
        return Err(io::Error::new(
          io::ErrorKind::TimedOut,
          "blocking writer gate expired",
        ));
      }
    }
    Ok(())
  }
}

struct ReleaseGate(Arc<Gate>);

impl Drop for ReleaseGate {
  fn drop(&mut self) {
    self.0.release();
  }
}

#[derive(Default)]
struct BlockingWriteState {
  bytes: Vec<u8>,
  inputs: Vec<Vec<u8>>,
  accepted: Vec<usize>,
  calls: usize,
  flushes: usize,
}

struct CallGate {
  call: usize,
  gate: Arc<Gate>,
  started: Option<Sender<()>>,
}

struct GatePartialWriter {
  gates: Vec<CallGate>,
  state: Arc<Mutex<BlockingWriteState>>,
}

impl Write for GatePartialWriter {
  fn write(&mut self, input: &[u8]) -> io::Result<usize> {
    // Every submitted input is recorded before its gate, so a replayed call
    // appears as an extra entry even if it never commits a byte.
    let call = {
      let mut state = self.state.lock().expect("writer state mutex is healthy");
      state.inputs.push(input.to_vec());
      state.inputs.len()
    };
    if let Some(gated) = self.gates.iter_mut().find(|gated| gated.call == call)
      && let Some(started) = gated.started.take()
    {
      started
        .send(())
        .map_err(|_| io::Error::other("test observer disappeared"))?;
      gated.gate.wait()?;
    }
    let count = input.len().min(2);
    let mut state = self.state.lock().expect("writer state mutex is healthy");
    state.calls += 1;
    state.accepted.push(count);
    state.bytes.extend_from_slice(&input[..count]);
    Ok(count)
  }

  fn flush(&mut self) -> io::Result<()> {
    self
      .state
      .lock()
      .expect("writer state mutex is healthy")
      .flushes += 1;
    Ok(())
  }
}

#[test]
fn blocking_writer_cancellation_keeps_worker_permit_and_recovers_without_replay() {
  let request = Resources {
    disk: 1,
    ..Resources::ZERO
  };
  let mut runtime = blocking_runtime(1, request);
  let resources = resource_scope(8, 0);
  let gate = Arc::new(Gate::new());
  let _release_on_unwind = ReleaseGate(Arc::clone(&gate));
  let second_gate = Arc::new(Gate::new());
  let _release_second_on_unwind = ReleaseGate(Arc::clone(&second_gate));
  let (started_tx, started_rx) = mpsc::channel();
  let (second_started_tx, second_started_rx) = mpsc::channel();
  let state = Arc::new(Mutex::new(BlockingWriteState::default()));
  let stream = GatePartialWriter {
    gates: vec![
      CallGate {
        call: 1,
        gate: Arc::clone(&gate),
        started: Some(started_tx),
      },
      CallGate {
        call: 2,
        gate: Arc::clone(&second_gate),
        started: Some(second_started_tx),
      },
    ],
    state: Arc::clone(&state),
  };
  let buffer = managed(&resources, 8);
  let mut writer: BlockingWriter<GatePartialWriter> =
    blocking_io::writer(runtime.handle(), request, stream, buffer)
      .expect("caller-owned blocking writer should initialize");

  block_on(writer.write_all(b"abcdefg"))
    .expect("the adapter should accept bytes into its managed staging buffer");
  started_rx
    .recv_timeout(WAIT)
    .expect("the actual blocking worker call should reach the gate");
  let mut observer = Box::pin(writer.flush());
  assert!(poll_once(observer.as_mut()).is_pending());
  drop(observer);

  let held = runtime.snapshot();
  assert_eq!(held.outstanding, 1);
  assert_eq!(held.running, 1);
  assert_eq!(held.reserved.disk, request.disk);
  assert_eq!(resources.snapshot().managed_memory, 8);
  let observed = state.lock().expect("writer state mutex is healthy");
  assert!(observed.bytes.is_empty());
  assert!(observed.accepted.is_empty());
  assert_eq!(observed.inputs, [b"abcdefg".as_slice()]);
  drop(observed);
  assert!(matches!(
    second_started_rx.try_recv(),
    Err(TryRecvError::Empty)
  ));

  // Once released, the first call commits exactly `ab`; the fresh observer then
  // submits the second call, whose gate arrival is witnessed before cancel.
  gate.release();
  let mut second_observer = Box::pin(writer.flush());
  let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
  let mut context = Context::from_waker(&waker);
  let deadline = Instant::now() + WAIT;
  loop {
    match second_observer.as_mut().poll(&mut context) {
      Poll::Ready(_) => panic!("the gated second worker call must keep the flush pending"),
      Poll::Pending => match second_started_rx.try_recv() {
        Ok(()) => break,
        Err(TryRecvError::Empty) => {
          assert!(
            Instant::now() < deadline,
            "the second blocking worker call did not reach its gate in time"
          );
          thread::park_timeout(Duration::from_millis(2));
        }
        Err(TryRecvError::Disconnected) => {
          panic!("the second worker call dropped its gate announcer without arriving")
        }
      },
    }
  }
  drop(second_observer);

  let held = runtime.snapshot();
  assert_eq!(held.outstanding, 1);
  assert_eq!(held.running, 1);
  assert_eq!(held.reserved.disk, request.disk);
  assert_eq!(resources.snapshot().managed_memory, 8);
  let observed = state.lock().expect("writer state mutex is healthy");
  assert_eq!(observed.bytes.as_slice(), b"ab");
  assert_eq!(observed.accepted, [2]);
  assert_eq!(
    observed.inputs,
    [b"abcdefg".as_slice(), b"cdefg".as_slice()]
  );
  drop(observed);

  second_gate.release();
  block_on(writer.flush()).expect("a fresh observer should collect the completed worker result");
  let settled = runtime.snapshot();
  assert_eq!(settled.outstanding, 0);
  assert_eq!(settled.running, 0);
  assert_eq!(settled.reserved.disk, 0);
  assert_eq!(resources.snapshot().managed_memory, 8);
  block_on(writer.shutdown()).expect("shutdown should flush before completing");
  let observed = state.lock().expect("writer state mutex is healthy");
  assert_eq!(observed.bytes.as_slice(), b"abcdefg");
  assert_eq!(observed.accepted, [2, 2, 2, 1]);
  assert_eq!(
    observed.inputs,
    [
      b"abcdefg".as_slice(),
      b"cdefg".as_slice(),
      b"efg".as_slice(),
      b"g".as_slice()
    ],
    "neither cancelled worker call may be re-executed"
  );
  assert_eq!(
    observed.calls, 4,
    "partial worker calls must not replay any prefix"
  );
  assert!(observed.flushes >= 1);
  drop(observed);
  let settled = runtime.snapshot();
  assert_eq!(settled.outstanding, 0);
  assert_eq!(settled.running, 0);
  assert_eq!(settled.reserved.disk, 0);
  assert_eq!(
    resources.snapshot().managed_memory,
    8,
    "the writer remains the staging buffer's final owner"
  );
  drop(writer);
  assert_eq!(resources.snapshot().managed_memory, 0);
  runtime
    .shutdown(ShutdownMode::Drain)
    .expect("released worker should allow bounded runtime shutdown");
}

#[test]
fn pipe_registration_refusal_returns_original_fd_and_restores_flags() {
  let (reactor, reactor_handle) = reactor(1);
  let (dummy_reader, _dummy_writer) =
    std::io::pipe().expect("capacity-filling pipe should be created");
  let dummy = PipeReader::from_owned_fd(
    dummy_reader
      .as_fd()
      .try_clone_to_owned()
      .expect("dummy reader fd clone should be owned"),
    &reactor_handle,
  )
  .expect("first reader should consume the sole registration slot");
  assert_eq!(reactor_handle.registrations(), 1);

  let (target_reader, target_writer) = std::io::pipe().expect("target pipe should be created");
  let imported_fd = target_writer
    .as_fd()
    .try_clone_to_owned()
    .expect("target writer fd clone should be owned");
  let imported_fd_number = imported_fd.as_raw_fd();
  let refusal = match PipeWriter::from_owned_fd(imported_fd, &reactor_handle) {
    Err(error) => error,
    Ok(_) => panic!("the full reactor must refuse a second registration"),
  };
  assert_eq!(refusal.get_ref().as_raw_fd(), imported_fd_number);
  assert!(
    refusal.restoration_error().is_none(),
    "the import refusal must report successful status-flag rollback"
  );
  assert_eq!(reactor_handle.registrations(), 1);
  drop(dummy);
  assert_eq!(reactor_handle.registrations(), 0);

  let mut writer = PipeWriter::from_owned_fd(refusal.into_fd(), &reactor_handle)
    .expect("the returned original descriptor should import after capacity frees");
  block_on(writer.write_all(b"retained-fd"))
    .expect("the recovered descriptor should remain usable");
  block_on(writer.shutdown()).expect("recovered writer should close cleanly");
  drop(writer);
  drop(target_writer);

  let mut reader = PipeReader::from_owned_fd(
    target_reader
      .as_fd()
      .try_clone_to_owned()
      .expect("target reader fd clone should be owned"),
    &reactor_handle,
  )
  .expect("reader slot should be available after writer shutdown");
  drop(target_reader);
  let mut bytes = [0_u8; 32];
  read_exact_async(&mut reader, &mut bytes[..b"retained-fd".len()]);
  assert_eq!(&bytes[..b"retained-fd".len()], b"retained-fd");
  assert_eq!(
    block_on(reader.read(&mut bytes)).expect("closed target pipe should report EOF"),
    0
  );
  drop(reader);
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(reactor_handle.waiters(), 0);
  reactor
    .shutdown()
    .expect("all endpoint registrations should be removed");
}
