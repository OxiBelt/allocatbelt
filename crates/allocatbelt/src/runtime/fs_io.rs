//! Asynchronous traits over the bounded blocking filesystem API.
//!
//! [`AsyncFile`] owns one [`OwnedFile`](crate::runtime::fs::OwnedFile) and two
//! caller-sized [`ManagedBuf`](crate::runtime::managed::ManagedBuf) staging
//! buffers. Reads use bounded read-ahead; writes are accepted into the write
//! buffer and submitted to the blocking pool by flush, buffer pressure, seek,
//! read-after-write or shutdown. The buffers remain charged to their resource
//! scope for as long as this adapter or one of its admitted jobs owns them.
//!
//! Dropping an I/O future does not cancel or discard an admitted job. The
//! adapter retains it and its progress for the next poll. A blocking runtime
//! that cancels an admitted job before it starts is different: the runtime
//! drops the job's owned inputs, and the adapter becomes terminal because the
//! file and the buffer in that job cannot be recovered through the current
//! filesystem API. Polling then returns an explicit service error. Keep the
//! blocking runtime in drain mode while adapters are in use if those inputs
//! must remain available.
//!
//! Pool or disk-budget exhaustion rejects an operation before admission. The
//! rejected file and buffer are restored to the adapter, and the poll returns
//! `WouldBlock` with the typed submission reason as its error source. Retry
//! after capacity becomes available. This adapter uses no private worker or
//! unbounded queue.
//!
//! A read can fill the read buffer beyond the bytes returned to its caller.
//! Before writing or seeking relative to the current cursor, the adapter
//! compensates for unread read-ahead with an ordered seek. Writes preserve
//! their unsent suffix after partial progress or an I/O error; already-written
//! bytes are never replayed. `poll_shutdown` drains accepted writes, flushes,
//! then closes the owned file. Later polls return `BrokenPipe`.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::future::Future;
use std::io::{self, IoSliceMut, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::runtime::error::JoinError;
use crate::runtime::fs::{FileIoOutcome, FsHandle, FsSubmissionErrorKind, OwnedFile, SeekOutcome};
use crate::runtime::io::{AsyncRead, AsyncSeek, AsyncWrite};
use crate::runtime::job::Job;
use crate::runtime::managed::{ManagedBuf, ResourceError};

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;
  use crate::runtime::blocking::{Config, Runtime, ShutdownMode};
  use crate::runtime::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
  use crate::runtime::managed::{ResourceLimits, ResourceScope};
  use crate::runtime::resources::Resources;
  use std::fs::{self, OpenOptions};
  use std::future::Future;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicU64, Ordering};
  use std::sync::mpsc::{self, Receiver, Sender};
  use std::task::{Context, Poll, Wake, Waker};
  use std::thread;
  use std::time::Duration;

  static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

  struct Scratch(std::path::PathBuf);

  impl Scratch {
    fn new() -> Self {
      let id = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
      let path =
        std::env::temp_dir().join(format!("allocatbelt-fs-io-{}-{id}", std::process::id()));
      fs::create_dir(&path).unwrap();
      Self(path)
    }

    fn file(&self) -> std::path::PathBuf {
      self.0.join("data")
    }
  }

  impl Drop for Scratch {
    fn drop(&mut self) {
      let _ = fs::remove_dir_all(&self.0);
    }
  }

  fn runtime(max_outstanding: usize) -> Runtime {
    Runtime::new(Config {
      workers: 1,
      max_outstanding,
      capacity: Resources::ZERO,
    })
    .unwrap()
  }

  fn scope(read_capacity: usize, write_capacity: usize) -> ResourceScope {
    ResourceScope::new(ResourceLimits {
      managed_memory: read_capacity + write_capacity,
      disk_concurrent_ops: 4,
      network_concurrent_ops: 0,
    })
  }

  fn open_adapter(
    runtime: &Runtime,
    path: std::path::PathBuf,
    read_capacity: usize,
    write_capacity: usize,
  ) -> (ResourceScope, AsyncFile) {
    let scope = scope(read_capacity, write_capacity);
    let fs = FsHandle::new(runtime.handle(), scope.clone());
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    let file = fs.open(path, options).unwrap().join().unwrap().unwrap();
    let read = scope.try_alloc_zeroed(read_capacity).unwrap();
    let write = scope.try_alloc_zeroed(write_capacity).unwrap();
    (scope, AsyncFile::new(fs, file, read, write).unwrap())
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

  struct PanicOnDropWake {
    panic_on_drop: Arc<std::sync::atomic::AtomicBool>,
    wake_count: Arc<AtomicU64>,
  }

  impl Wake for PanicOnDropWake {
    fn wake(self: Arc<Self>) {
      self.wake_count.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.wake_count.fetch_add(1, Ordering::SeqCst);
    }
  }

  impl Drop for PanicOnDropWake {
    fn drop(&mut self) {
      if self.panic_on_drop.swap(false, Ordering::SeqCst) {
        panic!("injected waker destructor panic");
      }
    }
  }

  fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
      match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => return output,
        Poll::Pending => thread::park_timeout(Duration::from_secs(5)),
      }
    }
  }

  fn block_worker(runtime: &Runtime) -> (crate::runtime::Job<()>, Receiver<()>, Sender<()>) {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let job = runtime
      .try_spawn(Resources::ZERO, move |_| {
        started_tx.send(()).unwrap();
        let _ = release_rx.recv_timeout(Duration::from_secs(5));
      })
      .unwrap();
    (job, started_rx, release_tx)
  }

  #[test]
  fn real_file_read_ahead_is_rewound_before_write_and_current_seek() {
    let scratch = Scratch::new();
    let path = scratch.file();
    fs::write(&path, b"abcdef").unwrap();
    let mut runtime = runtime(16);
    let (_scope, mut file) = open_adapter(&runtime, path.clone(), 4, 3);

    let mut first = [0; 1];
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut first)).unwrap(),
      1
    );
    assert_eq!(&first, b"a");
    block_on(AsyncWriteExt::write_all(&mut file, b"XYZ")).unwrap();
    block_on(AsyncWriteExt::flush(&mut file)).unwrap();

    let position = block_on(AsyncSeekExt::seek(&mut file, SeekFrom::Start(0))).unwrap();
    assert_eq!(position, 0);
    let mut all = [0; 6];
    block_on(AsyncReadExt::read_exact(&mut file, &mut all)).unwrap();
    assert_eq!(&all, b"aXYZef");

    block_on(AsyncSeekExt::seek(&mut file, SeekFrom::Start(0))).unwrap();
    let mut first = [0; 1];
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut first)).unwrap(),
      1
    );
    assert_eq!(
      block_on(AsyncSeekExt::seek(&mut file, SeekFrom::Current(1))).unwrap(),
      2
    );
    let mut next = [0; 1];
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut next)).unwrap(),
      1
    );
    assert_eq!(&next, b"Y");

    block_on(AsyncSeekExt::seek(&mut file, SeekFrom::End(0))).unwrap();
    let mut eof = [0; 1];
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut eof)).unwrap(),
      0
    );
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut eof)).unwrap(),
      0
    );

    block_on(AsyncWriteExt::shutdown(&mut file)).unwrap();
    assert!(file.is_closed());
    let mut after_close = [0; 1];
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut after_close))
        .unwrap_err()
        .kind(),
      io::ErrorKind::BrokenPipe
    );
    assert_eq!(
      block_on(AsyncWriteExt::shutdown(&mut file))
        .unwrap_err()
        .kind(),
      io::ErrorKind::BrokenPipe
    );
    assert_eq!(fs::read(path).unwrap(), b"aXYZef");
    runtime.shutdown(ShutdownMode::Drain).unwrap();
  }

  #[test]
  fn read_after_staged_write_observes_the_updated_file_without_explicit_flush() {
    let scratch = Scratch::new();
    let path = scratch.file();
    fs::write(&path, b"abcdef").unwrap();
    let mut runtime = runtime(16);
    let (_scope, mut file) = open_adapter(&runtime, path.clone(), 8, 2);

    let mut first = [0; 1];
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut first)).unwrap(),
      1
    );
    assert_eq!(&first, b"a");
    assert_eq!(block_on(AsyncWriteExt::write(&mut file, b"XY")).unwrap(), 2);

    let mut next = [0; 1];
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut next)).unwrap(),
      1
    );
    assert_eq!(&next, b"d");
    block_on(AsyncWriteExt::shutdown(&mut file)).unwrap();
    assert_eq!(fs::read(path).unwrap(), b"aXYdef");
    runtime.shutdown(ShutdownMode::Drain).unwrap();
  }

  #[test]
  fn failed_read_ahead_rewind_preserves_bytes_for_retry() {
    let scratch = Scratch::new();
    let path = scratch.file();
    fs::write(&path, b"abcdef").unwrap();
    let mut runtime = runtime(16);
    let (_scope, mut file) = open_adapter(&runtime, path.clone(), 8, 2);
    let mut first = [0; 1];
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut first)).unwrap(),
      1
    );
    assert_eq!(block_on(AsyncWriteExt::write(&mut file, b"XY")).unwrap(), 2);

    let owned_file = file.file.take().unwrap();
    assert!(
      file
        .complete_active(ActiveResult::Seek(
          SeekOutcome {
            file: owned_file,
            position: Err(io::Error::other("injected rewind failure")),
          },
          CompletedSeekPurpose::RewindForWrite,
        ))
        .is_err()
    );
    assert_eq!(file.unread(), 5);

    let mut next = [0; 1];
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut next)).unwrap(),
      1
    );
    assert_eq!(&next, b"d");
    block_on(AsyncWriteExt::shutdown(&mut file)).unwrap();
    assert_eq!(fs::read(path).unwrap(), b"aXYdef");
    runtime.shutdown(ShutdownMode::Drain).unwrap();
  }

  #[test]
  fn failed_relative_user_seek_preserves_read_ahead() {
    let scratch = Scratch::new();
    let path = scratch.file();
    fs::write(&path, b"abcdef").unwrap();
    let mut runtime = runtime(16);
    let (_scope, mut file) = open_adapter(&runtime, path, 8, 2);
    let mut first = [0; 1];
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut first)).unwrap(),
      1
    );
    assert_eq!(&first, b"a");

    assert_eq!(
      block_on(AsyncSeekExt::seek(&mut file, SeekFrom::Current(-2)))
        .unwrap_err()
        .kind(),
      io::ErrorKind::InvalidInput
    );
    let mut next = [0; 1];
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut next)).unwrap(),
      1
    );
    assert_eq!(&next, b"b");
    block_on(AsyncWriteExt::shutdown(&mut file)).unwrap();
    runtime.shutdown(ShutdownMode::Drain).unwrap();
  }

  fn cancel_queued_io(write: bool) {
    let scratch = Scratch::new();
    let path = scratch.file();
    fs::write(&path, b"queued").unwrap();
    let mut runtime = runtime(2);
    let (scope, mut file) = open_adapter(&runtime, path, 4, 4);
    let (gate, started, release) = block_worker(&runtime);
    started.recv_timeout(Duration::from_secs(5)).unwrap();

    if write {
      assert_eq!(
        block_on(AsyncWriteExt::write(&mut file, b"sent")).unwrap(),
        4
      );
      let mut future = Box::pin(AsyncWriteExt::flush(&mut file));
      let mut cx = Context::from_waker(Waker::noop());
      assert!(future.as_mut().poll(&mut cx).is_pending());
    } else {
      let mut output = [0; 4];
      let mut future = Box::pin(AsyncReadExt::read(&mut file, &mut output));
      let mut cx = Context::from_waker(Waker::noop());
      assert!(future.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(scope.snapshot().disk_ops, 1);

    // The running gate and queued filesystem job fill the two-job bound.
    // Wait until shutdown has closed admission before releasing the worker,
    // so the filesystem closure is certainly canceled while still queued.
    let handle = runtime.handle();
    let release_after_close = release.clone();
    let close_observer = thread::spawn(move || {
      loop {
        match handle.try_spawn(Resources::ZERO, |_| ()) {
          Err(error) if error.kind() == crate::runtime::error::SubmitErrorKind::Closed => {
            release_after_close.send(()).unwrap();
            return;
          }
          Err(error) if error.kind() == crate::runtime::error::SubmitErrorKind::Full => {
            thread::yield_now();
          }
          other => panic!("unexpected probe submission before shutdown: {other:?}"),
        }
      }
    });
    runtime.shutdown(ShutdownMode::CancelPending).unwrap();
    close_observer.join().unwrap();
    gate.join().unwrap();

    let error = if write {
      block_on(AsyncWriteExt::flush(&mut file)).unwrap_err()
    } else {
      let mut output = [0; 4];
      block_on(AsyncReadExt::read(&mut file, &mut output)).unwrap_err()
    };
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert!(file.is_closed());
    drop(file);
    let snapshot = scope.snapshot();
    assert_eq!(snapshot.managed_memory, 0);
    assert_eq!(snapshot.disk_ops, 0);
  }

  #[test]
  fn cancel_pending_queued_read_and_write_close_and_release_adapter() {
    cancel_queued_io(false);
    cancel_queued_io(true);
  }

  #[test]
  fn shutdown_rejection_keeps_file_and_accepted_bytes_for_retry() {
    let scratch = Scratch::new();
    let path = scratch.file();
    let mut runtime = runtime(1);
    let (scope, mut file) = open_adapter(&runtime, path.clone(), 4, 4);
    assert_eq!(
      block_on(AsyncWriteExt::write(&mut file, b"kept")).unwrap(),
      4
    );
    let (gate, started, release) = block_worker(&runtime);
    started.recv_timeout(Duration::from_secs(5)).unwrap();

    let error = block_on(AsyncWriteExt::shutdown(&mut file)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(!file.is_closed());
    assert_eq!(file.write_len, 4);
    assert!(file.file.is_some());
    assert_eq!(scope.snapshot().disk_ops, 0);

    release.send(()).unwrap();
    gate.join().unwrap();
    block_on(AsyncWriteExt::shutdown(&mut file)).unwrap();
    assert!(file.is_closed());
    assert_eq!(fs::read(path).unwrap(), b"kept");
    assert_eq!(
      block_on(AsyncWriteExt::shutdown(&mut file))
        .unwrap_err()
        .kind(),
      io::ErrorKind::BrokenPipe
    );
    runtime.shutdown(ShutdownMode::Drain).unwrap();
  }

  #[test]
  fn canceled_read_future_keeps_the_admitted_job_and_its_buffer() {
    let scratch = Scratch::new();
    let path = scratch.file();
    fs::write(&path, b"retained").unwrap();
    let mut runtime = runtime(8);
    let (_scope, mut file) = open_adapter(&runtime, path, 4, 4);
    let (gate, started, release) = block_worker(&runtime);
    started.recv_timeout(Duration::from_secs(5)).unwrap();

    let mut output = [0; 4];
    let mut future = Box::pin(AsyncReadExt::read(&mut file, &mut output));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    drop(future);
    release.send(()).unwrap();
    gate.join().unwrap();

    let mut resumed = [0; 4];
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut resumed)).unwrap(),
      4
    );
    assert_eq!(&resumed, b"reta");
    runtime.shutdown(ShutdownMode::Drain).unwrap();
  }

  #[test]
  fn waker_drop_panic_keeps_the_admitted_job_attached_for_retry() {
    let scratch = Scratch::new();
    let path = scratch.file();
    fs::write(&path, b"data").unwrap();
    let mut runtime = runtime(2);
    let (scope, mut file) = open_adapter(&runtime, path, 4, 4);
    let (gate, started, release) = block_worker(&runtime);
    started.recv_timeout(Duration::from_secs(5)).unwrap();

    let panic_on_drop = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let wake_count = Arc::new(AtomicU64::new(0));
    let panic_waker = Waker::from(Arc::new(PanicOnDropWake {
      panic_on_drop,
      wake_count: Arc::clone(&wake_count),
    }));
    let mut panic_cx = Context::from_waker(&panic_waker);
    let mut output = [0; 4];
    assert!(
      Pin::new(&mut file)
        .poll_read(&mut panic_cx, &mut output)
        .is_pending()
    );
    drop(panic_waker);

    let normal_waker = Waker::noop();
    let mut normal_cx = Context::from_waker(normal_waker);
    let poll = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      Pin::new(&mut file).poll_read(&mut normal_cx, &mut output)
    }));
    assert!(poll.is_err());
    assert_eq!(wake_count.load(Ordering::SeqCst), 0);
    assert!(file.active.is_some());
    assert_eq!(scope.snapshot().disk_ops, 1);

    release.send(()).unwrap();
    gate.join().unwrap();
    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut output)).unwrap(),
      4
    );
    assert_eq!(&output, b"data");
    assert!(!file.is_closed());
    drop(file);
    let snapshot = scope.snapshot();
    assert_eq!(snapshot.managed_memory, 0);
    assert_eq!(snapshot.disk_ops, 0);
    runtime.shutdown(ShutdownMode::Drain).unwrap();
  }

  #[test]
  fn canceled_flush_preserves_staged_bytes_and_does_not_duplicate_them() {
    let scratch = Scratch::new();
    let path = scratch.file();
    let mut runtime = runtime(8);
    let (_scope, mut file) = open_adapter(&runtime, path.clone(), 4, 4);
    assert_eq!(
      block_on(AsyncWriteExt::write(&mut file, b"once")).unwrap(),
      4
    );

    let (gate, started, release) = block_worker(&runtime);
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut future = Box::pin(AsyncWriteExt::flush(&mut file));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    drop(future);
    release.send(()).unwrap();
    gate.join().unwrap();
    block_on(AsyncWriteExt::flush(&mut file)).unwrap();
    block_on(AsyncWriteExt::flush(&mut file)).unwrap();
    block_on(AsyncWriteExt::shutdown(&mut file)).unwrap();

    assert_eq!(fs::read(path).unwrap(), b"once");
    runtime.shutdown(ShutdownMode::Drain).unwrap();
  }

  #[test]
  fn full_pool_rejection_restores_file_and_read_buffer_for_retry() {
    let scratch = Scratch::new();
    let path = scratch.file();
    fs::write(&path, b"retry").unwrap();
    let mut runtime = runtime(1);
    let (scope, mut file) = open_adapter(&runtime, path, 4, 4);
    let (gate, started, release) = block_worker(&runtime);
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut output = [0; 2];
    let error = block_on(AsyncReadExt::read(&mut file, &mut output)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(
      error
        .get_ref()
        .and_then(|source| source.downcast_ref::<FsSubmissionErrorKind>())
        .is_some()
    );
    assert_eq!(scope.snapshot().disk_ops, 0);
    release.send(()).unwrap();
    gate.join().unwrap();

    assert_eq!(
      block_on(AsyncReadExt::read(&mut file, &mut output)).unwrap(),
      2
    );
    assert_eq!(&output, b"re");
    runtime.shutdown(ShutdownMode::Drain).unwrap();
  }

  #[test]
  fn partial_write_error_keeps_suffix_for_shutdown_retry() {
    let scratch = Scratch::new();
    let path = scratch.file();
    fs::write(&path, b"ab").unwrap();
    let mut runtime = runtime(8);
    let (_scope, mut file) = open_adapter(&runtime, path.clone(), 4, 4);
    assert_eq!(
      block_on(AsyncSeekExt::seek(&mut file, SeekFrom::End(0))).unwrap(),
      2
    );
    assert_eq!(
      block_on(AsyncWriteExt::write(&mut file, b"abcd")).unwrap(),
      4
    );

    let owned_file = file.file.take().unwrap();
    let mut buffer = file.write_buffer.take().unwrap();
    assert!(file.active.is_none());
    let storage = buffer.get_mut().unwrap();
    storage[..4].copy_from_slice(b"abcd");
    file.file = Some(owned_file);
    let owned_file = file.file.take().unwrap();
    assert!(
      file
        .complete_write(
          FileIoOutcome {
            file: owned_file,
            buffer,
            bytes: 2,
            error: Some(io::Error::other("injected partial error")),
          },
          4,
        )
        .is_err()
    );
    assert_eq!(file.write_len, 2);
    assert_eq!(&file.write_buffer.as_ref().unwrap()[..2], b"cd");
    assert!(!file.is_closed());
    block_on(AsyncWriteExt::shutdown(&mut file)).unwrap();
    assert!(file.is_closed());
    assert_eq!(fs::read(path).unwrap(), b"abcd");
    runtime.shutdown(ShutdownMode::Drain).unwrap();
  }
}

/// Why an [`AsyncFile`] could not be initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FsIoInitErrorKind {
  /// The read staging buffer must have nonzero capacity.
  EmptyReadBuffer,
  /// The write staging buffer must have nonzero capacity.
  EmptyWriteBuffer,
  /// The read staging buffer has another live clone.
  SharedReadBuffer,
  /// The write staging buffer has another live clone.
  SharedWriteBuffer,
}

impl std::fmt::Display for FsIoInitErrorKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(match self {
      Self::EmptyReadBuffer => "read staging buffer is empty",
      Self::EmptyWriteBuffer => "write staging buffer is empty",
      Self::SharedReadBuffer => "read staging buffer is shared",
      Self::SharedWriteBuffer => "write staging buffer is shared",
    })
  }
}

impl std::error::Error for FsIoInitErrorKind {}

/// Initialization failure with every original input returned unchanged.
pub struct FsIoInitError {
  /// Why the buffers could not be used for staging.
  pub kind: FsIoInitErrorKind,
  /// The filesystem handle supplied to [`AsyncFile::new`].
  pub fs: FsHandle,
  /// The file supplied to [`AsyncFile::new`].
  pub file: OwnedFile,
  /// The read buffer supplied to [`AsyncFile::new`].
  pub read_buffer: ManagedBuf,
  /// The write buffer supplied to [`AsyncFile::new`].
  pub write_buffer: ManagedBuf,
}

impl std::fmt::Debug for FsIoInitError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("FsIoInitError")
      .field("kind", &self.kind)
      .field("read_buffer", &self.read_buffer)
      .field("write_buffer", &self.write_buffer)
      .finish_non_exhaustive()
  }
}

impl std::fmt::Display for FsIoInitError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    self.kind.fmt(f)
  }
}

impl std::error::Error for FsIoInitError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceFailure {
  Cancelled,
  Panicked,
  WouldDeadlock,
}

impl std::fmt::Display for ServiceFailure {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(match self {
      Self::Cancelled => "blocking filesystem operation was cancelled before it started",
      Self::Panicked => "blocking filesystem operation panicked",
      Self::WouldDeadlock => "blocking filesystem job could not be joined from its worker",
    })
  }
}

impl std::error::Error for ServiceFailure {}

fn service_failure(error: JoinError) -> io::Error {
  let failure = match error {
    JoinError::Cancelled => ServiceFailure::Cancelled,
    JoinError::Panicked(_) => ServiceFailure::Panicked,
    JoinError::WouldDeadlock => ServiceFailure::WouldDeadlock,
  };
  io::Error::new(io::ErrorKind::BrokenPipe, failure)
}

fn submission_error(error: FsSubmissionErrorKind) -> io::Error {
  let kind = match error {
    FsSubmissionErrorKind::Runtime(
      crate::runtime::error::SubmitErrorKind::Full
      | crate::runtime::error::SubmitErrorKind::InsufficientResources,
    )
    | FsSubmissionErrorKind::Resource(ResourceError::Exhausted(_)) => io::ErrorKind::WouldBlock,
    FsSubmissionErrorKind::Runtime(crate::runtime::error::SubmitErrorKind::Closed) => {
      io::ErrorKind::BrokenPipe
    }
    FsSubmissionErrorKind::Runtime(crate::runtime::error::SubmitErrorKind::InvalidRequest)
    | FsSubmissionErrorKind::Resource(ResourceError::Invalid(_))
    | FsSubmissionErrorKind::Resource(ResourceError::OutOfMemory)
    | FsSubmissionErrorKind::Resource(ResourceError::Shared) => io::ErrorKind::Other,
  };
  io::Error::new(kind, error)
}

enum SeekPurpose {
  RewindForWrite,
  User(SeekFrom),
}

enum ActiveJob {
  Read(Job<FileIoOutcome>),
  Write {
    job: Job<FileIoOutcome>,
    requested: usize,
  },
  Flush(Job<(OwnedFile, io::Result<()>)>),
  Seek {
    job: Job<SeekOutcome>,
    purpose: SeekPurpose,
  },
}

/// An owned file implementing the runtime-neutral asynchronous I/O traits.
///
/// The two staging buffers must be uniquely owned and nonempty. Their lengths
/// bound read-ahead and accepted-but-not-yet-written data. A buffer can be
/// allocated with [`ResourceScope::try_alloc_zeroed`](
/// crate::runtime::managed::ResourceScope::try_alloc_zeroed); the adapter does
/// not grow or allocate staging storage itself.
pub struct AsyncFile {
  fs: FsHandle,
  file: Option<OwnedFile>,
  read_buffer: Option<ManagedBuf>,
  read_capacity: usize,
  read_start: usize,
  read_end: usize,
  read_error: Option<io::Error>,
  read_eof: bool,
  write_buffer: Option<ManagedBuf>,
  write_capacity: usize,
  write_len: usize,
  active: Option<ActiveJob>,
  completed_seek: Option<(SeekFrom, u64)>,
  last_flush: Option<io::Result<()>>,
  shutdown_requested: bool,
  closed: bool,
}

impl AsyncFile {
  /// Wraps an owned file and the caller's fixed, managed staging buffers.
  ///
  /// The adapter takes ownership of every input. If either buffer is empty
  /// or shared, the returned error contains the exact original values.
  pub fn new(
    fs: FsHandle,
    file: OwnedFile,
    mut read_buffer: ManagedBuf,
    mut write_buffer: ManagedBuf,
  ) -> Result<Self, FsIoInitError> {
    let invalid = if read_buffer.is_empty() {
      Some(FsIoInitErrorKind::EmptyReadBuffer)
    } else if write_buffer.is_empty() {
      Some(FsIoInitErrorKind::EmptyWriteBuffer)
    } else if read_buffer.get_mut().is_none() {
      Some(FsIoInitErrorKind::SharedReadBuffer)
    } else if write_buffer.get_mut().is_none() {
      Some(FsIoInitErrorKind::SharedWriteBuffer)
    } else {
      None
    };
    if let Some(kind) = invalid {
      return Err(FsIoInitError {
        kind,
        fs,
        file,
        read_buffer,
        write_buffer,
      });
    }
    let read_capacity = read_buffer.len();
    let write_capacity = write_buffer.len();
    Ok(Self {
      fs,
      file: Some(file),
      read_buffer: Some(read_buffer),
      read_capacity,
      read_start: 0,
      read_end: 0,
      read_error: None,
      read_eof: false,
      write_buffer: Some(write_buffer),
      write_capacity,
      write_len: 0,
      active: None,
      completed_seek: None,
      last_flush: None,
      shutdown_requested: false,
      closed: false,
    })
  }

  /// Whether `poll_shutdown` has completed and closed the file.
  #[must_use]
  pub const fn is_closed(&self) -> bool {
    self.closed
  }

  fn broken_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "asynchronous file is closed")
  }

  fn unavailable() -> io::Error {
    io::Error::other("asynchronous file staging state is unavailable")
  }

  fn unread(&self) -> usize {
    self.read_end.saturating_sub(self.read_start)
  }

  fn invalidate_read_ahead(&mut self) {
    self.read_start = 0;
    self.read_end = 0;
    self.read_error = None;
    self.read_eof = false;
  }

  fn start_read(&mut self) -> io::Result<()> {
    let Some(file) = self.file.take() else {
      return Err(Self::unavailable());
    };
    let Some(buffer) = self.read_buffer.take() else {
      self.file = Some(file);
      return Err(Self::unavailable());
    };
    match self.fs.read(file, buffer) {
      Ok(job) => {
        self.active = Some(ActiveJob::Read(job));
        self.read_start = 0;
        self.read_end = 0;
        self.read_error = None;
        self.read_eof = false;
        Ok(())
      }
      Err(error) => {
        let kind = error.kind;
        let (file, buffer) = error.into_input();
        self.file = Some(file);
        self.read_buffer = Some(buffer);
        Err(submission_error(kind))
      }
    }
  }

  fn start_write(&mut self) -> io::Result<()> {
    if self.write_len == 0 {
      return Ok(());
    }
    let Some(file) = self.file.take() else {
      return Err(Self::unavailable());
    };
    let Some(mut buffer) = self.write_buffer.take() else {
      self.file = Some(file);
      return Err(Self::unavailable());
    };
    if let Err(error) = buffer.try_resize(self.write_len) {
      self.file = Some(file);
      self.write_buffer = Some(buffer);
      return Err(io::Error::other(error));
    }
    let requested = self.write_len;
    match self.fs.write(file, buffer) {
      Ok(job) => {
        self.active = Some(ActiveJob::Write { job, requested });
        self.write_buffer = None;
        self.read_eof = false;
        Ok(())
      }
      Err(error) => {
        let kind = error.kind;
        let (file, mut buffer) = error.into_input();
        self.file = Some(file);
        if let Err(resize_error) = buffer.try_resize(self.write_capacity) {
          self.write_buffer = Some(buffer);
          return Err(io::Error::other(resize_error));
        }
        self.write_buffer = Some(buffer);
        Err(submission_error(kind))
      }
    }
  }

  fn start_flush(&mut self) -> io::Result<()> {
    let Some(file) = self.file.take() else {
      return Err(Self::unavailable());
    };
    match self.fs.flush(file) {
      Ok(job) => {
        self.active = Some(ActiveJob::Flush(job));
        self.last_flush = None;
        Ok(())
      }
      Err(error) => {
        let kind = error.kind;
        self.file = Some(error.into_input());
        Err(submission_error(kind))
      }
    }
  }

  fn start_seek(&mut self, target: SeekFrom, purpose: SeekPurpose) -> io::Result<()> {
    let Some(file) = self.file.take() else {
      return Err(Self::unavailable());
    };
    match self.fs.seek(file, target) {
      Ok(job) => {
        self.active = Some(ActiveJob::Seek { job, purpose });
        self.last_flush = None;
        Ok(())
      }
      Err(error) => {
        let kind = error.kind;
        let (file, _target) = error.into_input();
        self.file = Some(file);
        Err(submission_error(kind))
      }
    }
  }

  fn poll_active(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let Some(active) = self.active.as_mut() else {
      return Poll::Ready(Ok(()));
    };
    let result = match active {
      ActiveJob::Read(job) => Pin::new(job)
        .poll(cx)
        .map(|result| result.map(ActiveResult::Read)),
      ActiveJob::Write { job, requested } => Pin::new(job)
        .poll(cx)
        .map(|result| result.map(|outcome| ActiveResult::Write(outcome, *requested))),
      ActiveJob::Flush(job) => Pin::new(job)
        .poll(cx)
        .map(|result| result.map(ActiveResult::Flush)),
      ActiveJob::Seek { job, purpose } => {
        let purpose = match purpose {
          SeekPurpose::RewindForWrite => CompletedSeekPurpose::RewindForWrite,
          SeekPurpose::User(position) => CompletedSeekPurpose::User(*position),
        };
        Pin::new(job)
          .poll(cx)
          .map(|result| result.map(|outcome| ActiveResult::Seek(outcome, purpose)))
      }
    };
    match result {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Err(error)) => {
        // Keep the job in `self.active` for the entire poll. A user supplied
        // waker can panic while Job replaces and drops its previously stored
        // waker; taking the job first would unwind-drop it and detach its
        // owned file and managed buffer from this adapter.
        self.active.take();
        self.closed = true;
        self.file = None;
        self.read_buffer = None;
        self.write_buffer = None;
        self.read_start = 0;
        self.read_end = 0;
        self.write_len = 0;
        self.active = None;
        Poll::Ready(Err(service_failure(error)))
      }
      Poll::Ready(Ok(result)) => {
        self.active.take();
        Poll::Ready(self.complete_active(result))
      }
    }
  }

  fn complete_active(&mut self, result: ActiveResult) -> io::Result<()> {
    match result {
      ActiveResult::Read(outcome) => self.complete_read(outcome),
      ActiveResult::Write(outcome, requested) => self.complete_write(outcome, requested),
      ActiveResult::Flush((file, result)) => {
        self.file = Some(file);
        self.last_flush = Some(result);
        Ok(())
      }
      ActiveResult::Seek(outcome, purpose) => {
        self.file = Some(outcome.file);
        match purpose {
          CompletedSeekPurpose::RewindForWrite => match outcome.position {
            Ok(_) => {
              self.invalidate_read_ahead();
              Ok(())
            }
            Err(error) => Err(error),
          },
          CompletedSeekPurpose::User(original) => match outcome.position {
            Ok(position) => {
              self.invalidate_read_ahead();
              self.completed_seek = Some((original, position));
              Ok(())
            }
            Err(error) => Err(error),
          },
        }
      }
    }
  }

  fn complete_read(&mut self, outcome: FileIoOutcome) -> io::Result<()> {
    if outcome.bytes > self.read_capacity {
      self.closed = true;
      self.file = None;
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "filesystem read exceeded its managed staging buffer",
      ));
    }
    self.file = Some(outcome.file);
    self.read_buffer = Some(outcome.buffer);
    self.read_start = 0;
    self.read_end = outcome.bytes;
    self.read_error = outcome.error;
    self.read_eof = outcome.bytes == 0 && self.read_error.is_none();
    Ok(())
  }

  fn complete_write(&mut self, outcome: FileIoOutcome, requested: usize) -> io::Result<()> {
    if outcome.bytes > requested || outcome.buffer.len() != requested {
      self.closed = true;
      self.file = None;
      self.write_buffer = Some(outcome.buffer);
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "filesystem write returned invalid progress",
      ));
    }
    self.file = Some(outcome.file);
    let mut buffer = outcome.buffer;
    if let Some(storage) = buffer.get_mut() {
      storage.copy_within(outcome.bytes..requested, 0);
    } else {
      self.write_buffer = Some(buffer);
      self.closed = true;
      return Err(io::Error::other("managed write buffer became shared"));
    }
    if let Err(error) = buffer.try_resize(self.write_capacity) {
      self.write_buffer = Some(buffer);
      self.closed = true;
      self.file = None;
      return Err(io::Error::other(error));
    }
    self.write_len = requested - outcome.bytes;
    self.write_buffer = Some(buffer);
    self.read_eof = false;
    if let Some(error) = outcome.error {
      return Err(error);
    }
    if outcome.bytes != requested {
      return Err(io::Error::new(
        io::ErrorKind::WriteZero,
        "filesystem write made incomplete progress without an error",
      ));
    }
    Ok(())
  }

  fn poll_advance(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    match self.poll_active(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
    }
  }

  /// Drains accepted write bytes. If read-ahead exists, first restores the
  /// logical cursor (physical cursor minus unread staged bytes).
  fn poll_drain_writes(
    &mut self,
    cx: &mut Context<'_>,
    keep_flush_result: bool,
  ) -> Poll<io::Result<()>> {
    loop {
      if self.active.is_some() {
        match self.poll_advance(cx) {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
          Poll::Ready(Ok(())) => {}
        }
      }
      if self.write_len == 0 {
        if !keep_flush_result && let Some(result) = self.last_flush.take() {
          return Poll::Ready(result);
        }
        return Poll::Ready(Ok(()));
      }
      if let Some(result) = self.last_flush.take()
        && let Err(error) = result
      {
        return Poll::Ready(Err(error));
      }
      let unread = self.unread();
      if unread != 0 {
        let Ok(unread) = i64::try_from(unread) else {
          return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unread read-ahead exceeds a relative seek offset",
          )));
        };
        if let Err(error) = self.start_seek(SeekFrom::Current(-unread), SeekPurpose::RewindForWrite)
        {
          return Poll::Ready(Err(error));
        }
        continue;
      }
      if let Err(error) = self.start_write() {
        return Poll::Ready(Err(error));
      }
    }
  }

  fn poll_finish_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    match self.poll_drain_writes(cx, true) {
      Poll::Pending => return Poll::Pending,
      Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
      Poll::Ready(Ok(())) => {}
    }
    if let Some(result) = self.last_flush.take() {
      return Poll::Ready(result);
    }
    if let Err(error) = self.start_flush() {
      return Poll::Ready(Err(error));
    }
    loop {
      match self.poll_advance(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        Poll::Ready(Ok(())) => {}
      }
      if let Some(result) = self.last_flush.take() {
        return Poll::Ready(result);
      }
    }
  }

  fn take_completed_seek(&mut self, requested: SeekFrom) -> Option<u64> {
    match self.completed_seek.take() {
      Some((original, position)) if original == requested => Some(position),
      _ => None,
    }
  }

  fn adjusted_seek(&self, requested: SeekFrom) -> io::Result<SeekFrom> {
    let unread = self.unread();
    match requested {
      SeekFrom::Current(offset) if unread != 0 => {
        let unread = i64::try_from(unread).map_err(|_| {
          io::Error::new(
            io::ErrorKind::InvalidInput,
            "unread read-ahead exceeds a relative seek offset",
          )
        })?;
        offset
          .checked_sub(unread)
          .map(SeekFrom::Current)
          .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "relative seek offset overflow")
          })
      }
      _ => Ok(requested),
    }
  }
}

enum ActiveResult {
  Read(FileIoOutcome),
  Write(FileIoOutcome, usize),
  Flush((OwnedFile, io::Result<()>)),
  Seek(SeekOutcome, CompletedSeekPurpose),
}

enum CompletedSeekPurpose {
  RewindForWrite,
  User(SeekFrom),
}

impl std::fmt::Debug for AsyncFile {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("AsyncFile")
      .field("read_capacity", &self.read_capacity)
      .field("read_available", &self.unread())
      .field("write_capacity", &self.write_capacity)
      .field("write_buffered", &self.write_len)
      .field("operation_pending", &self.active.is_some())
      .field("closed", &self.closed)
      .finish()
  }
}

impl AsyncRead for AsyncFile {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    if this.closed || this.shutdown_requested {
      return Poll::Ready(Err(Self::broken_pipe()));
    }
    if buf.is_empty() {
      return Poll::Ready(Ok(0));
    }
    loop {
      // Complete admitted cursor operations and accepted writes before
      // returning bytes from older read-ahead. A write may have replaced
      // those bytes in the file while they were still buffered here.
      if this.active.is_some() || this.write_len != 0 {
        match this.poll_drain_writes(cx, false) {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
          Poll::Ready(Ok(())) => continue,
        }
      }
      if this.unread() != 0 {
        let count = this.unread().min(buf.len());
        let Some(buffer) = this.read_buffer.as_ref() else {
          return Poll::Ready(Err(Self::unavailable()));
        };
        buf[..count].copy_from_slice(&buffer[this.read_start..this.read_start + count]);
        this.read_start += count;
        return Poll::Ready(Ok(count));
      }
      if let Some(error) = this.read_error.take() {
        return Poll::Ready(Err(error));
      }
      if let Some((_, position)) = this.completed_seek.take() {
        let _ = position;
      }
      if this.read_eof && this.write_len == 0 && this.active.is_none() {
        return Poll::Ready(Ok(0));
      }
      if this.read_eof {
        return Poll::Ready(Ok(0));
      }
      if let Err(error) = this.start_read() {
        return Poll::Ready(Err(error));
      }
    }
  }

  fn poll_read_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &mut [IoSliceMut<'_>],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    if let Some(buffer) = bufs.iter_mut().find(|buffer| !buffer.is_empty()) {
      this.as_pin_mut().poll_read(cx, buffer)
    } else {
      this.as_pin_mut().poll_read(cx, &mut [])
    }
  }
}

impl AsyncFile {
  fn as_pin_mut(&mut self) -> Pin<&mut Self> {
    Pin::new(self)
  }
}

impl AsyncWrite for AsyncFile {
  fn poll_write(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    if this.closed || this.shutdown_requested {
      return Poll::Ready(Err(Self::broken_pipe()));
    }
    if let Some((_, position)) = this.completed_seek.take() {
      let _ = position;
    }
    if let Some(result) = this.last_flush.take()
      && let Err(error) = result
    {
      return Poll::Ready(Err(error));
    }
    if buf.is_empty() {
      return Poll::Ready(Ok(0));
    }
    if this.write_buffer.is_none() {
      return match this.poll_drain_writes(_cx, false) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Ready(Ok(())) => this.as_pin_mut().poll_write(_cx, buf),
      };
    }
    let Some(buffer) = this.write_buffer.as_mut() else {
      return Poll::Ready(Err(Self::unavailable()));
    };
    let available = this.write_capacity.saturating_sub(this.write_len);
    if available == 0 {
      return match this.poll_drain_writes(_cx, false) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Ready(Ok(())) => this.as_pin_mut().poll_write(_cx, buf),
      };
    }
    let count = available.min(buf.len());
    let Some(storage) = buffer.get_mut() else {
      return Poll::Ready(Err(io::Error::other("managed write buffer became shared")));
    };
    storage[this.write_len..this.write_len + count].copy_from_slice(&buf[..count]);
    this.write_len += count;
    this.last_flush = None;
    this.read_eof = false;
    Poll::Ready(Ok(count))
  }

  fn is_write_vectored(&self) -> bool {
    false
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    if this.closed || this.shutdown_requested {
      return Poll::Ready(Err(Self::broken_pipe()));
    }
    if let Some((_, position)) = this.completed_seek.take() {
      let _ = position;
    }
    this.poll_finish_flush(cx)
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    if this.closed {
      return match this.last_flush.take() {
        Some(result) => Poll::Ready(result),
        None => Poll::Ready(Err(Self::broken_pipe())),
      };
    }
    this.shutdown_requested = true;
    match this.poll_finish_flush(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(result) => {
        if result.is_ok() && !this.closed {
          this.file = None;
          this.closed = true;
        }
        Poll::Ready(result)
      }
    }
  }
}

impl AsyncSeek for AsyncFile {
  fn poll_seek(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    position: SeekFrom,
  ) -> Poll<io::Result<u64>> {
    let this = self.get_mut();
    if this.closed || this.shutdown_requested {
      return Poll::Ready(Err(Self::broken_pipe()));
    }
    if let Some(position) = this.take_completed_seek(position) {
      return Poll::Ready(Ok(position));
    }
    match this.poll_drain_writes(cx, false) {
      Poll::Pending => return Poll::Pending,
      Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
      Poll::Ready(Ok(())) => {}
    }
    if let Some(position_result) = this.take_completed_seek(position) {
      return Poll::Ready(Ok(position_result));
    }
    let actual = match this.adjusted_seek(position) {
      Ok(actual) => actual,
      Err(error) => return Poll::Ready(Err(error)),
    };
    if let Err(error) = this.start_seek(actual, SeekPurpose::User(position)) {
      return Poll::Ready(Err(error));
    }
    loop {
      match this.poll_advance(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        Poll::Ready(Ok(())) => {}
      }
      if let Some(position) = this.take_completed_seek(position) {
        return Poll::Ready(Ok(position));
      }
      if this.active.is_none() {
        return Poll::Ready(Err(Self::unavailable()));
      }
    }
  }
}
