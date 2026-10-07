use super::{FifoOpenError, FifoOpenOptions, FsHandle};
use crate::runtime::JoinError;
use crate::runtime::blocking::{Config, Runtime, ShutdownMode};
use crate::runtime::fs::FsSubmissionErrorKind;
use crate::runtime::io::{AsyncReadExt, AsyncWriteExt};
use crate::runtime::managed::{ResourceLimits, ResourceScope};
use crate::runtime::reactor::{Reactor, ReactorConfig};
use crate::runtime::resources::Resources;
use rustix::fs::{OFlags, fcntl_getfl};
use rustix::io::{FdFlags, fcntl_getfd};
use std::future::Future;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::task::{Context, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(8);
static NEXT_DIR: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);

impl Scratch {
  fn new() -> Self {
    let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("allocatbelt-fifo-{}-{id}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    Self(path)
  }

  fn child(&self, name: &str) -> PathBuf {
    self.0.join(name)
  }
}

impl Drop for Scratch {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.0);
  }
}

struct UnparkWaker(thread::Thread);

impl Wake for UnparkWaker {
  fn wake(self: Arc<Self>) {
    self.0.unpark();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.unpark();
  }
}

fn block_on<F: Future>(future: F) -> F::Output {
  let waker = Waker::from(Arc::new(UnparkWaker(thread::current())));
  let mut context = Context::from_waker(&waker);
  let mut future = pin!(future);
  let deadline = Instant::now() + TIMEOUT;
  loop {
    match future.as_mut().poll(&mut context) {
      std::task::Poll::Ready(output) => return output,
      std::task::Poll::Pending => {
        assert!(Instant::now() < deadline, "FIFO I/O timed out");
        thread::park_timeout(Duration::from_millis(5));
      }
    }
  }
}

fn runtime(workers: usize, max_outstanding: usize) -> Runtime {
  Runtime::new(Config {
    workers,
    max_outstanding,
    capacity: Resources::ZERO,
  })
  .unwrap()
}

fn scope(disk: usize) -> ResourceScope {
  ResourceScope::new(ResourceLimits {
    managed_memory: 0,
    disk_concurrent_ops: disk,
    network_concurrent_ops: 0,
  })
}

fn reactor(max_registrations: usize) -> (Reactor, crate::runtime::reactor::ReactorHandle) {
  let reactor = Reactor::new(ReactorConfig {
    max_registrations,
    max_waiters: 8,
  })
  .unwrap();
  let handle = reactor.handle();
  (reactor, handle)
}

#[test]
fn create_fifo_open_transfer_and_close_writer() {
  let scratch = Scratch::new();
  let path = scratch.child("stream");
  let mut runtime = runtime(2, 8);
  let scope = scope(4);
  let filesystem = FsHandle::new(runtime.handle(), scope.clone());
  let (_reactor, reactor) = reactor(4);

  filesystem
    .create_fifo(path.clone(), 0o640)
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let metadata = std::fs::symlink_metadata(&path).unwrap();
  assert!(metadata.file_type().is_fifo());
  assert_eq!(metadata.permissions().mode() & 0o777 & !0o640, 0);
  let duplicate = filesystem
    .create_fifo(path.clone(), 0o600)
    .unwrap()
    .join()
    .unwrap();
  assert_eq!(duplicate.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
  assert!(
    std::fs::symlink_metadata(&path)
      .unwrap()
      .file_type()
      .is_fifo()
  );

  let mut reader = filesystem
    .open_fifo_receiver(path.clone(), FifoOpenOptions::new(), &reactor)
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let mut writer = filesystem
    .open_fifo_sender(path.clone(), FifoOpenOptions::new(), &reactor)
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  assert!(
    fcntl_getfl(reader.get_ref())
      .unwrap()
      .contains(OFlags::NONBLOCK)
  );
  assert!(
    fcntl_getfl(writer.get_ref().unwrap())
      .unwrap()
      .contains(OFlags::NONBLOCK)
  );
  assert!(
    fcntl_getfd(reader.get_ref())
      .unwrap()
      .contains(FdFlags::CLOEXEC)
  );
  assert!(
    fcntl_getfd(writer.get_ref().unwrap())
      .unwrap()
      .contains(FdFlags::CLOEXEC)
  );

  assert_eq!(block_on(writer.write(b"fifo-data")).unwrap(), 9);
  let mut bytes = [0; 32];
  let read = block_on(reader.read(&mut bytes)).unwrap();
  assert_eq!(&bytes[..read], b"fifo-data");
  block_on(writer.shutdown()).unwrap();
  assert_eq!(block_on(reader.read(&mut bytes)).unwrap(), 0);
  assert_eq!(scope.snapshot().disk_ops, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn default_reader_can_receive_data_after_initial_eof() {
  let scratch = Scratch::new();
  let path = scratch.child("late-writer");
  let mut runtime = runtime(2, 8);
  let filesystem = FsHandle::new(runtime.handle(), scope(4));
  let (_reactor, reactor) = reactor(2);

  filesystem
    .create_fifo(path.clone(), 0o600)
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let mut reader = filesystem
    .open_fifo_receiver(path.clone(), FifoOpenOptions::new(), &reactor)
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let mut bytes = [0; 16];

  // Linux reports a FIFO read with no writers as EOF, but does not provide an
  // epoll readiness event for that state before the first writer has opened.
  // Observe that syscall result directly, then verify the registered async
  // endpoint remains usable when a writer arrives later.
  assert_eq!(rustix::io::read(reader.get_ref(), &mut bytes).unwrap(), 0);

  let mut writer = filesystem
    .open_fifo_sender(path, FifoOpenOptions::new(), &reactor)
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  assert_eq!(block_on(writer.write(b"late-data")).unwrap(), 9);
  let read = block_on(reader.read(&mut bytes)).unwrap();
  assert_eq!(&bytes[..read], b"late-data");

  block_on(writer.shutdown()).unwrap();
  assert_eq!(block_on(reader.read(&mut bytes)).unwrap(), 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn sender_without_reader_reports_enxio_and_linux_read_write_mode_self_peers() {
  let scratch = Scratch::new();
  let path = scratch.child("stream");
  let mut runtime = runtime(2, 8);
  let filesystem = FsHandle::new(runtime.handle(), scope(4));
  let (_reactor, reactor) = reactor(4);
  filesystem
    .create_fifo(path.clone(), 0o600)
    .unwrap()
    .join()
    .unwrap()
    .unwrap();

  let result = filesystem
    .open_fifo_sender(path.clone(), FifoOpenOptions::new(), &reactor)
    .unwrap()
    .join()
    .unwrap();
  let error = match result {
    Err(error) => error,
    Ok(_) => panic!("writer opened without a reader"),
  };
  match error {
    FifoOpenError::Open(error) => assert_eq!(
      error.raw_os_error(),
      Some(rustix::io::Errno::NXIO.raw_os_error())
    ),
    FifoOpenError::Import(error) => panic!("unexpected import error: {error}"),
  }

  let mut reader = filesystem
    .open_fifo_receiver(
      path.clone(),
      FifoOpenOptions::new().read_write(true),
      &reactor,
    )
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let mut writer = filesystem
    .open_fifo_sender(path, FifoOpenOptions::new().read_write(true), &reactor)
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  assert_eq!(block_on(writer.write(b"self-peer")).unwrap(), 9);
  let mut bytes = [0; 16];
  let read = block_on(reader.read(&mut bytes)).unwrap();
  assert_eq!(&bytes[..read], b"self-peer");
  drop(writer);
  drop(reader);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn invalid_mode_and_disk_rejection_return_the_exact_path_without_creation() {
  let scratch = Scratch::new();
  let mut runtime_initial = runtime(1, 4);
  let no_disk = scope(0);
  let filesystem = FsHandle::new(runtime_initial.handle(), no_disk.clone());

  let path = scratch.child("bad-mode");
  let error = filesystem.create_fifo(path.clone(), 0x1_0000).unwrap_err();
  assert_eq!(error.kind, FsSubmissionErrorKind::InvalidInput);
  let (returned, mode) = error.into_input();
  assert_eq!(returned, path);
  assert_eq!(mode, 0x1_0000);
  assert!(!returned.exists());

  let path = scratch.child("disk-full");
  let error = filesystem.create_fifo(path.clone(), 0o600).unwrap_err();
  assert!(matches!(error.kind, FsSubmissionErrorKind::Resource(_)));
  let (returned, mode) = error.into_input();
  assert_eq!(returned, path);
  assert_eq!(mode, 0o600);
  assert!(!returned.exists());
  assert_eq!(no_disk.snapshot().disk_ops, 0);
  runtime_initial.shutdown(ShutdownMode::Drain).unwrap();

  let mut runtime_with_full_queue = runtime(1, 1);
  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let blocker = runtime_with_full_queue
    .try_spawn(Resources::ZERO, move |_| {
      started_tx.send(()).unwrap();
      let _ = release_rx.recv_timeout(TIMEOUT);
    })
    .unwrap();
  started_rx.recv_timeout(TIMEOUT).unwrap();
  let scope = scope(1);
  let filesystem = FsHandle::new(runtime_with_full_queue.handle(), scope.clone());
  let (_reactor, reactor) = reactor(1);
  let path = scratch.child("runtime-full");
  let options = FifoOpenOptions::new().read_write(true);
  let error = filesystem
    .open_fifo_sender(path.clone(), options, &reactor)
    .unwrap_err();
  assert!(matches!(error.kind, FsSubmissionErrorKind::Runtime(_)));
  let (returned_path, returned_options) = error.into_input();
  assert_eq!(returned_path, path);
  assert_eq!(returned_options, options);
  assert!(!returned_path.exists());
  assert_eq!(scope.snapshot().disk_ops, 0);
  release_tx.send(()).unwrap();
  blocker.join().unwrap();
  runtime_with_full_queue
    .shutdown(ShutdownMode::Drain)
    .unwrap();
}

#[test]
fn queued_create_cancel_and_registration_failure_retain_expected_owners() {
  let scratch = Scratch::new();
  let path = scratch.child("queued-cancel");
  let runtime_before_cancel = runtime(1, 2);
  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let blocker = runtime_before_cancel
    .try_spawn(Resources::ZERO, move |_| {
      started_tx.send(()).unwrap();
      let _ = release_rx.recv_timeout(TIMEOUT);
    })
    .unwrap();
  started_rx.recv_timeout(TIMEOUT).unwrap();

  let queued_scope = scope(1);
  let filesystem = FsHandle::new(runtime_before_cancel.handle(), queued_scope.clone());
  let job = filesystem.create_fifo(path.clone(), 0o600).unwrap();
  assert_eq!(queued_scope.snapshot().disk_ops, 1);
  let probe_handle = runtime_before_cancel.handle();
  let shutdown = thread::spawn(move || {
    let mut runtime = runtime_before_cancel;
    runtime.shutdown(ShutdownMode::CancelPending)
  });
  let deadline = Instant::now() + TIMEOUT;
  loop {
    match probe_handle.try_spawn(Resources::ZERO, |_| ()) {
      Ok(probe) => {
        drop(probe);
        assert!(
          Instant::now() < deadline,
          "shutdown did not close admission"
        );
      }
      Err(error) if error.kind == crate::runtime::SubmitErrorKind::Closed => break,
      Err(error) if error.kind == crate::runtime::SubmitErrorKind::Full => {
        assert!(
          Instant::now() < deadline,
          "shutdown did not cancel queued work"
        );
        thread::yield_now();
      }
      Err(error) => panic!("unexpected submission failure during shutdown: {error}"),
    }
  }
  release_tx.send(()).unwrap();
  shutdown.join().unwrap().unwrap();
  assert!(matches!(job.join(), Err(JoinError::Cancelled)));
  blocker.join().unwrap();
  assert!(!path.exists());
  assert_eq!(queued_scope.snapshot().disk_ops, 0);

  let path = scratch.child("registration-full");
  let mut runtime_after_cancel = runtime(1, 4);
  let filesystem = FsHandle::new(runtime_after_cancel.handle(), scope(4));
  filesystem
    .create_fifo(path.clone(), 0o600)
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let (_reactor, reactor) = reactor(1);
  let _first_reader = filesystem
    .open_fifo_receiver(path.clone(), FifoOpenOptions::new(), &reactor)
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  let result = filesystem
    .open_fifo_receiver(path, FifoOpenOptions::new(), &reactor)
    .unwrap()
    .join()
    .unwrap();
  let error = match result {
    Err(error) => error,
    Ok(_) => panic!("registration unexpectedly succeeded with no slots"),
  };
  match error {
    FifoOpenError::Import(error) => {
      let fd = error.into_fd();
      assert!(fcntl_getfl(fd.as_fd()).unwrap().contains(OFlags::NONBLOCK));
    }
    FifoOpenError::Open(error) => panic!("unexpected open error: {error}"),
  }

  let regular = scratch.child("ordinary-file");
  std::fs::write(&regular, b"not a FIFO").unwrap();
  std::os::unix::fs::symlink(&regular, scratch.child("fifo-link")).unwrap();
  let result = filesystem
    .open_fifo_receiver(scratch.child("fifo-link"), FifoOpenOptions::new(), &reactor)
    .unwrap()
    .join()
    .unwrap();
  let error = match result {
    Err(error) => error,
    Ok(_) => panic!("symlink to a regular file passed FIFO validation"),
  };
  match error {
    FifoOpenError::Import(error) => {
      let fd = error.into_fd();
      assert!(std::fs::File::from(fd).metadata().unwrap().is_file());
    }
    FifoOpenError::Open(error) => panic!("unexpected open error: {error}"),
  }
  runtime_after_cancel.shutdown(ShutdownMode::Drain).unwrap();
}
