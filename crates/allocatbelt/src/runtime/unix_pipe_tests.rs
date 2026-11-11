use super::{PipeReader, PipeWriter, pipe};
use crate::runtime::asynchronous::{AsyncConfig, AsyncRuntime};
use crate::runtime::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::runtime::reactor::{Reactor, ReactorConfig};
use rustix::fs::{CWD, Mode, OFlags, fcntl_getfl, mkfifoat, openat};
use rustix::io::{Errno, FdFlags, fcntl_getfd, read, write};
use rustix::pipe::{PipeFlags, pipe_with};
use std::fs::File;
use std::future::Future;
use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(8);
static NEXT_FIFO: AtomicU64 = AtomicU64::new(1);

fn reactor(
  max_registrations: usize,
  max_waiters: usize,
) -> (Reactor, crate::runtime::reactor::ReactorHandle) {
  let reactor = Reactor::new(ReactorConfig {
    max_registrations,
    max_waiters,
  })
  .unwrap();
  let handle = reactor.handle();
  (reactor, handle)
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
  let mut future = Box::pin(future);
  let deadline = Instant::now() + TIMEOUT;
  loop {
    match future.as_mut().poll(&mut context) {
      Poll::Ready(value) => return value,
      Poll::Pending => {
        assert!(Instant::now() < deadline, "pipe operation timed out");
        thread::park_timeout(Duration::from_millis(10));
      }
    }
  }
}

#[test]
fn pipe_registers_cloexec_nonblocking_pair_and_transfers_partial_bytes_then_eof() {
  let (_reactor, handle) = reactor(4, 8);
  let (mut reader, mut writer) = pipe(&handle).unwrap();
  let read_flags = fcntl_getfl(reader.get_ref()).unwrap();
  let write_flags = fcntl_getfl(writer.get_ref().unwrap()).unwrap();
  assert!(read_flags.contains(OFlags::NONBLOCK));
  assert!(write_flags.contains(OFlags::NONBLOCK));
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

  assert_eq!(block_on(writer.write(b"pipe-data")).unwrap(), 9);
  let mut first = [0; 4];
  assert_eq!(block_on(reader.read(&mut first)).unwrap(), 4);
  assert_eq!(&first, b"pipe");
  let mut rest = [0; 16];
  let read = block_on(reader.read(&mut rest)).unwrap();
  assert_eq!(&rest[..read], b"-data");

  let writes = [IoSlice::new(b"vector-"), IoSlice::new(b"bytes")];
  let written = block_on(std::future::poll_fn(|cx| {
    Pin::new(&mut writer).poll_write_vectored(cx, &writes)
  }))
  .unwrap();
  assert_eq!(written, 12);
  let mut first = [0; 7];
  let mut second = [0; 8];
  let read = {
    let mut reads = [IoSliceMut::new(&mut first), IoSliceMut::new(&mut second)];
    block_on(std::future::poll_fn(|cx| {
      Pin::new(&mut reader).poll_read_vectored(cx, &mut reads)
    }))
    .unwrap()
  };
  assert_eq!(read, written);
  assert_eq!(&first, b"vector-");
  assert_eq!(&second[..read - first.len()], b"bytes");

  block_on(writer.flush()).unwrap();
  block_on(writer.shutdown()).unwrap();
  assert!(writer.get_ref().is_none());
  assert_eq!(block_on(reader.read(&mut rest)).unwrap(), 0);
  assert_eq!(handle.registrations(), 1);
  drop(reader);
  assert_eq!(handle.registrations(), 0);
}

#[test]
fn pair_registration_failure_reclaims_the_first_registration_and_both_fds() {
  let (_reactor, handle) = reactor(1, 2);
  let error = match pipe(&handle) {
    Ok(_) => panic!("reactor admitted both pipe endpoints above its registration bound"),
    Err(error) => error,
  };
  assert_eq!(error.kind(), io::ErrorKind::Other);
  assert_eq!(handle.registrations(), 0);
}

#[test]
fn invalid_imports_return_the_same_fd_without_changing_its_flags() {
  let (_reactor, handle) = reactor(8, 8);

  let file: OwnedFd = File::open("/dev/null").unwrap().into();
  let original_flags = fcntl_getfl(&file).unwrap();
  let error = match PipeReader::from_owned_fd(file, &handle) {
    Ok(_) => panic!("regular file was accepted as a pipe"),
    Err(error) => error,
  };
  let (file, _, _) = error.into_parts();
  assert_eq!(fcntl_getfl(&file).unwrap(), original_flags);

  let (read_fd, write_fd) = pipe_with(PipeFlags::CLOEXEC).unwrap();
  let read_flags = fcntl_getfl(&read_fd).unwrap();
  let error = match PipeReader::from_owned_fd(write_fd, &handle) {
    Ok(_) => panic!("write-only pipe end was accepted as a reader"),
    Err(error) => error,
  };
  let (write_fd, _, _) = error.into_parts();
  assert_eq!(fcntl_getfl(&write_fd).unwrap(), OFlags::WRONLY);
  let error = match PipeWriter::from_owned_fd(read_fd, &handle) {
    Ok(_) => panic!("read-only pipe end was accepted as a writer"),
    Err(error) => error,
  };
  let (read_fd, _, _) = error.into_parts();
  assert_eq!(fcntl_getfl(&read_fd).unwrap(), read_flags);
  assert_eq!(handle.registrations(), 0);
}

#[test]
fn packet_mode_pipe_is_rejected_before_registration() {
  let (_reactor, handle) = reactor(2, 2);
  let (read_fd, write_fd) = pipe_with(PipeFlags::DIRECT | PipeFlags::CLOEXEC).unwrap();
  let flags = fcntl_getfl(&write_fd).unwrap();
  assert!(flags.contains(OFlags::DIRECT));
  let error = match PipeWriter::from_owned_fd(write_fd, &handle) {
    Ok(_) => panic!("packet-mode pipe writer was accepted as a byte stream"),
    Err(error) => error,
  };
  let (write_fd, _, _) = error.into_parts();
  assert_eq!(fcntl_getfl(&write_fd).unwrap(), flags);
  drop(read_fd);
  assert_eq!(handle.registrations(), 0);
}

#[test]
fn path_only_fifo_import_is_rejected_without_mutating_the_descriptor() {
  let (_reactor, handle) = reactor(2, 2);
  let path = std::env::temp_dir().join(format!(
    "allocatbelt-pipe-path-{}-{}",
    std::process::id(),
    NEXT_FIFO.fetch_add(1, Ordering::Relaxed)
  ));
  mkfifoat(CWD, &path, Mode::RWXU).unwrap();
  let fd = openat(CWD, &path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).unwrap();
  let original_flags = fcntl_getfl(&fd).unwrap();
  let error = match PipeReader::from_owned_fd(fd, &handle) {
    Ok(_) => panic!("path-only FIFO descriptor was accepted"),
    Err(error) => error,
  };
  let (fd, _, _) = error.into_parts();
  assert_eq!(fcntl_getfl(&fd).unwrap(), original_flags);
  assert!(original_flags.contains(OFlags::PATH));
  std::fs::remove_file(path).unwrap();
  assert_eq!(handle.registrations(), 0);
}

#[test]
fn registration_failure_returns_imported_fd_and_restores_flags() {
  let (_reactor, handle) = reactor(1, 2);
  let (first_read, _first_write) = pipe_with(PipeFlags::CLOEXEC).unwrap();
  let _registered = PipeReader::from_owned_fd(first_read, &handle).unwrap();
  let (second_read, _second_write) = pipe_with(PipeFlags::CLOEXEC).unwrap();
  let original_flags = fcntl_getfl(&second_read).unwrap();
  let error = match PipeReader::from_owned_fd(second_read, &handle) {
    Ok(_) => panic!("reactor admitted more descriptors than its bound"),
    Err(error) => error,
  };
  assert_eq!(error.error().kind(), io::ErrorKind::Other);
  assert!(error.restoration_error().is_none());
  let (second_read, _, restoration_error) = error.into_parts();
  assert!(restoration_error.is_none());
  assert_eq!(fcntl_getfl(&second_read).unwrap(), original_flags);
  assert_eq!(handle.registrations(), 1);
}

#[test]
fn a_full_pipe_retains_one_writer_waiter_until_cancelled() {
  let (_reactor, handle) = reactor(2, 2);
  let (mut reader, mut writer) = pipe(&handle).unwrap();
  let storage = [0xa5; 16 * 1024];
  loop {
    match write(writer.get_ref().unwrap(), &storage) {
      Ok(count) => assert!(count > 0),
      Err(Errno::AGAIN) => break,
      Err(error) => panic!("filling kernel pipe failed: {error}"),
    }
  }
  let waker = Waker::from(Arc::new(UnparkWaker(thread::current())));
  let mut context = Context::from_waker(&waker);
  assert!(
    Pin::new(&mut writer)
      .poll_write(&mut context, b"blocked")
      .is_pending()
  );
  assert_eq!(handle.waiters(), 1);
  writer.cancel_io_waits();
  assert_eq!(handle.waiters(), 0);

  let mut drained = [0; 8192];
  assert!(block_on(reader.read(&mut drained)).unwrap() >= 4096);
  assert_eq!(block_on(writer.write(b"ok")).unwrap(), 2);
}

#[test]
fn exhausted_owned_poll_gates_pipe_operations_before_mutation() {
  let (_reactor, handle) = reactor(2, 2);
  let (mut reader, mut writer) = pipe(&handle).unwrap();
  assert_eq!(write(writer.get_ref().unwrap(), b"r").unwrap(), 1);
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let operations_were_gated = runtime
    .block_on(std::future::poll_fn(|cx| {
      for _ in 0..64 {
        assert!(super::poll_cooperative(cx, |_| Poll::Ready(())).is_ready());
      }
      let mut received = [0; 1];
      let read = Pin::new(&mut reader)
        .poll_read(cx, &mut received)
        .is_pending();
      let write = Pin::new(&mut writer).poll_write(cx, b"w").is_pending();
      let flush = Pin::new(&mut writer).poll_flush(cx).is_pending();
      let shutdown = Pin::new(&mut writer).poll_shutdown(cx).is_pending();
      Poll::Ready((read, write, flush, shutdown, writer.get_ref().is_some()))
    }))
    .unwrap();
  assert_eq!(operations_were_gated, (true, true, true, true, true));
  let mut received = [0; 1];
  assert_eq!(read(reader.get_ref(), &mut received).unwrap(), 1);
  assert_eq!(received, [b'r']);
  assert_eq!(read(reader.get_ref(), &mut received), Err(Errno::AGAIN));
  runtime
    .shutdown(crate::runtime::asynchronous::AsyncShutdown::Drain)
    .unwrap();
}

#[test]
fn rust_pipe_wrappers_do_not_change_process_sigpipe_policy() {
  const PROBE: &str = "ALLOCATBELT_UNIX_PIPE_SIGPIPE_PROBE";
  if std::env::var_os(PROBE).is_some() {
    let (_reactor, handle) = reactor(2, 2);
    let (_reader, mut writer) = pipe(&handle).unwrap();
    drop(_reader);
    let result = block_on(writer.write(b"no-reader"));
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    return;
  }

  let output = Command::new(std::env::current_exe().unwrap())
    .args([
      "--exact",
      "runtime::unix_pipe::tests::rust_pipe_wrappers_do_not_change_process_sigpipe_policy",
    ])
    .env(PROBE, "1")
    .output()
    .unwrap();
  assert!(
    output.status.success(),
    "SIGPIPE probe failed: {}",
    String::from_utf8_lossy(&output.stderr)
  );
}
