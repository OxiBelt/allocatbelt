use super::IoPool;
use crate::runtime::blocking_io;
use crate::runtime::fs::FsHandle;
use crate::runtime::io::AsyncReadExt;
use crate::runtime::managed::{ResourceLimits, ResourceScope};
use crate::runtime::net::NetHandle;
use crate::runtime::reactor::{Reactor, ReactorConfig};
use crate::runtime::{
  CancellationToken, Config, Handle, Job, JoinError, Resources, Runtime, ShutdownMode, Snapshot,
  SubmitErrorKind,
};
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(8);
static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);

impl Scratch {
  fn new() -> Self {
    let id = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    let path =
      std::env::temp_dir().join(format!("allocatbelt-io-pool-{}-{id}", std::process::id()));
    fs::create_dir(&path).unwrap();
    Self(path)
  }

  fn child(&self, name: &str) -> PathBuf {
    self.0.join(name)
  }
}

impl Drop for Scratch {
  fn drop(&mut self) {
    let _ = fs::remove_dir_all(&self.0);
  }
}

fn config() -> Config {
  Config {
    workers: 1,
    max_outstanding: 4,
    capacity: Resources::ZERO,
  }
}

fn scope() -> ResourceScope {
  ResourceScope::new(ResourceLimits {
    managed_memory: 64,
    disk_concurrent_ops: 2,
    network_concurrent_ops: 0,
  })
}

fn create_options() -> OpenOptions {
  let mut options = OpenOptions::new();
  options.write(true).create_new(true);
  options
}

fn wait_until(mut ready: impl FnMut() -> bool) {
  let deadline = Instant::now() + WATCHDOG;
  while !ready() {
    assert!(
      Instant::now() < deadline,
      "timed out waiting for pool state"
    );
    thread::yield_now();
  }
}

type Gate = (Job<()>, Receiver<()>, Sender<()>);

fn gate_user(runtime: &Runtime) -> Gate {
  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel::<()>();
  let job = runtime
    .try_spawn(Resources::ZERO, move |_| {
      started_tx.send(()).unwrap();
      let _ = release_rx.recv_timeout(WATCHDOG);
    })
    .unwrap();
  (job, started_rx, release_tx)
}

/// Holds one I/O worker and, once released, reports whether its token was
/// signalled while it ran.
fn gate_io(pool: &IoPool) -> (Job<bool>, Receiver<()>, Sender<()>) {
  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel::<()>();
  let job = pool
    .try_spawn(Resources::ZERO, move |token: CancellationToken| {
      started_tx.send(()).unwrap();
      let _ = release_rx.recv_timeout(WATCHDOG);
      token.is_cancelled()
    })
    .unwrap();
  (job, started_rx, release_tx)
}

/// A queued I/O job that reports whether its token was signalled.
fn queued_token_probe(pool: &IoPool) -> Job<bool> {
  pool
    .try_spawn(Resources::ZERO, |token: CancellationToken| {
      token.is_cancelled()
    })
    .unwrap()
}

fn block_on<F: Future>(future: F) -> F::Output {
  let mut future = std::pin::pin!(future);
  let mut cx = Context::from_waker(Waker::noop());
  let deadline = Instant::now() + WATCHDOG;
  loop {
    if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
      return output;
    }
    assert!(Instant::now() < deadline, "future did not complete");
    thread::yield_now();
  }
}

/// Releases a gate once `snapshot` reports the pool closed, so a cancelling
/// shutdown has taken the queue before the running gate returns.
fn release_after_close(
  snapshot: impl Fn() -> Snapshot + Send + 'static,
  release: Sender<()>,
) -> thread::JoinHandle<()> {
  thread::spawn(move || {
    wait_until(|| snapshot().closed);
    release.send(()).unwrap();
  })
}

#[test]
fn pools_have_distinct_queues_and_worker_names() {
  let mut user = Runtime::new(config()).unwrap();
  let mut pool = IoPool::new(config()).unwrap();
  let io_name = pool
    .try_spawn(Resources::ZERO, |_| {
      thread::current().name().map(str::to_owned)
    })
    .unwrap()
    .join()
    .unwrap();
  assert!(io_name.unwrap().starts_with("allocatbelt-io-"));
  let user_name = user
    .try_spawn(Resources::ZERO, |_| {
      thread::current().name().map(str::to_owned)
    })
    .unwrap()
    .join()
    .unwrap();
  assert!(user_name.unwrap().starts_with("allocatbelt-runtime-"));

  let (gate, started, release) = gate_io(&pool);
  started.recv_timeout(WATCHDOG).unwrap();
  let queued = pool.try_spawn(Resources::ZERO, |_| ()).unwrap();
  assert_eq!(pool.snapshot().queued, 1);
  assert_eq!(user.snapshot().queued, 0);
  assert_eq!(user.snapshot().outstanding, 0);
  release.send(()).unwrap();
  assert!(!gate.join().unwrap());
  queued.join().unwrap();
  pool.shutdown().unwrap();
  user.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn user_pool_cancel_pending_leaves_queued_adapter_operations_to_complete() {
  let scratch = Scratch::new();
  let path = scratch.child("created");
  let mut user = Runtime::new(config()).unwrap();
  let mut pool = IoPool::new(config()).unwrap();
  let scope = scope();
  let fs_handle = FsHandle::new(pool.handle(), scope.clone());

  let (user_gate, user_started, user_release) = gate_user(&user);
  user_started.recv_timeout(WATCHDOG).unwrap();
  let user_queued = user.try_spawn(Resources::ZERO, |_| 7_u8).unwrap();
  let (io_gate, io_started, io_release) = gate_io(&pool);
  io_started.recv_timeout(WATCHDOG).unwrap();

  // A filesystem operation and a stream read, both queued behind the gate.
  let open = fs_handle.open(path.clone(), create_options()).unwrap();
  let (pipe_reader, mut pipe_writer) = std::io::pipe().unwrap();
  let buffer = scope.try_alloc_zeroed(8).unwrap();
  let mut reader = blocking_io::reader(pool.handle(), Resources::ZERO, pipe_reader, buffer)
    .unwrap_or_else(|_| panic!("reader construction failed"));
  let mut output = [0_u8; 4];
  let mut cx = Context::from_waker(Waker::noop());
  {
    let mut read = Box::pin(reader.read(&mut output));
    assert!(read.as_mut().poll(&mut cx).is_pending());
  }
  assert_eq!(pool.snapshot().queued, 2);

  let user_handle: Handle = user.handle();
  let releaser = release_after_close(move || user_handle.snapshot(), user_release);
  user.shutdown(ShutdownMode::CancelPending).unwrap();
  releaser.join().unwrap();
  user_gate.join().unwrap();
  assert!(matches!(user_queued.join(), Err(JoinError::Cancelled)));

  // The I/O pool is still open and kept both adapter operations queued.
  let snapshot = pool.snapshot();
  assert!(!snapshot.closed);
  assert_eq!(snapshot.queued, 2);
  assert!(!path.exists());

  io_release.send(()).unwrap();
  assert!(!io_gate.join().unwrap());
  let created = open.join().unwrap().unwrap();
  drop(created);
  assert!(path.exists());
  pipe_writer.write_all(b"io").unwrap();
  assert_eq!(block_on(reader.read(&mut output)).unwrap(), 2);
  assert_eq!(&output[..2], b"io");
  drop(reader);
  pool.shutdown().unwrap();
  assert_eq!(scope.snapshot().disk_ops, 0);
}

#[test]
fn io_pool_shutdown_drains_queued_operations_without_signalling_tokens() {
  let scratch = Scratch::new();
  let path = scratch.child("drained");
  let mut user = Runtime::new(config()).unwrap();
  let mut pool = IoPool::new(config()).unwrap();
  let scope = scope();
  let fs_handle = FsHandle::new(pool.handle(), scope.clone());

  let (user_gate, user_started, user_release) = gate_user(&user);
  user_started.recv_timeout(WATCHDOG).unwrap();
  let user_queued = user.try_spawn(Resources::ZERO, |_| 11_u8).unwrap();
  let (io_gate, io_started, io_release) = gate_io(&pool);
  io_started.recv_timeout(WATCHDOG).unwrap();
  let open = fs_handle.open(path.clone(), create_options()).unwrap();
  let probe = queued_token_probe(&pool);

  let io_handle = pool.handle();
  let shutdown = thread::spawn(move || {
    let result = pool.shutdown();
    (pool, result)
  });
  wait_until(|| io_handle.snapshot().closed);
  // Shutdown waits; the queued operations keep their place and inputs.
  assert_eq!(io_handle.snapshot().queued, 2);
  assert!(!shutdown.is_finished());
  let closed = fs_handle
    .open(scratch.child("late"), create_options())
    .err()
    .unwrap_or_else(|| panic!("closed I/O pool admitted a filesystem operation"));
  assert!(matches!(
    closed.kind,
    crate::runtime::fs::FsSubmissionErrorKind::Runtime(SubmitErrorKind::Closed)
  ));
  io_release.send(()).unwrap();
  let (_pool, result) = shutdown.join().unwrap();
  result.unwrap();
  assert!(!io_gate.join().unwrap(), "running token was signalled");
  assert!(!probe.join().unwrap(), "queued token was signalled");
  drop(open.join().unwrap().unwrap());
  assert!(path.exists());
  assert_eq!(scope.snapshot().disk_ops, 0);

  // The user pool is still open and kept its queued closure.
  let snapshot = user.snapshot();
  assert!(!snapshot.closed);
  assert_eq!(snapshot.queued, 1);
  user_release.send(()).unwrap();
  user_gate.join().unwrap();
  assert_eq!(user_queued.join().unwrap(), 11);
  user.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn dropping_io_pool_detaches_and_queued_operations_still_complete() {
  let scratch = Scratch::new();
  let path = scratch.child("detached");
  let pool = IoPool::new(config()).unwrap();
  let scope = scope();
  let fs_handle = FsHandle::new(pool.handle(), scope.clone());
  let (io_gate, io_started, io_release) = gate_io(&pool);
  io_started.recv_timeout(WATCHDOG).unwrap();
  let open = fs_handle.open(path.clone(), create_options()).unwrap();
  let probe = queued_token_probe(&pool);
  let io_handle = pool.handle();

  // Dropping does not wait for the held worker and discards nothing.
  drop(pool);
  assert!(io_handle.snapshot().closed);
  assert_eq!(io_handle.snapshot().queued, 2);
  assert_eq!(scope.snapshot().disk_ops, 1);
  assert!(!open.is_finished());
  io_release.send(()).unwrap();
  assert!(!io_gate.join().unwrap(), "running token was signalled");
  assert!(!probe.join().unwrap(), "queued token was signalled");
  drop(open.join().unwrap().unwrap());
  assert!(path.exists());
  wait_until(|| scope.snapshot().disk_ops == 0);
}

#[test]
fn a_single_operation_is_still_cancelled_through_its_own_job() {
  let scratch = Scratch::new();
  let path = scratch.child("one-cancelled");
  let mut pool = IoPool::new(config()).unwrap();
  let scope = scope();
  let fs_handle = FsHandle::new(pool.handle(), scope.clone());
  let (io_gate, io_started, io_release) = gate_io(&pool);
  io_started.recv_timeout(WATCHDOG).unwrap();
  let cancelled = fs_handle.open(path.clone(), create_options()).unwrap();
  let kept = fs_handle
    .open(scratch.child("kept"), create_options())
    .unwrap();
  cancelled.cancel();
  io_release.send(()).unwrap();
  assert!(!io_gate.join().unwrap());
  assert!(matches!(cancelled.join(), Err(JoinError::Cancelled)));
  drop(kept.join().unwrap().unwrap());
  assert!(!path.exists());
  pool.shutdown().unwrap();
}

#[test]
fn network_connect_and_resolve_run_on_the_io_pool_and_survive_user_cancel_pending() {
  let mut user = Runtime::new(config()).unwrap();
  let mut pool = IoPool::new(config()).unwrap();
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 4,
    max_waiters: 4,
  })
  .unwrap();
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 4096,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 2,
  });
  let net = NetHandle::new(pool.handle(), scope.clone(), reactor.handle(), 4).unwrap();
  let listener = TcpListener::bind("127.0.0.1:0").unwrap();
  let address: SocketAddr = listener.local_addr().unwrap();

  let (user_gate, user_started, user_release) = gate_user(&user);
  user_started.recv_timeout(WATCHDOG).unwrap();
  let user_queued = user.try_spawn(Resources::ZERO, |_| ()).unwrap();
  let (io_gate, io_started, io_release) = gate_io(&pool);
  io_started.recv_timeout(WATCHDOG).unwrap();

  let mut cx = Context::from_waker(Waker::noop());
  let mut connect = Box::pin(net.connect(address));
  assert!(connect.as_mut().poll(&mut cx).is_pending());
  let mut resolve = Box::pin(net.resolve("127.0.0.1".to_owned(), address.port()));
  assert!(resolve.as_mut().poll(&mut cx).is_pending());
  // Both blocking calls are queued on the I/O pool, none on the user pool.
  assert_eq!(pool.snapshot().queued, 2);
  assert_eq!(user.snapshot().queued, 1);

  let user_handle = user.handle();
  let releaser = release_after_close(move || user_handle.snapshot(), user_release);
  user.shutdown(ShutdownMode::CancelPending).unwrap();
  releaser.join().unwrap();
  user_gate.join().unwrap();
  assert!(matches!(user_queued.join(), Err(JoinError::Cancelled)));
  assert_eq!(pool.snapshot().queued, 2);

  io_release.send(()).unwrap();
  assert!(!io_gate.join().unwrap());
  let stream = block_on(connect).unwrap_or_else(|error| panic!("connect failed: {error}"));
  let (_peer, _) = listener.accept().unwrap();
  let resolved = block_on(resolve).unwrap_or_else(|error| panic!("resolve failed: {error}"));
  assert!(resolved.iter().any(|resolved| resolved == address));
  drop(stream);
  drop(resolved);
  pool.shutdown().unwrap();
  reactor.shutdown().unwrap();
}

#[test]
fn io_pool_shutdown_from_its_worker_reports_deadlock() {
  let pool = Arc::new(std::sync::Mutex::new(IoPool::new(config()).unwrap()));
  let inner = Arc::clone(&pool);
  let ran = Arc::new(AtomicBool::new(false));
  let ran_in_job = Arc::clone(&ran);
  let job = pool
    .lock()
    .unwrap()
    .try_spawn(Resources::ZERO, move |_| {
      ran_in_job.store(true, Ordering::SeqCst);
      inner.lock().unwrap().shutdown()
    })
    .unwrap();
  let error = job.join().unwrap().unwrap_err();
  assert_eq!(error.kind(), std::io::ErrorKind::Deadlock);
  assert!(ran.load(Ordering::SeqCst));
  pool.lock().unwrap().shutdown().unwrap();
}
