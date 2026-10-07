use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{
  Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener as StdTcpListener, TcpStream as StdTcpStream,
  UdpSocket as StdUdpSocket,
};
use std::os::fd::{AsRawFd, OwnedFd};
use std::pin::Pin;
use std::pin::pin;
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

use super::{
  ConnectAttempt, ConnectProbeResult, NetHandle, NetworkError, ResolveError, ResolveSubmissionKind,
  TcpConnectError, TcpConnectRejectKind, TcpListenError, TcpListener, TcpSocket, UdpSocket,
  classify_connect_probe, classify_connect_start, finish_connect_probe, initiate_tcp_connect,
  wait_for_tcp_connect,
};
use crate::runtime::blocking::{Config, Runtime, ShutdownMode};
use crate::runtime::io::{AsyncRead, AsyncWrite, copy_with_buffer};
use crate::runtime::managed::{OperationRequest, ResourceLimits, ResourceScope};
use crate::runtime::reactor::{Reactor, ReactorConfig};
use crate::runtime::resources::Resources;

fn reactor(registrations: usize) -> Reactor {
  Reactor::new(ReactorConfig {
    max_registrations: registrations,
    max_waiters: 16,
  })
  .unwrap()
}

#[cfg(unix)]
#[test]
fn ready_unix_read_loop_yields_to_already_queued_sibling() {
  use std::os::unix::net::UnixStream as StdUnixStream;
  use std::sync::atomic::{AtomicBool, Ordering};

  use crate::runtime::asynchronous::{AsyncConfig, AsyncRuntime};

  struct Release(std::sync::mpsc::Sender<()>);
  impl Drop for Release {
    fn drop(&mut self) {
      let _ = self.0.send(());
    }
  }

  const READS: usize = 2_048;
  let reactor = reactor(2);
  let (read_side, mut peer) = StdUnixStream::pair().unwrap();
  peer.write_all(&vec![0_u8; READS]).unwrap();
  let stream = super::unix::UnixStream::from_std(read_side, &reactor.handle()).unwrap();
  drop(block_on(stream.fd.readable()).unwrap());

  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 4,
    max_scopes: 2,
  })
  .unwrap();
  let scope = runtime.scope().unwrap();
  let (started_tx, started_rx) = mpsc::channel();
  let (reader_done_tx, reader_done_rx) = mpsc::channel();
  let (sibling_done_tx, sibling_done_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let release_guard = Release(release_tx);
  let sibling_ran = Arc::new(AtomicBool::new(false));
  let bytes_read = Arc::new(std::sync::atomic::AtomicUsize::new(0));

  let read_count = Arc::clone(&bytes_read);
  let reader = scope
    .spawn(async move {
      started_tx.send(()).unwrap();
      release_rx.recv().unwrap();
      let mut byte = [0_u8; 1];
      for _ in 0..READS {
        assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
        assert_eq!(byte, [0]);
        read_count.fetch_add(1, Ordering::Relaxed);
      }
      reader_done_tx.send(()).unwrap();
    })
    .unwrap();
  started_rx
    .recv_timeout(IO_TIMEOUT)
    .expect("hot reader should occupy its worker before sibling admission");

  let sibling_flag = Arc::clone(&sibling_ran);
  let observed_reads = Arc::clone(&bytes_read);
  let sibling = scope
    .spawn(async move {
      assert!(observed_reads.load(Ordering::Relaxed) < READS);
      sibling_flag.store(true, Ordering::Release);
      sibling_done_tx.send(()).unwrap();
    })
    .unwrap();
  drop(release_guard);

  let completion_deadline = Instant::now() + IO_TIMEOUT;
  for done in [&reader_done_rx, &sibling_done_rx] {
    let remaining = completion_deadline.saturating_duration_since(Instant::now());
    if done.recv_timeout(remaining).is_err() {
      reader.abort_handle().abort();
      sibling.abort_handle().abort();
      runtime
        .shutdown(crate::runtime::asynchronous::AsyncShutdown::CancelPending)
        .unwrap();
      panic!("ready I/O and its queued sibling did not complete before the watchdog");
    }
  }
  while !reader.is_finished() || !sibling.is_finished() {
    if Instant::now() >= completion_deadline {
      reader.abort_handle().abort();
      sibling.abort_handle().abort();
      runtime
        .shutdown(crate::runtime::asynchronous::AsyncShutdown::CancelPending)
        .unwrap();
      panic!("completed network task bodies did not publish before the watchdog");
    }
    thread::yield_now();
  }

  runtime
    .block_on(async move {
      reader.await.unwrap();
      sibling.await.unwrap();
      scope.close().await;
    })
    .unwrap();
  runtime
    .shutdown(crate::runtime::asynchronous::AsyncShutdown::Drain)
    .unwrap();

  assert_eq!(bytes_read.load(Ordering::Relaxed), READS);
  assert!(sibling_ran.load(Ordering::Acquire));
}

#[cfg(unix)]
#[test]
fn ready_unix_read_attempt_preserves_input_at_zero_budget() {
  use std::os::unix::net::UnixStream as StdUnixStream;

  use crate::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};

  let reactor = reactor(2);
  let (read_side, mut peer) = StdUnixStream::pair().unwrap();
  peer.write_all(b"x").unwrap();
  let mut stream = super::unix::UnixStream::from_std(read_side, &reactor.handle()).unwrap();
  drop(block_on(stream.fd.readable()).unwrap());

  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let task = runtime
    .handle()
    .spawn(async move {
      let mut first = [0_u8; 1];
      std::future::poll_fn(|cx| {
        for _ in 0..64 {
          let mut empty = [];
          assert!(matches!(
            Pin::new(&mut stream).poll_read(cx, &mut empty),
            Poll::Ready(Ok(0))
          ));
        }
        match Pin::new(&mut stream).poll_read(cx, &mut first) {
          Poll::Pending => {
            assert!(stream.read_waiter_is_none());
            Poll::Ready(())
          }
          Poll::Ready(result) => panic!("zero-budget read consumed ready input: {result:?}"),
        }
      })
      .await;
      assert_eq!(first, [0]);

      let mut received = [0_u8; 1];
      assert_eq!(stream.read(&mut received).await.unwrap(), 1);
      assert_eq!(received, *b"x");
    })
    .unwrap();
  runtime.block_on(task).unwrap().unwrap();
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
}

#[cfg(unix)]
#[test]
fn pending_readiness_refunds_budget_and_preserves_its_waiter_at_zero() {
  use std::os::unix::net::UnixStream as StdUnixStream;

  use crate::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};

  let reactor = reactor(2);
  let (read_side, mut peer) = StdUnixStream::pair().unwrap();
  let mut stream = super::unix::UnixStream::from_std(read_side, &reactor.handle()).unwrap();
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let (waiting_tx, waiting_rx) = mpsc::channel();
  let task = runtime
    .handle()
    .spawn(async move {
      let mut waiter = None;
      std::future::poll_fn(|cx| {
        match super::poll_io_attempt(
          cx,
          &stream.fd,
          &mut waiter,
          super::IoDirection::Read,
          |_| -> io::Result<()> { unreachable!("pending readiness must not poll the endpoint") },
        ) {
          Poll::Pending => {
            assert!(waiter.is_some());
            Poll::Ready(())
          }
          Poll::Ready(result) => panic!("empty stream unexpectedly had readiness: {result:?}"),
        }
      })
      .await;

      std::future::poll_fn(|cx| {
        for _ in 0..64 {
          let mut empty = [];
          assert!(matches!(
            Pin::new(&mut stream).poll_read(cx, &mut empty),
            Poll::Ready(Ok(0))
          ));
        }
        let mut empty = [];
        assert!(Pin::new(&mut stream).poll_read(cx, &mut empty).is_pending());
        assert!(waiter.is_some());
        assert!(matches!(
          super::poll_io_attempt(
            cx,
            &stream.fd,
            &mut waiter,
            super::IoDirection::Read,
            |_| -> io::Result<()> {
              unreachable!("zero-budget poll must preserve the retained waiter")
            },
          ),
          Poll::Pending
        ));
        assert!(waiter.is_some());
        Poll::Ready(())
      })
      .await;
      drop(waiter);
      waiting_tx.send(()).unwrap();

      let mut received = [0_u8; 1];
      assert_eq!(stream.read(&mut received).await.unwrap(), 1);
      assert_eq!(received, *b"p");
    })
    .unwrap();
  waiting_rx
    .recv_timeout(IO_TIMEOUT)
    .expect("readiness waiter should be retained before peer data arrives");
  peer.write_all(b"p").unwrap();
  runtime.block_on(task).unwrap().unwrap();
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
}

#[cfg(unix)]
#[test]
fn stale_would_block_refunds_budget_while_interrupted_consumes_it() {
  use std::os::unix::net::UnixStream as StdUnixStream;

  use crate::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};

  let reactor = reactor(4);
  let (would_block_side, mut would_block_peer) = StdUnixStream::pair().unwrap();
  let (interrupted_side, mut interrupted_peer) = StdUnixStream::pair().unwrap();
  would_block_peer.write_all(b"w").unwrap();
  interrupted_peer.write_all(b"i").unwrap();
  let mut would_block_stream =
    super::unix::UnixStream::from_std(would_block_side, &reactor.handle()).unwrap();
  let mut interrupted_stream =
    super::unix::UnixStream::from_std(interrupted_side, &reactor.handle()).unwrap();
  drop(block_on(would_block_stream.fd.readable()).unwrap());
  drop(block_on(interrupted_stream.fd.readable()).unwrap());

  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap();
  let task = runtime
    .handle()
    .spawn(async move {
      let mut would_block_waiter = None;
      std::future::poll_fn(|cx| {
        match super::poll_io_attempt(
          cx,
          &would_block_stream.fd,
          &mut would_block_waiter,
          super::IoDirection::Read,
          |_| -> io::Result<()> { Err(io::ErrorKind::WouldBlock.into()) },
        ) {
          Poll::Ready(super::IoAttempt::RetryRefunded) => Poll::Ready(()),
          other => panic!("expected stale WouldBlock to refund and retry: {other:?}"),
        }
      })
      .await;
      std::future::poll_fn(|cx| {
        for _ in 0..64 {
          let mut empty = [];
          assert!(matches!(
            Pin::new(&mut would_block_stream).poll_read(cx, &mut empty),
            Poll::Ready(Ok(0))
          ));
        }
        let mut empty = [];
        assert!(
          Pin::new(&mut would_block_stream)
            .poll_read(cx, &mut empty)
            .is_pending()
        );
        Poll::Ready(())
      })
      .await;
      let mut received = [0_u8; 1];
      assert_eq!(would_block_stream.read(&mut received).await.unwrap(), 1);
      assert_eq!(received, *b"w");

      let mut interrupted_waiter = None;
      std::future::poll_fn(|cx| {
        match super::poll_io_attempt(
          cx,
          &interrupted_stream.fd,
          &mut interrupted_waiter,
          super::IoDirection::Read,
          |_| -> io::Result<()> { Err(io::ErrorKind::Interrupted.into()) },
        ) {
          Poll::Ready(super::IoAttempt::RetryCharged) => Poll::Ready(()),
          other => panic!("expected Interrupted to consume one unit: {other:?}"),
        }
      })
      .await;
      std::future::poll_fn(|cx| {
        for _ in 0..62 {
          let mut empty = [];
          assert!(matches!(
            Pin::new(&mut interrupted_stream).poll_read(cx, &mut empty),
            Poll::Ready(Ok(0))
          ));
        }
        let mut empty = [];
        assert!(
          Pin::new(&mut interrupted_stream)
            .poll_read(cx, &mut empty)
            .is_pending()
        );
        Poll::Ready(())
      })
      .await;
      let mut received = [0_u8; 1];
      assert_eq!(interrupted_stream.read(&mut received).await.unwrap(), 1);
      assert_eq!(received, *b"i");
    })
    .unwrap();
  runtime.block_on(task).unwrap().unwrap();
  runtime.shutdown(AsyncShutdown::Drain).unwrap();
}

#[cfg(unix)]
#[test]
fn manual_interrupted_io_attempts_self_wake_at_the_local_sixty_four_limit() {
  use std::os::unix::net::UnixStream as StdUnixStream;
  use std::sync::atomic::{AtomicUsize, Ordering};

  struct WakeCount(Arc<AtomicUsize>);
  impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
      self.0.fetch_add(1, Ordering::Relaxed);
    }
  }

  let reactor = reactor(2);
  let (read_side, mut peer) = StdUnixStream::pair().unwrap();
  peer.write_all(b"ready").unwrap();
  let stream = super::unix::UnixStream::from_std(read_side, &reactor.handle()).unwrap();
  drop(block_on(stream.fd.readable()).unwrap());

  let wake_count = Arc::new(AtomicUsize::new(0));
  let waker = Waker::from(Arc::new(WakeCount(Arc::clone(&wake_count))));
  let mut context = Context::from_waker(&waker);
  let mut waiter = None;
  let mut calls = 0;
  assert!(
    super::poll_io_with_retry(
      &mut context,
      &stream.fd,
      &mut waiter,
      super::IoDirection::Read,
      |_| -> io::Result<usize> {
        calls += 1;
        Err(io::ErrorKind::Interrupted.into())
      },
    )
    .is_pending()
  );
  assert_eq!(calls, 64);
  assert_eq!(wake_count.load(Ordering::Relaxed), 1);
}

const IO_TIMEOUT: Duration = Duration::from_secs(10);

struct UnparkWaker(thread::Thread);

impl Wake for UnparkWaker {
  fn wake(self: Arc<Self>) {
    self.0.unpark();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.unpark();
  }
}

fn set_tcp_timeouts(stream: &StdTcpStream) {
  stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
  stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
}

fn block_on<F: Future>(future: F) -> F::Output {
  let mut future = pin!(future);
  let mut context = Context::from_waker(Waker::noop());
  let deadline = Instant::now() + IO_TIMEOUT;
  loop {
    match future.as_mut().poll(&mut context) {
      Poll::Ready(value) => return value,
      Poll::Pending => {
        assert!(
          Instant::now() < deadline,
          "network future exceeded its test deadline"
        );
        thread::sleep(Duration::from_millis(1));
      }
    }
  }
}

#[cfg(unix)]
#[test]
fn unix_stream_preserves_data_eof_and_write_half_shutdown() {
  use std::io::Read;
  use std::os::unix::net::UnixStream as StdUnixStream;

  let reactor = reactor(4);
  let handle = reactor.handle();
  let (runtime_side, mut peer) = StdUnixStream::pair().unwrap();
  peer.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
  peer.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
  let stream = super::UnixStream::from_std(runtime_side, &handle).unwrap();

  assert_eq!(block_on(stream.write(b"hello")).unwrap(), 5);
  let mut received = [0; 5];
  peer.read_exact(&mut received).unwrap();
  assert_eq!(&received, b"hello");

  block_on(stream.shutdown()).unwrap();
  let mut byte = [0; 1];
  assert_eq!(peer.read(&mut byte).unwrap(), 0);

  peer.shutdown(std::net::Shutdown::Write).unwrap();
  assert_eq!(block_on(stream.read(&mut byte)).unwrap(), 0);
}

#[cfg(unix)]
#[test]
fn unix_stream_traits_mix_with_named_methods_and_wake_on_readiness() {
  use std::os::unix::net::UnixStream as StdUnixStream;

  let reactor = reactor(2);
  let handle = reactor.handle();
  let (runtime_side, mut peer) = StdUnixStream::pair().unwrap();
  peer.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
  peer.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
  let mut stream = super::UnixStream::from_std(runtime_side, &handle).unwrap();
  let mut incoming = [0; 4];

  let current = thread::current();
  let waker = Waker::from(Arc::new(UnparkWaker(current)));
  let mut context = Context::from_waker(&waker);
  assert!(
    Pin::new(&mut stream)
      .poll_read(&mut context, &mut incoming)
      .is_pending()
  );
  assert_eq!(handle.waiters(), 1);
  peer.write_all(b"read").unwrap();
  let deadline = Instant::now() + IO_TIMEOUT;
  let read = loop {
    thread::park_timeout(Duration::from_millis(10));
    match Pin::new(&mut stream).poll_read(&mut context, &mut incoming) {
      Poll::Ready(result) => break result.unwrap(),
      Poll::Pending => assert!(Instant::now() < deadline, "trait read was not woken"),
    }
  };
  assert_eq!(read, 4);
  assert_eq!(&incoming, b"read");

  peer.shutdown(std::net::Shutdown::Write).unwrap();
  let eof = block_on(std::future::poll_fn(|cx| {
    Pin::new(&mut stream).poll_read(cx, &mut incoming)
  }))
  .unwrap();
  assert_eq!(eof, 0);

  assert_eq!(block_on(stream.write(b"named")).unwrap(), 5);
  let mut named = [0; 5];
  peer.read_exact(&mut named).unwrap();
  assert_eq!(&named, b"named");

  let written = block_on(std::future::poll_fn(|cx| {
    Pin::new(&mut stream).poll_write(cx, b"trait")
  }))
  .unwrap();
  assert_eq!(written, 5);
  let mut trait_bytes = [0; 5];
  peer.read_exact(&mut trait_bytes).unwrap();
  assert_eq!(&trait_bytes, b"trait");

  block_on(std::future::poll_fn(|cx| {
    Pin::new(&mut stream).poll_shutdown(cx)
  }))
  .unwrap();
  assert_eq!(peer.read(&mut named).unwrap(), 0);
}

#[cfg(unix)]
#[test]
fn trait_cancel_io_waits_releases_read_and_write_waiters() {
  use std::os::unix::net::UnixStream as StdUnixStream;

  let reactor = reactor(1);
  let handle = reactor.handle();
  let (runtime_side, _peer) = StdUnixStream::pair().unwrap();
  let mut stream = super::UnixStream::from_std(runtime_side, &handle).unwrap();
  let chunk = [0u8; 4096];
  let mut writer = stream.get_ref();
  loop {
    match writer.write(&chunk) {
      Ok(_) => {}
      Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
      Err(error) => panic!("filling nonblocking socket failed: {error}"),
    }
  }

  let mut byte = [0; 1];
  let mut context = Context::from_waker(Waker::noop());
  assert!(
    Pin::new(&mut stream)
      .poll_read(&mut context, &mut byte)
      .is_pending()
  );
  assert!(
    Pin::new(&mut stream)
      .poll_write(&mut context, b"x")
      .is_pending()
  );
  assert_eq!(handle.waiters(), 2);
  stream.cancel_io_waits();
  assert_eq!(handle.waiters(), 0);
  assert_eq!(handle.registrations(), 1);
}

#[cfg(unix)]
#[test]
fn empty_trait_polls_release_stored_waiters_for_their_direction() {
  use std::os::unix::net::UnixStream as StdUnixStream;

  let reactor = reactor(1);
  let handle = reactor.handle();
  let (runtime_side, _peer) = StdUnixStream::pair().unwrap();
  let mut stream = super::UnixStream::from_std(runtime_side, &handle).unwrap();
  let mut context = Context::from_waker(Waker::noop());
  let mut byte = [0; 1];

  assert!(
    Pin::new(&mut stream)
      .poll_read(&mut context, &mut byte)
      .is_pending()
  );
  assert_eq!(handle.waiters(), 1);
  assert_eq!(
    Pin::new(&mut stream)
      .poll_read(&mut context, &mut [])
      .map(Result::unwrap),
    Poll::Ready(0)
  );
  assert_eq!(handle.waiters(), 0);

  let chunk = [0u8; 4096];
  let mut writer = stream.get_ref();
  loop {
    match writer.write(&chunk) {
      Ok(_) => {}
      Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
      Err(error) => panic!("filling nonblocking socket failed: {error}"),
    }
  }
  assert!(
    Pin::new(&mut stream)
      .poll_write(&mut context, b"x")
      .is_pending()
  );
  assert_eq!(handle.waiters(), 1);
  assert_eq!(
    Pin::new(&mut stream)
      .poll_write(&mut context, &[])
      .map(Result::unwrap),
    Poll::Ready(0)
  );
  assert_eq!(handle.waiters(), 0);
}

#[cfg(unix)]
#[test]
fn stream_traits_copy_large_input_through_partial_progress() {
  use std::os::unix::net::UnixStream as StdUnixStream;

  let reactor = reactor(4);
  let handle = reactor.handle();
  let (source_runtime, mut source_peer) = StdUnixStream::pair().unwrap();
  let (destination_runtime, mut destination_peer) = StdUnixStream::pair().unwrap();
  source_peer.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
  destination_peer.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
  let mut source = super::UnixStream::from_std(source_runtime, &handle).unwrap();
  let mut destination = super::UnixStream::from_std(destination_runtime, &handle).unwrap();
  let payload: Vec<u8> = (0..1_000_000).map(|index| (index % 251) as u8).collect();
  let writer = thread::spawn(move || {
    source_peer.write_all(&payload).unwrap();
    source_peer.shutdown(std::net::Shutdown::Write).unwrap();
    payload
  });
  let reader = thread::spawn(move || {
    let mut received = Vec::new();
    destination_peer.read_to_end(&mut received).unwrap();
    received
  });

  let mut scratch = [0; 8192];
  let copied = block_on(copy_with_buffer(
    &mut source,
    &mut destination,
    &mut scratch,
  ))
  .unwrap();
  block_on(destination.shutdown()).unwrap();
  assert_eq!(copied, 1_000_000);
  assert_eq!(reader.join().unwrap(), writer.join().unwrap());
}

#[cfg(unix)]
#[test]
fn read_waiter_observes_data_arriving_after_pending() {
  use std::os::unix::net::UnixStream as StdUnixStream;

  let reactor = reactor(2);
  let handle = reactor.handle();
  let (runtime_side, mut peer) = StdUnixStream::pair().unwrap();
  peer.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
  let stream = super::UnixStream::from_std(runtime_side, &handle).unwrap();
  let mut byte = [0; 1];
  {
    let mut future = pin!(stream.read(&mut byte));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    peer.write_all(b"x").unwrap();
    assert_eq!(block_on(future.as_mut()).unwrap(), 1);
  }
  assert_eq!(byte, *b"x");
}

#[cfg(unix)]
#[test]
fn stale_socket_readiness_is_cleared_and_waits_again() {
  use std::os::unix::net::UnixStream as StdUnixStream;

  let reactor = reactor(4);
  let handle = reactor.handle();
  let (runtime_side, mut peer) = StdUnixStream::pair().unwrap();
  peer.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
  let duplicate = runtime_side.try_clone().unwrap();
  let stream = super::UnixStream::from_std(runtime_side, &handle).unwrap();
  let other_reader = super::UnixStream::from_std(duplicate, &handle).unwrap();
  peer.write_all(b"a").unwrap();
  drop(block_on(stream.fd.readable()).unwrap());

  let mut first = [0; 1];
  assert_eq!(block_on(other_reader.read(&mut first)).unwrap(), 1);
  assert_eq!(first, *b"a");

  let mut next = [0; 1];
  {
    let mut future = pin!(stream.read(&mut next));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    peer.write_all(b"b").unwrap();
    assert_eq!(block_on(future.as_mut()).unwrap(), 1);
  }
  assert_eq!(next, *b"b");
}

#[cfg(unix)]
#[test]
fn dropping_pending_read_reclaims_its_waiter() {
  use std::os::unix::net::UnixStream as StdUnixStream;

  let reactor = reactor(2);
  let handle = reactor.handle();
  let (runtime_side, _peer) = StdUnixStream::pair().unwrap();
  let stream = super::UnixStream::from_std(runtime_side, &handle).unwrap();
  let mut byte = [0; 1];
  {
    let mut future = pin!(stream.read(&mut byte));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(handle.waiters(), 1);
  }
  assert_eq!(handle.waiters(), 0);
}

#[test]
fn udp_keeps_datagram_boundaries() {
  let reactor = reactor(4);
  let handle = reactor.handle();
  let left = StdUdpSocket::bind("127.0.0.1:0").unwrap();
  let right = StdUdpSocket::bind("127.0.0.1:0").unwrap();
  let right_addr = right.local_addr().unwrap();
  let left = UdpSocket::from_std(left, &handle).unwrap();
  let right = UdpSocket::from_std(right, &handle).unwrap();

  assert_eq!(block_on(left.send_to(b"one", right_addr)).unwrap(), 3);
  assert_eq!(block_on(left.send_to(b"second", right_addr)).unwrap(), 6);
  let mut buf = [0; 16];
  let (first_len, from) = block_on(right.recv_from(&mut buf)).unwrap();
  assert_eq!(&buf[..first_len], b"one");
  assert_eq!(from, left.get_ref().local_addr().unwrap());
  let (second_len, _) = block_on(right.recv_from(&mut buf)).unwrap();
  assert_eq!(&buf[..second_len], b"second");
}

#[test]
fn connected_udp_filters_peers_peeks_without_consuming_and_preserves_empty_messages() {
  let reactor = reactor(2);
  let handle = reactor.handle();
  let left = StdUdpSocket::bind("127.0.0.1:0").unwrap();
  let right = StdUdpSocket::bind("127.0.0.1:0").unwrap();
  let outsider = StdUdpSocket::bind("127.0.0.1:0").unwrap();
  let left_addr = left.local_addr().unwrap();
  let right_addr = right.local_addr().unwrap();
  left.connect(right_addr).unwrap();
  right.connect(left_addr).unwrap();
  let left = UdpSocket::from_std(left, &handle).unwrap();
  let right = UdpSocket::from_std(right, &handle).unwrap();

  outsider.send_to(b"outsider", right_addr).unwrap();
  assert_eq!(block_on(left.send(b"first-message")).unwrap(), 13);
  let mut short = [0; 3];
  assert_eq!(block_on(right.peek(&mut short)).unwrap(), 3);
  assert_eq!(&short, b"fir");
  let mut full = [0; 32];
  let (length, source) = block_on(right.peek_from(&mut full)).unwrap();
  assert_eq!(source, left_addr);
  assert_eq!(&full[..length], b"first-message");
  assert_eq!(block_on(right.recv(&mut short)).unwrap(), 3);
  assert_eq!(&short, b"fir");

  // Truncating receive discards the remainder, unlike a short peek.
  block_on(left.send(b"next")).unwrap();
  let length = block_on(right.recv(&mut full)).unwrap();
  assert_eq!(&full[..length], b"next");
  assert_eq!(block_on(left.send(&[])).unwrap(), 0);
  assert_eq!(block_on(right.peek(&mut full)).unwrap(), 0);
  assert_eq!(block_on(right.recv(&mut full)).unwrap(), 0);
  block_on(left.send(b"discard-by-empty-buffer")).unwrap();
  assert_eq!(block_on(right.recv(&mut [])).unwrap(), 0);
  block_on(left.send(b"after-empty")).unwrap();
  let length = block_on(right.recv(&mut full)).unwrap();
  assert_eq!(&full[..length], b"after-empty");
  assert_eq!(handle.waiters(), 0);
}

#[test]
fn cancelled_udp_peek_releases_waiter_and_zero_buffer_peek_keeps_datagram() {
  let reactor = reactor(1);
  let handle = reactor.handle();
  let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
  let address = socket.local_addr().unwrap();
  let peer = StdUdpSocket::bind("127.0.0.1:0").unwrap();
  let socket = UdpSocket::from_std(socket, &handle).unwrap();
  let mut byte = [0; 1];
  {
    let mut future = pin!(socket.peek_from(&mut byte));
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    assert_eq!(handle.waiters(), 1);
  }
  assert_eq!(handle.waiters(), 0);
  peer.send_to(b"preserve", address).unwrap();
  let (length, source) = block_on(socket.peek_from(&mut [])).unwrap();
  assert_eq!(length, 0);
  assert_eq!(source, peer.local_addr().unwrap());
  let mut bytes = [0; 16];
  let length = block_on(socket.recv(&mut bytes)).unwrap();
  assert_eq!(&bytes[..length], b"preserve");
  assert_eq!(handle.waiters(), 0);
}

#[cfg(unix)]
#[test]
fn unix_datagram_preserves_each_send_as_one_message() {
  use std::os::unix::net::UnixDatagram as StdUnixDatagram;

  let reactor = reactor(2);
  let handle = reactor.handle();
  let (left, right) = StdUnixDatagram::pair().unwrap();
  let left = super::UnixDatagram::from_std(left, &handle).unwrap();
  let right = super::UnixDatagram::from_std(right, &handle).unwrap();
  assert_eq!(block_on(left.send(b"a")).unwrap(), 1);
  assert_eq!(block_on(left.send(b"bc")).unwrap(), 2);
  let mut buf = [0; 8];
  let first = block_on(right.recv(&mut buf)).unwrap();
  assert_eq!(&buf[..first], b"a");
  let second = block_on(right.recv(&mut buf)).unwrap();
  assert_eq!(&buf[..second], b"bc");
}

#[test]
fn accepted_socket_is_returned_when_registration_table_is_full() {
  let reactor = reactor(1);
  let handle = reactor.handle();
  let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
  let address = listener.local_addr().unwrap();
  let listener = TcpListener::from_std(listener, &handle).unwrap();
  let mut peer = StdTcpStream::connect_timeout(&address, IO_TIMEOUT).unwrap();
  set_tcp_timeouts(&peer);
  peer.write_all(b"kept").unwrap();

  let error = block_on(listener.accept()).unwrap_err();
  let super::AcceptError::Registration(error) = error else {
    panic!("expected registration refusal");
  };
  let mut accepted = error.socket;
  set_tcp_timeouts(&accepted);
  let mut received = [0; 4];
  accepted.read_exact(&mut received).unwrap();
  assert_eq!(&received, b"kept");
}

#[test]
fn tcp_socket_listen_autobinds_and_accepts_with_zero_backlog() {
  let reactor = reactor(2);
  let handle = reactor.handle();
  let socket = TcpSocket::new_v4().unwrap();
  let listener = socket.listen(0, &handle).unwrap();
  let address = listener.get_ref().local_addr().unwrap();
  assert_ne!(
    address.port(),
    0,
    "listen should autobind an unbound socket"
  );

  let peer = StdTcpStream::connect_timeout(&address, IO_TIMEOUT).unwrap();
  set_tcp_timeouts(&peer);
  let (accepted, peer_address) = block_on(listener.accept()).unwrap();
  assert_eq!(peer_address, peer.local_addr().unwrap());
  drop((accepted, peer));
  reactor.shutdown().unwrap();
}

#[test]
fn tcp_socket_ip_traffic_class_round_trips_ds_values_and_rejects_overflow() {
  let ipv4 = TcpSocket::new_v4().unwrap();
  let ipv4_ecn = ipv4.tos_v4().unwrap() & 0x03;
  ipv4.set_tos_v4(0x2c).unwrap();
  let observed_ipv4 = ipv4.tos_v4().unwrap();
  assert_eq!(observed_ipv4 & 0xfc, 0x2c);
  assert_eq!(observed_ipv4 & 0x03, ipv4_ecn);
  assert_eq!(
    ipv4.set_tos_v4(256).unwrap_err().kind(),
    std::io::ErrorKind::InvalidInput
  );
  assert_eq!(ipv4.tos_v4().unwrap(), observed_ipv4);

  let ipv6 = TcpSocket::new_v6().unwrap();
  let ipv6_ecn = ipv6.tclass_v6().unwrap() & 0x03;
  ipv6.set_tclass_v6(0x38).unwrap();
  let observed_ipv6 = ipv6.tclass_v6().unwrap();
  assert_eq!(observed_ipv6 & 0xfc, 0x38);
  assert_eq!(observed_ipv6 & 0x03, ipv6_ecn);
  assert_eq!(
    ipv6.set_tclass_v6(u32::MAX).unwrap_err().kind(),
    std::io::ErrorKind::InvalidInput
  );
  assert_eq!(ipv6.tclass_v6().unwrap(), observed_ipv6);
}

#[cfg(target_os = "linux")]
#[test]
fn tcp_socket_device_binding_validates_inputs_and_reads_back_kernel_state() {
  let socket = TcpSocket::new_v4().unwrap();
  assert_eq!(socket.device().unwrap(), None);
  socket.bind_device(None).unwrap();
  socket.bind_device(Some(b"")).unwrap();
  for invalid in [b"lo\0bad".as_slice(), vec![b'x'; libc::IFNAMSIZ].as_slice()] {
    assert_eq!(
      socket.bind_device(Some(invalid)).unwrap_err().kind(),
      std::io::ErrorKind::InvalidInput
    );
  }
  assert_eq!(socket.device().unwrap(), None);

  match socket.bind_device(Some(b"lo")) {
    Ok(()) => {
      assert_eq!(socket.device().unwrap().as_deref(), Some(b"lo".as_slice()));
      socket.bind_device(None).unwrap();
      assert_eq!(socket.device().unwrap(), None);
    }
    Err(error) if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => {
      // Some containers do not grant the network capability needed for this option.
      assert_eq!(socket.device().unwrap(), None);
    }
    Err(error) => panic!("binding to loopback failed unexpectedly: {error}"),
  }
}

#[test]
fn tcp_socket_linger_is_checked_and_reset_before_drop() {
  let socket = TcpSocket::new_v4().unwrap();
  assert_eq!(socket.linger().unwrap(), None);

  socket.set_linger(Some(Duration::from_millis(1))).unwrap();
  assert_eq!(socket.linger().unwrap(), Some(Duration::from_secs(1)));
  assert!(socket.set_linger(Some(Duration::MAX)).is_err());
  assert_eq!(socket.linger().unwrap(), Some(Duration::from_secs(1)));

  socket.set_zero_linger().unwrap();
  assert_eq!(socket.linger().unwrap(), Some(Duration::ZERO));
  socket.set_linger(None).unwrap();
  assert_eq!(socket.linger().unwrap(), None);
}

#[test]
fn negative_listen_backlog_returns_unchanged_socket_for_retry() {
  let reactor = reactor(2);
  let handle = reactor.handle();
  let socket = TcpSocket::new_v4().unwrap();
  socket.bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
  let before = socket.local_addr().unwrap();

  let socket = match socket.listen(-1, &handle) {
    Err(TcpListenError::InvalidBacklog {
      backlog: -1,
      socket,
    }) => socket,
    other => panic!("expected preflight backlog rejection, got {other:?}"),
  };
  assert_eq!(socket.local_addr().unwrap(), before);

  let listener = socket.listen(1, &handle).unwrap();
  assert_eq!(listener.get_ref().local_addr().unwrap(), before);
  reactor.shutdown().unwrap();
}

#[test]
fn failed_listen_returns_socket_for_explicit_retry() {
  let reactor = reactor(2);
  let handle = reactor.handle();
  let reusable_socket = || {
    let socket = TcpSocket::new_v4().unwrap();
    rustix::net::sockopt::set_socket_reuseaddr(&socket.fd, true).unwrap();
    socket
  };
  let first = reusable_socket();
  first.bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
  let address = first.local_addr().unwrap();
  let second = reusable_socket();
  second.bind(address).unwrap();
  let listener = first.listen(8, &handle).unwrap();
  let second_fd = second.fd.as_raw_fd();

  let (error, second) = match second.listen(8, &handle) {
    Err(TcpListenError::Listen { error, socket }) => (error, socket),
    other => panic!("expected listen syscall failure with socket recovery, got {other:?}"),
  };
  assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
  assert_eq!(second.fd.as_raw_fd(), second_fd);
  assert_eq!(second.local_addr().unwrap(), address);

  drop(listener);
  let listener = second.listen(8, &handle).unwrap();
  assert_eq!(listener.get_ref().local_addr().unwrap(), address);
  drop(listener);
  reactor.shutdown().unwrap();
}

#[test]
fn listen_registration_failure_returns_listener_for_another_reactor() {
  let full_reactor = reactor(1);
  let full_handle = full_reactor.handle();
  let held = StdUdpSocket::bind("127.0.0.1:0").unwrap();
  let _held = UdpSocket::from_std(held, &full_handle).unwrap();

  let socket = TcpSocket::new_v4().unwrap();
  socket.bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
  let error = socket.listen(8, &full_handle).unwrap_err();
  let listener = match error {
    TcpListenError::Registration { listener, .. } => listener,
    other => panic!("expected registration failure with listener recovery, got {other:?}"),
  };
  let address = listener.local_addr().unwrap();

  let replacement_reactor = reactor(2);
  let replacement_handle = replacement_reactor.handle();
  let listener = TcpListener::from_std(listener, &replacement_handle).unwrap();
  let peer = StdTcpStream::connect_timeout(&address, IO_TIMEOUT).unwrap();
  set_tcp_timeouts(&peer);
  let (accepted, _) = block_on(listener.accept()).unwrap();
  drop((accepted, peer));

  replacement_reactor.shutdown().unwrap();
  full_reactor.shutdown().unwrap();
}

#[test]
fn stale_accept_readiness_is_cleared_then_rearmed() {
  let reactor = reactor(4);
  let handle = reactor.handle();
  let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
  let address = listener.local_addr().unwrap();
  let duplicate = listener.try_clone().unwrap();
  let listener = TcpListener::from_std(listener, &handle).unwrap();
  let other_listener = TcpListener::from_std(duplicate, &handle).unwrap();
  let _first_client = StdTcpStream::connect_timeout(&address, IO_TIMEOUT).unwrap();
  drop(block_on(listener.fd.readable()).unwrap());
  let (consumed, _) = other_listener.get_ref().accept().unwrap();
  drop(consumed);

  {
    let mut future = pin!(listener.accept());
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    let _second_client = StdTcpStream::connect_timeout(&address, IO_TIMEOUT).unwrap();
    let (stream, _) = block_on(future.as_mut()).unwrap();
    drop(stream);
  }
}

#[test]
fn rejected_registration_returns_the_socket() {
  let reactor = reactor(1);
  let handle = reactor.handle();
  let held = StdUdpSocket::bind("127.0.0.1:0").unwrap();
  let _held = UdpSocket::from_std(held, &handle).unwrap();
  let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
  let address = socket.local_addr().unwrap();
  let error = UdpSocket::from_std(socket, &handle).unwrap_err();
  assert_eq!(error.socket.local_addr().unwrap(), address);
}

#[test]
fn connect_runs_on_the_blocking_pool_and_releases_its_network_permit() {
  let mut runtime = Runtime::new(Config {
    workers: 1,
    max_outstanding: 2,
    capacity: Resources::ZERO,
  })
  .unwrap();
  let reactor = reactor(2);
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 0,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 1,
  });
  let net = NetHandle::new(runtime.handle(), scope.clone(), reactor.handle(), 4).unwrap();
  let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
  let address = listener.local_addr().unwrap();
  listener.set_nonblocking(true).unwrap();

  let stream = block_on(net.connect(address)).unwrap();
  let deadline = Instant::now() + IO_TIMEOUT;
  let (mut peer, _) = loop {
    match listener.accept() {
      Ok(accepted) => break accepted,
      Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
        assert!(
          Instant::now() < deadline,
          "blocking-pool connect was not accepted"
        );
        thread::sleep(Duration::from_millis(1));
      }
      Err(error) => panic!("TCP accept failed: {error}"),
    }
  };
  set_tcp_timeouts(&peer);
  assert_eq!(block_on(stream.write(b"hello")).unwrap(), 5);
  let mut received = [0; 5];
  peer.read_exact(&mut received).unwrap();
  assert_eq!(&received, b"hello");
  peer.write_all(b"reply").unwrap();
  let mut response = [0; 5];
  assert_eq!(block_on(stream.read(&mut response)).unwrap(), 5);
  assert_eq!(&response, b"reply");
  block_on(stream.shutdown()).unwrap();
  assert_eq!(peer.read(&mut response).unwrap(), 0);
  assert_eq!(scope.snapshot().network_ops, 0);
  assert_eq!(stream.get_ref().peer_addr().unwrap(), address);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn tcp_stream_quickack_round_trips_kernel_value() {
  let reactor = reactor(1);
  let handle = reactor.handle();
  let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
  let client = StdTcpStream::connect(listener.local_addr().unwrap()).unwrap();
  let (accepted, _) = listener.accept().unwrap();
  let stream = super::TcpStream::from_std(accepted, &handle).unwrap();

  stream.set_quickack(true).unwrap();
  assert!(stream.quickack().unwrap());
  stream.set_quickack(false).unwrap();
  assert!(!stream.quickack().unwrap());

  stream.set_linger(Some(Duration::from_millis(1))).unwrap();
  assert_eq!(stream.linger().unwrap(), Some(Duration::from_secs(1)));
  stream.set_zero_linger().unwrap();
  assert_eq!(stream.linger().unwrap(), Some(Duration::ZERO));
  stream.set_linger(None).unwrap();
  assert_eq!(stream.linger().unwrap(), None);

  drop(stream);
  drop(client);
  reactor.shutdown().unwrap();
}

#[test]
fn nonblocking_tcp_connect_preserves_bound_port_and_transfers_data() {
  let mut blocking = Runtime::new(Config {
    workers: 1,
    max_outstanding: 2,
    capacity: Resources::ZERO,
  })
  .unwrap();
  let reactor = reactor(4);
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 0,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 1,
  });
  let net = NetHandle::new(blocking.handle(), scope.clone(), reactor.handle(), 4).unwrap();
  let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
  let address = listener.local_addr().unwrap();
  listener.set_nonblocking(true).unwrap();

  let socket = TcpSocket::new_v4().unwrap();
  socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
  let local = socket.local_addr().unwrap();
  let stream = block_on(net.connect_socket(socket, address)).unwrap();
  let deadline = Instant::now() + IO_TIMEOUT;
  let (mut peer, peer_address) = loop {
    match listener.accept() {
      Ok(accepted) => break accepted,
      Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
        assert!(
          Instant::now() < deadline,
          "nonblocking connection not accepted"
        );
        thread::sleep(Duration::from_millis(1));
      }
      Err(error) => panic!("TCP accept failed: {error}"),
    }
  };
  set_tcp_timeouts(&peer);
  assert_eq!(peer_address, local);
  assert_eq!(stream.get_ref().peer_addr().unwrap(), address);
  assert_eq!(reactor.handle().registrations(), 1);
  assert_eq!(scope.snapshot().network_ops, 0);

  assert_eq!(block_on(stream.write(b"ping")).unwrap(), 4);
  let mut received = [0; 4];
  peer.read_exact(&mut received).unwrap();
  assert_eq!(&received, b"ping");
  peer.write_all(b"pong").unwrap();
  assert_eq!(block_on(stream.read(&mut received)).unwrap(), 4);
  assert_eq!(&received, b"pong");
  drop(stream);
  assert_eq!(reactor.handle().registrations(), 0);
  blocking.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn nonblocking_ipv6_tcp_connect_works_when_loopback_is_available() {
  let listener = match StdTcpListener::bind("[::1]:0") {
    Ok(listener) => listener,
    Err(error)
      if matches!(
        error.kind(),
        std::io::ErrorKind::AddrNotAvailable
          | std::io::ErrorKind::PermissionDenied
          | std::io::ErrorKind::Unsupported
      ) =>
    {
      eprintln!("IPv6 loopback unavailable; IPv6 connect test skipped: {error}");
      return;
    }
    Err(error) => panic!("IPv6 loopback setup failed unexpectedly: {error}"),
  };
  let address = listener.local_addr().unwrap();
  let reactor = reactor(2);
  let mut blocking = Runtime::new(Config {
    workers: 1,
    max_outstanding: 1,
    capacity: Resources::ZERO,
  })
  .unwrap();
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 0,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 1,
  });
  let net = NetHandle::new(blocking.handle(), scope, reactor.handle(), 1).unwrap();
  let stream = block_on(net.connect_nonblocking(address)).unwrap();
  let (peer, _) = listener.accept().unwrap();
  assert_eq!(stream.get_ref().peer_addr().unwrap(), address);
  drop(peer);
  drop(stream);
  blocking.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn tcp_socket_import_rejection_returns_the_same_listening_descriptor() {
  let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
  let address = listener.local_addr().unwrap();
  let fd: OwnedFd = listener.into();
  let raw = fd.as_raw_fd();
  let rejected = TcpSocket::from_owned_fd(fd).unwrap_err();
  assert_eq!(rejected.socket.as_raw_fd(), raw);
  let returned = StdTcpListener::from(rejected.socket);
  assert_eq!(returned.local_addr().unwrap(), address);
}

#[test]
fn tcp_socket_import_accepts_a_nonblocking_unconnected_tcp_descriptor() {
  let socket = TcpSocket::new_v4().unwrap();
  let imported = TcpSocket::from_owned_fd(socket.into_owned_fd()).unwrap();
  imported.bind("127.0.0.1:0".parse().unwrap()).unwrap();
  assert_eq!(
    imported.local_addr().unwrap().ip(),
    "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
  );
}

#[test]
fn tcp_socket_common_options_round_trip_kernel_values() {
  let socket = TcpSocket::new_v4().unwrap();

  socket.set_reuseaddr(true).unwrap();
  assert!(socket.reuseaddr().unwrap());
  socket.set_reuseaddr(false).unwrap();
  assert!(!socket.reuseaddr().unwrap());

  socket.set_reuseport(true).unwrap();
  assert!(socket.reuseport().unwrap());
  socket.set_reuseport(false).unwrap();
  assert!(!socket.reuseport().unwrap());

  socket.set_keepalive(true).unwrap();
  assert!(socket.keepalive().unwrap());
  socket.set_keepalive(false).unwrap();
  assert!(!socket.keepalive().unwrap());

  socket.set_nodelay(true).unwrap();
  assert!(socket.nodelay().unwrap());
  socket.set_nodelay(false).unwrap();
  assert!(!socket.nodelay().unwrap());

  socket.set_send_buffer_size(4096).unwrap();
  let send_size = socket.send_buffer_size().unwrap();
  assert!(send_size > 0);
  assert_eq!(
    socket.set_send_buffer_size(u32::MAX).unwrap_err().kind(),
    std::io::ErrorKind::InvalidInput
  );
  assert_eq!(socket.send_buffer_size().unwrap(), send_size);
  socket.set_recv_buffer_size(4096).unwrap();
  let receive_size = socket.recv_buffer_size().unwrap();
  assert!(receive_size > 0);
  assert_eq!(
    socket.set_recv_buffer_size(u32::MAX).unwrap_err().kind(),
    std::io::ErrorKind::InvalidInput
  );
  assert_eq!(socket.recv_buffer_size().unwrap(), receive_size);

  assert!(socket.take_error().unwrap().is_none());
}

#[test]
fn tcp_socket_take_error_consumes_a_completed_refusal_once() {
  let reactor = reactor(2);
  let handle = reactor.handle();
  let target = TcpSocket::new_v4().unwrap();
  target.bind("127.0.0.1:0".parse().unwrap()).unwrap();
  let address = target.local_addr().unwrap();

  let socket = TcpSocket::new_v4().unwrap();
  let alias_fd = socket.fd.try_clone().unwrap();
  let alias = TcpSocket::from_owned_fd(alias_fd).unwrap();
  let alias = super::TcpStream::from_std(alias.into_stream(), &handle).unwrap();

  assert_eq!(
    rustix::net::connect(&socket.fd, &address),
    Err(rustix::io::Errno::INPROGRESS)
  );
  let ready = block_on(alias.fd.writable()).unwrap();
  drop(ready);

  let error = socket.take_error().unwrap().unwrap();
  assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
  assert!(socket.take_error().unwrap().is_none());
  drop(alias);
  drop(target);
  reactor.shutdown().unwrap();
}

#[test]
fn socket_buffer_size_conversion_rejects_kernel_values_above_u32() {
  let error = super::kernel_buffer_size_u32(u32::MAX as usize + 1).unwrap_err();
  assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn tcp_connect_rejections_before_connect_return_the_supplied_socket() {
  let mut blocking = Runtime::new(Config {
    workers: 1,
    max_outstanding: 1,
    capacity: Resources::ZERO,
  })
  .unwrap();
  let reactor = reactor(1);
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 0,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let net = NetHandle::new(blocking.handle(), scope, reactor.handle(), 1).unwrap();
  let socket = TcpSocket::new_v4().unwrap();
  socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
  let local = socket.local_addr().unwrap();
  let error = block_on(net.connect_socket(socket, "127.0.0.1:9".parse().unwrap())).unwrap_err();
  match error {
    TcpConnectError::Submission(error) => {
      assert!(matches!(error.kind, TcpConnectRejectKind::Resource(_)));
      assert_eq!(error.socket.local_addr().unwrap(), local);
    }
    TcpConnectError::Operation(error) => panic!("unexpected operation error: {error}"),
  }
  assert_eq!(reactor.handle().registrations(), 0);
  assert_eq!(reactor.handle().waiters(), 0);
  blocking.shutdown(ShutdownMode::Drain).unwrap();

  let mut blocking = Runtime::new(Config {
    workers: 1,
    max_outstanding: 1,
    capacity: Resources::ZERO,
  })
  .unwrap();
  let reactor = self::reactor(1);
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 0,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 1,
  });
  let handle = reactor.handle();
  let _registered =
    TcpListener::from_std(StdTcpListener::bind("127.0.0.1:0").unwrap(), &handle).unwrap();
  let net = NetHandle::new(blocking.handle(), scope, handle.clone(), 1).unwrap();
  let socket = TcpSocket::new_v4().unwrap();
  socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
  let local = socket.local_addr().unwrap();
  let error = block_on(net.connect_socket(socket, "127.0.0.1:9".parse().unwrap())).unwrap_err();
  match error {
    TcpConnectError::Submission(error) => {
      assert!(matches!(error.kind, TcpConnectRejectKind::Registration(_)));
      assert_eq!(error.socket.local_addr().unwrap(), local);
      assert!(matches!(
        rustix::net::getpeername(&error.socket.fd),
        Ok(None) | Err(rustix::io::Errno::NOTCONN)
      ));
    }
    TcpConnectError::Operation(error) => panic!("unexpected operation error: {error}"),
  }
  assert_eq!(handle.registrations(), 1);
  assert_eq!(handle.waiters(), 0);
  drop(_registered);
  assert_eq!(handle.registrations(), 0);
  blocking.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn refused_nonblocking_connect_releases_its_permit_and_registration() {
  let mut blocking = Runtime::new(Config {
    workers: 1,
    max_outstanding: 1,
    capacity: Resources::ZERO,
  })
  .unwrap();
  let reactor = reactor(2);
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 0,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 1,
  });
  let net = NetHandle::new(blocking.handle(), scope.clone(), reactor.handle(), 1).unwrap();
  // A bound, non-listening socket reserves the refusal address throughout
  // this check, so parallel tests cannot turn it into a live listener.
  let reservation = TcpSocket::new_v4().unwrap();
  rustix::net::sockopt::set_socket_reuseaddr(&reservation.fd, false).unwrap();
  reservation.bind("127.0.0.1:0".parse().unwrap()).unwrap();
  let address = reservation.local_addr().unwrap();

  match block_on(net.connect_nonblocking(address)) {
    Err(TcpConnectError::Operation(NetworkError::Io(error))) => {
      assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    }
    Err(error) => panic!("unexpected connect error: {error}"),
    Ok(_) => panic!("connection to a non-listening loopback socket unexpectedly succeeded"),
  }
  assert_eq!(scope.snapshot().network_ops, 0);
  assert_eq!(reactor.handle().registrations(), 0);
  assert_eq!(reactor.handle().waiters(), 0);
  drop(reservation);
  blocking.shutdown(ShutdownMode::Drain).unwrap();

  let mut blocking = Runtime::new(Config {
    workers: 1,
    max_outstanding: 1,
    capacity: Resources::ZERO,
  })
  .unwrap();
  let reactor = self::reactor(1);
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 0,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 1,
  });
  let net = NetHandle::new(blocking.handle(), scope, reactor.handle(), 1).unwrap();
  let socket = TcpSocket::new_v4().unwrap();
  socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
  let local = socket.local_addr().unwrap();
  let error = block_on(net.connect_socket(socket, "[::1]:9".parse().unwrap())).unwrap_err();
  match error {
    TcpConnectError::Submission(error) => {
      assert!(matches!(error.kind, TcpConnectRejectKind::Socket(_)));
      assert_eq!(error.socket.local_addr().unwrap(), local);
    }
    TcpConnectError::Operation(error) => panic!("unexpected operation error: {error}"),
  }
  assert_eq!(reactor.handle().registrations(), 0);
  blocking.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn connect_probe_errors_are_terminal_except_peer_not_connected_after_zero_so_error() {
  assert!(matches!(classify_connect_start(Ok(())), Ok(false)));
  assert!(matches!(
    classify_connect_start(Err(rustix::io::Errno::INPROGRESS)),
    Ok(true)
  ));
  for error in [rustix::io::Errno::AGAIN, rustix::io::Errno::ALREADY] {
    let returned = classify_connect_start(Err(error)).unwrap_err();
    assert_eq!(returned.raw_os_error(), Some(error.raw_os_error()));
  }

  let peer_called = std::sync::atomic::AtomicBool::new(false);
  let not_connected = classify_connect_probe(Err(rustix::io::Errno::NOTCONN), || {
    peer_called.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok("127.0.0.1:80".parse().unwrap())
  })
  .unwrap();
  let not_connected_error = finish_connect_probe(Ok(not_connected)).unwrap_err();
  assert_eq!(
    not_connected_error.raw_os_error(),
    Some(rustix::io::Errno::NOTCONN.raw_os_error())
  );
  assert!(!peer_called.load(std::sync::atomic::Ordering::SeqCst));

  let pending = classify_connect_probe(Ok(()), || {
    Err(std::io::Error::from(rustix::io::Errno::NOTCONN))
  })
  .unwrap_err();
  assert_eq!(pending.kind(), std::io::ErrorKind::WouldBlock);
  assert!(matches!(finish_connect_probe(Err(pending)), Ok(false)));

  for error in [
    rustix::io::Errno::CONNREFUSED,
    rustix::io::Errno::AGAIN,
    rustix::io::Errno::INTR,
  ] {
    let probe = classify_connect_probe(Err(error), || {
      panic!("peer lookup must not follow nonzero SO_ERROR")
    })
    .unwrap();
    assert!(matches!(probe, ConnectProbeResult::SocketError(_)));
    let returned = finish_connect_probe(Ok(probe)).unwrap_err();
    assert_eq!(returned.raw_os_error(), Some(error.raw_os_error()));
  }
  assert!(matches!(
    finish_connect_probe(Err(std::io::Error::from(rustix::io::Errno::INTR))),
    Ok(false)
  ));
}

#[test]
fn terminal_connect_start_error_is_not_replayed_and_releases_owners() {
  let reactor = reactor(1);
  let handle = reactor.handle();
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 0,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 1,
  });
  let permit = scope
    .try_acquire(OperationRequest {
      disk: 0,
      network: 1,
    })
    .unwrap();
  let socket = TcpSocket::new_v4().unwrap();
  let stream = super::TcpStream::from_std(socket.into_stream(), &handle).unwrap();
  let attempt = ConnectAttempt::new(stream, permit);
  let calls = std::sync::atomic::AtomicUsize::new(0);
  let error = initiate_tcp_connect(
    attempt.stream_ref(),
    &"127.0.0.1:80".parse().unwrap(),
    |_, _| {
      calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
      Err(rustix::io::Errno::AGAIN)
    },
  )
  .unwrap_err();
  assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
  assert_eq!(
    error.raw_os_error(),
    Some(rustix::io::Errno::AGAIN.raw_os_error())
  );
  drop(attempt);
  assert_eq!(scope.snapshot().network_ops, 0);
  assert_eq!(handle.registrations(), 0);
  assert_eq!(handle.waiters(), 0);
}

#[test]
fn cancellation_drops_stale_connect_waiter_before_socket_and_permit() {
  struct PausedService {
    entered: mpsc::SyncSender<()>,
    release: std::sync::Mutex<mpsc::Receiver<()>>,
  }

  impl Wake for PausedService {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      let _ = self.entered.try_send(());
      // A failed test must never leave the reactor service blocked forever.
      let _ = self.release.lock().unwrap().recv_timeout(IO_TIMEOUT);
    }
  }

  struct ReleaseService(mpsc::SyncSender<()>);

  impl Drop for ReleaseService {
    fn drop(&mut self) {
      let _ = self.0.try_send(());
    }
  }

  let reactor = reactor(2);
  let handle = reactor.handle();
  let (control, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
  control.set_nonblocking(true).unwrap();
  let control = handle.register(control).unwrap();
  let (entered, entered_rx) = mpsc::sync_channel(1);
  let (release, release_rx) = mpsc::sync_channel(1);
  // Declared after the reactor: release runs first, including during unwind.
  let release_service = ReleaseService(release);
  let control_waker = Waker::from(Arc::new(PausedService {
    entered,
    release: std::sync::Mutex::new(release_rx),
  }));
  let mut control_wait = pin!(control.readable());
  assert!(matches!(
    control_wait
      .as_mut()
      .poll(&mut Context::from_waker(&control_waker)),
    Poll::Pending
  ));
  peer.write_all(b"pause").unwrap();
  entered_rx.recv_timeout(IO_TIMEOUT).unwrap();

  // An unconnected TCP socket can repeatedly deliver stale EPOLLOUT. With
  // the service paused, this fresh registration has no cached readiness and
  // its Pending poll deterministically stores one waiter rather than merely
  // yielding after the endpoint-call budget is exhausted.
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 0,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 1,
  });
  let permit = scope
    .try_acquire(OperationRequest {
      disk: 0,
      network: 1,
    })
    .unwrap();
  let socket = TcpSocket::new_v4().unwrap();
  let stream = super::TcpStream::from_std(socket.into_stream(), &handle).unwrap();
  let mut attempt = ConnectAttempt::new(stream, permit);
  assert_eq!(handle.registrations(), 2);
  {
    let mut waiting = pin!(wait_for_tcp_connect(&mut attempt, 1));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(waiting.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(handle.waiters(), 1);
  }
  drop(attempt);
  assert_eq!(scope.snapshot().network_ops, 0);
  assert_eq!(handle.waiters(), 0);
  assert_eq!(handle.registrations(), 1);
  drop(release_service);
}

#[test]
fn resolver_output_never_exceeds_its_bound_plus_one_overflow_item() {
  let mut runtime = Runtime::new(Config {
    workers: 1,
    max_outstanding: 2,
    capacity: Resources::ZERO,
  })
  .unwrap();
  let reactor = reactor(1);
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 2 * super::ADDRESS_RECORD_BYTES,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 1,
  });
  let net = NetHandle::new(runtime.handle(), scope.clone(), reactor.handle(), 1).unwrap();

  let addresses = match block_on(net.resolve("localhost".to_owned(), 80)) {
    Ok(addresses) => addresses,
    Err(ResolveError::Operation(NetworkError::TooManyAddresses(addresses))) => addresses,
    Err(ResolveError::Operation(NetworkError::Io(error))) => {
      panic!("localhost resolution failed: {error}")
    }
    Err(error) => panic!("unexpected resolver error: {error}"),
  };
  assert!(addresses.len() <= 2);
  let charged = addresses.charged_bytes();
  assert_eq!(scope.snapshot().managed_memory, charged);
  assert_eq!(scope.snapshot().network_ops, 0);
  let clone = addresses.clone();
  drop(addresses);
  assert_eq!(scope.snapshot().managed_memory, charged);
  drop(clone);
  assert_eq!(scope.snapshot().managed_memory, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn dns_memory_rejection_returns_the_owned_hostname() {
  let mut runtime = Runtime::new(Config {
    workers: 1,
    max_outstanding: 2,
    capacity: Resources::ZERO,
  })
  .unwrap();
  let reactor = reactor(1);
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 0,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 1,
  });
  let net = NetHandle::new(runtime.handle(), scope.clone(), reactor.handle(), 1).unwrap();

  let error = block_on(net.resolve("keep-this-host".to_owned(), 443)).unwrap_err();
  let ResolveError::Submission(error) = error else {
    panic!("expected DNS memory admission failure");
  };
  assert_eq!(error.host, "keep-this-host");
  assert_eq!(error.port, 443);
  assert!(matches!(error.kind, ResolveSubmissionKind::Resource(_)));
  assert_eq!(scope.snapshot().managed_memory, 0);
  assert_eq!(scope.snapshot().network_ops, 0);
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn dns_runtime_rejection_returns_the_owned_hostname() {
  let mut runtime = Runtime::new(Config {
    workers: 1,
    max_outstanding: 1,
    capacity: Resources::ZERO,
  })
  .unwrap();
  let reactor = reactor(1);
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 2 * super::ADDRESS_RECORD_BYTES,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 1,
  });
  let handle = runtime.handle();
  runtime.shutdown(ShutdownMode::Drain).unwrap();
  let net = NetHandle::new(handle, scope.clone(), reactor.handle(), 1).unwrap();

  let error = block_on(net.resolve("retry.this.host".to_owned(), 53)).unwrap_err();
  let ResolveError::Submission(error) = error else {
    panic!("expected runtime admission failure");
  };
  assert_eq!(error.host, "retry.this.host");
  assert_eq!(error.port, 53);
  assert!(matches!(error.kind, ResolveSubmissionKind::Runtime(_)));
  assert_eq!(scope.snapshot().network_ops, 0);
  assert_eq!(scope.snapshot().managed_memory, 0);
}

#[test]
fn dropping_dns_future_keeps_charges_until_blocking_worker_cleanup() {
  let mut runtime = Runtime::new(Config {
    workers: 1,
    max_outstanding: 2,
    capacity: Resources::ZERO,
  })
  .unwrap();
  let reactor = reactor(1);
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 2 * super::ADDRESS_RECORD_BYTES,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 1,
  });
  let net = NetHandle::new(runtime.handle(), scope.clone(), reactor.handle(), 1).unwrap();
  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let blocker = runtime
    .try_spawn(Resources::ZERO, move |_token| {
      started_tx.send(()).unwrap();
      release_rx.recv_timeout(IO_TIMEOUT).unwrap();
    })
    .unwrap();
  started_rx.recv_timeout(IO_TIMEOUT).unwrap();

  {
    let mut future = pin!(net.resolve("127.0.0.1".to_owned(), 80));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(scope.snapshot().network_ops, 1);
    assert_eq!(
      scope.snapshot().managed_memory,
      2 * super::ADDRESS_RECORD_BYTES
    );
  }
  release_tx.send(()).unwrap();
  blocker.join().unwrap();

  let deadline = Instant::now() + Duration::from_secs(3);
  loop {
    let snapshot = scope.snapshot();
    if snapshot.network_ops == 0 && snapshot.managed_memory == 0 {
      break;
    }
    assert!(
      Instant::now() < deadline,
      "detached resolver did not release charges"
    );
    thread::yield_now();
  }
  runtime.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn malformed_dns_records_are_rejected_without_unsafe_decoding() {
  assert_eq!(
    super::decode_address(&[0; super::ADDRESS_RECORD_BYTES]),
    None
  );
  assert_eq!(
    super::decode_address(&[4; super::ADDRESS_RECORD_BYTES - 1]),
    None
  );
  assert_eq!(
    super::decode_address(&[9; super::ADDRESS_RECORD_BYTES]),
    None
  );
}

#[test]
fn bounded_resolver_retains_only_one_overflow_address() {
  let addresses = [
    "127.0.0.1:80".parse::<SocketAddr>().unwrap(),
    "127.0.0.2:80".parse::<SocketAddr>().unwrap(),
    "127.0.0.3:80".parse::<SocketAddr>().unwrap(),
  ];
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 1024,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let storage = scope
    .try_alloc_zeroed(2 * super::ADDRESS_RECORD_BYTES)
    .unwrap();
  let error = super::collect_bounded(addresses.into_iter(), 1, storage, 0).unwrap_err();
  let NetworkError::TooManyAddresses(observed) = error else {
    panic!("expected bounded overflow");
  };
  assert_eq!(observed.len(), 2);
  assert_eq!(observed.get(0), Some(addresses[0]));
  assert_eq!(observed.get(1), Some(addresses[1]));
}

#[test]
fn resolved_ipv6_preserves_flow_scope_and_shared_memory_charge() {
  let address = SocketAddr::V6(SocketAddrV6::new(
    Ipv6Addr::LOCALHOST,
    4321,
    0x1234_5678,
    0x8765_4321,
  ));
  let scope = ResourceScope::new(ResourceLimits {
    managed_memory: 2 * super::ADDRESS_RECORD_BYTES,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let storage = scope
    .try_alloc_zeroed(2 * super::ADDRESS_RECORD_BYTES)
    .unwrap();
  let addresses = super::collect_bounded([address].into_iter(), 1, storage, 0).unwrap();
  assert_eq!(addresses.get(0), Some(address));
  let charge = addresses.charged_bytes();
  assert_eq!(scope.snapshot().managed_memory, charge);

  let clone = addresses.clone();
  drop(addresses);
  assert_eq!(scope.snapshot().managed_memory, charge);
  drop(clone);
  assert_eq!(scope.snapshot().managed_memory, 0);
}
