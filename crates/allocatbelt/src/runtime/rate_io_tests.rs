use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::Duration;

use super::*;
use crate::runtime::asynchronous::{LocalConfig, LocalRuntime};
use crate::runtime::io::{AsyncReadExt, AsyncWriteExt, POLL_BUDGET};
use crate::runtime::reactor::{Reactor, ReactorConfig};
use crate::runtime::time::TimerDriver;

#[derive(Debug)]
enum Action {
  Count(usize),
  PanicAfterCount(usize),
  Pending,
  Error(ErrorKind),
}

#[derive(Debug)]
struct ScriptIo {
  reads: VecDeque<Action>,
  writes: VecDeque<Action>,
  read_calls: usize,
  write_calls: usize,
  flush_calls: usize,
  shutdown_calls: usize,
  accepted: Vec<u8>,
}

impl ScriptIo {
  fn new(
    reads: impl IntoIterator<Item = Action>,
    writes: impl IntoIterator<Item = Action>,
  ) -> Self {
    Self {
      reads: reads.into_iter().collect(),
      writes: writes.into_iter().collect(),
      read_calls: 0,
      write_calls: 0,
      flush_calls: 0,
      shutdown_calls: 0,
      accepted: Vec::new(),
    }
  }
}

impl AsyncRead for ScriptIo {
  fn poll_read(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    output: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    this.read_calls += 1;
    let action = this.reads.pop_front().unwrap_or(Action::Count(0));
    match action {
      Action::Count(count) => {
        let filled = count.min(output.len());
        output[..filled].fill(b'r');
        Poll::Ready(Ok(count))
      }
      Action::PanicAfterCount(count) => {
        let filled = count.min(output.len());
        output[..filled].fill(b'r');
        panic!("endpoint panicked after consuming a read prefix");
      }
      Action::Pending => Poll::Pending,
      Action::Error(kind) => Poll::Ready(Err(kind.into())),
    }
  }
}

impl AsyncWrite for ScriptIo {
  fn poll_write(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    input: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    this.write_calls += 1;
    let action = this
      .writes
      .pop_front()
      .unwrap_or(Action::Count(input.len()));
    match action {
      Action::Count(count) => {
        let accepted = count.min(input.len());
        this.accepted.extend_from_slice(&input[..accepted]);
        Poll::Ready(Ok(count))
      }
      Action::PanicAfterCount(count) => {
        let accepted = count.min(input.len());
        this.accepted.extend_from_slice(&input[..accepted]);
        panic!("endpoint panicked after accepting a write prefix");
      }
      Action::Pending => Poll::Pending,
      Action::Error(kind) => Poll::Ready(Err(kind.into())),
    }
  }

  fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.as_mut().get_mut().flush_calls += 1;
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.as_mut().get_mut().shutdown_calls += 1;
    Poll::Ready(Ok(()))
  }
}

fn timer(max_registered: usize) -> (TimerDriver, TimerHandle) {
  let driver = TimerDriver::new_realtime(max_registered).expect("fixed real timer driver");
  let handle = driver.handle();
  (driver, handle)
}

fn bucket(rate: u64, burst: usize, reservations: usize) -> ByteRateLimit {
  ByteRateLimit::new(super::super::byte_rate::ByteRateConfig {
    bytes_per_second: rate,
    burst_bytes: burst,
    max_reservations: reservations,
  })
  .expect("valid test bucket")
}

fn context() -> Context<'static> {
  Context::from_waker(Waker::noop())
}

#[derive(Default)]
struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
  fn wake(self: Arc<Self>) {
    self.0.fetch_add(1, Ordering::Relaxed);
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.fetch_add(1, Ordering::Relaxed);
  }
}

fn run_future<F: Future>(future: F) -> F::Output {
  let mut future = Box::pin(future);
  let mut cx = context();
  for _ in 0..10_000 {
    match future.as_mut().poll(&mut cx) {
      Poll::Ready(output) => return output,
      Poll::Pending => thread::sleep(Duration::from_millis(1)),
    }
  }
  panic!("loopback stream operation did not finish")
}

#[test]
fn partial_read_write_and_eof_commit_only_reported_bytes() {
  let (_driver, timer) = timer(4);
  let read = bucket(1, 5, 1);
  let write = bucket(1, 4, 1);
  let inner = ScriptIo::new([Action::Count(2), Action::Count(0)], [Action::Count(2)]);
  let mut stream =
    RateLimitedIo::new(inner, read.clone(), write.clone(), timer).expect("real-clock adapter");
  let mut cx = context();

  let mut output = [0; 8];
  assert!(matches!(
    Pin::new(&mut stream).poll_read(&mut cx, &mut output),
    Poll::Ready(Ok(2))
  ));
  assert_eq!(&output[..2], b"rr");
  assert!(read.snapshot().available_bytes >= 3);
  assert!(read.snapshot().available_bytes <= 5);
  assert_eq!(read.snapshot().reserved_bytes, 0);

  let before_eof = read.snapshot().available_bytes;
  assert!(matches!(
    Pin::new(&mut stream).poll_read(&mut cx, &mut output),
    Poll::Ready(Ok(0))
  ));
  assert!(read.snapshot().available_bytes >= before_eof);

  assert!(matches!(
    Pin::new(&mut stream).poll_write(&mut cx, b"abcdef"),
    Poll::Ready(Ok(2))
  ));
  assert!(write.snapshot().available_bytes >= 2);
  assert_eq!(write.snapshot().reserved_bytes, 0);
  assert_eq!(stream.get_ref().accepted, b"ab");
}

#[test]
fn pending_would_block_and_errors_refund_all_unreported_credit() {
  let (_driver, timer) = timer(4);
  let write = bucket(1, 4, 1);
  let inner = ScriptIo::new(
    [],
    [
      Action::Pending,
      Action::Error(ErrorKind::WouldBlock),
      Action::Error(ErrorKind::PermissionDenied),
    ],
  );
  let mut stream =
    RateLimitedIo::new(inner, bucket(1, 4, 1), write.clone(), timer).expect("real-clock adapter");
  let mut cx = context();

  assert!(
    Pin::new(&mut stream)
      .poll_write(&mut cx, b"data")
      .is_pending()
  );
  assert_eq!(write.snapshot().available_bytes, 4);
  assert_eq!(write.snapshot().reserved_bytes, 0);

  for kind in [ErrorKind::WouldBlock, ErrorKind::PermissionDenied] {
    let error = match Pin::new(&mut stream).poll_write(&mut cx, b"data") {
      Poll::Ready(Err(error)) => error,
      other => panic!("expected {kind:?}, got {other:?}"),
    };
    assert_eq!(error.kind(), kind);
    assert_eq!(write.snapshot().available_bytes, 4);
    assert_eq!(write.snapshot().reserved_bytes, 0);
  }
}

#[test]
fn panicking_endpoints_spend_the_offer_before_a_sibling_can_reuse_credit() {
  use std::panic::{AssertUnwindSafe, catch_unwind};

  let (_driver, timer) = timer(4);
  let read = bucket(1, 4096, 1);
  let write = bucket(1, 4096, 1);
  let mut stream = RateLimitedIo::new(
    ScriptIo::new([Action::PanicAfterCount(3)], [Action::PanicAfterCount(3)]),
    read.clone(),
    write.clone(),
    timer.clone(),
  )
  .expect("real-clock adapter");
  let mut cx = context();
  let mut output = [0; 4096];
  assert!(
    catch_unwind(AssertUnwindSafe(|| {
      let _ = Pin::new(&mut stream).poll_read(&mut cx, &mut output);
    }))
    .is_err()
  );
  assert_eq!(&output[..3], b"rrr");
  assert_eq!(read.snapshot().reserved_bytes, 0);
  assert!(read.snapshot().available_bytes < 4096);

  assert!(
    catch_unwind(AssertUnwindSafe(|| {
      let _ = Pin::new(&mut stream).poll_write(&mut cx, &[b'w'; 4096]);
    }))
    .is_err()
  );
  assert_eq!(stream.get_ref().accepted, b"www");
  assert_eq!(write.snapshot().reserved_bytes, 0);
  assert!(write.snapshot().available_bytes < 4096);

  let mut sibling = RateLimitedIo::new(ScriptIo::new([], []), read, write, timer)
    .expect("real-clock sibling adapter");
  if let Poll::Ready(Ok(bytes)) = Pin::new(&mut sibling).poll_write(&mut cx, &[b'x'; 4096]) {
    assert!(bytes < 4096, "a panic must not refund the complete offer");
  }
}

#[test]
#[cfg(feature = "resource-feedback")]
fn panicking_endpoints_invalidate_only_their_directional_feedback() {
  use std::panic::{AssertUnwindSafe, catch_unwind};

  let (_driver, timer) = timer(4);
  let read_meter = IoFeedbackMeter::new();
  let write_meter = IoFeedbackMeter::new();
  let mut stream = RateLimitedIo::new(
    ScriptIo::new([Action::PanicAfterCount(1)], [Action::PanicAfterCount(1)]),
    bucket(1, 4096, 1),
    bucket(1, 4096, 1),
    timer,
  )
  .expect("real-clock adapter")
  .with_feedback_meters(read_meter.clone(), write_meter.clone());
  let mut cx = context();
  assert!(
    catch_unwind(AssertUnwindSafe(|| {
      let _ = Pin::new(&mut stream).poll_read(&mut cx, &mut [0; 4096]);
    }))
    .is_err()
  );
  assert!(read_meter.snapshot().diagnostics.invalid_io);
  assert!(!write_meter.snapshot().diagnostics.invalid_io);
  assert_eq!(read_meter.snapshot().committed_bytes, 0);
  assert_eq!(read_meter.snapshot().completions, 0);

  assert!(
    catch_unwind(AssertUnwindSafe(|| {
      let _ = Pin::new(&mut stream).poll_write(&mut cx, &[b'w'; 4096]);
    }))
    .is_err()
  );
  assert!(write_meter.snapshot().diagnostics.invalid_io);
  assert_eq!(write_meter.snapshot().committed_bytes, 0);
  assert_eq!(write_meter.snapshot().completions, 0);
}

#[test]
fn exhausted_credit_registers_a_real_wait_without_polling_or_self_waking() {
  let (driver, timer) = timer(4);
  let write = bucket(1, 1, 1);
  let inner = ScriptIo::new([], []);
  let mut stream = RateLimitedIo::new(inner, bucket(1, 1, 1), write.clone(), timer.clone())
    .expect("real-clock adapter");
  let wake = Arc::new(WakeCounter::default());
  let waker = Waker::from(Arc::clone(&wake));
  let mut cx = Context::from_waker(&waker);

  assert!(matches!(
    Pin::new(&mut stream).poll_write(&mut cx, b"x"),
    Poll::Ready(Ok(1))
  ));
  assert!(Pin::new(&mut stream).poll_write(&mut cx, b"y").is_pending());
  assert_eq!(stream.get_ref().write_calls, 1);
  assert_eq!(write.snapshot().available_bytes, 0);
  assert_eq!(write.snapshot().reserved_bytes, 0);
  assert_eq!(timer.registered(), 1);
  assert_eq!(wake.0.load(Ordering::Relaxed), 0);

  let parts = stream.into_parts();
  assert_eq!(timer.registered(), 1, "parts retain the active timer sleep");
  let stream = parts.into_adapter();
  drop(stream);
  assert_eq!(
    timer.registered(),
    0,
    "dropping the adapter cancels its sleep"
  );
  drop(driver);
}

#[test]
fn one_byte_of_replenished_credit_makes_minimum_stream_progress() {
  let (_driver, timer) = timer(4);
  let write = bucket(1_000, 1, 1);
  let inner = ScriptIo::new([], []);
  let mut stream =
    RateLimitedIo::new(inner, bucket(1, 1, 1), write.clone(), timer).expect("real-clock adapter");
  let mut cx = context();

  assert!(matches!(
    Pin::new(&mut stream).poll_write(&mut cx, b"a"),
    Poll::Ready(Ok(1))
  ));
  match Pin::new(&mut stream).poll_write(&mut cx, b"b") {
    Poll::Ready(Ok(1)) => {}
    Poll::Pending => {
      thread::sleep(Duration::from_millis(5));
      assert!(matches!(
        Pin::new(&mut stream).poll_write(&mut cx, b"bc"),
        Poll::Ready(Ok(1))
      ));
    }
    other => panic!("one replenished byte should progress, got {other:?}"),
  }
  assert_eq!(stream.get_ref().accepted, b"ab");
  assert_eq!(write.snapshot().reserved_bytes, 0);
}

#[test]
fn invalid_overcount_is_sticky_and_spends_the_entire_offer() {
  let (_driver, timer) = timer(4);
  let write = bucket(1, 3, 1);
  let inner = ScriptIo::new([], [Action::Count(4)]);
  let mut stream =
    RateLimitedIo::new(inner, bucket(1, 3, 1), write.clone(), timer).expect("real-clock adapter");
  let mut cx = context();

  let error = match Pin::new(&mut stream).poll_write(&mut cx, b"abcdef") {
    Poll::Ready(Err(error)) => error,
    other => panic!("expected invalid count, got {other:?}"),
  };
  assert_eq!(error.kind(), ErrorKind::InvalidData);
  assert_eq!(
    error
      .get_ref()
      .and_then(|source| source.downcast_ref::<RateIoFailure>()),
    Some(&RateIoFailure::InvalidWriteCount {
      reported: 4,
      offered: 3
    })
  );
  assert_eq!(write.snapshot().available_bytes, 0);
  assert_eq!(write.snapshot().reserved_bytes, 0);

  let second = Pin::new(&mut stream).poll_write(&mut cx, b"abcdef");
  assert!(matches!(second, Poll::Ready(Err(error)) if error.kind() == ErrorKind::InvalidData));
  assert_eq!(stream.get_ref().write_calls, 1);
}

#[test]
fn invalid_read_overcount_is_sticky_and_spends_the_entire_offer() {
  let (_driver, timer) = timer(4);
  let read = bucket(1, 3, 1);
  let inner = ScriptIo::new([Action::Count(4)], []);
  let mut stream =
    RateLimitedIo::new(inner, read.clone(), bucket(1, 3, 1), timer).expect("real-clock adapter");
  let mut cx = context();
  let mut output = [0; 8];

  let error = match Pin::new(&mut stream).poll_read(&mut cx, &mut output) {
    Poll::Ready(Err(error)) => error,
    other => panic!("expected invalid count, got {other:?}"),
  };
  assert_eq!(error.kind(), ErrorKind::InvalidData);
  assert_eq!(
    error
      .get_ref()
      .and_then(|source| source.downcast_ref::<RateIoFailure>()),
    Some(&RateIoFailure::InvalidReadCount {
      reported: 4,
      offered: 3
    })
  );
  assert_eq!(read.snapshot().available_bytes, 0);
  assert_eq!(read.snapshot().reserved_bytes, 0);
  assert_eq!(stream.get_ref().read_calls, 1);
}

#[test]
fn mutable_real_and_paused_timers_are_rejected_with_all_inputs() {
  let mutable_driver = TimerDriver::new(4).expect("mutable real timer driver");
  let mutable_timer = mutable_driver.handle();
  assert_eq!(mutable_timer.mode(), ClockMode::Real);
  assert!(!mutable_timer.is_realtime());
  let mutable_inner = ScriptIo::new([], []);
  let mutable_read = bucket(1, 2, 1);
  let mutable_write = bucket(1, 3, 1);
  let error = match RateLimitedIo::new(
    mutable_inner,
    mutable_read.clone(),
    mutable_write.clone(),
    mutable_timer.clone(),
  ) {
    Err(error) => error,
    Ok(_) => panic!("mutable real clock must be rejected"),
  };
  assert_eq!(error.failure(), RateIoFailure::NotRealTimeClock);
  let (inner, returned_read, returned_write, returned_timer) = error.into_inputs();
  assert_eq!(inner.write_calls, 0);
  assert_eq!(returned_read.snapshot(), mutable_read.snapshot());
  assert_eq!(returned_write.snapshot(), mutable_write.snapshot());
  assert_eq!(returned_timer.mode(), ClockMode::Real);
  assert!(!returned_timer.is_realtime());

  let (paused_driver, _) = TimerDriver::new_paused(4).expect("paused timer driver");
  let paused_timer = paused_driver.handle();
  assert_eq!(paused_timer.mode(), ClockMode::PausedManual);
  let paused_inner = ScriptIo::new([], []);
  let paused_read = bucket(1, 2, 1);
  let paused_write = bucket(1, 3, 1);
  let error = match RateLimitedIo::new(
    paused_inner,
    paused_read.clone(),
    paused_write.clone(),
    paused_timer.clone(),
  ) {
    Err(error) => error,
    Ok(_) => panic!("paused clock must be rejected"),
  };
  assert_eq!(error.failure(), RateIoFailure::NotRealTimeClock);
  let (inner, returned_read, returned_write, returned_timer) = error.into_inputs();
  assert_eq!(inner.write_calls, 0);
  assert_eq!(returned_read.snapshot(), paused_read.snapshot());
  assert_eq!(returned_write.snapshot(), paused_write.snapshot());
  assert_eq!(returned_timer.mode(), ClockMode::PausedManual);

  drop(mutable_driver);
  drop(paused_driver);
}

#[test]
fn immutable_real_timer_rejects_pause_through_an_alias_and_keeps_working() {
  let (_driver, timer) = timer(4);
  let mut stream = RateLimitedIo::new(
    ScriptIo::new([], []),
    bucket(1, 1, 1),
    bucket(1, 1, 1),
    timer.clone(),
  )
  .expect("fixed real-clock adapter");

  assert!(timer.pause().is_err(), "a real clock alias cannot pause it");
  assert!(timer.is_realtime());
  assert_eq!(timer.mode(), ClockMode::Real);

  let mut cx = context();
  assert!(matches!(
    Pin::new(&mut stream).poll_write(&mut cx, &[]),
    Poll::Ready(Ok(0))
  ));
  assert!(Pin::new(&mut stream).poll_flush(&mut cx).is_ready());
  assert_eq!(stream.failure(), None);
  assert_eq!(stream.get_ref().write_calls, 0);
  assert_eq!(stream.get_ref().flush_calls, 1);
}

#[derive(Debug)]
struct CooperativeWriter {
  calls: usize,
}

impl AsyncWrite for CooperativeWriter {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    input: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    crate::runtime::asynchronous::poll_cooperative_composed(cx, |_| {
      this.calls += 1;
      Poll::Ready(Ok(input.len()))
    })
  }

  fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }
}

struct WriteUntilBudgetStops<'a> {
  stream: &'a mut RateLimitedIo<CooperativeWriter>,
}

impl Future for WriteUntilBudgetStops<'_> {
  type Output = usize;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    let mut completed = 0;
    for _ in 0..=POLL_BUDGET {
      match Pin::new(&mut *this.stream).poll_write(cx, b"x") {
        Poll::Ready(Ok(1)) => completed += 1,
        Poll::Ready(other) => panic!("unexpected write result: {other:?}"),
        Poll::Pending => return Poll::Ready(completed),
      }
    }
    Poll::Ready(completed)
  }
}

#[test]
fn composed_endpoint_uses_one_shared_budget_unit_per_ready_write() {
  let (_driver, timer) = timer(4);
  let mut stream = RateLimitedIo::new(
    CooperativeWriter { calls: 0 },
    bucket(1, 1, 1),
    bucket(1_000_000, POLL_BUDGET + 1, 1),
    timer,
  )
  .expect("real-clock adapter");
  let mut runtime = LocalRuntime::new(LocalConfig {
    max_outstanding: 1,
    max_scopes: 1,
  })
  .expect("local runtime");

  let completed = runtime
    .block_on(WriteUntilBudgetStops {
      stream: &mut stream,
    })
    .expect("root poll completes");
  assert_eq!(completed, POLL_BUDGET);
  assert_eq!(stream.get_ref().calls, POLL_BUDGET);
}

#[test]
fn empty_and_control_operations_do_not_create_byte_reservations() {
  let (_driver, timer) = timer(4);
  let read = bucket(1, 3, 1);
  let write = bucket(1, 4, 1);
  let mut stream = RateLimitedIo::new(ScriptIo::new([], []), read.clone(), write.clone(), timer)
    .expect("real-clock adapter");
  let mut cx = context();

  assert!(matches!(
    Pin::new(&mut stream).poll_read(&mut cx, &mut []),
    Poll::Ready(Ok(0))
  ));
  assert!(matches!(
    Pin::new(&mut stream).poll_write(&mut cx, &[]),
    Poll::Ready(Ok(0))
  ));
  assert!(Pin::new(&mut stream).poll_flush(&mut cx).is_ready());
  assert!(Pin::new(&mut stream).poll_shutdown(&mut cx).is_ready());
  assert_eq!(read.snapshot().available_bytes, 3);
  assert_eq!(read.snapshot().reservations, 0);
  assert_eq!(write.snapshot().available_bytes, 4);
  assert_eq!(write.snapshot().reservations, 0);
  assert_eq!(stream.get_ref().read_calls, 0);
  assert_eq!(stream.get_ref().write_calls, 0);
  assert_eq!(stream.get_ref().flush_calls, 1);
  assert_eq!(stream.get_ref().shutdown_calls, 1);
}

#[test]
fn rate_limited_tcp_stream_transfers_a_real_loopback_exchange() {
  use std::io::{Read, Write};

  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 4,
    max_waiters: 8,
  })
  .expect("reactor");
  let address_listener = StdTcpListener::bind("127.0.0.1:0").expect("loopback listener");
  let address = address_listener.local_addr().expect("listener address");
  let mut peer =
    StdTcpStream::connect_timeout(&address, Duration::from_secs(2)).expect("loopback connect");
  peer
    .set_read_timeout(Some(Duration::from_secs(2)))
    .expect("peer read timeout");
  peer
    .set_write_timeout(Some(Duration::from_secs(2)))
    .expect("peer write timeout");
  let (accepted, _) = address_listener.accept().expect("accept loopback");
  let accepted = crate::runtime::net::TcpStream::from_std(accepted, &reactor.handle())
    .expect("register accepted stream");
  let (_timer_driver, timer) = timer(4);
  let mut stream = RateLimitedIo::new(
    accepted,
    bucket(1_000_000, 4, 1),
    bucket(1_000_000, 4, 1),
    timer,
  )
  .expect("real-clock adapter");

  run_future(stream.write_all(b"ping")).expect("rate-limited TCP write");
  let mut received = [0; 4];
  peer.read_exact(&mut received).expect("read from adapter");
  assert_eq!(&received, b"ping");

  peer.write_all(b"pong").expect("write to adapter");
  let mut received = [0; 4];
  run_future(stream.read_exact(&mut received)).expect("rate-limited TCP read");
  assert_eq!(&received, b"pong");

  drop(stream);
  drop(peer);
  drop(address_listener);
  reactor.shutdown().expect("reactor shutdown");
}

#[cfg(feature = "resource-feedback")]
#[test]
fn meters_count_only_committed_nonempty_successes_and_follow_component_recovery() {
  use crate::runtime::resource_feedback_meter::IoFeedbackMeter;

  let (_driver, timer) = timer(4);
  let read_meter = IoFeedbackMeter::new();
  let write_meter = IoFeedbackMeter::new();
  let inner = ScriptIo::new(
    [Action::Count(2), Action::Pending],
    [
      Action::Count(2),
      Action::Pending,
      Action::Error(ErrorKind::PermissionDenied),
    ],
  );
  let mut stream = RateLimitedIo::new(inner, bucket(1, 8, 1), bucket(1, 8, 1), timer)
    .expect("real-clock adapter")
    .with_feedback_meters(read_meter.clone(), write_meter.clone());
  let mut cx = context();

  assert_eq!(read_meter.snapshot().attached_sources, 1);
  assert_eq!(write_meter.snapshot().attached_sources, 1);
  let mut output = [0; 4];
  assert!(matches!(
    Pin::new(&mut stream).poll_read(&mut cx, &mut output),
    Poll::Ready(Ok(2))
  ));
  assert!(
    Pin::new(&mut stream)
      .poll_read(&mut cx, &mut output)
      .is_pending()
  );
  assert_eq!(read_meter.snapshot().committed_bytes, 2);
  assert_eq!(read_meter.snapshot().completions, 1);

  {
    let mut write_all = stream.write_all(b"data");
    assert!(Pin::new(&mut write_all).poll(&mut cx).is_pending());
  }
  assert_eq!(write_meter.snapshot().committed_bytes, 2);
  assert_eq!(write_meter.snapshot().completions, 1);
  let error = match Pin::new(&mut stream).poll_write(&mut cx, b"data") {
    Poll::Ready(Err(error)) => error,
    other => panic!("expected endpoint error, got {other:?}"),
  };
  assert_eq!(error.kind(), ErrorKind::PermissionDenied);
  assert_eq!(write_meter.snapshot().committed_bytes, 2);
  assert_eq!(write_meter.snapshot().completions, 1);

  let parts = stream.into_parts();
  assert_eq!(read_meter.snapshot().attached_sources, 1);
  assert_eq!(write_meter.snapshot().attached_sources, 1);
  let recovered = parts.into_adapter();
  drop(recovered.into_inner());
  assert_eq!(read_meter.snapshot().attached_sources, 0);
  assert_eq!(write_meter.snapshot().attached_sources, 0);
}

#[cfg(feature = "resource-feedback")]
#[test]
fn meters_share_counts_across_wrappers_and_invalidate_on_bad_counts() {
  use crate::runtime::resource_feedback_meter::IoFeedbackMeter;

  let (_driver, timer) = timer(4);
  let shared = IoFeedbackMeter::new();
  let read_first = IoFeedbackMeter::new();
  let read_second = IoFeedbackMeter::new();
  let mut first = RateLimitedIo::new(
    ScriptIo::new([], [Action::Count(1)]),
    bucket(1, 2, 1),
    bucket(1, 2, 1),
    timer.clone(),
  )
  .expect("real-clock adapter")
  .with_feedback_meters(read_first, shared.clone());
  let mut second = RateLimitedIo::new(
    ScriptIo::new([], [Action::Count(1)]),
    bucket(1, 2, 1),
    bucket(1, 2, 1),
    timer.clone(),
  )
  .expect("real-clock adapter")
  .with_feedback_meters(read_second, shared.clone());
  assert_eq!(shared.snapshot().attached_sources, 2);
  let mut cx = context();
  assert!(matches!(
    Pin::new(&mut first).poll_write(&mut cx, b"a"),
    Poll::Ready(Ok(1))
  ));
  assert!(matches!(
    Pin::new(&mut second).poll_write(&mut cx, b"b"),
    Poll::Ready(Ok(1))
  ));
  assert_eq!(shared.snapshot().committed_bytes, 2);
  assert_eq!(shared.snapshot().completions, 2);

  let bad_write_meter = IoFeedbackMeter::new();
  let mut bad = RateLimitedIo::new(
    ScriptIo::new([], [Action::Count(4)]),
    bucket(1, 1, 1),
    bucket(1, 3, 1),
    timer.clone(),
  )
  .expect("real-clock adapter")
  .with_feedback_meters(IoFeedbackMeter::new(), bad_write_meter.clone());
  let error = match Pin::new(&mut bad).poll_write(&mut cx, b"large") {
    Poll::Ready(Err(error)) => error,
    other => panic!("expected invalid endpoint count, got {other:?}"),
  };
  assert_eq!(error.kind(), ErrorKind::InvalidData);
  let invalid = bad_write_meter.snapshot();
  assert_eq!(invalid.committed_bytes, 0);
  assert_eq!(invalid.completions, 0);
  assert!(invalid.diagnostics.invalid_io);
}
