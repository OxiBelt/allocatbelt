use std::error::Error as StdError;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

use super::*;
use crate::runtime::byte_rate::ByteRateConfig;
use crate::runtime::managed::ResourceLimits;
use crate::runtime::reactor::{Reactor, ReactorConfig, ReactorHandle};
use crate::runtime::resource_domain::{
  DomainError, DomainResource, DomainResources, ResourceDomain,
};
use crate::runtime::time::{ClockMode, TimerDriver};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn reactor() -> Reactor {
  Reactor::new(ReactorConfig {
    max_registrations: 8,
    max_waiters: 16,
  })
  .expect("reactor")
}

fn register(socket: StdUdpSocket, reactor: &ReactorHandle) -> UdpSocket {
  UdpSocket::from_std(socket, reactor).expect("register UDP socket")
}

fn timer(max_registered: usize) -> (TimerDriver, TimerHandle) {
  let driver = TimerDriver::new_realtime(max_registered).expect("fixed real timer");
  let handle = driver.handle();
  (driver, handle)
}

fn bucket(rate: u64, burst: usize, max_reservations: usize) -> ByteRateLimit {
  ByteRateLimit::new(ByteRateConfig {
    bytes_per_second: rate,
    burst_bytes: burst,
    max_reservations,
  })
  .expect("valid byte-rate bucket")
}

fn scope(network: usize) -> ResourceScope {
  ResourceScope::new(ResourceLimits {
    managed_memory: 0,
    disk_concurrent_ops: 0,
    network_concurrent_ops: network,
  })
}

fn block_on<F: Future>(future: F) -> F::Output {
  let mut future = Box::pin(future);
  let mut context = Context::from_waker(Waker::noop());
  let deadline = Instant::now() + TEST_TIMEOUT;
  loop {
    match future.as_mut().poll(&mut context) {
      Poll::Ready(output) => return output,
      Poll::Pending => {
        assert!(Instant::now() < deadline, "UDP operation timed out");
        thread::sleep(Duration::from_millis(1));
      }
    }
  }
}

fn error_payload<T: StdError + 'static>(error: &io::Error) -> Option<&T> {
  error.get_ref()?.downcast_ref::<T>()
}

fn bind(address: SocketAddr) -> StdUdpSocket {
  StdUdpSocket::bind(address).expect("bind loopback UDP socket")
}

struct WakeSignal {
  wakes: AtomicUsize,
  sender: SyncSender<()>,
}

impl Wake for WakeSignal {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.wakes.fetch_add(1, Ordering::Release);
    let _ = self.sender.try_send(());
  }
}

fn wake_signal() -> (Waker, Receiver<()>, Arc<WakeSignal>) {
  let (sender, receiver) = mpsc::sync_channel(1);
  let signal = Arc::new(WakeSignal {
    wakes: AtomicUsize::new(0),
    sender,
  });
  (Waker::from(Arc::clone(&signal)), receiver, signal)
}

#[test]
fn loopback_sends_complete_datagrams_and_charges_truncated_receive_bytes() {
  let reactor = reactor();
  let handle = reactor.handle();
  let receiver_std = bind("127.0.0.1:0".parse().expect("loopback address"));
  let receiver_address = receiver_std.local_addr().expect("receiver address");
  let sender_std = bind("127.0.0.1:0".parse().expect("loopback address"));
  let sender_address = sender_std.local_addr().expect("sender address");
  let (_sender_timer_driver, sender_timer) = timer(4);
  let (_receiver_timer_driver, receiver_timer) = timer(4);
  let sender = RateLimitedUdp::new(
    register(sender_std, &handle),
    bucket(100_000, 64, 4),
    bucket(100_000, 64, 4),
    sender_timer,
    scope(1),
  )
  .expect("sender wrapper");
  let receiver_read = bucket(100_000, 8, 4);
  let receiver = RateLimitedUdp::new(
    register(receiver_std, &handle),
    receiver_read.clone(),
    bucket(100_000, 64, 4),
    receiver_timer,
    scope(1),
  )
  .expect("receiver wrapper");

  let short = b"hello";
  assert_eq!(
    block_on(sender.send_to(short, receiver_address)).expect("send short datagram"),
    short.len()
  );
  let mut full_buffer = [0_u8; 8];
  let (received, source) = block_on(receiver.recv_from(&mut full_buffer)).expect("receive");
  assert_eq!(received, short.len());
  assert_eq!(&full_buffer[..received], short);
  assert_eq!(source, sender_address);
  let after_partial_receive = receiver_read.snapshot();
  assert_eq!(after_partial_receive.reservations, 0);
  assert_eq!(after_partial_receive.reserved_bytes, 0);
  assert!(after_partial_receive.available_bytes >= 3);

  let long = b"datagram larger than the receive buffer";
  assert_eq!(
    block_on(sender.send_to(long, receiver_address)).expect("send long datagram"),
    long.len()
  );
  let mut truncated = [0_u8; 3];
  let (received, source) = block_on(receiver.recv_from(&mut truncated)).expect("truncated receive");
  assert_eq!(received, truncated.len());
  assert_eq!(&truncated, &long[..truncated.len()]);
  assert_eq!(source, sender_address);

  let snapshot = receiver_read.snapshot();
  assert_eq!(snapshot.reservations, 0);
  assert_eq!(snapshot.reserved_bytes, 0);
  assert!(snapshot.available_bytes <= 8);
  assert_eq!(receiver.resources().snapshot().network_ops, 0);
}

#[test]
fn zero_length_send_and_receive_still_transfer_a_datagram_and_take_network_slots() {
  let reactor = reactor();
  let handle = reactor.handle();
  let receiver_std = bind("127.0.0.1:0".parse().expect("loopback address"));
  let receiver_address = receiver_std.local_addr().expect("receiver address");
  let sender_std = bind("127.0.0.1:0".parse().expect("loopback address"));
  let sender_address = sender_std.local_addr().expect("sender address");
  let (_sender_timer_driver, sender_timer) = timer(2);
  let (_receiver_timer_driver, receiver_timer) = timer(2);
  let sender = RateLimitedUdp::new(
    register(sender_std, &handle),
    bucket(1, 4, 2),
    bucket(1, 4, 2),
    sender_timer,
    scope(1),
  )
  .expect("sender wrapper");
  let receiver = RateLimitedUdp::new(
    register(receiver_std, &handle),
    bucket(1, 4, 2),
    bucket(1, 4, 2),
    receiver_timer,
    scope(1),
  )
  .expect("receiver wrapper");

  assert_eq!(
    block_on(sender.send_to(&[], receiver_address)).expect("send empty datagram"),
    0
  );
  let mut empty = [];
  let (received, source) = block_on(receiver.recv_from(&mut empty)).expect("receive empty packet");
  assert_eq!(received, 0);
  assert_eq!(source, sender_address);
  assert_eq!(sender.resources().snapshot().network_ops, 0);
  assert_eq!(receiver.resources().snapshot().network_ops, 0);
  assert_eq!(sender.upload_rate().snapshot().reservations, 0);
  assert_eq!(receiver.download_rate().snapshot().reservations, 0);
}

#[test]
fn oversized_send_is_refused_before_the_socket_and_keeps_the_borrowed_datagram() {
  let reactor = reactor();
  let handle = reactor.handle();
  let peer = bind("127.0.0.1:0".parse().expect("loopback address"));
  peer.set_nonblocking(true).expect("nonblocking peer");
  let peer_address = peer.local_addr().expect("peer address");
  let sender_std = bind("127.0.0.1:0".parse().expect("loopback address"));
  let (_timer_driver, timer) = timer(2);
  let sender = RateLimitedUdp::new(
    register(sender_std, &handle),
    bucket(1_000, 3, 2),
    bucket(1_000, 3, 2),
    timer,
    scope(1),
  )
  .expect("sender wrapper");
  let datagram = *b"four";

  let error = block_on(sender.send_to(&datagram, peer_address)).expect_err("oversized refusal");
  assert_eq!(error.kind(), ErrorKind::InvalidInput);
  assert_eq!(
    error_payload::<RateDatagramFailure>(&error),
    Some(&RateDatagramFailure::ByteRate(ByteRateError::Oversized))
  );
  assert_eq!(&datagram, b"four");
  assert_eq!(sender.upload_rate().snapshot().reservations, 0);
  let mut received = [0_u8; 8];
  assert_eq!(
    peer.recv_from(&mut received).unwrap_err().kind(),
    ErrorKind::WouldBlock
  );
}

#[test]
fn token_wait_cancellation_releases_timer_and_keeps_network_slot_unclaimed() {
  let reactor = reactor();
  let handle = reactor.handle();
  let peer = bind("127.0.0.1:0".parse().expect("loopback address"));
  peer.set_nonblocking(true).expect("nonblocking peer");
  let peer_address = peer.local_addr().expect("peer address");
  let sender_std = bind("127.0.0.1:0".parse().expect("loopback address"));
  let (timer_driver, timer) = timer(2);
  let upload = bucket(1, 1, 1);
  upload
    .try_reserve(1)
    .expect("initial credit")
    .commit(1)
    .expect("spend initial credit");
  let resources = scope(1);
  let sender = RateLimitedUdp::new(
    register(sender_std, &handle),
    bucket(1, 1, 1),
    upload.clone(),
    timer.clone(),
    resources.clone(),
  )
  .expect("sender wrapper");
  let datagram = *b"x";
  let mut future = Box::pin(sender.send_to(&datagram, peer_address));
  let mut context = Context::from_waker(Waker::noop());

  assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
  assert_eq!(timer.registered(), 1);
  assert_eq!(resources.snapshot().network_ops, 0);
  drop(future);

  assert_eq!(timer.registered(), 0);
  assert_eq!(upload.snapshot().reservations, 0);
  assert_eq!(resources.snapshot().network_ops, 0);
  assert_eq!(&datagram, b"x");
  let mut received = [0_u8; 1];
  assert_eq!(
    peer.recv_from(&mut received).unwrap_err().kind(),
    ErrorKind::WouldBlock
  );
  drop(timer_driver);
}

#[test]
fn pending_receive_holds_exact_admission_then_completes_only_after_reactor_wake() {
  let reactor = reactor();
  let reactor_handle = reactor.handle();
  let receiver_std = bind("127.0.0.1:0".parse().expect("loopback address"));
  let receiver_address = receiver_std.local_addr().expect("receiver address");
  let peer = bind("127.0.0.1:0".parse().expect("loopback address"));
  let peer_address = peer.local_addr().expect("peer address");
  let (timer_driver, timer) = timer(2);
  let download = bucket(10_000, 8, 2);
  let resources = scope(1);
  let receiver = RateLimitedUdp::new(
    register(receiver_std, &reactor_handle),
    download.clone(),
    bucket(10_000, 8, 2),
    timer,
    resources.clone(),
  )
  .expect("receiver wrapper");
  let mut buffer = [0_u8; 8];
  let offered = buffer.len();
  let mut future = Box::pin(receiver.recv_from(&mut buffer));
  let (waker, wake_rx, wake_signal) = wake_signal();
  let mut context = Context::from_waker(&waker);

  assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
  assert_eq!(download.snapshot().reserved_bytes, offered);
  assert_eq!(download.snapshot().reservations, 1);
  assert_eq!(resources.snapshot().network_ops, 1);
  assert_eq!(reactor_handle.waiters(), 1);
  assert_eq!(timer_driver.handle().registered(), 0);

  assert_eq!(
    peer
      .send_to(b"abc", receiver_address)
      .expect("send UDP datagram"),
    3
  );
  wake_rx
    .recv_timeout(TEST_TIMEOUT)
    .expect("the reactor must wake the registered receive task");
  assert!(wake_signal.wakes.load(Ordering::Acquire) > 0);

  let (count, source) = match future.as_mut().poll(&mut context) {
    Poll::Ready(Ok(result)) => result,
    other => panic!("receive did not complete after its wake: {other:?}"),
  };
  drop(future);
  assert_eq!(count, 3);
  assert_eq!(source, peer_address);
  assert_eq!(&buffer[..count], b"abc");
  let settled = download.snapshot();
  assert_eq!(settled.reserved_bytes, 0);
  assert_eq!(settled.reservations, 0);
  assert!(settled.available_bytes >= 5);
  assert_eq!(resources.snapshot().network_ops, 0);
  assert_eq!(reactor_handle.waiters(), 0);
}

#[test]
fn dropping_pending_receive_removes_readiness_waiter_and_refunds_both_admissions() {
  let reactor = reactor();
  let reactor_handle = reactor.handle();
  let receiver_std = bind("127.0.0.1:0".parse().expect("loopback address"));
  let (timer_driver, timer) = timer(2);
  let download = bucket(10_000, 8, 2);
  let resources = scope(1);
  let receiver = RateLimitedUdp::new(
    register(receiver_std, &reactor_handle),
    download.clone(),
    bucket(10_000, 8, 2),
    timer,
    resources.clone(),
  )
  .expect("receiver wrapper");
  let mut buffer = [0_u8; 8];
  let offered = buffer.len();
  let mut future = Box::pin(receiver.recv_from(&mut buffer));
  let mut context = Context::from_waker(Waker::noop());

  assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
  assert_eq!(download.snapshot().reserved_bytes, offered);
  assert_eq!(download.snapshot().reservations, 1);
  assert_eq!(resources.snapshot().network_ops, 1);
  assert_eq!(reactor_handle.waiters(), 1);
  assert_eq!(timer_driver.handle().registered(), 0);

  drop(future);

  let refunded = download.snapshot();
  assert_eq!(refunded.available_bytes, offered);
  assert_eq!(refunded.reserved_bytes, 0);
  assert_eq!(refunded.reservations, 0);
  assert_eq!(resources.snapshot().network_ops, 0);
  assert_eq!(reactor_handle.waiters(), 0);
  assert_eq!(timer_driver.handle().registered(), 0);
}

#[test]
fn fixed_real_datagram_wait_progresses_while_an_application_clock_stays_paused() {
  let reactor = reactor();
  let handle = reactor.handle();
  let peer = bind("127.0.0.1:0".parse().expect("loopback address"));
  peer
    .set_read_timeout(Some(TEST_TIMEOUT))
    .expect("peer timeout");
  let peer_address = peer.local_addr().expect("peer address");
  let sender_std = bind("127.0.0.1:0".parse().expect("loopback address"));
  let (application_driver, _) = TimerDriver::new_paused(2).expect("paused application clock");
  let (timer_driver, timer) = timer(2);
  assert_eq!(application_driver.handle().mode(), ClockMode::PausedManual);
  let upload = bucket(10, 1, 1);
  upload
    .try_reserve(1)
    .expect("initial credit")
    .commit(1)
    .expect("spend initial credit");
  let sender = RateLimitedUdp::new(
    register(sender_std, &handle),
    bucket(10, 1, 1),
    upload,
    timer.clone(),
    scope(1),
  )
  .expect("fixed real timer accepted");
  let datagram = *b"r";
  let mut future = Box::pin(sender.send_to(&datagram, peer_address));
  let mut context = Context::from_waker(Waker::noop());
  assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
  assert_eq!(application_driver.handle().mode(), ClockMode::PausedManual);
  assert_eq!(timer.registered(), 1);

  assert_eq!(
    block_on(future.as_mut()).expect("send after real rate wait"),
    1
  );
  let mut received = [0_u8; 1];
  assert_eq!(
    peer.recv_from(&mut received).expect("loopback receive").0,
    1
  );
  assert_eq!(&received, &datagram);
  assert_eq!(application_driver.handle().mode(), ClockMode::PausedManual);
  assert_eq!(timer.registered(), 0);
  drop(timer_driver);
}

#[test]
fn operation_admission_failure_refunds_bytes_and_preserves_borrowed_input() {
  let reactor = reactor();
  let handle = reactor.handle();
  let peer = bind("127.0.0.1:0".parse().expect("loopback address"));
  peer.set_nonblocking(true).expect("nonblocking peer");
  let peer_address = peer.local_addr().expect("peer address");
  let sender_std = bind("127.0.0.1:0".parse().expect("loopback address"));
  let upload = bucket(100_000, 32, 2);
  let resources = scope(0);
  let (_timer_driver, timer) = timer(2);
  let sender = RateLimitedUdp::new(
    register(sender_std, &handle),
    bucket(100_000, 32, 2),
    upload.clone(),
    timer,
    resources.clone(),
  )
  .expect("sender wrapper");
  let datagram = *b"retained";

  let error = block_on(sender.send_to(&datagram, peer_address)).expect_err("network slot refusal");
  assert_eq!(error.kind(), ErrorKind::InvalidInput);
  assert_eq!(
    error_payload::<ResourceError>(&error),
    Some(&ResourceError::Invalid(ResourceKind::Network))
  );
  assert_eq!(&datagram, b"retained");
  assert_eq!(upload.snapshot().available_bytes, 32);
  assert_eq!(upload.snapshot().reservations, 0);
  assert_eq!(resources.snapshot().network_ops, 0);
  let mut received = [0_u8; 16];
  assert_eq!(
    peer.recv_from(&mut received).unwrap_err().kind(),
    ErrorKind::WouldBlock
  );
}

#[test]
fn socket_error_refunds_the_whole_unreported_reservation() {
  let reactor = reactor();
  let handle = reactor.handle();
  let socket = bind("127.0.0.1:0".parse().expect("loopback address"));
  let upload = bucket(100_000, 32, 2);
  let resources = scope(1);
  let (_timer_driver, timer) = timer(2);
  let sender = RateLimitedUdp::new(
    register(socket, &handle),
    bucket(100_000, 32, 2),
    upload.clone(),
    timer,
    resources.clone(),
  )
  .expect("sender wrapper");

  let error = block_on(sender.send(b"unconnected")).expect_err("unconnected send");
  assert!(error.raw_os_error().is_some());
  assert_eq!(upload.snapshot().available_bytes, 32);
  assert_eq!(upload.snapshot().reservations, 0);
  assert_eq!(resources.snapshot().network_ops, 0);
}

#[test]
fn mutable_and_paused_timers_are_rejected_with_every_original_input() {
  let reactor = reactor();
  let handle = reactor.handle();
  let bucket_read = bucket(10, 4, 2);
  let bucket_write = bucket(10, 4, 2);
  let mutable_driver = TimerDriver::new(2).expect("mutable timer");
  let mutable_timer = mutable_driver.handle();
  let socket = register(
    bind("127.0.0.1:0".parse().expect("loopback address")),
    &handle,
  );
  let address = socket
    .get_ref()
    .local_addr()
    .expect("original socket remains owned");
  let error = RateLimitedUdp::new(
    socket,
    bucket_read.clone(),
    bucket_write.clone(),
    mutable_timer.clone(),
    scope(1),
  )
  .expect_err("mutable real mode is not an immutable real-time clock");
  assert_eq!(error.failure(), RateDatagramBuildFailure::NotRealTimeClock);
  let inputs = error.into_inputs();
  assert_eq!(
    inputs
      .socket
      .get_ref()
      .local_addr()
      .expect("returned socket"),
    address
  );
  assert_eq!(inputs.download_rate.snapshot(), bucket_read.snapshot());
  assert_eq!(inputs.upload_rate.snapshot(), bucket_write.snapshot());
  assert!(!inputs.timer.is_realtime());

  let (paused_driver, _) = TimerDriver::new_paused(2).expect("paused timer");
  let paused_timer = paused_driver.handle();
  let socket = register(
    bind("127.0.0.1:0".parse().expect("loopback address")),
    &handle,
  );
  let address = socket
    .get_ref()
    .local_addr()
    .expect("original socket remains owned");
  let error = RateLimitedUdp::new(
    socket,
    bucket_read.clone(),
    bucket_write.clone(),
    paused_timer,
    scope(1),
  )
  .expect_err("paused timer refused");
  assert_eq!(error.failure(), RateDatagramBuildFailure::NotRealTimeClock);
  let inputs = error.into_inputs();
  assert_eq!(
    inputs
      .socket
      .get_ref()
      .local_addr()
      .expect("returned socket"),
    address
  );
  assert_eq!(inputs.download_rate.snapshot(), bucket_read.snapshot());
  assert_eq!(inputs.upload_rate.snapshot(), bucket_write.snapshot());
  assert_eq!(inputs.timer.mode(), ClockMode::PausedManual);
  drop(mutable_driver);
  drop(paused_driver);
}

#[test]
fn tenant_control_charge_refusal_returns_the_original_socket_and_buckets() {
  let reactor = reactor();
  let handle = reactor.handle();
  let domain = ResourceDomain::new(DomainResources::ZERO.with(DomainResource::Control, 4096), 1)
    .expect("bounded resource domain");
  let tenant = domain
    .tenant(DomainResources::ZERO)
    .expect("tenant without control capacity");
  let resources = ResourceScope::from_tenant(
    ResourceLimits {
      managed_memory: 0,
      disk_concurrent_ops: 0,
      network_concurrent_ops: 1,
    },
    tenant,
  );
  let (timer_driver, timer) = timer(2);
  let download = bucket(10, 4, 2);
  let upload = bucket(10, 4, 2);
  let socket = register(
    bind("127.0.0.1:0".parse().expect("loopback address")),
    &handle,
  );
  let address = socket
    .get_ref()
    .local_addr()
    .expect("original socket remains owned");
  let error = RateLimitedUdp::new(socket, download.clone(), upload.clone(), timer, resources)
    .expect_err("tenant cannot admit wrapper metadata");
  assert!(matches!(
    error.failure(),
    RateDatagramBuildFailure::Control(DomainError::Invalid)
      | RateDatagramBuildFailure::Control(DomainError::AboveCeiling(DomainResource::Control))
  ));
  let inputs = error.into_inputs();
  assert_eq!(
    inputs
      .socket
      .get_ref()
      .local_addr()
      .expect("returned socket"),
    address
  );
  assert_eq!(inputs.download_rate.snapshot(), download.snapshot());
  assert_eq!(inputs.upload_rate.snapshot(), upload.snapshot());
  assert!(inputs.timer.is_realtime());
  drop(timer_driver);
}

#[test]
fn impossible_reported_count_spends_full_offer_and_latches_shared_fault() {
  let reactor = reactor();
  let handle = reactor.handle();
  let read = bucket(10, 4, 2);
  let (_timer_driver, timer) = timer(2);
  let wrapper = RateLimitedUdp::new(
    register(
      bind("127.0.0.1:0".parse().expect("loopback address")),
      &handle,
    ),
    read.clone(),
    bucket(10, 4, 2),
    timer,
    scope(1),
  )
  .expect("wrapper");
  let reservation = read.try_reserve(3).expect("synthetic offered credit");

  let error = wrapper
    .inner
    .settle(reservation, 4, 3, DatagramDirection::Download)
    .expect_err("impossible endpoint count");
  assert_eq!(error.kind(), ErrorKind::InvalidData);
  assert_eq!(
    error_payload::<RateDatagramFailure>(&error),
    Some(&RateDatagramFailure::InvalidReceiveCount {
      reported: 4,
      offered: 3,
    })
  );
  assert_eq!(read.snapshot().available_bytes, 1);
  assert_eq!(read.snapshot().reserved_bytes, 0);

  let alias = wrapper.clone();
  let mut empty = [];
  let sticky = block_on(alias.recv(&mut empty)).expect_err("fault blocks aliases and empty ops");
  assert_eq!(sticky.kind(), ErrorKind::InvalidData);
  assert_eq!(
    error_payload::<RateDatagramFailure>(&sticky),
    error_payload(&error)
  );
  assert_eq!(read.snapshot().available_bytes, 1);
}

#[cfg(feature = "resource-feedback")]
#[test]
fn feedback_meters_record_only_committed_datagram_bytes_and_live_until_last_clone() {
  use crate::runtime::resource_feedback_meter::IoFeedbackMeter;

  let reactor = reactor();
  let handle = reactor.handle();
  let peer = bind("127.0.0.1:0".parse().expect("loopback address"));
  peer
    .set_read_timeout(Some(TEST_TIMEOUT))
    .expect("peer timeout");
  let peer_address = peer.local_addr().expect("peer address");
  let socket = register(
    bind("127.0.0.1:0".parse().expect("loopback address")),
    &handle,
  );
  let download_meter = IoFeedbackMeter::new();
  let upload_meter = IoFeedbackMeter::new();
  let (_timer_driver, timer) = timer(2);
  let wrapper = RateLimitedUdp::new_metered(
    socket,
    bucket(100_000, 32, 4),
    bucket(100_000, 32, 4),
    timer,
    scope(1),
    download_meter.clone(),
    upload_meter.clone(),
  )
  .expect("metered UDP wrapper");
  let alias = wrapper.clone();
  assert_eq!(download_meter.snapshot().attached_sources, 1);
  assert_eq!(upload_meter.snapshot().attached_sources, 1);

  assert_eq!(
    block_on(wrapper.send_to(b"meter", peer_address)).expect("send metered datagram"),
    5
  );
  let mut received = [0_u8; 8];
  assert_eq!(peer.recv_from(&mut received).expect("peer receive").0, 5);
  let snapshot = upload_meter.snapshot();
  assert_eq!(snapshot.committed_bytes, 5);
  assert_eq!(snapshot.completions, 1);
  assert_eq!(download_meter.snapshot().committed_bytes, 0);

  drop(wrapper);
  assert_eq!(upload_meter.snapshot().attached_sources, 1);
  drop(alias);
  assert_eq!(upload_meter.snapshot().attached_sources, 0);
  assert_eq!(download_meter.snapshot().attached_sources, 0);
}

#[cfg(feature = "resource-feedback")]
#[test]
fn rejected_metered_constructor_returns_both_original_meters_without_registering_them() {
  use crate::runtime::resource_feedback_meter::IoFeedbackMeter;

  let reactor = reactor();
  let handle = reactor.handle();
  let mutable_driver = TimerDriver::new(2).expect("mutable timer");
  let download_meter = IoFeedbackMeter::new();
  let upload_meter = IoFeedbackMeter::new();
  let socket = register(
    bind("127.0.0.1:0".parse().expect("loopback address")),
    &handle,
  );
  let address = socket
    .get_ref()
    .local_addr()
    .expect("original socket remains owned");
  let error = RateLimitedUdp::new_metered(
    socket,
    bucket(10, 4, 2),
    bucket(10, 4, 2),
    mutable_driver.handle(),
    scope(1),
    download_meter.clone(),
    upload_meter.clone(),
  )
  .expect_err("mutable timer rejected before registration");

  assert_eq!(error.failure(), RateDatagramBuildFailure::NotRealTimeClock);
  let inputs = error.into_inputs();
  assert_eq!(
    inputs
      .socket
      .get_ref()
      .local_addr()
      .expect("returned socket"),
    address
  );
  let (returned_download, returned_upload) =
    inputs.feedback_meters.expect("meter handles recovered");
  assert_eq!(returned_download.snapshot().attached_sources, 0);
  assert_eq!(returned_upload.snapshot().attached_sources, 0);
  assert_eq!(download_meter.snapshot().attached_sources, 0);
  assert_eq!(upload_meter.snapshot().attached_sources, 0);
}
