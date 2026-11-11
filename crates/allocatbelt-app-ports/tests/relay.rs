use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream as StdTcpStream};
use std::os::fd::AsRawFd;
use std::pin::{Pin, pin};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};
use allocatbelt::runtime::io::pipes;
use allocatbelt::runtime::io::{
  AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BoundedReadStop,
};
use allocatbelt::runtime::managed::{
  OperationRequest, ResourceError, ResourceKind, ResourceLimits, ResourceScope,
};
use allocatbelt::runtime::net::TcpStream;
use allocatbelt::runtime::reactor::{Reactor, ReactorConfig};
use allocatbelt_app_ports::relay::{
  RelayBufferDirection, RelayInitErrorKind, RelayInputs, RelaySession, relay_io,
};

const WATCHDOG: Duration = Duration::from_secs(45);
const CHILD_MARKER: &str = "ALLOCATBELT_RELAY_WATCHDOG_CHILD";

fn async_runtime() -> AsyncRuntime {
  AsyncRuntime::new(AsyncConfig {
    workers: 2,
    max_outstanding: 8,
    max_scopes: 2,
  })
  .expect("relay test runtime should start")
}

fn resources(memory: usize, network: usize) -> ResourceScope {
  ResourceScope::new(ResourceLimits {
    managed_memory: memory,
    disk_concurrent_ops: 0,
    network_concurrent_ops: network,
  })
}

fn reactor(registrations: usize) -> Reactor {
  Reactor::new(ReactorConfig {
    max_registrations: registrations,
    max_waiters: registrations * 4,
  })
  .expect("relay test reactor should start")
}

fn connected_stream(
  handle: &allocatbelt::runtime::reactor::ReactorHandle,
) -> (TcpStream, StdTcpStream) {
  let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener should bind");
  let client = StdTcpStream::connect(listener.local_addr().expect("listener address"))
    .expect("loopback connection should open");
  let (peer, _) = listener.accept().expect("loopback peer should accept");
  drop(listener);
  let endpoint = TcpStream::from_std(client, handle).expect("relay endpoint should register");
  (endpoint, peer)
}

fn two_inputs(
  handle: &allocatbelt::runtime::reactor::ReactorHandle,
  resources: &ResourceScope,
  scratch_bytes: usize,
) -> (RelayInputs, [StdTcpStream; 2]) {
  let (a, peer_a) = connected_stream(handle);
  let (b, peer_b) = connected_stream(handle);
  let inputs = RelayInputs {
    a,
    b,
    a_to_b: resources
      .try_alloc_zeroed(scratch_bytes)
      .expect("A-to-B scratch should fit"),
    b_to_a: resources
      .try_alloc_zeroed(scratch_bytes)
      .expect("B-to-A scratch should fit"),
  };
  (inputs, [peer_a, peer_b])
}

fn within_watchdog(test_name: &str, case: fn()) {
  if std::env::var_os(CHILD_MARKER).is_some() {
    case();
    return;
  }
  let mut child = WatchdogChild(
    Command::new(std::env::current_exe().expect("integration test executable should resolve"))
      .args(["--exact", test_name, "--nocapture"])
      .env(CHILD_MARKER, "1")
      .spawn()
      .expect("watchdog child should start"),
  );
  let deadline = Instant::now() + WATCHDOG;
  loop {
    if let Some(status) = child.0.try_wait().expect("child status should be readable") {
      assert!(
        status.success(),
        "relay case {test_name} failed: {status:?}"
      );
      return;
    }
    assert!(
      Instant::now() < deadline,
      "relay case {test_name} timed out"
    );
    thread::sleep(Duration::from_millis(10));
  }
}

struct WatchdogChild(Child);

impl Drop for WatchdogChild {
  fn drop(&mut self) {
    if !matches!(self.0.try_wait(), Ok(Some(_))) {
      let _ = self.0.kill();
      let _ = self.0.wait();
    }
  }
}

macro_rules! watchdog_test {
  ($name:ident, $case:ident) => {
    #[test]
    fn $name() {
      within_watchdog(stringify!($name), $case);
    }
  };
}

watchdog_test!(
  constructor_recovers_empty_shared_and_resource_refusals,
  constructor_recovery_case
);
watchdog_test!(
  generic_buffer_validation_precedes_endpoint_polls,
  validation_before_poll_case
);
watchdog_test!(
  relay_error_preserves_short_write_suffix_progress,
  scripted_error_progress_case
);
watchdog_test!(
  generic_relay_reports_bounded_duplex_backpressure,
  bounded_pipe_backpressure_case
);
watchdog_test!(tcp_half_close_delivers_reverse_reply, tcp_half_close_case);
watchdog_test!(
  cancellation_returns_suffix_and_forbids_restart,
  cancel_and_finish_case
);
watchdog_test!(
  canceled_borrowed_run_publishes_positive_prefix_and_charge,
  canceled_publication_case
);
watchdog_test!(
  finished_output_clone_retains_only_its_buffer_charge,
  output_clone_charge_case
);
watchdog_test!(
  owned_task_abort_drops_session_instead_of_returning_output,
  owned_abort_case
);

fn constructor_recovery_case() {
  let reactor = reactor(4);
  let handle = reactor.handle();
  let scope = resources(128, 2);
  let (mut inputs, peers) = two_inputs(&handle, &scope, 8);
  inputs.a_to_b.get_mut().expect("unique buffer")[..4].copy_from_slice(b"keep");
  let original_fds = [
    inputs.a.get_ref().as_raw_fd(),
    inputs.b.get_ref().as_raw_fd(),
  ];
  let original_buffers = [
    (
      inputs.a_to_b.as_slice().as_ptr(),
      inputs.a_to_b.charged_bytes(),
    ),
    (
      inputs.b_to_a.as_slice().as_ptr(),
      inputs.b_to_a.charged_bytes(),
    ),
  ];
  let shared = inputs.a_to_b.clone();
  let error = match RelaySession::new(inputs, &scope) {
    Ok(_) => panic!("shared scratch unexpectedly constructed a session"),
    Err(error) => error,
  };
  assert!(matches!(
    error.kind,
    RelayInitErrorKind::Shared(RelayBufferDirection::AToB)
  ));
  assert_eq!(&error.inputs.a_to_b.as_slice()[..4], b"keep");
  assert_eq!(error.inputs.a.get_ref().as_raw_fd(), original_fds[0]);
  assert_eq!(error.inputs.b.get_ref().as_raw_fd(), original_fds[1]);
  assert_eq!(
    error.inputs.a_to_b.as_slice().as_ptr(),
    original_buffers[0].0
  );
  assert_eq!(
    error.inputs.b_to_a.as_slice().as_ptr(),
    original_buffers[1].0
  );
  assert_eq!(error.inputs.a_to_b.charged_bytes(), original_buffers[0].1);
  assert_eq!(error.inputs.b_to_a.charged_bytes(), original_buffers[1].1);
  assert_eq!(scope.snapshot().network_ops, 0);
  drop(shared);
  let recovered = RelaySession::new(error.inputs, &scope)
    .expect("released shared clone should allow reusing the returned inputs");
  assert_eq!(scope.snapshot().network_ops, 2);
  drop(recovered.finish());
  assert_eq!(scope.snapshot().network_ops, 0);
  drop(peers);

  let empty_scope = resources(64, 2);
  let (mut empty_inputs, empty_peers) = two_inputs(&handle, &empty_scope, 8);
  empty_inputs.b_to_a = empty_scope
    .try_alloc_zeroed(0)
    .expect("empty storage is valid to allocate");
  let empty_original_fds = [
    empty_inputs.a.get_ref().as_raw_fd(),
    empty_inputs.b.get_ref().as_raw_fd(),
  ];
  let empty_a_ptr = empty_inputs.a_to_b.as_slice().as_ptr();
  let empty_a_charge = empty_inputs.a_to_b.charged_bytes();
  let empty_b_ptr = empty_inputs.b_to_a.as_slice().as_ptr();
  let empty_b_charge = empty_inputs.b_to_a.charged_bytes();
  let empty_error = match RelaySession::new(empty_inputs, &empty_scope) {
    Ok(_) => panic!("empty scratch unexpectedly constructed a session"),
    Err(error) => error,
  };
  assert!(matches!(
    empty_error.kind,
    RelayInitErrorKind::Empty(RelayBufferDirection::BToA)
  ));
  assert_eq!(empty_scope.snapshot().network_ops, 0);
  assert_eq!(
    empty_error.inputs.a.get_ref().as_raw_fd(),
    empty_original_fds[0]
  );
  assert_eq!(
    empty_error.inputs.b.get_ref().as_raw_fd(),
    empty_original_fds[1]
  );
  assert_eq!(empty_error.inputs.a_to_b.as_slice().as_ptr(), empty_a_ptr);
  assert_eq!(empty_error.inputs.a_to_b.charged_bytes(), empty_a_charge);
  assert_eq!(empty_error.inputs.b_to_a.as_slice().as_ptr(), empty_b_ptr);
  assert_eq!(empty_error.inputs.b_to_a.charged_bytes(), empty_b_charge);
  let mut empty_recovered = empty_error.inputs;
  empty_recovered.b_to_a = empty_scope
    .try_alloc_zeroed(8)
    .expect("replacement scratch fits after the empty-input refusal");
  let empty_reused = RelaySession::new(empty_recovered, &empty_scope)
    .expect("caller can repair and reuse the returned original endpoints");
  assert_eq!(empty_scope.snapshot().network_ops, 2);
  drop(empty_reused.finish());
  assert_eq!(empty_scope.snapshot().network_ops, 0);
  drop(empty_peers);

  let tight_scope = resources(64, 2);
  let occupied = tight_scope
    .try_acquire(OperationRequest {
      disk: 0,
      network: 1,
    })
    .expect("one network slot should be occupiable");
  let (mut tight_inputs, tight_peers) = two_inputs(&handle, &tight_scope, 8);
  tight_inputs.a_to_b.get_mut().expect("unique buffer")[0] = 0x5a;
  let tight_fds = [
    tight_inputs.a.get_ref().as_raw_fd(),
    tight_inputs.b.get_ref().as_raw_fd(),
  ];
  let tight_buffers = [
    (
      tight_inputs.a_to_b.as_slice().as_ptr(),
      tight_inputs.a_to_b.charged_bytes(),
    ),
    (
      tight_inputs.b_to_a.as_slice().as_ptr(),
      tight_inputs.b_to_a.charged_bytes(),
    ),
  ];
  let tight_error = match RelaySession::new(tight_inputs, &tight_scope) {
    Ok(_) => panic!("two endpoints unexpectedly fit a one-slot scope"),
    Err(error) => error,
  };
  assert!(matches!(
    tight_error.kind,
    RelayInitErrorKind::Resource(ResourceError::Exhausted(ResourceKind::Network))
  ));
  assert_eq!(tight_error.inputs.a_to_b.as_slice()[0], 0x5a);
  assert_eq!(tight_error.inputs.a.get_ref().as_raw_fd(), tight_fds[0]);
  assert_eq!(tight_error.inputs.b.get_ref().as_raw_fd(), tight_fds[1]);
  assert_eq!(
    tight_error.inputs.a_to_b.as_slice().as_ptr(),
    tight_buffers[0].0
  );
  assert_eq!(
    tight_error.inputs.b_to_a.as_slice().as_ptr(),
    tight_buffers[1].0
  );
  assert_eq!(
    tight_error.inputs.a_to_b.charged_bytes(),
    tight_buffers[0].1
  );
  assert_eq!(
    tight_error.inputs.b_to_a.charged_bytes(),
    tight_buffers[1].1
  );
  assert_eq!(tight_scope.snapshot().network_ops, 1);
  drop(occupied);
  assert_eq!(tight_scope.snapshot().network_ops, 0);
  let reused = RelaySession::new(tight_error.inputs, &tight_scope)
    .expect("returned inputs should admit after the occupied slot is released");
  assert_eq!(tight_scope.snapshot().network_ops, 2);
  drop(reused.finish());
  assert_eq!(tight_scope.snapshot().network_ops, 0);
  drop(tight_peers);
  assert_eq!(scope.snapshot().managed_memory, 0);
  assert_eq!(empty_scope.snapshot().managed_memory, 0);
  assert_eq!(tight_scope.snapshot().managed_memory, 0);
  assert_eq!(handle.registrations(), 0);
  assert_eq!(handle.waiters(), 0);
  reactor.shutdown().expect("reactor should close");
}

struct PollCounter(Arc<AtomicUsize>);

impl AsyncRead for PollCounter {
  fn poll_read(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    _buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    self.0.fetch_add(1, Ordering::SeqCst);
    Poll::Ready(Ok(0))
  }
}

impl AsyncWrite for PollCounter {
  fn poll_write(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    _buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    self.0.fetch_add(1, Ordering::SeqCst);
    Poll::Ready(Ok(0))
  }

  fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.0.fetch_add(1, Ordering::SeqCst);
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.0.fetch_add(1, Ordering::SeqCst);
    Poll::Ready(Ok(()))
  }
}

fn validation_before_poll_case() {
  let runtime = async_runtime();
  let resources = resources(16, 0);
  let mut empty = resources
    .try_alloc_zeroed(0)
    .expect("empty buffer is allowed to be allocated");
  let mut first = resources.try_alloc_zeroed(8).expect("scratch should fit");
  let mut second = resources.try_alloc_zeroed(8).expect("scratch should fit");
  let polls = Arc::new(AtomicUsize::new(0));
  let mut a = PollCounter(Arc::clone(&polls));
  let mut b = PollCounter(Arc::clone(&polls));
  let mut progress = Default::default();
  let empty_error = runtime
    .block_on(relay_io(
      &mut a,
      &mut b,
      &mut empty,
      &mut first,
      &mut progress,
    ))
    .expect("root poll should complete")
    .expect_err("empty scratch must be rejected");
  assert_eq!(empty_error.kind(), io::ErrorKind::InvalidInput);
  assert_eq!(polls.load(Ordering::SeqCst), 0);

  drop(empty);
  let shared = second.clone();
  let shared_error = runtime
    .block_on(relay_io(
      &mut a,
      &mut b,
      &mut first,
      &mut second,
      &mut progress,
    ))
    .expect("root poll should complete")
    .expect_err("shared scratch must be rejected");
  assert_eq!(shared_error.kind(), io::ErrorKind::InvalidInput);
  assert_eq!(polls.load(Ordering::SeqCst), 0);
  drop(shared);
  drop((first, second));
  assert_eq!(resources.snapshot().managed_memory, 0);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should close");
}

struct ScriptedSource {
  bytes: Vec<u8>,
  read_once: bool,
}

impl AsyncRead for ScriptedSource {
  fn poll_read(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    if self.read_once {
      return Poll::Pending;
    }
    self.read_once = true;
    let len = self.bytes.len().min(buf.len());
    buf[..len].copy_from_slice(&self.bytes[..len]);
    Poll::Ready(Ok(len))
  }
}

impl AsyncWrite for ScriptedSource {
  fn poll_write(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    _buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    Poll::Pending
  }

  fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }
}

struct ScriptedDestination {
  accepted: Vec<u8>,
  write_calls: usize,
}

impl AsyncRead for ScriptedDestination {
  fn poll_read(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    _buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    Poll::Pending
  }
}

impl AsyncWrite for ScriptedDestination {
  fn poll_write(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.as_mut().get_mut();
    let call = this.write_calls;
    this.write_calls += 1;
    match call {
      0 => {
        let accepted = 2.min(buf.len());
        this.accepted.extend_from_slice(&buf[..accepted]);
        Poll::Ready(Ok(accepted))
      }
      1 => Poll::Pending,
      2 => Poll::Ready(Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "scripted destination failure after pending",
      ))),
      _ => panic!("copy polled destination after its scripted terminal error"),
    }
  }

  fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }
}

fn scripted_error_progress_case() {
  let runtime = async_runtime();
  let resources = resources(16, 0);
  let mut a_to_b = resources.try_alloc_zeroed(8).expect("scratch fits");
  let mut b_to_a = resources.try_alloc_zeroed(8).expect("scratch fits");
  let payload = b"abcdef";
  let mut source = ScriptedSource {
    bytes: payload.to_vec(),
    read_once: false,
  };
  let mut destination = ScriptedDestination {
    accepted: Vec::new(),
    write_calls: 0,
  };
  let mut progress = Default::default();
  let terminal_error = {
    let mut copy = pin!(relay_io(
      &mut source,
      &mut destination,
      &mut a_to_b,
      &mut b_to_a,
      &mut progress,
    ));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(copy.as_mut().poll(&mut context), Poll::Pending));
    match copy.as_mut().poll(&mut context) {
      Poll::Ready(Err(error)) => error,
      Poll::Ready(Ok(counts)) => panic!("script unexpectedly completed: {counts:?}"),
      Poll::Pending => panic!("scripted failure should follow the pending write"),
    }
  };
  assert_eq!(terminal_error.kind(), io::ErrorKind::BrokenPipe);
  assert_eq!(destination.accepted, payload[..2]);
  assert_eq!(destination.write_calls, 3);
  assert_eq!(progress.transferred, (2, 0));
  assert_eq!(progress.unwritten, (2..payload.len(), 0..0));
  assert_eq!(
    &a_to_b.as_slice()[progress.unwritten.0.clone()],
    &payload[2..],
    "retained bytes must be the actual source suffix"
  );
  assert_eq!(resources.snapshot().managed_memory, 16);
  drop((a_to_b, b_to_a));
  assert_eq!(resources.snapshot().managed_memory, 0);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
}

fn bounded_pipe_backpressure_case() {
  let runtime = async_runtime();
  let pipe_resources = resources(40, 0);
  // In `duplex`, endpoint zero writes ring zero and endpoint one writes ring
  // one. `peer_a` is endpoint one, so its source direction is the second ring.
  let relay_a_to_peer_ring = pipe_resources
    .try_alloc_zeroed(4)
    .expect("reverse destination ring fits");
  let peer_a_to_relay_ring = pipe_resources
    .try_alloc_zeroed(16)
    .expect("finite source ring fits");
  let (mut relay_a, mut peer_a) = pipes::duplex(relay_a_to_peer_ring, peer_a_to_relay_ring)
    .expect("first duplex pair should initialize");
  let b_to_a_ring = pipe_resources
    .try_alloc_zeroed(4)
    .expect("bounded destination ring fits");
  let b_to_a_reverse = pipe_resources
    .try_alloc_zeroed(4)
    .expect("reverse input ring fits");
  let (mut relay_b, mut peer_b) =
    pipes::duplex(b_to_a_ring, b_to_a_reverse).expect("second duplex pair should initialize");
  let source: Vec<u8> = (0..16).map(|index| (index * 7) as u8).collect();
  let reverse: Vec<u8> = (0..4).map(|index| (0xf0 + index) as u8).collect();
  runtime
    .block_on(async {
      peer_a.write_all(&source).await?;
      peer_a.shutdown().await?;
      peer_b.write_all(&reverse).await?;
      peer_b.shutdown().await?;
      Ok::<(), std::io::Error>(())
    })
    .expect("root poll should complete")
    .expect("bounded sources should be preloaded");

  let scratch_scope = resources(16, 0);
  let mut scratch_a = scratch_scope
    .try_alloc_zeroed(8)
    .expect("A-to-B scratch fits");
  let mut scratch_b = scratch_scope
    .try_alloc_zeroed(8)
    .expect("B-to-A scratch fits");
  let mut progress = Default::default();
  let saw_pending = {
    let mut relay = pin!(relay_io(
      &mut relay_a,
      &mut relay_b,
      &mut scratch_a,
      &mut scratch_b,
      &mut progress,
    ));
    let mut context = Context::from_waker(Waker::noop());
    match relay.as_mut().poll(&mut context) {
      Poll::Pending => true,
      Poll::Ready(result) => panic!("relay completed before destination gate: {result:?}"),
    }
  };
  assert!(
    saw_pending,
    "relay should yield while its destination is gated"
  );
  relay_a.cancel_io_waits();
  relay_b.cancel_io_waits();
  assert!(
    !progress.unwritten.0.is_empty(),
    "pending source suffix is retained"
  );
  assert_eq!(progress.transferred, (4, reverse.len() as u64));
  assert_eq!(
    &scratch_a.as_slice()[progress.unwritten.0.clone()],
    &source[4..8],
    "reported unwritten bytes must match the actual source suffix"
  );
  let mut returned = [0xa5; 5];
  let reverse_read = runtime
    .block_on(peer_a.read_to_end_bounded(&mut returned))
    .expect("root poll should complete")
    .expect("reverse output should reach EOF");
  assert_eq!(reverse_read.stop, BoundedReadStop::Eof);
  assert_eq!(&returned[..reverse_read.filled], reverse);
  assert_eq!(returned[reverse_read.filled], 0xa5);

  let mut full_ring = [0; 4];
  runtime
    .block_on(peer_b.read_exact(&mut full_ring))
    .expect("root poll should complete")
    .expect("destination ring contains its full capacity");
  assert_eq!(&full_ring, &source[..4]);

  assert_eq!(
    progress.transferred.0, 4,
    "full peer ring accepts only its capacity"
  );
  drop((relay_a, relay_b, peer_a, peer_b));
  assert_eq!(pipe_resources.snapshot().managed_memory, 0);
  assert_eq!(scratch_scope.snapshot().managed_memory, 16);
  drop((scratch_a, scratch_b));
  assert_eq!(scratch_scope.snapshot().managed_memory, 0);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should close");
}

fn tcp_half_close_case() {
  const BYTES: usize = 8192;
  const TIMEOUT: Duration = Duration::from_secs(10);
  let reactor = reactor(2);
  let handle = reactor.handle();
  let (a, mut peer_a) = connected_stream(&handle);
  let (b, mut peer_b) = connected_stream(&handle);
  for peer in [&peer_a, &peer_b] {
    peer
      .set_read_timeout(Some(TIMEOUT))
      .expect("peer read timeout");
    peer
      .set_write_timeout(Some(TIMEOUT))
      .expect("peer write timeout");
  }
  let request: Vec<u8> = (0..BYTES).map(|index| (index % 239) as u8).collect();
  let reply: Vec<u8> = (0..BYTES).map(|index| (index % 233) as u8).collect();
  let expected_request = request.clone();
  let expected_reply = reply.clone();
  let client = thread::spawn(move || {
    peer_a
      .write_all(&request)
      .expect("client sends exact payload");
    peer_a
      .shutdown(Shutdown::Write)
      .expect("client half closes its write side");
    let mut received = Vec::new();
    peer_a
      .read_to_end(&mut received)
      .expect("client receives reverse response");
    received
  });
  let server = thread::spawn(move || {
    let mut received = Vec::new();
    peer_b
      .read_to_end(&mut received)
      .expect("server observes propagated EOF");
    peer_b
      .write_all(&reply)
      .expect("server sends reply after EOF");
    peer_b
      .shutdown(Shutdown::Write)
      .expect("server half closes its write side");
    received
  });

  let resources = resources(2 * 2048, 2);
  let inputs = RelayInputs {
    a,
    b,
    a_to_b: resources.try_alloc_zeroed(2048).expect("scratch fits"),
    b_to_a: resources.try_alloc_zeroed(2048).expect("scratch fits"),
  };
  let mut session = RelaySession::new(inputs, &resources).expect("session admits both endpoints");
  let runtime = async_runtime();
  let counts = runtime
    .block_on(session.run())
    .expect("root poll should complete")
    .expect("TCP relay should reach both half closes");
  let output = session.finish();
  assert_eq!(counts, (BYTES as u64, BYTES as u64));
  assert_eq!(output.progress.unwritten, (0..0, 0..0));
  assert_eq!(
    server.join().expect("server thread joins"),
    expected_request
  );
  assert_eq!(client.join().expect("client thread joins"), expected_reply);
  assert_eq!(resources.snapshot().network_ops, 0);
  assert_eq!(resources.snapshot().managed_memory, 4096);
  drop(output);
  assert_eq!(resources.snapshot().managed_memory, 0);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  assert_eq!(handle.registrations(), 0);
  assert_eq!(handle.waiters(), 0);
  reactor.shutdown().expect("reactor should stop");
}

fn cancel_and_finish_case() {
  let reactor = reactor(2);
  let handle = reactor.handle();
  let (a, _peer_a) = connected_stream(&handle);
  let (b, _peer_b) = connected_stream(&handle);
  let resources = resources(128, 2);
  let inputs = RelayInputs {
    a,
    b,
    a_to_b: resources.try_alloc_zeroed(64).expect("scratch fits"),
    b_to_a: resources.try_alloc_zeroed(64).expect("scratch fits"),
  };
  let mut session = RelaySession::new(inputs, &resources).expect("session admits endpoints");
  let pending = {
    let mut run = pin!(session.run());
    let mut context = Context::from_waker(Waker::noop());
    matches!(run.as_mut().poll(&mut context), Poll::Pending)
  };
  assert!(pending, "idle TCP relay should wait for either source");
  let runtime = async_runtime();
  let repeated = runtime
    .block_on(session.run())
    .expect("root poll should complete")
    .expect_err("a polled session cannot replay after cancellation");
  assert_eq!(repeated.kind(), std::io::ErrorKind::InvalidInput);
  let output = session.finish();
  assert_eq!(output.progress.transferred, (0, 0));
  assert_eq!(output.progress.unwritten, (0..0, 0..0));
  assert_eq!(resources.snapshot().network_ops, 0);
  assert_eq!(
    resources.snapshot().managed_memory,
    output.a_to_b.charged_bytes() + output.b_to_a.charged_bytes()
  );
  assert_eq!(handle.registrations(), 0);
  assert_eq!(handle.waiters(), 0);
  drop(output);
  assert_eq!(resources.snapshot().managed_memory, 0);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}

fn output_clone_charge_case() {
  let reactor = reactor(2);
  let handle = reactor.handle();
  let (a, mut peer_a) = connected_stream(&handle);
  let (b, mut peer_b) = connected_stream(&handle);
  peer_a
    .shutdown(Shutdown::Write)
    .expect("first peer should send EOF");
  peer_b
    .shutdown(Shutdown::Write)
    .expect("second peer should send EOF");
  peer_a
    .set_read_timeout(Some(Duration::from_secs(5)))
    .expect("first peer read timeout");
  peer_b
    .set_read_timeout(Some(Duration::from_secs(5)))
    .expect("second peer read timeout");
  let resources = resources(128, 2);
  let inputs = RelayInputs {
    a,
    b,
    a_to_b: resources.try_alloc_zeroed(64).expect("scratch fits"),
    b_to_a: resources.try_alloc_zeroed(64).expect("scratch fits"),
  };
  let expected_charge = inputs.a_to_b.charged_bytes() + inputs.b_to_a.charged_bytes();
  let mut session = RelaySession::new(inputs, &resources).expect("session admits endpoints");
  let runtime = async_runtime();
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("owned task scope should open");
  let task = scope
    .spawn(async move {
      let copied = session.run().await;
      let output = session.finish();
      (copied, output)
    })
    .expect("relay task should be admitted");
  let (copied, output) = runtime
    .block_on(task)
    .expect("root poll should complete")
    .expect("owned relay task should return its output");
  assert_eq!(copied.expect("empty streams should relay to EOF"), (0, 0));
  let mut peer_a_eof = [0; 1];
  let mut peer_b_eof = [0; 1];
  assert_eq!(
    peer_a.read(&mut peer_a_eof).expect("first peer sees EOF"),
    0
  );
  assert_eq!(
    peer_b.read(&mut peer_b_eof).expect("second peer sees EOF"),
    0
  );
  assert_eq!(resources.snapshot().network_ops, 0);
  assert_eq!(resources.snapshot().managed_memory, expected_charge);
  runtime
    .block_on(scope.close())
    .expect("scope close poll should complete");
  let retained = output.a_to_b.clone();
  drop(output);
  assert_eq!(
    resources.snapshot().managed_memory,
    retained.charged_bytes()
  );
  drop(retained);
  assert_eq!(resources.snapshot().managed_memory, 0);
  assert_eq!(handle.registrations(), 0);
  assert_eq!(handle.waiters(), 0);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}

fn canceled_publication_case() {
  let reactor = reactor(2);
  let handle = reactor.handle();
  let (a, mut peer_a) = connected_stream(&handle);
  let (b, mut peer_b) = connected_stream(&handle);
  let payload = b"publish only the bytes accepted before cancellation".to_vec();
  let expected = payload.clone();
  peer_a
    .set_write_timeout(Some(Duration::from_secs(5)))
    .expect("source write timeout");
  peer_b
    .set_read_timeout(Some(Duration::from_secs(5)))
    .expect("destination read timeout");
  peer_b
    .set_write_timeout(Some(Duration::from_secs(5)))
    .expect("destination tail timeout");
  peer_b
    .shutdown(Shutdown::Write)
    .expect("reverse source should be EOF");
  let received = Arc::new(AtomicBool::new(false));
  let waiter = Arc::new(Mutex::new(None::<Waker>));
  let peer_received = Arc::clone(&received);
  let peer_waiter = Arc::clone(&waiter);
  let peer = thread::spawn(move || {
    let mut prefix = vec![0; expected.len()];
    peer_b
      .read_exact(&mut prefix)
      .expect("peer observes the forwarded prefix");
    peer_received.store(true, Ordering::Release);
    let wake = peer_waiter
      .lock()
      .expect("waker mutex should not poison")
      .take();
    if let Some(waker) = wake {
      waker.wake();
    }
    let mut tail = Vec::new();
    peer_b
      .read_to_end(&mut tail)
      .expect("finish closes destination after cancellation");
    (prefix, tail)
  });
  peer_a
    .write_all(&payload)
    .expect("source writes finite witness payload");

  let resources = resources(64, 2);
  let inputs = RelayInputs {
    a,
    b,
    a_to_b: resources.try_alloc_zeroed(16).expect("scratch fits"),
    b_to_a: resources.try_alloc_zeroed(16).expect("scratch fits"),
  };
  let expected_charge = inputs.a_to_b.charged_bytes() + inputs.b_to_a.charged_bytes();
  let mut session = RelaySession::new(inputs, &resources).expect("session admits endpoints");
  let runtime = async_runtime();
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("owned task scope should open");
  let task_received = Arc::clone(&received);
  let task_waiter = Arc::clone(&waiter);
  let task_reactor = handle.clone();
  let task = scope
    .spawn(async move {
      let observed_pending = {
        let mut run = pin!(session.run());
        poll_fn(|cx| match run.as_mut().poll(cx) {
          Poll::Ready(result) => Poll::Ready(Err(result.err().unwrap_or_else(|| {
            io::Error::other("relay completed before its source remained open")
          }))),
          Poll::Pending => {
            if task_received.load(Ordering::Acquire) {
              return Poll::Ready(Ok(()));
            }
            *task_waiter.lock().expect("waker mutex should not poison") = Some(cx.waker().clone());
            if task_received.load(Ordering::Acquire) {
              Poll::Ready(Ok(()))
            } else {
              Poll::Pending
            }
          }
        })
        .await
      };
      let progress_before_retry = session.progress().clone();
      let waiters_before_retry = task_reactor.waiters();
      let retry = session
        .run()
        .await
        .expect_err("canceled run cannot restart");
      let progress_after_retry = session.progress().clone();
      let waiters_after_retry = task_reactor.waiters();
      let output = session.finish();
      (
        observed_pending,
        progress_before_retry,
        retry.kind(),
        progress_after_retry,
        waiters_before_retry,
        waiters_after_retry,
        output,
      )
    })
    .expect("owned task should be admitted");
  let (
    observed_pending,
    before_retry,
    retry_kind,
    after_retry,
    waiters_before_retry,
    waiters_after_retry,
    output,
  ) = runtime
    .block_on(task)
    .expect("root poll should complete")
    .expect("owned task should publish canceled borrowed-run output");
  observed_pending.expect("relay should remain pending after forwarding data");
  assert_eq!(before_retry.transferred.0, payload.len() as u64);
  assert_eq!(before_retry.unwritten, (0..0, 0..0));
  assert_eq!(retry_kind, io::ErrorKind::InvalidInput);
  assert_eq!(after_retry, before_retry, "refusal must not alter progress");
  assert_eq!(waiters_after_retry, waiters_before_retry);
  assert_eq!(output.progress, before_retry);
  assert_eq!(resources.snapshot().network_ops, 0);
  assert_eq!(resources.snapshot().managed_memory, expected_charge);
  runtime
    .block_on(scope.close())
    .expect("scope close should complete");
  let (forwarded, tail) = peer.join().expect("peer reader should join");
  assert_eq!(forwarded, payload);
  assert!(
    tail.is_empty(),
    "finish closes the destination after prefix"
  );
  let retained = output.a_to_b.clone();
  let retained_charge = retained.charged_bytes();
  drop(output);
  assert_eq!(resources.snapshot().managed_memory, retained_charge);
  drop(retained);
  assert_eq!(resources.snapshot().managed_memory, 0);
  assert_eq!(handle.registrations(), 0);
  assert_eq!(handle.waiters(), 0);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}

fn owned_abort_case() {
  let reactor = reactor(2);
  let handle = reactor.handle();
  let (a, _peer_a) = connected_stream(&handle);
  let (b, _peer_b) = connected_stream(&handle);
  let resources = resources(128, 2);
  let inputs = RelayInputs {
    a,
    b,
    a_to_b: resources.try_alloc_zeroed(64).expect("scratch fits"),
    b_to_a: resources.try_alloc_zeroed(64).expect("scratch fits"),
  };
  let mut session = RelaySession::new(inputs, &resources).expect("session admits endpoints");
  let runtime = async_runtime();
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("owned task scope should open");
  let (pending_tx, pending_rx) = std::sync::mpsc::channel();
  let task = scope
    .spawn(async move {
      let pending = {
        let mut run = pin!(session.run());
        let mut context = Context::from_waker(Waker::noop());
        matches!(run.as_mut().poll(&mut context), Poll::Pending)
      };
      pending_tx
        .send(pending)
        .expect("pending observer remains live");
      std::future::pending::<()>().await;
    })
    .expect("relay task should be admitted");
  assert!(
    pending_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("task should poll"),
    "task must observe a real pending relay poll before abort"
  );
  assert_eq!(handle.registrations(), 2);
  assert!(handle.waiters() > 0, "pending relay should retain waiters");
  task.abort();
  runtime
    .block_on(scope.close())
    .expect("scope close should await actual task cleanup");
  let joined = runtime
    .block_on(task)
    .expect("join root poll should complete");
  assert!(joined.is_err(), "aborted whole-session task has no output");
  assert_eq!(resources.snapshot().network_ops, 0);
  assert_eq!(resources.snapshot().managed_memory, 0);
  assert_eq!(handle.registrations(), 0);
  assert_eq!(handle.waiters(), 0);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}
