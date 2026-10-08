use std::future::{self, Future};
use std::os::fd::AsRawFd;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use allocatbelt::runtime::asynchronous::{
  AsyncConfig, AsyncJoinError, AsyncRuntime, AsyncShutdown,
};
use allocatbelt::runtime::managed::{OperationRequest, ResourceLimits, ResourceScope};
use allocatbelt::runtime::net::{NetHandle, TcpConnectError, TcpConnectRejectKind, TcpSocket};
use allocatbelt::runtime::reactor::{Reactor, ReactorConfig};
use allocatbelt::runtime::{
  Config as BlockingConfig, Resources, Runtime as BlockingRuntime, ShutdownMode,
};
use allocatbelt_app_ports::http::{self, HttpConfig, MAX_REQUEST_BYTES};
use allocatbelt_app_ports::memory::{checksum, pattern_byte};

#[test]
fn nonblocking_socket_http_progresses_with_a_full_blocking_pool() {
  within_watchdog(nonblocking_exchange);
}

#[test]
fn registration_rejection_cleans_up_the_scope_owned_http_server() {
  within_watchdog(registration_rejection);
}

fn within_watchdog(run: fn()) {
  let (done_tx, done_rx) = mpsc::channel();
  let worker = thread::spawn(move || {
    run();
    done_tx
      .send(())
      .expect("qualification receiver remains live");
  });
  done_rx
    .recv_timeout(Duration::from_secs(10))
    .expect("nonblocking HTTP exchange must finish within its watchdog");
  worker.join().expect("qualification worker must finish");
}

fn nonblocking_exchange() {
  let mut blocking = BlockingRuntime::new(BlockingConfig {
    workers: 1,
    max_outstanding: 1,
    capacity: Resources::ZERO,
  })
  .expect("blocking runtime should start");
  let blocking_handle = blocking.handle();
  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let blocker = blocking_handle
    .try_spawn(Resources::ZERO, move |_| {
      started_tx.send(()).expect("gate receiver remains live");
      release_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("exchange must finish before the blocking gate is released");
    })
    .expect("gate should occupy the only blocking admission slot");
  started_rx
    .recv_timeout(Duration::from_secs(5))
    .expect("blocking worker should enter its gate");

  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 3,
    max_waiters: 6,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 2,
    max_outstanding: 4,
    max_scopes: 2,
  })
  .expect("async runtime should start");
  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: 3 * MAX_REQUEST_BYTES + 256,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 2,
  });
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("HTTP scope should open");
  let socket = TcpSocket::new_v4().expect("listener socket should open");
  socket
    .bind("127.0.0.1:0".parse().expect("valid loopback address"))
    .expect("listener socket should bind");
  let address = socket
    .local_addr()
    .expect("bound address should be available");
  let listener = socket
    .listen(1, &reactor_handle)
    .expect("listener socket should register");
  let server_resources = resources.clone();
  let server = scope
    .spawn(async move {
      let (stream, _) = listener.accept().await.expect("client should connect");
      http::serve_connection_with_id(stream, server_resources).await
    })
    .expect("server task should be admitted");
  let net = NetHandle::new(
    blocking_handle.clone(),
    resources.clone(),
    reactor_handle.clone(),
    1,
  )
  .expect("network handle should initialize");
  let request_id = 0x5351;
  let config = HttpConfig {
    body_bytes: 1739,
    seed: 91,
  };
  let (client_checksum, server_result) = runtime
    .block_on(async {
      let socket = TcpSocket::new_v4().expect("client socket should open");
      socket
        .set_nodelay(true)
        .expect("client option should apply");
      assert!(socket.nodelay().expect("client option should read back"));
      socket
        .bind("127.0.0.1:0".parse().expect("valid client address"))
        .expect("client socket should bind explicitly");
      let mut stream = net
        .connect_socket(socket, address)
        .await
        .expect("nonblocking connect must not need blocking-pool admission");
      let endpoint_permit = resources
        .try_acquire(OperationRequest {
          disk: 0,
          network: 1,
        })
        .expect("client endpoint should retain its network charge");
      let actual = http::transact_client_io(&mut stream, &resources, request_id, config)
        .await
        .expect("shared client kernel should finish");
      drop(stream);
      drop(endpoint_permit);
      let served = server
        .await
        .expect("server join should finish")
        .expect("shared server kernel should finish");
      (actual, served)
    })
    .expect("HTTP root should finish");
  let expected = checksum(
    &(0..config.body_bytes)
      .map(|index| pattern_byte(config.seed, index))
      .collect::<Vec<_>>(),
  );
  assert_eq!(client_checksum, expected);
  assert_eq!(server_result, (request_id, expected));
  assert_eq!(blocking_handle.snapshot().outstanding, 1);

  assert_eq!(scope.snapshot().active_tasks, 0);
  runtime.block_on(scope.close()).expect("scope should close");
  assert_eq!(resources.snapshot().managed_memory, 0);
  assert_eq!(resources.snapshot().network_ops, 0);
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(reactor_handle.waiters(), 0);
  release_tx
    .send(())
    .expect("blocking gate should remain held");
  blocker.join().expect("blocking gate should finish");
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}

fn registration_rejection() {
  let mut blocking = BlockingRuntime::new(BlockingConfig {
    workers: 1,
    max_outstanding: 1,
    capacity: Resources::ZERO,
  })
  .expect("blocking runtime should start");
  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 1,
    max_waiters: 2,
  })
  .expect("reactor should start");
  let reactor_handle = reactor.handle();
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 1,
    max_scopes: 2,
  })
  .expect("async runtime should start");
  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: 3 * MAX_REQUEST_BYTES + 256,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 2,
  });
  let scope = runtime
    .scope_with_resources(&resources)
    .expect("HTTP scope should open");
  let socket = TcpSocket::new_v4().expect("listener socket should open");
  socket
    .bind("127.0.0.1:0".parse().expect("valid loopback address"))
    .expect("listener socket should bind");
  let address = socket
    .local_addr()
    .expect("bound address should be available");
  let listener = socket
    .listen(1, &reactor_handle)
    .expect("listener should occupy registration");
  let (pending_tx, pending_rx) = mpsc::channel();
  let server_resources = resources.clone();
  let server = scope
    .spawn(async move {
      let mut accepting = Box::pin(listener.accept());
      let mut announced = false;
      let (stream, _) = future::poll_fn(|cx| {
        let result = accepting.as_mut().poll(cx);
        if result.is_pending() && !announced {
          pending_tx.send(()).expect("pending receiver remains live");
          announced = true;
        }
        result
      })
      .await
      .expect("an admitted client should connect");
      http::serve_connection_with_id(stream, server_resources).await
    })
    .expect("server should occupy the only owned task slot");
  pending_rx
    .recv_timeout(Duration::from_secs(5))
    .expect("HTTP server must actually wait for its client");
  let net = NetHandle::new(
    blocking.handle(),
    resources.clone(),
    reactor_handle.clone(),
    1,
  )
  .expect("network handle should initialize");
  let socket = TcpSocket::new_v4().expect("client socket should open");
  socket
    .set_nodelay(true)
    .expect("client option should apply");
  socket
    .bind("127.0.0.1:0".parse().expect("valid client address"))
    .expect("client socket should bind explicitly");
  let client_address = socket
    .local_addr()
    .expect("client address should be available");
  let client_owned_fd = socket.into_owned_fd();
  let client_fd = client_owned_fd.as_raw_fd();
  let socket = TcpSocket::from_owned_fd(client_owned_fd)
    .expect("exclusively owned client socket should import unchanged");
  let rejected = runtime
    .block_on(net.connect_socket(socket, address))
    .expect("pre-connect rejection should finish")
    .expect_err("listener exhausts the reactor registration bound");
  let TcpConnectError::Submission(rejected) = rejected else {
    panic!("registration refusal must preserve the supplied client socket");
  };
  assert!(matches!(
    rejected.kind,
    TcpConnectRejectKind::Registration(_)
  ));
  assert_eq!(
    rejected
      .socket
      .local_addr()
      .expect("returned socket remains bound"),
    client_address
  );
  assert!(
    rejected
      .socket
      .nodelay()
      .expect("returned option should read back")
  );
  assert_eq!(resources.snapshot().network_ops, 0);
  assert_eq!(reactor_handle.registrations(), 1);
  let returned_fd = rejected.socket.into_owned_fd();
  assert_eq!(returned_fd.as_raw_fd(), client_fd);
  drop(returned_fd);
  server.abort_handle().abort();
  assert!(matches!(
    runtime
      .block_on(server)
      .expect("server cancellation must finish"),
    Err(AsyncJoinError::Cancelled)
  ));
  assert_eq!(scope.snapshot().active_tasks, 0);
  let sentinel = scope
    .spawn(async { 17 })
    .expect("cancelled server slot must be reusable");
  assert_eq!(
    runtime
      .block_on(sentinel)
      .expect("sentinel root should finish")
      .expect("sentinel should complete"),
    17
  );
  assert_eq!(scope.snapshot().active_tasks, 0);
  runtime
    .block_on(scope.close())
    .expect("HTTP scope should close");
  assert_eq!(resources.snapshot().managed_memory, 0);
  assert_eq!(resources.snapshot().network_ops, 0);
  assert_eq!(reactor_handle.registrations(), 0);
  assert_eq!(reactor_handle.waiters(), 0);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("async runtime should stop");
  blocking
    .shutdown(ShutdownMode::Drain)
    .expect("blocking runtime should stop");
  reactor.shutdown().expect("reactor should stop");
}
