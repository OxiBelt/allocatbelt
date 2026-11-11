use super::*;
use std::io::{self, Write};
use std::net::{
  TcpListener as StdTcpListener, TcpStream as StdTcpStream, UdpSocket as StdUdpSocket,
};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown, LocalConfig};
use crate::runtime::byte_rate::{ByteRateConfig, ByteRateLimit};
use crate::runtime::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use crate::runtime::managed::{OperationRequest, ResourceLimits, ResourceScope};
use crate::runtime::net::{TcpStream, UdpSocket};
use crate::runtime::reactor::{Reactor, ReactorConfig};
use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};
use crate::runtime::time::{TimerDriver, TimerError};

#[cfg(not(loom))]
use crate::runtime::rate_io::RateIoFailure;
#[cfg(feature = "resource-feedback")]
use crate::runtime::resource_feedback_meter::IoFeedbackMeter;

fn byte_rate(rate: u64, burst: usize, reservations: usize) -> ByteRateLimit {
  ByteRateLimit::new(ByteRateConfig {
    bytes_per_second: rate,
    burst_bytes: burst,
    max_reservations: reservations,
  })
  .expect("valid test rate")
}

fn make_bindings(
  resources: &ResourceScope,
  disk_rate: Option<&ByteRateLimit>,
  upload_rate: Option<&ByteRateLimit>,
  download_rate: Option<&ByteRateLimit>,
  timer: Option<&TimerHandle>,
  #[cfg(feature = "resource-feedback")] meters: Option<IoMeters>,
) -> Result<IoBindings, DomainError> {
  IoBindings::new(
    resources,
    disk_rate,
    upload_rate,
    download_rate,
    timer,
    #[cfg(feature = "resource-feedback")]
    meters,
  )
}

fn controlled_scope(
  control: usize,
  resources: ResourceLimits,
) -> (
  ResourceDomain,
  crate::runtime::resource_domain::TenantDomain,
  ResourceScope,
) {
  let ceiling = DomainResources::ZERO
    .with(DomainResource::Control, control)
    .with(DomainResource::Memory, 1 << 20)
    .with(DomainResource::Disk, 8)
    .with(DomainResource::Network, 8);
  let domain = ResourceDomain::with_waiters(ceiling, 2, 0).expect("test domain");
  let tenant = domain.tenant(ceiling).expect("test tenant");
  let scope = ResourceScope::try_from_tenant(resources, tenant.clone()).expect("test scope");
  (domain, tenant, scope)
}

#[derive(Debug)]
struct ProbeIo {
  id: u64,
  polls: Arc<AtomicUsize>,
}

impl AsyncRead for ProbeIo {
  fn poll_read(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    output: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    self.polls.fetch_add(1, Ordering::SeqCst);
    output.fill(b'x');
    Poll::Ready(Ok(output.len()))
  }
}

impl AsyncWrite for ProbeIo {
  fn poll_write(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    input: &[u8],
  ) -> Poll<io::Result<usize>> {
    self.polls.fetch_add(1, Ordering::SeqCst);
    Poll::Ready(Ok(input.len()))
  }

  fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.polls.fetch_add(1, Ordering::SeqCst);
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.polls.fetch_add(1, Ordering::SeqCst);
    Poll::Ready(Ok(()))
  }
}

fn registered_udp(reactor: &Reactor) -> UdpSocket {
  let socket = StdUdpSocket::bind("127.0.0.1:0").expect("bind UDP socket");
  UdpSocket::from_std(socket, &reactor.handle()).expect("register UDP socket")
}

#[test]
fn bindings_share_one_control_charge_and_the_same_resource_ledger() {
  let (domain, tenant, scope) = controlled_scope(
    1 << 20,
    ResourceLimits {
      managed_memory: 64,
      network_concurrent_ops: 1,
      ..ResourceLimits::default()
    },
  );
  let domain_baseline = domain.snapshot().used.get(DomainResource::Control)
    - tenant
      .snapshot()
      .expect("tenant snapshot")
      .used
      .get(DomainResource::Control);
  let before_binding = domain.snapshot().used.get(DomainResource::Control);
  let inner_bytes = std::mem::size_of::<BindingsInner>();
  let bindings = make_bindings(
    &scope,
    None,
    None,
    None,
    None,
    #[cfg(feature = "resource-feedback")]
    None,
  )
  .expect("bindings fit Control limit");
  assert_eq!(
    domain.snapshot().used.get(DomainResource::Control),
    before_binding + inner_bytes
  );

  let clone = bindings.clone();
  let resources = bindings.resources();
  assert_eq!(resources.limits().network_concurrent_ops, 1);
  let permit = resources
    .try_acquire(OperationRequest {
      disk: 0,
      network: 1,
    })
    .expect("binding exposes the same operation ledger");
  assert_eq!(
    resources.snapshot().network_ops,
    1,
    "the local ledger reports the one held operation"
  );
  drop(permit);

  drop(scope);
  drop(resources);
  drop(bindings);
  assert_eq!(
    domain.snapshot().used.get(DomainResource::Control),
    before_binding + inner_bytes,
    "a clone retains the binding and scope charges"
  );
  drop(clone);
  assert_eq!(
    domain.snapshot().used.get(DomainResource::Control),
    domain_baseline
  );
}

#[test]
fn bindings_control_precharge_failure_does_not_change_the_scope_or_inputs() {
  let (_domain, tenant, scope) = controlled_scope(
    1 << 20,
    ResourceLimits {
      managed_memory: 64,
      ..ResourceLimits::default()
    },
  );
  let baseline = tenant
    .snapshot()
    .expect("domain snapshot")
    .used
    .get(DomainResource::Control);
  tenant
    .set_limits(DomainResources::ZERO.with(DomainResource::Control, baseline))
    .expect("lower tenant limit to current use");
  let download = byte_rate(10, 8, 2);
  assert_eq!(
    make_bindings(
      &scope,
      None,
      None,
      Some(&download),
      None,
      #[cfg(feature = "resource-feedback")]
      None,
    )
    .err(),
    Some(DomainError::Exhausted(DomainResource::Control))
  );
  assert_eq!(
    tenant
      .snapshot()
      .expect("domain snapshot")
      .used
      .get(DomainResource::Control),
    baseline
  );
  assert_eq!(download.snapshot().bytes_per_second, 10);
  assert_eq!(scope.snapshot().managed_memory, 0);
}

#[test]
fn missing_rate_configuration_returns_the_unpolled_original_endpoint() {
  let resources = ResourceScope::new(ResourceLimits::default());
  let bindings = make_bindings(
    &resources,
    None,
    None,
    None,
    None,
    #[cfg(feature = "resource-feedback")]
    None,
  )
  .expect("unbounded bindings");
  let polls = Arc::new(AtomicUsize::new(0));
  let result = bindings.rate_io(ProbeIo {
    id: 17,
    polls: Arc::clone(&polls),
  });
  let error = match result {
    Err(error) => error,
    Ok(_) => panic!("missing rates unexpectedly produced a stream adapter"),
  };
  assert_eq!(
    error.failure(),
    super::super::DriverRateIoFailure::MissingUploadAndDownloadRates
  );
  assert_eq!(error.into_inner().id, 17);

  let disk_error = match bindings.disk_io(ProbeIo {
    id: 23,
    polls: Arc::clone(&polls),
  }) {
    Err(error) => error,
    Ok(_) => panic!("missing disk rate unexpectedly produced an adapter"),
  };
  assert_eq!(
    disk_error.failure(),
    super::super::DriverRateIoFailure::MissingDiskRate
  );
  assert_eq!(disk_error.into_inner().id, 23);
  assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[test]
fn both_owning_builders_export_bindings_for_their_selected_buckets() {
  let rate = ByteRateConfig {
    bytes_per_second: 16,
    burst_bytes: 2,
    max_reservations: 2,
  };
  let disk_rate = ByteRateConfig {
    bytes_per_second: 16,
    burst_bytes: 3,
    max_reservations: 2,
  };

  let mut current = super::super::CurrentThreadBuilder::new(LocalConfig {
    max_outstanding: 8,
    max_scopes: 4,
  })
  .disk_rate(disk_rate)
  .upload_rate(rate)
  .download_rate(rate)
  .rate_timer_registrations(16)
  .build()
  .expect("build current-thread driver");
  let current_bindings = current.io_bindings().expect("current bindings");
  let mut current_stream = current_bindings
    .clone()
    .rate_io(ProbeIo {
      id: 41,
      polls: Arc::new(AtomicUsize::new(0)),
    })
    .expect("current network adapter");
  let current_write = current
    .block_on(std::future::poll_fn(|cx| {
      Pin::new(&mut current_stream).poll_write(cx, b"abc")
    }))
    .expect("current root poll");
  assert_eq!(current_write.expect("current stream write"), 2);
  assert_eq!(
    current
      .upload_rate()
      .expect("selected upload bucket")
      .snapshot()
      .available_bytes,
    0
  );

  let mut current_disk = current_bindings
    .disk_io(ProbeIo {
      id: 42,
      polls: Arc::new(AtomicUsize::new(0)),
    })
    .expect("current disk adapter");
  let current_disk_write = current
    .block_on(std::future::poll_fn(|cx| {
      Pin::new(&mut current_disk).poll_write(cx, b"xyz")
    }))
    .expect("current disk root poll");
  assert_eq!(current_disk_write.expect("current disk write"), 3);
  assert_eq!(
    current
      .disk_rate()
      .expect("selected disk bucket")
      .snapshot()
      .available_bytes,
    0
  );
  drop(current_disk);
  drop(current_stream);
  drop(current_bindings);
  drop(current);

  let multi = super::super::MultiThreadBuilder::new(AsyncConfig {
    workers: 1,
    max_outstanding: 8,
    max_scopes: 4,
  })
  .disk_rate(disk_rate)
  .upload_rate(rate)
  .download_rate(rate)
  .rate_timer_registrations(16)
  .build()
  .expect("build multithread driver");
  let multi_bindings = multi.io_bindings().expect("multithread bindings");
  let mut multi_stream = multi_bindings
    .clone()
    .rate_io(ProbeIo {
      id: 43,
      polls: Arc::new(AtomicUsize::new(0)),
    })
    .expect("multithread network adapter");
  let multi_write = multi
    .block_on(std::future::poll_fn(|cx| {
      Pin::new(&mut multi_stream).poll_write(cx, b"abc")
    }))
    .expect("multithread root poll");
  assert_eq!(multi_write.expect("multithread stream write"), 2);
  assert_eq!(
    multi
      .upload_rate()
      .expect("selected upload bucket")
      .snapshot()
      .available_bytes,
    0
  );

  let mut multi_disk = multi_bindings
    .disk_io(ProbeIo {
      id: 44,
      polls: Arc::new(AtomicUsize::new(0)),
    })
    .expect("multithread disk adapter");
  let multi_disk_write = multi
    .block_on(std::future::poll_fn(|cx| {
      Pin::new(&mut multi_disk).poll_write(cx, b"xyz")
    }))
    .expect("multithread disk root poll");
  assert_eq!(multi_disk_write.expect("multithread disk write"), 3);
  assert_eq!(
    multi
      .disk_rate()
      .expect("selected disk bucket")
      .snapshot()
      .available_bytes,
    0
  );
}

#[test]
fn datagram_metadata_refusal_returns_the_original_socket() {
  let (_domain, tenant, scope) = controlled_scope(
    1 << 20,
    ResourceLimits {
      network_concurrent_ops: 1,
      ..ResourceLimits::default()
    },
  );
  let timer = TimerDriver::new_realtime(2).expect("rate timer");
  let download = byte_rate(16, 8, 1);
  let upload = byte_rate(16, 8, 1);
  let bindings = make_bindings(
    &scope,
    None,
    Some(&upload),
    Some(&download),
    Some(&timer.handle()),
    #[cfg(feature = "resource-feedback")]
    None,
  )
  .expect("bindings fit Control limit");
  let current_control = tenant
    .snapshot()
    .expect("tenant snapshot")
    .used
    .get(DomainResource::Control);
  tenant
    .set_limits(DomainResources::ZERO.with(DomainResource::Control, current_control))
    .expect("remove only the remaining Control headroom");

  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 2,
  })
  .expect("reactor");
  let socket = registered_udp(&reactor);
  let address = socket.get_ref().local_addr().expect("socket address");
  let error = match bindings.rate_datagram(socket) {
    Err(error) => error,
    Ok(_) => panic!("UDP metadata charge unexpectedly succeeded"),
  };
  assert_eq!(
    error.failure(),
    DriverRateDatagramFailure::Adapter(RateDatagramBuildFailure::Control(DomainError::Exhausted(
      DomainResource::Control
    )))
  );
  let socket = error.into_inner();
  assert_eq!(
    socket.get_ref().local_addr().expect("recovered address"),
    address
  );
  drop(socket);
  drop(bindings);
  drop(scope);
  drop(timer);
  drop(reactor);
}

#[test]
fn driver_timer_close_is_observed_by_retained_bindings() {
  let resources = ResourceScope::new(ResourceLimits::default());
  let timer = TimerDriver::new_realtime(4).expect("rate timer");
  let handle = timer.handle();
  let download = byte_rate(16, 8, 1);
  let upload = byte_rate(16, 8, 1);
  let bindings = make_bindings(
    &resources,
    None,
    Some(&upload),
    Some(&download),
    Some(&handle),
    #[cfg(feature = "resource-feedback")]
    None,
  )
  .expect("bindings");
  drop(timer);

  let polls = Arc::new(AtomicUsize::new(0));
  let error = match bindings.rate_io(ProbeIo {
    id: 31,
    polls: Arc::clone(&polls),
  }) {
    Err(error) => error,
    Ok(_) => panic!("closed driver timer unexpectedly built a stream"),
  };
  assert_eq!(
    error.failure(),
    super::super::DriverRateIoFailure::Adapter(RateIoFailure::Timer(TimerError::Closed))
  );
  assert_eq!(error.into_inner().id, 31);
  assert_eq!(polls.load(Ordering::SeqCst), 0);

  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 2,
  })
  .expect("reactor");
  let socket = registered_udp(&reactor);
  let address = socket.get_ref().local_addr().expect("socket address");
  let error = match bindings.rate_datagram(socket) {
    Err(error) => error,
    Ok(_) => panic!("closed driver timer unexpectedly built a UDP adapter"),
  };
  assert_eq!(
    error.failure(),
    DriverRateDatagramFailure::Adapter(RateDatagramBuildFailure::TimerClosed)
  );
  assert_eq!(
    error
      .into_inner()
      .get_ref()
      .local_addr()
      .expect("recovered address"),
    address
  );
  drop(bindings);
  drop(reactor);
}

#[test]
fn cloned_binding_wraps_real_tcp_in_a_static_task_and_releases_its_fee() {
  let (domain, tenant, scope) = controlled_scope(
    1 << 20,
    ResourceLimits {
      network_concurrent_ops: 1,
      ..ResourceLimits::default()
    },
  );
  let domain_baseline = domain.snapshot().used.get(DomainResource::Control)
    - tenant
      .snapshot()
      .expect("tenant snapshot")
      .used
      .get(DomainResource::Control);
  let rate_timer = TimerDriver::new_realtime(4).expect("rate timer");
  let download = byte_rate(1, 1, 1);
  let upload = byte_rate(16, 8, 1);

  #[cfg(feature = "resource-feedback")]
  let download_meter = IoFeedbackMeter::new();
  #[cfg(feature = "resource-feedback")]
  let meters = IoMeters {
    disk: IoFeedbackMeter::new(),
    upload: IoFeedbackMeter::new(),
    download: download_meter.clone(),
  };

  let before_binding = domain.snapshot().used.get(DomainResource::Control);
  let bindings = make_bindings(
    &scope,
    None,
    Some(&upload),
    Some(&download),
    Some(&rate_timer.handle()),
    #[cfg(feature = "resource-feedback")]
    Some(meters),
  )
  .expect("bindings");
  let binding_bytes = std::mem::size_of::<BindingsInner>();
  assert_eq!(
    domain.snapshot().used.get(DomainResource::Control),
    before_binding + binding_bytes
  );

  let listener = StdTcpListener::bind("127.0.0.1:0").expect("TCP listener");
  let client_std =
    StdTcpStream::connect(listener.local_addr().expect("listener address")).expect("TCP connect");
  let (mut server_std, _) = listener.accept().expect("TCP accept");
  server_std.write_all(b"ab").expect("seed TCP bytes");
  drop(server_std);

  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2,
    max_waiters: 2,
  })
  .expect("reactor");
  let reactor_handle = reactor.handle();
  let client = TcpStream::from_std(client_std, &reactor_handle).expect("register TCP client");
  drop(reactor_handle);

  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 8,
    max_scopes: 4,
  })
  .expect("single-worker executor");
  let handle = runtime.handle();
  let task_bindings = bindings.clone();
  let (first_byte_tx, first_byte_rx) = mpsc::sync_channel(1);
  let read_job = handle
    .spawn(async move {
      let _network_operation = task_bindings
        .resources()
        .try_acquire(OperationRequest {
          disk: 0,
          network: 1,
        })
        .expect("network operation permit from binding scope");
      let mut stream = task_bindings
        .rate_io(client)
        .expect("configured TCP rate adapter");
      let mut bytes = [0_u8; 2];
      stream.read_exact(&mut bytes[..1]).await?;
      first_byte_tx.send(()).expect("first byte notification");
      stream.read_exact(&mut bytes[1..]).await?;
      io::Result::Ok(bytes)
    })
    .expect("admit static TCP task");

  drop(scope);
  drop(bindings);
  assert_eq!(
    domain.snapshot().used.get(DomainResource::Control),
    before_binding + binding_bytes,
    "the spawned task's clone retains the shared charge"
  );
  first_byte_rx
    .recv_timeout(Duration::from_secs(2))
    .expect("first TCP byte arrived");
  assert_eq!(download.snapshot().available_bytes, 0);

  let (ready_tx, ready_rx) = mpsc::sync_channel(1);
  let sibling = handle
    .spawn(async move {
      ready_tx.send(()).expect("sibling notification");
    })
    .expect("admit sibling task");
  ready_rx
    .recv_timeout(Duration::from_millis(500))
    .expect("ready sibling ran while the TCP task waited for real-time credit");
  runtime
    .block_on(sibling)
    .expect("root poll")
    .expect("sibling task result");

  let output = runtime
    .block_on(read_job)
    .expect("root poll")
    .expect("TCP task result")
    .expect("TCP read");
  assert_eq!(&output, b"ab");
  assert_eq!(
    domain.snapshot().used.get(DomainResource::Control),
    domain_baseline,
    "the last task-owned binding clone releases the shared and scope charges"
  );
  assert_eq!(domain.snapshot().used.get(DomainResource::Network), 0);

  #[cfg(feature = "resource-feedback")]
  {
    let sample = download_meter.snapshot();
    assert_eq!(sample.committed_bytes, 2);
    assert_eq!(sample.attached_sources, 0);
  }

  runtime
    .shutdown(AsyncShutdown::CancelPending)
    .expect("shutdown executor");
  drop(reactor);
  drop(rate_timer);
}
