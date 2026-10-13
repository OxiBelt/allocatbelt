use super::*;

use allocatbelt::runtime::asynchronous::AsyncConfig;
use allocatbelt::runtime::fs::OwnedFile;
use allocatbelt::runtime::io::{AsyncRead, AsyncWrite};
use allocatbelt::runtime::resource_domain::{DomainResources, ResourceDomain};
use allocatbelt::runtime::resource_feedback::{
  FeedbackSensor, FeedbackSensorError, FeedbackShutdownProgress, FeedbackWorkerFailure,
  ResourceFeedbackService,
};
use allocatbelt::runtime::resource_feedback_actuator::{
  CpuFeedbackTarget, RuntimeFeedbackActuator,
};
use allocatbelt::runtime::resource_feedback_meter::IoFeedbackMeter;
use allocatbelt::runtime::resource_feedback_policy::{FeedbackResource, FeedbackSample};
use allocatbelt::runtime::resource_feedback_sensor::{
  IoFeedbackSource, ProcessCpuSensor, RuntimeFeedbackSensor,
};
use allocatbelt::runtime::{Config as BlockingConfig, MultiThreadBuilder};
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

static NEXT_DISK_FILE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct TinyIo;

struct StdTcpIo(std::net::TcpStream);

struct OverloadedSensor;

struct CleanupPanickingSensor;

impl FeedbackSensor for OverloadedSensor {
  fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
    Ok(FeedbackSample::new(
      std::time::Instant::now(),
      Some(10_000),
      Some(10_000),
      Some(10_000),
    ))
  }
}

impl FeedbackSensor for CleanupPanickingSensor {
  fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
    Ok(FeedbackSample::new(Instant::now(), Some(0), None, None))
  }
}

impl Drop for CleanupPanickingSensor {
  fn drop(&mut self) {
    panic!("controlled feedback sensor cleanup panic");
  }
}

impl AsyncRead for TinyIo {
  fn poll_read(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    output: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let count = output.len().min(4);
    output[..count].fill(0x5a);
    Poll::Ready(Ok(count))
  }
}

impl AsyncWrite for TinyIo {
  fn poll_write(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    input: &[u8],
  ) -> Poll<io::Result<usize>> {
    Poll::Ready(Ok(input.len()))
  }

  fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }
}

impl AsyncRead for StdTcpIo {
  fn poll_read(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    output: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    match self.0.read(output) {
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
      result => Poll::Ready(result),
    }
  }
}

impl AsyncWrite for StdTcpIo {
  fn poll_write(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    input: &[u8],
  ) -> Poll<io::Result<usize>> {
    match self.0.write(input) {
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
      result => Poll::Ready(result),
    }
  }

  fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(self.0.flush())
  }

  fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(self.get_mut().0.shutdown(std::net::Shutdown::Write))
  }
}

fn context(waker: &Waker) -> Context<'_> {
  Context::from_waker(waker)
}

fn external_domain(workload: Workload, workers: usize) -> ApplicationDomain {
  ApplicationDomain::new_with_calibrations(
    workload,
    workers,
    ApplicationMode::ExternalPressure,
    FeedbackCalibrations::default(),
  )
  .expect("pressure domain")
}

#[test]
fn writerless_feedback_health_reports_worker_cleanup_fault_after_join() {
  let domain = external_domain(Workload::Http, 2);
  let readback_domain = domain.readback_domain();
  let baseline = domain.fixed_global_control_baseline();
  let mut bindings = domain.for_tokio().expect("pressure bindings");
  bindings
    .shutdown_feedback(Duration::from_secs(5))
    .expect("replace the healthy default feedback fixture");
  let tenant = domain.tenant();
  let service = ResourceFeedbackService::start_in_tenant(
    feedback_policy(2),
    CleanupPanickingSensor,
    RuntimeFeedbackActuator::new(
      CpuFeedbackTarget::Tenant(tenant.clone()),
      bindings.io.disk_rate.clone(),
      bindings.io.download_rate.clone(),
    ),
    &tenant,
  )
  .expect("controlled faulting service startup");
  let metrics = service.metrics_handle();
  bindings.feedback.metrics = Some(metrics.clone());
  bindings.feedback.service = Some(service);

  let shutdown_error = bindings
    .shutdown_feedback(Duration::from_secs(5))
    .expect_err("cleanup panic must be reported by service join");
  assert!(shutdown_error.contains("feedback service shutdown failed"));
  let snapshot = metrics.snapshot();
  assert!(
    snapshot.shutdown_complete,
    "join must finish despite the fault"
  );
  assert_eq!(
    snapshot.worker_failure,
    Some(FeedbackWorkerFailure::PayloadCleanupPanicked)
  );
  assert!(bindings.validate_feedback_health("after_shutdown").is_err());
  bindings
    .shutdown_auxiliary_timer()
    .expect("rate timer shutdown after faulted service join");

  drop(metrics);
  drop(tenant);
  drop(bindings);
  drop(domain);
  let released = readback_domain.snapshot();
  assert_eq!(released.live_tenants, 0);
  assert_eq!(released.used.get(DomainResource::Control), baseline);
}

#[test]
fn tokio_pressure_binding_meters_only_real_download_and_upload_operations() {
  let domain = external_domain(Workload::Http, 2);
  let readback_domain = domain.readback_domain();
  let baseline = domain.fixed_global_control_baseline();
  let mut bindings = domain.for_tokio().expect("pressure bindings");
  assert!(bindings.feedback_started());

  let metrics = bindings
    .feedback
    .metrics
    .as_ref()
    .expect("feedback metrics")
    .snapshot();
  assert_eq!(
    metrics
      .control(FeedbackResource::CpuConcurrency)
      .current_limit,
    2
  );
  assert_eq!(
    metrics.control(FeedbackResource::DiskRate).current_limit,
    APPLICATION_RATE_CEILING_BYTES_PER_SECOND
  );
  assert_eq!(
    metrics.control(FeedbackResource::NetworkRate).current_limit,
    APPLICATION_RATE_CEILING_BYTES_PER_SECOND
  );
  let policy_rows = bindings.policy_rows();
  assert!(policy_rows.iter().any(|(key, value)| {
    key == "feedback.network_source" && value == "IoBindings_download_application_bytes_only"
  }));
  assert!(
    policy_rows
      .iter()
      .any(|(key, value)| key == "feedback.upload_controlled" && value == "false")
  );
  assert!(policy_rows.iter().any(|(key, value)| {
    key == "feedback.policy.download.floor" && value == &FEEDBACK_RATE_FLOOR.to_string()
  }));
  assert!(policy_rows.iter().any(|(key, value)| {
    key == "feedback.policy.version" && value == "runtime-feedback-policy-v1"
  }));
  assert!(policy_rows.iter().any(|(key, value)| {
    key == "feedback.cpu_reduction_rule" && value == "floor_current_limit_over_10_zero_is_quantized"
  }));
  assert!(
    policy_rows
      .iter()
      .any(|(key, value)| { key == "feedback.calibration.download.status" && value == "missing" })
  );
  assert!(policy_rows.iter().any(|(key, value)| {
    key == "feedback.pressure_claim"
      && value == "application_byte_throughput_only_external_contention_unmeasured"
  }));
  assert!(policy_rows.iter().any(|(key, value)| {
    key == "feedback.pressure_qualification_requested" && value == "false"
  }));
  assert!(
    !policy_rows
      .iter()
      .any(|(key, _)| key == "feedback.pressure_qualification")
  );

  let io = bindings.io();
  let meters = io.meters.as_ref().expect("shared directional meters");
  let mut stream = io.rate_io(TinyIo).expect("metered download/upload stream");
  assert_eq!(meters.download.snapshot().attached_sources, 1);
  assert_eq!(meters.upload.snapshot().attached_sources, 1);
  let waker = Waker::noop();
  let mut cx = context(waker);
  let mut received = [0; 4];
  assert!(matches!(
    Pin::new(&mut stream).poll_read(&mut cx, &mut received),
    Poll::Ready(Ok(4))
  ));
  assert!(matches!(
    Pin::new(&mut stream).poll_write(&mut cx, b"data"),
    Poll::Ready(Ok(4))
  ));
  assert_eq!(meters.download.snapshot().committed_bytes, 4);
  assert_eq!(meters.upload.snapshot().committed_bytes, 4);
  drop(stream);
  assert_eq!(meters.download.snapshot().attached_sources, 0);
  assert_eq!(meters.upload.snapshot().attached_sources, 0);
  assert_eq!(meters.upload.snapshot().committed_bytes, 4);

  bindings
    .shutdown_feedback(Duration::from_secs(5))
    .expect("feedback worker must join");
  let after_shutdown_rows = bindings
    .runtime_rows("after_shutdown")
    .expect("shutdown feedback readback")
    .into_iter()
    .collect::<std::collections::HashMap<_, _>>();
  assert_eq!(
    after_shutdown_rows["after_shutdown.feedback.shutdown_complete"],
    "true"
  );
  assert_eq!(
    after_shutdown_rows["after_shutdown.feedback.disk_rate.telemetry"],
    "missing"
  );
  assert_eq!(
    after_shutdown_rows["after_shutdown.feedback.disk_rate.no_change"],
    "telemetry_unavailable"
  );
  assert!(after_shutdown_rows.contains_key("after_shutdown.feedback.last_sample_age_ns"));
  assert!(after_shutdown_rows.contains_key("after_shutdown.feedback.cpu.pending_generation"));
  assert!(bindings.validate_feedback_health("after_shutdown").is_ok());
  bindings
    .shutdown_auxiliary_timer()
    .expect("rate timer shutdown");
  drop(io);
  drop(bindings);
  drop(domain);
  let released = readback_domain.snapshot();
  assert_eq!(released.live_tenants, 0);
  assert_eq!(released.used.get(DomainResource::Control), baseline);
}

#[test]
fn tokio_feedback_meters_follow_real_loopback_read_and_write_and_release_clones() {
  let domain = external_domain(Workload::Http, 2);
  let readback_domain = domain.readback_domain();
  let baseline = domain.fixed_global_control_baseline();
  let mut bindings = domain.for_tokio().expect("pressure bindings");
  let io = bindings.io();
  let meters = io.meters.as_ref().expect("shared directional meters");
  let retained_download_meter = meters.download.clone();
  let retained_upload_meter = meters.upload.clone();

  let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
  let address = listener.local_addr().expect("loopback address");
  let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
  let (finished_sender, finished_receiver) = std::sync::mpsc::sync_channel(1);
  let server = std::thread::spawn(move || {
    let (mut stream, _) = listener.accept().expect("accept loopback client");
    stream
      .set_read_timeout(Some(Duration::from_secs(5)))
      .expect("bound loopback server read");
    stream
      .set_write_timeout(Some(Duration::from_secs(5)))
      .expect("bound loopback server write");
    stream.write_all(b"downld").expect("write download payload");
    ready_sender
      .send(())
      .expect("signal downloaded payload ready");
    let mut response = [0; 4];
    stream
      .read_exact(&mut response)
      .expect("read upload payload");
    assert_eq!(&response, b"up!!");
    finished_sender
      .send(())
      .expect("signal bounded loopback server completion");
  });
  let client = std::net::TcpStream::connect(address).expect("connect loopback client");
  client
    .set_nonblocking(true)
    .expect("set nonblocking loopback client");
  ready_receiver
    .recv_timeout(Duration::from_secs(5))
    .expect("server published download payload");
  let mut stream = io
    .rate_io(StdTcpIo(client))
    .expect("rate-limit actual loopback stream");
  let waker = Waker::noop();
  let mut cx = context(waker);
  let mut downloaded = [0; 6];
  let mut downloaded_len = 0;
  let deadline = Instant::now() + Duration::from_secs(5);
  while downloaded_len < downloaded.len() {
    match Pin::new(&mut stream).poll_read(&mut cx, &mut downloaded[downloaded_len..]) {
      Poll::Ready(Ok(0)) => panic!("loopback stream closed before the payload completed"),
      Poll::Ready(Ok(count)) => downloaded_len += count,
      Poll::Ready(Err(error)) => panic!("loopback download failed: {error}"),
      Poll::Pending => {
        assert!(
          Instant::now() < deadline,
          "loopback download made no bounded progress"
        );
        std::thread::yield_now();
      }
    }
  }
  assert_eq!(&downloaded, b"downld");
  assert_eq!(meters.download.snapshot().committed_bytes, 6);
  assert_eq!(meters.upload.snapshot().committed_bytes, 0);

  let mut uploaded_len = 0;
  while uploaded_len < b"up!!".len() {
    match Pin::new(&mut stream).poll_write(&mut cx, &b"up!!"[uploaded_len..]) {
      Poll::Ready(Ok(0)) => panic!("loopback upload made no progress"),
      Poll::Ready(Ok(count)) => uploaded_len += count,
      Poll::Ready(Err(error)) => panic!("loopback upload failed: {error}"),
      Poll::Pending => {
        assert!(
          Instant::now() < deadline,
          "loopback upload made no bounded progress"
        );
        std::thread::yield_now();
      }
    }
  }
  assert_eq!(meters.download.snapshot().committed_bytes, 6);
  assert_eq!(meters.upload.snapshot().committed_bytes, 4);
  drop(stream);
  assert_eq!(meters.download.snapshot().attached_sources, 0);
  assert_eq!(meters.upload.snapshot().attached_sources, 0);
  finished_receiver
    .recv_timeout(Duration::from_secs(5))
    .expect("loopback server completed within its socket timeout");
  server.join().expect("loopback server completion");

  bindings
    .shutdown_feedback(Duration::from_secs(5))
    .expect("feedback worker must join");
  bindings
    .shutdown_auxiliary_timer()
    .expect("rate timer shutdown");
  drop(io);
  drop(bindings);
  drop(domain);
  let retained = readback_domain.snapshot();
  assert_eq!(retained.live_tenants, 1);
  assert!(retained.used.get(DomainResource::Control) > baseline);
  drop(retained_download_meter);
  drop(retained_upload_meter);
  let released = readback_domain.snapshot();
  assert_eq!(released.live_tenants, 0);
  assert_eq!(released.used.get(DomainResource::Control), baseline);
}

#[test]
fn native_pressure_factory_uses_the_owning_driver_feedback_service() {
  let domain = external_domain(Workload::Disk, 2);
  let readback_domain = domain.readback_domain();
  let baseline = domain.fixed_global_control_baseline();
  let factory = domain
    .feedback_factory()
    .expect("feedback factory")
    .unwrap();
  let rates = domain.rate_configs();
  let mut driver = MultiThreadBuilder::new(AsyncConfig {
    workers: 2,
    max_outstanding: 8,
    max_scopes: 2,
  })
  .resources(domain.local_limits())
  .resource_domain(domain.tenant())
  .rate_timer_registrations(256)
  .disk_rate(rates.disk)
  .upload_rate(rates.upload)
  .download_rate(rates.download)
  .blocking(BlockingConfig {
    workers: 2,
    max_outstanding: 8,
    capacity: allocatbelt::runtime::Resources {
      disk: 8,
      ..allocatbelt::runtime::Resources::ZERO
    },
  })
  .filesystem()
  .feedback_sources(factory)
  .build()
  .expect("native feedback service startup");
  let bindings = domain
    .for_native(&driver)
    .expect("native pressure bindings");
  assert!(bindings.feedback_started());
  let disk_meter = bindings
    .io
    .meters
    .as_ref()
    .expect("native feedback meters")
    .disk
    .clone();
  let meter = disk_meter.snapshot();
  assert!(meter.diagnostics.is_clear());
  assert_eq!(meter.committed_bytes, 0);
  assert_eq!(meter.attached_sources, 1);
  assert!(
    bindings
      .policy_rows()
      .iter()
      .any(|(key, value)| { key == "feedback.network_direction" && value == "download_only" })
  );
  let calibration_rows = bindings
    .policy_rows()
    .into_iter()
    .collect::<std::collections::HashMap<_, _>>();
  assert_eq!(
    calibration_rows["feedback.calibration.disk.status"],
    "missing"
  );
  assert_eq!(
    calibration_rows["feedback.pressure_claim"],
    "application_byte_throughput_only_external_contention_unmeasured"
  );

  let path = std::env::temp_dir().join(format!(
    "allocatbelt-feedback-disk-{}-{}",
    std::process::id(),
    NEXT_DISK_FILE.fetch_add(1, Ordering::Relaxed),
  ));
  let standard = std::fs::OpenOptions::new()
    .create_new(true)
    .read(true)
    .write(true)
    .open(&path)
    .expect("create a real filesystem target");
  let mut buffer = driver
    .resources()
    .try_alloc_zeroed(4)
    .expect("managed disk payload");
  buffer
    .get_mut()
    .expect("exclusive disk payload")
    .copy_from_slice(b"data");
  let outcome = driver
    .filesystem()
    .expect("native filesystem")
    .write(OwnedFile::from_std(standard), buffer)
    .expect("native disk write admission")
    .join()
    .expect("native disk write join");
  assert_eq!(outcome.bytes, 4);
  assert!(outcome.error.is_none());
  assert_eq!(disk_meter.snapshot().committed_bytes, 4);
  drop(outcome);
  std::fs::remove_file(&path).expect("remove real filesystem target");

  let scope = driver.scope().expect("native scope");
  driver.block_on(scope.close()).expect("native scope close");
  driver
    .request_shutdown(allocatbelt::runtime::MultiShutdown {
      tasks: allocatbelt::runtime::asynchronous::AsyncShutdown::Drain,
      blocking: allocatbelt::runtime::ShutdownMode::Drain,
      processes: allocatbelt::runtime::process::ProcessShutdownMode::Wait,
    })
    .expect("native shutdown request");
  let deadline = Instant::now() + Duration::from_secs(5);
  loop {
    match driver
      .drive_shutdown_step()
      .expect("native shutdown progress")
    {
      allocatbelt::runtime::ShutdownProgress::Complete => break,
      allocatbelt::runtime::ShutdownProgress::Pending => {
        assert!(
          Instant::now() < deadline,
          "native service shutdown timed out"
        );
        std::thread::sleep(Duration::from_millis(1));
      }
    }
  }
  let mut bindings = bindings;
  bindings
    .shutdown_feedback(Duration::from_secs(5))
    .expect("native feedback owner was joined by driver");
  let rows = bindings
    .runtime_rows("after_shutdown")
    .expect("native shutdown feedback readback")
    .into_iter()
    .collect::<std::collections::HashMap<_, _>>();
  assert_eq!(rows["after_shutdown.feedback.shutdown_complete"], "true");
  assert_eq!(
    rows["after_shutdown.feedback.disk_rate.telemetry"],
    "missing"
  );
  assert_eq!(
    rows["after_shutdown.feedback.disk_rate.no_change"],
    "telemetry_unavailable"
  );
  drop(bindings);
  drop(driver);
  drop(domain);
  let released = readback_domain.snapshot();
  assert_eq!(released.live_tenants, 1);
  assert!(released.used.get(DomainResource::Control) > baseline);
  drop(disk_meter);
  let final_snapshot = readback_domain.snapshot();
  assert_eq!(final_snapshot.live_tenants, 0);
  assert_eq!(final_snapshot.used.get(DomainResource::Control), baseline);
}

#[test]
fn shared_actuator_changes_tenant_cpu_disk_and_download_but_not_upload() {
  let limits = DomainResources::ZERO
    .with(DomainResource::Cpu, 10)
    .with(DomainResource::Control, 4 * 1024 * 1024);
  let domain = ResourceDomain::new(limits, 1).expect("feedback test domain");
  let baseline = domain.snapshot().used.get(DomainResource::Control);
  let tenant = domain.tenant(limits).expect("feedback test tenant");
  let rate_config = fixed_rate_config();
  let disk = ByteRateLimit::new_in_tenant(rate_config, &tenant).expect("disk bucket");
  let upload = ByteRateLimit::new_in_tenant(rate_config, &tenant).expect("upload bucket");
  let download = ByteRateLimit::new_in_tenant(rate_config, &tenant).expect("download bucket");
  let service = ResourceFeedbackService::start_in_tenant(
    feedback_policy(10),
    OverloadedSensor,
    RuntimeFeedbackActuator::new(
      CpuFeedbackTarget::Tenant(tenant.clone()),
      disk.clone(),
      download.clone(),
    ),
    &tenant,
  )
  .expect("feedback service startup");
  let metrics = service.metrics_handle();
  let deadline = std::time::Instant::now() + Duration::from_secs(4);
  loop {
    let snapshot = metrics.snapshot();
    if snapshot
      .control(FeedbackResource::CpuConcurrency)
      .current_limit
      < 10
      && snapshot.control(FeedbackResource::DiskRate).current_limit
        < APPLICATION_RATE_CEILING_BYTES_PER_SECOND
      && snapshot
        .control(FeedbackResource::NetworkRate)
        .current_limit
        < APPLICATION_RATE_CEILING_BYTES_PER_SECOND
    {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "controls were not actuated: {snapshot:?}; tenant={:?}; disk={:?}; download={:?}",
      tenant.snapshot(),
      disk.snapshot(),
      download.snapshot()
    );
    std::thread::sleep(Duration::from_millis(10));
  }
  let tenant_snapshot = tenant.snapshot().expect("tenant actuator readback");
  assert_eq!(tenant_snapshot.limit.get(DomainResource::Cpu), 9);
  assert!(disk.snapshot().bytes_per_second < APPLICATION_RATE_CEILING_BYTES_PER_SECOND);
  assert!(download.snapshot().bytes_per_second < APPLICATION_RATE_CEILING_BYTES_PER_SECOND);
  assert_eq!(
    upload.snapshot().bytes_per_second,
    APPLICATION_RATE_CEILING_BYTES_PER_SECOND
  );
  assert!(
    tenant
      .try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 10))
      .is_err()
  );
  let metrics_snapshot = metrics.snapshot();
  assert_eq!(
    metrics_snapshot
      .control(FeedbackResource::CpuConcurrency)
      .current_limit,
    tenant_snapshot.limit.get(DomainResource::Cpu) as u64
  );
  assert_eq!(
    metrics_snapshot
      .control(FeedbackResource::DiskRate)
      .current_limit,
    disk.snapshot().bytes_per_second
  );
  assert_eq!(
    metrics_snapshot
      .control(FeedbackResource::NetworkRate)
      .current_limit,
    download.snapshot().bytes_per_second
  );

  let mut service = service;
  loop {
    match service.try_shutdown().expect("feedback join") {
      FeedbackShutdownProgress::Complete => break,
      FeedbackShutdownProgress::Pending => {
        assert!(
          std::time::Instant::now() < deadline,
          "feedback join timed out"
        );
        std::thread::sleep(Duration::from_millis(1));
      }
    }
  }
  drop(service);
  drop(metrics);
  drop(disk);
  drop(upload);
  drop(download);
  drop(tenant);
  let released = domain.snapshot();
  assert_eq!(released.live_tenants, 0);
  assert_eq!(released.used.get(DomainResource::Control), baseline);
}

#[test]
fn feedback_sources_keep_disk_and_download_freshness_independent() {
  let disk_meter = IoFeedbackMeter::new();
  let download_meter = IoFeedbackMeter::new();
  let upload_meter = IoFeedbackMeter::new();
  let capacity = NonZeroU64::new(1).expect("positive test calibration");
  let cpu = ProcessCpuSensor::new(NonZeroU32::new(2).expect("nonzero workers"))
    .expect("process CPU sensor");
  let mut sensor = RuntimeFeedbackSensor::new(
    cpu,
    Some(IoFeedbackSource::new(disk_meter.clone(), capacity)),
    Some(IoFeedbackSource::new(download_meter.clone(), capacity)),
    NonZeroU32::new(1).expect("one dense sample"),
  );
  let first = sensor.sample().expect("initial sensor sample");
  assert_eq!(first.disk_utilization_basis_points, None);
  assert_eq!(first.network_utilization_basis_points, None);

  let timer = TimerDriver::new_realtime(8).expect("rate timer");
  let rate = ByteRateLimit::new(fixed_rate_config()).expect("rate bucket");
  let mut disk_stream = RateLimitedIo::new(TinyIo, rate.clone(), rate.clone(), timer.handle())
    .expect("rate adapter")
    .with_feedback_meters(disk_meter.clone(), upload_meter.clone());
  let mut download_stream = RateLimitedIo::new(TinyIo, rate.clone(), rate, timer.handle())
    .expect("download rate adapter")
    .with_feedback_meters(download_meter.clone(), upload_meter.clone());
  let waker = Waker::noop();
  let mut cx = context(waker);
  let mut received = [0; 4];
  for stream in [&mut disk_stream, &mut download_stream] {
    assert!(matches!(
      Pin::new(stream).poll_read(&mut cx, &mut received),
      Poll::Ready(Ok(4))
    ));
  }
  let baseline = sensor.sample().expect("download baseline sample");
  assert_eq!(baseline.disk_utilization_basis_points, None);
  assert_eq!(baseline.network_utilization_basis_points, None);

  let mut fresh_download = None;
  for _ in 0..4 {
    std::thread::sleep(Duration::from_millis(110));
    assert!(matches!(
      Pin::new(&mut disk_stream).poll_read(&mut cx, &mut received),
      Poll::Ready(Ok(4))
    ));
    assert!(matches!(
      Pin::new(&mut download_stream).poll_read(&mut cx, &mut received),
      Poll::Ready(Ok(4))
    ));
    let sample = sensor.sample().expect("independent source sample");
    assert!(sample.disk_utilization_basis_points.is_some());
    if sample.network_utilization_basis_points.is_some() {
      fresh_download = sample.network_utilization_basis_points;
      break;
    }
  }
  assert!(
    fresh_download.is_some(),
    "download source never became dense"
  );
  drop(download_stream);
  assert_eq!(download_meter.snapshot().attached_sources, 0);
  assert_eq!(upload_meter.snapshot().attached_sources, 1);
  let mut stale_download = None;
  for _ in 0..6 {
    std::thread::sleep(Duration::from_millis(110));
    assert!(matches!(
      Pin::new(&mut disk_stream).poll_read(&mut cx, &mut received),
      Poll::Ready(Ok(4))
    ));
    let sample = sensor
      .sample()
      .expect("fresh disk and stale download sample");
    assert!(sample.disk_utilization_basis_points.is_some());
    stale_download = sample.network_utilization_basis_points;
  }
  assert_eq!(stale_download, None);
  assert!(disk_meter.snapshot().committed_bytes > 0);
  drop(disk_stream);
  assert_eq!(upload_meter.snapshot().attached_sources, 0);
  timer.shutdown().expect("timer shutdown");
}

#[test]
fn rate_change_changes_admission_for_the_next_stream_read() {
  let timer = TimerDriver::new_realtime(8).expect("rate timer");
  let rate = ByteRateLimit::new(ByteRateConfig {
    bytes_per_second: 4,
    burst_bytes: 4,
    max_reservations: 2,
  })
  .expect("small test rate bucket");
  let mut stream = RateLimitedIo::new(TinyIo, rate.clone(), rate.clone(), timer.handle())
    .expect("rate-limited test stream");
  let waker = Waker::noop();
  let mut cx = context(waker);
  let mut received = [0; 4];
  assert!(matches!(
    Pin::new(&mut stream).poll_read(&mut cx, &mut received),
    Poll::Ready(Ok(4))
  ));
  assert!(
    rate
      .compare_exchange_rate(4, 1)
      .expect("reduce the shared rate bucket")
  );
  std::thread::sleep(Duration::from_millis(350));
  assert!(matches!(
    Pin::new(&mut stream).poll_read(&mut cx, &mut received),
    Poll::Pending
  ));
  assert_eq!(rate.snapshot().bytes_per_second, 1);
  drop(stream);
  timer.shutdown().expect("rate timer shutdown");
}
