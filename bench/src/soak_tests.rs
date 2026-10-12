use std::fs;
use std::future::{Future, poll_fn};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use allocatbelt::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};
use allocatbelt::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};
use allocatbelt_app_ports::{disk, memory};

use super::{
  MAX_REFERENCE_BYTES, load_reference_ring, open_exclusive_private, parse_args, parse_ring_header,
  sha256_digest, sha256_hex, validate_ring_row, verify_reference_ring_unchanged,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

fn temp_path(label: &str) -> PathBuf {
  let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
  std::env::temp_dir().join(format!(
    "allocatbelt-soak-{label}-{}-{id}",
    std::process::id()
  ))
}

struct BlockDrop(Receiver<()>);

impl Drop for BlockDrop {
  fn drop(&mut self) {
    let _ = self.0.recv_timeout(Duration::from_secs(3));
  }
}

struct ReleaseOnDrop(SyncSender<()>);

impl Drop for ReleaseOnDrop {
  fn drop(&mut self) {
    let _ = self.0.send(());
  }
}

struct CountingWake(AtomicUsize);

impl Wake for CountingWake {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.fetch_add(1, Ordering::SeqCst);
  }
}

struct ConnectionGate {
  state: Mutex<ConnectionGateState>,
}

struct ConnectionGateState {
  released: bool,
  entered: bool,
  entered_tx: Option<SyncSender<()>>,
  waker: Option<Waker>,
}

impl ConnectionGate {
  fn new() -> (Arc<Self>, Receiver<()>) {
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    (
      Arc::new(Self {
        state: Mutex::new(ConnectionGateState {
          released: false,
          entered: false,
          entered_tx: Some(entered_tx),
          waker: None,
        }),
      }),
      entered_rx,
    )
  }

  async fn wait(&self) {
    poll_fn(|cx| {
      let mut replacement = Some(cx.waker().clone());
      let (released, entered_tx, old_waker) = {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let entered_tx = if state.entered {
          None
        } else {
          state.entered = true;
          state.entered_tx.take()
        };
        if state.released {
          (true, entered_tx, None)
        } else {
          let old_waker = replacement
            .take()
            .and_then(|waker| state.waker.replace(waker));
          (false, entered_tx, old_waker)
        }
      };
      drop(old_waker);
      drop(replacement);
      if let Some(entered_tx) = entered_tx {
        let _ = entered_tx.send(());
      }
      if released {
        Poll::Ready(())
      } else {
        Poll::Pending
      }
    })
    .await
  }

  fn release(&self) {
    let wake = {
      let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
      state.released = true;
      state.waker.take()
    };
    if let Some(waker) = wake {
      waker.wake();
    }
  }
}

struct NativeAcceptorFixture {
  _application_domain: crate::application::runtime_bindings::ApplicationDomain,
  driver: allocatbelt::runtime::driver::MultiThreadDriver,
  scope: Option<allocatbelt::runtime::asynchronous::OwnedTaskScope>,
  handle: allocatbelt::runtime::asynchronous::AsyncHandle,
  resources: allocatbelt::runtime::managed::ResourceScope,
  io: crate::application::runtime_bindings::ApplicationIoBindings,
  net: allocatbelt::runtime::net::NetHandle,
  fs_handle: allocatbelt::runtime::fs::FsHandle,
  timer: allocatbelt::runtime::time::TimerHandle,
  listener: Option<allocatbelt::runtime::net::TcpListener>,
  address: std::net::SocketAddrV4,
}

impl NativeAcceptorFixture {
  fn new() -> Self {
    use allocatbelt::runtime::asynchronous::AsyncConfig;
    use allocatbelt::runtime::driver::MultiThreadBuilder;
    use allocatbelt::runtime::reactor::ReactorConfig;
    use allocatbelt::runtime::{Config as BlockingConfig, Resources};

    let workers = 2;
    let application_domain = crate::application::runtime_bindings::ApplicationDomain::new(
      crate::application::Workload::Mixed,
      workers,
    )
    .expect("create acceptor test domain");
    let limits = application_domain.local_limits();
    let rates = application_domain.rate_config();
    let driver = MultiThreadBuilder::new(AsyncConfig {
      workers,
      max_outstanding: 32,
      max_scopes: 2,
    })
    .resources(limits)
    .resource_domain(application_domain.tenant())
    .timer(2)
    .rate_timer_registrations(64)
    .blocking(BlockingConfig {
      workers,
      max_outstanding: 32,
      capacity: Resources {
        disk: 8,
        ..Resources::ZERO
      },
    })
    .filesystem()
    .reactor(ReactorConfig {
      max_registrations: 24,
      max_waiters: 40,
    })
    .disk_rate(rates)
    .upload_rate(rates)
    .download_rate(rates)
    .build()
    .expect("start acceptor test runtime");
    let bindings = application_domain
      .for_native(&driver)
      .expect("bind acceptor test runtime");
    let resources = bindings.resources();
    let io = bindings.io();
    let scope = driver.scope().expect("create acceptor test scope");
    let handle = scope.handle();
    let blocking = driver.blocking().expect("blocking pool");
    let reactor = driver.reactor().expect("reactor");
    let timer = driver.timer().expect("timer");
    let fs_handle = driver.filesystem().expect("filesystem");
    let net =
      allocatbelt::runtime::net::NetHandle::new(blocking, resources.clone(), reactor.clone(), 1)
        .expect("create network handle");
    let (listener, address) = super::native_listener(&reactor).expect("bind test listener");
    Self {
      _application_domain: application_domain,
      driver,
      scope: Some(scope),
      handle,
      resources,
      io,
      net,
      fs_handle,
      timer,
      listener: Some(listener),
      address,
    }
  }

  fn spawn_acceptor(
    &mut self,
    events: Arc<super::EventQueue>,
    stop: Arc<super::StopSignal>,
  ) -> allocatbelt::runtime::asynchronous::AsyncJob<Result<(), &'static str>> {
    let listener = self.listener.take().expect("acceptor listener available");
    let handle = self.handle.clone();
    handle
      .spawn(super::accept_http(
        listener,
        handle.clone(),
        self.resources.clone(),
        self.io.clone(),
        self.timer.clone(),
        events,
        stop,
      ))
      .expect("admit production acceptor loop")
  }

  fn http_context(&self, admission: super::HttpAdmissionLease) -> super::OperationContext {
    super::OperationContext {
      net: self.net.clone(),
      fs_handle: self.fs_handle.clone(),
      resources: self.resources.clone(),
      io: self.io.clone(),
      address: self.address,
      http_admission: Some(admission),
    }
  }

  fn shutdown(&mut self) {
    super::shutdown_native(&mut self.driver, self.scope.take())
      .expect("shutdown acceptor test runtime");
  }
}

async fn handler_event_before_timeout(
  events: &super::EventQueue,
  timer: &allocatbelt::runtime::time::TimerHandle,
) -> Result<super::HandlerEvent, &'static str> {
  let timeout = timer
    .sleep(Duration::from_secs(3))
    .map_err(|_| "handler test timeout admission failed")?;
  let mut timeout = std::pin::pin!(timeout);
  poll_fn(|cx| {
    if let Poll::Ready(event) = events.poll_event(cx) {
      return Poll::Ready(Ok(event));
    }
    if timeout.as_mut().poll(cx).is_ready() {
      return Poll::Ready(Err("handler completion was not published before timeout"));
    }
    Poll::Pending
  })
  .await
}

fn http_test_outputs(label: &str) -> (PathBuf, super::OutputFiles) {
  let directory = temp_path(label);
  fs::create_dir(&directory).expect("create HTTP test output directory");
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
      .expect("set HTTP test output directory mode");
  }
  let identity = super::SoakIdentity {
    report: directory.join("receipt.json"),
    terminals: directory.join("terminals.tsv"),
    samples: directory.join("samples.tsv"),
    campaign_id: "acceptor-test".into(),
    host_id: "local-test".into(),
    run_id: label.into(),
    allocator: "allocatbelt".into(),
    executor: "bounded".into(),
    source_sha256: "a".repeat(64),
    binary_sha256: "b".repeat(64),
    resource_ceiling_sha256: "c".repeat(64),
    nonce: "d".repeat(32),
  };
  let ring = super::ReferenceRing {
    bytes: Vec::new(),
    expected: (0..8).map(canonical_expected).collect(),
    file_sha256: [0; 32],
    average_rate_per_second: 4,
  };
  let outputs = super::OutputFiles::create(&identity, &ring).expect("create HTTP test streams");
  (directory, outputs)
}

fn publish_test_http_pair(
  event: super::HandlerEvent,
  client_checksum: u64,
  outputs: &mut super::OutputFiles,
) -> super::SoakStats {
  let expected_checksum = canonical_expected(2);
  assert_eq!(client_checksum, expected_checksum);
  let mut slots: [Option<super::TerminalSlot>; super::WINDOW] = std::array::from_fn(|_| None);
  slots[0] = Some(super::TerminalSlot {
    global_id: 0,
    reference_work_id: 2,
    family: super::Family::Http,
    expected_checksum,
    job: None,
    client_checksum: Some(Ok(client_checksum)),
    handler_checksum: None,
    ready_checksum: None,
  });
  let mut stats = super::SoakStats {
    attempted: 1,
    ..super::SoakStats::default()
  };
  let mut next_terminal_id = 0;
  super::finish_handler_event(
    event,
    &mut slots,
    outputs,
    &mut stats,
    &mut next_terminal_id,
  )
  .expect("publish paired HTTP terminal");
  assert_eq!(stats.completed, 1);
  assert_eq!(stats.errors, 0);
  assert_eq!(next_terminal_id, 1);
  stats
}

fn ring_text(profile: &str, rows: usize, rate: u64) -> String {
  let source = "a".repeat(64);
  let binary = "b".repeat(64);
  let pulse = if profile == "burst" { rate * 4 } else { rate };
  let trace_ns = if profile == "burst" {
    rows.div_ceil(rate as usize) as u64 * 1_000_000_000
  } else {
    (rows as u64) * 1_000_000_000 / rate
  };
  let mut text = format!(
    "schema\tallocatbelt-app-oracle-v2\nsource_sha256\t{source}\nbinary_sha256\t{binary}\nprofile\t{profile}\nworkload\tmixed\nmode\topen_loop\naverage_rate_per_second\t{rate}\npulse_rate_per_second\t{pulse}\narrivals\t{rows}\ntrace_duration_ns\t{trace_ns}\nkernel_config\tinterleave=cpu,memory,http,disk\nid\tscheduled_ns\tworkload\texpected_checksum\n"
  );
  for id in 0..rows {
    let scheduled = if profile == "burst" {
      (id as u64 / rate) * 1_000_000_000 + (id as u64 % rate) * 250_000_000 / rate
    } else {
      id as u64 * 1_000_000_000 / rate
    };
    let family = ["cpu", "memory", "http", "disk"][id % 4];
    text.push_str(&format!("{id}\t{scheduled}\t{family}\t{}\n", id + 100));
  }
  text
}

fn canonical_expected(reference_work_id: u64) -> u64 {
  let inputs = crate::application::canonical_soak_inputs(reference_work_id);
  match inputs.family {
    crate::application::Workload::Cpu => {
      allocatbelt_app_ports::cpu::kernel(inputs.cpu_seed, inputs.cpu_rounds)
    }
    crate::application::Workload::Memory => {
      (0..inputs.memory.grown_bytes).fold(0xcbf2_9ce4_8422_2325, |hash, index| {
        (hash ^ u64::from(memory::pattern_byte(inputs.memory.seed, index)))
          .wrapping_mul(0x0000_0100_0000_01b3)
      })
    }
    crate::application::Workload::Http => {
      (0..inputs.http_body_bytes).fold(0xcbf2_9ce4_8422_2325, |hash, index| {
        (hash ^ u64::from(memory::pattern_byte(inputs.http_seed, index)))
          .wrapping_mul(0x0000_0100_0000_01b3)
      })
    }
    crate::application::Workload::Disk => {
      (0..inputs.disk.bytes).fold(0xcbf2_9ce4_8422_2325, |hash, index| {
        (hash ^ u64::from(disk::payload_byte(inputs.disk.seed, index)))
          .wrapping_mul(0x0000_0100_0000_01b3)
      })
    }
    crate::application::Workload::Mixed => panic!("canonical ring input must be standalone"),
  }
}

fn canonical_ring_text(rows: usize) -> String {
  let source = "a".repeat(64);
  let binary = "b".repeat(64);
  let rate = 4;
  let trace_ns = (rows as u64) * 1_000_000_000 / rate;
  let mut text = format!(
    "schema\tallocatbelt-app-oracle-v2\nsource_sha256\t{source}\nbinary_sha256\t{binary}\nprofile\tmixed\nworkload\tmixed\nmode\topen_loop\naverage_rate_per_second\t{rate}\npulse_rate_per_second\t{rate}\narrivals\t{rows}\ntrace_duration_ns\t{trace_ns}\nkernel_config\tinterleave=cpu,memory,http,disk\nid\tscheduled_ns\tworkload\texpected_checksum\n"
  );
  for id in 0..rows {
    let scheduled = id as u64 * 1_000_000_000 / rate;
    let family = ["cpu", "memory", "http", "disk"][id % 4];
    text.push_str(&format!(
      "{id}\t{scheduled}\t{family}\t{}\n",
      canonical_expected(id as u64)
    ));
  }
  text
}

fn receipt_uint(receipt: &str, key: &str) -> u128 {
  let marker = format!("\"{key}\":");
  let start = receipt.find(&marker).expect("receipt field") + marker.len();
  let digits = receipt[start..]
    .chars()
    .take_while(char::is_ascii_digit)
    .collect::<String>();
  digits.parse().expect("receipt integer")
}

fn test_domain() -> (
  ResourceDomain,
  allocatbelt::runtime::resource_domain::TenantDomain,
) {
  let limits = DomainResources::ZERO.with(DomainResource::Control, MAX_REFERENCE_BYTES * 2);
  let domain = ResourceDomain::new(limits, 1).expect("test resource domain");
  let tenant = domain.tenant(limits).expect("test tenant");
  (domain, tenant)
}

#[test]
fn sha256_matches_known_vectors_and_incremental_updates() {
  assert_eq!(
    sha256_hex(b""),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  );
  assert_eq!(
    sha256_hex(b"abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  );
  let text = ring_text("mixed", 8, 4);
  let mut hash = super::Sha256::new();
  for chunk in text.as_bytes().chunks(7) {
    hash.update(chunk);
  }
  let digest = hash.finish();
  let mut hex = String::new();
  for byte in digest {
    use std::fmt::Write as _;
    write!(hex, "{byte:02x}").expect("write digest");
  }
  assert_eq!(hex, sha256_hex(text.as_bytes()));
}

#[test]
fn parses_only_canonical_external_ring_and_checks_each_schedule_and_family() {
  let source = "a".repeat(64);
  let binary = "b".repeat(64);
  let text = ring_text("mixed", 8, 4);
  let lines = text.lines().collect::<Vec<_>>();
  let header = parse_ring_header(&lines, "mixed", &source, &binary).expect("ring header");
  for (id, line) in lines[12..].iter().enumerate() {
    assert_eq!(
      validate_ring_row(line, id as u64, header).expect("canonical row"),
      id as u64 + 100
    );
  }
  let bad_schedule = "0\t1\tcpu\t100";
  assert!(validate_ring_row(bad_schedule, 0, header).is_err());
  let bad_family = "0\t0\tdisk\t100";
  assert!(validate_ring_row(bad_family, 0, header).is_err());
  let noncanonical_number = "0\t00\tcpu\t100";
  assert!(validate_ring_row(noncanonical_number, 0, header).is_err());
  assert!(parse_ring_header(&lines, "burst", &source, &binary).is_err());
  assert!(parse_ring_header(&lines, "mixed", &binary, &source).is_err());
}

#[test]
fn ring_storage_has_exact_control_lifetime_and_detects_file_mutation() {
  let path = temp_path("ring");
  let contents = ring_text("mixed", 8, 4);
  fs::write(&path, contents.as_bytes()).expect("write test reference ring");
  let (domain, tenant) = test_domain();
  let initial = domain.snapshot().used.get(DomainResource::Control);
  let file_sha = super::digest_hex(&sha256_digest(contents.as_bytes()));
  assert!(
    load_reference_ring(
      &path,
      &tenant,
      "mixed",
      &"a".repeat(64),
      &"b".repeat(64),
      &"0".repeat(64),
    )
    .is_err()
  );
  assert_eq!(domain.snapshot().used.get(DomainResource::Control), initial);
  let mut charged = load_reference_ring(
    &path,
    &tenant,
    "mixed",
    &"a".repeat(64),
    &"b".repeat(64),
    &file_sha,
  )
  .expect("load external ring");
  assert_eq!(charged.ring.expected.len(), 8);
  assert_eq!(charged.ring.file_sha256, sha256_digest(contents.as_bytes()));
  assert_eq!(charged.ring.average_rate_per_second, 4);
  assert_eq!(
    domain.snapshot().used.get(DomainResource::Control),
    initial + contents.len() + 8 * std::mem::size_of::<u64>()
  );
  verify_reference_ring_unchanged(&path, &mut charged.ring).expect("unchanged ring");
  let mut modified = contents.into_bytes();
  let last = modified.len() - 3;
  modified[last] ^= 1;
  fs::write(&path, modified).expect("mutate reference file");
  assert!(verify_reference_ring_unchanged(&path, &mut charged.ring).is_err());
  drop(charged);
  assert_eq!(domain.snapshot().used.get(DomainResource::Control), initial);
  drop(tenant);
  drop(domain);
  fs::remove_file(path).expect("remove test reference ring");
}

#[test]
fn rejects_oversized_and_truncated_reference_files_before_runtime_creation() {
  let path = temp_path("bad-ring");
  let (domain, tenant) = test_domain();
  let initial = domain.snapshot().used.get(DomainResource::Control);
  let oversized = vec![b'x'; MAX_REFERENCE_BYTES + 1];
  fs::write(&path, oversized).expect("write oversized ring");
  assert!(
    load_reference_ring(
      &path,
      &tenant,
      "mixed",
      &"a".repeat(64),
      &"b".repeat(64),
      &"0".repeat(64),
    )
    .is_err()
  );
  let truncated = b"schema\tallocatbelt-app-oracle-v2\n";
  fs::write(&path, truncated).expect("write truncated ring");
  let truncated_sha = super::digest_hex(&sha256_digest(truncated));
  assert!(
    load_reference_ring(
      &path,
      &tenant,
      "mixed",
      &"a".repeat(64),
      &"b".repeat(64),
      &truncated_sha,
    )
    .is_err()
  );
  assert_eq!(domain.snapshot().used.get(DomainResource::Control), initial);
  drop(tenant);
  drop(domain);
  fs::remove_file(path).expect("remove bad ring");
}

#[test]
fn cli_accepts_short_functional_horizon_but_keeps_reference_and_identity_pins_required() {
  let parsed = parse_args([
    "--duration-seconds".into(),
    "1".into(),
    "--sample-interval-ms".into(),
    "100".into(),
    "--reference-ring".into(),
    "/private/ring.tsv".into(),
    "--reference-ring-sha256".into(),
    "e".repeat(64),
    "--output".into(),
    "/private/output".into(),
    "--profile".into(),
    "mixed".into(),
    "--executor".into(),
    "bounded".into(),
    "--workload".into(),
    "mixed".into(),
    "--resource-ceiling-sha256".into(),
    "c".repeat(64),
  ])
  .expect("short test horizon");
  assert_eq!(parsed.duration, std::time::Duration::from_secs(1));
  assert!(super::validate_fixed_policy_request(None).is_ok());
  assert!(super::validate_fixed_policy_request(Some("fixed_policy")).is_ok());
  let pressure_error = super::validate_fixed_policy_request(Some("external_pressure"))
    .expect_err("pressure comparison is outside the fixed-policy soak contract");
  assert!(pressure_error.contains("unsupported"));
  assert!(
    parse_args([
      "--duration-seconds".into(),
      "1".into(),
      "--sample-interval-ms".into(),
      "100".into(),
      "--reference-ring".into(),
      "/private/ring.tsv".into(),
      "--profile".into(),
      "mixed".into(),
      "--resource-ceiling-sha256".into(),
      "c".repeat(64),
    ])
    .is_err()
  );
}

#[test]
fn output_files_are_exclusive_and_private() {
  let path = temp_path("private-output");
  let file = open_exclusive_private(&path).expect("create output");
  drop(file);
  assert!(open_exclusive_private(&path).is_err());
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
      fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
      0o600
    );
  }
  fs::remove_file(path).expect("remove output");
}

#[test]
fn failed_soak_preserves_streams_and_keeps_an_incomplete_marker() {
  let directory = temp_path("partial");
  fs::create_dir(&directory).expect("create partial output directory");
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
      .expect("set partial output directory mode");
  }
  let identity = super::SoakIdentity {
    report: directory.join("receipt.json"),
    terminals: directory.join("terminals.tsv"),
    samples: directory.join("samples.tsv"),
    campaign_id: "partial".into(),
    host_id: "host".into(),
    run_id: "run".into(),
    allocator: "allocatbelt".into(),
    executor: "bounded".into(),
    source_sha256: "a".repeat(64),
    binary_sha256: "b".repeat(64),
    resource_ceiling_sha256: "c".repeat(64),
    nonce: "d".repeat(32),
  };
  let ring = super::ReferenceRing {
    bytes: Vec::new(),
    expected: vec![0; 8],
    file_sha256: [0; 32],
    average_rate_per_second: 4,
  };
  drop(super::OutputFiles::create(&identity, &ring).expect("create partial streams"));
  let report = fs::read_to_string(directory.join("receipt.json")).expect("read failure marker");
  assert!(report.contains("allocatbelt.runtime-soak-incomplete.v1"));
  assert!(directory.join("terminals.tsv").is_file());
  assert!(directory.join("samples.tsv").is_file());
  assert!(!directory.join("receipt.incomplete.tmp").exists());
  fs::remove_dir_all(directory).expect("remove partial artifacts");
}

#[test]
fn burst_admission_uses_one_quarter_active_and_three_quarters_idle() {
  assert!(super::burst_admission_open("burst", Duration::ZERO));
  assert!(super::burst_admission_open(
    "burst",
    Duration::from_nanos(249_999_999)
  ));
  assert!(!super::burst_admission_open(
    "burst",
    Duration::from_millis(250)
  ));
  assert!(!super::burst_admission_open(
    "burst",
    Duration::from_millis(999)
  ));
  assert!(super::burst_admission_open("burst", Duration::from_secs(1)));
  assert!(super::burst_admission_open(
    "mixed",
    Duration::from_millis(500)
  ));
}

#[test]
fn sparse_or_repeated_historical_samples_fail_the_monotonic_cadence_check() {
  let started = 50_000_000_000u128;
  let interval = Duration::from_millis(100);
  let expected_first = started + 100_000_000;
  assert!(super::sample_cadence_matches(
    1,
    interval,
    started,
    expected_first
  ));
  assert!(super::sample_cadence_matches(
    1,
    interval,
    started,
    expected_first + 10_000_000
  ));
  assert!(!super::sample_cadence_matches(
    1,
    interval,
    started,
    expected_first + 10_000_001
  ));
  assert!(!super::sample_cadence_matches(
    2,
    interval,
    started,
    expected_first
  ));
}

#[test]
fn rss_growth_gate_enforces_the_five_percent_boundary_and_requires_both_windows() {
  assert!(super::rss_growth_within_percent(Some(100), Some(105), 5));
  assert!(!super::rss_growth_within_percent(Some(100), Some(106), 5));
  assert!(!super::rss_growth_within_percent(Some(0), Some(0), 5));
  assert!(!super::rss_growth_within_percent(Some(100), None, 5));
  assert!(!super::rss_growth_within_percent(None, Some(100), 5));
}

#[test]
fn rss_windows_have_exact_bounded_sample_counts_and_endpoint_rules() {
  use super::RssWindow::{FinalHour, FirstPostWarmupHour};

  assert_eq!(super::rss_window(299_900_000_000), None);
  assert_eq!(
    super::rss_window(300_000_000_000),
    Some(FirstPostWarmupHour)
  );
  assert_eq!(
    super::rss_window(3_899_900_000_000),
    Some(FirstPostWarmupHour)
  );
  assert_eq!(super::rss_window(3_900_000_000_000), None);
  assert_eq!(super::rss_window(7_199_900_000_000), None);
  assert_eq!(super::rss_window(7_200_000_000_000), Some(FinalHour));
  assert_eq!(super::rss_window(10_800_000_000_000), Some(FinalHour));
  assert_eq!(super::rss_window(10_800_100_000_000), None);

  let mut first_count = 0;
  let mut final_count = 0;
  for sample_index in 0..=108_000u128 {
    let elapsed_ns = sample_index * 100_000_000;
    match super::rss_window(elapsed_ns) {
      Some(FirstPostWarmupHour) => first_count += 1,
      Some(FinalHour) => final_count += 1,
      None => {}
    }
  }
  assert_eq!(first_count, 36_000);
  assert_eq!(final_count, 36_001);
  assert_eq!(first_count + final_count, 72_001);
}

#[test]
fn horizon_gate_uses_exact_trace_and_drain_phases_and_enforces_rss_growth() {
  let started = 12_000_000_000u128;
  let trace_duration = 10_800_000_000_000u128;
  let trace_end = started + trace_duration;
  let mut stats = super::SoakStats {
    attempted: 8,
    completed: 8,
    sample_count: 108_001,
    started_monotonic_ns: started,
    trace_ended_monotonic_ns: trace_end,
    drain_ended_monotonic_ns: trace_end + 5_000_000_000,
    // Teardown and receipt work are deliberately much longer than the trace;
    // they must not extend or shorten the measured horizon.
    shutdown_ended_monotonic_ns: trace_end + 90_000_000_000,
    postprocess_ended_monotonic_ns: trace_end + 120_000_000_000,
    ..super::SoakStats::default()
  };
  let qualifies = |stats: &super::SoakStats, first_median, final_median| {
    super::qualifies_horizon(
      Duration::from_secs(10_800),
      Duration::from_millis(100),
      stats,
      36_000,
      36_001,
      first_median,
      final_median,
    )
  };

  assert!(qualifies(&stats, Some(100), Some(105)));
  assert!(!qualifies(&stats, Some(100), Some(106)));

  stats.trace_ended_monotonic_ns = started + trace_duration - 1;
  stats.shutdown_ended_monotonic_ns += 600_000_000_000;
  stats.postprocess_ended_monotonic_ns += 900_000_000_000;
  assert!(!qualifies(&stats, Some(100), Some(100)));

  stats.trace_ended_monotonic_ns = started + trace_duration + 5_000_000_001;
  stats.drain_ended_monotonic_ns = stats.trace_ended_monotonic_ns + 1;
  assert!(!qualifies(&stats, Some(100), Some(100)));

  stats.trace_ended_monotonic_ns = started + trace_duration;
  stats.drain_ended_monotonic_ns = stats.trace_ended_monotonic_ns + 5_000_000_001;
  assert!(!qualifies(&stats, Some(100), Some(100)));

  stats.drain_ended_monotonic_ns = stats.trace_ended_monotonic_ns + 1;
  stats.sample_count -= 1;
  assert!(!qualifies(&stats, Some(100), Some(100)));
}

#[test]
fn production_cpu_interval_waits_for_final_sample_and_both_join_sets() {
  assert!(!super::drain_is_complete(false, true, true, true));
  assert!(!super::drain_is_complete(true, false, true, true));
  assert!(!super::drain_is_complete(true, true, false, true));
  assert!(!super::drain_is_complete(true, true, true, false));
  assert!(super::drain_is_complete(true, true, true, true));
}

#[test]
fn handler_completion_is_not_published_until_its_actual_future_drop_finishes() {
  let runtime = AsyncRuntime::new(AsyncConfig {
    workers: 1,
    max_outstanding: 4,
    max_scopes: 1,
  })
  .expect("start handler publication runtime");
  let handle = runtime.handle();
  let events = super::EventQueue::new();
  let (started_tx, started_rx) = mpsc::sync_channel(1);
  let (release_tx, release_rx) = mpsc::sync_channel(1);
  let _release_on_unwind = ReleaseOnDrop(release_tx.clone());
  let job = handle
    .spawn(async move {
      let _blocked_drop = BlockDrop(release_rx);
      started_tx.send(()).expect("signal handler start");
      Ok(super::HandlerEvent {
        reference_work_id: 2,
        checksum: 7,
        failure: None,
      })
    })
    .expect("admit handler task");
  started_rx
    .recv_timeout(Duration::from_secs(2))
    .expect("handler reached its destructor");

  let mut publication = Box::pin(super::publish_joined_handler(job, &events));
  let mut context = Context::from_waker(Waker::noop());
  assert!(publication.as_mut().poll(&mut context).is_pending());
  assert!(events.poll_event(&mut context).is_pending());

  release_tx.send(()).expect("release blocking destructor");
  let deadline = Instant::now() + Duration::from_secs(2);
  loop {
    match publication.as_mut().poll(&mut context) {
      Poll::Ready(result) => {
        assert_eq!(result, Ok(()));
        break;
      }
      Poll::Pending if Instant::now() < deadline => std::thread::yield_now(),
      Poll::Pending => panic!("handler completion publication did not wake after drop"),
    }
  }
  let event = match events.poll_event(&mut context) {
    Poll::Ready(event) => event,
    Poll::Pending => panic!("joined handler event was not published"),
  };
  assert_eq!(event.reference_work_id, 2);
  assert_eq!(event.checksum, 7);
  drop(publication);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .expect("join handler test runtime");
}

#[test]
fn production_acceptor_reaps_one_http_exchange_without_a_second_connection() {
  let mut fixture = NativeAcceptorFixture::new();
  let events = Arc::new(super::EventQueue::new());
  let stop = Arc::new(super::StopSignal::new());
  let acceptor = fixture.spawn_acceptor(Arc::clone(&events), Arc::clone(&stop));
  let inputs = crate::application::canonical_soak_inputs(2);
  let client = fixture
    .handle
    .spawn(super::operation_future(
      super::Family::Http,
      inputs,
      2,
      fixture.http_context(stop.admit_http().expect("admit HTTP client")),
    ))
    .expect("admit one loopback HTTP client");
  let (client_checksum, event) = fixture
    .handle
    .block_on(async {
      let checksum = client.await.map_err(|_| "HTTP client join failed")??;
      let event = handler_event_before_timeout(&events, &fixture.timer).await?;
      Ok::<_, &'static str>((checksum, event))
    })
    .expect("poll paired HTTP completion")
    .expect("HTTP client and handler completed");
  assert_eq!(event.reference_work_id, 2);
  assert_eq!(event.failure, None);
  assert_eq!(event.checksum, client_checksum);

  let (directory, mut outputs) = http_test_outputs("acceptor-single");
  let stats = publish_test_http_pair(event, client_checksum, &mut outputs);
  assert_eq!(stats.completed, 1);
  assert!(
    !acceptor.is_finished(),
    "the acceptor should remain open while workload admission remains open"
  );
  stop.close_http_admission();
  fixture
    .handle
    .block_on(acceptor)
    .expect("join production acceptor")
    .expect("acceptor should drain normally")
    .expect("acceptor body should succeed");
  outputs.seal_streams().expect("seal paired terminal stream");
  drop(outputs);
  let terminals =
    fs::read_to_string(directory.join("terminals.tsv")).expect("read production-loop terminal");
  let terminal = terminals.lines().nth(4).expect("one HTTP terminal row");
  assert!(terminal.starts_with("0\t2\thttp\tcompleted\t"));
  fixture.shutdown();
  fs::remove_dir_all(directory).expect("remove HTTP test artifacts");
}

#[test]
fn admitted_connection_crossing_horizon_is_accepted_and_drained() {
  let mut fixture = NativeAcceptorFixture::new();
  let events = Arc::new(super::EventQueue::new());
  let stop = Arc::new(super::StopSignal::new());
  let acceptor = fixture.spawn_acceptor(Arc::clone(&events), Arc::clone(&stop));
  let (gate, entered_rx) = ConnectionGate::new();
  let inputs = crate::application::canonical_soak_inputs(2);
  let operation = super::operation_future(
    super::Family::Http,
    inputs,
    2,
    fixture.http_context(stop.admit_http().expect("admit gated HTTP client")),
  );
  let gate_for_client = Arc::clone(&gate);
  let client = fixture
    .handle
    .spawn(async move {
      gate_for_client.wait().await;
      operation.await
    })
    .expect("admit gated loopback HTTP client");
  entered_rx
    .recv_timeout(Duration::from_secs(3))
    .expect("admitted client reached the pre-connect gate");

  // This is the horizon transition: no new application HTTP roles can be
  // admitted, but the outstanding role keeps acceptance alive.
  stop.close_http_admission();
  fixture
    .handle
    .block_on(async {
      fixture
        .timer
        .sleep(Duration::from_millis(50))
        .map_err(|_| "horizon gate timer admission failed")?
        .await
        .map_err(|_| "horizon gate timer closed")
    })
    .expect("poll closed-admission interval")
    .expect("wait at horizon");
  assert!(
    !acceptor.is_finished(),
    "acceptor stopped while an admitted connection was still gated"
  );

  gate.release();
  let (client_checksum, event) = fixture
    .handle
    .block_on(async {
      let checksum = client
        .await
        .map_err(|_| "gated HTTP client join failed")??;
      let event = handler_event_before_timeout(&events, &fixture.timer).await?;
      Ok::<_, &'static str>((checksum, event))
    })
    .expect("poll gated HTTP completion")
    .expect("gated HTTP pair should drain");
  assert_eq!(event.reference_work_id, 2);
  assert_eq!(event.failure, None);
  assert_eq!(event.checksum, client_checksum);

  let (directory, mut outputs) = http_test_outputs("acceptor-horizon");
  publish_test_http_pair(event, client_checksum, &mut outputs);
  fixture
    .handle
    .block_on(acceptor)
    .expect("join drained production acceptor")
    .expect("acceptor join should succeed")
    .expect("acceptor body should succeed");
  outputs
    .seal_streams()
    .expect("seal horizon terminal stream");
  drop(outputs);
  let terminals =
    fs::read_to_string(directory.join("terminals.tsv")).expect("read drained terminal stream");
  assert!(
    terminals
      .lines()
      .nth(4)
      .is_some_and(|line| { line.starts_with("0\t2\thttp\tcompleted\t") })
  );
  fixture.shutdown();
  fs::remove_dir_all(directory).expect("remove horizon test artifacts");
}

#[test]
fn emergency_stop_wakes_both_waiters_with_the_fixed_handler_window_full() {
  let mut fixture = NativeAcceptorFixture::new();
  let events = Arc::new(super::EventQueue::new());
  let stop = Arc::new(super::StopSignal::new());
  let acceptor = fixture.spawn_acceptor(Arc::clone(&events), Arc::clone(&stop));
  let mut leases: [Option<super::HttpAdmissionLease>; super::WINDOW] =
    std::array::from_fn(|_| Some(stop.admit_http().expect("admit bounded HTTP role")));
  let mut clients: [Option<std::net::TcpStream>; super::WINDOW] = std::array::from_fn(|_| None);
  for client in &mut clients {
    *client = Some(
      std::net::TcpStream::connect(std::net::SocketAddr::V4(fixture.address))
        .expect("open idle loopback client"),
    );
  }

  let deadline = Instant::now() + Duration::from_secs(3);
  loop {
    let accepted = fixture.resources.snapshot().network_ops;
    let alive_tasks = fixture.handle.metrics().snapshot().num_alive_tasks;
    let drain_waiter_registered = stop
      .http_admission
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .waker
      .is_some();
    if accepted == super::WINDOW && alive_tasks > super::WINDOW && drain_waiter_registered {
      break;
    }
    assert!(
      Instant::now() < deadline,
      "acceptor did not fill its handler window"
    );
    std::thread::sleep(Duration::from_millis(1));
  }
  assert_eq!(fixture.resources.snapshot().network_ops, super::WINDOW);

  let stop_counter = Arc::new(CountingWake(AtomicUsize::new(0)));
  let drain_counter = Arc::new(CountingWake(AtomicUsize::new(0)));
  let stop_probe = Waker::from(Arc::clone(&stop_counter));
  let drain_probe = Waker::from(Arc::clone(&drain_counter));
  let saved_stop_waker = {
    let mut slot = stop.waker.lock().unwrap_or_else(PoisonError::into_inner);
    slot.replace(stop_probe)
  };
  let saved_drain_waker = {
    let mut state = stop
      .http_admission
      .lock()
      .unwrap_or_else(PoisonError::into_inner);
    assert_eq!(state.active, super::WINDOW);
    state.waker.replace(drain_probe)
  }
  .expect("full acceptor registered its admission-drain waiter");
  stop.request();
  assert_eq!(stop_counter.0.load(Ordering::SeqCst), 1);
  assert_eq!(drain_counter.0.load(Ordering::SeqCst), 1);

  // The test probes both stored wake paths above, then wakes the original
  // runtime task so it can observe emergency stop and join the handlers.
  if let Some(waker) = saved_stop_waker {
    waker.wake();
  }
  saved_drain_waker.wake();
  drop(clients);
  fixture
    .handle
    .block_on(acceptor)
    .expect("join emergency-stopped acceptor")
    .expect("acceptor join should succeed")
    .expect("acceptor should join every full-window handler");
  for lease in &mut leases {
    lease.take();
  }
  assert_eq!(fixture.resources.snapshot().network_ops, 0);
  fixture.shutdown();
}

#[test]
fn short_native_soak_progresses_past_one_window_and_emits_reference_receipts() {
  let directory = temp_path("e2e");
  fs::create_dir(&directory).expect("create output directory");
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
      .expect("set output directory mode");
  }
  let reference_path = directory.join("reference.tsv");
  fs::write(&reference_path, canonical_ring_text(8).as_bytes())
    .expect("write independent serial reference");
  let identity = super::SoakIdentity {
    report: directory.join("soak-receipt.json"),
    terminals: directory.join("terminal-records.tsv"),
    samples: directory.join("resource-samples.tsv"),
    campaign_id: "test-campaign".into(),
    host_id: "local-test".into(),
    run_id: "window-progress-run".into(),
    allocator: "allocatbelt".into(),
    executor: "bounded".into(),
    source_sha256: "a".repeat(64),
    binary_sha256: "b".repeat(64),
    resource_ceiling_sha256: "c".repeat(64),
    nonce: "d".repeat(32),
  };
  let args = super::SoakArgs {
    duration: std::time::Duration::from_secs(2),
    sample_interval: std::time::Duration::from_millis(100),
    reference_path,
    reference_sha256: super::digest_hex(&sha256_digest(canonical_ring_text(8).as_bytes())),
    output_dir: Some(directory.clone()),
    profile: "mixed".into(),
    resource_ceiling_sha256: "c".repeat(64),
  };
  super::run_soak(args, identity).expect("run one-second native soak");

  let receipt = fs::read_to_string(directory.join("soak-receipt.json")).expect("read soak receipt");
  assert!(receipt.starts_with('{') && receipt.ends_with('}'));
  assert!(!receipt.contains("allocatbelt.runtime-soak-incomplete.v1"));
  assert!(receipt.contains("\"schema\":\"allocatbelt.runtime-soak.v1\""));
  assert!(receipt.contains("\"qualified_horizon\":false"));
  assert!(receipt.contains("\"errors\":0"));
  assert!(receipt.contains("\"lost\":0"));
  assert!(receipt.contains("\"final_global_live_tenants\":0"));
  let started = receipt_uint(&receipt, "started_monotonic_ns");
  let trace = receipt_uint(&receipt, "trace_ended_monotonic_ns");
  let drain = receipt_uint(&receipt, "drain_ended_monotonic_ns");
  let shutdown = receipt_uint(&receipt, "shutdown_ended_monotonic_ns");
  let postprocess = receipt_uint(&receipt, "postprocess_ended_monotonic_ns");
  assert!(started <= trace && trace <= drain && drain <= shutdown && shutdown <= postprocess);
  assert_eq!(postprocess, receipt_uint(&receipt, "ended_monotonic_ns"));
  assert!(receipt_uint(&receipt, "production_cpu_ended_ns") <= drain);
  assert!(receipt_uint(&receipt, "actual_trace_duration_ns") >= 2_000_000_000);
  assert!(receipt_uint(&receipt, "completed") > super::WINDOW as u128);

  let terminals =
    fs::read_to_string(directory.join("terminal-records.tsv")).expect("read terminal stream");
  let terminal_lines = terminals.lines().collect::<Vec<_>>();
  assert_eq!(
    terminal_lines[0],
    "schema\tallocatbelt.runtime-soak-terminals.v1"
  );
  assert!(terminal_lines[1].starts_with("reference_ring_sha256\t"));
  assert_eq!(terminal_lines[3], super::TERMINAL_HEADER);
  assert!(terminal_lines.len() > 4 + super::WINDOW);
  for (expected_global_id, row) in terminal_lines[4..].iter().enumerate() {
    let columns = row.split('\t').collect::<Vec<_>>();
    assert_eq!(columns.len(), 6);
    assert_eq!(columns[0], expected_global_id.to_string());
    assert_eq!(columns[1], (expected_global_id % 8).to_string());
    assert_eq!(columns[3], "completed");
    assert_eq!(columns[4], columns[5]);
  }

  let samples =
    fs::read_to_string(directory.join("resource-samples.tsv")).expect("read resource samples");
  let sample_lines = samples.lines().collect::<Vec<_>>();
  assert_eq!(sample_lines[0], super::SAMPLE_HEADER);
  assert!(sample_lines.len() >= 2);
  assert_eq!(
    sample_lines[1].split('\t').count(),
    super::SAMPLE_HEADER.split('\t').count()
  );
  fs::remove_dir_all(directory).expect("remove soak artifacts");
}
