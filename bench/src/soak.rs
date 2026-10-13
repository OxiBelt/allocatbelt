//! One-process continuous mixed-load soak with frozen external references.
//!
//! This module is deliberately separate from the short application lanes: it
//! owns one bounded workload window for the whole horizon and streams its
//! terminal and resource records as they complete.

use std::fs::{File, OpenOptions};
use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

#[cfg(feature = "resource-feedback")]
use crate::application::feedback_trace::{
  FeedbackTraceCollector, FeedbackTraceFinalizer, FeedbackTracePhase,
};
use crate::application::runtime_bindings::ApplicationMode;
use allocatbelt::runtime::asynchronous::{
  AsyncConfig, AsyncError, AsyncHandle, AsyncJob, AsyncJoinError, AsyncShutdown,
};
use allocatbelt::runtime::driver::MultiThreadDriver;
use allocatbelt::runtime::fs::FsHandle;
use allocatbelt::runtime::io::{AsyncRead, AsyncWrite};
use allocatbelt::runtime::managed::{OperationPermit, OperationRequest, ResourceScope};
use allocatbelt::runtime::net::{
  NetHandle, TcpListener as NativeListener, TcpStream as NativeStream,
};
use allocatbelt::runtime::process::ProcessShutdownMode;
use allocatbelt::runtime::reactor::ReactorConfig;
use allocatbelt::runtime::resource_domain::{
  DomainError, DomainReservation, DomainResource, DomainResources, DomainSnapshot, TenantDomain,
};
#[cfg(feature = "resource-feedback")]
use allocatbelt::runtime::resource_feedback::FeedbackWorkerFailure;
use allocatbelt::runtime::time::TimerHandle;
use allocatbelt::runtime::{
  Config as BlockingConfig, MultiShutdown, MultiThreadBuilder, Resources, ShutdownMode,
  ShutdownProgress,
};
use allocatbelt_app_ports::cpu;
use allocatbelt_app_ports::disk;
use allocatbelt_app_ports::http::{self, HttpConfig};
use allocatbelt_app_ports::memory;

const QUALIFIED_SECONDS: u64 = 10_800;
const WARMUP_SECONDS: u64 = 300;
const SAMPLE_INTERVAL_MS: u64 = 100;
const SAMPLE_LATE_TOLERANCE_NS: u128 = 10_000_000;
const WINDOW: usize = 8;
const MAX_REFERENCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REFERENCE_ROWS: usize = 65_536;
const MIN_REFERENCE_ROWS: usize = 8;
const MAX_ROOT_FUTURE_BYTES: usize = 64 * 1024;
const SAMPLE_SCRATCH_CONTROL_BYTES: usize = 16 * 1024;
#[cfg(feature = "resource-feedback")]
const MAX_EXTERNAL_RECEIPT_JSON_BYTES: usize = 16 * 1024;
const REFERENCE_HEADER: &str = "id\tscheduled_ns\tworkload\texpected_checksum";
const TERMINAL_HEADER: &str =
  "global_id\treference_work_id\tfamily\tstatus\tobserved_checksum\tring_expected_checksum";
const SAMPLE_HEADER: &str = "monotonic_ns\trss_kib\tglobal_cpu_ceiling\tglobal_cpu_limit\tglobal_cpu_used\tglobal_memory_ceiling\tglobal_memory_limit\tglobal_memory_used\tglobal_disk_ceiling\tglobal_disk_limit\tglobal_disk_used\tglobal_network_ceiling\tglobal_network_limit\tglobal_network_used\tglobal_tasks_ceiling\tglobal_tasks_limit\tglobal_tasks_used\tglobal_control_ceiling\tglobal_control_limit\tglobal_control_used\ttenant_cpu_ceiling\ttenant_cpu_limit\ttenant_cpu_used\ttenant_memory_ceiling\ttenant_memory_limit\ttenant_memory_used\ttenant_disk_ceiling\ttenant_disk_limit\ttenant_disk_used\ttenant_network_ceiling\ttenant_network_limit\ttenant_network_used\ttenant_tasks_ceiling\ttenant_tasks_limit\ttenant_tasks_used\ttenant_control_ceiling\ttenant_control_limit\ttenant_control_used\tscope_memory_limit\tscope_memory_used\tscope_disk_limit\tscope_disk_used\tscope_network_limit\tscope_network_used\tdisk_rate_limit_bps\tdisk_rate_burst_bytes\tdisk_rate_ceiling_bps\tdisk_rate_ceiling_burst_bytes\tdisk_rate_max_reservations\tdisk_rate_available_bytes\tdisk_rate_reserved_bytes\tdisk_rate_reservations\tupload_rate_limit_bps\tupload_rate_burst_bytes\tupload_rate_ceiling_bps\tupload_rate_ceiling_burst_bytes\tupload_rate_max_reservations\tupload_rate_available_bytes\tupload_rate_reserved_bytes\tupload_rate_reservations\tdownload_rate_limit_bps\tdownload_rate_burst_bytes\tdownload_rate_ceiling_bps\tdownload_rate_ceiling_burst_bytes\tdownload_rate_max_reservations\tdownload_rate_available_bytes\tdownload_rate_reserved_bytes\tdownload_rate_reservations";
const SOAK_KERNEL_CONFIG: &str = "interleave=cpu,memory,http,disk";

#[cfg(feature = "resource-feedback")]
struct FixedJsonBuffer<'a> {
  bytes: &'a mut [u8],
  length: usize,
}

#[cfg(feature = "resource-feedback")]
impl std::fmt::Write for FixedJsonBuffer<'_> {
  fn write_str(&mut self, value: &str) -> std::fmt::Result {
    let end = self
      .length
      .checked_add(value.len())
      .ok_or(std::fmt::Error)?;
    let Some(destination) = self.bytes.get_mut(self.length..end) else {
      return Err(std::fmt::Error);
    };
    destination.copy_from_slice(value.as_bytes());
    self.length = end;
    Ok(())
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SoakArgs {
  duration: Duration,
  sample_interval: Duration,
  reference_path: PathBuf,
  reference_sha256: String,
  output_dir: Option<PathBuf>,
  profile: String,
  resource_ceiling_sha256: String,
  comparison_mode: ApplicationMode,
}

#[derive(Debug)]
struct ReferenceRing {
  bytes: Vec<u8>,
  expected: Vec<u64>,
  file_sha256: [u8; 32],
  average_rate_per_second: u64,
}

#[derive(Debug)]
struct ChargedRing {
  ring: ReferenceRing,
  _byte_capacity: DomainReservation,
  _checksum_capacity: DomainReservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RingHeader<'a> {
  source_sha256: &'a str,
  binary_sha256: &'a str,
  profile: &'a str,
  average_rate_per_second: u64,
  pulse_rate_per_second: u64,
  arrivals: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SoakIdentity {
  report: PathBuf,
  terminals: PathBuf,
  samples: PathBuf,
  campaign_id: String,
  host_id: String,
  run_id: String,
  allocator: String,
  executor: String,
  source_sha256: String,
  binary_sha256: String,
  resource_ceiling_sha256: String,
  nonce: String,
}

#[derive(Clone, Copy, Debug)]
struct HandlerEvent {
  reference_work_id: u64,
  checksum: u64,
  failure: Option<&'static str>,
}

struct EventQueue {
  state: Mutex<EventQueueState>,
}

struct EventQueueState {
  slots: [Option<HandlerEvent>; WINDOW],
  read_index: usize,
  count: usize,
  waker: Option<Waker>,
}

struct StopSignal {
  requested: AtomicBool,
  waker: Mutex<Option<Waker>>,
  http_admission: Mutex<HttpAdmissionState>,
}

struct HttpAdmissionState {
  open: bool,
  active: usize,
  waker: Option<Waker>,
}

struct HttpAdmissionLease(Arc<StopSignal>);

#[derive(Debug)]
enum AcceptorProgress {
  Handler(Result<Result<HandlerEvent, &'static str>, AsyncJoinError>),
  Connection(Result<Option<(NativeStream, SocketAddr)>, &'static str>),
  Stop,
}

struct TerminalSlot {
  global_id: u64,
  reference_work_id: u64,
  family: Family,
  expected_checksum: u64,
  job: Option<AsyncJob<Result<u64, &'static str>>>,
  client_checksum: Option<Result<u64, &'static str>>,
  handler_checksum: Option<u64>,
  ready_checksum: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Family {
  Cpu,
  Memory,
  Http,
  Disk,
}

impl Family {
  const fn label(self) -> &'static str {
    match self {
      Self::Cpu => "cpu",
      Self::Memory => "memory",
      Self::Http => "http",
      Self::Disk => "disk",
    }
  }
}

struct OutputFiles {
  paths: [PathBuf; 3],
  report_temp_path: PathBuf,
  report: Option<File>,
  terminals: Option<File>,
  samples: Option<File>,
  incomplete_marker: &'static str,
  committed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FeedbackSoakStatus {
  started: bool,
  joined: bool,
  worker_failure: Option<&'static str>,
  trace_worker_joined: bool,
}

#[derive(Clone, Copy)]
enum SoakTracePhase {
  #[cfg(feature = "resource-feedback")]
  ProductionStart,
  ProductionEnd,
  DrainEnd,
  RssBefore,
  RssAfterDrain,
  ShutdownEnd,
  RssAfterShutdown,
}

#[cfg(feature = "resource-feedback")]
type SoakTraceFinalizer = FeedbackTraceFinalizer;
#[cfg(not(feature = "resource-feedback"))]
type SoakTraceFinalizer = ();

#[derive(Default)]
struct SoakFeedbackTrace {
  #[cfg(feature = "resource-feedback")]
  collector: Option<FeedbackTraceCollector>,
}

struct SoakSessionResult {
  stats: SoakStats,
  feedback_finalizer: Option<SoakTraceFinalizer>,
  feedback_status: Option<FeedbackSoakStatus>,
}

impl SoakFeedbackTrace {
  #[cfg(feature = "resource-feedback")]
  fn start_external(
    bindings: &crate::application::runtime_bindings::ApplicationRunBindings,
  ) -> Result<Self, String> {
    if !bindings.mode().feedback_enabled() {
      return Err("external soak feedback was selected but the runtime is fixed-policy".into());
    }
    if !bindings.feedback_started() {
      return Err("external soak feedback service did not start".into());
    }
    let collector = bindings
      .start_feedback_trace_for_mode("soak")?
      .ok_or_else(|| "external soak requires a feedback trace collector".to_owned())?;
    Ok(Self {
      collector: Some(collector),
    })
  }

  fn mark_phase(
    &self,
    phase: SoakTracePhase,
    at: Instant,
    rss: Option<crate::application::ProcessMemory>,
  ) -> Result<(), String> {
    #[cfg(feature = "resource-feedback")]
    if let Some(collector) = &self.collector {
      let phase = match phase {
        SoakTracePhase::ProductionStart => FeedbackTracePhase::ProductionStart,
        SoakTracePhase::ProductionEnd => FeedbackTracePhase::ProductionEnd,
        SoakTracePhase::DrainEnd => FeedbackTracePhase::DrainEnd,
        SoakTracePhase::RssBefore => FeedbackTracePhase::RssBefore,
        SoakTracePhase::RssAfterDrain => FeedbackTracePhase::RssAfterDrain,
        SoakTracePhase::ShutdownEnd => FeedbackTracePhase::ShutdownEnd,
        SoakTracePhase::RssAfterShutdown => FeedbackTracePhase::RssAfterShutdown,
      };
      return collector.mark_phase(phase, at, rss);
    }
    let _ = self;
    let _ = (phase, at, rss);
    Ok(())
  }

  #[cfg(feature = "resource-feedback")]
  fn mark_phase_with_bounds(
    &self,
    phase: SoakTracePhase,
    at: Instant,
    rss: Option<crate::application::ProcessMemory>,
  ) -> Result<Option<MonotonicBounds>, String> {
    if let Some(collector) = &self.collector {
      let trace_phase = feedback_trace_phase(phase);
      collector.mark_phase(trace_phase, at, rss)?;
      let (lower_ns, upper_ns) = collector.monotonic_bounds(at)?;
      return Ok(Some(MonotonicBounds { lower_ns, upper_ns }));
    }
    let _ = (self, phase, at, rss);
    Ok(None)
  }

  #[cfg(feature = "resource-feedback")]
  fn monotonic_bounds(&self, at: Instant) -> Result<Option<MonotonicBounds>, String> {
    if let Some(collector) = &self.collector {
      let (lower_ns, upper_ns) = collector.monotonic_bounds(at)?;
      return Ok(Some(MonotonicBounds { lower_ns, upper_ns }));
    }
    Ok(None)
  }

  #[cfg(feature = "resource-feedback")]
  fn has_collector(&self) -> bool {
    self.collector.is_some()
  }

  #[cfg(not(feature = "resource-feedback"))]
  fn has_collector(&self) -> bool {
    false
  }

  fn capture_endpoint(&self, phase: SoakTracePhase) -> Result<EndpointTimestamp, String> {
    #[cfg(feature = "resource-feedback")]
    if self.has_collector() {
      let at = Instant::now();
      let bounds = self
        .mark_phase_with_bounds(phase, at, None)?
        .ok_or_else(|| "external soak trace clock bounds are unavailable".to_owned())?;
      return Ok(EndpointTimestamp {
        scalar_ns: bounds.lower_ns,
        bounds: Some(bounds),
      });
    }

    // Preserve fixed-policy v1 timestamp ordering and source.
    let scalar_ns = monotonic_ns()?;
    self.mark_phase(phase, Instant::now(), None)?;
    Ok(EndpointTimestamp {
      scalar_ns,
      bounds: None,
    })
  }

  fn stop_for_finalization(&mut self) -> Result<Option<SoakTraceFinalizer>, String> {
    #[cfg(feature = "resource-feedback")]
    {
      self
        .collector
        .take()
        .map(FeedbackTraceCollector::stop_for_finalization)
        .transpose()
    }
    #[cfg(not(feature = "resource-feedback"))]
    {
      let _ = self;
      Ok(None)
    }
  }
}

#[cfg(feature = "resource-feedback")]
fn feedback_trace_phase(phase: SoakTracePhase) -> FeedbackTracePhase {
  match phase {
    SoakTracePhase::ProductionStart => FeedbackTracePhase::ProductionStart,
    SoakTracePhase::ProductionEnd => FeedbackTracePhase::ProductionEnd,
    SoakTracePhase::DrainEnd => FeedbackTracePhase::DrainEnd,
    SoakTracePhase::RssBefore => FeedbackTracePhase::RssBefore,
    SoakTracePhase::RssAfterDrain => FeedbackTracePhase::RssAfterDrain,
    SoakTracePhase::ShutdownEnd => FeedbackTracePhase::ShutdownEnd,
    SoakTracePhase::RssAfterShutdown => FeedbackTracePhase::RssAfterShutdown,
  }
}

fn mark_finalizer_phase(
  finalizer: Option<&SoakTraceFinalizer>,
  phase: SoakTracePhase,
  at: Instant,
  rss: Option<crate::application::ProcessMemory>,
) -> Result<(), String> {
  #[cfg(feature = "resource-feedback")]
  if let Some(finalizer) = finalizer {
    let phase = match phase {
      SoakTracePhase::ProductionStart => FeedbackTracePhase::ProductionStart,
      SoakTracePhase::ProductionEnd => FeedbackTracePhase::ProductionEnd,
      SoakTracePhase::DrainEnd => FeedbackTracePhase::DrainEnd,
      SoakTracePhase::RssBefore => FeedbackTracePhase::RssBefore,
      SoakTracePhase::RssAfterDrain => FeedbackTracePhase::RssAfterDrain,
      SoakTracePhase::ShutdownEnd => FeedbackTracePhase::ShutdownEnd,
      SoakTracePhase::RssAfterShutdown => FeedbackTracePhase::RssAfterShutdown,
    };
    return finalizer.mark_phase(phase, at, rss);
  }
  let _ = (finalizer, phase, at, rss);
  Ok(())
}

#[cfg(feature = "resource-feedback")]
fn finish_feedback_finalizer(
  finalizer: Option<SoakTraceFinalizer>,
  at: Option<Instant>,
) -> Result<Option<MonotonicBounds>, String> {
  let Some(finalizer) = finalizer else {
    return Ok(None);
  };
  let Some(at) = at else {
    finalizer.finish()?;
    return Ok(None);
  };
  let (lower_ns, upper_ns) = finalizer.finish_at(at)?;
  Ok(Some(MonotonicBounds { lower_ns, upper_ns }))
}

#[cfg(not(feature = "resource-feedback"))]
fn finish_feedback_finalizer(
  finalizer: Option<SoakTraceFinalizer>,
  _at: Option<Instant>,
) -> Result<Option<MonotonicBounds>, String> {
  let _ = finalizer;
  Ok(None)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MonotonicBounds {
  lower_ns: u128,
  upper_ns: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EndpointTimestamp {
  /// The external receipt represents each bracket by its lower endpoint.
  scalar_ns: u128,
  #[cfg_attr(not(feature = "resource-feedback"), allow(dead_code))]
  bounds: Option<MonotonicBounds>,
}

impl SoakStats {
  fn record_endpoint(&mut self, phase: SoakTracePhase, endpoint: EndpointTimestamp) {
    match phase {
      #[cfg(feature = "resource-feedback")]
      SoakTracePhase::ProductionStart => {
        self.started_monotonic_ns = endpoint.scalar_ns;
        self.started_monotonic_bounds = endpoint.bounds;
      }
      SoakTracePhase::ProductionEnd => {
        self.trace_ended_monotonic_ns = endpoint.scalar_ns;
        self.trace_ended_monotonic_bounds = endpoint.bounds;
      }
      SoakTracePhase::DrainEnd => {
        self.drain_ended_monotonic_ns = endpoint.scalar_ns;
        self.drain_ended_monotonic_bounds = endpoint.bounds;
      }
      SoakTracePhase::ShutdownEnd => {
        self.shutdown_ended_monotonic_ns = endpoint.scalar_ns;
        self.shutdown_ended_monotonic_bounds = endpoint.bounds;
      }
      SoakTracePhase::RssBefore
      | SoakTracePhase::RssAfterDrain
      | SoakTracePhase::RssAfterShutdown => {}
    }
  }
}

fn application_mode_from_value(value: Option<&str>) -> Result<ApplicationMode, String> {
  ApplicationMode::from_comparison_family(value)
}

fn application_mode_from_environment() -> Result<ApplicationMode, String> {
  match std::env::var("ALLOCATBELT_APP_COMPARISON_FAMILY") {
    Ok(value) => application_mode_from_value(Some(&value)),
    Err(std::env::VarError::NotPresent) => application_mode_from_value(None),
    Err(std::env::VarError::NotUnicode(_)) => {
      Err("ALLOCATBELT_APP_COMPARISON_FAMILY is not valid Unicode".into())
    }
  }
}

#[cfg(feature = "resource-feedback")]
fn feedback_failure_label(failure: FeedbackWorkerFailure) -> &'static str {
  match failure {
    FeedbackWorkerFailure::Panicked => "panicked",
    FeedbackWorkerFailure::ClockExhausted => "clock_exhausted",
    FeedbackWorkerFailure::PayloadCleanupPanicked => "payload_cleanup_panicked",
  }
}

#[derive(Default)]
struct SoakStats {
  attempted: u64,
  completed: u64,
  errors: u64,
  lost: u64,
  sample_count: u64,
  production_cpu_started_ns: u128,
  production_cpu_ended_ns: u128,
  started_monotonic_ns: u128,
  trace_ended_monotonic_ns: u128,
  drain_ended_monotonic_ns: u128,
  shutdown_ended_monotonic_ns: u128,
  postprocess_ended_monotonic_ns: u128,
  ended_monotonic_ns: u128,
  #[cfg_attr(not(feature = "resource-feedback"), allow(dead_code))]
  started_monotonic_bounds: Option<MonotonicBounds>,
  #[cfg_attr(not(feature = "resource-feedback"), allow(dead_code))]
  trace_ended_monotonic_bounds: Option<MonotonicBounds>,
  #[cfg_attr(not(feature = "resource-feedback"), allow(dead_code))]
  drain_ended_monotonic_bounds: Option<MonotonicBounds>,
  #[cfg_attr(not(feature = "resource-feedback"), allow(dead_code))]
  shutdown_ended_monotonic_bounds: Option<MonotonicBounds>,
  #[cfg_attr(not(feature = "resource-feedback"), allow(dead_code))]
  postprocess_ended_monotonic_bounds: Option<MonotonicBounds>,
  qualified_horizon: bool,
}

struct ReceiptData<'a> {
  identity: &'a SoakIdentity,
  args: &'a SoakArgs,
  ring_sha256: &'a [u8; 32],
  ring_rows: usize,
  ring_average_rate_per_second: u64,
  stats: &'a SoakStats,
  terminal_sha: &'a [u8; 32],
  sample_sha: &'a [u8; 32],
  first_hour_median_kib: Option<u64>,
  final_hour_median_kib: Option<u64>,
  global: DomainSnapshot,
  tenant: DomainSnapshot,
  baseline_control: usize,
  #[cfg(feature = "resource-feedback")]
  feedback: Option<FeedbackSoakStatus>,
}

struct OperationContext {
  net: NetHandle,
  fs_handle: FsHandle,
  resources: ResourceScope,
  io: crate::application::runtime_bindings::ApplicationIoBindings,
  address: SocketAddrV4,
  http_admission: Option<HttpAdmissionLease>,
}

struct SampleAccumulator<'a> {
  started_monotonic_ns: u128,
  interval: Duration,
  stats: &'a mut SoakStats,
  first_hour_rss: &'a mut Vec<u64>,
  final_hour_rss: &'a mut Vec<u64>,
}

/// Runs the dedicated native soak binary's validated command line.
pub fn run_cli() -> ExitCode {
  match run_from_process() {
    Ok(()) => ExitCode::SUCCESS,
    Err(error) => {
      eprintln!("runtime soak failed: {error}");
      ExitCode::FAILURE
    }
  }
}

fn run_from_process() -> Result<(), String> {
  let args = parse_args(std::env::args().skip(1))?;
  let identity = SoakIdentity::from_environment(&args)?;
  run_soak(args, identity)
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<SoakArgs, String> {
  let mut duration_seconds = None;
  let mut interval_ms = None;
  let mut reference_path = None;
  let mut reference_sha256 = None;
  let mut output_dir = None;
  let mut profile = None;
  let mut ceiling_sha = None;
  let mut args = args.into_iter();
  while let Some(key) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| format!("missing value for {key}"))?;
    match key.as_str() {
      "--duration-seconds" | "--seconds" => {
        duration_seconds = Some(parse_positive(&value, "duration seconds")?)
      }
      "--sample-interval-ms" => interval_ms = Some(parse_positive(&value, "sample interval")?),
      "--reference-ring" => reference_path = Some(PathBuf::from(value)),
      "--reference-ring-sha256" => reference_sha256 = Some(value),
      "--output" | "--output-dir" => output_dir = Some(PathBuf::from(value)),
      "--profile" => profile = Some(value),
      "--resource-ceiling-sha256" => ceiling_sha = Some(value),
      "--executor" => {
        if value != "bounded" {
          return Err("this binary runs only the owning allocatbelt executor".into());
        }
      }
      "--workload" => {
        if value != "mixed" {
          return Err("the continuous soak workload is fixed to mixed".into());
        }
      }
      _ => return Err(format!("unknown argument {key}")),
    }
  }
  let env_duration = optional_env_positive("ALLOCATBELT_SOAK_DURATION_SECONDS")?;
  if duration_seconds.is_some() && env_duration.is_some() && duration_seconds != env_duration {
    return Err("duration command and environment pins differ".into());
  }
  let duration_seconds = duration_seconds
    .or(env_duration)
    .unwrap_or(QUALIFIED_SECONDS);
  let env_interval = optional_env_positive("ALLOCATBELT_SOAK_SAMPLE_INTERVAL_MS")?;
  if interval_ms.is_some() && env_interval.is_some() && interval_ms != env_interval {
    return Err("sample interval command and environment pins differ".into());
  }
  let interval_ms = interval_ms.or(env_interval).unwrap_or(SAMPLE_INTERVAL_MS);
  let env_profile = std::env::var("ALLOCATBELT_SOAK_PROFILE").ok();
  if profile.is_some() && env_profile.is_some() && profile != env_profile {
    return Err("profile command and environment pins differ".into());
  }
  let profile = profile
    .or(env_profile)
    .ok_or_else(|| "--profile or ALLOCATBELT_SOAK_PROFILE is required".to_owned())?;
  if !matches!(profile.as_str(), "mixed" | "burst" | "oversubscribed") {
    return Err("--profile must be mixed, burst, or oversubscribed".into());
  }
  let ceiling = ceiling_sha
    .or_else(|| std::env::var("ALLOCATBELT_SOAK_RESOURCE_CEILING_SHA256").ok())
    .ok_or_else(|| "--resource-ceiling-sha256 is required".to_owned())?;
  validate_sha256(&ceiling, "resource ceiling")?;
  let comparison_mode = application_mode_from_environment()?;
  let duration = Duration::from_secs(duration_seconds);
  let sample_interval = Duration::from_millis(interval_ms);
  if interval_ms != SAMPLE_INTERVAL_MS {
    return Err("sample interval is frozen at 100 milliseconds".into());
  }
  if duration_seconds > QUALIFIED_SECONDS {
    return Err("duration exceeds the frozen three-hour horizon".into());
  }
  let env_reference = std::env::var_os("ALLOCATBELT_SOAK_REFERENCE_RING").map(PathBuf::from);
  if reference_path.is_some() && env_reference.is_some() && reference_path != env_reference {
    return Err("reference ring command and environment paths differ".into());
  }
  let reference_path = reference_path
    .or(env_reference)
    .ok_or_else(|| "--reference-ring is required".to_owned())?;
  let env_reference_sha = std::env::var("ALLOCATBELT_SOAK_REFERENCE_RING_SHA256").ok();
  if reference_sha256.is_some()
    && env_reference_sha.is_some()
    && reference_sha256 != env_reference_sha
  {
    return Err("reference ring SHA command and environment pins differ".into());
  }
  let reference_sha256 = reference_sha256
    .or(env_reference_sha)
    .ok_or_else(|| "--reference-ring-sha256 is required".to_owned())?;
  validate_sha256(&reference_sha256, "reference ring")?;
  Ok(SoakArgs {
    duration,
    sample_interval,
    reference_path,
    reference_sha256,
    output_dir,
    profile,
    resource_ceiling_sha256: ceiling,
    comparison_mode,
  })
}

impl SoakIdentity {
  fn from_environment(args: &SoakArgs) -> Result<Self, String> {
    let output_dir = args
      .output_dir
      .clone()
      .or_else(|| std::env::var_os("ALLOCATBELT_SOAK_OUTPUT_DIR").map(PathBuf::from));
    let report = env_path("ALLOCATBELT_SOAK_REPORT")
      .or_else(|| {
        output_dir
          .as_ref()
          .map(|path| path.join("soak-receipt.tsv"))
      })
      .ok_or_else(|| "--output or ALLOCATBELT_SOAK_REPORT is required".to_owned())?;
    let terminals = env_path("ALLOCATBELT_SOAK_TERMINALS")
      .or_else(|| {
        output_dir
          .as_ref()
          .map(|path| path.join("terminal-records.tsv"))
      })
      .ok_or_else(|| "--output or ALLOCATBELT_SOAK_TERMINALS is required".to_owned())?;
    let samples = env_path("ALLOCATBELT_SOAK_SAMPLES")
      .or_else(|| {
        output_dir
          .as_ref()
          .map(|path| path.join("resource-samples.tsv"))
      })
      .ok_or_else(|| "--output or ALLOCATBELT_SOAK_SAMPLES is required".to_owned())?;
    let source_sha256 = required_env("ALLOCATBELT_SOAK_SOURCE_SHA256")?;
    let binary_sha256 = required_env("ALLOCATBELT_SOAK_BINARY_SHA256")?;
    validate_sha256(&source_sha256, "source")?;
    validate_sha256(&binary_sha256, "binary")?;
    let resource_ceiling_sha256 = args.resource_ceiling_sha256.clone();
    let campaign_id = required_env("ALLOCATBELT_SOAK_CAMPAIGN_ID")?;
    let host_id = required_env("ALLOCATBELT_SOAK_HOST_ID")?;
    let run_id = required_env("ALLOCATBELT_SOAK_RUN_ID")?;
    let allocator = required_env("ALLOCATBELT_SOAK_ALLOCATOR")?;
    let executor =
      std::env::var("ALLOCATBELT_SOAK_EXECUTOR").unwrap_or_else(|_| "bounded".to_owned());
    let nonce = std::env::var("ALLOCATBELT_SOAK_NONCE")
      .or_else(|_| std::env::var("ALLOCATBELT_APP_REPORT_NONCE"))
      .map_err(|_| "ALLOCATBELT_SOAK_NONCE is required".to_owned())?;
    if allocator != "allocatbelt" || executor != "bounded" {
      return Err("dedicated soak identity must name allocatbelt/bounded".into());
    }
    validate_hex(&nonce, 32, "soak nonce")?;
    for (label, value) in [
      ("campaign ID", campaign_id.as_str()),
      ("host ID", host_id.as_str()),
      ("run ID", run_id.as_str()),
      ("nonce", nonce.as_str()),
    ] {
      if value.is_empty()
        || value.len() > 256
        || !value
          .bytes()
          .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
      {
        return Err(format!("{label} is empty, oversized, or not TSV-safe"));
      }
    }
    if let Ok(env_ceiling) = std::env::var("ALLOCATBELT_SOAK_RESOURCE_CEILING_SHA256")
      && env_ceiling != resource_ceiling_sha256
    {
      return Err("resource-ceiling command and environment pins differ".into());
    }
    Ok(Self {
      report,
      terminals,
      samples,
      campaign_id,
      host_id,
      run_id,
      allocator,
      executor,
      source_sha256,
      binary_sha256,
      resource_ceiling_sha256,
      nonce,
    })
  }
}

impl OutputFiles {
  fn create(
    identity: &SoakIdentity,
    ring: &ReferenceRing,
    comparison_mode: ApplicationMode,
  ) -> Result<Self, String> {
    let paths = [
      identity.report.clone(),
      identity.terminals.clone(),
      identity.samples.clone(),
    ];
    validate_output_paths(&paths)?;
    let mut report_temp_path = paths[0].clone();
    report_temp_path.set_extension("incomplete.tmp");
    if report_temp_path == paths[1] || report_temp_path == paths[2] {
      return Err("temporary receipt path aliases a stream output".into());
    }
    safe_basename(&report_temp_path)?;
    let mut output = Self {
      paths,
      report_temp_path,
      report: None,
      terminals: None,
      samples: None,
      incomplete_marker: if comparison_mode.feedback_enabled() {
        "allocatbelt.runtime-soak-incomplete.v2"
      } else {
        "allocatbelt.runtime-soak-incomplete.v1"
      },
      committed: false,
    };
    output.report = Some(
      open_exclusive_private(&output.paths[0])
        .map_err(|error| format!("exclusive soak receipt create failed: {error}"))?,
    );
    writeln!(
      output
        .report
        .as_mut()
        .ok_or("receipt stream was not opened")?,
      "{}",
      output.incomplete_marker,
    )
    .map_err(|error| format!("soak incomplete marker write failed: {error}"))?;
    output
      .report
      .as_mut()
      .ok_or("receipt stream was not opened")?
      .sync_all()
      .map_err(|error| format!("soak incomplete marker sync failed: {error}"))?;
    output.terminals = Some(
      open_exclusive_private(&output.paths[1])
        .map_err(|error| format!("exclusive soak terminal stream create failed: {error}"))?,
    );
    output.samples = Some(
      open_exclusive_private(&output.paths[2])
        .map_err(|error| format!("exclusive soak sample stream create failed: {error}"))?,
    );
    writeln!(
      output.terminals.as_mut().ok_or("terminal stream was not opened")?,
      "schema\tallocatbelt.runtime-soak-terminals.v1\nreference_ring_sha256\t{}\nreference_ring_rows\t{}\n{TERMINAL_HEADER}",
      digest_hex(&ring.file_sha256),
      ring.expected.len(),
    )
    .map_err(|error| format!("terminal stream header write failed: {error}"))?;
    writeln!(
      output
        .samples
        .as_mut()
        .ok_or("sample stream was not opened")?,
      "{SAMPLE_HEADER}"
    )
    .map_err(|error| format!("sample stream header write failed: {error}"))?;
    Ok(output)
  }

  fn terminal(
    &mut self,
    global_id: u64,
    reference_work_id: u64,
    family: Family,
    observed_checksum: u64,
    expected_checksum: u64,
  ) -> Result<(), String> {
    let file = self
      .terminals
      .as_mut()
      .ok_or_else(|| "terminal stream was already closed".to_owned())?;
    writeln!(
      file,
      "{global_id}\t{reference_work_id}\t{}\tcompleted\t{observed_checksum}\t{expected_checksum}",
      family.label()
    )
    .map_err(|error| format!("terminal stream write failed: {error}"))
  }

  fn sample(
    &mut self,
    monotonic_ns: u128,
    rss_kib: u64,
    global: DomainSnapshot,
    tenant: DomainSnapshot,
    scope: allocatbelt::runtime::managed::ResourceSnapshot,
    io_rows: &[(String, String)],
  ) -> Result<(), String> {
    let file = self
      .samples
      .as_mut()
      .ok_or_else(|| "sample stream was already closed".to_owned())?;
    write!(file, "{monotonic_ns}\t{rss_kib}")
      .map_err(|error| format!("sample stream write failed: {error}"))?;
    for (snapshot, dimensions) in [
      (
        global,
        [
          DomainResource::Cpu,
          DomainResource::Memory,
          DomainResource::Disk,
          DomainResource::Network,
          DomainResource::Tasks,
          DomainResource::Control,
        ],
      ),
      (
        tenant,
        [
          DomainResource::Cpu,
          DomainResource::Memory,
          DomainResource::Disk,
          DomainResource::Network,
          DomainResource::Tasks,
          DomainResource::Control,
        ],
      ),
    ] {
      for dimension in dimensions {
        write!(
          file,
          "\t{}\t{}\t{}",
          snapshot.ceiling.get(dimension),
          snapshot.limit.get(dimension),
          snapshot.used.get(dimension)
        )
        .map_err(|error| format!("sample stream write failed: {error}"))?;
      }
    }
    for value in [
      scope.limits.managed_memory,
      scope.managed_memory,
      scope.limits.disk_concurrent_ops,
      scope.disk_ops,
      scope.limits.network_concurrent_ops,
      scope.network_ops,
    ] {
      write!(file, "\t{value}").map_err(|error| format!("sample stream write failed: {error}"))?;
    }
    for (bucket, field) in [
      ("disk", "bytes_per_second"),
      ("disk", "burst_bytes"),
      ("disk", "ceiling_bytes_per_second"),
      ("disk", "ceiling_burst_bytes"),
      ("disk", "max_reservations"),
      ("disk", "available_bytes"),
      ("disk", "reserved_bytes"),
      ("disk", "reservations"),
      ("upload", "bytes_per_second"),
      ("upload", "burst_bytes"),
      ("upload", "ceiling_bytes_per_second"),
      ("upload", "ceiling_burst_bytes"),
      ("upload", "max_reservations"),
      ("upload", "available_bytes"),
      ("upload", "reserved_bytes"),
      ("upload", "reservations"),
      ("download", "bytes_per_second"),
      ("download", "burst_bytes"),
      ("download", "ceiling_bytes_per_second"),
      ("download", "ceiling_burst_bytes"),
      ("download", "max_reservations"),
      ("download", "available_bytes"),
      ("download", "reserved_bytes"),
      ("download", "reservations"),
    ] {
      let key = match (bucket, field) {
        ("disk", "bytes_per_second") => "disk_bytes_per_second",
        ("disk", "burst_bytes") => "disk_burst_bytes",
        ("disk", "ceiling_bytes_per_second") => "disk_ceiling_bytes_per_second",
        ("disk", "ceiling_burst_bytes") => "disk_ceiling_burst_bytes",
        ("disk", "max_reservations") => "disk_max_reservations",
        ("disk", "available_bytes") => "disk_available_bytes",
        ("disk", "reserved_bytes") => "disk_reserved_bytes",
        ("disk", "reservations") => "disk_reservations",
        ("upload", "bytes_per_second") => "upload_bytes_per_second",
        ("upload", "burst_bytes") => "upload_burst_bytes",
        ("upload", "ceiling_bytes_per_second") => "upload_ceiling_bytes_per_second",
        ("upload", "ceiling_burst_bytes") => "upload_ceiling_burst_bytes",
        ("upload", "max_reservations") => "upload_max_reservations",
        ("upload", "available_bytes") => "upload_available_bytes",
        ("upload", "reserved_bytes") => "upload_reserved_bytes",
        ("upload", "reservations") => "upload_reservations",
        ("download", "bytes_per_second") => "download_bytes_per_second",
        ("download", "burst_bytes") => "download_burst_bytes",
        ("download", "ceiling_bytes_per_second") => "download_ceiling_bytes_per_second",
        ("download", "ceiling_burst_bytes") => "download_ceiling_burst_bytes",
        ("download", "max_reservations") => "download_max_reservations",
        ("download", "available_bytes") => "download_available_bytes",
        ("download", "reserved_bytes") => "download_reserved_bytes",
        ("download", "reservations") => "download_reservations",
        _ => return Err("unknown byte-rate sample field".into()),
      };
      write!(file, "\t{}", row_number(io_rows, key)?)
        .map_err(|error| format!("sample stream write failed: {error}"))?;
    }
    writeln!(file).map_err(|error| format!("sample stream newline failed: {error}"))
  }

  fn seal_streams(&mut self) -> Result<([u8; 32], [u8; 32]), String> {
    for (label, file) in [
      ("terminal", self.terminals.as_mut()),
      ("sample", self.samples.as_mut()),
    ] {
      let file = file.ok_or_else(|| format!("{label} stream was already closed"))?;
      file
        .sync_all()
        .map_err(|error| format!("{label} stream sync failed: {error}"))?;
    }
    self.terminals.take();
    self.samples.take();
    Ok((sha256_file(&self.paths[1])?, sha256_file(&self.paths[2])?))
  }

  fn complete(&mut self, receipt: ReceiptData<'_>) -> Result<(), String> {
    #[cfg(feature = "resource-feedback")]
    if receipt.args.comparison_mode.feedback_enabled() {
      return self.complete_external(receipt);
    }
    #[cfg(not(feature = "resource-feedback"))]
    if receipt.args.comparison_mode.feedback_enabled() {
      return Err("external-pressure soak receipt requires the resource-feedback feature".into());
    }
    self.complete_fixed(receipt)
  }

  fn complete_fixed(&mut self, receipt: ReceiptData<'_>) -> Result<(), String> {
    let ReceiptData {
      identity,
      args,
      ring_sha256,
      ring_rows,
      ring_average_rate_per_second,
      stats,
      terminal_sha,
      sample_sha,
      first_hour_median_kib,
      final_hour_median_kib,
      global,
      tenant,
      baseline_control,
      ..
    } = receipt;
    let mut file = open_exclusive_private(&self.report_temp_path)
      .map_err(|error| format!("exclusive soak receipt temp create failed: {error}"))?;
    let terminal_name = safe_basename(&self.paths[1])?;
    let sample_name = safe_basename(&self.paths[2])?;
    write!(
      file,
      "{{\"schema\":\"allocatbelt.runtime-soak.v1\",\"campaign_id\":\"{}\",\"host_id\":\"{}\",\"run_id\":\"{}\",\"nonce\":\"{}\",\"allocator\":\"{}\",\"executor\":\"{}\",\"workload\":\"mixed\",\"profile\":\"{}\",\"comparison_family\":\"fixed_policy\",\"source_sha256\":\"{}\",\"binary_sha256\":\"{}\",\"resource_ceiling_sha256\":\"{}\",\"reference_ring_sha256\":\"{}\",\"reference_ring_rows\":{},\"reference_average_rate_per_second\":{},\"duration_seconds\":{},\"sample_interval_ms\":{},\"warmup_seconds\":{},\"logical_window\":{},\"attempted\":{},\"completed\":{},\"errors\":{},\"lost\":{},\"terminal_records\":{},\"terminal_stream_sha256\":\"{}\",\"terminal_stream_relative_path\":\"{}\",\"resource_samples_count\":{},\"resource_samples_sha256\":\"{}\",\"resource_samples_relative_path\":\"{}\",\"first_post_warmup_hour_rss_median_kib\":{},\"final_hour_rss_median_kib\":{},",
      identity.campaign_id,
      identity.host_id,
      identity.run_id,
      identity.nonce,
      identity.allocator,
      identity.executor,
      args.profile,
      identity.source_sha256,
      identity.binary_sha256,
      identity.resource_ceiling_sha256,
      digest_hex(ring_sha256),
      ring_rows,
      ring_average_rate_per_second,
      args.duration.as_secs(),
      args.sample_interval.as_millis(),
      WARMUP_SECONDS,
      WINDOW,
      stats.attempted,
      stats.completed,
      stats.errors,
      stats.lost,
      stats.completed,
      digest_hex(terminal_sha),
      terminal_name,
      stats.sample_count,
      digest_hex(sample_sha),
      sample_name,
      first_hour_median_kib.map_or_else(|| "null".to_owned(), |value| value.to_string()),
      final_hour_median_kib.map_or_else(|| "null".to_owned(), |value| value.to_string()),
    )
    .map_err(|error| format!("soak receipt prefix write failed: {error}"))?;
    write!(
      file,
      "\"qualified_horizon\":{},\"started_monotonic_ns\":{},\"trace_ended_monotonic_ns\":{},\"drain_ended_monotonic_ns\":{},\"shutdown_ended_monotonic_ns\":{},\"postprocess_ended_monotonic_ns\":{},\"ended_monotonic_ns\":{},\"actual_trace_duration_ns\":{},\"drain_duration_ns\":{},\"shutdown_duration_ns\":{},\"postprocess_after_shutdown_ns\":{},\"production_cpu_started_ns\":{},\"production_cpu_ended_ns\":{},\"production_cpu_ns\":{},\"final_global_live_tenants\":{},\"final_global_cpu_used\":{},\"final_global_memory_used\":{},\"final_global_disk_used\":{},\"final_global_network_used\":{},\"final_global_tasks_used\":{},\"final_global_control_used\":{},\"fixed_global_control_baseline\":{},\"final_tenant_cpu_used\":{},\"final_tenant_memory_used\":{},\"final_tenant_disk_used\":{},\"final_tenant_network_used\":{},\"final_tenant_tasks_used\":{},\"final_tenant_control_used\":{},\"final_scope_memory_used\":0,\"final_scope_disk_used\":0,\"final_scope_network_used\":0}}",
      stats.qualified_horizon,
      stats.started_monotonic_ns,
      stats.trace_ended_monotonic_ns,
      stats.drain_ended_monotonic_ns,
      stats.shutdown_ended_monotonic_ns,
      stats.postprocess_ended_monotonic_ns,
      stats.ended_monotonic_ns,
      stats.trace_ended_monotonic_ns.saturating_sub(stats.started_monotonic_ns),
      stats
        .drain_ended_monotonic_ns
        .saturating_sub(stats.trace_ended_monotonic_ns),
      stats
        .shutdown_ended_monotonic_ns
        .saturating_sub(stats.drain_ended_monotonic_ns),
      stats
        .postprocess_ended_monotonic_ns
        .saturating_sub(stats.shutdown_ended_monotonic_ns),
      stats.production_cpu_started_ns,
      stats.production_cpu_ended_ns,
      stats
        .production_cpu_ended_ns
        .saturating_sub(stats.production_cpu_started_ns),
      global.live_tenants,
      global.used.get(DomainResource::Cpu),
      global.used.get(DomainResource::Memory),
      global.used.get(DomainResource::Disk),
      global.used.get(DomainResource::Network),
      global.used.get(DomainResource::Tasks),
      global.used.get(DomainResource::Control),
      baseline_control,
      tenant.used.get(DomainResource::Cpu),
      tenant.used.get(DomainResource::Memory),
      tenant.used.get(DomainResource::Disk),
      tenant.used.get(DomainResource::Network),
      tenant.used.get(DomainResource::Tasks),
      tenant.used.get(DomainResource::Control),
    )
    .map_err(|error| format!("soak receipt completion write failed: {error}"))?;
    file
      .sync_all()
      .map_err(|error| format!("soak receipt temp sync failed: {error}"))?;
    drop(file);
    std::fs::rename(&self.report_temp_path, &self.paths[0])
      .map_err(|error| format!("atomic soak receipt publish failed: {error}"))?;
    self.report.take();
    Ok(())
  }

  #[cfg(feature = "resource-feedback")]
  fn complete_external(&mut self, receipt: ReceiptData<'_>) -> Result<(), String> {
    let ReceiptData {
      identity,
      args,
      ring_sha256,
      ring_rows,
      ring_average_rate_per_second,
      stats,
      terminal_sha,
      sample_sha,
      first_hour_median_kib,
      final_hour_median_kib,
      global,
      tenant,
      baseline_control,
      feedback,
    } = receipt;
    let feedback = feedback
      .ok_or_else(|| "external soak receipt has no captured feedback service status".to_owned())?;
    if !feedback.started
      || !feedback.joined
      || feedback.worker_failure.is_some()
      || !feedback.trace_worker_joined
    {
      return Err("external soak feedback service or trace worker did not join".into());
    }
    let started_bounds = stats.started_monotonic_bounds.ok_or_else(|| {
      "external soak receipt omitted the production-start clock bounds".to_owned()
    })?;
    let trace_ended_bounds = stats
      .trace_ended_monotonic_bounds
      .ok_or_else(|| "external soak receipt omitted the production-end clock bounds".to_owned())?;
    let drain_ended_bounds = stats
      .drain_ended_monotonic_bounds
      .ok_or_else(|| "external soak receipt omitted the drain-end clock bounds".to_owned())?;
    let shutdown_ended_bounds = stats
      .shutdown_ended_monotonic_bounds
      .ok_or_else(|| "external soak receipt omitted the shutdown-end clock bounds".to_owned())?;
    let postprocess_ended_bounds = stats
      .postprocess_ended_monotonic_bounds
      .ok_or_else(|| "external soak receipt omitted the postprocess clock bounds".to_owned())?;
    for (scalar, bounds) in [
      (stats.started_monotonic_ns, started_bounds),
      (stats.trace_ended_monotonic_ns, trace_ended_bounds),
      (stats.drain_ended_monotonic_ns, drain_ended_bounds),
      (stats.shutdown_ended_monotonic_ns, shutdown_ended_bounds),
      (
        stats.postprocess_ended_monotonic_ns,
        postprocess_ended_bounds,
      ),
    ] {
      if bounds.lower_ns > bounds.upper_ns || scalar != bounds.lower_ns {
        return Err(
          "external soak scalar timestamp is not the lower endpoint of its TraceClock bracket"
            .into(),
        );
      }
    }
    let terminal_name = safe_basename(&self.paths[1])?;
    let sample_name = safe_basename(&self.paths[2])?;
    use crate::application::feedback_policy_probe as json;
    let receipt_value = json::json_object([
      (
        "schema",
        json::json_string_value("allocatbelt.runtime-soak.v2"),
      ),
      (
        "campaign_id",
        json::json_string_value(identity.campaign_id.as_str()),
      ),
      (
        "host_id",
        json::json_string_value(identity.host_id.as_str()),
      ),
      ("run_id", json::json_string_value(identity.run_id.as_str())),
      ("nonce", json::json_string_value(identity.nonce.as_str())),
      (
        "allocator",
        json::json_string_value(identity.allocator.as_str()),
      ),
      (
        "executor",
        json::json_string_value(identity.executor.as_str()),
      ),
      ("workload", json::json_string_value("mixed")),
      ("profile", json::json_string_value(args.profile.as_str())),
      (
        "comparison_family",
        json::json_string_value("external_pressure"),
      ),
      ("mode", json::json_string_value("soak")),
      ("qualification_eligible", json::json_bool(false)),
      (
        "source_sha256",
        json::json_string_value(identity.source_sha256.as_str()),
      ),
      (
        "binary_sha256",
        json::json_string_value(identity.binary_sha256.as_str()),
      ),
      (
        "resource_ceiling_sha256",
        json::json_string_value(identity.resource_ceiling_sha256.as_str()),
      ),
      (
        "reference_ring_sha256",
        json::json_string_value(digest_hex(ring_sha256)),
      ),
      ("reference_ring_rows", json::json_usize(ring_rows)?),
      (
        "reference_average_rate_per_second",
        json::json_u64(ring_average_rate_per_second),
      ),
      ("duration_seconds", json::json_u64(args.duration.as_secs())),
      (
        "sample_interval_ms",
        json::json_u128(args.sample_interval.as_millis()),
      ),
      ("warmup_seconds", json::json_u64(WARMUP_SECONDS)),
      ("logical_window", json::json_usize(WINDOW)?),
      ("attempted", json::json_u64(stats.attempted)),
      ("completed", json::json_u64(stats.completed)),
      ("errors", json::json_u64(stats.errors)),
      ("lost", json::json_u64(stats.lost)),
      ("terminal_records", json::json_u64(stats.completed)),
      (
        "terminal_stream_sha256",
        json::json_string_value(digest_hex(terminal_sha)),
      ),
      (
        "terminal_stream_relative_path",
        json::json_string_value(terminal_name),
      ),
      ("resource_samples_count", json::json_u64(stats.sample_count)),
      (
        "resource_samples_sha256",
        json::json_string_value(digest_hex(sample_sha)),
      ),
      (
        "resource_samples_relative_path",
        json::json_string_value(sample_name),
      ),
      (
        "first_post_warmup_hour_rss_median_kib",
        first_hour_median_kib.map_or_else(json::json_null, json::json_u64),
      ),
      (
        "final_hour_rss_median_kib",
        final_hour_median_kib.map_or_else(json::json_null, json::json_u64),
      ),
      ("feedback_started", json::json_bool(feedback.started)),
      ("feedback_worker_joined", json::json_bool(feedback.joined)),
      (
        "feedback_worker_failure",
        feedback
          .worker_failure
          .map_or_else(json::json_null, json::json_string_value),
      ),
      (
        "feedback_trace_worker_joined",
        json::json_bool(feedback.trace_worker_joined),
      ),
      (
        "qualified_horizon",
        json::json_bool(stats.qualified_horizon),
      ),
      (
        "started_monotonic_ns",
        json::json_u128(stats.started_monotonic_ns),
      ),
      (
        "started_monotonic_lower_ns",
        json::json_u128(started_bounds.lower_ns),
      ),
      (
        "started_monotonic_upper_ns",
        json::json_u128(started_bounds.upper_ns),
      ),
      (
        "trace_ended_monotonic_ns",
        json::json_u128(stats.trace_ended_monotonic_ns),
      ),
      (
        "trace_ended_monotonic_lower_ns",
        json::json_u128(trace_ended_bounds.lower_ns),
      ),
      (
        "trace_ended_monotonic_upper_ns",
        json::json_u128(trace_ended_bounds.upper_ns),
      ),
      (
        "drain_ended_monotonic_ns",
        json::json_u128(stats.drain_ended_monotonic_ns),
      ),
      (
        "drain_ended_monotonic_lower_ns",
        json::json_u128(drain_ended_bounds.lower_ns),
      ),
      (
        "drain_ended_monotonic_upper_ns",
        json::json_u128(drain_ended_bounds.upper_ns),
      ),
      (
        "shutdown_ended_monotonic_ns",
        json::json_u128(stats.shutdown_ended_monotonic_ns),
      ),
      (
        "shutdown_ended_monotonic_lower_ns",
        json::json_u128(shutdown_ended_bounds.lower_ns),
      ),
      (
        "shutdown_ended_monotonic_upper_ns",
        json::json_u128(shutdown_ended_bounds.upper_ns),
      ),
      (
        "postprocess_ended_monotonic_ns",
        json::json_u128(stats.postprocess_ended_monotonic_ns),
      ),
      (
        "postprocess_ended_monotonic_lower_ns",
        json::json_u128(postprocess_ended_bounds.lower_ns),
      ),
      (
        "postprocess_ended_monotonic_upper_ns",
        json::json_u128(postprocess_ended_bounds.upper_ns),
      ),
      (
        "ended_monotonic_ns",
        json::json_u128(stats.ended_monotonic_ns),
      ),
      (
        "actual_trace_duration_ns",
        json::json_u128(
          stats
            .trace_ended_monotonic_ns
            .saturating_sub(stats.started_monotonic_ns),
        ),
      ),
      (
        "drain_duration_ns",
        json::json_u128(
          stats
            .drain_ended_monotonic_ns
            .saturating_sub(stats.trace_ended_monotonic_ns),
        ),
      ),
      (
        "shutdown_duration_ns",
        json::json_u128(
          stats
            .shutdown_ended_monotonic_ns
            .saturating_sub(stats.drain_ended_monotonic_ns),
        ),
      ),
      (
        "postprocess_after_shutdown_ns",
        json::json_u128(
          stats
            .postprocess_ended_monotonic_ns
            .saturating_sub(stats.shutdown_ended_monotonic_ns),
        ),
      ),
      (
        "production_cpu_started_ns",
        json::json_u128(stats.production_cpu_started_ns),
      ),
      (
        "production_cpu_ended_ns",
        json::json_u128(stats.production_cpu_ended_ns),
      ),
      (
        "production_cpu_ns",
        json::json_u128(
          stats
            .production_cpu_ended_ns
            .saturating_sub(stats.production_cpu_started_ns),
        ),
      ),
      (
        "final_global_live_tenants",
        json::json_usize(global.live_tenants)?,
      ),
      (
        "final_global_cpu_used",
        json::json_usize(global.used.get(DomainResource::Cpu))?,
      ),
      (
        "final_global_memory_used",
        json::json_usize(global.used.get(DomainResource::Memory))?,
      ),
      (
        "final_global_disk_used",
        json::json_usize(global.used.get(DomainResource::Disk))?,
      ),
      (
        "final_global_network_used",
        json::json_usize(global.used.get(DomainResource::Network))?,
      ),
      (
        "final_global_tasks_used",
        json::json_usize(global.used.get(DomainResource::Tasks))?,
      ),
      (
        "final_global_control_used",
        json::json_usize(global.used.get(DomainResource::Control))?,
      ),
      (
        "fixed_global_control_baseline",
        json::json_usize(baseline_control)?,
      ),
      (
        "final_tenant_cpu_used",
        json::json_usize(tenant.used.get(DomainResource::Cpu))?,
      ),
      (
        "final_tenant_memory_used",
        json::json_usize(tenant.used.get(DomainResource::Memory))?,
      ),
      (
        "final_tenant_disk_used",
        json::json_usize(tenant.used.get(DomainResource::Disk))?,
      ),
      (
        "final_tenant_network_used",
        json::json_usize(tenant.used.get(DomainResource::Network))?,
      ),
      (
        "final_tenant_tasks_used",
        json::json_usize(tenant.used.get(DomainResource::Tasks))?,
      ),
      (
        "final_tenant_control_used",
        json::json_usize(tenant.used.get(DomainResource::Control))?,
      ),
      ("final_scope_memory_used", json::json_u64(0)),
      ("final_scope_disk_used", json::json_u64(0)),
      ("final_scope_network_used", json::json_u64(0)),
    ])?;
    let mut json_bytes = [0u8; MAX_EXTERNAL_RECEIPT_JSON_BYTES];
    let json_length = {
      let mut output = FixedJsonBuffer {
        bytes: &mut json_bytes,
        length: 0,
      };
      json::write_canonical_json(&receipt_value, &mut output)?;
      output.length
    };
    drop(receipt_value);
    let mut file = open_exclusive_private(&self.report_temp_path)
      .map_err(|error| format!("exclusive soak receipt temp create failed: {error}"))?;
    file
      .write_all(&json_bytes[..json_length])
      .map_err(|error| format!("canonical external soak receipt write failed: {error}"))?;
    file
      .sync_all()
      .map_err(|error| format!("external soak receipt temp sync failed: {error}"))?;
    drop(file);
    std::fs::rename(&self.report_temp_path, &self.paths[0])
      .map_err(|error| format!("atomic external soak receipt publish failed: {error}"))?;
    self.report.take();
    Ok(())
  }

  fn commit(&mut self) {
    self.committed = true;
  }
}

impl Drop for OutputFiles {
  fn drop(&mut self) {
    if !self.committed {
      if let Some(report) = self.report.as_mut() {
        let _ = writeln!(report, "\n{}", self.incomplete_marker);
        let _ = report.sync_all();
      }
      if let Some(terminals) = self.terminals.as_mut() {
        let _ = terminals.sync_all();
      }
      if let Some(samples) = self.samples.as_mut() {
        let _ = samples.sync_all();
      }
    }
  }
}

fn optional_env_positive(name: &str) -> Result<Option<u64>, String> {
  std::env::var(name)
    .ok()
    .map(|value| parse_positive(&value, name))
    .transpose()
}

fn env_path(name: &str) -> Option<PathBuf> {
  std::env::var_os(name).map(PathBuf::from)
}

fn required_env(name: &str) -> Result<String, String> {
  std::env::var(name).map_err(|_| format!("{name} is required"))
}

fn parse_positive(value: &str, name: &str) -> Result<u64, String> {
  let parsed = value
    .parse::<u64>()
    .map_err(|_| format!("invalid {name}"))?;
  if parsed == 0 {
    return Err(format!("{name} must be positive"));
  }
  Ok(parsed)
}

fn validate_sha256(value: &str, name: &str) -> Result<(), String> {
  validate_hex(value, 64, name)
}

fn validate_hex(value: &str, length: usize, name: &str) -> Result<(), String> {
  if value.len() != length || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    return Err(format!(
      "{name} must contain {length} hexadecimal characters"
    ));
  }
  Ok(())
}

fn open_exclusive_private(path: &Path) -> io::Result<File> {
  let mut options = OpenOptions::new();
  options.write(true).create_new(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
  }
  options.open(path)
}

fn reserve_control(tenant: &TenantDomain, bytes: usize) -> Result<DomainReservation, DomainError> {
  tenant.try_acquire(DomainResources::ZERO.with(DomainResource::Control, bytes))
}

fn load_reference_ring(
  path: &Path,
  tenant: &TenantDomain,
  profile: &str,
  source_sha256: &str,
  binary_sha256: &str,
  expected_file_sha256: &str,
) -> Result<ChargedRing, String> {
  let metadata = std::fs::symlink_metadata(path)
    .map_err(|error| format!("reference ring metadata failed: {error}"))?;
  if !metadata.is_file() || metadata.file_type().is_symlink() {
    return Err("reference ring path must name a regular non-symlink file".into());
  }
  let byte_len = usize::try_from(metadata.len())
    .map_err(|_| "reference ring length does not fit this platform".to_owned())?;
  if byte_len == 0 || byte_len > MAX_REFERENCE_BYTES {
    return Err(format!(
      "reference ring must contain 1..={MAX_REFERENCE_BYTES} bytes"
    ));
  }
  let byte_charge = reserve_control(tenant, byte_len)
    .map_err(|error| format!("reference bytes exceeded Control admission: {error:?}"))?;
  let mut bytes = Vec::new();
  bytes
    .try_reserve_exact(byte_len)
    .map_err(|_| "reference ring byte allocation failed".to_owned())?;
  if bytes.capacity() != byte_len {
    return Err("reference ring byte allocation exceeded its admitted capacity".into());
  }
  bytes.resize(byte_len, 0);
  let mut file =
    File::open(path).map_err(|error| format!("reference ring open failed: {error}"))?;
  if !file
    .metadata()
    .map_err(|error| format!("reference ring opened-file metadata failed: {error}"))?
    .is_file()
  {
    return Err("reference ring descriptor did not open a regular file".into());
  }
  file
    .read_exact(&mut bytes)
    .map_err(|error| format!("reference ring read failed: {error}"))?;
  let mut extra = [0u8; 1];
  if file
    .read(&mut extra)
    .map_err(|error| format!("reference ring trailing-byte check failed: {error}"))?
    != 0
  {
    return Err("reference ring changed while it was read".into());
  }
  let file_sha256 = sha256_digest(&bytes);
  if !digest_matches_hex(&file_sha256, expected_file_sha256) {
    return Err("reference ring bytes differ from the externally supplied SHA-256 pin".into());
  }
  let line_count = bytes.iter().filter(|byte| **byte == b'\n').count();
  let line_bytes = line_count
    .checked_mul(std::mem::size_of::<&str>())
    .ok_or("reference line index size overflow")?;
  let line_charge = reserve_control(tenant, line_bytes)
    .map_err(|error| format!("reference line index exceeded Control admission: {error:?}"))?;
  let lines = split_lines(&bytes)?;
  let header = parse_ring_header(&lines, profile, source_sha256, binary_sha256)?;
  let row_count = lines
    .len()
    .checked_sub(12)
    .ok_or("reference ring is truncated")?;
  if row_count != header.arrivals {
    return Err("reference ring row count differs from its frozen arrivals".into());
  }
  if !(MIN_REFERENCE_ROWS..=MAX_REFERENCE_ROWS).contains(&row_count) || row_count % 4 != 0 {
    return Err("reference ring must have 8..=65536 rows in a multiple of four".into());
  }
  let checksum_bytes = row_count
    .checked_mul(std::mem::size_of::<u64>())
    .ok_or("reference checksum storage size overflow")?;
  let checksum_charge = reserve_control(tenant, checksum_bytes)
    .map_err(|error| format!("reference checksum storage exceeded Control admission: {error:?}"))?;
  let mut expected = Vec::new();
  expected
    .try_reserve_exact(row_count)
    .map_err(|_| "reference checksum allocation failed".to_owned())?;
  if expected.capacity() != row_count {
    return Err("reference checksum allocation exceeded its admitted capacity".into());
  }
  for (id, line) in lines[12..].iter().enumerate() {
    let checksum = validate_ring_row(line, id as u64, header)?;
    expected.push(checksum);
  }
  let average_rate_per_second = header.average_rate_per_second;
  drop(lines);
  drop(line_charge);
  let ring = ReferenceRing {
    bytes,
    expected,
    file_sha256,
    average_rate_per_second,
  };
  Ok(ChargedRing {
    ring,
    _byte_capacity: byte_charge,
    _checksum_capacity: checksum_charge,
  })
}

fn digest_matches_hex(digest: &[u8; 32], expected: &str) -> bool {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  if expected.len() != 64 {
    return false;
  }
  expected
    .as_bytes()
    .chunks_exact(2)
    .zip(digest)
    .all(|(pair, byte)| pair == [HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]])
}

fn split_lines(bytes: &[u8]) -> Result<Vec<&str>, String> {
  if bytes.last() != Some(&b'\n') || bytes.contains(&b'\r') {
    return Err("reference ring must be LF-terminated TSV without CR bytes".into());
  }
  let mut lines = Vec::new();
  lines
    .try_reserve_exact(bytes.iter().filter(|byte| **byte == b'\n').count())
    .map_err(|_| "reference ring line index allocation failed".to_owned())?;
  let expected_capacity = bytes.iter().filter(|byte| **byte == b'\n').count();
  if lines.capacity() != expected_capacity {
    return Err("reference ring line index exceeded its admitted capacity".into());
  }
  for line in bytes
    .split(|byte| *byte == b'\n')
    .take_while(|line| !line.is_empty())
  {
    lines.push(std::str::from_utf8(line).map_err(|_| "reference ring contains non-UTF-8 data")?);
  }
  Ok(lines)
}

fn parse_ring_header<'a>(
  lines: &[&'a str],
  requested_profile: &str,
  source_sha256: &str,
  binary_sha256: &str,
) -> Result<RingHeader<'a>, String> {
  if lines.len() < 12
    || lines[0] != "schema\tallocatbelt-app-oracle-v2"
    || lines[4] != "workload\tmixed"
    || lines[5] != "mode\topen_loop"
    || lines[10] != format!("kernel_config\t{SOAK_KERNEL_CONFIG}")
    || lines[11] != REFERENCE_HEADER
  {
    return Err("reference ring schema, identity, or canonical kernel differs".into());
  }
  let source = header_value(lines[1], "source_sha256")?;
  let binary = header_value(lines[2], "binary_sha256")?;
  if source != source_sha256 || binary != binary_sha256 {
    return Err("reference ring source/binary identity differs from this process".into());
  }
  let profile = header_value(lines[3], "profile")?;
  if profile != requested_profile {
    return Err("reference ring profile differs from the requested treatment".into());
  }
  let average_rate_per_second = parse_header_number(lines[6], "average_rate_per_second")?;
  let pulse_rate_per_second = parse_header_number(lines[7], "pulse_rate_per_second")?;
  let arrivals = usize::try_from(parse_header_number(lines[8], "arrivals")?)
    .map_err(|_| "reference ring arrivals do not fit this platform")?;
  let trace_duration_ns = parse_header_number(lines[9], "trace_duration_ns")?;
  if average_rate_per_second == 0 || average_rate_per_second > 1_000_000_000 {
    return Err("reference ring average rate is outside its canonical bound".into());
  }
  if profile == "burst" && average_rate_per_second > 250_000_000 {
    return Err("reference burst average rate exceeds its canonical bound".into());
  }
  let expected_pulse_rate = if profile == "burst" {
    average_rate_per_second
      .checked_mul(4)
      .ok_or("reference burst pulse rate overflows")?
  } else {
    average_rate_per_second
  };
  if pulse_rate_per_second != expected_pulse_rate {
    return Err("reference ring pulse rate differs from its profile".into());
  }
  let expected_trace_ns = if profile == "burst" {
    let cycles = arrivals
      .checked_add(average_rate_per_second as usize - 1)
      .ok_or("reference burst duration overflow")?
      / average_rate_per_second as usize;
    u64::try_from(cycles)
      .ok()
      .and_then(|count| count.checked_mul(1_000_000_000))
      .ok_or("reference burst duration overflow")?
  } else {
    let value = (arrivals as u128)
      .checked_mul(1_000_000_000)
      .ok_or("reference trace duration overflow")?
      / u128::from(average_rate_per_second);
    u64::try_from(value).map_err(|_| "reference trace duration does not fit u64")?
  };
  if trace_duration_ns != expected_trace_ns {
    return Err("reference ring trace duration differs from its frozen rate and count".into());
  }
  Ok(RingHeader {
    source_sha256: source,
    binary_sha256: binary,
    profile,
    average_rate_per_second,
    pulse_rate_per_second,
    arrivals,
  })
}

fn header_value<'a>(line: &'a str, expected_key: &str) -> Result<&'a str, String> {
  let (key, value) = line
    .split_once('\t')
    .ok_or_else(|| format!("reference ring lacks {expected_key}"))?;
  if key != expected_key || value.is_empty() {
    return Err(format!("reference ring field {expected_key} is malformed"));
  }
  Ok(value)
}

fn parse_header_number(line: &str, key: &str) -> Result<u64, String> {
  parse_canonical_u64(header_value(line, key)?)
    .ok_or_else(|| format!("reference ring field {key} is not a canonical u64"))
}

fn parse_canonical_u64(value: &str) -> Option<u64> {
  if value == "0"
    || (value
      .as_bytes()
      .first()
      .is_some_and(|byte| (b'1'..=b'9').contains(byte))
      && value.bytes().all(|byte| byte.is_ascii_digit()))
  {
    value.parse::<u64>().ok()
  } else {
    None
  }
}

fn burst_admission_open(profile: &str, elapsed: Duration) -> bool {
  profile != "burst" || elapsed.as_nanos() % 1_000_000_000 < 250_000_000
}

fn sample_cadence_matches(
  sample_index: u64,
  interval: Duration,
  started_monotonic_ns: u128,
  actual_monotonic_ns: u128,
) -> bool {
  let Some(expected_offset) = interval.as_nanos().checked_mul(u128::from(sample_index)) else {
    return false;
  };
  let Some(expected) = started_monotonic_ns.checked_add(expected_offset) else {
    return false;
  };
  expected.abs_diff(actual_monotonic_ns) <= SAMPLE_LATE_TOLERANCE_NS
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RssWindow {
  FirstPostWarmupHour,
  FinalHour,
}

fn rss_window(elapsed_ns: u128) -> Option<RssWindow> {
  if (300_000_000_000..3_900_000_000_000).contains(&elapsed_ns) {
    Some(RssWindow::FirstPostWarmupHour)
  } else if (7_200_000_000_000..10_800_000_000_000).contains(&elapsed_ns) {
    Some(RssWindow::FinalHour)
  } else {
    None
  }
}

fn drain_is_complete(
  stopping: bool,
  final_sample_written: bool,
  slots_empty: bool,
  acceptor_finished: bool,
) -> bool {
  stopping && final_sample_written && slots_empty && acceptor_finished
}

fn qualifies_horizon(
  requested_duration: Duration,
  sample_interval: Duration,
  stats: &SoakStats,
  first_hour_samples: usize,
  final_hour_samples: usize,
  first_hour_median_kib: Option<u64>,
  final_hour_median_kib: Option<u64>,
) -> bool {
  let expected_samples = QUALIFIED_SECONDS * 1000 / SAMPLE_INTERVAL_MS + 1;
  let Some(trace_duration_ns) = stats
    .trace_ended_monotonic_ns
    .checked_sub(stats.started_monotonic_ns)
  else {
    return false;
  };
  let Some(drain_duration_ns) = stats
    .drain_ended_monotonic_ns
    .checked_sub(stats.trace_ended_monotonic_ns)
  else {
    return false;
  };
  let Some(max_trace_duration_ns) = requested_duration.as_nanos().checked_add(5_000_000_000) else {
    return false;
  };

  requested_duration == Duration::from_secs(QUALIFIED_SECONDS)
    && sample_interval == Duration::from_millis(SAMPLE_INTERVAL_MS)
    && stats.sample_count == expected_samples
    && first_hour_samples == 36_000
    && final_hour_samples == 36_000
    && stats.completed == stats.attempted
    && stats.errors == 0
    && stats.lost == 0
    && trace_duration_ns >= requested_duration.as_nanos()
    && trace_duration_ns <= max_trace_duration_ns
    && drain_duration_ns <= 5_000_000_000
    && rss_growth_within_percent(first_hour_median_kib, final_hour_median_kib, 5)
}

fn validate_ring_row(line: &str, id: u64, header: RingHeader<'_>) -> Result<u64, String> {
  let mut fields = line.split('\t');
  let row_id = fields.next().ok_or("reference row is missing ID")?;
  let scheduled = fields.next().ok_or("reference row is missing schedule")?;
  let family = fields.next().ok_or("reference row is missing family")?;
  let checksum = fields.next().ok_or("reference row is missing checksum")?;
  if fields.next().is_some() || parse_canonical_u64(row_id) != Some(id) {
    return Err(format!("reference ring row {id} has malformed fields"));
  }
  let expected_family = ["cpu", "memory", "http", "disk"][(id % 4) as usize];
  if family != expected_family {
    return Err(format!(
      "reference ring row {id} breaks the frozen family interleave"
    ));
  }
  let scheduled = parse_canonical_u64(scheduled)
    .ok_or_else(|| format!("reference ring row {id} has invalid schedule"))?;
  let expected_schedule = if header.profile == "burst" {
    let rate = header.average_rate_per_second;
    let cycle = id / rate;
    let slot = id % rate;
    cycle
      .checked_mul(1_000_000_000)
      .and_then(|base| base.checked_add(slot * 250_000_000 / rate))
      .ok_or("reference burst schedule overflow")?
  } else {
    u64::try_from((u128::from(id) * 1_000_000_000) / u128::from(header.average_rate_per_second))
      .map_err(|_| "reference schedule does not fit u64")?
  };
  if scheduled != expected_schedule {
    return Err(format!(
      "reference ring row {id} has a noncanonical schedule"
    ));
  }
  parse_canonical_u64(checksum)
    .ok_or_else(|| format!("reference ring row {id} checksum is not a canonical u64"))
}

fn verify_reference_ring_unchanged(path: &Path, ring: &mut ReferenceRing) -> Result<(), String> {
  let metadata = std::fs::symlink_metadata(path)
    .map_err(|error| format!("reference ring final metadata check failed: {error}"))?;
  if !metadata.is_file() || metadata.file_type().is_symlink() {
    return Err("reference ring path changed to a non-regular file during the soak".into());
  }
  let mut file =
    File::open(path).map_err(|error| format!("reference ring re-open failed: {error}"))?;
  file
    .read_exact(&mut ring.bytes)
    .map_err(|error| format!("reference ring changed before final verification: {error}"))?;
  let mut extra = [0u8; 1];
  if file
    .read(&mut extra)
    .map_err(|error| format!("reference ring final length check failed: {error}"))?
    != 0
    || sha256_digest(&ring.bytes) != ring.file_sha256
  {
    return Err("reference ring changed during the soak".into());
  }
  Ok(())
}

#[cfg(test)]
fn sha256_hex(bytes: &[u8]) -> String {
  let digest = sha256_digest(bytes);
  let mut output = String::with_capacity(64);
  for byte in digest {
    use std::fmt::Write as _;
    let _ = write!(output, "{byte:02x}");
  }
  output
}

fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
  let mut hasher = Sha256::new();
  hasher.update(bytes);
  hasher.finish()
}

struct Sha256 {
  state: [u32; 8],
  block: [u8; 64],
  used: usize,
  length: u64,
}

impl Sha256 {
  const fn new() -> Self {
    Self {
      state: [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
      ],
      block: [0; 64],
      used: 0,
      length: 0,
    }
  }

  fn update(&mut self, mut input: &[u8]) {
    self.length = self.length.wrapping_add(input.len() as u64);
    while !input.is_empty() {
      let count = (64 - self.used).min(input.len());
      self.block[self.used..self.used + count].copy_from_slice(&input[..count]);
      self.used += count;
      input = &input[count..];
      if self.used == 64 {
        compress(&mut self.state, &self.block);
        self.used = 0;
      }
    }
  }

  fn finish(mut self) -> [u8; 32] {
    let bit_length = self.length.wrapping_mul(8);
    self.block[self.used] = 0x80;
    self.used += 1;
    if self.used > 56 {
      self.block[self.used..].fill(0);
      compress(&mut self.state, &self.block);
      self.block = [0; 64];
      self.used = 0;
    }
    self.block[self.used..56].fill(0);
    self.block[56..64].copy_from_slice(&bit_length.to_be_bytes());
    compress(&mut self.state, &self.block);
    let mut output = [0u8; 32];
    for (chunk, word) in output.chunks_exact_mut(4).zip(self.state) {
      chunk.copy_from_slice(&word.to_be_bytes());
    }
    output
  }
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
  const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  let mut words = [0u32; 64];
  for (index, chunk) in block.chunks_exact(4).enumerate() {
    words[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
  }
  for index in 16..64 {
    let x = words[index - 15];
    let y = words[index - 2];
    let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
    let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
    words[index] = words[index - 16]
      .wrapping_add(s0)
      .wrapping_add(words[index - 7])
      .wrapping_add(s1);
  }
  let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
  for index in 0..64 {
    let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
    let choice = (e & f) ^ (!e & g);
    let temp1 = h
      .wrapping_add(sum1)
      .wrapping_add(choice)
      .wrapping_add(K[index])
      .wrapping_add(words[index]);
    let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
    let majority = (a & b) ^ (a & c) ^ (b & c);
    let temp2 = sum0.wrapping_add(majority);
    h = g;
    g = f;
    f = e;
    e = d.wrapping_add(temp1);
    d = c;
    c = b;
    b = a;
    a = temp1.wrapping_add(temp2);
  }
  for (target, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
    *target = target.wrapping_add(value);
  }
}

fn run_soak(args: SoakArgs, identity: SoakIdentity) -> Result<(), String> {
  if application_mode_from_environment()? != args.comparison_mode {
    return Err("soak comparison family changed after argument validation".into());
  }
  if args.comparison_mode.feedback_enabled() {
    validate_external_feedback_identity(&args, &identity)?;
  }
  let workers = if args.profile == "oversubscribed" {
    2
  } else {
    4
  };
  let application_domain =
    crate::application::runtime_bindings::ApplicationDomain::new_for_profile(
      crate::application::Workload::Mixed,
      workers,
      &args.profile,
    )?;
  let tenant = application_domain.tenant();
  let mut charged_ring = load_reference_ring(
    &args.reference_path,
    &tenant,
    &args.profile,
    &identity.source_sha256,
    &identity.binary_sha256,
    &args.reference_sha256,
  )?;
  let metadata_charge_bytes = fixed_metadata_charge(&args, &identity)?;
  let metadata_charge = reserve_control(&tenant, metadata_charge_bytes)
    .map_err(|error| format!("soak controller metadata exceeded Control admission: {error:?}"))?;
  let sample_value_count = usize::try_from(QUALIFIED_SECONDS * 1000 / SAMPLE_INTERVAL_MS + 1)
    .map_err(|_| "fixed sample count does not fit this platform")?;
  let median_value_count = sample_value_count / 3 + 1;
  let median_bytes = median_value_count
    .checked_mul(2)
    .and_then(|count| count.checked_mul(std::mem::size_of::<u64>()))
    .ok_or("RSS median storage size overflow")?;
  let median_charge = reserve_control(&tenant, median_bytes)
    .map_err(|error| format!("RSS median storage exceeded Control admission: {error:?}"))?;
  let mut first_hour_rss = reserve_u64_vec(median_value_count)?;
  let mut final_hour_rss = reserve_u64_vec(median_value_count)?;
  let mut outputs = OutputFiles::create(&identity, &charged_ring.ring, args.comparison_mode)?;
  let readback_domain = application_domain.readback_domain();
  let fixed_global_control_baseline = application_domain.fixed_global_control_baseline();
  let session = run_native_session(
    &application_domain,
    &args,
    &charged_ring.ring,
    &mut outputs,
    &mut first_hour_rss,
    &mut final_hour_rss,
  );
  let mut session = session?;
  let mut stats = session.stats;
  if args.comparison_mode.feedback_enabled() != session.feedback_finalizer.is_some()
    || args.comparison_mode.feedback_enabled() != session.feedback_status.is_some()
  {
    return Err("soak runtime feedback status differs from the selected comparison family".into());
  }
  verify_reference_ring_unchanged(&args.reference_path, &mut charged_ring.ring)?;
  let (terminal_sha, sample_sha) = outputs.seal_streams()?;
  let first_hour_median = median(&mut first_hour_rss);
  let final_hour_median = median(&mut final_hour_rss);
  let ring_sha256 = charged_ring.ring.file_sha256;
  let ring_rows = charged_ring.ring.expected.len();
  let ring_average_rate_per_second = charged_ring.ring.average_rate_per_second;
  let first_hour_sample_count = first_hour_rss.len();
  let final_hour_sample_count = final_hour_rss.len();
  // All runtime-facing owner payloads and their charges are released before
  // the final domain check. The receipt identity and atomic file publisher are
  // external evidence-sink metadata, outside the runtime resource domain.
  drop(first_hour_rss);
  drop(final_hour_rss);
  drop(median_charge);
  drop(charged_ring);
  drop(metadata_charge);
  tenant.close();
  drop(application_domain);
  if let Some(finalizer) = session.feedback_finalizer.as_ref() {
    let rss_after_shutdown = crate::application::sample_process_memory()?;
    let at = Instant::now();
    mark_finalizer_phase(
      Some(finalizer),
      SoakTracePhase::RssAfterShutdown,
      at,
      Some(rss_after_shutdown),
    )?;
  }
  let postprocess_at = args.comparison_mode.feedback_enabled().then(Instant::now);
  if let Some(bounds) =
    finish_feedback_finalizer(session.feedback_finalizer.take(), postprocess_at)?
  {
    stats.postprocess_ended_monotonic_ns = bounds.lower_ns;
    stats.postprocess_ended_monotonic_bounds = Some(bounds);
  } else {
    stats.postprocess_ended_monotonic_ns = monotonic_ns()?;
  }
  let tenant_final = tenant
    .snapshot()
    .map_err(|error| format!("final tenant readback failed: {error:?}"))?;
  drop(tenant);
  let global_final = readback_domain.snapshot();
  stats.ended_monotonic_ns = stats.postprocess_ended_monotonic_ns;
  stats.qualified_horizon = qualifies_horizon(
    args.duration,
    args.sample_interval,
    &stats,
    first_hour_sample_count,
    final_hour_sample_count,
    first_hour_median,
    final_hour_median,
  );
  validate_final_domain(global_final, tenant_final, fixed_global_control_baseline)?;
  outputs.complete(ReceiptData {
    identity: &identity,
    args: &args,
    ring_sha256: &ring_sha256,
    ring_rows,
    ring_average_rate_per_second,
    stats: &stats,
    terminal_sha: &terminal_sha,
    sample_sha: &sample_sha,
    first_hour_median_kib: first_hour_median,
    final_hour_median_kib: final_hour_median,
    global: global_final,
    tenant: tenant_final,
    baseline_control: fixed_global_control_baseline,
    #[cfg(feature = "resource-feedback")]
    feedback: session.feedback_status,
  })?;
  drop(identity);
  drop(args);
  drop(readback_domain);
  outputs.commit();
  Ok(())
}

fn validate_external_feedback_identity(
  args: &SoakArgs,
  identity: &SoakIdentity,
) -> Result<(), String> {
  for (name, expected) in [
    ("ALLOCATBELT_APP_REPORT_NONCE", identity.nonce.as_str()),
    ("ALLOCATBELT_APP_RUN_ID", identity.run_id.as_str()),
    ("ALLOCATBELT_APP_EXECUTOR", identity.executor.as_str()),
    ("ALLOCATBELT_APP_ALLOCATOR", identity.allocator.as_str()),
    ("ALLOCATBELT_APP_WORKLOAD", "mixed"),
    ("ALLOCATBELT_APP_PROFILE", args.profile.as_str()),
    (
      "ALLOCATBELT_APP_SOURCE_SHA256",
      identity.source_sha256.as_str(),
    ),
    (
      "ALLOCATBELT_APP_BINARY_SHA256",
      identity.binary_sha256.as_str(),
    ),
  ] {
    match std::env::var(name) {
      Ok(value) if value == expected => {}
      Ok(_) => return Err(format!("{name} differs from the pinned soak identity")),
      Err(std::env::VarError::NotPresent) => {
        return Err(format!("{name} is required for external soak feedback"));
      }
      Err(std::env::VarError::NotUnicode(_)) => {
        return Err(format!("{name} is not valid Unicode"));
      }
    }
  }
  Ok(())
}

fn fixed_metadata_charge(args: &SoakArgs, identity: &SoakIdentity) -> Result<usize, String> {
  let mut bytes = std::mem::size_of::<SoakArgs>()
    .checked_add(std::mem::size_of::<SoakIdentity>())
    .and_then(|value| value.checked_add(std::mem::size_of::<ReferenceRing>()))
    .and_then(|value| value.checked_add(std::mem::size_of::<EventQueue>()))
    .and_then(|value| value.checked_add(std::mem::size_of::<StopSignal>()))
    .and_then(|value| value.checked_add(std::mem::size_of::<OperationContext>()))
    .and_then(|value| value.checked_add(std::mem::size_of::<SampleAccumulator<'static>>()))
    .and_then(|value| value.checked_add(std::mem::size_of::<ReceiptData<'static>>()))
    .and_then(|value| value.checked_add(std::mem::size_of::<OutputFiles>()))
    .and_then(|value| value.checked_add(std::mem::size_of::<SoakSessionResult>()))
    .and_then(|value| value.checked_add(std::mem::size_of::<[Option<TerminalSlot>; WINDOW]>()))
    .and_then(|value| value.checked_add(std::mem::size_of::<SoakStats>()))
    // Precharge the caller-owned poll frame and bounded RSS/I/O-row/hash scratch
    // before the selected driver publishes workers or this sampling loop runs.
    .and_then(|value| value.checked_add(MAX_ROOT_FUTURE_BYTES))
    .and_then(|value| value.checked_add(SAMPLE_SCRATCH_CONTROL_BYTES))
    .ok_or_else(|| "soak control metadata size overflow".to_owned())?;
  for capacity in [
    args.profile.capacity(),
    args.resource_ceiling_sha256.capacity(),
    args.reference_sha256.capacity(),
    identity.campaign_id.capacity(),
    identity.host_id.capacity(),
    identity.run_id.capacity(),
    identity.allocator.capacity(),
    identity.executor.capacity(),
    identity.source_sha256.capacity(),
    identity.binary_sha256.capacity(),
    identity.resource_ceiling_sha256.capacity(),
    identity.nonce.capacity(),
  ] {
    bytes = bytes
      .checked_add(capacity)
      .ok_or_else(|| "soak identity Control charge overflow".to_owned())?;
  }
  for path in [
    &args.reference_path,
    &identity.report,
    &identity.terminals,
    &identity.samples,
  ] {
    bytes = bytes
      .checked_add(std::mem::size_of::<PathBuf>())
      .and_then(|value| value.checked_add(path.as_os_str().len()))
      .ok_or_else(|| "soak path Control charge overflow".to_owned())?;
  }
  if let Some(output_dir) = &args.output_dir {
    bytes = bytes
      .checked_add(std::mem::size_of::<PathBuf>())
      .and_then(|value| value.checked_add(output_dir.as_os_str().len()))
      .ok_or_else(|| "soak output directory Control charge overflow".to_owned())?;
  }
  Ok(bytes)
}

fn reserve_u64_vec(capacity: usize) -> Result<Vec<u64>, String> {
  let mut values = Vec::new();
  values
    .try_reserve_exact(capacity)
    .map_err(|_| "RSS median allocation failed".to_owned())?;
  if values.capacity() != capacity {
    return Err("RSS median allocation exceeded its admitted capacity".into());
  }
  Ok(values)
}

fn median(values: &mut [u64]) -> Option<u64> {
  if values.is_empty() {
    return None;
  }
  values.sort_unstable();
  Some(values[values.len() / 2])
}

fn rss_growth_within_percent(
  first_hour_kib: Option<u64>,
  final_hour_kib: Option<u64>,
  percent: u32,
) -> bool {
  let (Some(first), Some(final_value)) = (first_hour_kib, final_hour_kib) else {
    return false;
  };
  first != 0 && u128::from(final_value) * 100 <= u128::from(first) * (100 + u128::from(percent))
}

fn validate_final_domain(
  global: DomainSnapshot,
  tenant: DomainSnapshot,
  baseline_control: usize,
) -> Result<(), String> {
  for (name, snapshot) in [("global", global), ("tenant", tenant)] {
    for resource in [
      DomainResource::Cpu,
      DomainResource::Memory,
      DomainResource::Disk,
      DomainResource::Network,
      DomainResource::Tasks,
    ] {
      if snapshot.used.get(resource) != 0 {
        return Err(format!("final {name} {:?} usage is nonzero", resource));
      }
    }
  }
  if global.used.get(DomainResource::Control) != baseline_control
    || tenant.used.get(DomainResource::Control) != 0
    || global.live_tenants != 0
  {
    return Err("final domain Control/live-tenant readback did not return to baseline".into());
  }
  Ok(())
}

fn validate_output_paths(paths: &[PathBuf; 3]) -> Result<(), String> {
  if paths[0] == paths[1] || paths[0] == paths[2] || paths[1] == paths[2] {
    return Err("soak report, terminal and sample paths must be distinct".into());
  }
  let parent = paths[0]
    .parent()
    .filter(|path| !path.as_os_str().is_empty())
    .unwrap_or_else(|| Path::new("."));
  if !parent.is_absolute() {
    return Err("soak output paths must be absolute".into());
  }
  for path in paths {
    if !path.is_absolute()
      || path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        != parent
    {
      return Err("soak output files must share one absolute private directory".into());
    }
    safe_basename(path)?;
  }
  let metadata = std::fs::symlink_metadata(parent)
    .map_err(|error| format!("soak output directory metadata failed: {error}"))?;
  if !metadata.is_dir() || metadata.file_type().is_symlink() {
    return Err("soak output parent must be a real directory".into());
  }
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
      return Err("soak output directory must be private to its owner".into());
    }
  }
  Ok(())
}

fn safe_basename(path: &Path) -> Result<&str, String> {
  let name = path
    .file_name()
    .and_then(|name| name.to_str())
    .ok_or_else(|| "soak output path has no UTF-8 basename".to_owned())?;
  if name.is_empty()
    || !name
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
  {
    return Err("soak output basename must use portable ASCII filename characters".into());
  }
  Ok(name)
}

fn row_number(rows: &[(String, String)], key: &str) -> Result<u64, String> {
  rows
    .iter()
    .find(|(name, _)| name == key)
    .ok_or_else(|| format!("runtime I/O readback omitted {key}"))?
    .1
    .parse::<u64>()
    .map_err(|_| format!("runtime I/O readback {key} is not a u64"))
}

fn digest_hex(digest: &[u8; 32]) -> String {
  let mut output = String::with_capacity(64);
  for byte in digest {
    use std::fmt::Write as _;
    let _ = write!(output, "{byte:02x}");
  }
  output
}

fn sha256_file(path: &Path) -> Result<[u8; 32], String> {
  let mut file = File::open(path).map_err(|error| format!("artifact open failed: {error}"))?;
  let mut hasher = Sha256::new();
  let mut buffer = [0u8; 8192];
  loop {
    let count = file
      .read(&mut buffer)
      .map_err(|error| format!("artifact read failed: {error}"))?;
    if count == 0 {
      break;
    }
    hasher.update(&buffer[..count]);
  }
  Ok(hasher.finish())
}

fn monotonic_ns() -> Result<u128, String> {
  let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
  let seconds = u128::try_from(time.tv_sec).map_err(|_| "monotonic seconds are negative")?;
  let nanos = u128::try_from(time.tv_nsec).map_err(|_| "monotonic nanoseconds are negative")?;
  seconds
    .checked_mul(1_000_000_000)
    .and_then(|base| base.checked_add(nanos))
    .ok_or_else(|| "monotonic timestamp overflow".to_owned())
}

fn process_cpu_time_ns() -> u128 {
  let time = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
  (time.tv_sec as u128) * 1_000_000_000 + time.tv_nsec as u128
}

impl EventQueue {
  fn new() -> Self {
    Self {
      state: Mutex::new(EventQueueState {
        slots: [None; WINDOW],
        read_index: 0,
        count: 0,
        waker: None,
      }),
    }
  }

  fn push(&self, event: HandlerEvent) -> Result<(), &'static str> {
    let wake = {
      let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
      if state.count == WINDOW {
        return Err("bounded HTTP completion queue filled");
      }
      let write_index = (state.read_index + state.count) % WINDOW;
      state.slots[write_index] = Some(event);
      state.count += 1;
      state.waker.take()
    };
    if let Some(waker) = wake {
      waker.wake();
    }
    Ok(())
  }

  fn poll_event(&self, cx: &mut Context<'_>) -> Poll<HandlerEvent> {
    let mut replacement = Some(cx.waker().clone());
    let (event, old_waker) = {
      let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
      if state.count != 0 {
        let index = state.read_index;
        state.read_index = (state.read_index + 1) % WINDOW;
        state.count -= 1;
        (state.slots[index].take(), None)
      } else {
        let Some(replacement) = replacement.take() else {
          return Poll::Pending;
        };
        let old_waker = state.waker.replace(replacement);
        (None, old_waker)
      }
    };
    drop(old_waker);
    drop(replacement);
    event.map_or(Poll::Pending, Poll::Ready)
  }
}

impl StopSignal {
  fn new() -> Self {
    Self {
      requested: AtomicBool::new(false),
      waker: Mutex::new(None),
      http_admission: Mutex::new(HttpAdmissionState {
        open: true,
        active: 0,
        waker: None,
      }),
    }
  }

  fn is_requested(&self) -> bool {
    self.requested.load(Ordering::Acquire)
  }

  fn request(&self) {
    self.requested.store(true, Ordering::Release);
    let stop_wake = {
      self
        .waker
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
    };
    let admission_wake = {
      self
        .http_admission
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .waker
        .take()
    };
    if let Some(waker) = stop_wake {
      waker.wake();
    }
    if let Some(waker) = admission_wake {
      waker.wake();
    }
  }

  fn register(&self, waker: &Waker) {
    let replacement = waker.clone();
    let old = {
      let mut slot = self.waker.lock().unwrap_or_else(PoisonError::into_inner);
      slot.replace(replacement)
    };
    drop(old);
    if self.is_requested() {
      self.request();
    }
  }

  fn admit_http(self: &Arc<Self>) -> Result<HttpAdmissionLease, &'static str> {
    let mut state = self
      .http_admission
      .lock()
      .unwrap_or_else(PoisonError::into_inner);
    if !state.open {
      return Err("HTTP workload admission is closed");
    }
    state.active = state
      .active
      .checked_add(1)
      .ok_or("HTTP admitted-connection count overflow")?;
    Ok(HttpAdmissionLease(Arc::clone(self)))
  }

  fn close_http_admission(&self) {
    let wake = {
      let mut state = self
        .http_admission
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
      state.open = false;
      state.waker.take()
    };
    if let Some(waker) = wake {
      waker.wake();
    }
  }

  fn poll_http_drain(&self, cx: &mut Context<'_>) -> Poll<()> {
    let mut replacement = Some(cx.waker().clone());
    let (drained, old_waker) = {
      let mut state = self
        .http_admission
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
      if !state.open && state.active == 0 {
        (true, None)
      } else {
        let Some(replacement) = replacement.take() else {
          return Poll::Pending;
        };
        (false, state.waker.replace(replacement))
      }
    };
    drop(old_waker);
    drop(replacement);
    if self.is_requested() {
      self.request();
    }
    if drained {
      Poll::Ready(())
    } else {
      Poll::Pending
    }
  }

  fn release_http_admission(&self) {
    let wake = {
      let mut state = self
        .http_admission
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
      if state.active == 0 {
        None
      } else {
        state.active -= 1;
        if !state.open && state.active == 0 {
          state.waker.take()
        } else {
          None
        }
      }
    };
    if let Some(waker) = wake {
      waker.wake();
    }
  }
}

impl Drop for HttpAdmissionLease {
  fn drop(&mut self) {
    self.0.release_http_admission();
  }
}

struct StopOnDrop(Arc<StopSignal>);

impl Drop for StopOnDrop {
  fn drop(&mut self) {
    self.0.request();
  }
}

fn run_native_session(
  application_domain: &crate::application::runtime_bindings::ApplicationDomain,
  args: &SoakArgs,
  ring: &ReferenceRing,
  outputs: &mut OutputFiles,
  first_hour_rss: &mut Vec<u64>,
  final_hour_rss: &mut Vec<u64>,
) -> Result<SoakSessionResult, String> {
  let workers = if args.profile == "oversubscribed" {
    2
  } else {
    4
  };
  let limits = application_domain.local_limits();
  let rate_configs = application_domain.rate_configs();
  let blocking = BlockingConfig {
    workers,
    max_outstanding: 64,
    capacity: Resources {
      disk: WINDOW,
      ..Resources::ZERO
    },
  };
  let builder = MultiThreadBuilder::new(AsyncConfig {
    workers,
    max_outstanding: 64,
    max_scopes: 2,
  })
  .resources(limits)
  .resource_domain(application_domain.tenant())
  .timer(2)
  .rate_timer_registrations(256)
  .blocking(blocking)
  .filesystem()
  .reactor(ReactorConfig {
    max_registrations: 2 * WINDOW + 4,
    max_waiters: 4 * WINDOW + 8,
  })
  .disk_rate(rate_configs.disk)
  .upload_rate(rate_configs.upload)
  .download_rate(rate_configs.download);
  #[cfg(feature = "resource-feedback")]
  let builder = if args.comparison_mode.feedback_enabled() {
    let factory = application_domain
      .feedback_factory()?
      .ok_or_else(|| "external soak omitted its feedback service factory".to_owned())?;
    builder.feedback_sources(factory)
  } else {
    builder
  };
  let mut driver = builder
    .build()
    .map_err(|error| format!("owning soak runtime startup failed: {error}"))?;
  let mut scope = None;
  let mut run_bindings = None;
  let mut feedback_trace = SoakFeedbackTrace::default();
  let run_result: Result<SoakStats, String> = (|| {
    let bindings = application_domain.for_native(&driver)?;
    if bindings.mode() != args.comparison_mode {
      return Err("soak runtime comparison family differs from its frozen arguments".into());
    }
    #[cfg(feature = "resource-feedback")]
    if args.comparison_mode.feedback_enabled() {
      feedback_trace = SoakFeedbackTrace::start_external(&bindings)?;
    }
    let resources = bindings.resources();
    let io = bindings.io();
    let child_scope = driver
      .scope()
      .map_err(|error| format!("soak task scope startup failed: {error}"))?;
    let handle = child_scope.handle();
    scope = Some(child_scope);
    crate::application::warm_bounded_for(&handle, workers)?;
    let blocking_handle = driver
      .blocking()
      .ok_or_else(|| "owning soak runtime omitted its blocking pool".to_owned())?;
    crate::application::disk_lane::warm_native_workers(&blocking_handle, &handle, workers)?;
    let fs_handle = driver
      .filesystem()
      .ok_or_else(|| "owning soak runtime omitted its filesystem".to_owned())?;
    let reactor = driver
      .reactor()
      .ok_or_else(|| "owning soak runtime omitted its reactor".to_owned())?;
    let timer = driver
      .timer()
      .ok_or_else(|| "owning soak runtime omitted its sampling timer".to_owned())?;
    let net = NetHandle::new(blocking_handle, resources.clone(), reactor.clone(), 1)
      .map_err(|error| format!("soak network handle startup failed: {error}"))?;
    let (listener, address) = native_listener(&reactor)?;
    #[cfg(feature = "resource-feedback")]
    let startup_observation = if args.comparison_mode.feedback_enabled() {
      Some(bindings.wait_for_feedback_startup_observation()?)
    } else {
      None
    };
    #[cfg(not(feature = "resource-feedback"))]
    if args.comparison_mode.feedback_enabled() {
      return Err("external-pressure soak requires the resource-feedback feature".into());
    }
    if args.comparison_mode.feedback_enabled() {
      let rss_before = crate::application::sample_process_memory()?;
      feedback_trace.mark_phase(SoakTracePhase::RssBefore, Instant::now(), Some(rss_before))?;
    }
    let mut stats = SoakStats::default();
    if !args.comparison_mode.feedback_enabled() {
      stats.started_monotonic_ns = monotonic_ns()?;
    }
    let started = Instant::now();
    if args.comparison_mode.feedback_enabled() {
      #[cfg(feature = "resource-feedback")]
      {
        let startup_sample = startup_observation
          .ok_or_else(|| "external soak startup telemetry observation is missing".to_owned())?;
        let production_bounds = feedback_trace
          .monotonic_bounds(started)?
          .ok_or_else(|| "external soak trace clock bounds are unavailable".to_owned())?;
        let sample_bounds = feedback_trace
          .monotonic_bounds(startup_sample)?
          .ok_or_else(|| "external soak startup TraceClock is unavailable".to_owned())?;
        bindings.validate_feedback_startup_observation(
          startup_sample,
          started,
          Some((sample_bounds.lower_ns, sample_bounds.upper_ns)),
          Some((production_bounds.lower_ns, production_bounds.upper_ns)),
        )?;
        let bounds = feedback_trace
          .mark_phase_with_bounds(SoakTracePhase::ProductionStart, started, None)?
          .ok_or_else(|| "external soak production-start TraceClock is unavailable".to_owned())?;
        if bounds != production_bounds {
          return Err(
            "soak production-start TraceClock changed across one captured Instant".into(),
          );
        }
        stats.record_endpoint(
          SoakTracePhase::ProductionStart,
          EndpointTimestamp {
            scalar_ns: bounds.lower_ns,
            bounds: Some(bounds),
          },
        );
      }
      #[cfg(not(feature = "resource-feedback"))]
      {
        return Err("external-pressure soak requires the resource-feedback feature".into());
      }
    }
    let cpu_start = process_cpu_time_ns();
    {
      let mut samples = SampleAccumulator {
        started_monotonic_ns: stats.started_monotonic_ns,
        interval: args.sample_interval,
        stats: &mut stats,
        first_hour_rss,
        final_hour_rss,
      };
      sample_runtime(&bindings, outputs, 0, &mut samples)?;
    }
    let future = drive_window(
      handle,
      listener,
      net.clone(),
      fs_handle.clone(),
      resources.clone(),
      io.clone(),
      timer,
      address,
      ring,
      args,
      outputs,
      first_hour_rss,
      final_hour_rss,
      &bindings,
      started,
      stats,
      cpu_start,
      &feedback_trace,
    );
    if std::mem::size_of_val(&future) > MAX_ROOT_FUTURE_BYTES {
      return Err("soak root future exceeded its precharged 64 KiB Control bound".into());
    }
    let driven = driver
      .block_on(future)
      .map_err(|error| format!("soak root future failed: {error}"));
    run_bindings = Some(bindings);
    let stats = driven??;
    if args.comparison_mode.feedback_enabled() {
      let rss_after_drain = crate::application::sample_process_memory()?;
      feedback_trace.mark_phase(
        SoakTracePhase::RssAfterDrain,
        Instant::now(),
        Some(rss_after_drain),
      )?;
      let drain_upper_ns = stats
        .drain_ended_monotonic_bounds
        .ok_or_else(|| "external soak omitted its drain-end clock bracket".to_owned())?
        .upper_ns;
      #[cfg(feature = "resource-feedback")]
      {
        let trace = &feedback_trace;
        run_bindings
          .as_ref()
          .ok_or_else(|| "external soak lost its feedback bindings after drain".to_owned())?
          .wait_for_feedback_observation_after(drain_upper_ns, |sample_at| {
            trace
              .monotonic_bounds(sample_at)?
              .map(|bounds| (bounds.lower_ns, bounds.upper_ns))
              .ok_or_else(|| "external soak post-drain sample lost its TraceClock".to_owned())
          })?;
      }
      #[cfg(not(feature = "resource-feedback"))]
      {
        let _ = drain_upper_ns;
        return Err("external-pressure soak requires the resource-feedback feature".into());
      }
    }
    Ok(stats)
  })();
  let shutdown_result = shutdown_native(&mut driver, scope.take());
  let feedback_shutdown_result = if args.comparison_mode.feedback_enabled() {
    run_bindings.as_mut().map_or(Ok(()), |bindings| {
      bindings.shutdown_feedback(Duration::from_secs(60))
    })
  } else {
    Ok(())
  };
  let timer_shutdown_result = if args.comparison_mode.feedback_enabled() {
    run_bindings
      .as_mut()
      .map_or(Ok(()), |bindings| bindings.shutdown_auxiliary_timer())
  } else {
    Ok(())
  };
  let mut shutdown_endpoint = None;
  let shutdown_phase_result = if args.comparison_mode.feedback_enabled() {
    if feedback_trace.has_collector() {
      match feedback_trace.capture_endpoint(SoakTracePhase::ShutdownEnd) {
        Ok(endpoint) => {
          shutdown_endpoint = Some(endpoint);
          Ok(())
        }
        Err(error) => Err(error),
      }
    } else {
      feedback_trace.mark_phase(SoakTracePhase::ShutdownEnd, Instant::now(), None)
    }
  } else {
    Ok(())
  };
  let feedback_finalizer = feedback_trace.stop_for_finalization()?;
  let feedback_status: Option<FeedbackSoakStatus> = if args.comparison_mode.feedback_enabled() {
    #[cfg(feature = "resource-feedback")]
    {
      let bindings = run_bindings
        .as_ref()
        .ok_or_else(|| "external soak lost its owning runtime bindings".to_owned())?;
      let (joined, worker_failure) = bindings.feedback_shutdown_status().ok_or_else(|| {
        "external soak feedback metrics were not retained through shutdown".to_owned()
      })?;
      Some(FeedbackSoakStatus {
        started: bindings.feedback_started(),
        joined,
        worker_failure: worker_failure.map(feedback_failure_label),
        trace_worker_joined: feedback_finalizer.is_some(),
      })
    }
    #[cfg(not(feature = "resource-feedback"))]
    {
      return Err("external-pressure soak requires the resource-feedback feature".into());
    }
  } else {
    None
  };
  let feedback_health_result = if args.comparison_mode.feedback_enabled() {
    run_bindings.as_ref().map_or(Ok(()), |bindings| {
      bindings.validate_feedback_health("after_shutdown")
    })
  } else {
    Ok(())
  };
  let quiet_result = run_bindings.as_ref().map_or(Ok(()), validate_runtime_quiet);
  drop(run_bindings);
  drop(driver);
  let mut stats = run_result?;
  shutdown_result?;
  feedback_shutdown_result?;
  timer_shutdown_result?;
  shutdown_phase_result?;
  feedback_health_result?;
  quiet_result?;
  if let Some(endpoint) = shutdown_endpoint {
    stats.record_endpoint(SoakTracePhase::ShutdownEnd, endpoint);
  } else {
    stats.shutdown_ended_monotonic_ns = monotonic_ns()?;
  }
  stats.ended_monotonic_ns = stats.shutdown_ended_monotonic_ns;
  if let Some(status) = feedback_status
    && (!status.started
      || !status.joined
      || status.worker_failure.is_some()
      || !status.trace_worker_joined)
  {
    return Err("external soak feedback or trace worker did not finish cleanly".into());
  }
  Ok(SoakSessionResult {
    stats,
    feedback_finalizer,
    feedback_status,
  })
}

fn validate_runtime_quiet(
  bindings: &crate::application::runtime_bindings::ApplicationRunBindings,
) -> Result<(), String> {
  let (global, tenant, scope) = bindings.snapshots()?;
  for (name, snapshot) in [("global", global), ("tenant", tenant)] {
    for resource in [
      DomainResource::Cpu,
      DomainResource::Memory,
      DomainResource::Disk,
      DomainResource::Network,
      DomainResource::Tasks,
    ] {
      if snapshot.used.get(resource) != 0 {
        return Err(format!(
          "runtime shutdown left {name} {:?} charged",
          resource
        ));
      }
    }
  }
  if scope.managed_memory != 0 || scope.disk_ops != 0 || scope.network_ops != 0 {
    return Err("runtime shutdown left managed scope resources charged".into());
  }
  let rows = bindings.io().readback_rows();
  for key in [
    "disk_reserved_bytes",
    "disk_reservations",
    "upload_reserved_bytes",
    "upload_reservations",
    "download_reserved_bytes",
    "download_reservations",
  ] {
    if row_number(&rows, key)? != 0 {
      return Err(format!("runtime shutdown left {key} charged"));
    }
  }
  Ok(())
}

fn shutdown_native(
  driver: &mut MultiThreadDriver,
  scope: Option<allocatbelt::runtime::asynchronous::OwnedTaskScope>,
) -> Result<(), String> {
  let mut failure = None;
  if let Some(scope) = scope {
    match driver.block_on(scope.close()) {
      Ok(()) => {}
      Err(error) => failure = Some(format!("soak scope close root failed: {error}")),
    }
  }
  if let Err(error) = driver.request_shutdown(MultiShutdown {
    tasks: AsyncShutdown::Drain,
    blocking: ShutdownMode::Drain,
    processes: ProcessShutdownMode::Wait,
  }) {
    failure.get_or_insert_with(|| format!("soak runtime shutdown request failed: {error}"));
  }
  let deadline = Instant::now() + Duration::from_secs(60);
  loop {
    match driver.drive_shutdown_step() {
      Ok(ShutdownProgress::Complete) => break,
      Ok(ShutdownProgress::Pending) => {
        if Instant::now() >= deadline {
          failure.get_or_insert_with(|| "soak runtime shutdown exceeded 60 seconds".to_owned());
          break;
        }
        std::thread::yield_now();
      }
      Err(error) => {
        failure.get_or_insert_with(|| format!("soak runtime shutdown failed: {error}"));
        break;
      }
    }
  }
  failure.map_or(Ok(()), Err)
}

#[derive(Debug)]
enum Progress {
  Operation(usize),
  Handler(HandlerEvent),
  Timer(Result<(), &'static str>),
  Acceptor(Result<Result<(), &'static str>, AsyncJoinError>),
}

#[allow(clippy::too_many_arguments)]
async fn drive_window(
  handle: AsyncHandle,
  listener: NativeListener,
  net: NetHandle,
  fs_handle: FsHandle,
  resources: ResourceScope,
  io: crate::application::runtime_bindings::ApplicationIoBindings,
  timer: TimerHandle,
  address: SocketAddrV4,
  ring: &ReferenceRing,
  args: &SoakArgs,
  outputs: &mut OutputFiles,
  first_hour_rss: &mut Vec<u64>,
  final_hour_rss: &mut Vec<u64>,
  bindings: &crate::application::runtime_bindings::ApplicationRunBindings,
  started: Instant,
  mut stats: SoakStats,
  cpu_start: u128,
  feedback_trace: &SoakFeedbackTrace,
) -> Result<SoakStats, String> {
  let events = Arc::new(EventQueue::new());
  let stop = Arc::new(StopSignal::new());
  let _stop_on_drop = StopOnDrop(Arc::clone(&stop));
  let acceptor = handle
    .spawn(accept_http(
      listener,
      handle.clone(),
      resources.clone(),
      io.clone(),
      timer.clone(),
      Arc::clone(&events),
      Arc::clone(&stop),
    ))
    .map_err(|error| format!("soak HTTP acceptor admission failed: {}", error.kind))?;
  let deadline = started
    .checked_add(args.duration)
    .ok_or_else(|| "soak duration deadline overflow".to_owned())?;
  let drain_deadline = deadline
    .checked_add(Duration::from_secs(5))
    .ok_or_else(|| "soak drain deadline overflow".to_owned())?;
  let mut next_sample_index = 1u64;
  let first_sample = started
    .checked_add(args.sample_interval)
    .ok_or_else(|| "first soak sample deadline overflow".to_owned())?;
  let mut sleep = timer
    .sleep_until(first_sample)
    .map_err(|error| format!("soak sample timer registration failed: {error:?}"))?;
  let mut slots: [Option<TerminalSlot>; WINDOW] = std::array::from_fn(|_| None);
  let mut next_global_id = 0u64;
  let mut next_terminal_id = 0u64;
  let mut acceptor = Some(acceptor);
  let mut acceptor_finished = false;
  let mut stopping = false;
  let mut production_cpu_started = false;
  let mut final_sample_written = false;
  stats.production_cpu_started_ns = cpu_start;

  loop {
    if !stopping && Instant::now() >= deadline {
      stopping = true;
      stop.close_http_admission();
      let endpoint = feedback_trace.capture_endpoint(SoakTracePhase::ProductionEnd)?;
      stats.record_endpoint(SoakTracePhase::ProductionEnd, endpoint);
    }
    if !stopping {
      while let Some(index) = slots.iter().position(Option::is_none) {
        let elapsed = Instant::now().saturating_duration_since(started);
        if Instant::now() >= deadline || !burst_admission_open(&args.profile, elapsed) {
          break;
        }
        let reference_work_id = next_global_id % ring.expected.len() as u64;
        let expected_checksum = *ring
          .expected
          .get(reference_work_id as usize)
          .ok_or_else(|| "soak reference work ID is outside the frozen ring".to_owned())?;
        let inputs = crate::application::canonical_soak_inputs(reference_work_id);
        let family = match inputs.family {
          crate::application::Workload::Cpu => Family::Cpu,
          crate::application::Workload::Memory => Family::Memory,
          crate::application::Workload::Http => Family::Http,
          crate::application::Workload::Disk => Family::Disk,
          crate::application::Workload::Mixed => {
            return Err("canonical soak input returned nested mixed workload".into());
          }
        };
        let http_admission = if family == Family::Http {
          Some(
            stop
              .admit_http()
              .map_err(|error| format!("soak HTTP admission failed: {error}"))?,
          )
        } else {
          None
        };
        let job = match handle.spawn(operation_future(
          family,
          inputs,
          reference_work_id,
          OperationContext {
            net: net.clone(),
            fs_handle: fs_handle.clone(),
            resources: resources.clone(),
            io: io.clone(),
            address,
            http_admission,
          },
        )) {
          Ok(job) => job,
          Err(error) if error.kind == AsyncError::Full => break,
          Err(error) => {
            return Err(format!(
              "soak operation admission failed: {} at global ID {next_global_id}",
              error.kind
            ));
          }
        };
        slots[index] = Some(TerminalSlot {
          global_id: next_global_id,
          reference_work_id,
          family,
          expected_checksum,
          job: Some(job),
          client_checksum: None,
          handler_checksum: None,
          ready_checksum: None,
        });
        stats.attempted = stats
          .attempted
          .checked_add(1)
          .ok_or_else(|| "soak operation count overflow".to_owned())?;
        next_global_id = next_global_id
          .checked_add(1)
          .ok_or_else(|| "soak global observation ID overflow".to_owned())?;
      }
    }
    if !production_cpu_started
      && Instant::now().saturating_duration_since(started) >= Duration::from_secs(WARMUP_SECONDS)
    {
      stats.production_cpu_started_ns = process_cpu_time_ns();
      production_cpu_started = true;
    }
    if drain_is_complete(
      stopping,
      final_sample_written,
      slots.iter().all(Option::is_none),
      acceptor_finished,
    ) {
      if feedback_trace.has_collector() {
        stats.production_cpu_ended_ns = process_cpu_time_ns();
        let endpoint = feedback_trace.capture_endpoint(SoakTracePhase::DrainEnd)?;
        stats.record_endpoint(SoakTracePhase::DrainEnd, endpoint);
      } else {
        stats.drain_ended_monotonic_ns = monotonic_ns()?;
        stats.production_cpu_ended_ns = process_cpu_time_ns();
        feedback_trace.mark_phase(SoakTracePhase::DrainEnd, Instant::now(), None)?;
      }
      break;
    }

    let progress = poll_fn(|cx| {
      if let Poll::Ready(result) = Pin::new(&mut sleep).poll(cx) {
        return Poll::Ready(Progress::Timer(result.map_err(|_| "sample timer closed")));
      }
      if let Poll::Ready(event) = events.poll_event(cx) {
        return Poll::Ready(Progress::Handler(event));
      }
      if let Some(job) = acceptor.as_mut()
        && let Poll::Ready(result) = Pin::new(job).poll(cx)
      {
        acceptor.take();
        return Poll::Ready(Progress::Acceptor(result));
      }
      for (index, slot) in slots.iter_mut().enumerate() {
        if let Some(slot) = slot
          && let Some(job) = slot.job.as_mut()
          && let Poll::Ready(result) = Pin::new(job).poll(cx)
        {
          let result = match result {
            Ok(result) => result,
            Err(_) => Err("soak operation task was cancelled"),
          };
          slot.client_checksum = Some(result);
          slot.job.take();
          return Poll::Ready(Progress::Operation(index));
        }
      }
      Poll::Pending
    })
    .await;

    match progress {
      Progress::Operation(index) => {
        finish_ready_slot(
          index,
          &mut slots,
          outputs,
          &mut stats,
          &mut next_terminal_id,
        )?;
      }
      Progress::Handler(event) => {
        finish_handler_event(
          event,
          &mut slots,
          outputs,
          &mut stats,
          &mut next_terminal_id,
        )?;
      }
      Progress::Acceptor(result) => match result {
        Ok(Ok(())) if stopping => acceptor_finished = true,
        Ok(Ok(())) => return Err("soak HTTP acceptor stopped before the horizon".into()),
        Ok(Err(error)) => return Err(format!("soak HTTP acceptor failed: {error}")),
        Err(error) => return Err(format!("soak HTTP acceptor join failed: {error}")),
      },
      Progress::Timer(Ok(())) => {
        if final_sample_written {
          return Err("soak workload did not drain within five seconds of the horizon".into());
        }
        let now_elapsed = Instant::now().saturating_duration_since(started);
        let final_sample_due = next_sample_index
          .checked_mul(args.sample_interval.as_millis() as u64)
          .is_some_and(|elapsed_ms| elapsed_ms >= args.duration.as_millis() as u64);
        {
          let mut samples = SampleAccumulator {
            started_monotonic_ns: stats.started_monotonic_ns,
            interval: args.sample_interval,
            stats: &mut stats,
            first_hour_rss,
            final_hour_rss,
          };
          sample_runtime(bindings, outputs, next_sample_index, &mut samples)?;
        }
        if final_sample_due {
          final_sample_written = true;
          sleep
            .reset(drain_deadline)
            .map_err(|error| format!("soak drain watchdog registration failed: {error:?}"))?;
        } else {
          let interval = args.sample_interval.as_nanos();
          let elapsed = interval
            .checked_mul(u128::from(next_sample_index + 1))
            .ok_or_else(|| "soak next-sample offset overflow".to_owned())?;
          let elapsed = Duration::from_nanos(
            u64::try_from(elapsed).map_err(|_| "soak next-sample deadline does not fit")?,
          );
          let next = started
            .checked_add(elapsed)
            .ok_or_else(|| "soak next-sample deadline overflow".to_owned())?;
          sleep
            .reset(next)
            .map_err(|error| format!("soak next-sample timer reset failed: {error:?}"))?;
          next_sample_index = next_sample_index
            .checked_add(1)
            .ok_or_else(|| "soak sample index overflow".to_owned())?;
        }
        if now_elapsed >= args.duration && !stopping {
          stopping = true;
          stop.close_http_admission();
          let endpoint = feedback_trace.capture_endpoint(SoakTracePhase::ProductionEnd)?;
          stats.record_endpoint(SoakTracePhase::ProductionEnd, endpoint);
        }
        if final_sample_due && stopping && Instant::now() >= drain_deadline {
          return Err("soak drain exceeded its five-second bound".into());
        }
      }
      Progress::Timer(Err(error)) => return Err(error.into()),
    }
    if stopping
      && Instant::now() >= drain_deadline
      && !(slots.iter().all(Option::is_none) && acceptor_finished)
    {
      return Err("soak active work did not drain within five seconds".into());
    }
  }
  drop(_stop_on_drop);
  Ok(stats)
}

fn sample_runtime(
  bindings: &crate::application::runtime_bindings::ApplicationRunBindings,
  outputs: &mut OutputFiles,
  sample_index: u64,
  accumulator: &mut SampleAccumulator<'_>,
) -> Result<u128, String> {
  let rss_kib = crate::application::sample_process_memory()?.rss_kib;
  let (global, tenant, scope) = bindings.snapshots()?;
  let io_rows = bindings.io().readback_rows();
  let timestamp = monotonic_ns()?;
  if !sample_cadence_matches(
    sample_index,
    accumulator.interval,
    accumulator.started_monotonic_ns,
    timestamp,
  ) {
    return Err(format!(
      "soak sample {sample_index} missed its 100 ms monotonic cadence"
    ));
  }
  outputs.sample(timestamp, rss_kib, global, tenant, scope, &io_rows)?;
  drop(io_rows);
  let scheduled_elapsed = accumulator
    .interval
    .as_nanos()
    .checked_mul(u128::from(sample_index))
    .ok_or_else(|| "sample window offset overflow".to_owned())?;
  match rss_window(scheduled_elapsed) {
    Some(RssWindow::FirstPostWarmupHour) => {
      if accumulator.first_hour_rss.len() == accumulator.first_hour_rss.capacity() {
        return Err("first-hour RSS median sample bound was exceeded".into());
      }
      accumulator.first_hour_rss.push(rss_kib);
    }
    Some(RssWindow::FinalHour) => {
      if accumulator.final_hour_rss.len() == accumulator.final_hour_rss.capacity() {
        return Err("final-hour RSS median sample bound was exceeded".into());
      }
      accumulator.final_hour_rss.push(rss_kib);
    }
    None => {}
  }
  accumulator.stats.sample_count = accumulator
    .stats
    .sample_count
    .checked_add(1)
    .ok_or_else(|| "soak sample count overflow".to_owned())?;
  Ok(timestamp)
}

fn finish_ready_slot(
  index: usize,
  slots: &mut [Option<TerminalSlot>; WINDOW],
  outputs: &mut OutputFiles,
  stats: &mut SoakStats,
  next_terminal_id: &mut u64,
) -> Result<(), String> {
  let Some(slot) = slots[index].as_mut() else {
    return Err("soak observer completed an empty logical slot".into());
  };
  if slot.ready_checksum.is_some() {
    return flush_ordered_terminals(slots, outputs, stats, next_terminal_id);
  }
  let Some(client_result) = slot.client_checksum.as_ref() else {
    return Ok(());
  };
  let observed = match client_result {
    Ok(checksum) => *checksum,
    Err(_) => {
      return Err("soak application operation failed".into());
    }
  };
  let final_checksum = if slot.family == Family::Http {
    let Some(handler_checksum) = slot.handler_checksum else {
      return Ok(());
    };
    if handler_checksum != observed {
      return Err("soak HTTP client/server checksums differ".into());
    }
    handler_checksum
  } else {
    observed
  };
  if final_checksum != slot.expected_checksum {
    return Err(format!(
      "soak result differs from the external reference at global ID {}",
      slot.global_id
    ));
  }
  slot.ready_checksum = Some(final_checksum);
  flush_ordered_terminals(slots, outputs, stats, next_terminal_id)
}

fn finish_handler_event(
  event: HandlerEvent,
  slots: &mut [Option<TerminalSlot>; WINDOW],
  outputs: &mut OutputFiles,
  stats: &mut SoakStats,
  next_terminal_id: &mut u64,
) -> Result<(), String> {
  if let Some(failure) = event.failure {
    return Err(format!("soak HTTP handler failed: {failure}"));
  }
  let index = slots
    .iter_mut()
    .position(|slot| {
      slot.as_ref().is_some_and(|slot| {
        slot.family == Family::Http
          && slot.reference_work_id == event.reference_work_id
          && slot.handler_checksum.is_none()
      })
    })
    .ok_or_else(|| "soak HTTP handler completion had no live client".to_owned())?;
  let slot = slots[index]
    .as_mut()
    .ok_or_else(|| "soak HTTP handler slot disappeared".to_owned())?;
  slot.handler_checksum = Some(event.checksum);
  finish_ready_slot(index, slots, outputs, stats, next_terminal_id)
}

fn flush_ordered_terminals(
  slots: &mut [Option<TerminalSlot>; WINDOW],
  outputs: &mut OutputFiles,
  stats: &mut SoakStats,
  next_terminal_id: &mut u64,
) -> Result<(), String> {
  loop {
    let ready = slots.iter().enumerate().find_map(|(index, slot)| {
      let slot = slot.as_ref()?;
      let checksum = slot.ready_checksum?;
      (slot.global_id == *next_terminal_id).then_some((
        index,
        slot.global_id,
        slot.reference_work_id,
        slot.family,
        checksum,
        slot.expected_checksum,
      ))
    });
    let Some((index, global_id, reference_work_id, family, checksum, expected)) = ready else {
      return Ok(());
    };
    outputs.terminal(global_id, reference_work_id, family, checksum, expected)?;
    slots[index] = None;
    stats.completed = stats
      .completed
      .checked_add(1)
      .ok_or_else(|| "soak completion count overflow".to_owned())?;
    *next_terminal_id = next_terminal_id
      .checked_add(1)
      .ok_or_else(|| "soak terminal ID overflow".to_owned())?;
  }
}

#[allow(clippy::too_many_arguments)]
async fn accept_http(
  listener: NativeListener,
  handle: AsyncHandle,
  resources: ResourceScope,
  io: crate::application::runtime_bindings::ApplicationIoBindings,
  timer: TimerHandle,
  events: Arc<EventQueue>,
  stop: Arc<StopSignal>,
) -> Result<(), &'static str> {
  let mut handlers: [Option<AsyncJob<Result<HandlerEvent, &'static str>>>; WINDOW] =
    std::array::from_fn(|_| None);
  loop {
    let can_accept = handlers.iter().any(Option::is_none);
    let mut accepted_future = std::pin::pin!(accept_until_stopped(&listener, &stop));
    let progress = poll_fn(|cx| {
      if stop.is_requested() {
        return Poll::Ready(AcceptorProgress::Stop);
      }
      for handler_slot in &mut handlers {
        let completed = match handler_slot.as_mut() {
          Some(handler) => match Pin::new(handler).poll(cx) {
            Poll::Ready(result) => Some(result),
            Poll::Pending => None,
          },
          None => None,
        };
        if let Some(result) = completed {
          handler_slot.take();
          return Poll::Ready(AcceptorProgress::Handler(result));
        }
      }
      let drained = stop.poll_http_drain(cx).is_ready();
      if drained && handlers.iter().all(Option::is_none) {
        return Poll::Ready(AcceptorProgress::Stop);
      }
      if drained || !can_accept {
        return Poll::Pending;
      }
      match accepted_future.as_mut().poll(cx) {
        Poll::Ready(result) => Poll::Ready(AcceptorProgress::Connection(result)),
        Poll::Pending => Poll::Pending,
      }
    })
    .await;

    let (free_index, stream) = match progress {
      AcceptorProgress::Handler(result) => {
        publish_joined_handler_result(result, &events)?;
        continue;
      }
      AcceptorProgress::Connection(Ok(Some((stream, _peer)))) => (
        handlers
          .iter()
          .position(Option::is_none)
          .ok_or("HTTP handler window was full after accept")?,
        stream,
      ),
      AcceptorProgress::Connection(Ok(None)) | AcceptorProgress::Stop => break,
      AcceptorProgress::Connection(Err(error)) => return Err(error),
    };
    let handler_resources = resources.clone();
    let handler_io = io.clone();
    let endpoint_permit = resources
      .try_acquire(OperationRequest {
        disk: 0,
        network: 1,
      })
      .map_err(|_| "HTTP handler endpoint admission failed")?;
    let mut handler_future = Some(async move {
      let result = async move {
        let endpoint = NativeEndpoint {
          stream,
          _permit: endpoint_permit,
        };
        let mut endpoint = handler_io
          .rate_io(endpoint)
          .map_err(|_| "HTTP handler byte-rate adapter failed")?;
        http::serve_connection_io(&mut endpoint, &handler_resources)
          .await
          .map_err(|_| "HTTP server kernel rejected the request")
      }
      .await;
      let event = match result {
        Ok((reference_work_id, checksum)) => HandlerEvent {
          reference_work_id,
          checksum,
          failure: None,
        },
        Err(failure) => HandlerEvent {
          reference_work_id: u64::MAX,
          checksum: 0,
          failure: Some(failure),
        },
      };
      Ok(event)
    });
    let handler_job = loop {
      let future = handler_future
        .take()
        .ok_or("HTTP handler future was lost before admission")?;
      match handle.spawn(future) {
        Ok(job) => break job,
        Err(error) if error.kind == AsyncError::Full => {
          handler_future = Some(error.into_future());
          timer
            .sleep(Duration::from_millis(1))
            .map_err(|_| "HTTP handler retry timer admission failed")?
            .await
            .map_err(|_| "HTTP handler retry timer closed")?;
        }
        Err(_) => return Err("HTTP handler task admission closed"),
      }
    };
    handlers[free_index] = Some(handler_job);
  }
  for handler in &mut handlers {
    if let Some(handler) = handler.take() {
      publish_joined_handler(handler, &events).await?;
    }
  }
  Ok(())
}

async fn publish_joined_handler(
  handler: AsyncJob<Result<HandlerEvent, &'static str>>,
  events: &EventQueue,
) -> Result<(), &'static str> {
  publish_joined_handler_result(handler.await, events)
}

fn publish_joined_handler_result(
  joined: Result<Result<HandlerEvent, &'static str>, AsyncJoinError>,
  events: &EventQueue,
) -> Result<(), &'static str> {
  let event = joined.map_err(|_| "HTTP handler task was cancelled")??;
  events.push(event)
}

async fn accept_until_stopped(
  listener: &NativeListener,
  stop: &StopSignal,
) -> Result<Option<(NativeStream, SocketAddr)>, &'static str> {
  let mut accepted = std::pin::pin!(listener.accept());
  poll_fn(|cx| {
    if stop.is_requested() {
      return Poll::Ready(Ok(None));
    }
    match accepted.as_mut().poll(cx) {
      Poll::Ready(Ok(connection)) => Poll::Ready(Ok(Some(connection))),
      Poll::Ready(Err(_)) => Poll::Ready(Err("HTTP listener accept failed")),
      Poll::Pending => {
        stop.register(cx.waker());
        if stop.is_requested() {
          Poll::Ready(Ok(None))
        } else {
          Poll::Pending
        }
      }
    }
  })
  .await
}

async fn operation_future(
  family: Family,
  inputs: crate::application::CanonicalSoakInputs,
  reference_work_id: u64,
  context: OperationContext,
) -> Result<u64, &'static str> {
  let OperationContext {
    net,
    fs_handle,
    resources,
    io,
    address,
    http_admission,
  } = context;
  let _http_admission = http_admission;
  match family {
    Family::Cpu => Ok(cpu::kernel(inputs.cpu_seed, inputs.cpu_rounds)),
    Family::Memory => {
      let output = memory::run_operation(&resources, inputs.memory)
        .map_err(|_| "memory port operation failed")?;
      let checksum = output.report.checksum;
      drop(output);
      Ok(checksum)
    }
    Family::Http => {
      if inputs.http_body_bytes != 4096 {
        return Err("canonical HTTP body length differs from the frozen 4096-byte body");
      }
      let stream = net
        .connect_nonblocking(SocketAddr::V4(address))
        .await
        .map_err(|_| "HTTP nonblocking connect failed")?;
      let permit = resources
        .try_acquire(OperationRequest {
          disk: 0,
          network: 1,
        })
        .map_err(|_| "HTTP client endpoint admission failed")?;
      let endpoint = NativeEndpoint {
        stream,
        _permit: permit,
      };
      let mut endpoint = io
        .rate_io(endpoint)
        .map_err(|_| "HTTP client byte-rate adapter failed")?;
      http::transact_client_io(
        &mut endpoint,
        &resources,
        reference_work_id,
        HttpConfig {
          body_bytes: inputs.http_body_bytes,
          seed: inputs.http_seed,
        },
      )
      .await
      .map_err(|_| "HTTP client kernel failed")
    }
    Family::Disk => disk::run_operation(&fs_handle, &resources, inputs.disk)
      .await
      .map(|report| report.checksum)
      .map_err(|_| "disk port operation failed"),
  }
}

fn native_listener(
  reactor: &allocatbelt::runtime::reactor::ReactorHandle,
) -> Result<(NativeListener, SocketAddrV4), String> {
  let listener = StdTcpListener::bind(("127.0.0.1", 0))
    .map_err(|error| format!("soak loopback listener bind failed: {error}"))?;
  let address = listener
    .local_addr()
    .map_err(|error| format!("soak listener address read failed: {error}"))?;
  let SocketAddr::V4(address) = address else {
    return Err("soak listener did not bind IPv4".into());
  };
  if !address.ip().is_loopback() {
    return Err("soak listener is outside IPv4 loopback".into());
  }
  let listener = NativeListener::from_std(listener, reactor)
    .map_err(|error| format!("soak listener reactor registration failed: {}", error.error))?;
  Ok((listener, address))
}

struct NativeEndpoint {
  stream: NativeStream,
  _permit: OperationPermit,
}

impl AsyncRead for NativeEndpoint {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buffer: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.get_mut().stream).poll_read(cx, buffer)
  }
}

impl AsyncWrite for NativeEndpoint {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buffer: &[u8],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.get_mut().stream).poll_write(cx, buffer)
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.get_mut().stream).poll_flush(cx)
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
  }
}

#[cfg(test)]
#[path = "soak_tests.rs"]
mod tests;
