//! Bounded streaming capture of the owning external-pressure feedback service.

use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use allocatbelt::runtime::byte_rate::{ByteRateLimit, ByteRateSnapshot};
use allocatbelt::runtime::managed::{ResourceScope, ResourceSnapshot};
use allocatbelt::runtime::resource_domain::{
  DomainReservation, DomainResource, DomainSnapshot, ResourceDomain, TenantDomain,
};
use allocatbelt::runtime::resource_feedback::{
  FeedbackEvent, FeedbackEventKind, FeedbackHistoryError, FeedbackMetricsHandle,
  FeedbackMetricsSnapshot,
};
use allocatbelt::runtime::resource_feedback_meter::{IoFeedbackMeter, IoFeedbackMeterSnapshot};
use allocatbelt::runtime::resource_feedback_policy::{
  ACTUATION_COOLDOWN, FeedbackResource, SAMPLE_INTERVAL as FEEDBACK_SAMPLE_INTERVAL,
};

use super::ProcessMemory;
use super::runtime_bindings::ApplicationTaskLease;
use super::runtime_bindings::FeedbackTraceHasher;

#[path = "feedback_trace_events.rs"]
mod feedback_trace_events;
#[path = "trace_clock.rs"]
mod trace_clock;
#[path = "trace_file.rs"]
mod trace_file;

use feedback_trace_events::encode_event;
use trace_clock::TraceClock;
use trace_file::TraceFile;

pub(super) const EVENT_SCHEMA: &str = feedback_trace_events::EVENT_SCHEMA;
pub(super) const RESOURCE_SAMPLE_SCHEMA: &str =
  "allocatbelt.application-feedback-resource-sample.v1";
pub(super) const TRACE_MANIFEST_SCHEMA: &str = "allocatbelt.application-feedback-trace-manifest.v1";

pub(super) const TRACE_HISTORY_CAPACITY: usize = 16_384;
const HISTORY_READ_BATCH: usize = 128;
const EVENT_RECORD_BYTES: usize = 2 * 1024;
const SAMPLE_RECORD_BYTES: usize = 8 * 1024;
const MANIFEST_BYTES: usize = 16 * 1024;
const PROC_STATUS_BYTES: usize = 4 * 1024;
const MAX_TRACE_PATH_BYTES: usize = 3 * 1024;
const MAX_TRACE_FILE_SUFFIX_BYTES: usize = 64;
const MAX_TRACE_HORIZON_SECONDS: u64 = 11_400;
const SAMPLE_INTERVAL: Duration = FEEDBACK_SAMPLE_INTERVAL;
const SAMPLES_PER_SECOND: u64 = 1_000_000_000 / SAMPLE_INTERVAL.as_nanos() as u64;
const MAX_SAMPLE_CYCLES: u64 = MAX_TRACE_HORIZON_SECONDS * SAMPLES_PER_SECOND + 1;
const MAX_SAMPLE_ROWS: u64 = MAX_SAMPLE_CYCLES + 1;
const MAX_TICKETS_PER_CONTROL: u64 =
  MAX_TRACE_HORIZON_SECONDS * 1_000 / ACTUATION_COOLDOWN.as_millis() as u64 + 1;
const MAX_EVENT_RECORDS: u64 = MAX_SAMPLE_CYCLES * 3 + 3 * MAX_TICKETS_PER_CONTROL * 4 + 100;
const MAX_EVENT_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SAMPLE_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_MANIFEST_FILE_BYTES: u64 = 64 * 1024;
const TRACE_HORIZON: Duration = Duration::from_secs(MAX_TRACE_HORIZON_SECONDS);
const FINISH_TIMEOUT: Duration = Duration::from_secs(5);
const DROP_WAIT: Duration = Duration::from_millis(250);
const MAX_IDENTITY_TEXT: usize = 256;

const SAMPLE_HEADER: &str = concat!(
  "schema\tallocatbelt.application-feedback-resource-sample.v1\n",
  "sample_sequence\twindow_lower_ns\twindow_upper_ns\trss_kib\thwm_kib",
  "\tcollector_task_lease_count",
  "\tglobal_ceiling_cpu\tglobal_limit_cpu\tglobal_used_cpu",
  "\tglobal_ceiling_memory\tglobal_limit_memory\tglobal_used_memory",
  "\tglobal_ceiling_disk\tglobal_limit_disk\tglobal_used_disk",
  "\tglobal_ceiling_network\tglobal_limit_network\tglobal_used_network",
  "\tglobal_ceiling_tasks\tglobal_limit_tasks\tglobal_used_tasks",
  "\tglobal_ceiling_control\tglobal_limit_control\tglobal_used_control",
  "\ttenant_ceiling_cpu\ttenant_limit_cpu\ttenant_used_cpu",
  "\ttenant_ceiling_memory\ttenant_limit_memory\ttenant_used_memory",
  "\ttenant_ceiling_disk\ttenant_limit_disk\ttenant_used_disk",
  "\ttenant_ceiling_network\ttenant_limit_network\ttenant_used_network",
  "\ttenant_ceiling_tasks\ttenant_limit_tasks\ttenant_used_tasks",
  "\ttenant_ceiling_control\ttenant_limit_control\ttenant_used_control",
  "\tscope_managed_memory_limit\tscope_disk_operation_limit",
  "\tscope_network_operation_limit\tscope_managed_memory_used",
  "\tscope_disk_operations_used\tscope_network_operations_used",
  "\tdisk_rate_bytes_per_second\tdisk_rate_burst_bytes",
  "\tdisk_rate_ceiling_bytes_per_second\tdisk_rate_ceiling_burst_bytes",
  "\tdisk_rate_max_reservations\tdisk_rate_available_bytes",
  "\tdisk_rate_reserved_bytes\tdisk_rate_reservations",
  "\tupload_rate_bytes_per_second\tupload_rate_burst_bytes",
  "\tupload_rate_ceiling_bytes_per_second\tupload_rate_ceiling_burst_bytes",
  "\tupload_rate_max_reservations\tupload_rate_available_bytes",
  "\tupload_rate_reserved_bytes\tupload_rate_reservations",
  "\tdownload_rate_bytes_per_second\tdownload_rate_burst_bytes",
  "\tdownload_rate_ceiling_bytes_per_second\tdownload_rate_ceiling_burst_bytes",
  "\tdownload_rate_max_reservations\tdownload_rate_available_bytes",
  "\tdownload_rate_reserved_bytes\tdownload_rate_reservations",
  "\tdisk_meter_measured_lower_ns\tdisk_meter_measured_upper_ns",
  "\tdisk_meter_committed_bytes\tdisk_meter_completions",
  "\tdisk_meter_attached_sources\tdisk_meter_generation",
  "\tdisk_meter_counter_overflow\tdisk_meter_invalid_io",
  "\tdisk_meter_source_count_overflow\tdisk_meter_generation_overflow",
  "\tupload_meter_measured_lower_ns\tupload_meter_measured_upper_ns",
  "\tupload_meter_committed_bytes\tupload_meter_completions",
  "\tupload_meter_attached_sources\tupload_meter_generation",
  "\tupload_meter_counter_overflow\tupload_meter_invalid_io",
  "\tupload_meter_source_count_overflow\tupload_meter_generation_overflow",
  "\tdownload_meter_measured_lower_ns\tdownload_meter_measured_upper_ns",
  "\tdownload_meter_committed_bytes\tdownload_meter_completions",
  "\tdownload_meter_attached_sources\tdownload_meter_generation",
  "\tdownload_meter_counter_overflow\tdownload_meter_invalid_io",
  "\tdownload_meter_source_count_overflow\tdownload_meter_generation_overflow",
  "\tfeedback_sample_count\tfeedback_stop_requested",
  "\tfeedback_shutdown_complete\tfeedback_worker_failure",
  "\tcpu_current_limit\tcpu_utilization_basis_points\tcpu_telemetry",
  "\tcpu_policy_faulted\tcpu_pending_generation\tcpu_no_change",
  "\tdisk_current_limit\tdisk_utilization_basis_points\tdisk_telemetry",
  "\tdisk_policy_faulted\tdisk_pending_generation\tdisk_no_change",
  "\tdownload_current_limit\tdownload_utilization_basis_points\tdownload_telemetry",
  "\tdownload_policy_faulted\tdownload_pending_generation\tdownload_no_change\n",
);

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub(crate) enum FeedbackTracePhase {
  ProductionStart = 0,
  ProductionEnd = 1,
  DrainEnd = 2,
  RssBefore = 3,
  RssAfterDrain = 4,
  ShutdownEnd = 5,
  RssAfterShutdown = 6,
  OwnerRelease = 7,
}

const PHASE_COUNT: usize = 8;

#[derive(Clone, Copy)]
struct PhaseMarker {
  at: Instant,
  rss: Option<ProcessMemory>,
}

#[derive(Clone)]
struct FixedText {
  bytes: [u8; MAX_IDENTITY_TEXT],
  length: usize,
}

impl FixedText {
  fn from_value(value: &str, hexadecimal: Option<usize>) -> Result<Self, TraceFailure> {
    if value.is_empty()
      || value.len() > MAX_IDENTITY_TEXT
      || !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
      || hexadecimal.is_some_and(|length| {
        value.len() != length || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
      })
    {
      return Err(TraceFailure::Identity);
    }
    let mut bytes = [0; MAX_IDENTITY_TEXT];
    bytes[..value.len()].copy_from_slice(value.as_bytes());
    Ok(Self {
      bytes,
      length: value.len(),
    })
  }

  #[cfg(test)]
  fn from_literal(value: &'static str) -> Self {
    let mut bytes = [0; MAX_IDENTITY_TEXT];
    bytes[..value.len()].copy_from_slice(value.as_bytes());
    Self {
      bytes,
      length: value.len(),
    }
  }

  fn from_environment(
    name: &'static str,
    hexadecimal: Option<usize>,
  ) -> Result<Self, TraceFailure> {
    let value = env::var(name).map_err(|_| TraceFailure::Identity)?;
    Self::from_value(&value, hexadecimal)
  }

  fn as_str(&self) -> Result<&str, TraceFailure> {
    std::str::from_utf8(&self.bytes[..self.length]).map_err(|_| TraceFailure::Identity)
  }
}

struct TraceIdentity {
  report_nonce: FixedText,
  run_id: FixedText,
  executor: FixedText,
  allocator: FixedText,
  workload: FixedText,
  profile: FixedText,
  run_mode: FixedText,
  source_sha256: FixedText,
  binary_sha256: FixedText,
  process_id: u32,
  pressure_qualification: bool,
}

impl TraceIdentity {
  fn from_environment(pressure_qualification: bool, run_mode: &str) -> Result<Self, TraceFailure> {
    Ok(Self {
      report_nonce: FixedText::from_environment("ALLOCATBELT_APP_REPORT_NONCE", Some(32))?,
      run_id: FixedText::from_environment("ALLOCATBELT_APP_RUN_ID", None)?,
      executor: FixedText::from_environment("ALLOCATBELT_APP_EXECUTOR", None)?,
      allocator: FixedText::from_environment("ALLOCATBELT_APP_ALLOCATOR", None)?,
      workload: FixedText::from_environment("ALLOCATBELT_APP_WORKLOAD", None)?,
      profile: FixedText::from_environment("ALLOCATBELT_APP_PROFILE", None)?,
      run_mode: FixedText::from_value(run_mode, None)?,
      source_sha256: FixedText::from_environment("ALLOCATBELT_APP_SOURCE_SHA256", Some(64))?,
      binary_sha256: FixedText::from_environment("ALLOCATBELT_APP_BINARY_SHA256", Some(64))?,
      process_id: std::process::id(),
      pressure_qualification,
    })
  }

  #[cfg(test)]
  fn test_identity() -> Self {
    Self {
      report_nonce: FixedText::from_literal("0123456789abcdef0123456789abcdef"),
      run_id: FixedText::from_literal("feedback-trace-test"),
      executor: FixedText::from_literal("tokio-1.53.1"),
      allocator: FixedText::from_literal("allocatbelt"),
      workload: FixedText::from_literal("cpu"),
      profile: FixedText::from_literal("steady"),
      run_mode: FixedText::from_literal("capacity"),
      source_sha256: FixedText::from_literal(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      ),
      binary_sha256: FixedText::from_literal(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      ),
      process_id: std::process::id(),
      pressure_qualification: false,
    }
  }
}

pub(super) struct FeedbackTraceInputs {
  pub(super) metrics: FeedbackMetricsHandle,
  pub(super) domain: ResourceDomain,
  pub(super) tenant: TenantDomain,
  pub(super) resources: ResourceScope,
  pub(super) disk_rate: ByteRateLimit,
  pub(super) upload_rate: ByteRateLimit,
  pub(super) download_rate: ByteRateLimit,
  pub(super) disk_meter: IoFeedbackMeter,
  pub(super) upload_meter: IoFeedbackMeter,
  pub(super) download_meter: IoFeedbackMeter,
  pub(super) fixed_global_control_baseline: usize,
}

pub(super) struct FeedbackTraceAdmission {
  control: DomainReservation,
  task: ApplicationTaskLease,
}

impl FeedbackTraceAdmission {
  pub(super) fn new(control: DomainReservation, task: ApplicationTaskLease) -> Self {
    Self { control, task }
  }
}

struct TraceState {
  stop_requested: AtomicBool,
  abort_requested: AtomicBool,
  phases: Mutex<[Option<PhaseMarker>; PHASE_COUNT]>,
}

struct TraceOwner {
  state: TraceState,
  task: Mutex<Option<ApplicationTaskLease>>,
  _control: DomainReservation,
}

struct TraceBuffers {
  events: [Option<FeedbackEvent>; HISTORY_READ_BATCH],
  event_record: [u8; EVENT_RECORD_BYTES],
  sample_record: [u8; SAMPLE_RECORD_BYTES],
  manifest: [u8; MANIFEST_BYTES],
  proc_status: [u8; PROC_STATUS_BYTES],
  identity: TraceIdentity,
}

impl TraceBuffers {
  fn new(identity: TraceIdentity) -> Self {
    Self {
      events: [None; HISTORY_READ_BATCH],
      event_record: [0; EVENT_RECORD_BYTES],
      sample_record: [0; SAMPLE_RECORD_BYTES],
      manifest: [0; MANIFEST_BYTES],
      proc_status: [0; PROC_STATUS_BYTES],
      identity,
    }
  }
}

pub(super) fn control_charge_bytes() -> usize {
  std::mem::size_of::<TraceOwner>()
    .saturating_add(std::mem::size_of::<FeedbackTraceCollector>())
    .saturating_add(std::mem::size_of::<FeedbackTraceAdmission>())
    .saturating_add(std::mem::size_of::<FeedbackTraceInputs>())
    .saturating_add(std::mem::size_of::<TraceWorkerStartup>())
    .saturating_add(std::mem::size_of::<TraceWorkerOutput>())
    .saturating_add(std::mem::size_of::<TraceWorkerResult>())
    .saturating_add(std::mem::size_of::<TraceBuffers>())
    .saturating_add(4 * MAX_TRACE_PATH_BYTES)
    .saturating_add(3 * MAX_TRACE_FILE_SUFFIX_BYTES)
    .saturating_add(2 * std::mem::size_of::<usize>())
}

struct TraceDirectory {
  path: PathBuf,
  device: u64,
  mode: u32,
}

impl TraceDirectory {
  fn validate(path: OsString) -> Result<Self, TraceFailure> {
    let path = PathBuf::from(path);
    if !path.is_absolute() || path.as_os_str().len() > MAX_TRACE_PATH_BYTES {
      return Err(TraceFailure::Directory);
    }
    let metadata = fs::symlink_metadata(&path).map_err(|_| TraceFailure::Directory)?;
    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
      return Err(TraceFailure::Directory);
    }
    Ok(Self {
      path,
      device: metadata.dev(),
      mode: metadata.mode() & 0o777,
    })
  }
}

#[derive(Clone, Copy, Debug)]
enum TraceFailure {
  Aborted,
  Directory,
  Identity,
  Clock,
  History(FeedbackHistoryError),
  Sequence { expected: u64, actual: u64 },
  SequenceOverflow,
  MissingEvent,
  MissingWorkerJoin,
  EventRecordBudget,
  SampleRecordBudget,
  SampleSequenceOverflow,
  SampleEncoding,
  EventEncoding,
  EventWrite(io::ErrorKind),
  SampleWrite(io::ErrorKind),
  ManifestWrite(io::ErrorKind),
  ProcessStatus,
  DomainSnapshot,
  WorkerPanicked,
  WorkerTimeout,
  WorkerChannel,
  HorizonExceeded,
  Phase,
}

impl TraceFailure {
  fn description(self) -> String {
    match self {
      Self::Aborted => "feedback trace collection was abandoned".into(),
      Self::Directory => {
        "feedback trace directory must be an existing private absolute directory".into()
      }
      Self::Identity => "feedback trace identity is missing or malformed".into(),
      Self::Clock => "feedback trace monotonic clock could not be bracketed".into(),
      Self::History(error) => format!("feedback history read failed: {error:?}"),
      Self::Sequence { expected, actual } => {
        format!("feedback history sequence discontinuity: expected {expected}, got {actual}")
      }
      Self::SequenceOverflow => "feedback trace sequence overflowed".into(),
      Self::MissingEvent => "feedback history returned an empty or missing event slot".into(),
      Self::MissingWorkerJoin => "feedback trace stopped before WorkerJoined".into(),
      Self::EventRecordBudget => "feedback trace exceeded its finite event-record budget".into(),
      Self::SampleRecordBudget => "feedback trace exceeded its finite sample-row budget".into(),
      Self::SampleSequenceOverflow => "feedback resource sample sequence overflowed".into(),
      Self::SampleEncoding => "feedback resource sample exceeded its fixed record buffer".into(),
      Self::EventEncoding => "feedback event exceeded its fixed record buffer".into(),
      Self::EventWrite(kind) => format!("feedback event file write failed: {kind:?}"),
      Self::SampleWrite(kind) => format!("feedback resource sample write failed: {kind:?}"),
      Self::ManifestWrite(kind) => format!("feedback trace manifest write failed: {kind:?}"),
      Self::ProcessStatus => "feedback trace could not read bounded process RSS status".into(),
      Self::DomainSnapshot => "feedback trace could not capture domain or meter snapshots".into(),
      Self::WorkerPanicked => "feedback trace worker panicked".into(),
      Self::WorkerTimeout => "feedback trace worker exceeded its finite stop deadline".into(),
      Self::WorkerChannel => "feedback trace worker did not publish a completion result".into(),
      Self::HorizonExceeded => "feedback trace exceeded its finite 11,400-second horizon".into(),
      Self::Phase => "feedback trace phase marker was missing or duplicated".into(),
    }
  }
}

struct TraceWorkerOutput {
  manifest_file: TraceFile,
  buffers: Box<TraceBuffers>,
  clock: TraceClock,
  directory: TraceDirectory,
  event_hash: [u8; 64],
  event_bytes: u64,
  event_count: u64,
  first_event_sequence: Option<u64>,
  last_event_sequence: Option<u64>,
  ring_wrapped: bool,
  sample_hash: [u8; 64],
  sample_bytes: u64,
  sample_count: u64,
  first_sample_sequence: Option<u64>,
  last_sample_sequence: Option<u64>,
  phase_markers: [Option<PhaseMarker>; PHASE_COUNT],
  fixed_global_control_baseline: usize,
  // Drop only after retained files, paths and buffers. This keeps their
  // Control charge alive if the receiver abandons a queued worker result.
  _charge_guard: Arc<TraceOwner>,
}

type TraceWorkerResult = Result<TraceWorkerOutput, TraceFailure>;

struct TraceWorkerStartup {
  event_file: TraceFile,
  sample_file: TraceFile,
  manifest_file: TraceFile,
  buffers: Box<TraceBuffers>,
  clock: TraceClock,
  directory: TraceDirectory,
  sample_hash: FeedbackTraceHasher,
  started_at: Instant,
}

pub(crate) struct FeedbackTraceCollector {
  owner: Option<Arc<TraceOwner>>,
  worker: Option<JoinHandle<()>>,
  result: mpsc::Receiver<TraceWorkerResult>,
  clock: TraceClock,
}

pub(crate) struct FeedbackTraceFinalizer {
  owner: Option<Arc<TraceOwner>>,
  output: Option<TraceWorkerOutput>,
}

impl FeedbackTraceCollector {
  pub(super) fn start(
    directory: OsString,
    pressure_qualification: bool,
    run_mode: &'static str,
    inputs: FeedbackTraceInputs,
    admission: FeedbackTraceAdmission,
  ) -> Result<Self, String> {
    let identity = TraceIdentity::from_environment(pressure_qualification, run_mode)
      .map_err(TraceFailure::description)?;
    Self::start_with_identity(directory, inputs, admission, identity)
  }

  fn start_with_identity(
    directory: OsString,
    inputs: FeedbackTraceInputs,
    admission: FeedbackTraceAdmission,
    identity: TraceIdentity,
  ) -> Result<Self, String> {
    let directory = TraceDirectory::validate(directory).map_err(TraceFailure::description)?;
    let clock = TraceClock::capture().map_err(|_| TraceFailure::Clock.description())?;
    let collector_clock = clock;
    let buffers = Box::new(TraceBuffers::new(identity));
    let event_path = directory.path.join("feedback-events.jsonl");
    let sample_path = directory.path.join("resource-samples.tsv");
    let manifest_path = directory.path.join("feedback-trace-manifest.tsv");
    let event_file = TraceFile::create(&event_path, MAX_EVENT_FILE_BYTES)
      .map_err(|error| format!("feedback event file creation failed: {error}"))?;
    let mut sample_file = TraceFile::create(&sample_path, MAX_SAMPLE_FILE_BYTES)
      .map_err(|error| format!("feedback sample file creation failed: {error}"))?;
    let manifest_file = TraceFile::create(&manifest_path, MAX_MANIFEST_FILE_BYTES)
      .map_err(|error| format!("feedback manifest file reservation failed: {error}"))?;
    let mut sample_hash = FeedbackTraceHasher::new();
    sample_file
      .write_all(SAMPLE_HEADER.as_bytes())
      .map_err(|error| format!("feedback sample header write failed: {error}"))?;
    sample_hash.update(SAMPLE_HEADER.as_bytes());
    let owner = Arc::new(TraceOwner {
      state: TraceState {
        stop_requested: AtomicBool::new(false),
        abort_requested: AtomicBool::new(false),
        phases: Mutex::new([None; PHASE_COUNT]),
      },
      task: Mutex::new(Some(admission.task)),
      _control: admission.control,
    });
    let started_at = Instant::now();
    let (sender, result) = mpsc::sync_channel(1);
    let worker_owner = Arc::clone(&owner);
    let worker = thread::Builder::new()
      .name("application-feedback-trace".into())
      .spawn(move || {
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
          run_trace_worker(
            inputs,
            worker_owner,
            TraceWorkerStartup {
              event_file,
              sample_file,
              manifest_file,
              buffers,
              clock,
              directory,
              sample_hash,
              started_at,
            },
          )
        }))
        .unwrap_or(Err(TraceFailure::WorkerPanicked));
        let _ = sender.send(outcome);
      })
      .map_err(|error| format!("feedback trace worker start failed: {error}"))?;
    Ok(Self {
      owner: Some(owner),
      worker: Some(worker),
      result,
      clock: collector_clock,
    })
  }

  pub(crate) fn mark_phase(
    &self,
    phase: FeedbackTracePhase,
    at: Instant,
    rss: Option<ProcessMemory>,
  ) -> Result<(), String> {
    let owner = self
      .owner
      .as_ref()
      .ok_or_else(|| "feedback trace owner has already been released".to_owned())?;
    mark_phase_owner(owner, phase, Some(at), rss, true).map_err(TraceFailure::description)
  }

  /// Maps the same captured event Instant used by `mark_phase` through the
  /// exact TraceClock anchor written to the manifest.
  pub(crate) fn monotonic_bounds(&self, at: Instant) -> Result<(u128, u128), String> {
    self
      .clock
      .bounds(at)
      .map_err(|_| TraceFailure::Clock.description())
  }

  pub(crate) fn stop_for_finalization(mut self) -> Result<FeedbackTraceFinalizer, String> {
    let owner = self
      .owner
      .as_ref()
      .ok_or_else(|| "feedback trace owner is missing".to_owned())?;
    owner.state.stop_requested.store(true, Ordering::Release);
    let received = match self.result.recv_timeout(FINISH_TIMEOUT) {
      Ok(result) => result,
      Err(mpsc::RecvTimeoutError::Timeout) => {
        return Err(TraceFailure::WorkerTimeout.description());
      }
      Err(mpsc::RecvTimeoutError::Disconnected) => {
        return Err(TraceFailure::WorkerChannel.description());
      }
    };
    let worker = self
      .worker
      .take()
      .ok_or_else(|| "feedback trace worker handle is missing".to_owned())?;
    join_bounded(worker, FINISH_TIMEOUT).map_err(TraceFailure::description)?;
    let output = received.map_err(TraceFailure::description)?;
    let owner = self.owner.take();
    if let Some(owner) = &owner {
      let task = owner
        .task
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
      drop(task);
    }
    Ok(FeedbackTraceFinalizer {
      owner,
      output: Some(output),
    })
  }
}

impl FeedbackTraceFinalizer {
  pub(crate) fn mark_phase(
    &self,
    phase: FeedbackTracePhase,
    at: Instant,
    rss: Option<ProcessMemory>,
  ) -> Result<(), String> {
    let owner = self
      .owner
      .as_ref()
      .ok_or_else(|| "feedback trace owner has already been released".to_owned())?;
    mark_phase_owner(owner, phase, Some(at), rss, true).map_err(TraceFailure::description)
  }

  /// Maps a captured Instant through the worker's TraceClock, which is the
  /// anchor used for both the event and its manifest phase bracket.
  pub(crate) fn monotonic_bounds(&self, at: Instant) -> Result<(u128, u128), String> {
    self
      .output
      .as_ref()
      .ok_or_else(|| "feedback trace completion data is missing".to_owned())?
      .clock
      .bounds(at)
      .map_err(|_| TraceFailure::Clock.description())
  }

  /// Marks owner release and returns that event's exact shared-clock bracket.
  pub(crate) fn finish_at(self, at: Instant) -> Result<(u128, u128), String> {
    self
      .finish_inner(Some(at))?
      .ok_or_else(|| "feedback trace release bounds are unavailable".to_owned())
  }

  pub(crate) fn finish(self) -> Result<(), String> {
    self.finish_inner(None).map(|_| ())
  }

  /// Captures a caller-owned owner-release Instant only after it is ordered
  /// beyond the post-shutdown RSS bracket. Call this before taking an
  /// explicit release timestamp for `finish_at`.
  pub(crate) fn owner_release_instant_after_anchor(&self) -> Result<Instant, String> {
    self
      .release_instant_after_anchor()
      .map_err(TraceFailure::description)
  }

  fn release_instant_after_anchor(&self) -> Result<Instant, TraceFailure> {
    let owner = self.owner.as_ref().ok_or(TraceFailure::Phase)?;
    let output = self.output.as_ref().ok_or(TraceFailure::Phase)?;
    let rss_after_shutdown = owner
      .state
      .phases
      .lock()
      .unwrap_or_else(PoisonError::into_inner)[FeedbackTracePhase::RssAfterShutdown as usize]
      .ok_or(TraceFailure::Phase)?;
    let now = Instant::now();
    if now.checked_duration_since(rss_after_shutdown.at).is_none() {
      return Err(TraceFailure::Phase);
    }
    let anchor_width_ns = output
      .clock
      .upper_ns
      .checked_sub(output.clock.lower_ns)
      .ok_or(TraceFailure::Clock)?;
    let anchor_width_ns = u64::try_from(anchor_width_ns).map_err(|_| TraceFailure::Clock)?;
    let release_not_before = rss_after_shutdown
      .at
      .checked_add(Duration::from_nanos(anchor_width_ns))
      .ok_or(TraceFailure::Clock)?;

    // TraceClock bounds its anchor width to 50 ms. The RSS marker is already
    // in the past, so this sleep is finite and no longer than that width.
    loop {
      let remaining = release_not_before.saturating_duration_since(Instant::now());
      if remaining.is_zero() {
        break;
      }
      thread::sleep(remaining);
    }
    Ok(Instant::now())
  }

  fn finish_inner(mut self, release_at: Option<Instant>) -> Result<Option<(u128, u128)>, String> {
    let owner = self
      .owner
      .as_ref()
      .ok_or_else(|| "feedback trace owner is missing".to_owned())?;
    let at = match release_at {
      Some(at) => at,
      None => self
        .release_instant_after_anchor()
        .map_err(TraceFailure::description)?,
    };
    let bounds = release_at.map(|_| self.monotonic_bounds(at)).transpose()?;
    mark_phase_owner(
      owner,
      FeedbackTracePhase::OwnerRelease,
      Some(at),
      None,
      true,
    )
    .map_err(TraceFailure::description)?;
    {
      let mut output = self
        .output
        .take()
        .ok_or_else(|| "feedback trace completion data is missing".to_owned())?;
      output.phase_markers = *owner
        .state
        .phases
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
      let length = encode_manifest(&mut output).map_err(TraceFailure::description)?;
      output
        .manifest_file
        .write_all(&output.buffers.manifest[..length])
        .map_err(|error| TraceFailure::ManifestWrite(error.kind()).description())?;
      output
        .manifest_file
        .finish()
        .map_err(|error| TraceFailure::ManifestWrite(error.kind()).description())?;
    }
    self.owner.take();
    Ok(bounds)
  }
}

impl Drop for FeedbackTraceFinalizer {
  fn drop(&mut self) {
    self.output.take();
    self.owner.take();
  }
}

fn join_bounded(worker: JoinHandle<()>, timeout: Duration) -> Result<(), TraceFailure> {
  let deadline = Instant::now()
    .checked_add(timeout)
    .ok_or(TraceFailure::WorkerTimeout)?;
  while !worker.is_finished() {
    if Instant::now() >= deadline {
      drop(worker);
      return Err(TraceFailure::WorkerTimeout);
    }
    thread::sleep(Duration::from_millis(1));
  }
  worker.join().map_err(|_| TraceFailure::WorkerPanicked)
}

impl Drop for FeedbackTraceCollector {
  fn drop(&mut self) {
    if let Some(owner) = &self.owner {
      owner.state.abort_requested.store(true, Ordering::Release);
      owner.state.stop_requested.store(true, Ordering::Release);
    }
    if let Some(worker) = self.worker.take()
      && self.result.recv_timeout(DROP_WAIT).is_ok()
    {
      let _ = join_bounded(worker, DROP_WAIT);
    }
  }
}

fn mark_phase_owner(
  owner: &TraceOwner,
  phase: FeedbackTracePhase,
  at: Option<Instant>,
  rss: Option<ProcessMemory>,
  reject_duplicate: bool,
) -> Result<(), TraceFailure> {
  let Some(at) = at else {
    return Ok(());
  };
  let mut phases = owner
    .state
    .phases
    .lock()
    .unwrap_or_else(PoisonError::into_inner);
  let slot = &mut phases[phase as usize];
  if reject_duplicate && slot.is_some() {
    return Err(TraceFailure::Phase);
  }
  *slot = Some(PhaseMarker { at, rss });
  Ok(())
}

fn run_trace_worker(
  inputs: FeedbackTraceInputs,
  owner: Arc<TraceOwner>,
  startup: TraceWorkerStartup,
) -> TraceWorkerResult {
  let TraceWorkerStartup {
    mut event_file,
    mut sample_file,
    manifest_file,
    mut buffers,
    clock,
    directory,
    mut sample_hash,
    started_at,
  } = startup;
  let mut event_hash = FeedbackTraceHasher::new();
  let mut cursor = 0u64;
  let mut event_count = 0u64;
  let mut first_event_sequence = None;
  let mut last_event_sequence = None;
  let mut ring_wrapped = false;
  let mut saw_worker_joined = false;
  let mut sample_count = 0u64;
  let mut first_sample_sequence = None;
  let mut last_sample_sequence = None;
  let mut next_sample = started_at;
  let horizon_end = started_at
    .checked_add(TRACE_HORIZON)
    .ok_or(TraceFailure::HorizonExceeded)?;

  loop {
    if Instant::now() >= horizon_end {
      return Err(TraceFailure::HorizonExceeded);
    }
    if owner.state.abort_requested.load(Ordering::Acquire) {
      return Err(TraceFailure::Aborted);
    }
    let read = inputs
      .metrics
      .read_history_after(cursor, &mut buffers.events)
      .map_err(TraceFailure::History)?;
    ring_wrapped |= read.truncated;
    if read.more_available && read.written == 0 {
      return Err(TraceFailure::MissingEvent);
    }
    for index in 0..read.written {
      let Some(event) = buffers.events[index] else {
        return Err(TraceFailure::MissingEvent);
      };
      if event_count >= MAX_EVENT_RECORDS {
        return Err(TraceFailure::EventRecordBudget);
      }
      let expected = cursor
        .checked_add(1)
        .ok_or(TraceFailure::SequenceOverflow)?;
      if event.sequence != expected {
        return Err(TraceFailure::Sequence {
          expected,
          actual: event.sequence,
        });
      }
      let length = encode_event(&mut buffers.event_record, &clock, event)
        .map_err(|_| TraceFailure::EventEncoding)?;
      event_file
        .write_all(&buffers.event_record[..length])
        .map_err(|error| TraceFailure::EventWrite(error.kind()))?;
      event_hash.update(&buffers.event_record[..length]);
      cursor = event.sequence;
      event_count = event_count
        .checked_add(1)
        .ok_or(TraceFailure::SequenceOverflow)?;
      first_event_sequence.get_or_insert(event.sequence);
      last_event_sequence = Some(event.sequence);
      saw_worker_joined |= matches!(event.kind, FeedbackEventKind::WorkerJoined { .. });
      buffers.events[index] = None;
    }

    let now = Instant::now();
    let terminal_history_drained = owner.state.stop_requested.load(Ordering::Acquire)
      && saw_worker_joined
      && !read.more_available;
    if now >= next_sample || terminal_history_drained {
      if sample_count >= MAX_SAMPLE_ROWS {
        return Err(TraceFailure::SampleRecordBudget);
      }
      let sequence = sample_count
        .checked_add(1)
        .ok_or(TraceFailure::SampleSequenceOverflow)?;
      let length = encode_resource_sample(&inputs, &clock, &mut buffers, sequence)?;
      sample_file
        .write_all(&buffers.sample_record[..length])
        .map_err(|error| TraceFailure::SampleWrite(error.kind()))?;
      sample_hash.update(&buffers.sample_record[..length]);
      sample_count = sequence;
      first_sample_sequence.get_or_insert(sequence);
      last_sample_sequence = Some(sequence);
      if now >= next_sample {
        next_sample = now
          .checked_add(SAMPLE_INTERVAL)
          .ok_or(TraceFailure::SampleSequenceOverflow)?;
      }
    }

    if terminal_history_drained {
      break;
    }
    if !read.more_available {
      thread::sleep(Duration::from_millis(2));
    }
  }
  if !saw_worker_joined || event_count == 0 || first_event_sequence != Some(1) {
    return Err(TraceFailure::MissingWorkerJoin);
  }

  let fixed_global_control_baseline = inputs.fixed_global_control_baseline;
  let phase_markers = *owner
    .state
    .phases
    .lock()
    .unwrap_or_else(PoisonError::into_inner);
  drop(inputs);
  let event_bytes = event_file
    .finish()
    .map_err(|error| TraceFailure::EventWrite(error.kind()))?;
  let sample_bytes = sample_file
    .finish()
    .map_err(|error| TraceFailure::SampleWrite(error.kind()))?;
  Ok(TraceWorkerOutput {
    manifest_file,
    buffers,
    clock,
    directory,
    event_hash: event_hash.finish_hex(),
    event_bytes,
    event_count,
    first_event_sequence,
    last_event_sequence,
    ring_wrapped,
    sample_hash: sample_hash.finish_hex(),
    sample_bytes,
    sample_count,
    first_sample_sequence,
    last_sample_sequence,
    phase_markers,
    fixed_global_control_baseline,
    _charge_guard: owner,
  })
}

fn encode_resource_sample(
  inputs: &FeedbackTraceInputs,
  clock: &TraceClock,
  buffers: &mut TraceBuffers,
  sequence: u64,
) -> Result<usize, TraceFailure> {
  let started_at = Instant::now();
  let global = inputs.domain.snapshot();
  let tenant = inputs
    .tenant
    .snapshot()
    .map_err(|_| TraceFailure::DomainSnapshot)?;
  let scope = inputs.resources.snapshot();
  let disk_rate = inputs.disk_rate.snapshot();
  let upload_rate = inputs.upload_rate.snapshot();
  let download_rate = inputs.download_rate.snapshot();
  let disk_meter = inputs.disk_meter.snapshot();
  let upload_meter = inputs.upload_meter.snapshot();
  let download_meter = inputs.download_meter.snapshot();
  let feedback = inputs.metrics.snapshot();
  let rss = read_process_status(&mut buffers.proc_status)?;
  let ended_at = Instant::now();
  let (window_lower, _) = clock.bounds(started_at).map_err(|_| TraceFailure::Clock)?;
  let (_, window_upper) = clock.bounds(ended_at).map_err(|_| TraceFailure::Clock)?;
  let mut output = Cursor::new(buffers.sample_record.as_mut_slice());
  write!(
    output,
    "{sequence}\t{window_lower}\t{window_upper}\t{}\t{}\t1",
    rss.rss_kib, rss.hwm_kib
  )
  .map_err(|_| TraceFailure::SampleEncoding)?;
  write_domain_snapshot(&mut output, global).map_err(|_| TraceFailure::SampleEncoding)?;
  write_domain_snapshot(&mut output, tenant).map_err(|_| TraceFailure::SampleEncoding)?;
  write_resource_snapshot(&mut output, scope).map_err(|_| TraceFailure::SampleEncoding)?;
  write_rate_snapshot(&mut output, disk_rate).map_err(|_| TraceFailure::SampleEncoding)?;
  write_rate_snapshot(&mut output, upload_rate).map_err(|_| TraceFailure::SampleEncoding)?;
  write_rate_snapshot(&mut output, download_rate).map_err(|_| TraceFailure::SampleEncoding)?;
  write_meter_snapshot(&mut output, clock, disk_meter).map_err(|_| TraceFailure::SampleEncoding)?;
  write_meter_snapshot(&mut output, clock, upload_meter)
    .map_err(|_| TraceFailure::SampleEncoding)?;
  write_meter_snapshot(&mut output, clock, download_meter)
    .map_err(|_| TraceFailure::SampleEncoding)?;
  write_feedback_snapshot(&mut output, feedback).map_err(|_| TraceFailure::SampleEncoding)?;
  output
    .write_all(b"\n")
    .map_err(|_| TraceFailure::SampleEncoding)?;
  usize::try_from(output.position()).map_err(|_| TraceFailure::SampleEncoding)
}

fn write_domain_snapshot(out: &mut impl Write, snapshot: DomainSnapshot) -> io::Result<()> {
  for resource in DOMAIN_DIMENSIONS {
    write!(
      out,
      "\t{}\t{}\t{}",
      snapshot.ceiling.get(resource),
      snapshot.limit.get(resource),
      snapshot.used.get(resource)
    )?;
  }
  Ok(())
}

const DOMAIN_DIMENSIONS: [DomainResource; 6] = [
  DomainResource::Cpu,
  DomainResource::Memory,
  DomainResource::Disk,
  DomainResource::Network,
  DomainResource::Tasks,
  DomainResource::Control,
];

fn write_resource_snapshot(out: &mut impl Write, snapshot: ResourceSnapshot) -> io::Result<()> {
  write!(
    out,
    "\t{}\t{}\t{}\t{}\t{}\t{}",
    snapshot.limits.managed_memory,
    snapshot.limits.disk_concurrent_ops,
    snapshot.limits.network_concurrent_ops,
    snapshot.managed_memory,
    snapshot.disk_ops,
    snapshot.network_ops
  )
}

fn write_rate_snapshot(out: &mut impl Write, snapshot: ByteRateSnapshot) -> io::Result<()> {
  write!(
    out,
    "\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
    snapshot.bytes_per_second,
    snapshot.burst_bytes,
    snapshot.ceiling_bytes_per_second,
    snapshot.ceiling_burst_bytes,
    snapshot.max_reservations,
    snapshot.available_bytes,
    snapshot.reserved_bytes,
    snapshot.reservations
  )
}

fn write_meter_snapshot(
  out: &mut impl Write,
  clock: &TraceClock,
  snapshot: IoFeedbackMeterSnapshot,
) -> io::Result<()> {
  let (lower, upper) = clock
    .bounds(snapshot.measured_at)
    .map_err(io::Error::other)?;
  write!(
    out,
    "\t{lower}\t{upper}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
    snapshot.committed_bytes,
    snapshot.completions,
    snapshot.attached_sources,
    snapshot.generation,
    snapshot.diagnostics.counter_overflow,
    snapshot.diagnostics.invalid_io,
    snapshot.diagnostics.source_count_overflow,
    snapshot.diagnostics.generation_overflow
  )
}

fn write_feedback_snapshot(
  out: &mut impl Write,
  snapshot: FeedbackMetricsSnapshot,
) -> io::Result<()> {
  write!(
    out,
    "\t{}\t{}\t{}\t",
    snapshot.sample_count, snapshot.stop_requested, snapshot.shutdown_complete
  )?;
  match snapshot.worker_failure {
    Some(failure) => write!(out, "{failure:?}")?,
    None => out.write_all(b"none")?,
  }
  for resource in [
    FeedbackResource::CpuConcurrency,
    FeedbackResource::DiskRate,
    FeedbackResource::NetworkRate,
  ] {
    let control = snapshot.control(resource);
    write!(out, "\t{}\t", control.current_limit)?;
    match control.utilization_basis_points {
      Some(value) => write!(out, "{value}")?,
      None => out.write_all(b"none")?,
    }
    write!(
      out,
      "\t{:?}\t{}\t",
      control.telemetry, control.policy_faulted
    )?;
    match control.pending_generation {
      Some(value) => write!(out, "{value}")?,
      None => out.write_all(b"none")?,
    }
    write!(out, "\t{:?}", control.no_change)?;
  }
  Ok(())
}

fn read_process_status(
  buffer: &mut [u8; PROC_STATUS_BYTES],
) -> Result<ProcessMemory, TraceFailure> {
  let mut file = File::open("/proc/self/status").map_err(|_| TraceFailure::ProcessStatus)?;
  let mut count = 0;
  loop {
    if count == buffer.len() {
      return Err(TraceFailure::ProcessStatus);
    }
    let read = file
      .read(&mut buffer[count..])
      .map_err(|_| TraceFailure::ProcessStatus)?;
    if read == 0 {
      break;
    }
    count += read;
  }
  let contents = &buffer[..count];
  let mut rss_kib = None;
  let mut hwm_kib = None;
  for line in contents.split(|byte| *byte == b'\n') {
    if let Some(value) = line.strip_prefix(b"VmRSS:") {
      rss_kib = parse_kib(value);
    } else if let Some(value) = line.strip_prefix(b"VmHWM:") {
      hwm_kib = parse_kib(value);
    }
  }
  match (rss_kib, hwm_kib) {
    (Some(rss_kib), Some(hwm_kib)) => Ok(ProcessMemory { rss_kib, hwm_kib }),
    _ => Err(TraceFailure::ProcessStatus),
  }
}

fn parse_kib(bytes: &[u8]) -> Option<u64> {
  let mut value = None;
  let mut number = 0u64;
  for byte in bytes.iter().copied() {
    if byte.is_ascii_digit() {
      number = number
        .checked_mul(10)?
        .checked_add(u64::from(byte - b'0'))?;
      value = Some(number);
    } else if value.is_some() {
      break;
    }
  }
  value
}

fn encode_manifest(output: &mut TraceWorkerOutput) -> Result<usize, TraceFailure> {
  let mut out = Cursor::new(output.buffers.manifest.as_mut_slice());
  let identity = &output.buffers.identity;
  writeln!(out, "schema\t{TRACE_MANIFEST_SCHEMA}")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "identity\tprocess_id\t{}", identity.process_id)
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  for (name, value) in [
    ("report_nonce", identity.report_nonce.as_str()?),
    ("run_id", identity.run_id.as_str()?),
    ("executor", identity.executor.as_str()?),
    ("allocator", identity.allocator.as_str()?),
    ("workload", identity.workload.as_str()?),
    ("profile", identity.profile.as_str()?),
    ("mode", identity.run_mode.as_str()?),
    ("source_sha256", identity.source_sha256.as_str()?),
    ("binary_sha256", identity.binary_sha256.as_str()?),
  ] {
    writeln!(out, "identity\t{name}\t{value}")
      .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  }
  writeln!(
    out,
    "identity\tpressure_qualification\t{}",
    identity.pressure_qualification
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(
    out,
    "trace_directory\tdevice\t{}\tmode\t{:o}",
    output.directory.device, output.directory.mode
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  write!(
    out,
    "artifact\tfeedback-events.jsonl\t{}\t",
    output.event_bytes
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  out
    .write_all(&output.event_hash)
    .and_then(|()| out.write_all(b"\n"))
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  write!(
    out,
    "artifact\tresource-samples.tsv\t{}\t",
    output.sample_bytes
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  out
    .write_all(&output.sample_hash)
    .and_then(|()| out.write_all(b"\n"))
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(
    out,
    "events\t{EVENT_SCHEMA}\t{}\t{}\t{}\tring_wrapped\t{}\tread_gaps\t0",
    output.event_count,
    output.first_event_sequence.unwrap_or(0),
    output.last_event_sequence.unwrap_or(0),
    output.ring_wrapped
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(
    out,
    "samples\t{RESOURCE_SAMPLE_SCHEMA}\t{}\t{}\t{}",
    output.sample_count,
    output.first_sample_sequence.unwrap_or(0),
    output.last_sample_sequence.unwrap_or(0)
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(
    out,
    "clock_anchor\t{}\t{}",
    output.clock.lower_ns, output.clock.upper_ns
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "history_capacity\t{TRACE_HISTORY_CAPACITY}")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(
    out,
    "budget\tmax_horizon_seconds\t{MAX_TRACE_HORIZON_SECONDS}"
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(
    out,
    "budget\tsample_interval_ms\t{}",
    SAMPLE_INTERVAL.as_millis()
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "budget\tmax_sample_rows\t{MAX_SAMPLE_ROWS}")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "budget\tmax_sample_cycles\t{MAX_SAMPLE_CYCLES}")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "budget\tterminal_sample_headroom\t1")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(
    out,
    "budget\tmax_sample_record_bytes\t{SAMPLE_RECORD_BYTES}"
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(
    out,
    "budget\tmax_sample_file_bytes\t{MAX_SAMPLE_FILE_BYTES}"
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "budget\tmax_event_records\t{MAX_EVENT_RECORDS}")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "budget\tmax_event_record_bytes\t{EVENT_RECORD_BYTES}")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "budget\tmax_event_file_bytes\t{MAX_EVENT_FILE_BYTES}")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(
    out,
    "budget\tmax_manifest_file_bytes\t{MAX_MANIFEST_FILE_BYTES}"
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "budget\tbase_events_per_sample_cycle\t3")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "budget\tcontrol_count\t3")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(
    out,
    "budget\tactuation_cooldown_ms\t{}",
    ACTUATION_COOLDOWN.as_millis()
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(
    out,
    "budget\tmax_tickets_per_control\t{MAX_TICKETS_PER_CONTROL}"
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "budget\tevents_per_ticket\t4")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "budget\tapplication_reconciliation_requests\t0")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "budget\tterminal_event_headroom\t100")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  for (index, marker) in output.phase_markers.iter().enumerate() {
    let Some(marker) = marker else {
      return Err(TraceFailure::Phase);
    };
    let (lower, upper) = output
      .clock
      .bounds(marker.at)
      .map_err(|_| TraceFailure::Clock)?;
    let name = phase_name(index).ok_or(TraceFailure::Phase)?;
    write!(out, "phase\t{name}\t{lower}\t{upper}\t")
      .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
    if let Some(rss) = marker.rss {
      writeln!(out, "{}\t{}", rss.rss_kib, rss.hwm_kib)
        .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
    } else {
      out
        .write_all(b"none\tnone\n")
        .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
    }
  }
  writeln!(
    out,
    "control\tcollector_charge_bytes\t{}\texpected_global_control_baseline\t{}",
    control_charge_bytes(),
    output.fixed_global_control_baseline
  )
  .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "task\tcollector_task_lease_count\t1")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  writeln!(out, "completion\tcomplete\ttrue")
    .map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))?;
  usize::try_from(out.position()).map_err(|_| TraceFailure::ManifestWrite(io::ErrorKind::WriteZero))
}

fn phase_name(index: usize) -> Option<&'static str> {
  Some(match index {
    0 => "production_start",
    1 => "production_end",
    2 => "drain_end",
    3 => "rss_before",
    4 => "rss_after_drain",
    5 => "shutdown_end",
    6 => "rss_after_shutdown",
    7 => "owner_release",
    _ => return None,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs::{DirBuilder, OpenOptions};
  use std::os::unix::fs::DirBuilderExt;
  use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
  use std::time::Duration;

  use allocatbelt::runtime::byte_rate::ByteRateConfig;
  use allocatbelt::runtime::managed::ResourceLimits;
  use allocatbelt::runtime::resource_domain::{DomainResources, ResourceDomain};
  use allocatbelt::runtime::resource_feedback::{
    FeedbackActuator, FeedbackActuatorError, FeedbackHistoryConfig, FeedbackSensor,
    FeedbackSensorError, FeedbackShutdownProgress, ResourceFeedbackService,
  };
  use allocatbelt::runtime::resource_feedback_policy::{
    FeedbackControlConfig, FeedbackSample, PlanTicket, ResourceFeedbackPolicyConfig,
  };

  static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

  struct TraceFixture(PathBuf);

  impl TraceFixture {
    fn new() -> Self {
      let path = env::temp_dir().join(format!(
        "allocatbelt-feedback-trace-{}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, AtomicOrdering::Relaxed)
      ));
      DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .expect("private trace directory");
      Self(path)
    }
  }

  impl Drop for TraceFixture {
    fn drop(&mut self) {
      let _ = fs::remove_dir_all(&self.0);
    }
  }

  struct TicketSensor;

  impl FeedbackSensor for TicketSensor {
    fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
      Ok(FeedbackSample::new(
        Instant::now(),
        Some(9_000),
        Some(9_000),
        Some(9_000),
      ))
    }
  }

  struct FixedActuator;

  impl FeedbackActuator for FixedActuator {
    fn readback(&mut self, resource: FeedbackResource) -> Result<u64, FeedbackActuatorError> {
      Ok(match resource {
        FeedbackResource::CpuConcurrency => 2,
        FeedbackResource::DiskRate | FeedbackResource::NetworkRate => 1000,
      })
    }

    fn apply(&mut self, _ticket: PlanTicket) -> Result<(), FeedbackActuatorError> {
      Ok(())
    }
  }

  struct TestRuntime {
    domain: ResourceDomain,
    tenant: TenantDomain,
    resources: ResourceScope,
    rates: [ByteRateLimit; 3],
    meters: [IoFeedbackMeter; 3],
    service: ResourceFeedbackService,
    fixed_control_baseline: usize,
  }

  impl TestRuntime {
    fn new(history_capacity: usize) -> Self {
      let ceiling = DomainResources::ZERO
        .with(DomainResource::Cpu, 4)
        .with(DomainResource::Tasks, 8)
        .with(DomainResource::Control, 8 * 1024 * 1024);
      let domain = ResourceDomain::new(ceiling, 1).expect("trace test domain");
      let fixed_control_baseline = domain.snapshot().used.get(DomainResource::Control);
      let tenant = domain.tenant(ceiling).expect("trace test tenant");
      let resources = ResourceScope::from_tenant(ResourceLimits::default(), tenant.clone());
      let rate_config = ByteRateConfig {
        bytes_per_second: 4096,
        burst_bytes: 4096,
        max_reservations: 8,
      };
      let rates = [
        ByteRateLimit::new_in_tenant(rate_config, &tenant).expect("disk rate"),
        ByteRateLimit::new_in_tenant(rate_config, &tenant).expect("upload rate"),
        ByteRateLimit::new_in_tenant(rate_config, &tenant).expect("download rate"),
      ];
      let meters = [
        IoFeedbackMeter::new_in_tenant(&tenant).expect("disk meter"),
        IoFeedbackMeter::new_in_tenant(&tenant).expect("upload meter"),
        IoFeedbackMeter::new_in_tenant(&tenant).expect("download meter"),
      ];
      let policy = ResourceFeedbackPolicyConfig {
        cpu_concurrency: FeedbackControlConfig::new(1, 2, 4, 3000, 8000),
        disk_rate: FeedbackControlConfig::new(100, 1000, 2000, 3000, 8000),
        network_rate: FeedbackControlConfig::new(100, 1000, 2000, 3000, 8000),
      };
      let history = FeedbackHistoryConfig::new(
        std::num::NonZeroUsize::new(history_capacity).expect("nonzero history capacity"),
      );
      let service = ResourceFeedbackService::start_in_tenant_with_history(
        policy,
        TicketSensor,
        FixedActuator,
        &tenant,
        history,
      )
      .expect("history service");
      Self {
        domain,
        tenant,
        resources,
        rates,
        meters,
        service,
        fixed_control_baseline,
      }
    }

    fn inputs(&self) -> FeedbackTraceInputs {
      FeedbackTraceInputs {
        metrics: self.service.metrics_handle(),
        domain: self.domain.clone(),
        tenant: self.tenant.clone(),
        resources: self.resources.clone(),
        disk_rate: self.rates[0].clone(),
        upload_rate: self.rates[1].clone(),
        download_rate: self.rates[2].clone(),
        disk_meter: self.meters[0].clone(),
        upload_meter: self.meters[1].clone(),
        download_meter: self.meters[2].clone(),
        fixed_global_control_baseline: self.fixed_control_baseline,
      }
    }

    fn admission(&self) -> FeedbackTraceAdmission {
      let control = self
        .tenant
        .try_acquire(DomainResources::ZERO.with(DomainResource::Control, control_charge_bytes()))
        .expect("collector Control charge");
      let task =
        super::super::runtime_bindings::ApplicationTaskAdmission::for_tenant(self.tenant.clone())
          .reserve()
          .expect("collector task lease");
      FeedbackTraceAdmission::new(control, task)
    }

    fn stop(&mut self) {
      self.service.request_stop();
      let deadline = Instant::now() + Duration::from_secs(2);
      loop {
        match self.service.try_shutdown() {
          Ok(FeedbackShutdownProgress::Complete) => return,
          Ok(FeedbackShutdownProgress::Pending) => {
            assert!(Instant::now() < deadline, "feedback service did not join");
            thread::sleep(Duration::from_millis(1));
          }
          Err(error) => panic!("feedback service shutdown failed: {error}"),
        }
      }
    }

    fn wait_for_samples(&self, count: u64) {
      let deadline = Instant::now() + Duration::from_secs(2);
      while self.service.metrics().sample_count < count {
        assert!(
          Instant::now() < deadline,
          "feedback worker did not accept enough samples"
        );
        thread::sleep(Duration::from_millis(1));
      }
    }
  }

  fn rss_marker() -> ProcessMemory {
    read_process_status(&mut [0; PROC_STATUS_BYTES]).expect("bounded process RSS")
  }

  fn trace_collector(fixture: &TraceFixture, runtime: &TestRuntime) -> FeedbackTraceCollector {
    FeedbackTraceCollector::start_with_identity(
      fixture.0.as_os_str().to_os_string(),
      runtime.inputs(),
      runtime.admission(),
      TraceIdentity::test_identity(),
    )
    .expect("feedback trace collector")
  }

  fn finalizer_after_shutdown(
    runtime: &mut TestRuntime,
    collector: FeedbackTraceCollector,
  ) -> FeedbackTraceFinalizer {
    let rss_before_at = Instant::now();
    collector
      .mark_phase(
        FeedbackTracePhase::RssBefore,
        rss_before_at,
        Some(rss_marker()),
      )
      .unwrap();
    collector
      .mark_phase(FeedbackTracePhase::ProductionStart, Instant::now(), None)
      .unwrap();
    runtime.wait_for_samples(3);
    collector
      .mark_phase(FeedbackTracePhase::ProductionEnd, Instant::now(), None)
      .unwrap();
    collector
      .mark_phase(FeedbackTracePhase::DrainEnd, Instant::now(), None)
      .unwrap();
    collector
      .mark_phase(
        FeedbackTracePhase::RssAfterDrain,
        Instant::now(),
        Some(rss_marker()),
      )
      .unwrap();
    runtime.stop();
    collector
      .mark_phase(FeedbackTracePhase::ShutdownEnd, Instant::now(), None)
      .unwrap();
    collector.stop_for_finalization().unwrap()
  }

  fn widen_test_anchor(finalizer: &mut FeedbackTraceFinalizer, width: Duration) {
    let clock = &mut finalizer.output.as_mut().expect("finalizer output").clock;
    clock.upper_ns = clock
      .lower_ns
      .checked_add(width.as_nanos())
      .expect("wide test anchor fits the monotonic clock range");
  }

  fn manifest_artifact_hash<'a>(manifest: &'a str, file: &str) -> &'a str {
    manifest
      .lines()
      .filter_map(|line| {
        let mut fields = line.split('\t');
        if fields.next() == Some("artifact") && fields.next() == Some(file) {
          let _bytes = fields.next()?;
          fields.next()
        } else {
          None
        }
      })
      .next()
      .expect("manifest artifact hash")
  }

  fn manifest_phase_bounds(manifest: &str, phase: &str) -> (u128, u128) {
    let line = manifest
      .lines()
      .find(|line| line.starts_with(&format!("phase\t{phase}\t")))
      .expect("manifest phase bounds");
    let mut fields = line.split('\t');
    assert_eq!(fields.next(), Some("phase"));
    assert_eq!(fields.next(), Some(phase));
    let lower = fields
      .next()
      .expect("phase lower bound")
      .parse()
      .expect("numeric phase lower bound");
    let upper = fields
      .next()
      .expect("phase upper bound")
      .parse()
      .expect("numeric phase upper bound");
    (lower, upper)
  }

  fn sha256(bytes: &[u8]) -> [u8; 64] {
    let mut hash = FeedbackTraceHasher::new();
    hash.update(bytes);
    hash.finish_hex()
  }

  #[test]
  fn bounded_trace_constants_fit_the_declared_control_charge() {
    assert!(control_charge_bytes() >= std::mem::size_of::<TraceBuffers>());
    assert!(control_charge_bytes() >= std::mem::size_of::<TraceWorkerStartup>());
    assert_eq!(TRACE_HISTORY_CAPACITY, 16_384);
    assert_eq!(HISTORY_READ_BATCH, 128);
    assert!(MAX_EVENT_RECORDS * EVENT_RECORD_BYTES as u64 <= MAX_EVENT_FILE_BYTES);
    assert!(
      MAX_SAMPLE_ROWS * SAMPLE_RECORD_BYTES as u64 + SAMPLE_HEADER.len() as u64
        <= MAX_SAMPLE_FILE_BYTES
    );
    assert_eq!(TRACE_HORIZON, Duration::from_secs(11_400));
    assert_eq!(MAX_SAMPLE_CYCLES, 114_001);
    assert_eq!(MAX_SAMPLE_ROWS, 114_002);
    assert_eq!(MAX_EVENT_RECORDS, 478_915);
  }

  #[test]
  fn complete_trace_streams_events_samples_hashes_and_releases_control() {
    let mut runtime = TestRuntime::new(TRACE_HISTORY_CAPACITY);
    let before_trace = runtime.domain.snapshot().used.get(DomainResource::Control);
    let tasks_before_trace = runtime
      .tenant
      .snapshot()
      .unwrap()
      .used
      .get(DomainResource::Tasks);
    let fixture = TraceFixture::new();
    let collector = trace_collector(&fixture, &runtime);
    assert!(runtime.domain.snapshot().used.get(DomainResource::Control) > before_trace);
    assert_eq!(
      runtime
        .tenant
        .snapshot()
        .unwrap()
        .used
        .get(DomainResource::Tasks),
      tasks_before_trace + 1,
      "the collector owns one separately charged Task lease"
    );

    let rss_before_at = Instant::now();
    collector
      .mark_phase(
        FeedbackTracePhase::RssBefore,
        rss_before_at,
        Some(rss_marker()),
      )
      .unwrap();
    let production_start = Instant::now();
    let production_start_bounds = collector.monotonic_bounds(production_start).unwrap();
    collector
      .mark_phase(FeedbackTracePhase::ProductionStart, production_start, None)
      .unwrap();
    runtime.wait_for_samples(3);
    let production_end = Instant::now();
    let production_end_bounds = collector.monotonic_bounds(production_end).unwrap();
    collector
      .mark_phase(FeedbackTracePhase::ProductionEnd, production_end, None)
      .unwrap();
    let drain_end = Instant::now();
    let drain_end_bounds = collector.monotonic_bounds(drain_end).unwrap();
    collector
      .mark_phase(FeedbackTracePhase::DrainEnd, drain_end, None)
      .unwrap();
    collector
      .mark_phase(
        FeedbackTracePhase::RssAfterDrain,
        Instant::now(),
        Some(rss_marker()),
      )
      .unwrap();

    runtime.stop();
    let tasks_with_collector_after_shutdown = runtime
      .tenant
      .snapshot()
      .unwrap()
      .used
      .get(DomainResource::Tasks);
    assert!(tasks_with_collector_after_shutdown > 0);
    let shutdown_end = Instant::now();
    let shutdown_end_bounds = collector.monotonic_bounds(shutdown_end).unwrap();
    collector
      .mark_phase(FeedbackTracePhase::ShutdownEnd, shutdown_end, None)
      .unwrap();
    let finalizer = collector.stop_for_finalization().unwrap();
    let control_with_finalizer = runtime.domain.snapshot().used.get(DomainResource::Control);
    assert!(control_with_finalizer >= control_charge_bytes());
    assert_eq!(
      runtime
        .tenant
        .snapshot()
        .unwrap()
        .used
        .get(DomainResource::Tasks),
      tasks_with_collector_after_shutdown - 1,
      "finalization releases the collector Task lease before final ledger checks"
    );
    let rss_after_shutdown_at = Instant::now();
    finalizer
      .mark_phase(
        FeedbackTracePhase::RssAfterShutdown,
        rss_after_shutdown_at,
        Some(rss_marker()),
      )
      .unwrap();
    let owner_release = Instant::now();
    let owner_release_bounds = finalizer.monotonic_bounds(owner_release).unwrap();
    assert_eq!(
      finalizer.finish_at(owner_release).unwrap(),
      owner_release_bounds
    );
    assert_eq!(
      runtime.domain.snapshot().used.get(DomainResource::Control),
      control_with_finalizer - control_charge_bytes()
    );

    let manifest = fs::read_to_string(fixture.0.join("feedback-trace-manifest.tsv"))
      .expect("completed manifest");
    assert_eq!(
      manifest_phase_bounds(&manifest, "production_start"),
      production_start_bounds
    );
    assert_eq!(
      manifest_phase_bounds(&manifest, "production_end"),
      production_end_bounds
    );
    assert_eq!(
      manifest_phase_bounds(&manifest, "drain_end"),
      drain_end_bounds
    );
    assert_eq!(
      manifest_phase_bounds(&manifest, "shutdown_end"),
      shutdown_end_bounds
    );
    assert_eq!(
      manifest_phase_bounds(&manifest, "owner_release"),
      owner_release_bounds
    );
    let event_path = fixture.0.join("feedback-events.jsonl");
    let event_bytes = fs::read(&event_path).expect("event stream");
    let sample_bytes = fs::read(fixture.0.join("resource-samples.tsv")).expect("sample stream");
    assert!(manifest.contains("completion\tcomplete\ttrue\n"));
    assert!(manifest.contains("read_gaps\t0\n"));
    assert!(manifest.contains("task\tcollector_task_lease_count\t1\n"));
    assert!(manifest.contains("phase\towner_release\t"));
    let expected_event_hash = sha256(&event_bytes);
    let expected_sample_hash = sha256(&sample_bytes);
    assert_eq!(
      manifest_artifact_hash(&manifest, "feedback-events.jsonl").as_bytes(),
      expected_event_hash.as_slice()
    );
    assert_eq!(
      manifest_artifact_hash(&manifest, "resource-samples.tsv").as_bytes(),
      expected_sample_hash.as_slice()
    );
    let event_text = std::str::from_utf8(&event_bytes).expect("JSON-lines UTF-8");
    assert!(event_text.lines().count() >= 6);
    assert!(event_text.lines().all(|line| {
      line.starts_with("{\"schema\":\"allocatbelt.application-feedback-event.v1\"")
        && line.len() < EVENT_RECORD_BYTES
    }));
    assert!(event_text.contains("\"kind\":\"plan\""));
    let sample_text = std::str::from_utf8(&sample_bytes).expect("sample TSV UTF-8");
    assert!(sample_text.contains("global_ceiling_cpu"));
    let mut sample_rows = sample_text.lines();
    let sample_header = sample_rows.next().expect("sample schema header");
    assert_eq!(
      sample_header,
      "schema\tallocatbelt.application-feedback-resource-sample.v1"
    );
    let sample_columns = sample_rows.next().expect("sample column header");
    let lease_column = sample_columns
      .split('\t')
      .position(|field| field == "collector_task_lease_count")
      .expect("explicit collector Task lease column");
    let data_rows: Vec<_> = sample_rows.filter(|row| !row.is_empty()).collect();
    assert!(
      data_rows.len() >= 2,
      "initial and terminal samples are required"
    );
    assert!(
      data_rows
        .iter()
        .all(|row| row.split('\t').nth(lease_column) == Some("1"))
    );
    let sample_summary = manifest
      .lines()
      .find(|line| line.starts_with("samples\t"))
      .expect("sample summary row");
    let mut sample_summary = sample_summary.split('\t');
    assert_eq!(sample_summary.next(), Some("samples"));
    assert_eq!(sample_summary.next(), Some(RESOURCE_SAMPLE_SCHEMA));
    let sample_count = sample_summary
      .next()
      .expect("sample count")
      .parse::<u64>()
      .expect("numeric sample count");
    assert_eq!(sample_count, data_rows.len() as u64);
    assert_eq!(sample_summary.next(), Some("1"));
    assert_eq!(
      sample_summary
        .next()
        .expect("last sample sequence")
        .parse::<u64>()
        .expect("numeric last sample sequence"),
      sample_count
    );
    let mut tampered = OpenOptions::new()
      .append(true)
      .open(&event_path)
      .expect("append tamper marker");
    tampered.write_all(b"tamper\n").unwrap();
    let tampered_bytes = fs::read(&event_path).expect("tampered event stream");
    assert_ne!(
      manifest_artifact_hash(&manifest, "feedback-events.jsonl").as_bytes(),
      &sha256(&tampered_bytes)
    );
  }

  #[test]
  fn finish_waits_out_wide_anchor_before_emitting_owner_release() {
    let mut runtime = TestRuntime::new(TRACE_HISTORY_CAPACITY);
    let fixture = TraceFixture::new();
    let collector = trace_collector(&fixture, &runtime);
    let mut finalizer = finalizer_after_shutdown(&mut runtime, collector);
    widen_test_anchor(&mut finalizer, Duration::from_millis(25));

    let rss_after_shutdown = rss_marker();
    let rss_after_shutdown_at = Instant::now();
    let expected_rss_bounds = finalizer.monotonic_bounds(rss_after_shutdown_at).unwrap();
    finalizer
      .mark_phase(
        FeedbackTracePhase::RssAfterShutdown,
        rss_after_shutdown_at,
        Some(rss_after_shutdown),
      )
      .unwrap();
    finalizer.finish().unwrap();

    let manifest = fs::read_to_string(fixture.0.join("feedback-trace-manifest.tsv"))
      .expect("completed manifest");
    let rss_bounds = manifest_phase_bounds(&manifest, "rss_after_shutdown");
    let owner_release_bounds = manifest_phase_bounds(&manifest, "owner_release");
    assert_eq!(rss_bounds, expected_rss_bounds);
    assert!(rss_bounds.1 <= owner_release_bounds.0);
    let phase_rows: Vec<_> = manifest
      .lines()
      .filter(|line| line.starts_with("phase\t"))
      .collect();
    let rss_row = phase_rows
      .iter()
      .position(|line| line.starts_with("phase\trss_after_shutdown\t"))
      .expect("RSS-after-shutdown phase row");
    let release_row = phase_rows
      .iter()
      .position(|line| line.starts_with("phase\towner_release\t"))
      .expect("owner-release phase row");
    assert!(rss_row < release_row);
  }

  #[test]
  fn caller_release_capture_waits_before_preserving_explicit_finish_at() {
    let mut runtime = TestRuntime::new(TRACE_HISTORY_CAPACITY);
    let fixture = TraceFixture::new();
    let collector = trace_collector(&fixture, &runtime);
    let mut finalizer = finalizer_after_shutdown(&mut runtime, collector);
    widen_test_anchor(&mut finalizer, Duration::from_millis(25));

    let rss_after_shutdown = rss_marker();
    let rss_after_shutdown_at = Instant::now();
    let expected_rss_bounds = finalizer.monotonic_bounds(rss_after_shutdown_at).unwrap();
    finalizer
      .mark_phase(
        FeedbackTracePhase::RssAfterShutdown,
        rss_after_shutdown_at,
        Some(rss_after_shutdown),
      )
      .unwrap();
    let owner_release_at = finalizer.owner_release_instant_after_anchor().unwrap();
    let expected_release_bounds = finalizer.monotonic_bounds(owner_release_at).unwrap();
    assert!(expected_rss_bounds.1 <= expected_release_bounds.0);
    assert_eq!(
      finalizer.finish_at(owner_release_at).unwrap(),
      expected_release_bounds,
    );

    let manifest = fs::read_to_string(fixture.0.join("feedback-trace-manifest.tsv"))
      .expect("completed manifest");
    assert_eq!(
      manifest_phase_bounds(&manifest, "rss_after_shutdown"),
      expected_rss_bounds,
    );
    assert_eq!(
      manifest_phase_bounds(&manifest, "owner_release"),
      expected_release_bounds,
    );
  }

  #[test]
  fn stale_history_cursor_fails_without_a_completion_manifest_and_releases_charge() {
    let mut runtime = TestRuntime::new(2);
    let before_trace = runtime.domain.snapshot().used.get(DomainResource::Control);
    let before_tasks = runtime
      .tenant
      .snapshot()
      .unwrap()
      .used
      .get(DomainResource::Tasks);
    let fixture = TraceFixture::new();
    let collector = trace_collector(&fixture, &runtime);
    assert_eq!(
      runtime
        .tenant
        .snapshot()
        .unwrap()
        .used
        .get(DomainResource::Tasks),
      before_tasks + 1
    );
    let result = collector.stop_for_finalization();
    assert!(result.is_err(), "stale history must fail closed");
    assert_eq!(
      fs::metadata(fixture.0.join("feedback-trace-manifest.tsv"))
        .expect("reserved manifest")
        .len(),
      0
    );
    assert_eq!(
      runtime.domain.snapshot().used.get(DomainResource::Control),
      before_trace
    );
    assert_eq!(
      runtime
        .tenant
        .snapshot()
        .unwrap()
        .used
        .get(DomainResource::Tasks),
      before_tasks
    );
    runtime.stop();
  }

  #[test]
  fn abandoned_queued_output_retains_control_and_task_until_backing_is_dropped() {
    let mut runtime = TestRuntime::new(TRACE_HISTORY_CAPACITY);
    let fixture = TraceFixture::new();
    let mut collector = trace_collector(&fixture, &runtime);
    collector
      .owner
      .as_ref()
      .expect("collector owner")
      .state
      .stop_requested
      .store(true, Ordering::Release);
    runtime.stop();

    let outcome = collector
      .result
      .recv_timeout(FINISH_TIMEOUT)
      .expect("worker must publish its complete queued output");
    let worker = collector.worker.take().expect("worker handle");
    join_bounded(worker, FINISH_TIMEOUT).expect("worker join");
    let output = outcome.expect("complete worker output");
    let control_with_queued_output = runtime.domain.snapshot().used.get(DomainResource::Control);
    let tasks_with_queued_output = runtime
      .tenant
      .snapshot()
      .unwrap()
      .used
      .get(DomainResource::Tasks);

    drop(collector);
    assert_eq!(
      runtime.domain.snapshot().used.get(DomainResource::Control),
      control_with_queued_output,
      "queued output keeps its shared Control owner alive"
    );
    assert_eq!(
      runtime
        .tenant
        .snapshot()
        .unwrap()
        .used
        .get(DomainResource::Tasks),
      tasks_with_queued_output,
      "queued output keeps the collector Task lease alive"
    );

    drop(output);
    assert_eq!(
      runtime.domain.snapshot().used.get(DomainResource::Control),
      control_with_queued_output - control_charge_bytes()
    );
    assert_eq!(
      runtime
        .tenant
        .snapshot()
        .unwrap()
        .used
        .get(DomainResource::Tasks),
      tasks_with_queued_output - 1
    );
  }
}
