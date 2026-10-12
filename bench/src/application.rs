//! Bounded CPU, memory, HTTP, and disk application comparison lanes.
//!
//! This is a development benchmark, not a performance claim. The lane keeps
//! an independent scheduled-arrival producer and a separate result observer;
//! workload checksums come from the same app-port kernels for both executors.

use std::collections::{HashSet, VecDeque};
use std::env;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};
use std::{future::Future, pin::Pin};

use allocatbelt::runtime::asynchronous::{
  AsyncConfig, AsyncError, AsyncHandle, AsyncJob, AsyncRuntime, AsyncShutdown,
};
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt_app_ports::cpu;
use allocatbelt_app_ports::disk::{self, DiskConfig, DiskReport};
use allocatbelt_app_ports::memory::{self, MemoryConfig, MemoryOutput};

#[path = "application/disk_lane.rs"]
mod disk_lane;
#[path = "application/http.rs"]
mod http;

const WORKERS: usize = 4;
const WINDOW: usize = 8;
const CAPACITY_HORIZON: Duration = Duration::from_secs(30);
const OPEN_LOOP_ARRIVALS: usize = 5000;
const MAX_OPEN_LOOP_ARRIVALS: usize = 1_000_000;
const MAX_TRACE: Duration = Duration::from_secs(300);
const MAX_CAPACITY_JOBS: usize = 10_000_000;
const WARMUP_TIMEOUT: Duration = Duration::from_secs(30);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(300);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(900);
pub(super) const SETUP_DEADLINE: Duration = Duration::from_secs(120);
const MAX_RETAINED_MEMORY_OUTPUTS: usize = WINDOW;
static EXECUTION_DEADLINES: OnceLock<ExecutionDeadlines> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
pub(super) struct ExecutionDeadlines {
  pub(super) trace: Duration,
  pub(super) drain: Duration,
  pub(super) shutdown: Duration,
  pub(super) process: Duration,
}

impl Default for ExecutionDeadlines {
  fn default() -> Self {
    Self {
      trace: MAX_TRACE,
      drain: DRAIN_TIMEOUT,
      shutdown: SHUTDOWN_TIMEOUT,
      process: PROCESS_TIMEOUT,
    }
  }
}

pub(super) fn execution_deadlines() -> ExecutionDeadlines {
  *EXECUTION_DEADLINES.get_or_init(ExecutionDeadlines::default)
}

pub(super) fn remaining_process_deadline(started: Instant) -> Duration {
  started
    .checked_add(execution_deadlines().process)
    .map_or(Duration::ZERO, |deadline| {
      deadline.saturating_duration_since(Instant::now())
    })
}
pub(super) const HTTP_CONNECT_POLICY_SCHEMA: &str = "http-nonblocking-connect-v1";
const TSV_HEADER: &str = "schema\tallocator\texecutor\tworkload\tmode\tasync_workers\tblocking_workers\ttopology\tlogical_window\tglobal_task_limit\tretained_window\tarrival_rate_per_second\trequested_arrivals\tattempted\tadmitted\trejected_full\trejected_resource\tcompleted_on_time\tcompleted_late\terrors\tcancellations\tunresolved\tlost\tresult_digest\texpected_digest\tcapacity_publications_per_second\tsuccessful_throughput_through_drain_per_second\tsetup_ns\ttimer_pair_median_ns\twall_through_drain_ns\tdrain_tail_ns\tresponse_p50_ns\tresponse_p95_ns\tresponse_p99_ns\tproducer_lateness_mean_ns\tproducer_lateness_max_ns\tmax_observed_managed_bytes\tretained_managed_bytes\tmanaged_limit_bytes\tdisk_limit_ops\tnetwork_limit_ops\tfinal_managed_bytes\tfinal_disk_ops\tfinal_network_ops\trss_before_kib\trss_after_drain_kib\trss_after_shutdown_kib\thwm_before_kib\thwm_after_drain_kib\thwm_after_shutdown_kib\tshutdown_ns\trejected_logical_window\trejected_backend_full";

/// Executor under test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Executor {
  /// allocatbelt's owned asynchronous runtime.
  Bounded,
  /// Tokio's multi-thread asynchronous runtime.
  Tokio,
}

impl Executor {
  fn parse(value: &str) -> Result<Self, String> {
    match value {
      "bounded" => Ok(Self::Bounded),
      "tokio" => Ok(Self::Tokio),
      _ => Err("--executor must be bounded or tokio".into()),
    }
  }

  fn label(self) -> &'static str {
    match self {
      Self::Bounded => "allocatbelt",
      Self::Tokio => "tokio-1.53.1",
    }
  }
}

/// Application workload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Workload {
  /// Deterministic integer kernel.
  Cpu,
  /// Managed allocation, growth and retained output.
  Memory,
  /// Paired loopback HTTP client/server transaction.
  Http,
  /// Multi-chunk positional file transaction.
  Disk,
}

impl Workload {
  fn parse(value: &str) -> Result<Self, String> {
    match value {
      "cpu" => Ok(Self::Cpu),
      "memory" => Ok(Self::Memory),
      "http" => Ok(Self::Http),
      "disk" => Ok(Self::Disk),
      _ => Err("--workload must be cpu, memory, http, or disk".into()),
    }
  }

  fn label(self) -> &'static str {
    match self {
      Self::Cpu => "cpu",
      Self::Memory => "memory",
      Self::Http => "http",
      Self::Disk => "disk",
    }
  }
}

/// Arrival policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
  /// Keep an eight-operation logical window full for a fixed horizon.
  Capacity,
  /// Submit the configured number of IDs against absolute scheduled arrivals.
  OpenLoop,
}

impl Mode {
  fn parse(value: &str) -> Result<Self, String> {
    match value {
      "capacity" => Ok(Self::Capacity),
      "open_loop" => Ok(Self::OpenLoop),
      _ => Err("--mode must be capacity or open_loop".into()),
    }
  }

  fn label(self) -> &'static str {
    match self {
      Self::Capacity => "capacity",
      Self::OpenLoop => "open_loop",
    }
  }
}

/// Fixed lane input. Open-loop rate is supplied from a frozen pilot result;
/// this module never clamps it or launches a timing campaign itself.
#[derive(Clone, Copy, Debug)]
pub struct Options {
  /// Executor under test.
  pub executor: Executor,
  /// Workload.
  pub workload: Workload,
  /// Arrival mode.
  pub mode: Mode,
  /// Open-loop arrivals per second. Required only in open-loop mode.
  pub rate_per_second: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct LaneConfig {
  rounds: u32,
  memory: MemoryConfig,
  disk: DiskConfig,
}

impl Default for LaneConfig {
  fn default() -> Self {
    Self {
      rounds: 50_000,
      memory: MemoryConfig::default(),
      disk: DiskConfig::default(),
    }
  }
}

enum WorkOutput {
  Cpu(u64),
  Memory(MemoryOutput),
  Disk(DiskReport),
}

impl WorkOutput {
  fn value(&self) -> u64 {
    match self {
      Self::Cpu(value) => *value,
      Self::Memory(output) => output.report.checksum,
      Self::Disk(output) => output.checksum,
    }
  }
}

enum Job {
  Bounded(AsyncJob<allocatbelt_app_ports::PortResult<WorkOutput>>),
  Tokio {
    handle: tokio::task::JoinHandle<allocatbelt_app_ports::PortResult<WorkOutput>>,
    result: Option<Result<allocatbelt_app_ports::PortResult<WorkOutput>, tokio::task::JoinError>>,
  },
}

impl Job {
  fn poll_finished(&mut self, cx: &mut Context<'_>) -> Poll<()> {
    match self {
      Self::Bounded(job) => Pin::new(job).poll_finished(cx),
      Self::Tokio { handle, result } => {
        if result.is_some() {
          return Poll::Ready(());
        }
        match Pin::new(handle).poll(cx) {
          Poll::Pending => Poll::Pending,
          Poll::Ready(output) => {
            *result = Some(output);
            Poll::Ready(())
          }
        }
      }
    }
  }
}

pub(super) struct ObserverEventSender<T> {
  sender: Option<mpsc::SyncSender<T>>,
  observer: Arc<OnceLock<thread::Thread>>,
}

impl<T> ObserverEventSender<T> {
  pub(super) fn new(sender: mpsc::SyncSender<T>, observer: Arc<OnceLock<thread::Thread>>) -> Self {
    Self {
      sender: Some(sender),
      observer,
    }
  }

  fn wake_observer(&self) {
    if let Some(observer) = self.observer.get() {
      observer.unpark();
    }
  }

  pub(super) fn send(&self, event: T) -> Result<(), mpsc::SendError<T>> {
    let result = match &self.sender {
      Some(sender) => sender.send(event),
      None => return Err(mpsc::SendError(event)),
    };
    if result.is_ok() {
      self.wake_observer();
    }
    result
  }
}

impl<T> Clone for ObserverEventSender<T> {
  fn clone(&self) -> Self {
    Self {
      sender: self.sender.as_ref().cloned(),
      observer: Arc::clone(&self.observer),
    }
  }
}

impl<T> Drop for ObserverEventSender<T> {
  fn drop(&mut self) {
    // Drop the real sender before waking so a receiver that runs immediately
    // can observe Disconnected when this was the final sender.
    if let Some(sender) = self.sender.take() {
      drop(sender);
    }
    self.wake_observer();
  }
}

pub(super) struct ObserverWake(thread::Thread);

impl Wake for ObserverWake {
  fn wake(self: Arc<Self>) {
    self.0.unpark();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.unpark();
  }
}

#[derive(Clone)]
enum DiskDriver {
  Native(allocatbelt::runtime::fs::FsHandle),
  Tokio {
    handle: tokio::runtime::Handle,
    slots: Arc<tokio::sync::Semaphore>,
  },
}

#[derive(Clone)]
enum Submitter {
  Bounded {
    handle: AsyncHandle,
    disk: Option<allocatbelt::runtime::fs::FsHandle>,
  },
  Tokio {
    handle: tokio::runtime::Handle,
    slots: Arc<tokio::sync::Semaphore>,
    disk_slots: Option<Arc<tokio::sync::Semaphore>>,
  },
}

#[derive(Clone)]
enum Observer {
  Bounded(AsyncHandle),
  Tokio,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rejection {
  Full,
  Closed,
}

impl Submitter {
  fn submit(
    &self,
    workload: Workload,
    config: LaneConfig,
    resources: &ResourceScope,
    id: u64,
  ) -> Result<Job, Rejection> {
    let seed = job_seed(id);
    match self {
      Self::Bounded { handle, disk } => {
        let driver = disk.clone().map(DiskDriver::Native);
        let operation = operation(workload, config, resources.clone(), seed, driver);
        handle.spawn(operation).map(Job::Bounded).map_err(|error| {
          if error.kind == AsyncError::Full {
            Rejection::Full
          } else {
            Rejection::Closed
          }
        })
      }
      Self::Tokio {
        handle,
        slots,
        disk_slots,
      } => {
        let permit = slots
          .clone()
          .try_acquire_owned()
          .map_err(|error| match error {
            tokio::sync::TryAcquireError::Closed => Rejection::Closed,
            tokio::sync::TryAcquireError::NoPermits => Rejection::Full,
          })?;
        let driver = disk_slots.clone().map(|slots| DiskDriver::Tokio {
          handle: handle.clone(),
          slots,
        });
        let operation = operation(workload, config, resources.clone(), seed, driver);
        Ok(Job::Tokio {
          handle: handle.spawn(async move {
            let result = operation.await;
            drop(permit);
            result
          }),
          result: None,
        })
      }
    }
  }
}

async fn operation(
  workload: Workload,
  config: LaneConfig,
  resources: ResourceScope,
  seed: u64,
  driver: Option<DiskDriver>,
) -> allocatbelt_app_ports::PortResult<WorkOutput> {
  match workload {
    Workload::Cpu => Ok(WorkOutput::Cpu(cpu::kernel(seed, config.rounds))),
    Workload::Memory => Ok(WorkOutput::Memory(memory::run_operation(
      &resources,
      MemoryConfig {
        seed,
        ..config.memory
      },
    )?)),
    Workload::Http => Err("HTTP operation escaped its paired transaction lane".into()),
    Workload::Disk => {
      let disk_config = DiskConfig {
        seed,
        ..config.disk
      };
      let output = match driver.ok_or("disk executor driver is missing")? {
        DiskDriver::Native(fs_handle) => {
          disk_lane::run_native_operation(&fs_handle, &resources, disk_config).await?
        }
        DiskDriver::Tokio { handle, slots } => {
          disk_lane::run_tokio_operation(&handle, &slots, &resources, disk_config)
            .await
            .map_err(std::io::Error::other)?
        }
      };
      Ok(WorkOutput::Disk(output))
    }
  }
}

impl Observer {
  fn join(&self, job: Job) -> Result<WorkOutput, String> {
    match (self, job) {
      (Self::Bounded(handle), Job::Bounded(job)) => handle
        .block_on(job)
        .map_err(|error| format!("allocatbelt observer root failed: {error}"))?
        .map_err(|error| format!("allocatbelt application task failed: {error}"))?
        .map_err(|error| error.to_string()),
      (
        Self::Tokio,
        Job::Tokio {
          result: Some(result),
          ..
        },
      ) => result
        .map_err(|error| format!("Tokio application task failed: {error}"))?
        .map_err(|error| error.to_string()),
      (Self::Tokio, Job::Tokio { result: None, .. }) => {
        Err("Tokio task was consumed before terminal completion".into())
      }
      _ => Err("job was delivered to the wrong executor observer".into()),
    }
  }
}

enum ObserverEvent {
  Rejected {
    id: u64,
    scheduled: Instant,
  },
  Job {
    id: u64,
    scheduled: Instant,
    horizon_end: Instant,
    job: Job,
  },
  Done {
    attempted: usize,
    horizon_end: Instant,
  },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdState {
  Unseen,
  Rejected,
  Admitted,
  Completed,
  Failed,
}

#[derive(Debug)]
struct ProducerReport {
  attempted: usize,
  admitted: usize,
  rejected_full: usize,
  rejected_logical_window: usize,
  rejected_backend_full: usize,
  lateness_sum_ns: u128,
  lateness_max_ns: u64,
  started_at: Instant,
  production_end: Instant,
  trace_overrun: bool,
}

#[derive(Debug)]
struct ObserverReport {
  completed_on_time: usize,
  completed_late: usize,
  errors: usize,
  cancellations: usize,
  digest: u64,
  latencies_ns: Vec<u64>,
  max_observed_managed_bytes: usize,
  retained_managed_bytes: usize,
  final_statuses: Option<Vec<IdState>>,
  last_observed: Instant,
  records: Vec<IdRecord>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct IdRecord {
  pub(super) id: u64,
  pub(super) scheduled_ns: u64,
  pub(super) completion_ns: u64,
  pub(super) terminal: &'static str,
  pub(super) checksum: u64,
  pub(super) expected_checksum: u64,
}

#[derive(Debug)]
pub(crate) struct Counts {
  producer: ProducerReport,
  observer: ObserverReport,
  expected_checksum: u64,
  final_resources: allocatbelt::runtime::managed::ResourceSnapshot,
  blocking_workers: usize,
  topology: &'static str,
  setup_ns: u128,
  timer_pair_median_ns: u64,
  driver_shutdown_ns: u128,
  rss_before: ProcessMemory,
  rss_after_drain: ProcessMemory,
  rss_after_shutdown: ProcessMemory,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ProcessMemory {
  rss_kib: u64,
  hwm_kib: u64,
}

pub(super) struct ProcessCheckpoints {
  pub(super) setup_started: Instant,
  pub(super) timer_pair_median_ns: u64,
  pub(super) rss_before: ProcessMemory,
  pub(super) rss_after_drain: ProcessMemory,
  pub(super) rss_after_shutdown: ProcessMemory,
}

pub(super) fn sample_process_memory() -> Result<ProcessMemory, String> {
  let status = std::fs::read_to_string("/proc/self/status")
    .map_err(|error| format!("could not read process RSS from /proc: {error}"))?;
  let mut rss_kib = None;
  let mut hwm_kib = None;
  for line in status.lines() {
    if let Some(value) = line.strip_prefix("VmRSS:") {
      rss_kib = value
        .split_whitespace()
        .next()
        .and_then(|value| value.parse().ok());
    } else if let Some(value) = line.strip_prefix("VmHWM:") {
      hwm_kib = value
        .split_whitespace()
        .next()
        .and_then(|value| value.parse().ok());
    }
  }
  Ok(ProcessMemory {
    rss_kib: rss_kib.ok_or_else(|| "VmRSS missing from /proc/self/status".to_owned())?,
    hwm_kib: hwm_kib.ok_or_else(|| "VmHWM missing from /proc/self/status".to_owned())?,
  })
}

pub(super) fn process_cpu_time_ns() -> u128 {
  let sample = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
  (sample.tv_sec as u128) * 1_000_000_000 + sample.tv_nsec as u128
}

pub(super) fn sample_after_checkpoint_delay() -> Result<ProcessMemory, String> {
  thread::sleep(Duration::from_millis(100));
  sample_process_memory()
}

pub(super) fn run_shutdown_with_timeout<F>(label: &'static str, shutdown: F) -> Result<u128, String>
where
  F: FnOnce() -> Result<(), String> + Send + 'static,
{
  let started = Instant::now();
  let (done_tx, done_rx) = mpsc::sync_channel(1);
  let worker = thread::Builder::new()
    .name("application-driver-shutdown".into())
    .spawn(move || {
      let _ = done_tx.send(shutdown());
    })
    .map_err(|error| format!("{label} shutdown watchdog start failed: {error}"))?;
  let result = done_rx
    .recv_timeout(execution_deadlines().shutdown)
    .map_err(|error| format!("{label} shutdown exceeded its finite deadline: {error}"))?;
  worker
    .join()
    .map_err(|_| format!("{label} shutdown worker panicked"))?;
  result?;
  Ok(started.elapsed().as_nanos())
}

pub(super) fn write_shutdown_report(
  trace_ns: u128,
  production_through_drain_cpu_ns: u128,
  successful_completions: usize,
  timings: &[(&'static str, u128)],
) -> Result<(), String> {
  let Some(path) = env::var_os("ALLOCATBELT_APP_SHUTDOWN_REPORT") else {
    return Ok(());
  };
  if timings.is_empty() {
    return Err("shutdown report requires at least one driver timing".into());
  }
  let mut report = String::from("kind\tname\tduration_ns\n");
  report.push_str(&format!("phase\tproduction_trace\t{trace_ns}\n"));
  report.push_str(&format!(
    "phase\tproduction_through_drain_cpu_ns\t{production_through_drain_cpu_ns}\n"
  ));
  report.push_str(&format!(
    "phase\tsuccessful_completions\t{successful_completions}\n"
  ));
  let cpu_per_completion = if successful_completions == 0 {
    0
  } else {
    production_through_drain_cpu_ns / successful_completions as u128
  };
  report.push_str(&format!(
    "phase\tcpu_ns_per_successful_completion\t{cpu_per_completion}\n"
  ));
  for (driver, duration_ns) in timings {
    report.push_str("driver\t");
    report.push_str(driver);
    report.push('\t');
    report.push_str(&duration_ns.to_string());
    report.push('\n');
  }
  let mut file = OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(path)
    .map_err(|error| format!("shutdown report create failed: {error}"))?;
  file
    .write_all(report.as_bytes())
    .map_err(|error| format!("shutdown report write failed: {error}"))
}

pub(super) fn write_id_report(
  records: &[IdRecord],
  allocator: &str,
  options: Options,
) -> Result<(), String> {
  let Some(path) = env::var_os("ALLOCATBELT_APP_ID_REPORT") else {
    return Ok(());
  };
  let nonce = required_report_field("ALLOCATBELT_APP_REPORT_NONCE")?;
  let run_id = required_report_field("ALLOCATBELT_APP_RUN_ID")?;
  let source_hash = required_report_field("ALLOCATBELT_APP_SOURCE_SHA256")?;
  let binary_hash = required_report_field("ALLOCATBELT_APP_BINARY_SHA256")?;
  if !is_hex(&nonce, 32)
    || !is_token(&run_id)
    || !is_hex(&source_hash, 64)
    || !is_hex(&binary_hash, 64)
  {
    return Err("per-ID report identity contains an invalid token".into());
  }
  let mut ordered = records.to_vec();
  ordered.sort_unstable_by_key(|record| record.id);
  let mut report = String::from("schema\tallocatbelt-app-arrivals-v2\nidentity\t");
  report.push_str(&format!(
    "{nonce}\t{run_id}\t{}\t{allocator}\t{}\t{source_hash}\t{binary_hash}\n",
    options.executor.label(),
    options.workload.label()
  ));
  report.push_str("id\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum\n");
  for record in ordered {
    report.push_str(&format!(
      "{}\t{}\t{}\t{}\t{}\t{}\n",
      record.id,
      record.scheduled_ns,
      record.completion_ns,
      record.terminal,
      record.checksum,
      record.expected_checksum
    ));
  }
  let mut file = OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(path)
    .map_err(|error| format!("per-ID report create failed: {error}"))?;
  file
    .write_all(report.as_bytes())
    .map_err(|error| format!("per-ID report write failed: {error}"))
}

fn required_report_field(name: &str) -> Result<String, String> {
  env::var(name).map_err(|_| format!("per-ID report requires {name}"))
}

fn is_hex(value: &str, len: usize) -> bool {
  value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_token(value: &str) -> bool {
  !value.is_empty()
    && value
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub(super) fn measure_timer_pair_median_ns() -> u64 {
  let mut samples = Vec::with_capacity(257);
  for _ in 0..257 {
    let start = Instant::now();
    let end = Instant::now();
    samples.push(end.saturating_duration_since(start).as_nanos() as u64);
  }
  samples.sort_unstable();
  samples[samples.len() / 2]
}

fn run_with_limits(
  options: Options,
  capacity_horizon: Option<Duration>,
  open_loop_arrivals: Option<usize>,
) -> Result<Counts, String> {
  let setup_started = Instant::now();
  validate_options(options)?;
  let open_loop_arrivals = open_loop_arrivals.unwrap_or(OPEN_LOOP_ARRIVALS);
  if options.mode == Mode::OpenLoop {
    validate_arrivals(open_loop_arrivals)?;
    validate_trace(options, open_loop_arrivals, execution_deadlines().trace)?;
  }
  let config = LaneConfig::default();
  let oracle_count = open_loop_arrivals;
  // Open-loop reference work is bounded and belongs to setup: recomputing the
  // memory or disk reference payload after observing a result delays the
  // credit that releases the producer's unchanged eight-operation window.
  let open_loop_oracle = if options.mode == Mode::OpenLoop {
    Some(build_expected_oracle(
      options.workload,
      &config,
      oracle_count,
    )?)
  } else {
    None
  };
  let limits = resource_limits(options.workload);
  let resources = ResourceScope::new(limits);
  let mut disk_runtime =
    if options.workload == Workload::Disk && options.executor == Executor::Bounded {
      Some(
        allocatbelt::runtime::Runtime::new(allocatbelt::runtime::Config {
          workers: 4,
          max_outstanding: WINDOW,
          capacity: allocatbelt::runtime::Resources {
            disk: WINDOW,
            ..allocatbelt::runtime::Resources::ZERO
          },
        })
        .map_err(|error| format!("allocatbelt filesystem runtime start failed: {error}"))?,
      )
    } else {
      None
    };
  let native_fs = disk_runtime
    .as_ref()
    .map(|runtime| allocatbelt::runtime::fs::FsHandle::new(runtime.handle(), resources.clone()));
  let (submitter, observer, scope, runtime) = match options.executor {
    Executor::Bounded => {
      let async_runtime = AsyncRuntime::new(AsyncConfig {
        workers: WORKERS,
        max_outstanding: WINDOW,
        max_scopes: 2,
      })
      .map_err(|error| format!("allocatbelt async runtime start failed: {error}"))?;
      let scope = async_runtime
        .scope_with_resources(&resources)
        .map_err(|error| format!("allocatbelt scope start failed: {error}"))?;
      let handle = scope.handle();
      warm_bounded(&handle)?;
      if options.workload == Workload::Disk
        && let Some(fs_runtime) = &disk_runtime
      {
        disk_lane::warm_native_workers(fs_runtime, &handle, 4)?;
      }
      let observer = Observer::Bounded(handle.clone());
      (
        Submitter::Bounded {
          handle,
          disk: native_fs.clone(),
        },
        observer,
        Some(scope),
        ExecutorRuntime::Bounded(async_runtime),
      )
    }
    Executor::Tokio => {
      let runtime_built = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .max_blocking_threads(4)
        .thread_name("allocatbelt-app-tokio")
        .build()
        .map_err(|error| format!("Tokio runtime start failed: {error}"))?;
      let handle = runtime_built.handle().clone();
      let slots = Arc::new(tokio::sync::Semaphore::new(WINDOW));
      let disk_slots =
        (options.workload == Workload::Disk).then(|| Arc::new(tokio::sync::Semaphore::new(WINDOW)));
      warm_tokio(&handle)?;
      if options.workload == Workload::Disk {
        disk_lane::warm_tokio_workers(&handle, 4)?;
      }
      let observer = Observer::Tokio;
      (
        Submitter::Tokio {
          handle,
          slots,
          disk_slots,
        },
        observer,
        None,
        ExecutorRuntime::Tokio(runtime_built),
      )
    }
  };
  // CPU/memory intentionally create no blocking-service workers.
  let mut scope_keepalive = scope;

  let id_states = if options.mode == Mode::OpenLoop {
    let arrivals = open_loop_arrivals;
    let mut states = Vec::new();
    states
      .try_reserve_exact(arrivals)
      .map_err(|_| "could not reserve bounded open-loop ID table".to_owned())?;
    states.resize(arrivals, IdState::Unseen);
    Some(Arc::new(Mutex::new(states)))
  } else {
    None
  };
  let event_capacity = match options.mode {
    Mode::Capacity => 2 * WINDOW + 1,
    Mode::OpenLoop => open_loop_arrivals
      .checked_mul(4)
      .and_then(|n| n.checked_add(1))
      .ok_or_else(|| "open-loop event capacity overflow".to_owned())?,
  };
  let (events_tx, events_rx) = mpsc::sync_channel(event_capacity);
  let observer_thread_target = Arc::new(OnceLock::new());
  let events_tx = ObserverEventSender::new(events_tx, Arc::clone(&observer_thread_target));
  let (credits_tx, credits_rx) = mpsc::sync_channel(WINDOW);
  let (producer_tx, producer_rx) = mpsc::sync_channel(1);
  let observer_ids = id_states.clone();
  let observer_open_loop_oracle = open_loop_oracle.clone();
  let observer_resources = resources.clone();
  let observer_arrivals = open_loop_arrivals;
  let observer_pending_limit = if options.mode == Mode::OpenLoop {
    observer_arrivals
  } else {
    WINDOW
  };
  let (observer_tx, observer_rx) = mpsc::sync_channel(1);
  let observer_thread = thread::Builder::new()
    .name("application-observer".into())
    .spawn(move || {
      let report = observe(
        observer,
        options,
        config,
        observer_resources,
        events_rx,
        credits_tx,
        observer_ids,
        observer_arrivals,
        observer_pending_limit,
        Duration::from_millis(100),
        observer_open_loop_oracle,
      );
      let _ = observer_tx.send(report);
    })
    .map_err(|error| format!("observer thread start failed: {error}"))?;
  if observer_thread_target
    .set(observer_thread.thread().clone())
    .is_err()
  {
    return Err("application observer thread was registered twice".into());
  }

  let timer_pair_median_ns = measure_timer_pair_median_ns();
  let rss_before = sample_process_memory()?;
  if setup_started.elapsed() > SETUP_DEADLINE {
    return Err("application setup exceeded its 120 second finite deadline".into());
  }
  let producer_states = id_states;
  let producer_resources = resources.clone();
  let production_cpu_started = process_cpu_time_ns();
  let producer_thread = thread::Builder::new()
    .name("application-producer".into())
    .spawn(move || {
      let report = produce(
        submitter,
        options,
        config,
        &producer_resources,
        events_tx,
        credits_rx,
        producer_states,
        capacity_horizon.unwrap_or(CAPACITY_HORIZON),
        open_loop_arrivals,
      );
      let _ = producer_tx.send(report);
    })
    .map_err(|error| format!("producer thread start failed: {error}"))?;

  let producer = producer_rx
    .recv_timeout(remaining_process_deadline(setup_started))
    .map_err(|error| format!("producer deadline failed: {error}"))??;
  producer_thread
    .join()
    .map_err(|_| "application producer panicked".to_owned())?;
  let process_deadline = setup_started + execution_deadlines().process;
  let drain_deadline =
    (producer.production_end + execution_deadlines().drain).min(process_deadline);
  let drain_remaining = drain_deadline.saturating_duration_since(Instant::now());
  let observer_report = observer_rx
    .recv_timeout(drain_remaining)
    .map_err(|error| format!("application drain deadline failed: {error}"))??;
  observer_thread
    .join()
    .map_err(|_| "application observer panicked".to_owned())?;
  let production_cpu_ns = process_cpu_time_ns().saturating_sub(production_cpu_started);
  let rss_after_drain = sample_after_checkpoint_delay()?;
  let expected_checksum = expected_digest(
    options,
    &observer_report,
    &producer,
    open_loop_oracle.as_deref(),
  );
  let statuses = observer_report.final_statuses.as_ref();
  validate_counts(
    options,
    &producer,
    &observer_report,
    statuses,
    expected_checksum,
    open_loop_arrivals,
    open_loop_oracle.as_deref(),
  )?;
  let last_observed = observer_report.last_observed;
  if last_observed.saturating_duration_since(producer.production_end) > execution_deadlines().drain
  {
    return Err("application drain exceeded its finite deadline".into());
  }

  let shutdown_started = Instant::now();
  let mut shutdown_timings = Vec::with_capacity(2);
  match (options.executor, runtime) {
    (Executor::Bounded, ExecutorRuntime::Bounded(runtime)) => {
      let scope = scope_keepalive
        .take()
        .ok_or_else(|| "bounded scope ownership was lost".to_owned())?;
      let elapsed_ns = run_shutdown_with_timeout("allocatbelt async runtime", move || {
        runtime
          .block_on(scope.close())
          .map_err(|error| format!("scope close failed: {error}"))?;
        runtime
          .shutdown(AsyncShutdown::Drain)
          .map_err(|error| format!("allocatbelt runtime shutdown failed: {error}"))
      })?;
      shutdown_timings.push(("allocatbelt async runtime", elapsed_ns));
    }
    (Executor::Tokio, ExecutorRuntime::Tokio(runtime)) => {
      let elapsed_ns = run_shutdown_with_timeout("Tokio runtime", move || {
        runtime.shutdown_timeout(execution_deadlines().shutdown);
        Ok(())
      })?;
      shutdown_timings.push(("Tokio runtime", elapsed_ns));
    }
    _ => return Err("executor runtime ownership mismatch".into()),
  }
  if let Some(mut fs_runtime) = disk_runtime.take() {
    let elapsed_ns = run_shutdown_with_timeout("allocatbelt filesystem runtime", move || {
      fs_runtime
        .shutdown(allocatbelt::runtime::ShutdownMode::Drain)
        .map_err(|error| format!("allocatbelt filesystem runtime shutdown failed: {error}"))
    })?;
    shutdown_timings.push(("allocatbelt filesystem runtime", elapsed_ns));
  }
  let driver_shutdown_ns = shutdown_started.elapsed().as_nanos();
  write_shutdown_report(
    producer
      .production_end
      .saturating_duration_since(producer.started_at)
      .as_nanos(),
    production_cpu_ns,
    observer_report.completed_on_time + observer_report.completed_late,
    &shutdown_timings,
  )?;
  let rss_after_shutdown = sample_after_checkpoint_delay()?;
  let final_resources = resources.snapshot();
  if final_resources.managed_memory != 0
    || final_resources.disk_ops != 0
    || final_resources.network_ops != 0
  {
    return Err(format!(
      "nonzero final resource ledger: {final_resources:?}"
    ));
  }
  if producer.trace_overrun {
    return Err("open-loop producer exceeded its finite trace deadline".into());
  }
  let (blocking_workers, topology) = match (options.executor, options.workload) {
    (_, Workload::Disk) => match options.executor {
      Executor::Bounded => (4, "4 async + 4 filesystem workers"),
      Executor::Tokio => (4, "4 async + 4 blocking workers"),
    },
    (_, _) => (0, "4 async workers"),
  };
  let setup_ns = producer
    .started_at
    .saturating_duration_since(setup_started)
    .as_nanos();
  Ok(Counts {
    producer,
    observer: observer_report,
    expected_checksum,
    final_resources,
    blocking_workers,
    topology,
    setup_ns,
    timer_pair_median_ns,
    driver_shutdown_ns,
    rss_before,
    rss_after_drain,
    rss_after_shutdown,
  })
}

enum ExecutorRuntime {
  Bounded(AsyncRuntime),
  Tokio(tokio::runtime::Runtime),
}

fn resource_limits(workload: Workload) -> ResourceLimits {
  match workload {
    Workload::Cpu => ResourceLimits {
      managed_memory: 0,
      disk_concurrent_ops: 0,
      network_concurrent_ops: 0,
    },
    Workload::Memory => ResourceLimits {
      managed_memory: 160 * 1024,
      disk_concurrent_ops: 0,
      network_concurrent_ops: 0,
    },
    Workload::Http => ResourceLimits {
      managed_memory: 8 * (2 * allocatbelt_app_ports::http::MAX_REQUEST_BYTES + 2 * 128),
      disk_concurrent_ops: 0,
      network_concurrent_ops: 16,
    },
    Workload::Disk => ResourceLimits {
      managed_memory: 8 * DiskConfig::default().bytes,
      disk_concurrent_ops: 8,
      network_concurrent_ops: 0,
    },
  }
}

fn validate_options(options: Options) -> Result<(), String> {
  if options.mode == Mode::OpenLoop {
    let rate = options
      .rate_per_second
      .ok_or_else(|| "open-loop mode requires --rate".to_owned())?;
    if rate == 0 || rate > 1_000_000_000 {
      return Err("open-loop --rate must be in 1..=1000000000".into());
    }
  }
  Ok(())
}

fn validate_trace(options: Options, arrivals: usize, deadline: Duration) -> Result<(), String> {
  let rate = options
    .rate_per_second
    .ok_or_else(|| "open-loop mode requires --rate".to_owned())?;
  let trace_ns = (arrivals as u128)
    .checked_mul(1_000_000_000)
    .ok_or_else(|| "open-loop trace duration overflow".to_owned())?
    / u128::from(rate);
  let trace_ns =
    u64::try_from(trace_ns).map_err(|_| "open-loop trace duration overflow".to_owned())?;
  if Duration::from_nanos(trace_ns) > deadline {
    return Err("open-loop trace exceeds its finite trace deadline".into());
  }
  Ok(())
}

pub(super) fn arrival_times(
  id: u64,
  scheduled: Instant,
  completed: Instant,
  rate: u64,
) -> Result<(u64, u64), String> {
  if rate == 0 {
    return Err("per-ID arrival rate must be positive".into());
  }
  let offset_ns = u128::from(id)
    .checked_mul(1_000_000_000)
    .ok_or_else(|| "per-ID scheduled offset overflow".to_owned())?
    / u128::from(rate);
  let offset_ns =
    u64::try_from(offset_ns).map_err(|_| "per-ID scheduled offset overflow".to_owned())?;
  let origin = scheduled
    .checked_sub(Duration::from_nanos(offset_ns))
    .ok_or_else(|| "per-ID scheduled instant precedes trace origin".to_owned())?;
  let completion_ns = completed
    .checked_duration_since(origin)
    .ok_or_else(|| "per-ID completion precedes trace origin".to_owned())?
    .as_nanos();
  let completion_ns =
    u64::try_from(completion_ns).map_err(|_| "per-ID completion timestamp overflow".to_owned())?;
  Ok((offset_ns, completion_ns))
}

pub(super) fn validate_id_records(
  records: &[IdRecord],
  expected: &[u64],
) -> Result<(usize, usize), String> {
  if records.len() != expected.len() {
    return Err("per-ID report has a missing or extra terminal record".into());
  }
  let mut seen = Vec::new();
  seen
    .try_reserve_exact(expected.len())
    .map_err(|_| "could not reserve per-ID report validation table".to_owned())?;
  seen.resize(expected.len(), false);
  let mut completed = 0usize;
  let mut rejected = 0usize;
  for record in records {
    let index = usize::try_from(record.id).map_err(|_| "per-ID report ID overflow".to_owned())?;
    let slot = seen
      .get_mut(index)
      .ok_or_else(|| "per-ID report contains an out-of-range ID".to_owned())?;
    if *slot {
      return Err("per-ID report repeats a terminal ID".into());
    }
    *slot = true;
    if record.expected_checksum != expected[index] {
      return Err("per-ID report oracle checksum mismatch".into());
    }
    match record.terminal {
      "completed" if record.checksum == expected[index] => completed += 1,
      "rejected" if record.checksum == 0 => rejected += 1,
      "error" => return Err("per-ID report contains a failed terminal result".into()),
      _ => return Err("per-ID report terminal checksum is invalid".into()),
    }
  }
  if seen.iter().any(|recorded| !recorded) {
    return Err("per-ID report omitted a terminal ID".into());
  }
  Ok((completed, rejected))
}

fn trace_exceeded(mode: Mode, started_at: Instant, ended_at: Instant) -> bool {
  mode == Mode::OpenLoop
    && ended_at.saturating_duration_since(started_at) > execution_deadlines().trace
}

fn wall_through_drain_ns(
  started_at: Instant,
  production_end: Instant,
  last_observed: Instant,
) -> u128 {
  last_observed
    .max(production_end)
    .saturating_duration_since(started_at)
    .as_nanos()
}

struct WarmState {
  entrants: usize,
  released: bool,
}

struct WarmGate {
  state: Mutex<WarmState>,
  changed: Condvar,
  deadline: Instant,
}

impl WarmGate {
  fn new(expected: usize, timeout: Duration) -> Arc<Self> {
    let _ = expected;
    Arc::new(Self {
      state: Mutex::new(WarmState {
        entrants: 0,
        released: false,
      }),
      changed: Condvar::new(),
      deadline: Instant::now() + timeout,
    })
  }

  fn arrive_and_wait(&self) -> bool {
    let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
    state.entrants += 1;
    self.changed.notify_all();
    while !state.released {
      let Some(remaining) = self.deadline.checked_duration_since(Instant::now()) else {
        return false;
      };
      let (next, result) = self
        .changed
        .wait_timeout(state, remaining)
        .unwrap_or_else(|e| e.into_inner());
      state = next;
      if result.timed_out() && !state.released {
        return false;
      }
    }
    true
  }

  fn release_after_all(&self, expected: usize) -> Result<(), String> {
    let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
    while state.entrants < expected {
      let Some(remaining) = self.deadline.checked_duration_since(Instant::now()) else {
        return Err("worker warm-up exceeded 30 seconds".into());
      };
      let (next, result) = self
        .changed
        .wait_timeout(state, remaining)
        .unwrap_or_else(|e| e.into_inner());
      state = next;
      if result.timed_out() && state.entrants < expected {
        return Err("worker warm-up exceeded 30 seconds".into());
      }
    }
    state.released = true;
    self.changed.notify_all();
    Ok(())
  }
}

fn warm_bounded(handle: &AsyncHandle) -> Result<(), String> {
  let gate = WarmGate::new(WORKERS, WARMUP_TIMEOUT);
  let mut jobs = Vec::new();
  jobs
    .try_reserve_exact(WORKERS)
    .map_err(|_| "could not reserve worker warm-up handles".to_owned())?;
  for _ in 0..WORKERS {
    let gate = Arc::clone(&gate);
    jobs.push(
      handle
        .spawn(async move {
          let thread_id = thread::current().id();
          let ready = gate.arrive_and_wait();
          (thread_id, ready)
        })
        .map_err(|error| format!("allocatbelt warm-up admission failed: {}", error.kind))?,
    );
  }
  gate.release_after_all(WORKERS)?;
  let mut seen = HashSet::new();
  for job in jobs {
    let (thread_id, ready) = handle
      .block_on(job)
      .map_err(|error| format!("allocatbelt warm-up root failed: {error}"))?
      .map_err(|error| format!("allocatbelt warm-up task failed: {error}"))?;
    if !ready {
      return Err("allocatbelt worker warm-up gate timed out".into());
    }
    seen.insert(thread_id);
  }
  if seen.len() != WORKERS {
    return Err(format!(
      "expected {WORKERS} started async workers, saw {}",
      seen.len()
    ));
  }
  Ok(())
}

fn warm_tokio(handle: &tokio::runtime::Handle) -> Result<(), String> {
  let gate = WarmGate::new(WORKERS, WARMUP_TIMEOUT);
  let mut jobs = Vec::new();
  jobs
    .try_reserve_exact(WORKERS)
    .map_err(|_| "could not reserve Tokio warm-up handles".to_owned())?;
  for _ in 0..WORKERS {
    let gate = Arc::clone(&gate);
    jobs.push(handle.spawn(async move {
      let thread_id = thread::current().id();
      let ready = gate.arrive_and_wait();
      (thread_id, ready)
    }));
  }
  gate.release_after_all(WORKERS)?;
  let mut seen = HashSet::new();
  for job in jobs {
    let (thread_id, ready) = handle
      .block_on(job)
      .map_err(|error| format!("Tokio warm-up task failed: {error}"))?;
    if !ready {
      return Err("Tokio worker warm-up gate timed out".into());
    }
    seen.insert(thread_id);
  }
  if seen.len() != WORKERS {
    return Err(format!(
      "expected {WORKERS} started Tokio workers, saw {}",
      seen.len()
    ));
  }
  Ok(())
}

#[allow(clippy::too_many_arguments)]
fn produce(
  submitter: Submitter,
  options: Options,
  config: LaneConfig,
  resources: &ResourceScope,
  events: ObserverEventSender<ObserverEvent>,
  credits: mpsc::Receiver<()>,
  states: Option<Arc<Mutex<Vec<IdState>>>>,
  capacity_horizon: Duration,
  open_loop_arrivals: usize,
) -> Result<ProducerReport, String> {
  let start = Instant::now();
  let horizon_end = match options.mode {
    Mode::Capacity => start + capacity_horizon,
    Mode::OpenLoop => {
      let rate = options.rate_per_second.expect("validated open-loop rate");
      start
        + Duration::from_nanos(((open_loop_arrivals as u128 * 1_000_000_000) / rate as u128) as u64)
    }
  };
  let mut attempted = 0;
  let mut admitted = 0;
  let mut rejected_logical_window = 0;
  let mut rejected_backend_full = 0;
  let mut lateness_sum_ns = 0u128;
  let mut lateness_max_ns = 0u64;
  let mut outstanding = 0usize;
  let mut next_capacity_id = 0u64;

  loop {
    while let Ok(()) = credits.try_recv() {
      outstanding = outstanding.saturating_sub(1);
    }
    let (id, scheduled) = match options.mode {
      Mode::Capacity => {
        if Instant::now() >= horizon_end {
          break;
        }
        if attempted >= MAX_CAPACITY_JOBS {
          return Err(
            "capacity mode reached the 10,000,000 operation safety cap before its horizon".into(),
          );
        }
        while outstanding >= WINDOW {
          if Instant::now() >= horizon_end {
            break;
          }
          match credits.recv_timeout(horizon_end.saturating_duration_since(Instant::now())) {
            Ok(()) => outstanding -= 1,
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
              return Err("capacity observer closed before returning window credit".into());
            }
          }
        }
        if Instant::now() >= horizon_end {
          break;
        }
        let id = next_capacity_id;
        next_capacity_id += 1;
        (id, Instant::now())
      }
      Mode::OpenLoop => {
        if attempted >= open_loop_arrivals {
          break;
        }
        let rate = options.rate_per_second.expect("validated open-loop rate");
        let scheduled_ns = (attempted as u128 * 1_000_000_000) / rate as u128;
        let scheduled = start + Duration::from_nanos(scheduled_ns as u64);
        if let Some(remaining) = scheduled.checked_duration_since(Instant::now()) {
          thread::sleep(remaining);
        }
        while let Ok(()) = credits.try_recv() {
          outstanding = outstanding.saturating_sub(1);
        }
        (attempted as u64, scheduled)
      }
    };
    let lateness_ns = Instant::now()
      .saturating_duration_since(scheduled)
      .as_nanos();
    lateness_sum_ns = lateness_sum_ns.saturating_add(lateness_ns);
    lateness_max_ns = lateness_max_ns.max(lateness_ns.min(u128::from(u64::MAX)) as u64);
    attempted += 1;
    let state_table = states.as_ref();
    if options.mode == Mode::OpenLoop && outstanding >= WINDOW {
      rejected_logical_window += 1;
      if let Some(states) = state_table {
        states.lock().unwrap_or_else(|e| e.into_inner())[id as usize] = IdState::Rejected;
      }
      events
        .send(ObserverEvent::Rejected { id, scheduled })
        .map_err(|_| "observer queue closed before rejection publication".to_owned())?;
      continue;
    }
    match submitter.submit(options.workload, config, resources, id) {
      Ok(job) => {
        admitted += 1;
        outstanding += 1;
        if let Some(states) = state_table {
          states.lock().unwrap_or_else(|e| e.into_inner())[id as usize] = IdState::Admitted;
        }
        events
          .send(ObserverEvent::Job {
            id,
            scheduled,
            horizon_end,
            job,
          })
          .map_err(|_| "observer queue closed before publication".to_owned())?;
      }
      Err(Rejection::Full) => {
        rejected_backend_full += 1;
        if let Some(states) = state_table {
          states.lock().unwrap_or_else(|e| e.into_inner())[id as usize] = IdState::Rejected;
        }
        if options.mode == Mode::OpenLoop {
          events
            .send(ObserverEvent::Rejected { id, scheduled })
            .map_err(|_| "observer queue closed before rejection publication".to_owned())?;
        }
        if options.mode == Mode::Capacity {
          return Err("capacity mode encountered a backend Full rejection".into());
        }
      }
      Err(Rejection::Closed) => return Err("executor closed during admission".into()),
    }
  }
  let production_end = Instant::now();
  let trace_overrun = trace_exceeded(options.mode, start, production_end);
  events
    .send(ObserverEvent::Done {
      attempted,
      horizon_end,
    })
    .map_err(|_| "observer queue closed before producer completion".to_owned())?;
  Ok(ProducerReport {
    attempted,
    admitted,
    rejected_full: rejected_logical_window + rejected_backend_full,
    rejected_logical_window,
    rejected_backend_full,
    lateness_sum_ns,
    lateness_max_ns,
    started_at: start,
    production_end,
    trace_overrun,
  })
}

#[allow(clippy::too_many_arguments)]
fn observe(
  observer: Observer,
  options: Options,
  config: LaneConfig,
  resources: ResourceScope,
  events: mpsc::Receiver<ObserverEvent>,
  credits: mpsc::SyncSender<()>,
  states: Option<Arc<Mutex<Vec<IdState>>>>,
  open_loop_arrivals: usize,
  pending_limit: usize,
  watchdog_timeout: Duration,
  open_loop_oracle: Option<Arc<Vec<u64>>>,
) -> Result<ObserverReport, String> {
  let mut completed_on_time = 0;
  let mut completed_late = 0;
  let mut errors = 0;
  let cancellations = 0;
  let mut digest = 0u64;
  let mut latencies_ns = Vec::new();
  let mut records = Vec::new();
  if options.mode == Mode::OpenLoop {
    records
      .try_reserve_exact(open_loop_arrivals)
      .map_err(|_| "could not reserve bounded per-ID records".to_owned())?;
  }
  if options.mode == Mode::OpenLoop {
    latencies_ns
      .try_reserve_exact(open_loop_arrivals)
      .map_err(|_| "could not reserve bounded latency samples".to_owned())?;
  }
  let mut retained = VecDeque::new();
  let mut max_observed_managed_bytes = 0;
  let mut retained_managed_bytes = 0usize;
  let mut last_observed = Instant::now();
  let mut next_capacity_id = 0u64;
  let mut pending = Vec::<(u64, Instant, Instant, Job)>::new();
  pending
    .try_reserve_exact(pending_limit)
    .map_err(|_| "could not reserve bounded observer jobs".to_owned())?;
  let mut producer_done = false;
  let completion_waker = Waker::from(Arc::new(ObserverWake(thread::current())));
  loop {
    let mut made_progress = false;
    let event = match events.try_recv() {
      Ok(event) => Some(event),
      Err(mpsc::TryRecvError::Empty) => None,
      Err(mpsc::TryRecvError::Disconnected) => {
        if !producer_done {
          return Err("observer queue closed before pending jobs were consumed".into());
        }
        None
      }
    };
    if let Some(event) = event {
      made_progress = true;
      match event {
        ObserverEvent::Done {
          attempted: _attempted,
          horizon_end: _horizon_end,
        } => {
          producer_done = true;
        }
        ObserverEvent::Rejected { id, scheduled } => {
          let completion = Instant::now();
          let rate = options
            .rate_per_second
            .ok_or_else(|| "open-loop rate missing".to_owned())?;
          let (scheduled_ns, completion_ns) = arrival_times(id, scheduled, completion, rate)?;
          let expected_checksum =
            open_loop_expected(options.workload, &config, id, open_loop_oracle.as_deref())?;
          records.push(IdRecord {
            id,
            scheduled_ns,
            completion_ns,
            terminal: "rejected",
            checksum: 0,
            expected_checksum,
          });
        }
        ObserverEvent::Job {
          id,
          scheduled,
          horizon_end,
          job,
        } => {
          if options.mode == Mode::Capacity {
            accept_capacity_id(&mut next_capacity_id, id)?;
          }
          pending.push((id, scheduled, horizon_end, job));
        }
      }
    }
    record_managed_sample(&resources, &mut max_observed_managed_bytes);
    let mut index = 0;
    while index < pending.len() {
      let poll = {
        let mut context = Context::from_waker(&completion_waker);
        pending[index].3.poll_finished(&mut context)
      };
      if poll.is_pending() {
        index += 1;
        continue;
      }
      let (id, scheduled, horizon_end, job) = pending.swap_remove(index);
      made_progress = true;
      let result = observer.join(job);
      let observed = Instant::now();
      last_observed = observed;
      let mut completed = false;
      let mut checksum = 0;
      match result {
        Ok(output) => {
          let output_value = output.value();
          checksum = output_value;
          if !validate_output_with_oracle(
            options.workload,
            &config,
            id,
            &output,
            open_loop_oracle.as_deref(),
          ) {
            errors += 1;
          } else {
            completed = true;
            digest = digest.wrapping_add(output_value ^ id);
            if observed <= horizon_end {
              completed_on_time += 1;
            } else {
              completed_late += 1;
            }
            if options.mode == Mode::OpenLoop {
              latencies_ns.push(observed.saturating_duration_since(scheduled).as_nanos() as u64);
            }
            if let WorkOutput::Memory(memory) = output {
              record_managed_sample(&resources, &mut max_observed_managed_bytes);
              if retained.len() == MAX_RETAINED_MEMORY_OUTPUTS
                && let Some(WorkOutput::Memory(old)) = retained.pop_front()
              {
                retained_managed_bytes =
                  retained_managed_bytes.saturating_sub(old.buffer.charged_bytes());
              }
              retained_managed_bytes += memory.buffer.charged_bytes();
              retained.push_back(WorkOutput::Memory(memory));
            }
          }
        }
        Err(_) => {
          errors += 1;
          if options.mode == Mode::OpenLoop {
            latencies_ns.push(observed.saturating_duration_since(scheduled).as_nanos() as u64);
          }
        }
      }
      if options.mode == Mode::OpenLoop {
        let rate = options
          .rate_per_second
          .ok_or_else(|| "open-loop rate missing".to_owned())?;
        let (scheduled_ns, completion_ns) = arrival_times(id, scheduled, observed, rate)?;
        let expected_checksum =
          open_loop_expected(options.workload, &config, id, open_loop_oracle.as_deref())?;
        records.push(IdRecord {
          id,
          scheduled_ns,
          completion_ns,
          terminal: if completed { "completed" } else { "error" },
          checksum,
          expected_checksum,
        });
      }
      if let Some(states) = &states {
        let mut states = states.lock().unwrap_or_else(|e| e.into_inner());
        let state = states
          .get_mut(id as usize)
          .ok_or_else(|| "observer saw an out-of-range open-loop ID".to_owned())?;
        if *state != IdState::Admitted {
          return Err("observer saw a duplicate or unadmitted open-loop ID".into());
        }
        *state = if completed {
          IdState::Completed
        } else {
          IdState::Failed
        };
      }
      let _ = credits.send(());
    }
    if producer_done && pending.is_empty() {
      let final_statuses =
        states.map(|states| std::mem::take(&mut *states.lock().unwrap_or_else(|e| e.into_inner())));
      return Ok(ObserverReport {
        completed_on_time,
        completed_late,
        errors,
        cancellations,
        digest,
        latencies_ns,
        max_observed_managed_bytes,
        retained_managed_bytes,
        final_statuses,
        last_observed,
        records,
      });
    }
    if !made_progress {
      thread::park_timeout(watchdog_timeout);
    }
  }
}

fn record_managed_sample(resources: &ResourceScope, maximum: &mut usize) {
  *maximum = (*maximum).max(resources.snapshot().managed_memory);
}

fn job_seed(id: u64) -> u64 {
  0x6a09_e667_f3bc_c909 ^ id.wrapping_mul(0xd6e8_feb8_6659_fd93)
}

fn expected_value(workload: Workload, config: &LaneConfig, id: u64) -> u64 {
  let seed = job_seed(id);
  match workload {
    Workload::Cpu => cpu::kernel(seed, config.rounds),
    Workload::Memory => {
      let cfg = MemoryConfig {
        seed,
        ..config.memory
      };
      (0..cfg.grown_bytes).fold(0xcbf2_9ce4_8422_2325, |hash, index| {
        (hash ^ u64::from(memory::pattern_byte(seed, index))).wrapping_mul(0x0000_0100_0000_01b3)
      })
    }
    Workload::Http => 0,
    Workload::Disk => {
      let disk_config = DiskConfig {
        seed,
        ..config.disk
      };
      (0..disk_config.bytes).fold(0xcbf2_9ce4_8422_2325, |hash, index| {
        (hash ^ u64::from(disk::payload_byte(disk_config.seed, index)))
          .wrapping_mul(0x0000_0100_0000_01b3)
      })
    }
  }
}

fn open_loop_expected(
  workload: Workload,
  config: &LaneConfig,
  id: u64,
  oracle: Option<&Vec<u64>>,
) -> Result<u64, String> {
  match oracle {
    Some(values) => values
      .get(id as usize)
      .copied()
      .ok_or_else(|| "open-loop per-ID oracle missed a result".to_owned()),
    None => Ok(expected_value(workload, config, id)),
  }
}

fn build_expected_oracle(
  workload: Workload,
  config: &LaneConfig,
  count: usize,
) -> Result<Arc<Vec<u64>>, String> {
  if count > MAX_OPEN_LOOP_ARRIVALS {
    return Err("open-loop reference oracle exceeds the configured ID bound".into());
  }
  let mut oracle = Vec::new();
  oracle
    .try_reserve_exact(count)
    .map_err(|_| "could not reserve bounded open-loop result oracle".to_owned())?;
  oracle.extend((0..count).map(|id| canonical_expected_value(workload, config, id as u64)));
  Ok(Arc::new(oracle))
}

fn canonical_expected_value(workload: Workload, config: &LaneConfig, id: u64) -> u64 {
  match workload {
    Workload::Http => http::expected_request_checksum(id, http::ORACLE_BODY_BYTES),
    _ => expected_value(workload, config, id),
  }
}

fn oracle_kernel_config(workload: Workload, config: &LaneConfig) -> String {
  match workload {
    Workload::Cpu => format!("rounds={}", config.rounds),
    Workload::Memory => format!(
      "initial_bytes={};grown_bytes={};seed={:#018x}",
      config.memory.initial_bytes, config.memory.grown_bytes, config.memory.seed
    ),
    Workload::Disk => format!(
      "bytes={};offset={};seed={:#018x}",
      config.disk.bytes, config.disk.offset, config.disk.seed
    ),
    Workload::Http => format!("body_bytes={}", http::ORACLE_BODY_BYTES),
  }
}

fn emit_oracle_only(args: impl Iterator<Item = String>) -> Result<(), String> {
  let mut args = args;
  let command = args
    .next()
    .ok_or_else(|| "--emit-oracle-only requires an output path".to_owned())?;
  if command != "--emit-oracle-only" {
    return Err("oracle emitter command must start with --emit-oracle-only".into());
  }
  let path = args
    .next()
    .ok_or_else(|| "--emit-oracle-only requires an output path".to_owned())?;
  let mut workload = None;
  let mut rate = None;
  let mut arrivals = OPEN_LOOP_ARRIVALS;
  let mut arrivals_set = false;
  let mut deadlines = ExecutionDeadlines::default();
  let mut source_hash = None;
  let mut binary_hash = None;
  while let Some(key) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| format!("missing value for {key}"))?;
    match key.as_str() {
      "--workload" => workload = Some(Workload::parse(&value)?),
      "--rate" => rate = Some(value.parse().map_err(|_| "invalid --rate".to_owned())?),
      "--arrivals" => {
        arrivals = value.parse().map_err(|_| "invalid --arrivals".to_owned())?;
        arrivals_set = true;
      }
      "--trace-deadline-seconds" => deadlines.trace = parse_deadline(&value, "trace")?,
      "--source-sha256" => source_hash = Some(value),
      "--binary-sha256" => binary_hash = Some(value),
      _ => return Err(format!("unknown oracle argument {key}")),
    }
  }
  let workload = workload.ok_or_else(|| "oracle emitter requires --workload".to_owned())?;
  let source_hash =
    source_hash.ok_or_else(|| "oracle emitter requires --source-sha256".to_owned())?;
  let binary_hash =
    binary_hash.ok_or_else(|| "oracle emitter requires --binary-sha256".to_owned())?;
  if !is_hex(&source_hash, 64) || !is_hex(&binary_hash, 64) {
    return Err("oracle source and binary hashes must be 64 hexadecimal characters".into());
  }
  let rate = rate.ok_or_else(|| "oracle emitter requires --rate".to_owned())?;
  if !(1..=1_000_000_000).contains(&rate) {
    return Err("oracle --rate must be in 1..=1000000000".into());
  }
  if !arrivals_set {
    return Err("oracle emitter requires an explicit --arrivals count".into());
  }
  if deadlines.trace.as_secs() > 3600 {
    return Err("oracle trace deadline exceeds its finite 3600 second bound".into());
  }
  validate_arrivals(arrivals)?;
  let options = Options {
    executor: Executor::Bounded,
    workload,
    mode: Mode::OpenLoop,
    rate_per_second: Some(rate),
  };
  validate_trace(options, arrivals, deadlines.trace)?;
  let config = LaneConfig::default();
  let oracle = build_expected_oracle(workload, &config, arrivals)?;
  let mut report = String::from("schema\tallocatbelt-app-oracle-v1\n");
  report.push_str(&format!(
    "source_sha256\t{source_hash}\nbinary_sha256\t{binary_hash}\n"
  ));
  report.push_str(&format!(
    "workload\t{}\nmode\topen_loop\n",
    workload.label()
  ));
  report.push_str(&format!("rate_per_second\t{rate}\narrivals\t{arrivals}\n"));
  report.push_str(&format!(
    "kernel_config\t{}\n",
    oracle_kernel_config(workload, &config)
  ));
  report.push_str("id\texpected_checksum\n");
  for (id, checksum) in oracle.iter().enumerate() {
    report.push_str(&format!("{id}\t{checksum}\n"));
  }
  let mut file = OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(path)
    .map_err(|error| format!("oracle output create failed: {error}"))?;
  file
    .write_all(report.as_bytes())
    .map_err(|error| format!("oracle output write failed: {error}"))
}

#[cfg(test)]
fn validate_output(workload: Workload, config: &LaneConfig, id: u64, output: &WorkOutput) -> bool {
  validate_output_with_oracle(workload, config, id, output, None)
}

fn validate_output_with_oracle(
  workload: Workload,
  config: &LaneConfig,
  id: u64,
  output: &WorkOutput,
  open_loop_oracle: Option<&Vec<u64>>,
) -> bool {
  match (workload, output) {
    (Workload::Cpu, WorkOutput::Cpu(value)) => {
      let expected = match open_loop_oracle {
        Some(oracle) => oracle.get(id as usize).copied(),
        None => Some(expected_value(workload, config, id)),
      };
      expected == Some(*value)
    }
    (Workload::Memory, WorkOutput::Memory(output)) => {
      let expected = match open_loop_oracle {
        Some(oracle) => oracle.get(id as usize).copied(),
        None => Some(expected_value(workload, config, id)),
      };
      output.report.charged_after_growth == output.buffer.charged_bytes()
        && output.buffer.len() == config.memory.grown_bytes
        && output.report.checksum == memory::checksum(output.buffer.as_slice())
        && expected == Some(output.report.checksum)
    }
    (Workload::Disk, WorkOutput::Disk(output)) => {
      let expected = match open_loop_oracle {
        Some(oracle) => oracle.get(id as usize).copied(),
        None => Some(expected_value(workload, config, id)),
      };
      output.offset == config.disk.offset
        && output.bytes == config.disk.bytes
        && expected == Some(output.checksum)
        && output.temp_directory_removed
    }
    _ => false,
  }
}

fn accept_capacity_id(next: &mut u64, id: u64) -> Result<(), String> {
  if id != *next {
    return Err(format!("capacity observer expected ID {next}, got {id}"));
  }
  *next = next
    .checked_add(1)
    .ok_or_else(|| "capacity observer ID overflow".to_owned())?;
  Ok(())
}

fn expected_digest(
  options: Options,
  observer: &ObserverReport,
  producer: &ProducerReport,
  open_loop_oracle: Option<&Vec<u64>>,
) -> u64 {
  let mut digest = 0u64;
  match &observer.final_statuses {
    Some(statuses) => {
      for (id, state) in statuses.iter().enumerate() {
        if *state == IdState::Completed {
          let value = match open_loop_oracle {
            Some(oracle) => oracle[id],
            None => expected_value(options.workload, &LaneConfig::default(), id as u64),
          };
          digest = digest.wrapping_add(value ^ id as u64);
        }
      }
    }
    None => {
      let count = producer.admitted;
      for id in 0..count {
        let value = match open_loop_oracle {
          Some(oracle) => oracle[id],
          None => expected_value(options.workload, &LaneConfig::default(), id as u64),
        };
        digest = digest.wrapping_add(value ^ id as u64);
      }
    }
  }
  digest
}

fn validate_counts(
  options: Options,
  producer: &ProducerReport,
  observer: &ObserverReport,
  statuses: Option<&Vec<IdState>>,
  expected_checksum: u64,
  open_loop_arrivals: usize,
  open_loop_oracle: Option<&Vec<u64>>,
) -> Result<(), String> {
  let completed = observer.completed_on_time + observer.completed_late;
  if producer.rejected_full != producer.rejected_logical_window + producer.rejected_backend_full {
    return Err("Full rejection counters do not reconcile".into());
  }
  if observer.digest != expected_checksum {
    return Err("per-ID validated results do not match the independent digest".into());
  }
  if observer.errors != 0 || observer.cancellations != 0 {
    return Err("application lane reported an error or cancellation".into());
  }
  if producer.admitted != completed {
    return Err(format!(
      "admitted/completed mismatch: {} != {completed}",
      producer.admitted
    ));
  }
  if options.mode == Mode::Capacity && producer.rejected_full != 0 {
    return Err("capacity mode rejected an operation".into());
  }
  if options.mode == Mode::OpenLoop {
    let oracle = open_loop_oracle
      .ok_or_else(|| "open-loop checksum oracle missing during per-ID validation".to_owned())?;
    if oracle.len() != open_loop_arrivals {
      return Err("open-loop checksum oracle length differs from requested arrivals".into());
    }
    let (recorded_completed, recorded_rejected) = validate_id_records(&observer.records, oracle)?;
    if recorded_completed != producer.admitted || recorded_rejected != producer.rejected_full {
      return Err("per-ID terminal counts differ from the producer report".into());
    }
    let states = statuses.ok_or_else(|| "open-loop ID table missing after drain".to_owned())?;
    if states.len() != open_loop_arrivals
      || states
        .iter()
        .any(|state| !matches!(state, IdState::Rejected | IdState::Completed))
      || states
        .iter()
        .filter(|state| **state == IdState::Completed)
        .count()
        != producer.admitted
    {
      return Err("open-loop IDs are missing, repeated, or unresolved".into());
    }
    if producer.attempted != open_loop_arrivals
      || producer.attempted != producer.admitted + producer.rejected_full
    {
      return Err("open-loop attempt accounting does not balance".into());
    }
  }
  Ok(())
}

/// Parses CLI arguments and emits one TSV row. The caller supplies the
/// allocator label from its binary; this function performs no timing run
/// until explicitly invoked by the benchmark runner.
pub fn main(allocator: &'static str) -> ExitCode {
  let args = env::args().skip(1).collect::<Vec<_>>();
  if args
    .first()
    .is_some_and(|argument| argument == "--emit-oracle-only")
  {
    return match emit_oracle_only(args.into_iter()) {
      Ok(()) => ExitCode::SUCCESS,
      Err(error) => {
        eprintln!("application oracle invalid: {error}");
        ExitCode::from(2)
      }
    };
  }
  match parse_args(args.into_iter()) {
    Ok((options, arrivals, deadlines)) if options.workload == Workload::Http => {
      let _ = EXECUTION_DEADLINES.set(deadlines);
      match http::run_and_print(allocator, options, arrivals) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
          eprintln!("application run invalid: {error}");
          ExitCode::FAILURE
        }
      }
    }
    Ok((options, arrivals, deadlines)) if options.workload == Workload::Disk => {
      let _ = EXECUTION_DEADLINES.set(deadlines);
      match disk_lane::run_and_print(allocator, options, arrivals) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
          eprintln!("application run invalid: {error}");
          ExitCode::FAILURE
        }
      }
    }
    Ok((options, arrivals, deadlines)) => {
      let _ = EXECUTION_DEADLINES.set(deadlines);
      match run_with_limits(options, None, Some(arrivals)) {
        Ok(counts) => {
          if let Err(error) = write_id_report(&counts.observer.records, allocator, options) {
            eprintln!("application run invalid: {error}");
            return ExitCode::FAILURE;
          }
          print_row(allocator, options, &counts);
          ExitCode::SUCCESS
        }
        Err(error) => {
          eprintln!("application run invalid: {error}");
          ExitCode::FAILURE
        }
      }
    }
    Err(error) => {
      eprintln!("{error}\n{}", usage());
      ExitCode::from(2)
    }
  }
}

fn parse_args(
  args: impl Iterator<Item = String>,
) -> Result<(Options, usize, ExecutionDeadlines), String> {
  let mut executor = None;
  let mut workload = None;
  let mut mode = None;
  let mut rate = None;
  let mut arrivals = OPEN_LOOP_ARRIVALS;
  let mut arrivals_set = false;
  let mut deadlines = ExecutionDeadlines::default();
  let mut args = args;
  while let Some(key) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| format!("missing value for {key}"))?;
    match key.as_str() {
      "--executor" => executor = Some(Executor::parse(&value)?),
      "--workload" => workload = Some(Workload::parse(&value)?),
      "--mode" => mode = Some(Mode::parse(&value)?),
      "--rate" => rate = Some(value.parse().map_err(|_| "invalid --rate".to_owned())?),
      "--arrivals" => {
        arrivals = value.parse().map_err(|_| "invalid --arrivals".to_owned())?;
        arrivals_set = true;
      }
      "--trace-deadline-seconds" => deadlines.trace = parse_deadline(&value, "trace")?,
      "--drain-deadline-seconds" => deadlines.drain = parse_deadline(&value, "drain")?,
      "--shutdown-deadline-seconds" => deadlines.shutdown = parse_deadline(&value, "shutdown")?,
      "--process-deadline-seconds" => deadlines.process = parse_deadline(&value, "process")?,
      _ => return Err(format!("unknown argument {key}")),
    }
  }
  let options = Options {
    executor: executor.ok_or_else(|| "--executor is required".to_owned())?,
    workload: workload.ok_or_else(|| "--workload is required".to_owned())?,
    mode: mode.ok_or_else(|| "--mode is required".to_owned())?,
    rate_per_second: rate,
  };
  validate_options(options)?;
  validate_deadline_budget(deadlines, options.workload, options.executor, options.mode)?;
  if options.mode == Mode::OpenLoop {
    validate_arrivals(arrivals)?;
    validate_trace(options, arrivals, deadlines.trace)?;
  } else if arrivals_set {
    return Err("--arrivals applies only to open_loop mode".into());
  }
  Ok((options, arrivals, deadlines))
}

fn parse_deadline(value: &str, name: &str) -> Result<Duration, String> {
  let seconds = value
    .parse::<u64>()
    .map_err(|_| format!("invalid --{name}-deadline-seconds"))?;
  if seconds == 0 {
    return Err(format!("--{name}-deadline-seconds must be positive"));
  }
  Ok(Duration::from_secs(seconds))
}

fn validate_deadline_budget(
  deadlines: ExecutionDeadlines,
  workload: Workload,
  executor: Executor,
  mode: Mode,
) -> Result<(), String> {
  let caps = [3600, 3600, 600, 7200];
  let seconds = [
    deadlines.trace.as_secs(),
    deadlines.drain.as_secs(),
    deadlines.shutdown.as_secs(),
    deadlines.process.as_secs(),
  ];
  if seconds.iter().zip(caps).any(|(value, cap)| *value > cap) {
    return Err("deadline exceeds its finite safety bound".into());
  }
  let trace_seconds = if mode == Mode::OpenLoop {
    deadlines.trace.as_secs()
  } else {
    // Keep the measurement horizon at 30 seconds, with a separate finite
    // allowance to observe that horizon and publish production completion.
    CAPACITY_HORIZON.as_secs() + 1
  };
  let shutdown_units = match (workload, executor) {
    (Workload::Http, Executor::Bounded) => 3,
    (Workload::Disk, Executor::Bounded) => 2,
    _ => 1,
  };
  let required = SETUP_DEADLINE
    .as_secs()
    .checked_add(trace_seconds)
    .and_then(|value| value.checked_add(deadlines.drain.as_secs()))
    .and_then(|value| value.checked_add(deadlines.shutdown.as_secs().checked_mul(shutdown_units)?))
    .ok_or_else(|| "deadline budget arithmetic overflow".to_owned())?;
  if deadlines.process.as_secs() < required {
    return Err("process deadline must cover setup, trace, drain, and every shutdown phase".into());
  }
  Ok(())
}

fn validate_arrivals(arrivals: usize) -> Result<(), String> {
  if !(1..=MAX_OPEN_LOOP_ARRIVALS).contains(&arrivals) {
    return Err(format!(
      "--arrivals must be in 1..={MAX_OPEN_LOOP_ARRIVALS}"
    ));
  }
  Ok(())
}

fn usage() -> &'static str {
  "usage: bench-application-* --executor bounded|tokio --workload cpu|memory|http|disk --mode capacity|open_loop [--rate ARRIVALS_PER_SECOND] [--arrivals N] [--trace-deadline-seconds S --drain-deadline-seconds S --shutdown-deadline-seconds S --process-deadline-seconds S]; or --emit-oracle-only PATH --workload cpu|memory|http|disk --rate N --arrivals N"
}

fn print_row(allocator: &str, options: Options, counts: &Counts) {
  let completed = counts.observer.completed_on_time + counts.observer.completed_late;
  let wall_ns = wall_through_drain_ns(
    counts.producer.started_at,
    counts.producer.production_end,
    counts.observer.last_observed,
  );
  let capacity_rate = if options.mode == Mode::Capacity {
    ((counts.observer.completed_on_time as f64) / CAPACITY_HORIZON.as_secs_f64()).to_string()
  } else {
    String::new()
  };
  let drained_rate = completed as f64 / wall_ns.max(1) as f64 * 1_000_000_000.0;
  let mut samples = counts.observer.latencies_ns.clone();
  samples.sort_unstable();
  let p50 = percentile(&samples, 50);
  let p95 = percentile(&samples, 95);
  let p99 = percentile(&samples, 99);
  let drain_tail_ns = counts
    .observer
    .last_observed
    .saturating_duration_since(counts.producer.production_end)
    .as_nanos();
  let final_resources = &counts.final_resources;
  let limits = resource_limits(options.workload);
  let global_task_limit = match options.workload {
    Workload::Http => 17,
    _ => WINDOW,
  };
  let fields = [
    "2".to_owned(),
    allocator.to_owned(),
    options.executor.label().to_owned(),
    options.workload.label().to_owned(),
    options.mode.label().to_owned(),
    WORKERS.to_string(),
    counts.blocking_workers.to_string(),
    counts.topology.to_owned(),
    WINDOW.to_string(),
    global_task_limit.to_string(),
    if options.workload == Workload::Memory {
      WINDOW
    } else {
      0
    }
    .to_string(),
    options
      .rate_per_second
      .map_or(String::new(), |rate| rate.to_string()),
    if options.mode == Mode::OpenLoop {
      counts.producer.attempted.to_string()
    } else {
      String::new()
    },
    counts.producer.attempted.to_string(),
    counts.producer.admitted.to_string(),
    counts.producer.rejected_full.to_string(),
    "0".to_owned(),
    counts.observer.completed_on_time.to_string(),
    counts.observer.completed_late.to_string(),
    counts.observer.errors.to_string(),
    counts.observer.cancellations.to_string(),
    counts
      .producer
      .admitted
      .saturating_sub(completed + counts.observer.errors + counts.observer.cancellations)
      .to_string(),
    counts
      .producer
      .attempted
      .saturating_sub(completed)
      .to_string(),
    counts.observer.digest.to_string(),
    counts.expected_checksum.to_string(),
    capacity_rate,
    drained_rate.to_string(),
    counts.setup_ns.to_string(),
    counts.timer_pair_median_ns.to_string(),
    wall_ns.to_string(),
    drain_tail_ns.to_string(),
    p50.to_string(),
    p95.to_string(),
    p99.to_string(),
    if counts.producer.attempted == 0 {
      "0".to_owned()
    } else {
      (counts.producer.lateness_sum_ns / counts.producer.attempted as u128).to_string()
    },
    counts.producer.lateness_max_ns.to_string(),
    counts.observer.max_observed_managed_bytes.to_string(),
    counts.observer.retained_managed_bytes.to_string(),
    limits.managed_memory.to_string(),
    limits.disk_concurrent_ops.to_string(),
    limits.network_concurrent_ops.to_string(),
    final_resources.managed_memory.to_string(),
    final_resources.disk_ops.to_string(),
    final_resources.network_ops.to_string(),
    counts.rss_before.rss_kib.to_string(),
    counts.rss_after_drain.rss_kib.to_string(),
    counts.rss_after_shutdown.rss_kib.to_string(),
    counts.rss_before.hwm_kib.to_string(),
    counts.rss_after_drain.hwm_kib.to_string(),
    counts.rss_after_shutdown.hwm_kib.to_string(),
    counts.driver_shutdown_ns.to_string(),
    counts.producer.rejected_logical_window.to_string(),
    counts.producer.rejected_backend_full.to_string(),
  ];
  debug_assert_eq!(fields.len(), TSV_HEADER.split('\t').count());
  println!("{TSV_HEADER}");
  let output = format!("{}\n", fields.join("\t"));
  let _ = io::stdout().write_all(output.as_bytes());
}

fn percentile(samples: &[u64], percentile: usize) -> u64 {
  if samples.is_empty() {
    return 0;
  }
  let rank = percentile
    .saturating_mul(samples.len())
    .div_ceil(100)
    .max(1);
  samples[rank.saturating_sub(1).min(samples.len() - 1)]
}

#[cfg(test)]
mod tests {
  use super::{
    AsyncConfig, AsyncRuntime, AsyncShutdown, DiskReport, Executor, IdState, Job, LaneConfig, Mode,
    Observer, ObserverEvent, ObserverEventSender, ObserverReport, Options, ProducerReport,
    WorkOutput, Workload, accept_capacity_id, observe, resource_limits, run_with_limits,
    validate_output,
  };
  use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
  use std::sync::{Arc, Mutex, OnceLock, mpsc};
  use std::task::Waker;
  use std::thread;
  use std::time::{Duration, Instant};

  #[test]
  fn cli_arrival_count_is_optional_bounded_and_open_loop_only() {
    let base = [
      "--executor",
      "bounded",
      "--workload",
      "cpu",
      "--mode",
      "open_loop",
      "--rate",
      "1000",
    ];
    let parsed =
      super::parse_args(base.iter().map(|value| (*value).to_owned())).expect("default arrivals");
    assert_eq!(parsed.1, 5000);
    let custom = base.iter().copied().chain(["--arrivals", "42"]);
    assert_eq!(
      super::parse_args(custom.map(str::to_owned))
        .expect("custom arrivals")
        .1,
      42
    );
    let excessive = base.iter().copied().chain(["--arrivals", "1000001"]);
    assert!(super::parse_args(excessive.map(str::to_owned)).is_err());
    let finite = base.iter().copied().chain([
      "--trace-deadline-seconds",
      "10",
      "--drain-deadline-seconds",
      "20",
      "--shutdown-deadline-seconds",
      "5",
      "--process-deadline-seconds",
      "155",
    ]);
    let parsed = super::parse_args(finite.map(str::to_owned)).expect("finite explicit deadlines");
    assert_eq!(parsed.2.trace, Duration::from_secs(10));
    let http_with_all_shutdowns = [
      "--executor",
      "bounded",
      "--workload",
      "http",
      "--mode",
      "open_loop",
      "--rate",
      "1000",
      "--trace-deadline-seconds",
      "10",
      "--drain-deadline-seconds",
      "20",
      "--shutdown-deadline-seconds",
      "5",
      "--process-deadline-seconds",
      "165",
    ];
    assert!(
      super::parse_args(
        http_with_all_shutdowns
          .iter()
          .map(|value| (*value).to_owned())
      )
      .is_ok()
    );
    let short_http_budget =
      http_with_all_shutdowns.map(|value| if value == "165" { "164" } else { value });
    assert!(super::parse_args(short_http_budget.iter().map(|value| (*value).to_owned())).is_err());
    let undersized_process = base.iter().copied().chain([
      "--trace-deadline-seconds",
      "10",
      "--drain-deadline-seconds",
      "20",
      "--shutdown-deadline-seconds",
      "5",
      "--process-deadline-seconds",
      "154",
    ]);
    assert!(super::parse_args(undersized_process.map(str::to_owned)).is_err());
    let too_long_trace = [
      "--executor",
      "bounded",
      "--workload",
      "cpu",
      "--mode",
      "open_loop",
      "--rate",
      "1",
      "--arrivals",
      "301",
      "--trace-deadline-seconds",
      "300",
      "--drain-deadline-seconds",
      "300",
      "--shutdown-deadline-seconds",
      "60",
      "--process-deadline-seconds",
      "900",
    ];
    assert!(super::parse_args(too_long_trace.iter().map(|value| (*value).to_owned())).is_err());
    let capacity = [
      "--executor",
      "bounded",
      "--workload",
      "cpu",
      "--mode",
      "capacity",
      "--arrivals",
      "42",
    ];
    assert!(super::parse_args(capacity.iter().map(|value| (*value).to_owned())).is_err());
  }

  #[test]
  fn oracle_only_emitter_writes_the_canonical_reference_without_a_timing_run() {
    let nonce = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .expect("system time")
      .as_nanos();
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-app-oracle-{}-{nonce}.tsv",
      std::process::id()
    ));
    let args = [
      "--emit-oracle-only".to_owned(),
      path.to_str().expect("UTF-8 temporary path").to_owned(),
      "--workload".to_owned(),
      "cpu".to_owned(),
      "--source-sha256".to_owned(),
      "b".repeat(64),
      "--binary-sha256".to_owned(),
      "c".repeat(64),
      "--rate".to_owned(),
      "1000".to_owned(),
      "--arrivals".to_owned(),
      "2".to_owned(),
    ];
    super::emit_oracle_only(args.iter().cloned()).expect("write canonical oracle");
    let contents = std::fs::read_to_string(&path).expect("oracle output");
    let lines = contents.lines().collect::<Vec<_>>();
    assert_eq!(lines[0], "schema\tallocatbelt-app-oracle-v1");
    assert_eq!(lines[1], format!("source_sha256\t{}", "b".repeat(64)));
    assert_eq!(lines[2], format!("binary_sha256\t{}", "c".repeat(64)));
    assert_eq!(lines[3], "workload\tcpu");
    assert_eq!(lines[4], "mode\topen_loop");
    assert_eq!(lines[5], "rate_per_second\t1000");
    assert_eq!(lines[6], "arrivals\t2");
    assert_eq!(lines[7], "kernel_config\trounds=50000");
    assert_eq!(lines[8], "id\texpected_checksum");
    assert_eq!(
      lines[9],
      format!(
        "0\t{}",
        super::expected_value(Workload::Cpu, &LaneConfig::default(), 0)
      )
    );
    assert_eq!(
      lines[10],
      format!(
        "1\t{}",
        super::expected_value(Workload::Cpu, &LaneConfig::default(), 1)
      )
    );
    assert!(super::emit_oracle_only(args.iter().cloned()).is_err());
    std::fs::remove_file(path).expect("remove oracle output");
  }

  #[test]
  fn per_id_arrival_clock_is_stable_when_terminals_arrive_out_of_order() {
    let origin = Instant::now();
    let id_ten = origin + Duration::from_millis(10);
    let id_five = origin + Duration::from_millis(5);
    let (ten_scheduled, ten_completed) =
      super::arrival_times(10, id_ten, origin + Duration::from_millis(12), 1000)
        .expect("ID ten timing");
    let (five_scheduled, five_completed) =
      super::arrival_times(5, id_five, origin + Duration::from_millis(20), 1000)
        .expect("ID five timing");
    assert_eq!(ten_scheduled, 10_000_000);
    assert_eq!(five_scheduled, 5_000_000);
    assert_eq!(ten_completed, 12_000_000);
    assert_eq!(five_completed, 20_000_000);
  }

  #[test]
  fn per_id_records_allow_out_of_order_completion_and_reject_replay_or_corruption() {
    let expected = [11, 22, 33];
    let valid = [
      super::IdRecord {
        id: 2,
        scheduled_ns: 2,
        completion_ns: 5,
        terminal: "completed",
        checksum: 33,
        expected_checksum: 33,
      },
      super::IdRecord {
        id: 0,
        scheduled_ns: 0,
        completion_ns: 4,
        terminal: "completed",
        checksum: 11,
        expected_checksum: 11,
      },
      super::IdRecord {
        id: 1,
        scheduled_ns: 1,
        completion_ns: 3,
        terminal: "rejected",
        checksum: 0,
        expected_checksum: 22,
      },
    ];
    assert_eq!(super::validate_id_records(&valid, &expected), Ok((2, 1)));

    let mut replayed = valid;
    replayed[0].id = 0;
    assert!(super::validate_id_records(&replayed, &expected).is_err());

    let mut corrupted = valid;
    corrupted[0].checksum ^= 1;
    assert!(super::validate_id_records(&corrupted, &expected).is_err());
    corrupted = valid;
    corrupted[2].expected_checksum ^= 1;
    assert!(super::validate_id_records(&corrupted, &expected).is_err());
  }

  #[test]
  fn producer_wait_uses_remaining_whole_process_budget() {
    let expired = Instant::now() - Duration::from_secs(901);
    assert_eq!(super::remaining_process_deadline(expired), Duration::ZERO);
    assert!(super::remaining_process_deadline(Instant::now()) > Duration::ZERO);
  }

  #[test]
  fn cpu_result_validation_checks_each_job_against_its_stable_id() {
    let config = LaneConfig::default();
    let expected = super::expected_value(Workload::Cpu, &config, 7);
    assert!(validate_output(
      Workload::Cpu,
      &config,
      7,
      &WorkOutput::Cpu(expected)
    ));
    assert!(!validate_output(
      Workload::Cpu,
      &config,
      7,
      &WorkOutput::Cpu(expected ^ 1),
    ));
    assert!(!validate_output(
      Workload::Cpu,
      &config,
      8,
      &WorkOutput::Cpu(expected)
    ));
  }

  #[test]
  fn precomputed_open_loop_cpu_oracle_rejects_corruption_and_wrong_ids() {
    let config = LaneConfig::default();
    let oracle = vec![
      super::expected_value(Workload::Cpu, &config, 0),
      super::expected_value(Workload::Cpu, &config, 1),
    ];
    assert!(super::validate_output_with_oracle(
      Workload::Cpu,
      &config,
      1,
      &WorkOutput::Cpu(oracle[1]),
      Some(&oracle),
    ));
    assert!(!super::validate_output_with_oracle(
      Workload::Cpu,
      &config,
      1,
      &WorkOutput::Cpu(oracle[1] ^ 1),
      Some(&oracle),
    ));
    assert!(!super::validate_output_with_oracle(
      Workload::Cpu,
      &config,
      2,
      &WorkOutput::Cpu(oracle[1]),
      Some(&oracle),
    ));
  }

  #[test]
  fn bounded_memory_oracle_preserves_buffer_integrity_checks() {
    let config = LaneConfig::default();
    let oracle =
      super::build_expected_oracle(Workload::Memory, &config, 2).expect("bounded memory oracle");
    let seed = super::job_seed(1);
    let resources = ResourceScope::new(super::resource_limits(Workload::Memory));
    let mut buffer = resources
      .try_alloc_zeroed(config.memory.grown_bytes)
      .expect("test buffer allocation");
    for (index, byte) in buffer
      .get_mut()
      .expect("unique buffer")
      .iter_mut()
      .enumerate()
    {
      *byte = super::memory::pattern_byte(seed, index);
    }
    let output = || {
      WorkOutput::Memory(super::MemoryOutput {
        report: super::memory::MemoryReport {
          peak_replacement_was_enforced: false,
          charged_after_growth: buffer.charged_bytes(),
          checksum: super::memory::checksum(buffer.as_slice()),
        },
        buffer: buffer.clone(),
      })
    };
    let valid = output();
    assert!(super::validate_output_with_oracle(
      Workload::Memory,
      &config,
      1,
      &valid,
      Some(&oracle),
    ));
    assert!(!super::validate_output_with_oracle(
      Workload::Memory,
      &config,
      2,
      &valid,
      Some(&oracle),
    ));

    let mut corrupted = resources
      .try_alloc_zeroed(config.memory.grown_bytes)
      .expect("corruption-test buffer allocation");
    for (index, byte) in corrupted
      .get_mut()
      .expect("unique corruption-test buffer")
      .iter_mut()
      .enumerate()
    {
      *byte = super::memory::pattern_byte(seed, index);
    }
    corrupted.get_mut().expect("unique corruption-test buffer")[7] ^= 1;
    let corrupted_checksum = super::memory::checksum(corrupted.as_slice());
    let corrupted_output = WorkOutput::Memory(super::MemoryOutput {
      report: super::memory::MemoryReport {
        peak_replacement_was_enforced: false,
        charged_after_growth: corrupted.charged_bytes(),
        checksum: corrupted_checksum,
      },
      buffer: corrupted,
    });
    assert!(!super::validate_output_with_oracle(
      Workload::Memory,
      &config,
      1,
      &corrupted_output,
      Some(&oracle),
    ));
    drop(resources);
  }

  #[test]
  fn bounded_disk_oracle_validates_id_specific_checksum() {
    let config = LaneConfig::default();
    let oracle =
      super::build_expected_oracle(Workload::Disk, &config, 2).expect("bounded disk oracle");
    let id = 1u64;
    let expected_from_payload =
      (0..config.disk.bytes).fold(0xcbf2_9ce4_8422_2325, |hash, index| {
        (hash ^ u64::from(super::disk::payload_byte(super::job_seed(id), index)))
          .wrapping_mul(0x0000_0100_0000_01b3)
      });
    assert_eq!(oracle[id as usize], expected_from_payload);
    let output = |checksum| {
      WorkOutput::Disk(DiskReport {
        offset: config.disk.offset,
        bytes: config.disk.bytes,
        checksum,
        resources_after_cleanup: ResourceScope::new(ResourceLimits {
          managed_memory: 0,
          disk_concurrent_ops: 0,
          network_concurrent_ops: 0,
        })
        .snapshot(),
        temp_directory_removed: true,
      })
    };
    assert!(super::validate_output_with_oracle(
      Workload::Disk,
      &config,
      id,
      &output(expected_from_payload),
      Some(&oracle),
    ));
    assert!(!super::validate_output_with_oracle(
      Workload::Disk,
      &config,
      id,
      &output(expected_from_payload ^ 1),
      Some(&oracle),
    ));
    assert!(!super::validate_output_with_oracle(
      Workload::Disk,
      &config,
      id + 1,
      &output(expected_from_payload),
      Some(&oracle),
    ));
  }

  #[test]
  fn open_loop_expected_digest_uses_only_completed_ids_from_the_oracle() {
    let config = LaneConfig::default();
    let oracle =
      super::build_expected_oracle(Workload::Memory, &config, 4).expect("bounded memory oracle");
    let observer = ObserverReport {
      completed_on_time: 1,
      completed_late: 1,
      errors: 1,
      cancellations: 0,
      digest: 0,
      latencies_ns: Vec::new(),
      max_observed_managed_bytes: 0,
      retained_managed_bytes: 0,
      final_statuses: Some(vec![
        IdState::Completed,
        IdState::Rejected,
        IdState::Completed,
        IdState::Failed,
      ]),
      last_observed: Instant::now(),
      records: Vec::new(),
    };
    let producer = ProducerReport {
      attempted: 4,
      admitted: 3,
      rejected_full: 1,
      rejected_logical_window: 1,
      rejected_backend_full: 0,
      lateness_sum_ns: 0,
      lateness_max_ns: 0,
      started_at: Instant::now(),
      production_end: Instant::now(),
      trace_overrun: false,
    };
    let expected = oracle[0].wrapping_add(oracle[2] ^ 2);
    assert_eq!(
      super::expected_digest(
        Options {
          executor: Executor::Bounded,
          workload: Workload::Memory,
          mode: Mode::OpenLoop,
          rate_per_second: Some(100),
        },
        &observer,
        &producer,
        Some(&oracle),
      ),
      expected
    );
  }

  #[test]
  fn allocatbelt_terminal_poll_wakes_the_observer_only_after_publication() {
    let runtime = AsyncRuntime::new(AsyncConfig {
      workers: 1,
      max_outstanding: 1,
      max_scopes: 1,
    })
    .expect("allocatbelt runtime");
    let handle = runtime.handle();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let mut job = Job::Bounded(
      handle
        .spawn(async move {
          release_rx.await.map_err(|_| "gate closed".to_owned())?;
          Ok(WorkOutput::Cpu(42))
        })
        .expect("admit gated task"),
    );
    let completion_waker = Waker::from(Arc::new(super::ObserverWake(thread::current())));
    let mut context = std::task::Context::from_waker(&completion_waker);
    assert!(job.poll_finished(&mut context).is_pending());
    release_tx.send(()).expect("release gated task");
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut terminal = false;
    while Instant::now() < deadline {
      if job.poll_finished(&mut context).is_ready() {
        terminal = true;
        break;
      }
      thread::park_timeout(deadline.saturating_duration_since(Instant::now()));
    }
    assert!(
      terminal,
      "terminal publication must wake the observer before its bound"
    );
    let output = match job {
      Job::Bounded(job) => handle
        .block_on(job)
        .expect("root poll")
        .expect("task result")
        .expect("workload result"),
      Job::Tokio { .. } => unreachable!(),
    };
    assert_eq!(output.value(), 42);
    runtime
      .shutdown(AsyncShutdown::Drain)
      .expect("runtime drains after join consumption");
  }

  #[test]
  fn observer_event_send_unparks_a_parked_observer() {
    let (raw_events_tx, events_rx) = mpsc::sync_channel(1);
    let observer_target = Arc::new(OnceLock::new());
    let events_tx = ObserverEventSender::new(raw_events_tx, Arc::clone(&observer_target));
    let (park_ready_tx, park_ready_rx) = mpsc::sync_channel(1);
    let (awake_tx, awake_rx) = mpsc::sync_channel(1);
    let observer = thread::spawn(move || {
      observer_target
        .set(thread::current())
        .expect("register observer thread once");
      park_ready_tx.send(()).expect("publish park readiness");
      thread::park_timeout(Duration::from_secs(5));
      awake_tx.send(()).expect("publish wake");
      assert!(matches!(
        events_rx.try_recv(),
        Ok(ObserverEvent::Done { attempted: 0, .. })
      ));
    });
    park_ready_rx
      .recv_timeout(Duration::from_secs(1))
      .expect("observer registers before producer sends");

    events_tx
      .send(ObserverEvent::Done {
        attempted: 0,
        horizon_end: Instant::now(),
      })
      .expect("send producer completion");
    awake_rx
      .recv_timeout(Duration::from_secs(1))
      .expect("event send wakes the parked observer");
    observer.join().expect("observer should exit cleanly");
    drop(events_tx);
  }

  #[test]
  fn producer_panic_disconnects_observer_without_pending_jobs() {
    let (raw_events_tx, events_rx) = mpsc::sync_channel(1);
    let observer_target = Arc::new(OnceLock::new());
    let events_tx = ObserverEventSender::new(raw_events_tx, Arc::clone(&observer_target));
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (report_tx, report_rx) = mpsc::sync_channel(1);
    let observer = thread::spawn(move || {
      observer_target
        .set(thread::current())
        .expect("register observer thread once");
      let _ = started_tx.send(());
      let result = observe(
        Observer::Tokio,
        Options {
          executor: Executor::Tokio,
          workload: Workload::Cpu,
          mode: Mode::OpenLoop,
          rate_per_second: Some(1000),
        },
        LaneConfig::default(),
        ResourceScope::new(resource_limits(Workload::Cpu)),
        events_rx,
        mpsc::sync_channel(8).0,
        None,
        0,
        0,
        Duration::from_secs(5),
        None,
      );
      let _ = report_tx.send(result);
    });
    started_rx
      .recv_timeout(Duration::from_secs(1))
      .expect("observer starts");

    let producer = thread::spawn(move || {
      drop(events_tx);
      panic!("injected producer failure before Done");
    });
    assert!(producer.join().is_err());
    let error = report_rx
      .recv_timeout(Duration::from_secs(1))
      .expect("last sender drop must wake observer")
      .expect_err("missing Done must remain an error");
    assert!(error.contains("observer queue closed before pending jobs"));
    observer.join().expect("observer thread should exit");
  }

  #[test]
  fn producer_panic_disconnects_observer_with_a_pending_job() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
      .worker_threads(1)
      .enable_all()
      .build()
      .expect("test runtime");
    let handle = runtime.handle().clone();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let job = Job::Tokio {
      handle: handle.spawn(async move {
        release_rx
          .await
          .map_err(|_| "test gate closed".to_owned())?;
        Ok(WorkOutput::Cpu(42))
      }),
      result: None,
    };
    let (raw_events_tx, events_rx) = mpsc::sync_channel(2);
    let observer_target = Arc::new(OnceLock::new());
    let events_tx = ObserverEventSender::new(raw_events_tx, Arc::clone(&observer_target));
    let scheduled = Instant::now();
    events_tx
      .send(ObserverEvent::Job {
        id: 0,
        scheduled,
        horizon_end: scheduled + Duration::from_secs(5),
        job,
      })
      .expect("publish pending job");
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (report_tx, report_rx) = mpsc::sync_channel(1);
    let observer = thread::spawn(move || {
      if observer_target.set(thread::current()).is_err() {
        let _ = report_tx.send(Err("observer target set twice".to_owned()));
        return;
      }
      let _ = started_tx.send(());
      let result = observe(
        Observer::Tokio,
        Options {
          executor: Executor::Tokio,
          workload: Workload::Cpu,
          mode: Mode::OpenLoop,
          rate_per_second: Some(1000),
        },
        LaneConfig::default(),
        ResourceScope::new(resource_limits(Workload::Cpu)),
        events_rx,
        mpsc::sync_channel(8).0,
        Some(Arc::new(Mutex::new(vec![IdState::Admitted]))),
        1,
        1,
        Duration::from_secs(5),
        None,
      );
      let _ = report_tx.send(result);
    });
    started_rx
      .recv_timeout(Duration::from_secs(1))
      .expect("observer starts");

    let producer_sender = events_tx.clone();
    let producer = thread::spawn(move || {
      drop(producer_sender);
      panic!("injected producer failure before Done");
    });
    drop(events_tx);
    assert!(producer.join().is_err());
    let error = report_rx
      .recv_timeout(Duration::from_secs(1))
      .expect("last sender drop must wake observer")
      .expect_err("missing Done must remain an error");
    assert!(error.contains("observer queue closed before pending jobs"));
    observer.join().expect("observer thread should exit");

    release_tx
      .send(())
      .expect("release pending task for runtime shutdown");
    runtime.shutdown_timeout(Duration::from_secs(2));
  }

  #[test]
  fn capacity_id_guard_accepts_a_prefix_and_rejects_duplicate_or_skipped_ids() {
    let mut next = 0;
    assert!(accept_capacity_id(&mut next, 0).is_ok());
    assert!(accept_capacity_id(&mut next, 1).is_ok());
    assert!(accept_capacity_id(&mut next, 1).is_err());
    assert_eq!(next, 2);
    assert!(accept_capacity_id(&mut next, 3).is_err());
    assert_eq!(next, 2);
  }

  #[test]
  fn measured_trace_deadline_accepts_exact_limit_and_rejects_overrun() {
    let end = Instant::now();
    assert!(!super::trace_exceeded(
      Mode::OpenLoop,
      end - std::time::Duration::from_secs(300),
      end
    ));
    assert!(super::trace_exceeded(
      Mode::OpenLoop,
      end - std::time::Duration::from_secs(301),
      end
    ));
    assert!(!super::trace_exceeded(
      Mode::Capacity,
      end - std::time::Duration::from_secs(301),
      end
    ));
  }

  #[test]
  fn wall_through_drain_includes_the_full_horizon_when_work_finishes_early() {
    let start = Instant::now();
    let production_end = start + std::time::Duration::from_secs(30);
    let last_observed = start + std::time::Duration::from_secs(4);
    assert_eq!(
      super::wall_through_drain_ns(start, production_end, last_observed),
      std::time::Duration::from_secs(30).as_nanos()
    );
  }

  #[test]
  fn managed_sampler_observes_a_live_charge_and_keeps_its_maximum() {
    let resources = ResourceScope::new(ResourceLimits {
      managed_memory: 1024,
      disk_concurrent_ops: 0,
      network_concurrent_ops: 0,
    });
    let buffer = resources.try_alloc_zeroed(512).expect("managed allocation");
    let mut maximum = 0;
    super::record_managed_sample(&resources, &mut maximum);
    assert_eq!(maximum, 512);
    drop(buffer);
    super::record_managed_sample(&resources, &mut maximum);
    assert_eq!(maximum, 512);
    assert_eq!(resources.snapshot().managed_memory, 0);
  }

  #[test]
  fn disk_result_validation_checks_the_id_specific_payload_checksum() {
    let config = LaneConfig::default();
    let id = 11;
    let expected = super::expected_value(Workload::Disk, &config, id);
    let output = |checksum| {
      WorkOutput::Disk(DiskReport {
        offset: config.disk.offset,
        bytes: config.disk.bytes,
        checksum,
        resources_after_cleanup: ResourceScope::new(ResourceLimits {
          managed_memory: 0,
          disk_concurrent_ops: 0,
          network_concurrent_ops: 0,
        })
        .snapshot(),
        temp_directory_removed: true,
      })
    };
    assert!(validate_output(
      Workload::Disk,
      &config,
      id,
      &output(expected)
    ));
    assert!(!validate_output(
      Workload::Disk,
      &config,
      id,
      &output(expected ^ 1)
    ));
    assert!(!validate_output(
      Workload::Disk,
      &config,
      id + 1,
      &output(expected)
    ));
  }

  #[test]
  fn observer_consumes_a_later_ready_job_before_an_earlier_pending_job() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
      .worker_threads(2)
      .enable_all()
      .build()
      .expect("test runtime");
    let handle = runtime.handle().clone();
    let (release_first, first_gate) = tokio::sync::oneshot::channel::<()>();
    let config = LaneConfig::default();
    let first_value = super::expected_value(Workload::Cpu, &config, 0);
    let second_value = super::expected_value(Workload::Cpu, &config, 1);
    let first = Job::Tokio {
      handle: handle.spawn(async move {
        first_gate
          .await
          .map_err(|_| "test gate closed".to_owned())?;
        Ok(WorkOutput::Cpu(first_value))
      }),
      result: None,
    };
    let second = Job::Tokio {
      handle: handle.spawn(async move { Ok(WorkOutput::Cpu(second_value)) }),
      result: None,
    };
    let started = Instant::now();
    let horizon = started + std::time::Duration::from_secs(5);
    let (events_tx, events_rx) = mpsc::sync_channel(16);
    let (credits_tx, credits_rx) = mpsc::sync_channel(8);
    events_tx
      .send(ObserverEvent::Job {
        id: 0,
        scheduled: started,
        horizon_end: horizon,
        job: first,
      })
      .expect("first job event");
    events_tx
      .send(ObserverEvent::Job {
        id: 1,
        scheduled: started,
        horizon_end: horizon,
        job: second,
      })
      .expect("second job event");
    events_tx
      .send(ObserverEvent::Done {
        attempted: 2,
        horizon_end: horizon,
      })
      .expect("producer completion event");
    drop(events_tx);
    let states = Arc::new(Mutex::new(vec![IdState::Admitted; 2]));
    let (report_tx, report_rx) = mpsc::sync_channel(1);
    let observer = std::thread::spawn(move || {
      let _ = report_tx.send(observe(
        Observer::Tokio,
        Options {
          executor: Executor::Tokio,
          workload: Workload::Cpu,
          mode: Mode::OpenLoop,
          rate_per_second: Some(1000),
        },
        config,
        ResourceScope::new(resource_limits(Workload::Cpu)),
        events_rx,
        credits_tx,
        Some(Arc::clone(&states)),
        2,
        8,
        Duration::from_secs(5),
        None,
      ));
    });

    credits_rx
      .recv_timeout(std::time::Duration::from_secs(2))
      .expect("second job should return credit while job zero is pending");
    release_first.send(()).expect("release first job");
    let report = report_rx
      .recv_timeout(std::time::Duration::from_secs(2))
      .expect("observer completion should arrive before the watchdog")
      .expect("all jobs should drain");
    observer.join().expect("observer thread should not panic");
    assert_eq!(report.completed_on_time + report.completed_late, 2);
    assert_eq!(report.errors, 0);
    assert_eq!(report.final_statuses.unwrap(), vec![IdState::Completed; 2]);
    assert_eq!(credits_rx.try_iter().count(), 1);
  }

  #[test]
  fn disk_observer_samples_managed_storage_while_an_admitted_job_is_pending() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
      .worker_threads(2)
      .enable_all()
      .build()
      .expect("test runtime");
    let handle = runtime.handle().clone();
    let config = LaneConfig::default();
    let disk_config = config.disk;
    let resources = ResourceScope::new(resource_limits(Workload::Disk));
    let job_resources = resources.clone();
    let ready_job_resources = resources.clone();
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let checksum = super::expected_value(Workload::Disk, &config, 0);
    let job = Job::Tokio {
      handle: handle.spawn(async move {
        let buffer = job_resources
          .try_alloc_zeroed(512)
          .map_err(|error| error.to_string())?;
        started_tx.send(()).expect("test observes allocation");
        release_rx
          .await
          .map_err(|_| "test gate closed".to_owned())?;
        drop(buffer);
        Ok(WorkOutput::Disk(DiskReport {
          offset: disk_config.offset,
          bytes: disk_config.bytes,
          checksum,
          resources_after_cleanup: job_resources.snapshot(),
          temp_directory_removed: true,
        }))
      }),
      result: None,
    };
    started_rx
      .recv_timeout(std::time::Duration::from_secs(2))
      .expect("disk job should hold its managed buffer before observer startup");
    let ready_checksum = super::expected_value(Workload::Disk, &config, 1);
    let ready_job = Job::Tokio {
      handle: handle.spawn(async move {
        Ok(WorkOutput::Disk(DiskReport {
          offset: disk_config.offset,
          bytes: disk_config.bytes,
          checksum: ready_checksum,
          resources_after_cleanup: ready_job_resources.snapshot(),
          temp_directory_removed: true,
        }))
      }),
      result: None,
    };
    let started = Instant::now();
    let horizon = started + std::time::Duration::from_secs(5);
    let (events_tx, events_rx) = mpsc::sync_channel(16);
    let (credits_tx, credits_rx) = mpsc::sync_channel(8);
    events_tx
      .send(ObserverEvent::Job {
        id: 0,
        scheduled: started,
        horizon_end: horizon,
        job,
      })
      .expect("disk job event");
    events_tx
      .send(ObserverEvent::Job {
        id: 1,
        scheduled: started,
        horizon_end: horizon,
        job: ready_job,
      })
      .expect("ready disk job event");
    events_tx
      .send(ObserverEvent::Done {
        attempted: 2,
        horizon_end: horizon,
      })
      .expect("producer completion event");
    drop(events_tx);
    let states = Arc::new(Mutex::new(vec![IdState::Admitted; 2]));
    let (report_tx, report_rx) = mpsc::sync_channel(1);
    let observer = std::thread::spawn(move || {
      let _ = report_tx.send(observe(
        Observer::Tokio,
        Options {
          executor: Executor::Tokio,
          workload: Workload::Disk,
          mode: Mode::OpenLoop,
          rate_per_second: Some(1000),
        },
        config,
        resources,
        events_rx,
        credits_tx,
        Some(states),
        2,
        8,
        Duration::from_millis(100),
        None,
      ));
    });

    credits_rx
      .recv_timeout(std::time::Duration::from_secs(2))
      .expect("ready second disk result proves observer sampled the pending first buffer");
    release_tx.send(()).expect("release disk job");
    let report = report_rx
      .recv_timeout(std::time::Duration::from_secs(2))
      .expect("disk observer completion should arrive before the watchdog")
      .expect("disk result should validate");
    observer.join().expect("observer thread should not panic");
    assert!(report.max_observed_managed_bytes >= 512);
    assert_eq!(report.completed_on_time + report.completed_late, 2);
  }

  #[test]
  fn synthetic_capacity_run_keeps_ids_checksums_and_managed_output_bounded() {
    let counts = run_with_limits(
      Options {
        executor: Executor::Bounded,
        workload: Workload::Memory,
        mode: Mode::Capacity,
        rate_per_second: None,
      },
      Some(std::time::Duration::from_millis(20)),
      None,
    )
    .expect("short capacity lane should drain and validate");
    assert_eq!(counts.producer.rejected_full, 0);
    assert_eq!(
      counts.producer.admitted,
      counts.observer.completed_on_time + counts.observer.completed_late
    );
    assert!(counts.observer.retained_managed_bytes <= 8 * 8192);
    assert_eq!(counts.final_resources.managed_memory, 0);
  }

  #[test]
  fn synthetic_open_loop_run_balances_every_id_and_detects_checksum() {
    let counts = run_with_limits(
      Options {
        executor: Executor::Tokio,
        workload: Workload::Cpu,
        mode: Mode::OpenLoop,
        rate_per_second: Some(100_000),
      },
      None,
      Some(128),
    )
    .expect("short open-loop lane should drain and validate");
    assert_eq!(counts.producer.attempted, 128);
    assert_eq!(
      counts.producer.rejected_full,
      counts.producer.rejected_logical_window + counts.producer.rejected_backend_full
    );
    assert_eq!(
      counts.producer.admitted + counts.producer.rejected_full,
      128
    );
    assert_eq!(counts.observer.digest, counts.expected_checksum);
  }

  #[test]
  fn synthetic_open_loop_memory_run_uses_the_bounded_oracle() {
    let counts = run_with_limits(
      Options {
        executor: Executor::Bounded,
        workload: Workload::Memory,
        mode: Mode::OpenLoop,
        rate_per_second: Some(100),
      },
      None,
      Some(4),
    )
    .expect("short open-loop memory lane should drain and validate");
    assert_eq!(counts.producer.attempted, 4);
    assert_eq!(counts.producer.admitted, 4);
    assert_eq!(counts.observer.errors, 0);
    assert_eq!(counts.observer.digest, counts.expected_checksum);
    assert!(counts.observer.retained_managed_bytes <= 4 * 8192);
    assert_eq!(counts.final_resources.managed_memory, 0);
  }

  #[test]
  fn native_multichunk_disk_jobs_drain_filesystem_workers_and_resources() {
    let counts = run_with_limits(
      Options {
        executor: Executor::Bounded,
        workload: Workload::Disk,
        mode: Mode::OpenLoop,
        rate_per_second: Some(100),
      },
      None,
      Some(4),
    )
    .expect("native disk app lane should drain and validate");
    assert_eq!(counts.producer.attempted, 4);
    assert_eq!(counts.producer.admitted, 4);
    assert_eq!(counts.observer.errors, 0);
    assert_eq!(counts.observer.digest, counts.expected_checksum);
    assert_eq!(counts.final_resources.managed_memory, 0);
    assert_eq!(counts.final_resources.disk_ops, 0);
  }

  #[test]
  fn tokio_multichunk_disk_jobs_drain_bounded_filesystem_steps() {
    let counts = run_with_limits(
      Options {
        executor: Executor::Tokio,
        workload: Workload::Disk,
        mode: Mode::OpenLoop,
        rate_per_second: Some(100),
      },
      None,
      Some(4),
    )
    .expect("Tokio disk app lane should drain and validate");
    assert_eq!(counts.producer.attempted, 4);
    assert_eq!(counts.producer.admitted, 4);
    assert_eq!(counts.observer.errors, 0);
    assert_eq!(counts.observer.digest, counts.expected_checksum);
    assert_eq!(counts.final_resources.managed_memory, 0);
    assert_eq!(counts.final_resources.disk_ops, 0);
  }
}
