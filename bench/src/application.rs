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
  AsyncConfig, AsyncError, AsyncHandle, AsyncJob, AsyncShutdown,
};
use allocatbelt::runtime::cpu_gate::CpuGate;
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt::runtime::process::ProcessShutdownMode;
use allocatbelt::runtime::resource_domain::DomainResource;
use allocatbelt::runtime::{
  Config as BlockingConfig, MultiShutdown, MultiThreadBuilder, MultiThreadDriver, ShutdownMode,
};
use allocatbelt_app_ports::cpu;
use allocatbelt_app_ports::disk::{self, DiskConfig, DiskReport};
use allocatbelt_app_ports::memory::{self, MemoryConfig, MemoryOutput};

#[path = "application/disk_lane.rs"]
pub(crate) mod disk_lane;
#[cfg(feature = "resource-feedback")]
#[path = "application/feedback_policy_probe.rs"]
pub(crate) mod feedback_policy_probe;
#[cfg(feature = "resource-feedback")]
#[path = "application/feedback_trace.rs"]
pub(crate) mod feedback_trace;
#[path = "application/http.rs"]
mod http;
#[path = "application/runtime_bindings.rs"]
pub(crate) mod runtime_bindings;
#[cfg(feature = "resource-feedback")]
use feedback_trace::{FeedbackTraceCollector, FeedbackTracePhase};
pub(super) use runtime_bindings::{
  APPLICATION_TASK_CEILING, ApplicationDomain, ApplicationIoBindings, ApplicationMode,
  ApplicationRunBindings, ApplicationTaskAdmission,
};

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
const PROCESS_TIMEOUT: Duration = Duration::from_secs(1200);
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

pub(super) fn capacity_pulse_end(
  plan: ArrivalPlan,
  started: Instant,
  horizon_end: Instant,
) -> Instant {
  if plan.profile != Profile::Burst {
    return horizon_end;
  }
  let elapsed_ns = Instant::now().saturating_duration_since(started).as_nanos();
  let cycle = (elapsed_ns / 1_000_000_000) as u64;
  started
    .checked_add(Duration::from_secs(cycle))
    .and_then(|cycle_start| cycle_start.checked_add(Duration::from_millis(250)))
    .map_or(horizon_end, |pulse_end| pulse_end.min(horizon_end))
}

pub(super) fn wait_until_capacity_pulse(plan: ArrivalPlan, started: Instant, horizon_end: Instant) {
  if plan.profile != Profile::Burst {
    return;
  }
  let now = Instant::now();
  let elapsed_ns = now.saturating_duration_since(started).as_nanos();
  let phase_ns = elapsed_ns % 1_000_000_000;
  if capacity_pulse_active(elapsed_ns) {
    return;
  }
  let wait_ns = 1_000_000_000 - phase_ns;
  let pulse_start = now
    .checked_add(Duration::from_nanos(wait_ns as u64))
    .unwrap_or(horizon_end);
  thread::sleep(pulse_start.min(horizon_end).saturating_duration_since(now));
}

fn capacity_pulse_active(elapsed_ns: u128) -> bool {
  elapsed_ns % 1_000_000_000 < 250_000_000
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
  /// Evenly interleaved CPU, memory, HTTP, and disk transactions.
  Mixed,
}

impl Workload {
  pub(super) fn parse(value: &str) -> Result<Self, String> {
    match value {
      "cpu" => Ok(Self::Cpu),
      "memory" => Ok(Self::Memory),
      "http" => Ok(Self::Http),
      "disk" => Ok(Self::Disk),
      "mixed" => Ok(Self::Mixed),
      _ => Err("--workload must be cpu, memory, http, disk, or mixed".into()),
    }
  }

  pub(super) fn label(self) -> &'static str {
    match self {
      Self::Cpu => "cpu",
      Self::Memory => "memory",
      Self::Http => "http",
      Self::Disk => "disk",
      Self::Mixed => "mixed",
    }
  }

  pub(super) fn family_index(self) -> Option<usize> {
    match self {
      Self::Cpu => Some(0),
      Self::Memory => Some(1),
      Self::Http => Some(2),
      Self::Disk => Some(3),
      Self::Mixed => None,
    }
  }
}

/// Frozen open-loop arrival/workload schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
  /// Uniform single-workload arrivals.
  Steady,
  /// One global stream evenly split across CPU, memory, HTTP, and disk.
  Mixed,
  /// Uniform average rate delivered in 250 ms pulses once per second.
  Burst,
  /// Uniform arrivals on a matched two-worker executor.
  Oversubscribed,
  /// Deliberate safety overload, excluded from qualification.
  SafetyOverload,
}

impl Profile {
  fn parse(value: &str) -> Result<Self, String> {
    match value {
      "steady" => Ok(Self::Steady),
      "mixed" => Ok(Self::Mixed),
      "burst" => Ok(Self::Burst),
      "oversubscribed" => Ok(Self::Oversubscribed),
      "safety_overload" => Ok(Self::SafetyOverload),
      _ => Err("--profile must be steady, mixed, burst, oversubscribed, or safety_overload".into()),
    }
  }

  pub fn label(self) -> &'static str {
    match self {
      Self::Steady => "steady",
      Self::Mixed => "mixed",
      Self::Burst => "burst",
      Self::Oversubscribed => "oversubscribed",
      Self::SafetyOverload => "safety_overload",
    }
  }

  pub fn minimum_successes(self) -> usize {
    if self == Self::Mixed {
      400_000
    } else {
      100_000
    }
  }

  pub fn qualifies(self) -> bool {
    self != Self::SafetyOverload
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArrivalPlan {
  pub profile: Profile,
  pub workload: Workload,
  pub arrivals: usize,
  pub average_rate_per_second: u64,
  pub async_workers: usize,
}

impl ArrivalPlan {
  fn new(profile: Profile, workload: Workload, arrivals: usize, rate: u64) -> Result<Self, String> {
    validate_arrivals(arrivals)?;
    if rate == 0 || rate > 1_000_000_000 {
      return Err("open-loop --rate must be in 1..=1000000000".into());
    }
    if profile == Profile::Mixed && workload != Workload::Mixed {
      return Err("--profile mixed requires --workload mixed".into());
    }
    if workload == Workload::Mixed && profile == Profile::Steady {
      return Err(
        "--workload mixed requires the mixed, burst, oversubscribed, or safety_overload profile"
          .into(),
      );
    }
    if profile == Profile::Burst && rate > 250_000_000 {
      return Err("burst average rate must not exceed 250000000 arrivals per second".into());
    }
    Ok(Self {
      profile,
      workload,
      arrivals,
      average_rate_per_second: rate,
      async_workers: if profile == Profile::Oversubscribed {
        2
      } else {
        WORKERS
      },
    })
  }

  pub fn workload_for(self, id: u64) -> Workload {
    if self.workload != Workload::Mixed {
      return self.workload;
    }
    match id % 4 {
      0 => Workload::Cpu,
      1 => Workload::Memory,
      2 => Workload::Http,
      _ => Workload::Disk,
    }
  }

  pub fn scheduled_offset_ns(self, id: u64) -> Result<u64, String> {
    if id >= self.arrivals as u64 {
      return Err("arrival plan ID is outside its finite count".into());
    }
    let offset = match self.profile {
      Profile::Burst => {
        let rate = u128::from(self.average_rate_per_second);
        let cycle = u128::from(id) / rate;
        let slot = u128::from(id) % rate;
        cycle
          .checked_mul(1_000_000_000)
          .and_then(|base| base.checked_add(slot.checked_mul(250_000_000)? / rate))
          .ok_or_else(|| "burst arrival offset overflow".to_owned())?
      }
      _ => {
        u128::from(id)
          .checked_mul(1_000_000_000)
          .ok_or_else(|| "arrival offset overflow".to_owned())?
          / u128::from(self.average_rate_per_second)
      }
    };
    u64::try_from(offset).map_err(|_| "arrival offset exceeds finite timestamp".to_owned())
  }

  pub fn trace_duration_ns(self) -> Result<u64, String> {
    let duration = if self.profile == Profile::Burst {
      let rate = u128::from(self.average_rate_per_second);
      let cycles = (self.arrivals as u128).div_ceil(rate);
      cycles
        .checked_mul(1_000_000_000)
        .ok_or_else(|| "burst trace duration overflow".to_owned())?
    } else {
      (self.arrivals as u128)
        .checked_mul(1_000_000_000)
        .ok_or_else(|| "open-loop trace duration overflow".to_owned())?
        / u128::from(self.average_rate_per_second)
    };
    u64::try_from(duration)
      .map_err(|_| "open-loop trace duration exceeds finite timestamp".to_owned())
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
pub(super) struct LaneConfig {
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
    disk_io: allocatbelt::runtime::fs::BlockingByteIo,
    cpu_gate: CpuGate,
    task_admission: ApplicationTaskAdmission,
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
    disk_io: Option<allocatbelt::runtime::fs::BlockingByteIo>,
    cpu_gate: CpuGate,
    task_admission: ApplicationTaskAdmission,
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
        disk_io,
        cpu_gate,
        task_admission,
      } => {
        let permit = slots
          .clone()
          .try_acquire_owned()
          .map_err(|error| match error {
            tokio::sync::TryAcquireError::Closed => Rejection::Closed,
            tokio::sync::TryAcquireError::NoPermits => Rejection::Full,
          })?;
        let driver = match disk_slots.clone() {
          Some(slots) => Some(DiskDriver::Tokio {
            handle: handle.clone(),
            slots,
            disk_io: disk_io.clone().ok_or(Rejection::Closed)?,
            cpu_gate: cpu_gate.clone(),
            task_admission: task_admission.clone(),
          }),
          None => None,
        };
        let operation = operation(workload, config, resources.clone(), seed, driver);
        let task_lease = task_admission.reserve().map_err(|_| Rejection::Closed)?;
        let gated = cpu_gate.wrap(operation).map_err(|_| Rejection::Closed)?;
        Ok(Job::Tokio {
          handle: handle.spawn(async move {
            let result = normalize_cpu_gated_result(gated.await);
            drop(permit);
            drop(task_lease);
            result
          }),
          result: None,
        })
      }
    }
  }
}

fn normalize_cpu_gated_result<T>(
  result: Result<
    allocatbelt_app_ports::PortResult<T>,
    allocatbelt::runtime::resource_domain::DomainError,
  >,
) -> allocatbelt_app_ports::PortResult<T> {
  match result {
    Ok(output) => output,
    Err(error) => Err(Box::new(std::io::Error::other(format!(
      "CPU gate rejected a productive poll: {error:?}"
    )))),
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
        DiskDriver::Tokio {
          handle,
          slots,
          disk_io,
          cpu_gate,
          task_admission,
        } => disk_lane::run_tokio_operation(
          &handle,
          &slots,
          &resources,
          &disk_io,
          &cpu_gate,
          &task_admission,
          disk_config,
        )
        .await
        .map_err(std::io::Error::other)?,
      };
      Ok(WorkOutput::Disk(output))
    }
    Workload::Mixed => Err("mixed workload must be dispatched by its per-ID plan".into()),
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
  production_cpu_started_ns: u128,
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
  family_published_on_time: [u64; 4],
}

#[derive(Clone, Copy, Debug)]
pub(super) struct IdRecord {
  pub(super) id: u64,
  pub(super) workload: Workload,
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
  async_workers: usize,
  topology: &'static str,
  setup_ns: u128,
  timer_pair_median_ns: u64,
  driver_shutdown_ns: u128,
  rss_before: ProcessMemory,
  rss_after_drain: ProcessMemory,
  rss_after_shutdown: ProcessMemory,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProcessMemory {
  pub(crate) rss_kib: u64,
  pub(crate) hwm_kib: u64,
}

pub(super) struct ProcessCheckpoints {
  pub(super) setup_started: Instant,
  pub(super) timer_pair_median_ns: u64,
  pub(super) rss_before: ProcessMemory,
  pub(super) rss_after_drain: ProcessMemory,
  pub(super) rss_after_shutdown: ProcessMemory,
}

pub(crate) fn sample_process_memory() -> Result<ProcessMemory, String> {
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
  production_cpu_started_ns: u128,
  production_cpu_ended_ns: u128,
  successful_completions: usize,
  timings: &[(&'static str, u128)],
) -> Result<(), String> {
  let Some(path) = env::var_os("ALLOCATBELT_APP_SHUTDOWN_REPORT") else {
    return Ok(());
  };
  if timings.is_empty() {
    return Err("shutdown report requires at least one driver timing".into());
  }
  let identity = [
    ("report_nonce", "ALLOCATBELT_APP_REPORT_NONCE"),
    ("run_id", "ALLOCATBELT_APP_RUN_ID"),
    ("executor", "ALLOCATBELT_APP_EXECUTOR"),
    ("allocator", "ALLOCATBELT_APP_ALLOCATOR"),
    ("workload", "ALLOCATBELT_APP_WORKLOAD"),
    ("profile", "ALLOCATBELT_APP_PROFILE"),
    ("source_sha256", "ALLOCATBELT_APP_SOURCE_SHA256"),
    ("binary_sha256", "ALLOCATBELT_APP_BINARY_SHA256"),
  ];
  let mut report = String::from("schema\tallocatbelt-app-phase-v1\t\n");
  for (name, variable) in identity {
    let value =
      env::var(variable).map_err(|_| format!("phase report identity is missing {variable}"))?;
    report.push_str(&format!("identity\t{name}\t{value}\n"));
  }
  let production_through_drain_cpu_ns =
    production_cpu_ended_ns.saturating_sub(production_cpu_started_ns);
  report.push_str(&format!("phase\tproduction_trace\t{trace_ns}\n"));
  report.push_str(&format!(
    "phase\tproduction_cpu_started_ns\t{production_cpu_started_ns}\n"
  ));
  report.push_str(&format!(
    "phase\tproduction_cpu_ended_ns\t{production_cpu_ended_ns}\n"
  ));
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
  profile: Profile,
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
  let mut report = String::from("schema\tallocatbelt-app-arrivals-v3\nidentity\t");
  report.push_str(&format!(
    "{nonce}\t{run_id}\t{}\t{allocator}\t{}\t{}\t{source_hash}\t{binary_hash}\n",
    options.executor.label(),
    options.workload.label(),
    profile.label()
  ));
  report
    .push_str("id\tworkload\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum\n");
  for record in ordered {
    report.push_str(&format!(
      "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
      record.id,
      record.workload.label(),
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

pub(super) fn write_capacity_family_report(
  attempted: usize,
  family_published_on_time: [u64; 4],
  options: Options,
  profile: Profile,
) -> Result<(), String> {
  if options.mode != Mode::Capacity || options.workload != Workload::Mixed {
    return Ok(());
  }
  let Some(path) = env::var_os("ALLOCATBELT_APP_FAMILY_REPORT") else {
    return Ok(());
  };
  let fields = [
    ("report_nonce", "ALLOCATBELT_APP_REPORT_NONCE"),
    ("run_id", "ALLOCATBELT_APP_RUN_ID"),
    ("executor", "ALLOCATBELT_APP_EXECUTOR"),
    ("allocator", "ALLOCATBELT_APP_ALLOCATOR"),
    ("workload", "ALLOCATBELT_APP_WORKLOAD"),
    ("profile", "ALLOCATBELT_APP_PROFILE"),
    ("source_sha256", "ALLOCATBELT_APP_SOURCE_SHA256"),
    ("binary_sha256", "ALLOCATBELT_APP_BINARY_SHA256"),
  ];
  let mut report = String::from("schema\tallocatbelt-app-capacity-families-v1\t\n");
  for (name, variable) in fields {
    let value =
      env::var(variable).map_err(|_| format!("capacity family identity is missing {variable}"))?;
    report.push_str(&format!("identity\t{name}\t{value}\n"));
  }
  let family_names = ["cpu", "memory", "http", "disk"];
  let mut expected_total = 0u64;
  let mut completed_total = 0u64;
  for (index, family) in family_names.into_iter().enumerate() {
    let scheduled = if attempted.is_multiple_of(4) {
      attempted / 4
    } else if index < attempted % 4 {
      attempted / 4 + 1
    } else {
      attempted / 4
    };
    let published = family_published_on_time[index];
    report.push_str(&format!("family\t{family}\t{scheduled}\t{published}\n"));
    expected_total += scheduled as u64;
    completed_total += published;
  }
  if expected_total != attempted as u64 || completed_total > attempted as u64 {
    return Err("capacity family counts do not balance the production stream".into());
  }
  report.push_str(&format!(
    "phase\ttrace_seconds\t{}\n",
    CAPACITY_HORIZON.as_secs()
  ));
  report.push_str(&format!("phase\tprofile\t{}\n", profile.label()));
  let mut file = OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(path)
    .map_err(|error| format!("capacity family report create failed: {error}"))?;
  file
    .write_all(report.as_bytes())
    .map_err(|error| format!("capacity family report write failed: {error}"))
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

fn validate_runtime_report_allocator(
  actual_binary_allocator: &str,
  report_requested: bool,
  reported_allocator: Option<&str>,
) -> Result<(), String> {
  if !report_requested {
    return Ok(());
  }
  let reported = reported_allocator
    .ok_or_else(|| "runtime report requires ALLOCATBELT_APP_ALLOCATOR".to_owned())?;
  if reported != actual_binary_allocator {
    return Err(format!(
      "runtime report allocator {reported:?} differs from executable allocator {actual_binary_allocator:?}"
    ));
  }
  Ok(())
}

fn validate_runtime_report_allocator_from_env(actual_binary_allocator: &str) -> Result<(), String> {
  validate_runtime_report_allocator(
    actual_binary_allocator,
    env::var_os("ALLOCATBELT_APP_RUNTIME_REPORT").is_some(),
    env::var("ALLOCATBELT_APP_ALLOCATOR").ok().as_deref(),
  )
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

#[cfg(test)]
fn run_with_limits(
  options: Options,
  capacity_horizon: Option<Duration>,
  open_loop_arrivals: Option<usize>,
) -> Result<Counts, String> {
  let arrivals = open_loop_arrivals.unwrap_or(OPEN_LOOP_ARRIVALS);
  let rate = options.rate_per_second.unwrap_or(1);
  let plan = ArrivalPlan::new(Profile::Steady, options.workload, arrivals, rate)?;
  run_with_plan(options, plan, capacity_horizon)
}

fn run_with_plan(
  options: Options,
  plan: ArrivalPlan,
  capacity_horizon: Option<Duration>,
) -> Result<Counts, String> {
  let setup_started = Instant::now();
  validate_options(options)?;
  let open_loop_arrivals = plan.arrivals;
  if options.mode == Mode::OpenLoop {
    validate_arrival_plan(plan, execution_deadlines().trace)?;
  } else if !matches!(
    plan.profile,
    Profile::Steady | Profile::Mixed | Profile::Burst | Profile::Oversubscribed
  ) {
    return Err("capacity mode supports steady, mixed, burst, or oversubscribed profiles".into());
  }
  let config = LaneConfig::default();
  // Open-loop reference work is bounded and belongs to setup: recomputing the
  // memory or disk reference payload after observing a result delays the
  // credit that releases the producer's unchanged eight-operation window.
  let open_loop_oracle = if options.mode == Mode::OpenLoop {
    Some(build_plan_expected_oracle(plan, &config)?)
  } else {
    None
  };
  let domain =
    ApplicationDomain::new_for_profile(options.workload, plan.async_workers, plan.profile.label())?;
  let rate_configs = domain.rate_configs();
  #[cfg(feature = "resource-feedback")]
  let mut feedback_trace;
  let (submitter, observer, scope, runtime, resources, mut run_bindings) = match options.executor {
    Executor::Bounded => {
      let async_config = AsyncConfig {
        workers: plan.async_workers,
        max_outstanding: WINDOW,
        max_scopes: 2,
      };
      let mut builder = MultiThreadBuilder::new(async_config)
        .resource_domain(domain.tenant())
        .resources(domain.local_limits())
        .rate_timer_registrations(256)
        .disk_rate(rate_configs.disk)
        .upload_rate(rate_configs.upload)
        .download_rate(rate_configs.download);
      #[cfg(feature = "resource-feedback")]
      if let Some(factory) = domain.feedback_factory()? {
        builder = builder.feedback_sources(factory);
      }
      if matches!(options.workload, Workload::Disk | Workload::Mixed) {
        builder = builder
          .blocking(BlockingConfig {
            workers: plan.async_workers,
            max_outstanding: WINDOW,
            capacity: allocatbelt::runtime::Resources {
              disk: WINDOW,
              ..allocatbelt::runtime::Resources::ZERO
            },
          })
          .filesystem();
      }
      let driver = builder
        .build()
        .map_err(|error| format!("allocatbelt application driver start failed: {error}"))?;
      let run_bindings = domain.for_native(&driver)?;
      #[cfg(feature = "resource-feedback")]
      {
        feedback_trace = run_bindings.start_feedback_trace(options.mode)?;
      }
      let resources = run_bindings.resources();
      let scope = driver
        .scope()
        .map_err(|error| format!("allocatbelt scope start failed: {error}"))?;
      let native_fs = driver.filesystem();
      let handle = scope.handle();
      warm_bounded_for(&handle, plan.async_workers)?;
      if matches!(options.workload, Workload::Disk | Workload::Mixed) {
        let blocking = driver.blocking().ok_or_else(|| {
          "owning driver omitted its selected blocking filesystem pool".to_owned()
        })?;
        disk_lane::warm_native_workers(&blocking, &handle, plan.async_workers)?;
      }
      let observer = Observer::Bounded(handle.clone());
      (
        Submitter::Bounded {
          handle,
          disk: native_fs.clone(),
        },
        observer,
        Some(scope),
        ExecutorRuntime::Bounded(Box::new(driver)),
        resources,
        run_bindings,
      )
    }
    Executor::Tokio => {
      let run_bindings = domain.for_tokio()?;
      #[cfg(feature = "resource-feedback")]
      {
        feedback_trace = run_bindings.start_feedback_trace(options.mode)?;
      }
      let resources = run_bindings.resources();
      let runtime_built = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(plan.async_workers)
        .max_blocking_threads(plan.async_workers)
        .thread_name("allocatbelt-app-tokio")
        .build()
        .map_err(|error| format!("Tokio runtime start failed: {error}"))?;
      let handle = runtime_built.handle().clone();
      let slots = Arc::new(tokio::sync::Semaphore::new(WINDOW));
      let disk_slots = matches!(options.workload, Workload::Disk | Workload::Mixed)
        .then(|| Arc::new(tokio::sync::Semaphore::new(WINDOW)));
      warm_tokio_for(&handle, plan.async_workers)?;
      if matches!(options.workload, Workload::Disk | Workload::Mixed) {
        disk_lane::warm_tokio_workers(&handle, plan.async_workers)?;
      }
      let observer = Observer::Tokio;
      (
        Submitter::Tokio {
          handle,
          slots,
          disk_slots,
          disk_io: run_bindings.io().blocking_disk_io(),
          cpu_gate: run_bindings.cpu_gate(),
          task_admission: run_bindings.task_admission(),
        },
        observer,
        None,
        ExecutorRuntime::Tokio(runtime_built),
        resources,
        run_bindings,
      )
    }
  };
  // CPU/memory intentionally create no filesystem blocking-service workers.
  let mut scope_keepalive = scope;
  let observer_task_lease = run_bindings.reserve_task()?;

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
    Mode::OpenLoop => 2 * WINDOW + 1,
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
      let _task_lease = observer_task_lease;
      let report = observe_with_plan(
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
        plan,
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
  #[cfg(feature = "resource-feedback")]
  if let Some(trace) = feedback_trace.as_ref() {
    trace.mark_phase(
      FeedbackTracePhase::RssBefore,
      Instant::now(),
      Some(rss_before),
    )?;
  }
  if setup_started.elapsed() > SETUP_DEADLINE {
    return Err("application setup exceeded its 120 second finite deadline".into());
  }
  let mut runtime_readback = RuntimeBindingWriter::begin(options, plan, &run_bindings)?;
  #[cfg(feature = "resource-feedback")]
  let startup_feedback_observation = if run_bindings.mode().feedback_enabled() {
    Some(run_bindings.wait_for_feedback_startup_observation()?)
  } else {
    None
  };
  #[cfg(feature = "resource-feedback")]
  if startup_feedback_observation.is_some() && setup_started.elapsed() > SETUP_DEADLINE {
    return Err("application startup feedback wait exceeded the finite setup deadline".into());
  }
  let producer_states = id_states;
  let producer_resources = resources.clone();
  let producer_task_lease = run_bindings.reserve_task()?;
  let producer_thread = thread::Builder::new()
    .name("application-producer".into())
    .spawn(move || {
      let _task_lease = producer_task_lease;
      let report = produce_with_plan(
        submitter,
        options,
        config,
        &producer_resources,
        events_tx,
        credits_rx,
        producer_states,
        capacity_horizon.unwrap_or(CAPACITY_HORIZON),
        plan,
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
  #[cfg(feature = "resource-feedback")]
  if let Some(sample_at) = startup_feedback_observation {
    let (sample_bounds, production_bounds) = if let Some(trace) = feedback_trace.as_ref() {
      (
        Some(trace.monotonic_bounds(sample_at)?),
        Some(trace.monotonic_bounds(producer.started_at)?),
      )
    } else {
      (None, None)
    };
    run_bindings.validate_feedback_startup_observation(
      sample_at,
      producer.started_at,
      sample_bounds,
      production_bounds,
    )?;
  }
  #[cfg(feature = "resource-feedback")]
  if let Some(trace) = feedback_trace.as_ref() {
    trace.mark_phase(
      FeedbackTracePhase::ProductionStart,
      producer.started_at,
      None,
    )?;
    trace.mark_phase(
      FeedbackTracePhase::ProductionEnd,
      producer.production_end,
      None,
    )?;
  }
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
  #[cfg(feature = "resource-feedback")]
  let collector_task_lease_count = usize::from(feedback_trace.is_some());
  #[cfg(not(feature = "resource-feedback"))]
  let collector_task_lease_count = 0;
  #[cfg(feature = "resource-feedback")]
  let feedback_drain_upper_ns = if let Some(trace) = feedback_trace.as_ref() {
    let drain_end = Instant::now();
    let (_, drain_upper_ns) = trace.monotonic_bounds(drain_end)?;
    trace.mark_phase(FeedbackTracePhase::DrainEnd, drain_end, None)?;
    Some(drain_upper_ns)
  } else {
    None
  };
  let production_cpu_ended_ns = process_cpu_time_ns();
  let drain_readback = runtime_readback.as_mut().map_or(Ok(()), |readback| {
    readback.capture_after_drain(&run_bindings, collector_task_lease_count)
  });
  let feedback_drain_health = run_bindings.validate_feedback_health("after_drain");
  drain_readback?;
  let rss_after_drain = sample_after_checkpoint_delay()?;
  #[cfg(feature = "resource-feedback")]
  if let Some(trace) = feedback_trace.as_ref() {
    trace.mark_phase(
      FeedbackTracePhase::RssAfterDrain,
      Instant::now(),
      Some(rss_after_drain),
    )?;
  }
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
    plan,
  )?;
  let last_observed = observer_report.last_observed;
  if last_observed.saturating_duration_since(producer.production_end) > execution_deadlines().drain
  {
    return Err("application drain exceeded its finite deadline".into());
  }

  #[cfg(feature = "resource-feedback")]
  if let (Some(drain_upper_ns), Some(trace)) = (feedback_drain_upper_ns, feedback_trace.as_ref()) {
    run_bindings.wait_for_feedback_observation_after(drain_upper_ns, |sample_at| {
      trace.monotonic_bounds(sample_at)
    })?;
  }

  let shutdown_started = Instant::now();
  let mut shutdown_timings = Vec::with_capacity(3);
  match (options.executor, runtime) {
    (Executor::Bounded, ExecutorRuntime::Bounded(mut runtime)) => {
      let scope = scope_keepalive
        .take()
        .ok_or_else(|| "bounded scope ownership was lost".to_owned())?;
      let shutdown_task_lease = run_bindings.reserve_task()?;
      let elapsed_ns = run_shutdown_with_timeout("allocatbelt application driver", move || {
        let _task_lease = shutdown_task_lease;
        runtime
          .block_on(scope.close())
          .map_err(|error| format!("scope close failed: {error}"))?;
        runtime
          .request_shutdown(MultiShutdown {
            tasks: AsyncShutdown::Drain,
            blocking: ShutdownMode::Drain,
            processes: ProcessShutdownMode::Wait,
          })
          .map_err(|error| format!("allocatbelt driver shutdown request failed: {error}"))?;
        loop {
          match runtime
            .drive_shutdown_step()
            .map_err(|error| format!("allocatbelt driver shutdown failed: {error}"))?
          {
            allocatbelt::runtime::ShutdownProgress::Complete => return Ok(()),
            allocatbelt::runtime::ShutdownProgress::Pending => {
              thread::sleep(Duration::from_millis(1));
            }
          }
        }
      })?;
      shutdown_timings.push(("allocatbelt application driver", elapsed_ns));
    }
    (Executor::Tokio, ExecutorRuntime::Tokio(runtime)) => {
      let shutdown_task_lease = run_bindings.reserve_task()?;
      let elapsed_ns = run_shutdown_with_timeout("Tokio runtime", move || {
        let _task_lease = shutdown_task_lease;
        runtime.shutdown_timeout(execution_deadlines().shutdown);
        Ok(())
      })?;
      shutdown_timings.push(("Tokio runtime", elapsed_ns));
    }
    _ => return Err("executor runtime ownership mismatch".into()),
  }
  let feedback_shutdown_started = Instant::now();
  let feedback_shutdown = run_bindings.shutdown_feedback(execution_deadlines().shutdown);
  let feedback_shutdown_ns = feedback_shutdown_started.elapsed().as_nanos();
  if options.executor == Executor::Tokio && run_bindings.feedback_started() {
    shutdown_timings.push(("Tokio resource feedback", feedback_shutdown_ns));
  }
  let timer_shutdown = run_bindings.shutdown_auxiliary_timer();
  #[cfg(feature = "resource-feedback")]
  if let Some(trace) = feedback_trace.as_ref() {
    trace.mark_phase(FeedbackTracePhase::ShutdownEnd, Instant::now(), None)?;
  }
  #[cfg(feature = "resource-feedback")]
  let trace_finalizer = feedback_trace
    .take()
    .map(FeedbackTraceCollector::stop_for_finalization)
    .transpose()?;
  let shutdown_readback = runtime_readback.as_mut().map_or(Ok(()), |readback| {
    readback.capture("after_shutdown", &run_bindings)
  });
  let feedback_shutdown_health = run_bindings.validate_feedback_health("after_shutdown");
  let feedback_health_error = [
    feedback_drain_health.err(),
    feedback_shutdown.err(),
    feedback_shutdown_health.err(),
  ]
  .into_iter()
  .flatten()
  .next();
  let driver_shutdown_ns = shutdown_started.elapsed().as_nanos();
  let shutdown_report = write_shutdown_report(
    producer
      .production_end
      .saturating_duration_since(producer.started_at)
      .as_nanos(),
    producer.production_cpu_started_ns,
    production_cpu_ended_ns,
    observer_report.completed_on_time + observer_report.completed_late,
    &shutdown_timings,
  );
  timer_shutdown?;
  shutdown_readback?;
  shutdown_report?;
  let final_resources = resources.snapshot();
  if final_resources.managed_memory != 0
    || final_resources.disk_ops != 0
    || final_resources.network_ops != 0
  {
    return Err(format!(
      "nonzero final resource ledger: {final_resources:?}"
    ));
  }
  let (global_domain, tenant_domain, _) = run_bindings.snapshots()?;
  for (name, snapshot) in [("global", global_domain), ("tenant", tenant_domain)] {
    if snapshot.used.get(DomainResource::Cpu) != 0
      || snapshot.used.get(DomainResource::Memory) != 0
      || snapshot.used.get(DomainResource::Disk) != 0
      || snapshot.used.get(DomainResource::Network) != 0
      || snapshot.used.get(DomainResource::Tasks) != 0
    {
      return Err(format!(
        "nonzero final {name} resource usage: {:?}",
        snapshot.used
      ));
    }
  }
  let readback_domain = domain.readback_domain();
  let fixed_control_baseline = domain.fixed_global_control_baseline();
  drop(run_bindings);
  drop(resources);
  drop(domain);
  let rss_after_shutdown = sample_after_checkpoint_delay()?;
  #[cfg(feature = "resource-feedback")]
  if let Some(finalizer) = trace_finalizer.as_ref() {
    finalizer.mark_phase(
      FeedbackTracePhase::RssAfterShutdown,
      Instant::now(),
      Some(rss_after_shutdown),
    )?;
  }
  #[cfg(feature = "resource-feedback")]
  if let Some(finalizer) = trace_finalizer {
    finalizer.finish()?;
  }
  if let Some(readback) = runtime_readback {
    readback.finish(&readback_domain, fixed_control_baseline)?;
  }
  if let Some(error) = feedback_health_error {
    return Err(error);
  }
  if producer.trace_overrun {
    return Err("open-loop producer exceeded its finite trace deadline".into());
  }
  let (blocking_workers, topology) = match (options.executor, options.workload) {
    (Executor::Bounded, Workload::Mixed) if plan.async_workers == 2 => {
      (2, "2 async + 2 filesystem workers")
    }
    (Executor::Bounded, Workload::Mixed) => (4, "4 async + 4 filesystem workers"),
    (Executor::Tokio, Workload::Mixed) if plan.async_workers == 2 => {
      (2, "2 async + 2 blocking workers")
    }
    (Executor::Tokio, Workload::Mixed) => (4, "4 async + 4 blocking workers"),
    (_, Workload::Disk) => match options.executor {
      Executor::Bounded if plan.async_workers == 2 => (2, "2 async + 2 filesystem workers"),
      Executor::Bounded => (4, "4 async + 4 filesystem workers"),
      Executor::Tokio if plan.async_workers == 2 => (2, "2 async + 2 blocking workers"),
      Executor::Tokio => (4, "4 async + 4 blocking workers"),
    },
    (_, _) if plan.async_workers == 2 => (0, "2 async workers"),
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
    async_workers: plan.async_workers,
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
  Bounded(Box<MultiThreadDriver>),
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
    Workload::Mixed => ResourceLimits {
      // The shared live window can skew toward the most memory-heavy family.
      // Reserve eight maximum disk buffers plus the observer's retained
      // memory-output window so slow families cannot turn interleaving into
      // a resource-admission failure.
      managed_memory: WINDOW * DiskConfig::default().bytes
        + MAX_RETAINED_MEMORY_OUTPUTS * MemoryConfig::default().grown_bytes,
      disk_concurrent_ops: 8,
      network_concurrent_ops: 16,
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

pub(super) struct RuntimeBindingWriter {
  path: std::path::PathBuf,
  rows: Vec<(String, String)>,
}

impl RuntimeBindingWriter {
  pub(super) fn begin(
    options: Options,
    plan: ArrivalPlan,
    bindings: &ApplicationRunBindings,
  ) -> Result<Option<Self>, String> {
    let Some(path) = env::var_os("ALLOCATBELT_APP_RUNTIME_REPORT") else {
      return Ok(None);
    };
    let mut writer = Self {
      path: path.into(),
      rows: Vec::new(),
    };
    let identity = [
      ("report_nonce", "ALLOCATBELT_APP_REPORT_NONCE"),
      ("run_id", "ALLOCATBELT_APP_RUN_ID"),
      ("allocator", "ALLOCATBELT_APP_ALLOCATOR"),
      ("executor", "ALLOCATBELT_APP_EXECUTOR"),
      ("source_sha256", "ALLOCATBELT_APP_SOURCE_SHA256"),
      ("binary_sha256", "ALLOCATBELT_APP_BINARY_SHA256"),
      ("comparison_family", "ALLOCATBELT_APP_COMPARISON_FAMILY"),
      (
        "resource_ceiling_sha256",
        "ALLOCATBELT_APP_RESOURCE_CEILING_SHA256",
      ),
      ("policy_sha256", "ALLOCATBELT_APP_POLICY_SHA256"),
    ];
    for (name, variable) in identity {
      let value = env::var(variable)
        .map_err(|_| format!("runtime readback identity is missing {variable}"))?;
      if matches!(
        name,
        "source_sha256" | "binary_sha256" | "resource_ceiling_sha256" | "policy_sha256"
      ) && !is_hex(&value, 64)
      {
        return Err(format!(
          "runtime readback identity {name} is not a SHA-256 value"
        ));
      }
      if name == "report_nonce" && !is_hex(&value, 32) {
        return Err("runtime readback report nonce is malformed".into());
      }
      if name == "run_id" && !is_token(&value) {
        return Err("runtime readback run ID is malformed".into());
      }
      writer.add(format!("identity.{name}"), value)?;
    }
    writer.add(
      "identity.hashes_are_echoed_bindings_not_self_proof".to_owned(),
      "controller_must_independently_verify_source_binary_TSV_and_receipt_hashes".to_owned(),
    )?;
    let profile = env::var("ALLOCATBELT_APP_PROFILE")
      .map_err(|_| "runtime readback identity is missing ALLOCATBELT_APP_PROFILE".to_owned())?;
    let workload = env::var("ALLOCATBELT_APP_WORKLOAD")
      .map_err(|_| "runtime readback identity is missing ALLOCATBELT_APP_WORKLOAD".to_owned())?;
    let executor = env::var("ALLOCATBELT_APP_EXECUTOR").unwrap_or_default();
    let comparison_family = env::var("ALLOCATBELT_APP_COMPARISON_FAMILY").unwrap_or_default();
    if profile != plan.profile.label() || workload != options.workload.label() {
      return Err(
        "runtime readback profile/workload differs from the selected application run".into(),
      );
    }
    let expected_executor = match options.executor {
      Executor::Bounded => "allocatbelt",
      Executor::Tokio => "tokio-1.53.1",
    };
    if executor != expected_executor {
      return Err("runtime readback executor differs from the selected executor".into());
    }
    if comparison_family != bindings.mode().comparison_family() {
      return Err(
        "runtime readback comparison family differs from the selected runtime mode".into(),
      );
    }
    if bindings.mode() == ApplicationMode::ExternalPressure && !bindings.feedback_started() {
      return Err("external-pressure comparison started without its feedback service".into());
    }
    for (key, value) in [
      ("identity.profile", profile),
      ("identity.workload", workload),
      ("configuration.mode", options.mode.label().to_owned()),
      (
        "configuration.rate_per_second",
        options
          .rate_per_second
          .map_or_else(|| "0".to_owned(), |rate| rate.to_string()),
      ),
      ("configuration.arrivals", plan.arrivals.to_string()),
      (
        "configuration.async_workers",
        plan.async_workers.to_string(),
      ),
      ("configuration.logical_window", WINDOW.to_string()),
      (
        "configuration.trace_duration_ns",
        if options.mode == Mode::OpenLoop {
          plan.trace_duration_ns()?.to_string()
        } else {
          CAPACITY_HORIZON.as_nanos().to_string()
        },
      ),
      (
        "configuration.pulse_rate_per_second",
        if plan.profile == Profile::Burst {
          options
            .rate_per_second
            .unwrap_or(0)
            .checked_mul(4)
            .ok_or_else(|| "runtime readback burst rate overflow".to_owned())?
            .to_string()
        } else {
          options
            .rate_per_second
            .map_or_else(|| "0".to_owned(), |rate| rate.to_string())
        },
      ),
      (
        "configuration.task_ceiling",
        APPLICATION_TASK_CEILING.to_string(),
      ),
      (
        "accounting.cpu",
        if options.executor == Executor::Bounded {
          "owning_scheduler_domain_cpu_tickets"
        } else {
          "cpu_gate_per_tokio_future_poll_and_blocking_io"
        }
        .to_owned(),
      ),
      (
        "accounting.tasks",
        if options.executor == Executor::Bounded {
          "owning_scheduler_tasks_plus_explicit_root_roles"
        } else {
          "explicit_tokio_task_leases_plus_root_roles"
        }
        .to_owned(),
      ),
      (
        "accounting.managed_payload",
        "ResourceScope_and_tenant_domain".to_owned(),
      ),
      (
        "accounting.disk_operations",
        "ResourceScope_disk_permits".to_owned(),
      ),
      (
        "accounting.disk_bytes",
        if options.executor == Executor::Bounded {
          "owning_FsRate_per_syscall"
        } else {
          "shared_BlockingByteIo_per_syscall_inside_spawn_blocking"
        }
        .to_owned(),
      ),
      (
        "accounting.network_operations",
        "ResourceScope_network_permits".to_owned(),
      ),
      (
        "accounting.network_bytes",
        "IoBindings_directional_byte_buckets".to_owned(),
      ),
      (
        "accounting.opaque_runtime_allocations",
        "excluded_from_managed_payload_and_measured_by_RSS".to_owned(),
      ),
      (
        "accounting.receipt_writer_storage",
        "bounded_metadata_outside_application_ResourceScope".to_owned(),
      ),
    ] {
      writer.add(key.to_owned(), value)?;
    }
    for (key, value) in bindings.policy_rows() {
      writer.add(key, value)?;
    }
    let lane = LaneConfig::default();
    for (key, value) in [
      ("kernel.cpu_rounds", lane.rounds.to_string()),
      (
        "kernel.memory_initial_bytes",
        lane.memory.initial_bytes.to_string(),
      ),
      (
        "kernel.memory_grown_bytes",
        lane.memory.grown_bytes.to_string(),
      ),
      ("kernel.memory_seed", lane.memory.seed.to_string()),
      ("kernel.disk_bytes", lane.disk.bytes.to_string()),
      ("kernel.disk_offset", lane.disk.offset.to_string()),
      ("kernel.disk_seed", lane.disk.seed.to_string()),
      (
        "kernel.http_body_bytes",
        http::ORACLE_BODY_BYTES.to_string(),
      ),
      ("kernel.mixed_interleave", "cpu,memory,http,disk".to_owned()),
    ] {
      writer.add(key.to_owned(), value)?;
    }
    let domain_limits = bindings.domain_limits();
    for (name, resource) in [
      ("cpu", DomainResource::Cpu),
      ("memory", DomainResource::Memory),
      ("disk", DomainResource::Disk),
      ("network", DomainResource::Network),
      ("tasks", DomainResource::Tasks),
      ("control", DomainResource::Control),
    ] {
      writer.add(
        format!("configuration.domain_ceiling.{name}"),
        domain_limits.get(resource).to_string(),
      )?;
    }
    writer.add(
      "configuration.managed_memory_limit_bytes".to_owned(),
      bindings.resources().limits().managed_memory.to_string(),
    )?;
    writer.add(
      "configuration.disk_operation_limit".to_owned(),
      bindings
        .resources()
        .limits()
        .disk_concurrent_ops
        .to_string(),
    )?;
    writer.add(
      "configuration.network_operation_limit".to_owned(),
      bindings
        .resources()
        .limits()
        .network_concurrent_ops
        .to_string(),
    )?;
    writer.add(
      "configuration.fixed_global_control_baseline".to_owned(),
      bindings.fixed_global_control_baseline().to_string(),
    )?;
    let setup_rows = bindings.runtime_rows("setup")?;
    let setup_control = setup_rows
      .iter()
      .find(|(key, _)| key == "setup.global.used.control")
      .map(|(_, value)| value.clone())
      .ok_or_else(|| "runtime setup omitted its actual global Control usage".to_owned())?;
    writer.add(
      "configuration.setup_global_control".to_owned(),
      setup_control,
    )?;
    writer.add(
      "configuration.blocking_disk_adapter_constructed".to_owned(),
      bindings.io().has_blocking_disk_byte_io().to_string(),
    )?;
    for (key, value) in setup_rows {
      writer.add(key, value)?;
    }
    Ok(Some(writer))
  }

  pub(super) fn capture(
    &mut self,
    stage: &str,
    bindings: &ApplicationRunBindings,
  ) -> Result<(), String> {
    self.capture_with_collector_task_lease(stage, bindings, 0)
  }

  pub(super) fn capture_after_drain(
    &mut self,
    bindings: &ApplicationRunBindings,
    collector_task_lease_count: usize,
  ) -> Result<(), String> {
    self.capture_with_collector_task_lease("after_drain", bindings, collector_task_lease_count)
  }

  fn capture_with_collector_task_lease(
    &mut self,
    stage: &str,
    bindings: &ApplicationRunBindings,
    collector_task_lease_count: usize,
  ) -> Result<(), String> {
    if collector_task_lease_count > 1 || (stage != "after_drain" && collector_task_lease_count != 0)
    {
      return Err("runtime readback received an invalid collector Task lease allowance".into());
    }
    let rows = bindings.runtime_rows(stage)?;
    if matches!(stage, "after_drain" | "after_shutdown") {
      let required_zero = [
        ".global.used.cpu",
        ".global.used.memory",
        ".global.used.disk",
        ".global.used.network",
        ".tenant.used.cpu",
        ".tenant.used.memory",
        ".tenant.used.disk",
        ".tenant.used.network",
        ".scope.managed_memory_used",
        ".scope.disk_operations_used",
        ".scope.network_operations_used",
      ];
      for suffix in required_zero {
        let key = format!("{stage}{suffix}");
        let value = rows
          .iter()
          .find(|(candidate, _)| candidate == &key)
          .map(|(_, value)| value)
          .ok_or_else(|| format!("runtime readback omitted {key}"))?;
        if value != "0" {
          return Err(format!(
            "runtime readback found nonzero usage at {key}: {value}"
          ));
        }
      }
      for owner in ["global", "tenant"] {
        let key = format!("{stage}.{owner}.used.tasks");
        let actual = rows
          .iter()
          .find(|(candidate, _)| candidate == &key)
          .map(|(_, value)| value.as_str())
          .ok_or_else(|| format!("runtime readback omitted {key}"))?
          .parse::<usize>()
          .map_err(|_| format!("runtime readback has a malformed Task count at {key}"))?;
        let application_work = actual
          .checked_sub(collector_task_lease_count)
          .ok_or_else(|| format!("runtime readback is below the collector lease at {key}"))?;
        if application_work != 0 {
          return Err(format!(
            "runtime readback found application Task work at {stage}.{owner}: {application_work}"
          ));
        }
        self.add(
          format!("{stage}.{owner}.application_work_tasks"),
          application_work.to_string(),
        )?;
      }
      self.add(
        format!("{stage}.collector_task_lease_count"),
        collector_task_lease_count.to_string(),
      )?;
    }
    for (key, value) in rows {
      self.add(key, value)?;
    }
    Ok(())
  }

  fn add(&mut self, key: String, value: String) -> Result<(), String> {
    if key.is_empty()
      || key.contains(['\t', '\n', '\r'])
      || value.contains(['\t', '\n', '\r'])
      || self.rows.iter().any(|(existing, _)| existing == &key)
    {
      return Err("runtime readback contains a duplicate or unframed field".into());
    }
    self.rows.push((key, value));
    Ok(())
  }

  pub(super) fn finish(
    mut self,
    readback_domain: &allocatbelt::runtime::resource_domain::ResourceDomain,
    fixed_global_control_baseline: usize,
  ) -> Result<(), String> {
    let released = readback_domain.snapshot();
    for (key, value) in runtime_bindings::after_release_global_snapshot_rows(
      &released,
      fixed_global_control_baseline,
    )? {
      self.add(key, value)?;
    }
    self.rows.sort_by(|left, right| left.0.cmp(&right.0));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
      use std::os::unix::fs::OpenOptionsExt;
      options.mode(0o600);
    }
    let mut file = options
      .open(&self.path)
      .map_err(|error| format!("runtime readback create failed: {error}"))?;
    writeln!(
      file,
      "schema\t{}",
      runtime_bindings::RUNTIME_BINDING_RECEIPT_SCHEMA_V2
    )
    .map_err(|error| format!("runtime readback schema write failed: {error}"))?;
    for (key, value) in self.rows {
      writeln!(file, "{key}\t{value}")
        .map_err(|error| format!("runtime readback field write failed: {error}"))?;
    }
    file
      .sync_all()
      .map_err(|error| format!("runtime readback sync failed: {error}"))?;
    Ok(())
  }
}

fn validate_arrival_plan(plan: ArrivalPlan, deadline: Duration) -> Result<(), String> {
  let trace_ns = plan.trace_duration_ns()?;
  if Duration::from_nanos(trace_ns) > deadline {
    return Err("arrival plan exceeds its finite trace deadline".into());
  }
  Ok(())
}

#[cfg(test)]
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
  arrival_times_from_offset(scheduled, completed, offset_ns)
}

pub(super) fn arrival_times_for_plan(
  id: u64,
  scheduled: Instant,
  completed: Instant,
  plan: ArrivalPlan,
) -> Result<(u64, u64), String> {
  let scheduled_ns = plan.scheduled_offset_ns(id)?;
  arrival_times_from_offset(scheduled, completed, scheduled_ns)
}

fn arrival_times_from_offset(
  scheduled: Instant,
  completed: Instant,
  offset_ns: u64,
) -> Result<(u64, u64), String> {
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

#[cfg(test)]
fn trace_exceeded(mode: Mode, started_at: Instant, ended_at: Instant) -> bool {
  mode == Mode::OpenLoop
    && ended_at.saturating_duration_since(started_at) > execution_deadlines().trace
}

pub(super) fn trace_exceeded_for_plan(
  mode: Mode,
  started_at: Instant,
  ended_at: Instant,
  plan: ArrivalPlan,
) -> Result<bool, String> {
  if mode == Mode::Capacity {
    return Ok(false);
  }
  let planned_ns = plan.trace_duration_ns()?;
  let planned = Duration::from_nanos(planned_ns);
  let configured = execution_deadlines().trace;
  Ok(planned > configured || ended_at.saturating_duration_since(started_at) > configured)
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
        return Err(format!(
          "worker warm-up exceeded 30 seconds ({} of {expected} workers arrived)",
          state.entrants
        ));
      };
      let (next, result) = self
        .changed
        .wait_timeout(state, remaining)
        .unwrap_or_else(|e| e.into_inner());
      state = next;
      if result.timed_out() && state.entrants < expected {
        return Err(format!(
          "worker warm-up exceeded 30 seconds ({} of {expected} workers arrived)",
          state.entrants
        ));
      }
    }
    state.released = true;
    self.changed.notify_all();
    Ok(())
  }
}

pub(crate) fn warm_bounded_for(handle: &AsyncHandle, workers: usize) -> Result<(), String> {
  let gate = WarmGate::new(workers, WARMUP_TIMEOUT);
  let mut jobs = Vec::new();
  jobs
    .try_reserve_exact(workers)
    .map_err(|_| "could not reserve worker warm-up handles".to_owned())?;
  for _ in 0..workers {
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
  gate.release_after_all(workers)?;
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
  if seen.len() != workers {
    return Err(format!(
      "expected {workers} started async workers, saw {}",
      seen.len()
    ));
  }
  Ok(())
}

fn warm_tokio_for(handle: &tokio::runtime::Handle, workers: usize) -> Result<(), String> {
  let gate = WarmGate::new(workers, WARMUP_TIMEOUT);
  let mut jobs = Vec::new();
  jobs
    .try_reserve_exact(workers)
    .map_err(|_| "could not reserve Tokio warm-up handles".to_owned())?;
  for _ in 0..workers {
    let gate = Arc::clone(&gate);
    jobs.push(handle.spawn(async move {
      let thread_id = thread::current().id();
      let ready = gate.arrive_and_wait();
      (thread_id, ready)
    }));
  }
  gate.release_after_all(workers)?;
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
  if seen.len() != workers {
    return Err(format!(
      "expected {workers} started Tokio workers, saw {}",
      seen.len()
    ));
  }
  Ok(())
}

#[allow(clippy::too_many_arguments)]
fn produce_with_plan(
  submitter: Submitter,
  options: Options,
  config: LaneConfig,
  resources: &ResourceScope,
  events: ObserverEventSender<ObserverEvent>,
  credits: mpsc::Receiver<()>,
  states: Option<Arc<Mutex<Vec<IdState>>>>,
  capacity_horizon: Duration,
  plan: ArrivalPlan,
) -> Result<ProducerReport, String> {
  let start = Instant::now();
  let horizon_end = match options.mode {
    Mode::Capacity => start + capacity_horizon,
    Mode::OpenLoop => start
      .checked_add(Duration::from_nanos(plan.trace_duration_ns()?))
      .ok_or_else(|| "arrival trace end instant overflow".to_owned())?,
  };
  let mut attempted = 0;
  let mut admitted = 0;
  let mut rejected_logical_window = 0;
  let mut rejected_backend_full = 0;
  let mut lateness_sum_ns = 0u128;
  let mut lateness_max_ns = 0u64;
  let mut outstanding = 0usize;
  let mut next_capacity_id = 0u64;

  // Start the production CPU interval after warmup/setup and immediately
  // before the producer can observe or schedule its first operation.
  let production_cpu_started_ns = process_cpu_time_ns();
  loop {
    while let Ok(()) = credits.try_recv() {
      outstanding = outstanding.saturating_sub(1);
    }
    if options.mode == Mode::Capacity {
      wait_until_capacity_pulse(plan, start, horizon_end);
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
        let pulse_end = capacity_pulse_end(plan, start, horizon_end);
        while outstanding >= WINDOW {
          if Instant::now() >= horizon_end {
            break;
          }
          match credits.recv_timeout(pulse_end.saturating_duration_since(Instant::now())) {
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
        if Instant::now() >= pulse_end {
          continue;
        }
        let id = next_capacity_id;
        next_capacity_id += 1;
        (id, Instant::now())
      }
      Mode::OpenLoop => {
        if attempted >= plan.arrivals {
          break;
        }
        let scheduled_ns = plan.scheduled_offset_ns(attempted as u64)?;
        let scheduled = start
          .checked_add(Duration::from_nanos(scheduled_ns))
          .ok_or_else(|| "arrival scheduled instant overflow".to_owned())?;
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
    let workload = plan.workload_for(id);
    match submitter.submit(workload, config, resources, id) {
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
  if options.mode == Mode::OpenLoop
    && let Some(remaining) = horizon_end.checked_duration_since(Instant::now())
  {
    thread::sleep(remaining);
  }
  let production_end = Instant::now();
  let trace_overrun = trace_exceeded_for_plan(options.mode, start, production_end, plan)?;
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
    production_cpu_started_ns,
    trace_overrun,
  })
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
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
  let plan = ArrivalPlan::new(
    Profile::Steady,
    options.workload,
    open_loop_arrivals,
    options.rate_per_second.unwrap_or(1),
  )?;
  observe_with_plan(
    observer,
    options,
    config,
    resources,
    events,
    credits,
    states,
    open_loop_arrivals,
    pending_limit,
    watchdog_timeout,
    open_loop_oracle,
    plan,
  )
}

#[allow(clippy::too_many_arguments)]
fn observe_with_plan(
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
  plan: ArrivalPlan,
) -> Result<ObserverReport, String> {
  let mut completed_on_time = 0;
  let mut completed_late = 0;
  let mut errors = 0;
  let cancellations = 0;
  let mut digest = 0u64;
  let mut latencies_ns = Vec::new();
  let mut records = Vec::new();
  let mut family_published_on_time = [0u64; 4];
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
          let (scheduled_ns, completion_ns) =
            arrival_times_for_plan(id, scheduled, completion, plan)?;
          let workload = plan.workload_for(id);
          let expected_checksum =
            open_loop_expected(workload, &config, id, open_loop_oracle.as_deref())?;
          records.push(IdRecord {
            id,
            workload,
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
      let workload = plan.workload_for(id);
      match result {
        Ok(output) => {
          let output_value = output.value();
          checksum = output_value;
          if !validate_output_with_oracle(
            workload,
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
              if let Some(index) = workload.family_index() {
                family_published_on_time[index] = family_published_on_time[index].saturating_add(1);
              }
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
        let (scheduled_ns, completion_ns) = arrival_times_for_plan(id, scheduled, observed, plan)?;
        let expected_checksum =
          open_loop_expected(workload, &config, id, open_loop_oracle.as_deref())?;
        records.push(IdRecord {
          id,
          workload,
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
        family_published_on_time,
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

/// Canonical work inputs for a separately frozen mixed soak reference ring.
/// The observation ID remains separate from this reference work ID.
#[derive(Clone, Copy, Debug)]
pub struct CanonicalSoakInputs {
  pub family: Workload,
  pub cpu_seed: u64,
  pub cpu_rounds: u32,
  pub memory: MemoryConfig,
  pub disk: DiskConfig,
  pub http_seed: u64,
  pub http_body_bytes: usize,
}

pub fn canonical_soak_inputs(reference_work_id: u64) -> CanonicalSoakInputs {
  let config = LaneConfig::default();
  let seed = job_seed(reference_work_id);
  CanonicalSoakInputs {
    family: [
      Workload::Cpu,
      Workload::Memory,
      Workload::Http,
      Workload::Disk,
    ][(reference_work_id % 4) as usize],
    cpu_seed: seed,
    cpu_rounds: config.rounds,
    memory: MemoryConfig {
      seed,
      ..config.memory
    },
    disk: DiskConfig {
      seed,
      ..config.disk
    },
    http_seed: http::request_seed(reference_work_id),
    http_body_bytes: http::ORACLE_BODY_BYTES,
  }
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
    Workload::Mixed => match id % 4 {
      0 => expected_value(Workload::Cpu, config, id),
      1 => expected_value(Workload::Memory, config, id),
      2 => http::expected_request_checksum(id, http::ORACLE_BODY_BYTES),
      _ => expected_value(Workload::Disk, config, id),
    },
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

#[cfg(test)]
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

pub(super) fn build_plan_expected_oracle(
  plan: ArrivalPlan,
  config: &LaneConfig,
) -> Result<Arc<Vec<u64>>, String> {
  let mut oracle = Vec::new();
  oracle
    .try_reserve_exact(plan.arrivals)
    .map_err(|_| "could not reserve bounded profile oracle".to_owned())?;
  for id in 0..plan.arrivals {
    oracle.push(canonical_expected_value(
      plan.workload_for(id as u64),
      config,
      id as u64,
    ));
  }
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
    Workload::Mixed => "interleave=cpu,memory,http,disk".to_owned(),
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
  let mut profile = None;
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
      "--profile" => profile = Some(Profile::parse(&value)?),
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
  let profile = profile.ok_or_else(|| "oracle emitter requires --profile".to_owned())?;
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
  let plan = ArrivalPlan::new(profile, workload, arrivals, rate)?;
  validate_arrival_plan(plan, deadlines.trace)?;
  let config = LaneConfig::default();
  let oracle = build_plan_expected_oracle(plan, &config)?;
  let pulse_rate = if profile == Profile::Burst {
    rate
      .checked_mul(4)
      .ok_or_else(|| "burst pulse rate overflow".to_owned())?
  } else {
    rate
  };
  let mut report = String::from("schema\tallocatbelt-app-oracle-v2\n");
  report.push_str(&format!(
    "source_sha256\t{source_hash}\nbinary_sha256\t{binary_hash}\n"
  ));
  report.push_str(&format!(
    "profile\t{}\nworkload\t{}\nmode\topen_loop\n",
    profile.label(),
    workload.label()
  ));
  report.push_str(&format!(
    "average_rate_per_second\t{rate}\npulse_rate_per_second\t{pulse_rate}\narrivals\t{arrivals}\n"
  ));
  report.push_str(&format!(
    "trace_duration_ns\t{}\n",
    plan.trace_duration_ns()?
  ));
  report.push_str(&format!(
    "kernel_config\t{}\n",
    oracle_kernel_config(plan.workload, &config)
  ));
  report.push_str("id\tscheduled_ns\tworkload\texpected_checksum\n");
  for (id, checksum) in oracle.iter().enumerate() {
    report.push_str(&format!(
      "{id}\t{}\t{}\t{checksum}\n",
      plan.scheduled_offset_ns(id as u64)?,
      plan.workload_for(id as u64).label()
    ));
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

#[allow(clippy::too_many_arguments)]
fn validate_counts(
  options: Options,
  producer: &ProducerReport,
  observer: &ObserverReport,
  statuses: Option<&Vec<IdState>>,
  expected_checksum: u64,
  open_loop_arrivals: usize,
  open_loop_oracle: Option<&Vec<u64>>,
  plan: ArrivalPlan,
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
    if observer
      .records
      .iter()
      .any(|record| plan.workload_for(record.id) != record.workload)
    {
      return Err("per-ID workload differs from the canonical profile".into());
    }
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
    .is_some_and(|argument| argument == "--emit-feedback-policy-only")
  {
    #[cfg(feature = "resource-feedback")]
    {
      return match feedback_policy_probe::emit(args.into_iter()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
          eprintln!("application feedback policy probe invalid: {error}");
          ExitCode::from(2)
        }
      };
    }
    #[cfg(not(feature = "resource-feedback"))]
    {
      eprintln!("--emit-feedback-policy-only requires the resource-feedback feature");
      return ExitCode::from(2);
    }
  }
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
  let (options, plan, deadlines) = match parse_args(args.into_iter()) {
    Ok(parsed) => parsed,
    Err(error) => {
      eprintln!("{error}\n{}", usage());
      return ExitCode::from(2);
    }
  };
  if let Err(error) = validate_runtime_report_allocator_from_env(allocator) {
    eprintln!("application runtime identity invalid: {error}");
    return ExitCode::FAILURE;
  }
  let _ = EXECUTION_DEADLINES.set(deadlines);
  if matches!(options.workload, Workload::Http | Workload::Mixed) {
    return match http::run_and_print(allocator, options, plan) {
      Ok(()) => ExitCode::SUCCESS,
      Err(error) => {
        eprintln!("application run invalid: {error}");
        ExitCode::FAILURE
      }
    };
  }
  if options.workload == Workload::Disk {
    return match disk_lane::run_and_print(allocator, options, plan) {
      Ok(()) => ExitCode::SUCCESS,
      Err(error) => {
        eprintln!("application run invalid: {error}");
        ExitCode::FAILURE
      }
    };
  }
  match run_with_plan(options, plan, None) {
    Ok(counts) => {
      if let Err(error) =
        write_id_report(&counts.observer.records, allocator, options, plan.profile)
      {
        eprintln!("application run invalid: {error}");
        return ExitCode::FAILURE;
      }
      if let Err(error) = write_capacity_family_report(
        counts.producer.attempted,
        counts.observer.family_published_on_time,
        options,
        plan.profile,
      ) {
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

fn parse_args(
  args: impl Iterator<Item = String>,
) -> Result<(Options, ArrivalPlan, ExecutionDeadlines), String> {
  let mut executor = None;
  let mut workload = None;
  let mut mode = None;
  let mut rate = None;
  let mut arrivals = OPEN_LOOP_ARRIVALS;
  let mut arrivals_set = false;
  let mut profile = Profile::Steady;
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
      "--profile" => profile = Profile::parse(&value)?,
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
  if options.mode == Mode::Capacity
    && !matches!(
      profile,
      Profile::Steady | Profile::Mixed | Profile::Burst | Profile::Oversubscribed
    )
  {
    return Err("capacity mode supports steady, mixed, burst, or oversubscribed profiles".into());
  }
  let plan = if options.mode == Mode::OpenLoop {
    let rate = rate.ok_or_else(|| "open-loop mode requires --rate".to_owned())?;
    let plan = ArrivalPlan::new(profile, options.workload, arrivals, rate)?;
    validate_arrival_plan(plan, deadlines.trace)?;
    plan
  } else if arrivals_set {
    return Err("--arrivals applies only to open_loop mode".into());
  } else {
    ArrivalPlan::new(profile, options.workload, OPEN_LOOP_ARRIVALS, 1)?
  };
  let application_mode = selected_application_mode()?;
  validate_deadline_budget(
    deadlines,
    plan,
    options.executor,
    options.mode,
    application_mode,
  )?;
  Ok((options, plan, deadlines))
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

fn selected_application_mode() -> Result<ApplicationMode, String> {
  application_mode_from_environment_value(env::var("ALLOCATBELT_APP_COMPARISON_FAMILY"))
}

fn application_mode_from_environment_value(
  value: Result<String, env::VarError>,
) -> Result<ApplicationMode, String> {
  let comparison_family = match value {
    Ok(value) => Some(value),
    Err(env::VarError::NotPresent) => None,
    Err(env::VarError::NotUnicode(_)) => {
      return Err("ALLOCATBELT_APP_COMPARISON_FAMILY is not valid Unicode".into());
    }
  };
  ApplicationMode::from_comparison_family(comparison_family.as_deref())
}

fn validate_deadline_budget(
  deadlines: ExecutionDeadlines,
  plan: ArrivalPlan,
  executor: Executor,
  mode: Mode,
  application_mode: ApplicationMode,
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
  let base_shutdown_units: u64 = match (plan.workload, executor) {
    (Workload::Mixed, Executor::Bounded) => 4,
    (Workload::Http, Executor::Bounded) => 3,
    (Workload::Disk, Executor::Bounded) => 2,
    _ => 1,
  };
  let feedback_shutdown_units =
    if executor == Executor::Tokio && application_mode == ApplicationMode::ExternalPressure {
      1
    } else {
      0
    };
  let shutdown_units = base_shutdown_units
    .checked_add(feedback_shutdown_units)
    .ok_or_else(|| "deadline budget arithmetic overflow".to_owned())?;
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
  "usage: bench-application-* --executor bounded|tokio --workload cpu|memory|http|disk --mode capacity|open_loop [--rate ARRIVALS_PER_SECOND] [--arrivals N] [--trace-deadline-seconds S --drain-deadline-seconds S --shutdown-deadline-seconds S --process-deadline-seconds S]; or --emit-oracle-only PATH --workload cpu|memory|http|disk --rate N --arrivals N; or --emit-feedback-policy-only --workload cpu|memory|http|disk|mixed --profile steady|mixed|burst|oversubscribed"
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
    counts.async_workers.to_string(),
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
    ApplicationMode, AsyncConfig, AsyncShutdown, DiskReport, ExecutionDeadlines, Executor, IdState,
    Job, LaneConfig, Mode, Observer, ObserverEvent, ObserverEventSender, ObserverReport, Options,
    ProducerReport, Profile, SETUP_DEADLINE, WorkOutput, Workload, accept_capacity_id,
    application_mode_from_environment_value, observe, resource_limits, run_with_limits,
    validate_deadline_budget, validate_output,
  };
  use allocatbelt::runtime::asynchronous::AsyncRuntime;
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
    assert_eq!(parsed.1.arrivals, 5000);
    let custom = base.iter().copied().chain(["--arrivals", "42"]);
    assert_eq!(
      super::parse_args(custom.map(str::to_owned))
        .expect("custom arrivals")
        .1
        .arrivals,
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
  fn runtime_report_allocator_must_match_the_executable_identity() {
    assert_eq!(
      super::validate_runtime_report_allocator("allocatbelt", true, Some("allocatbelt")),
      Ok(())
    );
    assert!(
      super::validate_runtime_report_allocator("allocatbelt", true, Some("mimalloc-secure"))
        .is_err()
    );
    assert!(super::validate_runtime_report_allocator("tokio-1.53.1", true, None).is_err());
    assert_eq!(
      super::validate_runtime_report_allocator("allocatbelt", false, None),
      Ok(())
    );
  }

  #[test]
  fn arrival_profiles_freeze_burst_pulses_mixed_interleave_and_worker_count() {
    let burst = super::ArrivalPlan::new(Profile::Burst, Workload::Cpu, 6, 4).expect("burst plan");
    assert_eq!(
      burst.trace_duration_ns().expect("burst duration"),
      2_000_000_000
    );
    assert_eq!(burst.scheduled_offset_ns(0).expect("first pulse slot"), 0);
    assert_eq!(
      burst.scheduled_offset_ns(1).expect("second pulse slot"),
      62_500_000
    );
    assert_eq!(
      burst.scheduled_offset_ns(3).expect("last pulse slot"),
      187_500_000
    );
    assert_eq!(
      burst.scheduled_offset_ns(4).expect("next cycle"),
      1_000_000_000
    );

    let mixed =
      super::ArrivalPlan::new(Profile::Mixed, Workload::Mixed, 400_000, 4000).expect("mixed plan");
    assert_eq!(
      (0..8)
        .map(|id| mixed.workload_for(id).label())
        .collect::<Vec<_>>(),
      [
        "cpu", "memory", "http", "disk", "cpu", "memory", "http", "disk"
      ]
    );

    let oversubscribed =
      super::ArrivalPlan::new(Profile::Oversubscribed, Workload::Cpu, 100_000, 1000)
        .expect("two-worker plan");
    assert_eq!(oversubscribed.async_workers, 2);
    assert!(!Profile::SafetyOverload.qualifies());
  }

  #[test]
  fn burst_capacity_window_is_active_only_for_the_quarter_cycle() {
    assert!(super::capacity_pulse_active(0));
    assert!(super::capacity_pulse_active(249_999_999));
    assert!(!super::capacity_pulse_active(250_000_000));
    assert!(!super::capacity_pulse_active(999_999_999));
    assert!(super::capacity_pulse_active(1_000_000_000));
    assert!(super::capacity_pulse_active(1_249_999_999));
    assert!(!super::capacity_pulse_active(1_250_000_000));
  }

  #[test]
  fn mixed_memory_ceiling_covers_eight_disk_jobs_and_retained_memory_outputs() {
    let limits = super::resource_limits(Workload::Mixed);
    let expected = super::WINDOW * super::DiskConfig::default().bytes
      + super::MAX_RETAINED_MEMORY_OUTPUTS * super::MemoryConfig::default().grown_bytes;
    assert_eq!(limits.managed_memory, expected);
    assert_eq!(limits.disk_concurrent_ops, super::WINDOW);
    assert_eq!(limits.network_concurrent_ops, 2 * super::WINDOW);
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
      "--profile".to_owned(),
      "steady".to_owned(),
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
    assert_eq!(lines[0], "schema\tallocatbelt-app-oracle-v2");
    assert_eq!(lines[1], format!("source_sha256\t{}", "b".repeat(64)));
    assert_eq!(lines[2], format!("binary_sha256\t{}", "c".repeat(64)));
    assert_eq!(lines[3], "profile\tsteady");
    assert_eq!(lines[4], "workload\tcpu");
    assert_eq!(lines[5], "mode\topen_loop");
    assert_eq!(lines[6], "average_rate_per_second\t1000");
    assert_eq!(lines[7], "pulse_rate_per_second\t1000");
    assert_eq!(lines[8], "arrivals\t2");
    assert_eq!(lines[9], "trace_duration_ns\t2000000");
    assert_eq!(lines[10], "kernel_config\trounds=50000");
    assert_eq!(lines[11], "id\tscheduled_ns\tworkload\texpected_checksum");
    assert_eq!(
      lines[12],
      format!(
        "0\t0\tcpu\t{}",
        super::expected_value(Workload::Cpu, &LaneConfig::default(), 0)
      )
    );
    assert_eq!(
      lines[13],
      format!(
        "1\t1000000\tcpu\t{}",
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
        workload: Workload::Cpu,
        scheduled_ns: 2,
        completion_ns: 5,
        terminal: "completed",
        checksum: 33,
        expected_checksum: 33,
      },
      super::IdRecord {
        id: 0,
        workload: Workload::Cpu,
        scheduled_ns: 0,
        completion_ns: 4,
        terminal: "completed",
        checksum: 11,
        expected_checksum: 11,
      },
      super::IdRecord {
        id: 1,
        workload: Workload::Cpu,
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
    let expired = Instant::now() - super::execution_deadlines().process - Duration::from_secs(1);
    assert_eq!(super::remaining_process_deadline(expired), Duration::ZERO);
    assert!(super::remaining_process_deadline(Instant::now()) > Duration::ZERO);
  }

  #[test]
  fn deadline_budget_counts_only_the_tokio_external_feedback_shutdown_unit() {
    let shutdown = Duration::from_secs(11);
    let drain = Duration::from_secs(7);
    let plan = super::ArrivalPlan::new(Profile::Steady, Workload::Cpu, 1, 1)
      .expect("CPU deadline test plan");
    let prior_exact = SETUP_DEADLINE.as_secs()
      + super::CAPACITY_HORIZON.as_secs()
      + 1
      + drain.as_secs()
      + shutdown.as_secs();
    let external_exact = prior_exact + shutdown.as_secs();
    let deadlines = |process_seconds| ExecutionDeadlines {
      trace: Duration::from_secs(1),
      drain,
      shutdown,
      process: Duration::from_secs(process_seconds),
    };

    assert!(
      validate_deadline_budget(
        deadlines(prior_exact),
        plan,
        Executor::Tokio,
        Mode::Capacity,
        ApplicationMode::ExternalPressure,
      )
      .is_err()
    );
    assert!(
      validate_deadline_budget(
        deadlines(external_exact),
        plan,
        Executor::Tokio,
        Mode::Capacity,
        ApplicationMode::ExternalPressure,
      )
      .is_ok()
    );
    assert!(
      validate_deadline_budget(
        deadlines(prior_exact),
        plan,
        Executor::Tokio,
        Mode::Capacity,
        ApplicationMode::Fixed,
      )
      .is_ok()
    );
    assert!(
      validate_deadline_budget(
        deadlines(prior_exact),
        plan,
        Executor::Bounded,
        Mode::Capacity,
        ApplicationMode::ExternalPressure,
      )
      .is_ok()
    );
  }

  #[test]
  fn selected_application_mode_rejects_unknown_and_nonunicode_environment_values() {
    assert_eq!(
      application_mode_from_environment_value(Err(std::env::VarError::NotPresent))
        .expect("unset mode selects fixed policy"),
      ApplicationMode::Fixed
    );
    assert!(application_mode_from_environment_value(Ok("unknown".to_owned())).is_err());
    assert!(
      application_mode_from_environment_value(Err(std::env::VarError::NotUnicode(
        std::ffi::OsString::from("external_pressure"),
      )))
      .is_err()
    );
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
    let forged_checksum_with_bad_payload = WorkOutput::Memory(super::MemoryOutput {
      report: super::memory::MemoryReport {
        peak_replacement_was_enforced: false,
        charged_after_growth: corrupted.charged_bytes(),
        checksum: oracle[1],
      },
      buffer: corrupted.clone(),
    });
    assert!(!super::validate_output_with_oracle(
      Workload::Memory,
      &config,
      1,
      &forged_checksum_with_bad_payload,
      Some(&oracle),
    ));
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
    let mut forged_charge = output();
    if let WorkOutput::Memory(output) = &mut forged_charge {
      output.report.charged_after_growth += 1;
    }
    assert!(!super::validate_output_with_oracle(
      Workload::Memory,
      &config,
      1,
      &forged_charge,
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
    let mut wrong_offset = output(expected_from_payload);
    if let WorkOutput::Disk(report) = &mut wrong_offset {
      report.offset += 1;
    }
    assert!(!super::validate_output_with_oracle(
      Workload::Disk,
      &config,
      id,
      &wrong_offset,
      Some(&oracle),
    ));
    let mut missing_cleanup = output(expected_from_payload);
    if let WorkOutput::Disk(report) = &mut missing_cleanup {
      report.temp_directory_removed = false;
    }
    assert!(!super::validate_output_with_oracle(
      Workload::Disk,
      &config,
      id,
      &missing_cleanup,
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
      family_published_on_time: [0; 4],
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
      production_cpu_started_ns: super::process_cpu_time_ns(),
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
        1,
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
    assert!(
      error.contains("observer queue closed before pending jobs"),
      "unexpected observer failure after producer panic: {error}"
    );
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
