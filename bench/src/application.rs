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
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

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
const MAX_TRACE: Duration = Duration::from_secs(300);
const MAX_CAPACITY_JOBS: usize = 10_000_000;
const WARMUP_TIMEOUT: Duration = Duration::from_secs(30);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(300);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(900);
const MAX_RETAINED_MEMORY_OUTPUTS: usize = WINDOW;
const TSV_HEADER: &str = "schema\tallocator\texecutor\tworkload\tmode\tasync_workers\tblocking_workers\ttopology\tlogical_window\tglobal_task_limit\tretained_window\tarrival_rate_per_second\trequested_arrivals\tattempted\tadmitted\trejected_full\trejected_resource\tcompleted_on_time\tcompleted_late\terrors\tcancellations\tunresolved\tlost\tresult_digest\texpected_digest\tcapacity_publications_per_second\tsuccessful_throughput_through_drain_per_second\tsetup_ns\ttimer_pair_median_ns\twall_through_drain_ns\tdrain_tail_ns\tresponse_p50_ns\tresponse_p95_ns\tresponse_p99_ns\tproducer_lateness_mean_ns\tproducer_lateness_max_ns\tmax_observed_managed_bytes\tretained_managed_bytes\tmanaged_limit_bytes\tdisk_limit_ops\tnetwork_limit_ops\tfinal_managed_bytes\tfinal_disk_ops\tfinal_network_ops\trss_before_kib\trss_after_drain_kib\trss_after_shutdown_kib\thwm_before_kib\thwm_after_drain_kib\thwm_after_shutdown_kib\tshutdown_ns";

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
  /// Submit exactly 5,000 IDs against absolute scheduled arrivals.
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
  Tokio(tokio::task::JoinHandle<allocatbelt_app_ports::PortResult<WorkOutput>>),
}

impl Job {
  fn is_finished(&self) -> bool {
    match self {
      Self::Bounded(job) => job.is_finished(),
      Self::Tokio(job) => job.is_finished(),
    }
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
  Tokio(tokio::runtime::Handle),
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
    ready_events: mpsc::SyncSender<ObserverEvent>,
  ) -> Result<Job, Rejection> {
    let seed = job_seed(id);
    match self {
      Self::Bounded { handle, disk } => {
        let driver = disk.clone().map(DiskDriver::Native);
        let operation = operation(workload, config, resources.clone(), seed, driver);
        let future = async move {
          let result = operation.await;
          let _ = ready_events.send(ObserverEvent::Ready);
          result
        };
        handle.spawn(future).map(Job::Bounded).map_err(|error| {
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
        Ok(Job::Tokio(handle.spawn(async move {
          let result = operation.await;
          let _ = ready_events.send(ObserverEvent::Ready);
          drop(permit);
          result
        })))
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
      (Self::Tokio(handle), Job::Tokio(job)) => handle
        .block_on(job)
        .map_err(|error| format!("Tokio application task failed: {error}"))?
        .map_err(|error| error.to_string()),
      _ => Err("job was delivered to the wrong executor observer".into()),
    }
  }
}

enum ObserverEvent {
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
  Ready,
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
    .recv_timeout(SHUTDOWN_TIMEOUT)
    .map_err(|error| format!("{label} shutdown exceeded 60 seconds: {error}"))?;
  worker
    .join()
    .map_err(|_| format!("{label} shutdown worker panicked"))?;
  result?;
  Ok(started.elapsed().as_nanos())
}

pub(super) fn write_shutdown_report(
  trace_ns: u128,
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

/// Runs a CPU or memory lane. This is called only by the benchmark binary;
/// tests use the private short-run settings below and make no speed claim.
pub(crate) fn run(options: Options) -> Result<Counts, String> {
  if options.workload == Workload::Http {
    return Err("HTTP workload uses its paired transaction observer".into());
  }
  run_with_limits(options, None, None)
}

fn run_with_limits(
  options: Options,
  capacity_horizon: Option<Duration>,
  open_loop_arrivals: Option<usize>,
) -> Result<Counts, String> {
  let setup_started = Instant::now();
  validate_options(options)?;
  let config = LaneConfig::default();
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
      let observer = Observer::Tokio(handle.clone());
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
    let arrivals = open_loop_arrivals.unwrap_or(OPEN_LOOP_ARRIVALS);
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
    Mode::OpenLoop => 4 * open_loop_arrivals.unwrap_or(OPEN_LOOP_ARRIVALS) + 1,
  };
  let (events_tx, events_rx) = mpsc::sync_channel(event_capacity);
  let (credits_tx, credits_rx) = mpsc::sync_channel(WINDOW);
  let (producer_tx, producer_rx) = mpsc::sync_channel(1);
  let observer_ids = id_states.clone();
  let observer_resources = resources.clone();
  let observer_arrivals = open_loop_arrivals.unwrap_or(OPEN_LOOP_ARRIVALS);
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
      );
      let _ = observer_tx.send(report);
    })
    .map_err(|error| format!("observer thread start failed: {error}"))?;

  let timer_pair_median_ns = measure_timer_pair_median_ns();
  let rss_before = sample_process_memory()?;
  let producer_states = id_states;
  let producer_resources = resources.clone();
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
        open_loop_arrivals.unwrap_or(OPEN_LOOP_ARRIVALS),
      );
      let _ = producer_tx.send(report);
    })
    .map_err(|error| format!("producer thread start failed: {error}"))?;

  let producer = producer_rx
    .recv_timeout(PROCESS_TIMEOUT)
    .map_err(|error| format!("producer deadline failed: {error}"))??;
  producer_thread
    .join()
    .map_err(|_| "application producer panicked".to_owned())?;
  let drain_deadline = producer.production_end + DRAIN_TIMEOUT;
  let drain_remaining = drain_deadline.saturating_duration_since(Instant::now());
  let observer_report = observer_rx
    .recv_timeout(drain_remaining)
    .map_err(|error| format!("application drain deadline failed: {error}"))??;
  observer_thread
    .join()
    .map_err(|_| "application observer panicked".to_owned())?;
  let rss_after_drain = sample_after_checkpoint_delay()?;
  let expected_checksum = expected_digest(options, &observer_report, &producer);
  let statuses = observer_report.final_statuses.as_ref();
  validate_counts(
    options,
    &producer,
    &observer_report,
    statuses,
    expected_checksum,
    open_loop_arrivals.unwrap_or(OPEN_LOOP_ARRIVALS),
  )?;
  let last_observed = observer_report.last_observed;
  if last_observed.saturating_duration_since(producer.production_end) > DRAIN_TIMEOUT {
    return Err("application drain exceeded its 300 second deadline".into());
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
        runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
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
    return Err("open-loop producer exceeded its 300 second trace deadline".into());
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
    let trace_ns = (OPEN_LOOP_ARRIVALS as u128 * 1_000_000_000) / rate as u128;
    let trace = Duration::from_nanos(trace_ns as u64);
    if trace > MAX_TRACE {
      return Err("5,000-arrival open-loop trace exceeds 300 seconds".into());
    }
  }
  Ok(())
}

fn trace_exceeded(mode: Mode, started_at: Instant, ended_at: Instant) -> bool {
  mode == Mode::OpenLoop && ended_at.saturating_duration_since(started_at) > MAX_TRACE
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
  events: mpsc::SyncSender<ObserverEvent>,
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
  let mut rejected_full = 0;
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
      rejected_full += 1;
      if let Some(states) = state_table {
        states.lock().unwrap_or_else(|e| e.into_inner())[id as usize] = IdState::Rejected;
      }
      continue;
    }
    match submitter.submit(options.workload, config, resources, id, events.clone()) {
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
        rejected_full += 1;
        if let Some(states) = state_table {
          states.lock().unwrap_or_else(|e| e.into_inner())[id as usize] = IdState::Rejected;
        }
        if options.mode == Mode::Capacity {
          return Err("capacity mode encountered a task-window Full rejection".into());
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
    rejected_full,
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
) -> Result<ObserverReport, String> {
  let mut completed_on_time = 0;
  let mut completed_late = 0;
  let mut errors = 0;
  let cancellations = 0;
  let mut digest = 0u64;
  let mut latencies_ns = Vec::new();
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
  loop {
    let event = match events.recv_timeout(Duration::from_micros(100)) {
      Ok(event) => Some(event),
      Err(mpsc::RecvTimeoutError::Timeout) => None,
      Err(mpsc::RecvTimeoutError::Disconnected) => {
        if !producer_done {
          return Err("observer queue closed before pending jobs were consumed".into());
        }
        None
      }
    };
    if let Some(event) = event {
      match event {
        ObserverEvent::Done {
          attempted: _attempted,
          horizon_end: _horizon_end,
        } => {
          producer_done = true;
        }
        ObserverEvent::Ready => {}
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
      if !pending[index].3.is_finished() {
        index += 1;
        continue;
      }
      let (id, scheduled, horizon_end, job) = pending.swap_remove(index);
      let result = observer.join(job);
      let observed = Instant::now();
      last_observed = observed;
      let mut completed = false;
      match result {
        Ok(output) => {
          let output_value = output.value();
          if !validate_output(options.workload, &config, id, &output) {
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
      });
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

fn validate_output(workload: Workload, config: &LaneConfig, id: u64, output: &WorkOutput) -> bool {
  match (workload, output) {
    (Workload::Cpu, WorkOutput::Cpu(value)) => *value == expected_value(workload, config, id),
    (Workload::Memory, WorkOutput::Memory(output)) => {
      output.report.charged_after_growth == output.buffer.charged_bytes()
        && output.buffer.len() == config.memory.grown_bytes
        && output.report.checksum == memory::checksum(output.buffer.as_slice())
        && output.report.checksum == expected_value(workload, config, id)
    }
    (Workload::Disk, WorkOutput::Disk(output)) => {
      output.offset == config.disk.offset
        && output.bytes == config.disk.bytes
        && output.checksum == expected_value(workload, config, id)
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

fn expected_digest(options: Options, observer: &ObserverReport, producer: &ProducerReport) -> u64 {
  let mut digest = 0u64;
  match &observer.final_statuses {
    Some(statuses) => {
      for (id, state) in statuses.iter().enumerate() {
        if *state == IdState::Completed {
          let value = expected_value(options.workload, &LaneConfig::default(), id as u64);
          digest = digest.wrapping_add(value ^ id as u64);
        }
      }
    }
    None => {
      let count = producer.admitted;
      for id in 0..count {
        let value = expected_value(options.workload, &LaneConfig::default(), id as u64);
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
) -> Result<(), String> {
  let completed = observer.completed_on_time + observer.completed_late;
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
  match parse_args(env::args().skip(1)) {
    Ok(options) if options.workload == Workload::Http => {
      match http::run_and_print(allocator, options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
          eprintln!("application run invalid: {error}");
          ExitCode::FAILURE
        }
      }
    }
    Ok(options) if options.workload == Workload::Disk => {
      match disk_lane::run_and_print(allocator, options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
          eprintln!("application run invalid: {error}");
          ExitCode::FAILURE
        }
      }
    }
    Ok(options) => match run(options) {
      Ok(counts) => {
        print_row(allocator, options, &counts);
        ExitCode::SUCCESS
      }
      Err(error) => {
        eprintln!("application run invalid: {error}");
        ExitCode::FAILURE
      }
    },
    Err(error) => {
      eprintln!("{error}\n{}", usage());
      ExitCode::from(2)
    }
  }
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Options, String> {
  let mut executor = None;
  let mut workload = None;
  let mut mode = None;
  let mut rate = None;
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
  Ok(options)
}

fn usage() -> &'static str {
  "usage: bench-application-* --executor bounded|tokio --workload cpu|memory|http|disk --mode capacity|open_loop [--rate ARRIVALS_PER_SECOND]"
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
    "1".to_owned(),
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
      OPEN_LOOP_ARRIVALS.to_string()
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
    DiskReport, Executor, IdState, Job, LaneConfig, Mode, Observer, ObserverEvent, Options,
    WorkOutput, Workload, accept_capacity_id, observe, resource_limits, run_with_limits,
    validate_output,
  };
  use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
  use std::sync::{Arc, Mutex, mpsc};
  use std::time::Instant;

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
    let first = Job::Tokio(handle.spawn(async move {
      first_gate
        .await
        .map_err(|_| "test gate closed".to_owned())?;
      Ok(WorkOutput::Cpu(first_value))
    }));
    let second = Job::Tokio(handle.spawn(async move { Ok(WorkOutput::Cpu(second_value)) }));
    let started = Instant::now();
    let horizon = started + std::time::Duration::from_secs(5);
    let (events_tx, events_rx) = mpsc::channel();
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
        Observer::Tokio(handle),
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
    let job = Job::Tokio(handle.spawn(async move {
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
    }));
    started_rx
      .recv_timeout(std::time::Duration::from_secs(2))
      .expect("disk job should hold its managed buffer before observer startup");
    let ready_checksum = super::expected_value(Workload::Disk, &config, 1);
    let ready_job = Job::Tokio(handle.spawn(async move {
      Ok(WorkOutput::Disk(DiskReport {
        offset: disk_config.offset,
        bytes: disk_config.bytes,
        checksum: ready_checksum,
        resources_after_cleanup: ready_job_resources.snapshot(),
        temp_directory_removed: true,
      }))
    }));
    let started = Instant::now();
    let horizon = started + std::time::Duration::from_secs(5);
    let (events_tx, events_rx) = mpsc::channel();
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
        Observer::Tokio(handle),
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
      counts.producer.admitted + counts.producer.rejected_full,
      128
    );
    assert_eq!(counts.observer.digest, counts.expected_checksum);
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
