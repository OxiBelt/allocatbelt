//! Paired loopback HTTP transactions for the application comparator.
//!
//! The workload logic stays in `allocatbelt-app-ports::http`; this module
//! owns only listener/client setup, bounded admission, result pairing, and
//! executor-specific endpoint adapters.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream};
use std::pin::Pin;
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, Instant};

use allocatbelt::runtime::asynchronous::{
  AsyncConfig, AsyncHandle, AsyncJob, AsyncRuntime, AsyncShutdown,
};
use allocatbelt::runtime::channel;
use allocatbelt::runtime::io::{AsyncRead, AsyncWrite};
use allocatbelt::runtime::managed::{
  OperationRequest, ResourceLimits, ResourceScope, ResourceSnapshot,
};
use allocatbelt::runtime::net::{NetHandle, TcpListener as NativeListener};
use allocatbelt::runtime::reactor::{Reactor, ReactorConfig, ReactorHandle};
use allocatbelt::runtime::{Config as BlockingConfig, Resources};
use allocatbelt_app_ports::http::{self, HttpConfig};
use allocatbelt_app_ports::memory::pattern_byte;
use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite};

use super::{Executor, Mode, Options, WORKERS};

const WINDOW: usize = 8;
const TASK_LIMIT: usize = 2 * WINDOW + 1;
const BODY_BYTES: usize = 4096;
const CAPACITY_HORIZON: Duration = Duration::from_secs(30);
const OPEN_LOOP_ARRIVALS: usize = 5000;
const MAX_TRACE: Duration = Duration::from_secs(300);
const MAX_CAPACITY_JOBS: usize = 10_000_000;
const WARMUP_TIMEOUT: Duration = Duration::from_secs(30);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(300);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(900);

#[derive(Clone)]
struct RoleLease {
  _hold: Arc<()>,
}

struct PairToken {
  id: u64,
  lease: RoleLease,
}

enum ClientJob {
  Bounded(AsyncJob<Result<u64, String>>),
  Tokio(tokio::task::JoinHandle<Result<u64, String>>),
}

impl ClientJob {
  fn is_finished(&self) -> bool {
    match self {
      Self::Bounded(job) => job.is_finished(),
      Self::Tokio(job) => job.is_finished(),
    }
  }
}

type HandlerResult = Result<(u64, u64), String>;
type HandlerOutput = (HandlerResult, RoleLease);
type JoinedHandler = HandlerOutput;

enum HandlerJob {
  Bounded(AsyncJob<HandlerOutput>),
  Tokio(tokio::task::JoinHandle<HandlerOutput>),
}

impl HandlerJob {
  fn is_finished(&self) -> bool {
    match self {
      Self::Bounded(job) => job.is_finished(),
      Self::Tokio(job) => job.is_finished(),
    }
  }
}

struct HandlerRecord {
  id: u64,
  _lease: RoleLease,
  job: HandlerJob,
}

enum Event {
  Client {
    id: u64,
    scheduled: Instant,
    horizon_end: Instant,
    job: ClientJob,
  },
  Rejected(u64),
  Handler(HandlerRecord),
  Done(ProducerReport),
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

#[derive(Clone, Copy, Debug)]
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
struct Report {
  producer: ProducerReport,
  rss_before: super::ProcessMemory,
  rss_after_drain: super::ProcessMemory,
  rss_after_shutdown: super::ProcessMemory,
  setup_ns: u128,
  timer_pair_median_ns: u64,
  on_time: usize,
  late: usize,
  errors: usize,
  digest: u64,
  expected: u64,
  p50_ns: u64,
  p95_ns: u64,
  p99_ns: u64,
  max_observed_managed_bytes: usize,
  final_resources: ResourceSnapshot,
  shutdown_ns: u128,
  last_observed: Instant,
  drain_tail_ns: u128,
  async_workers: usize,
  blocking_workers: usize,
  topology: &'static str,
}

#[derive(Debug)]
struct ObserverReport {
  on_time: usize,
  late: usize,
  errors: usize,
  digest: u64,
  expected: u64,
  latencies: Vec<u64>,
  max_observed_managed_bytes: usize,
  last_observed: Instant,
}

#[derive(Default)]
struct PendingPair {
  client: Option<(Instant, Instant, ClientJob)>,
  handler: Option<PendingHandler>,
}

type PendingHandler = (HandlerResult, RoleLease, RoleLease);

#[derive(Clone, Copy)]
struct Settings {
  horizon: Duration,
  arrivals: usize,
  body_bytes: usize,
}

impl Settings {
  fn production(options: Options) -> Result<Self, String> {
    if options.workload != super::Workload::Http {
      return Err("HTTP lane received a non-HTTP workload".into());
    }
    if options.mode == Mode::OpenLoop {
      let rate = options
        .rate_per_second
        .ok_or_else(|| "open-loop mode requires --rate".to_owned())?;
      if rate == 0 || rate > 1_000_000_000 {
        return Err("open-loop --rate must be in 1..=1000000000".into());
      }
      let trace_ns = (OPEN_LOOP_ARRIVALS as u128 * 1_000_000_000) / rate as u128;
      if trace_ns > MAX_TRACE.as_nanos() {
        return Err("5,000-arrival open-loop trace exceeds 300 seconds".into());
      }
    }
    Ok(Self {
      horizon: CAPACITY_HORIZON,
      arrivals: OPEN_LOOP_ARRIVALS,
      body_bytes: BODY_BYTES,
    })
  }

  fn event_capacity(self, mode: Mode) -> usize {
    match mode {
      Mode::Capacity => 4 * WINDOW + 1,
      Mode::OpenLoop => 4 * self.arrivals + 1,
    }
  }
}

pub(super) fn run_and_print(allocator: &str, options: Options) -> Result<(), String> {
  let settings = Settings::production(options)?;
  let report = match options.executor {
    Executor::Bounded => run_bounded(options, settings)?,
    Executor::Tokio => run_tokio(options, settings)?,
  };
  print_row(allocator, options, &report);
  Ok(())
}

pub(super) fn limits() -> ResourceLimits {
  ResourceLimits {
    managed_memory: WINDOW * 2 * http::MAX_REQUEST_BYTES + WINDOW * 2 * 128,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 2 * WINDOW,
  }
}

fn native_address(reactor: &ReactorHandle) -> Result<(NativeListener, SocketAddr), String> {
  let listener = StdTcpListener::bind(("127.0.0.1", 0))
    .map_err(|error| format!("loopback listener bind failed: {error}"))?;
  let address = listener
    .local_addr()
    .map_err(|error| format!("loopback listener address failed: {error}"))?;
  let listener = NativeListener::from_std(listener, reactor)
    .map_err(|error| format!("loopback listener registration failed: {}", error.error))?;
  Ok((listener, address))
}

fn std_listener() -> Result<(StdTcpListener, SocketAddr), String> {
  let listener = StdTcpListener::bind(("127.0.0.1", 0))
    .map_err(|error| format!("loopback listener bind failed: {error}"))?;
  let address = listener
    .local_addr()
    .map_err(|error| format!("loopback listener address failed: {error}"))?;
  Ok((listener, address))
}

fn run_bounded(options: Options, settings: Settings) -> Result<Report, String> {
  let setup_started = Instant::now();
  let resources = ResourceScope::new(limits());
  let async_runtime = AsyncRuntime::new(AsyncConfig {
    workers: WORKERS,
    max_outstanding: TASK_LIMIT,
    max_scopes: 2,
  })
  .map_err(|error| format!("allocatbelt async runtime start failed: {error}"))?;
  let scope = async_runtime
    .scope_with_resources(&resources)
    .map_err(|error| format!("allocatbelt task scope start failed: {error}"))?;
  let async_handle = scope.handle();
  super::warm_bounded(&async_handle)?;

  let mut blocking_runtime = allocatbelt::runtime::Runtime::new(BlockingConfig {
    workers: 1,
    max_outstanding: WINDOW + 1,
    capacity: Resources::ZERO,
  })
  .map_err(|error| format!("allocatbelt connector pool start failed: {error}"))?;
  let warm_job = blocking_runtime
    .handle()
    .try_spawn(Resources::ZERO, |_token| thread::current().id())
    .map_err(|error| format!("allocatbelt connector warm-up submit failed: {error:?}"))?;
  let connector_thread = async_handle
    .block_on(warm_job)
    .map_err(|error| format!("allocatbelt connector warm-up root failed: {error}"))?
    .map_err(|error| format!("allocatbelt connector warm-up task failed: {error}"))?;
  let _connector_worker_started = connector_thread;

  let reactor = Reactor::new(ReactorConfig {
    max_registrations: 2 * WINDOW + 4,
    max_waiters: 4 * WINDOW + 8,
  })
  .map_err(|error| format!("allocatbelt reactor start failed: {error}"))?;
  let reactor_handle = reactor.handle();
  let net = NetHandle::new(
    blocking_runtime.handle(),
    resources.clone(),
    reactor_handle.clone(),
    1,
  )
  .map_err(|error| format!("allocatbelt network handle setup failed: {error}"))?;
  let (listener, address) = native_address(&reactor_handle)?;

  let (roles_tx, roles_rx) = channel::channel(WINDOW, WINDOW)
    .map_err(|error| format!("HTTP accept-role channel setup failed: {error}"))?;
  let (events_tx, events_rx) = mpsc::sync_channel(settings.event_capacity(options.mode));
  let (ready_tx, ready_rx) = mpsc::sync_channel(1);
  let accept_handle = async_handle.clone();
  let accept_resources = resources.clone();
  let accept_event_tx = events_tx.clone();
  let accept_task = async_handle
    .spawn(async move {
      let _ = ready_tx.send(());
      accept_native(
        listener,
        roles_rx,
        accept_handle,
        accept_resources,
        accept_event_tx,
      )
      .await
    })
    .map_err(|error| format!("allocatbelt accept-task admission failed: {}", error.kind))?;
  ready_rx
    .recv_timeout(WARMUP_TIMEOUT)
    .map_err(|error| format!("allocatbelt accept task did not start: {error}"))?;

  let (credits_tx, credits_rx) = mpsc::sync_channel(WINDOW);
  let (producer_tx, producer_rx) = mpsc::sync_channel(1);
  let observer_handle = async_handle.clone();
  let observer_resources = resources.clone();
  let (observer_tx, observer_rx) = mpsc::sync_channel(1);
  let observer_thread = thread::Builder::new()
    .name("http-application-observer".into())
    .spawn(move || {
      let report = observe_events(
        Joiner::Bounded(observer_handle),
        options,
        settings,
        observer_resources,
        events_rx,
        credits_tx,
      );
      let _ = observer_tx.send(report);
    })
    .map_err(|error| format!("HTTP observer thread start failed: {error}"))?;

  let timer_pair_median_ns = super::measure_timer_pair_median_ns();
  let rss_before = super::sample_process_memory()?;
  let producer_handle = async_handle.clone();
  let producer_resources = resources.clone();
  let producer_net = net.clone();
  let producer_thread = thread::Builder::new()
    .name("http-application-producer".into())
    .spawn(move || {
      let report = produce_native(
        producer_handle,
        producer_net,
        producer_resources,
        address,
        roles_tx,
        events_tx,
        credits_rx,
        options,
        settings,
      );
      let _ = producer_tx.send(report);
    })
    .map_err(|error| format!("HTTP producer thread start failed: {error}"))?;

  let producer_result = producer_rx
    .recv_timeout(PROCESS_TIMEOUT)
    .map_err(|error| format!("HTTP producer deadline failed: {error}"))?;
  producer_thread
    .join()
    .map_err(|_| "HTTP producer panicked".to_owned())?;
  let producer = producer_result?;
  let drain_deadline = producer.production_end + DRAIN_TIMEOUT;
  let drain_remaining = drain_deadline.saturating_duration_since(Instant::now());
  let observed = observer_rx
    .recv_timeout(drain_remaining)
    .map_err(|error| format!("HTTP transaction drain deadline failed: {error}"))??;
  observer_thread
    .join()
    .map_err(|_| "HTTP observer panicked".to_owned())?;
  let rss_after_drain = super::sample_after_checkpoint_delay()?;
  async_handle
    .block_on(accept_task)
    .map_err(|error| format!("allocatbelt accept task join failed: {error}"))?
    .map_err(|error| format!("allocatbelt accept task output join failed: {error}"))?
    .map_err(|error| format!("allocatbelt accept task failed: {error}"))?;
  validate_pair_counts(options.mode, settings.arrivals, &producer, &observed)?;
  if observed
    .last_observed
    .saturating_duration_since(producer.production_end)
    > DRAIN_TIMEOUT
  {
    return Err("HTTP transaction drain exceeded 300 seconds".into());
  }

  let shutdown_started = Instant::now();
  let mut shutdown_timings = Vec::with_capacity(3);
  let elapsed_ns = super::run_shutdown_with_timeout("allocatbelt HTTP async runtime", move || {
    async_runtime
      .block_on(scope.close())
      .map_err(|error| format!("allocatbelt scope close failed: {error}"))?;
    async_runtime
      .shutdown(AsyncShutdown::Drain)
      .map_err(|error| format!("allocatbelt async runtime shutdown failed: {error}"))
  })?;
  shutdown_timings.push(("allocatbelt HTTP async runtime", elapsed_ns));
  let elapsed_ns = super::run_shutdown_with_timeout("allocatbelt connector pool", move || {
    blocking_runtime
      .shutdown(allocatbelt::runtime::ShutdownMode::Drain)
      .map_err(|error| format!("allocatbelt connector pool shutdown failed: {error}"))
  })?;
  shutdown_timings.push(("allocatbelt connector pool", elapsed_ns));
  let elapsed_ns = super::run_shutdown_with_timeout("allocatbelt reactor", move || {
    reactor
      .shutdown()
      .map_err(|error| format!("allocatbelt reactor shutdown failed: {error}"))
  })?;
  shutdown_timings.push(("allocatbelt reactor", elapsed_ns));
  let shutdown_ns = shutdown_started.elapsed().as_nanos();
  super::write_shutdown_report(
    producer
      .production_end
      .saturating_duration_since(producer.started_at)
      .as_nanos(),
    &shutdown_timings,
  )?;
  let rss_after_shutdown = super::sample_after_checkpoint_delay()?;
  let final_resources = resources.snapshot();
  if final_resources.managed_memory != 0
    || final_resources.disk_ops != 0
    || final_resources.network_ops != 0
  {
    return Err(format!(
      "HTTP final resource ledger is not empty: {final_resources:?}"
    ));
  }
  if producer.trace_overrun {
    return Err("HTTP open-loop producer exceeded its 300 second trace deadline".into());
  }
  Ok(build_report(
    super::ProcessCheckpoints {
      setup_started,
      timer_pair_median_ns,
      rss_before,
      rss_after_drain,
      rss_after_shutdown,
    },
    producer,
    observed,
    final_resources,
    shutdown_ns,
    1,
    "4 async + 1 blocking + dedicated reactor",
  ))
}

fn run_tokio(options: Options, settings: Settings) -> Result<Report, String> {
  let setup_started = Instant::now();
  let resources = ResourceScope::new(limits());
  let runtime = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(WORKERS)
    .max_blocking_threads(1)
    .thread_name("allocatbelt-app-tokio")
    .enable_all()
    .build()
    .map_err(|error| format!("Tokio runtime start failed: {error}"))?;
  let handle = runtime.handle().clone();
  super::warm_tokio(&handle)?;
  let connector_thread = handle.spawn_blocking(|| thread::current().id());
  let _connector_worker_started = handle
    .block_on(connector_thread)
    .map_err(|error| format!("Tokio connector warm-up failed: {error}"))?;

  let (std_listener, address) = std_listener()?;
  std_listener
    .set_nonblocking(true)
    .map_err(|error| format!("Tokio listener nonblocking setup failed: {error}"))?;
  let listener = {
    let _entered = handle.enter();
    tokio::net::TcpListener::from_std(std_listener)
      .map_err(|error| format!("Tokio listener registration failed: {error}"))?
  };

  let task_slots = Arc::new(tokio::sync::Semaphore::new(TASK_LIMIT));
  let accept_slot = task_slots
    .clone()
    .try_acquire_owned()
    .map_err(|_| "Tokio task window could not reserve its accept slot".to_owned())?;
  let (roles_tx, roles_rx) = channel::channel(WINDOW, WINDOW)
    .map_err(|error| format!("HTTP accept-role channel setup failed: {error}"))?;
  let (events_tx, events_rx) = mpsc::sync_channel(settings.event_capacity(options.mode));
  let (ready_tx, ready_rx) = mpsc::sync_channel(1);
  let accept_handle = handle.clone();
  let accept_resources = resources.clone();
  let accept_slots = task_slots.clone();
  let accept_event_tx = events_tx.clone();
  let accept_task = handle.spawn(async move {
    let _accept_slot = accept_slot;
    let _ = ready_tx.send(());
    accept_tokio(
      listener,
      roles_rx,
      accept_handle,
      accept_slots,
      accept_resources,
      accept_event_tx,
    )
    .await
  });
  ready_rx
    .recv_timeout(WARMUP_TIMEOUT)
    .map_err(|error| format!("Tokio accept task did not start: {error}"))?;

  let (credits_tx, credits_rx) = mpsc::sync_channel(WINDOW);
  let (producer_tx, producer_rx) = mpsc::sync_channel(1);
  let observer_handle = handle.clone();
  let observer_resources = resources.clone();
  let (observer_tx, observer_rx) = mpsc::sync_channel(1);
  let observer_thread = thread::Builder::new()
    .name("http-application-observer".into())
    .spawn(move || {
      let report = observe_events(
        Joiner::Tokio(observer_handle),
        options,
        settings,
        observer_resources,
        events_rx,
        credits_tx,
      );
      let _ = observer_tx.send(report);
    })
    .map_err(|error| format!("HTTP observer thread start failed: {error}"))?;
  let timer_pair_median_ns = super::measure_timer_pair_median_ns();
  let rss_before = super::sample_process_memory()?;
  let producer_handle = handle.clone();
  let producer_resources = resources.clone();
  let producer_slots = task_slots.clone();
  let producer_thread = thread::Builder::new()
    .name("http-application-producer".into())
    .spawn(move || {
      let report = produce_tokio(
        producer_handle,
        producer_slots,
        producer_resources,
        address,
        roles_tx,
        events_tx,
        credits_rx,
        options,
        settings,
      );
      let _ = producer_tx.send(report);
    })
    .map_err(|error| format!("HTTP producer thread start failed: {error}"))?;

  let producer_result = producer_rx
    .recv_timeout(PROCESS_TIMEOUT)
    .map_err(|error| format!("HTTP producer deadline failed: {error}"))?;
  producer_thread
    .join()
    .map_err(|_| "HTTP producer panicked".to_owned())?;
  let producer = producer_result?;
  let drain_deadline = producer.production_end + DRAIN_TIMEOUT;
  let drain_remaining = drain_deadline.saturating_duration_since(Instant::now());
  let observed = observer_rx
    .recv_timeout(drain_remaining)
    .map_err(|error| format!("HTTP transaction drain deadline failed: {error}"))??;
  observer_thread
    .join()
    .map_err(|_| "HTTP observer panicked".to_owned())?;
  let rss_after_drain = super::sample_after_checkpoint_delay()?;
  handle
    .block_on(accept_task)
    .map_err(|error| format!("Tokio accept task join failed: {error}"))?
    .map_err(|error| format!("Tokio accept task failed: {error}"))?;
  validate_pair_counts(options.mode, settings.arrivals, &producer, &observed)?;
  if observed
    .last_observed
    .saturating_duration_since(producer.production_end)
    > DRAIN_TIMEOUT
  {
    return Err("HTTP transaction drain exceeded 300 seconds".into());
  }

  let shutdown_started = Instant::now();
  let elapsed_ns = super::run_shutdown_with_timeout("Tokio HTTP runtime", move || {
    runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
    Ok(())
  })?;
  let shutdown_timings = [("Tokio HTTP runtime", elapsed_ns)];
  let shutdown_ns = shutdown_started.elapsed().as_nanos();
  super::write_shutdown_report(
    producer
      .production_end
      .saturating_duration_since(producer.started_at)
      .as_nanos(),
    &shutdown_timings,
  )?;
  let rss_after_shutdown = super::sample_after_checkpoint_delay()?;
  let final_resources = resources.snapshot();
  if final_resources.managed_memory != 0
    || final_resources.disk_ops != 0
    || final_resources.network_ops != 0
  {
    return Err(format!(
      "Tokio HTTP final resource ledger is not empty: {final_resources:?}"
    ));
  }
  if producer.trace_overrun {
    return Err("HTTP open-loop producer exceeded its 300 second trace deadline".into());
  }
  Ok(build_report(
    super::ProcessCheckpoints {
      setup_started,
      timer_pair_median_ns,
      rss_before,
      rss_after_drain,
      rss_after_shutdown,
    },
    producer,
    observed,
    final_resources,
    shutdown_ns,
    1,
    "4 async + 1 blocking + integrated I/O driver",
  ))
}

async fn accept_native(
  listener: NativeListener,
  mut roles: channel::Receiver<PairToken>,
  handle: AsyncHandle,
  resources: ResourceScope,
  events: mpsc::SyncSender<Event>,
) -> Result<(), String> {
  while let Some(token) = roles.recv().await {
    // A producer-issued role token is consumed before accept, so the listener
    // cannot retain an unaccounted accepted socket while awaiting a handler.
    let (mut stream, _) = listener
      .accept()
      .await
      .map_err(|error| format!("allocatbelt accept failed: {error}"))?;
    let id = token.id;
    let observer_lease = token.lease.clone();
    let task_lease = token.lease;
    let handler_resources = resources.clone();
    let ready_events = events.clone();
    let job = handle
      .spawn(async move {
        let endpoint_permit = handler_resources
          .try_acquire(OperationRequest {
            disk: 0,
            network: 1,
          })
          .map_err(|error| error.to_string());
        let result = match endpoint_permit {
          Ok(permit) => {
            let result = http::serve_connection_io(&mut stream, &handler_resources)
              .await
              .map_err(|error| error.to_string());
            drop(stream);
            drop(permit);
            result
          }
          Err(error) => {
            drop(stream);
            Err(error)
          }
        };
        let output = (result, task_lease);
        let _ = ready_events.send(Event::Ready);
        output
      })
      .map_err(|error| format!("allocatbelt handler admission failed: {}", error.kind))?;
    events
      .send(Event::Handler(HandlerRecord {
        id,
        _lease: observer_lease,
        job: HandlerJob::Bounded(job),
      }))
      .map_err(|_| "HTTP observer queue closed while publishing handler".to_owned())?;
  }
  Ok(())
}

async fn accept_tokio(
  listener: tokio::net::TcpListener,
  mut roles: channel::Receiver<PairToken>,
  handle: tokio::runtime::Handle,
  slots: Arc<tokio::sync::Semaphore>,
  resources: ResourceScope,
  events: mpsc::SyncSender<Event>,
) -> Result<(), String> {
  while let Some(token) = roles.recv().await {
    // Reserve global task capacity and the pair role before accepting a file
    // descriptor. The lease remains in the observer record through join.
    let task_slot = slots
      .clone()
      .acquire_owned()
      .await
      .map_err(|error| format!("Tokio handler task window closed: {error}"))?;
    let (stream, _) = listener
      .accept()
      .await
      .map_err(|error| format!("Tokio accept failed: {error}"))?;
    let id = token.id;
    let observer_lease = token.lease.clone();
    let task_lease = token.lease;
    let handler_resources = resources.clone();
    let ready_events = events.clone();
    let job = handle.spawn(async move {
      let _task_slot = task_slot;
      let result = match handler_resources.try_acquire(OperationRequest {
        disk: 0,
        network: 1,
      }) {
        Ok(permit) => {
          let mut endpoint = TokioEndpoint {
            stream,
            _permit: permit,
          };
          let result = http::serve_connection_io(&mut endpoint, &handler_resources)
            .await
            .map_err(|error| error.to_string());
          drop(endpoint);
          result
        }
        Err(error) => {
          drop(stream);
          Err(error.to_string())
        }
      };
      let output = (result, task_lease);
      let _ = ready_events.send(Event::Ready);
      output
    });
    events
      .send(Event::Handler(HandlerRecord {
        id,
        _lease: observer_lease,
        job: HandlerJob::Tokio(job),
      }))
      .map_err(|_| "HTTP observer queue closed while publishing handler".to_owned())?;
  }
  Ok(())
}

#[allow(clippy::too_many_arguments)]
fn produce_native(
  handle: AsyncHandle,
  net: NetHandle,
  resources: ResourceScope,
  address: SocketAddr,
  roles: channel::Sender<PairToken>,
  events: mpsc::SyncSender<Event>,
  credits: mpsc::Receiver<()>,
  options: Options,
  settings: Settings,
) -> Result<ProducerReport, String> {
  let role_sender = roles.clone();
  let ready_events = events.clone();
  produce(options, settings, events, credits, move |id, lease| {
    let net = net.clone();
    let resources = resources.clone();
    let operation = async move {
      let mut stream = net
        .connect(address)
        .await
        .map_err(|error| format!("allocatbelt HTTP connect failed: {error}"))?;
      let permit = resources
        .try_acquire(OperationRequest {
          disk: 0,
          network: 1,
        })
        .map_err(|error| format!("allocatbelt client endpoint admission failed: {error}"))?;
      let result = http::transact_client_io(
        &mut stream,
        &resources,
        id,
        HttpConfig {
          body_bytes: settings.body_bytes,
          seed: request_seed(id),
        },
      )
      .await
      .map_err(|error| error.to_string());
      drop(stream);
      drop(permit);
      result
    };
    let ready_events = ready_events.clone();
    let future = async move {
      let result = operation.await;
      let _ = ready_events.send(Event::Ready);
      result
    };
    let job = handle.spawn(future).map_err(|error| {
      if error.kind == allocatbelt::runtime::asynchronous::AsyncError::Full {
        SubmitResult::Full
      } else {
        SubmitResult::Closed
      }
    })?;
    let token = PairToken { id, lease };
    handle
      .block_on(role_sender.send(token))
      .map_err(|_| SubmitResult::Closed)?
      .map_err(|_| SubmitResult::Closed)?;
    Ok(ClientJob::Bounded(job))
  })
}

#[allow(clippy::too_many_arguments)]
fn produce_tokio(
  handle: tokio::runtime::Handle,
  slots: Arc<tokio::sync::Semaphore>,
  resources: ResourceScope,
  address: SocketAddr,
  roles: channel::Sender<PairToken>,
  events: mpsc::SyncSender<Event>,
  credits: mpsc::Receiver<()>,
  options: Options,
  settings: Settings,
) -> Result<ProducerReport, String> {
  let role_sender = roles.clone();
  let ready_events = events.clone();
  produce(options, settings, events, credits, move |id, lease| {
    let task_slot = slots
      .clone()
      .try_acquire_owned()
      .map_err(|error| match error {
        tokio::sync::TryAcquireError::Closed => SubmitResult::Closed,
        tokio::sync::TryAcquireError::NoPermits => SubmitResult::Full,
      })?;
    let token = PairToken { id, lease };
    handle
      .block_on(role_sender.send(token))
      .map_err(|_| SubmitResult::Closed)?;
    let handle_for_connect = handle.clone();
    let resources_for_client = resources.clone();
    let operation = async move {
      let stream = tokio_connect(&handle_for_connect, &resources_for_client, address)
        .await
        .map_err(|error| format!("Tokio HTTP connect failed: {error}"))?;
      let permit = resources_for_client
        .try_acquire(OperationRequest {
          disk: 0,
          network: 1,
        })
        .map_err(|error| format!("Tokio client endpoint admission failed: {error}"))?;
      let mut endpoint = TokioEndpoint {
        stream,
        _permit: permit,
      };
      let result = http::transact_client_io(
        &mut endpoint,
        &resources_for_client,
        id,
        HttpConfig {
          body_bytes: settings.body_bytes,
          seed: request_seed(id),
        },
      )
      .await
      .map_err(|error| error.to_string());
      drop(endpoint);
      result
    };
    let ready_events = ready_events.clone();
    Ok(ClientJob::Tokio(handle.spawn(async move {
      let _task_slot = task_slot;
      let result = operation.await;
      let _ = ready_events.send(Event::Ready);
      result
    })))
  })
}

#[derive(Clone, Copy)]
enum SubmitResult {
  Full,
  Closed,
}

fn produce(
  options: Options,
  settings: Settings,
  events: mpsc::SyncSender<Event>,
  credits: mpsc::Receiver<()>,
  mut submit: impl FnMut(u64, RoleLease) -> Result<ClientJob, SubmitResult>,
) -> Result<ProducerReport, String> {
  let started_at = Instant::now();
  let horizon_end = match options.mode {
    Mode::Capacity => started_at + settings.horizon,
    Mode::OpenLoop => {
      let rate = options
        .rate_per_second
        .expect("validated HTTP open-loop rate");
      started_at
        + Duration::from_nanos(((settings.arrivals as u128 * 1_000_000_000) / rate as u128) as u64)
    }
  };
  let mut attempted = 0usize;
  let mut admitted = 0usize;
  let mut rejected_logical_window = 0usize;
  let mut rejected_backend_full = 0usize;
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
          return Err("HTTP capacity lane reached its 10M operation safety cap".into());
        }
        while outstanding >= WINDOW {
          if Instant::now() >= horizon_end {
            break;
          }
          match credits.recv_timeout(horizon_end.saturating_duration_since(Instant::now())) {
            Ok(()) => outstanding -= 1,
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
              return Err("HTTP observer closed before returning window credit".into());
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
        if attempted >= settings.arrivals {
          break;
        }
        let rate = options
          .rate_per_second
          .expect("validated HTTP open-loop rate");
        let offset_ns = (attempted as u128 * 1_000_000_000) / rate as u128;
        let scheduled = started_at + Duration::from_nanos(offset_ns as u64);
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
    if options.mode == Mode::OpenLoop && outstanding >= WINDOW {
      rejected_logical_window += 1;
      events
        .send(Event::Rejected(id))
        .map_err(|_| "HTTP observer queue closed before rejection publication".to_owned())?;
      continue;
    }
    let lease = RoleLease {
      _hold: Arc::new(()),
    };
    match submit(id, lease) {
      Ok(job) => {
        admitted += 1;
        outstanding += 1;
        events
          .send(Event::Client {
            id,
            scheduled,
            horizon_end,
            job,
          })
          .map_err(|_| "HTTP observer queue closed before client publication".to_owned())?;
      }
      Err(SubmitResult::Full) => {
        rejected_backend_full += 1;
        if options.mode == Mode::OpenLoop {
          events
            .send(Event::Rejected(id))
            .map_err(|_| "HTTP observer queue closed before rejection publication".to_owned())?;
        }
        if options.mode == Mode::Capacity {
          return Err("HTTP capacity lane encountered a backend Full rejection".into());
        }
      }
      Err(SubmitResult::Closed) => {
        return Err("HTTP executor closed during client admission".into());
      }
    }
  }
  let production_end = Instant::now();
  let trace_overrun = super::trace_exceeded(options.mode, started_at, production_end);
  let report = ProducerReport {
    attempted,
    admitted,
    rejected_full: rejected_logical_window + rejected_backend_full,
    rejected_logical_window,
    rejected_backend_full,
    lateness_sum_ns,
    lateness_max_ns,
    started_at,
    production_end,
    trace_overrun,
  };
  events
    .send(Event::Done(report))
    .map_err(|_| "HTTP observer queue closed before producer completion".to_owned())?;
  Ok(report)
}

enum Joiner {
  Bounded(AsyncHandle),
  Tokio(tokio::runtime::Handle),
}

impl Joiner {
  fn client(&self, job: ClientJob) -> Result<u64, String> {
    match (self, job) {
      (Self::Bounded(handle), ClientJob::Bounded(job)) => handle
        .block_on(job)
        .map_err(|error| format!("allocatbelt client root failed: {error}"))?
        .map_err(|error| format!("allocatbelt client task failed: {error}"))?,
      (Self::Tokio(handle), ClientJob::Tokio(job)) => handle
        .block_on(job)
        .map_err(|error| format!("Tokio client join failed: {error}"))?,
      _ => Err("HTTP client job belongs to the wrong executor".into()),
    }
  }

  fn handler(&self, job: HandlerJob) -> Result<JoinedHandler, String> {
    let (result, task_lease) = match (self, job) {
      (Self::Bounded(handle), HandlerJob::Bounded(job)) => handle
        .block_on(job)
        .map_err(|error| format!("allocatbelt handler root failed: {error}"))?
        .map_err(|error| format!("allocatbelt handler task failed: {error}"))?,
      (Self::Tokio(handle), HandlerJob::Tokio(job)) => handle
        .block_on(job)
        .map_err(|error| format!("Tokio handler join failed: {error}"))?,
      _ => return Err("HTTP handler job belongs to the wrong executor".into()),
    };
    Ok((result, task_lease))
  }
}

fn observe_events(
  joiner: Joiner,
  options: Options,
  settings: Settings,
  resources: ResourceScope,
  events: mpsc::Receiver<Event>,
  credits: mpsc::SyncSender<()>,
) -> Result<ObserverReport, String> {
  let mut pending = HashMap::<u64, PendingPair>::new();
  pending
    .try_reserve(if options.mode == Mode::OpenLoop {
      settings.arrivals
    } else {
      WINDOW + 1
    })
    .map_err(|_| "could not reserve bounded HTTP pair table".to_owned())?;
  let mut handler_jobs = Vec::<(u64, HandlerJob, RoleLease)>::new();
  handler_jobs
    .try_reserve_exact(WINDOW)
    .map_err(|_| "could not reserve bounded HTTP handler jobs".to_owned())?;
  let mut states = if options.mode == Mode::OpenLoop {
    let mut values = Vec::new();
    values
      .try_reserve_exact(settings.arrivals)
      .map_err(|_| "could not reserve HTTP observer ID table".to_owned())?;
    values.resize(settings.arrivals, IdState::Unseen);
    Some(values)
  } else {
    None
  };
  let mut producer: Option<ProducerReport> = None;
  let mut next_scheduled_id = 0u64;
  let mut completed = 0usize;
  let mut on_time = 0usize;
  let mut late = 0usize;
  let mut errors = 0usize;
  let mut first_error = None;
  let mut digest = 0u64;
  let mut latencies = Vec::new();
  if options.mode == Mode::OpenLoop {
    latencies
      .try_reserve_exact(settings.arrivals)
      .map_err(|_| "could not reserve bounded HTTP latency samples".to_owned())?;
  }
  let mut max_observed_managed_bytes = 0usize;
  let mut last_observed = Instant::now();

  loop {
    max_observed_managed_bytes =
      max_observed_managed_bytes.max(resources.snapshot().managed_memory);
    let mut events_disconnected = false;
    let event = match events.recv_timeout(Duration::from_millis(1)) {
      Ok(event) => Some(event),
      Err(mpsc::RecvTimeoutError::Timeout) => None,
      Err(mpsc::RecvTimeoutError::Disconnected) => {
        events_disconnected = true;
        None
      }
    };
    if let Some(event) = event {
      match event {
        Event::Done(report) => producer = Some(report),
        Event::Client {
          id,
          scheduled,
          horizon_end,
          job,
        } => {
          if id != next_scheduled_id {
            return Err("HTTP producer published client IDs out of sequence".into());
          }
          next_scheduled_id += 1;
          if let Some(states) = &mut states {
            let state = states
              .get_mut(id as usize)
              .ok_or_else(|| "HTTP client ID was out of range".to_owned())?;
            if *state != IdState::Unseen {
              return Err("HTTP producer repeated an open-loop ID".into());
            }
            *state = IdState::Admitted;
          }
          let pair = pending.entry(id).or_default();
          if pair.client.replace((scheduled, horizon_end, job)).is_some() {
            return Err(format!("duplicate HTTP client result record for ID {id}"));
          }
        }
        Event::Rejected(id) => {
          if id != next_scheduled_id {
            return Err("HTTP producer published rejected IDs out of sequence".into());
          }
          next_scheduled_id += 1;
          if let Some(states) = &mut states {
            let state = states
              .get_mut(id as usize)
              .ok_or_else(|| "HTTP rejected ID was out of range".to_owned())?;
            if *state != IdState::Unseen {
              return Err("HTTP producer repeated an open-loop ID".into());
            }
            *state = IdState::Rejected;
          }
        }
        Event::Handler(record) => {
          handler_jobs.push((record.id, record.job, record._lease));
        }
        Event::Ready => {}
      }
    }

    let mut index = 0;
    while index < handler_jobs.len() {
      if !handler_jobs[index].1.is_finished() {
        index += 1;
        continue;
      }
      let (id, job, event_lease) = handler_jobs.swap_remove(index);
      let (handler_result, task_lease) = joiner.handler(job)?;
      let pair_id = handler_result
        .as_ref()
        .map_or(id, |(handler_id, _)| *handler_id);
      let pair = pending.entry(pair_id).or_default();
      if pair
        .handler
        .replace((handler_result, event_lease, task_lease))
        .is_some()
      {
        return Err("duplicate HTTP handler result record".into());
      }
    }

    while let Some(id) = pending.iter().find_map(|(id, pair)| {
      (pair
        .client
        .as_ref()
        .is_some_and(|(_, _, job)| job.is_finished())
        && pair.handler.is_some())
      .then_some(*id)
    }) {
      let mut pair = pending.remove(&id).expect("ready pair remains present");
      let (scheduled, horizon_end, client_job) = pair.client.take().expect("ready client exists");
      let (handler_result, event_lease, task_lease) =
        pair.handler.take().expect("ready handler exists");
      let client_result = joiner.client(client_job);
      // Publication time is captured immediately after the second join is
      // consumed. Checksum/reference validation is deliberately outside the
      // measured response interval.
      let observed = Instant::now();
      drop(task_lease);
      drop(event_lease);
      last_observed = observed;
      if options.mode == Mode::OpenLoop {
        latencies.push(observed.saturating_duration_since(scheduled).as_nanos() as u64);
      }
      let result = match (client_result, handler_result) {
        (Ok(client_checksum), Ok((handler_id, handler_checksum))) => {
          if handler_id != id || handler_checksum != client_checksum {
            Err("HTTP client/handler request IDs or checksums differ".to_owned())
          } else if client_checksum != expected_request_checksum(id, settings.body_bytes) {
            Err("HTTP response checksum does not match its request ID".to_owned())
          } else {
            Ok(client_checksum)
          }
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
      };
      match result {
        Ok(value) => {
          if observed <= horizon_end {
            on_time += 1;
          } else {
            late += 1;
          }
          digest = digest.wrapping_add(value);
          if let Some(states) = &mut states {
            let state = states
              .get_mut(id as usize)
              .ok_or_else(|| "HTTP observer saw an out-of-range request ID".to_owned())?;
            if *state != IdState::Admitted {
              return Err("HTTP observer saw a duplicate or unadmitted request ID".into());
            }
            *state = IdState::Completed;
          }
        }
        Err(error) => {
          errors += 1;
          if first_error.is_none() {
            first_error = Some(error);
          }
          if let Some(states) = &mut states
            && let Some(state) = states.get_mut(id as usize)
            && *state == IdState::Admitted
          {
            *state = IdState::Failed;
          }
        }
      }
      completed += 1;
      // In open-loop mode the producer never waits for the observer and may
      // have finished its fixed trace before this pair drains. Capacity mode
      // likewise has no further admissions after Done.
      let _ = credits.send(());
    }
    if producer.is_some_and(|report| completed >= report.admitted) {
      break;
    }
    if events_disconnected && handler_jobs.is_empty() && pending.is_empty() {
      return Err(format!(
        "HTTP event channel closed without a complete pair drain (completed {completed}, admitted {}, pending {}, done {})",
        producer.map_or(0, |report| report.admitted),
        pending.len(),
        producer.is_some(),
      ));
    }
  }
  let producer = producer.ok_or_else(|| "HTTP producer completion record missing".to_owned())?;
  if next_scheduled_id != producer.attempted as u64 {
    return Err("HTTP observer did not see every producer ID exactly once".into());
  }
  if !pending.is_empty() {
    return Err("HTTP observer drained with unpaired client or handler records".into());
  }
  if let Some(values) = &states
    && (values.iter().any(|state| {
      !matches!(
        state,
        IdState::Rejected | IdState::Completed | IdState::Failed
      )
    }) || values
      .iter()
      .filter(|state| matches!(state, IdState::Completed | IdState::Failed))
      .count()
      != producer.admitted)
  {
    return Err("HTTP open-loop IDs are missing or unresolved".into());
  }
  let mut expected = 0u64;
  match &states {
    Some(values) => {
      for (id, state) in values.iter().enumerate() {
        match state {
          IdState::Completed => {
            expected =
              expected.wrapping_add(expected_request_checksum(id as u64, settings.body_bytes));
          }
          IdState::Rejected => {}
          _ => return Err("HTTP open-loop ID table has an unresolved request".into()),
        }
      }
    }
    None => {
      for id in 0..producer.admitted as u64 {
        expected = expected.wrapping_add(expected_request_checksum(id, settings.body_bytes));
      }
    }
  }
  if digest != expected {
    return Err(format!(
      "HTTP per-ID result digest differs from the independent reference ({digest:#x} != {expected:#x}; completed={completed}, admitted={}, errors={errors}, first_error={first_error:?})",
      producer.admitted,
    ));
  }
  Ok(ObserverReport {
    on_time,
    late,
    errors,
    digest,
    expected,
    latencies,
    max_observed_managed_bytes,
    last_observed,
  })
}

struct TokioEndpoint {
  stream: tokio::net::TcpStream,
  _permit: allocatbelt::runtime::managed::OperationPermit,
}

impl AsyncRead for TokioEndpoint {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    let mut read_buf = tokio::io::ReadBuf::new(buf);
    match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
      Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Pending => Poll::Pending,
    }
  }
}

impl AsyncWrite for TokioEndpoint {
  fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.get_mut().stream).poll_flush(cx)
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
  }
}

async fn tokio_connect(
  handle: &tokio::runtime::Handle,
  resources: &ResourceScope,
  address: SocketAddr,
) -> Result<tokio::net::TcpStream, String> {
  // Match NetHandle::connect: one temporary slot covers the blocking connect
  // and registration phase, then drops in the worker before publication.
  let temporary = resources
    .try_acquire(OperationRequest {
      disk: 0,
      network: 1,
    })
    .map_err(|error| format!("Tokio connect operation admission failed: {error}"))?;
  let entered_handle = handle.clone();
  handle
    .spawn_blocking(move || -> io::Result<tokio::net::TcpStream> {
      let _temporary = temporary;
      let stream = StdTcpStream::connect(address)?;
      stream.set_nonblocking(true)?;
      let _entered = entered_handle.enter();
      tokio::net::TcpStream::from_std(stream)
    })
    .await
    .map_err(|error| format!("Tokio blocking connect task failed: {error}"))?
    .map_err(|error| format!("Tokio blocking connect/registration failed: {error}"))
}

fn expected_request_checksum(id: u64, body_bytes: usize) -> u64 {
  (0..body_bytes).fold(0xcbf2_9ce4_8422_2325, |hash, index| {
    (hash ^ u64::from(pattern_byte(request_seed(id), index))).wrapping_mul(0x0000_0100_0000_01b3)
  })
}

fn request_seed(id: u64) -> u64 {
  0xbb67_ae85_84ca_a73b ^ id.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

fn validate_pair_counts(
  mode: Mode,
  arrivals: usize,
  producer: &ProducerReport,
  observer: &ObserverReport,
) -> Result<(), String> {
  let completed = observer.on_time + observer.late;
  if producer.rejected_full != producer.rejected_logical_window + producer.rejected_backend_full
    || producer.attempted != producer.admitted + producer.rejected_full
    || producer.admitted != completed
  {
    return Err("HTTP producer and paired completion counts do not balance".into());
  }
  if observer.errors != 0 || observer.digest != observer.expected {
    return Err("HTTP lane had failed transactions or a checksum mismatch".into());
  }
  if mode == Mode::Capacity && producer.rejected_full != 0 {
    return Err("HTTP capacity lane rejected a transaction".into());
  }
  if mode == Mode::OpenLoop && producer.attempted != arrivals {
    return Err("HTTP open-loop lane did not schedule every request ID".into());
  }
  Ok(())
}

fn build_report(
  checkpoints: super::ProcessCheckpoints,
  producer: ProducerReport,
  observer: ObserverReport,
  final_resources: ResourceSnapshot,
  shutdown_ns: u128,
  blocking_workers: usize,
  topology: &'static str,
) -> Report {
  let mut latencies = observer.latencies;
  latencies.sort_unstable();
  let last_observed = observer.last_observed;
  let drain_tail_ns = last_observed
    .saturating_duration_since(producer.production_end)
    .as_nanos();
  Report {
    setup_ns: producer
      .started_at
      .saturating_duration_since(checkpoints.setup_started)
      .as_nanos(),
    timer_pair_median_ns: checkpoints.timer_pair_median_ns,
    rss_before: checkpoints.rss_before,
    rss_after_drain: checkpoints.rss_after_drain,
    rss_after_shutdown: checkpoints.rss_after_shutdown,
    producer,
    on_time: observer.on_time,
    late: observer.late,
    errors: observer.errors,
    digest: observer.digest,
    expected: observer.expected,
    p50_ns: percentile(&latencies, 50),
    p95_ns: percentile(&latencies, 95),
    p99_ns: percentile(&latencies, 99),
    max_observed_managed_bytes: observer.max_observed_managed_bytes,
    final_resources,
    shutdown_ns,
    last_observed,
    drain_tail_ns,
    async_workers: WORKERS,
    blocking_workers,
    topology,
  }
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

fn print_row(allocator: &str, options: Options, report: &Report) {
  let capacity_rate = if options.mode == Mode::Capacity {
    (report.on_time as f64 / CAPACITY_HORIZON.as_secs_f64()).to_string()
  } else {
    String::new()
  };
  let wall_ns = super::wall_through_drain_ns(
    report.producer.started_at,
    report.producer.production_end,
    report.last_observed,
  );
  let drained_rate =
    (report.on_time + report.late) as f64 / wall_ns.max(1) as f64 * 1_000_000_000.0;
  let values = [
    "2".to_owned(),
    allocator.to_owned(),
    options.executor.label().to_owned(),
    "http".to_owned(),
    options.mode.label().to_owned(),
    report.async_workers.to_string(),
    report.blocking_workers.to_string(),
    report.topology.to_owned(),
    WINDOW.to_string(),
    TASK_LIMIT.to_string(),
    "0".to_owned(),
    options
      .rate_per_second
      .map_or(String::new(), |rate| rate.to_string()),
    if options.mode == Mode::OpenLoop {
      report.producer.attempted.to_string()
    } else {
      String::new()
    },
    report.producer.attempted.to_string(),
    report.producer.admitted.to_string(),
    report.producer.rejected_full.to_string(),
    "0".to_owned(),
    report.on_time.to_string(),
    report.late.to_string(),
    report.errors.to_string(),
    "0".to_owned(),
    report
      .producer
      .admitted
      .saturating_sub(report.on_time + report.late + report.errors)
      .to_string(),
    report
      .producer
      .attempted
      .saturating_sub(report.on_time + report.late)
      .to_string(),
    report.digest.to_string(),
    report.expected.to_string(),
    capacity_rate,
    drained_rate.to_string(),
    report.setup_ns.to_string(),
    report.timer_pair_median_ns.to_string(),
    wall_ns.to_string(),
    report.drain_tail_ns.to_string(),
    report.p50_ns.to_string(),
    report.p95_ns.to_string(),
    report.p99_ns.to_string(),
    if report.producer.attempted == 0 {
      "0".to_owned()
    } else {
      (report.producer.lateness_sum_ns / report.producer.attempted as u128).to_string()
    },
    report.producer.lateness_max_ns.to_string(),
    report.max_observed_managed_bytes.to_string(),
    "0".to_owned(),
    limits().managed_memory.to_string(),
    "0".to_owned(),
    limits().network_concurrent_ops.to_string(),
    report.final_resources.managed_memory.to_string(),
    report.final_resources.disk_ops.to_string(),
    report.final_resources.network_ops.to_string(),
    report.rss_before.rss_kib.to_string(),
    report.rss_after_drain.rss_kib.to_string(),
    report.rss_after_shutdown.rss_kib.to_string(),
    report.rss_before.hwm_kib.to_string(),
    report.rss_after_drain.hwm_kib.to_string(),
    report.rss_after_shutdown.hwm_kib.to_string(),
    report.shutdown_ns.to_string(),
    report.producer.rejected_logical_window.to_string(),
    report.producer.rejected_backend_full.to_string(),
  ];
  debug_assert_eq!(values.len(), super::TSV_HEADER.split('\t').count());
  println!("{}", super::TSV_HEADER);
  println!("{}", values.join("\t"));
}

#[cfg(test)]
mod tests {
  use super::{
    ClientJob, Event, HandlerJob, HandlerRecord, Joiner, Mode, ProducerReport, RoleLease, Settings,
    expected_request_checksum, observe_events, run_bounded, run_tokio,
  };
  use crate::application::{Executor, Options, Workload};
  use allocatbelt::runtime::managed::ResourceScope;
  use std::sync::{Arc, mpsc};
  use std::time::Duration;
  use std::time::Instant;

  fn options(executor: Executor, mode: Mode, rate_per_second: Option<u64>) -> Options {
    Options {
      executor,
      workload: Workload::Http,
      mode,
      rate_per_second,
    }
  }

  fn settings(mode: Mode) -> Settings {
    Settings {
      horizon: Duration::from_millis(40),
      arrivals: if mode == Mode::OpenLoop { 32 } else { 64 },
      body_bytes: 256,
    }
  }

  #[test]
  fn allocatbelt_pairs_each_http_client_with_handler_and_cleans_ledgers() {
    let mode = Mode::OpenLoop;
    let report = run_bounded(options(Executor::Bounded, mode, Some(1000)), settings(mode))
      .expect("bounded HTTP pair lane should drain");
    assert_eq!(report.producer.attempted, 32);
    assert_eq!(report.producer.admitted, report.on_time + report.late);
    assert_eq!(report.errors, 0);
    assert_eq!(report.digest, report.expected);
    assert_eq!(report.final_resources.managed_memory, 0);
    assert_eq!(report.final_resources.network_ops, 0);
  }

  #[test]
  fn tokio_pairs_each_http_client_with_handler_and_cleans_ledgers() {
    let mode = Mode::Capacity;
    let report = run_tokio(options(Executor::Tokio, mode, None), settings(mode))
      .expect("Tokio HTTP pair lane should drain");
    assert_eq!(report.producer.rejected_full, 0);
    assert_eq!(report.producer.admitted, report.on_time + report.late);
    assert_eq!(report.errors, 0);
    assert_eq!(report.digest, report.expected);
    assert_eq!(report.final_resources.managed_memory, 0);
    assert_eq!(report.final_resources.network_ops, 0);
  }

  #[test]
  fn later_http_pair_is_observed_while_an_earlier_client_remains_pending() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
      .worker_threads(2)
      .enable_all()
      .build()
      .expect("test runtime");
    let handle = runtime.handle().clone();
    let (release_first, first_gate) = tokio::sync::oneshot::channel::<()>();
    let first_checksum = expected_request_checksum(0, 256);
    let second_checksum = expected_request_checksum(1, 256);
    let first_client = ClientJob::Tokio(handle.spawn(async move {
      first_gate
        .await
        .map_err(|_| "test gate closed".to_owned())?;
      Ok(first_checksum)
    }));
    let second_client = ClientJob::Tokio(handle.spawn(async move { Ok(second_checksum) }));
    let first_handler = HandlerJob::Tokio(handle.spawn(async move {
      (
        Ok((0, first_checksum)),
        RoleLease {
          _hold: Arc::new(()),
        },
      )
    }));
    let second_handler = HandlerJob::Tokio(handle.spawn(async move {
      (
        Ok((1, second_checksum)),
        RoleLease {
          _hold: Arc::new(()),
        },
      )
    }));
    let started = Instant::now();
    let horizon = started + Duration::from_secs(5);
    let (events_tx, events_rx) = mpsc::channel();
    let (credits_tx, credits_rx) = mpsc::sync_channel(8);
    events_tx
      .send(Event::Client {
        id: 0,
        scheduled: started,
        horizon_end: horizon,
        job: first_client,
      })
      .expect("first client event");
    events_tx
      .send(Event::Client {
        id: 1,
        scheduled: started,
        horizon_end: horizon,
        job: second_client,
      })
      .expect("second client event");
    events_tx
      .send(Event::Handler(HandlerRecord {
        id: 0,
        _lease: RoleLease {
          _hold: Arc::new(()),
        },
        job: first_handler,
      }))
      .expect("first handler event");
    events_tx
      .send(Event::Handler(HandlerRecord {
        id: 1,
        _lease: RoleLease {
          _hold: Arc::new(()),
        },
        job: second_handler,
      }))
      .expect("second handler event");
    events_tx
      .send(Event::Done(ProducerReport {
        attempted: 2,
        admitted: 2,
        rejected_full: 0,
        rejected_logical_window: 0,
        rejected_backend_full: 0,
        lateness_sum_ns: 0,
        lateness_max_ns: 0,
        started_at: started,
        production_end: Instant::now(),
        trace_overrun: false,
      }))
      .expect("producer completion event");
    drop(events_tx);

    let selected_options = options(Executor::Tokio, Mode::OpenLoop, Some(1000));
    let selected_settings = Settings {
      horizon: Duration::from_secs(1),
      arrivals: 2,
      body_bytes: 256,
    };
    let (report_tx, report_rx) = mpsc::sync_channel(1);
    let observer = std::thread::spawn(move || {
      let _ = report_tx.send(observe_events(
        Joiner::Tokio(handle),
        selected_options,
        selected_settings,
        ResourceScope::new(super::limits()),
        events_rx,
        credits_tx,
      ));
    });

    credits_rx
      .recv_timeout(Duration::from_secs(2))
      .expect("second pair should return a credit while pair zero is pending");
    release_first.send(()).expect("release first client");
    let report = report_rx
      .recv_timeout(Duration::from_secs(2))
      .expect("HTTP observer completion should arrive before the watchdog")
      .expect("all pairs should drain");
    observer.join().expect("observer thread should not panic");
    assert_eq!(report.on_time + report.late, 2);
    assert_eq!(report.errors, 0);
    assert_eq!(report.digest, first_checksum.wrapping_add(second_checksum));
    assert_eq!(report.digest, report.expected);
    assert_eq!(credits_rx.try_iter().count(), 1);
  }
}
