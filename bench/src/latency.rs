//! Allocation-churn and blocking/async-executor latency probes.
//!
//! Allocation samples time allocation, payload access and deallocation; they
//! are not raw allocator-call timings. Blocking samples run from the intended
//! arrival until an independent observer polls the public join future to Ready,
//! after result publication. Producer lateness remains in the latency sample
//! and is also reported separately. The throughput lane times
//! batches and does not collect per-operation times.

use std::collections::VecDeque;
use std::future::Future;
use std::hint::black_box;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use allocatbelt::runtime::{
  Config, Resources, Runtime, ShutdownMode,
  asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown},
};

const MAX_COUNT: usize = 1_000_000;
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(60);
const CSV_HEADER: &str = "allocator,lane,workload,mode,executor,workers,admission_window,arrival_rate,bytes,requested,attempted,completed,dropped,checksum,elapsed_ns,throughput_per_s,timer_overhead_ns,p50_ns,p95_ns,p99_ns,arrival_lateness_mean_ns,arrival_lateness_max_ns";
const EVENT_BATCH: usize = 64;
const ASYNC_YIELD_ROUNDS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
  Allocator,
  Blocking,
  Async,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Workload {
  Local,
  Aligned,
  Mixed,
  Ready,
  Yielding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
  Latency,
  Throughput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutorKind {
  Bounded,
  Tokio,
}

#[derive(Clone, Debug)]
struct Options {
  lane: Lane,
  workload: Workload,
  mode: Mode,
  executor: Option<ExecutorKind>,
  count: usize,
  workers: usize,
  arrival_rate: u64,
  bytes: usize,
  window: usize,
}

impl Options {
  fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
    let mut lane = None;
    let mut workload = Workload::Local;
    let mut workload_explicit = false;
    let mut mode = Mode::Latency;
    let mut executor = None;
    let mut count = None;
    let mut workers = 4usize;
    let mut arrival_rate = 10_000u64;
    let mut bytes = 256usize;
    let mut window = None;
    let mut workers_explicit = false;
    let mut arrival_rate_explicit = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
      let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value"));
      match arg.as_str() {
        "--lane" => {
          lane = Some(match value()?.as_str() {
            "allocator" => Lane::Allocator,
            "blocking" => Lane::Blocking,
            "async" => Lane::Async,
            other => {
              return Err(format!(
                "unknown lane {other:?} (allocator, blocking or async)"
              ));
            }
          })
        }
        "--workload" => {
          workload_explicit = true;
          workload = match value()?.as_str() {
            "local" => Workload::Local,
            "aligned" => Workload::Aligned,
            "mixed" => Workload::Mixed,
            "ready" => Workload::Ready,
            "yielding" => Workload::Yielding,
            other => {
              return Err(format!(
                "unknown workload {other:?} (local, aligned, mixed, ready or yielding)"
              ));
            }
          }
        }
        "--mode" => {
          mode = match value()?.as_str() {
            "latency" => Mode::Latency,
            "throughput" => Mode::Throughput,
            other => return Err(format!("unknown mode {other:?} (latency or throughput)")),
          }
        }
        "--executor" => {
          executor = Some(match value()?.as_str() {
            "bounded" => ExecutorKind::Bounded,
            "tokio" => ExecutorKind::Tokio,
            other => return Err(format!("unknown executor {other:?} (bounded or tokio)")),
          })
        }
        "--ops" | "--jobs" => count = Some(parse_usize(&arg, &value()?)?),
        "--workers" => {
          workers = parse_usize(&arg, &value()?)?;
          workers_explicit = true;
        }
        "--arrival-rate" => {
          arrival_rate = parse_u64(&arg, &value()?)?;
          arrival_rate_explicit = true;
        }
        "--bytes" => bytes = parse_usize(&arg, &value()?)?,
        "--window" => window = Some(parse_usize(&arg, &value()?)?),
        "-h" | "--help" => return Err(usage().to_owned()),
        _ => return Err(format!("unknown argument {arg:?}\n{}", usage())),
      }
    }
    let lane = lane.ok_or_else(|| format!("--lane is required\n{}", usage()))?;
    if lane == Lane::Async && !workload_explicit {
      workload = Workload::Ready;
    }
    let count = count.unwrap_or(if lane == Lane::Allocator {
      20_000
    } else {
      5_000
    });
    if count == 0 || count > MAX_COUNT {
      return Err(format!("operation count must be from 1 to {MAX_COUNT}"));
    }
    if workers == 0 || workers > 1024 {
      return Err("--workers must be from 1 to 1024".to_owned());
    }
    if lane != Lane::Allocator && workers > count {
      if workers_explicit {
        return Err("--workers cannot exceed --jobs".to_owned());
      }
      workers = count;
    }
    let requested_window = window;
    let window = window.unwrap_or_else(|| workers.saturating_mul(4).min(count));
    if window == 0 || window > count {
      return Err("--window must be from 1 to the requested job count".to_owned());
    }
    if arrival_rate == 0 {
      return Err("--arrival-rate must be at least 1".to_owned());
    }
    if bytes == 0 || bytes > 2 * 1024 * 1024 {
      return Err("--bytes must be from 1 to 2097152".to_owned());
    }
    match (lane, executor) {
      (Lane::Allocator, Some(_)) => {
        return Err("--executor applies only to --lane blocking".to_owned());
      }
      (Lane::Blocking | Lane::Async, None) => {
        return Err("--executor is required for --lane blocking or async".to_owned());
      }
      _ => {}
    }
    if lane == Lane::Blocking
      && count
        .checked_mul(bytes)
        .is_none_or(|n| n > 512 * 1024 * 1024)
    {
      return Err("--jobs times --bytes must fit within 512 MiB".to_owned());
    }
    if lane == Lane::Allocator && workers_explicit {
      return Err("--workers applies only to --lane blocking or async".to_owned());
    }
    if lane == Lane::Allocator && arrival_rate_explicit {
      return Err("--arrival-rate applies only to --lane blocking or async".to_owned());
    }
    if requested_window.is_some() && lane != Lane::Async {
      return Err("--window applies only to --lane async".to_owned());
    }
    if lane == Lane::Async && window < workers {
      return Err("async --window must be at least --workers to warm every worker".to_owned());
    }
    if lane == Lane::Blocking && workload != Workload::Local {
      return Err("blocking jobs currently support only --workload local".to_owned());
    }
    if lane == Lane::Allocator && matches!(workload, Workload::Ready | Workload::Yielding) {
      return Err("allocator lane workload must be local, aligned or mixed".to_owned());
    }
    if lane == Lane::Async && matches!(workload, Workload::Local | Workload::Aligned) {
      return Err("async lane workload must be ready, yielding or mixed".to_owned());
    }
    if lane == Lane::Async
      && workload == Workload::Mixed
      && window
        .checked_mul(bytes)
        .and_then(|n| n.checked_mul(8))
        .is_none_or(|n| n > 512 * 1024 * 1024)
    {
      return Err(
        "--window times --bytes times 8 must fit within 512 MiB for mixed async work".to_owned(),
      );
    }
    Ok(Self {
      lane,
      workload,
      mode,
      executor,
      count,
      workers,
      arrival_rate,
      bytes,
      window,
    })
  }
}

fn usage() -> &'static str {
  "usage: bench-latency-* --lane allocator|blocking|async [--workload local|aligned|mixed|ready|yielding] \\
   [--mode latency|throughput] [--executor bounded|tokio] [--ops N|--jobs N] \\
   [--workers N] [--arrival-rate JOBS_PER_SECOND] [--window N] [--bytes N]"
}

fn parse_u64(flag: &str, value: &str) -> Result<u64, String> {
  if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
    return Err(format!("{flag} needs a non-negative decimal integer"));
  }
  value.parse().map_err(|_| format!("{flag} is too large"))
}

fn parse_usize(flag: &str, value: &str) -> Result<usize, String> {
  usize::try_from(parse_u64(flag, value)?).map_err(|_| format!("{flag} is too large"))
}

fn timer_overhead_ns() -> u64 {
  let mut samples = Vec::with_capacity(2_001);
  for _ in 0..2_001 {
    let start = Instant::now();
    samples.push(start.elapsed().as_nanos().min(u64::MAX as u128) as u64);
  }
  samples.sort_unstable();
  samples[samples.len() / 2]
}

fn percentile(samples: &mut [u64], p: usize) -> Option<u64> {
  if samples.is_empty() {
    return None;
  }
  samples.sort_unstable();
  let rank = (samples.len() * p).div_ceil(100).max(1) - 1;
  Some(samples[rank])
}

fn number(v: Option<u64>) -> String {
  v.map_or_else(|| "NA".to_owned(), |n| n.to_string())
}

fn rate(count: usize, elapsed_ns: u64) -> f64 {
  if elapsed_ns == 0 {
    0.0
  } else {
    count as f64 * 1e9 / elapsed_ns as f64
  }
}

#[repr(align(256))]
struct Aligned256([u8; 256]);

#[repr(align(4096))]
struct Aligned4096([u8; 4096]);

fn allocation_work(workload: Workload, id: usize, bytes: usize) -> u64 {
  let n = match workload {
    Workload::Local => 64,
    Workload::Aligned => 0,
    Workload::Mixed => match id % 8 {
      0 => 16,
      1 => 128,
      2 => 512,
      3 => 4_096,
      4 => 32_768,
      5 => 65_536,
      6 => 262_144,
      _ => bytes,
    },
    Workload::Ready | Workload::Yielding => unreachable!("async-only workload in allocator lane"),
  };
  match workload {
    Workload::Aligned => {
      let a = Box::new(Aligned256([id as u8; 256]));
      let b = Box::new(Aligned4096([id.wrapping_add(1) as u8; 4096]));
      let value = u64::from(a.0[255]) + u64::from(b.0[4095]);
      black_box((&a, &b));
      value
    }
    _ => {
      let mut data = Vec::with_capacity(n);
      data.resize(n, id as u8);
      let value = u64::from(data[0]) + u64::from(data[n - 1]) + n as u64;
      black_box(&data);
      value
    }
  }
}

fn run_allocator(allocator: &str, o: &Options, overhead: u64) {
  let mut samples = if o.mode == Mode::Latency {
    vec![0; o.count]
  } else {
    Vec::new()
  };
  // Give each allocator the same initial cache/refill activity outside the
  // measured trace. Keep the sample storage reserved before this warm-up.
  for i in 0..o.count.min(1_000) {
    black_box(allocation_work(o.workload, i, o.bytes));
  }
  let mut checksum = 0u64;
  let start = Instant::now();
  if o.mode == Mode::Latency {
    for (i, sample) in samples.iter_mut().enumerate() {
      let before = Instant::now();
      checksum = checksum.wrapping_add(allocation_work(o.workload, i, o.bytes));
      *sample = before.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    }
  } else {
    for i in 0..o.count {
      checksum = checksum.wrapping_add(allocation_work(o.workload, i, o.bytes));
    }
  }
  let elapsed = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
  black_box(checksum);
  let expected = (0..o.count).fold(0u64, |sum, i| {
    let n = match o.workload {
      Workload::Local => 64,
      Workload::Aligned => 0,
      Workload::Mixed => match i % 8 {
        0 => 16,
        1 => 128,
        2 => 512,
        3 => 4_096,
        4 => 32_768,
        5 => 65_536,
        6 => 262_144,
        _ => o.bytes,
      },
      Workload::Ready | Workload::Yielding => unreachable!("async-only workload in allocator lane"),
    };
    let value = match o.workload {
      Workload::Aligned => u64::from(i as u8) + u64::from(i.wrapping_add(1) as u8),
      _ => u64::from(i as u8) * 2 + n as u64,
    };
    sum.wrapping_add(value)
  });
  assert_eq!(checksum, expected, "allocation trace checksum mismatch");
  let (p50, p95, p99) = if o.mode == Mode::Latency {
    (
      percentile(&mut samples, 50),
      percentile(&mut samples, 95),
      percentile(&mut samples, 99),
    )
  } else {
    (None, None, None)
  };
  println!("{CSV_HEADER}");
  println!(
    "{allocator},allocator,{},{},NA,1,NA,NA,{},{},{},{},{},0x{checksum:016x},{elapsed},{:.3},{overhead},{},{},{},0,0",
    workload_name(o.workload),
    mode_name(o.mode),
    o.bytes,
    o.count,
    o.count,
    o.count,
    0,
    rate(o.count, elapsed),
    number(p50),
    number(p95),
    number(p99)
  );
}

fn workload_name(w: Workload) -> &'static str {
  match w {
    Workload::Local => "local",
    Workload::Aligned => "aligned",
    Workload::Mixed => "mixed",
    Workload::Ready => "ready",
    Workload::Yielding => "yielding",
  }
}

fn mode_name(m: Mode) -> &'static str {
  match m {
    Mode::Latency => "latency",
    Mode::Throughput => "throughput",
  }
}

type Work = Box<dyn FnOnce() -> u64 + Send + 'static>;

enum Handle {
  Bounded(allocatbelt::runtime::Job<u64>),
  Tokio(tokio::task::JoinHandle<u64>),
  BoundedAsync(allocatbelt::runtime::asynchronous::AsyncJob<u64>),
  TokioAsync(tokio::task::JoinHandle<u64>),
}

impl Handle {
  fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, String>> {
    match self {
      Self::Bounded(job) => Pin::new(job)
        .poll(cx)
        .map(|result| result.map_err(|error| format!("bounded join: {error}"))),
      Self::Tokio(job) => Pin::new(job)
        .poll(cx)
        .map(|result| result.map_err(|error| format!("Tokio join: {error}"))),
      Self::BoundedAsync(job) => Pin::new(job)
        .poll(cx)
        .map(|result| result.map_err(|error| format!("bounded async join: {error}"))),
      Self::TokioAsync(job) => Pin::new(job)
        .poll(cx)
        .map(|result| result.map_err(|error| format!("Tokio async join: {error}"))),
    }
  }

  #[cfg(test)]
  fn is_finished(&self) -> bool {
    match self {
      Self::Bounded(job) => job.is_finished(),
      Self::Tokio(job) | Self::TokioAsync(job) => job.is_finished(),
      Self::BoundedAsync(job) => job.is_finished(),
    }
  }
}

enum ObserverEvent {
  Submitted(usize, Handle, Instant),
  Ready(usize),
  AsyncSubmitted(usize, Handle, Instant),
  SubmissionStats {
    attempted: usize,
    dropped: usize,
    lateness_sum: u128,
    lateness_max: u64,
  },
}

struct EventState {
  queue: VecDeque<ObserverEvent>,
  ready_queued: Vec<bool>,
  failure: Option<String>,
}

struct EventQueue {
  state: Mutex<EventState>,
  wake: Condvar,
  capacity: usize,
}

impl EventQueue {
  fn new(jobs: usize) -> Result<Arc<Self>, String> {
    let capacity = jobs
      .checked_mul(2)
      .and_then(|n| n.checked_add(1))
      .ok_or("observer event capacity overflows")?;
    let mut queue = VecDeque::new();
    queue
      .try_reserve_exact(capacity)
      .map_err(|error| format!("cannot reserve observer event queue: {error}"))?;
    Ok(Arc::new(Self {
      state: Mutex::new(EventState {
        queue,
        ready_queued: vec![false; jobs],
        failure: None,
      }),
      wake: Condvar::new(),
      capacity,
    }))
  }

  fn push(&self, event: ObserverEvent) -> Result<(), String> {
    let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
    if state.queue.len() == self.capacity {
      let message = "observer event queue exceeded its preallocated bound".to_owned();
      state.failure = Some(message.clone());
      self.wake.notify_one();
      return Err(message);
    }
    state.queue.push_back(event);
    self.wake.notify_one();
    Ok(())
  }

  fn ready(&self, id: usize) {
    let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
    if id >= state.ready_queued.len() || state.ready_queued[id] {
      return;
    }
    if state.queue.len() == self.capacity {
      state.failure = Some("observer event queue exceeded its preallocated bound".to_owned());
    } else {
      state.ready_queued[id] = true;
      state.queue.push_back(ObserverEvent::Ready(id));
    }
    self.wake.notify_one();
  }

  fn drain(&self, batch: &mut Vec<ObserverEvent>, timeout: Duration) -> Result<(), String> {
    batch.clear();
    let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(failure) = &state.failure {
      return Err(failure.clone());
    }
    if state.queue.is_empty() {
      let (next, waited) = self
        .wake
        .wait_timeout(state, timeout)
        .unwrap_or_else(PoisonError::into_inner);
      state = next;
      if state.queue.is_empty() && waited.timed_out() {
        return Ok(());
      }
    }
    if let Some(failure) = &state.failure {
      return Err(failure.clone());
    }
    for _ in 0..EVENT_BATCH.min(state.queue.len()) {
      if let Some(event) = state.queue.pop_front() {
        if let ObserverEvent::Ready(id) = &event
          && let Some(queued) = state.ready_queued.get_mut(*id)
        {
          *queued = false;
        }
        batch.push(event);
      }
    }
    Ok(())
  }
}

struct ReadyWake {
  id: usize,
  events: Arc<EventQueue>,
}

impl Wake for ReadyWake {
  fn wake(self: Arc<Self>) {
    self.events.ready(self.id);
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.events.ready(self.id);
  }
}

struct StartGate {
  base: Mutex<Option<Instant>>,
  wake: Condvar,
}

impl StartGate {
  fn wait(&self) -> Instant {
    let mut base = self.base.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
      if let Some(at) = *base {
        return at;
      }
      base = self.wake.wait(base).unwrap_or_else(PoisonError::into_inner);
    }
  }

  fn open(&self, at: Instant) {
    *self.base.lock().unwrap_or_else(PoisonError::into_inner) = Some(at);
    self.wake.notify_one();
  }
}

struct Executors {
  bounded: Option<Runtime>,
  tokio: Option<tokio::runtime::Runtime>,
  bytes: usize,
}

impl Drop for Executors {
  fn drop(&mut self) {
    // An observer error can drop the producer's finished return packet on
    // this thread. Preserve the bounded error path instead of letting
    // Tokio's ordinary runtime destructor wait for blocking jobs.
    if let Some(runtime) = self.tokio.take() {
      runtime.shutdown_background();
    }
  }
}

impl Executors {
  fn new(
    kind: ExecutorKind,
    jobs: usize,
    workers: usize,
    bytes: usize,
    keep_alive: Duration,
  ) -> Result<Self, String> {
    match kind {
      ExecutorKind::Bounded => {
        let memory = jobs
          .checked_mul(bytes)
          .ok_or("job memory budget overflows")?;
        let runtime = Runtime::new(Config {
          workers,
          max_outstanding: jobs,
          capacity: Resources {
            cpu: jobs,
            memory,
            disk: 0,
            network: 0,
          },
        })
        .map_err(|e| format!("bounded runtime: {e}"))?;
        Ok(Self {
          bounded: Some(runtime),
          tokio: None,
          bytes,
        })
      }
      ExecutorKind::Tokio => {
        let runtime = tokio::runtime::Builder::new_current_thread()
          .max_blocking_threads(workers)
          .thread_keep_alive(keep_alive)
          .thread_name("latency-tokio-blocking")
          .build()
          .map_err(|e| format!("Tokio runtime: {e}"))?;
        Ok(Self {
          bounded: None,
          tokio: Some(runtime),
          bytes,
        })
      }
    }
  }

  fn submit(&self, kind: ExecutorKind, work: Work) -> Result<Handle, String> {
    match kind {
      ExecutorKind::Bounded => self
        .bounded
        .as_ref()
        .ok_or("bounded executor missing")?
        .try_spawn(
          Resources {
            cpu: 1,
            memory: self.bytes,
            disk: 0,
            network: 0,
          },
          move |_| work(),
        )
        .map(Handle::Bounded)
        .map_err(|e| format!("bounded submit: {e}")),
      ExecutorKind::Tokio => Ok(Handle::Tokio(
        self
          .tokio
          .as_ref()
          .ok_or("Tokio executor missing")?
          .spawn_blocking(work),
      )),
    }
  }

  fn join(&self, handle: Handle) -> Result<u64, String> {
    match handle {
      Handle::Bounded(h) => h.join().map_err(|e| format!("bounded join: {e}")),
      Handle::Tokio(h) => self
        .tokio
        .as_ref()
        .ok_or("Tokio executor missing")?
        .block_on(h)
        .map_err(|e| format!("Tokio join: {e}")),
      Handle::BoundedAsync(_) | Handle::TokioAsync(_) => {
        Err("async join passed to blocking executor".to_owned())
      }
    }
  }

  fn shutdown(&mut self) -> Result<(), String> {
    if let Some(runtime) = self.bounded.as_mut() {
      runtime
        .shutdown(ShutdownMode::Drain)
        .map_err(|e| format!("bounded shutdown: {e}"))?;
    }
    if let Some(runtime) = self.tokio.take() {
      runtime.shutdown_background();
    }
    Ok(())
  }
}

type AsyncWork = Pin<Box<dyn Future<Output = u64> + Send + 'static>>;

struct AsyncExecutors {
  bounded: Option<AsyncRuntime>,
  tokio: Option<tokio::runtime::Runtime>,
}

impl Drop for AsyncExecutors {
  fn drop(&mut self) {
    if let Some(runtime) = self.tokio.take() {
      runtime.shutdown_background();
    }
  }
}

impl AsyncExecutors {
  fn new(kind: ExecutorKind, workers: usize, window: usize) -> Result<Self, String> {
    match kind {
      ExecutorKind::Bounded => Ok(Self {
        bounded: Some(
          AsyncRuntime::new(AsyncConfig {
            workers,
            max_outstanding: window,
            max_scopes: 1,
          })
          .map_err(|e| format!("bounded async runtime: {e}"))?,
        ),
        tokio: None,
      }),
      ExecutorKind::Tokio => Ok(Self {
        bounded: None,
        tokio: Some(
          tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .thread_name("latency-tokio-async")
            .build()
            .map_err(|e| format!("Tokio async runtime: {e}"))?,
        ),
      }),
    }
  }

  fn submit(&self, kind: ExecutorKind, future: AsyncWork) -> Result<Handle, String> {
    match kind {
      ExecutorKind::Bounded => self
        .bounded
        .as_ref()
        .ok_or("bounded async executor missing")?
        .handle()
        .spawn(future)
        .map(Handle::BoundedAsync)
        .map_err(|error| format!("bounded async submit: {}", error.kind)),
      ExecutorKind::Tokio => Ok(Handle::TokioAsync(
        self
          .tokio
          .as_ref()
          .ok_or("Tokio async executor missing")?
          .spawn(future),
      )),
    }
  }

  fn join(&self, handle: Handle) -> Result<u64, String> {
    match handle {
      Handle::BoundedAsync(job) => self
        .bounded
        .as_ref()
        .ok_or("bounded async executor missing")?
        .block_on(job)
        .map_err(|error| format!("bounded async block_on: {error}"))?
        .map_err(|error| format!("bounded async join: {error}")),
      Handle::TokioAsync(job) => self
        .tokio
        .as_ref()
        .ok_or("Tokio async executor missing")?
        .block_on(job)
        .map_err(|error| format!("Tokio async join: {error}")),
      Handle::Bounded(_) | Handle::Tokio(_) => {
        Err("blocking join passed to async executor".to_owned())
      }
    }
  }

  fn shutdown(&mut self) -> Result<(), String> {
    if let Some(runtime) = self.bounded.take() {
      runtime
        .shutdown(AsyncShutdown::Drain)
        .map_err(|e| format!("bounded async shutdown: {e}"))?;
    }
    if let Some(runtime) = self.tokio.take() {
      runtime.shutdown_background();
    }
    Ok(())
  }
}

struct YieldOnce(bool);

impl Future for YieldOnce {
  type Output = ();

  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    if self.0 {
      Poll::Ready(())
    } else {
      self.0 = true;
      cx.waker().wake_by_ref();
      Poll::Pending
    }
  }
}

async fn async_work(id: usize, workload: Workload, bytes: usize) -> u64 {
  let mut checksum = id as u64;
  match workload {
    Workload::Ready => checksum = checksum.wrapping_add(1),
    Workload::Yielding => {
      for turn in 1..=ASYNC_YIELD_ROUNDS {
        checksum = checksum.wrapping_add(turn as u64);
        YieldOnce(false).await;
      }
    }
    Workload::Mixed => {
      let mut chunks = Vec::with_capacity(8);
      for chunk in 0..ASYNC_YIELD_ROUNDS {
        let byte = id.wrapping_add(chunk) as u8;
        let mut payload = Vec::with_capacity(bytes);
        payload.resize(bytes, byte);
        checksum = payload
          .iter()
          .fold(checksum, |sum, value| sum.wrapping_add(u64::from(*value)));
        black_box(&payload);
        chunks.push(payload);
        YieldOnce(false).await;
      }
      black_box(&chunks);
    }
    Workload::Local | Workload::Aligned => unreachable!("allocator-only workload in async lane"),
  }
  checksum
}

fn expected_async_checksum(id: usize, workload: Workload, bytes: usize) -> u64 {
  match workload {
    Workload::Ready => (id as u64).wrapping_add(1),
    Workload::Yielding => (id as u64).wrapping_add((1..=ASYNC_YIELD_ROUNDS).sum::<usize>() as u64),
    Workload::Mixed => (0..ASYNC_YIELD_ROUNDS).fold(id as u64, |sum, chunk| {
      sum.wrapping_add((id.wrapping_add(chunk) as u8 as u64).wrapping_mul(bytes as u64))
    }),
    Workload::Local | Workload::Aligned => unreachable!("allocator-only workload in async lane"),
  }
}

fn warm_async_workers(
  executors: &AsyncExecutors,
  kind: ExecutorKind,
  workers: usize,
) -> Result<(), String> {
  type WarmGate = Arc<(Mutex<bool>, Condvar)>;
  struct WarmRelease(WarmGate);
  impl Drop for WarmRelease {
    fn drop(&mut self) {
      *self.0.0.lock().unwrap_or_else(PoisonError::into_inner) = true;
      self.0.1.notify_all();
    }
  }
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let release = WarmRelease(Arc::clone(&gate));
  let (arrived_tx, arrived_rx) = mpsc::sync_channel(workers);
  let mut handles = Vec::with_capacity(workers);
  let mut failure = None;
  for _ in 0..workers {
    let gate = Arc::clone(&gate);
    let arrived = arrived_tx.clone();
    match executors.submit(
      kind,
      Box::pin(async move {
        let _ = arrived.send(());
        let mut open = gate.0.lock().unwrap_or_else(PoisonError::into_inner);
        while !*open {
          open = gate.1.wait(open).unwrap_or_else(PoisonError::into_inner);
        }
        drop(open);
        0xa5
      }),
    ) {
      Ok(handle) => handles.push(handle),
      Err(error) => {
        failure = Some(error);
        break;
      }
    }
  }
  drop(arrived_tx);
  if failure.is_none() {
    for _ in 0..workers {
      if let Err(error) = arrived_rx.recv_timeout(COMPLETION_TIMEOUT) {
        failure = Some(format!("async worker warmup arrival: {error}"));
        break;
      }
    }
  }
  drop(release);
  for handle in handles {
    match executors.join(handle) {
      Ok(0xa5) => {}
      Ok(_) if failure.is_none() => {
        failure = Some("async worker warmup checksum mismatch".to_owned())
      }
      Err(error) if failure.is_none() => failure = Some(error),
      Ok(_) | Err(_) => {}
    }
  }
  failure.map_or(Ok(()), Err)
}

fn intended_offset_ns(index: usize, rate: u64) -> u64 {
  ((index as u128 * 1_000_000_000u128) / u128::from(rate)).min(u64::MAX as u128) as u64
}

fn poll_observed(
  id: usize,
  slots: &mut [Option<(Handle, Instant)>],
  wakers: &[Waker],
  samples: &mut Vec<u64>,
  checksum: &mut u64,
  completed: &mut usize,
  bytes: usize,
) -> Result<(), String> {
  let Some(Some((handle, intended_at))) = slots.get_mut(id) else {
    return Ok(());
  };
  let mut cx = Context::from_waker(&wakers[id]);
  if let Poll::Ready(result) = handle.poll(&mut cx) {
    // This timestamp follows the public join future's Ready result, after
    // the runtime has published the outcome for an observer to consume.
    let observed_at = (samples.capacity() > 0).then(Instant::now);
    let sum = result?;
    let expected = (id as u64).wrapping_add((id as u8 as u64).wrapping_mul(bytes as u64));
    if sum != expected {
      return Err(format!("job {id} checksum {sum} did not match {expected}"));
    }
    if let Some(observed_at) = observed_at {
      samples.push(
        observed_at
          .saturating_duration_since(*intended_at)
          .as_nanos()
          .min(u64::MAX as u128) as u64,
      );
    }
    *checksum = checksum.wrapping_add(sum);
    *completed += 1;
    slots[id] = None;
  }
  Ok(())
}

struct AsyncObserver<'a> {
  slots: &'a mut [Option<(Handle, Instant)>],
  wakers: &'a [Waker],
  samples: &'a mut Vec<u64>,
  checksum: &'a mut u64,
  completed: &'a mut usize,
  workload: Workload,
  bytes: usize,
  in_flight: &'a AtomicUsize,
}

impl AsyncObserver<'_> {
  fn poll(&mut self, id: usize) -> Result<(), String> {
    let Some(Some((handle, intended_at))) = self.slots.get_mut(id) else {
      return Ok(());
    };
    let mut cx = Context::from_waker(&self.wakers[id]);
    if let Poll::Ready(result) = handle.poll(&mut cx) {
      let observed_at = (self.samples.capacity() > 0).then(Instant::now);
      let intended_at = *intended_at;
      self.slots[id] = None;
      let previous = self.in_flight.fetch_sub(1, Ordering::AcqRel);
      if previous == 0 {
        return Err("async admission window accounting underflow".to_owned());
      }
      let sum = result?;
      let expected = expected_async_checksum(id, self.workload, self.bytes);
      if sum != expected {
        return Err(format!(
          "async job {id} checksum {sum} did not match {expected}"
        ));
      }
      if let Some(observed_at) = observed_at {
        self.samples.push(
          observed_at
            .saturating_duration_since(intended_at)
            .as_nanos()
            .min(u64::MAX as u128) as u64,
        );
      }
      *self.checksum = self.checksum.wrapping_add(sum);
      *self.completed += 1;
    }
    Ok(())
  }
}

fn try_acquire_window(in_flight: &AtomicUsize, window: usize) -> bool {
  let mut current = in_flight.load(Ordering::Acquire);
  loop {
    if current >= window {
      return false;
    }
    match in_flight.compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
    {
      Ok(_) => return true,
      Err(observed) => current = observed,
    }
  }
}

fn run_blocking(allocator: &str, o: &Options, overhead: u64) -> Result<(), String> {
  let kind = o.executor.ok_or("blocking lane requires an executor")?;
  let trace_span = Duration::from_nanos(intended_offset_ns(o.count, o.arrival_rate));
  let keep_alive = trace_span
    .saturating_add(COMPLETION_TIMEOUT)
    .saturating_add(Duration::from_secs(1));
  let executors = Executors::new(kind, o.count, o.workers, o.bytes, keep_alive)?;
  warm_workers(&executors, kind, o.workers, o.bytes)?;
  let mut samples = if o.mode == Mode::Latency {
    Vec::with_capacity(o.count)
  } else {
    Vec::new()
  };
  let events = EventQueue::new(o.count)?;
  let mut slots: Vec<Option<(Handle, Instant)>> =
    std::iter::repeat_with(|| None).take(o.count).collect();
  let mut wakers = Vec::with_capacity(o.count);
  for id in 0..o.count {
    wakers.push(Waker::from(Arc::new(ReadyWake {
      id,
      events: Arc::clone(&events),
    })));
  }
  let mut batch = Vec::with_capacity(EVENT_BATCH);
  let start_gate = Arc::new(StartGate {
    base: Mutex::new(None),
    wake: Condvar::new(),
  });
  let producer_gate = Arc::clone(&start_gate);
  let producer_events = Arc::clone(&events);
  let (ready_tx, ready_rx) = mpsc::sync_channel::<()>(1);
  let count = o.count;
  let arrival_rate = o.arrival_rate;
  let bytes = o.bytes;
  let producer = std::thread::spawn(move || {
    let _ = ready_tx.send(());
    let base = producer_gate.wait();
    let mut attempted = 0usize;
    let mut dropped = 0usize;
    let mut lateness_sum = 0u128;
    let mut lateness_max = 0u64;
    for id in 0..count {
      let offset = intended_offset_ns(id, arrival_rate);
      let target = base + Duration::from_nanos(offset);
      if let Some(left) = target.checked_duration_since(Instant::now()) {
        std::thread::sleep(left);
      }
      attempted += 1;
      let work: Work = Box::new(move || {
        let mut payload = Vec::with_capacity(bytes);
        payload.resize(bytes, id as u8);
        let sum = payload
          .iter()
          .fold(id as u64, |sum, b| sum.wrapping_add(u64::from(*b)));
        black_box(&payload);
        sum
      });
      // Keep the intended arrival even when the producer runs late. Starting
      // at actual submission would hide generator delays from tail latency.
      let late = Instant::now()
        .saturating_duration_since(target)
        .as_nanos()
        .min(u64::MAX as u128) as u64;
      lateness_sum = lateness_sum.saturating_add(u128::from(late));
      lateness_max = lateness_max.max(late);
      match executors.submit(kind, work) {
        Ok(handle) => {
          if producer_events
            .push(ObserverEvent::Submitted(id, handle, target))
            .is_err()
          {
            break;
          }
        }
        Err(_) => {
          dropped += 1;
        }
      }
    }
    let _ = producer_events.push(ObserverEvent::SubmissionStats {
      attempted,
      dropped,
      lateness_sum,
      lateness_max,
    });
    // The thread's return packet owns both executors until the observer has
    // consumed every public join. Shutting Tokio down here would cancel
    // accepted jobs that are still queued behind the final submission.
    executors
  });
  if let Err(error) = ready_rx.recv_timeout(COMPLETION_TIMEOUT) {
    start_gate.open(Instant::now());
    let _ = producer.join();
    return Err(format!("submission producer startup: {error}"));
  }
  let base = Instant::now();
  start_gate.open(base);

  let mut completed = 0usize;
  let mut checksum = 0u64;
  let mut accepted = 0usize;
  let mut submission_stats = None;
  let deadline = base + trace_span + COMPLETION_TIMEOUT;
  while submission_stats.is_none() || completed < accepted {
    let now = Instant::now();
    if now >= deadline {
      return Err(format!(
        "completion observer timed out after {completed} of {accepted} results"
      ));
    }
    events.drain(&mut batch, deadline.saturating_duration_since(now))?;
    for event in batch.drain(..) {
      match event {
        ObserverEvent::Submitted(id, handle, intended_at) => {
          if id >= slots.len() || slots[id].is_some() {
            return Err(format!("duplicate or invalid submitted job id {id}"));
          }
          slots[id] = Some((handle, intended_at));
          accepted += 1;
          poll_observed(
            id,
            &mut slots,
            &wakers,
            &mut samples,
            &mut checksum,
            &mut completed,
            o.bytes,
          )?;
        }
        ObserverEvent::AsyncSubmitted(..) => {
          return Err("async result entered the blocking observer".to_owned());
        }
        ObserverEvent::Ready(id) => {
          poll_observed(
            id,
            &mut slots,
            &wakers,
            &mut samples,
            &mut checksum,
            &mut completed,
            o.bytes,
          )?;
        }
        ObserverEvent::SubmissionStats {
          attempted,
          dropped,
          lateness_sum,
          lateness_max,
        } => {
          if submission_stats.is_some() {
            return Err("duplicate producer statistics event".to_owned());
          }
          submission_stats = Some((attempted, dropped, lateness_sum, lateness_max));
        }
      }
    }
  }
  let (attempted, dropped, lateness_sum, lateness_max) =
    submission_stats.ok_or("submission statistics missing")?;
  let elapsed = base.elapsed().as_nanos().min(u64::MAX as u128) as u64;
  let mut executors = producer
    .join()
    .map_err(|_| "submission producer panicked")?;
  executors.shutdown()?;
  if attempted != o.count {
    return Err(format!(
      "producer attempted {attempted} of {} jobs",
      o.count
    ));
  }
  if completed != accepted {
    return Err(format!("observed {completed} of {accepted} admitted jobs"));
  }
  let (p50, p95, p99) = if o.mode == Mode::Latency {
    (
      percentile(&mut samples, 50),
      percentile(&mut samples, 95),
      percentile(&mut samples, 99),
    )
  } else {
    (None, None, None)
  };
  let kind_name = match kind {
    ExecutorKind::Bounded => "bounded",
    ExecutorKind::Tokio => "tokio",
  };
  println!("{CSV_HEADER}");
  println!(
    "{allocator},blocking,{},{},{kind_name},{},{},{},{},{},{attempted},{completed},{dropped},0x{checksum:016x},{elapsed},{:.3},{overhead},{},{},{},{:.0},{lateness_max}",
    workload_name(o.workload),
    mode_name(o.mode),
    o.workers,
    o.count,
    o.arrival_rate,
    o.bytes,
    o.count,
    rate(accepted, elapsed),
    number(p50),
    number(p95),
    number(p99),
    if attempted == 0 {
      0.0
    } else {
      lateness_sum as f64 / attempted as f64
    }
  );
  Ok(())
}

fn run_async(allocator: &str, o: &Options, overhead: u64) -> Result<(), String> {
  let kind = o.executor.ok_or("async lane requires an executor")?;
  let trace_span = Duration::from_nanos(intended_offset_ns(o.count, o.arrival_rate));
  let executors = AsyncExecutors::new(kind, o.workers, o.window)?;
  warm_async_workers(&executors, kind, o.workers)?;
  let mut samples = if o.mode == Mode::Latency {
    Vec::with_capacity(o.count)
  } else {
    Vec::new()
  };
  let events = EventQueue::new(o.count)?;
  let mut slots: Vec<Option<(Handle, Instant)>> =
    std::iter::repeat_with(|| None).take(o.count).collect();
  let mut wakers = Vec::with_capacity(o.count);
  for id in 0..o.count {
    wakers.push(Waker::from(Arc::new(ReadyWake {
      id,
      events: Arc::clone(&events),
    })));
  }
  let mut batch = Vec::with_capacity(EVENT_BATCH);
  let start_gate = Arc::new(StartGate {
    base: Mutex::new(None),
    wake: Condvar::new(),
  });
  let producer_gate = Arc::clone(&start_gate);
  let producer_events = Arc::clone(&events);
  let in_flight = Arc::new(AtomicUsize::new(0));
  let producer_in_flight = Arc::clone(&in_flight);
  let (ready_tx, ready_rx) = mpsc::sync_channel::<()>(1);
  let count = o.count;
  let arrival_rate = o.arrival_rate;
  let workload = o.workload;
  let bytes = o.bytes;
  let window = o.window;
  let producer = std::thread::spawn(move || {
    let _ = ready_tx.send(());
    let base = producer_gate.wait();
    let mut attempted = 0usize;
    let mut dropped = 0usize;
    let mut lateness_sum = 0u128;
    let mut lateness_max = 0u64;
    for id in 0..count {
      let target = base + Duration::from_nanos(intended_offset_ns(id, arrival_rate));
      if let Some(left) = target.checked_duration_since(Instant::now()) {
        std::thread::sleep(left);
      }
      attempted += 1;
      let late = Instant::now()
        .saturating_duration_since(target)
        .as_nanos()
        .min(u64::MAX as u128) as u64;
      lateness_sum = lateness_sum.saturating_add(u128::from(late));
      lateness_max = lateness_max.max(late);
      if !try_acquire_window(&producer_in_flight, window) {
        dropped += 1;
        continue;
      }
      let future: AsyncWork = Box::pin(async_work(id, workload, bytes));
      match executors.submit(kind, future) {
        Ok(handle) => {
          if producer_events
            .push(ObserverEvent::AsyncSubmitted(id, handle, target))
            .is_err()
          {
            producer_in_flight.fetch_sub(1, Ordering::AcqRel);
            break;
          }
        }
        Err(_) => {
          producer_in_flight.fetch_sub(1, Ordering::AcqRel);
          dropped += 1;
        }
      }
    }
    let _ = producer_events.push(ObserverEvent::SubmissionStats {
      attempted,
      dropped,
      lateness_sum,
      lateness_max,
    });
    executors
  });
  if let Err(error) = ready_rx.recv_timeout(COMPLETION_TIMEOUT) {
    start_gate.open(Instant::now());
    let _ = producer.join();
    return Err(format!("async submission producer startup: {error}"));
  }
  let base = Instant::now();
  start_gate.open(base);

  let mut completed = 0usize;
  let mut checksum = 0u64;
  let mut accepted = 0usize;
  let mut submission_stats = None;
  let mut observer = AsyncObserver {
    slots: &mut slots,
    wakers: &wakers,
    samples: &mut samples,
    checksum: &mut checksum,
    completed: &mut completed,
    workload: o.workload,
    bytes: o.bytes,
    in_flight: &in_flight,
  };
  let deadline = base + trace_span + COMPLETION_TIMEOUT;
  while submission_stats.is_none() || *observer.completed < accepted {
    let now = Instant::now();
    if now >= deadline {
      return Err(format!(
        "async completion observer timed out after {} of {accepted} results",
        observer.completed
      ));
    }
    events.drain(&mut batch, deadline.saturating_duration_since(now))?;
    for event in batch.drain(..) {
      match event {
        ObserverEvent::AsyncSubmitted(id, handle, intended_at) => {
          if id >= observer.slots.len() || observer.slots[id].is_some() {
            return Err(format!("duplicate or invalid async job id {id}"));
          }
          observer.slots[id] = Some((handle, intended_at));
          accepted += 1;
          observer.poll(id)?;
        }
        ObserverEvent::Ready(id) => {
          observer.poll(id)?;
        }
        ObserverEvent::SubmissionStats {
          attempted,
          dropped,
          lateness_sum,
          lateness_max,
        } => {
          if submission_stats.is_some() {
            return Err("duplicate async producer statistics event".to_owned());
          }
          submission_stats = Some((attempted, dropped, lateness_sum, lateness_max));
        }
        ObserverEvent::Submitted(..) => {
          return Err("blocking result entered the async observer".to_owned());
        }
      }
    }
  }
  let (attempted, dropped, lateness_sum, lateness_max) =
    submission_stats.ok_or("async submission statistics missing")?;
  let elapsed = base.elapsed().as_nanos().min(u64::MAX as u128) as u64;
  let mut executors = producer
    .join()
    .map_err(|_| "async submission producer panicked")?;
  executors.shutdown()?;
  if attempted != o.count {
    return Err(format!(
      "async producer attempted {attempted} of {} jobs",
      o.count
    ));
  }
  if *observer.completed != accepted {
    return Err(format!(
      "observed {} of {accepted} async jobs",
      observer.completed
    ));
  }
  let completed = *observer.completed;
  let checksum = *observer.checksum;
  let (p50, p95, p99) = if o.mode == Mode::Latency {
    (
      percentile(observer.samples, 50),
      percentile(observer.samples, 95),
      percentile(observer.samples, 99),
    )
  } else {
    (None, None, None)
  };
  let kind_name = match kind {
    ExecutorKind::Bounded => "bounded-async",
    ExecutorKind::Tokio => "tokio-async",
  };
  println!("{CSV_HEADER}");
  println!(
    "{allocator},async,{},{},{kind_name},{},{},{},{},{},{attempted},{completed},{dropped},0x{checksum:016x},{elapsed},{:.3},{overhead},{},{},{},{:.0},{lateness_max}",
    workload_name(workload),
    mode_name(o.mode),
    o.workers,
    o.window,
    o.arrival_rate,
    o.bytes,
    o.count,
    rate(accepted, elapsed),
    number(p50),
    number(p95),
    number(p99),
    if attempted == 0 {
      0.0
    } else {
      lateness_sum as f64 / attempted as f64
    }
  );
  Ok(())
}

// Hold all warm jobs simultaneously. Quick jobs alone could run on just one
// lazily created Tokio worker, leaving startup/faults in the measured lane.
fn warm_workers(
  executors: &Executors,
  kind: ExecutorKind,
  workers: usize,
  bytes: usize,
) -> Result<(), String> {
  struct Release(Arc<(Mutex<bool>, Condvar)>);
  impl Drop for Release {
    fn drop(&mut self) {
      *self.0.0.lock().unwrap_or_else(PoisonError::into_inner) = true;
      self.0.1.notify_all();
    }
  }
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let release = Release(Arc::clone(&gate));
  let (arrived_tx, arrived_rx) = mpsc::sync_channel(workers);
  let mut handles = Vec::with_capacity(workers);
  for _ in 0..workers {
    let gate = Arc::clone(&gate);
    let arrived = arrived_tx.clone();
    handles.push(executors.submit(
      kind,
      Box::new(move || {
        let payload = vec![0xa5u8; bytes];
        let checksum = payload.iter().map(|&b| u64::from(b)).sum();
        let _ = arrived.send(());
        let mut open = gate.0.lock().unwrap_or_else(PoisonError::into_inner);
        while !*open {
          open = gate.1.wait(open).unwrap_or_else(PoisonError::into_inner);
        }
        drop(open);
        black_box(&payload);
        checksum
      }),
    )?);
  }
  drop(arrived_tx);
  for _ in 0..workers {
    arrived_rx
      .recv_timeout(COMPLETION_TIMEOUT)
      .map_err(|e| format!("worker warmup arrival: {e}"))?;
  }
  drop(release);
  for handle in handles {
    let checksum = executors.join(handle)?;
    if checksum != 0xa5 * bytes as u64 {
      return Err("worker warmup checksum mismatch".to_owned());
    }
  }
  Ok(())
}

pub fn main(allocator: &str) -> ExitCode {
  let options = match Options::parse(std::env::args().skip(1)) {
    Ok(value) => value,
    Err(error) => {
      eprintln!("{error}");
      return ExitCode::from(2);
    }
  };
  let overhead = timer_overhead_ns();
  let result = match options.lane {
    Lane::Allocator => {
      run_allocator(allocator, &options, overhead);
      Ok(())
    }
    Lane::Blocking => run_blocking(allocator, &options, overhead),
    Lane::Async => run_async(allocator, &options, overhead),
  };
  match result {
    Ok(()) => ExitCode::SUCCESS,
    Err(error) => {
      eprintln!("bench-latency: {error}");
      ExitCode::FAILURE
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn args(values: &[&str]) -> Result<Options, String> {
    Options::parse(values.iter().map(|s| (*s).to_owned()))
  }

  #[test]
  fn parser_requires_unambiguous_lane_and_executor() {
    assert!(args(&[]).is_err());
    assert!(args(&["--lane", "blocking"]).is_err());
    assert!(args(&["--lane", "allocator", "--executor", "tokio"]).is_err());
    assert!(args(&["--lane", "allocator", "--ops", "2"]).is_ok());
    assert!(args(&["--lane", "blocking", "--executor", "bounded", "--jobs", "2"]).is_ok());
    let async_options = args(&["--lane", "async", "--executor", "tokio", "--jobs", "2"]).unwrap();
    assert_eq!(async_options.workload, Workload::Ready);
    assert_eq!(async_options.window, 2);
    assert_eq!(
      args(&[
        "--lane",
        "async",
        "--executor",
        "bounded",
        "--jobs",
        "2",
        "--workload",
        "yielding"
      ])
      .unwrap()
      .workload,
      Workload::Yielding
    );
  }

  #[test]
  fn parser_rejects_invalid_measurement_bounds() {
    for values in [
      vec!["--lane", "allocator", "--ops", "0"],
      vec!["--lane", "allocator", "--workers", "0"],
      vec![
        "--lane",
        "blocking",
        "--executor",
        "tokio",
        "--arrival-rate",
        "0",
      ],
      vec![
        "--lane",
        "blocking",
        "--executor",
        "tokio",
        "--jobs",
        "2",
        "--workload",
        "aligned",
      ],
      vec!["--lane", "allocator", "--workers", "2"],
      vec!["--lane", "allocator", "--bytes", "2097153"],
      vec!["--lane", "async", "--executor", "tokio", "--window", "0"],
      vec![
        "--lane",
        "async",
        "--executor",
        "tokio",
        "--jobs",
        "2",
        "--window",
        "3",
      ],
      vec![
        "--lane",
        "async",
        "--executor",
        "tokio",
        "--jobs",
        "2",
        "--window",
        "1",
      ],
      vec![
        "--lane",
        "async",
        "--executor",
        "tokio",
        "--workload",
        "local",
      ],
      vec!["--lane", "allocator", "--workload", "ready"],
      vec!["--lane", "blocking", "--executor", "tokio", "--window", "2"],
    ] {
      assert!(args(&values).is_err());
    }
  }

  #[test]
  fn async_admission_window_rejects_at_capacity_and_reopens_after_completion() {
    let in_flight = AtomicUsize::new(0);
    assert!(try_acquire_window(&in_flight, 2));
    assert!(try_acquire_window(&in_flight, 2));
    assert!(!try_acquire_window(&in_flight, 2));
    assert_eq!(in_flight.load(Ordering::Acquire), 2);
    in_flight.fetch_sub(1, Ordering::AcqRel);
    assert!(try_acquire_window(&in_flight, 2));
    assert_eq!(in_flight.load(Ordering::Acquire), 2);
  }

  #[test]
  fn async_worker_warmup_releases_submitted_tasks_after_partial_failure() {
    let executors = AsyncExecutors::new(ExecutorKind::Bounded, 2, 1).unwrap();
    assert!(warm_async_workers(&executors, ExecutorKind::Bounded, 2).is_err());
    let mut executors = executors;
    executors.shutdown().unwrap();
  }

  #[test]
  fn async_observer_ignores_empty_slots_and_cleans_failed_terminal_joins() {
    let empty_in_flight = AtomicUsize::new(0);
    let mut empty_slots = [];
    let empty_wakers = [];
    let mut empty_samples = Vec::new();
    let mut empty_checksum = 0;
    let mut empty_completed = 0;
    AsyncObserver {
      slots: &mut empty_slots,
      wakers: &empty_wakers,
      samples: &mut empty_samples,
      checksum: &mut empty_checksum,
      completed: &mut empty_completed,
      workload: Workload::Ready,
      bytes: 1,
      in_flight: &empty_in_flight,
    }
    .poll(0)
    .unwrap();
    assert_eq!(empty_in_flight.load(Ordering::Acquire), 0);
    assert_eq!(empty_completed, 0);

    for kind in [ExecutorKind::Bounded, ExecutorKind::Tokio] {
      let executors = AsyncExecutors::new(kind, 1, 1).unwrap();
      let handle = executors
        .submit(
          kind,
          Box::pin(async { panic!("benchmark error-path fixture") }),
        )
        .unwrap();
      let deadline = Instant::now() + Duration::from_secs(5);
      while !handle.is_finished() {
        assert!(Instant::now() < deadline, "async panic did not finish");
        std::thread::yield_now();
      }

      let events = EventQueue::new(1).unwrap();
      let wakers = [Waker::from(Arc::new(ReadyWake { id: 0, events }))];
      let in_flight = AtomicUsize::new(1);
      let mut slots = [Some((handle, Instant::now()))];
      let mut samples = Vec::new();
      let mut checksum = 0;
      let mut completed = 0;
      let result = AsyncObserver {
        slots: &mut slots,
        wakers: &wakers,
        samples: &mut samples,
        checksum: &mut checksum,
        completed: &mut completed,
        workload: Workload::Ready,
        bytes: 1,
        in_flight: &in_flight,
      }
      .poll(0);
      assert!(result.is_err());
      assert!(slots[0].is_none());
      assert_eq!(in_flight.load(Ordering::Acquire), 0);
      assert_eq!(completed, 0);
      let mut executors = executors;
      executors.shutdown().unwrap();
    }
  }

  #[test]
  fn percentiles_use_nearest_rank() {
    let mut data = [40, 10, 20, 30];
    assert_eq!(percentile(&mut data, 50), Some(20));
    assert_eq!(percentile(&mut data, 95), Some(40));
    assert_eq!(percentile(&mut [], 99), None);
  }

  #[test]
  fn readiness_notifications_coalesce_and_can_be_rearmed() {
    let events = EventQueue::new(3).unwrap();
    for _ in 0..1000 {
      events.ready(2);
    }
    assert_eq!(events.state.lock().unwrap().queue.len(), 1);
    let mut batch = Vec::with_capacity(EVENT_BATCH);
    events.drain(&mut batch, Duration::ZERO).unwrap();
    assert!(matches!(&batch[..], [ObserverEvent::Ready(2)]));
    events.ready(2);
    events.ready(0);
    events.drain(&mut batch, Duration::ZERO).unwrap();
    assert!(matches!(
      &batch[..],
      [ObserverEvent::Ready(2), ObserverEvent::Ready(0)]
    ));
    assert_eq!(events.state.lock().unwrap().queue.len(), 0);
  }

  #[test]
  fn notification_capacity_failure_is_visible_to_the_observer() {
    let events = EventQueue::new(1).unwrap();
    let event = || ObserverEvent::SubmissionStats {
      attempted: 0,
      dropped: 0,
      lateness_sum: 0,
      lateness_max: 0,
    };
    for _ in 0..events.capacity {
      events.push(event()).unwrap();
    }
    assert!(events.push(event()).is_err());
    assert!(
      events
        .drain(&mut Vec::with_capacity(EVENT_BATCH), Duration::ZERO)
        .is_err()
    );
  }

  #[test]
  fn already_published_results_include_producer_lateness() {
    let mut executors =
      Executors::new(ExecutorKind::Bounded, 1, 1, 1, Duration::from_secs(60)).unwrap();
    let handle = executors
      .submit(ExecutorKind::Bounded, Box::new(|| 0))
      .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    if let Handle::Bounded(job) = &handle {
      while !job.is_finished() {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
      }
    }
    let events = EventQueue::new(1).unwrap();
    let wakers = [Waker::from(Arc::new(ReadyWake { id: 0, events }))];
    let mut slots = [Some((handle, Instant::now() - Duration::from_secs(1)))];
    let mut samples = Vec::with_capacity(1);
    let mut checksum = 0;
    let mut completed = 0;
    poll_observed(
      0,
      &mut slots,
      &wakers,
      &mut samples,
      &mut checksum,
      &mut completed,
      1,
    )
    .unwrap();
    assert_eq!(completed, 1);
    assert!(samples[0] >= 1_000_000_000);
    assert!(slots[0].is_none());
    executors.shutdown().unwrap();
  }

  #[test]
  fn accepted_tokio_jobs_finish_before_executor_shutdown() {
    // Offer a burst to one worker so the last accepted jobs remain queued
    // when submission ends. The observer must retain the runtime owner until
    // their public joins resolve, rather than cancelling that backlog.
    let options = Options {
      lane: Lane::Blocking,
      workload: Workload::Local,
      mode: Mode::Latency,
      executor: Some(ExecutorKind::Tokio),
      count: 128,
      workers: 1,
      arrival_rate: 1_000_000_000,
      bytes: 1_048_576,
      window: 128,
    };
    run_blocking("test", &options, 0).unwrap();
  }

  #[test]
  fn async_lane_drains_public_joins_for_all_workloads_and_executors() {
    for workload in [Workload::Ready, Workload::Yielding, Workload::Mixed] {
      for executor in [ExecutorKind::Bounded, ExecutorKind::Tokio] {
        let options = Options {
          lane: Lane::Async,
          workload,
          mode: Mode::Latency,
          executor: Some(executor),
          count: 8,
          workers: 2,
          arrival_rate: 1_000_000_000,
          bytes: 64,
          window: 8,
        };
        run_async("test", &options, 0).unwrap();
      }
    }
  }

  #[test]
  fn error_cleanup_does_not_wait_for_a_running_tokio_job() {
    let executors = Executors::new(ExecutorKind::Tokio, 1, 1, 1, Duration::from_secs(60)).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let handle = executors
      .submit(
        ExecutorKind::Tokio,
        Box::new(move || {
          started_tx.send(()).unwrap();
          release_rx.recv().unwrap();
          0
        }),
      )
      .unwrap();
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let (dropped_tx, dropped_rx) = mpsc::channel();
    let cleanup = std::thread::spawn(move || {
      drop(executors);
      dropped_tx.send(()).unwrap();
    });
    let completed_without_release = dropped_rx.recv_timeout(Duration::from_secs(2));
    // Rescue a blocking destructor before asserting, so a regression fails
    // finitely instead of stranding the test worker and its captured channel.
    release_tx.send(()).unwrap();
    cleanup.join().unwrap();
    assert!(completed_without_release.is_ok());
    drop(handle);
  }
}
