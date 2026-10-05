#![allow(
  unsafe_code,
  reason = "this diagnostic binary wraps System to count benchmark allocations"
)]

//! Runtime diagnostic lane, separate from the throughput benchmark.
//!
//! ```text
//! bench-runtime-diagnostic [--workers N] [--jobs N] [--window N]
//! ```
//!
//! Workers first block in submitted jobs while the driver fills the queue.
//! The row reports submit allocations, queue depth, p99 submit/start/work
//! completion latency, and retained memory for inline 4 KiB results and
//! returned cancellation tokens. Run the same command against baseline and
//! candidate source; percentiles describe this controlled backlog workload.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use allocatbelt_runtime::{
  CancellationToken, Config, Job, Resources, Runtime, ShutdownMode, SubmitErrorKind,
};

const RESULT_BYTES: usize = 4 * 1024;
const MAX_WORKERS: usize = 1024;
const MAX_WINDOW: usize = 65_536;
const MAX_REJECT_ITERATIONS: usize = 10_000_000;

static TRACK_ALLOCATIONS: AtomicBool = AtomicBool::new(false);
static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static REALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static REALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static DEALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static DEALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static LARGEST_ALLOC: AtomicU64 = AtomicU64::new(0);
static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);

struct CountingSystem;

#[global_allocator]
static GLOBAL: CountingSystem = CountingSystem;

// SAFETY: Every allocation operation delegates the caller's pointer and layout to `System`.
unsafe impl GlobalAlloc for CountingSystem {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    // SAFETY: The caller supplies the layout required by GlobalAlloc::alloc.
    let pointer = unsafe { System.alloc(layout) };
    if !pointer.is_null() {
      LIVE_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
      record_allocation(layout.size());
    }
    pointer
  }

  unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
    // SAFETY: The caller supplies the layout required by GlobalAlloc::alloc_zeroed.
    let pointer = unsafe { System.alloc_zeroed(layout) };
    if !pointer.is_null() {
      LIVE_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
      record_allocation(layout.size());
    }
    pointer
  }

  unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
    if TRACK_ALLOCATIONS.load(Ordering::Relaxed) {
      DEALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
      DEALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
    }
    LIVE_BYTES.fetch_sub(layout.size() as u64, Ordering::Relaxed);
    // SAFETY: The caller supplies a pointer allocated by this GlobalAlloc with this layout.
    unsafe { System.dealloc(pointer, layout) };
  }

  unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    // SAFETY: The caller supplies a pointer and old layout allocated by this GlobalAlloc.
    let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
    if !new_pointer.is_null() {
      let old_size = layout.size() as u64;
      let new_size = new_size as u64;
      if new_size >= old_size {
        LIVE_BYTES.fetch_add(new_size - old_size, Ordering::Relaxed);
      } else {
        LIVE_BYTES.fetch_sub(old_size - new_size, Ordering::Relaxed);
      }
      if TRACK_ALLOCATIONS.load(Ordering::Relaxed) {
        REALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        REALLOC_BYTES.fetch_add(new_size, Ordering::Relaxed);
        LARGEST_ALLOC.fetch_max(new_size, Ordering::Relaxed);
      }
    }
    new_pointer
  }
}

fn record_allocation(size: usize) {
  if TRACK_ALLOCATIONS.load(Ordering::Relaxed) {
    let size = size as u64;
    ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    ALLOC_BYTES.fetch_add(size, Ordering::Relaxed);
    LARGEST_ALLOC.fetch_max(size, Ordering::Relaxed);
  }
}

#[derive(Clone, Copy, Default)]
struct AllocationCounts {
  alloc_calls: u64,
  alloc_bytes: u64,
  realloc_calls: u64,
  realloc_bytes: u64,
  dealloc_calls: u64,
  dealloc_bytes: u64,
  largest_alloc: u64,
}

struct AllocationTracking {
  active: bool,
}

impl AllocationTracking {
  fn start() -> Self {
    TRACK_ALLOCATIONS.store(false, Ordering::Relaxed);
    ALLOC_CALLS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    REALLOC_CALLS.store(0, Ordering::Relaxed);
    REALLOC_BYTES.store(0, Ordering::Relaxed);
    DEALLOC_CALLS.store(0, Ordering::Relaxed);
    DEALLOC_BYTES.store(0, Ordering::Relaxed);
    LARGEST_ALLOC.store(0, Ordering::Relaxed);
    TRACK_ALLOCATIONS.store(true, Ordering::Relaxed);
    Self { active: true }
  }

  fn stop(mut self) -> AllocationCounts {
    TRACK_ALLOCATIONS.store(false, Ordering::Relaxed);
    self.active = false;
    allocation_counts()
  }
}

impl Drop for AllocationTracking {
  fn drop(&mut self) {
    if self.active {
      TRACK_ALLOCATIONS.store(false, Ordering::Relaxed);
    }
  }
}

fn allocation_counts() -> AllocationCounts {
  AllocationCounts {
    alloc_calls: ALLOC_CALLS.load(Ordering::Relaxed),
    alloc_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
    realloc_calls: REALLOC_CALLS.load(Ordering::Relaxed),
    realloc_bytes: REALLOC_BYTES.load(Ordering::Relaxed),
    dealloc_calls: DEALLOC_CALLS.load(Ordering::Relaxed),
    dealloc_bytes: DEALLOC_BYTES.load(Ordering::Relaxed),
    largest_alloc: LARGEST_ALLOC.load(Ordering::Relaxed),
  }
}

#[derive(Clone, Copy)]
struct Options {
  workers: usize,
  jobs: usize,
  window: usize,
  reject_iterations: Option<usize>,
}

impl Options {
  fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
    let default_workers = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    let (mut workers, mut jobs, mut window, mut reject_iterations) =
      (default_workers, 512, None, None);
    while let Some(arg) = args.next() {
      let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value"));
      match arg.as_str() {
        "--workers" => workers = number(&arg, &value()?)?,
        "--jobs" => jobs = number(&arg, &value()?)?,
        "--window" => window = Some(number(&arg, &value()?)?),
        "--reject-iterations" => reject_iterations = Some(number(&arg, &value()?)?),
        "-h" | "--help" => return Err(usage().to_owned()),
        _ => return Err(format!("unknown argument {arg:?}\n{}", usage())),
      }
    }
    let options = Self {
      workers,
      jobs,
      window: window.unwrap_or(jobs),
      reject_iterations,
    };
    options.validate()?;
    Ok(options)
  }

  fn validate(self) -> Result<(), String> {
    if self.workers == 0 || self.workers > MAX_WORKERS {
      return Err(format!("--workers must be from 1 to {MAX_WORKERS}"));
    }
    if self.jobs == 0 || self.jobs > MAX_WINDOW {
      return Err(format!("--jobs must be from 1 to {MAX_WINDOW}"));
    }
    if self.window < self.jobs || self.window > MAX_WINDOW {
      return Err(format!(
        "--window must be from --jobs ({}) to {MAX_WINDOW}",
        self.jobs
      ));
    }
    if self.workers > self.jobs {
      return Err("--workers must not exceed --jobs".to_owned());
    }
    if let Some(iterations) = self.reject_iterations
      && (iterations == 0 || iterations > MAX_REJECT_ITERATIONS)
    {
      return Err(format!(
        "--reject-iterations must be from 1 to {MAX_REJECT_ITERATIONS}"
      ));
    }
    self
      .window
      .checked_mul(RESULT_BYTES)
      .ok_or_else(|| "--window times 4096 overflows".to_owned())?;
    Ok(())
  }
}

fn usage() -> &'static str {
  "usage: bench-runtime-diagnostic [--workers N] [--jobs N] [--window N] [--reject-iterations N]"
}

fn number(flag: &str, value: &str) -> Result<usize, String> {
  if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
    return Err(format!("{flag} needs a non-negative decimal integer"));
  }
  value
    .parse()
    .map_err(|_| format!("{flag} is too large for this platform"))
}

#[derive(Default)]
struct GateState {
  waiting: usize,
  released: bool,
}

#[derive(Default)]
struct Gate {
  state: Mutex<GateState>,
  changed: Condvar,
}

impl Gate {
  fn block(&self) {
    let mut state = self.lock();
    state.waiting += 1;
    self.changed.notify_all();
    while !state.released {
      state = self
        .changed
        .wait(state)
        .unwrap_or_else(PoisonError::into_inner);
    }
  }

  fn wait_for(&self, count: usize) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut state = self.lock();
    while state.waiting < count {
      let remaining = deadline.saturating_duration_since(Instant::now());
      if remaining.is_zero() {
        return Err(format!(
          "only {} of {count} workers reached the diagnostic gate",
          state.waiting
        ));
      }
      let (next, _) = self
        .changed
        .wait_timeout(state, remaining)
        .unwrap_or_else(PoisonError::into_inner);
      state = next;
    }
    Ok(())
  }

  fn release(&self) {
    let mut state = self.lock();
    state.released = true;
    self.changed.notify_all();
  }

  fn lock(&self) -> MutexGuard<'_, GateState> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }
}

/// Release blocked jobs before runtime cleanup on every success/error path.
struct GateRelease(Arc<Gate>);

impl Drop for GateRelease {
  fn drop(&mut self) {
    self.0.release();
  }
}

fn warm_workers(runtime: &Runtime, workers: usize) -> Result<(), String> {
  let gate = Arc::new(Gate::default());
  let _release = GateRelease(Arc::clone(&gate));
  let mut jobs = Vec::with_capacity(workers);
  for _ in 0..workers {
    let gate = Arc::clone(&gate);
    let job = runtime
      .try_spawn(Resources::ZERO, move |_| gate.block())
      .map_err(|error| format!("warm-up submit: {}", error.kind))?;
    jobs.push(job);
  }
  gate.wait_for(workers)?;
  gate.release();
  for job in jobs {
    job
      .join()
      .map_err(|error| format!("warm-up join: {error}"))?;
  }
  Ok(())
}

fn atomic_samples(count: usize) -> Arc<Vec<AtomicU64>> {
  Arc::new((0..count).map(|_| AtomicU64::new(u64::MAX)).collect())
}

fn nanos(duration: Duration) -> u64 {
  u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn p99(mut samples: Vec<u64>) -> u64 {
  samples.sort_unstable();
  let index = samples
    .len()
    .saturating_mul(99)
    .div_ceil(100)
    .saturating_sub(1);
  samples[index]
}

fn timing_samples(samples: &[AtomicU64], label: &str) -> Result<Vec<u64>, String> {
  samples
    .iter()
    .map(|sample| {
      let value = sample.load(Ordering::Relaxed);
      (value != u64::MAX)
        .then_some(value)
        .ok_or_else(|| format!("missing {label} timestamp"))
    })
    .collect()
}

fn byte_delta(later: u64, earlier: u64) -> u64 {
  later.saturating_sub(earlier)
}

fn measure(options: Options) -> Result<(), String> {
  let memory_capacity = options
    .window
    .checked_mul(RESULT_BYTES)
    .ok_or_else(|| "queue memory capacity overflows".to_owned())?;
  let config = Config {
    workers: options.workers,
    max_outstanding: options.window,
    capacity: Resources {
      cpu: options.window,
      memory: memory_capacity,
      disk: 0,
      network: 0,
    },
  };

  let live_before_runtime = LIVE_BYTES.load(Ordering::Relaxed);
  let tracking = AllocationTracking::start();
  let runtime = Runtime::new(config);
  let init_allocations = tracking.stop();
  let mut runtime = runtime.map_err(|error| format!("runtime construction: {error}"))?;
  let handle = runtime.handle();
  warm_workers(&runtime, options.workers)?;
  let runtime_live_bytes = byte_delta(LIVE_BYTES.load(Ordering::Relaxed), live_before_runtime);

  let gate = Arc::new(Gate::default());
  let _release = GateRelease(Arc::clone(&gate));
  let starts = atomic_samples(options.jobs);
  let finishes = atomic_samples(options.jobs);
  let mut submit_ns = Vec::with_capacity(options.jobs);
  let mut jobs: Vec<Job<(CancellationToken, [u8; RESULT_BYTES])>> =
    Vec::with_capacity(options.jobs);
  let mut tokens = Vec::with_capacity(options.jobs);
  let request = Resources {
    cpu: 1,
    memory: RESULT_BYTES,
    disk: 0,
    network: 0,
  };
  let live_before_submit = LIVE_BYTES.load(Ordering::Relaxed);
  let tracking = AllocationTracking::start();
  for id in 0..options.jobs {
    let gate = Arc::clone(&gate);
    let starts = Arc::clone(&starts);
    let finishes = Arc::clone(&finishes);
    let submitted_at = Instant::now();
    let job = handle
      .try_spawn(request, move |token| {
        starts[id].store(nanos(submitted_at.elapsed()), Ordering::Relaxed);
        gate.block();
        let result = black_box([id as u8; RESULT_BYTES]);
        finishes[id].store(nanos(submitted_at.elapsed()), Ordering::Relaxed);
        (token, result)
      })
      .map_err(|error| format!("submission {id}: {}", error.kind))?;
    submit_ns.push(nanos(submitted_at.elapsed()));
    jobs.push(job);
  }
  let submit_allocations = tracking.stop();
  let live_after_submit = LIVE_BYTES.load(Ordering::Relaxed);
  gate.wait_for(options.workers)?;
  let queued_before_release = runtime.snapshot().queued;
  gate.release();
  while jobs.iter().any(|job| !job.is_finished()) {
    std::thread::yield_now();
  }
  let live_ready = LIVE_BYTES.load(Ordering::Relaxed);

  let mut checksum = 0u64;
  for job in jobs.drain(..) {
    let (token, result) = job.join().map_err(|error| format!("join: {error}"))?;
    checksum = checksum.wrapping_add(u64::from(result[0]));
    tokens.push(token);
  }
  let expected_checksum =
    (0..options.jobs).fold(0u64, |sum, id| sum.wrapping_add(u64::from(id as u8)));
  if checksum != expected_checksum {
    return Err(format!("result checksum {checksum} != {expected_checksum}"));
  }
  let live_joined_with_tokens = LIVE_BYTES.load(Ordering::Relaxed);
  // Compute and release sample buffers only after both packet-release
  // snapshots, so benchmark bookkeeping does not look like runtime memory.
  let submit_p99 = p99(submit_ns);
  let start_p99 = p99(timing_samples(&starts, "start")?);
  let completion_p99 = p99(timing_samples(&finishes, "completion")?);
  runtime
    .shutdown(ShutdownMode::Drain)
    .map_err(|error| format!("runtime shutdown: {error}"))?;
  let live_before_runtime_drop = LIVE_BYTES.load(Ordering::Relaxed);
  drop(runtime);
  drop(handle);
  let live_after_runtime_drop = LIVE_BYTES.load(Ordering::Relaxed);
  let runtime_released_bytes = byte_delta(live_before_runtime_drop, live_after_runtime_drop);
  tokens.clear();
  let live_after_token_values_drop = LIVE_BYTES.load(Ordering::Relaxed);
  drop(tokens);
  let live_after_token_drop = LIVE_BYTES.load(Ordering::Relaxed);
  let token_retained_bytes = byte_delta(live_after_runtime_drop, live_after_token_values_drop);
  let token_vector_buffer_bytes = byte_delta(live_after_token_values_drop, live_after_token_drop);
  let packet_release_bytes = byte_delta(live_ready, live_joined_with_tokens);
  let result_payload_bytes = options.jobs.saturating_mul(RESULT_BYTES) as u64;
  let error_priorities_ok = check_error_priorities()?;

  println!(
    "workers\tjobs\twindow\truntime_new_alloc_calls\truntime_new_alloc_bytes\t\
     runtime_new_realloc_calls\truntime_new_realloc_bytes\truntime_new_largest_alloc_bytes\t\
     runtime_live_bytes\tsubmit_alloc_calls\tsubmit_alloc_bytes\tsubmit_realloc_calls\t\
     submit_realloc_bytes\tsubmit_dealloc_calls\tsubmit_dealloc_bytes\t\
     submitted_live_bytes\tqueued_before_release\tp99_submit_ns\tp99_start_ns\t\
     p99_completion_ns\tinline_4k_payload_bytes\tcompleted_packet_release_bytes\t\
     runtime_released_bytes\ttoken_retained_bytes\ttoken_vector_buffer_bytes\t\
     error_priorities_ok\tchecksum"
  );
  println!(
    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
    options.workers,
    options.jobs,
    options.window,
    init_allocations.alloc_calls,
    init_allocations.alloc_bytes,
    init_allocations.realloc_calls,
    init_allocations.realloc_bytes,
    init_allocations.largest_alloc,
    runtime_live_bytes,
    submit_allocations.alloc_calls,
    submit_allocations.alloc_bytes,
    submit_allocations.realloc_calls,
    submit_allocations.realloc_bytes,
    submit_allocations.dealloc_calls,
    submit_allocations.dealloc_bytes,
    byte_delta(live_after_submit, live_before_submit),
    queued_before_release,
    submit_p99,
    start_p99,
    completion_p99,
    result_payload_bytes,
    packet_release_bytes,
    runtime_released_bytes,
    token_retained_bytes,
    token_vector_buffer_bytes,
    u8::from(error_priorities_ok),
    checksum,
  );
  if !error_priorities_ok {
    return Err("submission rejection priorities changed".to_owned());
  }
  if let Some(iterations) = options.reject_iterations {
    measure_rejections(iterations)?;
  }
  Ok(())
}

fn measure_rejections(iterations: usize) -> Result<(), String> {
  println!(
    "rejection_case\titerations\talloc_calls\talloc_bytes\trealloc_calls\t\
     realloc_bytes\tdealloc_calls\tdealloc_bytes\tlive_bytes_delta\ttotal_ns\t\
     ns_per_reject\tp99_reject_ns\tkind_mismatches"
  );
  for (label, expected) in [
    ("Full", SubmitErrorKind::Full),
    ("Closed", SubmitErrorKind::Closed),
    ("InvalidRequest", SubmitErrorKind::InvalidRequest),
    (
      "InsufficientResources",
      SubmitErrorKind::InsufficientResources,
    ),
  ] {
    measure_rejection_case(label, expected, iterations)?;
  }
  Ok(())
}

fn measure_rejection_case(
  label: &str,
  expected: SubmitErrorKind,
  iterations: usize,
) -> Result<(), String> {
  let request = |cpu| Resources {
    cpu,
    memory: 0,
    disk: 0,
    network: 0,
  };
  let is_full = expected == SubmitErrorKind::Full;
  let is_insufficient = expected == SubmitErrorKind::InsufficientResources;
  let held_case = is_full || is_insufficient;
  let config = Config {
    workers: 1,
    max_outstanding: usize::from(is_full) + 2 * usize::from(!is_full),
    capacity: request(1),
  };
  let mut runtime = Runtime::new(config).map_err(|error| format!("{label} runtime: {error}"))?;
  warm_workers(&runtime, 1)?;
  let handle = runtime.handle();
  let gate = Arc::new(Gate::default());
  let _release = GateRelease(Arc::clone(&gate));
  let held = if held_case {
    let task_gate = Arc::clone(&gate);
    let job = handle
      .try_spawn(request(1), move |_| task_gate.block())
      .map_err(|error| format!("{label} setup: {}", error.kind))?;
    gate.wait_for(1)?;
    Some(job)
  } else {
    None
  };
  if expected == SubmitErrorKind::Closed {
    runtime
      .shutdown(ShutdownMode::Drain)
      .map_err(|error| format!("Closed setup shutdown: {error}"))?;
  }
  let submitted_request =
    if expected == SubmitErrorKind::InvalidRequest || expected == SubmitErrorKind::Closed {
      request(2)
    } else {
      request(1)
    };
  let mut samples = Vec::with_capacity(iterations);
  let live_before = LIVE_BYTES.load(Ordering::Relaxed);
  let tracking = AllocationTracking::start();
  let started = Instant::now();
  let mut kind_mismatches = 0usize;
  for _ in 0..iterations {
    let attempt = Instant::now();
    match handle.try_spawn(submitted_request, |_| ()) {
      Err(error) => {
        kind_mismatches += usize::from(error.kind != expected);
      }
      Ok(job) => {
        kind_mismatches += 1;
        drop(job);
      }
    }
    samples.push(nanos(attempt.elapsed()));
  }
  let total_ns = nanos(started.elapsed());
  let allocations = tracking.stop();
  let live_after = LIVE_BYTES.load(Ordering::Relaxed);
  let p99_ns = p99(samples);
  println!(
    "{label}\t{iterations}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{total_ns}\t{}\t{p99_ns}\t{kind_mismatches}",
    allocations.alloc_calls,
    allocations.alloc_bytes,
    allocations.realloc_calls,
    allocations.realloc_bytes,
    allocations.dealloc_calls,
    allocations.dealloc_bytes,
    byte_delta(live_after, live_before),
    total_ns / iterations as u64,
  );
  if let Some(job) = held {
    gate.release();
    job
      .join()
      .map_err(|error| format!("{label} held job: {error}"))?;
  }
  if !runtime.snapshot().closed {
    runtime
      .shutdown(ShutdownMode::Drain)
      .map_err(|error| format!("{label} shutdown: {error}"))?;
  }
  drop(handle);
  drop(runtime);
  if kind_mismatches != 0 {
    return Err(format!(
      "{label} produced {kind_mismatches} unexpected outcomes"
    ));
  }
  Ok(())
}

fn check_error_priorities() -> Result<bool, String> {
  let resource = |cpu| Resources {
    cpu,
    memory: 0,
    disk: 0,
    network: 0,
  };
  let full_config = Config {
    workers: 1,
    max_outstanding: 1,
    capacity: resource(1),
  };
  let mut full_runtime = Runtime::new(full_config).map_err(|error| error.to_string())?;
  let full_gate = Arc::new(Gate::default());
  let _release_full = GateRelease(Arc::clone(&full_gate));
  let task_gate = Arc::clone(&full_gate);
  let held = full_runtime
    .try_spawn(resource(1), move |_| {
      task_gate.block();
    })
    .map_err(|error| format!("priority setup: {}", error.kind))?;
  full_gate.wait_for(1)?;
  let invalid = match full_runtime.try_spawn(resource(2), |_| ()) {
    Err(error) => error.kind,
    Ok(job) => {
      drop(job);
      SubmitErrorKind::Full
    }
  };
  let full = match full_runtime.try_spawn(resource(1), |_| ()) {
    Err(error) => error.kind,
    Ok(job) => {
      drop(job);
      SubmitErrorKind::InsufficientResources
    }
  };
  full_gate.release();
  held
    .join()
    .map_err(|error| format!("priority held job: {error}"))?;
  full_runtime
    .shutdown(ShutdownMode::Drain)
    .map_err(|error| format!("priority shutdown: {error}"))?;
  let closed = match full_runtime.try_spawn(resource(2), |_| ()) {
    Err(error) => error.kind,
    Ok(job) => {
      drop(job);
      SubmitErrorKind::InsufficientResources
    }
  };

  let insufficient_config = Config {
    workers: 1,
    max_outstanding: 2,
    capacity: resource(1),
  };
  let mut insufficient_runtime =
    Runtime::new(insufficient_config).map_err(|error| error.to_string())?;
  let insufficient_gate = Arc::new(Gate::default());
  let _release_insufficient = GateRelease(Arc::clone(&insufficient_gate));
  let task_gate = Arc::clone(&insufficient_gate);
  let held = insufficient_runtime
    .try_spawn(resource(1), move |_| {
      task_gate.block();
    })
    .map_err(|error| format!("insufficient setup: {}", error.kind))?;
  insufficient_gate.wait_for(1)?;
  let insufficient = match insufficient_runtime.try_spawn(resource(1), |_| ()) {
    Err(error) => error.kind,
    Ok(job) => {
      drop(job);
      SubmitErrorKind::Full
    }
  };
  insufficient_gate.release();
  held
    .join()
    .map_err(|error| format!("insufficient held job: {error}"))?;
  insufficient_runtime
    .shutdown(ShutdownMode::Drain)
    .map_err(|error| format!("insufficient shutdown: {error}"))?;

  Ok(
    invalid == SubmitErrorKind::InvalidRequest
      && full == SubmitErrorKind::Full
      && closed == SubmitErrorKind::Closed
      && insufficient == SubmitErrorKind::InsufficientResources,
  )
}

fn main() -> ExitCode {
  let options = match Options::parse(std::env::args().skip(1)) {
    Ok(options) => options,
    Err(error) => {
      eprintln!("{error}\n{}", usage());
      return ExitCode::from(2);
    }
  };
  match measure(options) {
    Ok(()) => ExitCode::SUCCESS,
    Err(error) => {
      eprintln!("bench-runtime-diagnostic: {error}");
      ExitCode::FAILURE
    }
  }
}
