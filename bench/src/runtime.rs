//! Blocking-job executor benchmark: allocatbelt-runtime's bounded executor
//! against Tokio's blocking pool, under whichever global allocator the
//! binary installs (`bench-runtime-{system,mimalloc,allocatbelt}`), so the
//! allocator and the executor vary independently.
//!
//! ```text
//! bench-runtime-* --executor bounded|tokio [--start warm|cold] [--workers N]
//!                 [--window N] [--jobs N] [--bytes N] [--cpu-iters N] [--quick]
//! ```
//!
//! Both executors run the same deterministic [`job_work`] for job ids
//! `0..jobs`, submitted by the same driver: a FIFO window of at most
//! `window` outstanding jobs, which joins the oldest job before submitting
//! the next once full. The Tokio side is `spawn_blocking` on a
//! current-thread runtime with `max_blocking_threads(workers)`: this compares
//! blocking pools, not Tokio's async scheduler.
//!
//! The timed region is the first job submission to the last join. Building
//! the runtime and shutting it down are outside it. What happens before it
//! depends on `--start`:
//!
//! - `warm` (default): `workers` warm-up jobs, which do no benchmark work,
//!   are submitted and must all be running at once before any is released
//!   (or the run fails), so each executor has started `workers` threads
//!   before timing. This does not keep them: `workers` is a cap, not a fixed
//!   population, and Tokio retires blocking threads idle past its keep-alive.
//! - `cold`: no warm-up. The bounded runtime may start its workers when it
//!   is built, outside the timed region, while Tokio starts blocking threads
//!   on demand inside it, so cold results include asymmetric start-up and do
//!   not compare the executors' steady-state speed.
//!
//! After timing, the sum of the job results is checked against a sequential
//! run of the same jobs, and every job must have completed. A header and one
//! tab-separated row go to standard output; a failed run exits with code 1,
//! invalid arguments with 2. Memory figures the kernel does not report are
//! `NA`.

use std::collections::VecDeque;
use std::hint::black_box;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use allocatbelt_profile::Usage;
use allocatbelt_runtime::{Config, Resources, Runtime, ShutdownMode};

/// Which executor runs the jobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Executor {
  /// `allocatbelt_runtime::Runtime`.
  Bounded,
  /// `tokio::task::spawn_blocking` on a current-thread runtime.
  Tokio,
}

impl Executor {
  fn name(self) -> &'static str {
    match self {
      Self::Bounded => "bounded",
      Self::Tokio => "tokio",
    }
  }
}

/// What runs before the timed region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
  /// Every worker thread is started, all at once, before timing.
  Warm,
  /// Nothing; thread start-up falls wherever each executor does it.
  Cold,
}

impl Start {
  fn name(self) -> &'static str {
    match self {
      Self::Warm => "warm",
      Self::Cold => "cold",
    }
  }
}

/// The most worker threads a run may ask for: warm start runs them all at
/// once, so an argument must not be able to start an unbounded number.
pub const MAX_WORKERS: usize = 1024;

/// How long the warm-up waits for every worker to be running.
const WARM_UP_TIMEOUT: Duration = Duration::from_secs(30);

/// The benchmark's parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
  /// The executor under test.
  pub executor: Executor,
  /// What runs before timing.
  pub start: Start,
  /// Worker (blocking) threads, at most.
  pub workers: usize,
  /// Jobs submitted and not yet joined, at most; at least `workers`.
  pub window: usize,
  /// Jobs to run.
  pub jobs: usize,
  /// Bytes each job allocates and writes in full.
  pub bytes: usize,
  /// Extra mixing rounds per job, for CPU-bound jobs.
  pub cpu_iters: u64,
}

const USAGE: &str = "usage: bench-runtime-* --executor bounded|tokio [--start warm|cold] \
[--workers N] [--window N] [--jobs N] [--bytes N] [--cpu-iters N] [--quick]";

impl Options {
  /// Parses the arguments after the program name. Explicit values win over
  /// `--quick`, whatever their order.
  pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
    let (mut executor, mut start) = (None, Start::Warm);
    let (mut workers, mut window, mut jobs, mut bytes, mut cpu_iters) =
      (None, None, None, None, None);
    let mut quick = false;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
      let mut value = || it.next().ok_or_else(|| format!("{a} needs a value"));
      match a.as_str() {
        "--executor" => {
          executor = Some(match value()?.as_str() {
            "bounded" => Executor::Bounded,
            "tokio" => Executor::Tokio,
            v => return Err(format!("unknown executor {v:?} (bounded or tokio)")),
          });
        }
        "--start" => {
          start = match value()?.as_str() {
            "warm" => Start::Warm,
            "cold" => Start::Cold,
            v => return Err(format!("unknown start {v:?} (warm or cold)")),
          };
        }
        "--workers" => workers = Some(number(&a, &value()?)?),
        "--window" => window = Some(number(&a, &value()?)?),
        "--jobs" => jobs = Some(number(&a, &value()?)?),
        "--bytes" => bytes = Some(number(&a, &value()?)?),
        "--cpu-iters" => cpu_iters = Some(number(&a, &value()?)?),
        "--quick" => quick = true,
        "-h" | "--help" => return Err(USAGE.to_owned()),
        _ => return Err(format!("unknown argument {a:?}\n{USAGE}")),
      }
    }
    let executor = executor.ok_or_else(|| format!("--executor is required\n{USAGE}"))?;
    let size = |v: Option<u64>, default: usize, flag: &str| -> Result<usize, String> {
      v.map_or(Ok(default), |v| {
        usize::try_from(v).map_err(|_| format!("{flag} is too large"))
      })
    };
    let default_workers = std::thread::available_parallelism().map_or(4, |n| n.get().min(16));
    let workers = size(workers, default_workers, "--workers")?;
    let o = Self {
      executor,
      start,
      workers,
      window: size(window, workers.saturating_mul(4), "--window")?,
      jobs: size(jobs, if quick { 2_000 } else { 100_000 }, "--jobs")?,
      bytes: size(bytes, if quick { 4_096 } else { 65_536 }, "--bytes")?,
      cpu_iters: cpu_iters.unwrap_or(if quick { 100 } else { 1_000 }),
    };
    o.validate()?;
    Ok(o)
  }

  fn validate(&self) -> Result<(), String> {
    if self.workers == 0 || self.workers > MAX_WORKERS {
      return Err(format!("--workers must be from 1 to {MAX_WORKERS}"));
    }
    if self.window < self.workers {
      return Err(format!(
        "--window ({}) must be at least --workers ({})",
        self.window, self.workers
      ));
    }
    if self.jobs == 0 {
      return Err("--jobs must be at least 1".to_owned());
    }
    self.memory_capacity()?;
    Ok(())
  }

  /// Memory the bounded runtime admits: every job in the window holds its
  /// reservation from submission, queued ones included, not only running.
  fn memory_capacity(&self) -> Result<usize, String> {
    self
      .window
      .checked_mul(self.bytes)
      .ok_or_else(|| "--window times --bytes overflows".to_owned())
  }
}

/// Parses a decimal count: ASCII digits only (no sign), within `u64`.
fn number(flag: &str, v: &str) -> Result<u64, String> {
  let err = || format!("{flag} needs a non-negative decimal integer, not {v:?}");
  if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
    return Err(err());
  }
  v.parse().map_err(|_| err())
}

/// SplitMix64's finalizer.
fn mix(mut z: u64) -> u64 {
  z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
  z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
  z ^ (z >> 31)
}

/// One job: allocates exactly `bytes`, writes every byte from a stream
/// seeded by `id`, hashes them back, mixes `cpu_iters` more rounds and frees
/// the buffer. Not inlined, so profiles show it as its own function.
#[inline(never)]
pub fn job_work(id: u64, bytes: usize, cpu_iters: u64) -> u64 {
  let mut buf: Vec<u8> = Vec::with_capacity(bytes);
  let mut s = mix(id ^ 0x9e37_79b9_7f4a_7c15);
  while buf.len() < bytes {
    s = mix(s.wrapping_add(0x9e37_79b9_7f4a_7c15));
    let n = (bytes - buf.len()).min(8);
    buf.extend_from_slice(&s.to_le_bytes()[..n]);
  }
  // The buffer must exist in memory, not be fused away with the reads.
  black_box(&mut buf);
  let mut h = mix(id) ^ bytes as u64;
  for chunk in buf.chunks(8) {
    let mut w = [0u8; 8];
    w[..chunk.len()].copy_from_slice(chunk);
    h = mix(h ^ u64::from_le_bytes(w));
  }
  for _ in 0..cpu_iters {
    h = mix(h);
  }
  h
}

/// The sum of the job results, and how many jobs completed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
  /// Wrapping sum of the results, independent of completion order.
  pub checksum: u64,
  /// Jobs joined successfully.
  pub completed: usize,
}

/// What the jobs `0..jobs` should add up to, run on the calling thread.
pub fn reference(o: &Options) -> Tally {
  let mut t = Tally::default();
  for id in 0..o.jobs as u64 {
    t.checksum = t.checksum.wrapping_add(job_work(id, o.bytes, o.cpu_iters));
    t.completed += 1;
  }
  t
}

/// Submits jobs `0..jobs` keeping at most `window` outstanding: once the
/// window is full, the oldest job is joined before the next is submitted.
/// Holds at most `min(window, jobs)` handles, reserved up front.
fn drive<H>(
  jobs: usize,
  window: usize,
  mut submit: impl FnMut(u64) -> Result<H, String>,
  mut join: impl FnMut(H) -> Result<u64, String>,
) -> Result<Tally, String> {
  let mut pending = VecDeque::new();
  pending
    .try_reserve(window.min(jobs))
    .map_err(|e| format!("cannot reserve the submission window: {e}"))?;
  let mut t = Tally::default();
  let mut settle = |h, t: &mut Tally| -> Result<(), String> {
    t.checksum = t.checksum.wrapping_add(join(h)?);
    t.completed += 1;
    Ok(())
  };
  for id in 0..jobs as u64 {
    if pending.len() >= window
      && let Some(h) = pending.pop_front()
    {
      settle(h, &mut t)?;
    }
    pending.push_back(submit(id)?);
  }
  while let Some(h) = pending.pop_front() {
    settle(h, &mut t)?;
  }
  Ok(t)
}

/// A job as both executors take it.
type Work = Box<dyn FnOnce() -> u64 + Send + 'static>;

/// What the benchmark needs of an executor.
trait Exec {
  type Handle;
  fn submit(&self, work: Work) -> Result<Self::Handle, String>;
  fn join(&self, h: Self::Handle) -> Result<u64, String>;
  fn shutdown(self) -> Result<(), String>;
}

/// Submits `workers` jobs that each report they are running and then wait
/// to be released, and releases them only once all report within
/// `timeout`. Every error (a failed submission, a join, a job that never
/// starts) drops the release channels, so the jobs already running return
/// and nothing is left waiting.
fn warm_up<E: Exec>(e: &E, workers: usize, timeout: Duration) -> Result<(), String> {
  let (started_tx, started_rx) = mpsc::channel::<()>();
  let mut releases = Vec::with_capacity(workers);
  let mut handles = Vec::with_capacity(workers);
  let mut err = None;
  for _ in 0..workers {
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let started = started_tx.clone();
    let work: Work = Box::new(move || {
      let _ = started.send(());
      // Returns on release or when the sender is dropped.
      let _ = release_rx.recv();
      0
    });
    match e.submit(work) {
      Ok(h) => {
        releases.push(release_tx);
        handles.push(h);
      }
      Err(msg) => {
        err = Some(format!("warm-up submit: {msg}"));
        break;
      }
    }
  }
  drop(started_tx);
  if err.is_none() {
    let deadline = Instant::now() + timeout;
    for n in 0..workers {
      let left = deadline.saturating_duration_since(Instant::now());
      if started_rx.recv_timeout(left).is_err() {
        err = Some(format!(
          "warm-up: {n} of {workers} workers running after {timeout:?}"
        ));
        break;
      }
    }
  }
  // Releases the jobs on success and on every error.
  drop(releases);
  for h in handles {
    if let Err(msg) = e.join(h) {
      err.get_or_insert(format!("warm-up join: {msg}"));
    }
  }
  err.map_or(Ok(()), Err)
}

/// Resource use of the timed region.
#[derive(Clone, Copy, Debug, Default)]
struct Measured {
  wall_s: f64,
  usage: Usage,
}

/// Warms up if asked, times the jobs and shuts the executor down, also
/// after an error.
fn measure<E: Exec>(e: E, o: &Options) -> Result<(Tally, Measured), String> {
  let result = (|| -> Result<(Tally, Measured), String> {
    if o.start == Start::Warm {
      warm_up(&e, o.workers, WARM_UP_TIMEOUT)?;
    }
    let (bytes, cpu_iters) = (o.bytes, o.cpu_iters);
    let before = Usage::of_self();
    let start = Instant::now();
    let tally = drive(
      o.jobs,
      o.window,
      |id| e.submit(Box::new(move || job_work(id, bytes, cpu_iters))),
      |h| e.join(h),
    )?;
    let wall_s = start.elapsed().as_secs_f64();
    let usage = Usage::of_self().since(&before);
    Ok((tally, Measured { wall_s, usage }))
  })();
  let shutdown = e.shutdown();
  let result = result?;
  shutdown?;
  Ok(result)
}

/// allocatbelt-runtime, reserving `bytes` of memory per job. Warm-up jobs
/// reserve the same, so warm-up admission is no looser than the jobs'.
struct Bounded {
  rt: Runtime,
  bytes: usize,
}

impl Exec for Bounded {
  type Handle = allocatbelt_runtime::Job<u64>;
  fn submit(&self, work: Work) -> Result<Self::Handle, String> {
    self
      .rt
      .try_spawn(job_resources(self.bytes), move |_cancel| work())
      .map_err(|e| format!("submit: {e}"))
  }
  fn join(&self, h: Self::Handle) -> Result<u64, String> {
    h.join().map_err(|e| format!("join: {e}"))
  }
  fn shutdown(mut self) -> Result<(), String> {
    self
      .rt
      .shutdown(ShutdownMode::Drain)
      .map_err(|e| format!("bounded runtime shutdown: {e}"))
  }
}

/// Tokio's blocking pool, driven from a current-thread runtime.
struct Tokio(tokio::runtime::Runtime);

impl Exec for Tokio {
  type Handle = tokio::task::JoinHandle<u64>;
  fn submit(&self, work: Work) -> Result<Self::Handle, String> {
    Ok(self.0.spawn_blocking(work))
  }
  fn join(&self, h: Self::Handle) -> Result<u64, String> {
    self.0.block_on(h).map_err(|e| format!("join: {e}"))
  }
  fn shutdown(self) -> Result<(), String> {
    self.0.shutdown_background();
    Ok(())
  }
}

/// What one job reserves: one CPU and its buffer, which is all it
/// allocates beyond a few words; it does no disk or network I/O.
fn job_resources(bytes: usize) -> Resources {
  Resources {
    cpu: 1,
    memory: bytes,
    disk: 0,
    network: 0,
  }
}

fn bounded(o: &Options) -> Result<Bounded, String> {
  // Admission counts queued jobs too, so the capacity covers the whole
  // window; the worker count is set on its own.
  let config = Config {
    workers: o.workers,
    max_outstanding: o.window,
    capacity: Resources {
      cpu: o.window,
      memory: o.memory_capacity()?,
      disk: 0,
      network: 0,
    },
  };
  let rt = Runtime::new(config).map_err(|e| format!("bounded runtime: {e}"))?;
  Ok(Bounded { rt, bytes: o.bytes })
}

fn tokio(o: &Options) -> Result<Tokio, String> {
  tokio::runtime::Builder::new_current_thread()
    .max_blocking_threads(o.workers)
    .thread_name("tokio-blocking")
    .build()
    .map(Tokio)
    .map_err(|e| format!("tokio runtime: {e}"))
}

fn run(o: &Options) -> Result<(Tally, Measured), String> {
  match o.executor {
    Executor::Bounded => measure(bounded(o)?, o),
    Executor::Tokio => measure(tokio(o)?, o),
  }
}

/// The columns of the output row, in order. `scripts/bench-runtime.sh`
/// checks rows against the same list.
pub const HEADER: &str = "allocator\texecutor\tstart\tworkers\twindow\tjobs\tbytes\tcpu_iters\t\
wall_ms\tjobs_per_s\tuser_ms\tsystem_ms\trss_kib\thwm_kib\tminflt\tmajflt\tchecksum\tcompleted\t\
expected_checksum\texpected_completed\tstatus";

/// A `/proc/self/status` size in KiB, or `NA` when the kernel does not
/// report it.
fn status_kib(field: &str) -> String {
  std::fs::read_to_string("/proc/self/status")
    .ok()
    .and_then(|s| {
      s.lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
    })
    .map_or_else(|| "NA".to_owned(), |v| v.to_string())
}

/// Runs the benchmark with the process's arguments; `allocator` names the
/// binary's global allocator in the output.
pub fn main(allocator: &str) -> ExitCode {
  let o = match Options::parse(std::env::args().skip(1)) {
    Ok(o) => o,
    Err(msg) => {
      eprintln!("{msg}");
      return ExitCode::from(2);
    }
  };
  let (tally, m) = match run(&o) {
    Ok(r) => r,
    Err(msg) => {
      eprintln!("bench-runtime: {msg}");
      return ExitCode::FAILURE;
    }
  };
  // Read before the reference run, which allocates as well.
  let (rss, hwm) = (status_kib("VmRSS:"), status_kib("VmHWM:"));
  let expected = reference(&o);
  let ok = tally == expected;
  let jobs_per_s = if m.wall_s > 0.0 {
    tally.completed as f64 / m.wall_s
  } else {
    0.0
  };
  println!("{HEADER}");
  println!(
    "{allocator}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.1}\t{jobs_per_s:.0}\t{:.0}\t{:.0}\t{rss}\t{hwm}\t\
     {}\t{}\t{}\t{}\t{}\t{}\t{}",
    o.executor.name(),
    o.start.name(),
    o.workers,
    o.window,
    o.jobs,
    o.bytes,
    o.cpu_iters,
    m.wall_s * 1e3,
    m.usage.user_s * 1e3,
    m.usage.sys_s * 1e3,
    m.usage.minflt,
    m.usage.majflt,
    tally.checksum,
    tally.completed,
    expected.checksum,
    expected.completed,
    if ok { "ok" } else { "FAIL" },
  );
  if ok {
    ExitCode::SUCCESS
  } else {
    eprintln!(
      "bench-runtime: checksum {} (expected {}), {} of {} jobs completed",
      tally.checksum, expected.checksum, tally.completed, expected.completed
    );
    ExitCode::FAILURE
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};

  fn args(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_owned).collect()
  }

  fn tiny(executor: Executor, start: Start) -> Options {
    Options {
      executor,
      start,
      workers: 2,
      window: 3,
      jobs: 37,
      bytes: 1_003,
      cpu_iters: 5,
    }
  }

  const ALL: [(Executor, Start); 4] = [
    (Executor::Bounded, Start::Warm),
    (Executor::Bounded, Start::Cold),
    (Executor::Tokio, Start::Warm),
    (Executor::Tokio, Start::Cold),
  ];

  #[test]
  fn job_work_is_deterministic_and_depends_on_every_input() {
    assert_eq!(job_work(7, 1_003, 9), job_work(7, 1_003, 9));
    assert_ne!(job_work(7, 1_003, 9), job_work(8, 1_003, 9));
    assert_ne!(job_work(7, 1_003, 9), job_work(7, 1_004, 9));
    assert_ne!(job_work(7, 1_003, 9), job_work(7, 1_003, 10));
    assert_ne!(job_work(0, 0, 0), job_work(1, 0, 0));
  }

  #[test]
  fn reference_is_stable_and_counts_every_job() {
    let o = tiny(Executor::Bounded, Start::Warm);
    let r = reference(&o);
    assert_eq!(r, reference(&o));
    assert_eq!(r.completed, o.jobs);
  }

  #[test]
  fn driver_keeps_the_window_and_joins_oldest_first() {
    let outstanding = std::cell::RefCell::new(VecDeque::new());
    let mut peak = 0;
    let t = drive(
      20,
      4,
      |id| {
        let mut q = outstanding.borrow_mut();
        q.push_back(id);
        peak = peak.max(q.len());
        Ok(id)
      },
      |id| {
        assert_eq!(outstanding.borrow_mut().pop_front(), Some(id));
        Ok(id)
      },
    )
    .expect("drive");
    assert_eq!(peak, 4);
    assert_eq!(
      t,
      Tally {
        checksum: (0..20).sum(),
        completed: 20
      }
    );
    assert!(outstanding.borrow().is_empty());
  }

  #[test]
  fn driver_stops_at_the_first_error() {
    let join = |id| {
      if id == 3 {
        Err("join".to_owned())
      } else {
        Ok(id)
      }
    };
    assert_eq!(drive(5, 2, Ok, join), Err("join".to_owned()));
    let submit = |id| {
      if id == 4 {
        Err("submit".to_owned())
      } else {
        Ok(id)
      }
    };
    assert_eq!(drive(5, 2, submit, Ok), Err("submit".to_owned()));
  }

  #[test]
  fn driver_stores_at_most_the_jobs() {
    let t = drive(3, usize::MAX, Ok, Ok).expect("drive");
    assert_eq!(t.completed, 3);
  }

  #[test]
  fn huge_window_runs_without_panicking() {
    let o = Options::parse(args(&format!(
      "--executor tokio --workers 1 --window {} --bytes 0 --jobs 1",
      usize::MAX
    )))
    .expect("parse");
    let (t, _) = run(&o).expect("run");
    assert_eq!(t, reference(&o));
  }

  #[test]
  fn every_executor_and_start_matches_the_reference() {
    for (executor, start) in ALL {
      for window in [2, 3, 8] {
        let o = Options {
          window,
          ..tiny(executor, start)
        };
        let (t, _) = run(&o).expect("run");
        assert_eq!(t, reference(&o), "{executor:?} {start:?}, window {window}");
      }
    }
  }

  /// Runs `jobs` jobs that sleep and records how many ran at once.
  fn peak_concurrency<E: Exec>(e: E, start: Start, workers: usize, jobs: usize) -> usize {
    if start == Start::Warm {
      warm_up(&e, workers, WARM_UP_TIMEOUT).expect("warm-up");
    }
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let t = drive(
      jobs,
      4 * workers,
      |_| {
        let (active, peak) = (Arc::clone(&active), Arc::clone(&peak));
        e.submit(Box::new(move || {
          let now = active.fetch_add(1, Ordering::SeqCst) + 1;
          peak.fetch_max(now, Ordering::SeqCst);
          std::thread::sleep(Duration::from_millis(20));
          active.fetch_sub(1, Ordering::SeqCst);
          1
        }))
      },
      |h| e.join(h),
    )
    .expect("drive");
    assert_eq!(t.completed, jobs);
    e.shutdown().expect("shutdown");
    peak.load(Ordering::SeqCst)
  }

  #[test]
  fn concurrency_never_exceeds_workers_and_reaches_them() {
    let workers = 3;
    for (executor, start) in ALL {
      let o = Options {
        workers,
        window: 4 * workers,
        ..tiny(executor, start)
      };
      let peak = match executor {
        Executor::Bounded => peak_concurrency(bounded(&o).expect("bounded"), start, workers, 24),
        Executor::Tokio => peak_concurrency(tokio(&o).expect("tokio"), start, workers, 24),
      };
      assert_eq!(peak, workers, "{executor:?} {start:?}");
    }
  }

  /// Runs each job on a new thread, and fails the `fail_at`-th submission.
  struct Failing {
    fail_at: usize,
    submitted: AtomicUsize,
  }

  impl Exec for Failing {
    type Handle = mpsc::Receiver<u64>;
    fn submit(&self, work: Work) -> Result<Self::Handle, String> {
      if self.submitted.fetch_add(1, Ordering::SeqCst) == self.fail_at {
        return Err("full".to_owned());
      }
      let (tx, rx) = mpsc::channel();
      std::thread::spawn(move || tx.send(work()));
      Ok(rx)
    }
    fn join(&self, h: Self::Handle) -> Result<u64, String> {
      h.recv().map_err(|e| e.to_string())
    }
    fn shutdown(self) -> Result<(), String> {
      Ok(())
    }
  }

  /// Accepts every job but runs them one at a time.
  struct OneThread(mpsc::Sender<(Work, mpsc::Sender<u64>)>);

  impl OneThread {
    fn new() -> Self {
      let (tx, rx) = mpsc::channel::<(Work, mpsc::Sender<u64>)>();
      std::thread::spawn(move || {
        for (work, done) in rx {
          let _ = done.send(work());
        }
      });
      Self(tx)
    }
  }

  impl Exec for OneThread {
    type Handle = mpsc::Receiver<u64>;
    fn submit(&self, work: Work) -> Result<Self::Handle, String> {
      let (tx, rx) = mpsc::channel();
      self.0.send((work, tx)).map_err(|e| e.to_string())?;
      Ok(rx)
    }
    fn join(&self, h: Self::Handle) -> Result<u64, String> {
      h.recv().map_err(|e| e.to_string())
    }
    fn shutdown(self) -> Result<(), String> {
      Ok(())
    }
  }

  #[test]
  fn warm_up_errors_release_the_running_jobs() {
    let e = Failing {
      fail_at: 2,
      submitted: AtomicUsize::new(0),
    };
    let err = warm_up(&e, 4, WARM_UP_TIMEOUT).expect_err("submit fails");
    assert!(err.contains("submit"), "{err}");
    let t = Instant::now();
    let err = warm_up(&OneThread::new(), 2, Duration::from_millis(200)).expect_err("times out");
    assert!(err.contains("1 of 2 workers"), "{err}");
    assert!(t.elapsed() < Duration::from_secs(10));
  }

  #[test]
  fn explicit_values_win_over_quick() {
    let o = Options::parse(args(
      "--jobs 10 --quick --executor tokio --start cold --workers 3 --window 5 --bytes 0 \
       --cpu-iters 2",
    ))
    .expect("parse");
    assert_eq!(
      o,
      Options {
        executor: Executor::Tokio,
        start: Start::Cold,
        workers: 3,
        window: 5,
        jobs: 10,
        bytes: 0,
        cpu_iters: 2,
      }
    );
    let q = Options::parse(args("--executor bounded --workers 2 --quick")).expect("parse");
    assert_eq!(
      (q.start, q.window, q.jobs, q.bytes, q.cpu_iters),
      (Start::Warm, 8, 2_000, 4_096, 100)
    );
  }

  #[test]
  fn rejects_invalid_arguments() {
    for bad in [
      "",
      "--workers 2",
      "--executor async",
      "--executor",
      "--executor tokio --start hot",
      "--executor tokio --workers 0",
      "--executor tokio --workers 1025 --window 2000",
      "--executor tokio --workers 4 --window 3",
      "--executor tokio --jobs 0",
      "--executor tokio --jobs -1",
      "--executor tokio --jobs +1",
      "--executor tokio --jobs 18446744073709551616",
      "--executor tokio --bytes 1k",
      "--executor tokio --workers",
      "--executor tokio --frobnicate",
      "--executor tokio --help",
      "--executor tokio --workers 1 --window 18446744073709551615 --bytes 2",
    ] {
      assert!(Options::parse(args(bad)).is_err(), "accepted {bad:?}");
    }
  }

  #[test]
  fn script_checks_the_same_columns() {
    let script = include_str!("../../scripts/bench-runtime.sh");
    let columns = HEADER.replace('\t', " ");
    assert!(
      script.contains(&format!("bench_columns=({columns})")),
      "scripts/bench-runtime.sh bench_columns differ from HEADER"
    );
  }

  #[test]
  fn script_requests_the_same_defaults() {
    let script = include_str!("../../scripts/bench-runtime.sh");
    let full = Options::parse(args("--executor tokio --workers 1")).expect("parse");
    let quick = Options::parse(args("--executor tokio --workers 1 --quick")).expect("parse");
    for (o, flag) in [(&full, ""), (&quick, "--quick ")] {
      let line = format!(
        "req_jobs=\"${{req_jobs:-{}}}\" req_bytes=\"${{req_bytes:-{}}}\" \
         req_cpu_iters=\"${{req_cpu_iters:-{}}}\"",
        o.jobs, o.bytes, o.cpu_iters
      );
      assert!(script.contains(&line), "{flag}defaults differ: {line}");
    }
    assert!(script.contains("req_start=warm"));
    assert_eq!(full.start, Start::Warm);
    assert!(script.contains(&format!("<= {MAX_WORKERS}")));
    let default = Options::parse(args("--executor tokio")).expect("parse");
    assert!((1..=16).contains(&default.workers));
    assert_eq!(default.window, 4 * default.workers);
  }
}
