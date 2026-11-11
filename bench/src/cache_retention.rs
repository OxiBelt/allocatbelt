//! Retained-memory probe for allocatbelt's per-thread TLS cache.
//!
//! Build the same source against each candidate allocator revision and pass
//! a distinct `--variant` label. The trace is deterministic and bounded. The
//! `parked` sample is taken with every worker alive after it has flushed its
//! cache; the final sample follows worker joins and a main-thread purge.
//! Set `ALLOCATBELT_RETAINED_SMAPS_PATH` to request an optional, bounded
//! per-mapping sidecar. The path is read only after the primary parked
//! rollup and checksum have been validated. Capture is non-atomic and its
//! own mapping/file activity and stack use happen after that primary sample;
//! it is diagnostic evidence, not part of the CSV or acceptance gates.
//! Capture is byte-bounded but filesystem I/O is not time-bounded, so the
//! external runner must retain its process timeout and require successful exit.
//! Reported process memory includes stacks, libc thread state, mappings and
//! kernel residency decisions, so none of the fields directly measure the
//! logical cache size or establish a latency/performance improvement.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use allocatbelt::Allocatbelt;

const MAX_WORKERS: usize = 512;
const MIN_WORKERS: usize = 1;
const STACK_BYTES: usize = 2 * 1024 * 1024;
const TRACE_ROUNDS: usize = 16;
// This is only the worker enrollment deadline. It does not bound joining a
// worker or allocator purge; the remote runner's outer process timeout does.
const PARK_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_SMAPS_BYTES: usize = 64 * 1024;
const SMAPS_BUFFER_BYTES: usize = MAX_SMAPS_BYTES + 1;
const MAX_SIDECAR_BYTES: usize = 16 * 1024 * 1024;
const SIDECAR_BUFFER_BYTES: usize = 16 * 1024;
const SIDECAR_ENV: &str = "ALLOCATBELT_RETAINED_SMAPS_PATH";
// Readers require this envelope and trailer, plus a successful probe exit;
// failed or truncated captures cannot be accepted as complete snapshots.
const SIDECAR_HEADER: &[u8] = b"ALLOCATBELT-SMAPS-SIDECAR-V1\n";
const SIDECAR_COMPLETE: &[u8] = b"\nALLOCATBELT-SMAPS-COMPLETE-V1\n";
const PAGE_CLASS_SIZES: [usize; 32] = [
  16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024,
  1280, 1536, 1792, 2048, 2560, 3072, 3584, 4096, 5120, 6144, 7168, 8192,
];
const CSV_HEADER: &str = "schema,allocator,variant,rustc_version,target,workers,stack_bytes,trace,trace_rounds,allocations_per_worker,stage,worker_threads_alive,workers_parked,workers_joined,checksum,rss_kib,pss_kib,private_clean_kib,private_dirty_kib,anonymous_kib,logical_cache_bytes_per_thread,binary_bytes";

static GLOBAL: Allocatbelt = Allocatbelt;

/// Deterministic trace choice. `Minimal` initializes one small class' TLS
/// cache and flushes it; `AllClasses` visits the fixed table of 32 classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Trace {
  /// One 16-byte small allocation class per trace round.
  Minimal,
  /// One allocation from each core small-object class per trace round.
  AllClasses,
}

impl Trace {
  fn sizes(self) -> &'static [usize] {
    match self {
      Self::Minimal => &PAGE_CLASS_SIZES[..1],
      Self::AllClasses => &PAGE_CLASS_SIZES,
    }
  }

  fn as_str(self) -> &'static str {
    match self {
      Self::Minimal => "minimal",
      Self::AllClasses => "all-classes",
    }
  }
}

/// Parsed probe configuration. It has no unbounded workload dimensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeConfig {
  /// Explicit source-variant label, such as `baseline`, `inverse`, or `word`.
  pub variant: String,
  /// Caller-recorded compiler identity from the candidate build manifest.
  pub rustc_version: String,
  /// Number of simultaneously alive worker threads (1..=512).
  pub workers: usize,
  /// Which fixed deterministic trace to run.
  pub trace: Trace,
  /// Optional modeled cache bytes per thread; never used as a measured value.
  pub logical_cache_bytes_per_thread: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Rollup {
  rss_kib: u64,
  pss_kib: u64,
  private_clean_kib: u64,
  private_dirty_kib: u64,
  anonymous_kib: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StageCounts {
  alive: usize,
  parked: usize,
  joined: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParseRollupError {
  InvalidLine,
  Duplicate(&'static str),
  InvalidValue(&'static str),
  Missing(&'static str),
  TooLarge,
  InvalidUtf8,
}

impl std::fmt::Display for ParseRollupError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "invalid smaps_rollup data: {self:?}")
  }
}

impl std::error::Error for ParseRollupError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeError {
  Usage,
  InvalidConfig,
  SmapsRead,
  SmapsParse(ParseRollupError),
  SmapsSidecar(SidecarError),
  Spawn,
  /// A worker did not enroll at the park gate within the enrollment deadline.
  /// The outer runner timeout separately bounds subsequent joins and purge.
  ParkTimeout,
  WorkerPanic,
  ChecksumMismatch,
  ExecutableMetadata,
  Output,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SidecarError {
  Create,
  Read,
  Write,
  TooLarge,
}

impl std::fmt::Display for ProbeError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{self:?}")
  }
}

impl std::error::Error for ProbeError {}

/// Runs the probe from its CLI and writes the fixed CSV schema to stdout.
pub fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
  let config = parse_args(std::env::args().skip(1))?;
  run(config).map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<ProbeConfig, ProbeError> {
  let mut variant = None;
  let mut rustc_version = None;
  let mut workers = None;
  let mut trace = None;
  let mut logical_cache_bytes_per_thread = None;
  let mut args = args.into_iter();
  while let Some(arg) = args.next() {
    let value = args.next().ok_or(ProbeError::Usage)?;
    match arg.as_str() {
      "--variant" if variant.is_none() => variant = Some(value),
      "--rustc-version" if rustc_version.is_none() => rustc_version = Some(value),
      "--workers" if workers.is_none() => {
        workers = Some(value.parse().map_err(|_| ProbeError::InvalidConfig)?);
      }
      "--trace" if trace.is_none() => {
        trace = Some(match value.as_str() {
          "minimal" => Trace::Minimal,
          "all-classes" => Trace::AllClasses,
          _ => return Err(ProbeError::InvalidConfig),
        });
      }
      "--logical-cache-bytes-per-thread" if logical_cache_bytes_per_thread.is_none() => {
        logical_cache_bytes_per_thread =
          Some(value.parse().map_err(|_| ProbeError::InvalidConfig)?);
      }
      _ => return Err(ProbeError::Usage),
    }
  }
  let config = ProbeConfig {
    variant: variant.ok_or(ProbeError::Usage)?,
    rustc_version: rustc_version.ok_or(ProbeError::Usage)?,
    workers: workers.ok_or(ProbeError::Usage)?,
    trace: trace.ok_or(ProbeError::Usage)?,
    logical_cache_bytes_per_thread,
  };
  validate_config(&config)?;
  Ok(config)
}

fn validate_config(config: &ProbeConfig) -> Result<(), ProbeError> {
  if !(MIN_WORKERS..=MAX_WORKERS).contains(&config.workers)
    || !valid_label(&config.variant)
    || !valid_label(&config.rustc_version)
  {
    return Err(ProbeError::InvalidConfig);
  }
  Ok(())
}

fn valid_label(value: &str) -> bool {
  !value.is_empty()
    && value.len() <= 160
    && value
      .bytes()
      .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

fn run(config: ProbeConfig) -> Result<(), ProbeError> {
  run_with_callbacks(
    config,
    || std::env::var_os(SIDECAR_ENV).map(PathBuf::from),
    |config, binary_bytes, allocations_per_worker, rows| {
      let stdout = io::stdout();
      let mut output = stdout.lock();
      write_rows(
        &mut output,
        config,
        binary_bytes,
        allocations_per_worker,
        rows,
      )
    },
  )
}

fn run_with_callbacks(
  config: ProbeConfig,
  sidecar_path: impl FnOnce() -> Option<PathBuf>,
  emit_rows: impl FnOnce(
    &ProbeConfig,
    u64,
    usize,
    [(&str, StageCounts, Rollup, u64); 3],
  ) -> io::Result<()>,
) -> Result<(), ProbeError> {
  validate_config(&config)?;
  let binary_bytes = std::env::current_exe()
    .and_then(std::fs::metadata)
    .map_err(|_| ProbeError::ExecutableMetadata)?
    .len();

  prewarm();
  let _ = read_rollup()?;
  let warm = read_rollup()?;
  let gate = Arc::new(ParkGate::new(config.workers));
  let mut cohort = ParkedCohort::new(Arc::clone(&gate));
  for worker in 0..config.workers {
    let worker_gate = Arc::clone(&gate);
    let trace = config.trace;
    let builder = thread::Builder::new().stack_size(STACK_BYTES);
    match builder.spawn(move || {
      let checksum = run_trace(worker, trace);
      GLOBAL.flush_thread_cache();
      worker_gate.park(worker, checksum);
      checksum
    }) {
      Ok(handle) => cohort.push(handle),
      Err(_) => return Err(ProbeError::Spawn),
    }
  }

  let parked_checksum = gate.wait_parked(config.workers, PARK_TIMEOUT)?;
  let parked = read_rollup()?;
  let expected = expected_checksum(config.workers, config.trace);
  if parked_checksum != expected {
    return Err(ProbeError::ChecksumMismatch);
  }
  if let Some(path) = sidecar_path() {
    capture_smaps_sidecar(&path).map_err(ProbeError::SmapsSidecar)?;
  }

  let joined_checksum = cohort.join()?;
  if joined_checksum != expected {
    return Err(ProbeError::ChecksumMismatch);
  }
  GLOBAL.purge();
  let after_join_purge = read_rollup()?;
  let trace_allocations_per_worker = config.trace.sizes().len() * TRACE_ROUNDS;
  let rows = [
    (
      "warm",
      StageCounts {
        alive: 0,
        parked: 0,
        joined: 0,
      },
      warm,
      0,
    ),
    (
      "parked",
      StageCounts {
        alive: config.workers,
        parked: config.workers,
        joined: 0,
      },
      parked,
      parked_checksum,
    ),
    (
      "after_join_purge",
      StageCounts {
        alive: 0,
        parked: 0,
        joined: config.workers,
      },
      after_join_purge,
      joined_checksum,
    ),
  ];
  emit_rows(&config, binary_bytes, trace_allocations_per_worker, rows)
    .map_err(|_| ProbeError::Output)
}

fn prewarm() {
  std::hint::black_box(run_trace(0, Trace::AllClasses));
  GLOBAL.flush_thread_cache();
  GLOBAL.purge();
}

fn run_trace(worker: usize, trace: Trace) -> u64 {
  let mut checksum = 0u64;
  for round in 0..TRACE_ROUNDS {
    for (class, size) in trace.sizes().iter().copied().enumerate() {
      let byte = ((worker + round + class) % 251 + 1) as u8;
      let mut buffer = Vec::with_capacity(size);
      buffer.resize(size, byte);
      let touched = buffer
        .iter()
        .fold(0u64, |sum, value| sum.wrapping_add(u64::from(*value)));
      checksum = checksum.wrapping_add(touched ^ (size as u64).rotate_left((class % 64) as u32));
      std::hint::black_box(&buffer);
      drop(buffer);
    }
  }
  checksum
}

fn expected_checksum(workers: usize, trace: Trace) -> u64 {
  (0..workers).fold(0u64, |total, worker| {
    let per_worker = (0..TRACE_ROUNDS).fold(0u64, |subtotal, round| {
      trace
        .sizes()
        .iter()
        .copied()
        .enumerate()
        .fold(subtotal, |sum, (class, size)| {
          let byte = ((worker + round + class) % 251 + 1) as u64;
          let touched = (size as u64).wrapping_mul(byte);
          sum.wrapping_add(touched ^ (size as u64).rotate_left((class % 64) as u32))
        })
    });
    total.wrapping_add(per_worker)
  })
}

struct GateState {
  parked: usize,
  release: bool,
  checksums: Vec<u64>,
}

struct ParkGate {
  state: Mutex<GateState>,
  changed: Condvar,
}

impl ParkGate {
  fn new(workers: usize) -> Self {
    Self {
      state: Mutex::new(GateState {
        parked: 0,
        release: false,
        checksums: vec![0; workers],
      }),
      changed: Condvar::new(),
    }
  }

  fn park(&self, worker: usize, checksum: u64) {
    let mut state = lock(&self.state);
    if state.release {
      return;
    }
    state.checksums[worker] = checksum;
    state.parked += 1;
    self.changed.notify_all();
    while !state.release {
      state = wait(&self.changed, state);
    }
  }

  fn wait_parked(&self, workers: usize, timeout: Duration) -> Result<u64, ProbeError> {
    let deadline = Instant::now()
      .checked_add(timeout)
      .ok_or(ProbeError::InvalidConfig)?;
    let mut state = lock(&self.state);
    while state.parked != workers {
      let now = Instant::now();
      if now >= deadline {
        return Err(ProbeError::ParkTimeout);
      }
      let remaining = deadline.saturating_duration_since(now);
      let (next, result) = wait_timeout(&self.changed, state, remaining);
      state = next;
      if result.timed_out() && state.parked != workers {
        return Err(ProbeError::ParkTimeout);
      }
    }
    Ok(
      state
        .checksums
        .iter()
        .copied()
        .fold(0u64, u64::wrapping_add),
    )
  }

  fn release(&self) {
    let mut state = lock(&self.state);
    state.release = true;
    self.changed.notify_all();
  }
}

struct ParkedCohort {
  gate: Arc<ParkGate>,
  handles: Vec<JoinHandle<u64>>,
}

impl ParkedCohort {
  fn new(gate: Arc<ParkGate>) -> Self {
    Self {
      gate,
      handles: Vec::new(),
    }
  }

  fn push(&mut self, handle: JoinHandle<u64>) {
    self.handles.push(handle);
  }

  fn join(mut self) -> Result<u64, ProbeError> {
    self.gate.release();
    join_all(std::mem::take(&mut self.handles))
  }
}

impl Drop for ParkedCohort {
  fn drop(&mut self) {
    self.gate.release();
    for handle in self.handles.drain(..) {
      let _ = handle.join();
    }
  }
}

fn join_all(handles: Vec<JoinHandle<u64>>) -> Result<u64, ProbeError> {
  let mut checksum = 0u64;
  let mut panicked = false;
  for handle in handles {
    match handle.join() {
      Ok(value) => checksum = checksum.wrapping_add(value),
      Err(_) => panicked = true,
    }
  }
  if panicked {
    Err(ProbeError::WorkerPanic)
  } else {
    Ok(checksum)
  }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn wait<'a, T>(condvar: &Condvar, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
  condvar.wait(guard).unwrap_or_else(PoisonError::into_inner)
}

fn wait_timeout<'a, T>(
  condvar: &Condvar,
  guard: MutexGuard<'a, T>,
  duration: Duration,
) -> (MutexGuard<'a, T>, std::sync::WaitTimeoutResult) {
  condvar
    .wait_timeout(guard, duration)
    .unwrap_or_else(PoisonError::into_inner)
}

fn read_rollup() -> Result<Rollup, ProbeError> {
  let mut file = File::open("/proc/self/smaps_rollup").map_err(|_| ProbeError::SmapsRead)?;
  read_rollup_reader(&mut file)
}

fn read_rollup_reader(reader: &mut impl Read) -> Result<Rollup, ProbeError> {
  let mut bytes = [0u8; SMAPS_BUFFER_BYTES];
  let mut len = 0;
  loop {
    if len == bytes.len() {
      return Err(ProbeError::SmapsParse(ParseRollupError::TooLarge));
    }
    let read = reader
      .read(&mut bytes[len..])
      .map_err(|_| ProbeError::SmapsRead)?;
    if read == 0 {
      break;
    }
    len += read;
  }
  if len > MAX_SMAPS_BYTES {
    return Err(ProbeError::SmapsParse(ParseRollupError::TooLarge));
  }
  let text = std::str::from_utf8(&bytes[..len])
    .map_err(|_| ProbeError::SmapsParse(ParseRollupError::InvalidUtf8))?;
  parse_rollup(text).map_err(ProbeError::SmapsParse)
}

fn capture_smaps_sidecar(path: &Path) -> Result<(), SidecarError> {
  let mut input = File::open("/proc/self/smaps").map_err(|_| SidecarError::Read)?;
  capture_smaps_to_path(path, &mut input, MAX_SIDECAR_BYTES)
}

fn capture_smaps_to_path(
  path: &Path,
  reader: &mut impl Read,
  maximum_bytes: usize,
) -> Result<(), SidecarError> {
  let mut output = OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(path)
    .map_err(|_| SidecarError::Create)?;
  let result = stream_smaps(reader, &mut output, maximum_bytes);
  drop(output);
  if result.is_err() {
    // Remove partial data when possible. If removal fails, the runner's
    // recorded nonzero outcome still disqualifies any leftover sidecar.
    let _ = std::fs::remove_file(path);
  }
  result
}

fn stream_smaps(
  reader: &mut impl Read,
  writer: &mut impl Write,
  maximum_bytes: usize,
) -> Result<(), SidecarError> {
  let maximum_body = maximum_bytes
    .checked_sub(SIDECAR_HEADER.len() + SIDECAR_COMPLETE.len())
    .ok_or(SidecarError::TooLarge)?;
  writer
    .write_all(SIDECAR_HEADER)
    .map_err(|_| SidecarError::Write)?;
  let mut buffer = [0u8; SIDECAR_BUFFER_BYTES];
  let mut copied = 0usize;
  loop {
    let count = match reader.read(&mut buffer) {
      Ok(count) => count,
      Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
      Err(_) => return Err(SidecarError::Read),
    };
    if count == 0 {
      break;
    }
    let next = copied.checked_add(count).ok_or(SidecarError::TooLarge)?;
    if next > maximum_body {
      return Err(SidecarError::TooLarge);
    }
    writer
      .write_all(&buffer[..count])
      .map_err(|_| SidecarError::Write)?;
    copied = next;
  }
  // Flush the body before publishing the completion marker. There is no
  // fallible output operation after a full marker has been written.
  writer.flush().map_err(|_| SidecarError::Write)?;
  writer
    .write_all(SIDECAR_COMPLETE)
    .map_err(|_| SidecarError::Write)
}

fn parse_rollup(text: &str) -> Result<Rollup, ParseRollupError> {
  let mut rss = None;
  let mut pss = None;
  let mut private_clean = None;
  let mut private_dirty = None;
  let mut anonymous = None;
  for line in text.lines() {
    let Some((name, value)) = line.split_once(':') else {
      continue;
    };
    let target = match name {
      "Rss" => &mut rss,
      "Pss" => &mut pss,
      "Private_Clean" => &mut private_clean,
      "Private_Dirty" => &mut private_dirty,
      "Anonymous" => &mut anonymous,
      _ => continue,
    };
    if target.is_some() {
      return Err(ParseRollupError::Duplicate(match name {
        "Rss" => "Rss",
        "Pss" => "Pss",
        "Private_Clean" => "Private_Clean",
        "Private_Dirty" => "Private_Dirty",
        _ => "Anonymous",
      }));
    }
    let mut words = value.split_whitespace();
    let amount = words
      .next()
      .ok_or(ParseRollupError::InvalidLine)?
      .parse::<u64>()
      .map_err(|_| {
        ParseRollupError::InvalidValue(match name {
          "Rss" => "Rss",
          "Pss" => "Pss",
          "Private_Clean" => "Private_Clean",
          "Private_Dirty" => "Private_Dirty",
          _ => "Anonymous",
        })
      })?;
    if words.next() != Some("kB") || words.next().is_some() {
      return Err(ParseRollupError::InvalidValue(match name {
        "Rss" => "Rss",
        "Pss" => "Pss",
        "Private_Clean" => "Private_Clean",
        "Private_Dirty" => "Private_Dirty",
        _ => "Anonymous",
      }));
    }
    *target = Some(amount);
  }
  Ok(Rollup {
    rss_kib: rss.ok_or(ParseRollupError::Missing("Rss"))?,
    pss_kib: pss.ok_or(ParseRollupError::Missing("Pss"))?,
    private_clean_kib: private_clean.ok_or(ParseRollupError::Missing("Private_Clean"))?,
    private_dirty_kib: private_dirty.ok_or(ParseRollupError::Missing("Private_Dirty"))?,
    anonymous_kib: anonymous.ok_or(ParseRollupError::Missing("Anonymous"))?,
  })
}

fn write_rows(
  output: &mut impl Write,
  config: &ProbeConfig,
  binary_bytes: u64,
  allocations_per_worker: usize,
  rows: [(&str, StageCounts, Rollup, u64); 3],
) -> io::Result<()> {
  writeln!(output, "{CSV_HEADER}")?;
  let target = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
  for (stage, counts, memory, checksum) in rows {
    write!(output, "1,allocatbelt,")?;
    write_csv_field(output, &config.variant)?;
    output.write_all(b",")?;
    write_csv_field(output, &config.rustc_version)?;
    output.write_all(b",")?;
    write_csv_field(output, &target)?;
    writeln!(
      output,
      ",{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
      config.workers,
      STACK_BYTES,
      config.trace.as_str(),
      TRACE_ROUNDS,
      allocations_per_worker,
      stage,
      counts.alive,
      counts.parked,
      counts.joined,
      checksum,
      memory.rss_kib,
      memory.pss_kib,
      memory.private_clean_kib,
      memory.private_dirty_kib,
      memory.anonymous_kib,
      config
        .logical_cache_bytes_per_thread
        .map_or_else(|| "".to_owned(), |value| value.to_string()),
      binary_bytes,
    )?;
  }
  output.flush()
}

fn write_csv_field(output: &mut impl Write, value: &str) -> io::Result<()> {
  if value
    .bytes()
    .any(|byte| matches!(byte, b',' | b'"' | b'\n' | b'\r'))
  {
    output.write_all(b"\"")?;
    for byte in value.bytes() {
      if byte == b'"' {
        output.write_all(b"\"\"")?;
      } else {
        output.write_all(&[byte])?;
      }
    }
    output.write_all(b"\"")
  } else {
    output.write_all(value.as_bytes())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::atomic::{AtomicU64, Ordering};

  static NEXT_SIDECAR_TEST: AtomicU64 = AtomicU64::new(0);

  fn sidecar_test_path(label: &str) -> PathBuf {
    let sequence = NEXT_SIDECAR_TEST.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
      "allocatbelt-smaps-{}-{sequence}-{label}",
      std::process::id()
    ))
  }

  #[test]
  fn rollup_requires_exact_fields_and_kilobyte_units() {
    let parsed = parse_rollup(
      "Rss: 10 kB\nPss: 8 kB\nPrivate_Clean: 2 kB\nPrivate_Dirty: 3 kB\nAnonymous: 5 kB\n",
    )
    .unwrap();
    assert_eq!(
      parsed,
      Rollup {
        rss_kib: 10,
        pss_kib: 8,
        private_clean_kib: 2,
        private_dirty_kib: 3,
        anonymous_kib: 5,
      }
    );
    assert_eq!(
      parse_rollup(
        "Rss: 10 bytes\nPss: 8 kB\nPrivate_Clean: 2 kB\nPrivate_Dirty: 3 kB\nAnonymous: 5 kB\n"
      ),
      Err(ParseRollupError::InvalidValue("Rss"))
    );
    assert_eq!(
      parse_rollup("Rss: 10 kB\nPss: 8 kB\nPrivate_Clean: 2 kB\nPrivate_Dirty: 3 kB\n"),
      Err(ParseRollupError::Missing("Anonymous"))
    );
    assert_eq!(
      parse_rollup(
        "Rss: 10 kB\nRss: 11 kB\nPss: 8 kB\nPrivate_Clean: 2 kB\nPrivate_Dirty: 3 kB\nAnonymous: 5 kB\n"
      ),
      Err(ParseRollupError::Duplicate("Rss"))
    );
  }

  #[test]
  fn unavailable_and_oversized_rollup_sources_are_errors() {
    struct DeniedReader;

    impl Read for DeniedReader {
      fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "test"))
      }
    }

    assert_eq!(
      read_rollup_reader(&mut DeniedReader),
      Err(ProbeError::SmapsRead)
    );
    let oversized = vec![b' '; SMAPS_BUFFER_BYTES + 1];
    assert_eq!(
      read_rollup_reader(&mut io::Cursor::new(oversized)),
      Err(ProbeError::SmapsParse(ParseRollupError::TooLarge))
    );
  }

  #[test]
  fn smaps_sidecar_is_bounded_complete_and_create_new() {
    let path = sidecar_test_path("complete");
    let source = b"1000-2000 rw-p 00000000 00:00 0 [heap]\nRss: 4 kB\n";
    let maximum_bytes = SIDECAR_HEADER.len() + source.len() + SIDECAR_COMPLETE.len();
    capture_smaps_to_path(&path, &mut io::Cursor::new(source), maximum_bytes).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), maximum_bytes);
    assert!(bytes.starts_with(SIDECAR_HEADER));
    assert!(bytes.ends_with(SIDECAR_COMPLETE));
    assert!(bytes.windows(source.len()).any(|window| window == source));

    assert_eq!(
      capture_smaps_to_path(&path, &mut io::Cursor::new(source), maximum_bytes),
      Err(SidecarError::Create)
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    std::fs::remove_file(path).unwrap();
  }

  #[test]
  fn sidecar_overflow_read_write_and_path_failures_are_typed_and_incomplete_files_removed() {
    let sidecar_limit = SIDECAR_HEADER.len() + SIDECAR_COMPLETE.len() + 8;
    let oversized_path = sidecar_test_path("oversized");
    assert_eq!(
      capture_smaps_to_path(
        &oversized_path,
        &mut io::Cursor::new(b"more than the configured limit"),
        sidecar_limit,
      ),
      Err(SidecarError::TooLarge)
    );
    assert!(!oversized_path.exists());

    struct DeniedReader;
    impl Read for DeniedReader {
      fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "test"))
      }
    }
    let read_path = sidecar_test_path("read-error");
    assert_eq!(
      capture_smaps_to_path(&read_path, &mut DeniedReader, sidecar_limit),
      Err(SidecarError::Read)
    );
    assert!(!read_path.exists());

    struct DeniedWriter;
    impl Write for DeniedWriter {
      fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "test"))
      }
      fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "test"))
      }
    }
    assert_eq!(
      stream_smaps(
        &mut io::Cursor::new(b"smaps"),
        &mut DeniedWriter,
        sidecar_limit,
      ),
      Err(SidecarError::Write)
    );

    struct FlushFailureWriter(Vec<u8>);
    impl Write for FlushFailureWriter {
      fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
      }
      fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "test"))
      }
    }
    let mut flush_failure = FlushFailureWriter(Vec::new());
    assert_eq!(
      stream_smaps(
        &mut io::Cursor::new(b"smaps"),
        &mut flush_failure,
        sidecar_limit,
      ),
      Err(SidecarError::Write)
    );
    assert!(!flush_failure.0.ends_with(SIDECAR_COMPLETE));

    let missing_parent = sidecar_test_path("missing-parent").join("sidecar");
    assert_eq!(
      capture_smaps_to_path(
        &missing_parent,
        &mut io::Cursor::new(b"smaps"),
        sidecar_limit,
      ),
      Err(SidecarError::Create)
    );
    assert!(!missing_parent.exists());
  }

  #[test]
  fn two_worker_probe_keeps_primary_csv_and_emits_complete_sidecar() {
    let path = sidecar_test_path("probe");
    let config = ProbeConfig {
      variant: "sidecar-test".to_owned(),
      rustc_version: "rustc test".to_owned(),
      workers: 2,
      trace: Trace::Minimal,
      logical_cache_bytes_per_thread: None,
    };
    let mut csv = Vec::new();
    run_with_callbacks(
      config,
      || Some(path.clone()),
      |config, binary_bytes, allocations_per_worker, rows| {
        write_rows(&mut csv, config, binary_bytes, allocations_per_worker, rows)
      },
    )
    .unwrap();

    let text = std::str::from_utf8(&csv).unwrap();
    assert!(text.starts_with(&format!("{CSV_HEADER}\n")));
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some(CSV_HEADER));
    let rows: Vec<Vec<&str>> = lines.map(|line| line.split(',').collect()).collect();
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|row| row.len() == 22));
    assert_eq!(rows[0][10], "warm");
    assert_eq!(rows[1][10], "parked");
    assert_eq!(&rows[1][11..14], ["2", "2", "0"]);
    assert_eq!(rows[2][10], "after_join_purge");
    assert_eq!(&rows[2][11..14], ["0", "0", "2"]);

    let sidecar = std::fs::read(&path).unwrap();
    assert!(sidecar.starts_with(SIDECAR_HEADER));
    assert!(sidecar.ends_with(SIDECAR_COMPLETE));
    assert!(
      sidecar
        .windows(b"VmFlags:".len())
        .any(|part| part == b"VmFlags:")
    );
    std::fs::remove_file(path).unwrap();
  }

  #[test]
  fn fixed_trace_checksums_are_repeatable_and_distinct() {
    for trace in [Trace::Minimal, Trace::AllClasses] {
      let actual = (0..3).fold(0u64, |sum, worker| {
        sum.wrapping_add(run_trace(worker, trace))
      });
      assert_eq!(actual, expected_checksum(3, trace));
    }
    assert_ne!(
      expected_checksum(1, Trace::Minimal),
      expected_checksum(1, Trace::AllClasses)
    );
    assert_eq!(Trace::AllClasses.sizes().len(), PAGE_CLASS_SIZES.len());
    assert_eq!(Trace::Minimal.sizes(), &[16]);
  }

  #[test]
  fn released_gate_does_not_enroll_or_wait_for_a_late_worker() {
    let gate = Arc::new(ParkGate::new(1));
    gate.release();
    let worker_gate = Arc::clone(&gate);
    let worker = thread::spawn(move || {
      worker_gate.park(0, 7);
      7
    });
    assert_eq!(worker.join().unwrap(), 7);
    assert_eq!(gate.wait_parked(0, Duration::from_secs(1)), Ok(0));
  }

  #[test]
  fn dropping_partial_cohort_releases_and_joins_its_parked_worker() {
    let gate = Arc::new(ParkGate::new(2));
    let mut cohort = ParkedCohort::new(Arc::clone(&gate));
    let (unparked_tx, unparked_rx) = std::sync::mpsc::sync_channel(1);
    let (finish_tx, finish_rx) = std::sync::mpsc::sync_channel(1);
    let worker_gate = Arc::clone(&gate);
    let worker = thread::spawn(move || {
      worker_gate.park(0, 11);
      unparked_tx.send(()).unwrap();
      finish_rx.recv().unwrap();
      11
    });
    cohort.push(worker);
    assert_eq!(gate.wait_parked(1, Duration::from_secs(2)), Ok(11));

    let (dropped_tx, dropped_rx) = std::sync::mpsc::sync_channel(1);
    let dropper = thread::spawn(move || {
      drop(cohort);
      dropped_tx.send(()).unwrap();
    });
    unparked_rx
      .recv_timeout(Duration::from_secs(2))
      .expect("dropping the cohort releases its parked worker");
    assert!(matches!(
      dropped_rx.try_recv(),
      Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    finish_tx.send(()).unwrap();
    dropped_rx
      .recv_timeout(Duration::from_secs(2))
      .expect("cohort drop joins its worker before returning");
    dropper.join().unwrap();
  }

  #[test]
  fn unwind_drop_releases_parked_worker_under_a_watchdog() {
    let gate = Arc::new(ParkGate::new(1));
    let mut cohort = ParkedCohort::new(Arc::clone(&gate));
    let (unparked_tx, unparked_rx) = std::sync::mpsc::sync_channel(1);
    let worker_gate = Arc::clone(&gate);
    cohort.push(thread::spawn(move || {
      worker_gate.park(0, 13);
      unparked_tx.send(()).unwrap();
      13
    }));
    assert_eq!(gate.wait_parked(1, Duration::from_secs(2)), Ok(13));

    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    let unwinder = thread::spawn(move || {
      let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _cohort = cohort;
        panic!("exercise cohort cleanup during unwind");
      }));
      done_tx.send(result.is_err()).unwrap();
    });
    unparked_rx
      .recv_timeout(Duration::from_secs(2))
      .expect("unwinding cohort drop releases its worker");
    assert!(
      done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("cohort cleanup completes under the watchdog")
    );
    unwinder.join().unwrap();
  }

  #[test]
  fn join_reports_worker_panic_after_joining_every_worker_under_watchdog() {
    let gate = Arc::new(ParkGate::new(2));
    let mut cohort = ParkedCohort::new(Arc::clone(&gate));
    cohort.push(thread::spawn(|| -> u64 { panic!("probe worker panic") }));
    let worker_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = Arc::clone(&worker_done);
    let worker_gate = Arc::clone(&gate);
    cohort.push(thread::spawn(move || {
      worker_gate.park(1, 17);
      done.store(true, std::sync::atomic::Ordering::Release);
      17
    }));
    assert_eq!(gate.wait_parked(1, Duration::from_secs(2)), Ok(17));

    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let joiner = thread::spawn(move || result_tx.send(cohort.join()).unwrap());
    assert_eq!(
      result_rx.recv_timeout(Duration::from_secs(2)),
      Ok(Err(ProbeError::WorkerPanic))
    );
    joiner.join().unwrap();
    assert!(worker_done.load(std::sync::atomic::Ordering::Acquire));
  }

  #[test]
  fn configuration_bounds_workers_and_labels() {
    let base = ProbeConfig {
      variant: "baseline".to_owned(),
      rustc_version: "rustc 1.99.0".to_owned(),
      workers: 32,
      trace: Trace::Minimal,
      logical_cache_bytes_per_thread: None,
    };
    assert_eq!(validate_config(&base), Ok(()));
    let mut invalid = base.clone();
    invalid.workers = 0;
    assert_eq!(validate_config(&invalid), Err(ProbeError::InvalidConfig));
    invalid = base.clone();
    invalid.workers = MAX_WORKERS + 1;
    assert_eq!(validate_config(&invalid), Err(ProbeError::InvalidConfig));
    invalid = base;
    invalid.variant = "bad\nlabel".to_owned();
    assert_eq!(validate_config(&invalid), Err(ProbeError::InvalidConfig));
  }

  #[test]
  fn cli_requires_explicit_variant_build_metadata_and_trace() {
    let args = [
      "--variant".to_owned(),
      "word".to_owned(),
      "--rustc-version".to_owned(),
      "rustc 1.99.0".to_owned(),
      "--workers".to_owned(),
      "512".to_owned(),
      "--trace".to_owned(),
      "all-classes".to_owned(),
    ];
    let parsed = parse_args(args).unwrap();
    assert_eq!(parsed.variant, "word");
    assert_eq!(parsed.workers, 512);
    assert_eq!(parsed.trace, Trace::AllClasses);
    assert!(parse_args(["--workers".to_owned(), "1".to_owned()]).is_err());
  }

  #[test]
  fn output_rows_keep_fixed_schema_and_stage_counts() {
    let config = ProbeConfig {
      variant: "inverse".to_owned(),
      rustc_version: "rustc 1.99.0".to_owned(),
      workers: 32,
      trace: Trace::Minimal,
      logical_cache_bytes_per_thread: Some(6_008),
    };
    let sample = Rollup {
      rss_kib: 10,
      pss_kib: 9,
      private_clean_kib: 2,
      private_dirty_kib: 3,
      anonymous_kib: 5,
    };
    let mut output = Vec::new();
    write_rows(
      &mut output,
      &config,
      123_456,
      TRACE_ROUNDS,
      [
        (
          "warm",
          StageCounts {
            alive: 0,
            parked: 0,
            joined: 0,
          },
          sample,
          0,
        ),
        (
          "parked",
          StageCounts {
            alive: 32,
            parked: 32,
            joined: 0,
          },
          sample,
          99,
        ),
        (
          "after_join_purge",
          StageCounts {
            alive: 0,
            parked: 0,
            joined: 32,
          },
          sample,
          99,
        ),
      ],
    )
    .unwrap();
    let text = std::str::from_utf8(&output).unwrap();
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some(CSV_HEADER));
    let rows: Vec<&str> = lines.collect();
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|row| row.split(',').count() == 22));
    assert!(rows[0].contains(",warm,0,0,0,0,"));
    assert!(rows[1].contains(",parked,32,32,0,99,"));
    assert!(rows[2].contains(",after_join_purge,0,0,32,99,"));
  }
}
