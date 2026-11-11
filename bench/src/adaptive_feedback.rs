//! Bounded caller-side measurements for `runtime::adaptive::AdaptiveController`.
//!
//! This module is a bench adapter, not a runtime sensor or pressure governor.
//! It accepts an already-open cgroup v2 directory, opens only fixed sensor
//! names relative to that descriptor with `NOFOLLOW`, and never moves a task
//! or changes a cgroup control. A caller must use a leaf group and coordinate
//! its external writers. Sensor reads are ordered observations, not atomic
//! snapshots.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fs::File;
use std::io::Read;
use std::time::{Duration, Instant};

use allocatbelt::runtime::adaptive::FeedbackSample;
use allocatbelt::runtime::cgroup::{CgroupSnapshot, CpuMaxReadback, Limit};
use rustix::fd::OwnedFd;
use rustix::fs::{FileType, OFlags, fstat, openat};

pub const MAX_SENSOR_BYTES: usize = 16 * 1024;
pub const MAX_WINDOW_IDS: usize = 65_536;
const SENSOR_NAMES: [&str; 8] = [
  "cpu.stat",
  "memory.current",
  "memory.max",
  "memory.high",
  "memory.events.local",
  "cpu.pressure",
  "memory.pressure",
  "cpu.max",
];

fn sensor_limit(name: &str) -> usize {
  match name {
    "cpu.stat" | "memory.events.local" => MAX_SENSOR_BYTES,
    _ => 4 * 1024,
  }
}

fn append_bounded_chunk(prefix: &mut Vec<u8>, chunk: &[u8], limit: usize) -> usize {
  let available = limit.saturating_sub(prefix.len());
  let retained = chunk.len().min(available);
  prefix.extend_from_slice(&chunk[..retained]);
  chunk.len() - retained
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescriptorIdentity {
  /// Debug-formatted kernel device identity; retained without lossy casts.
  pub device: String,
  /// Debug-formatted inode number from `fstat`.
  pub inode: String,
  pub mode: String,
  pub uid: String,
  pub gid: String,
}

fn identity(fd: impl rustix::fd::AsFd) -> Result<DescriptorIdentity, IdentityError> {
  let stat = fstat(fd).map_err(|error| IdentityError {
    message: error.to_string(),
    native_errno: error.raw_os_error(),
  })?;
  Ok(DescriptorIdentity {
    device: format!("{:?}", stat.st_dev),
    inode: format!("{:?}", stat.st_ino),
    mode: format!("{:?}", stat.st_mode),
    uid: format!("{:?}", stat.st_uid),
    gid: format!("{:?}", stat.st_gid),
  })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SensorError {
  Io {
    error: String,
    native_errno: i32,
  },
  NotDirectory,
  Oversize {
    name: &'static str,
    limit: usize,
    raw_prefix: Vec<u8>,
    digest64: u64,
  },
  Parse {
    name: &'static str,
    reason: ParseError,
    raw_bytes: Vec<u8>,
    digest64: u64,
  },
  Partial(Box<PartialSensorCapture>),
  Missing {
    name: &'static str,
  },
  IdentityChanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IdentityError {
  message: String,
  native_errno: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialSensorCapture {
  pub group: DescriptorIdentity,
  pub started: Instant,
  pub failed_at: Instant,
  pub files: Vec<RawSensorFile>,
  pub failed_name: &'static str,
  pub raw_prefix: Vec<u8>,
  pub digest64: u64,
  pub observed_bytes: usize,
  pub error: String,
  pub error_kind: SensorFailureKind,
  pub native_errno: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorFailureKind {
  Open,
  Read,
  Stat,
  Oversize,
  Parse,
  IdentityChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
  InvalidUtf8,
  Empty,
  Malformed,
  DuplicateKey,
  MissingKey,
  Overflow,
  NonFiniteControl,
  CounterRegression,
  ZeroDenominator,
  ChangedControls,
  SafetyEvent,
  NoCompletedResponses,
  Conservation,
  Capacity,
  DuplicateId,
  InvalidTransition,
  NonMonotonicTime,
  ReadPointSkew,
  ChecksumMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSensorFile {
  pub name: &'static str,
  pub bytes: Vec<u8>,
  /// FNV-1a diagnostic digest. Exact bytes are retained; this digest is not
  /// an authentication primitive.
  pub digest64: u64,
  pub identity: DescriptorIdentity,
  /// Monotonic bracket around the file-content read; its midpoint is the
  /// representative counter observation and its width bounds uncertainty.
  pub read_started: Instant,
  pub read_finished: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuCounters {
  pub usage_usec: u64,
  pub nr_periods: u64,
  pub nr_throttled: u64,
  pub throttled_usec: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryEvents {
  pub high: u64,
  pub max: u64,
  pub oom: u64,
  pub oom_kill: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PsiLine {
  pub avg10: String,
  pub avg60: String,
  pub avg300: String,
  pub total_usec: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PsiCounters {
  pub some: PsiLine,
  pub full: PsiLine,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FiniteCpuMax {
  pub quota_us: u64,
  pub period_us: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedSensors {
  pub cpu: CpuCounters,
  pub memory_current: u64,
  pub memory_max: u64,
  pub memory_high: u64,
  pub events: MemoryEvents,
  pub cpu_psi: PsiCounters,
  pub memory_psi: PsiCounters,
  pub cpu_max: FiniteCpuMax,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorSnapshot {
  pub group: DescriptorIdentity,
  pub started: Instant,
  pub finished: Instant,
  pub files: Vec<RawSensorFile>,
  pub parsed: ParsedSensors,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafetyCounters {
  pub memory_max: u64,
  pub events: MemoryEvents,
}

impl SafetyCounters {
  pub fn from_snapshot(snapshot: &SensorSnapshot) -> Self {
    Self {
      memory_max: snapshot.parsed.memory_max,
      events: snapshot.parsed.events,
    }
  }

  /// Compares every observed boundary, including boundaries between feedback windows.
  pub fn check_next(
    &mut self,
    snapshot: &SensorSnapshot,
    original_memory_max: u64,
  ) -> Result<(), FeedbackUnavailable> {
    let next = Self::from_snapshot(snapshot);
    if self.memory_max != original_memory_max || next.memory_max != original_memory_max {
      self.memory_max = next.memory_max;
      self.events = next.events;
      return Err(FeedbackUnavailable::OriginalMemoryMax);
    }
    let safety_event = next.events.max > self.events.max
      || next.events.oom > self.events.oom
      || next.events.oom_kill > self.events.oom_kill;
    let monotonic = next.events.high >= self.events.high
      && next.events.max >= self.events.max
      && next.events.oom >= self.events.oom
      && next.events.oom_kill >= self.events.oom_kill;
    self.memory_max = next.memory_max;
    self.events = next.events;
    if safety_event {
      Err(FeedbackUnavailable::MemorySafetyEvent)
    } else if !monotonic {
      Err(FeedbackUnavailable::Sensor(ParseError::CounterRegression))
    } else {
      Ok(())
    }
  }
}

struct PartialSensorFailure {
  name: &'static str,
  raw_prefix: Vec<u8>,
  observed_bytes: usize,
  error_kind: SensorFailureKind,
  error: String,
  native_errno: Option<i32>,
}

/// Owns a duplicate or otherwise caller-provided group directory descriptor.
/// It never discovers a cgroup path or opens a mount/root.
pub struct SensorReader {
  directory: OwnedFd,
  group: DescriptorIdentity,
}

impl SensorReader {
  pub fn new(directory: OwnedFd) -> Result<Self, SensorError> {
    let stat = fstat(&directory).map_err(|error| SensorError::Io {
      error: error.to_string(),
      native_errno: error.raw_os_error(),
    })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
      return Err(SensorError::NotDirectory);
    }
    let group = identity(&directory).map_err(|error| SensorError::Io {
      error: error.message,
      native_errno: error.native_errno,
    })?;
    Ok(Self { directory, group })
  }

  pub fn read(&self) -> Result<SensorSnapshot, SensorError> {
    let started = Instant::now();
    let mut files = Vec::with_capacity(SENSOR_NAMES.len());
    for name in SENSOR_NAMES {
      let read_started = Instant::now();
      let fd = match openat(
        &self.directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
      ) {
        Ok(fd) => fd,
        Err(error) => {
          return Err(self.partial(
            started,
            files,
            PartialSensorFailure {
              name,
              raw_prefix: Vec::new(),
              observed_bytes: 0,
              error_kind: SensorFailureKind::Open,
              error: error.to_string(),
              native_errno: Some(error.raw_os_error()),
            },
          ));
        }
      };
      let mut file = File::from(fd);
      let file_identity = match identity(&file) {
        Ok(identity) => identity,
        Err(error) => {
          return Err(SensorError::Partial(Box::new(identity_failure_capture(
            self.group.clone(),
            started,
            files,
            name,
            Vec::new(),
            0,
            error,
          ))));
        }
      };
      let mut bytes = Vec::with_capacity(256);
      let mut observed_bytes = 0usize;
      let limit = sensor_limit(name);
      let mut chunk = [0u8; 1024];
      loop {
        let count = match file.read(&mut chunk) {
          Ok(count) => count,
          Err(error) => {
            let observed_bytes = bytes.len();
            return Err(self.partial(
              started,
              files,
              PartialSensorFailure {
                name,
                raw_prefix: bytes,
                observed_bytes,
                error_kind: SensorFailureKind::Read,
                error: error.to_string(),
                native_errno: error.raw_os_error(),
              },
            ));
          }
        };
        if count == 0 {
          break;
        }
        let Some(next_observed_bytes) = observed_bytes.checked_add(count) else {
          return Err(self.partial_with_observed(
            started,
            files,
            PartialSensorFailure {
              name,
              raw_prefix: bytes,
              observed_bytes: usize::MAX,
              error_kind: SensorFailureKind::Oversize,
              error: "oversize observed byte count overflow".into(),
              native_errno: None,
            },
          ));
        };
        let overflow = append_bounded_chunk(&mut bytes, &chunk[..count], limit);
        observed_bytes = next_observed_bytes;
        if overflow != 0 {
          let digest = digest64(&bytes);
          return Err(self.partial_with_observed(started, files, PartialSensorFailure {
            name, raw_prefix: bytes, observed_bytes, error_kind: SensorFailureKind::Oversize,
            error: format!("oversize limit={limit} observed_bytes={observed_bytes} overflow_bytes={overflow} digest64={digest:016x}"),
            native_errno: None,
          }));
        }
      }
      let read_finished = Instant::now();
      let after = match identity(&file) {
        Ok(identity) => identity,
        Err(error) => {
          return Err(SensorError::Partial(Box::new(identity_failure_capture(
            self.group.clone(),
            started,
            files,
            name,
            bytes.clone(),
            bytes.len(),
            error,
          ))));
        }
      };
      if after != file_identity {
        let observed_bytes = bytes.len();
        return Err(self.partial_with_observed(
          started,
          files,
          PartialSensorFailure {
            name,
            raw_prefix: bytes.clone(),
            observed_bytes,
            error_kind: SensorFailureKind::IdentityChanged,
            error: "file identity changed during read".into(),
            native_errno: None,
          },
        ));
      }
      files.push(RawSensorFile {
        name,
        digest64: digest64(&bytes),
        bytes,
        identity: file_identity,
        read_started,
        read_finished,
      });
    }
    let parsed = match parse_files(&files) {
      Ok(parsed) => parsed,
      Err(error) => {
        let (name, raw_prefix) = match &error {
          SensorError::Parse {
            name, raw_bytes, ..
          } => (*name, raw_bytes.clone()),
          SensorError::Missing { name } => (*name, Vec::new()),
          _ => ("<parse>", Vec::new()),
        };
        let observed_bytes = raw_prefix.len();
        return Err(self.partial(
          started,
          files,
          PartialSensorFailure {
            name,
            raw_prefix,
            observed_bytes,
            error_kind: SensorFailureKind::Parse,
            error: format!("{error:?}"),
            native_errno: None,
          },
        ));
      }
    };
    let finished = Instant::now();
    let group_after = match identity(&self.directory) {
      Ok(identity) => identity,
      Err(error) => {
        return Err(SensorError::Partial(Box::new(identity_failure_capture(
          self.group.clone(),
          started,
          files,
          "<directory>",
          Vec::new(),
          0,
          error,
        ))));
      }
    };
    if group_after != self.group {
      return Err(self.partial_with_observed(
        started,
        files,
        PartialSensorFailure {
          name: "<directory>",
          raw_prefix: Vec::new(),
          observed_bytes: 0,
          error_kind: SensorFailureKind::IdentityChanged,
          error: "group identity changed during read".into(),
          native_errno: None,
        },
      ));
    }
    Ok(SensorSnapshot {
      group: self.group.clone(),
      started,
      finished,
      files,
      parsed,
    })
  }

  fn partial(
    &self,
    started: Instant,
    files: Vec<RawSensorFile>,
    failure: PartialSensorFailure,
  ) -> SensorError {
    self.partial_with_observed(started, files, failure)
  }

  fn partial_with_observed(
    &self,
    started: Instant,
    files: Vec<RawSensorFile>,
    failure: PartialSensorFailure,
  ) -> SensorError {
    SensorError::Partial(Box::new(partial_capture(
      self.group.clone(),
      started,
      files,
      failure,
    )))
  }
}

fn partial_capture(
  group: DescriptorIdentity,
  started: Instant,
  files: Vec<RawSensorFile>,
  failure: PartialSensorFailure,
) -> PartialSensorCapture {
  let digest = digest64(&failure.raw_prefix);
  PartialSensorCapture {
    group,
    started,
    failed_at: Instant::now(),
    files,
    failed_name: failure.name,
    raw_prefix: failure.raw_prefix,
    digest64: digest,
    observed_bytes: failure.observed_bytes,
    error: failure.error,
    error_kind: failure.error_kind,
    native_errno: failure.native_errno,
  }
}

fn identity_failure_capture(
  group: DescriptorIdentity,
  started: Instant,
  files: Vec<RawSensorFile>,
  failed_name: &'static str,
  raw_prefix: Vec<u8>,
  observed_bytes: usize,
  error: IdentityError,
) -> PartialSensorCapture {
  partial_capture(
    group,
    started,
    files,
    PartialSensorFailure {
      name: failed_name,
      raw_prefix,
      observed_bytes,
      error_kind: SensorFailureKind::Stat,
      error: error.message,
      native_errno: Some(error.native_errno),
    },
  )
}

fn digest64(bytes: &[u8]) -> u64 {
  bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
    (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
  })
}

fn raw<'a>(files: &'a [RawSensorFile], name: &'static str) -> Result<&'a [u8], SensorError> {
  files
    .iter()
    .find(|file| file.name == name)
    .map(|file| file.bytes.as_slice())
    .ok_or(SensorError::Missing { name })
}

fn map_parse<T>(
  name: &'static str,
  bytes: &[u8],
  value: Result<T, ParseError>,
) -> Result<T, SensorError> {
  value.map_err(|reason| SensorError::Parse {
    name,
    reason,
    raw_bytes: bytes.to_vec(),
    digest64: digest64(bytes),
  })
}

fn parse_files(files: &[RawSensorFile]) -> Result<ParsedSensors, SensorError> {
  let cpu_stat = raw(files, "cpu.stat")?;
  let memory_current = raw(files, "memory.current")?;
  let memory_max = raw(files, "memory.max")?;
  let memory_high = raw(files, "memory.high")?;
  let memory_events = raw(files, "memory.events.local")?;
  let cpu_pressure = raw(files, "cpu.pressure")?;
  let memory_pressure = raw(files, "memory.pressure")?;
  let cpu_max = raw(files, "cpu.max")?;
  Ok(ParsedSensors {
    cpu: map_parse("cpu.stat", cpu_stat, parse_cpu_stat(cpu_stat))?,
    memory_current: map_parse(
      "memory.current",
      memory_current,
      parse_single_u64(memory_current),
    )?,
    memory_max: map_parse("memory.max", memory_max, parse_finite_memory(memory_max))?,
    memory_high: map_parse("memory.high", memory_high, parse_finite_memory(memory_high))?,
    events: map_parse(
      "memory.events.local",
      memory_events,
      parse_memory_events(memory_events),
    )?,
    cpu_psi: map_parse("cpu.pressure", cpu_pressure, parse_psi(cpu_pressure))?,
    memory_psi: map_parse(
      "memory.pressure",
      memory_pressure,
      parse_psi(memory_pressure),
    )?,
    cpu_max: map_parse("cpu.max", cpu_max, parse_cpu_max(cpu_max))?,
  })
}

fn text(bytes: &[u8]) -> Result<&str, ParseError> {
  std::str::from_utf8(bytes).map_err(|_| ParseError::InvalidUtf8)
}

fn parse_key_values(bytes: &[u8]) -> Result<Vec<(&str, u64)>, ParseError> {
  let input = text(bytes)?;
  let mut values = Vec::new();
  for line in input.lines() {
    let mut words = line.split_ascii_whitespace();
    let key = words.next().ok_or(ParseError::Malformed)?;
    let value = words.next().ok_or(ParseError::Malformed)?;
    if words.next().is_some() || values.iter().any(|(existing, _)| *existing == key) {
      return Err(if values.iter().any(|(existing, _)| *existing == key) {
        ParseError::DuplicateKey
      } else {
        ParseError::Malformed
      });
    }
    values.push((key, value.parse().map_err(|_| ParseError::Overflow)?));
  }
  if values.is_empty() {
    return Err(ParseError::Empty);
  }
  Ok(values)
}

fn required(values: &[(&str, u64)], key: &str) -> Result<u64, ParseError> {
  values
    .iter()
    .find(|(name, _)| *name == key)
    .map(|(_, value)| *value)
    .ok_or(ParseError::MissingKey)
}

pub fn parse_cpu_stat(bytes: &[u8]) -> Result<CpuCounters, ParseError> {
  let values = parse_key_values(bytes)?;
  Ok(CpuCounters {
    usage_usec: required(&values, "usage_usec")?,
    nr_periods: required(&values, "nr_periods")?,
    nr_throttled: required(&values, "nr_throttled")?,
    throttled_usec: required(&values, "throttled_usec")?,
  })
}

pub fn parse_memory_events(bytes: &[u8]) -> Result<MemoryEvents, ParseError> {
  let values = parse_key_values(bytes)?;
  Ok(MemoryEvents {
    high: required(&values, "high")?,
    max: required(&values, "max")?,
    oom: required(&values, "oom")?,
    oom_kill: required(&values, "oom_kill")?,
  })
}

pub fn parse_single_u64(bytes: &[u8]) -> Result<u64, ParseError> {
  let input = text(bytes)?.trim();
  if input.is_empty() {
    return Err(ParseError::Empty);
  }
  if input.split_ascii_whitespace().count() != 1 {
    return Err(ParseError::Malformed);
  }
  input.parse().map_err(|_| ParseError::Overflow)
}

fn parse_finite_memory(bytes: &[u8]) -> Result<u64, ParseError> {
  if text(bytes)?.trim() == "max" {
    return Err(ParseError::NonFiniteControl);
  }
  parse_single_u64(bytes)
}

pub fn parse_cpu_max(bytes: &[u8]) -> Result<FiniteCpuMax, ParseError> {
  let input = text(bytes)?;
  let mut fields = input.split_ascii_whitespace();
  let quota = fields.next().ok_or(ParseError::Empty)?;
  let period = fields.next().ok_or(ParseError::MissingKey)?;
  if fields.next().is_some() {
    return Err(ParseError::Malformed);
  }
  if quota == "max" {
    return Err(ParseError::NonFiniteControl);
  }
  let quota_us = quota.parse().map_err(|_| ParseError::Overflow)?;
  let period_us = period.parse().map_err(|_| ParseError::Overflow)?;
  if quota_us == 0 || period_us == 0 {
    return Err(ParseError::ZeroDenominator);
  }
  Ok(FiniteCpuMax {
    quota_us,
    period_us,
  })
}

fn parse_avg(value: &str) -> Result<String, ParseError> {
  let mut pieces = value.split('.');
  let integer = pieces.next().ok_or(ParseError::Malformed)?;
  if integer.is_empty() || !integer.bytes().all(|byte| byte.is_ascii_digit()) {
    return Err(ParseError::Malformed);
  }
  if let Some(fraction) = pieces.next()
    && (fraction.is_empty()
      || !fraction.bytes().all(|byte| byte.is_ascii_digit())
      || pieces.next().is_some())
  {
    return Err(ParseError::Malformed);
  }
  Ok(value.to_owned())
}

pub fn parse_psi(bytes: &[u8]) -> Result<PsiCounters, ParseError> {
  let input = text(bytes)?;
  let mut some = None;
  let mut full = None;
  for line in input.lines() {
    let mut words = line.split_ascii_whitespace();
    let category = words.next().ok_or(ParseError::Malformed)?;
    let mut avg10 = None;
    let mut avg60 = None;
    let mut avg300 = None;
    let mut total = None;
    for field in words {
      let (key, value) = field.split_once('=').ok_or(ParseError::Malformed)?;
      let slot = match key {
        "avg10" => &mut avg10,
        "avg60" => &mut avg60,
        "avg300" => &mut avg300,
        "total" => &mut total,
        _ => return Err(ParseError::Malformed),
      };
      if slot.is_some() {
        return Err(ParseError::DuplicateKey);
      }
      *slot = Some(value);
    }
    let parsed = PsiLine {
      avg10: parse_avg(avg10.ok_or(ParseError::MissingKey)?)?,
      avg60: parse_avg(avg60.ok_or(ParseError::MissingKey)?)?,
      avg300: parse_avg(avg300.ok_or(ParseError::MissingKey)?)?,
      total_usec: total
        .ok_or(ParseError::MissingKey)?
        .parse()
        .map_err(|_| ParseError::Overflow)?,
    };
    let target = match category {
      "some" => &mut some,
      "full" => &mut full,
      _ => return Err(ParseError::Malformed),
    };
    if target.replace(parsed).is_some() {
      return Err(ParseError::DuplicateKey);
    }
  }
  Ok(PsiCounters {
    some: some.ok_or(ParseError::MissingKey)?,
    full: full.ok_or(ParseError::MissingKey)?,
  })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowCpu {
  pub raw_basis_points: u128,
  pub controller_basis_points: u16,
  pub saturated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowPsi {
  pub cpu_some_delta_usec: u64,
  pub cpu_full_delta_usec: u64,
  pub memory_some_delta_usec: u64,
  pub memory_full_delta_usec: u64,
  pub cpu_some_stall_basis_points: u128,
  pub cpu_full_stall_basis_points: u128,
  pub memory_some_stall_basis_points: u128,
  pub memory_full_stall_basis_points: u128,
  pub cpu_elapsed_ns: u128,
  pub cpu_uncertainty_bound_ns: u128,
  pub memory_elapsed_ns: u128,
  pub memory_uncertainty_bound_ns: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LatencySummary {
  pub completed: usize,
  pub p50_ns: u64,
  pub p95_ns: u64,
  pub p99_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackUnavailable {
  NoCompletedResponses,
  ObserverDelay,
  Sensor(ParseError),
  ChangedGroup,
  ChangedControls,
  OriginalMemoryMax,
  MemorySafetyEvent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowFeedback {
  pub sample: FeedbackSample,
  pub cpu: WindowCpu,
  pub memory_raw_basis_points: u128,
  pub psi: WindowPsi,
  pub cpu_elapsed_ns: u128,
  pub cpu_elapsed_usec: u128,
  pub cpu_uncertainty_bound_ns: u128,
  pub memory_current: u64,
  pub original_memory_max: u64,
  pub memory_high: u64,
  pub memory_high_event_delta: u64,
  pub latency: LatencySummary,
}

fn delta(end: u64, start: u64) -> Result<u64, ParseError> {
  end.checked_sub(start).ok_or(ParseError::CounterRegression)
}

fn psi_stall_bp(delta_usec: u64, elapsed_usec: u128) -> Result<u128, ParseError> {
  u128::from(delta_usec)
    .checked_mul(10_000)
    .ok_or(ParseError::Overflow)
    .map(|value| value / elapsed_usec)
}

const MAX_READ_POINT_UNCERTAINTY_NS: u128 = 10_000_000;

fn read_point_elapsed(
  start: &SensorSnapshot,
  end: &SensorSnapshot,
  name: &'static str,
) -> Result<(u128, u128), ParseError> {
  let start_file = start
    .files
    .iter()
    .find(|file| file.name == name)
    .ok_or(ParseError::MissingKey)?;
  let end_file = end
    .files
    .iter()
    .find(|file| file.name == name)
    .ok_or(ParseError::MissingKey)?;
  let start_span = start_file
    .read_finished
    .checked_duration_since(start_file.read_started)
    .ok_or(ParseError::NonMonotonicTime)?;
  let end_span = end_file
    .read_finished
    .checked_duration_since(end_file.read_started)
    .ok_or(ParseError::NonMonotonicTime)?;
  let start_midpoint = start_file
    .read_started
    .checked_add(start_span / 2)
    .ok_or(ParseError::Overflow)?;
  let end_midpoint = end_file
    .read_started
    .checked_add(end_span / 2)
    .ok_or(ParseError::Overflow)?;
  let elapsed_ns = end_midpoint
    .checked_duration_since(start_midpoint)
    .ok_or(ParseError::NonMonotonicTime)?
    .as_nanos();
  let uncertainty_bound_ns = start_span
    .as_nanos()
    .checked_add(end_span.as_nanos())
    .ok_or(ParseError::Overflow)?;
  if uncertainty_bound_ns > MAX_READ_POINT_UNCERTAINTY_NS {
    return Err(ParseError::ReadPointSkew);
  }
  if elapsed_ns == 0 {
    return Err(ParseError::ZeroDenominator);
  }
  Ok((elapsed_ns, uncertainty_bound_ns))
}

pub fn quota_cpu_basis_points(
  delta_usage_usec: u64,
  elapsed_usec: u128,
  quota_us: u64,
  period_us: u64,
) -> Result<WindowCpu, ParseError> {
  if elapsed_usec == 0 || quota_us == 0 || period_us == 0 {
    return Err(ParseError::ZeroDenominator);
  }
  let numerator = u128::from(delta_usage_usec)
    .checked_mul(u128::from(period_us))
    .and_then(|value| value.checked_mul(10_000))
    .ok_or(ParseError::Overflow)?;
  let denominator = elapsed_usec
    .checked_mul(u128::from(quota_us))
    .ok_or(ParseError::Overflow)?;
  let raw_basis_points = numerator / denominator;
  let saturated = raw_basis_points > 10_000;
  Ok(WindowCpu {
    raw_basis_points,
    controller_basis_points: raw_basis_points.min(10_000) as u16,
    saturated,
  })
}

pub fn fixed_max_memory_basis_points(current: u64, original_max: u64) -> Result<u128, ParseError> {
  if original_max == 0 {
    return Err(ParseError::ZeroDenominator);
  }
  u128::from(current)
    .checked_mul(10_000)
    .ok_or(ParseError::Overflow)
    .map(|value| value / u128::from(original_max))
}

fn nearest_rank(values: &[u64], percentile: u128) -> Result<u64, ParseError> {
  if values.is_empty() {
    return Err(ParseError::NoCompletedResponses);
  }
  let n = values.len() as u128;
  let rank = percentile
    .checked_mul(n)
    .ok_or(ParseError::Overflow)?
    .div_ceil(100)
    .max(1);
  let index = usize::try_from(rank - 1).map_err(|_| ParseError::Overflow)?;
  values.get(index).copied().ok_or(ParseError::Overflow)
}

pub fn latency_summary(samples: &[u64]) -> Result<LatencySummary, ParseError> {
  if samples.is_empty() {
    return Err(ParseError::NoCompletedResponses);
  }
  let mut ordered = samples.to_vec();
  ordered.sort_unstable();
  Ok(LatencySummary {
    completed: ordered.len(),
    p50_ns: nearest_rank(&ordered, 50)?,
    p95_ns: nearest_rank(&ordered, 95)?,
    p99_ns: nearest_rank(&ordered, 99)?,
  })
}

fn finite_cpu(readback: CpuMaxReadback) -> Result<FiniteCpuMax, FeedbackUnavailable> {
  match readback.quota_us {
    Limit::Value(quota_us) if quota_us > 0 && readback.period_us > 0 => Ok(FiniteCpuMax {
      quota_us,
      period_us: readback.period_us,
    }),
    _ => Err(FeedbackUnavailable::Sensor(ParseError::NonFiniteControl)),
  }
}

pub fn feedback_for_window(
  start: &SensorSnapshot,
  end: &SensorSnapshot,
  controls_start: &CgroupSnapshot,
  controls_end: &CgroupSnapshot,
  original_memory_max: u64,
  completed_latencies_ns: &[u64],
) -> Result<WindowFeedback, FeedbackUnavailable> {
  if start.group != end.group {
    return Err(FeedbackUnavailable::ChangedGroup);
  }
  if controls_start.cpu_max != controls_end.cpu_max
    || controls_start.memory_high != controls_end.memory_high
    || controls_start.memory_max != controls_end.memory_max
    || start.parsed.cpu_max != end.parsed.cpu_max
    || start.parsed.memory_high != end.parsed.memory_high
    || start.parsed.memory_max != end.parsed.memory_max
  {
    return Err(FeedbackUnavailable::ChangedControls);
  }
  if controls_start.memory_max != Limit::Value(original_memory_max)
    || controls_end.memory_max != Limit::Value(original_memory_max)
    || start.parsed.memory_max != original_memory_max
    || end.parsed.memory_max != original_memory_max
  {
    return Err(FeedbackUnavailable::OriginalMemoryMax);
  }
  if end.parsed.events.max > start.parsed.events.max
    || end.parsed.events.oom > start.parsed.events.oom
    || end.parsed.events.oom_kill > start.parsed.events.oom_kill
  {
    return Err(FeedbackUnavailable::MemorySafetyEvent);
  }
  if completed_latencies_ns.is_empty() {
    return Err(FeedbackUnavailable::NoCompletedResponses);
  }
  let cpu = finite_cpu(controls_start.cpu_max)?;
  if start.parsed.cpu_max.quota_us != cpu.quota_us
    || start.parsed.cpu_max.period_us != cpu.period_us
    || end.parsed.cpu_max.quota_us != cpu.quota_us
    || end.parsed.cpu_max.period_us != cpu.period_us
    || controls_start.memory_max != Limit::Value(start.parsed.memory_max)
    || controls_end.memory_max != Limit::Value(end.parsed.memory_max)
    || controls_start.memory_high != Limit::Value(start.parsed.memory_high)
    || controls_end.memory_high != Limit::Value(end.parsed.memory_high)
  {
    return Err(FeedbackUnavailable::ChangedControls);
  }
  let (elapsed_ns, cpu_uncertainty_bound_ns) =
    read_point_elapsed(start, end, "cpu.stat").map_err(FeedbackUnavailable::Sensor)?;
  let elapsed_usec = elapsed_ns / 1_000;
  if elapsed_usec == 0 {
    return Err(FeedbackUnavailable::Sensor(ParseError::ZeroDenominator));
  }
  let cpu_delta = delta(end.parsed.cpu.usage_usec, start.parsed.cpu.usage_usec)
    .map_err(FeedbackUnavailable::Sensor)?;
  for (after, before) in [
    (end.parsed.cpu.nr_periods, start.parsed.cpu.nr_periods),
    (end.parsed.cpu.nr_throttled, start.parsed.cpu.nr_throttled),
    (
      end.parsed.cpu.throttled_usec,
      start.parsed.cpu.throttled_usec,
    ),
    (end.parsed.events.high, start.parsed.events.high),
    (end.parsed.events.max, start.parsed.events.max),
    (end.parsed.events.oom, start.parsed.events.oom),
    (end.parsed.events.oom_kill, start.parsed.events.oom_kill),
    (
      end.parsed.cpu_psi.some.total_usec,
      start.parsed.cpu_psi.some.total_usec,
    ),
    (
      end.parsed.cpu_psi.full.total_usec,
      start.parsed.cpu_psi.full.total_usec,
    ),
    (
      end.parsed.memory_psi.some.total_usec,
      start.parsed.memory_psi.some.total_usec,
    ),
    (
      end.parsed.memory_psi.full.total_usec,
      start.parsed.memory_psi.full.total_usec,
    ),
  ] {
    delta(after, before).map_err(FeedbackUnavailable::Sensor)?;
  }
  let cpu = quota_cpu_basis_points(cpu_delta, elapsed_usec, cpu.quota_us, cpu.period_us)
    .map_err(FeedbackUnavailable::Sensor)?;
  let memory_raw_basis_points =
    fixed_max_memory_basis_points(end.parsed.memory_current, original_memory_max)
      .map_err(FeedbackUnavailable::Sensor)?;
  if memory_raw_basis_points > 10_000 {
    return Err(FeedbackUnavailable::MemorySafetyEvent);
  }
  let cpu_some = delta(
    end.parsed.cpu_psi.some.total_usec,
    start.parsed.cpu_psi.some.total_usec,
  )
  .map_err(FeedbackUnavailable::Sensor)?;
  let cpu_full = delta(
    end.parsed.cpu_psi.full.total_usec,
    start.parsed.cpu_psi.full.total_usec,
  )
  .map_err(FeedbackUnavailable::Sensor)?;
  let memory_some = delta(
    end.parsed.memory_psi.some.total_usec,
    start.parsed.memory_psi.some.total_usec,
  )
  .map_err(FeedbackUnavailable::Sensor)?;
  let memory_full = delta(
    end.parsed.memory_psi.full.total_usec,
    start.parsed.memory_psi.full.total_usec,
  )
  .map_err(FeedbackUnavailable::Sensor)?;
  let (cpu_psi_elapsed_ns, cpu_psi_uncertainty_bound_ns) =
    read_point_elapsed(start, end, "cpu.pressure").map_err(FeedbackUnavailable::Sensor)?;
  let (memory_psi_elapsed_ns, memory_psi_uncertainty_bound_ns) =
    read_point_elapsed(start, end, "memory.pressure").map_err(FeedbackUnavailable::Sensor)?;
  let cpu_psi_elapsed_usec = cpu_psi_elapsed_ns / 1_000;
  let memory_psi_elapsed_usec = memory_psi_elapsed_ns / 1_000;
  if cpu_psi_elapsed_usec == 0 || memory_psi_elapsed_usec == 0 {
    return Err(FeedbackUnavailable::Sensor(ParseError::ZeroDenominator));
  }
  let psi = WindowPsi {
    cpu_some_delta_usec: cpu_some,
    cpu_full_delta_usec: cpu_full,
    memory_some_delta_usec: memory_some,
    memory_full_delta_usec: memory_full,
    cpu_some_stall_basis_points: psi_stall_bp(cpu_some, cpu_psi_elapsed_usec)
      .map_err(FeedbackUnavailable::Sensor)?,
    cpu_full_stall_basis_points: psi_stall_bp(cpu_full, cpu_psi_elapsed_usec)
      .map_err(FeedbackUnavailable::Sensor)?,
    memory_some_stall_basis_points: psi_stall_bp(memory_some, memory_psi_elapsed_usec)
      .map_err(FeedbackUnavailable::Sensor)?,
    memory_full_stall_basis_points: psi_stall_bp(memory_full, memory_psi_elapsed_usec)
      .map_err(FeedbackUnavailable::Sensor)?,
    cpu_elapsed_ns: cpu_psi_elapsed_ns,
    cpu_uncertainty_bound_ns: cpu_psi_uncertainty_bound_ns,
    memory_elapsed_ns: memory_psi_elapsed_ns,
    memory_uncertainty_bound_ns: memory_psi_uncertainty_bound_ns,
  };
  let latency = latency_summary(completed_latencies_ns).map_err(FeedbackUnavailable::Sensor)?;
  let p99_ns = latency.p99_ns;
  let memory_bp = u16::try_from(memory_raw_basis_points)
    .map_err(|_| FeedbackUnavailable::Sensor(ParseError::Overflow))?;
  Ok(WindowFeedback {
    sample: FeedbackSample {
      at: end.finished,
      p99: Duration::from_nanos(p99_ns),
      cpu_basis_points: cpu.controller_basis_points,
      memory_basis_points: memory_bp,
    },
    cpu,
    memory_raw_basis_points,
    psi,
    cpu_elapsed_ns: elapsed_ns,
    cpu_elapsed_usec: elapsed_usec,
    cpu_uncertainty_bound_ns,
    memory_current: end.parsed.memory_current,
    original_memory_max,
    memory_high: end.parsed.memory_high,
    memory_high_event_delta: end.parsed.events.high - start.parsed.events.high,
    latency,
  })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
  Offered,
  Pending,
  RejectedFull,
  RejectedResource,
  Completed,
  Error,
  Cancelled,
}

#[derive(Clone, Debug)]
struct DispatchCommitment {
  source_seal_ns: u64,
  commit_ns: u64,
  ack_ns: Option<u64>,
}

#[derive(Clone, Debug)]
struct WorkItem {
  id: u64,
  offered_epoch: u64,
  dispatch: Option<DispatchCommitment>,
  scheduled_ns: u64,
  offered_ns: Option<u64>,
  expected_checksum: u64,
  attempted_ns: Option<u64>,
  admitted_ns: Option<u64>,
  started_ns: Option<u64>,
  finished_ns: Option<u64>,
  disposition: Disposition,
  attempted_epoch: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Conservation {
  pub offered: usize,
  pub attempted: usize,
  pub not_attempted: usize,
  pub rejected_full: usize,
  pub rejected_resource: usize,
  pub accepted: usize,
  pub completed: usize,
  pub errors: usize,
  pub cancelled: usize,
  pub pending_before: usize,
  pub pending_after: usize,
  pub delayed_unattempted: usize,
  pub attempt_pending: usize,
  pub checksum: u64,
  pub expected_checksum: u64,
  pub producer_lateness_mean_ns: u64,
  pub producer_lateness_max_ns: u64,
  pub items: Vec<ItemChronology>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemChronology {
  pub id: u64,
  pub offered_epoch: u64,
  pub source_seal_ns: Option<u64>,
  pub commit_ns: Option<u64>,
  pub dispatch_ack_ns: Option<u64>,
  pub scheduled_ns: u64,
  pub offered_ns: Option<u64>,
  pub attempted_ns: Option<u64>,
  pub admitted_ns: Option<u64>,
  pub started_ns: Option<u64>,
  pub finished_ns: Option<u64>,
  pub disposition: Disposition,
}

pub struct WindowLedger {
  entries: Vec<WorkItem>,
  max_ids: usize,
  epoch: u64,
  active: bool,
  offers_sealed: bool,
  offer_seal_source_ns: Option<u64>,
  offer_commit_ns: Option<u64>,
  dispatch_ack_ns: Option<u64>,
  accepted: usize,
  completed: usize,
  errors: usize,
  cancelled: usize,
  pending_before: usize,
  checksum: u64,
  expected_checksum: u64,
  latencies_ns: Vec<u64>,
}

impl WindowLedger {
  pub fn new(max_ids: usize) -> Result<Self, ParseError> {
    if max_ids == 0 || max_ids > MAX_WINDOW_IDS {
      return Err(ParseError::Capacity);
    }
    Ok(Self {
      entries: Vec::with_capacity(max_ids),
      max_ids,
      epoch: 0,
      active: false,
      offers_sealed: false,
      offer_seal_source_ns: None,
      offer_commit_ns: None,
      dispatch_ack_ns: None,
      accepted: 0,
      completed: 0,
      errors: 0,
      cancelled: 0,
      pending_before: 0,
      checksum: 0,
      expected_checksum: 0,
      latencies_ns: Vec::with_capacity(max_ids),
    })
  }

  pub fn begin_window(&mut self) -> Result<(), ParseError> {
    if self.active {
      return Err(ParseError::InvalidTransition);
    }
    self.epoch = self.epoch.checked_add(1).ok_or(ParseError::Overflow)?;
    self.active = true;
    self.offers_sealed = false;
    self.offer_seal_source_ns = None;
    self.offer_commit_ns = None;
    self.dispatch_ack_ns = None;
    self.accepted = 0;
    self.completed = 0;
    self.errors = 0;
    self.cancelled = 0;
    self.pending_before = self
      .entries
      .iter()
      .filter(|item| item.disposition == Disposition::Pending)
      .count();
    self.checksum = 0;
    self.expected_checksum = 0;
    self.latencies_ns.clear();
    Ok(())
  }

  pub fn offer(
    &mut self,
    id: u64,
    scheduled_ns: u64,
    expected_checksum: u64,
  ) -> Result<(), ParseError> {
    if !self.active || self.offers_sealed {
      return Err(ParseError::InvalidTransition);
    }
    if self.entries.len() == self.max_ids {
      return Err(ParseError::Capacity);
    }
    if self.entries.iter().any(|item| item.id == id) {
      return Err(ParseError::DuplicateId);
    }
    self.entries.push(WorkItem {
      id,
      offered_epoch: self.epoch,
      dispatch: None,
      scheduled_ns,
      offered_ns: None,
      expected_checksum,
      attempted_ns: None,
      admitted_ns: None,
      started_ns: None,
      finished_ns: None,
      disposition: Disposition::Offered,
      attempted_epoch: None,
    });
    Ok(())
  }

  pub fn seal_offers(&mut self, source_ns: u64, commit_ns: u64) -> Result<(), ParseError> {
    if !self.active || self.offers_sealed {
      return Err(ParseError::InvalidTransition);
    }
    if commit_ns < source_ns
      || self
        .entries
        .iter()
        .any(|item| item.offered_epoch == self.epoch && item.scheduled_ns < source_ns)
    {
      return Err(ParseError::NonMonotonicTime);
    }
    self.offers_sealed = true;
    self.offer_seal_source_ns = Some(source_ns);
    self.offer_commit_ns = Some(commit_ns);
    for item in self
      .entries
      .iter_mut()
      .filter(|item| item.offered_epoch == self.epoch)
    {
      if item.dispatch.is_some() {
        return Err(ParseError::InvalidTransition);
      }
      item.dispatch = Some(DispatchCommitment {
        source_seal_ns: source_ns,
        commit_ns,
        ack_ns: None,
      });
    }
    Ok(())
  }

  pub fn acknowledge_offers(&mut self, ack_ns: u64) -> Result<(), ParseError> {
    if !self.active || !self.offers_sealed || self.dispatch_ack_ns.is_some() {
      return Err(ParseError::InvalidTransition);
    }
    let source_ns = self
      .offer_seal_source_ns
      .ok_or(ParseError::InvalidTransition)?;
    let commit_ns = self.offer_commit_ns.ok_or(ParseError::InvalidTransition)?;
    if ack_ns < source_ns || ack_ns < commit_ns {
      return Err(ParseError::NonMonotonicTime);
    }
    self.dispatch_ack_ns = Some(ack_ns);
    for item in self
      .entries
      .iter_mut()
      .filter(|item| item.offered_epoch == self.epoch)
    {
      let dispatch = item
        .dispatch
        .as_mut()
        .ok_or(ParseError::InvalidTransition)?;
      if dispatch.ack_ns.is_some() {
        return Err(ParseError::InvalidTransition);
      }
      dispatch.ack_ns = Some(ack_ns);
    }
    Ok(())
  }

  fn check_dispatch_time(&self, id: u64, at_ns: u64) -> Result<(), ParseError> {
    let index = self.item_index(id)?;
    let watermark = self.entries[index]
      .dispatch
      .as_ref()
      .and_then(|dispatch| dispatch.ack_ns)
      .ok_or(ParseError::InvalidTransition)?;
    if at_ns < watermark {
      return Err(ParseError::NonMonotonicTime);
    }
    Ok(())
  }

  pub fn arrived(&mut self, id: u64, at_ns: u64) -> Result<(), ParseError> {
    if !self.active || !self.offers_sealed {
      return Err(ParseError::InvalidTransition);
    }
    self.check_dispatch_time(id, at_ns)?;
    let index = self.item_index(id)?;
    let item = &mut self.entries[index];
    if item.disposition != Disposition::Offered
      || item.offered_ns.is_some()
      || at_ns < item.scheduled_ns
    {
      return Err(ParseError::InvalidTransition);
    }
    item.offered_ns = Some(at_ns);
    Ok(())
  }

  fn item_index(&self, id: u64) -> Result<usize, ParseError> {
    self
      .entries
      .iter()
      .position(|item| item.id == id)
      .ok_or(ParseError::InvalidTransition)
  }

  pub fn attempt(&mut self, id: u64, at_ns: u64) -> Result<u64, ParseError> {
    if !self.active || !self.offers_sealed {
      return Err(ParseError::InvalidTransition);
    }
    self.check_dispatch_time(id, at_ns)?;
    let epoch = self.epoch;
    let index = self.item_index(id)?;
    let lateness = {
      let item = &mut self.entries[index];
      if item.disposition != Disposition::Offered || item.attempted_ns.is_some() {
        return Err(ParseError::InvalidTransition);
      }
      let offered_ns = item.offered_ns.ok_or(ParseError::InvalidTransition)?;
      if at_ns < offered_ns {
        return Err(ParseError::NonMonotonicTime);
      }
      let lateness = at_ns
        .checked_sub(item.scheduled_ns)
        .ok_or(ParseError::NonMonotonicTime)?;
      item.attempted_ns = Some(at_ns);
      item.attempted_epoch = Some(epoch);
      lateness
    };
    Ok(lateness)
  }

  pub fn accept(&mut self, id: u64, admitted_ns: u64) -> Result<(), ParseError> {
    if !self.active || !self.offers_sealed {
      return Err(ParseError::InvalidTransition);
    }
    self.check_dispatch_time(id, admitted_ns)?;
    let index = self.item_index(id)?;
    {
      let item = &mut self.entries[index];
      let attempted = item.attempted_ns.ok_or(ParseError::InvalidTransition)?;
      if item.disposition != Disposition::Offered || admitted_ns < attempted {
        return Err(ParseError::InvalidTransition);
      }
      item.admitted_ns = Some(admitted_ns);
      item.disposition = Disposition::Pending;
    }
    self.accepted += 1;
    Ok(())
  }

  pub fn reject(&mut self, id: u64, kind: Disposition, at_ns: u64) -> Result<(), ParseError> {
    if !self.active || !self.offers_sealed {
      return Err(ParseError::InvalidTransition);
    }
    self.check_dispatch_time(id, at_ns)?;
    if !matches!(
      kind,
      Disposition::RejectedFull | Disposition::RejectedResource
    ) {
      return Err(ParseError::InvalidTransition);
    }
    let index = self.item_index(id)?;
    {
      let item = &mut self.entries[index];
      if item.disposition != Disposition::Offered {
        return Err(ParseError::InvalidTransition);
      }
      let offered_ns = item.offered_ns.ok_or(ParseError::InvalidTransition)?;
      if let Some(attempted) = item.attempted_ns {
        if at_ns < attempted {
          return Err(ParseError::NonMonotonicTime);
        }
      } else {
        at_ns
          .checked_sub(offered_ns)
          .ok_or(ParseError::NonMonotonicTime)?;
        item.attempted_ns = Some(at_ns);
        item.attempted_epoch = Some(self.epoch);
      }
      item.disposition = kind;
    }
    Ok(())
  }

  pub fn started(&mut self, id: u64, at_ns: u64) -> Result<(), ParseError> {
    if !self.active || !self.offers_sealed {
      return Err(ParseError::InvalidTransition);
    }
    self.check_dispatch_time(id, at_ns)?;
    let index = self.item_index(id)?;
    let item = &mut self.entries[index];
    let admitted = item.admitted_ns.ok_or(ParseError::InvalidTransition)?;
    if item.disposition != Disposition::Pending || item.started_ns.is_some() || at_ns < admitted {
      return Err(ParseError::InvalidTransition);
    }
    item.started_ns = Some(at_ns);
    Ok(())
  }

  pub fn complete(&mut self, id: u64, finished_ns: u64, checksum: u64) -> Result<(), ParseError> {
    if !self.active || !self.offers_sealed {
      return Err(ParseError::InvalidTransition);
    }
    self.check_dispatch_time(id, finished_ns)?;
    let index = self.item_index(id)?;
    let (scheduled_ns, started_ns, expected_checksum) = {
      let item = &self.entries[index];
      (
        item.scheduled_ns,
        item.started_ns.ok_or(ParseError::InvalidTransition)?,
        item.expected_checksum,
      )
    };
    if self.latencies_ns.len() == self.max_ids {
      return Err(ParseError::Capacity);
    }
    let latency = finished_ns
      .checked_sub(scheduled_ns)
      .ok_or(ParseError::NonMonotonicTime)?;
    let matches = checksum == expected_checksum;
    {
      let item = &mut self.entries[index];
      if item.disposition != Disposition::Pending
        || finished_ns < started_ns
        || finished_ns < scheduled_ns
      {
        return Err(ParseError::InvalidTransition);
      }
      item.finished_ns = Some(finished_ns);
      item.disposition = if matches {
        Disposition::Completed
      } else {
        Disposition::Error
      };
    }
    self.expected_checksum ^= expected_checksum;
    self.checksum ^= checksum;
    if !matches {
      self.errors += 1;
      return Err(ParseError::ChecksumMismatch);
    }
    self.latencies_ns.push(latency);
    self.completed += 1;
    Ok(())
  }

  pub fn fail(&mut self, id: u64, at_ns: u64, cancelled: bool) -> Result<(), ParseError> {
    if !self.active || !self.offers_sealed {
      return Err(ParseError::InvalidTransition);
    }
    self.check_dispatch_time(id, at_ns)?;
    let index = self.item_index(id)?;
    {
      let item = &mut self.entries[index];
      if item.disposition != Disposition::Pending {
        return Err(ParseError::InvalidTransition);
      }
      let admitted_ns = item.admitted_ns.ok_or(ParseError::InvalidTransition)?;
      if item.started_ns.is_some_and(|started_ns| at_ns < started_ns) {
        return Err(ParseError::NonMonotonicTime);
      }
      if at_ns < admitted_ns {
        return Err(ParseError::InvalidTransition);
      }
      item.finished_ns = Some(at_ns);
      item.disposition = if cancelled {
        Disposition::Cancelled
      } else {
        Disposition::Error
      };
    }
    if cancelled {
      self.cancelled += 1;
    } else {
      self.errors += 1;
    }
    Ok(())
  }

  pub fn disposition(&self, id: u64) -> Option<Disposition> {
    self
      .entries
      .iter()
      .find(|item| item.id == id)
      .map(|item| item.disposition)
  }

  pub fn latencies_ns(&self) -> &[u64] {
    &self.latencies_ns
  }

  pub fn conservation(&self) -> Result<Conservation, ParseError> {
    let pending_after = self
      .entries
      .iter()
      .filter(|item| item.disposition == Disposition::Pending)
      .count();
    let not_attempted = self
      .entries
      .iter()
      .filter(|item| item.attempted_ns.is_none())
      .count();
    let delayed_unattempted = not_attempted;
    let attempt_pending = self
      .entries
      .iter()
      .filter(|item| item.disposition == Disposition::Offered && item.attempted_ns.is_some())
      .count();
    let offered = self.entries.len();
    let attempted = self
      .entries
      .iter()
      .filter(|item| item.attempted_ns.is_some())
      .count();
    let rejected_full = self
      .entries
      .iter()
      .filter(|item| item.disposition == Disposition::RejectedFull)
      .count();
    let rejected_resource = self
      .entries
      .iter()
      .filter(|item| item.disposition == Disposition::RejectedResource)
      .count();
    let accepted = self
      .entries
      .iter()
      .filter(|item| item.admitted_ns.is_some())
      .count();
    if offered != not_attempted + rejected_full + rejected_resource + accepted + attempt_pending {
      return Err(ParseError::Conservation);
    }
    let mut lateness_total = 0u128;
    let mut lateness_max = 0u64;
    let mut lateness_count = 0u128;
    for item in self
      .entries
      .iter()
      .filter(|item| item.attempted_epoch == Some(self.epoch))
    {
      let attempted = item.attempted_ns.ok_or(ParseError::NonMonotonicTime)?;
      let lateness = attempted
        .checked_sub(item.scheduled_ns)
        .ok_or(ParseError::NonMonotonicTime)?;
      lateness_total = lateness_total
        .checked_add(u128::from(lateness))
        .ok_or(ParseError::Overflow)?;
      lateness_count += 1;
      lateness_max = lateness_max.max(lateness);
    }
    let current_terminal = self.completed + self.errors + self.cancelled;
    if self.accepted.checked_add(self.pending_before) != current_terminal.checked_add(pending_after)
    {
      return Err(ParseError::Conservation);
    }
    let items = self
      .entries
      .iter()
      .map(|item| ItemChronology {
        id: item.id,
        offered_epoch: item.offered_epoch,
        source_seal_ns: item
          .dispatch
          .as_ref()
          .map(|dispatch| dispatch.source_seal_ns),
        commit_ns: item.dispatch.as_ref().map(|dispatch| dispatch.commit_ns),
        dispatch_ack_ns: item.dispatch.as_ref().and_then(|dispatch| dispatch.ack_ns),
        scheduled_ns: item.scheduled_ns,
        offered_ns: item.offered_ns,
        attempted_ns: item.attempted_ns,
        admitted_ns: item.admitted_ns,
        started_ns: item.started_ns,
        finished_ns: item.finished_ns,
        disposition: item.disposition,
      })
      .collect();
    let producer_lateness_mean_ns = u64::try_from(
      lateness_total
        .checked_div(lateness_count)
        .unwrap_or_default(),
    )
    .map_err(|_| ParseError::Overflow)?;
    Ok(Conservation {
      offered,
      attempted,
      not_attempted,
      rejected_full,
      rejected_resource,
      accepted,
      completed: self
        .entries
        .iter()
        .filter(|item| item.disposition == Disposition::Completed)
        .count(),
      errors: self
        .entries
        .iter()
        .filter(|item| item.disposition == Disposition::Error)
        .count(),
      cancelled: self
        .entries
        .iter()
        .filter(|item| item.disposition == Disposition::Cancelled)
        .count(),
      pending_before: self.pending_before,
      pending_after,
      delayed_unattempted,
      attempt_pending,
      checksum: self.checksum,
      expected_checksum: self.expected_checksum,
      producer_lateness_mean_ns,
      producer_lateness_max_ns: lateness_max,
      items,
    })
  }

  pub fn seal_window(&mut self) -> Result<Conservation, ParseError> {
    if !self.active || !self.offers_sealed || self.dispatch_ack_ns.is_none() {
      return Err(ParseError::InvalidTransition);
    }
    let result = self.conservation()?;
    self.active = false;
    Ok(result)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use allocatbelt::runtime::cgroup::MAX_IO_DEVICES;

  fn psi() -> &'static [u8] {
    b"some avg10=0.00 avg60=0.00 avg300=0.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
  }

  fn parsed(usage: u64, high_event: u64) -> ParsedSensors {
    let line = |total_usec| PsiLine {
      avg10: "0.00".into(),
      avg60: "0.00".into(),
      avg300: "0.00".into(),
      total_usec,
    };
    ParsedSensors {
      cpu: CpuCounters {
        usage_usec: usage,
        nr_periods: usage,
        nr_throttled: 0,
        throttled_usec: 0,
      },
      memory_current: 256,
      memory_max: 512,
      memory_high: 128,
      events: MemoryEvents {
        high: high_event,
        max: 0,
        oom: 0,
        oom_kill: 0,
      },
      cpu_psi: PsiCounters {
        some: line(usage),
        full: line(usage),
      },
      memory_psi: PsiCounters {
        some: line(usage),
        full: line(usage),
      },
      cpu_max: FiniteCpuMax {
        quota_us: 100_000,
        period_us: 100_000,
      },
    }
  }

  fn snapshot(started: Instant, finished: Instant, usage: u64, high_event: u64) -> SensorSnapshot {
    let group = DescriptorIdentity {
      device: "1".into(),
      inode: "2".into(),
      mode: "dir".into(),
      uid: "1000".into(),
      gid: "1000".into(),
    };
    let files = ["cpu.stat", "cpu.pressure", "memory.pressure"]
      .into_iter()
      .map(|name| RawSensorFile {
        name,
        bytes: Vec::new(),
        digest64: 0,
        identity: group.clone(),
        read_started: started,
        read_finished: finished,
      })
      .collect();
    SensorSnapshot {
      group,
      started,
      finished,
      files,
      parsed: parsed(usage, high_event),
    }
  }

  fn controls(quota_us: u64) -> CgroupSnapshot {
    CgroupSnapshot {
      cpu_max: CpuMaxReadback {
        quota_us: Limit::Value(quota_us),
        period_us: 100_000,
      },
      memory_high: Limit::Value(128),
      memory_max: Limit::Value(512),
      io_max: [None; MAX_IO_DEVICES],
      io_max_len: 0,
    }
  }

  #[test]
  fn quota_dimensions_cover_half_one_and_one_and_half_cpu() {
    assert_eq!(
      quota_cpu_basis_points(50_000, 100_000, 50_000, 100_000)
        .unwrap()
        .raw_basis_points,
      10_000
    );
    assert_eq!(
      quota_cpu_basis_points(100_000, 100_000, 100_000, 100_000)
        .unwrap()
        .raw_basis_points,
      10_000
    );
    assert_eq!(
      quota_cpu_basis_points(150_000, 100_000, 150_000, 100_000)
        .unwrap()
        .raw_basis_points,
      10_000
    );
  }

  #[test]
  fn cpu_formula_rejects_zero_overflow_and_reports_burst_saturation() {
    assert_eq!(
      quota_cpu_basis_points(1, 0, 1, 1),
      Err(ParseError::ZeroDenominator)
    );
    assert_eq!(
      quota_cpu_basis_points(u64::MAX, 1, 1, u64::MAX),
      Err(ParseError::Overflow)
    );
    let value = quota_cpu_basis_points(2, 1, 1, 1).unwrap();
    assert_eq!(value.raw_basis_points, 20_000);
    assert_eq!(value.controller_basis_points, 10_000);
    assert!(value.saturated);
  }

  #[test]
  fn memory_uses_original_finite_max() {
    assert_eq!(fixed_max_memory_basis_points(256, 512), Ok(5_000));
    assert_eq!(
      fixed_max_memory_basis_points(512, 0),
      Err(ParseError::ZeroDenominator)
    );
  }

  #[test]
  fn required_cpu_and_event_keys_reject_duplicate_missing_and_overflow() {
    assert_eq!(
      parse_cpu_stat(b"usage_usec 1\nusage_usec 2\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0"),
      Err(ParseError::DuplicateKey)
    );
    assert_eq!(
      parse_cpu_stat(b"usage_usec 1\nnr_periods 0\nnr_throttled 0"),
      Err(ParseError::MissingKey)
    );
    assert_eq!(
      parse_memory_events(b"high 0\nmax 0\noom 0\noom_kill 18446744073709551616"),
      Err(ParseError::Overflow)
    );
  }

  #[test]
  fn psi_requires_complete_unique_some_and_full_lines() {
    assert!(parse_psi(psi()).is_ok());
    assert_eq!(parse_psi(b"some avg10=0 avg60=0 avg300=0 total=1\nsome avg10=0 avg60=0 avg300=0 total=2\nfull avg10=0 avg60=0 avg300=0 total=0"), Err(ParseError::DuplicateKey));
    assert_eq!(
      parse_psi(b"some avg10=0 avg60=0 avg300=0 total=1"),
      Err(ParseError::MissingKey)
    );
  }

  #[test]
  fn nearest_rank_boundaries_and_empty_population_are_explicit() {
    assert_eq!(
      latency_summary(&[100, 1, 50]).unwrap(),
      LatencySummary {
        completed: 3,
        p50_ns: 50,
        p95_ns: 100,
        p99_ns: 100
      }
    );
    assert_eq!(latency_summary(&[]), Err(ParseError::NoCompletedResponses));
  }

  #[test]
  fn partial_sensor_capture_keeps_prior_files_prefix_digest_and_errno() {
    let group = DescriptorIdentity {
      device: "dev".into(),
      inode: "ino".into(),
      mode: "mode".into(),
      uid: "uid".into(),
      gid: "gid".into(),
    };
    let bytes = b"partial bytes".to_vec();
    let prior = RawSensorFile {
      name: "cpu.stat",
      digest64: digest64(b"usage_usec 1"),
      bytes: b"usage_usec 1".to_vec(),
      identity: group.clone(),
      read_started: Instant::now(),
      read_finished: Instant::now(),
    };
    let capture = partial_capture(
      group.clone(),
      Instant::now(),
      vec![prior.clone()],
      PartialSensorFailure {
        name: "memory.events.local",
        raw_prefix: bytes.clone(),
        observed_bytes: bytes.len(),
        error_kind: SensorFailureKind::Read,
        error: "read failed".into(),
        native_errno: Some(5),
      },
    );
    assert_eq!(capture.group, group);
    assert_eq!(capture.files, vec![prior]);
    assert_eq!(capture.failed_name, "memory.events.local");
    assert_eq!(capture.raw_prefix, bytes);
    assert_eq!(capture.digest64, digest64(b"partial bytes"));
    assert_eq!(capture.observed_bytes, bytes.len());
    assert_eq!(capture.native_errno, Some(5));
  }

  #[test]
  fn oversize_read_retains_crossing_chunk_up_to_cap() {
    let mut prefix = vec![b'a'; 3_500];
    let crossing = [b'b'; 1_024];
    let overflow = append_bounded_chunk(&mut prefix, &crossing, 4_096);
    assert_eq!(prefix.len(), 4_096);
    assert_eq!(&prefix[3_500..], &[b'b'; 596]);
    assert_eq!(overflow, 428);
  }

  #[test]
  fn injected_fstat_error_keeps_native_errno_and_directory_stage() {
    let group = DescriptorIdentity {
      device: "dev".into(),
      inode: "ino".into(),
      mode: "mode".into(),
      uid: "uid".into(),
      gid: "gid".into(),
    };
    let stat_failure = identity_failure_capture(
      group,
      Instant::now(),
      Vec::new(),
      "<directory>",
      Vec::new(),
      0,
      IdentityError {
        message: "stat denied".into(),
        native_errno: 13,
      },
    );
    assert_eq!(stat_failure.error_kind, SensorFailureKind::Stat);
    assert_eq!(stat_failure.failed_name, "<directory>");
    assert_eq!(stat_failure.native_errno, Some(13));
  }

  #[test]
  fn partial_completion_and_rejections_conserve_accepted_work() {
    let now = 1_000u64;
    let mut ledger = WindowLedger::new(8).unwrap();
    ledger.begin_window().unwrap();
    ledger.offer(1, now, 7).unwrap();
    ledger.offer(2, now, 8).unwrap();
    ledger.seal_offers(now, now).unwrap();
    ledger.acknowledge_offers(now).unwrap();
    ledger.arrived(1, now).unwrap();
    ledger.arrived(2, now).unwrap();
    ledger.attempt(1, now).unwrap();
    ledger.accept(1, now).unwrap();
    ledger.started(1, now).unwrap();
    ledger.complete(1, now + 5, 7).unwrap();
    assert_eq!(ledger.latencies_ns(), &[5]);
    assert_eq!(
      latency_summary(ledger.latencies_ns()).unwrap(),
      LatencySummary {
        completed: 1,
        p50_ns: 5,
        p95_ns: 5,
        p99_ns: 5
      }
    );
    ledger.attempt(2, now).unwrap();
    ledger.reject(2, Disposition::RejectedFull, now).unwrap();
    let counts = ledger.conservation().unwrap();
    assert_eq!(
      (
        counts.offered,
        counts.attempted,
        counts.completed,
        counts.rejected_full
      ),
      (2, 2, 1, 1)
    );
  }

  #[test]
  fn pending_work_carries_between_windows_and_cancel_is_not_completion() {
    let now = 1_000u64;
    let mut ledger = WindowLedger::new(4).unwrap();
    ledger.begin_window().unwrap();
    ledger.offer(1, now, 1).unwrap();
    ledger.seal_offers(now, now).unwrap();
    ledger.acknowledge_offers(now).unwrap();
    ledger.arrived(1, now).unwrap();
    ledger.attempt(1, now).unwrap();
    ledger.accept(1, now).unwrap();
    assert_eq!(ledger.conservation().unwrap().pending_after, 1);
    ledger.seal_window().unwrap();
    ledger.begin_window().unwrap();
    ledger.seal_offers(now, now).unwrap();
    ledger.acknowledge_offers(now).unwrap();
    assert_eq!(ledger.conservation().unwrap().pending_before, 1);
    ledger.fail(1, now + 1_000_000, true).unwrap();
    let counts = ledger.conservation().unwrap();
    assert_eq!(
      (counts.completed, counts.cancelled, counts.pending_after),
      (0, 1, 0)
    );
  }

  #[test]
  fn started_error_and_cancel_reject_prestart_time_without_mutation() {
    let now = 1_000u64;
    let started = now + 100;
    let mut ledger = WindowLedger::new(4).unwrap();
    ledger.begin_window().unwrap();
    for id in 1..=4 {
      ledger.offer(id, now, id).unwrap();
    }
    ledger.seal_offers(now, now).unwrap();
    ledger.acknowledge_offers(now).unwrap();
    for id in 1..=4 {
      ledger.arrived(id, now).unwrap();
      ledger.attempt(id, now).unwrap();
      ledger.accept(id, now).unwrap();
      ledger.started(id, started).unwrap();
    }

    let before = ledger.conservation().unwrap();
    assert_eq!(before.pending_after, 4);
    assert_eq!(before.errors, 0);
    assert_eq!(before.cancelled, 0);
    assert_eq!(
      ledger.fail(1, started - 1, false),
      Err(ParseError::NonMonotonicTime)
    );
    assert_eq!(ledger.conservation().unwrap(), before);
    assert_eq!(ledger.disposition(1), Some(Disposition::Pending));
    assert_eq!(ledger.entries[0].finished_ns, None);
    assert!(ledger.latencies_ns().is_empty());

    assert_eq!(
      ledger.fail(2, started - 1, true),
      Err(ParseError::NonMonotonicTime)
    );
    assert_eq!(ledger.conservation().unwrap(), before);
    assert_eq!(ledger.disposition(2), Some(Disposition::Pending));
    assert_eq!(ledger.entries[1].finished_ns, None);
    assert!(ledger.latencies_ns().is_empty());

    ledger.fail(3, started, false).unwrap();
    ledger.fail(4, started, true).unwrap();
    let after = ledger.conservation().unwrap();
    assert_eq!(
      (after.errors, after.cancelled, after.pending_after),
      (1, 1, 2)
    );
    assert_eq!(ledger.entries[2].finished_ns, Some(started));
    assert_eq!(ledger.entries[3].finished_ns, Some(started));
    assert!(ledger.latencies_ns().is_empty());
  }

  #[test]
  fn id_and_sample_limits_refuse_instead_of_dropping() {
    let now = 1_000u64;
    let mut ledger = WindowLedger::new(1).unwrap();
    ledger.begin_window().unwrap();
    ledger.offer(1, now, 1).unwrap();
    assert_eq!(ledger.offer(2, now, 2), Err(ParseError::Capacity));
    assert_eq!(ledger.offer(1, now, 2), Err(ParseError::Capacity));
    let mut duplicate = WindowLedger::new(2).unwrap();
    duplicate.begin_window().unwrap();
    duplicate.offer(1, now, 1).unwrap();
    assert_eq!(duplicate.offer(1, now, 2), Err(ParseError::DuplicateId));
  }

  #[test]
  fn counter_reset_and_nonfinite_cpu_control_are_not_zero() {
    assert_eq!(delta(0, 1), Err(ParseError::CounterRegression));
    assert_eq!(
      parse_cpu_max(b"max 100000\n"),
      Err(ParseError::NonFiniteControl)
    );
    assert_eq!(parse_single_u64(b""), Err(ParseError::Empty));
  }

  #[test]
  fn changed_tier_excludes_window_and_safety_events_fail_closed() {
    let base = Instant::now();
    let start = snapshot(base, base + Duration::from_millis(1), 1, 0);
    let end = snapshot(
      base + Duration::from_secs(1),
      base + Duration::from_secs(1) + Duration::from_millis(1),
      100_001,
      1,
    );
    assert_eq!(
      feedback_for_window(
        &start,
        &end,
        &controls(100_000),
        &controls(150_000),
        512,
        &[1_000_000]
      ),
      Err(FeedbackUnavailable::ChangedControls)
    );
    let mut unsafe_end = end.clone();
    unsafe_end.parsed.events.max = 1;
    assert_eq!(
      feedback_for_window(
        &start,
        &unsafe_end,
        &controls(100_000),
        &controls(100_000),
        512,
        &[1_000_000]
      ),
      Err(FeedbackUnavailable::MemorySafetyEvent)
    );
    assert_eq!(
      feedback_for_window(
        &start,
        &unsafe_end,
        &controls(100_000),
        &controls(100_000),
        512,
        &[]
      ),
      Err(FeedbackUnavailable::MemorySafetyEvent)
    );
    assert_eq!(
      feedback_for_window(
        &start,
        &end,
        &controls(100_000),
        &controls(100_000),
        512,
        &[]
      ),
      Err(FeedbackUnavailable::NoCompletedResponses)
    );
  }

  #[test]
  fn cpu_uses_per_file_midpoints_not_the_shortened_snapshot_gap() {
    let base = Instant::now();
    let start_end = base + Duration::from_millis(200);
    let end_start = base + Duration::from_secs(1);
    let mut start = snapshot(base, start_end, 1, 0);
    let mut end = snapshot(
      end_start,
      end_start + Duration::from_millis(200),
      100_001,
      0,
    );
    for file in &mut start.files {
      file.read_started = base;
      file.read_finished = base + Duration::from_millis(2);
    }
    for file in &mut end.files {
      file.read_started = end_start;
      file.read_finished = end_start + Duration::from_millis(2);
    }
    let feedback = feedback_for_window(
      &start,
      &end,
      &controls(100_000),
      &controls(100_000),
      512,
      &[1_000_000],
    )
    .unwrap();
    assert_eq!(feedback.cpu_elapsed_ns, 1_000_000_000);
    assert_eq!(feedback.cpu_uncertainty_bound_ns, 4_000_000);
    // The cpu.stat read midpoints are base + 1 ms and base + 1.001 s, so
    // 100,000 us of CPU over 1,000,000 us at a one-CPU quota is 10%, or 1,000 bp.
    // The shorter 800 ms snapshot gap would incorrectly produce 1,250 bp.
    assert_eq!(feedback.cpu.raw_basis_points, 1_000);
  }

  #[test]
  fn excessive_per_file_read_skew_makes_feedback_unavailable() {
    let base = Instant::now();
    let end_time = base + Duration::from_secs(1);
    let mut start = snapshot(base, base + Duration::from_millis(1), 1, 0);
    let mut end = snapshot(end_time, end_time + Duration::from_millis(1), 100_001, 0);
    for file in &mut start.files {
      file.read_started = base;
      file.read_finished = base + Duration::from_millis(6);
    }
    for file in &mut end.files {
      file.read_started = end_time;
      file.read_finished = end_time + Duration::from_millis(6);
    }
    assert_eq!(
      feedback_for_window(
        &start,
        &end,
        &controls(100_000),
        &controls(100_000),
        512,
        &[1_000_000]
      ),
      Err(FeedbackUnavailable::Sensor(ParseError::ReadPointSkew))
    );
  }

  #[test]
  fn invocation_safety_baseline_catches_events_between_windows() {
    let base = Instant::now();
    let first = snapshot(base, base + Duration::from_millis(1), 1, 0);
    let mut baseline = SafetyCounters::from_snapshot(&first);
    let mut gap_event = snapshot(
      base + Duration::from_secs(1),
      base + Duration::from_secs(1) + Duration::from_millis(1),
      2,
      0,
    );
    gap_event.parsed.events.oom_kill = 1;
    assert_eq!(
      baseline.check_next(&gap_event, 512),
      Err(FeedbackUnavailable::MemorySafetyEvent)
    );
  }

  #[test]
  fn final_drain_safety_boundary_catches_post_window_oom_kill() {
    let base = Instant::now();
    let last_window = snapshot(base, base + Duration::from_millis(1), 1, 0);
    let mut baseline = SafetyCounters::from_snapshot(&last_window);
    let mut drain_end = snapshot(
      base + Duration::from_secs(1),
      base + Duration::from_secs(1) + Duration::from_millis(1),
      2,
      0,
    );
    drain_end.parsed.events.oom_kill = 1;
    assert_eq!(
      baseline.check_next(&drain_end, 512),
      Err(FeedbackUnavailable::MemorySafetyEvent)
    );
  }

  #[test]
  fn event_before_schedule_commit_acknowledgement_is_rejected() {
    let mut uncommittable = WindowLedger::new(2).unwrap();
    uncommittable.begin_window().unwrap();
    uncommittable.offer(2, 109, 2).unwrap();
    assert_eq!(
      uncommittable.seal_offers(110, 115),
      Err(ParseError::NonMonotonicTime)
    );

    let mut ledger = WindowLedger::new(2).unwrap();
    ledger.begin_window().unwrap();
    ledger.offer(1, 120, 1).unwrap();
    ledger.seal_offers(110, 115).unwrap();
    ledger.acknowledge_offers(120).unwrap();
    assert_eq!(ledger.arrived(1, 119), Err(ParseError::NonMonotonicTime));
    assert_eq!(ledger.arrived(1, 120), Ok(()));
  }

  #[test]
  fn unresolved_attempt_is_counted_and_prior_offer_can_carry_into_attempt() {
    let now = 1_000u64;
    let mut ledger = WindowLedger::new(4).unwrap();
    ledger.begin_window().unwrap();
    ledger.offer(1, now, 1).unwrap();
    ledger.seal_offers(now, now).unwrap();
    ledger.acknowledge_offers(now).unwrap();
    assert_eq!(ledger.offer(3, now, 3), Err(ParseError::InvalidTransition));
    ledger.arrived(1, now).unwrap();
    ledger.attempt(1, now).unwrap();
    let pending = ledger.conservation().unwrap();
    assert_eq!(
      (
        pending.offered,
        pending.attempted,
        pending.not_attempted,
        pending.attempt_pending
      ),
      (1, 1, 0, 1)
    );
    ledger.seal_window().unwrap();

    let mut carryover = WindowLedger::new(4).unwrap();
    carryover.begin_window().unwrap();
    carryover.offer(2, now, 2).unwrap();
    carryover.seal_offers(now, now).unwrap();
    carryover.acknowledge_offers(now).unwrap();
    carryover.seal_window().unwrap();
    carryover.begin_window().unwrap();
    carryover.seal_offers(now, now).unwrap();
    carryover.acknowledge_offers(now + 10).unwrap();
    carryover.arrived(2, now + 1).unwrap();
    carryover.attempt(2, now + 2).unwrap();
    carryover.accept(2, now + 3).unwrap();
    let moved = carryover.conservation().unwrap();
    assert_eq!(
      (
        moved.offered,
        moved.attempted,
        moved.accepted,
        moved.not_attempted
      ),
      (1, 1, 1, 0)
    );
  }

  #[test]
  fn rejection_can_record_an_implicit_attempt_only_when_no_attempt_exists() {
    let now = 1_000u64;
    let mut implicit = WindowLedger::new(2).unwrap();
    implicit.begin_window().unwrap();
    implicit.offer(1, now, 1).unwrap();
    implicit.seal_offers(now, now).unwrap();
    implicit.acknowledge_offers(now).unwrap();
    implicit.arrived(1, now).unwrap();
    implicit
      .reject(1, Disposition::RejectedResource, now + 1)
      .unwrap();
    let counts = implicit.conservation().unwrap();
    assert_eq!(
      (
        counts.attempted,
        counts.rejected_resource,
        counts.attempt_pending
      ),
      (1, 1, 0)
    );
  }
}
