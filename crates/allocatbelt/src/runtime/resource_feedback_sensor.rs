//! Bounded Linux process CPU telemetry for the opt-in feedback service.
//!
//! This source measures user plus system CPU time of this process, normalized
//! by an explicitly configured CPU capacity. It does not attribute tenants,
//! measure run-queue pressure, or supply disk/network latency. Those readings
//! are missing and freeze their controls until an appropriate source is used.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::num::{NonZeroU32, NonZeroU64};
use std::time::{Duration, Instant};

#[path = "resource_feedback_cpu.rs"]
mod cpu;

use cpu::{MAX_STAT_LEN, ProcessCpuTicks, cpu_utilization_basis_points, parse_proc_stat};

use super::resource_feedback::{FeedbackSensor, FeedbackSensorError};
use super::resource_feedback_meter::{IoFeedbackMeter, IoFeedbackMeterSnapshot};
use super::resource_feedback_policy::FeedbackSample;
use super::resource_feedback_policy::{MAX_DENSE_SAMPLE_GAP, SAMPLE_INTERVAL, TELEMETRY_FRESHNESS};

const MAX_READ_CALLS: usize = 32;

/// An owned `/proc/self/stat` descriptor and fixed-size measurement state.
/// Every sample uses a real monotonic timestamp captured before reading the
/// counters, so read or scheduling delays age the datum conservatively. The
/// first successful read supplies a baseline and returns no utilization; a
/// read/parse failure invalidates it.
pub struct ProcessCpuSensor {
  stat: File,
  capacity: NonZeroU32,
  ticks_per_second: u64,
  previous: Option<(Instant, ProcessCpuTicks)>,
}

impl ProcessCpuSensor {
  /// Opens this process's Linux CPU counters. `capacity` is the number of CPU
  /// equivalents used as the utilization denominator, independent of virtual
  /// runtime clocks and configurable concurrency limits.
  pub fn new(capacity: NonZeroU32) -> io::Result<Self> {
    let ticks_per_second = rustix::param::clock_ticks_per_second();
    if ticks_per_second == 0 {
      return Err(io::ErrorKind::Unsupported.into());
    }
    Ok(Self {
      stat: File::open("/proc/self/stat")?,
      capacity,
      ticks_per_second,
      previous: None,
    })
  }

  fn read_ticks(stat: &mut File) -> Result<ProcessCpuTicks, FeedbackSensorError> {
    stat
      .seek(SeekFrom::Start(0))
      .map_err(|_| FeedbackSensorError::ReadFailed)?;
    let mut storage = [0_u8; MAX_STAT_LEN + 1];
    let mut len = 0;
    for _ in 0..MAX_READ_CALLS {
      match stat.read(&mut storage[len..]) {
        Ok(0) => {
          return parse_proc_stat(&storage[..len]).map_err(|_| FeedbackSensorError::ReadFailed);
        }
        Ok(count) => {
          len += count;
          if len > MAX_STAT_LEN {
            return Err(FeedbackSensorError::ReadFailed);
          }
        }
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
        Err(_) => return Err(FeedbackSensorError::ReadFailed),
      }
    }
    Err(FeedbackSensorError::ReadFailed)
  }

  fn sample_with_reader(
    &mut self,
    read_ticks: impl FnOnce(&mut File) -> Result<ProcessCpuTicks, FeedbackSensorError>,
  ) -> Result<FeedbackSample, FeedbackSensorError> {
    // This conservative timestamp precedes the complete /proc read. A long
    // read or a deschedule after it cannot make old counters appear fresh.
    let at = Instant::now();
    let ticks = match read_ticks(&mut self.stat) {
      Ok(ticks) => ticks,
      Err(error) => {
        self.previous = None;
        return Err(error);
      }
    };
    let utilization = self.previous.and_then(|(previous_at, previous_ticks)| {
      let elapsed = at.checked_duration_since(previous_at)?;
      cpu_utilization_basis_points(
        previous_ticks,
        ticks,
        elapsed,
        self.ticks_per_second,
        self.capacity.get(),
      )
      .ok()
    });
    self.previous = Some((at, ticks));
    Ok(FeedbackSample::new(at, utilization, None, None))
  }
}

impl FeedbackSensor for ProcessCpuSensor {
  fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
    self.sample_with_reader(Self::read_ticks)
  }
}

/// A selected stream meter normalized by an explicit calibrated
/// application-byte capacity.
#[derive(Clone, Debug)]
pub struct IoFeedbackSource {
  meter: IoFeedbackMeter,
  capacity_bytes_per_second: NonZeroU64,
}

impl IoFeedbackSource {
  /// Selects a shared meter and its calibrated application-byte capacity.
  #[must_use]
  pub const fn new(meter: IoFeedbackMeter, capacity_bytes_per_second: NonZeroU64) -> Self {
    Self {
      meter,
      capacity_bytes_per_second,
    }
  }

  /// Borrows the meter shared with stream adapters.
  #[must_use]
  pub const fn meter(&self) -> &IoFeedbackMeter {
    &self.meter
  }

  /// Calibrated application bytes per second used as the 100% denominator.
  #[must_use]
  pub const fn capacity_bytes_per_second(&self) -> NonZeroU64 {
    self.capacity_bytes_per_second
  }
}

#[derive(Clone, Copy)]
struct IoFeedbackTracker {
  capacity_bytes_per_second: NonZeroU64,
  minimum_dense_observations: u32,
  previous: Option<IoFeedbackMeterSnapshot>,
  dense_intervals: u32,
}

impl IoFeedbackTracker {
  const fn new(
    capacity_bytes_per_second: NonZeroU64,
    minimum_dense_observations: NonZeroU32,
  ) -> Self {
    Self {
      capacity_bytes_per_second,
      minimum_dense_observations: minimum_dense_observations.get(),
      previous: None,
      dense_intervals: 0,
    }
  }

  fn clear(&mut self) {
    self.previous = None;
    self.dense_intervals = 0;
  }

  fn rebaseline(&mut self, snapshot: IoFeedbackMeterSnapshot) {
    self.previous = Some(snapshot);
    self.dense_intervals = 0;
  }

  fn observe(&mut self, snapshot: IoFeedbackMeterSnapshot, observed_at: Instant) -> Option<u16> {
    if !snapshot.usable()
      || observed_at
        .checked_duration_since(snapshot.measured_at)
        .is_none_or(|age| age > TELEMETRY_FRESHNESS)
    {
      self.clear();
      return None;
    }

    let Some(previous) = self.previous else {
      self.rebaseline(snapshot);
      return None;
    };
    if snapshot.generation != previous.generation
      || snapshot.committed_bytes < previous.committed_bytes
      || snapshot.completions < previous.completions
    {
      self.rebaseline(snapshot);
      return None;
    }

    let Some(elapsed) = snapshot
      .measured_at
      .checked_duration_since(previous.measured_at)
    else {
      self.rebaseline(snapshot);
      return None;
    };
    if elapsed < SAMPLE_INTERVAL || elapsed > MAX_DENSE_SAMPLE_GAP {
      self.rebaseline(snapshot);
      return None;
    }

    let bytes = snapshot.committed_bytes - previous.committed_bytes;
    let completions = snapshot.completions - previous.completions;
    if (bytes == 0) != (completions == 0) {
      self.clear();
      return None;
    }

    self.previous = Some(snapshot);
    self.dense_intervals = self.dense_intervals.saturating_add(1);
    if self.dense_intervals < self.minimum_dense_observations {
      return None;
    }

    application_utilization_basis_points(bytes, elapsed, self.capacity_bytes_per_second.get())
  }
}

/// Real-time feedback combining process CPU counters with selected disk and
/// network stream meters.
///
/// Each byte source must be explicitly selected and calibrated. A meter is
/// readable only while at least one matching `RateLimitedIo` direction owns a
/// registration. For one dense interval, utilization is
/// `min(10_000, delta_committed_application_bytes * 10_000 / (elapsed_seconds * capacity_bytes_per_second))`;
/// 10,000 basis points means 100 percent. The meter time is captured with the
/// counter snapshot, and the sample timestamp uses the earliest contributing
/// measurement so sensor processing and later policy work count toward age.
/// This is application-byte rate normalized by an explicit calibration, not
/// physical disk or wire utilization, tenant attribution, latency, or tail
/// pressure. Selecting the same meter for both disk and network intentionally
/// measures the same logical byte source twice, once against each calibration.
pub struct RuntimeFeedbackSensor {
  process_cpu: ProcessCpuSensor,
  disk: Option<(IoFeedbackSource, IoFeedbackTracker)>,
  network: Option<(IoFeedbackSource, IoFeedbackTracker)>,
}

impl RuntimeFeedbackSensor {
  /// Combines an owned CPU source with optional calibrated disk and network
  /// application-byte sources. Each selected source needs the given number of
  /// consecutive 100–200 ms snapshot intervals before its first utilization
  /// reading. After that it reports each dense interval using that interval's
  /// actual elapsed time. Fresh attached idle intervals are valid and report
  /// zero after this density threshold; unattached or stale sources remain
  /// missing.
  #[must_use]
  pub fn new(
    process_cpu: ProcessCpuSensor,
    disk: Option<IoFeedbackSource>,
    network: Option<IoFeedbackSource>,
    minimum_dense_observations: NonZeroU32,
  ) -> Self {
    let disk = disk.map(|source| {
      let tracker =
        IoFeedbackTracker::new(source.capacity_bytes_per_second, minimum_dense_observations);
      (source, tracker)
    });
    let network = network.map(|source| {
      let tracker =
        IoFeedbackTracker::new(source.capacity_bytes_per_second, minimum_dense_observations);
      (source, tracker)
    });
    Self {
      process_cpu,
      disk,
      network,
    }
  }
}

impl FeedbackSensor for RuntimeFeedbackSensor {
  fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
    let cpu_sample = self.process_cpu.sample().ok();
    let disk_snapshot = self
      .disk
      .as_ref()
      .map(|(source, _)| source.meter.snapshot());
    let shares_meter = self
      .disk
      .as_ref()
      .zip(self.network.as_ref())
      .is_some_and(|((disk, _), (network, _))| disk.meter.same_meter(&network.meter));
    let network_snapshot = if shares_meter {
      disk_snapshot
    } else {
      self
        .network
        .as_ref()
        .map(|(source, _)| source.meter.snapshot())
    };
    let observed_at = Instant::now();

    let disk_utilization = self
      .disk
      .as_mut()
      .zip(disk_snapshot)
      .and_then(|((_, tracker), snapshot)| tracker.observe(snapshot, observed_at));
    let network_utilization = self
      .network
      .as_mut()
      .zip(network_snapshot)
      .and_then(|((_, tracker), snapshot)| tracker.observe(snapshot, observed_at));
    let disk_reading = disk_utilization
      .zip(disk_snapshot)
      .map(|(utilization, snapshot)| (snapshot.measured_at, utilization));
    let network_reading = network_utilization
      .zip(network_snapshot)
      .map(|(utilization, snapshot)| (snapshot.measured_at, utilization));

    Ok(combine_feedback_sample(
      cpu_sample,
      disk_reading,
      network_reading,
      observed_at,
    ))
  }
}

fn combine_feedback_sample(
  cpu: Option<FeedbackSample>,
  disk: Option<(Instant, u16)>,
  network: Option<(Instant, u16)>,
  observed_at: Instant,
) -> FeedbackSample {
  let cpu = cpu
    .and_then(|sample| {
      sample
        .cpu_utilization_basis_points
        .map(|value| (sample.at, value))
    })
    .filter(|(at, _)| source_is_fresh(*at, observed_at));
  let disk = disk.filter(|(at, _)| source_is_fresh(*at, observed_at));
  let network = network.filter(|(at, _)| source_is_fresh(*at, observed_at));
  let at = [
    cpu.map(|sample| sample.0),
    disk.map(|sample| sample.0),
    network.map(|sample| sample.0),
  ]
  .into_iter()
  .flatten()
  .min()
  .unwrap_or(observed_at);
  FeedbackSample::new(
    at,
    cpu.map(|sample| sample.1),
    disk.map(|sample| sample.1),
    network.map(|sample| sample.1),
  )
}

fn source_is_fresh(measured_at: Instant, observed_at: Instant) -> bool {
  observed_at
    .checked_duration_since(measured_at)
    .is_some_and(|age| age <= TELEMETRY_FRESHNESS)
}

fn application_utilization_basis_points(
  bytes: u64,
  elapsed: Duration,
  capacity_bytes_per_second: u64,
) -> Option<u16> {
  let numerator = u128::from(bytes)
    .checked_mul(10_000)?
    .checked_mul(1_000_000_000)?;
  let denominator = u128::from(capacity_bytes_per_second).checked_mul(elapsed.as_nanos())?;
  if denominator == 0 {
    return None;
  }
  u16::try_from((numerator / denominator).min(10_000)).ok()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn io_snapshot(
    measured_at: Instant,
    committed_bytes: u64,
    completions: u64,
    attached_sources: u32,
    generation: u64,
  ) -> IoFeedbackMeterSnapshot {
    IoFeedbackMeterSnapshot {
      measured_at,
      committed_bytes,
      completions,
      attached_sources,
      generation,
      diagnostics: Default::default(),
    }
  }

  fn make_tracker(capacity: u64, minimum_dense: u32) -> IoFeedbackTracker {
    IoFeedbackTracker::new(
      NonZeroU64::new(capacity).unwrap(),
      NonZeroU32::new(minimum_dense).unwrap(),
    )
  }

  #[test]
  fn live_process_cpu_reads_start_with_baseline_and_leave_other_controls_missing() {
    let mut sensor = ProcessCpuSensor::new(NonZeroU32::new(1).unwrap()).unwrap();
    let first = sensor.sample().unwrap();
    assert_eq!(first.cpu_utilization_basis_points, None);
    assert_eq!(first.disk_utilization_basis_points, None);
    assert_eq!(first.network_utilization_basis_points, None);
    std::thread::sleep(std::time::Duration::from_millis(2));
    let next = sensor.sample().unwrap();
    assert!(next.at > first.at);
    assert!(next.cpu_utilization_basis_points.is_some());
    assert_eq!(next.disk_utilization_basis_points, None);
    assert_eq!(next.network_utilization_basis_points, None);
  }

  #[test]
  fn delayed_proc_read_keeps_its_start_time_and_only_stales_cpu() {
    let mut process_cpu = ProcessCpuSensor::new(NonZeroU32::new(1).unwrap()).unwrap();
    let baseline = process_cpu
      .sample_with_reader(ProcessCpuSensor::read_ticks)
      .unwrap();
    assert_eq!(baseline.cpu_utilization_basis_points, None);

    let cpu = process_cpu
      .sample_with_reader(|stat| {
        std::thread::sleep(Duration::from_millis(25));
        ProcessCpuSensor::read_ticks(stat)
      })
      .unwrap();
    let completed_at = Instant::now();
    assert!(cpu.cpu_utilization_basis_points.is_some());
    assert!(
      completed_at.duration_since(cpu.at) >= Duration::from_millis(25),
      "CPU measurement time must precede the delayed /proc read"
    );

    let observed_at = cpu.at + TELEMETRY_FRESHNESS + Duration::from_millis(1);
    let fresh_meter_at = observed_at - Duration::from_millis(100);
    let combined = combine_feedback_sample(
      Some(cpu),
      Some((fresh_meter_at, 4_000)),
      Some((fresh_meter_at, 2_000)),
      observed_at,
    );
    assert_eq!(combined.cpu_utilization_basis_points, None);
    assert_eq!(combined.disk_utilization_basis_points, Some(4_000));
    assert_eq!(combined.network_utilization_basis_points, Some(2_000));
    assert_eq!(combined.at, fresh_meter_at);
  }

  #[test]
  fn source_requires_dense_snapshots_and_accepts_attached_idle_as_zero() {
    let start = Instant::now();
    let mut tracker = make_tracker(2_000, 2);
    assert_eq!(tracker.observe(io_snapshot(start, 0, 0, 1, 0), start), None);
    assert_eq!(
      tracker.observe(
        io_snapshot(start + Duration::from_millis(100), 0, 0, 1, 0),
        start + Duration::from_millis(100),
      ),
      None
    );
    assert_eq!(
      tracker.observe(
        io_snapshot(start + Duration::from_millis(200), 0, 0, 1, 0),
        start + Duration::from_millis(200),
      ),
      Some(0),
      "fresh attached snapshots with no completions establish known idle"
    );
    assert_eq!(
      tracker.observe(
        io_snapshot(start + Duration::from_millis(300), 100, 1, 1, 0),
        start + Duration::from_millis(300),
      ),
      Some(5_000)
    );
  }

  #[test]
  fn missing_sparse_stale_and_reset_generation_samples_clear_the_baseline() {
    let start = Instant::now();
    let mut tracker = make_tracker(1_000, 1);
    assert_eq!(
      tracker.observe(io_snapshot(start, 0, 0, 0, 0), start),
      None,
      "unattached sources are unknown rather than healthy idle"
    );
    assert_eq!(tracker.observe(io_snapshot(start, 0, 0, 1, 0), start), None);
    assert_eq!(
      tracker.observe(
        io_snapshot(start + Duration::from_millis(201), 10, 1, 1, 0),
        start + Duration::from_millis(201),
      ),
      None,
      "a sparse interval rebaselines instead of averaging stale work"
    );
    assert_eq!(
      tracker.observe(
        io_snapshot(start + Duration::from_millis(301), 10, 1, 1, 1),
        start + Duration::from_millis(301),
      ),
      None,
      "a reset generation cannot reuse old counters"
    );
    assert_eq!(
      tracker.observe(
        io_snapshot(start + Duration::from_millis(401), 20, 2, 1, 1),
        start + Duration::from_millis(401),
      ),
      Some(1_000)
    );

    let mut stale = make_tracker(1_000, 1);
    assert_eq!(
      stale.observe(
        io_snapshot(start, 0, 0, 1, 0),
        start + TELEMETRY_FRESHNESS + Duration::from_millis(1),
      ),
      None
    );
    assert_eq!(stale.previous, None);

    let mut overflow = make_tracker(1_000, 1);
    let mut snapshot = io_snapshot(start, 0, 0, 1, 0);
    snapshot.diagnostics.counter_overflow = true;
    assert_eq!(overflow.observe(snapshot, start), None);
    assert_eq!(overflow.previous, None);
  }

  #[test]
  fn application_byte_rate_uses_checked_actual_elapsed_and_clamps_at_capacity() {
    assert_eq!(
      application_utilization_basis_points(50, Duration::from_millis(100), 1_000),
      Some(5_000)
    );
    assert_eq!(
      application_utilization_basis_points(10_000, Duration::from_millis(100), 1_000),
      Some(10_000)
    );
    assert_eq!(
      application_utilization_basis_points(1, Duration::ZERO, 1_000),
      None
    );
  }

  #[test]
  fn runtime_sensor_combines_live_cpu_with_directional_meter_counts() {
    let process_cpu = ProcessCpuSensor::new(NonZeroU32::new(1).unwrap()).unwrap();
    let read_meter = IoFeedbackMeter::new();
    let write_meter = IoFeedbackMeter::new();
    let _read_registration = read_meter.register_source();
    let _write_registration = write_meter.register_source();
    let mut sensor = RuntimeFeedbackSensor::new(
      process_cpu,
      Some(IoFeedbackSource::new(
        read_meter.clone(),
        NonZeroU64::new(10_000).unwrap(),
      )),
      Some(IoFeedbackSource::new(
        write_meter.clone(),
        NonZeroU64::new(10_000).unwrap(),
      )),
      NonZeroU32::new(1).unwrap(),
    );

    let baseline = sensor.sample().unwrap();
    assert_eq!(baseline.cpu_utilization_basis_points, None);
    assert_eq!(baseline.disk_utilization_basis_points, None);
    assert_eq!(baseline.network_utilization_basis_points, None);

    for _ in 0..5 {
      read_meter.record_completion(100);
      write_meter.record_completion(50);
      std::thread::sleep(Duration::from_millis(110));
      let sample = sensor.sample().unwrap();
      if let (Some(disk), Some(network)) = (
        sample.disk_utilization_basis_points,
        sample.network_utilization_basis_points,
      ) {
        assert!(sample.cpu_utilization_basis_points.is_some());
        assert!(disk > 0 && disk <= 10_000);
        assert!(network > 0 && network <= 10_000);
        return;
      }
    }
    panic!("dense directional meter samples did not become available");
  }

  #[test]
  fn one_shared_meter_selection_uses_the_same_snapshot_for_both_controls() {
    let process_cpu = ProcessCpuSensor::new(NonZeroU32::new(1).unwrap()).unwrap();
    let meter = IoFeedbackMeter::new();
    let _registration = meter.register_source();
    let mut sensor = RuntimeFeedbackSensor::new(
      process_cpu,
      Some(IoFeedbackSource::new(
        meter.clone(),
        NonZeroU64::new(10_000).unwrap(),
      )),
      Some(IoFeedbackSource::new(
        meter.clone(),
        NonZeroU64::new(10_000).unwrap(),
      )),
      NonZeroU32::new(1).unwrap(),
    );
    let _ = sensor.sample().unwrap();

    for _ in 0..5 {
      meter.record_completion(100);
      std::thread::sleep(Duration::from_millis(110));
      let sample = sensor.sample().unwrap();
      if let (Some(disk), Some(network)) = (
        sample.disk_utilization_basis_points,
        sample.network_utilization_basis_points,
      ) {
        assert_eq!(disk, network);
        return;
      }
    }
    panic!("shared meter did not produce a dense sample");
  }
}
