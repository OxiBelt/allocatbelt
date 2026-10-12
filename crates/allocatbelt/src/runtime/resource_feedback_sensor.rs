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
use std::num::NonZeroU32;
use std::time::Instant;

#[path = "resource_feedback_cpu.rs"]
mod cpu;

use cpu::{MAX_STAT_LEN, ProcessCpuTicks, cpu_utilization_basis_points, parse_proc_stat};

use super::resource_feedback::{FeedbackSensor, FeedbackSensorError};
use super::resource_feedback_policy::FeedbackSample;

const MAX_READ_CALLS: usize = 32;

/// An owned `/proc/self/stat` descriptor and fixed-size measurement state.
/// Every sample uses real monotonic time. The first successful read supplies
/// a baseline and returns no utilization; a read/parse failure invalidates it.
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

  fn read_ticks(&mut self) -> Result<ProcessCpuTicks, FeedbackSensorError> {
    self
      .stat
      .seek(SeekFrom::Start(0))
      .map_err(|_| FeedbackSensorError::ReadFailed)?;
    let mut storage = [0_u8; MAX_STAT_LEN + 1];
    let mut len = 0;
    for _ in 0..MAX_READ_CALLS {
      match self.stat.read(&mut storage[len..]) {
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
}

impl FeedbackSensor for ProcessCpuSensor {
  fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
    let ticks = match self.read_ticks() {
      Ok(ticks) => ticks,
      Err(error) => {
        self.previous = None;
        return Err(error);
      }
    };
    let at = Instant::now();
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

#[cfg(test)]
mod tests {
  use super::*;

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
}
