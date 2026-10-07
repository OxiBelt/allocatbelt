//! Deterministic integer work and its bounded owned-task adapter.

use allocatbelt::runtime::asynchronous::{AbortHandle, AsyncError, AsyncJob, OwnedTaskScope};

use crate::{PortResult, join_message, message};

/// Maximum number of independent jobs in the functional example.
pub const MAX_JOBS: usize = 16;
/// Maximum rounds per job in the functional example.
pub const MAX_ROUNDS: u32 = 1_000_000;

/// Bounded input to [`run`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuConfig {
  /// Number of independently admitted jobs.
  pub jobs: usize,
  /// Integer rounds per job.
  pub rounds: u32,
  /// Base input seed; each job mixes in its stable index.
  pub seed: u64,
}

impl Default for CpuConfig {
  fn default() -> Self {
    Self {
      jobs: 4,
      rounds: 50_000,
      seed: 0x6a09_e667_f3bc_c909,
    }
  }
}

/// A deterministic, allocation-free CPU kernel shared with future adapters.
#[must_use]
pub fn kernel(seed: u64, rounds: u32) -> u64 {
  let mut value = seed ^ 0x9e37_79b9_7f4a_7c15;
  for index in 0..rounds {
    value ^= seed.rotate_left(index % u64::BITS);
    value ^= value.wrapping_add(u64::from(index).wrapping_mul(0xbf58_476d_1ce4_e5b9));
    value = value.rotate_left(27).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^= value >> 31;
  }
  value ^ seed.rotate_left(19) ^ u64::from(rounds)
}

async fn run_job(seed: u64, rounds: u32) -> u64 {
  kernel(seed, rounds)
}

struct AdmittedJobs {
  jobs: Vec<(usize, AsyncJob<u64>)>,
  controls: Vec<AbortHandle>,
}

impl AdmittedJobs {
  fn new(capacity: usize) -> PortResult<Self> {
    let mut jobs = Vec::new();
    jobs.try_reserve_exact(capacity)?;
    let mut controls = Vec::new();
    controls.try_reserve_exact(capacity)?;
    Ok(Self { jobs, controls })
  }

  fn push(&mut self, index: usize, job: AsyncJob<u64>) {
    self.controls.push(job.abort_handle());
    self.jobs.push((index, job));
  }

  async fn abort_and_drain(&mut self) {
    for control in &self.controls {
      control.abort();
    }
    while let Some((_, job)) = self.jobs.pop() {
      let _ = job.await;
    }
    self.controls.clear();
  }
}

impl Drop for AdmittedJobs {
  fn drop(&mut self) {
    // Dropping an AsyncJob detaches it. This guard requests cancellation if
    // the caller cancels `run`; scope close remains the join point for cleanup.
    for control in &self.controls {
      control.abort();
    }
  }
}

/// Runs the fixed jobs on an explicitly bounded owned scope and combines
/// their results in stable job-index order. On a `Full` rejection it retains
/// the exact rejected future, awaits one of its own admitted jobs, then retries
/// once capacity has actually been released. If no owned job can release a
/// full scheduler, it returns the recovered future's admission error instead
/// of spinning against unrelated work.
pub async fn run(scope: &OwnedTaskScope, config: CpuConfig) -> PortResult<u64> {
  if config.jobs == 0 || config.jobs > MAX_JOBS || config.rounds == 0 || config.rounds > MAX_ROUNDS
  {
    return Err(message("CPU config exceeds its functional bounds").into());
  }

  let mut jobs = AdmittedJobs::new(config.jobs)?;
  let mut results = Vec::new();
  results.try_reserve_exact(config.jobs)?;
  results.resize(config.jobs, None);
  for index in 0..config.jobs {
    let seed = config.seed ^ (index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
    let mut future = run_job(seed, config.rounds);
    loop {
      match scope.spawn(future) {
        Ok(job) => {
          jobs.push(index, job);
          break;
        }
        Err(error) => {
          let kind = error.kind;
          future = error.into_future();
          if kind != AsyncError::Full {
            jobs.abort_and_drain().await;
            return Err(join_message(kind).into());
          }
          let Some((completed_index, active)) = jobs.jobs.pop() else {
            return Err(message("CPU task capacity is full with no owned job to await").into());
          };
          match active.await {
            Ok(result) => results[completed_index] = Some(result),
            Err(error) => {
              jobs.abort_and_drain().await;
              return Err(join_message(error).into());
            }
          }
        }
      }
    }
  }

  while let Some((index, job)) = jobs.jobs.pop() {
    match job.await {
      Ok(result) => results[index] = Some(result),
      Err(error) => {
        jobs.abort_and_drain().await;
        return Err(join_message(error).into());
      }
    }
  }
  jobs.controls.clear();
  let mut digest = config.seed;
  for (index, result) in results.into_iter().enumerate() {
    let Some(result) = result else {
      return Err(message("CPU result collection missed a completed job").into());
    };
    digest = digest.rotate_left(11) ^ result ^ index as u64;
  }
  Ok(digest)
}

#[cfg(test)]
mod tests {
  use super::{CpuConfig, kernel};

  #[test]
  fn kernel_is_repeatable_and_sensitive_to_work_inputs() {
    let first = kernel(7, 8192);
    assert_eq!(first, kernel(7, 8192));
    assert_ne!(first, kernel(8, 8192));
    assert_ne!(first, kernel(7, 8191));
    assert_eq!(CpuConfig::default().jobs, 4);
  }
}
