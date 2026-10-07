//! Deterministic integer work and its bounded owned-task adapter.

use allocatbelt::runtime::asynchronous::{AsyncJoinError, OwnedTaskScope};

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

/// Runs the fixed jobs on an explicitly bounded owned scope and combines
/// their results in stable job-index order.
pub async fn run(scope: &OwnedTaskScope, config: CpuConfig) -> PortResult<u64> {
  if config.jobs == 0 || config.jobs > MAX_JOBS || config.rounds == 0 || config.rounds > MAX_ROUNDS
  {
    return Err(message("CPU config exceeds its functional bounds").into());
  }

  let mut jobs = Vec::new();
  jobs.try_reserve_exact(config.jobs)?;
  let mut rejected = None;
  for index in 0..config.jobs {
    let seed = config.seed ^ (index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
    match scope.spawn(async move { kernel(seed, config.rounds) }) {
      Ok(job) => jobs.push(job),
      Err(error) => {
        rejected = Some(error.kind);
        break;
      }
    }
  }

  let mut results = Vec::new();
  results.try_reserve_exact(jobs.len())?;
  for job in jobs {
    results.push(
      job
        .await
        .map_err(|error: AsyncJoinError| join_message(error))?,
    );
  }
  if let Some(error) = rejected {
    return Err(join_message(error).into());
  }
  let digest = results
    .into_iter()
    .enumerate()
    .fold(config.seed, |digest, (index, result)| {
      digest.rotate_left(11) ^ result ^ index as u64
    });
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
