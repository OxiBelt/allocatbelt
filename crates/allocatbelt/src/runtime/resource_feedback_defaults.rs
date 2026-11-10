//! Default CPU capacity for the opt-in feedback service.
//!
//! The default path derives one number, the CPU capacity, and everything else
//! from constants: [`ResourceFeedbackPolicyConfig::process_default`] is a
//! constant function of that number. This module opens and parses no file to
//! find it. The capacity is whatever [`std::thread::available_parallelism`]
//! reports, so it follows the standard library's definition, which honours
//! the thread's CPU affinity and the CPU quota the standard library itself
//! reports; any file access behind that call is the standard library's own.
//! The value is read when a factory is created and is not refreshed.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::io;
use std::num::{NonZeroU32, NonZeroUsize};

use super::resource_feedback_policy::ResourceFeedbackPolicyConfig;

/// Converts a parallelism query result into a feedback CPU capacity.
///
/// A failed query counts as one CPU, and a count beyond `u32::MAX` saturates.
/// The function is pure: tests inject the query result.
#[must_use]
pub fn cpu_capacity_from(parallelism: io::Result<NonZeroUsize>) -> NonZeroU32 {
  match parallelism {
    Ok(count) => NonZeroU32::try_from(count).unwrap_or(NonZeroU32::MAX),
    Err(_) => NonZeroU32::MIN,
  }
}

/// The CPU capacity of the default path: `available_parallelism()`, or one
/// when the standard library cannot tell.
#[must_use]
pub fn default_cpu_capacity() -> NonZeroU32 {
  cpu_capacity_from(std::thread::available_parallelism())
}

/// The process-default policy for [`default_cpu_capacity`].
#[must_use]
pub fn default_policy() -> ResourceFeedbackPolicyConfig {
  ResourceFeedbackPolicyConfig::process_default(default_cpu_capacity())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::resource_feedback_policy::ResourceFeedbackPolicy;

  #[test]
  fn capacity_follows_the_injected_parallelism_and_falls_back_to_one() {
    for count in [1_usize, 2, 12, 4096] {
      let capacity = cpu_capacity_from(Ok(NonZeroUsize::new(count).unwrap()));
      assert_eq!(usize::try_from(capacity.get()).unwrap(), count);
    }
    assert_eq!(
      cpu_capacity_from(Err(io::ErrorKind::Unsupported.into())),
      NonZeroU32::MIN
    );
    assert_eq!(cpu_capacity_from(Ok(NonZeroUsize::MAX)), NonZeroU32::MAX);
  }

  #[test]
  fn host_default_capacity_is_at_least_one_and_its_policy_validates() {
    let capacity = default_cpu_capacity();
    assert!(capacity.get() >= 1);
    let policy = default_policy();
    assert_eq!(
      policy,
      ResourceFeedbackPolicyConfig::process_default(capacity)
    );
    assert_eq!(policy.cpu_concurrency.ceiling, u64::from(capacity.get()));
    assert!(ResourceFeedbackPolicy::new(policy).is_ok());
  }
}
