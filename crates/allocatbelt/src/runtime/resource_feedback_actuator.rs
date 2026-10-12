//! Feedback actuators for managed CPU admission and application-byte buckets.
//!
//! These controls affect their declared runtime domain and selected buckets.
//! They do not write OS quotas or intercept I/O that bypasses those buckets.
//! Component compare-exchange prevents a stale feedback writer from clobbering
//! another controller's limit. Public handles remain explicitly shared.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use super::byte_rate::ByteRateLimit;
use super::resource_domain::{DomainResource, ResourceDomain, TenantDomain};
use super::resource_feedback::{FeedbackActuator, FeedbackActuatorError};
use super::resource_feedback_policy::{FeedbackResource, PlanTicket};

/// Which managed CPU ledger the feedback controller changes.
#[derive(Clone, Debug)]
pub enum CpuFeedbackTarget {
  /// The global soft CPU ceiling shared by every tenant.
  Global(ResourceDomain),
  /// One tenant's soft CPU ceiling, still bounded by the global ceiling.
  Tenant(TenantDomain),
}

/// Owned handles to one CPU control and selected disk/network byte buckets.
/// Use the same buckets in the actual I/O paths; getters or feedback alone
/// do not intercept arbitrary syscalls. Directional policies can select the
/// relevant bucket explicitly rather than claiming a physical traffic limit.
pub struct RuntimeFeedbackActuator {
  cpu: CpuFeedbackTarget,
  disk: ByteRateLimit,
  network: ByteRateLimit,
}

impl RuntimeFeedbackActuator {
  #[must_use]
  pub fn new(cpu: CpuFeedbackTarget, disk: ByteRateLimit, network: ByteRateLimit) -> Self {
    Self { cpu, disk, network }
  }
}

impl FeedbackActuator for RuntimeFeedbackActuator {
  fn readback(&mut self, resource: FeedbackResource) -> Result<u64, FeedbackActuatorError> {
    match resource {
      FeedbackResource::CpuConcurrency => {
        let snapshot = match &self.cpu {
          CpuFeedbackTarget::Global(domain) => domain.snapshot(),
          CpuFeedbackTarget::Tenant(tenant) => tenant
            .snapshot()
            .map_err(|_| FeedbackActuatorError::Unavailable)?,
        };
        u64::try_from(snapshot.limit.get(DomainResource::Cpu))
          .map_err(|_| FeedbackActuatorError::OperationFailed)
      }
      FeedbackResource::DiskRate => Ok(self.disk.snapshot().bytes_per_second),
      FeedbackResource::NetworkRate => Ok(self.network.snapshot().bytes_per_second),
    }
  }

  fn apply(&mut self, ticket: PlanTicket) -> Result<(), FeedbackActuatorError> {
    let changed = match ticket.resource() {
      FeedbackResource::CpuConcurrency => {
        let expected = usize::try_from(ticket.from_limit())
          .map_err(|_| FeedbackActuatorError::OperationFailed)?;
        let desired =
          usize::try_from(ticket.to_limit()).map_err(|_| FeedbackActuatorError::OperationFailed)?;
        match &self.cpu {
          CpuFeedbackTarget::Global(domain) => {
            domain.compare_exchange_limit(DomainResource::Cpu, expected, desired)
          }
          CpuFeedbackTarget::Tenant(tenant) => {
            tenant.compare_exchange_limit(DomainResource::Cpu, expected, desired)
          }
        }
        .map_err(|_| FeedbackActuatorError::OperationFailed)?
      }
      FeedbackResource::DiskRate => self
        .disk
        .compare_exchange_rate(ticket.from_limit(), ticket.to_limit())
        .map_err(|_| FeedbackActuatorError::OperationFailed)?,
      FeedbackResource::NetworkRate => self
        .network
        .compare_exchange_rate(ticket.from_limit(), ticket.to_limit())
        .map_err(|_| FeedbackActuatorError::OperationFailed)?,
    };
    if changed {
      Ok(())
    } else {
      Err(FeedbackActuatorError::OperationFailed)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::byte_rate::ByteRateConfig;
  use crate::runtime::resource_domain::DomainResources;
  use crate::runtime::resource_feedback::{
    FeedbackSensor, FeedbackSensorError, FeedbackShutdownProgress, ResourceFeedbackService,
  };
  use crate::runtime::resource_feedback_policy::{
    FeedbackControlConfig, FeedbackSample, ResourceFeedbackPolicyConfig,
  };
  use std::time::{Duration, Instant};

  struct BusySensor;
  impl FeedbackSensor for BusySensor {
    fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
      Ok(FeedbackSample::new(
        Instant::now(),
        Some(10000),
        Some(10000),
        Some(10000),
      ))
    }
  }

  #[test]
  fn autonomous_service_changes_actual_domain_and_buckets_without_clobbering_bursts() {
    let domain = ResourceDomain::new(
      DomainResources::ZERO
        .with(DomainResource::Cpu, 64)
        .with(DomainResource::Control, 4096),
      1,
    )
    .unwrap();
    let config = ByteRateConfig {
      bytes_per_second: 100,
      burst_bytes: 64,
      max_reservations: 2,
    };
    let disk = ByteRateLimit::new(config).unwrap();
    let network = ByteRateLimit::new(config).unwrap();
    let actuator = RuntimeFeedbackActuator::new(
      CpuFeedbackTarget::Global(domain.clone()),
      disk.clone(),
      network.clone(),
    );
    let policy = ResourceFeedbackPolicyConfig {
      cpu_concurrency: FeedbackControlConfig::new(1, 64, 64, 3000, 8000),
      disk_rate: FeedbackControlConfig::new(1, 100, 100, 3000, 8000),
      network_rate: FeedbackControlConfig::new(1, 100, 100, 3000, 8000),
    };
    let mut service = ResourceFeedbackService::start(policy, BusySensor, actuator).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while domain.snapshot().limit.get(DomainResource::Cpu) == 64
      || disk.snapshot().bytes_per_second == 100
      || network.snapshot().bytes_per_second == 100
    {
      assert!(
        Instant::now() < deadline,
        "actual control changes did not complete"
      );
      std::thread::sleep(Duration::from_millis(10));
    }
    assert!(domain.snapshot().limit.get(DomainResource::Cpu) >= 58);
    assert!(disk.snapshot().bytes_per_second >= 90);
    assert!(network.snapshot().bytes_per_second >= 90);
    assert_eq!(disk.snapshot().burst_bytes, 64);
    assert_eq!(network.snapshot().burst_bytes, 64);
    while service.try_shutdown().unwrap() != FeedbackShutdownProgress::Complete {
      assert!(
        Instant::now() < deadline,
        "feedback worker did not finish shutdown"
      );
      std::thread::yield_now();
    }
  }

  #[test]
  fn tenant_readback_preserves_global_cpu() {
    let domain = ResourceDomain::new(
      DomainResources::ZERO
        .with(DomainResource::Cpu, 64)
        .with(DomainResource::Control, 4096),
      1,
    )
    .unwrap();
    let tenant = domain.tenant(domain.snapshot().ceiling).unwrap();
    tenant
      .set_limits(
        tenant
          .snapshot()
          .unwrap()
          .limit
          .with(DomainResource::Cpu, 32),
      )
      .unwrap();
    let config = ByteRateConfig {
      bytes_per_second: 100,
      burst_bytes: 64,
      max_reservations: 2,
    };
    let mut actuator = RuntimeFeedbackActuator::new(
      CpuFeedbackTarget::Tenant(tenant),
      ByteRateLimit::new(config).unwrap(),
      ByteRateLimit::new(config).unwrap(),
    );
    assert_eq!(
      actuator.readback(FeedbackResource::CpuConcurrency).unwrap(),
      32
    );
    assert_eq!(domain.snapshot().limit.get(DomainResource::Cpu), 64);
  }
}
