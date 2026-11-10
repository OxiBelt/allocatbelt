//! Feedback actuators for managed CPU admission and application-byte buckets.
//!
//! These controls affect their declared runtime domain and selected buckets.
//! They do not write OS quotas or intercept I/O that bypasses those buckets.
//! Component compare-exchange prevents a stale feedback writer from clobbering
//! another controller's limit. Public handles remain explicitly shared.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use super::byte_rate::ByteRateLimit;
use super::resource_domain::{
  DefaultFeedbackRegistration, DomainResource, ResourceDomain, TenantDomain,
};
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

impl CpuFeedbackTarget {
  fn read_limit(&self) -> Result<u64, FeedbackActuatorError> {
    let snapshot = match self {
      Self::Global(domain) => domain.snapshot(),
      Self::Tenant(tenant) => tenant
        .snapshot()
        .map_err(|_| FeedbackActuatorError::Unavailable)?,
    };
    u64::try_from(snapshot.limit.get(DomainResource::Cpu))
      .map_err(|_| FeedbackActuatorError::OperationFailed)
  }

  fn compare_exchange(&self, ticket: PlanTicket) -> Result<bool, FeedbackActuatorError> {
    let expected =
      usize::try_from(ticket.from_limit()).map_err(|_| FeedbackActuatorError::OperationFailed)?;
    let desired =
      usize::try_from(ticket.to_limit()).map_err(|_| FeedbackActuatorError::OperationFailed)?;
    match self {
      Self::Global(domain) => domain.compare_exchange_limit(DomainResource::Cpu, expected, desired),
      Self::Tenant(tenant) => tenant.compare_exchange_limit(DomainResource::Cpu, expected, desired),
    }
    .map_err(|_| FeedbackActuatorError::OperationFailed)
  }
}

/// Owned handles to one CPU control and selected disk/network byte buckets.
/// Use the same buckets in the actual I/O paths; getters or feedback alone
/// do not intercept arbitrary syscalls. Directional policies can select the
/// relevant bucket explicitly rather than claiming a physical traffic limit.
///
/// Every output is a compare-exchange of a limit this runtime keeps: one CPU
/// soft limit of a resource domain and the rate of one bucket per byte
/// dimension. The actuator rejects, delays and reorders no request, changes
/// no priority or thread count, and writes no operating-system or
/// control-group setting. A tenant CPU target is an explicit caller choice.
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
      FeedbackResource::CpuConcurrency => self.cpu.read_limit(),
      FeedbackResource::DiskRate => Ok(self.disk.snapshot().bytes_per_second),
      FeedbackResource::NetworkRate => Ok(self.network.snapshot().bytes_per_second),
    }
  }

  fn apply(&mut self, ticket: PlanTicket) -> Result<(), FeedbackActuatorError> {
    let changed = match ticket.resource() {
      FeedbackResource::CpuConcurrency => self.cpu.compare_exchange(ticket)?,
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

/// Actuator of the default path: the global CPU soft limit and nothing else.
///
/// It owns no byte bucket. Disk and network readbacks return the fixed values
/// given at construction, which are the policy's unselected initial limits,
/// so startup verification compares real configuration rather than a bucket
/// nothing uses. Those dimensions have no admissible change; a disk or
/// network ticket is refused with [`FeedbackActuatorError::Unavailable`] and
/// the service latches that control instead of pretending a write happened.
///
/// The actuator built by the default factory also holds its domain's single
/// default-controller registration and the soft limit it started from. When
/// it is dropped it first returns the limit to that start value with one
/// compare-exchange, only if the limit still equals the last value it wrote
/// successfully and no change of its own failed, and then releases the
/// registration. It never retries or rolls back a failed change.
pub struct GlobalCpuFeedbackActuator {
  cpu: CpuFeedbackTarget,
  fixed_disk_rate: u64,
  fixed_network_rate: u64,
  default: Option<DefaultOwnership>,
}

/// What the default path's actuator owns besides its target.
struct DefaultOwnership {
  start_limit: usize,
  last_applied: Option<usize>,
  failed: bool,
  // Dropped after `GlobalCpuFeedbackActuator::drop` restored the limit.
  _registration: DefaultFeedbackRegistration,
}

impl GlobalCpuFeedbackActuator {
  /// Selects `domain`'s global CPU soft limit. The fixed byte-rate values are
  /// reported unchanged by every readback. An actuator built here takes no
  /// default-controller registration.
  #[must_use]
  pub const fn new(domain: ResourceDomain, fixed_disk_rate: u64, fixed_network_rate: u64) -> Self {
    Self {
      cpu: CpuFeedbackTarget::Global(domain),
      fixed_disk_rate,
      fixed_network_rate,
      default: None,
    }
  }

  /// The default path's actuator. It keeps `registration` until it is
  /// dropped, and `start_limit` is the global CPU soft limit it returns to on
  /// drop when the limit is still the last value it wrote.
  pub(crate) const fn with_default_registration(
    domain: ResourceDomain,
    registration: DefaultFeedbackRegistration,
    start_limit: usize,
    fixed_disk_rate: u64,
    fixed_network_rate: u64,
  ) -> Self {
    Self {
      cpu: CpuFeedbackTarget::Global(domain),
      fixed_disk_rate,
      fixed_network_rate,
      default: Some(DefaultOwnership {
        start_limit,
        last_applied: None,
        failed: false,
        _registration: registration,
      }),
    }
  }

  /// The CPU ledger this actuator changes: always
  /// [`CpuFeedbackTarget::Global`].
  #[must_use]
  pub const fn target(&self) -> &CpuFeedbackTarget {
    &self.cpu
  }
}

impl FeedbackActuator for GlobalCpuFeedbackActuator {
  fn readback(&mut self, resource: FeedbackResource) -> Result<u64, FeedbackActuatorError> {
    match resource {
      FeedbackResource::CpuConcurrency => self.cpu.read_limit(),
      FeedbackResource::DiskRate => Ok(self.fixed_disk_rate),
      FeedbackResource::NetworkRate => Ok(self.fixed_network_rate),
    }
  }

  fn apply(&mut self, ticket: PlanTicket) -> Result<(), FeedbackActuatorError> {
    match ticket.resource() {
      FeedbackResource::CpuConcurrency => {
        let result = match self.cpu.compare_exchange(ticket) {
          Ok(true) => Ok(()),
          Ok(false) => Err(FeedbackActuatorError::OperationFailed),
          Err(error) => Err(error),
        };
        if let Some(default) = &mut self.default {
          match result {
            Ok(()) => default.last_applied = usize::try_from(ticket.to_limit()).ok(),
            Err(_) => default.failed = true,
          }
        }
        result
      }
      FeedbackResource::DiskRate | FeedbackResource::NetworkRate => {
        Err(FeedbackActuatorError::Unavailable)
      }
    }
  }
}

impl Drop for GlobalCpuFeedbackActuator {
  fn drop(&mut self) {
    let (Some(default), CpuFeedbackTarget::Global(domain)) = (&self.default, &self.cpu) else {
      return;
    };
    if default.failed {
      return;
    }
    if let Some(last) = default.last_applied
      && last != default.start_limit
    {
      // Changes nothing if anyone else changed the limit since; a raise
      // wakes CPU waiters like any other increase.
      let _ = domain.compare_exchange_limit(DomainResource::Cpu, last, default.start_limit);
    }
    // The registration is released when `default` is dropped after this.
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

  fn cpu_domain(limit: usize) -> ResourceDomain {
    ResourceDomain::new(
      DomainResources::ZERO
        .with(DomainResource::Cpu, limit)
        .with(DomainResource::Control, 4096),
      1,
    )
    .unwrap()
  }

  #[test]
  fn global_cpu_actuator_targets_the_global_ledger_and_reports_fixed_byte_rates() {
    let domain = cpu_domain(8);
    let mut actuator = GlobalCpuFeedbackActuator::new(domain, 7, 9);
    assert!(matches!(actuator.target(), CpuFeedbackTarget::Global(_)));
    assert_eq!(
      actuator.readback(FeedbackResource::CpuConcurrency).unwrap(),
      8
    );
    assert_eq!(actuator.readback(FeedbackResource::DiskRate).unwrap(), 7);
    assert_eq!(actuator.readback(FeedbackResource::NetworkRate).unwrap(), 9);
  }

  #[test]
  fn global_cpu_actuator_lowers_only_the_global_cpu_soft_limit() {
    let domain = cpu_domain(20);
    let tenant = domain.tenant(domain.snapshot().ceiling).unwrap();
    let policy = ResourceFeedbackPolicyConfig {
      cpu_concurrency: FeedbackControlConfig::new(1, 20, 20, 4000, 8000),
      disk_rate: FeedbackControlConfig::new(5, 5, 5, 4000, 8000),
      network_rate: FeedbackControlConfig::new(6, 6, 6, 4000, 8000),
    };
    let actuator = GlobalCpuFeedbackActuator::new(domain.clone(), 5, 6);
    let mut service = ResourceFeedbackService::start(policy, BusySensor, actuator).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while domain.snapshot().limit.get(DomainResource::Cpu) == 20 {
      assert!(Instant::now() < deadline, "global CPU limit did not change");
      std::thread::sleep(Duration::from_millis(10));
    }
    // The first reduction is 20 -> 18; a stalled test thread may see a later one.
    assert!(domain.snapshot().limit.get(DomainResource::Cpu) <= 18);
    assert_eq!(domain.snapshot().ceiling.get(DomainResource::Cpu), 20);
    assert_eq!(
      tenant.snapshot().unwrap().limit.get(DomainResource::Cpu),
      20
    );
    while service.try_shutdown().unwrap() != FeedbackShutdownProgress::Complete {
      assert!(
        Instant::now() < deadline,
        "feedback worker did not finish shutdown"
      );
      std::thread::yield_now();
    }
  }

  fn stop_service(mut service: ResourceFeedbackService) {
    let deadline = Instant::now() + Duration::from_secs(5);
    service.request_stop();
    while service.try_shutdown().unwrap() != FeedbackShutdownProgress::Complete {
      assert!(
        Instant::now() < deadline,
        "feedback worker did not finish shutdown"
      );
      std::thread::yield_now();
    }
  }

  fn start_default_busy(domain: &ResourceDomain) -> ResourceFeedbackService {
    let registration = domain.try_register_default_feedback().unwrap();
    let policy = ResourceFeedbackPolicyConfig {
      cpu_concurrency: FeedbackControlConfig::new(1, 20, 20, 4000, 8000),
      disk_rate: FeedbackControlConfig::new(5, 5, 5, 4000, 8000),
      network_rate: FeedbackControlConfig::new(6, 6, 6, 4000, 8000),
    };
    let actuator =
      GlobalCpuFeedbackActuator::with_default_registration(domain.clone(), registration, 20, 5, 6);
    ResourceFeedbackService::start(policy, BusySensor, actuator).unwrap()
  }

  fn wait_until_lowered(domain: &ResourceDomain) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while domain.snapshot().limit.get(DomainResource::Cpu) == 20 {
      assert!(Instant::now() < deadline, "global CPU limit did not change");
      std::thread::sleep(Duration::from_millis(10));
    }
  }

  #[test]
  fn default_actuator_returns_the_limit_it_lowered_when_it_stops() {
    let domain = cpu_domain(20);
    let service = start_default_busy(&domain);
    wait_until_lowered(&domain);
    assert!(domain.try_register_default_feedback().is_none());
    stop_service(service);
    // The limit is back at the start value before the registration is free.
    assert_eq!(domain.snapshot().limit.get(DomainResource::Cpu), 20);
    assert!(domain.try_register_default_feedback().is_some());
  }

  #[test]
  fn default_actuator_leaves_an_externally_changed_limit_in_place() {
    let domain = cpu_domain(20);
    let service = start_default_busy(&domain);
    wait_until_lowered(&domain);
    let snapshot = domain.snapshot();
    domain
      .set_limits(snapshot.limit.with(DomainResource::Cpu, 7))
      .unwrap();
    stop_service(service);
    assert_eq!(domain.snapshot().limit.get(DomainResource::Cpu), 7);
    assert!(domain.try_register_default_feedback().is_some());
  }

  #[test]
  fn default_actuator_that_never_wrote_changes_nothing_on_drop() {
    let domain = cpu_domain(20);
    let registration = domain.try_register_default_feedback().unwrap();
    domain
      .set_limits(domain.snapshot().limit.with(DomainResource::Cpu, 12))
      .unwrap();
    drop(GlobalCpuFeedbackActuator::with_default_registration(
      domain.clone(),
      registration,
      20,
      5,
      6,
    ));
    assert_eq!(domain.snapshot().limit.get(DomainResource::Cpu), 12);
    assert!(domain.try_register_default_feedback().is_some());
  }
}
