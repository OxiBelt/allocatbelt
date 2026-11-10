//! Cloneable factories for feedback services owned by runtime drivers.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::io;
use std::num::NonZeroU32;
use std::sync::Arc;

use super::super::asynchronous::RuntimeMetrics;
use super::super::byte_rate::ByteRateLimit;
use super::super::managed::ResourceScope;
use super::super::resource_domain::{DomainError, DomainResource, TenantDomain};
use super::super::resource_feedback::{
  FeedbackActuator, FeedbackHistoryConfig, FeedbackSensor, FeedbackStartError,
  ResourceFeedbackService,
};
use super::super::resource_feedback_actuator::GlobalCpuFeedbackActuator;
use super::super::resource_feedback_defaults::default_cpu_capacity;
use super::super::resource_feedback_meter::IoFeedbackMeter;
use super::super::resource_feedback_policy::{
  PolicyError, ResourceFeedbackPolicy, ResourceFeedbackPolicyConfig,
};
use super::super::resource_feedback_sensor::ProcessCpuSensor;

/// Owned runtime resources a feedback source may select from.
///
/// The byte buckets account application admission. A factory must choose the
/// bucket that matches its metric and must install the same bucket in the
/// corresponding I/O path; this context does not imply physical traffic
/// interception. Current-thread drivers have no executor thread metrics, so
/// `runtime_metrics` is `None` there.
#[derive(Clone)]
pub struct FeedbackContext {
  /// Root managed-resource scope, including its bound tenant when selected.
  pub resources: ResourceScope,
  /// Explicit disk application-byte bucket.
  pub disk_rate: Option<ByteRateLimit>,
  /// Network bytes admitted for uploads.
  pub upload_rate: Option<ByteRateLimit>,
  /// Network bytes admitted for downloads.
  pub download_rate: Option<ByteRateLimit>,
  /// Application-byte telemetry shared with explicitly wrapped disk reads and writes.
  pub disk_meter: IoFeedbackMeter,
  /// Application-byte telemetry shared with explicitly wrapped upload writes.
  pub upload_meter: IoFeedbackMeter,
  /// Application-byte telemetry shared with explicitly wrapped download reads.
  pub download_meter: IoFeedbackMeter,
  /// Multithread executor diagnostics, when the driver has them.
  pub runtime_metrics: Option<RuntimeMetrics>,
}

impl fmt::Debug for FeedbackContext {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("FeedbackContext")
      .field("resource_scope", &self.resources.snapshot())
      .field(
        "disk_rate",
        &self.disk_rate.as_ref().map(ByteRateLimit::snapshot),
      )
      .field(
        "upload_rate",
        &self.upload_rate.as_ref().map(ByteRateLimit::snapshot),
      )
      .field(
        "download_rate",
        &self.download_rate.as_ref().map(ByteRateLimit::snapshot),
      )
      .field("runtime_metrics_enabled", &self.runtime_metrics.is_some())
      .field("disk_meter_selected", &true)
      .field("upload_meter_selected", &true)
      .field("download_meter_selected", &true)
      .finish()
  }
}

/// Fixed set of feedback meters retained by an opted-in owning driver.
///
/// The owner creates these only when a feedback factory is configured, so
/// default drivers do not allocate meter state or take meter timestamps.
#[derive(Clone)]
pub(crate) struct FeedbackMeters {
  pub(crate) disk: IoFeedbackMeter,
  pub(crate) upload: IoFeedbackMeter,
  pub(crate) download: IoFeedbackMeter,
}

impl FeedbackMeters {
  pub(crate) fn new() -> Self {
    Self {
      disk: IoFeedbackMeter::new(),
      upload: IoFeedbackMeter::new(),
      download: IoFeedbackMeter::new(),
    }
  }

  pub(crate) fn new_in_tenant(tenant: &TenantDomain) -> Result<Self, DomainError> {
    Ok(Self {
      disk: IoFeedbackMeter::new_in_tenant(tenant)?,
      upload: IoFeedbackMeter::new_in_tenant(tenant)?,
      download: IoFeedbackMeter::new_in_tenant(tenant)?,
    })
  }
}

/// Why an owning driver could not construct its selected feedback service.
#[derive(Debug)]
#[non_exhaustive]
pub enum FeedbackFactoryError {
  /// Policy configuration failed validation before any worker was started.
  InvalidPolicy(PolicyError),
  /// Caller-provided source construction failed.
  Sources(io::Error),
  /// Sensor, actuator, or feedback worker startup failed.
  Service(FeedbackStartError),
  /// History-enabled feedback requires a tenant whose Control ledger can
  /// charge the retained ring.
  HistoryRequiresTenant,
  /// The default factory changes the global CPU soft limit of the driver's
  /// resource domain, and the builder selected none. Nothing was started.
  DefaultRequiresResourceDomain,
}

impl fmt::Display for FeedbackFactoryError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidPolicy(error) => write!(f, "invalid feedback policy: {error}"),
      Self::Sources(error) => write!(f, "feedback source construction failed: {error}"),
      Self::Service(error) => error.fmt(f),
      Self::HistoryRequiresTenant => {
        f.write_str("feedback history requires a tenant Control ledger")
      }
      Self::DefaultRequiresResourceDomain => {
        f.write_str("default feedback requires a driver resource domain")
      }
    }
  }
}

impl std::error::Error for FeedbackFactoryError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::InvalidPolicy(error) => Some(error),
      Self::Sources(error) => Some(error),
      Self::Service(error) => Some(error),
      Self::HistoryRequiresTenant | Self::DefaultRequiresResourceDomain => None,
    }
  }
}

type BuildFeedbackService =
  dyn Fn(FeedbackContext) -> Result<ResourceFeedbackService, FeedbackFactoryError> + Send + Sync;

/// Cloneable source factory stored by an owning driver builder.
///
/// Clones share only the immutable factory closure. Each driver build invokes
/// it once with that build's fresh resource and bucket handles and receives a
/// separate owned sensor, actuator, and service.
#[derive(Clone)]
pub struct FeedbackFactory {
  build: Arc<BuildFeedbackService>,
  invalid_policy: Option<PolicyError>,
}

impl FeedbackFactory {
  pub(crate) fn validate(&self) -> Result<(), FeedbackFactoryError> {
    match self.invalid_policy {
      Some(error) => Err(FeedbackFactoryError::InvalidPolicy(error)),
      None => Ok(()),
    }
  }

  pub(crate) fn build(
    &self,
    context: FeedbackContext,
  ) -> Result<ResourceFeedbackService, FeedbackFactoryError> {
    self.validate()?;
    (self.build)(context)
  }
}

impl fmt::Debug for FeedbackFactory {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("FeedbackFactory")
      .field("policy_valid", &self.invalid_policy.is_none())
      .finish_non_exhaustive()
  }
}

/// Creates a reusable feedback source factory after validating its policy.
///
/// `sources` runs once per driver build, after ordinary runtime services are
/// ready and before the permanent process-signal bridge is installed. It
/// receives freshly built resource handles and returns an owned sensor and
/// actuator. If source construction or service startup fails, the driver
/// rolls back services it owns; side effects the closure performs outside that
/// ownership are the closure's responsibility.
pub fn feedback_sources<F, S, A>(
  policy: ResourceFeedbackPolicyConfig,
  sources: F,
) -> FeedbackFactory
where
  F: Fn(FeedbackContext) -> io::Result<(S, A)> + Send + Sync + 'static,
  S: FeedbackSensor,
  A: FeedbackActuator,
{
  feedback_sources_inner(policy, None, sources)
}

/// Creates a reusable feedback source factory with charged bounded history.
///
/// Every driver build must provide a tenant-bound resource scope. History is
/// reserved from that tenant's Control ledger before source callbacks or
/// actuator readbacks run; ordinary [`feedback_sources`] remains history-off.
pub fn feedback_sources_with_history<F, S, A>(
  policy: ResourceFeedbackPolicyConfig,
  history: FeedbackHistoryConfig,
  sources: F,
) -> FeedbackFactory
where
  F: Fn(FeedbackContext) -> io::Result<(S, A)> + Send + Sync + 'static,
  S: FeedbackSensor,
  A: FeedbackActuator,
{
  feedback_sources_inner(policy, Some(history), sources)
}

fn feedback_sources_inner<F, S, A>(
  policy: ResourceFeedbackPolicyConfig,
  history: Option<FeedbackHistoryConfig>,
  sources: F,
) -> FeedbackFactory
where
  F: Fn(FeedbackContext) -> io::Result<(S, A)> + Send + Sync + 'static,
  S: FeedbackSensor,
  A: FeedbackActuator,
{
  let invalid_policy = ResourceFeedbackPolicy::new(policy).err();
  let build = Arc::new(move |context: FeedbackContext| {
    let tenant = context.resources.tenant_domain().cloned();
    let service = if let Some(history) = history {
      let Some(tenant) = tenant else {
        return Err(FeedbackFactoryError::HistoryRequiresTenant);
      };
      let prepared =
        ResourceFeedbackService::prepare_in_tenant_with_history::<S, A>(policy, &tenant, history)
          .map_err(FeedbackFactoryError::Service)?;
      let (sensor, actuator) = sources(context).map_err(FeedbackFactoryError::Sources)?;
      ResourceFeedbackService::start_with_prepared_history(sensor, actuator, prepared)
    } else {
      let (sensor, actuator) = sources(context).map_err(FeedbackFactoryError::Sources)?;
      match tenant {
        Some(tenant) => ResourceFeedbackService::start_in_tenant(policy, sensor, actuator, &tenant),
        None => ResourceFeedbackService::start(policy, sensor, actuator),
      }
    };
    service.map_err(FeedbackFactoryError::Service)
  });
  FeedbackFactory {
    build,
    invalid_policy,
  }
}

/// Creates the default feedback factory for this process's CPU capacity.
///
/// Feedback stays off until a builder selects this factory with
/// `feedback_sources`. The capacity is the standard library's parallelism
/// query (one if it fails), read once here by `default_cpu_capacity`; see
/// [`default_feedback_for_capacity`] for everything derived from it.
#[must_use]
pub fn default_feedback() -> FeedbackFactory {
  default_feedback_for_capacity(default_cpu_capacity())
}

/// Creates the default feedback factory for an explicit CPU capacity.
///
/// The policy is [`ResourceFeedbackPolicyConfig::process_default`]. Each
/// driver build opens a [`ProcessCpuSensor`], which reads this process's CPU
/// time and reports disk and network utilization as missing, and a
/// [`GlobalCpuFeedbackActuator`] on the global CPU soft limit of the domain
/// the builder's `resource_domain` tenant belongs to. No tenant limit, byte
/// bucket or byte meter is selected, so only that one limit can change.
///
/// `cpu_capacity` is the sensor's utilization denominator. The CPU control
/// starts at the global CPU soft limit the domain has when the driver is
/// built and stays between `DEFAULT_CPU_FLOOR` and the domain's hard CPU
/// ceiling, so a limit lowered by an earlier driver can recover. Reductions
/// are a tenth of the current limit, so a limit below ten does not fall.
/// A domain without CPU, or a ceiling the policy cannot represent, fails with
/// [`FeedbackFactoryError::InvalidPolicy`]; startup failures are reported as
/// [`FeedbackFactoryError::Service`]. Select the default factory for at most
/// one driver per domain: two services moving the same limit see each
/// other's changes as external drift and latch.
///
/// A builder without `resource_domain` has no CPU ledger to change; the build
/// fails with [`FeedbackFactoryError::DefaultRequiresResourceDomain`] before
/// any sensor is opened rather than adjusting a ledger nothing admits against.
#[must_use]
pub fn default_feedback_for_capacity(cpu_capacity: NonZeroU32) -> FeedbackFactory {
  let policy = ResourceFeedbackPolicyConfig::process_default(cpu_capacity);
  let invalid_policy = ResourceFeedbackPolicy::new(policy).err();
  let build = Arc::new(move |context: FeedbackContext| {
    let Some(tenant) = context.resources.tenant_domain().cloned() else {
      return Err(FeedbackFactoryError::DefaultRequiresResourceDomain);
    };
    let global = tenant.global_domain();
    let snapshot = global.snapshot();
    let to_u64 = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
    let mut policy = policy;
    policy.cpu_concurrency.initial = to_u64(snapshot.limit.get(DomainResource::Cpu));
    policy.cpu_concurrency.ceiling = to_u64(snapshot.ceiling.get(DomainResource::Cpu));
    ResourceFeedbackPolicy::new(policy).map_err(FeedbackFactoryError::InvalidPolicy)?;
    let sensor = ProcessCpuSensor::new(cpu_capacity).map_err(FeedbackFactoryError::Sources)?;
    let actuator = GlobalCpuFeedbackActuator::new(
      global,
      policy.disk_rate.initial,
      policy.network_rate.initial,
    );
    ResourceFeedbackService::start_in_tenant(policy, sensor, actuator, &tenant)
      .map_err(FeedbackFactoryError::Service)
  });
  FeedbackFactory {
    build,
    invalid_policy,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::num::NonZeroUsize;
  use std::sync::atomic::{AtomicU64, Ordering};
  use std::time::{Duration, Instant};

  use crate::runtime::managed::ResourceLimits;
  use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};
  use crate::runtime::resource_feedback::{
    FeedbackActuatorError, FeedbackEventKind, FeedbackSensorError, FeedbackShutdownProgress,
  };
  use crate::runtime::resource_feedback_policy::{
    FeedbackControlConfig, FeedbackResource, FeedbackSample, NoChangeReason, PlanTicket,
    TelemetryStatus, UNSELECTED_BYTE_RATE,
  };

  struct QuietSensor;

  impl FeedbackSensor for QuietSensor {
    fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
      Ok(FeedbackSample::new(Instant::now(), None, None, None))
    }
  }

  struct FixedActuator([AtomicU64; 3]);

  impl FixedActuator {
    fn new() -> Self {
      Self([
        AtomicU64::new(16),
        AtomicU64::new(1000),
        AtomicU64::new(1000),
      ])
    }
  }

  impl FeedbackActuator for FixedActuator {
    fn readback(&mut self, resource: FeedbackResource) -> Result<u64, FeedbackActuatorError> {
      Ok(self.0[resource as usize].load(Ordering::SeqCst))
    }

    fn apply(&mut self, _ticket: PlanTicket) -> Result<(), FeedbackActuatorError> {
      Ok(())
    }
  }

  fn policy() -> ResourceFeedbackPolicyConfig {
    ResourceFeedbackPolicyConfig {
      cpu_concurrency: FeedbackControlConfig::new(4, 16, 64, 3000, 8000),
      disk_rate: FeedbackControlConfig::new(100, 1000, 2000, 3000, 8000),
      network_rate: FeedbackControlConfig::new(100, 1000, 2000, 3000, 8000),
    }
  }

  fn stable_control_usage(domain: &ResourceDomain, timeout: Duration) -> usize {
    let deadline = Instant::now() + timeout;
    let mut previous = None;
    let mut stable_reads = 0;
    loop {
      let current = domain.snapshot().used.get(DomainResource::Control);
      if previous == Some(current) {
        stable_reads += 1;
        if stable_reads == 5 {
          return current;
        }
      } else {
        previous = Some(current);
        stable_reads = 0;
      }
      assert!(Instant::now() < deadline, "Control usage did not settle");
      std::thread::sleep(Duration::from_millis(1));
    }
  }

  #[test]
  fn tenant_bound_feedback_factory_uses_charged_service_startup() {
    let ceiling = DomainResources::ZERO.with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 0).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let before = domain.snapshot().used.get(DomainResource::Control);
    let resources = ResourceScope::from_tenant(ResourceLimits::default(), tenant);
    let context = FeedbackContext {
      resources,
      disk_rate: None,
      upload_rate: None,
      download_rate: None,
      disk_meter: IoFeedbackMeter::new(),
      upload_meter: IoFeedbackMeter::new(),
      download_meter: IoFeedbackMeter::new(),
      runtime_metrics: None,
    };
    let factory = feedback_sources(policy(), |_| Ok((QuietSensor, FixedActuator::new())));
    let mut service = factory.build(context).unwrap();
    assert!(domain.snapshot().used.get(DomainResource::Control) > before);

    service.request_stop();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      match service.try_shutdown() {
        Ok(FeedbackShutdownProgress::Complete) => break,
        Ok(FeedbackShutdownProgress::Pending) => {
          assert!(Instant::now() < deadline, "factory service did not stop");
          std::thread::yield_now();
        }
        Err(error) => panic!("factory service failed to stop: {error}"),
      }
    }
    let metrics = service.metrics_handle();
    drop(service);
    let retained = stable_control_usage(&domain, Duration::from_secs(2));
    assert!(retained > before);
    drop(metrics);
    assert_eq!(
      stable_control_usage(&domain, Duration::from_secs(2)),
      before
    );
  }

  #[test]
  fn history_feedback_factory_requires_a_tenant_before_source_construction() {
    let called = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let source_called = Arc::clone(&called);
    let factory = feedback_sources_with_history(
      policy(),
      FeedbackHistoryConfig::new(NonZeroUsize::new(8).unwrap()),
      move |_| {
        source_called.fetch_add(1, Ordering::SeqCst);
        Ok((QuietSensor, FixedActuator::new()))
      },
    );
    let context = FeedbackContext {
      resources: ResourceScope::new(ResourceLimits::default()),
      disk_rate: None,
      upload_rate: None,
      download_rate: None,
      disk_meter: IoFeedbackMeter::new(),
      upload_meter: IoFeedbackMeter::new(),
      download_meter: IoFeedbackMeter::new(),
      runtime_metrics: None,
    };
    assert!(matches!(
      factory.build(context),
      Err(FeedbackFactoryError::HistoryRequiresTenant)
    ));
    assert_eq!(called.load(Ordering::SeqCst), 0);
  }

  #[test]
  fn history_feedback_factory_reserves_control_before_source_construction() {
    let ceiling = DomainResources::ZERO.with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 0).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    tenant
      .set_limits(DomainResources::ZERO.with(DomainResource::Control, 0))
      .unwrap();
    let source_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_calls = Arc::clone(&source_calls);
    let factory = feedback_sources_with_history(
      policy(),
      FeedbackHistoryConfig::new(NonZeroUsize::new(8).unwrap()),
      move |_| {
        observed_calls.fetch_add(1, Ordering::SeqCst);
        Ok((QuietSensor, FixedActuator::new()))
      },
    );
    let context = FeedbackContext {
      resources: ResourceScope::from_tenant(ResourceLimits::default(), tenant),
      disk_rate: None,
      upload_rate: None,
      download_rate: None,
      disk_meter: IoFeedbackMeter::new(),
      upload_meter: IoFeedbackMeter::new(),
      download_meter: IoFeedbackMeter::new(),
      runtime_metrics: None,
    };

    assert!(matches!(
      factory.build(context),
      Err(FeedbackFactoryError::Service(FeedbackStartError::Domain(
        DomainError::Exhausted(DomainResource::Control)
      )))
    ));
    assert_eq!(source_calls.load(Ordering::SeqCst), 0);
  }

  #[test]
  fn history_feedback_factory_releases_precharge_when_source_creation_fails() {
    let ceiling = DomainResources::ZERO.with(DomainResource::Control, 1 << 20);
    let domain = Arc::new(ResourceDomain::with_waiters(ceiling, 1, 0).unwrap());
    let tenant = domain.tenant(ceiling).unwrap();
    let before = domain.snapshot().used.get(DomainResource::Control);
    let observed_domain = Arc::clone(&domain);
    let saw_precharge = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let source_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_precharge = Arc::clone(&saw_precharge);
    let observed_calls = Arc::clone(&source_calls);
    let factory = feedback_sources_with_history(
      policy(),
      FeedbackHistoryConfig::new(NonZeroUsize::new(8).unwrap()),
      move |_| -> io::Result<(QuietSensor, FixedActuator)> {
        observed_calls.fetch_add(1, Ordering::SeqCst);
        observed_precharge.store(
          observed_domain.snapshot().used.get(DomainResource::Control) > before,
          Ordering::SeqCst,
        );
        Err(io::Error::other("intentional source construction refusal"))
      },
    );
    let context = FeedbackContext {
      resources: ResourceScope::from_tenant(ResourceLimits::default(), tenant),
      disk_rate: None,
      upload_rate: None,
      download_rate: None,
      disk_meter: IoFeedbackMeter::new(),
      upload_meter: IoFeedbackMeter::new(),
      download_meter: IoFeedbackMeter::new(),
      runtime_metrics: None,
    };

    assert!(matches!(
      factory.build(context),
      Err(FeedbackFactoryError::Sources(_))
    ));
    assert_eq!(source_calls.load(Ordering::SeqCst), 1);
    assert!(saw_precharge.load(Ordering::SeqCst));
    assert_eq!(
      stable_control_usage(&domain, Duration::from_secs(2)),
      before
    );
  }

  #[test]
  fn history_feedback_factory_records_joined_shutdown_and_retains_charge_with_handle() {
    let ceiling = DomainResources::ZERO.with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 0).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let before = domain.snapshot().used.get(DomainResource::Control);
    let context = FeedbackContext {
      resources: ResourceScope::from_tenant(ResourceLimits::default(), tenant),
      disk_rate: None,
      upload_rate: None,
      download_rate: None,
      disk_meter: IoFeedbackMeter::new(),
      upload_meter: IoFeedbackMeter::new(),
      download_meter: IoFeedbackMeter::new(),
      runtime_metrics: None,
    };
    let factory = feedback_sources_with_history(
      policy(),
      FeedbackHistoryConfig::new(NonZeroUsize::new(32).unwrap()),
      |_| Ok((QuietSensor, FixedActuator::new())),
    );
    let mut service = factory.build(context).unwrap();
    let metrics = service.metrics_handle();
    let retained_metrics = metrics.clone();
    assert!(domain.snapshot().used.get(DomainResource::Control) > before);

    service.request_stop();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      match service.try_shutdown() {
        Ok(FeedbackShutdownProgress::Complete) => break,
        Ok(FeedbackShutdownProgress::Pending) => {
          assert!(Instant::now() < deadline, "history service did not join");
          std::thread::yield_now();
        }
        Err(error) => panic!("history service failed to join: {error}"),
      }
    }
    let mut events = [None; 8];
    let read = metrics.read_history_after(0, &mut events).unwrap();
    assert!(events[..read.written].iter().any(|event| matches!(
      event.unwrap().kind,
      FeedbackEventKind::WorkerJoined { panicked: false }
    )));
    drop(service);
    let retained = stable_control_usage(&domain, Duration::from_secs(2));
    assert!(retained > before);
    drop(metrics);
    assert_eq!(
      stable_control_usage(&domain, Duration::from_secs(2)),
      retained
    );
    drop(retained_metrics);
    assert_eq!(
      stable_control_usage(&domain, Duration::from_secs(2)),
      before
    );
  }

  fn bare_context(resources: ResourceScope) -> FeedbackContext {
    FeedbackContext {
      resources,
      disk_rate: None,
      upload_rate: None,
      download_rate: None,
      disk_meter: IoFeedbackMeter::new(),
      upload_meter: IoFeedbackMeter::new(),
      download_meter: IoFeedbackMeter::new(),
      runtime_metrics: None,
    }
  }

  fn stop(mut service: ResourceFeedbackService) {
    service.request_stop();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !matches!(
      service.try_shutdown(),
      Ok(FeedbackShutdownProgress::Complete)
    ) {
      assert!(Instant::now() < deadline, "default service did not stop");
      std::thread::yield_now();
    }
  }

  #[test]
  fn default_feedback_without_a_resource_domain_fails_with_a_typed_error() {
    let factory = default_feedback();
    assert!(factory.validate().is_ok());
    assert!(matches!(
      factory.build(bare_context(ResourceScope::new(ResourceLimits::default()))),
      Err(FeedbackFactoryError::DefaultRequiresResourceDomain)
    ));
  }

  #[test]
  fn default_feedback_controls_only_the_global_cpu_limit_and_freezes_byte_rates() {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 6)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 0).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let factory = default_feedback_for_capacity(NonZeroU32::new(6).unwrap());
    let service = factory
      .build(bare_context(ResourceScope::from_tenant(
        ResourceLimits::default(),
        tenant.clone(),
      )))
      .unwrap();
    let metrics = service.metrics_handle();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
      let snapshot = metrics.snapshot();
      // The CPU sensor's first read is a baseline; wait for real plans.
      let frozen = snapshot.sample_count >= 3;
      if frozen {
        for resource in [FeedbackResource::DiskRate, FeedbackResource::NetworkRate] {
          let control = snapshot.control(resource);
          assert_eq!(control.current_limit, UNSELECTED_BYTE_RATE);
          assert_eq!(control.telemetry, TelemetryStatus::Missing);
          assert_eq!(control.utilization_basis_points, None);
          assert_eq!(
            control.no_change,
            Some(NoChangeReason::TelemetryUnavailable)
          );
          assert!(!control.policy_faulted);
        }
        assert_eq!(
          snapshot
            .control(FeedbackResource::CpuConcurrency)
            .current_limit,
          6
        );
        break;
      }
      assert!(
        Instant::now() < deadline,
        "byte dimensions did not report missing"
      );
      std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(domain.snapshot().limit.get(DomainResource::Cpu), 6);
    assert_eq!(tenant.snapshot().unwrap().limit.get(DomainResource::Cpu), 6);
    stop(service);
  }

  #[test]
  fn default_feedback_starts_at_the_soft_limit_below_the_hard_ceiling() {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 9)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 0).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    // An earlier owner lowered the soft limit; the capacity differs from both.
    assert!(
      domain
        .compare_exchange_limit(DomainResource::Cpu, 9, 5)
        .unwrap()
    );
    let factory = default_feedback_for_capacity(NonZeroU32::new(4).unwrap());
    let service = factory
      .build(bare_context(ResourceScope::from_tenant(
        ResourceLimits::default(),
        tenant,
      )))
      .unwrap();
    assert_eq!(
      service
        .metrics()
        .control(FeedbackResource::CpuConcurrency)
        .current_limit,
      5
    );
    assert_eq!(domain.snapshot().limit.get(DomainResource::Cpu), 5);
    assert_eq!(domain.snapshot().ceiling.get(DomainResource::Cpu), 9);
    stop(service);
  }

  #[test]
  fn default_feedback_rejects_a_zero_global_cpu_limit() {
    let ceiling = DomainResources::ZERO.with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 0).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let factory = default_feedback_for_capacity(NonZeroU32::new(4).unwrap());
    assert!(matches!(
      factory.build(bare_context(ResourceScope::from_tenant(
        ResourceLimits::default(),
        tenant,
      ))),
      Err(FeedbackFactoryError::InvalidPolicy(_))
    ));
  }
}
