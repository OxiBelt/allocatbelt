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
use super::super::resource_domain::{DomainError, DomainResource, ResourceDomain, TenantDomain};
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

/// Fixed set of feedback meters retained by an owning driver.
///
/// The owner creates these only when a builder selects a factory with
/// `feedback_sources`. The default service reads no byte meter, so drivers
/// built with the default selection, or with feedback turned off, allocate no
/// meter state and their I/O paths take no meter timestamps.
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
  /// Another default feedback service already controls the driver's resource
  /// domain. A domain has at most one; nothing was started.
  DefaultDomainAlreadyControlled,
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
      Self::DefaultDomainAlreadyControlled => {
        f.write_str("another default feedback service already controls this resource domain")
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
      Self::HistoryRequiresTenant
      | Self::DefaultRequiresResourceDomain
      | Self::DefaultDomainAlreadyControlled => None,
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
/// A builder with a `resource_domain` already starts the same service by
/// default; selecting this factory with `feedback_sources` makes its startup
/// errors fail the build instead of being recorded in the driver's feedback
/// status. Because a domain has one default service at a time, selecting it
/// for a driver of a domain whose default service already runs (for example,
/// one an earlier driver started implicitly) fails with
/// [`FeedbackFactoryError::DefaultDomainAlreadyControlled`]. See
/// [`default_feedback_for_capacity`] for what the service changes and costs.
///
/// The capacity is the standard library's parallelism query (one if it
/// fails), read once here by `default_cpu_capacity`.
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
/// # What the default service changes
///
/// Bound runtimes take one CPU unit of their domain for each active poll or
/// blocking call, so the global CPU soft limit bounds the simultaneous polls
/// and blocking calls of every runtime bound to that domain, across all of
/// its drivers and tenants, not only explicit CPU gates. The service starts
/// at the soft limit it finds and never raises the limit above that value.
/// After three dense readings at or above 80% of process CPU time over
/// `cpu_capacity`, it lowers the limit by a tenth of its current value; a
/// limit below ten does not fall, so one that starts at ten or more stops at
/// nine. At or below 40% it raises a lowered limit by one slot, at most once
/// per second, back toward the start value. When the service stops, it
/// returns the limit to the start value with one compare-exchange, but only
/// if the limit is still the last value it wrote and none of its changes
/// failed. The reading is process-wide, so the default services of several
/// domains in one process react to the same readings. Behaviour under real
/// pressure is not qualified.
///
/// Changing the global CPU soft limit while the service runs is external
/// drift: the service latches that control (visible through the driver's
/// `feedback_metrics()`) until the driver's `request_feedback_reconcile` is
/// called, and it does not restore a limit someone else changed.
///
/// # What it costs
///
/// Each service keeps a `Control` charge on the tenant that built the driver
/// (its shared state, worker and monitor payloads and
/// `ResourceFeedbackService::owner_payload_bytes()` of owner payload), runs
/// two threads (the sampler and a join monitor) and keeps one descriptor on
/// `/proc/self/stat` open, read every 100 ms on the real clock, also for a
/// driver whose application clock is paused or virtual. Driver shutdown waits
/// for the sampler to stop.
///
/// # One default service per domain
///
/// Two services moving the same limit would see each other's changes as
/// external drift and latch. While another default service (selected
/// explicitly or started by default) holds the domain, the build fails with
/// [`FeedbackFactoryError::DefaultDomainAlreadyControlled`]. The registration
/// is released when that service's actuator is dropped: after its sampler
/// stopped, after its startup failed, or, for a driver dropped without
/// shutdown, when its detached sampler exits, so an immediate rebuild may
/// still find the domain controlled.
///
/// A domain whose CPU soft limit is zero, or a limit the policy cannot
/// represent, fails with [`FeedbackFactoryError::InvalidPolicy`]; startup
/// failures are reported as [`FeedbackFactoryError::Service`]. A builder
/// without `resource_domain` has no CPU ledger to change; the build fails
/// with [`FeedbackFactoryError::DefaultRequiresResourceDomain`] before any
/// sensor is opened rather than adjusting a ledger nothing admits against.
#[must_use]
pub fn default_feedback_for_capacity(cpu_capacity: NonZeroU32) -> FeedbackFactory {
  let invalid_policy =
    ResourceFeedbackPolicy::new(ResourceFeedbackPolicyConfig::process_default(cpu_capacity)).err();
  let build = Arc::new(move |context: FeedbackContext| {
    let Some(tenant) = context.resources.tenant_domain().cloned() else {
      return Err(FeedbackFactoryError::DefaultRequiresResourceDomain);
    };
    start_default_service(&tenant, || cpu_capacity)
  });
  FeedbackFactory {
    build,
    invalid_policy,
  }
}

/// The default policy on `global`'s current CPU soft limit: the control
/// starts at that limit and uses it as its ceiling, so it never rises above
/// what the caller configured.
pub(crate) fn default_policy_for_domain(
  global: &ResourceDomain,
  cpu_capacity: NonZeroU32,
) -> Result<ResourceFeedbackPolicyConfig, PolicyError> {
  let limit = global.snapshot().limit.get(DomainResource::Cpu);
  let limit = u64::try_from(limit).unwrap_or(u64::MAX);
  let mut policy = ResourceFeedbackPolicyConfig::process_default(cpu_capacity);
  policy.cpu_concurrency.initial = limit;
  policy.cpu_concurrency.ceiling = limit;
  ResourceFeedbackPolicy::new(policy)?;
  Ok(policy)
}

/// Starts the default service on the global CPU soft limit of `tenant`'s
/// domain, shared by the explicit factory and the builder's default selection.
///
/// The domain's default-controller registration is taken first, then the CPU
/// capacity is obtained and the limit read; the registration moves into the
/// actuator, and every failure below drops it again.
pub(crate) fn start_default_service(
  tenant: &TenantDomain,
  cpu_capacity: impl FnOnce() -> NonZeroU32,
) -> Result<ResourceFeedbackService, FeedbackFactoryError> {
  let global = tenant.global_domain();
  let registration = global
    .try_register_default_feedback()
    .ok_or(FeedbackFactoryError::DefaultDomainAlreadyControlled)?;
  let cpu_capacity = cpu_capacity();
  let policy = default_policy_for_domain(&global, cpu_capacity)
    .map_err(FeedbackFactoryError::InvalidPolicy)?;
  // The policy accepted this limit, so it fits a 32-bit slot count.
  let start_limit = usize::try_from(policy.cpu_concurrency.initial).unwrap_or(usize::MAX);
  let sensor = open_default_sensor(cpu_capacity).map_err(FeedbackFactoryError::Sources)?;
  let actuator = GlobalCpuFeedbackActuator::with_default_registration(
    global,
    registration,
    start_limit,
    policy.disk_rate.initial,
    policy.network_rate.initial,
  );
  ResourceFeedbackService::start_in_tenant(policy, sensor, actuator, tenant)
    .map_err(FeedbackFactoryError::Service)
}

#[cfg(test)]
thread_local! {
  static FAIL_NEXT_DEFAULT_SENSOR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Makes the next default sensor opened on this thread fail, as an
/// unreadable `/proc/self/stat` would.
#[cfg(test)]
pub(crate) fn fail_next_default_sensor_for_test() {
  FAIL_NEXT_DEFAULT_SENSOR.set(true);
}

fn open_default_sensor(cpu_capacity: NonZeroU32) -> io::Result<ProcessCpuSensor> {
  #[cfg(test)]
  if FAIL_NEXT_DEFAULT_SENSOR.replace(false) {
    return Err(io::ErrorKind::PermissionDenied.into());
  }
  ProcessCpuSensor::new(cpu_capacity)
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
    DEFAULT_CPU_FLOOR, FeedbackControlConfig, FeedbackResource, FeedbackSample, NoChangeReason,
    PlanTicket, TelemetryStatus, UNSELECTED_BYTE_RATE,
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
  fn default_policy_never_rises_above_the_soft_limit_it_finds() {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 16)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 0).unwrap();
    domain
      .set_limits(ceiling.with(DomainResource::Cpu, 4))
      .unwrap();
    let policy = default_policy_for_domain(&domain, NonZeroU32::new(8).unwrap()).unwrap();
    assert_eq!(policy.cpu_concurrency.initial, 4);
    assert_eq!(policy.cpu_concurrency.ceiling, 4);
    assert_eq!(policy.cpu_concurrency.floor, DEFAULT_CPU_FLOOR);
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
