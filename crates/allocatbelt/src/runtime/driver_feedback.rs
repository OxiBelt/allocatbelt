//! Cloneable factories for feedback services owned by runtime drivers.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::io;
use std::sync::Arc;

use super::super::asynchronous::RuntimeMetrics;
use super::super::byte_rate::ByteRateLimit;
use super::super::managed::ResourceScope;
use super::super::resource_feedback::{
  FeedbackActuator, FeedbackSensor, FeedbackStartError, ResourceFeedbackService,
};
use super::super::resource_feedback_meter::IoFeedbackMeter;
use super::super::resource_feedback_policy::{
  PolicyError, ResourceFeedbackPolicy, ResourceFeedbackPolicyConfig,
};

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
}

impl fmt::Display for FeedbackFactoryError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidPolicy(error) => write!(f, "invalid feedback policy: {error}"),
      Self::Sources(error) => write!(f, "feedback source construction failed: {error}"),
      Self::Service(error) => error.fmt(f),
    }
  }
}

impl std::error::Error for FeedbackFactoryError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::InvalidPolicy(error) => Some(error),
      Self::Sources(error) => Some(error),
      Self::Service(error) => Some(error),
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
  let invalid_policy = ResourceFeedbackPolicy::new(policy).err();
  let build = Arc::new(move |context: FeedbackContext| {
    let tenant = context.resources.tenant_domain().cloned();
    let (sensor, actuator) = sources(context).map_err(FeedbackFactoryError::Sources)?;
    match tenant {
      Some(tenant) => ResourceFeedbackService::start_in_tenant(policy, sensor, actuator, &tenant),
      None => ResourceFeedbackService::start(policy, sensor, actuator),
    }
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
  use std::sync::atomic::{AtomicU64, Ordering};
  use std::time::{Duration, Instant};

  use crate::runtime::managed::ResourceLimits;
  use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};
  use crate::runtime::resource_feedback::{
    FeedbackActuatorError, FeedbackSensorError, FeedbackShutdownProgress,
  };
  use crate::runtime::resource_feedback_policy::{
    FeedbackControlConfig, FeedbackResource, FeedbackSample, PlanTicket,
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
}
