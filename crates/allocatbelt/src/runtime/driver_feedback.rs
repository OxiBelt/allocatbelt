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
  let build = Arc::new(move |context| {
    let (sensor, actuator) = sources(context).map_err(FeedbackFactoryError::Sources)?;
    ResourceFeedbackService::start(policy, sensor, actuator).map_err(FeedbackFactoryError::Service)
  });
  FeedbackFactory {
    build,
    invalid_policy,
  }
}
