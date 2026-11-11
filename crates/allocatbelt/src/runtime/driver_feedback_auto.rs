//! The builder's feedback selection and the default service it starts.
//!
//! A builder starts with [`FeedbackSelection::Auto`]. For a driver bound to a
//! resource domain whose global CPU soft limit is nonzero, the build starts
//! the default service of `default_feedback` on that soft limit. Startup is
//! best effort: any failure is recorded in the driver's [`FeedbackStatus`]
//! and the driver is built without feedback. The default selection allocates
//! no byte meter, and a driver it does not apply to spawns no thread and
//! charges no `Control` for feedback. What the service changes and costs is
//! documented once, on `default_feedback_for_capacity`; a builder's
//! `without_feedback` turns it off.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::io;

use super::super::resource_domain::{DomainError, DomainResource, TenantDomain};
use super::super::resource_feedback::{FeedbackStartError, ResourceFeedbackService};
use super::super::resource_feedback_defaults::default_cpu_capacity;
use super::feedback::{
  FeedbackFactory, FeedbackFactoryError, default_policy_for_domain, start_default_service,
};

/// Which feedback service a builder starts.
#[derive(Clone, Debug, Default)]
pub(crate) enum FeedbackSelection {
  /// The default service, when it applies; never fails the build. It moves
  /// the domain's global CPU soft limit, which bounds the polls and blocking
  /// calls of every runtime bound to that domain; see
  /// `default_feedback_for_capacity`.
  #[default]
  Auto,
  /// No feedback service.
  Disabled,
  /// A caller-selected factory whose errors fail the build.
  Explicit(FeedbackFactory),
}

/// The feedback outcome of a driver build.
///
/// It records what the build did and does not change afterwards: a service
/// that later latches a control (for example, on external drift of the CPU
/// limit) still reports `Running`; its controls are visible through the
/// driver's `feedback_metrics()`. Shutdown progress of a started service is
/// reported by the driver's shutdown calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FeedbackStatus {
  /// The driver owns a feedback service started by this build, either the
  /// default one or one selected with `feedback_sources`.
  Running,
  /// The builder turned feedback off with `without_feedback`.
  Disabled,
  /// The default service does not apply to this driver; nothing was started.
  NotApplicable(FeedbackNotApplicable),
  /// The default service applied but did not start; the driver was built
  /// without it and nothing it started is retained.
  NotStarted(FeedbackNotStarted),
}

/// Why the default service does not apply to a driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FeedbackNotApplicable {
  /// The builder has no `resource_domain`, so no CPU ledger exists to change.
  NoResourceDomain,
  /// The domain's global CPU soft limit is zero when the driver is built.
  /// (A domain without a CPU ceiling cannot build a bound runtime at all.)
  NoCpuLimit,
  /// The domain's CPU soft limit is outside what the default policy can
  /// represent.
  CpuLimitNotRepresentable,
}

/// Why an applicable default service did not start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FeedbackNotStarted {
  /// Another default service already controls the driver's resource domain.
  DomainAlreadyControlled,
  /// The process CPU sensor could not be opened.
  Sensor(io::ErrorKind),
  /// The tenant refused the service's `Control` charge (for example, it has
  /// too little headroom) or the domain refused another operation.
  Domain(DomainError),
  /// A service thread could not be created.
  ThreadSpawn(io::ErrorKind),
  /// Startup verification failed, for example because the CPU limit changed
  /// between the applicability check and the service's readback.
  Startup,
}

impl FeedbackNotStarted {
  fn from_error(error: &FeedbackFactoryError) -> Self {
    match error {
      FeedbackFactoryError::DefaultDomainAlreadyControlled => Self::DomainAlreadyControlled,
      FeedbackFactoryError::Sources(error) => Self::Sensor(error.kind()),
      FeedbackFactoryError::Service(FeedbackStartError::Domain(error)) => Self::Domain(*error),
      FeedbackFactoryError::Service(FeedbackStartError::ThreadSpawn(error)) => {
        Self::ThreadSpawn(error.kind())
      }
      _ => Self::Startup,
    }
  }
}

/// Checks whether the default service applies to a driver bound to `tenant`
/// without reading the CPU capacity or opening a sensor.
fn applicability(tenant: Option<&TenantDomain>) -> Result<&TenantDomain, FeedbackNotApplicable> {
  let tenant = tenant.ok_or(FeedbackNotApplicable::NoResourceDomain)?;
  let global = tenant.global_domain();
  let snapshot = global.snapshot();
  if snapshot.limit.get(DomainResource::Cpu) == 0 {
    return Err(FeedbackNotApplicable::NoCpuLimit);
  }
  // Policy validity does not depend on the capacity, which is only the
  // sensor's denominator; check it with the smallest one.
  default_policy_for_domain(&global, std::num::NonZeroU32::MIN)
    .map_err(|_| FeedbackNotApplicable::CpuLimitNotRepresentable)?;
  Ok(tenant)
}

/// Starts the default service for a driver bound to `tenant`, if it applies.
///
/// The CPU capacity is read once, only after the service is known to apply
/// and the domain's registration was taken.
/// No error escapes: a failed start is returned as its status.
pub(crate) fn start_default_selection(
  tenant: Option<&TenantDomain>,
) -> (Option<ResourceFeedbackService>, FeedbackStatus) {
  let tenant = match applicability(tenant) {
    Ok(tenant) => tenant,
    Err(reason) => return (None, FeedbackStatus::NotApplicable(reason)),
  };
  match start_default_service(tenant, default_cpu_capacity) {
    Ok(service) => (Some(service), FeedbackStatus::Running),
    // The limit changed after the applicability check.
    Err(FeedbackFactoryError::InvalidPolicy(_)) => {
      let limit = tenant.global_domain().snapshot().limit;
      let reason = if limit.get(DomainResource::Cpu) == 0 {
        FeedbackNotApplicable::NoCpuLimit
      } else {
        FeedbackNotApplicable::CpuLimitNotRepresentable
      };
      (None, FeedbackStatus::NotApplicable(reason))
    }
    Err(error) => (
      None,
      FeedbackStatus::NotStarted(FeedbackNotStarted::from_error(&error)),
    ),
  }
}
