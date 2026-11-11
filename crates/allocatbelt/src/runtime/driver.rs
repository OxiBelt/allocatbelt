//! Owning facades for the local and worker-pool runtimes.
//!
//! Builders validate every configured bound before starting a thread, bind
//! the executor's existing root scope to one managed-resource ledger, and own
//! each selected driver. Shutdown starts by closing admission. Status checks
//! retain unfinished owners; explicit cleanup steps may run user destructors
//! and can therefore take unbounded time. A service panic payload stays with
//! its driver after a status error; dropping that owner may run user code.
//!
//! The signal driver is a process-wide permanent bridge. A facade can expose
//! subscriptions through it, but its shutdown status does not claim that the
//! global bridge has stopped.
//!
//! Bucket reservation tables and rate-timer wait registrations use configured
//! bounds, while caller-created endpoint objects remain caller-controlled.
//! Tenant-bound facades charge their declared owner, feedback, meter, bucket,
//! and resource-ledger payloads to `ResourceDomain::Control`. Private timer
//! and provider metadata have separate accounting requirements; the control
//! budget is not a bound on process RSS or standard-library allocations.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

#[cfg(feature = "resource-feedback")]
#[path = "driver_feedback.rs"]
mod feedback;
#[cfg(feature = "resource-feedback")]
#[path = "driver_feedback_auto.rs"]
mod feedback_auto;

#[path = "driver_io.rs"]
mod io_bindings;
pub use io_bindings::IoBindings;
#[cfg(not(loom))]
pub use io_bindings::{DriverRateDatagramError, DriverRateDatagramFailure};

#[cfg(feature = "resource-feedback")]
pub use super::resource_feedback::FeedbackHistoryConfig;
#[cfg(feature = "resource-feedback")]
use feedback::FeedbackMeters;
#[cfg(feature = "resource-feedback")]
pub use feedback::{
  FeedbackContext, FeedbackFactory, FeedbackFactoryError, default_feedback,
  default_feedback_for_capacity, feedback_sources, feedback_sources_with_history,
};
#[cfg(feature = "resource-feedback")]
pub use feedback_auto::{FeedbackNotApplicable, FeedbackNotStarted, FeedbackStatus};
#[cfg(feature = "resource-feedback")]
use feedback_auto::{FeedbackSelection, start_default_selection};

use std::fmt;
use std::future::Future;
use std::io;
use std::sync::Arc;

use super::ShutdownMode;
use super::asynchronous::{
  AsyncConfig, AsyncError, AsyncHandle, AsyncRuntime, AsyncRuntimeOptions, AsyncShutdown,
  AsyncThreadOptions, HandoffConfig, LocalConfig, LocalError, LocalHandle, LocalRuntime,
  LocalSendHandle, LocalTaskScope, OwnedTaskScope, RuntimeMetrics,
};
use super::byte_rate::{ByteRateConfig, ByteRateError, ByteRateLimit};
use super::fs::FsHandle;
#[cfg(not(loom))]
use super::io::{AsyncRead, AsyncWrite};
use super::managed::{ResourceLimits, ResourceScope};
use super::process::{ProcessBuildError, ProcessDriver, ProcessShutdownError, ProcessShutdownMode};
#[cfg(not(loom))]
use super::rate_io::{RateIoFailure, RateLimitedIo};
use super::reactor::{Reactor, ReactorConfig, ReactorError, ReactorHandle};
use super::resource_domain::{ControlCharge, DomainError, TenantDomain};
#[cfg(feature = "resource-feedback")]
use super::resource_feedback::{
  FeedbackMetricsHandle, FeedbackShutdownError, FeedbackShutdownProgress, ReconcileRequestError,
  ResourceFeedbackService,
};
#[cfg(feature = "resource-feedback")]
use super::resource_feedback_meter::IoFeedbackMeter;
#[cfg(feature = "resource-feedback")]
use super::resource_feedback_policy::FeedbackResource;
use super::signal::{SignalDriver, SignalError};
use super::time::{ClockMode, IdleCoordinator, TimerDriver, TimerError, TimerHandle};
use super::{Config as BlockingConfig, Handle as BlockingHandle, Runtime as BlockingRuntime};
use super::{IoPool, IoPoolHandle};

/// A successful shutdown request is still waiting for some owned work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownProgress {
  /// Every closeable service has completed and all of its service threads
  /// have exited. The process-wide signal bridge remains permanent.
  Complete,
  /// At least one task, job, process, callback or service thread is still
  /// owned and unfinished.
  Pending,
}

/// Shutdown request or service-completion failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DriverShutdownError {
  /// A shutdown status or cleanup step ran before a shutdown request.
  NotRequested,
  /// A second request selected different shutdown behavior.
  PolicyAlreadyFixed,
  /// A close helper thread could not be started; retrying the same request
  /// is safe and preserves the driver owner.
  CloseThread(io::ErrorKind),
  /// Owner-thread local shutdown was called from the wrong thread.
  Local(LocalError),
  /// An async worker failed while exiting.
  Async(AsyncError),
  /// A blocking worker or cleanup step failed.
  Blocking(io::ErrorKind),
  /// An I/O adapter pool worker or cleanup step failed.
  IoPool(io::ErrorKind),
  /// Process reaping or its private reactor failed.
  Process(ProcessShutdownError),
  /// Timer service or close worker failed.
  Timer(TimerError),
  /// Reactor service or close worker failed.
  Reactor(ReactorError),
  /// Autonomous feedback service failed while stopping.
  #[cfg(feature = "resource-feedback")]
  Feedback(FeedbackShutdownError),
}

impl DriverShutdownError {
  /// Whether retrying the same shutdown request can resume completion.
  /// A failed helper launch retains the original owner and is not latched
  /// as a worker failure.
  #[must_use]
  pub const fn is_retryable(self) -> bool {
    matches!(
      self,
      Self::CloseThread(_)
        | Self::Async(AsyncError::JoinMonitorSpawnFailed)
        | Self::Blocking(io::ErrorKind::WouldBlock)
        | Self::IoPool(io::ErrorKind::WouldBlock)
        | Self::Process(ProcessShutdownError::JoinMonitorSpawn)
        | Self::Timer(TimerError::JoinMonitorSpawn)
        | Self::Reactor(ReactorError::JoinMonitorSpawn)
    )
  }
}

fn remember_shutdown_failure(
  stored: &mut Option<DriverShutdownError>,
  error: DriverShutdownError,
) -> DriverShutdownError {
  if error.is_retryable() {
    stored.unwrap_or(error)
  } else {
    *stored.get_or_insert(error)
  }
}

impl fmt::Display for DriverShutdownError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::NotRequested => f.write_str("shutdown has not been requested"),
      Self::PolicyAlreadyFixed => f.write_str("shutdown policy is already fixed"),
      Self::CloseThread(kind) => write!(f, "close helper could not start: {kind}"),
      Self::Local(error) => error.fmt(f),
      Self::Async(error) => error.fmt(f),
      Self::Blocking(kind) => write!(f, "blocking shutdown failed: {kind}"),
      Self::IoPool(kind) => write!(f, "I/O pool shutdown failed: {kind}"),
      Self::Process(error) => error.fmt(f),
      Self::Timer(error) => error.fmt(f),
      Self::Reactor(error) => error.fmt(f),
      #[cfg(feature = "resource-feedback")]
      Self::Feedback(error) => error.fmt(f),
    }
  }
}

impl std::error::Error for DriverShutdownError {}

/// Why owning-runtime construction failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum DriverBuildError {
  /// One or more requested bounds are zero, out of range, or overflow.
  InvalidConfiguration(&'static str),
  /// Filesystem services require an owned I/O adapter pool.
  FilesystemNeedsIoPool,
  /// Local executor storage could not be reserved.
  Local(LocalError),
  /// Async executor storage or thread startup failed.
  Async(AsyncError),
  /// Blocking pool construction failed.
  Blocking(io::Error),
  /// I/O adapter pool construction failed.
  IoPool(io::Error),
  /// Timer construction failed.
  Timer(TimerError),
  /// Reactor construction failed.
  Reactor(io::Error),
  /// Process driver construction failed.
  Process(ProcessBuildError),
  /// Process-wide signal bridge construction or configuration failed.
  Signal(SignalError),
  /// A directional application-byte bucket has invalid bounds.
  ByteRate(ByteRateError),
  /// A selected provider could not reserve global and tenant metadata.
  ResourceDomain(DomainError),
  /// A factory selected with `feedback_sources`, or its service, failed
  /// during startup. The default selection never reports this error.
  #[cfg(feature = "resource-feedback")]
  Feedback(FeedbackFactoryError),
}

impl fmt::Display for DriverBuildError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidConfiguration(reason) => write!(f, "invalid runtime configuration: {reason}"),
      Self::FilesystemNeedsIoPool => {
        f.write_str("filesystem services require a configured I/O pool")
      }
      Self::Local(error) => error.fmt(f),
      Self::Async(error) => error.fmt(f),
      Self::Blocking(error) => write!(f, "blocking pool construction failed: {error}"),
      Self::IoPool(error) => write!(f, "I/O pool construction failed: {error}"),
      Self::Timer(error) => error.fmt(f),
      Self::Reactor(error) => write!(f, "reactor construction failed: {error}"),
      Self::Process(error) => error.fmt(f),
      Self::Signal(error) => error.fmt(f),
      Self::ByteRate(error) => error.fmt(f),
      Self::ResourceDomain(error) => error.fmt(f),
      #[cfg(feature = "resource-feedback")]
      Self::Feedback(error) => error.fmt(f),
    }
  }
}

impl std::error::Error for DriverBuildError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Local(error) => Some(error),
      Self::Async(error) => Some(error),
      Self::Blocking(error) | Self::IoPool(error) | Self::Reactor(error) => Some(error),
      Self::Process(error) => Some(error),
      Self::Signal(error) => Some(error),
      Self::Timer(error) => Some(error),
      Self::ByteRate(error) => Some(error),
      Self::ResourceDomain(error) => Some(error),
      #[cfg(feature = "resource-feedback")]
      Self::Feedback(error) => Some(error),
      Self::InvalidConfiguration(_) | Self::FilesystemNeedsIoPool => None,
    }
  }
}

fn bind_filesystem_rate(
  filesystem: Option<FsHandle>,
  disk_rate: Option<&ByteRateLimit>,
  #[cfg(feature = "resource-feedback")] feedback_meters: Option<&FeedbackMeters>,
) -> Result<Option<FsHandle>, DriverBuildError> {
  let Some(filesystem) = filesystem else {
    return Ok(None);
  };
  let Some(disk_rate) = disk_rate else {
    return Ok(Some(filesystem));
  };
  #[cfg(feature = "resource-feedback")]
  if let Some(meters) = feedback_meters {
    return filesystem
      .with_metered_byte_rate(disk_rate, &meters.disk)
      .map(Some)
      .map_err(DriverBuildError::ResourceDomain);
  }
  filesystem
    .with_byte_rate(disk_rate)
    .map(Some)
    .map_err(DriverBuildError::ResourceDomain)
}

/// Why a facade could not construct a rate-limited stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DriverRateIoFailure {
  /// Neither upload nor download admission was configured.
  MissingUploadAndDownloadRates,
  /// Download/read admission was not configured.
  MissingDownloadRate,
  /// Upload/write admission was not configured.
  MissingUploadRate,
  /// Disk application-byte admission was not configured.
  MissingDiskRate,
  /// The builder did not create its private fixed real-clock timer.
  MissingRateTimer,
  /// The underlying rate adapter rejected its construction inputs.
  Adapter(RateIoFailure),
}

/// Recoverable original endpoint from a facade rate-I/O construction failure.
pub struct DriverRateIoError<T> {
  inner: T,
  failure: DriverRateIoFailure,
}

impl<T> DriverRateIoError<T> {
  /// Why rate-limited I/O could not be constructed.
  #[must_use]
  pub const fn failure(&self) -> DriverRateIoFailure {
    self.failure
  }

  /// Returns the original endpoint unchanged.
  #[must_use]
  pub fn into_inner(self) -> T {
    self.inner
  }
}

impl<T: fmt::Debug> fmt::Debug for DriverRateIoError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("DriverRateIoError")
      .field("failure", &self.failure)
      .field("inner", &self.inner)
      .finish()
  }
}

impl<T: fmt::Debug> fmt::Display for DriverRateIoError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "could not construct driver rate I/O: {:?}", self.failure)
  }
}

impl<T: fmt::Debug> std::error::Error for DriverRateIoError<T> {}

#[cfg(feature = "resource-feedback")]
fn poll_feedback_service(
  service: Option<&mut ResourceFeedbackService>,
  failure: &mut Option<DriverShutdownError>,
) -> bool {
  let Some(service) = service else {
    return true;
  };
  match service.try_shutdown() {
    Ok(FeedbackShutdownProgress::Complete) => true,
    Ok(FeedbackShutdownProgress::Pending) => false,
    Err(error) => {
      failure.get_or_insert(DriverShutdownError::Feedback(error));
      service.is_shutdown_complete()
    }
  }
}

#[cfg(not(loom))]
fn build_rate_io<T: AsyncRead + AsyncWrite + Unpin>(
  inner: T,
  download_rate: Option<ByteRateLimit>,
  upload_rate: Option<ByteRateLimit>,
  timer: Option<TimerHandle>,
  #[cfg(feature = "resource-feedback")] feedback_meters: Option<&FeedbackMeters>,
) -> Result<RateLimitedIo<T>, DriverRateIoError<T>> {
  let (read_rate, write_rate) = match (download_rate, upload_rate) {
    (Some(read_rate), Some(write_rate)) => (read_rate, write_rate),
    (None, None) => {
      return Err(DriverRateIoError {
        inner,
        failure: DriverRateIoFailure::MissingUploadAndDownloadRates,
      });
    }
    (None, Some(_)) => {
      return Err(DriverRateIoError {
        inner,
        failure: DriverRateIoFailure::MissingDownloadRate,
      });
    }
    (Some(_), None) => {
      return Err(DriverRateIoError {
        inner,
        failure: DriverRateIoFailure::MissingUploadRate,
      });
    }
  };
  let Some(timer) = timer else {
    return Err(DriverRateIoError {
      inner,
      failure: DriverRateIoFailure::MissingRateTimer,
    });
  };
  finish_rate_io(
    inner,
    read_rate,
    write_rate,
    timer,
    #[cfg(feature = "resource-feedback")]
    feedback_meters.map(|meters| (meters.download.clone(), meters.upload.clone())),
  )
}

#[cfg(not(loom))]
fn build_disk_io<T: AsyncRead + AsyncWrite + Unpin>(
  inner: T,
  disk_rate: Option<ByteRateLimit>,
  timer: Option<TimerHandle>,
  #[cfg(feature = "resource-feedback")] feedback_meters: Option<&FeedbackMeters>,
) -> Result<RateLimitedIo<T>, DriverRateIoError<T>> {
  let Some(disk_rate) = disk_rate else {
    return Err(DriverRateIoError {
      inner,
      failure: DriverRateIoFailure::MissingDiskRate,
    });
  };
  let Some(timer) = timer else {
    return Err(DriverRateIoError {
      inner,
      failure: DriverRateIoFailure::MissingRateTimer,
    });
  };
  finish_rate_io(
    inner,
    disk_rate.clone(),
    disk_rate,
    timer,
    #[cfg(feature = "resource-feedback")]
    feedback_meters.map(|meters| (meters.disk.clone(), meters.disk.clone())),
  )
}

#[cfg(not(loom))]
fn finish_rate_io<T: AsyncRead + AsyncWrite + Unpin>(
  inner: T,
  read_rate: ByteRateLimit,
  write_rate: ByteRateLimit,
  timer: TimerHandle,
  #[cfg(feature = "resource-feedback")] meters: Option<(IoFeedbackMeter, IoFeedbackMeter)>,
) -> Result<RateLimitedIo<T>, DriverRateIoError<T>> {
  let adapter = match RateLimitedIo::new(inner, read_rate, write_rate, timer) {
    Ok(adapter) => adapter,
    Err(error) => {
      let failure = DriverRateIoFailure::Adapter(error.failure());
      let (inner, _, _, _) = error.into_inputs();
      return Err(DriverRateIoError { inner, failure });
    }
  };
  #[cfg(feature = "resource-feedback")]
  if let Some((read, write)) = meters {
    return Ok(adapter.with_feedback_meters(read, write));
  }
  Ok(adapter)
}

/// Shutdown choices for an owner-thread runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentShutdown {
  /// How the optional blocking pool handles queued jobs.
  pub blocking: ShutdownMode,
  /// Whether managed child processes are awaited or terminated first.
  pub processes: ProcessShutdownMode,
}

impl Default for CurrentShutdown {
  fn default() -> Self {
    Self {
      blocking: ShutdownMode::CancelPending,
      processes: ProcessShutdownMode::Wait,
    }
  }
}

/// Shutdown choices for a worker-pool runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultiShutdown {
  /// How admitted async tasks are handled.
  pub tasks: AsyncShutdown,
  /// How the optional blocking pool handles queued jobs.
  pub blocking: ShutdownMode,
  /// Whether managed child processes are awaited or terminated first.
  pub processes: ProcessShutdownMode,
}

impl Default for MultiShutdown {
  fn default() -> Self {
    Self {
      tasks: AsyncShutdown::CancelPending,
      blocking: ShutdownMode::CancelPending,
      processes: ProcessShutdownMode::Wait,
    }
  }
}

#[derive(Clone, Debug, Default)]
struct ServiceOptions {
  timer_registrations: Option<usize>,
  timer_mode: ClockMode,
  rate_timer_registrations: Option<usize>,
  reactor: Option<ReactorConfig>,
  blocking: Option<BlockingConfig>,
  io_pool: Option<BlockingConfig>,
  filesystem: bool,
  process_children: Option<usize>,
  signal_listeners: Option<usize>,
  disk_rate: Option<ByteRateConfig>,
  upload_rate: Option<ByteRateConfig>,
  download_rate: Option<ByteRateConfig>,
  #[cfg(feature = "resource-feedback")]
  feedback: FeedbackSelection,
}

struct ByteRateLimits {
  disk: Option<ByteRateLimit>,
  upload: Option<ByteRateLimit>,
  download: Option<ByteRateLimit>,
}

#[cfg(feature = "resource-feedback")]
struct FeedbackStartupInputs {
  resources: ResourceScope,
  disk_rate: Option<ByteRateLimit>,
  upload_rate: Option<ByteRateLimit>,
  download_rate: Option<ByteRateLimit>,
  runtime_metrics: Option<RuntimeMetrics>,
  meters: Option<FeedbackMeters>,
}

impl ServiceOptions {
  fn owner_control(
    &self,
    tenant: Option<&TenantDomain>,
    owner_bytes: usize,
    executor_bytes: usize,
    max_outstanding: usize,
  ) -> Result<ControlCharge, DriverBuildError> {
    // Executor and active blocking/service values already own their exact
    // inline charges. The containing facade accounts their surrounding fields
    // and padding without reserving those value payloads a second time.
    let mut bytes =
      owner_bytes
        .checked_sub(executor_bytes)
        .ok_or(DriverBuildError::InvalidConfiguration(
          "executor metadata exceeds its facade",
        ))?;
    if self.blocking.is_some() {
      bytes = bytes
        .checked_sub(std::mem::size_of::<BlockingRuntime>())
        .ok_or(DriverBuildError::InvalidConfiguration(
          "blocking metadata exceeds its facade",
        ))?;
    }
    if self.io_pool.is_some() {
      bytes = bytes.checked_sub(std::mem::size_of::<IoPool>()).ok_or(
        DriverBuildError::InvalidConfiguration("I/O pool metadata exceeds its facade"),
      )?;
    }
    if tenant.is_some() {
      if self.reactor.is_some() {
        bytes = bytes.checked_sub(std::mem::size_of::<Reactor>()).ok_or(
          DriverBuildError::InvalidConfiguration("reactor metadata exceeds its facade"),
        )?;
      }
      if self.process_children.is_some() {
        bytes = bytes
          .checked_sub(std::mem::size_of::<ProcessDriver>())
          .ok_or(DriverBuildError::InvalidConfiguration(
            "process metadata exceeds its facade",
          ))?;
      }
      let timers = usize::from(self.timer_registrations.is_some())
        + usize::from(self.rate_timer_capacity(max_outstanding)?.is_some());
      bytes = bytes
        .checked_sub(timers * TimerDriver::owner_payload_bytes())
        .ok_or(DriverBuildError::InvalidConfiguration(
          "timer metadata exceeds its facade",
        ))?;
    }
    // Only an explicit factory is known to own a service here. The default
    // selection keeps the full facade charge and releases the service's
    // inline share only once that service has started and charged it.
    #[cfg(feature = "resource-feedback")]
    if tenant.is_some() && matches!(self.feedback, FeedbackSelection::Explicit(_)) {
      bytes = bytes
        .checked_sub(ResourceFeedbackService::owner_payload_bytes())
        .ok_or(DriverBuildError::InvalidConfiguration(
          "feedback metadata exceeds its facade",
        ))?;
    }
    ControlCharge::try_new(tenant, bytes).map_err(DriverBuildError::ResourceDomain)
  }

  fn validate(&self, max_outstanding: usize) -> Result<(), DriverBuildError> {
    if self.timer_registrations == Some(0) {
      return Err(DriverBuildError::InvalidConfiguration(
        "timer registrations must be nonzero",
      ));
    }
    if self.rate_timer_registrations == Some(0) {
      return Err(DriverBuildError::InvalidConfiguration(
        "rate timer registrations must be nonzero",
      ));
    }
    if self.rate_timer_registrations.is_some()
      && self.disk_rate.is_none()
      && (self.upload_rate.is_none() || self.download_rate.is_none())
    {
      return Err(DriverBuildError::InvalidConfiguration(
        "a rate timer requires a disk bucket or both network buckets",
      ));
    }
    if self.disk_rate.is_some() || (self.upload_rate.is_some() && self.download_rate.is_some()) {
      self.rate_timer_capacity(max_outstanding)?;
    }
    if self.timer_mode != ClockMode::Real && self.timer_registrations.is_none() {
      return Err(DriverBuildError::InvalidConfiguration(
        "a paused clock requires a timer registration bound",
      ));
    }
    if let Some(config) = self.reactor
      && (config.max_registrations == 0
        || config.max_waiters == 0
        || config.max_registrations > (1 << 24)
        || config.max_waiters > (1 << 24))
    {
      return Err(DriverBuildError::InvalidConfiguration(
        "reactor bounds must be between 1 and 2^24",
      ));
    }
    if let Some(config) = self.blocking
      && (config.workers == 0 || config.max_outstanding == 0)
    {
      return Err(DriverBuildError::InvalidConfiguration(
        "blocking workers and outstanding capacity must be nonzero",
      ));
    }
    if let Some(config) = self.io_pool
      && (config.workers == 0 || config.max_outstanding == 0)
    {
      return Err(DriverBuildError::InvalidConfiguration(
        "I/O pool workers and outstanding capacity must be nonzero",
      ));
    }
    if self.filesystem && self.io_pool.is_none() {
      return Err(DriverBuildError::FilesystemNeedsIoPool);
    }
    if self
      .process_children
      .is_some_and(|bound| bound == 0 || bound > (1 << 24))
    {
      return Err(DriverBuildError::InvalidConfiguration(
        "process capacity must be between 1 and 2^24",
      ));
    }
    if self
      .signal_listeners
      .is_some_and(|bound| bound == 0 || bound > 64)
    {
      return Err(DriverBuildError::InvalidConfiguration(
        "signal listener capacity must be between 1 and 64",
      ));
    }
    #[cfg(feature = "resource-feedback")]
    if let FeedbackSelection::Explicit(factory) = &self.feedback {
      factory.validate().map_err(DriverBuildError::Feedback)?;
    }
    Ok(())
  }

  fn build_rate_limits(
    &self,
    tenant: Option<&TenantDomain>,
  ) -> Result<ByteRateLimits, DriverBuildError> {
    let create = |config| match tenant {
      Some(tenant) => ByteRateLimit::new_in_tenant(config, tenant),
      None => ByteRateLimit::new(config),
    };
    let disk = self
      .disk_rate
      .map(create)
      .transpose()
      .map_err(DriverBuildError::ByteRate)?;
    let upload = self
      .upload_rate
      .map(create)
      .transpose()
      .map_err(DriverBuildError::ByteRate)?;
    let download = self
      .download_rate
      .map(create)
      .transpose()
      .map_err(DriverBuildError::ByteRate)?;
    Ok(ByteRateLimits {
      disk,
      upload,
      download,
    })
  }

  fn rate_timer_capacity(&self, max_outstanding: usize) -> Result<Option<usize>, DriverBuildError> {
    if self.disk_rate.is_none() && (self.upload_rate.is_none() || self.download_rate.is_none()) {
      return Ok(None);
    }
    let directions_per_outstanding = match (
      self.disk_rate.is_some(),
      self.upload_rate.is_some() && self.download_rate.is_some(),
    ) {
      (true, true) => 4,
      (true, false) | (false, true) => 2,
      (false, false) => return Ok(None),
    };
    let capacity = match self.rate_timer_registrations {
      Some(capacity) => capacity,
      None => max_outstanding
        .checked_mul(directions_per_outstanding)
        .ok_or(DriverBuildError::InvalidConfiguration(
          "default rate timer capacity overflows",
        ))?,
    };
    if capacity == 0 {
      return Err(DriverBuildError::InvalidConfiguration(
        "rate timer capacity must be nonzero",
      ));
    }
    Ok(Some(capacity))
  }

  fn build_services(
    &self,
    resources: &ResourceScope,
    startup: &mut StartupGuard,
    coordinator: Arc<IdleCoordinator>,
    current_thread: bool,
    max_outstanding: usize,
  ) -> Result<Option<FsHandle>, DriverBuildError> {
    if let Some(config) = self.blocking {
      startup.blocking = Some(
        BlockingRuntime::with_resources(config, resources.clone())
          .map_err(DriverBuildError::Blocking)?,
      );
    }
    if let Some(config) = self.io_pool {
      startup.io_pool =
        Some(IoPool::with_resources(config, resources.clone()).map_err(DriverBuildError::IoPool)?);
    }
    if let Some(max_registered) = self.timer_registrations {
      startup.timer = Some(
        TimerDriver::new_for_runtime(
          max_registered,
          self.timer_mode,
          current_thread,
          coordinator,
          resources.tenant_domain(),
        )
        .map_err(DriverBuildError::Timer)?,
      );
    }
    if let Some(max_registered) = self.rate_timer_capacity(max_outstanding)? {
      startup.rate_timer = Some(
        match resources.tenant_domain() {
          Some(tenant) => TimerDriver::new_realtime_in_tenant(max_registered, tenant),
          None => TimerDriver::new_realtime(max_registered),
        }
        .map_err(DriverBuildError::Timer)?,
      );
    }
    if let Some(config) = self.reactor {
      startup.reactor = Some(
        match resources.tenant_domain() {
          Some(tenant) => Reactor::new_in_tenant(config, tenant),
          None => Reactor::new(config),
        }
        .map_err(DriverBuildError::Reactor)?,
      );
    }
    if let Some(max_children) = self.process_children {
      startup.process = Some(
        match resources.tenant_domain() {
          Some(tenant) => ProcessDriver::new_in_tenant(max_children, tenant),
          None => ProcessDriver::new(max_children),
        }
        .map_err(DriverBuildError::Process)?,
      );
    }
    let filesystem = if self.filesystem {
      let io_pool = startup
        .io_pool
        .as_ref()
        .ok_or(DriverBuildError::FilesystemNeedsIoPool)?;
      Some(FsHandle::new(io_pool.handle(), resources.clone()))
    } else {
      None
    };
    Ok(filesystem)
  }

  /// Meters for an explicit factory, charged to the bound tenant. The
  /// default selection and a disabled one allocate none.
  #[cfg(feature = "resource-feedback")]
  fn feedback_meters(
    &self,
    tenant: Option<&TenantDomain>,
  ) -> Result<Option<FeedbackMeters>, DriverBuildError> {
    if !matches!(self.feedback, FeedbackSelection::Explicit(_)) {
      return Ok(None);
    }
    match tenant {
      Some(tenant) => FeedbackMeters::new_in_tenant(tenant),
      None => Ok(FeedbackMeters::new()),
    }
    .map(Some)
    .map_err(DriverBuildError::ResourceDomain)
  }

  /// Starts the selected feedback service. Only an explicit factory can fail
  /// the build; the default selection records its outcome in the status.
  #[cfg(feature = "resource-feedback")]
  fn start_feedback(
    &self,
    inputs: FeedbackStartupInputs,
    startup: &mut StartupGuard,
    owner_control: &mut ControlCharge,
  ) -> Result<FeedbackStatus, DriverBuildError> {
    match &self.feedback {
      FeedbackSelection::Disabled => Ok(FeedbackStatus::Disabled),
      FeedbackSelection::Explicit(factory) => {
        let Some(meters) = inputs.meters else {
          return Err(DriverBuildError::InvalidConfiguration(
            "feedback meters were not prepared for the selected service",
          ));
        };
        startup.feedback = Some(
          factory
            .build(FeedbackContext {
              resources: inputs.resources,
              disk_rate: inputs.disk_rate,
              upload_rate: inputs.upload_rate,
              download_rate: inputs.download_rate,
              disk_meter: meters.disk,
              upload_meter: meters.upload,
              download_meter: meters.download,
              runtime_metrics: inputs.runtime_metrics,
            })
            .map_err(DriverBuildError::Feedback)?,
        );
        Ok(FeedbackStatus::Running)
      }
      FeedbackSelection::Auto => {
        let (service, status) = start_default_selection(inputs.resources.tenant_domain());
        if let Some(service) = service {
          // The started service charges its own inline owner payload, which
          // the facade charged as part of itself; release the facade's share
          // so that, once started, the payload is charged once, as with an
          // explicit factory. During startup the default path is one owner
          // payload higher than the explicit path. If the split fails (a
          // facade smaller than that payload), the facade keeps its full
          // charge and that payload stays charged twice while the driver
          // lives; nothing fails.
          if let Ok(share) = owner_control.split_off(ResourceFeedbackService::owner_payload_bytes())
          {
            drop(share);
          }
          startup.feedback = Some(service);
        }
        Ok(status)
      }
    }
  }

  fn start_signal(&self, startup: &mut StartupGuard) -> Result<(), DriverBuildError> {
    if let Some(max_listeners) = self.signal_listeners {
      // The permanent process signal bridge remains the final startup action.
      startup.signal = Some(SignalDriver::new(max_listeners).map_err(DriverBuildError::Signal)?);
    }
    Ok(())
  }
}

macro_rules! service_builder_methods {
  ($builder:ty) => {
    impl $builder {
      /// Selects a bounded timer driver.
      pub fn timer(mut self, max_registered: usize) -> Self {
        self.services.timer_registrations = Some(max_registered);
        self
      }

      /// Starts the owning timer clock in `mode` with a bounded registration
      /// capacity. `PausedAuto` is accepted only by the current-thread
      /// executor and advances only after its local queues are quiescent.
      pub fn clock(mut self, mode: ClockMode, max_registered: usize) -> Self {
        self.services.timer_registrations = Some(max_registered);
        self.services.timer_mode = mode;
        self
      }

      /// Selects the initial mode for a timer configured with [`Self::timer`].
      pub fn timer_mode(mut self, mode: ClockMode) -> Self {
        self.services.timer_mode = mode;
        self
      }

      /// Selects the fixed real-clock timer capacity used by rate-limited I/O.
      /// Both upload and download buckets must also be configured.
      /// The default is two wait registrations per maximum outstanding task
      /// for each selected network or explicit disk adapter class. It bounds
      /// timer waiters, not the number of endpoints a caller may construct.
      pub fn rate_timer_registrations(mut self, max_registered: usize) -> Self {
        self.services.rate_timer_registrations = Some(max_registered);
        self
      }

      /// Selects a bounded readiness reactor.
      pub fn reactor(mut self, config: ReactorConfig) -> Self {
        self.services.reactor = Some(config);
        self
      }

      /// Selects the blocking worker pool that runs caller closures. Adapter
      /// operations never run on it; see [`Self::io_pool`].
      pub fn blocking(mut self, config: BlockingConfig) -> Self {
        self.services.blocking = Some(config);
        self
      }

      /// Selects the I/O adapter pool: a fixed set of workers and its own
      /// queue for the filesystem front end, the blocking stream adapters
      /// and network connect and name resolution, separate from the
      /// blocking pool. It shuts down in its own step, after the blocking
      /// pool's step has completed and before child processes. That step
      /// always drains: admitted adapter operations finish, so a stream
      /// blocked in a read (such as stdin) keeps shutdown pending until the
      /// read returns.
      ///
      /// With a `resource_domain`, the pool reserves a waiter share of its
      /// `max_outstanding` in addition to the executor's and the blocking
      /// pool's, so the domain's waiter table must hold their sum; a table
      /// that is too small fails the build with `DriverBuildError::IoPool`
      /// wrapping `DomainError::WaitersFull`.
      pub fn io_pool(mut self, config: BlockingConfig) -> Self {
        self.services.io_pool = Some(config);
        self
      }

      /// Adds the filesystem front end. An I/O pool must also be selected
      /// with [`Self::io_pool`].
      pub fn filesystem(mut self) -> Self {
        self.services.filesystem = true;
        self
      }

      /// Selects bounded child-process ownership and reaping.
      pub fn processes(mut self, max_children: usize) -> Self {
        self.services.process_children = Some(max_children);
        self
      }

      /// Joins the process-wide signal bridge with this listener ceiling.
      pub fn signals(mut self, max_listeners: usize) -> Self {
        self.services.signal_listeners = Some(max_listeners);
        self
      }

      /// Selects one disk application-byte bucket for the owning filesystem
      /// handle and explicit disk stream adapters. Copies charge their read
      /// and write directions separately. Direct standard-library calls remain
      /// outside this application-byte contract.
      pub fn disk_rate(mut self, config: ByteRateConfig) -> Self {
        self.services.disk_rate = Some(config);
        self
      }

      /// Selects the upload application-byte bucket.
      pub fn upload_rate(mut self, config: ByteRateConfig) -> Self {
        self.services.upload_rate = Some(config);
        self
      }

      /// Selects the download application-byte bucket.
      pub fn download_rate(mut self, config: ByteRateConfig) -> Self {
        self.services.download_rate = Some(config);
        self
      }

      /// Replaces the default feedback selection with a per-driver factory.
      /// Its validation, source and startup errors fail the build.
      #[cfg(feature = "resource-feedback")]
      pub fn feedback_sources(mut self, factory: FeedbackFactory) -> Self {
        self.services.feedback = FeedbackSelection::Explicit(factory);
        self
      }

      /// Turns resource feedback off for drivers built from this builder.
      ///
      /// By default a builder with a `resource_domain` starts the default
      /// service on that domain's global CPU soft limit when it applies. That
      /// limit bounds the simultaneous polls and blocking calls of every
      /// runtime bound to the domain, and the service lowers it under high
      /// process CPU use (see [`default_feedback_for_capacity`]). It also
      /// costs a tenant `Control` charge, two threads (sampler and join
      /// monitor), so a current-thread driver's process is no longer
      /// single-threaded, and one open `/proc/self/stat` descriptor read every
      /// 100 ms on the real clock, also when the driver's clock is paused.
      ///
      /// With this selection the build starts no feedback service and spawns
      /// no feedback thread, and the driver reports
      /// [`FeedbackStatus::Disabled`]. Use it where the domain's CPU limit
      /// must stay fixed. A later `feedback_sources` call selects that
      /// factory instead.
      #[cfg(feature = "resource-feedback")]
      pub fn without_feedback(mut self) -> Self {
        self.services.feedback = FeedbackSelection::Disabled;
        self
      }
    }
  };
}

/// Builder for an owner-thread runtime. Its local tasks, handles and shutdown
/// cleanup stay on the thread that calls [`CurrentThreadBuilder::build`].
#[derive(Clone, Debug)]
pub struct CurrentThreadBuilder {
  config: LocalConfig,
  resources: ResourceLimits,
  tenant: Option<TenantDomain>,
  services: ServiceOptions,
}

impl CurrentThreadBuilder {
  /// Starts a builder with local executor limits and an initially empty
  /// managed-resource scope.
  pub const fn new(config: LocalConfig) -> Self {
    Self {
      config,
      tenant: None,
      resources: ResourceLimits {
        managed_memory: 0,
        disk_concurrent_ops: 0,
        network_concurrent_ops: 0,
      },
      services: ServiceOptions {
        timer_registrations: None,
        timer_mode: ClockMode::Real,
        rate_timer_registrations: None,
        reactor: None,
        blocking: None,
        io_pool: None,
        filesystem: false,
        process_children: None,
        signal_listeners: None,
        disk_rate: None,
        upload_rate: None,
        download_rate: None,
        #[cfg(feature = "resource-feedback")]
        feedback: FeedbackSelection::Auto,
      },
    }
  }

  /// Sets the shared ledger used by the executor root and filesystem handle.
  pub const fn resources(mut self, limits: ResourceLimits) -> Self {
    self.resources = limits;
    self
  }

  /// Binds managed storage and operation permits to a shared global/tenant
  /// domain in addition to this builder's local resource limits.
  pub fn resource_domain(mut self, tenant: TenantDomain) -> Self {
    self.tenant = Some(tenant);
    self
  }

  /// Builds the local runtime and selected services after validating every
  /// configured bound. Failed startup joins any service threads already
  /// started; process signals are initialized last because their bridge is
  /// permanent.
  pub fn build(self) -> Result<CurrentThreadDriver, DriverBuildError> {
    if self.config.max_outstanding == 0 || self.config.max_scopes == 0 {
      return Err(DriverBuildError::InvalidConfiguration(
        "local task and scope bounds must be nonzero",
      ));
    }
    self.services.validate(self.config.max_outstanding)?;
    let resources = match self.tenant {
      Some(tenant) => ResourceScope::try_from_tenant(self.resources, tenant)
        .map_err(DriverBuildError::ResourceDomain)?,
      None => ResourceScope::new(self.resources),
    };
    let mut owner_control = self.services.owner_control(
      resources.tenant_domain(),
      std::mem::size_of::<CurrentThreadDriver>(),
      std::mem::size_of::<LocalRuntime>(),
      self.config.max_outstanding,
    )?;
    let ByteRateLimits {
      disk: disk_rate,
      upload: upload_rate,
      download: download_rate,
    } = self.services.build_rate_limits(resources.tenant_domain())?;
    #[cfg(feature = "resource-feedback")]
    let feedback_meters = self.services.feedback_meters(resources.tenant_domain())?;
    let mut startup = StartupGuard::default();
    startup.local = Some(
      LocalRuntime::with_resources(self.config, resources.clone())
        .map_err(DriverBuildError::Local)?,
    );
    let coordinator = startup
      .local
      .as_ref()
      .map(LocalRuntime::idle_coordinator)
      .unwrap_or_else(|| IdleCoordinator::new(None));
    let filesystem = self.services.build_services(
      &resources,
      &mut startup,
      Arc::clone(&coordinator),
      true,
      self.config.max_outstanding,
    )?;
    let filesystem = bind_filesystem_rate(
      filesystem,
      disk_rate.as_ref(),
      #[cfg(feature = "resource-feedback")]
      feedback_meters.as_ref(),
    )?;
    #[cfg(feature = "resource-feedback")]
    let feedback_status = self.services.start_feedback(
      FeedbackStartupInputs {
        resources: resources.clone(),
        disk_rate: disk_rate.clone(),
        upload_rate: upload_rate.clone(),
        download_rate: download_rate.clone(),
        runtime_metrics: None,
        meters: feedback_meters.clone(),
      },
      &mut startup,
      &mut owner_control,
    )?;
    self.services.start_signal(&mut startup)?;
    if let Some(timer) = startup.timer.as_ref().map(TimerDriver::handle) {
      let blocking_handle = startup.blocking.as_ref().map(BlockingRuntime::handle);
      let io_pool_handle = startup.io_pool.as_ref().map(IoPool::handle);
      if let Some(blocking) = startup.blocking.as_mut() {
        blocking.bind_clock(timer.clone());
      }
      if let Some(io_pool) = startup.io_pool.as_mut() {
        io_pool.bind_clock(timer.clone());
      }
      if let Some(local) = startup.local.as_mut() {
        local.attach_idle_clock(timer, blocking_handle, io_pool_handle);
      }
    }
    Ok(CurrentThreadDriver {
      local: startup.local.take().unwrap_or_else(|| unreachable!()),
      resources,
      timer: startup.timer.take(),
      rate_timer: startup.rate_timer.take(),
      reactor: startup.reactor.take(),
      blocking: startup.blocking.take(),
      io_pool: startup.io_pool.take(),
      filesystem,
      process: startup.process.take(),
      signal: startup.signal.take(),
      #[cfg(feature = "resource-feedback")]
      feedback: startup.feedback.take(),
      #[cfg(feature = "resource-feedback")]
      feedback_meters,
      #[cfg(feature = "resource-feedback")]
      feedback_status,
      disk_rate,
      upload_rate,
      download_rate,
      shutdown: None,
      shutdown_failure: None,
      blocking_shutdown_requested: false,
      io_pool_shutdown_requested: false,
      process_shutdown_requested: false,
      io_shutdown_requested: false,
      _control: owner_control,
    })
  }
}

service_builder_methods!(CurrentThreadBuilder);

/// Builder for a multithreaded executor and its selected services.
#[derive(Clone, Debug)]
pub struct MultiThreadBuilder {
  config: AsyncConfig,
  handoffs: Option<HandoffConfig>,
  thread_options: Option<AsyncThreadOptions>,
  resources: ResourceLimits,
  tenant: Option<TenantDomain>,
  services: ServiceOptions,
}

impl MultiThreadBuilder {
  /// Starts a builder with worker-pool limits and an initially empty
  /// managed-resource scope.
  pub const fn new(config: AsyncConfig) -> Self {
    Self {
      config,
      handoffs: None,
      tenant: None,
      thread_options: None,
      resources: ResourceLimits {
        managed_memory: 0,
        disk_concurrent_ops: 0,
        network_concurrent_ops: 0,
      },
      services: ServiceOptions {
        timer_registrations: None,
        timer_mode: ClockMode::Real,
        rate_timer_registrations: None,
        reactor: None,
        blocking: None,
        io_pool: None,
        filesystem: false,
        process_children: None,
        signal_listeners: None,
        disk_rate: None,
        upload_rate: None,
        download_rate: None,
        #[cfg(feature = "resource-feedback")]
        feedback: FeedbackSelection::Auto,
      },
    }
  }

  /// Prestarts bounded helper threads for [`super::asynchronous::try_block_in_place`].
  pub const fn with_handoffs(mut self, config: HandoffConfig) -> Self {
    self.handoffs = Some(config);
    self
  }

  /// Applies names, stack sizes and lifecycle hooks to executor threads.
  pub fn thread_options(mut self, options: AsyncThreadOptions) -> Self {
    self.thread_options = Some(options);
    self
  }

  /// Sets the shared ledger used by the executor root and filesystem handle.
  pub const fn resources(mut self, limits: ResourceLimits) -> Self {
    self.resources = limits;
    self
  }

  /// Binds managed storage and operation permits to a shared global/tenant
  /// domain in addition to this builder's local resource limits.
  pub fn resource_domain(mut self, tenant: TenantDomain) -> Self {
    self.tenant = Some(tenant);
    self
  }

  /// Builds the async runtime and selected services after validating every
  /// configured bound. Failed startup joins any service threads already
  /// started; process signals are initialized last because their bridge is
  /// permanent.
  pub fn build(self) -> Result<MultiThreadDriver, DriverBuildError> {
    if self.config.workers == 0 || self.config.max_outstanding == 0 || self.config.max_scopes == 0 {
      return Err(DriverBuildError::InvalidConfiguration(
        "async worker, task and scope bounds must be nonzero",
      ));
    }
    if let Some(handoffs) = self.handoffs
      && (handoffs.max_handoffs == 0
        || self
          .config
          .workers
          .checked_add(handoffs.max_handoffs)
          .is_none())
    {
      return Err(DriverBuildError::InvalidConfiguration(
        "handoff bound must be nonzero and fit the worker count",
      ));
    }
    if self.services.timer_mode == ClockMode::PausedAuto {
      return Err(DriverBuildError::InvalidConfiguration(
        "paused automatic time requires the current-thread executor",
      ));
    }
    self.services.validate(self.config.max_outstanding)?;
    let resources = match self.tenant {
      Some(tenant) => ResourceScope::try_from_tenant(self.resources, tenant)
        .map_err(DriverBuildError::ResourceDomain)?,
      None => ResourceScope::new(self.resources),
    };
    let mut owner_control = self.services.owner_control(
      resources.tenant_domain(),
      std::mem::size_of::<MultiThreadDriver>(),
      std::mem::size_of::<AsyncRuntime>(),
      self.config.max_outstanding,
    )?;
    let ByteRateLimits {
      disk: disk_rate,
      upload: upload_rate,
      download: download_rate,
    } = self.services.build_rate_limits(resources.tenant_domain())?;
    #[cfg(feature = "resource-feedback")]
    let feedback_meters = self.services.feedback_meters(resources.tenant_domain())?;
    let mut startup = StartupGuard::default();
    let mut options =
      AsyncRuntimeOptions::new().thread_options(self.thread_options.unwrap_or_default());
    if let Some(handoffs) = self.handoffs {
      options = options.handoffs(handoffs);
    }
    let asynchronous =
      AsyncRuntime::with_resources_and_options(self.config, resources.clone(), options)
        .map_err(DriverBuildError::Async)?;
    startup.asynchronous = Some(asynchronous);
    let filesystem = self.services.build_services(
      &resources,
      &mut startup,
      match resources.tenant_domain() {
        Some(tenant) => {
          IdleCoordinator::new_in_tenant(None, tenant).map_err(DriverBuildError::ResourceDomain)?
        }
        None => IdleCoordinator::new(None),
      },
      false,
      self.config.max_outstanding,
    )?;
    let filesystem = bind_filesystem_rate(
      filesystem,
      disk_rate.as_ref(),
      #[cfg(feature = "resource-feedback")]
      feedback_meters.as_ref(),
    )?;
    #[cfg(feature = "resource-feedback")]
    let runtime_metrics = startup.asynchronous.as_ref().map(AsyncRuntime::metrics);
    #[cfg(feature = "resource-feedback")]
    let feedback_status = self.services.start_feedback(
      FeedbackStartupInputs {
        resources: resources.clone(),
        disk_rate: disk_rate.clone(),
        upload_rate: upload_rate.clone(),
        download_rate: download_rate.clone(),
        runtime_metrics,
        meters: feedback_meters.clone(),
      },
      &mut startup,
      &mut owner_control,
    )?;
    self.services.start_signal(&mut startup)?;
    if let Some(timer) = startup.timer.as_ref().map(TimerDriver::handle) {
      if let Some(blocking) = startup.blocking.as_mut() {
        blocking.bind_clock(timer.clone());
      }
      if let Some(io_pool) = startup.io_pool.as_mut() {
        io_pool.bind_clock(timer);
      }
    }
    Ok(MultiThreadDriver {
      asynchronous: startup
        .asynchronous
        .take()
        .unwrap_or_else(|| unreachable!()),
      resources,
      timer: startup.timer.take(),
      rate_timer: startup.rate_timer.take(),
      reactor: startup.reactor.take(),
      blocking: startup.blocking.take(),
      io_pool: startup.io_pool.take(),
      filesystem,
      process: startup.process.take(),
      signal: startup.signal.take(),
      #[cfg(feature = "resource-feedback")]
      feedback: startup.feedback.take(),
      #[cfg(feature = "resource-feedback")]
      feedback_meters,
      #[cfg(feature = "resource-feedback")]
      feedback_status,
      disk_rate,
      upload_rate,
      download_rate,
      shutdown: None,
      shutdown_failure: None,
      blocking_shutdown_requested: false,
      io_pool_shutdown_requested: false,
      process_shutdown_requested: false,
      io_shutdown_requested: false,
      _control: owner_control,
    })
  }
}

service_builder_methods!(MultiThreadBuilder);

#[derive(Default)]
struct StartupGuard {
  local: Option<LocalRuntime>,
  asynchronous: Option<AsyncRuntime>,
  blocking: Option<BlockingRuntime>,
  io_pool: Option<IoPool>,
  timer: Option<TimerDriver>,
  rate_timer: Option<TimerDriver>,
  reactor: Option<Reactor>,
  process: Option<ProcessDriver>,
  signal: Option<SignalDriver>,
  #[cfg(feature = "resource-feedback")]
  feedback: Option<ResourceFeedbackService>,
}

impl Drop for StartupGuard {
  fn drop(&mut self) {
    #[cfg(feature = "resource-feedback")]
    if let Some(feedback) = self.feedback.as_mut() {
      feedback.request_stop();
      while !feedback.is_shutdown_complete() {
        let _ = feedback.try_shutdown();
        if !feedback.is_shutdown_complete() {
          std::thread::yield_now();
        }
      }
    }
    #[cfg(feature = "resource-feedback")]
    self.feedback.take();
    if let Some(process) = self.process.as_mut() {
      let _ = process.shutdown(ProcessShutdownMode::Wait);
    }
    if let Some(reactor) = self.reactor.take() {
      let _ = reactor.shutdown();
    }
    if let Some(timer) = self.timer.take() {
      let _ = timer.shutdown();
    }
    if let Some(timer) = self.rate_timer.take() {
      let _ = timer.shutdown();
    }
    if let Some(blocking) = self.blocking.as_mut() {
      let _ = blocking.shutdown(ShutdownMode::CancelPending);
    }
    if let Some(io_pool) = self.io_pool.as_mut() {
      let _ = io_pool.shutdown();
    }
    if let Some(asynchronous) = self.asynchronous.take() {
      let _ = asynchronous.shutdown(AsyncShutdown::CancelPending);
    }
    self.local.take();
    self.process.take();
    self.signal.take();
  }
}

/// Owner-thread runtime and its selected service drivers.
pub struct CurrentThreadDriver {
  local: LocalRuntime,
  resources: ResourceScope,
  timer: Option<TimerDriver>,
  rate_timer: Option<TimerDriver>,
  reactor: Option<Reactor>,
  blocking: Option<BlockingRuntime>,
  io_pool: Option<IoPool>,
  filesystem: Option<FsHandle>,
  process: Option<ProcessDriver>,
  signal: Option<SignalDriver>,
  #[cfg(feature = "resource-feedback")]
  feedback: Option<ResourceFeedbackService>,
  #[cfg(feature = "resource-feedback")]
  feedback_meters: Option<FeedbackMeters>,
  #[cfg(feature = "resource-feedback")]
  feedback_status: FeedbackStatus,
  disk_rate: Option<ByteRateLimit>,
  upload_rate: Option<ByteRateLimit>,
  download_rate: Option<ByteRateLimit>,
  shutdown: Option<CurrentShutdown>,
  shutdown_failure: Option<DriverShutdownError>,
  blocking_shutdown_requested: bool,
  io_pool_shutdown_requested: bool,
  process_shutdown_requested: bool,
  io_shutdown_requested: bool,
  _control: ControlCharge,
}

impl CurrentThreadDriver {
  /// The local executor's existing implicit root handle.
  #[must_use]
  pub fn handle(&self) -> LocalHandle {
    self.local.handle()
  }

  /// Cross-thread submission to the local runtime's implicit root scope.
  #[must_use]
  pub fn send_handle(&self) -> LocalSendHandle {
    self.local.send_handle()
  }

  /// Polls a borrowed root future and local tasks on this owner thread.
  pub fn block_on<F: Future>(&mut self, future: F) -> Result<F::Output, LocalError> {
    self.local.block_on(future)
  }

  /// Creates a child local scope on the same managed-resource ledger.
  pub fn scope(&self) -> Result<LocalTaskScope, LocalError> {
    self.local.scope_with_resources(&self.resources)
  }

  /// The ledger shared by the executor root and the filesystem service.
  #[must_use]
  pub const fn resources(&self) -> &ResourceScope {
    &self.resources
  }

  /// A handle to the selected timer, if present.
  #[must_use]
  pub fn timer(&self) -> Option<TimerHandle> {
    self.timer.as_ref().map(TimerDriver::handle)
  }

  /// The current-thread runtime's owned clock, if a timer was selected.
  #[must_use]
  pub fn clock(&self) -> Option<TimerHandle> {
    self.timer()
  }

  /// The selected clock's current mode, if this runtime owns a timer.
  #[must_use]
  pub fn clock_mode(&self) -> Option<ClockMode> {
    self.clock().map(|clock| clock.mode())
  }

  /// A handle to the selected reactor, if present.
  #[must_use]
  pub fn reactor(&self) -> Option<ReactorHandle> {
    self.reactor.as_ref().map(Reactor::handle)
  }

  /// A handle to the selected blocking pool, if present.
  #[must_use]
  pub fn blocking(&self) -> Option<BlockingHandle> {
    self.blocking.as_ref().map(BlockingRuntime::handle)
  }

  /// A handle to the selected I/O adapter pool, if present, for building
  /// blocking stream adapters. A caller cannot queue its own closure
  /// through it.
  #[must_use]
  pub fn io_pool(&self) -> Option<IoPoolHandle> {
    self.io_pool.as_ref().map(IoPool::handle)
  }

  /// The filesystem front end over this runtime's I/O pool and ledger.
  #[must_use]
  pub fn filesystem(&self) -> Option<FsHandle> {
    self.filesystem.clone()
  }

  /// The owned process driver, if selected.
  #[must_use]
  pub const fn processes(&self) -> Option<&ProcessDriver> {
    self.process.as_ref()
  }

  /// The process-wide signal integration, if selected.
  #[must_use]
  pub const fn signals(&self) -> Option<&SignalDriver> {
    self.signal.as_ref()
  }

  /// A clone of the configured disk application-byte bucket.
  #[must_use]
  pub fn disk_rate(&self) -> Option<ByteRateLimit> {
    self.disk_rate.clone()
  }

  /// Clones of the selected directional byte buckets.
  #[must_use]
  pub fn upload_rate(&self) -> Option<ByteRateLimit> {
    self.upload_rate.clone()
  }

  /// Clones of the selected directional byte buckets.
  #[must_use]
  pub fn download_rate(&self) -> Option<ByteRateLimit> {
    self.download_rate.clone()
  }

  /// Creates cloneable bindings for the configured resource and I/O policies.
  ///
  /// Move clones into owned tasks to wrap endpoints without retaining this
  /// driver. The shared payload is charged to the bound tenant before it is
  /// allocated. Driver shutdown still closes its rate timer. Stream adapters
  /// limit bytes; logical operation permits use the returned binding's scope.
  pub fn io_bindings(&self) -> Result<IoBindings, DomainError> {
    let timer = self.rate_timer.as_ref().map(TimerDriver::handle);
    IoBindings::new(
      &self.resources,
      self.disk_rate.as_ref(),
      self.upload_rate.as_ref(),
      self.download_rate.as_ref(),
      timer.as_ref(),
      #[cfg(feature = "resource-feedback")]
      self.feedback_meters.clone(),
    )
  }

  /// Wraps an application stream with download/read and upload/write buckets.
  ///
  /// The adapter uses a private fixed real-clock timer, independently of this
  /// runtime's virtual application clock. Missing rates return the original
  /// endpoint unchanged. This does not intercept filesystem calls or raw I/O
  /// that bypasses the returned adapter.
  #[cfg(not(loom))]
  pub fn rate_io<T: AsyncRead + AsyncWrite + Unpin>(
    &self,
    inner: T,
  ) -> Result<RateLimitedIo<T>, DriverRateIoError<T>> {
    build_rate_io(
      inner,
      self.download_rate.clone(),
      self.upload_rate.clone(),
      self.rate_timer.as_ref().map(TimerDriver::handle),
      #[cfg(feature = "resource-feedback")]
      self.feedback_meters.as_ref(),
    )
  }

  /// Wraps an application stream with the selected disk bucket on both
  /// reads and writes. This adapter is explicit; it does not intercept the
  /// filesystem front end or raw file I/O that bypasses the returned stream.
  #[cfg(not(loom))]
  pub fn disk_io<T: AsyncRead + AsyncWrite + Unpin>(
    &self,
    inner: T,
  ) -> Result<RateLimitedIo<T>, DriverRateIoError<T>> {
    build_disk_io(
      inner,
      self.disk_rate.clone(),
      self.rate_timer.as_ref().map(TimerDriver::handle),
      #[cfg(feature = "resource-feedback")]
      self.feedback_meters.as_ref(),
    )
  }

  /// A cloneable metrics handle for this driver's feedback service, if the
  /// build started one (by default or from `feedback_sources`).
  #[cfg(feature = "resource-feedback")]
  #[must_use]
  pub fn feedback_metrics(&self) -> Option<FeedbackMetricsHandle> {
    self
      .feedback
      .as_ref()
      .map(ResourceFeedbackService::metrics_handle)
  }

  /// What the build did about resource feedback: started a service, was
  /// turned off, found the default service not applicable, or could not
  /// start it. This is the build outcome: a service that later latches a
  /// control still reports [`FeedbackStatus::Running`]; read its controls
  /// through [`Self::feedback_metrics`].
  #[cfg(feature = "resource-feedback")]
  #[must_use]
  pub const fn feedback_status(&self) -> FeedbackStatus {
    self.feedback_status
  }

  /// Queues one readback reconciliation for a latched control of this
  /// driver's feedback service, or returns `None` when the build started no
  /// service.
  ///
  /// A control latches after a failed or ambiguous change, or when its limit
  /// was changed by someone else (external drift), for example a caller that
  /// sets the domain's global CPU soft limit while the default service runs.
  /// After reconciliation the service continues from the limit it reads
  /// back. To keep a caller-set limit fixed instead, build the driver with
  /// `without_feedback`.
  #[cfg(feature = "resource-feedback")]
  pub fn request_feedback_reconcile(
    &self,
    resource: FeedbackResource,
  ) -> Option<Result<(), ReconcileRequestError>> {
    self
      .feedback
      .as_ref()
      .map(|feedback| feedback.request_reconcile(resource))
  }

  /// Closes local admission and requests cancellation according to `policy`.
  /// Supporting services remain open while owner-thread future cleanup,
  /// blocking work, I/O adapter work and child reaping finish, in that
  /// order. Repeating the same request is safe; a different policy is
  /// rejected.
  pub fn request_shutdown(&mut self, policy: CurrentShutdown) -> Result<(), DriverShutdownError> {
    if self.shutdown.is_some_and(|current| current != policy) {
      return Err(DriverShutdownError::PolicyAlreadyFixed);
    }
    self.shutdown = Some(policy);
    #[cfg(feature = "resource-feedback")]
    if let Some(feedback) = self.feedback.as_ref() {
      feedback.request_stop();
    }
    self.local.request_shutdown();
    Ok(())
  }

  fn request_blocking_shutdown(
    &mut self,
    policy: CurrentShutdown,
  ) -> Result<(), DriverShutdownError> {
    if self.blocking_shutdown_requested {
      return Ok(());
    }
    if let Some(blocking) = self.blocking.as_mut() {
      blocking
        .request_shutdown(policy.blocking)
        .map_err(|error| DriverShutdownError::Blocking(error.kind()))?;
    }
    self.blocking_shutdown_requested = true;
    Ok(())
  }

  /// The I/O pool's own shutdown step, separate from the blocking pool's.
  /// It always drains: admitted adapter operations are never discarded.
  fn request_io_pool_shutdown(&mut self) -> Result<(), DriverShutdownError> {
    if self.io_pool_shutdown_requested {
      return Ok(());
    }
    if let Some(io_pool) = self.io_pool.as_mut() {
      io_pool
        .request_shutdown()
        .map_err(|error| DriverShutdownError::IoPool(error.kind()))?;
    }
    self.io_pool_shutdown_requested = true;
    Ok(())
  }

  fn request_process_shutdown(
    &mut self,
    policy: CurrentShutdown,
  ) -> Result<(), DriverShutdownError> {
    if self.process_shutdown_requested {
      return Ok(());
    }
    if let Some(process) = self.process.as_mut() {
      process
        .request_shutdown(policy.processes)
        .map_err(|error| DriverShutdownError::CloseThread(error.kind()))?;
    }
    self.process_shutdown_requested = true;
    Ok(())
  }

  fn request_io_shutdown(&mut self) -> Result<(), DriverShutdownError> {
    if self.io_shutdown_requested {
      return Ok(());
    }
    if let Some(timer) = self.timer.as_mut() {
      timer
        .request_shutdown()
        .map_err(|error| DriverShutdownError::CloseThread(error.kind()))?;
    }
    if let Some(timer) = self.rate_timer.as_mut() {
      timer
        .request_shutdown()
        .map_err(|error| DriverShutdownError::CloseThread(error.kind()))?;
    }
    if let Some(reactor) = self.reactor.as_mut() {
      reactor
        .request_shutdown()
        .map_err(|error| DriverShutdownError::CloseThread(error.kind()))?;
    }
    self.io_shutdown_requested = true;
    Ok(())
  }

  /// Checks actual completion without cleaning up local futures or queued
  /// blocking closures. Use [`CurrentThreadDriver::drive_shutdown_step`] for
  /// owner-thread cleanup; one user destructor or completion waker may block.
  pub fn try_shutdown(&mut self) -> Result<ShutdownProgress, DriverShutdownError> {
    if self.shutdown.is_none() {
      return Err(DriverShutdownError::NotRequested);
    }
    let mut failure = None;
    #[cfg(feature = "resource-feedback")]
    let feedback_complete = poll_feedback_service(self.feedback.as_mut(), &mut failure);
    #[cfg(not(feature = "resource-feedback"))]
    let feedback_complete = true;
    let local_complete = self.local.shutdown_complete();
    let mut blocking_complete = false;
    if local_complete && feedback_complete {
      if let Some(policy) = self.shutdown {
        self.request_blocking_shutdown(policy)?;
      }
      if let Some(blocking) = self.blocking.as_mut() {
        match blocking.poll_shutdown() {
          Ok(done) => blocking_complete = done,
          Err(error) => {
            failure.get_or_insert(DriverShutdownError::Blocking(error.kind()));
            blocking_complete = blocking.shutdown_complete();
          }
        }
      } else {
        blocking_complete = true;
      }
    }

    let mut io_pool_complete = false;
    if blocking_complete && feedback_complete {
      self.request_io_pool_shutdown()?;
      if let Some(io_pool) = self.io_pool.as_mut() {
        match io_pool.poll_shutdown() {
          Ok(done) => io_pool_complete = done,
          Err(error) => {
            failure.get_or_insert(DriverShutdownError::IoPool(error.kind()));
            io_pool_complete = io_pool.shutdown_complete();
          }
        }
      } else {
        io_pool_complete = true;
      }
    }

    let mut process_complete = false;
    if io_pool_complete && feedback_complete {
      if let Some(policy) = self.shutdown {
        self.request_process_shutdown(policy)?;
      }
      if let Some(process) = self.process.as_mut() {
        match process.poll_shutdown() {
          Ok(done) => process_complete = done,
          Err(error) => {
            failure.get_or_insert(DriverShutdownError::Process(error));
            process_complete = process.shutdown_complete();
          }
        }
      } else {
        process_complete = true;
      }
    }

    let mut io_complete = false;
    if process_complete && feedback_complete {
      self.request_io_shutdown()?;
      io_complete = true;
      if let Some(timer) = self.timer.as_mut() {
        match timer.poll_shutdown() {
          Ok(done) => io_complete &= done,
          Err(error) => {
            failure.get_or_insert(DriverShutdownError::Timer(error));
          }
        }
      }
      if let Some(timer) = self.rate_timer.as_mut() {
        match timer.poll_shutdown() {
          Ok(done) => io_complete &= done,
          Err(error) => {
            failure.get_or_insert(DriverShutdownError::Timer(error));
          }
        }
      }
      if let Some(reactor) = self.reactor.as_mut() {
        match reactor.poll_shutdown() {
          Ok(done) => io_complete &= done,
          Err(error) => {
            failure.get_or_insert(DriverShutdownError::Reactor(error));
          }
        }
      }
    }
    if let Some(error) = failure {
      return Err(remember_shutdown_failure(&mut self.shutdown_failure, error));
    }
    if let Some(error) = self.shutdown_failure {
      return Err(error);
    }
    let complete = local_complete
      && blocking_complete
      && io_pool_complete
      && process_complete
      && io_complete
      && feedback_complete;
    Ok(if complete {
      ShutdownProgress::Complete
    } else {
      ShutdownProgress::Pending
    })
  }

  /// Runs one owner-thread task cleanup and drops at most one queued job of
  /// the user blocking pool, then checks all services. That check advances
  /// the I/O pool's draining step once it has been requested; it never
  /// discards an I/O pool operation. Local future destructors and queued
  /// job captures can take unbounded time while this explicit method runs.
  pub fn drive_shutdown_step(&mut self) -> Result<ShutdownProgress, DriverShutdownError> {
    if self.shutdown.is_none() {
      return Err(DriverShutdownError::NotRequested);
    }
    if let Err(error) = self.local.drive_shutdown_step() {
      remember_shutdown_failure(
        &mut self.shutdown_failure,
        DriverShutdownError::Local(error),
      );
    }
    if let Some(blocking) = self.blocking.as_mut()
      && self.blocking_shutdown_requested
      && let Err(error) = blocking.drive_shutdown_step()
    {
      remember_shutdown_failure(
        &mut self.shutdown_failure,
        DriverShutdownError::Blocking(error.kind()),
      );
    }
    self.try_shutdown()
  }
}

/// Multithreaded runtime and its selected service drivers.
pub struct MultiThreadDriver {
  asynchronous: AsyncRuntime,
  resources: ResourceScope,
  timer: Option<TimerDriver>,
  rate_timer: Option<TimerDriver>,
  reactor: Option<Reactor>,
  blocking: Option<BlockingRuntime>,
  io_pool: Option<IoPool>,
  filesystem: Option<FsHandle>,
  process: Option<ProcessDriver>,
  signal: Option<SignalDriver>,
  #[cfg(feature = "resource-feedback")]
  feedback: Option<ResourceFeedbackService>,
  #[cfg(feature = "resource-feedback")]
  feedback_meters: Option<FeedbackMeters>,
  #[cfg(feature = "resource-feedback")]
  feedback_status: FeedbackStatus,
  disk_rate: Option<ByteRateLimit>,
  upload_rate: Option<ByteRateLimit>,
  download_rate: Option<ByteRateLimit>,
  shutdown: Option<MultiShutdown>,
  shutdown_failure: Option<DriverShutdownError>,
  blocking_shutdown_requested: bool,
  io_pool_shutdown_requested: bool,
  process_shutdown_requested: bool,
  io_shutdown_requested: bool,
  _control: ControlCharge,
}

impl MultiThreadDriver {
  /// The async executor's existing implicit root handle.
  #[must_use]
  pub fn handle(&self) -> AsyncHandle {
    self.asynchronous.handle()
  }

  /// A cloneable diagnostic view that remains usable after runtime shutdown.
  #[must_use]
  pub fn metrics(&self) -> RuntimeMetrics {
    self.asynchronous.metrics()
  }

  /// Polls a borrowed root future on the caller's thread.
  pub fn block_on<F: Future>(&self, future: F) -> Result<F::Output, AsyncError> {
    self.asynchronous.block_on(future)
  }

  /// Creates a cancellable child scope on the same managed-resource ledger.
  pub fn scope(&self) -> Result<OwnedTaskScope, AsyncError> {
    self.asynchronous.scope_with_resources(&self.resources)
  }

  /// The ledger shared by the executor root and filesystem service.
  #[must_use]
  pub const fn resources(&self) -> &ResourceScope {
    &self.resources
  }

  /// A handle to the selected timer, if present.
  #[must_use]
  pub fn timer(&self) -> Option<TimerHandle> {
    self.timer.as_ref().map(TimerDriver::handle)
  }

  /// A handle to the selected reactor, if present.
  #[must_use]
  pub fn reactor(&self) -> Option<ReactorHandle> {
    self.reactor.as_ref().map(Reactor::handle)
  }

  /// A handle to the selected blocking pool, if present.
  #[must_use]
  pub fn blocking(&self) -> Option<BlockingHandle> {
    self.blocking.as_ref().map(BlockingRuntime::handle)
  }

  /// A handle to the selected I/O adapter pool, if present, for building
  /// blocking stream adapters. A caller cannot queue its own closure
  /// through it.
  #[must_use]
  pub fn io_pool(&self) -> Option<IoPoolHandle> {
    self.io_pool.as_ref().map(IoPool::handle)
  }

  /// The filesystem front end over this runtime's I/O pool and ledger.
  #[must_use]
  pub fn filesystem(&self) -> Option<FsHandle> {
    self.filesystem.clone()
  }

  /// The owned process driver, if selected.
  #[must_use]
  pub const fn processes(&self) -> Option<&ProcessDriver> {
    self.process.as_ref()
  }

  /// The process-wide signal integration, if selected.
  #[must_use]
  pub const fn signals(&self) -> Option<&SignalDriver> {
    self.signal.as_ref()
  }

  /// A clone of the configured disk application-byte bucket.
  #[must_use]
  pub fn disk_rate(&self) -> Option<ByteRateLimit> {
    self.disk_rate.clone()
  }

  /// Clones of the selected directional byte bucket.
  #[must_use]
  pub fn upload_rate(&self) -> Option<ByteRateLimit> {
    self.upload_rate.clone()
  }

  /// Clones of the selected directional byte bucket.
  #[must_use]
  pub fn download_rate(&self) -> Option<ByteRateLimit> {
    self.download_rate.clone()
  }

  /// Creates cloneable bindings for the configured resource and I/O policies.
  ///
  /// Move clones into owned tasks to wrap endpoints without retaining this
  /// driver. The shared payload is charged to the bound tenant before it is
  /// allocated. Driver shutdown still closes its rate timer. Stream adapters
  /// limit bytes; logical operation permits use the returned binding's scope.
  pub fn io_bindings(&self) -> Result<IoBindings, DomainError> {
    let timer = self.rate_timer.as_ref().map(TimerDriver::handle);
    IoBindings::new(
      &self.resources,
      self.disk_rate.as_ref(),
      self.upload_rate.as_ref(),
      self.download_rate.as_ref(),
      timer.as_ref(),
      #[cfg(feature = "resource-feedback")]
      self.feedback_meters.clone(),
    )
  }

  /// Wraps an application stream with download/read and upload/write buckets.
  ///
  /// The adapter uses a private fixed real-clock timer, independently of any
  /// application clock. Missing rates return the original endpoint unchanged.
  /// This does not intercept filesystem calls or raw I/O that bypasses the
  /// returned adapter.
  #[cfg(not(loom))]
  pub fn rate_io<T: AsyncRead + AsyncWrite + Unpin>(
    &self,
    inner: T,
  ) -> Result<RateLimitedIo<T>, DriverRateIoError<T>> {
    build_rate_io(
      inner,
      self.download_rate.clone(),
      self.upload_rate.clone(),
      self.rate_timer.as_ref().map(TimerDriver::handle),
      #[cfg(feature = "resource-feedback")]
      self.feedback_meters.as_ref(),
    )
  }

  /// Wraps an application stream with the selected disk bucket on both
  /// reads and writes. This adapter is explicit; it does not intercept the
  /// filesystem front end or raw file I/O that bypasses the returned stream.
  #[cfg(not(loom))]
  pub fn disk_io<T: AsyncRead + AsyncWrite + Unpin>(
    &self,
    inner: T,
  ) -> Result<RateLimitedIo<T>, DriverRateIoError<T>> {
    build_disk_io(
      inner,
      self.disk_rate.clone(),
      self.rate_timer.as_ref().map(TimerDriver::handle),
      #[cfg(feature = "resource-feedback")]
      self.feedback_meters.as_ref(),
    )
  }

  /// A cloneable metrics handle for this driver's feedback service, if the
  /// build started one (by default or from `feedback_sources`).
  #[cfg(feature = "resource-feedback")]
  #[must_use]
  pub fn feedback_metrics(&self) -> Option<FeedbackMetricsHandle> {
    self
      .feedback
      .as_ref()
      .map(ResourceFeedbackService::metrics_handle)
  }

  /// What the build did about resource feedback: started a service, was
  /// turned off, found the default service not applicable, or could not
  /// start it. This is the build outcome: a service that later latches a
  /// control still reports [`FeedbackStatus::Running`]; read its controls
  /// through [`Self::feedback_metrics`].
  #[cfg(feature = "resource-feedback")]
  #[must_use]
  pub const fn feedback_status(&self) -> FeedbackStatus {
    self.feedback_status
  }

  /// Queues one readback reconciliation for a latched control of this
  /// driver's feedback service, or returns `None` when the build started no
  /// service.
  ///
  /// A control latches after a failed or ambiguous change, or when its limit
  /// was changed by someone else (external drift), for example a caller that
  /// sets the domain's global CPU soft limit while the default service runs.
  /// After reconciliation the service continues from the limit it reads
  /// back. To keep a caller-set limit fixed instead, build the driver with
  /// `without_feedback`.
  #[cfg(feature = "resource-feedback")]
  pub fn request_feedback_reconcile(
    &self,
    resource: FeedbackResource,
  ) -> Option<Result<(), ReconcileRequestError>> {
    self
      .feedback
      .as_ref()
      .map(|feedback| feedback.request_reconcile(resource))
  }

  /// Closes executor admission. Blocking jobs continue first, then the I/O
  /// adapter pool drains in its own step, then managed children are reaped,
  /// and timer/reactor services close only after those stages finish. This
  /// keeps dependencies available to already-admitted async work, blocking
  /// closures that use adapters, and their completion chain.
  pub fn request_shutdown(&mut self, policy: MultiShutdown) -> Result<(), DriverShutdownError> {
    if self.shutdown.is_some_and(|current| current != policy) {
      return Err(DriverShutdownError::PolicyAlreadyFixed);
    }
    self.shutdown = Some(policy);
    #[cfg(feature = "resource-feedback")]
    if let Some(feedback) = self.feedback.as_ref() {
      feedback.request_stop();
    }
    self.asynchronous.request_shutdown(policy.tasks);
    Ok(())
  }

  fn request_blocking_shutdown(
    &mut self,
    policy: MultiShutdown,
  ) -> Result<(), DriverShutdownError> {
    if self.blocking_shutdown_requested {
      return Ok(());
    }
    if let Some(blocking) = self.blocking.as_mut() {
      blocking
        .request_shutdown(policy.blocking)
        .map_err(|error| DriverShutdownError::Blocking(error.kind()))?;
    }
    self.blocking_shutdown_requested = true;
    Ok(())
  }

  /// The I/O pool's own shutdown step, separate from the blocking pool's.
  /// It always drains: admitted adapter operations are never discarded.
  fn request_io_pool_shutdown(&mut self) -> Result<(), DriverShutdownError> {
    if self.io_pool_shutdown_requested {
      return Ok(());
    }
    if let Some(io_pool) = self.io_pool.as_mut() {
      io_pool
        .request_shutdown()
        .map_err(|error| DriverShutdownError::IoPool(error.kind()))?;
    }
    self.io_pool_shutdown_requested = true;
    Ok(())
  }

  fn request_process_shutdown(&mut self, policy: MultiShutdown) -> Result<(), DriverShutdownError> {
    if self.process_shutdown_requested {
      return Ok(());
    }
    if let Some(process) = self.process.as_mut() {
      process
        .request_shutdown(policy.processes)
        .map_err(|error| DriverShutdownError::CloseThread(error.kind()))?;
    }
    self.process_shutdown_requested = true;
    Ok(())
  }

  fn request_io_shutdown(&mut self) -> Result<(), DriverShutdownError> {
    if self.io_shutdown_requested {
      return Ok(());
    }
    if let Some(timer) = self.timer.as_mut() {
      timer
        .request_shutdown()
        .map_err(|error| DriverShutdownError::CloseThread(error.kind()))?;
    }
    if let Some(timer) = self.rate_timer.as_mut() {
      timer
        .request_shutdown()
        .map_err(|error| DriverShutdownError::CloseThread(error.kind()))?;
    }
    if let Some(reactor) = self.reactor.as_mut() {
      reactor
        .request_shutdown()
        .map_err(|error| DriverShutdownError::CloseThread(error.kind()))?;
    }
    self.io_shutdown_requested = true;
    Ok(())
  }

  /// Checks actual completion without dropping user work on the caller.
  /// Queued blocking closures require an explicit cleanup step.
  pub fn try_shutdown(&mut self) -> Result<ShutdownProgress, DriverShutdownError> {
    if self.shutdown.is_none() {
      return Err(DriverShutdownError::NotRequested);
    }
    let mut failure = None;
    #[cfg(feature = "resource-feedback")]
    let feedback_complete = poll_feedback_service(self.feedback.as_mut(), &mut failure);
    #[cfg(not(feature = "resource-feedback"))]
    let feedback_complete = true;
    if let Err(error) = self.asynchronous.poll_shutdown() {
      failure.get_or_insert(DriverShutdownError::Async(error));
    }
    let async_complete = self.asynchronous.shutdown_complete();
    let mut blocking_complete = false;
    if async_complete && feedback_complete {
      if let Some(policy) = self.shutdown {
        self.request_blocking_shutdown(policy)?;
      }
      if let Some(blocking) = self.blocking.as_mut() {
        match blocking.poll_shutdown() {
          Ok(done) => blocking_complete = done,
          Err(error) => {
            failure.get_or_insert(DriverShutdownError::Blocking(error.kind()));
            blocking_complete = blocking.shutdown_complete();
          }
        }
      } else {
        blocking_complete = true;
      }
    }

    let mut io_pool_complete = false;
    if blocking_complete && feedback_complete {
      self.request_io_pool_shutdown()?;
      if let Some(io_pool) = self.io_pool.as_mut() {
        match io_pool.poll_shutdown() {
          Ok(done) => io_pool_complete = done,
          Err(error) => {
            failure.get_or_insert(DriverShutdownError::IoPool(error.kind()));
            io_pool_complete = io_pool.shutdown_complete();
          }
        }
      } else {
        io_pool_complete = true;
      }
    }

    let mut process_complete = false;
    if io_pool_complete && feedback_complete {
      if let Some(policy) = self.shutdown {
        self.request_process_shutdown(policy)?;
      }
      if let Some(process) = self.process.as_mut() {
        match process.poll_shutdown() {
          Ok(done) => process_complete = done,
          Err(error) => {
            failure.get_or_insert(DriverShutdownError::Process(error));
            process_complete = process.shutdown_complete();
          }
        }
      } else {
        process_complete = true;
      }
    }

    let mut io_complete = false;
    if process_complete && feedback_complete {
      self.request_io_shutdown()?;
      io_complete = true;
      if let Some(timer) = self.timer.as_mut() {
        match timer.poll_shutdown() {
          Ok(done) => io_complete &= done,
          Err(error) => {
            failure.get_or_insert(DriverShutdownError::Timer(error));
          }
        }
      }
      if let Some(timer) = self.rate_timer.as_mut() {
        match timer.poll_shutdown() {
          Ok(done) => io_complete &= done,
          Err(error) => {
            failure.get_or_insert(DriverShutdownError::Timer(error));
          }
        }
      }
      if let Some(reactor) = self.reactor.as_mut() {
        match reactor.poll_shutdown() {
          Ok(done) => io_complete &= done,
          Err(error) => {
            failure.get_or_insert(DriverShutdownError::Reactor(error));
          }
        }
      }
    }
    if let Some(error) = failure {
      return Err(remember_shutdown_failure(&mut self.shutdown_failure, error));
    }
    if let Some(error) = self.shutdown_failure {
      return Err(error);
    }
    let complete = async_complete
      && blocking_complete
      && io_pool_complete
      && process_complete
      && io_complete
      && feedback_complete;
    Ok(if complete {
      ShutdownProgress::Complete
    } else {
      ShutdownProgress::Pending
    })
  }

  /// Drops at most one queued job of the user blocking pool, then checks all
  /// services. That check advances the I/O pool's draining step once it has
  /// been requested; it never discards an I/O pool operation. A job capture's
  /// destructor can take unbounded time while this explicit cleanup step
  /// runs.
  pub fn drive_shutdown_step(&mut self) -> Result<ShutdownProgress, DriverShutdownError> {
    if self.shutdown.is_none() {
      return Err(DriverShutdownError::NotRequested);
    }
    if self.blocking_shutdown_requested
      && let Some(blocking) = self.blocking.as_mut()
      && let Err(error) = blocking.drive_shutdown_step()
    {
      remember_shutdown_failure(
        &mut self.shutdown_failure,
        DriverShutdownError::Blocking(error.kind()),
      );
    }
    self.try_shutdown()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::Resources;
  use std::pin::Pin;
  #[cfg(feature = "resource-feedback")]
  use std::sync::Condvar;
  use std::sync::Mutex;
  use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
  use std::sync::mpsc::{self, Receiver, SyncSender};
  use std::task::{Context, Wake, Waker};
  use std::time::{Duration, Instant};

  #[cfg(feature = "resource-feedback")]
  use crate::runtime::byte_rate::ByteRateConfig;
  #[cfg(all(not(loom), feature = "resource-feedback"))]
  use crate::runtime::io::AsyncWriteExt as RuntimeAsyncWriteExt;
  #[cfg(not(loom))]
  use crate::runtime::io::{
    AsyncRead as RuntimeAsyncRead, AsyncReadExt as RuntimeAsyncReadExt,
    AsyncWrite as RuntimeAsyncWrite,
  };
  #[cfg(feature = "resource-feedback")]
  use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};
  #[cfg(feature = "resource-feedback")]
  use crate::runtime::resource_feedback::{
    FeedbackActuator, FeedbackActuatorError, FeedbackSensor, FeedbackSensorError,
  };
  #[cfg(feature = "resource-feedback")]
  use crate::runtime::resource_feedback_actuator::{CpuFeedbackTarget, RuntimeFeedbackActuator};
  #[cfg(feature = "resource-feedback")]
  use crate::runtime::resource_feedback_policy::{
    FeedbackControlConfig, FeedbackResource, FeedbackSample, PlanTicket,
    ResourceFeedbackPolicyConfig,
  };

  static NEXT_FILE: AtomicUsize = AtomicUsize::new(1);
  // Service threads compete with the full all-feature suite; keep elapsed-time
  // watchdogs generous enough for scheduling while still bounding a deadlock.
  const DRIVER_TEST_WATCHDOG: Duration = Duration::from_secs(10);

  fn assert_send_sync<T: Send + Sync>() {}

  #[test]
  fn multithread_driver_remains_send_and_sync() {
    assert_send_sync::<MultiThreadDriver>();
  }

  fn local_config() -> LocalConfig {
    LocalConfig {
      max_outstanding: 4,
      max_scopes: 1,
    }
  }

  fn async_config() -> AsyncConfig {
    AsyncConfig {
      workers: 1,
      max_outstanding: 4,
      max_scopes: 1,
    }
  }

  fn limits(memory: usize) -> ResourceLimits {
    ResourceLimits {
      managed_memory: memory,
      disk_concurrent_ops: 2,
      network_concurrent_ops: 3,
    }
  }

  #[cfg(feature = "resource-feedback")]
  fn feedback_policy() -> ResourceFeedbackPolicyConfig {
    ResourceFeedbackPolicyConfig {
      cpu_concurrency: FeedbackControlConfig::new(4, 16, 64, 3000, 8000),
      disk_rate: FeedbackControlConfig::new(100, 1000, 2000, 3000, 8000),
      network_rate: FeedbackControlConfig::new(100, 1000, 2000, 3000, 8000),
    }
  }

  #[cfg(feature = "resource-feedback")]
  fn feedback_domain() -> (
    ResourceDomain,
    crate::runtime::resource_domain::TenantDomain,
  ) {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 64)
      .with(DomainResource::Tasks, 64)
      .with(DomainResource::Memory, 1 << 20)
      .with(DomainResource::Disk, 8)
      .with(DomainResource::Network, 8)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 2, 32).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    tenant
      .set_limits(ceiling.with(DomainResource::Cpu, 16))
      .unwrap();
    (domain, tenant)
  }

  #[cfg(feature = "resource-feedback")]
  fn feedback_rate_config() -> ByteRateConfig {
    ByteRateConfig {
      bytes_per_second: 1000,
      burst_bytes: 1024,
      max_reservations: 8,
    }
  }

  #[cfg(feature = "resource-feedback")]
  struct MissingFeedbackSensor;

  #[cfg(feature = "resource-feedback")]
  impl FeedbackSensor for MissingFeedbackSensor {
    fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
      Ok(FeedbackSample::new(Instant::now(), None, None, None))
    }
  }

  #[cfg(feature = "resource-feedback")]
  struct BusyFeedbackSensor;

  #[cfg(feature = "resource-feedback")]
  impl FeedbackSensor for BusyFeedbackSensor {
    fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
      Ok(FeedbackSample::new(
        Instant::now(),
        Some(9000),
        Some(9000),
        Some(9000),
      ))
    }
  }

  #[cfg(feature = "resource-feedback")]
  struct TestFeedbackActuator {
    limits: [u64; 3],
  }

  #[cfg(feature = "resource-feedback")]
  impl FeedbackActuator for TestFeedbackActuator {
    fn readback(&mut self, resource: FeedbackResource) -> Result<u64, FeedbackActuatorError> {
      Ok(self.limits[resource as usize])
    }

    fn apply(&mut self, ticket: PlanTicket) -> Result<(), FeedbackActuatorError> {
      self.limits[ticket.resource() as usize] = ticket.to_limit();
      Ok(())
    }
  }

  #[cfg(feature = "resource-feedback")]
  #[derive(Default)]
  struct SampleGate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
  }

  #[cfg(feature = "resource-feedback")]
  impl SampleGate {
    fn enter_and_wait(&self) {
      let mut state = self.state.lock().unwrap();
      state.0 = true;
      self.changed.notify_all();
      while !state.1 {
        state = self.changed.wait(state).unwrap();
      }
    }

    fn wait_until_entered(&self, timeout: Duration) -> bool {
      let state = self.state.lock().unwrap();
      let (state, _) = self
        .changed
        .wait_timeout_while(state, timeout, |state| !state.0)
        .unwrap();
      state.0
    }

    fn release(&self) {
      self.state.lock().unwrap().1 = true;
      self.changed.notify_all();
    }
  }

  #[cfg(feature = "resource-feedback")]
  struct GatedFeedbackSensor(Arc<SampleGate>);

  #[cfg(feature = "resource-feedback")]
  impl FeedbackSensor for GatedFeedbackSensor {
    fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
      self.0.enter_and_wait();
      Ok(FeedbackSample::new(Instant::now(), None, None, None))
    }
  }

  #[cfg(feature = "resource-feedback")]
  struct ReleaseSampleGate(Arc<SampleGate>);

  #[cfg(feature = "resource-feedback")]
  impl Drop for ReleaseSampleGate {
    fn drop(&mut self) {
      self.0.release();
    }
  }

  #[cfg(not(loom))]
  #[derive(Debug, PartialEq)]
  struct DriverTestIo {
    marker: u8,
    read_count: u8,
  }

  #[cfg(not(loom))]
  impl DriverTestIo {
    fn new(marker: u8) -> Self {
      Self {
        marker,
        read_count: 0,
      }
    }
  }

  #[cfg(not(loom))]
  impl RuntimeAsyncRead for DriverTestIo {
    fn poll_read(
      mut self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      buf: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
      if buf.is_empty() {
        return std::task::Poll::Ready(Ok(0));
      }
      buf[0] = self.marker.wrapping_add(self.read_count);
      self.read_count = self.read_count.wrapping_add(1);
      std::task::Poll::Ready(Ok(1))
    }
  }

  #[cfg(not(loom))]
  impl RuntimeAsyncWrite for DriverTestIo {
    fn poll_write(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
      std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> std::task::Poll<io::Result<()>> {
      std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
      std::task::Poll::Ready(Ok(()))
    }
  }

  fn shutdown_current_driver(driver: &mut CurrentThreadDriver) {
    driver.request_shutdown(CurrentShutdown::default()).unwrap();
    let deadline = Instant::now() + DRIVER_TEST_WATCHDOG;
    loop {
      match driver.drive_shutdown_step().unwrap() {
        ShutdownProgress::Complete => break,
        ShutdownProgress::Pending => {
          assert!(Instant::now() < deadline, "current driver did not stop");
          std::thread::yield_now();
        }
      }
    }
  }

  fn shutdown_multi_driver(driver: &mut MultiThreadDriver) {
    driver.request_shutdown(MultiShutdown::default()).unwrap();
    let deadline = Instant::now() + DRIVER_TEST_WATCHDOG;
    loop {
      match driver.try_shutdown().unwrap() {
        ShutdownProgress::Complete => break,
        ShutdownProgress::Pending => {
          if Instant::now() >= deadline {
            #[cfg(feature = "resource-feedback")]
            let feedback_complete = driver
              .feedback_metrics()
              .map(|metrics| metrics.snapshot().shutdown_complete);
            #[cfg(not(feature = "resource-feedback"))]
            let feedback_complete: Option<bool> = None;
            let rate_timer_closed = driver
              .rate_timer
              .as_ref()
              .map(|timer| timer.handle().is_closed());
            panic!(
              "multithread driver did not stop: async={}, blocking={:?}, process={:?}, feedback={feedback_complete:?}, rate_timer_closed={rate_timer_closed:?}",
              driver.asynchronous.shutdown_complete(),
              driver
                .blocking
                .as_ref()
                .map(|blocking| blocking.shutdown_complete()),
              driver
                .process
                .as_ref()
                .map(|process| process.shutdown_complete()),
            );
          }
          std::thread::yield_now();
        }
      }
    }
  }

  #[test]
  fn distinct_owning_facades_share_global_managed_limits_and_retained_results() {
    use crate::runtime::asynchronous::current_resource_scope;
    use crate::runtime::managed::{ResourceError, ResourceKind};
    use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};

    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 64)
      .with(DomainResource::Tasks, 64)
      .with(DomainResource::Memory, 8)
      .with(DomainResource::Disk, 2)
      .with(DomainResource::Network, 3)
      .with(DomainResource::Control, 1 << 16);
    let domain = ResourceDomain::with_waiters(ceiling, 2, 32).unwrap();
    let mut local = CurrentThreadBuilder::new(local_config())
      .resources(limits(8))
      .resource_domain(domain.tenant(ceiling).unwrap())
      .build()
      .unwrap();
    let mut threaded = MultiThreadBuilder::new(async_config())
      .resources(limits(8))
      .resource_domain(domain.tenant(ceiling).unwrap())
      .build()
      .unwrap();
    let held = local
      .block_on(async { current_resource_scope().try_alloc_zeroed(6) })
      .unwrap()
      .unwrap();
    let rejected = threaded
      .handle()
      .spawn(async { current_resource_scope().try_alloc_zeroed(4) })
      .unwrap();
    assert_eq!(
      threaded.block_on(rejected).unwrap().unwrap().map(drop),
      Err(ResourceError::Exhausted(ResourceKind::Memory))
    );
    assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 6);
    assert_eq!(threaded.resources().snapshot().managed_memory, 0);
    drop(held);
    let completed = threaded
      .handle()
      .spawn(async { current_resource_scope().try_alloc_zeroed(4) })
      .unwrap();
    let result = threaded.block_on(completed).unwrap().unwrap().unwrap();
    let retained = result.clone();
    drop(result);
    local.request_shutdown(CurrentShutdown::default()).unwrap();
    threaded.request_shutdown(MultiShutdown::default()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while local.drive_shutdown_step().unwrap() != ShutdownProgress::Complete
      || threaded.drive_shutdown_step().unwrap() != ShutdownProgress::Complete
    {
      assert!(Instant::now() < deadline, "facades did not finish shutdown");
      std::thread::yield_now();
    }
    drop(local);
    drop(threaded);
    assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 4);
    drop(retained);
    assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 0);
  }

  #[test]
  fn local_root_children_and_external_imports_share_the_bound_ledger() {
    use super::super::asynchronous::{AsyncJoinError, current_resource_scope};

    let limits = limits(8);
    let mut driver = CurrentThreadBuilder::new(local_config())
      .resources(limits)
      .build()
      .unwrap_or_else(|error| panic!("current-thread build failed: {error}"));

    let root_buffer = driver
      .block_on(async {
        assert_eq!(current_resource_scope().limits(), limits);
        current_resource_scope().try_alloc_zeroed(8)
      })
      .unwrap_or_else(|error| panic!("root block_on failed: {error}"))
      .unwrap_or_else(|error| panic!("root managed allocation failed: {error}"));
    assert_eq!(driver.resources().snapshot().managed_memory, 8);

    let local_job = driver
      .handle()
      .spawn_local(async { current_resource_scope().try_alloc_zeroed(1).is_err() })
      .unwrap_or_else(|error| panic!("local task admission failed: {error}"));
    assert!(
      driver
        .block_on(local_job)
        .unwrap_or_else(|error| panic!("local join poll failed: {error}"))
        .unwrap_or_else(|error: AsyncJoinError| panic!("local task failed: {error}"))
    );

    let external = driver.send_handle();
    let external_job = external
      .spawn(async move {
        assert_eq!(current_resource_scope().limits(), limits);
        current_resource_scope().try_alloc_zeroed(1).is_err()
      })
      .unwrap_or_else(|error| panic!("external submission failed: {error}"));
    assert!(
      driver
        .block_on(external_job)
        .unwrap_or_else(|error| panic!("external join poll failed: {error}"))
        .unwrap_or_else(|error| panic!("external task failed: {error}"))
    );

    driver
      .request_shutdown(CurrentShutdown::default())
      .unwrap_or_else(|error| panic!("shutdown request failed: {error}"));
    assert_eq!(
      driver.drive_shutdown_step().unwrap(),
      ShutdownProgress::Complete
    );
    assert!(matches!(external.spawn(async {}), Err(error) if error.kind == LocalError::Closed));
    drop(root_buffer);
    assert_eq!(driver.resources().snapshot().managed_memory, 0);
  }

  struct CheckBoundDrop(std::sync::Arc<AtomicBool>);

  impl Drop for CheckBoundDrop {
    fn drop(&mut self) {
      let bound = super::super::asynchronous::try_current_resource_scope().is_some();
      self.0.store(bound, Ordering::Release);
    }
  }

  #[test]
  fn queued_external_import_cleanup_keeps_the_root_resource_binding() {
    let mut driver = CurrentThreadBuilder::new(local_config())
      .resources(limits(8))
      .build()
      .unwrap_or_else(|error| panic!("current-thread build failed: {error}"));
    let observed = std::sync::Arc::new(AtomicBool::new(false));
    let marker = CheckBoundDrop(std::sync::Arc::clone(&observed));
    let job = driver
      .send_handle()
      .spawn(async move {
        let _marker = marker;
        std::future::pending::<()>().await;
      })
      .unwrap_or_else(|error| panic!("external submission failed: {error}"));

    driver
      .request_shutdown(CurrentShutdown::default())
      .unwrap_or_else(|error| panic!("shutdown request failed: {error}"));
    assert_eq!(driver.try_shutdown().unwrap(), ShutdownProgress::Pending);
    assert_eq!(
      driver.drive_shutdown_step().unwrap(),
      ShutdownProgress::Pending
    );
    assert!(observed.load(Ordering::Acquire));
    assert_eq!(
      driver.drive_shutdown_step().unwrap(),
      ShutdownProgress::Complete
    );
    drop(job);
  }

  #[test]
  fn async_root_and_worker_task_share_the_existing_single_scope() {
    use super::super::asynchronous::current_resource_scope;

    let limits = limits(16);
    let driver = MultiThreadBuilder::new(async_config())
      .resources(limits)
      .build()
      .unwrap_or_else(|error| panic!("multithread build failed: {error}"));
    assert_eq!(
      driver
        .block_on(async { current_resource_scope().limits() })
        .unwrap_or_else(|error| panic!("root block_on failed: {error}")),
      limits
    );

    let escaped = driver.handle();
    let job = escaped
      .spawn(async {
        current_resource_scope()
          .try_alloc_zeroed(12)
          .unwrap_or_else(|error| panic!("worker allocation failed: {error}"))
      })
      .unwrap_or_else(|error| panic!("worker task admission failed: {error}"));
    let buffer = driver
      .block_on(job)
      .unwrap_or_else(|error| panic!("worker join poll failed: {error}"))
      .unwrap_or_else(|error| panic!("worker task failed: {error}"));
    assert_eq!(driver.resources().snapshot().managed_memory, 12);
    drop(buffer);

    let mut driver = driver;
    driver
      .request_shutdown(MultiShutdown::default())
      .unwrap_or_else(|error| panic!("shutdown request failed: {error}"));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      match driver.try_shutdown() {
        Ok(ShutdownProgress::Complete) => break,
        Ok(ShutdownProgress::Pending) if Instant::now() < deadline => {
          std::thread::yield_now();
        }
        result => panic!("unexpected shutdown progress: {result:?}"),
      }
    }
    assert_eq!(
      escaped
        .block_on(async { current_resource_scope().limits().managed_memory })
        .unwrap_or_else(|error| panic!("escaped bound root poll failed: {error}")),
      16
    );
    assert!(matches!(escaped.spawn(async {}), Err(error) if error.kind == AsyncError::Closed));
  }

  struct BlockingWake {
    started: SyncSender<()>,
    release: Mutex<Receiver<()>>,
  }

  struct PanicDropGate {
    entered: SyncSender<()>,
    release: Mutex<Receiver<()>>,
  }

  impl Drop for PanicDropGate {
    fn drop(&mut self) {
      let _ = self.entered.send(());
      let _ = self
        .release
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .recv();
    }
  }

  impl BlockingWake {
    fn block(&self) {
      let _ = self.started.send(());
      let _ = self
        .release
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .recv();
    }
  }

  impl Wake for BlockingWake {
    fn wake(self: std::sync::Arc<Self>) {
      self.block();
    }

    fn wake_by_ref(self: &std::sync::Arc<Self>) {
      self.block();
    }
  }

  #[test]
  fn shutdown_stays_pending_until_a_close_waker_finishes() {
    let mut driver = MultiThreadBuilder::new(async_config())
      .timer(2)
      .build()
      .unwrap_or_else(|error| panic!("timer runtime build failed: {error}"));
    let timer = driver.timer().unwrap_or_else(|| panic!("timer is missing"));
    let mut sleep = Box::pin(
      timer
        .sleep(Duration::from_secs(60))
        .unwrap_or_else(|error| panic!("sleep creation failed: {error}")),
    );
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let waker = Waker::from(std::sync::Arc::new(BlockingWake {
      started: started_tx,
      release: Mutex::new(release_rx),
    }));
    let mut context = Context::from_waker(&waker);
    assert!(Pin::as_mut(&mut sleep).poll(&mut context).is_pending());

    driver
      .request_shutdown(MultiShutdown::default())
      .unwrap_or_else(|error| panic!("shutdown request failed: {error}"));
    let start_deadline = Instant::now() + Duration::from_secs(2);
    loop {
      assert_eq!(driver.try_shutdown().unwrap(), ShutdownProgress::Pending);
      match started_rx.try_recv() {
        Ok(()) => break,
        Err(mpsc::TryRecvError::Empty) if Instant::now() < start_deadline => {
          std::thread::yield_now();
        }
        result => panic!("close waker did not start: {result:?}"),
      }
    }
    assert_eq!(driver.try_shutdown().unwrap(), ShutdownProgress::Pending);

    release_tx
      .send(())
      .unwrap_or_else(|error| panic!("close waker release failed: {error}"));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      match driver.try_shutdown() {
        Ok(ShutdownProgress::Complete) => break,
        Ok(ShutdownProgress::Pending) if Instant::now() < deadline => {
          std::thread::yield_now();
        }
        result => panic!("unexpected shutdown progress: {result:?}"),
      }
    }
  }

  #[test]
  fn drain_keeps_timer_open_until_admitted_async_sleep_finishes() {
    let mut driver = MultiThreadBuilder::new(async_config())
      .timer(2)
      .build()
      .unwrap_or_else(|error| panic!("timer runtime build failed: {error}"));
    let timer = driver.timer().unwrap_or_else(|| panic!("timer is missing"));
    let job = driver
      .handle()
      .spawn(async move {
        timer
          .sleep(Duration::from_millis(10))
          .unwrap_or_else(|error| panic!("sleep creation failed: {error}"))
          .await
          .unwrap_or_else(|error| panic!("sleep failed during drain: {error}"));
        7
      })
      .unwrap_or_else(|error| panic!("async task admission failed: {error}"));

    driver
      .request_shutdown(MultiShutdown {
        tasks: AsyncShutdown::Drain,
        blocking: ShutdownMode::Drain,
        processes: ProcessShutdownMode::Wait,
      })
      .unwrap_or_else(|error| panic!("drain request failed: {error}"));
    assert_eq!(driver.try_shutdown().unwrap(), ShutdownProgress::Pending);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      match driver.try_shutdown() {
        Ok(ShutdownProgress::Complete) => break,
        Ok(ShutdownProgress::Pending) if Instant::now() < deadline => {
          std::thread::yield_now();
        }
        result => panic!("unexpected shutdown progress: {result:?}"),
      }
    }
    assert_eq!(
      driver
        .block_on(job)
        .unwrap_or_else(|error| panic!("join poll failed: {error}"))
        .unwrap_or_else(|error| panic!("drained task failed: {error}")),
      7
    );
  }

  #[test]
  fn blocking_drain_keeps_timer_open_for_nested_block_on() {
    let mut driver = MultiThreadBuilder::new(async_config())
      .timer(2)
      .blocking(BlockingConfig {
        workers: 1,
        max_outstanding: 2,
        capacity: Resources::ZERO,
      })
      .build()
      .unwrap_or_else(|error| panic!("runtime build failed: {error}"));
    let timer = driver.timer().unwrap_or_else(|| panic!("timer is missing"));
    let handle = driver.handle();
    let pool = driver
      .blocking()
      .unwrap_or_else(|| panic!("blocking pool is missing"));
    let (registered_tx, registered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let job = pool
      .try_spawn(Resources::ZERO, move |_token| {
        let mut sleep = Box::pin(
          timer
            .sleep(Duration::from_secs(30))
            .map_err(|_| "sleep creation failed")?,
        );
        let result = handle.block_on(async move {
          std::future::poll_fn(|cx| match sleep.as_mut().poll(cx) {
            std::task::Poll::Pending => {
              std::task::Poll::Ready(registered_tx.send(()).map_err(|_| "parent went away"))
            }
            std::task::Poll::Ready(Ok(())) => {
              std::task::Poll::Ready(Err("sleep elapsed before shutdown"))
            }
            std::task::Poll::Ready(Err(_)) => {
              std::task::Poll::Ready(Err("timer closed before shutdown"))
            }
          })
          .await?;
          release_rx
            .recv()
            .map_err(|_| "shutdown release channel closed")?;
          sleep
            .as_mut()
            .reset_after(Duration::from_millis(20))
            .map_err(|_| "timer closed during blocking drain")?;
          sleep
            .await
            .map_err(|_| "timer closed during blocking drain")
        });
        result.map_err(|_| "nested block_on failed")?
      })
      .unwrap_or_else(|error| panic!("blocking job admission failed: {error}"));
    registered_rx
      .recv_timeout(DRIVER_TEST_WATCHDOG)
      .unwrap_or_else(|error| panic!("nested timer sleep was not registered: {error}"));

    driver
      .request_shutdown(MultiShutdown {
        tasks: AsyncShutdown::CancelPending,
        blocking: ShutdownMode::Drain,
        processes: ProcessShutdownMode::Wait,
      })
      .unwrap_or_else(|error| panic!("shutdown request failed: {error}"));
    assert_eq!(driver.try_shutdown().unwrap(), ShutdownProgress::Pending);
    let async_deadline = Instant::now() + DRIVER_TEST_WATCHDOG;
    while !driver.asynchronous.shutdown_complete() {
      assert!(
        Instant::now() < async_deadline,
        "async driver did not drain"
      );
      assert_eq!(driver.try_shutdown().unwrap(), ShutdownProgress::Pending);
      std::thread::yield_now();
    }
    assert!(driver.asynchronous.shutdown_complete());
    assert!(!driver.timer().unwrap().is_closed());
    release_tx
      .send(())
      .unwrap_or_else(|error| panic!("blocking job release failed: {error}"));
    let deadline = Instant::now() + DRIVER_TEST_WATCHDOG;
    loop {
      match driver.try_shutdown() {
        Ok(ShutdownProgress::Complete) => break,
        Ok(ShutdownProgress::Pending) if Instant::now() < deadline => {
          std::thread::yield_now();
        }
        result => panic!("unexpected shutdown progress: {result:?}"),
      }
    }
    assert_eq!(job.join().unwrap().unwrap(), ());
  }

  #[test]
  fn drain_keeps_filesystem_pool_open_until_admitted_io_finishes() {
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-driver-drain-{}-{}",
      std::process::id(),
      NEXT_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, b"drain").unwrap_or_else(|error| panic!("fixture write failed: {error}"));
    let mut driver = MultiThreadBuilder::new(async_config())
      .resources(limits(16))
      .io_pool(BlockingConfig {
        workers: 1,
        max_outstanding: 4,
        capacity: Resources::ZERO,
      })
      .filesystem()
      .build()
      .unwrap_or_else(|error| panic!("filesystem runtime build failed: {error}"));
    let filesystem = driver
      .filesystem()
      .unwrap_or_else(|| panic!("filesystem service is missing"));
    let resources = driver.resources().clone();
    let task_path = path.clone();
    let job = driver
      .handle()
      .spawn(async move {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        let file = filesystem
          .open(task_path, options)
          .unwrap_or_else(|error| panic!("open submission failed: {error}"))
          .await
          .unwrap_or_else(|error| panic!("open job failed: {error}"))
          .unwrap_or_else(|error| panic!("open failed: {error}"));
        let outcome = filesystem
          .read(file, resources.try_alloc_zeroed(8).unwrap())
          .unwrap_or_else(|error| panic!("read submission failed: {error}"))
          .await
          .unwrap_or_else(|error| panic!("read job failed: {error}"));
        assert!(outcome.error.is_none());
        assert_eq!(&outcome.buffer[..outcome.bytes], b"drain");
        outcome.bytes
      })
      .unwrap_or_else(|error| panic!("async task admission failed: {error}"));

    driver
      .request_shutdown(MultiShutdown {
        tasks: AsyncShutdown::Drain,
        blocking: ShutdownMode::Drain,
        processes: ProcessShutdownMode::Wait,
      })
      .unwrap_or_else(|error| panic!("drain request failed: {error}"));
    assert_eq!(driver.try_shutdown().unwrap(), ShutdownProgress::Pending);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      match driver.try_shutdown() {
        Ok(ShutdownProgress::Complete) => break,
        Ok(ShutdownProgress::Pending) if Instant::now() < deadline => {
          std::thread::yield_now();
        }
        result => panic!("unexpected shutdown progress: {result:?}"),
      }
    }
    assert_eq!(
      driver
        .block_on(job)
        .unwrap_or_else(|error| panic!("join poll failed: {error}"))
        .unwrap_or_else(|error| panic!("drained task failed: {error}")),
      5
    );
    assert_eq!(driver.resources().snapshot().disk_ops, 0);
    std::fs::remove_file(path).unwrap_or_else(|error| panic!("fixture removal failed: {error}"));
  }

  #[test]
  fn shutdown_stays_pending_while_a_blocking_job_owns_its_capture() {
    let blocking = BlockingConfig {
      workers: 1,
      max_outstanding: 2,
      capacity: Resources::ZERO,
    };
    let mut driver = MultiThreadBuilder::new(async_config())
      .blocking(blocking)
      .build()
      .unwrap_or_else(|error| panic!("blocking runtime build failed: {error}"));
    let pool = driver
      .blocking()
      .unwrap_or_else(|| panic!("blocking pool is missing"));
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let job = pool
      .try_spawn(Resources::ZERO, move |_token| {
        let _ = started_tx.send(());
        let _ = release_rx.recv();
      })
      .unwrap_or_else(|error| panic!("blocking job admission failed: {error}"));
    started_rx
      .recv_timeout(Duration::from_secs(2))
      .unwrap_or_else(|error| panic!("blocking job did not start: {error}"));

    driver
      .request_shutdown(MultiShutdown::default())
      .unwrap_or_else(|error| panic!("shutdown request failed: {error}"));
    assert_eq!(driver.try_shutdown().unwrap(), ShutdownProgress::Pending);
    release_tx
      .send(())
      .unwrap_or_else(|error| panic!("blocking job release failed: {error}"));
    drop(job);

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      match driver.drive_shutdown_step() {
        Ok(ShutdownProgress::Complete) => break,
        Ok(ShutdownProgress::Pending) if Instant::now() < deadline => {
          std::thread::yield_now();
        }
        result => panic!("unexpected shutdown progress: {result:?}"),
      }
    }
  }

  #[test]
  fn shutdown_status_retains_worker_panic_payload_until_owner_drop() {
    let checker_budget = Duration::from_secs(3);
    let observer_budget = Duration::from_secs(4);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let payload = PanicDropGate {
      entered: entered_tx,
      release: Mutex::new(release_rx),
    };
    let mut payload = Some(payload);
    let blocking = super::super::blocking::Runtime::with_spawner(
      BlockingConfig {
        workers: 1,
        max_outstanding: 1,
        capacity: Resources::ZERO,
      },
      move |_builder, _worker| {
        let Some(payload) = payload.take() else {
          return Err(std::io::Error::other("unexpected second worker"));
        };
        std::thread::Builder::new().spawn(move || std::panic::panic_any(payload))
      },
      |_| {},
    )
    .unwrap_or_else(|error| panic!("blocking runtime build failed: {error}"));
    let resources = ResourceScope::new(limits(8));
    let asynchronous = AsyncRuntime::with_resources(async_config(), resources.clone())
      .unwrap_or_else(|error| panic!("async runtime build failed: {error}"));
    let mut driver = MultiThreadDriver {
      _control: ControlCharge::unbounded(std::mem::size_of::<MultiThreadDriver>()),
      asynchronous,
      resources,
      timer: Some(
        TimerDriver::new(1).unwrap_or_else(|error| panic!("timer driver build failed: {error}")),
      ),
      rate_timer: None,
      reactor: None,
      blocking: Some(blocking),
      io_pool: None,
      filesystem: None,
      process: None,
      signal: None,
      #[cfg(feature = "resource-feedback")]
      feedback: None,
      #[cfg(feature = "resource-feedback")]
      feedback_meters: None,
      #[cfg(feature = "resource-feedback")]
      feedback_status: FeedbackStatus::Disabled,
      disk_rate: None,
      upload_rate: None,
      download_rate: None,
      shutdown: None,
      shutdown_failure: None,
      blocking_shutdown_requested: false,
      io_pool_shutdown_requested: false,
      process_shutdown_requested: false,
      io_shutdown_requested: false,
    };
    driver
      .request_shutdown(MultiShutdown::default())
      .unwrap_or_else(|error| panic!("shutdown request failed: {error}"));

    let (status_tx, status_rx) = mpsc::sync_channel(1);
    let checker = std::thread::spawn(move || {
      let mut driver = driver;
      let deadline = Instant::now() + checker_budget;
      let status = loop {
        match driver.try_shutdown() {
          Err(error) => break Err(error),
          Ok(ShutdownProgress::Complete) => break Ok(()),
          Ok(ShutdownProgress::Pending) if Instant::now() < deadline => {
            std::thread::yield_now();
          }
          Ok(ShutdownProgress::Pending) => break Err(DriverShutdownError::NotRequested),
        }
      };
      let _ = status_tx.send((driver, status));
    });

    let (mut driver, status) = match status_rx.recv_timeout(observer_budget) {
      Ok(result) => result,
      Err(error) => {
        let _ = release_tx.send(());
        let (driver, observed_status) = status_rx
          .recv_timeout(Duration::from_secs(2))
          .unwrap_or_else(|second| {
            panic!(
              "shutdown status phase exceeded {observer_budget:?} and never returned after releasing the panic payload: {error}; {second}"
            )
          });
        let _ = checker.join();
        drop(driver);
        panic!(
          "shutdown status phase exceeded {observer_budget:?}; checker later returned {observed_status:?}"
        );
      }
    };
    assert!(matches!(
      status,
      Err(DriverShutdownError::Blocking(std::io::ErrorKind::Other))
    ));
    let timer = driver
      .timer
      .as_ref()
      .unwrap_or_else(|| panic!("timer driver is missing"))
      .handle();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      assert!(matches!(
        driver.try_shutdown(),
        Err(DriverShutdownError::Blocking(std::io::ErrorKind::Other))
      ));
      if matches!(timer.sleep_until(timer.now()), Err(TimerError::Closed)) {
        break;
      }
      assert!(
        Instant::now() < deadline,
        "shutdown status did not continue into timer cleanup"
      );
      std::thread::yield_now();
    }
    assert!(matches!(
      entered_rx.try_recv(),
      Err(mpsc::TryRecvError::Empty)
    ));
    release_tx
      .send(())
      .unwrap_or_else(|error| panic!("panic payload release failed: {error}"));
    drop(driver);
    entered_rx
      .recv_timeout(Duration::from_secs(2))
      .unwrap_or_else(|error| panic!("panic payload was not dropped with its owner: {error}"));
    checker
      .join()
      .unwrap_or_else(|_| panic!("shutdown status checker panicked"));
  }

  #[test]
  fn startup_failure_after_services_start_joins_the_partial_runtime() {
    let _permanent_signal =
      SignalDriver::new(1).unwrap_or_else(|error| panic!("signal setup failed: {error}"));
    let error = MultiThreadBuilder::new(async_config())
      .blocking(BlockingConfig {
        workers: 1,
        max_outstanding: 1,
        capacity: Resources::ZERO,
      })
      .timer(1)
      .reactor(ReactorConfig {
        max_registrations: 1,
        max_waiters: 1,
      })
      .processes(1)
      .signals(2)
      .build()
      .err()
      .unwrap_or_else(|| panic!("mismatched process signal ceiling unexpectedly built"));
    assert!(matches!(
      error,
      DriverBuildError::Signal(SignalError::ConfigurationMismatch)
    ));
  }

  #[test]
  fn invalid_service_combinations_are_rejected_before_build() {
    let error = CurrentThreadBuilder::new(local_config())
      .filesystem()
      .build()
      .err()
      .unwrap_or_else(|| panic!("filesystem without a pool unexpectedly built"));
    assert!(matches!(error, DriverBuildError::FilesystemNeedsIoPool));
    assert_eq!(
      error.to_string(),
      "filesystem services require a configured I/O pool"
    );
  }

  #[test]
  fn filesystem_with_only_a_blocking_pool_needs_an_io_pool() {
    let pool = BlockingConfig {
      workers: 1,
      max_outstanding: 1,
      capacity: Resources::ZERO,
    };
    let current = CurrentThreadBuilder::new(local_config())
      .blocking(pool)
      .filesystem()
      .build()
      .err()
      .unwrap_or_else(|| panic!("filesystem over a blocking pool unexpectedly built"));
    assert!(matches!(current, DriverBuildError::FilesystemNeedsIoPool));
    let multi = MultiThreadBuilder::new(async_config())
      .blocking(pool)
      .filesystem()
      .build()
      .err()
      .unwrap_or_else(|| panic!("filesystem over a blocking pool unexpectedly built"));
    assert!(matches!(multi, DriverBuildError::FilesystemNeedsIoPool));
    let empty = MultiThreadBuilder::new(async_config())
      .io_pool(BlockingConfig {
        workers: 0,
        max_outstanding: 1,
        capacity: Resources::ZERO,
      })
      .build()
      .err()
      .unwrap_or_else(|| panic!("a zero-worker I/O pool unexpectedly built"));
    assert!(matches!(empty, DriverBuildError::InvalidConfiguration(_)));
  }

  /// Drives a driver with a blocking pool and an I/O pool through shutdown
  /// and checks the documented order: the blocking pool drains first while
  /// the I/O pool stays open for the closures that use adapters, then the
  /// I/O pool closes in its own step, and child processes come after it.
  macro_rules! assert_pool_shutdown_order {
    ($driver:expr, $policy:expr) => {{
      let driver = &mut $driver;
      let path = std::env::temp_dir().join(format!(
        "allocatbelt-driver-pool-order-{}-{}",
        std::process::id(),
        NEXT_FILE.fetch_add(1, Ordering::Relaxed)
      ));
      std::fs::write(&path, b"order").unwrap();
      let filesystem = driver.filesystem().unwrap();
      let (blocking_started_tx, blocking_started_rx) = mpsc::channel::<()>();
      let (blocking_release_tx, blocking_release_rx) = mpsc::channel::<()>();
      let metadata_path = path.clone();
      let blocking_job = driver
        .blocking()
        .unwrap()
        .try_spawn(Resources::ZERO, move |_| {
          blocking_started_tx.send(()).unwrap();
          blocking_release_rx
            .recv_timeout(DRIVER_TEST_WATCHDOG)
            .unwrap();
          filesystem
            .metadata(metadata_path)
            .unwrap_or_else(|_| panic!("I/O pool closed before the blocking pool drained"))
            .join()
            .unwrap()
            .unwrap()
            .len()
        })
        .unwrap_or_else(|error| panic!("blocking admission failed: {}", error.kind));
      blocking_started_rx
        .recv_timeout(DRIVER_TEST_WATCHDOG)
        .unwrap();

      driver.request_shutdown($policy).unwrap();
      let deadline = Instant::now() + DRIVER_TEST_WATCHDOG;
      while !driver.blocking_shutdown_requested {
        assert_eq!(
          driver.drive_shutdown_step().unwrap(),
          ShutdownProgress::Pending
        );
        assert!(
          Instant::now() < deadline,
          "blocking pool step was not reached"
        );
        std::thread::yield_now();
      }
      assert!(driver.blocking.as_ref().unwrap().snapshot().closed);
      assert!(!driver.io_pool_shutdown_requested);
      assert!(!driver.io_pool.as_ref().unwrap().snapshot().closed);
      assert!(!driver.process_shutdown_requested);

      // Hold one I/O worker so the I/O pool step stays visible.
      let (io_release_tx, io_release_rx) = mpsc::channel::<()>();
      let io_job = driver
        .io_pool
        .as_ref()
        .unwrap()
        .try_spawn(Resources::ZERO, move |_| {
          let _ = io_release_rx.recv_timeout(DRIVER_TEST_WATCHDOG);
        })
        .unwrap_or_else(|error| panic!("I/O admission failed: {}", error.kind));
      blocking_release_tx.send(()).unwrap();
      assert_eq!(blocking_job.join().unwrap(), 5);
      while !driver.io_pool_shutdown_requested {
        assert_eq!(
          driver.drive_shutdown_step().unwrap(),
          ShutdownProgress::Pending
        );
        assert!(Instant::now() < deadline, "I/O pool step was not reached");
        std::thread::yield_now();
      }
      assert!(driver.blocking.as_ref().unwrap().shutdown_complete());
      assert!(driver.io_pool.as_ref().unwrap().snapshot().closed);
      assert_eq!(
        driver.drive_shutdown_step().unwrap(),
        ShutdownProgress::Pending
      );
      assert!(!driver.process_shutdown_requested);

      io_release_tx.send(()).unwrap();
      io_job.join().unwrap();
      while driver.drive_shutdown_step().unwrap() != ShutdownProgress::Complete {
        assert!(Instant::now() < deadline, "driver did not stop");
        std::thread::yield_now();
      }
      assert!(driver.io_pool.as_ref().unwrap().shutdown_complete());
      assert!(driver.process_shutdown_requested);
      std::fs::remove_file(path).unwrap();
    }};
  }

  fn order_pool(workers: usize) -> BlockingConfig {
    BlockingConfig {
      workers,
      max_outstanding: 4,
      capacity: Resources::ZERO,
    }
  }

  #[test]
  fn current_driver_shuts_down_blocking_then_io_pool_then_processes() {
    let mut driver = CurrentThreadBuilder::new(local_config())
      .resources(limits(16))
      .blocking(order_pool(1))
      .io_pool(order_pool(2))
      .filesystem()
      .processes(1)
      .build()
      .unwrap();
    assert_pool_shutdown_order!(
      driver,
      CurrentShutdown {
        blocking: ShutdownMode::Drain,
        processes: ProcessShutdownMode::Wait,
      }
    );
  }

  #[test]
  fn multi_driver_shuts_down_blocking_then_io_pool_then_processes() {
    let mut driver = MultiThreadBuilder::new(async_config())
      .resources(limits(16))
      .blocking(order_pool(1))
      .io_pool(order_pool(2))
      .filesystem()
      .processes(1)
      .build()
      .unwrap();
    assert_pool_shutdown_order!(
      driver,
      MultiShutdown {
        tasks: AsyncShutdown::Drain,
        blocking: ShutdownMode::Drain,
        processes: ProcessShutdownMode::Wait,
      }
    );
  }

  #[test]
  fn driver_blocking_cancel_pending_leaves_queued_filesystem_operations() {
    let mut driver = MultiThreadBuilder::new(async_config())
      .resources(limits(16))
      .blocking(order_pool(1))
      .io_pool(order_pool(1))
      .filesystem()
      .build()
      .unwrap();
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-driver-pool-cancel-{}-{}",
      std::process::id(),
      NEXT_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, b"kept").unwrap();
    let blocking = driver.blocking().unwrap();
    let (blocking_started_tx, blocking_started_rx) = mpsc::channel::<()>();
    let (blocking_release_tx, blocking_release_rx) = mpsc::channel::<()>();
    let blocking_gate = blocking
      .try_spawn(Resources::ZERO, move |_| {
        blocking_started_tx.send(()).unwrap();
        let _ = blocking_release_rx.recv_timeout(DRIVER_TEST_WATCHDOG);
      })
      .unwrap_or_else(|error| panic!("blocking admission failed: {}", error.kind));
    blocking_started_rx
      .recv_timeout(DRIVER_TEST_WATCHDOG)
      .unwrap();
    let queued_closure = blocking
      .try_spawn(Resources::ZERO, |_| ())
      .unwrap_or_else(|error| panic!("blocking admission failed: {}", error.kind));
    let (io_release_tx, io_release_rx) = mpsc::channel::<()>();
    let io_gate = driver
      .io_pool
      .as_ref()
      .unwrap()
      .try_spawn(Resources::ZERO, move |_| {
        let _ = io_release_rx.recv_timeout(DRIVER_TEST_WATCHDOG);
      })
      .unwrap_or_else(|error| panic!("I/O admission failed: {}", error.kind));
    let queued_metadata = driver
      .filesystem()
      .unwrap()
      .metadata(path.clone())
      .unwrap_or_else(|_| panic!("filesystem admission failed"));

    driver
      .request_shutdown(MultiShutdown {
        tasks: AsyncShutdown::CancelPending,
        blocking: ShutdownMode::CancelPending,
        processes: ProcessShutdownMode::Wait,
      })
      .unwrap();
    let deadline = Instant::now() + DRIVER_TEST_WATCHDOG;
    while !driver.blocking_shutdown_requested {
      assert_eq!(driver.try_shutdown().unwrap(), ShutdownProgress::Pending);
      assert!(
        Instant::now() < deadline,
        "blocking pool step was not reached"
      );
      std::thread::yield_now();
    }
    blocking_release_tx.send(()).unwrap();
    blocking_gate.join().unwrap();
    while !queued_closure.is_finished() {
      driver.drive_shutdown_step().unwrap();
      assert!(
        Instant::now() < deadline,
        "queued closure was not abandoned"
      );
      std::thread::yield_now();
    }
    assert!(matches!(
      queued_closure.join(),
      Err(crate::runtime::JoinError::Cancelled)
    ));
    // The blocking pool's cancel-pending shutdown left the adapter job queued.
    assert!(!queued_metadata.is_finished());
    io_release_tx.send(()).unwrap();
    io_gate.join().unwrap();
    assert_eq!(queued_metadata.join().unwrap().unwrap().len(), 4);
    while driver.drive_shutdown_step().unwrap() != ShutdownProgress::Complete {
      assert!(Instant::now() < deadline, "driver did not stop");
      std::thread::yield_now();
    }
    std::fs::remove_file(path).unwrap();
  }

  #[test]
  fn current_thread_paused_auto_advances_to_its_next_live_timer() {
    let mut driver = CurrentThreadBuilder::new(local_config())
      .clock(ClockMode::PausedAuto, 4)
      .build()
      .unwrap_or_else(|error| panic!("current-thread build failed: {error}"));
    let clock = driver.clock().unwrap_or_else(|| panic!("clock is missing"));
    let start = clock.now();
    let completed_at = driver
      .block_on(async {
        clock.sleep(Duration::from_secs(7)).unwrap().await.unwrap();
        clock.now()
      })
      .unwrap_or_else(|error| panic!("root block_on failed: {error}"));
    assert_eq!(completed_at, start + Duration::from_secs(7));
    assert_eq!(clock.mode(), ClockMode::PausedAuto);
  }

  #[test]
  fn current_thread_ready_local_work_runs_before_paused_auto_advance() {
    let mut driver = CurrentThreadBuilder::new(local_config())
      .clock(ClockMode::PausedAuto, 4)
      .build()
      .unwrap_or_else(|error| panic!("current-thread build failed: {error}"));
    let clock = driver.clock().unwrap_or_else(|| panic!("clock is missing"));
    let start = clock.now();
    let observed = std::sync::Arc::new(Mutex::new(None));
    let task_observed = std::sync::Arc::clone(&observed);
    let task_clock = clock.clone();
    driver
      .handle()
      .spawn_local(async move {
        *task_observed.lock().unwrap() = Some(task_clock.now());
      })
      .unwrap_or_else(|error| panic!("local task admission failed: {error}"));

    driver
      .block_on(async {
        clock.sleep(Duration::from_secs(11)).unwrap().await.unwrap();
      })
      .unwrap_or_else(|error| panic!("root block_on failed: {error}"));
    assert_eq!(*observed.lock().unwrap(), Some(start));
    assert_eq!(clock.now(), start + Duration::from_secs(11));
  }

  #[test]
  fn current_thread_paused_auto_imports_external_work_before_advancing() {
    let mut driver = CurrentThreadBuilder::new(local_config())
      .clock(ClockMode::PausedAuto, 4)
      .build()
      .unwrap_or_else(|error| panic!("current-thread build failed: {error}"));
    let clock = driver.clock().unwrap_or_else(|| panic!("clock is missing"));
    let start = clock.now();
    let observed = std::sync::Arc::new(Mutex::new(None));
    let task_observed = std::sync::Arc::clone(&observed);
    let task_clock = clock.clone();
    let job = driver
      .send_handle()
      .spawn(async move {
        *task_observed.lock().unwrap() = Some(task_clock.now());
      })
      .unwrap_or_else(|error| panic!("external task admission failed: {error}"));

    driver
      .block_on(async {
        clock.sleep(Duration::from_secs(13)).unwrap().await.unwrap();
      })
      .unwrap_or_else(|error| panic!("root block_on failed: {error}"));
    assert_eq!(*observed.lock().unwrap(), Some(start));
    assert_eq!(clock.now(), start + Duration::from_secs(13));
    drop(job);
  }

  #[test]
  fn paused_auto_is_rejected_by_the_multithread_builder() {
    let error = MultiThreadBuilder::new(async_config())
      .clock(ClockMode::PausedAuto, 2)
      .build()
      .err()
      .unwrap_or_else(|| panic!("multithread paused-auto clock unexpectedly built"));
    assert!(matches!(
      error,
      DriverBuildError::InvalidConfiguration(reason)
        if reason.contains("current-thread")
    ));
  }

  #[test]
  fn multithread_facade_applies_thread_options_and_exposes_metrics() {
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let options = AsyncThreadOptions::new()
      .thread_name_fn(|context| {
        let role = match context.role {
          super::super::asynchronous::AsyncThreadRole::Worker => "worker",
          super::super::asynchronous::AsyncThreadRole::HandoffHelper => "handoff",
        };
        format!("allocatbelt-test-{role}-{}", context.index)
      })
      .on_thread_start(move |context| {
        let _ = started_tx.send(context);
      });
    let driver = MultiThreadBuilder::new(async_config())
      .thread_options(options)
      .build()
      .unwrap_or_else(|error| panic!("multithread build failed: {error}"));
    let started = started_rx
      .recv_timeout(Duration::from_secs(2))
      .unwrap_or_else(|error| panic!("configured worker did not start: {error}"));
    assert_eq!(
      started.role,
      super::super::asynchronous::AsyncThreadRole::Worker
    );
    assert_eq!(started.index, 0);
    assert_eq!(started.physical_index, 0);

    let metrics = driver.metrics();
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.num_workers, 1);
    assert_eq!(snapshot.threads.len(), 1);
    assert_eq!(snapshot.threads[0].context, started);
    drop(driver);
    assert_eq!(metrics.snapshot().num_workers, 1);
  }

  #[test]
  fn facade_blocking_admission_inhibits_auto_advance_until_execution_finishes() {
    let driver = CurrentThreadBuilder::new(local_config())
      .clock(ClockMode::PausedAuto, 2)
      .blocking(BlockingConfig {
        workers: 1,
        max_outstanding: 2,
        capacity: Resources::ZERO,
      })
      .build()
      .unwrap_or_else(|error| panic!("current-thread build failed: {error}"));
    let clock = driver.clock().unwrap_or_else(|| panic!("clock is missing"));
    let start = clock.now();
    let mut sleep = clock.sleep(Duration::from_secs(3)).unwrap();
    let blocking = driver
      .blocking()
      .unwrap_or_else(|| panic!("blocking pool is missing"));
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let job = blocking
      .try_spawn(Resources::ZERO, move |_| {
        let _ = started_tx.send(());
        let _ = release_rx.recv();
      })
      .unwrap_or_else(|error| panic!("blocking job admission failed: {error}"));
    started_rx
      .recv_timeout(Duration::from_secs(2))
      .unwrap_or_else(|error| panic!("blocking job did not start: {error}"));

    let coordinator = clock.coordinator().clone();
    let epoch = coordinator.epoch().unwrap();
    let quiescent = coordinator
      .quiescent(epoch)
      .unwrap_or_else(|| panic!("clock idle epoch changed unexpectedly"));
    assert!(matches!(
      clock.auto_advance_if_idle(quiescent, false),
      super::super::time::AutoAdvance::Inhibited
    ));
    assert_eq!(clock.now(), start);

    release_tx
      .send(())
      .unwrap_or_else(|error| panic!("blocking job release failed: {error}"));
    job
      .join()
      .unwrap_or_else(|error| panic!("blocking job failed: {error}"));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      let epoch = coordinator.epoch().unwrap();
      let Some(quiescent) = coordinator.quiescent(epoch) else {
        std::thread::yield_now();
        continue;
      };
      match clock.auto_advance_if_idle(quiescent, false) {
        super::super::time::AutoAdvance::Advanced => break,
        super::super::time::AutoAdvance::Inhibited => {
          assert!(
            Instant::now() < deadline,
            "blocking inhibitor was not released"
          );
          std::thread::yield_now();
        }
        state => panic!("unexpected auto-advance state after job completion: {state:?}"),
      }
    }
    assert_eq!(clock.now(), start + Duration::from_secs(3));
    assert!(
      Pin::new(&mut sleep)
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
    );
  }

  #[test]
  fn facade_io_pool_admission_inhibits_auto_advance_until_execution_finishes() {
    let driver = CurrentThreadBuilder::new(local_config())
      .clock(ClockMode::PausedAuto, 2)
      .io_pool(BlockingConfig {
        workers: 1,
        max_outstanding: 2,
        capacity: Resources::ZERO,
      })
      .build()
      .unwrap_or_else(|error| panic!("current-thread build failed: {error}"));
    let clock = driver.clock().unwrap_or_else(|| panic!("clock is missing"));
    let start = clock.now();
    let mut sleep = clock.sleep(Duration::from_secs(3)).unwrap();
    let io_pool = driver
      .io_pool
      .as_ref()
      .unwrap_or_else(|| panic!("I/O pool is missing"));
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let job = io_pool
      .try_spawn(Resources::ZERO, move |_| {
        let _ = started_tx.send(());
        let _ = release_rx.recv();
      })
      .unwrap_or_else(|error| panic!("blocking job admission failed: {error}"));
    started_rx
      .recv_timeout(Duration::from_secs(2))
      .unwrap_or_else(|error| panic!("blocking job did not start: {error}"));

    let coordinator = clock.coordinator().clone();
    let epoch = coordinator.epoch().unwrap();
    let quiescent = coordinator
      .quiescent(epoch)
      .unwrap_or_else(|| panic!("clock idle epoch changed unexpectedly"));
    assert!(matches!(
      clock.auto_advance_if_idle(quiescent, false),
      super::super::time::AutoAdvance::Inhibited
    ));
    assert_eq!(clock.now(), start);

    release_tx
      .send(())
      .unwrap_or_else(|error| panic!("blocking job release failed: {error}"));
    job
      .join()
      .unwrap_or_else(|error| panic!("blocking job failed: {error}"));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      let epoch = coordinator.epoch().unwrap();
      let Some(quiescent) = coordinator.quiescent(epoch) else {
        std::thread::yield_now();
        continue;
      };
      match clock.auto_advance_if_idle(quiescent, false) {
        super::super::time::AutoAdvance::Advanced => break,
        super::super::time::AutoAdvance::Inhibited => {
          assert!(
            Instant::now() < deadline,
            "I/O pool inhibitor was not released"
          );
          std::thread::yield_now();
        }
        state => panic!("unexpected auto-advance state after job completion: {state:?}"),
      }
    }
    assert_eq!(clock.now(), start + Duration::from_secs(3));
    assert!(
      Pin::new(&mut sleep)
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_ready()
    );
  }

  #[test]
  fn startup_failure_after_an_io_pool_started_joins_it() {
    let _permanent_signal =
      SignalDriver::new(1).unwrap_or_else(|error| panic!("signal setup failed: {error}"));
    let error = MultiThreadBuilder::new(async_config())
      .io_pool(BlockingConfig {
        workers: 2,
        max_outstanding: 1,
        capacity: Resources::ZERO,
      })
      .filesystem()
      .timer(1)
      .signals(2)
      .build()
      .err()
      .unwrap_or_else(|| panic!("mismatched process signal ceiling unexpectedly built"));
    // The I/O pool started before the signal step failed; the rollback drains
    // and joins it before `build` returns.
    assert!(matches!(
      error,
      DriverBuildError::Signal(SignalError::ConfigurationMismatch)
    ));
  }

  #[cfg(not(loom))]
  #[test]
  fn rate_io_waits_on_its_real_timer_and_returns_unconfigured_endpoints() {
    let mut driver = CurrentThreadBuilder::new(local_config())
      .clock(ClockMode::PausedManual, 4)
      .download_rate(ByteRateConfig {
        bytes_per_second: 100,
        burst_bytes: 1,
        max_reservations: 4,
      })
      .upload_rate(ByteRateConfig {
        bytes_per_second: 100,
        burst_bytes: 1,
        max_reservations: 4,
      })
      .build()
      .unwrap_or_else(|error| panic!("current-thread build failed: {error}"));
    #[cfg(feature = "resource-feedback")]
    assert!(driver.feedback_metrics().is_none());

    let application_clock = driver.clock().unwrap();
    assert_eq!(application_clock.mode(), ClockMode::PausedManual);
    let application_time = application_clock.now();
    let mut stream = driver
      .rate_io(DriverTestIo::new(20))
      .unwrap_or_else(|error| panic!("network rate adapter failed: {error}"));
    let started_at = Instant::now();
    driver
      .block_on(async {
        let mut first = [0];
        assert_eq!(stream.read(&mut first).await?, 1);
        let mut second = [0];
        assert_eq!(stream.read(&mut second).await?, 1);
        Ok::<(), io::Error>(())
      })
      .unwrap_or_else(|error| panic!("paused-clock rate wait failed: {error}"))
      .unwrap_or_else(|error| panic!("rate-limited read failed: {error}"));
    assert!(started_at.elapsed() >= Duration::from_millis(5));
    assert_eq!(application_clock.now(), application_time);
    drop(stream);

    let mut unconfigured = CurrentThreadBuilder::new(local_config())
      .build()
      .unwrap_or_else(|error| panic!("default driver build failed: {error}"));
    let error = match unconfigured.rate_io(DriverTestIo::new(31)) {
      Ok(_) => panic!("unconfigured network rates unexpectedly built"),
      Err(error) => error,
    };
    assert_eq!(
      error.failure(),
      DriverRateIoFailure::MissingUploadAndDownloadRates
    );
    assert_eq!(error.into_inner().marker, 31);
    let error = match unconfigured.disk_io(DriverTestIo::new(32)) {
      Ok(_) => panic!("unconfigured disk rate unexpectedly built"),
      Err(error) => error,
    };
    assert_eq!(error.failure(), DriverRateIoFailure::MissingDiskRate);
    assert_eq!(error.into_inner().marker, 32);

    shutdown_current_driver(&mut driver);
    shutdown_current_driver(&mut unconfigured);
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn cloned_builder_creates_fresh_contexts_and_directional_feedback_meters() {
    let (_domain, tenant) = feedback_domain();
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&contexts);
    let factory = feedback_sources(feedback_policy(), move |context| {
      assert!(context.resources.tenant_domain().is_some());
      assert!(context.runtime_metrics.is_none());
      assert_eq!(context.disk_meter.snapshot().attached_sources, 0);
      assert_eq!(context.upload_meter.snapshot().attached_sources, 0);
      assert_eq!(context.download_meter.snapshot().attached_sources, 0);
      let tenant = context
        .resources
        .tenant_domain()
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tenant missing"))?;
      let disk = context
        .disk_rate
        .clone()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "disk rate missing"))?;
      let network = context
        .download_rate
        .clone()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "download rate missing"))?;
      observed.lock().unwrap().push((
        context.disk_meter.clone(),
        context.upload_meter.clone(),
        context.download_meter.clone(),
      ));
      Ok((
        MissingFeedbackSensor,
        RuntimeFeedbackActuator::new(CpuFeedbackTarget::Tenant(tenant), disk, network),
      ))
    });
    let builder = CurrentThreadBuilder::new(local_config())
      .resources(limits(64))
      .resource_domain(tenant)
      .disk_rate(feedback_rate_config())
      .upload_rate(feedback_rate_config())
      .download_rate(feedback_rate_config())
      .feedback_sources(factory);
    assert!(format!("{builder:?}").contains("CurrentThreadBuilder"));
    let mut first = builder
      .clone()
      .build()
      .unwrap_or_else(|error| panic!("first cloned build failed: {error}"));
    let mut second = builder
      .build()
      .unwrap_or_else(|error| panic!("second cloned build failed: {error}"));
    assert_eq!(contexts.lock().unwrap().len(), 2);
    assert!(first.feedback_metrics().is_some());
    assert!(second.feedback_metrics().is_some());

    let first_network = first
      .rate_io(DriverTestIo::new(1))
      .unwrap_or_else(|error| panic!("first network adapter failed: {error}"));
    let first_disk = first
      .disk_io(DriverTestIo::new(2))
      .unwrap_or_else(|error| panic!("first disk adapter failed: {error}"));
    let second_network = second
      .rate_io(DriverTestIo::new(3))
      .unwrap_or_else(|error| panic!("second network adapter failed: {error}"));
    let second_disk = second
      .disk_io(DriverTestIo::new(4))
      .unwrap_or_else(|error| panic!("second disk adapter failed: {error}"));
    let contexts = contexts.lock().unwrap();
    assert_eq!(contexts[0].0.snapshot().attached_sources, 2);
    assert_eq!(contexts[0].1.snapshot().attached_sources, 1);
    assert_eq!(contexts[0].2.snapshot().attached_sources, 1);
    assert_eq!(contexts[1].0.snapshot().attached_sources, 2);
    assert_eq!(contexts[1].1.snapshot().attached_sources, 1);
    assert_eq!(contexts[1].2.snapshot().attached_sources, 1);
    drop(contexts);

    drop(first_network);
    drop(first_disk);
    drop(second_network);
    drop(second_disk);
    shutdown_current_driver(&mut first);
    shutdown_current_driver(&mut second);
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn default_feedback_factory_builds_a_driver_on_the_global_cpu_limit() {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 4)
      .with(DomainResource::Tasks, 64)
      .with(DomainResource::Memory, 1 << 20)
      .with(DomainResource::Disk, 8)
      .with(DomainResource::Network, 8)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 2, 32).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let capacity = std::num::NonZeroU32::new(4).unwrap();
    let mut driver = MultiThreadBuilder::new(async_config())
      .resources(limits(64))
      .resource_domain(tenant.clone())
      .feedback_sources(default_feedback_for_capacity(capacity))
      .build()
      .unwrap_or_else(|error| panic!("default feedback driver build failed: {error}"));
    assert_eq!(driver.feedback_status(), FeedbackStatus::Running);
    let metrics = driver
      .feedback_metrics()
      .unwrap_or_else(|| panic!("default feedback service was not retained"));
    let snapshot = metrics.snapshot();
    assert_eq!(
      snapshot
        .control(FeedbackResource::CpuConcurrency)
        .current_limit,
      4
    );
    // No byte bucket was configured and none is needed by the default path.
    assert!(driver.disk_rate().is_none());
    assert!(driver.download_rate().is_none());
    assert_eq!(domain.snapshot().limit.get(DomainResource::Cpu), 4);
    assert_eq!(tenant.snapshot().unwrap().limit.get(DomainResource::Cpu), 4);
    shutdown_multi_driver(&mut driver);
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn default_feedback_factory_needs_a_resource_domain() {
    let result = CurrentThreadBuilder::new(local_config())
      .feedback_sources(default_feedback())
      .build();
    assert!(matches!(
      result,
      Err(DriverBuildError::Feedback(
        FeedbackFactoryError::DefaultRequiresResourceDomain
      ))
    ));
  }

  /// A domain whose CPU ceiling is below ten: the default policy can neither
  /// lower that limit (its step is a tenth) nor raise it past the ceiling, so
  /// these tests observe a limit that cannot move.
  #[cfg(feature = "resource-feedback")]
  fn default_selection_domain(cpu: usize, tenants: usize) -> (ResourceDomain, DomainResources) {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, cpu)
      .with(DomainResource::Tasks, 64)
      .with(DomainResource::Memory, 1 << 20)
      .with(DomainResource::Disk, 8)
      .with(DomainResource::Network, 8)
      .with(DomainResource::Control, 1 << 20);
    (
      ResourceDomain::with_waiters(ceiling, tenants, 32).unwrap(),
      ceiling,
    )
  }

  #[cfg(feature = "resource-feedback")]
  fn assert_default_service_on_cpu(metrics: &FeedbackMetricsHandle, cpu: u64) {
    use crate::runtime::resource_feedback_policy::UNSELECTED_BYTE_RATE;
    let snapshot = metrics.snapshot();
    assert_eq!(
      snapshot
        .control(FeedbackResource::CpuConcurrency)
        .current_limit,
      cpu
    );
    for resource in [FeedbackResource::DiskRate, FeedbackResource::NetworkRate] {
      assert_eq!(
        snapshot.control(resource).current_limit,
        UNSELECTED_BYTE_RATE
      );
    }
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn default_selection_starts_on_the_global_cpu_limit_for_both_builders() {
    let (domain, ceiling) = default_selection_domain(6, 2);
    let tenant = domain.tenant(ceiling).unwrap();
    let mut current = CurrentThreadBuilder::new(local_config())
      .resources(limits(64))
      .resource_domain(tenant.clone())
      .disk_rate(feedback_rate_config())
      .build()
      .unwrap_or_else(|error| panic!("default-feedback current-thread build failed: {error}"));
    assert_eq!(current.feedback_status(), FeedbackStatus::Running);
    assert_default_service_on_cpu(&current.feedback_metrics().unwrap(), 6);
    // The default service reads no byte meter: none is allocated, so the
    // disk adapter and filesystem paths take no meter timestamps.
    assert!(current.feedback_meters.is_none());
    // The facade releases its share of the service's inline payload once the
    // service charged it, exactly as for an explicitly selected factory.
    assert_eq!(
      current._control.bytes(),
      std::mem::size_of::<CurrentThreadDriver>()
        - std::mem::size_of::<LocalRuntime>()
        - ResourceFeedbackService::owner_payload_bytes()
        - TimerDriver::owner_payload_bytes()
    );
    assert!(domain.try_register_default_feedback().is_none());
    assert_eq!(domain.snapshot().limit.get(DomainResource::Cpu), 6);
    assert_eq!(tenant.snapshot().unwrap().limit.get(DomainResource::Cpu), 6);
    shutdown_current_driver(&mut current);
    drop(current);

    // The stopped service released the domain's registration.
    let mut multi = MultiThreadBuilder::new(async_config())
      .resources(limits(64))
      .resource_domain(tenant)
      .build()
      .unwrap_or_else(|error| panic!("default-feedback multithread build failed: {error}"));
    assert_eq!(multi.feedback_status(), FeedbackStatus::Running);
    assert_default_service_on_cpu(&multi.feedback_metrics().unwrap(), 6);
    assert!(multi.feedback_meters.is_none());
    assert_eq!(
      multi._control.bytes(),
      std::mem::size_of::<MultiThreadDriver>()
        - std::mem::size_of::<AsyncRuntime>()
        - ResourceFeedbackService::owner_payload_bytes()
    );
    assert_eq!(domain.snapshot().limit.get(DomainResource::Cpu), 6);
    shutdown_multi_driver(&mut multi);
    drop(multi);
    assert!(domain.try_register_default_feedback().is_some());
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn default_selection_without_a_domain_or_cpu_is_not_applicable() {
    let mut unbound = CurrentThreadBuilder::new(local_config())
      .build()
      .unwrap_or_else(|error| panic!("unbound build failed: {error}"));
    assert_eq!(
      unbound.feedback_status(),
      FeedbackStatus::NotApplicable(FeedbackNotApplicable::NoResourceDomain)
    );
    assert!(unbound.feedback_metrics().is_none());
    assert!(unbound.feedback_meters.is_none());
    shutdown_current_driver(&mut unbound);
    let mut unbound = MultiThreadBuilder::new(async_config())
      .build()
      .unwrap_or_else(|error| panic!("unbound build failed: {error}"));
    assert_eq!(
      unbound.feedback_status(),
      FeedbackStatus::NotApplicable(FeedbackNotApplicable::NoResourceDomain)
    );
    assert!(unbound.feedback_metrics().is_none());
    shutdown_multi_driver(&mut unbound);

    // A bound runtime takes a domain CPU unit for each poll, so a domain
    // without a CPU ceiling cannot build one; no status covers that case.
    let (no_cpu, ceiling) = default_selection_domain(0, 2);
    assert!(
      CurrentThreadBuilder::new(local_config())
        .resource_domain(no_cpu.tenant(ceiling).unwrap())
        .build()
        .is_err()
    );
    assert!(
      MultiThreadBuilder::new(async_config())
        .resource_domain(no_cpu.tenant(ceiling).unwrap())
        .build()
        .is_err()
    );

    // A zero soft limit below a nonzero ceiling builds; the default service
    // would start at a limit its policy floor rejects.
    let (lowered, ceiling) = default_selection_domain(4, 1);
    lowered
      .set_limits(ceiling.with(DomainResource::Cpu, 0))
      .unwrap();
    let mut driver = MultiThreadBuilder::new(async_config())
      .resource_domain(lowered.tenant(ceiling).unwrap())
      .build()
      .unwrap_or_else(|error| panic!("zero-limit build failed: {error}"));
    assert_eq!(
      driver.feedback_status(),
      FeedbackStatus::NotApplicable(FeedbackNotApplicable::NoCpuLimit)
    );
    assert!(driver.feedback_metrics().is_none());
    assert_eq!(
      driver._control.bytes(),
      std::mem::size_of::<MultiThreadDriver>() - std::mem::size_of::<AsyncRuntime>()
    );
    assert!(lowered.try_register_default_feedback().is_some());
    shutdown_multi_driver(&mut driver);
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn default_selection_that_cannot_start_builds_the_driver_without_feedback() {
    let (domain, ceiling) = default_selection_domain(4, 2);
    let tenant = domain.tenant(ceiling).unwrap();
    feedback::fail_next_default_sensor_for_test();
    let mut driver = CurrentThreadBuilder::new(local_config())
      .resources(limits(64))
      .resource_domain(tenant.clone())
      .build()
      .unwrap_or_else(|error| panic!("sensor-failure build failed: {error}"));
    assert_eq!(
      driver.feedback_status(),
      FeedbackStatus::NotStarted(FeedbackNotStarted::Sensor(io::ErrorKind::PermissionDenied))
    );
    assert!(driver.feedback_metrics().is_none());
    assert_eq!(
      driver._control.bytes(),
      std::mem::size_of::<CurrentThreadDriver>() - std::mem::size_of::<LocalRuntime>()
    );
    // The failed start released the registration it had taken.
    assert!(domain.try_register_default_feedback().is_some());
    let used = tenant.snapshot().unwrap().used.get(DomainResource::Control);

    // A second identical driver fits the tenant's Control limit exactly, so
    // the default service's own charge is refused and nothing is retained.
    tenant
      .set_limits(ceiling.with(DomainResource::Control, 2 * used))
      .unwrap();
    let mut constrained = CurrentThreadBuilder::new(local_config())
      .resources(limits(64))
      .resource_domain(tenant.clone())
      .build()
      .unwrap_or_else(|error| panic!("Control-constrained build failed: {error}"));
    assert_eq!(
      constrained.feedback_status(),
      FeedbackStatus::NotStarted(FeedbackNotStarted::Domain(DomainError::Exhausted(
        DomainResource::Control
      )))
    );
    assert!(constrained.feedback_metrics().is_none());
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      2 * used
    );
    assert!(domain.try_register_default_feedback().is_some());
    // The driver works once its tenant has room for a root call's charge.
    tenant.set_limits(ceiling).unwrap();
    assert_eq!(constrained.block_on(async { 7 }).unwrap(), 7);
    shutdown_current_driver(&mut constrained);
    shutdown_current_driver(&mut driver);
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn without_feedback_starts_nothing_and_explicit_factories_still_fail_the_build() {
    let (domain, ceiling) = default_selection_domain(4, 2);
    let tenant = domain.tenant(ceiling).unwrap();
    let mut driver = MultiThreadBuilder::new(async_config())
      .resource_domain(tenant.clone())
      .without_feedback()
      .build()
      .unwrap_or_else(|error| panic!("feedback-off build failed: {error}"));
    assert_eq!(driver.feedback_status(), FeedbackStatus::Disabled);
    assert!(driver.feedback_metrics().is_none());
    assert!(driver.feedback_meters.is_none());
    assert_eq!(
      driver._control.bytes(),
      std::mem::size_of::<MultiThreadDriver>() - std::mem::size_of::<AsyncRuntime>()
    );
    assert!(domain.try_register_default_feedback().is_some());
    shutdown_multi_driver(&mut driver);

    // The last selection wins, and an explicit factory's errors still fail
    // the build rather than falling back to the default service.
    let failing = feedback_sources(feedback_policy(), |_| {
      Err::<(MissingFeedbackSensor, TestFeedbackActuator), io::Error>(io::Error::other(
        "intentional source failure",
      ))
    });
    let error = CurrentThreadBuilder::new(local_config())
      .resource_domain(tenant.clone())
      .without_feedback()
      .feedback_sources(failing.clone())
      .build()
      .err()
      .unwrap_or_else(|| panic!("failing explicit factory unexpectedly built"));
    assert!(matches!(
      error,
      DriverBuildError::Feedback(FeedbackFactoryError::Sources(_))
    ));
    assert!(domain.try_register_default_feedback().is_some());
    let mut off = CurrentThreadBuilder::new(local_config())
      .resource_domain(tenant)
      .feedback_sources(failing)
      .without_feedback()
      .build()
      .unwrap_or_else(|error| panic!("feedback-off build failed: {error}"));
    assert_eq!(off.feedback_status(), FeedbackStatus::Disabled);
    shutdown_current_driver(&mut off);
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn a_build_failing_after_the_default_service_started_releases_it() {
    // The process-wide signal bridge is fixed at one listener (as in
    // `startup_failure_after_services_start_joins_the_partial_runtime`), so
    // asking for two fails at the last startup step, after feedback started.
    let _permanent_signal =
      SignalDriver::new(1).unwrap_or_else(|error| panic!("signal setup failed: {error}"));
    let (domain, ceiling) = default_selection_domain(4, 2);
    let error = CurrentThreadBuilder::new(local_config())
      .resource_domain(domain.tenant(ceiling).unwrap())
      .signals(2)
      .build()
      .err()
      .unwrap_or_else(|| panic!("mismatched process signal ceiling unexpectedly built"));
    assert!(matches!(
      error,
      DriverBuildError::Signal(SignalError::ConfigurationMismatch)
    ));
    // Startup rollback stopped the default service, which released the
    // domain's registration and left the CPU limit as it was.
    assert!(domain.try_register_default_feedback().is_some());
    assert_eq!(domain.snapshot().limit.get(DomainResource::Cpu), 4);
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn driver_forwards_feedback_reconciliation_after_external_drift() {
    use crate::runtime::resource_feedback_actuator::GlobalCpuFeedbackActuator;
    let (domain, ceiling) = default_selection_domain(20, 2);
    let global = domain.clone();
    // Busy readings make the service plan reductions, so its pre-write drift
    // check runs; fixed byte controls cannot change.
    let policy = ResourceFeedbackPolicyConfig {
      cpu_concurrency: FeedbackControlConfig::new(1, 20, 20, 4000, 8000),
      disk_rate: FeedbackControlConfig::new(5, 5, 5, 4000, 8000),
      network_rate: FeedbackControlConfig::new(6, 6, 6, 4000, 8000),
    };
    let mut driver = CurrentThreadBuilder::new(local_config())
      .resource_domain(domain.tenant(ceiling).unwrap())
      .feedback_sources(feedback_sources(policy, move |_| {
        Ok((
          BusyFeedbackSensor,
          GlobalCpuFeedbackActuator::new(global.clone(), 5, 6),
        ))
      }))
      .build()
      .unwrap_or_else(|error| panic!("feedback build failed: {error}"));
    let metrics = driver.feedback_metrics().unwrap();
    assert_eq!(
      driver.request_feedback_reconcile(FeedbackResource::CpuConcurrency),
      Some(Err(ReconcileRequestError::NotFaulted))
    );
    // Another writer changes the limit under the running service.
    domain
      .set_limits(ceiling.with(DomainResource::Cpu, 15))
      .unwrap();
    let faulted = || {
      metrics
        .snapshot()
        .control(FeedbackResource::CpuConcurrency)
        .policy_faulted
    };
    let deadline = Instant::now() + DRIVER_TEST_WATCHDOG;
    while !faulted() {
      assert!(Instant::now() < deadline, "external drift was not latched");
      std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(domain.snapshot().limit.get(DomainResource::Cpu), 15);
    assert_eq!(driver.feedback_status(), FeedbackStatus::Running);
    assert_eq!(
      driver.request_feedback_reconcile(FeedbackResource::CpuConcurrency),
      Some(Ok(()))
    );
    while faulted() {
      assert!(Instant::now() < deadline, "reconciliation did not complete");
      std::thread::sleep(Duration::from_millis(10));
    }
    assert!(domain.snapshot().limit.get(DomainResource::Cpu) <= 15);
    shutdown_current_driver(&mut driver);

    let mut off = CurrentThreadBuilder::new(local_config())
      .resource_domain(domain.tenant(ceiling).unwrap())
      .without_feedback()
      .build()
      .unwrap_or_else(|error| panic!("feedback-off build failed: {error}"));
    assert_eq!(
      off.request_feedback_reconcile(FeedbackResource::CpuConcurrency),
      None
    );
    shutdown_current_driver(&mut off);
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn a_domain_has_one_default_controller_until_its_service_stops() {
    let (domain, ceiling) = default_selection_domain(4, 4);
    let builder = CurrentThreadBuilder::new(local_config())
      .resources(limits(64))
      .resource_domain(domain.tenant(ceiling).unwrap());
    let mut first = builder
      .clone()
      .build()
      .unwrap_or_else(|error| panic!("first default build failed: {error}"));
    assert_eq!(first.feedback_status(), FeedbackStatus::Running);

    // A cloned builder on the same tenant, and a driver of another tenant of
    // the same domain, both find the domain controlled.
    let mut cloned = builder
      .build()
      .unwrap_or_else(|error| panic!("cloned default build failed: {error}"));
    assert_eq!(
      cloned.feedback_status(),
      FeedbackStatus::NotStarted(FeedbackNotStarted::DomainAlreadyControlled)
    );
    assert!(cloned.feedback_metrics().is_none());
    let mut other = MultiThreadBuilder::new(async_config())
      .resource_domain(domain.tenant(ceiling).unwrap())
      .build()
      .unwrap_or_else(|error| panic!("second-tenant default build failed: {error}"));
    assert_eq!(
      other.feedback_status(),
      FeedbackStatus::NotStarted(FeedbackNotStarted::DomainAlreadyControlled)
    );
    let explicit = MultiThreadBuilder::new(async_config())
      .resource_domain(domain.tenant(ceiling).unwrap())
      .feedback_sources(default_feedback_for_capacity(
        std::num::NonZeroU32::new(4).unwrap(),
      ))
      .build();
    assert!(matches!(
      explicit,
      Err(DriverBuildError::Feedback(
        FeedbackFactoryError::DefaultDomainAlreadyControlled
      ))
    ));
    // Caller-built factories with their own actuators are not restricted.
    let mut caller_built = CurrentThreadBuilder::new(local_config())
      .resource_domain(domain.tenant(ceiling).unwrap())
      .feedback_sources(feedback_sources(feedback_policy(), |_| {
        Ok((
          MissingFeedbackSensor,
          TestFeedbackActuator {
            limits: [16, 1000, 1000],
          },
        ))
      }))
      .build()
      .unwrap_or_else(|error| panic!("caller-built factory build failed: {error}"));
    assert_eq!(caller_built.feedback_status(), FeedbackStatus::Running);
    shutdown_current_driver(&mut caller_built);
    drop(caller_built);

    shutdown_current_driver(&mut first);
    drop(first);
    let mut next = CurrentThreadBuilder::new(local_config())
      .resource_domain(domain.tenant(ceiling).unwrap())
      .build()
      .unwrap_or_else(|error| panic!("follow-up default build failed: {error}"));
    assert_eq!(next.feedback_status(), FeedbackStatus::Running);
    assert_default_service_on_cpu(&next.feedback_metrics().unwrap(), 4);
    shutdown_current_driver(&mut next);
    shutdown_current_driver(&mut cloned);
    shutdown_multi_driver(&mut other);
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn feedback_factory_actuates_the_bound_domain_and_selected_byte_buckets() {
    let (_domain, tenant) = feedback_domain();
    let contexts_seen = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&contexts_seen);
    let factory = feedback_sources(feedback_policy(), move |context| {
      assert!(context.runtime_metrics.is_some());
      observed.fetch_add(1, Ordering::SeqCst);
      let tenant = context
        .resources
        .tenant_domain()
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "tenant missing"))?;
      let disk = context
        .disk_rate
        .clone()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "disk rate missing"))?;
      let network = context
        .download_rate
        .clone()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "download rate missing"))?;
      Ok((
        BusyFeedbackSensor,
        RuntimeFeedbackActuator::new(CpuFeedbackTarget::Tenant(tenant), disk, network),
      ))
    });
    let mut driver = MultiThreadBuilder::new(async_config())
      .resources(limits(64))
      .resource_domain(tenant.clone())
      .disk_rate(feedback_rate_config())
      .upload_rate(feedback_rate_config())
      .download_rate(feedback_rate_config())
      .feedback_sources(factory)
      .build()
      .unwrap_or_else(|error| panic!("feedback driver build failed: {error}"));
    assert_eq!(contexts_seen.load(Ordering::SeqCst), 1);

    let mut network = driver
      .rate_io(DriverTestIo::new(9))
      .unwrap_or_else(|error| panic!("network rate adapter failed: {error}"));
    let meter = driver
      .feedback_meters
      .as_ref()
      .map(|meters| meters.download.clone())
      .unwrap_or_else(|| panic!("feedback download meter was not retained"));
    driver
      .block_on(async {
        let mut byte = [0];
        assert_eq!(network.read(&mut byte).await?, 1);
        assert_eq!(network.write(&byte).await?, 1);
        Ok::<(), io::Error>(())
      })
      .unwrap_or_else(|error| panic!("network progress failed: {error}"))
      .unwrap_or_else(|error| panic!("network I/O failed: {error}"));
    assert_eq!(meter.snapshot().committed_bytes, 1);

    let deadline = Instant::now() + DRIVER_TEST_WATCHDOG;
    loop {
      let cpu_limit = tenant.snapshot().unwrap().limit.get(DomainResource::Cpu);
      let disk_limit = driver.disk_rate().unwrap().snapshot().bytes_per_second;
      let network_limit = driver.download_rate().unwrap().snapshot().bytes_per_second;
      if cpu_limit < 16 && disk_limit < 1000 && network_limit < 1000 {
        let metrics = driver.feedback_metrics().unwrap().snapshot();
        // Actuation and its subsequent readback acknowledgement are separate
        // operations. Require both rather than racing the metrics publication.
        if metrics
          .control(FeedbackResource::CpuConcurrency)
          .current_limit
          == cpu_limit as u64
          && metrics.control(FeedbackResource::DiskRate).current_limit == disk_limit
          && metrics.control(FeedbackResource::NetworkRate).current_limit == network_limit
        {
          break;
        }
      }
      assert!(
        Instant::now() < deadline,
        "feedback did not actuate all controls"
      );
      std::thread::yield_now();
    }
    drop(network);
    shutdown_multi_driver(&mut driver);
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn current_thread_feedback_shutdown_precedes_supporting_services() {
    let gate = Arc::new(SampleGate::default());
    let _release_on_exit = ReleaseSampleGate(Arc::clone(&gate));
    let sensor_gate = Arc::clone(&gate);
    let factory = feedback_sources(feedback_policy(), move |_| {
      Ok((
        GatedFeedbackSensor(Arc::clone(&sensor_gate)),
        TestFeedbackActuator {
          limits: [16, 1000, 1000],
        },
      ))
    });
    let mut driver = CurrentThreadBuilder::new(local_config())
      .timer(4)
      .reactor(ReactorConfig {
        max_registrations: 4,
        max_waiters: 4,
      })
      .blocking(BlockingConfig {
        workers: 1,
        max_outstanding: 2,
        capacity: Resources::ZERO,
      })
      .processes(1)
      .feedback_sources(factory)
      .build()
      .unwrap_or_else(|error| panic!("feedback driver build failed: {error}"));
    assert!(gate.wait_until_entered(DRIVER_TEST_WATCHDOG));
    driver
      .request_shutdown(CurrentShutdown::default())
      .unwrap_or_else(|error| panic!("shutdown request failed: {error}"));

    for _ in 0..8 {
      assert_eq!(driver.drive_shutdown_step(), Ok(ShutdownProgress::Pending));
      assert!(driver.local.shutdown_complete());
      assert!(!driver.blocking_shutdown_requested);
      assert!(!driver.process_shutdown_requested);
      assert!(!driver.io_shutdown_requested);
      assert!(!driver.timer().unwrap().is_closed());
      assert!(!driver.reactor().unwrap().is_closed());
      assert!(
        !driver
          .feedback_metrics()
          .unwrap()
          .snapshot()
          .shutdown_complete
      );
      std::thread::yield_now();
    }

    gate.release();
    let deadline = Instant::now() + DRIVER_TEST_WATCHDOG;
    loop {
      match driver.drive_shutdown_step() {
        Ok(ShutdownProgress::Complete) => break,
        Ok(ShutdownProgress::Pending) => {
          assert!(Instant::now() < deadline, "current driver did not stop");
          std::thread::yield_now();
        }
        Err(error) => panic!("current driver shutdown failed: {error}"),
      }
    }
    assert!(driver.blocking_shutdown_requested);
    assert!(driver.process_shutdown_requested);
    assert!(driver.io_shutdown_requested);
    assert!(driver.timer().unwrap().is_closed());
    assert!(driver.reactor().unwrap().is_closed());
    assert!(
      driver
        .feedback_metrics()
        .unwrap()
        .snapshot()
        .shutdown_complete
    );
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn multithread_feedback_shutdown_precedes_supporting_services() {
    let gate = Arc::new(SampleGate::default());
    let _release_on_exit = ReleaseSampleGate(Arc::clone(&gate));
    let sensor_gate = Arc::clone(&gate);
    let factory = feedback_sources(feedback_policy(), move |_| {
      Ok((
        GatedFeedbackSensor(Arc::clone(&sensor_gate)),
        TestFeedbackActuator {
          limits: [16, 1000, 1000],
        },
      ))
    });
    let mut driver = MultiThreadBuilder::new(async_config())
      .timer(4)
      .reactor(ReactorConfig {
        max_registrations: 4,
        max_waiters: 4,
      })
      .blocking(BlockingConfig {
        workers: 1,
        max_outstanding: 2,
        capacity: Resources::ZERO,
      })
      .processes(1)
      .feedback_sources(factory)
      .build()
      .unwrap_or_else(|error| panic!("feedback driver build failed: {error}"));
    assert!(gate.wait_until_entered(DRIVER_TEST_WATCHDOG));
    driver
      .request_shutdown(MultiShutdown::default())
      .unwrap_or_else(|error| panic!("shutdown request failed: {error}"));

    let async_deadline = Instant::now() + DRIVER_TEST_WATCHDOG;
    while !driver.asynchronous.shutdown_complete() {
      assert_eq!(driver.drive_shutdown_step(), Ok(ShutdownProgress::Pending));
      assert!(!driver.blocking_shutdown_requested);
      assert!(!driver.process_shutdown_requested);
      assert!(!driver.io_shutdown_requested);
      assert!(!driver.timer().unwrap().is_closed());
      assert!(!driver.reactor().unwrap().is_closed());
      assert!(
        !driver
          .feedback_metrics()
          .unwrap()
          .snapshot()
          .shutdown_complete
      );
      assert!(
        Instant::now() < async_deadline,
        "async cleanup did not finish while feedback was held"
      );
      std::thread::yield_now();
    }
    assert_eq!(driver.drive_shutdown_step(), Ok(ShutdownProgress::Pending));
    assert!(driver.asynchronous.shutdown_complete());
    assert!(!driver.blocking_shutdown_requested);
    assert!(!driver.process_shutdown_requested);
    assert!(!driver.io_shutdown_requested);
    assert!(!driver.timer().unwrap().is_closed());
    assert!(!driver.reactor().unwrap().is_closed());

    gate.release();
    let deadline = Instant::now() + DRIVER_TEST_WATCHDOG;
    loop {
      match driver.drive_shutdown_step() {
        Ok(ShutdownProgress::Complete) => break,
        Ok(ShutdownProgress::Pending) => {
          assert!(Instant::now() < deadline, "multithread driver did not stop");
          std::thread::yield_now();
        }
        Err(error) => panic!("multithread driver shutdown failed: {error}"),
      }
    }
    assert!(driver.blocking_shutdown_requested);
    assert!(driver.process_shutdown_requested);
    assert!(driver.io_shutdown_requested);
    assert!(driver.timer().unwrap().is_closed());
    assert!(driver.reactor().unwrap().is_closed());
    assert!(
      driver
        .feedback_metrics()
        .unwrap()
        .snapshot()
        .shutdown_complete
    );
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn blocked_feedback_sensor_keeps_the_driver_pending_until_owner_cleanup() {
    let gate = Arc::new(SampleGate::default());
    let sensor_gate = Arc::clone(&gate);
    let factory = feedback_sources(feedback_policy(), move |_| {
      Ok((
        GatedFeedbackSensor(Arc::clone(&sensor_gate)),
        TestFeedbackActuator {
          limits: [16, 1000, 1000],
        },
      ))
    });
    let mut driver = CurrentThreadBuilder::new(local_config())
      .feedback_sources(factory)
      .build()
      .unwrap_or_else(|error| panic!("feedback driver build failed: {error}"));
    assert!(gate.wait_until_entered(DRIVER_TEST_WATCHDOG));
    driver
      .request_shutdown(CurrentShutdown::default())
      .unwrap_or_else(|error| panic!("shutdown request failed: {error}"));
    assert_eq!(driver.try_shutdown(), Ok(ShutdownProgress::Pending));
    assert!(driver.feedback.is_some());
    assert!(driver.feedback_meters.is_some());
    assert!(
      !driver
        .feedback_metrics()
        .unwrap()
        .snapshot()
        .shutdown_complete
    );

    gate.release();
    let deadline = Instant::now() + DRIVER_TEST_WATCHDOG;
    loop {
      match driver.drive_shutdown_step() {
        Ok(ShutdownProgress::Complete) => break,
        Ok(ShutdownProgress::Pending) => {
          assert!(Instant::now() < deadline, "feedback owner did not finish");
          std::thread::yield_now();
        }
        Err(error) => panic!("feedback owner shutdown failed: {error}"),
      }
    }
    assert!(
      driver
        .feedback_metrics()
        .unwrap()
        .snapshot()
        .shutdown_complete
    );
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn failed_feedback_factory_rolls_back_started_async_services() {
    let (domain, tenant) = feedback_domain();
    let control_before = domain.snapshot().used.get(DomainResource::Control);
    let factory = feedback_sources(feedback_policy(), |_| {
      Err::<(MissingFeedbackSensor, TestFeedbackActuator), io::Error>(io::Error::other(
        "intentional source failure",
      ))
    });
    let error = MultiThreadBuilder::new(async_config())
      .resource_domain(tenant)
      .timer(4)
      .feedback_sources(factory)
      .build()
      .err()
      .unwrap_or_else(|| panic!("failing feedback factory unexpectedly built"));
    assert!(matches!(
      error,
      DriverBuildError::Feedback(FeedbackFactoryError::Sources(_))
    ));
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      control_before
    );
  }

  fn exercise_owned_filesystem_rate(
    filesystem: FsHandle,
    resources: &ResourceScope,
    rate: ByteRateLimit,
  ) {
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-driver-fs-rate-{}-{}",
      std::process::id(),
      NEXT_FILE.fetch_add(1, Ordering::Relaxed),
    ));
    let standard = std::fs::OpenOptions::new()
      .create_new(true)
      .read(true)
      .write(true)
      .open(&path)
      .unwrap();
    std::fs::remove_file(path).unwrap();
    let file = crate::runtime::fs::OwnedFile::from_std(standard);
    let mut buffer = resources.try_alloc_zeroed(8).unwrap();
    buffer.get_mut().unwrap().copy_from_slice(b"abcdefgh");
    let outcome = filesystem.write(file, buffer).unwrap().join().unwrap();
    assert!(outcome.error.is_none());
    assert_eq!(outcome.bytes, 8);
    assert_eq!(rate.snapshot().reserved_bytes, 0);
    assert!(rate.snapshot().available_bytes < 32);
    drop(outcome);
    assert_eq!(resources.snapshot().managed_memory, 0);
    assert_eq!(resources.snapshot().disk_ops, 0);
  }

  #[test]
  fn both_owning_builders_bind_disk_rate_to_actual_filesystem_calls() {
    let rate = ByteRateConfig {
      bytes_per_second: 1,
      burst_bytes: 32,
      max_reservations: 4,
    };
    let blocking = BlockingConfig {
      workers: 1,
      max_outstanding: 4,
      capacity: Resources::ZERO,
    };
    let mut local = CurrentThreadBuilder::new(local_config())
      .resources(limits(64))
      .io_pool(blocking)
      .filesystem()
      .disk_rate(rate)
      .build()
      .unwrap();
    exercise_owned_filesystem_rate(
      local.filesystem().unwrap(),
      local.resources(),
      local.disk_rate().unwrap(),
    );
    shutdown_current_driver(&mut local);
    let mut multi = MultiThreadBuilder::new(async_config())
      .resources(limits(64))
      .io_pool(blocking)
      .filesystem()
      .disk_rate(rate)
      .build()
      .unwrap();
    exercise_owned_filesystem_rate(
      multi.filesystem().unwrap(),
      multi.resources(),
      multi.disk_rate().unwrap(),
    );
    multi.request_shutdown(MultiShutdown::default()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while multi.try_shutdown().unwrap() != ShutdownProgress::Complete {
      assert!(
        Instant::now() < deadline,
        "filesystem-bound multithread driver did not stop"
      );
      std::thread::yield_now();
    }
  }

  #[cfg(feature = "resource-feedback")]
  #[test]
  fn owning_filesystem_uses_the_feedback_context_disk_meter() {
    let (_, tenant) = feedback_domain();
    let seen = Arc::new(Mutex::new(None));
    let observed = seen.clone();
    let factory = feedback_sources(feedback_policy(), move |context| {
      *observed.lock().unwrap() = Some(context.disk_meter.clone());
      Ok((
        MissingFeedbackSensor,
        TestFeedbackActuator {
          limits: [16, 1000, 1000],
        },
      ))
    });
    let mut driver = CurrentThreadBuilder::new(local_config())
      .resources(limits(64))
      .resource_domain(tenant)
      .io_pool(BlockingConfig {
        workers: 1,
        max_outstanding: 4,
        capacity: Resources::ZERO,
      })
      .filesystem()
      .disk_rate(feedback_rate_config())
      .feedback_sources(factory)
      .build()
      .unwrap();
    let meter = seen.lock().unwrap().as_ref().unwrap().clone();
    assert_eq!(meter.snapshot().attached_sources, 1);
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-driver-fs-meter-{}-{}",
      std::process::id(),
      NEXT_FILE.fetch_add(1, Ordering::Relaxed),
    ));
    let standard = std::fs::OpenOptions::new()
      .create_new(true)
      .read(true)
      .write(true)
      .open(&path)
      .unwrap();
    std::fs::remove_file(path).unwrap();
    let mut buffer = driver.resources().try_alloc_zeroed(3).unwrap();
    buffer.get_mut().unwrap().copy_from_slice(b"abc");
    let outcome = driver
      .filesystem()
      .unwrap()
      .write(crate::runtime::fs::OwnedFile::from_std(standard), buffer)
      .unwrap()
      .join()
      .unwrap();
    assert!(outcome.error.is_none());
    assert_eq!(outcome.bytes, 3);
    assert_eq!(meter.snapshot().committed_bytes, 3);
    drop(outcome);
    shutdown_current_driver(&mut driver);
    drop(driver);
    assert_eq!(meter.snapshot().attached_sources, 0);
  }

  #[test]
  fn retryable_join_monitor_failure_does_not_latch_facade_shutdown() {
    use crate::runtime::thread_completion::fail_next_monitor_for_test;
    let mut current = CurrentThreadBuilder::new(local_config())
      .timer(4)
      .build()
      .unwrap();
    current
      .request_shutdown(CurrentShutdown::default())
      .unwrap();
    fail_next_monitor_for_test();
    let deadline = Instant::now() + Duration::from_secs(3);
    let error = loop {
      match current.drive_shutdown_step() {
        Err(error) => break error,
        Ok(ShutdownProgress::Pending) => {
          assert!(
            Instant::now() < deadline,
            "injected timer monitor failure was not reached"
          );
          std::thread::yield_now();
        }
        Ok(ShutdownProgress::Complete) => panic!("timer monitor injection was skipped"),
      }
    };
    assert_eq!(
      error,
      DriverShutdownError::Timer(TimerError::JoinMonitorSpawn)
    );
    assert!(error.is_retryable());
    assert!(current.shutdown_failure.is_none());
    assert!(current.timer.is_some());
    shutdown_current_driver(&mut current);

    let mut multi = MultiThreadBuilder::new(async_config()).build().unwrap();
    multi.request_shutdown(MultiShutdown::default()).unwrap();
    fail_next_monitor_for_test();
    let error = multi.try_shutdown().unwrap_err();
    assert_eq!(
      error,
      DriverShutdownError::Async(AsyncError::JoinMonitorSpawnFailed)
    );
    assert!(error.is_retryable());
    assert!(multi.shutdown_failure.is_none());
    let deadline = Instant::now() + Duration::from_secs(3);
    while multi.try_shutdown().unwrap() != ShutdownProgress::Complete {
      assert!(
        Instant::now() < deadline,
        "retried async shutdown did not complete"
      );
      std::thread::yield_now();
    }
  }

  #[test]
  fn both_bound_facades_reap_selected_processes_and_release_provider_metadata() {
    use crate::runtime::resource_domain::{DomainResource, DomainResources};

    let ceilings = DomainResources::ZERO
      .with(DomainResource::Cpu, 4)
      .with(DomainResource::Memory, 1024)
      .with(DomainResource::Tasks, 64)
      .with(DomainResource::Control, 1 << 20);
    let domain =
      crate::runtime::resource_domain::ResourceDomain::with_waiters(ceilings, 1, 64).unwrap();
    let tenant = domain.tenant(ceilings).unwrap();
    let baseline = domain.snapshot().used.get(DomainResource::Control);
    let child_command = || {
      let mut command = std::process::Command::new("/bin/sh");
      command.args(["-c", "exit 0"]);
      command
    };

    let multi_completion_drain = crate::runtime::thread_completion::CompletionDrain::new();
    let multi_drain_registration = multi_completion_drain.register_for_current_thread();
    // This test pins the facade's exact Control charge and the return to the
    // baseline after the process provider drains; a default feedback service
    // would add its own charges, so it is turned off here.
    let mut multi = MultiThreadBuilder::new(async_config())
      .resource_domain(tenant.clone())
      .resources(limits(0))
      .processes(1)
      .without_feedback()
      .build()
      .unwrap();
    drop(multi_drain_registration);
    assert_eq!(
      multi._control.bytes(),
      std::mem::size_of::<MultiThreadDriver>()
        - std::mem::size_of::<AsyncRuntime>()
        - std::mem::size_of::<ProcessDriver>()
    );
    let mut child = multi.processes().unwrap().spawn(child_command()).unwrap();
    let exit = multi.block_on(child.wait()).unwrap().unwrap();
    assert!(exit.success());
    shutdown_multi_driver(&mut multi);
    drop(multi);
    assert!(
      multi_completion_drain.wait_until_drained(DRIVER_TEST_WATCHDOG),
      "multithread completion monitors retained their shared Control owners"
    );
    assert!(domain.snapshot().used.get(DomainResource::Control) > baseline);
    drop(child);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline
    );

    let current_completion_drain = crate::runtime::thread_completion::CompletionDrain::new();
    let current_drain_registration = current_completion_drain.register_for_current_thread();
    let mut current = CurrentThreadBuilder::new(local_config())
      .resource_domain(tenant)
      .resources(limits(0))
      .processes(1)
      .without_feedback()
      .build()
      .unwrap();
    drop(current_drain_registration);
    assert_eq!(
      current._control.bytes(),
      std::mem::size_of::<CurrentThreadDriver>()
        - std::mem::size_of::<LocalRuntime>()
        - std::mem::size_of::<ProcessDriver>()
    );
    let mut child = current.processes().unwrap().spawn(child_command()).unwrap();
    let exit = current.block_on(child.wait()).unwrap().unwrap();
    assert!(exit.success());
    shutdown_current_driver(&mut current);
    drop(current);
    assert!(
      current_completion_drain.wait_until_drained(DRIVER_TEST_WATCHDOG),
      "current-thread completion monitors retained their shared Control owners"
    );
    assert!(domain.snapshot().used.get(DomainResource::Control) > baseline);
    drop(child);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline
    );
  }

  #[cfg(all(feature = "resource-feedback", not(loom)))]
  #[test]
  fn bound_builder_charges_values_once_and_retained_handles_keep_metadata() {
    let (domain, tenant) = feedback_domain();
    let completion_drain = crate::runtime::thread_completion::CompletionDrain::new();
    let completion_drain_registration = completion_drain.register_for_current_thread();
    let baseline = domain.snapshot().used.get(DomainResource::Control);
    let seen = Arc::new(Mutex::new(None));
    let observed = seen.clone();
    let factory = feedback_sources(feedback_policy(), move |context| {
      assert!(context.resources.is_control_accounted());
      *observed.lock().unwrap() = Some(context.disk_meter.clone());
      Ok((
        MissingFeedbackSensor,
        TestFeedbackActuator {
          limits: [16, 1000, 1000],
        },
      ))
    });
    let mut driver = MultiThreadBuilder::new(async_config())
      .resources(limits(64))
      .resource_domain(tenant)
      .disk_rate(feedback_rate_config())
      .feedback_sources(factory)
      .build()
      .unwrap();
    drop(completion_drain_registration);
    assert!(driver.resources().is_control_accounted());
    assert_eq!(
      driver._control.bytes(),
      std::mem::size_of::<MultiThreadDriver>()
        - std::mem::size_of::<AsyncRuntime>()
        - ResourceFeedbackService::owner_payload_bytes()
        - TimerDriver::owner_payload_bytes()
    );
    let ledger = driver.resources().clone();
    let buffer = ledger.try_alloc_zeroed(1).unwrap();
    let bucket = driver.disk_rate().unwrap();
    let meter = seen.lock().unwrap().take().unwrap();
    let metrics = driver.feedback_metrics().unwrap();
    shutdown_multi_driver(&mut driver);
    drop(driver);
    assert!(
      completion_drain.wait_until_drained(DRIVER_TEST_WATCHDOG),
      "runtime completion monitors retained their shared Control owners"
    );
    let before = domain.snapshot().used.get(DomainResource::Control);
    assert!(before > baseline);
    drop(metrics);
    let after_metrics = domain.snapshot().used.get(DomainResource::Control);
    assert!(after_metrics < before);
    drop(meter);
    let after_meter = domain.snapshot().used.get(DomainResource::Control);
    assert!(after_meter < after_metrics);
    drop(bucket);
    let after_bucket = domain.snapshot().used.get(DomainResource::Control);
    assert!(after_bucket < after_meter);
    drop(ledger);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      after_bucket
    );
    drop(buffer);
    assert_eq!(domain.snapshot().used.get(DomainResource::Memory), 0);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      baseline
    );
  }

  #[test]
  fn charged_builder_refuses_metadata_before_startup_callbacks() {
    use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Control, 1 << 20)
      .with(DomainResource::Cpu, 4)
      .with(DomainResource::Tasks, 16);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 32).unwrap();
    let tenant = domain.tenant(ceiling).unwrap();
    let baseline = domain.snapshot();
    domain
      .set_limits(baseline.limit.with(
        DomainResource::Control,
        baseline.used.get(DomainResource::Control),
      ))
      .unwrap();
    let before = domain.snapshot();
    let called = Arc::new(AtomicUsize::new(0));
    let observed = called.clone();
    let result = MultiThreadBuilder::new(async_config())
      .resource_domain(tenant.clone())
      .thread_options(AsyncThreadOptions::new().on_thread_start(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
      }))
      .build();
    assert!(matches!(
      result,
      Err(DriverBuildError::ResourceDomain(DomainError::Exhausted(
        DomainResource::Control
      )))
    ));
    assert_eq!(called.load(Ordering::SeqCst), 0);
    assert_eq!(domain.snapshot(), before);
  }
}
