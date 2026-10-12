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

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::future::Future;
use std::io;
use std::sync::Arc;

use super::ShutdownMode;
use super::asynchronous::{
  AsyncConfig, AsyncError, AsyncHandle, AsyncRuntime, AsyncShutdown, AsyncThreadOptions,
  HandoffConfig, LocalConfig, LocalError, LocalHandle, LocalRuntime, LocalSendHandle,
  LocalTaskScope, OwnedTaskScope, RuntimeMetrics,
};
use super::byte_rate::{ByteRateConfig, ByteRateError, ByteRateLimit};
use super::fs::FsHandle;
use super::managed::{ResourceLimits, ResourceScope};
use super::process::{ProcessBuildError, ProcessDriver, ProcessShutdownError, ProcessShutdownMode};
use super::reactor::{Reactor, ReactorConfig, ReactorError, ReactorHandle};
use super::resource_domain::TenantDomain;
use super::signal::{SignalDriver, SignalError};
use super::time::{ClockMode, IdleCoordinator, TimerDriver, TimerError, TimerHandle};
use super::{Config as BlockingConfig, Handle as BlockingHandle, Runtime as BlockingRuntime};

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
  /// Process reaping or its private reactor failed.
  Process(ProcessShutdownError),
  /// Timer service or close worker failed.
  Timer(TimerError),
  /// Reactor service or close worker failed.
  Reactor(ReactorError),
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
      Self::Process(error) => error.fmt(f),
      Self::Timer(error) => error.fmt(f),
      Self::Reactor(error) => error.fmt(f),
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
  /// Filesystem services require an owned blocking pool.
  FilesystemNeedsBlocking,
  /// Local executor storage could not be reserved.
  Local(LocalError),
  /// Async executor storage or thread startup failed.
  Async(AsyncError),
  /// Blocking pool construction failed.
  Blocking(io::Error),
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
}

impl fmt::Display for DriverBuildError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidConfiguration(reason) => write!(f, "invalid runtime configuration: {reason}"),
      Self::FilesystemNeedsBlocking => {
        f.write_str("filesystem services require a configured blocking pool")
      }
      Self::Local(error) => error.fmt(f),
      Self::Async(error) => error.fmt(f),
      Self::Blocking(error) => write!(f, "blocking pool construction failed: {error}"),
      Self::Timer(error) => error.fmt(f),
      Self::Reactor(error) => write!(f, "reactor construction failed: {error}"),
      Self::Process(error) => error.fmt(f),
      Self::Signal(error) => error.fmt(f),
      Self::ByteRate(error) => error.fmt(f),
    }
  }
}

impl std::error::Error for DriverBuildError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Local(error) => Some(error),
      Self::Async(error) => Some(error),
      Self::Blocking(error) | Self::Reactor(error) => Some(error),
      Self::Process(error) => Some(error),
      Self::Signal(error) => Some(error),
      Self::Timer(error) => Some(error),
      Self::ByteRate(error) => Some(error),
      Self::InvalidConfiguration(_) | Self::FilesystemNeedsBlocking => None,
    }
  }
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

#[derive(Clone, Copy, Debug, Default)]
struct ServiceOptions {
  timer_registrations: Option<usize>,
  timer_mode: ClockMode,
  reactor: Option<ReactorConfig>,
  blocking: Option<BlockingConfig>,
  filesystem: bool,
  process_children: Option<usize>,
  signal_listeners: Option<usize>,
  upload_rate: Option<ByteRateConfig>,
  download_rate: Option<ByteRateConfig>,
}

impl ServiceOptions {
  fn validate(&self) -> Result<(), DriverBuildError> {
    if self.timer_registrations == Some(0) {
      return Err(DriverBuildError::InvalidConfiguration(
        "timer registrations must be nonzero",
      ));
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
    if self.filesystem && self.blocking.is_none() {
      return Err(DriverBuildError::FilesystemNeedsBlocking);
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
    Ok(())
  }

  fn build_rates(
    &self,
  ) -> Result<(Option<ByteRateLimit>, Option<ByteRateLimit>), DriverBuildError> {
    let upload = self
      .upload_rate
      .map(ByteRateLimit::new)
      .transpose()
      .map_err(DriverBuildError::ByteRate)?;
    let download = self
      .download_rate
      .map(ByteRateLimit::new)
      .transpose()
      .map_err(DriverBuildError::ByteRate)?;
    Ok((upload, download))
  }

  fn build_services(
    &self,
    resources: &ResourceScope,
    startup: &mut StartupGuard,
    coordinator: Arc<IdleCoordinator>,
    current_thread: bool,
  ) -> Result<Option<FsHandle>, DriverBuildError> {
    if let Some(config) = self.blocking {
      startup.blocking = Some(
        BlockingRuntime::with_resources(config, resources.clone())
          .map_err(DriverBuildError::Blocking)?,
      );
    }
    if let Some(max_registered) = self.timer_registrations {
      startup.timer = Some(
        TimerDriver::new_for_runtime(max_registered, self.timer_mode, current_thread, coordinator)
          .map_err(DriverBuildError::Timer)?,
      );
    }
    if let Some(config) = self.reactor {
      startup.reactor = Some(Reactor::new(config).map_err(DriverBuildError::Reactor)?);
    }
    if let Some(max_children) = self.process_children {
      startup.process = Some(ProcessDriver::new(max_children).map_err(DriverBuildError::Process)?);
    }
    let filesystem = if self.filesystem {
      let blocking = startup
        .blocking
        .as_ref()
        .ok_or(DriverBuildError::FilesystemNeedsBlocking)?;
      Some(FsHandle::new(blocking.handle(), resources.clone()))
    } else {
      None
    };
    if let Some(max_listeners) = self.signal_listeners {
      // The permanent process signal bridge is created after every other
      // fallible service so earlier owners can still be rolled back on error.
      startup.signal = Some(SignalDriver::new(max_listeners).map_err(DriverBuildError::Signal)?);
    }
    Ok(filesystem)
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

      /// Selects a bounded readiness reactor.
      pub fn reactor(mut self, config: ReactorConfig) -> Self {
        self.services.reactor = Some(config);
        self
      }

      /// Selects the blocking worker pool used by blocking jobs and optional
      /// filesystem operations.
      pub fn blocking(mut self, config: BlockingConfig) -> Self {
        self.services.blocking = Some(config);
        self
      }

      /// Adds the filesystem front end. A blocking pool must also be selected.
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
        reactor: None,
        blocking: None,
        filesystem: false,
        process_children: None,
        signal_listeners: None,
        upload_rate: None,
        download_rate: None,
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
    self.services.validate()?;
    let (upload_rate, download_rate) = self.services.build_rates()?;
    let resources = match self.tenant {
      Some(tenant) => ResourceScope::from_tenant(self.resources, tenant),
      None => ResourceScope::new(self.resources),
    };
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
    let filesystem =
      self
        .services
        .build_services(&resources, &mut startup, Arc::clone(&coordinator), true)?;
    if let Some(timer) = startup.timer.as_ref().map(TimerDriver::handle) {
      let blocking_handle = startup.blocking.as_ref().map(BlockingRuntime::handle);
      if let Some(blocking) = startup.blocking.as_mut() {
        blocking.bind_clock(timer.clone());
      }
      if let Some(local) = startup.local.as_mut() {
        local.attach_idle_clock(timer, blocking_handle);
      }
    }
    Ok(CurrentThreadDriver {
      local: startup.local.take().unwrap_or_else(|| unreachable!()),
      resources,
      timer: startup.timer.take(),
      reactor: startup.reactor.take(),
      blocking: startup.blocking.take(),
      filesystem,
      process: startup.process.take(),
      signal: startup.signal.take(),
      upload_rate,
      download_rate,
      shutdown: None,
      shutdown_failure: None,
      blocking_shutdown_requested: false,
      process_shutdown_requested: false,
      io_shutdown_requested: false,
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
        reactor: None,
        blocking: None,
        filesystem: false,
        process_children: None,
        signal_listeners: None,
        upload_rate: None,
        download_rate: None,
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
    self.services.validate()?;
    let (upload_rate, download_rate) = self.services.build_rates()?;
    let resources = match self.tenant {
      Some(tenant) => ResourceScope::from_tenant(self.resources, tenant),
      None => ResourceScope::new(self.resources),
    };
    let mut startup = StartupGuard::default();
    let asynchronous = match (self.handoffs, self.thread_options) {
      (Some(handoffs), Some(options)) => AsyncRuntime::with_resources_handoffs_and_thread_options(
        self.config,
        handoffs,
        resources.clone(),
        options,
      ),
      (Some(handoffs), None) => {
        AsyncRuntime::with_resources_and_handoffs(self.config, handoffs, resources.clone())
      }
      (None, Some(options)) => {
        AsyncRuntime::with_resources_and_thread_options(self.config, resources.clone(), options)
      }
      (None, None) => AsyncRuntime::with_resources(self.config, resources.clone()),
    }
    .map_err(DriverBuildError::Async)?;
    startup.asynchronous = Some(asynchronous);
    let filesystem =
      self
        .services
        .build_services(&resources, &mut startup, IdleCoordinator::new(None), false)?;
    if let Some(timer) = startup.timer.as_ref().map(TimerDriver::handle)
      && let Some(blocking) = startup.blocking.as_mut()
    {
      blocking.bind_clock(timer);
    }
    Ok(MultiThreadDriver {
      asynchronous: startup
        .asynchronous
        .take()
        .unwrap_or_else(|| unreachable!()),
      resources,
      timer: startup.timer.take(),
      reactor: startup.reactor.take(),
      blocking: startup.blocking.take(),
      filesystem,
      process: startup.process.take(),
      signal: startup.signal.take(),
      upload_rate,
      download_rate,
      shutdown: None,
      shutdown_failure: None,
      blocking_shutdown_requested: false,
      process_shutdown_requested: false,
      io_shutdown_requested: false,
    })
  }
}

service_builder_methods!(MultiThreadBuilder);

#[derive(Default)]
struct StartupGuard {
  local: Option<LocalRuntime>,
  asynchronous: Option<AsyncRuntime>,
  blocking: Option<BlockingRuntime>,
  timer: Option<TimerDriver>,
  reactor: Option<Reactor>,
  process: Option<ProcessDriver>,
  signal: Option<SignalDriver>,
}

impl Drop for StartupGuard {
  fn drop(&mut self) {
    if let Some(process) = self.process.as_mut() {
      let _ = process.shutdown(ProcessShutdownMode::Wait);
    }
    if let Some(reactor) = self.reactor.take() {
      let _ = reactor.shutdown();
    }
    if let Some(timer) = self.timer.take() {
      let _ = timer.shutdown();
    }
    if let Some(blocking) = self.blocking.as_mut() {
      let _ = blocking.shutdown(ShutdownMode::CancelPending);
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
  reactor: Option<Reactor>,
  blocking: Option<BlockingRuntime>,
  filesystem: Option<FsHandle>,
  process: Option<ProcessDriver>,
  signal: Option<SignalDriver>,
  upload_rate: Option<ByteRateLimit>,
  download_rate: Option<ByteRateLimit>,
  shutdown: Option<CurrentShutdown>,
  shutdown_failure: Option<DriverShutdownError>,
  blocking_shutdown_requested: bool,
  process_shutdown_requested: bool,
  io_shutdown_requested: bool,
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

  /// The filesystem front end over this runtime's blocking pool and ledger.
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

  /// Closes local admission and requests cancellation according to `policy`.
  /// Supporting services remain open while owner-thread future cleanup,
  /// blocking work and child reaping finish. Repeating the same request is
  /// safe; a different policy is rejected.
  pub fn request_shutdown(&mut self, policy: CurrentShutdown) -> Result<(), DriverShutdownError> {
    if self.shutdown.is_some_and(|current| current != policy) {
      return Err(DriverShutdownError::PolicyAlreadyFixed);
    }
    self.shutdown = Some(policy);
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
    let local_complete = self.local.shutdown_complete();
    let mut failure = None;
    let mut blocking_complete = false;
    if local_complete {
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

    let mut process_complete = false;
    if blocking_complete {
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
    if process_complete {
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
      self.shutdown_failure.get_or_insert(error);
    }
    if let Some(error) = self.shutdown_failure {
      return Err(error);
    }
    let complete = local_complete && blocking_complete && process_complete && io_complete;
    Ok(if complete {
      ShutdownProgress::Complete
    } else {
      ShutdownProgress::Pending
    })
  }

  /// Runs one owner-thread task cleanup and one blocking-pool cleanup step,
  /// then checks all services. Local future destructors and queued job
  /// captures can take unbounded time while this explicit method runs.
  pub fn drive_shutdown_step(&mut self) -> Result<ShutdownProgress, DriverShutdownError> {
    if self.shutdown.is_none() {
      return Err(DriverShutdownError::NotRequested);
    }
    if let Err(error) = self.local.drive_shutdown_step() {
      self
        .shutdown_failure
        .get_or_insert(DriverShutdownError::Local(error));
    }
    if self.local.shutdown_complete()
      && let Some(policy) = self.shutdown
    {
      self.request_blocking_shutdown(policy)?;
    }
    if let Some(blocking) = self.blocking.as_mut()
      && self.blocking_shutdown_requested
      && let Err(error) = blocking.drive_shutdown_step()
    {
      self
        .shutdown_failure
        .get_or_insert(DriverShutdownError::Blocking(error.kind()));
    }
    self.try_shutdown()
  }
}

/// Multithreaded runtime and its selected service drivers.
pub struct MultiThreadDriver {
  asynchronous: AsyncRuntime,
  resources: ResourceScope,
  timer: Option<TimerDriver>,
  reactor: Option<Reactor>,
  blocking: Option<BlockingRuntime>,
  filesystem: Option<FsHandle>,
  process: Option<ProcessDriver>,
  signal: Option<SignalDriver>,
  upload_rate: Option<ByteRateLimit>,
  download_rate: Option<ByteRateLimit>,
  shutdown: Option<MultiShutdown>,
  shutdown_failure: Option<DriverShutdownError>,
  blocking_shutdown_requested: bool,
  process_shutdown_requested: bool,
  io_shutdown_requested: bool,
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

  /// The filesystem front end over this runtime's blocking pool and ledger.
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

  /// Closes executor admission. Blocking jobs continue first, then managed
  /// children are reaped, and timer/reactor services close only after both
  /// stages finish. This keeps dependencies available to already-admitted
  /// async work and its completion chain.
  pub fn request_shutdown(&mut self, policy: MultiShutdown) -> Result<(), DriverShutdownError> {
    if self.shutdown.is_some_and(|current| current != policy) {
      return Err(DriverShutdownError::PolicyAlreadyFixed);
    }
    self.shutdown = Some(policy);
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
    if let Err(error) = self.asynchronous.poll_shutdown() {
      failure.get_or_insert(DriverShutdownError::Async(error));
    }
    let async_complete = self.asynchronous.shutdown_complete();
    let mut blocking_complete = false;
    if async_complete {
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

    let mut process_complete = false;
    if blocking_complete {
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
    if process_complete {
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
      self.shutdown_failure.get_or_insert(error);
    }
    if let Some(error) = self.shutdown_failure {
      return Err(error);
    }
    let complete = async_complete && blocking_complete && process_complete && io_complete;
    Ok(if complete {
      ShutdownProgress::Complete
    } else {
      ShutdownProgress::Pending
    })
  }

  /// Drops at most one queued blocking job, then checks all services. A job
  /// capture's destructor can take unbounded time while this explicit cleanup
  /// step runs.
  pub fn drive_shutdown_step(&mut self) -> Result<ShutdownProgress, DriverShutdownError> {
    if self.shutdown.is_none() {
      return Err(DriverShutdownError::NotRequested);
    }
    if self.blocking_shutdown_requested
      && let Some(blocking) = self.blocking.as_mut()
      && let Err(error) = blocking.drive_shutdown_step()
    {
      self
        .shutdown_failure
        .get_or_insert(DriverShutdownError::Blocking(error.kind()));
    }
    self.try_shutdown()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::Resources;
  use std::pin::Pin;
  use std::sync::Mutex;
  use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
  use std::sync::mpsc::{self, Receiver, SyncSender};
  use std::task::{Context, Wake, Waker};
  use std::time::{Duration, Instant};

  static NEXT_FILE: AtomicUsize = AtomicUsize::new(1);

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
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let job = pool
      .try_spawn(Resources::ZERO, move |_token| {
        let _ = started_tx.send(());
        handle
          .block_on(async move {
            let sleep = timer
              .sleep(Duration::from_millis(20))
              .map_err(|_| "sleep creation failed")?;
            sleep
              .await
              .map_err(|_| "timer closed during blocking drain")
          })
          .map_err(|_| "nested block_on failed")?
      })
      .unwrap_or_else(|error| panic!("blocking job admission failed: {error}"));
    started_rx
      .recv_timeout(Duration::from_secs(2))
      .unwrap_or_else(|error| panic!("blocking job did not start: {error}"));

    driver
      .request_shutdown(MultiShutdown {
        tasks: AsyncShutdown::CancelPending,
        blocking: ShutdownMode::Drain,
        processes: ProcessShutdownMode::Wait,
      })
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
      .blocking(BlockingConfig {
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
      asynchronous,
      resources,
      timer: Some(
        TimerDriver::new(1).unwrap_or_else(|error| panic!("timer driver build failed: {error}")),
      ),
      reactor: None,
      blocking: Some(blocking),
      filesystem: None,
      process: None,
      signal: None,
      upload_rate: None,
      download_rate: None,
      shutdown: None,
      shutdown_failure: None,
      blocking_shutdown_requested: false,
      process_shutdown_requested: false,
      io_shutdown_requested: false,
    };
    driver
      .request_shutdown(MultiShutdown::default())
      .unwrap_or_else(|error| panic!("shutdown request failed: {error}"));

    let (status_tx, status_rx) = mpsc::sync_channel(1);
    let checker = std::thread::spawn(move || {
      let mut driver = driver;
      let deadline = Instant::now() + Duration::from_secs(3);
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

    let (mut driver, status) = match status_rx.recv_timeout(Duration::from_secs(2)) {
      Ok(result) => result,
      Err(error) => {
        let _ = release_tx.send(());
        let (driver, _) = status_rx
          .recv_timeout(Duration::from_secs(2))
          .unwrap_or_else(|second| panic!("shutdown status never returned: {error}; {second}"));
        let _ = checker.join();
        drop(driver);
        panic!("shutdown status blocked while dropping a worker panic payload");
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
    assert!(matches!(error, DriverBuildError::FilesystemNeedsBlocking));
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
}
