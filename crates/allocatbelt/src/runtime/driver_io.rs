//! Cloneable, executor-independent bindings for configured driver I/O policy.
//!
//! An [`IoBindings`] clone keeps its resource scope, selected byte buckets,
//! fixed real-time timer handle, and optional feedback meters alive without
//! retaining the owning driver or its executors. The driver's shutdown still
//! closes the timer it owns, so a retained binding cannot create new adapters
//! after that close. Stream wrappers account application bytes only; callers
//! use [`IoBindings::resources`] when they need an operation permit for a
//! logical endpoint operation.
//!
//! The shared binding payload is charged once to the scope's tenant Control
//! limit when present. Arc allocator headers and the metadata of returned
//! stream adapter values are outside this charge. A returned UDP adapter has
//! its own declared Control charge and retains the same scope for its
//! per-datagram network permits.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::sync::Arc;

use super::super::byte_rate::ByteRateLimit;
use super::super::managed::ResourceScope;
use super::super::resource_domain::{ControlCharge, DomainError};
use super::super::time::TimerHandle;

#[cfg(not(loom))]
use super::super::io::{AsyncRead, AsyncWrite};
#[cfg(not(loom))]
use super::super::net::UdpSocket;
#[cfg(not(loom))]
use super::super::rate_datagram::{RateDatagramBuildFailure, RateLimitedUdp};
#[cfg(not(loom))]
use super::super::rate_io::RateLimitedIo;

#[cfg(feature = "resource-feedback")]
use super::feedback::FeedbackMeters as IoMeters;

struct BindingsInner {
  resources: ResourceScope,
  disk_rate: Option<ByteRateLimit>,
  upload_rate: Option<ByteRateLimit>,
  download_rate: Option<ByteRateLimit>,
  rate_timer: Option<TimerHandle>,
  #[cfg(feature = "resource-feedback")]
  meters: Option<IoMeters>,
  _control: ControlCharge,
}

/// Cloneable access to the resource and rate policies selected by an owning
/// driver.
///
/// Clones share one fixed binding payload. They do not keep the driver,
/// executor, reactor, or timer service owner alive. A task may move a clone
/// into a `'static` future and wrap an endpoint without capturing an
/// `Arc<Driver>`.
#[derive(Clone)]
pub struct IoBindings {
  inner: Arc<BindingsInner>,
}

impl fmt::Debug for IoBindings {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut debug = f.debug_struct("IoBindings");
    debug
      .field("disk_rate_selected", &self.inner.disk_rate.is_some())
      .field("upload_rate_selected", &self.inner.upload_rate.is_some())
      .field(
        "download_rate_selected",
        &self.inner.download_rate.is_some(),
      )
      .field("rate_timer_selected", &self.inner.rate_timer.is_some());
    #[cfg(feature = "resource-feedback")]
    debug.field("feedback_meters_selected", &self.inner.meters.is_some());
    debug.finish_non_exhaustive()
  }
}

impl IoBindings {
  /// Creates shared policies for an external executor from borrowed components.
  ///
  /// The caller retains the timer service owner. Missing or closed components
  /// are reported when wrapping an endpoint, recovering that endpoint. The
  /// scope's tenant admits this shared payload before allocation.
  pub fn from_components(
    resources: &ResourceScope,
    disk_rate: Option<&ByteRateLimit>,
    upload_rate: Option<&ByteRateLimit>,
    download_rate: Option<&ByteRateLimit>,
    rate_timer: Option<&TimerHandle>,
  ) -> Result<Self, DomainError> {
    Self::new(
      resources,
      disk_rate,
      upload_rate,
      download_rate,
      rate_timer,
      #[cfg(feature = "resource-feedback")]
      None,
    )
  }

  /// Creates the same policies with disk, upload and download feedback meters.
  /// Sources register when adapters are created, rather than at binding time.
  #[cfg(feature = "resource-feedback")]
  pub fn from_metered_components(
    resources: &ResourceScope,
    disk_rate: Option<&ByteRateLimit>,
    upload_rate: Option<&ByteRateLimit>,
    download_rate: Option<&ByteRateLimit>,
    rate_timer: Option<&TimerHandle>,
    meters: (
      &super::super::resource_feedback_meter::IoFeedbackMeter,
      &super::super::resource_feedback_meter::IoFeedbackMeter,
      &super::super::resource_feedback_meter::IoFeedbackMeter,
    ),
  ) -> Result<Self, DomainError> {
    Self::new(
      resources,
      disk_rate,
      upload_rate,
      download_rate,
      rate_timer,
      Some(IoMeters {
        disk: meters.0.clone(),
        upload: meters.1.clone(),
        download: meters.2.clone(),
      }),
    )
  }

  /// Builds one shared policy binding from the driver's selected components.
  ///
  /// The declared Inner payload is admitted to Control before cloning the
  /// components or allocating the Arc. The constructor is crate-private so
  /// owning drivers remain responsible for selecting components from one
  /// build and mapping admission failures into their typed build error.
  pub(crate) fn new(
    resources: &ResourceScope,
    disk_rate: Option<&ByteRateLimit>,
    upload_rate: Option<&ByteRateLimit>,
    download_rate: Option<&ByteRateLimit>,
    rate_timer: Option<&TimerHandle>,
    #[cfg(feature = "resource-feedback")] meters: Option<IoMeters>,
  ) -> Result<Self, DomainError> {
    let control = ControlCharge::try_new(
      resources.tenant_domain(),
      std::mem::size_of::<BindingsInner>(),
    )?;
    Ok(Self {
      inner: Arc::new(BindingsInner {
        resources: resources.clone(),
        disk_rate: disk_rate.cloned(),
        upload_rate: upload_rate.cloned(),
        download_rate: download_rate.cloned(),
        rate_timer: rate_timer.cloned(),
        #[cfg(feature = "resource-feedback")]
        meters,
        _control: control,
      }),
    })
  }

  /// Returns a clone of the exact scope used by bindings and UDP adapters.
  ///
  /// Stream rate adapters do not acquire operation permits themselves. A
  /// stream client that accounts a logical network operation should acquire
  /// the permit from this scope and hold it for that operation's lifetime.
  #[must_use]
  pub fn resources(&self) -> ResourceScope {
    self.inner.resources.clone()
  }

  /// Wraps an application stream with the configured download/read and
  /// upload/write buckets.
  ///
  /// Every refusal returns the original endpoint in the error. This limits
  /// application bytes accepted by the wrapped stream calls; it does not add
  /// operation permits or intercept I/O that bypasses the returned adapter.
  #[cfg(not(loom))]
  pub fn rate_io<T: AsyncRead + AsyncWrite + Unpin>(
    &self,
    inner: T,
  ) -> Result<RateLimitedIo<T>, super::DriverRateIoError<T>> {
    super::build_rate_io(
      inner,
      self.inner.download_rate.clone(),
      self.inner.upload_rate.clone(),
      self.inner.rate_timer.clone(),
      #[cfg(feature = "resource-feedback")]
      self.inner.meters.as_ref(),
    )
  }

  /// Wraps an application stream with the configured disk bucket on reads and
  /// writes. This explicit adapter does not intercept filesystem calls or
  /// acquire disk operation permits.
  #[cfg(not(loom))]
  pub fn disk_io<T: AsyncRead + AsyncWrite + Unpin>(
    &self,
    inner: T,
  ) -> Result<RateLimitedIo<T>, super::DriverRateIoError<T>> {
    super::build_disk_io(
      inner,
      self.inner.disk_rate.clone(),
      self.inner.rate_timer.clone(),
      #[cfg(feature = "resource-feedback")]
      self.inner.meters.as_ref(),
    )
  }

  /// Wraps a registered UDP socket with exact download and upload byte
  /// admission and the binding's network operation scope.
  ///
  /// The adapter retains the same scope, so each datagram owns one network
  /// permit through readiness and syscall completion. Every constructor
  /// refusal returns the original socket unchanged in the error.
  #[cfg(not(loom))]
  pub fn rate_datagram(
    &self,
    socket: UdpSocket,
  ) -> Result<RateLimitedUdp, DriverRateDatagramError> {
    let Some(download_rate) = self.inner.download_rate.as_ref() else {
      return Err(DriverRateDatagramError {
        socket,
        failure: if self.inner.upload_rate.is_some() {
          DriverRateDatagramFailure::MissingDownloadRate
        } else {
          DriverRateDatagramFailure::MissingUploadAndDownloadRates
        },
      });
    };
    let Some(upload_rate) = self.inner.upload_rate.as_ref() else {
      return Err(DriverRateDatagramError {
        socket,
        failure: DriverRateDatagramFailure::MissingUploadRate,
      });
    };
    let Some(timer) = self.inner.rate_timer.as_ref() else {
      return Err(DriverRateDatagramError {
        socket,
        failure: DriverRateDatagramFailure::MissingRateTimer,
      });
    };

    let result = {
      #[cfg(feature = "resource-feedback")]
      if let Some(meters) = &self.inner.meters {
        RateLimitedUdp::new_metered(
          socket,
          download_rate.clone(),
          upload_rate.clone(),
          timer.clone(),
          self.inner.resources.clone(),
          meters.download.clone(),
          meters.upload.clone(),
        )
      } else {
        RateLimitedUdp::new(
          socket,
          download_rate.clone(),
          upload_rate.clone(),
          timer.clone(),
          self.inner.resources.clone(),
        )
      }
      #[cfg(not(feature = "resource-feedback"))]
      RateLimitedUdp::new(
        socket,
        download_rate.clone(),
        upload_rate.clone(),
        timer.clone(),
        self.inner.resources.clone(),
      )
    };

    result.map_err(|error| {
      let failure = DriverRateDatagramFailure::Adapter(error.failure());
      let socket = error.into_inputs().socket;
      DriverRateDatagramError { socket, failure }
    })
  }
}

/// Why a driver binding could not construct a rate-limited datagram adapter.
#[cfg(not(loom))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DriverRateDatagramFailure {
  /// Neither network byte direction was configured.
  MissingUploadAndDownloadRates,
  /// Download/receive byte admission was not configured.
  MissingDownloadRate,
  /// Upload/send byte admission was not configured.
  MissingUploadRate,
  /// The driver did not create its private fixed real-clock timer.
  MissingRateTimer,
  /// The registered-socket adapter rejected its timer or metadata admission.
  Adapter(RateDatagramBuildFailure),
}

impl fmt::Display for DriverRateDatagramFailure {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "driver rate-limited UDP construction refused: {self:?}")
  }
}

impl std::error::Error for DriverRateDatagramFailure {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Adapter(error) => Some(error),
      Self::MissingUploadAndDownloadRates
      | Self::MissingDownloadRate
      | Self::MissingUploadRate
      | Self::MissingRateTimer => None,
    }
  }
}

/// A refused driver UDP wrapper together with the original registered socket.
#[cfg(not(loom))]
pub struct DriverRateDatagramError {
  socket: UdpSocket,
  failure: DriverRateDatagramFailure,
}

#[cfg(not(loom))]
impl DriverRateDatagramError {
  /// Why the UDP adapter could not be constructed.
  #[must_use]
  pub const fn failure(&self) -> DriverRateDatagramFailure {
    self.failure
  }

  /// Returns the original registered socket unchanged.
  #[must_use]
  pub fn into_inner(self) -> UdpSocket {
    self.socket
  }
}

#[cfg(not(loom))]
impl fmt::Debug for DriverRateDatagramError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("DriverRateDatagramError")
      .field("failure", &self.failure)
      .field("socket", &self.socket)
      .finish()
  }
}

#[cfg(not(loom))]
impl fmt::Display for DriverRateDatagramError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.failure)
  }
}

#[cfg(not(loom))]
impl std::error::Error for DriverRateDatagramError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.failure)
  }
}

#[cfg(all(test, not(loom)))]
#[path = "driver_io_tests.rs"]
mod tests;
