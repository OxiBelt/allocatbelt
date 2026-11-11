//! Exact byte admission for borrowed UDP datagrams.
//!
//! [`RateLimitedUdp`] wraps a registered [`super::net::UdpSocket`] and
//! reserves the complete input datagram or receive buffer before issuing one
//! socket operation. It never fragments, peeks, or copies datagrams. The
//! limits count application bytes reported by the socket API, not physical
//! disk or wire traffic; receives retain the wrapped socket's kernel
//! truncation behavior.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::error::Error;
use std::fmt;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::byte_rate::{ByteRateError, ByteRateLimit, ByteReservation};
use super::managed::{
  OperationPermit, OperationRequest, ResourceError, ResourceKind, ResourceScope,
};
use super::net::UdpSocket;
use super::resource_domain::{ControlCharge, DomainError};
use super::time::{ClockMode, TimerError, TimerHandle};

#[cfg(feature = "resource-feedback")]
use super::resource_feedback_meter::{IoFeedbackMeter, IoFeedbackRegistration};

const NETWORK_OPERATION: OperationRequest = OperationRequest {
  disk: 0,
  network: 1,
};

#[cfg(feature = "resource-feedback")]
struct DatagramMeters {
  download: IoFeedbackMeter,
  upload: IoFeedbackMeter,
  _download_registration: IoFeedbackRegistration,
  _upload_registration: IoFeedbackRegistration,
}

#[cfg(feature = "resource-feedback")]
impl DatagramMeters {
  fn new(download: IoFeedbackMeter, upload: IoFeedbackMeter) -> Self {
    let download_registration = download.register_source();
    let upload_registration = upload.register_source();
    Self {
      download,
      upload,
      _download_registration: download_registration,
      _upload_registration: upload_registration,
    }
  }

  fn meter(&self, direction: DatagramDirection) -> &IoFeedbackMeter {
    match direction {
      DatagramDirection::Download => &self.download,
      DatagramDirection::Upload => &self.upload,
    }
  }

  fn invalidate_all(&self) {
    self.download.mark_invalid_io();
    self.upload.mark_invalid_io();
  }
}

#[derive(Clone, Copy)]
enum DatagramDirection {
  Download,
  Upload,
}

/// Why the datagram wrapper could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RateDatagramBuildFailure {
  /// The timer is mutable or does not follow real monotonic time.
  NotRealTimeClock,
  /// The real monotonic clock reached the representable `Instant` boundary.
  ClockSaturated,
  /// The timer driver has already closed.
  TimerClosed,
  /// Tenant Control capacity could not admit the wrapper's fixed metadata.
  Control(DomainError),
}

impl fmt::Display for RateDatagramBuildFailure {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "rate-limited UDP construction refused: {self:?}")
  }
}

impl Error for RateDatagramBuildFailure {}

/// Every original input returned by a refused constructor.
pub struct RateDatagramBuildInputs {
  /// The original registered UDP socket.
  pub socket: UdpSocket,
  /// The download/receive byte bucket.
  pub download_rate: ByteRateLimit,
  /// The upload/send byte bucket.
  pub upload_rate: ByteRateLimit,
  /// The original immutable real-time timer handle.
  pub timer: TimerHandle,
  /// The original operation-resource scope.
  pub resources: ResourceScope,
  /// The original optional download and upload meters.
  #[cfg(feature = "resource-feedback")]
  pub feedback_meters: Option<(IoFeedbackMeter, IoFeedbackMeter)>,
}

impl fmt::Debug for RateDatagramBuildInputs {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut debug = f.debug_struct("RateDatagramBuildInputs");
    debug
      .field("socket", &self.socket)
      .field("download_rate", &self.download_rate)
      .field("upload_rate", &self.upload_rate)
      .field("timer", &self.timer)
      .field("resources", &self.resources);
    #[cfg(feature = "resource-feedback")]
    debug.field("feedback_meters", &self.feedback_meters);
    debug.finish()
  }
}

/// Constructor rejection together with every original input.
#[derive(Debug)]
pub struct RateDatagramBuildError {
  failure: RateDatagramBuildFailure,
  inputs: RateDatagramBuildInputs,
}

impl RateDatagramBuildError {
  /// Why construction was refused.
  #[must_use]
  pub const fn failure(&self) -> RateDatagramBuildFailure {
    self.failure
  }

  /// Returns the original socket, buckets, timer, scope, and optional meters.
  #[must_use]
  pub fn into_inputs(self) -> RateDatagramBuildInputs {
    self.inputs
  }
}

impl fmt::Display for RateDatagramBuildError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.failure)
  }
}

impl Error for RateDatagramBuildError {}

/// A terminal or transient failure specific to rate-limited datagrams.
///
/// Adapter-generated I/O errors carry this value as their `io::Error` payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RateDatagramFailure {
  /// The supplied timer is not a fixed real-time clock.
  NotRealTimeClock,
  /// The real monotonic clock reached the representable `Instant` boundary.
  ClockSaturated,
  /// A rate-wait deadline could not be represented.
  DeadlineOutOfRange,
  /// The timer could not register or complete a rate wait.
  Timer(TimerError),
  /// Exact byte admission failed.
  ByteRate(ByteRateError),
  /// A very short wait could not be kept armed without a wake-less Pending.
  WakeUnavailable,
  /// The socket returned more bytes than the complete datagram offer.
  InvalidSendCount { reported: usize, offered: usize },
  /// The socket returned more bytes than the initialized receive buffer.
  InvalidReceiveCount { reported: usize, offered: usize },
  /// A reservation rejected a count already validated against its size.
  ReservationCommit,
}

impl RateDatagramFailure {
  fn error_kind(self) -> ErrorKind {
    match self {
      Self::InvalidSendCount { .. }
      | Self::InvalidReceiveCount { .. }
      | Self::ReservationCommit
      | Self::ByteRate(ByteRateError::Overcommitted) => ErrorKind::InvalidData,
      Self::NotRealTimeClock
      | Self::ClockSaturated
      | Self::DeadlineOutOfRange
      | Self::Timer(TimerError::ClockSaturated | TimerError::Invalid)
      | Self::ByteRate(ByteRateError::InvalidConfig | ByteRateError::Oversized) => {
        ErrorKind::InvalidInput
      }
      Self::Timer(TimerError::Full) | Self::ByteRate(ByteRateError::ReservationsFull) => {
        ErrorKind::WouldBlock
      }
      Self::WakeUnavailable => ErrorKind::WouldBlock,
      Self::Timer(TimerError::OutOfMemory) => ErrorKind::OutOfMemory,
      Self::Timer(TimerError::Closed) => ErrorKind::BrokenPipe,
      Self::ByteRate(ByteRateError::Insufficient(_)) => ErrorKind::WouldBlock,
      Self::Timer(_) | Self::ByteRate(_) => ErrorKind::Other,
    }
  }

  fn is_sticky(self) -> bool {
    matches!(
      self,
      Self::NotRealTimeClock
        | Self::ClockSaturated
        | Self::Timer(TimerError::Closed | TimerError::ClockSaturated | TimerError::Invalid)
        | Self::InvalidSendCount { .. }
        | Self::InvalidReceiveCount { .. }
        | Self::ReservationCommit
    )
  }

  fn into_io_error(self) -> io::Error {
    io::Error::new(self.error_kind(), self)
  }
}

impl fmt::Display for RateDatagramFailure {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "rate-limited UDP operation failed: {self:?}")
  }
}

impl Error for RateDatagramFailure {}

struct Inner {
  socket: UdpSocket,
  download_rate: ByteRateLimit,
  upload_rate: ByteRateLimit,
  timer: TimerHandle,
  #[cfg(feature = "resource-feedback")]
  feedback: Option<DatagramMeters>,
  fault: Mutex<Option<RateDatagramFailure>>,
  _control: ControlCharge,
  resources: ResourceScope,
}

impl fmt::Debug for Inner {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut debug = f.debug_struct("RateLimitedUdpInner");
    debug
      .field("socket", &self.socket)
      .field("download_rate", &self.download_rate)
      .field("upload_rate", &self.upload_rate)
      .field("timer", &self.timer)
      .field("resources", &self.resources);
    #[cfg(feature = "resource-feedback")]
    debug.field("feedback_enabled", &self.feedback.is_some());
    debug.finish_non_exhaustive()
  }
}

/// A cloneable, exact-byte UDP wrapper.
///
/// Clones share one socket, both buckets, the resource scope, fixed metadata
/// charge, and optional meter registrations. Every datagram attempt takes one
/// network permit only after exact byte credit is available; the permit stays
/// live through socket readiness and syscall completion.
#[derive(Clone)]
pub struct RateLimitedUdp {
  inner: Arc<Inner>,
}

impl RateLimitedUdp {
  /// Owns a UDP socket with separate download and upload byte buckets.
  ///
  /// A mutable, paused, saturated, or closed timer and a failed tenant
  /// metadata charge are refused before the socket is polled. Every original
  /// component remains available from [`RateDatagramBuildError::into_inputs`].
  pub fn new(
    socket: UdpSocket,
    download_rate: ByteRateLimit,
    upload_rate: ByteRateLimit,
    timer: TimerHandle,
    resources: ResourceScope,
  ) -> Result<Self, RateDatagramBuildError> {
    Self::build(RateDatagramBuildInputs {
      socket,
      download_rate,
      upload_rate,
      timer,
      resources,
      #[cfg(feature = "resource-feedback")]
      feedback_meters: None,
    })
  }

  /// As [`Self::new`], with immutable download and upload meters attached
  /// before the shared owner is exposed.
  #[cfg(feature = "resource-feedback")]
  pub fn new_metered(
    socket: UdpSocket,
    download_rate: ByteRateLimit,
    upload_rate: ByteRateLimit,
    timer: TimerHandle,
    resources: ResourceScope,
    download_meter: IoFeedbackMeter,
    upload_meter: IoFeedbackMeter,
  ) -> Result<Self, RateDatagramBuildError> {
    Self::build(RateDatagramBuildInputs {
      socket,
      download_rate,
      upload_rate,
      timer,
      resources,
      feedback_meters: Some((download_meter, upload_meter)),
    })
  }

  fn build(inputs: RateDatagramBuildInputs) -> Result<Self, RateDatagramBuildError> {
    if let Some(failure) = timer_build_failure(&inputs.timer) {
      return Err(RateDatagramBuildError { failure, inputs });
    }
    let control_bytes = std::mem::size_of::<Inner>();
    let control = match ControlCharge::try_new(inputs.resources.tenant_domain(), control_bytes) {
      Ok(control) => control,
      Err(error) => {
        return Err(RateDatagramBuildError {
          failure: RateDatagramBuildFailure::Control(error),
          inputs,
        });
      }
    };
    let RateDatagramBuildInputs {
      socket,
      download_rate,
      upload_rate,
      timer,
      resources,
      #[cfg(feature = "resource-feedback")]
      feedback_meters,
    } = inputs;
    #[cfg(feature = "resource-feedback")]
    let feedback = feedback_meters.map(|(download, upload)| DatagramMeters::new(download, upload));
    Ok(Self {
      inner: Arc::new(Inner {
        socket,
        download_rate,
        upload_rate,
        timer,
        #[cfg(feature = "resource-feedback")]
        feedback,
        fault: Mutex::new(None),
        _control: control,
        resources,
      }),
    })
  }

  /// Borrows the download/receive bucket.
  #[must_use]
  pub fn download_rate(&self) -> &ByteRateLimit {
    &self.inner.download_rate
  }

  /// Borrows the upload/send bucket.
  #[must_use]
  pub fn upload_rate(&self) -> &ByteRateLimit {
    &self.inner.upload_rate
  }

  /// Borrows the operation-resource scope.
  #[must_use]
  pub fn resources(&self) -> &ResourceScope {
    &self.inner.resources
  }

  /// Sends one complete connected-peer datagram. Empty input still sends an
  /// empty datagram and still takes one network operation slot.
  pub async fn send(&self, datagram: &[u8]) -> io::Result<usize> {
    self.send_inner(datagram, None).await
  }

  /// Sends one complete datagram to `address`. Oversized datagrams fail exact
  /// admission before any syscall and remain intact in the caller's slice.
  pub async fn send_to(&self, datagram: &[u8], address: SocketAddr) -> io::Result<usize> {
    self.send_inner(datagram, Some(address)).await
  }

  /// Receives one datagram from the connected peer. A zero-length buffer still
  /// consumes one datagram. Larger datagrams retain the wrapped socket's
  /// kernel truncation behavior; only copied bytes are charged.
  pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
    let (reservation, permit) = self.begin(&self.inner.download_rate, buffer.len()).await?;
    let offered = reservation.bytes();
    let result = match self.inner.socket.recv(buffer).await {
      Ok(reported) => {
        self
          .inner
          .settle(reservation, reported, offered, DatagramDirection::Download)
      }
      Err(error) => {
        drop(reservation);
        Err(error)
      }
    };
    drop(permit);
    result
  }

  /// Receives one datagram and its source address. A zero-length buffer still
  /// consumes one datagram; excess bytes are discarded by the kernel.
  pub async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    let (reservation, permit) = self.begin(&self.inner.download_rate, buffer.len()).await?;
    let offered = reservation.bytes();
    let result = match self.inner.socket.recv_from(buffer).await {
      Ok((reported, source)) => self
        .inner
        .settle(reservation, reported, offered, DatagramDirection::Download)
        .map(|count| (count, source)),
      Err(error) => {
        drop(reservation);
        Err(error)
      }
    };
    drop(permit);
    result
  }

  async fn send_inner(&self, datagram: &[u8], address: Option<SocketAddr>) -> io::Result<usize> {
    let (reservation, permit) = self.begin(&self.inner.upload_rate, datagram.len()).await?;
    let offered = reservation.bytes();
    let result = match address {
      Some(address) => self.inner.socket.send_to(datagram, address).await,
      None => self.inner.socket.send(datagram).await,
    };
    let result = match result {
      Ok(reported) => self
        .inner
        .settle(reservation, reported, offered, DatagramDirection::Upload),
      Err(error) => {
        drop(reservation);
        Err(error)
      }
    };
    drop(permit);
    result
  }

  async fn begin(
    &self,
    bucket: &ByteRateLimit,
    offered: usize,
  ) -> io::Result<(ByteReservation, OperationPermit)> {
    if let Some(error) = self.inner.ready_error() {
      return Err(error);
    }
    let reservation = self.inner.reserve_exact(bucket, offered).await?;
    if let Some(error) = self.inner.ready_error() {
      drop(reservation);
      return Err(error);
    }
    let permit = self
      .inner
      .resources
      .try_acquire(NETWORK_OPERATION)
      .map_err(resource_error)?;
    Ok((reservation, permit))
  }
}

impl fmt::Debug for RateLimitedUdp {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("RateLimitedUdp")
      .field("inner", &self.inner)
      .finish()
  }
}

impl Inner {
  fn fault(&self) -> Option<RateDatagramFailure> {
    lock_fault(&self.fault).as_ref().copied()
  }

  fn latch_fault(&self, failure: RateDatagramFailure) -> RateDatagramFailure {
    let mut fault = lock_fault(&self.fault);
    if let Some(previous) = *fault {
      previous
    } else {
      *fault = Some(failure);
      failure
    }
  }

  fn ready_error(&self) -> Option<io::Error> {
    if let Some(failure) = self.fault() {
      return Some(failure.into_io_error());
    }
    runtime_clock_failure(&self.timer).map(|failure| {
      if failure.is_sticky() {
        self.latch_fault(failure)
      } else {
        failure
      }
      .into_io_error()
    })
  }

  async fn reserve_exact(
    &self,
    bucket: &ByteRateLimit,
    bytes: usize,
  ) -> io::Result<ByteReservation> {
    let mut immediate_expirations = 0_u8;
    loop {
      if let Some(error) = self.ready_error() {
        return Err(error);
      }
      match bucket.try_reserve(bytes) {
        Ok(reservation) => return Ok(reservation),
        Err(ByteRateError::Insufficient(wait)) => {
          let start = self.timer.now();
          let wait = if wait.is_zero() {
            Duration::from_nanos(1)
          } else {
            wait
          };
          let deadline = start
            .checked_add(wait)
            .ok_or_else(|| RateDatagramFailure::DeadlineOutOfRange.into_io_error())?;
          let sleep = self
            .timer
            .sleep_until(deadline)
            .map_err(|error| self.timer_error(error))?;
          if sleep.is_elapsed() {
            immediate_expirations = immediate_expirations.saturating_add(1);
            if immediate_expirations > 1 {
              return Err(RateDatagramFailure::WakeUnavailable.into_io_error());
            }
            continue;
          }
          sleep.await.map_err(|error| self.timer_error(error))?;
          immediate_expirations = 0;
        }
        Err(error) => return Err(RateDatagramFailure::ByteRate(error).into_io_error()),
      }
    }
  }

  fn settle(
    &self,
    reservation: ByteReservation,
    reported: usize,
    offered: usize,
    direction: DatagramDirection,
  ) -> io::Result<usize> {
    if reported > offered {
      commit_full(reservation, offered);
      #[cfg(feature = "resource-feedback")]
      if let Some(feedback) = &self.feedback {
        feedback.invalidate_all();
      }
      let failure = self.latch_fault(match direction {
        DatagramDirection::Download => {
          RateDatagramFailure::InvalidReceiveCount { reported, offered }
        }
        DatagramDirection::Upload => RateDatagramFailure::InvalidSendCount { reported, offered },
      });
      return Err(failure.into_io_error());
    }

    match reservation.commit(reported) {
      Ok(()) => {
        #[cfg(feature = "resource-feedback")]
        if reported != 0
          && let Some(feedback) = &self.feedback
        {
          let meter = feedback.meter(direction);
          match u64::try_from(reported) {
            Ok(bytes) => meter.record_completion(bytes),
            Err(_) => meter.mark_invalid_io(),
          }
        }
        Ok(reported)
      }
      Err((_error, reservation)) => {
        commit_full(reservation, offered);
        #[cfg(feature = "resource-feedback")]
        if let Some(feedback) = &self.feedback {
          feedback.invalidate_all();
        }
        let failure = self.latch_fault(RateDatagramFailure::ReservationCommit);
        Err(failure.into_io_error())
      }
    }
  }

  fn timer_error(&self, error: TimerError) -> io::Error {
    let failure = RateDatagramFailure::Timer(error);
    if failure.is_sticky() {
      self.latch_fault(failure).into_io_error()
    } else {
      failure.into_io_error()
    }
  }
}

fn lock_fault(
  fault: &Mutex<Option<RateDatagramFailure>>,
) -> MutexGuard<'_, Option<RateDatagramFailure>> {
  fault.lock().unwrap_or_else(PoisonError::into_inner)
}

fn commit_full(reservation: ByteReservation, offered: usize) {
  match reservation.commit(offered) {
    Ok(()) => {}
    Err((_error, reservation)) => drop(reservation),
  }
}

fn runtime_clock_failure(timer: &TimerHandle) -> Option<RateDatagramFailure> {
  let _ = timer.now();
  if timer.is_clock_saturated() {
    Some(RateDatagramFailure::ClockSaturated)
  } else if !timer.is_realtime() || timer.mode() != ClockMode::Real {
    Some(RateDatagramFailure::NotRealTimeClock)
  } else if timer.is_closed() {
    Some(RateDatagramFailure::Timer(TimerError::Closed))
  } else {
    None
  }
}

fn timer_build_failure(timer: &TimerHandle) -> Option<RateDatagramBuildFailure> {
  let _ = timer.now();
  if timer.is_clock_saturated() {
    Some(RateDatagramBuildFailure::ClockSaturated)
  } else if !timer.is_realtime() || timer.mode() != ClockMode::Real {
    Some(RateDatagramBuildFailure::NotRealTimeClock)
  } else if timer.is_closed() {
    Some(RateDatagramBuildFailure::TimerClosed)
  } else {
    None
  }
}

fn resource_error(error: ResourceError) -> io::Error {
  let kind = match error {
    ResourceError::Invalid(ResourceKind::Network) => ErrorKind::InvalidInput,
    ResourceError::Exhausted(ResourceKind::Network) => ErrorKind::WouldBlock,
    ResourceError::OutOfMemory => ErrorKind::OutOfMemory,
    ResourceError::Closed => ErrorKind::BrokenPipe,
    ResourceError::DomainControlExhausted => ErrorKind::WouldBlock,
    ResourceError::DomainAdmission => ErrorKind::Other,
    ResourceError::Invalid(_) | ResourceError::Exhausted(_) | ResourceError::Shared => {
      ErrorKind::Other
    }
  };
  io::Error::new(kind, error)
}

#[cfg(test)]
#[path = "rate_datagram_tests.rs"]
mod tests;
