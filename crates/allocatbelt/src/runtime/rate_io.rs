//! Real-time byte-rate limits for initialized asynchronous streams.
//!
//! [`RateLimitedIo`] charges application bytes accepted by one `AsyncRead` or
//! `AsyncWrite` call. Each nonempty poll reserves only the credit currently
//! available, capped by the configured burst, before polling the endpoint.
//! Partial completions commit their reported prefix; Pending, errors and EOF
//! refund unused credit. Rate waits use the supplied real-clock timer and do
//! not poll or retain the endpoint's input while waiting.
//! A panicking endpoint may already have transferred bytes. Unwinding spends
//! its complete offer conservatively and invalidates its directional telemetry.
//!
//! Vectored calls use the scalar trait fallback and offer only the first
//! nonempty slice. This keeps the adapter allocation-free and bounds each
//! endpoint call by the byte bucket's burst.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io::{self, ErrorKind, IoSlice, IoSliceMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use super::asynchronous::poll_cooperative_composed;
use super::byte_rate::{ByteRateError, ByteRateLimit, ByteReservation};
use super::io::{AsyncRead, AsyncWrite};
#[cfg(feature = "resource-feedback")]
use super::resource_feedback_meter::{IoFeedbackMeter, IoFeedbackRegistration};
use super::time::{ClockMode, Sleep, TimerError, TimerHandle};

#[cfg(feature = "resource-feedback")]
struct FeedbackMeters {
  read: IoFeedbackMeter,
  write: IoFeedbackMeter,
  _read_registration: IoFeedbackRegistration,
  _write_registration: IoFeedbackRegistration,
}

struct PanicOffer<'a> {
  reservation: Option<ByteReservation>,
  #[cfg(feature = "resource-feedback")]
  meter: Option<&'a IoFeedbackMeter>,
  #[cfg(not(feature = "resource-feedback"))]
  _lifetime: std::marker::PhantomData<&'a ()>,
}

impl Drop for PanicOffer<'_> {
  fn drop(&mut self) {
    let Some(reservation) = self.reservation.take() else {
      return;
    };
    if std::thread::panicking() {
      let offered = reservation.bytes();
      let _ = reservation.commit(offered);
      #[cfg(feature = "resource-feedback")]
      if let Some(meter) = self.meter {
        meter.mark_invalid_io();
      }
    }
  }
}

#[cfg(feature = "resource-feedback")]
impl FeedbackMeters {
  fn new(read: IoFeedbackMeter, write: IoFeedbackMeter) -> Self {
    let read_registration = read.register_source();
    let write_registration = write.register_source();
    Self {
      read,
      write,
      _read_registration: read_registration,
      _write_registration: write_registration,
    }
  }

  fn meter(&self, is_read: bool) -> &IoFeedbackMeter {
    if is_read { &self.read } else { &self.write }
  }
}

/// A terminal or transient failure specific to a rate-limited stream.
///
/// This value is stored as the payload of adapter-created `io::Error`s, so a
/// caller can inspect it with [`io::Error::get_ref`] and `downcast_ref`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RateIoFailure {
  /// The supplied timer is not an immutable real-time timer.
  NotRealTimeClock,
  /// The real monotonic clock reached the representable `Instant` boundary.
  ClockSaturated,
  /// A real-clock wait deadline could not be represented.
  DeadlineOutOfRange,
  /// The timer driver could not arm or complete a rate wait.
  Timer(TimerError),
  /// The bounded bucket could not admit a reservation.
  ByteRate(ByteRateError),
  /// A rate wait could not be kept armed without returning a wake-less Pending.
  WakeUnavailable,
  /// The read endpoint returned more bytes than the adapter offered.
  InvalidReadCount { reported: usize, offered: usize },
  /// The write endpoint reported more bytes accepted than the adapter offered.
  InvalidWriteCount { reported: usize, offered: usize },
  /// A reservation rejected a count already checked against its size.
  ReservationCommit,
}

impl RateIoFailure {
  fn error_kind(self) -> ErrorKind {
    match self {
      Self::InvalidReadCount { .. } | Self::InvalidWriteCount { .. } | Self::ReservationCommit => {
        ErrorKind::InvalidData
      }
      Self::NotRealTimeClock | Self::ClockSaturated | Self::DeadlineOutOfRange => {
        ErrorKind::InvalidInput
      }
      Self::Timer(TimerError::Full) | Self::ByteRate(ByteRateError::ReservationsFull) => {
        ErrorKind::WouldBlock
      }
      Self::WakeUnavailable => ErrorKind::WouldBlock,
      Self::Timer(TimerError::OutOfMemory) => ErrorKind::OutOfMemory,
      Self::Timer(TimerError::Closed) => ErrorKind::BrokenPipe,
      Self::Timer(TimerError::ClockSaturated | TimerError::Invalid) => ErrorKind::InvalidInput,
      Self::ByteRate(ByteRateError::Insufficient(_)) => ErrorKind::WouldBlock,
      Self::Timer(_) | Self::ByteRate(_) => ErrorKind::Other,
    }
  }

  fn is_sticky(self) -> bool {
    matches!(
      self,
      Self::NotRealTimeClock
        | Self::ClockSaturated
        | Self::DeadlineOutOfRange
        | Self::Timer(
          TimerError::Closed
            | TimerError::ClockSaturated
            | TimerError::Invalid
            | TimerError::DriverPanicked,
        )
        | Self::InvalidReadCount { .. }
        | Self::InvalidWriteCount { .. }
        | Self::ReservationCommit
    )
  }

  fn into_io_error(self) -> io::Error {
    io::Error::new(self.error_kind(), self)
  }
}

impl fmt::Display for RateIoFailure {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "rate-limited I/O failed: {self:?}")
  }
}

impl Error for RateIoFailure {}

/// The original inputs returned when construction rejects a non-real timer.
pub struct RateIoBuildError<T> {
  failure: RateIoFailure,
  inner: T,
  read_limit: ByteRateLimit,
  write_limit: ByteRateLimit,
  timer: TimerHandle,
}

impl<T> RateIoBuildError<T> {
  /// Why the adapter could not be constructed.
  #[must_use]
  pub const fn failure(&self) -> RateIoFailure {
    self.failure
  }

  /// Returns every original input unchanged.
  #[must_use]
  pub fn into_inputs(self) -> (T, ByteRateLimit, ByteRateLimit, TimerHandle) {
    (self.inner, self.read_limit, self.write_limit, self.timer)
  }
}

impl<T: fmt::Debug> fmt::Debug for RateIoBuildError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("RateIoBuildError")
      .field("failure", &self.failure)
      .field("inner", &self.inner)
      .finish_non_exhaustive()
  }
}

impl<T: fmt::Debug> fmt::Display for RateIoBuildError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "could not construct rate-limited I/O: {:?}",
      self.failure
    )
  }
}

impl<T: fmt::Debug> Error for RateIoBuildError<T> {}

/// Recoverable components from a rate-limited stream.
///
/// `into_adapter` resumes any rate-wait timer exactly where it was. Taking
/// only the components with `into_inputs` cancels adapter-owned sleeps and
/// releases optional feedback-meter source registrations; it does not alter
/// endpoint state or any endpoint-owned I/O waiter.
pub struct RateIoParts<T> {
  inner: T,
  read_limit: ByteRateLimit,
  write_limit: ByteRateLimit,
  timer: TimerHandle,
  read_wait: Option<Sleep>,
  write_wait: Option<Sleep>,
  failure: Option<RateIoFailure>,
  #[cfg(feature = "resource-feedback")]
  feedback: Option<FeedbackMeters>,
}

impl<T> RateIoParts<T> {
  /// Borrows the original endpoint.
  #[must_use]
  pub const fn inner(&self) -> &T {
    &self.inner
  }

  /// Borrows the read-direction bucket.
  #[must_use]
  pub const fn read_limit(&self) -> &ByteRateLimit {
    &self.read_limit
  }

  /// Borrows the write-direction bucket.
  #[must_use]
  pub const fn write_limit(&self) -> &ByteRateLimit {
    &self.write_limit
  }

  /// Borrows the explicit real-clock timer handle.
  #[must_use]
  pub const fn timer(&self) -> &TimerHandle {
    &self.timer
  }

  /// Returns the sticky adapter failure, if one was recorded.
  #[must_use]
  pub const fn failure(&self) -> Option<RateIoFailure> {
    self.failure
  }

  /// Rebuilds the adapter and retains any in-progress rate waits.
  #[must_use]
  pub fn into_adapter(self) -> RateLimitedIo<T> {
    RateLimitedIo {
      inner: self.inner,
      read_limit: self.read_limit,
      write_limit: self.write_limit,
      timer: self.timer,
      read_wait: self.read_wait,
      write_wait: self.write_wait,
      failure: self.failure,
      #[cfg(feature = "resource-feedback")]
      feedback: self.feedback,
    }
  }

  /// Returns the original endpoint, buckets and timer, cancelling adapter
  /// rate waits and releasing optional feedback-meter registrations.
  #[must_use]
  pub fn into_inputs(self) -> (T, ByteRateLimit, ByteRateLimit, TimerHandle) {
    (self.inner, self.read_limit, self.write_limit, self.timer)
  }

  /// Returns only the original endpoint. Endpoint-owned waiters and progress
  /// remain on it; adapter-owned rate timers and meter registrations are
  /// released.
  #[must_use]
  pub fn into_inner(self) -> T {
    self.inner
  }
}

impl<T: fmt::Debug> fmt::Debug for RateIoParts<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut debug = f.debug_struct("RateIoParts");
    debug
      .field("inner", &self.inner)
      .field("read_waiting", &self.read_wait.is_some())
      .field("write_waiting", &self.write_wait.is_some())
      .field("failure", &self.failure);
    #[cfg(feature = "resource-feedback")]
    debug.field("feedback_enabled", &self.feedback.is_some());
    debug.finish_non_exhaustive()
  }
}

/// A bidirectional stream with independent read and write byte buckets.
///
/// Construction requires a live immutable real-time [`TimerHandle`]. A
/// mutable or paused timer is rejected with every original input preserved.
/// Fixed real-time handles cannot be paused, so a timer wait remains a valid
/// wake source while credit is unavailable. The adapter does not self-wake or
/// poll the endpoint until admission succeeds.
pub struct RateLimitedIo<T> {
  inner: T,
  read_limit: ByteRateLimit,
  write_limit: ByteRateLimit,
  timer: TimerHandle,
  read_wait: Option<Sleep>,
  write_wait: Option<Sleep>,
  failure: Option<RateIoFailure>,
  #[cfg(feature = "resource-feedback")]
  feedback: Option<FeedbackMeters>,
}

impl<T> RateLimitedIo<T> {
  /// Creates a stream adapter with separate read and write buckets.
  ///
  /// A mutable-real, paused, saturated or closed timer is rejected while
  /// returning every original input through [`RateIoBuildError::into_inputs`].
  pub fn new(
    inner: T,
    read_limit: ByteRateLimit,
    write_limit: ByteRateLimit,
    timer: TimerHandle,
  ) -> Result<Self, RateIoBuildError<T>> {
    let failure = clock_failure(&timer);
    if let Some(failure) = failure {
      return Err(RateIoBuildError {
        failure,
        inner,
        read_limit,
        write_limit,
        timer,
      });
    }
    Ok(Self {
      inner,
      read_limit,
      write_limit,
      timer,
      read_wait: None,
      write_wait: None,
      failure: None,
      #[cfg(feature = "resource-feedback")]
      feedback: None,
    })
  }

  /// Borrows the original endpoint.
  #[must_use]
  pub const fn get_ref(&self) -> &T {
    &self.inner
  }

  /// Borrows the read-direction bucket.
  #[must_use]
  pub const fn read_limit(&self) -> &ByteRateLimit {
    &self.read_limit
  }

  /// Borrows the write-direction bucket.
  #[must_use]
  pub const fn write_limit(&self) -> &ByteRateLimit {
    &self.write_limit
  }

  /// Returns the sticky adapter failure, if one was recorded.
  #[must_use]
  pub const fn failure(&self) -> Option<RateIoFailure> {
    self.failure
  }

  /// Attaches separate read- and write-direction application-byte meters.
  /// Meter snapshots are usable while this adapter owns each direction's
  /// bounded source registration. Cloned meters may be shared by adapters.
  /// Updates count only validated successful completions after reservation
  /// commit.
  #[cfg(feature = "resource-feedback")]
  #[must_use]
  pub fn with_feedback_meters(mut self, read: IoFeedbackMeter, write: IoFeedbackMeter) -> Self {
    let feedback = FeedbackMeters::new(read, write);
    match self.failure {
      Some(RateIoFailure::InvalidReadCount { .. }) => feedback.read.mark_invalid_io(),
      Some(RateIoFailure::InvalidWriteCount { .. }) => feedback.write.mark_invalid_io(),
      Some(RateIoFailure::ReservationCommit) => {
        feedback.read.mark_invalid_io();
        feedback.write.mark_invalid_io();
      }
      _ => {}
    }
    self.feedback = Some(feedback);
    self
  }

  /// Recovers all components and keeps rate waits and optional meter
  /// registrations alive.
  #[must_use]
  pub fn into_parts(self) -> RateIoParts<T> {
    RateIoParts {
      inner: self.inner,
      read_limit: self.read_limit,
      write_limit: self.write_limit,
      timer: self.timer,
      read_wait: self.read_wait,
      write_wait: self.write_wait,
      failure: self.failure,
      #[cfg(feature = "resource-feedback")]
      feedback: self.feedback,
    }
  }

  /// Recovers only the endpoint. Its state and endpoint-owned I/O waiter are
  /// untouched; adapter-owned rate waits and meter registrations are released.
  #[must_use]
  pub fn into_inner(self) -> T {
    self.inner
  }

  fn clock_error(&mut self) -> Option<io::Error> {
    if self.failure.is_none()
      && let Some(failure) = clock_failure(&self.timer)
    {
      self.latch(failure);
    }
    self.failure.map(RateIoFailure::into_io_error)
  }

  fn latch(&mut self, failure: RateIoFailure) {
    if self.failure.is_none() && failure.is_sticky() {
      self.failure = Some(failure);
      self.read_wait = None;
      self.write_wait = None;
    }
  }

  fn poll_read_credit(
    &mut self,
    cx: &mut Context<'_>,
    maximum: usize,
  ) -> Poll<io::Result<ByteReservation>> {
    match poll_credit(
      &self.read_limit,
      &self.timer,
      &mut self.read_wait,
      maximum,
      cx,
    ) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Ok(reservation)) => Poll::Ready(Ok(reservation)),
      Poll::Ready(Err(failure)) => {
        self.latch(failure);
        Poll::Ready(Err(failure.into_io_error()))
      }
    }
  }

  fn poll_write_credit(
    &mut self,
    cx: &mut Context<'_>,
    maximum: usize,
  ) -> Poll<io::Result<ByteReservation>> {
    match poll_credit(
      &self.write_limit,
      &self.timer,
      &mut self.write_wait,
      maximum,
      cx,
    ) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Ok(reservation)) => Poll::Ready(Ok(reservation)),
      Poll::Ready(Err(failure)) => {
        self.latch(failure);
        Poll::Ready(Err(failure.into_io_error()))
      }
    }
  }

  fn commit_or_fault(
    &mut self,
    reservation: ByteReservation,
    used: usize,
    offered: usize,
    is_read: bool,
  ) -> Option<io::Error> {
    #[cfg(not(feature = "resource-feedback"))]
    let _ = is_read;
    match reservation.commit(used) {
      Ok(()) => None,
      Err((_failure, reservation)) => {
        // The returned count was checked against `offered`, which is the
        // reservation's size. If the bucket disagrees, spend the whole offer
        // conservatively so possibly transferred bytes cannot be replayed.
        match reservation.commit(offered) {
          Ok(()) => {}
          Err((_failure, reservation)) => drop(reservation),
        }
        self.latch(RateIoFailure::ReservationCommit);
        #[cfg(feature = "resource-feedback")]
        self.invalidate_feedback(is_read);
        Some(RateIoFailure::ReservationCommit.into_io_error())
      }
    }
  }

  #[cfg(feature = "resource-feedback")]
  fn record_feedback(&self, is_read: bool, bytes: usize) {
    if bytes == 0 {
      return;
    }
    if let Some(feedback) = &self.feedback {
      match u64::try_from(bytes) {
        Ok(bytes) => feedback.meter(is_read).record_completion(bytes),
        Err(_) => feedback.meter(is_read).mark_invalid_io(),
      }
    }
  }

  #[cfg(feature = "resource-feedback")]
  fn invalidate_feedback(&self, is_read: bool) {
    if let Some(feedback) = &self.feedback {
      feedback.meter(is_read).mark_invalid_io();
    }
  }
}

impl<T: AsyncRead + Unpin> AsyncRead for RateLimitedIo<T> {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    output: &mut [u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    poll_cooperative_composed(cx, |cx| {
      if let Some(error) = this.clock_error() {
        return Poll::Ready(Err(error));
      }
      if output.is_empty() {
        return Poll::Ready(Ok(0));
      }

      let maximum = output.len().min(this.read_limit.snapshot().burst_bytes);
      let reservation = match this.poll_read_credit(cx, maximum) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        Poll::Ready(Ok(reservation)) => reservation,
      };
      let offered = reservation.bytes();
      if let Some(error) = this.clock_error() {
        drop(reservation);
        return Poll::Ready(Err(error));
      }

      let mut guarded = PanicOffer {
        reservation: Some(reservation),
        #[cfg(feature = "resource-feedback")]
        meter: this.feedback.as_ref().map(|feedback| feedback.meter(true)),
        #[cfg(not(feature = "resource-feedback"))]
        _lifetime: std::marker::PhantomData,
      };
      let polled = Pin::new(&mut this.inner).poll_read(cx, &mut output[..offered]);
      // A normal return reports the transfer precisely, including when called
      // by a destructor during an unrelated unwind. Disarm before settling it.
      let reservation = guarded
        .reservation
        .take()
        .unwrap_or_else(|| unreachable!("byte offer was consumed"));
      drop(guarded);
      match polled {
        Poll::Pending => {
          drop(reservation);
          Poll::Pending
        }
        Poll::Ready(Err(error)) => {
          drop(reservation);
          Poll::Ready(Err(error))
        }
        Poll::Ready(Ok(reported)) if reported > offered => {
          match reservation.commit(offered) {
            Ok(()) => {}
            Err((_failure, reservation)) => drop(reservation),
          }
          let failure = RateIoFailure::InvalidReadCount { reported, offered };
          #[cfg(feature = "resource-feedback")]
          this.invalidate_feedback(true);
          this.latch(failure);
          Poll::Ready(Err(failure.into_io_error()))
        }
        Poll::Ready(Ok(reported)) => {
          match this.commit_or_fault(reservation, reported, offered, true) {
            Some(error) => Poll::Ready(Err(error)),
            None => {
              #[cfg(feature = "resource-feedback")]
              this.record_feedback(true, reported);
              Poll::Ready(Ok(reported))
            }
          }
        }
      }
    })
  }

  fn poll_read_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buffers: &mut [IoSliceMut<'_>],
  ) -> Poll<io::Result<usize>> {
    if let Some(buffer) = buffers.iter_mut().find(|buffer| !buffer.is_empty()) {
      self.poll_read(cx, buffer)
    } else {
      self.poll_read(cx, &mut [])
    }
  }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for RateLimitedIo<T> {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    input: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    poll_cooperative_composed(cx, |cx| {
      if let Some(error) = this.clock_error() {
        return Poll::Ready(Err(error));
      }
      if input.is_empty() {
        return Poll::Ready(Ok(0));
      }

      let maximum = input.len().min(this.write_limit.snapshot().burst_bytes);
      let reservation = match this.poll_write_credit(cx, maximum) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        Poll::Ready(Ok(reservation)) => reservation,
      };
      let offered = reservation.bytes();
      if let Some(error) = this.clock_error() {
        drop(reservation);
        return Poll::Ready(Err(error));
      }

      let mut guarded = PanicOffer {
        reservation: Some(reservation),
        #[cfg(feature = "resource-feedback")]
        meter: this.feedback.as_ref().map(|feedback| feedback.meter(false)),
        #[cfg(not(feature = "resource-feedback"))]
        _lifetime: std::marker::PhantomData,
      };
      let polled = Pin::new(&mut this.inner).poll_write(cx, &input[..offered]);
      let reservation = guarded
        .reservation
        .take()
        .unwrap_or_else(|| unreachable!("byte offer was consumed"));
      drop(guarded);
      match polled {
        Poll::Pending => {
          drop(reservation);
          Poll::Pending
        }
        Poll::Ready(Err(error)) => {
          drop(reservation);
          Poll::Ready(Err(error))
        }
        Poll::Ready(Ok(reported)) if reported > offered => {
          match reservation.commit(offered) {
            Ok(()) => {}
            Err((_failure, reservation)) => drop(reservation),
          }
          let failure = RateIoFailure::InvalidWriteCount { reported, offered };
          #[cfg(feature = "resource-feedback")]
          this.invalidate_feedback(false);
          this.latch(failure);
          Poll::Ready(Err(failure.into_io_error()))
        }
        Poll::Ready(Ok(reported)) => {
          match this.commit_or_fault(reservation, reported, offered, false) {
            Some(error) => Poll::Ready(Err(error)),
            None => {
              #[cfg(feature = "resource-feedback")]
              this.record_feedback(false, reported);
              Poll::Ready(Ok(reported))
            }
          }
        }
      }
    })
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buffers: &[IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    if let Some(buffer) = buffers.iter().find(|buffer| !buffer.is_empty()) {
      self.poll_write(cx, buffer)
    } else {
      self.poll_write(cx, &[])
    }
  }

  fn is_write_vectored(&self) -> bool {
    false
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    poll_cooperative_composed(cx, |cx| {
      if let Some(error) = this.clock_error() {
        return Poll::Ready(Err(error));
      }
      Pin::new(&mut this.inner).poll_flush(cx)
    })
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    poll_cooperative_composed(cx, |cx| {
      if let Some(error) = this.clock_error() {
        return Poll::Ready(Err(error));
      }
      Pin::new(&mut this.inner).poll_shutdown(cx)
    })
  }
}

fn clock_failure(timer: &TimerHandle) -> Option<RateIoFailure> {
  // `is_clock_saturated` reports the state observed by the last clock read.
  // Refresh it before admitting bytes or passing through control operations.
  let _ = timer.now();
  if timer.is_clock_saturated() {
    Some(RateIoFailure::ClockSaturated)
  } else if !timer.is_realtime() || timer.mode() != ClockMode::Real {
    Some(RateIoFailure::NotRealTimeClock)
  } else if timer.is_closed() {
    Some(RateIoFailure::Timer(TimerError::Closed))
  } else {
    None
  }
}

fn poll_credit(
  limit: &ByteRateLimit,
  timer: &TimerHandle,
  wait: &mut Option<Sleep>,
  maximum: usize,
  cx: &mut Context<'_>,
) -> Poll<Result<ByteReservation, RateIoFailure>> {
  let mut immediate_rechecks = 0;
  loop {
    if let Some(failure) = clock_failure(timer) {
      *wait = None;
      return Poll::Ready(Err(failure));
    }

    match limit.try_reserve_up_to(maximum) {
      Ok(reservation) => {
        *wait = None;
        return Poll::Ready(Ok(reservation));
      }
      Err(ByteRateError::Insufficient(delay)) => {
        if let Some(failure) = clock_failure(timer) {
          *wait = None;
          return Poll::Ready(Err(failure));
        }
        let now = timer.now();
        let Some(deadline) = now.checked_add(nonzero_delay(delay)) else {
          *wait = None;
          return Poll::Ready(Err(RateIoFailure::DeadlineOutOfRange));
        };

        let arm_result = if let Some(sleep) = wait.as_mut() {
          if sleep.deadline() == deadline {
            Ok(())
          } else {
            sleep.reset(deadline)
          }
        } else {
          match timer.sleep_until(deadline) {
            Ok(sleep) => {
              *wait = Some(sleep);
              Ok(())
            }
            Err(error) => Err(error),
          }
        };
        if let Err(error) = arm_result {
          *wait = None;
          return Poll::Ready(Err(RateIoFailure::Timer(error)));
        }

        if let Some(failure) = clock_failure(timer) {
          *wait = None;
          return Poll::Ready(Err(failure));
        }

        let Some(sleep) = wait.as_mut() else {
          return Poll::Ready(Err(RateIoFailure::WakeUnavailable));
        };
        match Pin::new(sleep).poll(cx) {
          Poll::Pending => return Poll::Pending,
          Poll::Ready(Err(error)) => {
            *wait = None;
            return Poll::Ready(Err(RateIoFailure::Timer(error)));
          }
          Poll::Ready(Ok(())) => {
            // A very short (for example, one-nanosecond) deadline can elapse
            // between arming and polling. Recheck credit once, then require a
            // newly registered future timer or return WouldBlock.
            immediate_rechecks += 1;
            if immediate_rechecks > 1 {
              *wait = None;
              return Poll::Ready(Err(RateIoFailure::WakeUnavailable));
            }
          }
        }
      }
      Err(error) => {
        *wait = None;
        return Poll::Ready(Err(RateIoFailure::ByteRate(error)));
      }
    }
  }
}

fn nonzero_delay(delay: Duration) -> Duration {
  if delay.is_zero() {
    Duration::from_nanos(1)
  } else {
    delay
  }
}

#[cfg(all(test, not(loom)))]
#[path = "rate_io_tests.rs"]
mod tests;
