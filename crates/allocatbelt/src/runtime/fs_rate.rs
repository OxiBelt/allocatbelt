//! Admission immediately before owned filesystem byte I/O.

#![forbid(unsafe_code)]

use std::io;
use std::sync::Arc;
use std::time::Duration;

use super::super::byte_rate::{ByteRateError, ByteRateLimit, ByteReservation};
use super::super::job::CancellationToken;
use super::super::resource_domain::{ControlCharge, DomainError, TenantDomain};
#[cfg(feature = "resource-feedback")]
use super::super::resource_feedback_meter::{IoFeedbackMeter, IoFeedbackRegistration};

#[cfg(test)]
#[path = "fs_rate_tests.rs"]
mod tests;

struct Inner {
  bucket: ByteRateLimit,
  #[cfg(feature = "resource-feedback")]
  meter: Option<IoFeedbackMeter>,
  #[cfg(feature = "resource-feedback")]
  _registration: Option<IoFeedbackRegistration>,
  _control: ControlCharge,
}

/// All configured handle clones and detached operations share one owner.
#[derive(Clone)]
pub(super) struct FsRateControl(Arc<Inner>);

impl FsRateControl {
  pub(super) fn new(
    bucket: &ByteRateLimit,
    tenant: Option<&TenantDomain>,
    #[cfg(feature = "resource-feedback")] meter: Option<&IoFeedbackMeter>,
  ) -> Result<Self, DomainError> {
    let control = ControlCharge::try_new(tenant, std::mem::size_of::<Inner>())?;
    #[cfg(feature = "resource-feedback")]
    let registration = meter.map(IoFeedbackMeter::register_source);
    Ok(Self(Arc::new(Inner {
      bucket: bucket.clone(),
      #[cfg(feature = "resource-feedback")]
      meter: meter.cloned(),
      #[cfg(feature = "resource-feedback")]
      _registration: registration,
      _control: control,
    })))
  }
}

/// Shared synchronous byte admission for owned blocking I/O on any executor.
///
/// Each call reserves immediately before its operation, waits on real time,
/// commits the reported prefix and refunds the unused offer. The operation
/// must report its actual byte count and transfer no bytes on an error.
/// Known shared metadata is charged once; caller-owned operation state,
/// allocator headers and worker stacks remain outside that charge.
#[derive(Clone)]
pub struct BlockingByteIo(FsRateControl);

impl BlockingByteIo {
  /// Creates a shared byte policy, retaining its bucket through final clones.
  pub fn new(bucket: &ByteRateLimit, tenant: Option<&TenantDomain>) -> Result<Self, DomainError> {
    FsRateControl::new(
      bucket,
      tenant,
      #[cfg(feature = "resource-feedback")]
      None,
    )
    .map(Self)
  }

  /// Creates the same policy with one completion-meter source registration.
  #[cfg(feature = "resource-feedback")]
  pub fn new_metered(
    bucket: &ByteRateLimit,
    tenant: Option<&TenantDomain>,
    meter: &IoFeedbackMeter,
  ) -> Result<Self, DomainError> {
    FsRateControl::new(bucket, tenant, Some(meter)).map(Self)
  }

  /// Executes one byte operation after admission, retaining credit while it runs.
  /// Cancellation is checked before waiting and before operation entry. Running
  /// syscalls are not interrupted. A panic spends the full offer conservatively.
  pub fn run(
    &self,
    maximum: usize,
    is_cancelled: impl FnMut() -> bool,
    operation: impl FnOnce(usize) -> io::Result<usize>,
  ) -> io::Result<usize> {
    limited_io_cancel_with_wait(
      Some(&self.0),
      maximum,
      is_cancelled,
      operation,
      std::thread::sleep,
    )
  }
}

/// Runs one byte syscall. No rate state or measurement work when unconfigured.
pub(super) fn limited_io(
  rate: Option<&FsRateControl>,
  maximum: usize,
  token: &CancellationToken,
  operation: impl FnOnce(usize) -> io::Result<usize>,
) -> io::Result<usize> {
  limited_io_with_wait(rate, maximum, token, operation, std::thread::sleep)
}

fn limited_io_with_wait(
  rate: Option<&FsRateControl>,
  maximum: usize,
  token: &CancellationToken,
  operation: impl FnOnce(usize) -> io::Result<usize>,
  wait_for_credit: impl FnMut(Duration),
) -> io::Result<usize> {
  limited_io_cancel_with_wait(
    rate,
    maximum,
    || token.is_cancelled(),
    operation,
    wait_for_credit,
  )
}

fn limited_io_cancel_with_wait(
  rate: Option<&FsRateControl>,
  maximum: usize,
  mut is_cancelled: impl FnMut() -> bool,
  operation: impl FnOnce(usize) -> io::Result<usize>,
  mut wait_for_credit: impl FnMut(Duration),
) -> io::Result<usize> {
  let Some(rate) = rate else {
    return operation(maximum);
  };
  let reservation = loop {
    if is_cancelled() {
      return Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "filesystem byte admission cancelled",
      ));
    }
    match rate.0.bucket.try_reserve_up_to(maximum) {
      Ok(reservation) => break reservation,
      Err(ByteRateError::Insufficient(wait)) => {
        // The blocking closure retains its CPU/operation/storage owners while
        // waiting. This is conservative concurrency accounting, not CPU usage.
        wait_for_credit(wait.min(Duration::from_millis(10)));
      }
      Err(error) => return Err(io::Error::new(io::ErrorKind::WouldBlock, error)),
    }
  };
  let offered = reservation.bytes();
  if is_cancelled() {
    return Err(io::Error::new(
      io::ErrorKind::Interrupted,
      "filesystem byte admission cancelled",
    ));
  }
  let mut guarded = PanicOffer {
    reservation: Some(reservation),
    #[cfg(feature = "resource-feedback")]
    meter: rate.0.meter.as_ref(),
    #[cfg(not(feature = "resource-feedback"))]
    _lifetime: std::marker::PhantomData,
  };
  let count = match operation(offered) {
    Ok(count) => count,
    Err(error) => {
      // A normal error guarantees no transfer even if this call is made by
      // a destructor during an unrelated unwind. Disarm before returning.
      drop(guarded.reservation.take());
      return Err(error);
    }
  };
  let reservation = guarded
    .reservation
    .take()
    .unwrap_or_else(|| unreachable!("byte offer was consumed"));
  if count > offered {
    // An invalid completion cannot mint credit. Spend the complete offer and
    // invalidate telemetry; never infer the endpoint's actual byte count.
    let _ = reservation.commit(offered);
    #[cfg(feature = "resource-feedback")]
    if let Some(meter) = &rate.0.meter {
      meter.mark_invalid_io();
    }
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "filesystem completion exceeded the byte offer",
    ));
  }
  reservation
    .commit(count)
    .map_err(|(error, _)| io::Error::new(io::ErrorKind::InvalidData, error))?;
  #[cfg(feature = "resource-feedback")]
  if count != 0
    && let Some(meter) = &rate.0.meter
  {
    meter.record_completion(count as u64);
  }
  Ok(count)
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
    if std::thread::panicking()
      && let Some(reservation) = self.reservation.take()
    {
      let offered = reservation.bytes();
      let _ = reservation.commit(offered);
      #[cfg(feature = "resource-feedback")]
      if let Some(meter) = self.meter {
        meter.mark_invalid_io();
      }
    }
  }
}

/// A rate-selected copy charges both its reads and writes. Metadata does not
/// consume application-byte credit. The caller owns the managed scratch space.
pub(super) fn copy_file(
  from: &std::path::Path,
  to: &std::path::Path,
  scratch: &mut [u8],
  rate: &FsRateControl,
  token: &CancellationToken,
) -> io::Result<u64> {
  use std::io::{Read, Write};
  if scratch.is_empty() {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "copy scratch is empty",
    ));
  }
  if token.is_cancelled() {
    return Err(io::ErrorKind::Interrupted.into());
  }
  let mut source = std::fs::File::open(from)?;
  let metadata = source.metadata()?;
  if !metadata.is_file() {
    return Err(io::Error::new(
      io::ErrorKind::InvalidInput,
      "copy source is not a regular file",
    ));
  }
  let mut destination = open_copy_destination(to, &metadata.permissions())?;
  if destination.metadata()?.is_file() {
    destination.set_permissions(metadata.permissions())?;
  }
  let mut copied = 0_u64;
  loop {
    let read = match limited_io(Some(rate), scratch.len(), token, |offered| {
      source.read(&mut scratch[..offered])
    }) {
      Err(error) if error.kind() == io::ErrorKind::Interrupted && !token.is_cancelled() => continue,
      result => result?,
    };
    if read == 0 {
      return Ok(copied);
    }
    let mut written = 0;
    while written < read {
      let count = match limited_io(Some(rate), read - written, token, |offered| {
        destination.write(&scratch[written..written + offered])
      }) {
        Err(error) if error.kind() == io::ErrorKind::Interrupted && !token.is_cancelled() => {
          continue;
        }
        result => result?,
      };
      if count == 0 {
        return Err(io::ErrorKind::WriteZero.into());
      }
      written += count;
      copied = copied
        .checked_add(count as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "copy byte count overflow"))?;
    }
  }
}

fn open_copy_destination(
  path: &std::path::Path,
  permissions: &std::fs::Permissions,
) -> io::Result<std::fs::File> {
  let mut options = std::fs::OpenOptions::new();
  options.write(true).create(true).truncate(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    options.mode(permissions.mode());
  }
  options.open(path)
}
