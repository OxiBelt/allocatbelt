//! Admission immediately before owned filesystem byte I/O.

#![forbid(unsafe_code)]

use std::io;
use std::sync::Arc;
use std::time::Duration;

use super::super::byte_rate::{ByteRateError, ByteRateLimit};
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
  mut wait_for_credit: impl FnMut(Duration),
) -> io::Result<usize> {
  let Some(rate) = rate else {
    return operation(maximum);
  };
  let reservation = loop {
    if token.is_cancelled() {
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
  if token.is_cancelled() {
    return Err(io::Error::new(
      io::ErrorKind::Interrupted,
      "filesystem byte admission cancelled",
    ));
  }
  let count = operation(offered)?;
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
