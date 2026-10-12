//! Bounded application-byte admission using real monotonic time.
//!
//! Reserve before starting I/O. A reservation owns its bucket and refunds
//! unused bytes on cancellation or partial completion. Bytes committed by a
//! syscall remain spent. This limits application bytes, not physical traffic.
//! [`ByteRateLimit::new_in_tenant`] charges the declared shared State payload
//! to the tenant's Control limit; legacy [`ByteRateLimit::new`] is uncharged.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::resource_domain::{ControlCharge, DomainError, TenantDomain};

const NANOS: u128 = 1_000_000_000;

/// Finite hard ceilings and reservation storage bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRateConfig {
  /// Initial and maximum replenishment in application bytes per second.
  pub bytes_per_second: u64,
  /// Initial and maximum burst in application bytes.
  pub burst_bytes: usize,
  /// Maximum simultaneously retained reservation owners.
  pub max_reservations: usize,
}

/// Why byte admission or a configuration change was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ByteRateError {
  /// Zero bounds or a reservation-byte bound that overflows.
  InvalidConfig,
  /// The request cannot fit even in a full bucket. Datagrams are not split.
  Oversized,
  /// All bounded reservation entries are in use.
  ReservationsFull,
  /// Insufficient tokens; wait before submitting any I/O.
  Insufficient(Duration),
  /// A change would exceed the construction-time ceiling.
  AboveCeiling,
  /// A claimed completion exceeds the original reservation.
  Overcommitted,
  /// The tenant domain could not admit this bucket's bounded metadata.
  Domain(DomainError),
}

impl fmt::Display for ByteRateError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "byte-rate operation refused: {self:?}")
  }
}

impl std::error::Error for ByteRateError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Domain(error) => Some(error),
      _ => None,
    }
  }
}

/// A coherent snapshot taken under the bucket lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ByteRateSnapshot {
  /// Current replenishment rate in application bytes per second.
  pub bytes_per_second: u64,
  /// Current burst capacity in application bytes.
  pub burst_bytes: usize,
  /// Construction-time maximum replenishment rate.
  pub ceiling_bytes_per_second: u64,
  /// Construction-time maximum burst capacity.
  pub ceiling_burst_bytes: usize,
  /// Construction-time maximum number of simultaneous reservation owners.
  pub max_reservations: usize,
  /// Tokens currently available for admission.
  pub available_bytes: usize,
  /// Bytes held by live reservation owners.
  pub reserved_bytes: usize,
  /// Live reservation owners; distinct from the configured maximum.
  pub reservations: usize,
}

struct State {
  ceilings: ByteRateConfig,
  rate: u64,
  burst: usize,
  available: usize,
  carry: u64,
  reserved: usize,
  reservations: usize,
  last: Instant,
  _control: ControlCharge,
}

impl State {
  fn refill(&mut self, now: Instant) {
    let Some(elapsed) = now.checked_duration_since(self.last) else {
      return;
    };
    self.last = now;
    let missing = self.burst - self.available;
    if missing == 0 {
      self.carry = 0;
      return;
    }
    let total = elapsed
      .as_nanos()
      .checked_mul(u128::from(self.rate))
      .and_then(|value| value.checked_add(u128::from(self.carry)));
    let Some(total) = total else {
      self.available = self.burst;
      self.carry = 0;
      return;
    };
    let whole = total / NANOS;
    if whole >= missing as u128 {
      self.available = self.burst;
      self.carry = 0;
    } else {
      self.available += whole as usize;
      self.carry = (total % NANOS) as u64;
    }
  }

  fn refund(&mut self, reserved: usize, unused: usize) {
    self.reserved -= reserved;
    self.reservations -= 1;
    self.available += unused.min(self.burst - self.available);
    if self.available == self.burst {
      self.carry = 0;
    }
  }
}

fn validate_config(config: ByteRateConfig) -> Result<(), ByteRateError> {
  if config.bytes_per_second == 0
    || config.burst_bytes == 0
    || config.max_reservations == 0
    || config
      .burst_bytes
      .checked_mul(config.max_reservations)
      .is_none()
  {
    Err(ByteRateError::InvalidConfig)
  } else {
    Ok(())
  }
}

/// A clonable bucket with no unbounded waiter queue.
#[derive(Clone)]
pub struct ByteRateLimit {
  shared: Arc<Mutex<State>>,
}

impl fmt::Debug for ByteRateLimit {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ByteRateLimit")
      .field("snapshot", &self.snapshot())
      .finish()
  }
}

impl ByteRateLimit {
  /// Creates a full bucket and fixes its hard ceilings.
  pub fn new(config: ByteRateConfig) -> Result<Self, ByteRateError> {
    validate_config(config)?;
    let control = ControlCharge::unbounded(std::mem::size_of::<State>());
    Ok(Self::with_control(config, control))
  }

  /// Creates a full bucket charged to `tenant`'s Control limit until the
  /// bucket and every outstanding reservation release its shared state.
  pub fn new_in_tenant(
    config: ByteRateConfig,
    tenant: &TenantDomain,
  ) -> Result<Self, ByteRateError> {
    validate_config(config)?;
    let control = ControlCharge::try_new(Some(tenant), std::mem::size_of::<State>())
      .map_err(ByteRateError::Domain)?;
    Ok(Self::with_control(config, control))
  }

  fn with_control(config: ByteRateConfig, control: ControlCharge) -> Self {
    Self {
      shared: Arc::new(Mutex::new(State {
        ceilings: config,
        rate: config.bytes_per_second,
        burst: config.burst_bytes,
        available: config.burst_bytes,
        carry: 0,
        reserved: 0,
        reservations: 0,
        last: Instant::now(),
        _control: control,
      })),
    }
  }

  /// Reserves exactly `bytes` before an operation. A zero-length request
  /// owns no reservation entry. Larger datagrams must be recovered intact.
  pub fn try_reserve(&self, bytes: usize) -> Result<ByteReservation, ByteRateError> {
    self.reserve_at(bytes, Instant::now())
  }

  /// Reserves available credit up to `maximum` for partial stream progress.
  /// Refills under the lock before choosing the size. This deliberately
  /// clamps to available credit rather than splitting an exact datagram;
  /// datagrams must continue using [`try_reserve`](Self::try_reserve).
  pub fn try_reserve_up_to(&self, maximum: usize) -> Result<ByteReservation, ByteRateError> {
    if maximum == 0 {
      return Ok(ByteReservation {
        shared: None,
        bytes: 0,
      });
    }
    let mut state = self
      .shared
      .lock()
      .unwrap_or_else(|error| error.into_inner());
    if state.reservations == state.ceilings.max_reservations {
      return Err(ByteRateError::ReservationsFull);
    }
    state.refill(Instant::now());
    let bytes = maximum.min(state.available);
    if bytes == 0 {
      let needed = NANOS - u128::from(state.carry);
      let nanos = needed.div_ceil(u128::from(state.rate));
      return Err(ByteRateError::Insufficient(Duration::new(
        (nanos / NANOS) as u64,
        (nanos % NANOS) as u32,
      )));
    }
    state.available -= bytes;
    state.reserved += bytes;
    state.reservations += 1;
    Ok(ByteReservation {
      shared: Some(Arc::clone(&self.shared)),
      bytes,
    })
  }

  fn reserve_at(&self, bytes: usize, now: Instant) -> Result<ByteReservation, ByteRateError> {
    let mut state = self
      .shared
      .lock()
      .unwrap_or_else(|error| error.into_inner());
    if bytes > state.burst {
      return Err(ByteRateError::Oversized);
    }
    if bytes == 0 {
      return Ok(ByteReservation {
        shared: None,
        bytes: 0,
      });
    }
    if state.reservations == state.ceilings.max_reservations {
      return Err(ByteRateError::ReservationsFull);
    }
    state.refill(now);
    if bytes > state.available {
      let needed =
        ((bytes - state.available) as u128 * NANOS).saturating_sub(u128::from(state.carry));
      let nanos = needed.div_ceil(u128::from(state.rate));
      let wait = Duration::new((nanos / NANOS) as u64, (nanos % NANOS) as u32);
      return Err(ByteRateError::Insufficient(wait));
    }
    state.available -= bytes;
    state.reserved += bytes;
    state.reservations += 1;
    Ok(ByteReservation {
      shared: Some(Arc::clone(&self.shared)),
      bytes,
    })
  }

  /// Advances at the old rate, then applies finite limits no greater than
  /// construction-time ceilings. Increasing a burst never creates tokens.
  pub fn set_limits(&self, bytes_per_second: u64, burst_bytes: usize) -> Result<(), ByteRateError> {
    self.set_limits_at(bytes_per_second, burst_bytes, Instant::now())
  }

  /// Changes only the rate when it still matches `expected`, preserving the
  /// current burst and outstanding reservations. A stale writer changes
  /// nothing, including stored refill balances. Feedback uses this operation
  /// to avoid overwriting a concurrent controller's rate or burst update.
  pub fn compare_exchange_rate(&self, expected: u64, desired: u64) -> Result<bool, ByteRateError> {
    let mut state = self
      .shared
      .lock()
      .unwrap_or_else(|error| error.into_inner());
    if state.rate != expected {
      return Ok(false);
    }
    if desired == 0 {
      return Err(ByteRateError::InvalidConfig);
    }
    if desired > state.ceilings.bytes_per_second {
      return Err(ByteRateError::AboveCeiling);
    }
    state.refill(Instant::now());
    state.rate = desired;
    state.carry = 0;
    Ok(true)
  }

  fn set_limits_at(&self, rate: u64, burst: usize, now: Instant) -> Result<(), ByteRateError> {
    let mut state = self
      .shared
      .lock()
      .unwrap_or_else(|error| error.into_inner());
    if rate == 0 || burst == 0 {
      return Err(ByteRateError::InvalidConfig);
    }
    if rate > state.ceilings.bytes_per_second || burst > state.ceilings.burst_bytes {
      return Err(ByteRateError::AboveCeiling);
    }
    state.refill(now);
    state.rate = rate;
    state.burst = burst;
    state.available = state.available.min(burst);
    state.carry = 0;
    Ok(())
  }

  /// Observes stored balances without advancing the clock.
  pub fn snapshot(&self) -> ByteRateSnapshot {
    let state = self
      .shared
      .lock()
      .unwrap_or_else(|error| error.into_inner());
    ByteRateSnapshot {
      bytes_per_second: state.rate,
      burst_bytes: state.burst,
      ceiling_bytes_per_second: state.ceilings.bytes_per_second,
      ceiling_burst_bytes: state.ceilings.burst_bytes,
      max_reservations: state.ceilings.max_reservations,
      available_bytes: state.available,
      reserved_bytes: state.reserved,
      reservations: state.reservations,
    }
  }
}

/// Owned admission retained through actual I/O completion. Drop refunds all
/// reserved bytes; after partial progress settle before losing this owner.
#[must_use = "retain until I/O completes, then commit the actual byte count"]
pub struct ByteReservation {
  shared: Option<Arc<Mutex<State>>>,
  bytes: usize,
}

impl fmt::Debug for ByteReservation {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ByteReservation")
      .field("bytes", &self.bytes)
      .finish_non_exhaustive()
  }
}

impl ByteReservation {
  /// Original admission size.
  pub fn bytes(&self) -> usize {
    self.bytes
  }

  /// Commits an actual completion and refunds the unwritten/unread suffix.
  /// Refusal preserves ownership so the caller can supply the correct count.
  pub fn commit(mut self, used: usize) -> Result<(), (ByteRateError, Self)> {
    if used > self.bytes {
      return Err((ByteRateError::Overcommitted, self));
    }
    if let Some(shared) = self.shared.take() {
      let mut state = shared.lock().unwrap_or_else(|error| error.into_inner());
      state.refund(self.bytes, self.bytes - used);
    }
    Ok(())
  }
}

impl Drop for ByteReservation {
  fn drop(&mut self) {
    if let Some(shared) = self.shared.take() {
      let mut state = shared.lock().unwrap_or_else(|error| error.into_inner());
      state.refund(self.bytes, self.bytes);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};

  fn bucket(rate: u64, burst: usize, entries: usize) -> ByteRateLimit {
    ByteRateLimit::new(ByteRateConfig {
      bytes_per_second: rate,
      burst_bytes: burst,
      max_reservations: entries,
    })
    .unwrap()
  }

  #[test]
  fn tenant_bucket_charge_survives_clones_and_final_reservation() {
    let limits = DomainResources::ZERO.with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(limits, 1, 0).unwrap();
    let tenant = domain.tenant(limits).unwrap();
    let before = domain.snapshot().used.get(DomainResource::Control);
    let state_bytes = std::mem::size_of::<State>();
    let limit = ByteRateLimit::new_in_tenant(
      ByteRateConfig {
        bytes_per_second: 10,
        burst_bytes: 32,
        max_reservations: 2,
      },
      &tenant,
    )
    .unwrap();
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      before + state_bytes
    );

    let clone = limit.clone();
    let reservation = clone.try_reserve(8).unwrap();
    drop(limit);
    drop(clone);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      before + state_bytes
    );
    drop(reservation);
    assert_eq!(domain.snapshot().used.get(DomainResource::Control), before);
  }

  #[test]
  fn tenant_bucket_control_rejection_precedes_shared_allocation() {
    let limits = DomainResources::ZERO.with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(limits, 1, 0).unwrap();
    let tenant = domain.tenant(limits).unwrap();
    let before = domain.snapshot().used.get(DomainResource::Control);
    let invalid = ByteRateConfig {
      bytes_per_second: 0,
      burst_bytes: 32,
      max_reservations: 2,
    };
    assert_eq!(
      ByteRateLimit::new_in_tenant(invalid, &tenant).map(drop),
      Err(ByteRateError::InvalidConfig)
    );
    tenant
      .set_limits(DomainResources::ZERO.with(DomainResource::Control, 0))
      .unwrap();
    assert!(matches!(
      ByteRateLimit::new_in_tenant(
        ByteRateConfig {
          bytes_per_second: 10,
          burst_bytes: 32,
          max_reservations: 2,
        },
        &tenant
      ),
      Err(ByteRateError::Domain(DomainError::Exhausted(
        DomainResource::Control
      )))
    ));
    assert_eq!(domain.snapshot().used.get(DomainResource::Control), before);
  }

  #[test]
  fn partial_completion_drop_and_final_owner_retain_exact_charge() {
    let limit = bucket(10, 100, 2);
    let reservation = limit.try_reserve(60).unwrap();
    assert_eq!(limit.snapshot().reserved_bytes, 60);
    reservation.commit(25).unwrap();
    assert_eq!(limit.snapshot().available_bytes, 75);
    let other = limit.clone();
    let reservation = limit.try_reserve(20).unwrap();
    drop(limit);
    assert_eq!(other.snapshot().reserved_bytes, 20);
    drop(reservation);
    assert_eq!(other.snapshot().available_bytes, 75);
    assert_eq!(other.snapshot().reservations, 0);
  }

  #[test]
  fn bounded_entries_oversized_and_zero_admission() {
    let limit = bucket(1, 10, 1);
    let reservation = limit.try_reserve(1).unwrap();
    assert_eq!(
      limit.try_reserve(1).unwrap_err(),
      ByteRateError::ReservationsFull
    );
    limit.try_reserve(0).unwrap().commit(0).unwrap();
    assert_eq!(limit.try_reserve(11).unwrap_err(), ByteRateError::Oversized);
    assert_eq!(limit.snapshot().reservations, 1);
    drop(reservation);
    assert_eq!(limit.snapshot().available_bytes, 10);
  }

  #[test]
  fn fraction_and_clamp_never_retain_hidden_surplus() {
    let limit = bucket(3, 10, 2);
    let start = limit.shared.lock().unwrap().last;
    limit.reserve_at(10, start).unwrap().commit(10).unwrap();
    assert_eq!(
      limit
        .reserve_at(2, start + Duration::from_millis(500))
        .unwrap_err(),
      ByteRateError::Insufficient(Duration::from_nanos(166_666_667))
    );
    limit
      .reserve_at(3, start + Duration::from_secs(1))
      .unwrap()
      .commit(3)
      .unwrap();
    limit
      .reserve_at(10, start + Duration::from_secs(100))
      .unwrap()
      .commit(10)
      .unwrap();
    assert_eq!(
      limit
        .reserve_at(1, start + Duration::from_secs(100))
        .unwrap_err(),
      ByteRateError::Insufficient(Duration::from_nanos(333_333_334))
    );
  }

  #[test]
  fn reconfiguration_preserves_old_reservation_and_never_mints() {
    let limit = bucket(10, 100, 2);
    let start = limit.shared.lock().unwrap().last;
    let pending = limit.reserve_at(80, start).unwrap();
    limit.set_limits_at(1, 50, start).unwrap();
    assert_eq!(limit.snapshot().available_bytes, 20);
    drop(pending);
    assert_eq!(limit.snapshot().available_bytes, 50);
    limit.set_limits_at(10, 100, start).unwrap();
    assert_eq!(limit.snapshot().available_bytes, 50);
    assert_eq!(limit.set_limits(11, 100), Err(ByteRateError::AboveCeiling));
  }

  #[test]
  fn snapshot_keeps_construction_ceilings_and_reservation_cap_after_lowering() {
    let limit = bucket(10, 100, 3);
    let first = limit.try_reserve(10).unwrap();
    limit.set_limits(5, 60).unwrap();

    let lowered = limit.snapshot();
    assert_eq!(lowered.bytes_per_second, 5);
    assert_eq!(lowered.burst_bytes, 60);
    assert_eq!(lowered.ceiling_bytes_per_second, 10);
    assert_eq!(lowered.ceiling_burst_bytes, 100);
    assert_eq!(lowered.max_reservations, 3);
    assert_eq!(lowered.reservations, 1);

    let second = limit.try_reserve(10).unwrap();
    let third = limit.try_reserve(10).unwrap();
    let full = limit.snapshot();
    assert_eq!(full.max_reservations, 3);
    assert_eq!(full.reservations, 3);
    assert_eq!(
      limit.try_reserve(1).unwrap_err(),
      ByteRateError::ReservationsFull
    );

    drop((first, second, third));
    assert_eq!(limit.snapshot().reservations, 0);
  }

  #[test]
  fn overcommit_returns_live_reservation() {
    let limit = bucket(1, 10, 1);
    let reservation = limit.try_reserve(4).unwrap();
    let (error, reservation) = reservation.commit(5).unwrap_err();
    assert_eq!(error, ByteRateError::Overcommitted);
    assert_eq!(limit.snapshot().reserved_bytes, 4);
    reservation.commit(1).unwrap();
    assert_eq!(limit.snapshot().available_bytes, 9);
    assert_eq!(limit.snapshot().reserved_bytes, 0);
  }

  #[test]
  fn rate_compare_exchange_preserves_burst_and_rejects_stale_writers() {
    let limit = bucket(10, 100, 2);
    limit.set_limits(5, 50).unwrap();
    let before = limit.snapshot();
    assert_eq!(limit.compare_exchange_rate(10, 9), Ok(false));
    assert_eq!(limit.snapshot(), before);
    assert_eq!(
      limit.compare_exchange_rate(5, 11),
      Err(ByteRateError::AboveCeiling)
    );
    assert_eq!(limit.snapshot(), before);
    assert_eq!(
      limit.compare_exchange_rate(5, 0),
      Err(ByteRateError::InvalidConfig)
    );
    assert_eq!(limit.compare_exchange_rate(5, 7), Ok(true));
    assert_eq!(limit.snapshot().bytes_per_second, 7);
    assert_eq!(limit.snapshot().burst_bytes, 50);
  }

  #[test]
  fn concurrent_rate_writers_have_one_winner() {
    let limit = bucket(100, 10, 1);
    let first = limit.clone();
    let second = limit.clone();
    let first = std::thread::spawn(move || first.compare_exchange_rate(100, 80).unwrap());
    let second = std::thread::spawn(move || second.compare_exchange_rate(100, 90).unwrap());
    assert_ne!(first.join().unwrap(), second.join().unwrap());
    assert!(matches!(limit.snapshot().bytes_per_second, 80 | 90));
    assert_eq!(limit.snapshot().available_bytes, 10);
  }

  #[test]
  fn partial_stream_admission_clamps_to_available_credit_and_refunds_unused_bytes() {
    let limit = bucket(1, 10, 2);
    limit.try_reserve(7).unwrap().commit(7).unwrap();
    let partial = limit.try_reserve_up_to(usize::MAX).unwrap();
    assert_eq!(partial.bytes(), 3);
    assert_eq!(limit.snapshot().available_bytes, 0);
    partial.commit(1).unwrap();
    assert_eq!(limit.snapshot().available_bytes, 2);
    assert_eq!(limit.snapshot().reserved_bytes, 0);
  }

  #[test]
  fn exhausted_stream_credit_reports_one_byte_wait_and_zero_uses_no_entry() {
    let limit = bucket(1, 10, 1);
    limit.try_reserve(10).unwrap().commit(10).unwrap();
    let error = limit.try_reserve_up_to(4096).unwrap_err();
    assert!(
      matches!(error, ByteRateError::Insufficient(wait) if wait > Duration::ZERO && wait <= Duration::from_secs(1))
    );
    let zero = limit.try_reserve_up_to(0).unwrap();
    assert_eq!(zero.bytes(), 0);
    assert_eq!(limit.snapshot().reservations, 0);
  }
}
