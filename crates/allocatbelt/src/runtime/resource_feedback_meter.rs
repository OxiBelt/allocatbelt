//! Fixed-storage telemetry for committed application-byte stream progress.
//!
//! The meter observes bytes a wrapped stream endpoint reports as accepted.
//! It does not observe kernel disk traffic, wire traffic, datagrams, tenants,
//! latency, or tail pressure. Snapshot timestamps use real monotonic time and
//! describe the counter state captured under the same lock.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use super::resource_domain::{ControlCharge, DomainError, TenantDomain};

/// Latched meter diagnostics. Any set field makes a snapshot unusable for
/// feedback until the unattached meter is explicitly reset.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IoFeedbackDiagnostics {
  /// Cumulative application-byte or completion counters reached `u64::MAX`.
  pub counter_overflow: bool,
  /// An endpoint returned an invalid count or reservation settlement failed.
  pub invalid_io: bool,
  /// The bounded active-source counter reached `u32::MAX`.
  pub source_count_overflow: bool,
  /// The meter generation counter could not advance during reset.
  pub generation_overflow: bool,
}

impl IoFeedbackDiagnostics {
  /// Whether the meter has any latched diagnostic.
  #[must_use]
  pub const fn is_clear(self) -> bool {
    !self.counter_overflow
      && !self.invalid_io
      && !self.source_count_overflow
      && !self.generation_overflow
  }
}

/// A coherent snapshot of cumulative committed application bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoFeedbackMeterSnapshot {
  /// Real monotonic time captured immediately before copying the counters.
  pub measured_at: Instant,
  /// Cumulative bytes accepted by wrapped stream endpoints.
  pub committed_bytes: u64,
  /// Cumulative nonempty successful completions.
  pub completions: u64,
  /// Number of live endpoint-direction registrations, saturating at `u32::MAX`.
  pub attached_sources: u32,
  /// Changes only after a successful explicit reset.
  pub generation: u64,
  /// Latched quality diagnostics.
  pub diagnostics: IoFeedbackDiagnostics,
}

impl IoFeedbackMeterSnapshot {
  /// Whether the counter state is valid and at least one endpoint direction
  /// currently reports into this meter.
  #[must_use]
  pub const fn usable(self) -> bool {
    self.diagnostics.is_clear() && self.attached_sources != 0
  }
}

#[derive(Default)]
struct State {
  committed_bytes: u64,
  completions: u64,
  attached_sources: u32,
  generation: u64,
  diagnostics: IoFeedbackDiagnostics,
}

struct Shared {
  state: Mutex<State>,
  _control: ControlCharge,
}

fn lock_state(shared: &Shared) -> MutexGuard<'_, State> {
  shared.state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A cloneable, fixed-storage meter shared by one or more stream adapters.
///
/// Cloning shares the cumulative counters. Creating a meter allocates its
/// fixed state once; snapshots and updates never grow storage or call user
/// code while holding the state lock.
#[derive(Clone)]
pub struct IoFeedbackMeter {
  shared: Arc<Shared>,
}

impl IoFeedbackMeter {
  /// Creates an empty meter with no attached endpoint sources.
  #[must_use]
  pub fn new() -> Self {
    Self::with_control(ControlCharge::unbounded(std::mem::size_of::<Shared>()))
  }

  /// Creates an empty meter whose shared counter payload is charged to the
  /// tenant's Control limit until its final clone or endpoint registration
  /// drops.
  pub fn new_in_tenant(tenant: &TenantDomain) -> Result<Self, DomainError> {
    let control = ControlCharge::try_new(Some(tenant), std::mem::size_of::<Shared>())?;
    Ok(Self::with_control(control))
  }

  fn with_control(control: ControlCharge) -> Self {
    Self {
      shared: Arc::new(Shared {
        state: Mutex::new(State::default()),
        _control: control,
      }),
    }
  }

  /// Captures the counters, attachment count, diagnostics, and real monotonic
  /// measurement time under one lock acquisition.
  #[must_use]
  pub fn snapshot(&self) -> IoFeedbackMeterSnapshot {
    let state = lock_state(&self.shared);
    let measured_at = Instant::now();
    IoFeedbackMeterSnapshot {
      measured_at,
      committed_bytes: state.committed_bytes,
      completions: state.completions,
      attached_sources: state.attached_sources,
      generation: state.generation,
      diagnostics: state.diagnostics,
    }
  }

  pub(crate) fn same_meter(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.shared, &other.shared)
  }

  /// Clears cumulative counters and recoverable diagnostics after every
  /// endpoint-direction registration has ended. A new generation tells
  /// sensors to discard their previous baseline.
  pub fn reset(&self) -> Result<(), IoFeedbackResetError> {
    let mut state = lock_state(&self.shared);
    if state.diagnostics.source_count_overflow {
      return Err(IoFeedbackResetError::SourceCountOverflow);
    }
    if state.attached_sources != 0 {
      return Err(IoFeedbackResetError::SourcesAttached);
    }
    let Some(generation) = state.generation.checked_add(1) else {
      state.diagnostics.generation_overflow = true;
      return Err(IoFeedbackResetError::GenerationOverflow);
    };
    state.committed_bytes = 0;
    state.completions = 0;
    state.generation = generation;
    state.diagnostics = IoFeedbackDiagnostics::default();
    Ok(())
  }

  pub(crate) fn record_completion(&self, bytes: u64) {
    if bytes == 0 {
      return;
    }
    let mut state = lock_state(&self.shared);
    let next_bytes = state.committed_bytes.checked_add(bytes);
    let next_completions = state.completions.checked_add(1);
    match (next_bytes, next_completions) {
      (Some(committed_bytes), Some(completions)) => {
        state.committed_bytes = committed_bytes;
        state.completions = completions;
      }
      (committed_bytes, completions) => {
        state.committed_bytes = committed_bytes.unwrap_or(u64::MAX);
        state.completions = completions.unwrap_or(u64::MAX);
        state.diagnostics.counter_overflow = true;
      }
    }
  }

  pub(crate) fn mark_invalid_io(&self) {
    lock_state(&self.shared).diagnostics.invalid_io = true;
  }

  pub(crate) fn register_source(&self) -> IoFeedbackRegistration {
    let counted = {
      let mut state = lock_state(&self.shared);
      match state.attached_sources.checked_add(1) {
        Some(attached_sources) if !state.diagnostics.source_count_overflow => {
          state.attached_sources = attached_sources;
          true
        }
        _ => {
          state.diagnostics.source_count_overflow = true;
          false
        }
      }
    };
    IoFeedbackRegistration {
      shared: Arc::clone(&self.shared),
      counted,
    }
  }
}

impl Default for IoFeedbackMeter {
  fn default() -> Self {
    Self::new()
  }
}

impl fmt::Debug for IoFeedbackMeter {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_tuple("IoFeedbackMeter")
      .field(&self.snapshot())
      .finish()
  }
}

/// Why a meter reset could not establish a safe new cumulative baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IoFeedbackResetError {
  /// At least one adapter still reports into this meter.
  SourcesAttached,
  /// Active-source registration overflow made the source count unknowable.
  SourceCountOverflow,
  /// The generation counter reached its representable limit.
  GenerationOverflow,
}

impl fmt::Display for IoFeedbackResetError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "I/O feedback meter reset refused: {self:?}")
  }
}

impl std::error::Error for IoFeedbackResetError {}

/// A bounded RAII registration held by a rate-limited endpoint direction.
pub(crate) struct IoFeedbackRegistration {
  shared: Arc<Shared>,
  counted: bool,
}

impl fmt::Debug for IoFeedbackRegistration {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("IoFeedbackRegistration")
      .field("counted", &self.counted)
      .finish_non_exhaustive()
  }
}

impl Drop for IoFeedbackRegistration {
  fn drop(&mut self) {
    if !self.counted {
      return;
    }
    let mut state = lock_state(&self.shared);
    if let Some(attached_sources) = state.attached_sources.checked_sub(1) {
      state.attached_sources = attached_sources;
    } else {
      state.diagnostics.source_count_overflow = true;
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};

  #[test]
  fn tenant_charge_lives_through_meter_clones_and_final_registration() {
    let limits = DomainResources::ZERO.with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(limits, 1, 0).unwrap();
    let tenant = domain.tenant(limits).unwrap();
    let before = domain.snapshot().used.get(DomainResource::Control);
    let shared_bytes = std::mem::size_of::<Shared>();
    let meter = IoFeedbackMeter::new_in_tenant(&tenant).unwrap();
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      before + shared_bytes
    );

    let clone = meter.clone();
    let registration = meter.register_source();
    drop(meter);
    drop(clone);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      before + shared_bytes
    );
    drop(registration);
    assert_eq!(domain.snapshot().used.get(DomainResource::Control), before);
  }

  #[test]
  fn tenant_control_rejection_leaves_meter_unallocated() {
    let limits = DomainResources::ZERO.with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(limits, 1, 0).unwrap();
    let tenant = domain.tenant(limits).unwrap();
    tenant
      .set_limits(DomainResources::ZERO.with(DomainResource::Control, 0))
      .unwrap();
    let before = domain.snapshot().used.get(DomainResource::Control);
    assert_eq!(
      IoFeedbackMeter::new_in_tenant(&tenant).map(drop),
      Err(DomainError::Exhausted(DomainResource::Control))
    );
    assert_eq!(domain.snapshot().used.get(DomainResource::Control), before);
  }

  #[test]
  fn shared_sources_count_until_each_registration_drops() {
    let meter = IoFeedbackMeter::new();
    let first = meter.register_source();
    let second = meter.register_source();
    assert_eq!(meter.snapshot().attached_sources, 2);
    drop(first);
    assert_eq!(meter.snapshot().attached_sources, 1);
    drop(second);
    let snapshot = meter.snapshot();
    assert_eq!(snapshot.attached_sources, 0);
    assert!(!snapshot.usable());
  }

  #[test]
  fn reset_requires_detached_sources_and_clears_overflow_in_a_new_generation() {
    let meter = IoFeedbackMeter::new();
    let registration = meter.register_source();
    meter.record_completion(u64::MAX);
    meter.record_completion(1);
    let overflowed = meter.snapshot();
    assert_eq!(overflowed.committed_bytes, u64::MAX);
    assert_eq!(overflowed.completions, 2);
    assert!(overflowed.diagnostics.counter_overflow);
    assert!(!overflowed.usable());
    assert_eq!(meter.reset(), Err(IoFeedbackResetError::SourcesAttached));

    drop(registration);
    meter.reset().expect("detached meter can reset");
    let reset = meter.snapshot();
    assert_eq!(reset.committed_bytes, 0);
    assert_eq!(reset.completions, 0);
    assert_eq!(reset.generation, overflowed.generation + 1);
    assert!(reset.diagnostics.is_clear());
  }

  #[test]
  fn invalid_io_latches_until_reset_and_zero_completions_are_ignored() {
    let meter = IoFeedbackMeter::new();
    let registration = meter.register_source();
    meter.record_completion(0);
    meter.mark_invalid_io();
    let invalid = meter.snapshot();
    assert_eq!(invalid.committed_bytes, 0);
    assert_eq!(invalid.completions, 0);
    assert!(invalid.diagnostics.invalid_io);
    drop(registration);
    meter.reset().expect("detached meter resets invalid state");
    assert!(meter.snapshot().diagnostics.is_clear());
  }

  #[test]
  fn source_count_saturates_and_cannot_be_reset_after_overflow() {
    let meter = IoFeedbackMeter::new();
    lock_state(&meter.shared).attached_sources = u32::MAX;
    let uncounted_registration = meter.register_source();
    let snapshot = meter.snapshot();
    assert_eq!(snapshot.attached_sources, u32::MAX);
    assert!(snapshot.diagnostics.source_count_overflow);
    assert!(!snapshot.usable());

    drop(uncounted_registration);
    assert_eq!(meter.snapshot().attached_sources, u32::MAX);
    assert_eq!(
      meter.reset(),
      Err(IoFeedbackResetError::SourceCountOverflow)
    );
  }
}
