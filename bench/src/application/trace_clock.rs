//! Bracketed mapping from `Instant` events to the host's `CLOCK_MONOTONIC`.
//!
//! Capturing the two clocks is not atomic. Consumers must retain the lower
//! and upper bounds, rather than treating a midpoint as an exact timestamp.
//! This uses the same host clock as an external pressure process; wall-clock
//! adjustments therefore cannot manufacture overlap between the two traces.

use std::time::Instant;

const MAX_ANCHOR_SPAN_NS: u128 = 50_000_000;

#[derive(Clone, Copy, Debug)]
pub(crate) struct TraceClock {
  pub(crate) origin: Instant,
  pub(crate) lower_ns: u128,
  pub(crate) upper_ns: u128,
}

impl TraceClock {
  pub(crate) fn capture() -> Result<Self, String> {
    let lower_ns = monotonic_ns()?;
    let origin = Instant::now();
    let upper_ns = monotonic_ns()?;
    Self::from_bracket(origin, lower_ns, upper_ns)
  }

  fn from_bracket(origin: Instant, lower_ns: u128, upper_ns: u128) -> Result<Self, String> {
    let span = upper_ns
      .checked_sub(lower_ns)
      .ok_or_else(|| "trace monotonic anchor moved backwards".to_owned())?;
    if span > MAX_ANCHOR_SPAN_NS {
      return Err("trace monotonic anchor exceeds its uncertainty bound".into());
    }
    Ok(Self {
      origin,
      lower_ns,
      upper_ns,
    })
  }

  /// Returns the full bracket for an event, including events before capture.
  pub(crate) fn bounds(&self, at: Instant) -> Result<(u128, u128), String> {
    if let Some(elapsed) = at.checked_duration_since(self.origin) {
      let shift = elapsed.as_nanos();
      let lower = self.lower_ns.checked_add(shift);
      let upper = self.upper_ns.checked_add(shift);
      lower
        .zip(upper)
        .ok_or_else(|| "trace clock mapping overflow".into())
    } else {
      let shift = self.origin.duration_since(at).as_nanos();
      let lower = self.lower_ns.checked_sub(shift);
      let upper = self.upper_ns.checked_sub(shift);
      lower
        .zip(upper)
        .ok_or_else(|| "trace event predates the host monotonic epoch".into())
    }
  }
}

pub(crate) fn monotonic_ns() -> Result<u128, String> {
  let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
  let seconds = u128::try_from(time.tv_sec).map_err(|_| "negative monotonic seconds")?;
  let nanos = u128::try_from(time.tv_nsec).map_err(|_| "negative monotonic nanoseconds")?;
  if nanos >= 1_000_000_000 {
    return Err("invalid monotonic nanoseconds".into());
  }
  seconds
    .checked_mul(1_000_000_000)
    .and_then(|base| base.checked_add(nanos))
    .ok_or_else(|| "trace monotonic timestamp overflow".into())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;

  #[test]
  fn mapping_preserves_uncertainty_for_startup_and_later_events() {
    let origin = Instant::now();
    let clock = TraceClock::from_bracket(origin, 100_000_000, 100_000_030).unwrap();
    assert_eq!(
      clock.bounds(origin - Duration::from_millis(10)).unwrap(),
      (90_000_000, 90_000_030)
    );
    assert_eq!(
      clock.bounds(origin + Duration::from_millis(10)).unwrap(),
      (110_000_000, 110_000_030)
    );
    assert!(TraceClock::from_bracket(origin, 2, 1).is_err());
    assert!(TraceClock::from_bracket(origin, 0, MAX_ANCHOR_SPAN_NS + 1).is_err());
    assert!(clock.bounds(origin - Duration::from_secs(1)).is_err());
  }

  #[test]
  fn real_anchor_brackets_the_same_host_clock() {
    let before = monotonic_ns().unwrap();
    let clock = TraceClock::capture().unwrap();
    let at = Instant::now();
    let after = monotonic_ns().unwrap();
    let (lower, upper) = clock.bounds(at).unwrap();
    assert!(before <= lower);
    assert!(lower <= upper);
    assert!(upper <= after + (clock.upper_ns - clock.lower_ns));
  }
}
