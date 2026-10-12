//! Parser and sampler arithmetic for Linux `/proc/self/stat` CPU accounting.
//!
//! The parser extracts `utime` and `stime` (fields 14 and 15, in clock ticks)
//! from a borrowed byte slice of at most [`MAX_STAT_LEN`] bytes. It uses no
//! heap allocation, floating point, unsafe code or panicking operations, so it
//! can run on fixed storage inside the allocator runtime.
//!
//! The `comm` field (field 2) is attacker-influenced: it may contain spaces,
//! parentheses and non-UTF-8 bytes. The parser therefore locates the final
//! closing parenthesis, requires a single space after it, and then splits the
//! remainder on ASCII whitespace. In that suffix the process state (field 3)
//! is index 0, `utime` is index 11 and `stime` is index 12.
//!
//! [`cpu_utilization_basis_points`] converts two samples into utilization of
//! the configured CPU capacity, in basis points clamped to `10_000`.
//!
//! # Scope
//!
//! - The value is physical process CPU time: user plus system time summed over
//!   every thread of this process. Time spent by waited-for children
//!   (`cutime`/`cstime`) is not included.
//! - It excludes kernel pressure: run-queue delay, PSI stalls, steal time,
//!   interrupt handling and work done by kernel threads on behalf of the
//!   process are invisible here.
//! - It does not attribute CPU per tenant and says nothing about I/O latency.
//!   Tenant accounting and I/O signals need separate sources.
//! - Reading `/proc/self/stat` and querying the tick rate and CPU count belong
//!   to the sampler, which will be implemented separately; this module only
//!   provides the pure parsing and arithmetic.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use core::fmt;
use core::time::Duration;

/// Maximum accepted length of a `/proc/self/stat` snapshot in bytes.
pub const MAX_STAT_LEN: usize = 8192;

/// Utilization reported when the process uses all configured CPU capacity.
pub const FULL_UTILIZATION_BASIS_POINTS: u16 = 10_000;

const STATE_SUFFIX_INDEX: usize = 0;
const UTIME_SUFFIX_INDEX: usize = 11;
const STIME_SUFFIX_INDEX: usize = 12;
const VALID_STATES: &[u8] = b"RSDZTtWXxKPI";
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// Cumulative CPU time of a process in clock ticks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessCpuTicks {
  /// Time scheduled in user mode (field 14).
  pub utime: u64,
  /// Time scheduled in kernel mode (field 15).
  pub stime: u64,
}

/// Reason a `/proc/self/stat` snapshot was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatParseError {
  /// The snapshot exceeds [`MAX_STAT_LEN`].
  TooLong,
  /// The snapshot does not start with a decimal pid followed by a space.
  MalformedPid,
  /// No `(` opening or `)` closing the `comm` field was found.
  MissingComm,
  /// The byte after the final `)` is not a space.
  MissingSuffixSpace,
  /// The state field is not one known single-byte process state.
  InvalidState,
  /// The snapshot ends before the `stime` field.
  MissingField,
  /// A counter field is not an unsigned decimal number.
  InvalidNumber,
  /// A counter field does not fit in `u64`.
  Overflow,
}

impl fmt::Display for StatParseError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let message = match self {
      Self::TooLong => "stat snapshot exceeds the maximum length",
      Self::MalformedPid => "stat snapshot has a malformed pid prefix",
      Self::MissingComm => "stat snapshot has no parenthesized comm field",
      Self::MissingSuffixSpace => "stat comm field is not followed by a space",
      Self::InvalidState => "stat state field is not a valid process state",
      Self::MissingField => "stat snapshot is missing cpu time fields",
      Self::InvalidNumber => "stat cpu time field is not a decimal number",
      Self::Overflow => "stat cpu time field overflows u64",
    };
    formatter.write_str(message)
  }
}

impl core::error::Error for StatParseError {}

/// Reason a CPU utilization sample could not be computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuUtilizationError {
  /// The elapsed interval is zero.
  ZeroInterval,
  /// The configured clock tick rate is zero.
  ZeroTicksPerSecond,
  /// The configured CPU count is zero.
  ZeroCpus,
  /// A counter in the current sample is lower than in the previous one.
  CounterReversed,
  /// An intermediate value does not fit in `u128`.
  Overflow,
}

impl fmt::Display for CpuUtilizationError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let message = match self {
      Self::ZeroInterval => "cpu sample interval is zero",
      Self::ZeroTicksPerSecond => "clock ticks per second is zero",
      Self::ZeroCpus => "cpu count is zero",
      Self::CounterReversed => "cpu time counter moved backwards",
      Self::Overflow => "cpu utilization arithmetic overflowed",
    };
    formatter.write_str(message)
  }
}

impl core::error::Error for CpuUtilizationError {}

/// Parses `utime` and `stime` from a `/proc/self/stat` snapshot.
///
/// # Errors
///
/// Returns a [`StatParseError`] for oversized, malformed or truncated input,
/// an invalid process state, or counters that are not decimal `u64` values.
pub fn parse_proc_stat(input: &[u8]) -> Result<ProcessCpuTicks, StatParseError> {
  if input.len() > MAX_STAT_LEN {
    return Err(StatParseError::TooLong);
  }

  let open = input
    .iter()
    .position(|&byte| byte == b'(')
    .ok_or(StatParseError::MissingComm)?;
  let Some((&b' ', pid)) = input.get(..open).and_then(<[u8]>::split_last) else {
    return Err(StatParseError::MalformedPid);
  };
  if pid.is_empty() || !pid.iter().all(u8::is_ascii_digit) {
    return Err(StatParseError::MalformedPid);
  }

  let close = input
    .iter()
    .rposition(|&byte| byte == b')')
    .ok_or(StatParseError::MissingComm)?;
  if close < open {
    return Err(StatParseError::MissingComm);
  }
  let Some((_, after_comm)) = input.split_at_checked(close) else {
    return Err(StatParseError::MissingComm);
  };
  let Some((&b' ', suffix)) = after_comm
    .split_first()
    .and_then(|(_, rest)| rest.split_first())
  else {
    return Err(StatParseError::MissingSuffixSpace);
  };

  let mut fields = suffix
    .split(u8::is_ascii_whitespace)
    .filter(|field| !field.is_empty());

  let state = fields
    .nth(STATE_SUFFIX_INDEX)
    .ok_or(StatParseError::MissingField)?;
  if !is_valid_state(state) {
    return Err(StatParseError::InvalidState);
  }

  let utime = fields
    .nth(UTIME_SUFFIX_INDEX - STATE_SUFFIX_INDEX - 1)
    .ok_or(StatParseError::MissingField)?;
  let stime = fields
    .nth(STIME_SUFFIX_INDEX - UTIME_SUFFIX_INDEX - 1)
    .ok_or(StatParseError::MissingField)?;

  Ok(ProcessCpuTicks {
    utime: parse_decimal_u64(utime)?,
    stime: parse_decimal_u64(stime)?,
  })
}

/// Computes process CPU utilization between two samples in basis points.
///
/// The result is `busy_ticks * 10_000 / (elapsed_seconds * ticks_per_second *
/// cpus)`, computed exactly with checked `u128` arithmetic, rounded down and
/// clamped to [`FULL_UTILIZATION_BASIS_POINTS`]. Clamping absorbs tick
/// granularity and sampling skew; it does not hide reversed counters.
///
/// # Errors
///
/// Returns a [`CpuUtilizationError`] for a zero interval, tick rate or CPU
/// count, a counter that moved backwards (for example after a reset), or an
/// intermediate value that overflows `u128`.
pub fn cpu_utilization_basis_points(
  previous: ProcessCpuTicks,
  current: ProcessCpuTicks,
  elapsed: Duration,
  ticks_per_second: u64,
  cpus: u32,
) -> Result<u16, CpuUtilizationError> {
  if elapsed.is_zero() {
    return Err(CpuUtilizationError::ZeroInterval);
  }
  if ticks_per_second == 0 {
    return Err(CpuUtilizationError::ZeroTicksPerSecond);
  }
  if cpus == 0 {
    return Err(CpuUtilizationError::ZeroCpus);
  }

  let user_delta = current
    .utime
    .checked_sub(previous.utime)
    .ok_or(CpuUtilizationError::CounterReversed)?;
  let system_delta = current
    .stime
    .checked_sub(previous.stime)
    .ok_or(CpuUtilizationError::CounterReversed)?;

  let busy_ticks = u128::from(user_delta)
    .checked_add(u128::from(system_delta))
    .ok_or(CpuUtilizationError::Overflow)?;
  let numerator = busy_ticks
    .checked_mul(NANOS_PER_SECOND)
    .and_then(|value| value.checked_mul(u128::from(FULL_UTILIZATION_BASIS_POINTS)))
    .ok_or(CpuUtilizationError::Overflow)?;
  let denominator = elapsed
    .as_nanos()
    .checked_mul(u128::from(ticks_per_second))
    .and_then(|value| value.checked_mul(u128::from(cpus)))
    .ok_or(CpuUtilizationError::Overflow)?;
  let basis_points = numerator
    .checked_div(denominator)
    .ok_or(CpuUtilizationError::Overflow)?
    .min(u128::from(FULL_UTILIZATION_BASIS_POINTS));

  u16::try_from(basis_points).map_err(|_| CpuUtilizationError::Overflow)
}

fn is_valid_state(field: &[u8]) -> bool {
  matches!(field, [state] if VALID_STATES.contains(state))
}

fn parse_decimal_u64(field: &[u8]) -> Result<u64, StatParseError> {
  if field.is_empty() {
    return Err(StatParseError::InvalidNumber);
  }
  let mut value: u64 = 0;
  for &byte in field {
    let digit = match byte {
      b'0'..=b'9' => u64::from(byte - b'0'),
      _ => return Err(StatParseError::InvalidNumber),
    };
    value = value
      .checked_mul(10)
      .and_then(|scaled| scaled.checked_add(digit))
      .ok_or(StatParseError::Overflow)?;
  }
  Ok(value)
}

#[cfg(test)]
mod tests {
  use super::*;

  const fn ticks(utime: u64, stime: u64) -> ProcessCpuTicks {
    ProcessCpuTicks { utime, stime }
  }

  #[test]
  fn parses_plain_snapshot() {
    let input = b"1234 (worker) S 1 2 3 4 5 6 7 8 9 10 250 75 13 14 15\n";
    assert_eq!(parse_proc_stat(input), Ok(ticks(250, 75)));
  }

  #[test]
  fn parses_comm_with_embedded_parentheses_and_spaces() {
    let input = b"42 (weird) (my name)) S 1 2 3 4 5 6 7 8 9 10 250 75 13 14\n";
    assert_eq!(parse_proc_stat(input), Ok(ticks(250, 75)));
  }

  #[test]
  fn ignores_spoofed_fields_inside_comm() {
    let input = b"5 (x) R 1 2 3 4 5 6 7 8 9 10 999 999) S 1 2 3 4 5 6 7 8 9 10 4 6\n";
    assert_eq!(parse_proc_stat(input), Ok(ticks(4, 6)));
  }

  #[test]
  fn parses_non_utf8_comm() {
    let input = b"7 (\xff\xfe \x80) R 1 2 3 4 5 6 7 8 9 10 11 12\n";
    assert_eq!(parse_proc_stat(input), Ok(ticks(11, 12)));
  }

  #[test]
  fn parses_empty_comm() {
    let input = b"7 () I 1 2 3 4 5 6 7 8 9 10 11 12";
    assert_eq!(parse_proc_stat(input), Ok(ticks(11, 12)));
  }

  #[test]
  fn accepts_mixed_ascii_whitespace_after_suffix_space() {
    let input = b"9 (a)  R\t1  2\n3 4 5 6 7 8 9 10\r250\x0c75\n\n";
    assert_eq!(parse_proc_stat(input), Ok(ticks(250, 75)));
  }

  #[test]
  fn rejects_missing_suffix_space() {
    assert_eq!(
      parse_proc_stat(b"9 (a)R 1 2 3 4 5 6 7 8 9 10 11 12"),
      Err(StatParseError::MissingSuffixSpace)
    );
    assert_eq!(
      parse_proc_stat(b"9 (a)\tR 1 2 3 4 5 6 7 8 9 10 11 12"),
      Err(StatParseError::MissingSuffixSpace)
    );
    assert_eq!(
      parse_proc_stat(b"9 (a)"),
      Err(StatParseError::MissingSuffixSpace)
    );
  }

  #[test]
  fn rejects_missing_or_unbalanced_comm() {
    assert_eq!(parse_proc_stat(b""), Err(StatParseError::MissingComm));
    assert_eq!(
      parse_proc_stat(b"9 a R 1 2 3 4 5 6 7 8 9 10 11 12"),
      Err(StatParseError::MissingComm)
    );
    assert_eq!(
      parse_proc_stat(b"9 (a R 1 2 3 4 5 6 7 8 9 10 11 12"),
      Err(StatParseError::MissingComm)
    );
    assert_eq!(
      parse_proc_stat(b"9 ) (a R 1 2 3 4 5 6 7 8 9 10 11 12"),
      Err(StatParseError::MalformedPid)
    );
  }

  #[test]
  fn rejects_malformed_pid_prefix() {
    assert_eq!(
      parse_proc_stat(b"(a) R 1 2 3 4 5 6 7 8 9 10 11 12"),
      Err(StatParseError::MalformedPid)
    );
    assert_eq!(
      parse_proc_stat(b" (a) R 1 2 3 4 5 6 7 8 9 10 11 12"),
      Err(StatParseError::MalformedPid)
    );
    assert_eq!(
      parse_proc_stat(b"-1 (a) R 1 2 3 4 5 6 7 8 9 10 11 12"),
      Err(StatParseError::MalformedPid)
    );
    assert_eq!(
      parse_proc_stat(b"1(a) R 1 2 3 4 5 6 7 8 9 10 11 12"),
      Err(StatParseError::MalformedPid)
    );
  }

  #[test]
  fn accepts_every_known_state() {
    let template = b"1 (a) ? 1 2 3 4 5 6 7 8 9 10 11 12\n";
    for &state in VALID_STATES {
      let mut line = *template;
      line[6] = state;
      assert_eq!(parse_proc_stat(&line), Ok(ticks(11, 12)), "state {state}");
    }
  }

  #[test]
  fn rejects_invalid_state() {
    for input in [
      &b"1 (a) Q 1 2 3 4 5 6 7 8 9 10 11 12"[..],
      b"1 (a) RR 1 2 3 4 5 6 7 8 9 10 11 12",
      b"1 (a) r 1 2 3 4 5 6 7 8 9 10 11 12",
      b"1 (a) \xd2 1 2 3 4 5 6 7 8 9 10 11 12",
      b"1 (a) 0 1 2 3 4 5 6 7 8 9 10 11 12",
    ] {
      assert_eq!(parse_proc_stat(input), Err(StatParseError::InvalidState));
    }
  }

  #[test]
  fn rejects_truncated_fields() {
    for input in [
      &b"1 (a) "[..],
      b"1 (a) \n",
      b"1 (a) R",
      b"1 (a) R 1 2 3 4 5 6 7 8 9 10",
      b"1 (a) R 1 2 3 4 5 6 7 8 9 10 11",
      b"1 (a) R 1 2 3 4 5 6 7 8 9 10 11 \n",
    ] {
      assert_eq!(parse_proc_stat(input), Err(StatParseError::MissingField));
    }
  }

  #[test]
  fn rejects_malformed_counters() {
    for input in [
      &b"1 (a) R 1 2 3 4 5 6 7 8 9 10 12a 12"[..],
      b"1 (a) R 1 2 3 4 5 6 7 8 9 10 11 -12",
      b"1 (a) R 1 2 3 4 5 6 7 8 9 10 +11 12",
      b"1 (a) R 1 2 3 4 5 6 7 8 9 10 0x1 12",
      b"1 (a) R 1 2 3 4 5 6 7 8 9 10 11 1.5",
    ] {
      assert_eq!(parse_proc_stat(input), Err(StatParseError::InvalidNumber));
    }
  }

  #[test]
  fn accepts_u64_max_and_rejects_counter_overflow() {
    assert_eq!(
      parse_proc_stat(b"1 (a) R 1 2 3 4 5 6 7 8 9 10 18446744073709551615 0"),
      Ok(ticks(u64::MAX, 0))
    );
    assert_eq!(
      parse_proc_stat(b"1 (a) R 1 2 3 4 5 6 7 8 9 10 18446744073709551616 0"),
      Err(StatParseError::Overflow)
    );
    assert_eq!(
      parse_proc_stat(b"1 (a) R 1 2 3 4 5 6 7 8 9 10 0 99999999999999999999999"),
      Err(StatParseError::Overflow)
    );
  }

  #[test]
  fn enforces_length_cap() {
    let line = b"1 (a) R 1 2 3 4 5 6 7 8 9 10 11 12\n";
    let mut at_cap = [b' '; MAX_STAT_LEN];
    at_cap[..line.len()].copy_from_slice(line);
    assert_eq!(parse_proc_stat(&at_cap), Ok(ticks(11, 12)));

    let over_cap = [b' '; MAX_STAT_LEN + 1];
    assert_eq!(parse_proc_stat(&over_cap), Err(StatParseError::TooLong));
  }

  #[test]
  fn computes_multicore_utilization_over_100ms() {
    let elapsed = Duration::from_millis(100);
    // 4 CPUs at 100 ticks/s offer 40 ticks in 100 ms; 20 busy ticks is half.
    assert_eq!(
      cpu_utilization_basis_points(ticks(1_000, 500), ticks(1_015, 505), elapsed, 100, 4),
      Ok(5_000)
    );
    // One fully busy CPU out of four.
    assert_eq!(
      cpu_utilization_basis_points(ticks(0, 0), ticks(7, 3), elapsed, 100, 4),
      Ok(2_500)
    );
    // Results round down: 1 tick of 40 is 250 bp, 1 of 120 is 83.33 bp.
    assert_eq!(
      cpu_utilization_basis_points(ticks(0, 0), ticks(1, 0), elapsed, 100, 4),
      Ok(250)
    );
    assert_eq!(
      cpu_utilization_basis_points(ticks(0, 0), ticks(0, 1), elapsed, 100, 12),
      Ok(83)
    );
    assert_eq!(
      cpu_utilization_basis_points(ticks(9, 9), ticks(9, 9), elapsed, 100, 4),
      Ok(0)
    );
  }

  #[test]
  fn clamps_high_load_to_full_utilization() {
    let elapsed = Duration::from_millis(100);
    assert_eq!(
      cpu_utilization_basis_points(ticks(0, 0), ticks(40, 0), elapsed, 100, 4),
      Ok(FULL_UTILIZATION_BASIS_POINTS)
    );
    assert_eq!(
      cpu_utilization_basis_points(ticks(0, 0), ticks(60, 40), elapsed, 100, 4),
      Ok(FULL_UTILIZATION_BASIS_POINTS)
    );
    assert_eq!(
      cpu_utilization_basis_points(
        ticks(0, 0),
        ticks(u64::MAX, u64::MAX),
        Duration::from_nanos(1),
        1,
        1
      ),
      Ok(FULL_UTILIZATION_BASIS_POINTS)
    );
  }

  #[test]
  fn rejects_counter_reset() {
    let elapsed = Duration::from_millis(100);
    assert_eq!(
      cpu_utilization_basis_points(ticks(500, 10), ticks(3, 20), elapsed, 100, 4),
      Err(CpuUtilizationError::CounterReversed)
    );
    assert_eq!(
      cpu_utilization_basis_points(ticks(10, 500), ticks(20, 3), elapsed, 100, 4),
      Err(CpuUtilizationError::CounterReversed)
    );
  }

  #[test]
  fn rejects_zero_interval_and_configuration() {
    let previous = ticks(0, 0);
    let current = ticks(1, 1);
    assert_eq!(
      cpu_utilization_basis_points(previous, current, Duration::ZERO, 100, 4),
      Err(CpuUtilizationError::ZeroInterval)
    );
    assert_eq!(
      cpu_utilization_basis_points(previous, current, Duration::from_millis(100), 0, 4),
      Err(CpuUtilizationError::ZeroTicksPerSecond)
    );
    assert_eq!(
      cpu_utilization_basis_points(previous, current, Duration::from_millis(100), 100, 0),
      Err(CpuUtilizationError::ZeroCpus)
    );
  }

  #[test]
  fn rejects_denominator_overflow() {
    assert_eq!(
      cpu_utilization_basis_points(ticks(0, 0), ticks(1, 1), Duration::MAX, u64::MAX, u32::MAX),
      Err(CpuUtilizationError::Overflow)
    );
  }
}
