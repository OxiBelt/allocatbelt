//! Allocation-free JSON-lines encoding of complete feedback history records.
//!
//! Every timestamp is a bracket in the host monotonic clock. Diagnostic text
//! is bounded and escaped; policy decisions, samples and tickets have explicit
//! numeric fields so the independent reader need not parse Rust debug output.

use std::fmt::{self, Write as _};
use std::io::{self, Write};
use std::time::Instant;

use allocatbelt::runtime::resource_feedback::{
  FeedbackEvent, FeedbackEventKind, FeedbackReadbackOutcome,
};
use allocatbelt::runtime::resource_feedback_policy::{
  DecisionStatus, FeedbackResource, FeedbackSample, NoChangeReason, PlanTicket, ResourceDecision,
};

use super::trace_clock::TraceClock;

pub(crate) const EVENT_SCHEMA: &str = "allocatbelt.application-feedback-event.v1";

/// Encodes into caller-owned fixed storage, allowing one file write per event.
/// Exhausting the slice is an error, never a valid truncated record.
pub(crate) fn encode_event(
  output: &mut [u8],
  clock: &TraceClock,
  event: FeedbackEvent,
) -> io::Result<usize> {
  let mut cursor = io::Cursor::new(output);
  write_event(&mut cursor, clock, event)?;
  usize::try_from(cursor.position()).map_err(io::Error::other)
}

pub(crate) fn timestamp(out: &mut impl Write, clock: &TraceClock, at: Instant) -> io::Result<()> {
  let (lower, upper) = clock.bounds(at).map_err(io::Error::other)?;
  write!(out, "[{lower},{upper}]")
}

fn optional_time(out: &mut impl Write, clock: &TraceClock, at: Option<Instant>) -> io::Result<()> {
  match at {
    Some(at) => timestamp(out, clock, at),
    None => out.write_all(b"null"),
  }
}

fn optional_number<T: fmt::Display>(out: &mut impl Write, value: Option<T>) -> io::Result<()> {
  match value {
    Some(value) => write!(out, "{value}"),
    None => out.write_all(b"null"),
  }
}

pub(crate) fn quoted(out: &mut impl Write, value: &str) -> io::Result<()> {
  out.write_all(b"\"")?;
  for byte in value.bytes() {
    match byte {
      b'"' => out.write_all(b"\\\"")?,
      b'\\' => out.write_all(b"\\\\")?,
      0..=31 => write!(out, "\\u{byte:04x}")?,
      _ => out.write_all(&[byte])?,
    }
  }
  out.write_all(b"\"")
}

struct DiagnosticBuffer {
  bytes: [u8; 1024],
  length: usize,
}

impl fmt::Write for DiagnosticBuffer {
  fn write_str(&mut self, value: &str) -> fmt::Result {
    let end = self.length.checked_add(value.len()).ok_or(fmt::Error)?;
    if end > self.bytes.len() {
      return Err(fmt::Error);
    }
    self.bytes[self.length..end].copy_from_slice(value.as_bytes());
    self.length = end;
    Ok(())
  }
}

fn diagnostic(out: &mut impl Write, value: impl fmt::Debug) -> io::Result<()> {
  let mut buffer = DiagnosticBuffer {
    bytes: [0; 1024],
    length: 0,
  };
  write!(&mut buffer, "{value:?}")
    .map_err(|_| io::Error::other("feedback diagnostic exceeded its fixed buffer"))?;
  let value = std::str::from_utf8(&buffer.bytes[..buffer.length]).map_err(io::Error::other)?;
  quoted(out, value)
}

fn resource(out: &mut impl Write, value: FeedbackResource) -> io::Result<()> {
  quoted(
    out,
    match value {
      FeedbackResource::CpuConcurrency => "cpu",
      FeedbackResource::DiskRate => "disk",
      FeedbackResource::NetworkRate => "download",
    },
  )
}

fn sample(out: &mut impl Write, clock: &TraceClock, value: FeedbackSample) -> io::Result<()> {
  out.write_all(b"{\"at\":")?;
  timestamp(out, clock, value.at)?;
  out.write_all(b",\"cpu_basis_points\":")?;
  optional_number(out, value.cpu_utilization_basis_points)?;
  out.write_all(b",\"disk_basis_points\":")?;
  optional_number(out, value.disk_utilization_basis_points)?;
  out.write_all(b",\"download_basis_points\":")?;
  optional_number(out, value.network_utilization_basis_points)?;
  out.write_all(b"}")
}

fn ticket(out: &mut impl Write, clock: &TraceClock, value: PlanTicket) -> io::Result<()> {
  out.write_all(b"{\"resource\":")?;
  resource(out, value.resource())?;
  write!(
    out,
    ",\"generation\":{},\"from_limit\":{},\"to_limit\":{},\"planned_at\":",
    value.generation(),
    value.from_limit(),
    value.to_limit()
  )?;
  timestamp(out, clock, value.planned_at())?;
  out.write_all(b"}")
}

fn no_change(out: &mut impl Write, value: NoChangeReason) -> io::Result<()> {
  let name = match value {
    NoChangeReason::TelemetryUnavailable => "telemetry_unavailable",
    NoChangeReason::PlanPending => "plan_pending",
    NoChangeReason::ActuationFaultLatched => "actuation_fault_latched",
    NoChangeReason::BreachSamplesRemaining { observed, required } => {
      return write!(
        out,
        "{{\"reason\":\"breach_samples_remaining\",\"observed\":{observed},\"required\":{required}}}"
      );
    }
    NoChangeReason::CoolingDown { remaining } => {
      return write!(
        out,
        "{{\"reason\":\"cooling_down\",\"remaining_ns\":{}}}",
        remaining.as_nanos()
      );
    }
    NoChangeReason::HysteresisBand => "hysteresis_band",
    NoChangeReason::AtFloor => "at_floor",
    NoChangeReason::AtCeiling => "at_ceiling",
    NoChangeReason::ReductionQuantized => "reduction_quantized",
    NoChangeReason::RecoveryQuantized => "recovery_quantized",
  };
  write!(out, "{{\"reason\":\"{name}\"}}")
}

fn decision(out: &mut impl Write, clock: &TraceClock, value: ResourceDecision) -> io::Result<()> {
  out.write_all(b"{\"resource\":")?;
  resource(out, value.resource)?;
  write!(
    out,
    ",\"current_limit\":{},\"utilization_basis_points\":",
    value.current_limit
  )?;
  optional_number(out, value.utilization_basis_points)?;
  out.write_all(b",\"telemetry\":")?;
  diagnostic(out, value.telemetry)?;
  match value.status {
    DecisionStatus::Planned(value) => {
      out.write_all(b",\"ticket\":")?;
      ticket(out, clock, value)?;
      out.write_all(b",\"no_change\":null")?;
    }
    DecisionStatus::NoChange(value) => {
      out.write_all(b",\"ticket\":null,\"no_change\":")?;
      no_change(out, value)?;
    }
  }
  out.write_all(b"}")
}

fn callback_times(
  out: &mut impl Write,
  clock: &TraceClock,
  start: Instant,
  end: Instant,
) -> io::Result<()> {
  out.write_all(b",\"started_at\":")?;
  timestamp(out, clock, start)?;
  out.write_all(b",\"completed_at\":")?;
  timestamp(out, clock, end)
}

fn readback(out: &mut impl Write, value: FeedbackReadbackOutcome) -> io::Result<()> {
  out.write_all(b",\"outcome\":")?;
  match value {
    FeedbackReadbackOutcome::Value(actual) => write!(out, "\"value\",\"actual_limit\":{actual}"),
    FeedbackReadbackOutcome::Failed(error) => {
      out.write_all(b"\"failed\",\"actual_limit\":null,\"error\":")?;
      diagnostic(out, error)
    }
    FeedbackReadbackOutcome::Panicked => out.write_all(b"\"panicked\",\"actual_limit\":null"),
  }
}

/// Writes one complete event followed by LF. A partial I/O error invalidates
/// the stream; the owning collector must never emit a completion manifest.
pub(crate) fn write_event(
  out: &mut impl Write,
  clock: &TraceClock,
  event: FeedbackEvent,
) -> io::Result<()> {
  write!(
    out,
    "{{\"schema\":\"{EVENT_SCHEMA}\",\"sequence\":{},\"at\":",
    event.sequence
  )?;
  timestamp(out, clock, event.at)?;
  out.write_all(b",\"kind\":")?;
  match event.kind {
    FeedbackEventKind::StartupReadback {
      resource: kind,
      expected_limit,
      started_at,
      completed_at,
      outcome,
    } => {
      out.write_all(b"\"startup_readback\",\"resource\":")?;
      resource(out, kind)?;
      write!(out, ",\"expected_limit\":{expected_limit}")?;
      callback_times(out, clock, started_at, completed_at)?;
      readback(out, outcome)?;
    }
    FeedbackEventKind::ServiceStarted => out.write_all(b"\"service_started\"")?,
    FeedbackEventKind::SensorCallback {
      started_at,
      completed_at,
      outcome,
      raw_sample,
    } => {
      out.write_all(b"\"sensor_callback\"")?;
      callback_times(out, clock, started_at, completed_at)?;
      out.write_all(b",\"outcome\":")?;
      diagnostic(out, outcome)?;
      out.write_all(b",\"raw_sample\":")?;
      match raw_sample {
        Some(value) => sample(out, clock, value)?,
        None => out.write_all(b"null")?,
      }
    }
    FeedbackEventKind::SampleDecision {
      sample_at,
      sample: value,
      accepted,
      rejection,
      planned_at,
    } => {
      out.write_all(b"\"sample_decision\",\"sample_at\":")?;
      timestamp(out, clock, sample_at)?;
      out.write_all(b",\"sample\":")?;
      sample(out, clock, value)?;
      write!(out, ",\"accepted\":{accepted},\"rejection\":")?;
      match rejection {
        Some(value) => diagnostic(out, value)?,
        None => out.write_all(b"null")?,
      }
      out.write_all(b",\"planned_at\":")?;
      optional_time(out, clock, planned_at)?;
    }
    FeedbackEventKind::Plan(value) => {
      out.write_all(b"\"plan\",\"planned_at\":")?;
      timestamp(out, clock, value.at)?;
      out.write_all(b",\"controls\":[")?;
      decision(out, clock, value.cpu_concurrency)?;
      out.write_all(b",")?;
      decision(out, clock, value.disk_rate)?;
      out.write_all(b",")?;
      decision(out, clock, value.network_rate)?;
      out.write_all(b"]")?;
    }
    FeedbackEventKind::PlanRejected(error) => {
      out.write_all(b"\"plan_rejected\",\"error\":")?;
      diagnostic(out, error)?;
    }
    FeedbackEventKind::PreApplyReadback {
      ticket: value,
      started_at,
      completed_at,
      outcome,
      matches_ticket,
    } => {
      out.write_all(b"\"pre_apply_readback\",\"ticket\":")?;
      ticket(out, clock, value)?;
      callback_times(out, clock, started_at, completed_at)?;
      readback(out, outcome)?;
      write!(out, ",\"matches_ticket\":{matches_ticket}")?;
    }
    FeedbackEventKind::Apply {
      ticket: value,
      started_at,
      completed_at,
      outcome,
    } => {
      out.write_all(b"\"apply\",\"ticket\":")?;
      ticket(out, clock, value)?;
      callback_times(out, clock, started_at, completed_at)?;
      out.write_all(b",\"outcome\":")?;
      diagnostic(out, outcome)?;
    }
    FeedbackEventKind::PostApplyReadback {
      ticket: value,
      started_at,
      completed_at,
      outcome,
    } => {
      out.write_all(b"\"post_apply_readback\",\"ticket\":")?;
      ticket(out, clock, value)?;
      callback_times(out, clock, started_at, completed_at)?;
      readback(out, outcome)?;
    }
    FeedbackEventKind::Acknowledgement {
      ticket: value,
      result,
      accepted,
      current_limit,
      pending_generation,
      faulted,
    } => {
      out.write_all(b"\"acknowledgement\",\"ticket\":")?;
      ticket(out, clock, value)?;
      out.write_all(b",\"result\":")?;
      diagnostic(out, result)?;
      write!(
        out,
        ",\"accepted\":{accepted},\"current_limit\":{current_limit},\"faulted\":{faulted},\"pending_generation\":"
      )?;
      optional_number(out, pending_generation)?;
    }
    FeedbackEventKind::ReconciliationRequested { resource: kind } => {
      out.write_all(b"\"reconciliation_requested\",\"resource\":")?;
      resource(out, kind)?;
    }
    FeedbackEventKind::ReconciliationStarted { resource: kind } => {
      out.write_all(b"\"reconciliation_started\",\"resource\":")?;
      resource(out, kind)?;
    }
    FeedbackEventKind::ReconciliationReadback {
      resource: kind,
      started_at,
      completed_at,
      outcome,
    } => {
      out.write_all(b"\"reconciliation_readback\",\"resource\":")?;
      resource(out, kind)?;
      callback_times(out, clock, started_at, completed_at)?;
      readback(out, outcome)?;
    }
    FeedbackEventKind::ReconciliationFinished {
      resource: kind,
      actual_limit,
      accepted,
      rejection,
      current_limit,
      pending_generation,
      faulted,
    } => {
      out.write_all(b"\"reconciliation_finished\",\"resource\":")?;
      resource(out, kind)?;
      out.write_all(b",\"actual_limit\":")?;
      optional_number(out, actual_limit)?;
      write!(
        out,
        ",\"accepted\":{accepted},\"current_limit\":{current_limit},\"faulted\":{faulted},\"pending_generation\":"
      )?;
      optional_number(out, pending_generation)?;
      out.write_all(b",\"rejection\":")?;
      match rejection {
        Some(value) => diagnostic(out, value)?,
        None => out.write_all(b"null")?,
      }
    }
    FeedbackEventKind::StopRequested => out.write_all(b"\"stop_requested\"")?,
    FeedbackEventKind::WorkerFailure(value) => {
      out.write_all(b"\"worker_failure\",\"failure\":")?;
      diagnostic(out, value)?;
    }
    FeedbackEventKind::WorkerJoined { panicked } => {
      write!(out, "\"worker_joined\",\"panicked\":{panicked}")?
    }
    _ => return Err(io::Error::other("unsupported feedback history event")),
  }
  out.write_all(b"}\n")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn escaping_and_diagnostic_storage_are_bounded() {
    let mut output = Vec::new();
    quoted(&mut output, "quote\" slash\\ tab\t\n").unwrap();
    assert_eq!(output, b"\"quote\\\" slash\\\\ tab\\u0009\\u000a\"");
    let oversized = "x".repeat(2048);
    assert!(diagnostic(&mut output, oversized).is_err());
  }

  #[test]
  fn startup_and_join_keep_numeric_identity_and_clock_brackets() {
    let clock = TraceClock::capture().unwrap();
    let at = Instant::now();
    let mut output = Vec::new();
    write_event(
      &mut output,
      &clock,
      FeedbackEvent {
        sequence: 1,
        at,
        kind: FeedbackEventKind::StartupReadback {
          resource: FeedbackResource::CpuConcurrency,
          expected_limit: 4,
          started_at: at,
          completed_at: at,
          outcome: FeedbackReadbackOutcome::Value(4),
        },
      },
    )
    .unwrap();
    write_event(
      &mut output,
      &clock,
      FeedbackEvent {
        sequence: 2,
        at,
        kind: FeedbackEventKind::WorkerJoined { panicked: false },
      },
    )
    .unwrap();
    let text = std::str::from_utf8(&output).unwrap();
    assert_eq!(text.lines().count(), 2);
    assert!(text.contains("\"expected_limit\":4"));
    assert!(text.contains("\"outcome\":\"value\",\"actual_limit\":4"));
    assert!(text.contains("\"sequence\":2"));
    assert!(text.contains("\"kind\":\"worker_joined\",\"panicked\":false"));
    assert!(!text.contains("Instant"));
  }

  #[test]
  fn an_exhausted_record_buffer_is_never_successful() {
    let clock = TraceClock::capture().unwrap();
    let event = FeedbackEvent {
      sequence: 1,
      at: Instant::now(),
      kind: FeedbackEventKind::WorkerJoined { panicked: false },
    };
    let mut too_small = [0; 16];
    assert!(encode_event(&mut too_small, &clock, event).is_err());
    let mut sufficient = [0; 1024];
    let count = encode_event(&mut sufficient, &clock, event).unwrap();
    assert_eq!(sufficient[count - 1], b'\n');
    assert!(sufficient[count..].iter().all(|byte| *byte == 0));
  }
}
