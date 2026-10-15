//! Construction-only numeric feedback-policy output for calibration preparation.
//!
//! This helper reports the policy the application runtime would use without
//! building an executor, starting the feedback worker, or observing a
//! workload. The one `ResourceDomain` construction is used only to measure
//! the fixed global Control baseline and is dropped before the result is
//! emitted.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use allocatbelt::runtime::byte_rate::{ByteRateConfig, ByteRateLimit};
use allocatbelt::runtime::managed::ResourceLimits;
use allocatbelt::runtime::resource_domain::{DomainResource, DomainResources, DomainSnapshot};
use allocatbelt::runtime::resource_feedback_meter::IoFeedbackMeter;
use allocatbelt::runtime::resource_feedback_policy::{
  ACTUATION_COOLDOWN, FEEDBACK_POLICY_VERSION, MAX_DENSE_SAMPLE_GAP, REQUIRED_BREACH_SAMPLES,
  SAMPLE_INTERVAL, TELEMETRY_FRESHNESS,
};

use super::runtime_bindings::{
  APPLICATION_BYTE_CALIBRATION_UNITS, APPLICATION_RATE_CEILING_BYTES_PER_SECOND, ApplicationDomain,
  ApplicationRateConfigs, CAPACITY_FLOOR_DIVISOR, CAPACITY_FLOOR_MINIMUM_BYTES_PER_SECOND,
  CAPACITY_FLOOR_POLICY_ID, CAPACITY_FLOOR_PROBE_ACTIVATION, CAPACITY_FLOOR_RULE,
  CAPACITY_FLOOR_RULE_VERSION, CAPACITY_FLOOR_RUNTIME_ACTIVATION, CapacityCalibrationArtifact,
  CapacityCalibrationProbeInput, CapacityFloorPolicy, FEEDBACK_MINIMUM_DENSE_OBSERVATIONS,
  FEEDBACK_RATE_FLOOR, ResolvedApplicationFeedback, after_release_global_snapshot_rows,
  application_domain_limits, construction_global_control_baseline, feedback_policy_control_config,
  fixed_rate_config,
};
use super::{Profile, Workload, resource_limits};

const SCHEMA: &str = "allocatbelt.application-feedback-policy-probe.v1";
const CALIBRATED_SCHEMA: &str = "allocatbelt.application-feedback-policy-probe.v2";
const CAPACITY_RESOLUTION_RULE_VERSION: &str = CAPACITY_FLOOR_RULE_VERSION;
const CPU_REDUCTION_RULE: &str = "floor_current_limit_over_10_zero_is_quantized";
const CPU_RECOVERY_INCREMENT: u64 = 1;
const NETWORK_SENSOR_SOURCE: &str = "download_application_bytes_only";
const METER_SOURCE_LIFETIME: &str = "registered_endpoint_owner";
const MAX_CANONICAL_JSON_FIELDS: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JsonValue {
  Object(BTreeMap<String, JsonValue>),
  String(String),
  Number(u64),
  Number128(u128),
  Bool(bool),
  Null,
}

fn object<const N: usize>(pairs: [(&str, JsonValue); N]) -> JsonValue {
  JsonValue::Object(
    pairs
      .into_iter()
      .map(|(key, value)| (key.to_owned(), value))
      .collect(),
  )
}

fn insert_object_field(value: &mut JsonValue, key: &str, field: JsonValue) -> Result<(), String> {
  match value {
    JsonValue::Object(fields) => {
      if fields.insert(key.to_owned(), field).is_some() {
        return Err(format!("feedback policy probe repeats object key {key}"));
      }
      Ok(())
    }
    _ => Err("internal feedback policy probe object construction failed".into()),
  }
}

fn string(value: impl Into<String>) -> JsonValue {
  JsonValue::String(value.into())
}

fn number(value: usize) -> Result<JsonValue, String> {
  u64::try_from(value)
    .map(JsonValue::Number)
    .map_err(|_| "feedback policy probe integer does not fit u64".to_owned())
}

fn number_u64(value: u64) -> JsonValue {
  JsonValue::Number(value)
}

fn duration_ns(value: Duration) -> Result<JsonValue, String> {
  u64::try_from(value.as_nanos())
    .map(JsonValue::Number)
    .map_err(|_| "feedback policy timing does not fit u64 nanoseconds".to_owned())
}

fn write_json_string(value: &str, output: &mut impl fmt::Write) -> fmt::Result {
  output.write_char('"')?;
  for character in value.chars() {
    match character {
      '"' => output.write_str("\\\"")?,
      '\\' => output.write_str("\\\\")?,
      '\u{08}' => output.write_str("\\b")?,
      '\u{09}' => output.write_str("\\t")?,
      '\u{0a}' => output.write_str("\\n")?,
      '\u{0c}' => output.write_str("\\f")?,
      '\u{0d}' => output.write_str("\\r")?,
      character if character.is_ascii_control() => {
        write!(output, "\\u{:04x}", u32::from(character))?;
      }
      character if character.is_ascii() => output.write_char(character)?,
      character => {
        let mut units = [0_u16; 2];
        for unit in character.encode_utf16(&mut units).iter() {
          write!(output, "\\u{unit:04x}")?;
        }
      }
    }
  }
  output.write_char('"')
}

fn write_json(value: &JsonValue, output: &mut impl fmt::Write) -> fmt::Result {
  match value {
    JsonValue::Object(fields) => {
      output.write_char('{')?;
      for (index, (key, child)) in fields.iter().enumerate() {
        if index != 0 {
          output.write_char(',')?;
        }
        write_json_string(key, output)?;
        output.write_char(':')?;
        write_json(child, output)?;
      }
      output.write_char('}')
    }
    JsonValue::String(value) => write_json_string(value, output),
    JsonValue::Number(value) => {
      write!(output, "{value}")
    }
    JsonValue::Number128(value) => write!(output, "{value}"),
    JsonValue::Bool(value) => output.write_str(if *value { "true" } else { "false" }),
    JsonValue::Null => output.write_str("null"),
  }
}

pub(crate) fn json_object(
  pairs: impl IntoIterator<Item = (&'static str, JsonValue)>,
) -> Result<JsonValue, String> {
  let mut fields = BTreeMap::new();
  let mut count = 0usize;
  for (key, value) in pairs {
    count = count
      .checked_add(1)
      .ok_or_else(|| "canonical JSON field count overflow".to_owned())?;
    if count > MAX_CANONICAL_JSON_FIELDS {
      return Err("canonical JSON object exceeds its fixed field bound".into());
    }
    if fields.insert(key.to_owned(), value).is_some() {
      return Err(format!("canonical JSON object repeats key {key}"));
    }
  }
  Ok(JsonValue::Object(fields))
}

pub(crate) fn json_string_value(value: impl Into<String>) -> JsonValue {
  JsonValue::String(value.into())
}

pub(crate) fn json_u64(value: u64) -> JsonValue {
  JsonValue::Number(value)
}

pub(crate) fn json_usize(value: usize) -> Result<JsonValue, String> {
  u64::try_from(value)
    .map(JsonValue::Number)
    .map_err(|_| "canonical JSON integer does not fit u64".to_owned())
}

pub(crate) fn json_u128(value: u128) -> JsonValue {
  JsonValue::Number128(value)
}

pub(crate) fn json_bool(value: bool) -> JsonValue {
  JsonValue::Bool(value)
}

pub(crate) fn json_null() -> JsonValue {
  JsonValue::Null
}

pub(crate) fn write_canonical_json(
  value: &JsonValue,
  output: &mut impl fmt::Write,
) -> Result<(), String> {
  write_json(value, output).map_err(|_| "canonical JSON output buffer is full".to_owned())?;
  output
    .write_char('\n')
    .map_err(|_| "canonical JSON output buffer is full".to_owned())
}

fn context_workers(profile: Profile) -> usize {
  if profile == Profile::Oversubscribed {
    2
  } else {
    4
  }
}

fn validate_context(workload: Workload, profile: Profile) -> Result<(), String> {
  let valid = match workload {
    Workload::Cpu | Workload::Memory | Workload::Http | Workload::Disk => matches!(
      profile,
      Profile::Steady | Profile::Burst | Profile::Oversubscribed
    ),
    Workload::Mixed => matches!(
      profile,
      Profile::Mixed | Profile::Burst | Profile::Oversubscribed
    ),
  };
  if valid {
    Ok(())
  } else {
    Err("feedback policy probe supports only the frozen 15 workload/profile contexts".into())
  }
}

fn control_value(floor: u64, initial: u64, ceiling: u64, low_bps: u16, high_bps: u16) -> JsonValue {
  object([
    ("ceiling", number_u64(ceiling)),
    ("floor", number_u64(floor)),
    ("high_bps", number_u64(u64::from(high_bps))),
    ("initial", number_u64(initial)),
    ("low_bps", number_u64(u64::from(low_bps))),
  ])
}

fn meter_bound(maximum_live: usize, source_rule: &'static str) -> Result<JsonValue, String> {
  Ok(object([
    ("lifetime", string(METER_SOURCE_LIFETIME)),
    ("maximum_live", number(maximum_live)?),
    ("minimum_live", number(0)?),
    ("source_rule", string(source_rule)),
  ]))
}

fn meter_source_bounds(workload: Workload) -> Result<JsonValue, String> {
  let uses_disk = matches!(workload, Workload::Disk | Workload::Mixed);
  let uses_http = matches!(workload, Workload::Http | Workload::Mixed);
  let disk_maximum = if uses_disk { 1 } else { 0 };
  // The application has one live client slot per WINDOW entry and the paired
  // HTTP acceptor has one handler slot per entry. Each wrapped endpoint owns
  // one read and one write registration; the two sides of a pair are distinct.
  let stream_maximum = if uses_http {
    super::WINDOW
      .checked_add(super::WINDOW)
      .ok_or_else(|| "HTTP meter source bound overflow".to_owned())?
  } else {
    0
  };
  Ok(object([
    (
      "disk",
      meter_bound(
        disk_maximum,
        if uses_disk {
          "disk_shared_owner"
        } else {
          "not_applicable"
        },
      )?,
    ),
    (
      "download",
      meter_bound(
        stream_maximum,
        if uses_http {
          "http_client_and_server_window"
        } else {
          "not_applicable"
        },
      )?,
    ),
    (
      "upload",
      meter_bound(
        stream_maximum,
        if uses_http {
          "http_client_and_server_window"
        } else {
          "not_applicable"
        },
      )?,
    ),
  ]))
}

fn meter_source_model() -> Result<JsonValue, String> {
  Ok(object([
    (
      "disk_registration_owner",
      string("one shared FsRateControl owner; clones retain its single registration"),
    ),
    (
      "disk_source_path",
      string("crates/allocatbelt/src/runtime/fs_rate.rs"),
    ),
    ("http_client_window", number(super::WINDOW)?),
    ("http_handler_window", number(super::WINDOW)?),
    (
      "http_client_window_source",
      string("bench/src/application.rs::WINDOW"),
    ),
    (
      "http_handler_window_source",
      string("bench/src/application/http.rs::{CLIENT_TASKS,HANDLER_TASKS}"),
    ),
    (
      "http_registration_owner",
      string(
        "each client and accepted handler RateLimitedIo registers one read and one write meter source",
      ),
    ),
    (
      "http_registration_source",
      string("crates/allocatbelt/src/runtime/rate_io.rs::FeedbackMeters::new"),
    ),
    ("http_source_path", string("bench/src/application/http.rs")),
    (
      "stream_registration_owner",
      string("one registration for each endpoint direction while the adapter lives"),
    ),
    (
      "disk_registration_source",
      string("crates/allocatbelt/src/runtime/fs_rate.rs::FsRateControl::new"),
    ),
  ]))
}

fn source_references() -> JsonValue {
  // The SourceV5 composer resolves these paths against the authenticated
  // SourceV4 inventory and carries the resulting exact file SHA-256 pins. The
  // construction probe itself does not claim that a binary can attest which
  // checkout bytes produced it.
  object([
    ("application_entrypoint", string("bench/src/application.rs")),
    ("application_http", string("bench/src/application/http.rs")),
    (
      "application_runtime_bindings",
      string("bench/src/application/runtime_bindings.rs"),
    ),
    (
      "construction_policy_probe",
      string("bench/src/application/feedback_policy_probe.rs"),
    ),
    (
      "disk_port_config",
      string("crates/allocatbelt-app-ports/src/disk.rs"),
    ),
    (
      "feedback_trace_collector",
      string("bench/src/application/feedback_trace.rs"),
    ),
    (
      "filesystem_rate_control",
      string("crates/allocatbelt/src/runtime/fs_rate.rs"),
    ),
    (
      "http_port_config",
      string("crates/allocatbelt-app-ports/src/http.rs"),
    ),
    (
      "memory_port_config",
      string("crates/allocatbelt-app-ports/src/memory.rs"),
    ),
    (
      "rate_limited_io",
      string("crates/allocatbelt/src/runtime/rate_io.rs"),
    ),
    (
      "resource_domain",
      string("crates/allocatbelt/src/runtime/resource_domain.rs"),
    ),
    (
      "resource_feedback_policy",
      string("crates/allocatbelt/src/runtime/resource_feedback_policy.rs"),
    ),
  ])
}

fn reader_context() -> Result<JsonValue, String> {
  Ok(object([
    ("actuation_cooldown_ns", duration_ns(ACTUATION_COOLDOWN)?),
    ("max_dense_gap_ns", duration_ns(MAX_DENSE_SAMPLE_GAP)?),
    (
      "minimum_dense_observations",
      number_u64(u64::from(FEEDBACK_MINIMUM_DENSE_OBSERVATIONS)),
    ),
    (
      "required_breach_samples",
      number_u64(u64::from(REQUIRED_BREACH_SAMPLES)),
    ),
    ("sample_interval_ns", duration_ns(SAMPLE_INTERVAL)?),
    ("telemetry_freshness_ns", duration_ns(TELEMETRY_FRESHNESS)?),
    ("version", string(FEEDBACK_POLICY_VERSION)),
  ]))
}

fn rust_control_context(
  workload: Workload,
  workers: usize,
  domain_limits: DomainResources,
  scope_limits: ResourceLimits,
) -> Result<JsonValue, String> {
  let feedback_policy = feedback_policy_control_config(workers);
  let rate_bucket = fixed_rate_config();
  let render_control =
    |control: allocatbelt::runtime::resource_feedback_policy::FeedbackControlConfig| {
      control_value(
        control.floor,
        control.initial,
        control.ceiling,
        control.low_utilization_basis_points,
        control.high_utilization_basis_points,
      )
    };

  let controls = object([
    ("cpu", render_control(feedback_policy.cpu_concurrency)),
    ("disk", render_control(feedback_policy.disk_rate)),
    ("download", render_control(feedback_policy.network_rate)),
  ]);
  let global_ceilings = object([
    (
      "control",
      number(domain_limits.get(DomainResource::Control))?,
    ),
    ("cpu", number(domain_limits.get(DomainResource::Cpu))?),
    ("disk", number(domain_limits.get(DomainResource::Disk))?),
    ("memory", number(domain_limits.get(DomainResource::Memory))?),
    (
      "network",
      number(domain_limits.get(DomainResource::Network))?,
    ),
    ("tasks", number(domain_limits.get(DomainResource::Tasks))?),
  ]);
  let tenant_ceilings = global_ceilings.clone();
  let scope = object([
    ("disk_operations", number(scope_limits.disk_concurrent_ops)?),
    ("managed_memory", number(scope_limits.managed_memory)?),
    (
      "network_operations",
      number(scope_limits.network_concurrent_ops)?,
    ),
  ]);
  let rate_bucket_value = || -> Result<JsonValue, String> {
    Ok(object([
      (
        "ceiling_bytes_per_second",
        number_u64(rate_bucket.bytes_per_second),
      ),
      ("ceiling_burst_bytes", number(rate_bucket.burst_bytes)?),
      ("max_reservations", number(rate_bucket.max_reservations)?),
    ]))
  };
  let rate_buckets = object([
    ("disk", rate_bucket_value()?),
    ("download", rate_bucket_value()?),
    ("upload", rate_bucket_value()?),
  ]);
  let required_byte_sources = object([
    (
      "disk",
      JsonValue::Bool(matches!(workload, Workload::Disk | Workload::Mixed)),
    ),
    (
      "download",
      JsonValue::Bool(matches!(workload, Workload::Http | Workload::Mixed)),
    ),
  ]);
  let algorithm = object([
    ("cpu_recovery_increment", number_u64(CPU_RECOVERY_INCREMENT)),
    ("cpu_reduction_rule", string(CPU_REDUCTION_RULE)),
    ("network_sensor_source", string(NETWORK_SENSOR_SOURCE)),
    ("upload_controlled", JsonValue::Bool(false)),
  ]);
  Ok(object([
    ("algorithm", algorithm),
    ("controls", controls),
    ("global_ceilings", global_ceilings),
    ("rate_buckets", rate_buckets),
    ("required_byte_sources", required_byte_sources),
    ("scope_limits", scope),
    ("tenant_ceilings", tenant_ceilings),
  ]))
}

fn resolved_rate_bucket_value(config: ByteRateConfig) -> Result<JsonValue, String> {
  Ok(object([
    (
      "ceiling_bytes_per_second",
      number_u64(config.bytes_per_second),
    ),
    (
      "initial_bytes_per_second",
      number_u64(config.bytes_per_second),
    ),
    ("ceiling_burst_bytes", number(config.burst_bytes)?),
    ("max_reservations", number(config.max_reservations)?),
  ]))
}

fn resolved_rate_buckets(rates: ApplicationRateConfigs) -> Result<JsonValue, String> {
  Ok(object([
    ("disk", resolved_rate_bucket_value(rates.disk)?),
    ("download", resolved_rate_bucket_value(rates.download)?),
    ("upload", resolved_rate_bucket_value(rates.upload)?),
  ]))
}

fn resolved_controls(policy: ResolvedApplicationFeedback) -> JsonValue {
  let render = |control: allocatbelt::runtime::resource_feedback_policy::FeedbackControlConfig| {
    control_value(
      control.floor,
      control.initial,
      control.ceiling,
      control.low_utilization_basis_points,
      control.high_utilization_basis_points,
    )
  };
  object([
    ("cpu", render(policy.policy.cpu_concurrency)),
    ("disk", render(policy.policy.disk_rate)),
    ("download", render(policy.policy.network_rate)),
  ])
}

fn resolved_rust_control_context(
  workload: Workload,
  domain_limits: DomainResources,
  scope_limits: ResourceLimits,
  resolved: ResolvedApplicationFeedback,
) -> Result<JsonValue, String> {
  let global_ceilings = object([
    (
      "control",
      number(domain_limits.get(DomainResource::Control))?,
    ),
    ("cpu", number(domain_limits.get(DomainResource::Cpu))?),
    ("disk", number(domain_limits.get(DomainResource::Disk))?),
    ("memory", number(domain_limits.get(DomainResource::Memory))?),
    (
      "network",
      number(domain_limits.get(DomainResource::Network))?,
    ),
    ("tasks", number(domain_limits.get(DomainResource::Tasks))?),
  ]);
  let scope = object([
    ("disk_operations", number(scope_limits.disk_concurrent_ops)?),
    ("managed_memory", number(scope_limits.managed_memory)?),
    (
      "network_operations",
      number(scope_limits.network_concurrent_ops)?,
    ),
  ]);
  let required_byte_sources = object([
    (
      "disk",
      JsonValue::Bool(matches!(workload, Workload::Disk | Workload::Mixed)),
    ),
    (
      "download",
      JsonValue::Bool(matches!(workload, Workload::Http | Workload::Mixed)),
    ),
  ]);
  let algorithm = object([
    ("cpu_recovery_increment", number_u64(CPU_RECOVERY_INCREMENT)),
    ("cpu_reduction_rule", string(CPU_REDUCTION_RULE)),
    ("network_sensor_source", string(NETWORK_SENSOR_SOURCE)),
    ("upload_controlled", JsonValue::Bool(false)),
  ]);
  Ok(object([
    ("algorithm", algorithm),
    ("controls", resolved_controls(resolved)),
    ("global_ceilings", global_ceilings.clone()),
    ("rate_buckets", resolved_rate_buckets(resolved.rates)?),
    ("required_byte_sources", required_byte_sources),
    ("scope_limits", scope),
    ("tenant_ceilings", global_ceilings),
  ]))
}

fn calibration_direction_value(
  artifact: &CapacityCalibrationArtifact,
  direction: &str,
  capacity: Option<std::num::NonZeroU64>,
  provenance_range: &std::ops::Range<usize>,
) -> JsonValue {
  let (capacity, units) = match capacity {
    Some(capacity) => (
      JsonValue::Number(capacity.get()),
      APPLICATION_BYTE_CALIBRATION_UNITS,
    ),
    None => (JsonValue::Null, "missing"),
  };
  object([
    ("bytes_per_second", capacity),
    ("direction", string(direction)),
    ("provenance", string(artifact.value(provenance_range))),
    ("units", string(units)),
  ])
}

fn capacity_floor_policy_descriptor() -> JsonValue {
  object([
    ("capacity_divisor", number_u64(CAPACITY_FLOOR_DIVISOR)),
    (
      "minimum_floor_bytes_per_second",
      number_u64(CAPACITY_FLOOR_MINIMUM_BYTES_PER_SECOND),
    ),
    ("policy_id", string(CAPACITY_FLOOR_POLICY_ID)),
    ("probe_activation", string(CAPACITY_FLOOR_PROBE_ACTIVATION)),
    ("rule", string(CAPACITY_FLOOR_RULE)),
    ("rule_version", string(CAPACITY_FLOOR_RULE_VERSION)),
    (
      "runtime_activation",
      string(CAPACITY_FLOOR_RUNTIME_ACTIVATION),
    ),
    (
      "static_floor_bytes_per_second",
      number_u64(FEEDBACK_RATE_FLOOR),
    ),
    (
      "static_rate_roof_bytes_per_second",
      number_u64(APPLICATION_RATE_CEILING_BYTES_PER_SECOND),
    ),
  ])
}

fn capacity_calibration_value(
  artifact: &CapacityCalibrationArtifact,
  resolved: ResolvedApplicationFeedback,
) -> Result<JsonValue, String> {
  let artifact_sha256 = std::str::from_utf8(&artifact.artifact_sha256)
    .map_err(|_| "loaded capacity calibration digest is not ASCII hexadecimal".to_owned())?;
  let relative_floor = resolved.capacity_floor_policy_id.is_some();
  let mut resolution = object([
    ("rate_buckets", resolved_rate_buckets(resolved.rates)?),
    (
      "rule",
      string(if relative_floor {
        "clip_relevant_initial_and_ceiling_to_raw_capacity_and_explicit_floor"
      } else {
        "clip_relevant_initial_and_ceiling_to_raw_capacity"
      }),
    ),
    (
      "rule_version",
      string(if relative_floor {
        CAPACITY_RESOLUTION_RULE_VERSION
      } else {
        "application-feedback-capacity-resolution-v1"
      }),
    ),
    (
      "static_rate_roof_bytes_per_second",
      number_u64(APPLICATION_RATE_CEILING_BYTES_PER_SECOND),
    ),
    ("controls", resolved_controls(resolved)),
    ("upload_controlled", JsonValue::Bool(false)),
  ]);
  if let Some(policy_id) = resolved.capacity_floor_policy_id {
    insert_object_field(
      &mut resolution,
      "capacity_floor_policy",
      capacity_floor_policy_descriptor(),
    )?;
    insert_object_field(
      &mut resolution,
      "capacity_floor_policy_id",
      string(policy_id),
    )?;
  }
  let mut value = object([
    ("artifact_sha256", string(artifact_sha256)),
    (
      "calibration_id",
      string(artifact.value(&artifact.calibration_id)),
    ),
    (
      "disk",
      calibration_direction_value(
        artifact,
        "disk",
        artifact.disk.bytes_per_second,
        &artifact.disk.provenance,
      ),
    ),
    (
      "download",
      calibration_direction_value(
        artifact,
        "download",
        artifact.download.bytes_per_second,
        &artifact.download.provenance,
      ),
    ),
    ("hash_scope", string("exact_bounded_artifact_bytes")),
    ("host_id", string(artifact.value(&artifact.host_id))),
    (
      "identity",
      object([
        ("host_id", string(artifact.value(&artifact.host_id))),
        ("profile", string(artifact.value(&artifact.profile))),
        (
          "source_sha256",
          string(artifact.value(&artifact.source_sha256)),
        ),
        ("workload", string(artifact.value(&artifact.workload))),
      ]),
    ),
    ("profile", string(artifact.value(&artifact.profile))),
    ("resolution", resolution),
    (
      "schema",
      string(super::runtime_bindings::CAPACITY_CALIBRATION_SCHEMA),
    ),
    (
      "source_sha256",
      string(artifact.value(&artifact.source_sha256)),
    ),
    (
      "verification_scope",
      string(
        "exact_artifact_hash_and_run_identity_only;producer_and_measurement_chronology_unverified",
      ),
    ),
    ("workload", string(artifact.value(&artifact.workload))),
  ]);
  if let Some(policy_id) = resolved.capacity_floor_policy_id {
    insert_object_field(&mut value, "capacity_floor_policy_id", string(policy_id))?;
  }
  Ok(value)
}

fn actual_rate_bucket(rate: &ByteRateLimit) -> Result<JsonValue, String> {
  let snapshot = rate.snapshot();
  Ok(object([
    ("bytes_per_second", number_u64(snapshot.bytes_per_second)),
    (
      "ceiling_bytes_per_second",
      number_u64(snapshot.ceiling_bytes_per_second),
    ),
    ("burst_bytes", number(snapshot.burst_bytes)?),
    ("ceiling_burst_bytes", number(snapshot.ceiling_burst_bytes)?),
    ("max_reservations", number(snapshot.max_reservations)?),
    ("reservations", number(snapshot.reservations)?),
  ]))
}

fn actual_meter(meter: &IoFeedbackMeter) -> JsonValue {
  let snapshot = meter.snapshot();
  object([
    (
      "attached_sources",
      number_u64(u64::from(snapshot.attached_sources)),
    ),
    ("committed_bytes", number_u64(snapshot.committed_bytes)),
    ("completions", number_u64(snapshot.completions)),
    (
      "diagnostics_clear",
      JsonValue::Bool(snapshot.diagnostics.is_clear()),
    ),
    ("generation", number_u64(snapshot.generation)),
  ])
}

fn actual_after_release(
  snapshot: &DomainSnapshot,
  fixed_global_control_baseline: usize,
) -> Result<JsonValue, String> {
  after_release_global_snapshot_rows(snapshot, fixed_global_control_baseline)?;
  let zero_dimensions = object([
    ("cpu", number(snapshot.used.get(DomainResource::Cpu))?),
    ("disk", number(snapshot.used.get(DomainResource::Disk))?),
    ("memory", number(snapshot.used.get(DomainResource::Memory))?),
    (
      "network",
      number(snapshot.used.get(DomainResource::Network))?,
    ),
    ("tasks", number(snapshot.used.get(DomainResource::Tasks))?),
  ]);
  Ok(object([
    (
      "control_used",
      number(snapshot.used.get(DomainResource::Control))?,
    ),
    (
      "control_matches_fixed_baseline",
      JsonValue::Bool(snapshot.used.get(DomainResource::Control) == fixed_global_control_baseline),
    ),
    (
      "expected_global_control_baseline",
      number(fixed_global_control_baseline)?,
    ),
    ("live_tenants", number(snapshot.live_tenants)?),
    ("zero_dimensions", zero_dimensions),
  ]))
}

fn build_calibrated_probe_value(
  workload: Workload,
  profile: Profile,
  calibration: &CapacityCalibrationArguments,
) -> Result<JsonValue, String> {
  validate_context(workload, profile)?;
  let workers = context_workers(profile);
  let scope_limits = resource_limits(workload);
  let domain = ApplicationDomain::new_for_feedback_probe(
    workload,
    workers,
    profile.label(),
    CapacityCalibrationProbeInput {
      path: &calibration.file,
      sha256: &calibration.sha256,
      host_id: &calibration.host_id,
      source_sha256: &calibration.source_sha256,
      capacity_floor_policy_id: calibration.capacity_floor_policy_id.as_deref(),
    },
  )?;
  let domain_limits = application_domain_limits(scope_limits, workers)?;
  let resolved = domain.resolved_feedback();
  let top_level_capacity_floor_policy_id = resolved.capacity_floor_policy_id;
  let artifact = domain
    .feedback_calibrations()
    .artifact
    .as_deref()
    .ok_or_else(|| "calibrated feedback probe did not retain its artifact".to_owned())?;
  let capacity_calibration = capacity_calibration_value(artifact, resolved)?;
  let rate_configs = domain.rate_configs();
  let rates = [
    ByteRateLimit::new_in_tenant(rate_configs.disk, &domain.tenant())
      .map_err(|error| format!("probe disk rate construction failed: {error:?}"))?,
    ByteRateLimit::new_in_tenant(rate_configs.upload, &domain.tenant())
      .map_err(|error| format!("probe upload rate construction failed: {error:?}"))?,
    ByteRateLimit::new_in_tenant(rate_configs.download, &domain.tenant())
      .map_err(|error| format!("probe download rate construction failed: {error:?}"))?,
  ];
  let tenant = domain.tenant();
  let meters = [
    IoFeedbackMeter::new_in_tenant(&tenant)
      .map_err(|error| format!("probe disk meter construction failed: {error:?}"))?,
    IoFeedbackMeter::new_in_tenant(&tenant)
      .map_err(|error| format!("probe upload meter construction failed: {error:?}"))?,
    IoFeedbackMeter::new_in_tenant(&tenant)
      .map_err(|error| format!("probe download meter construction failed: {error:?}"))?,
  ];
  let collector_control_charge_bytes = super::feedback_trace::control_charge_bytes();
  let collector_control = tenant
    .try_acquire(
      DomainResources::ZERO.with(DomainResource::Control, collector_control_charge_bytes),
    )
    .map_err(|error| format!("probe collector Control admission failed: {error:?}"))?;
  let collector_task = domain.reserve_task()?;
  let collector_admission =
    super::feedback_trace::FeedbackTraceAdmission::new(collector_control, collector_task);
  let tenant_snapshot = tenant
    .snapshot()
    .map_err(|error| format!("probe tenant snapshot failed: {error:?}"))?;
  let global_snapshot = domain.readback_domain().snapshot();
  let collector = object([
    (
      "control_charge_bytes",
      number(collector_control_charge_bytes)?,
    ),
    (
      "tenant_control_used_with_admission",
      number(tenant_snapshot.used.get(DomainResource::Control))?,
    ),
    (
      "tenant_tasks_used_with_admission",
      number(tenant_snapshot.used.get(DomainResource::Tasks))?,
    ),
    ("task_lease_count", number(1)?),
  ]);
  let actual_rate_buckets = object([
    ("disk", actual_rate_bucket(&rates[0])?),
    ("download", actual_rate_bucket(&rates[2])?),
    ("upload", actual_rate_bucket(&rates[1])?),
  ]);
  let actual_meters = object([
    ("disk", actual_meter(&meters[0])),
    ("download", actual_meter(&meters[2])),
    ("upload", actual_meter(&meters[1])),
  ]);
  let construction = object([
    ("collector", collector.clone()),
    (
      "global_control_used_with_owners",
      number(global_snapshot.used.get(DomainResource::Control))?,
    ),
    ("meters", actual_meters),
    ("rate_buckets", actual_rate_buckets),
    (
      "tenant_live_with_owners",
      number(tenant_snapshot.live_tenants)?,
    ),
  ]);
  let fixed_global_control_baseline = domain.fixed_global_control_baseline();
  let readback_domain = domain.readback_domain();
  let context = object([
    ("profile", string(profile.label())),
    ("workers", number(workers)?),
    ("workload", string(workload.label())),
  ]);
  let baseline = object([(
    "expected_global_control_baseline",
    number(fixed_global_control_baseline)?,
  )]);
  let meter_bounds = meter_source_bounds(workload)?;
  let rust_control_context =
    resolved_rust_control_context(workload, domain_limits, scope_limits, resolved)?;
  drop(collector_admission);
  drop(meters);
  drop(rates);
  drop(tenant);
  drop(domain);
  let after_release =
    actual_after_release(&readback_domain.snapshot(), fixed_global_control_baseline)?;
  let mut value = object([
    ("after_release", after_release),
    ("baseline", baseline),
    ("capacity_calibration", capacity_calibration),
    ("collector", collector),
    ("construction", construction),
    ("context", context),
    ("meter_source_bounds", meter_bounds),
    ("meter_source_model", meter_source_model()?),
    ("reader_context", reader_context()?),
    ("rust_control_context", rust_control_context),
    ("schema", string(CALIBRATED_SCHEMA)),
    ("source_references", source_references()),
  ]);
  if let Some(policy_id) = top_level_capacity_floor_policy_id {
    insert_object_field(&mut value, "capacity_floor_policy_id", string(policy_id))?;
  }
  Ok(value)
}

fn build_probe_value(workload: Workload, profile: Profile) -> Result<JsonValue, String> {
  validate_context(workload, profile)?;
  let workers = context_workers(profile);
  let scope_limits = resource_limits(workload);
  let domain_limits = application_domain_limits(scope_limits, workers)?;
  let fixed_global_control_baseline = construction_global_control_baseline(domain_limits)?;
  let context = object([
    ("profile", string(profile.label())),
    ("workers", number(workers)?),
    ("workload", string(workload.label())),
  ]);
  let collector = object([
    (
      "control_charge_bytes",
      number(super::feedback_trace::control_charge_bytes())?,
    ),
    ("task_lease_count", number(1)?),
  ]);
  let baseline = object([(
    "expected_global_control_baseline",
    number(fixed_global_control_baseline)?,
  )]);
  Ok(object([
    ("baseline", baseline),
    ("collector", collector),
    ("context", context),
    ("meter_source_bounds", meter_source_bounds(workload)?),
    ("meter_source_model", meter_source_model()?),
    ("reader_context", reader_context()?),
    (
      "rust_control_context",
      rust_control_context(workload, workers, domain_limits, scope_limits)?,
    ),
    ("schema", string(SCHEMA)),
    ("source_references", source_references()),
  ]))
}

#[derive(Debug)]
struct CapacityCalibrationArguments {
  file: PathBuf,
  sha256: String,
  host_id: String,
  source_sha256: String,
  capacity_floor_policy_id: Option<String>,
}

fn context_args(
  args: impl Iterator<Item = String>,
) -> Result<(Workload, Profile, Option<CapacityCalibrationArguments>), String> {
  let mut args = args;
  if args.next().as_deref() != Some("--emit-feedback-policy-only") {
    return Err("feedback policy probe command must start with --emit-feedback-policy-only".into());
  }
  let mut workload = None;
  let mut profile = None;
  let mut capacity_file = None;
  let mut capacity_sha256 = None;
  let mut host_id = None;
  let mut source_sha256 = None;
  let mut capacity_floor_policy_id: Option<String> = None;
  while let Some(key) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| format!("missing value for feedback policy probe argument {key}"))?;
    match key.as_str() {
      "--workload" if workload.is_none() => workload = Some(Workload::parse(&value)?),
      "--profile" if profile.is_none() => profile = Some(Profile::parse(&value)?),
      "--capacity-calibration-file" if capacity_file.is_none() => {
        capacity_file = Some(PathBuf::from(value));
      }
      "--capacity-calibration-sha256" if capacity_sha256.is_none() => {
        capacity_sha256 = Some(value);
      }
      "--host-id" if host_id.is_none() => host_id = Some(value),
      "--source-sha256" if source_sha256.is_none() => source_sha256 = Some(value),
      "--capacity-floor-policy-id" if capacity_floor_policy_id.is_none() => {
        CapacityFloorPolicy::from_id(Some(&value))?;
        capacity_floor_policy_id = Some(value);
      }
      "--workload" | "--profile" => {
        return Err(format!("duplicate feedback policy probe argument {key}"));
      }
      "--capacity-calibration-file"
      | "--capacity-calibration-sha256"
      | "--host-id"
      | "--source-sha256"
      | "--capacity-floor-policy-id" => {
        return Err(format!("duplicate feedback policy probe argument {key}"));
      }
      _ => return Err(format!("unknown feedback policy probe argument {key}")),
    }
  }
  let workload = workload.ok_or_else(|| "feedback policy probe requires --workload".to_owned())?;
  let profile = profile.ok_or_else(|| "feedback policy probe requires --profile".to_owned())?;
  validate_context(workload, profile)?;
  let capacity_arguments = [
    capacity_file.is_some(),
    capacity_sha256.is_some(),
    host_id.is_some(),
    source_sha256.is_some(),
  ];
  let supplied_capacity_arguments = capacity_arguments
    .iter()
    .filter(|supplied| **supplied)
    .count();
  let calibration = match (capacity_file, capacity_sha256, host_id, source_sha256) {
    (None, None, None, None) => {
      if capacity_floor_policy_id.is_some() {
        return Err("capacity floor policy ID requires capacity calibration arguments".into());
      }
      None
    }
    (Some(file), Some(sha256), Some(host_id), Some(source_sha256)) => {
      Some(CapacityCalibrationArguments {
        file,
        sha256,
        host_id,
        source_sha256,
        capacity_floor_policy_id,
      })
    }
    _ => {
      return Err(format!(
        "capacity calibration arguments must be supplied as one all-or-none group (received {supplied_capacity_arguments} of 4)"
      ));
    }
  };
  Ok((workload, profile, calibration))
}

fn canonical_json(value: &JsonValue) -> String {
  let mut output = String::new();
  write_canonical_json(value, &mut output).expect("String accepts canonical JSON output");
  output
}

pub(super) fn emit(args: impl Iterator<Item = String>) -> Result<(), String> {
  let (workload, profile, calibration) = context_args(args)?;
  let value = match calibration.as_ref() {
    Some(calibration) => build_calibrated_probe_value(workload, profile, calibration)?,
    None => build_probe_value(workload, profile)?,
  };
  let output = canonical_json(&value);
  print!("{output}");
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn field<'a>(value: &'a JsonValue, key: &str) -> &'a JsonValue {
    match value {
      JsonValue::Object(fields) => fields.get(key).unwrap_or_else(|| panic!("missing {key}")),
      _ => panic!("expected an object while reading {key}"),
    }
  }

  fn has_field(value: &JsonValue, key: &str) -> bool {
    match value {
      JsonValue::Object(fields) => fields.contains_key(key),
      _ => false,
    }
  }

  fn uint(value: &JsonValue) -> u64 {
    match value {
      JsonValue::Number(value) => *value,
      _ => panic!("expected an unsigned integer"),
    }
  }

  fn text(value: &JsonValue) -> &str {
    match value {
      JsonValue::String(value) => value,
      _ => panic!("expected a string"),
    }
  }

  fn object_len(value: &JsonValue) -> usize {
    match value {
      JsonValue::Object(fields) => fields.len(),
      _ => panic!("expected an object"),
    }
  }

  #[test]
  fn shared_json_writer_sorts_keys_encodes_typed_values_and_rejects_duplicates() {
    let value = json_object([
      ("z", json_u128(u128::MAX)),
      ("null", json_null()),
      ("a", json_bool(false)),
    ])
    .expect("unique canonical object keys");
    let mut output = String::new();
    write_canonical_json(&value, &mut output).expect("canonical JSON string");
    assert_eq!(
      output,
      format!("{{\"a\":false,\"null\":null,\"z\":{}}}\n", u128::MAX)
    );
    assert!(json_object([("duplicate", json_null()), ("duplicate", json_bool(true))]).is_err());
  }

  #[test]
  fn emits_the_exact_frozen_fifteen_contexts_from_runtime_constructors() {
    let cases = [
      (Workload::Cpu, Profile::Steady),
      (Workload::Cpu, Profile::Burst),
      (Workload::Cpu, Profile::Oversubscribed),
      (Workload::Memory, Profile::Steady),
      (Workload::Memory, Profile::Burst),
      (Workload::Memory, Profile::Oversubscribed),
      (Workload::Http, Profile::Steady),
      (Workload::Http, Profile::Burst),
      (Workload::Http, Profile::Oversubscribed),
      (Workload::Disk, Profile::Steady),
      (Workload::Disk, Profile::Burst),
      (Workload::Disk, Profile::Oversubscribed),
      (Workload::Mixed, Profile::Mixed),
      (Workload::Mixed, Profile::Burst),
      (Workload::Mixed, Profile::Oversubscribed),
    ];
    assert_eq!(cases.len(), 15);

    for (workload, profile) in cases {
      let value = build_probe_value(workload, profile).expect("frozen context builds");
      assert_eq!(text(field(&value, "schema")), SCHEMA);
      let context = field(&value, "context");
      assert_eq!(object_len(context), 3);
      assert_eq!(text(field(context, "workload")), workload.label());
      assert_eq!(text(field(context, "profile")), profile.label());
      let workers = context_workers(profile);
      assert_eq!(
        uint(field(context, "workers")),
        u64::try_from(workers).unwrap()
      );

      let reader = field(&value, "reader_context");
      assert_eq!(text(field(reader, "version")), FEEDBACK_POLICY_VERSION);
      assert_eq!(
        uint(field(reader, "minimum_dense_observations")),
        u64::from(FEEDBACK_MINIMUM_DENSE_OBSERVATIONS)
      );
      assert_eq!(
        uint(field(reader, "sample_interval_ns")),
        u64::try_from(SAMPLE_INTERVAL.as_nanos()).unwrap()
      );

      let controls = field(field(&value, "rust_control_context"), "controls");
      let policy = feedback_policy_control_config(workers);
      let expected_cpu = control_value(
        policy.cpu_concurrency.floor,
        policy.cpu_concurrency.initial,
        policy.cpu_concurrency.ceiling,
        policy.cpu_concurrency.low_utilization_basis_points,
        policy.cpu_concurrency.high_utilization_basis_points,
      );
      let expected_disk = control_value(
        policy.disk_rate.floor,
        policy.disk_rate.initial,
        policy.disk_rate.ceiling,
        policy.disk_rate.low_utilization_basis_points,
        policy.disk_rate.high_utilization_basis_points,
      );
      let expected_download = control_value(
        policy.network_rate.floor,
        policy.network_rate.initial,
        policy.network_rate.ceiling,
        policy.network_rate.low_utilization_basis_points,
        policy.network_rate.high_utilization_basis_points,
      );
      assert_eq!(field(controls, "cpu"), &expected_cpu);
      assert_eq!(field(controls, "disk"), &expected_disk);
      assert_eq!(field(controls, "download"), &expected_download);

      let rust_context = field(&value, "rust_control_context");
      let global = field(rust_context, "global_ceilings");
      let local_limits = resource_limits(workload);
      let domain_limits = application_domain_limits(local_limits, workers).unwrap();
      for (name, resource) in [
        ("control", DomainResource::Control),
        ("cpu", DomainResource::Cpu),
        ("disk", DomainResource::Disk),
        ("memory", DomainResource::Memory),
        ("network", DomainResource::Network),
        ("tasks", DomainResource::Tasks),
      ] {
        assert_eq!(
          uint(field(global, name)),
          u64::try_from(domain_limits.get(resource)).unwrap()
        );
      }
      assert_eq!(field(rust_context, "tenant_ceilings"), global);
      let scope = field(rust_context, "scope_limits");
      assert_eq!(
        uint(field(scope, "disk_operations")),
        u64::try_from(local_limits.disk_concurrent_ops).unwrap()
      );
      assert_eq!(
        uint(field(scope, "managed_memory")),
        u64::try_from(local_limits.managed_memory).unwrap()
      );
      assert_eq!(
        uint(field(scope, "network_operations")),
        u64::try_from(local_limits.network_concurrent_ops).unwrap()
      );
      let rate = fixed_rate_config();
      let buckets = field(rust_context, "rate_buckets");
      for direction in ["disk", "download", "upload"] {
        let bucket = field(buckets, direction);
        assert_eq!(
          uint(field(bucket, "ceiling_bytes_per_second")),
          rate.bytes_per_second
        );
        assert_eq!(
          uint(field(bucket, "ceiling_burst_bytes")),
          u64::try_from(rate.burst_bytes).unwrap()
        );
        assert_eq!(
          uint(field(bucket, "max_reservations")),
          u64::try_from(rate.max_reservations).unwrap()
        );
      }

      let source_bounds = field(&value, "meter_source_bounds");
      let has_disk = matches!(workload, Workload::Disk | Workload::Mixed);
      let has_http = matches!(workload, Workload::Http | Workload::Mixed);
      for direction in ["disk", "download", "upload"] {
        let bounds = field(source_bounds, direction);
        assert_eq!(uint(field(bounds, "minimum_live")), 0);
        assert_eq!(
          uint(field(bounds, "maximum_live")),
          match direction {
            "disk" =>
              if has_disk {
                1
              } else {
                0
              },
            _ if has_http => 2 * u64::try_from(super::super::WINDOW).unwrap(),
            _ => 0,
          }
        );
        assert_eq!(text(field(bounds, "lifetime")), METER_SOURCE_LIFETIME);
      }

      let collector = field(&value, "collector");
      assert_eq!(
        uint(field(collector, "control_charge_bytes")),
        u64::try_from(super::super::feedback_trace::control_charge_bytes()).unwrap()
      );
      assert_eq!(uint(field(collector, "task_lease_count")), 1);

      let baseline = field(&value, "baseline");
      let domain =
        allocatbelt::runtime::resource_domain::ResourceDomain::with_waiters(domain_limits, 1, 256)
          .expect("same-source domain constructs without a runtime worker");
      let snapshot = domain.snapshot();
      assert_eq!(snapshot.live_tenants, 0);
      assert_eq!(
        uint(field(baseline, "expected_global_control_baseline")),
        u64::try_from(snapshot.used.get(DomainResource::Control)).unwrap()
      );
      drop(domain);

      let output = canonical_json(&value);
      assert!(output.ends_with('\n'));
      assert!(output.starts_with("{\"baseline\":"));
      assert!(output.contains("\"reader_context\":"));
      assert!(output.contains("\"rust_control_context\":"));
      assert!(output.contains("\"source_references\":"));
    }
  }

  #[test]
  fn meter_sources_are_upper_bounds_and_do_not_claim_observed_registrations() {
    for (workload, expected_disk, expected_stream) in [
      (Workload::Cpu, 0, 0),
      (Workload::Memory, 0, 0),
      (Workload::Http, 0, 16),
      (Workload::Disk, 1, 0),
      (Workload::Mixed, 1, 16),
    ] {
      let bounds = meter_source_bounds(workload).unwrap();
      assert_eq!(
        uint(field(field(&bounds, "disk"), "maximum_live")),
        expected_disk
      );
      for direction in ["download", "upload"] {
        assert_eq!(
          uint(field(field(&bounds, direction), "maximum_live")),
          expected_stream
        );
      }
    }
    let model = meter_source_model().unwrap();
    assert_eq!(uint(field(&model, "http_client_window")), 8);
    assert_eq!(uint(field(&model, "http_handler_window")), 8);
    assert!(text(field(&model, "http_registration_owner")).contains("one read and one write"));
  }

  #[test]
  fn source_references_cover_each_numeric_or_registration_input() {
    let refs = source_references();
    assert_eq!(object_len(&refs), 12);
    for (name, path) in [
      ("application_entrypoint", "bench/src/application.rs"),
      ("application_http", "bench/src/application/http.rs"),
      (
        "application_runtime_bindings",
        "bench/src/application/runtime_bindings.rs",
      ),
      (
        "construction_policy_probe",
        "bench/src/application/feedback_policy_probe.rs",
      ),
      (
        "disk_port_config",
        "crates/allocatbelt-app-ports/src/disk.rs",
      ),
      (
        "feedback_trace_collector",
        "bench/src/application/feedback_trace.rs",
      ),
      (
        "filesystem_rate_control",
        "crates/allocatbelt/src/runtime/fs_rate.rs",
      ),
      (
        "http_port_config",
        "crates/allocatbelt-app-ports/src/http.rs",
      ),
      (
        "memory_port_config",
        "crates/allocatbelt-app-ports/src/memory.rs",
      ),
      (
        "rate_limited_io",
        "crates/allocatbelt/src/runtime/rate_io.rs",
      ),
      (
        "resource_domain",
        "crates/allocatbelt/src/runtime/resource_domain.rs",
      ),
      (
        "resource_feedback_policy",
        "crates/allocatbelt/src/runtime/resource_feedback_policy.rs",
      ),
    ] {
      assert_eq!(text(field(&refs, name)), path);
    }
  }

  #[test]
  fn only_supported_workload_profile_pairs_are_accepted() {
    assert!(validate_context(Workload::Cpu, Profile::Mixed).is_err());
    assert!(validate_context(Workload::Mixed, Profile::Steady).is_err());
    assert!(validate_context(Workload::Http, Profile::SafetyOverload).is_err());
    assert!(validate_context(Workload::Mixed, Profile::Mixed).is_ok());
  }

  fn test_capacity_artifact() -> (PathBuf, String, String) {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FILE: AtomicU64 = AtomicU64::new(1);
    let source_sha256 = "a".repeat(64);
    let bytes = format!(
      "schema\t{}\ncalibration_id\tprobe-cal-1\nhost_id\tagent-9700x\nprofile\tmixed\nworkload\tmixed\nsource_sha256\t{source_sha256}\ndisk.bytes_per_second\t750000000\ndisk.units\t{}\ndisk.provenance\tlocal-device-read-write-pilot\ndownload.bytes_per_second\t1250000000\ndownload.units\t{}\ndownload.provenance\tpaired-http-application-byte-pilot\n",
      super::super::runtime_bindings::CAPACITY_CALIBRATION_SCHEMA,
      APPLICATION_BYTE_CALIBRATION_UNITS,
      APPLICATION_BYTE_CALIBRATION_UNITS,
    )
    .into_bytes();
    let sha256 = super::super::runtime_bindings::capacity_artifact_hash::sha256_hex(&bytes);
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-feedback-probe-{}-{}.tsv",
      std::process::id(),
      NEXT_FILE.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::write(&path, bytes).expect("write probe calibration fixture");
    (path, sha256, source_sha256)
  }

  #[test]
  fn v1_arguments_keep_the_uncalibrated_probe_path_and_v1_shape() {
    let (workload, profile, calibration) = context_args(
      [
        "--emit-feedback-policy-only",
        "--workload",
        "disk",
        "--profile",
        "steady",
      ]
      .into_iter()
      .map(str::to_owned),
    )
    .expect("v1 probe arguments");
    assert_eq!(workload, Workload::Disk);
    assert_eq!(profile, Profile::Steady);
    assert!(calibration.is_none());
    let output = canonical_json(&build_probe_value(workload, profile).expect("v1 probe"));
    assert!(output.contains("\"schema\":\"allocatbelt.application-feedback-policy-probe.v1\""));
    assert!(!output.contains("capacity_calibration"));
    assert!(!output.contains("after_release"));
  }

  #[test]
  fn calibration_cli_arguments_are_an_explicit_all_or_none_group() {
    let hash = "a".repeat(64);
    let incomplete_groups = vec![
      vec![
        "--capacity-calibration-file".to_owned(),
        "artifact.tsv".to_owned(),
      ],
      vec![
        "--capacity-calibration-file".to_owned(),
        "artifact.tsv".to_owned(),
        "--capacity-calibration-sha256".to_owned(),
        hash.clone(),
      ],
      vec![
        "--capacity-calibration-file".to_owned(),
        "artifact.tsv".to_owned(),
        "--capacity-calibration-sha256".to_owned(),
        hash,
        "--host-id".to_owned(),
        "agent-9700x".to_owned(),
      ],
    ];
    for arguments in incomplete_groups {
      let mut full = [
        "--emit-feedback-policy-only",
        "--workload",
        "mixed",
        "--profile",
        "mixed",
      ]
      .into_iter()
      .map(str::to_owned)
      .collect::<Vec<_>>();
      full.extend(arguments);
      let error =
        context_args(full.into_iter()).expect_err("partial calibration group is rejected");
      assert!(error.contains("all-or-none group"), "{error}");
    }
    let hash = "a".repeat(64);
    let duplicate_host = context_args(
      [
        "--emit-feedback-policy-only".to_owned(),
        "--workload".to_owned(),
        "mixed".to_owned(),
        "--profile".to_owned(),
        "mixed".to_owned(),
        "--capacity-calibration-file".to_owned(),
        "artifact.tsv".to_owned(),
        "--capacity-calibration-sha256".to_owned(),
        hash.clone(),
        "--host-id".to_owned(),
        "agent-9700x".to_owned(),
        "--source-sha256".to_owned(),
        hash.clone(),
        "--host-id".to_owned(),
        "agent-9700x".to_owned(),
      ]
      .into_iter(),
    )
    .expect_err("duplicate host identity is rejected");
    assert!(
      duplicate_host.contains("duplicate feedback policy probe argument --host-id"),
      "{duplicate_host}"
    );

    let (workload, profile, calibration) = context_args(
      [
        "--emit-feedback-policy-only".to_owned(),
        "--workload".to_owned(),
        "mixed".to_owned(),
        "--profile".to_owned(),
        "mixed".to_owned(),
        "--capacity-calibration-file".to_owned(),
        "artifact.tsv".to_owned(),
        "--capacity-calibration-sha256".to_owned(),
        hash.clone(),
        "--host-id".to_owned(),
        "agent-9700x".to_owned(),
        "--source-sha256".to_owned(),
        hash.clone(),
      ]
      .into_iter(),
    )
    .expect("complete calibration argument group is accepted");
    assert_eq!(workload, Workload::Mixed);
    assert_eq!(profile, Profile::Mixed);
    let calibration = calibration.expect("complete group selects probe v2");
    assert_eq!(calibration.file, PathBuf::from("artifact.tsv"));
    assert_eq!(calibration.sha256, hash);
    assert_eq!(calibration.host_id, "agent-9700x");
    assert_eq!(calibration.source_sha256, "a".repeat(64));
    assert_eq!(calibration.capacity_floor_policy_id, None);
  }

  #[test]
  fn calibrated_floor_policy_id_is_exact_opt_in_and_requires_capacity_arguments() {
    let policy_only = context_args(
      [
        "--emit-feedback-policy-only".to_owned(),
        "--workload".to_owned(),
        "mixed".to_owned(),
        "--profile".to_owned(),
        "mixed".to_owned(),
        "--capacity-floor-policy-id".to_owned(),
        CAPACITY_FLOOR_POLICY_ID.to_owned(),
      ]
      .into_iter(),
    )
    .expect_err("policy ID alone cannot enable calibrated resolution");
    assert!(policy_only.contains("requires capacity calibration arguments"));

    let unknown = context_args(
      [
        "--emit-feedback-policy-only".to_owned(),
        "--workload".to_owned(),
        "mixed".to_owned(),
        "--profile".to_owned(),
        "mixed".to_owned(),
        "--capacity-calibration-file".to_owned(),
        "artifact.tsv".to_owned(),
        "--capacity-calibration-sha256".to_owned(),
        "a".repeat(64),
        "--host-id".to_owned(),
        "agent-9700x".to_owned(),
        "--source-sha256".to_owned(),
        "a".repeat(64),
        "--capacity-floor-policy-id".to_owned(),
        "unknown_policy".to_owned(),
      ]
      .into_iter(),
    )
    .expect_err("unknown relative-floor policy is rejected");
    assert!(unknown.contains("policy ID is unknown"));

    let duplicate = context_args(
      [
        "--emit-feedback-policy-only".to_owned(),
        "--workload".to_owned(),
        "mixed".to_owned(),
        "--profile".to_owned(),
        "mixed".to_owned(),
        "--capacity-calibration-file".to_owned(),
        "artifact.tsv".to_owned(),
        "--capacity-calibration-sha256".to_owned(),
        "a".repeat(64),
        "--host-id".to_owned(),
        "agent-9700x".to_owned(),
        "--source-sha256".to_owned(),
        "a".repeat(64),
        "--capacity-floor-policy-id".to_owned(),
        CAPACITY_FLOOR_POLICY_ID.to_owned(),
        "--capacity-floor-policy-id".to_owned(),
        CAPACITY_FLOOR_POLICY_ID.to_owned(),
      ]
      .into_iter(),
    )
    .expect_err("duplicate floor policy ID is rejected");
    assert!(
      duplicate.contains("duplicate feedback policy probe argument --capacity-floor-policy-id")
    );

    let hash = "a".repeat(64);
    let (workload, profile, selected) = context_args(
      [
        "--emit-feedback-policy-only".to_owned(),
        "--workload".to_owned(),
        "mixed".to_owned(),
        "--profile".to_owned(),
        "mixed".to_owned(),
        "--capacity-calibration-file".to_owned(),
        "artifact.tsv".to_owned(),
        "--capacity-calibration-sha256".to_owned(),
        hash.clone(),
        "--host-id".to_owned(),
        "agent-9700x".to_owned(),
        "--source-sha256".to_owned(),
        hash,
        "--capacity-floor-policy-id".to_owned(),
        CAPACITY_FLOOR_POLICY_ID.to_owned(),
      ]
      .into_iter(),
    )
    .expect("the exact source-published policy ID is accepted");
    assert_eq!(workload, Workload::Mixed);
    assert_eq!(profile, Profile::Mixed);
    assert_eq!(
      selected
        .expect("complete capacity group")
        .capacity_floor_policy_id
        .as_deref(),
      Some(CAPACITY_FLOOR_POLICY_ID),
    );
  }

  #[test]
  fn calibrated_probe_uses_resolved_constructor_values_and_reports_real_cleanup() {
    let (file, sha256, source_sha256) = test_capacity_artifact();
    let arguments = CapacityCalibrationArguments {
      file: file.clone(),
      sha256: sha256.clone(),
      host_id: "agent-9700x".to_owned(),
      source_sha256: source_sha256.clone(),
      capacity_floor_policy_id: None,
    };
    let value = build_calibrated_probe_value(Workload::Mixed, Profile::Mixed, &arguments)
      .expect("calibrated construction probe");
    assert_eq!(text(field(&value, "schema")), CALIBRATED_SCHEMA);
    assert!(!has_field(&value, "capacity_floor_policy_id"));
    let calibration = field(&value, "capacity_calibration");
    assert!(!has_field(calibration, "capacity_floor_policy_id"));
    let resolution = field(calibration, "resolution");
    assert!(!has_field(resolution, "capacity_floor_policy"));
    assert!(!has_field(resolution, "capacity_floor_policy_id"));
    assert_eq!(
      text(field(resolution, "rule_version")),
      "application-feedback-capacity-resolution-v1"
    );
    assert_eq!(
      text(field(
        field(&value, "capacity_calibration"),
        "artifact_sha256"
      )),
      sha256
    );
    assert!(
      text(field(
        field(&value, "capacity_calibration"),
        "verification_scope"
      ))
      .contains("producer_and_measurement_chronology_unverified")
    );

    let rust_context = field(&value, "rust_control_context");
    let controls = field(rust_context, "controls");
    assert_eq!(uint(field(field(controls, "disk"), "initial")), 750_000_000);
    assert_eq!(uint(field(field(controls, "disk"), "ceiling")), 750_000_000);
    assert_eq!(
      uint(field(field(controls, "download"), "initial")),
      1_250_000_000
    );
    assert_eq!(
      uint(field(field(controls, "download"), "ceiling")),
      1_250_000_000
    );
    let buckets = field(rust_context, "rate_buckets");
    assert_eq!(
      uint(field(field(buckets, "disk"), "ceiling_bytes_per_second")),
      750_000_000
    );
    assert_eq!(
      uint(field(
        field(buckets, "download"),
        "initial_bytes_per_second"
      )),
      1_250_000_000
    );
    assert_eq!(
      uint(field(field(buckets, "upload"), "ceiling_bytes_per_second")),
      APPLICATION_RATE_CEILING_BYTES_PER_SECOND
    );
    let resolution = field(field(&value, "capacity_calibration"), "resolution");
    assert_eq!(field(resolution, "controls"), controls);
    assert_eq!(field(resolution, "rate_buckets"), buckets);

    let construction = field(&value, "construction");
    let actual_buckets = field(construction, "rate_buckets");
    assert_eq!(
      uint(field(field(actual_buckets, "disk"), "bytes_per_second")),
      750_000_000
    );
    assert_eq!(
      uint(field(
        field(actual_buckets, "download"),
        "ceiling_bytes_per_second"
      )),
      1_250_000_000
    );
    assert_eq!(
      uint(field(
        field(field(construction, "meters"), "download"),
        "attached_sources"
      )),
      0
    );
    let collector = field(construction, "collector");
    assert_eq!(
      uint(field(collector, "tenant_tasks_used_with_admission")),
      1
    );
    assert!(uint(field(collector, "tenant_control_used_with_admission")) > 0);

    let after = field(&value, "after_release");
    assert_eq!(uint(field(after, "live_tenants")), 0);
    assert_eq!(
      uint(field(after, "control_used")),
      uint(field(after, "expected_global_control_baseline"))
    );
    assert_eq!(
      field(after, "control_matches_fixed_baseline"),
      &JsonValue::Bool(true)
    );
    let zeros = field(after, "zero_dimensions");
    for dimension in ["cpu", "memory", "disk", "network", "tasks"] {
      assert_eq!(uint(field(zeros, dimension)), 0);
    }
    std::fs::remove_file(file).expect("remove probe calibration fixture");
  }

  #[test]
  fn calibrated_probe_reports_the_explicit_capacity_relative_floor_for_low_capacity() {
    let (file, _original_sha, source_sha256) = test_capacity_artifact();
    let original = std::fs::read(&file).expect("read high-capacity fixture");
    let low = String::from_utf8(original)
      .expect("capacity fixture is UTF-8")
      .replace("750000000", "4617956")
      .replace("1250000000", "4617956")
      .into_bytes();
    std::fs::write(&file, &low).expect("write low-capacity fixture");
    let sha256 = super::super::runtime_bindings::capacity_artifact_hash::sha256_hex(&low);
    let arguments = CapacityCalibrationArguments {
      file: file.clone(),
      sha256,
      host_id: "agent-9700x".to_owned(),
      source_sha256,
      capacity_floor_policy_id: Some(CAPACITY_FLOOR_POLICY_ID.to_owned()),
    };
    let value = build_calibrated_probe_value(Workload::Mixed, Profile::Mixed, &arguments)
      .expect("explicit policy resolves low but genuine application capacity");
    assert_eq!(text(field(&value, "schema")), CALIBRATED_SCHEMA);
    let rust_context = field(&value, "rust_control_context");
    let controls = field(rust_context, "controls");
    assert_eq!(uint(field(field(controls, "disk"), "floor")), 461_795);
    assert_eq!(uint(field(field(controls, "download"), "floor")), 461_795);
    assert_eq!(uint(field(field(controls, "disk"), "initial")), 4_617_956);
    assert_eq!(
      uint(field(field(controls, "download"), "ceiling")),
      4_617_956
    );
    let calibration = field(&value, "capacity_calibration");
    assert_eq!(
      text(field(&value, "capacity_floor_policy_id")),
      CAPACITY_FLOOR_POLICY_ID
    );
    assert_eq!(
      text(field(calibration, "capacity_floor_policy_id")),
      CAPACITY_FLOOR_POLICY_ID
    );
    let resolution = field(calibration, "resolution");
    assert_eq!(
      text(field(resolution, "rule_version")),
      CAPACITY_FLOOR_RULE_VERSION
    );
    let descriptor = field(resolution, "capacity_floor_policy");
    assert_eq!(
      text(field(descriptor, "policy_id")),
      CAPACITY_FLOOR_POLICY_ID
    );
    assert_eq!(uint(field(descriptor, "capacity_divisor")), 10);
    std::fs::remove_file(file).expect("remove low-capacity fixture");
  }

  #[test]
  fn calibrated_probe_rejects_hash_and_identity_mismatches_without_output() {
    let (file, sha256, source_sha256) = test_capacity_artifact();
    let wrong_hash = CapacityCalibrationArguments {
      file: file.clone(),
      sha256: "bad".to_owned(),
      host_id: "agent-9700x".to_owned(),
      source_sha256: source_sha256.clone(),
      capacity_floor_policy_id: None,
    };
    assert!(build_calibrated_probe_value(Workload::Mixed, Profile::Mixed, &wrong_hash).is_err());
    let mismatched_hash = CapacityCalibrationArguments {
      file: file.clone(),
      sha256: "0".repeat(64),
      host_id: "agent-9700x".to_owned(),
      source_sha256: source_sha256.clone(),
      capacity_floor_policy_id: None,
    };
    assert!(
      build_calibrated_probe_value(Workload::Mixed, Profile::Mixed, &mismatched_hash).is_err()
    );
    let wrong_host = CapacityCalibrationArguments {
      file: file.clone(),
      sha256: sha256.clone(),
      host_id: "another-host".to_owned(),
      source_sha256: source_sha256.clone(),
      capacity_floor_policy_id: None,
    };
    assert!(build_calibrated_probe_value(Workload::Mixed, Profile::Mixed, &wrong_host).is_err());
    let wrong_source = CapacityCalibrationArguments {
      file: file.clone(),
      sha256,
      host_id: "agent-9700x".to_owned(),
      source_sha256: "b".repeat(64),
      capacity_floor_policy_id: None,
    };
    assert!(build_calibrated_probe_value(Workload::Mixed, Profile::Mixed, &wrong_source).is_err());
    std::fs::remove_file(file).expect("remove probe calibration fixture");
  }
}
