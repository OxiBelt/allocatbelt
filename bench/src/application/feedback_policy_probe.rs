//! Construction-only numeric feedback-policy output for calibration preparation.
//!
//! This helper reports the policy the application runtime would use without
//! building an executor, starting the feedback worker, or observing a
//! workload. The one `ResourceDomain` construction is used only to measure
//! the fixed global Control baseline and is dropped before the result is
//! emitted.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use allocatbelt::runtime::managed::ResourceLimits;
use allocatbelt::runtime::resource_domain::{DomainResource, DomainResources};
use allocatbelt::runtime::resource_feedback_policy::{
  ACTUATION_COOLDOWN, FEEDBACK_POLICY_VERSION, MAX_DENSE_SAMPLE_GAP, REQUIRED_BREACH_SAMPLES,
  SAMPLE_INTERVAL, TELEMETRY_FRESHNESS,
};

use super::runtime_bindings::{
  FEEDBACK_MINIMUM_DENSE_OBSERVATIONS, application_domain_limits,
  construction_global_control_baseline, feedback_policy_control_config, fixed_rate_config,
};
use super::{Profile, Workload, resource_limits};

const SCHEMA: &str = "allocatbelt.application-feedback-policy-probe.v1";
const CPU_REDUCTION_RULE: &str = "floor_current_limit_over_10_zero_is_quantized";
const CPU_RECOVERY_INCREMENT: u64 = 1;
const NETWORK_SENSOR_SOURCE: &str = "download_application_bytes_only";
const METER_SOURCE_LIFETIME: &str = "registered_endpoint_owner";

#[derive(Clone, Debug, Eq, PartialEq)]
enum JsonValue {
  Object(BTreeMap<String, JsonValue>),
  String(String),
  Number(u64),
  Bool(bool),
}

fn object<const N: usize>(pairs: [(&str, JsonValue); N]) -> JsonValue {
  JsonValue::Object(
    pairs
      .into_iter()
      .map(|(key, value)| (key.to_owned(), value))
      .collect(),
  )
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

fn write_json_string(value: &str, output: &mut String) {
  output.push('"');
  for character in value.chars() {
    match character {
      '"' => output.push_str("\\\""),
      '\\' => output.push_str("\\\\"),
      '\u{08}' => output.push_str("\\b"),
      '\u{09}' => output.push_str("\\t"),
      '\u{0a}' => output.push_str("\\n"),
      '\u{0c}' => output.push_str("\\f"),
      '\u{0d}' => output.push_str("\\r"),
      character if character.is_ascii_control() => {
        let _ = write!(output, "\\u{:04x}", u32::from(character));
      }
      character if character.is_ascii() => output.push(character),
      character => {
        let mut units = [0_u16; 2];
        for unit in character.encode_utf16(&mut units).iter() {
          let _ = write!(output, "\\u{unit:04x}");
        }
      }
    }
  }
  output.push('"');
}

fn write_json(value: &JsonValue, output: &mut String) {
  match value {
    JsonValue::Object(fields) => {
      output.push('{');
      for (index, (key, child)) in fields.iter().enumerate() {
        if index != 0 {
          output.push(',');
        }
        write_json_string(key, output);
        output.push(':');
        write_json(child, output);
      }
      output.push('}');
    }
    JsonValue::String(value) => write_json_string(value, output),
    JsonValue::Number(value) => {
      let _ = write!(output, "{value}");
    }
    JsonValue::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
  }
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

fn context_args(args: impl Iterator<Item = String>) -> Result<(Workload, Profile), String> {
  let mut args = args;
  if args.next().as_deref() != Some("--emit-feedback-policy-only") {
    return Err("feedback policy probe command must start with --emit-feedback-policy-only".into());
  }
  let mut workload = None;
  let mut profile = None;
  while let Some(key) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| format!("missing value for feedback policy probe argument {key}"))?;
    match key.as_str() {
      "--workload" if workload.is_none() => workload = Some(Workload::parse(&value)?),
      "--profile" if profile.is_none() => profile = Some(Profile::parse(&value)?),
      "--workload" | "--profile" => {
        return Err(format!("duplicate feedback policy probe argument {key}"));
      }
      _ => return Err(format!("unknown feedback policy probe argument {key}")),
    }
  }
  let workload = workload.ok_or_else(|| "feedback policy probe requires --workload".to_owned())?;
  let profile = profile.ok_or_else(|| "feedback policy probe requires --profile".to_owned())?;
  validate_context(workload, profile)?;
  Ok((workload, profile))
}

fn canonical_json(value: &JsonValue) -> String {
  let mut output = String::new();
  write_json(value, &mut output);
  output.push('\n');
  output
}

pub(super) fn emit(args: impl Iterator<Item = String>) -> Result<(), String> {
  let (workload, profile) = context_args(args)?;
  let output = canonical_json(&build_probe_value(workload, profile)?);
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
}
