//! One owning resource domain and matched fixed I/O policy for an application run.

use allocatbelt::runtime::byte_rate::{ByteRateConfig, ByteRateLimit};
use allocatbelt::runtime::cpu_gate::CpuGate;
use allocatbelt::runtime::driver::{IoBindings, MultiThreadDriver};
use allocatbelt::runtime::fs::BlockingByteIo;
use allocatbelt::runtime::io::{AsyncRead, AsyncWrite};
use allocatbelt::runtime::managed::{ResourceLimits, ResourceScope};
use allocatbelt::runtime::rate_io::RateLimitedIo;
use allocatbelt::runtime::resource_domain::{
  DomainReservation, DomainResource, DomainResources, DomainSnapshot, ResourceDomain, TenantDomain,
};
#[cfg(feature = "resource-feedback")]
use allocatbelt::runtime::resource_feedback::ResourceFeedbackService;
#[cfg(feature = "resource-feedback")]
use allocatbelt::runtime::resource_feedback::{
  FeedbackHistoryConfig, FeedbackMetricsHandle, FeedbackWorkerFailure,
};
#[cfg(feature = "resource-feedback")]
use allocatbelt::runtime::resource_feedback_actuator::{
  CpuFeedbackTarget, RuntimeFeedbackActuator,
};
#[cfg(feature = "resource-feedback")]
use allocatbelt::runtime::resource_feedback_meter::{IoFeedbackMeter, IoFeedbackMeterSnapshot};
#[cfg(feature = "resource-feedback")]
use allocatbelt::runtime::resource_feedback_policy::{
  ACTUATION_COOLDOWN, FEEDBACK_POLICY_VERSION, FeedbackControlConfig, FeedbackResource,
  MAX_DENSE_SAMPLE_GAP, REQUIRED_BREACH_SAMPLES, ResourceFeedbackPolicyConfig, SAMPLE_INTERVAL,
  TELEMETRY_FRESHNESS, TelemetryStatus,
};
#[cfg(feature = "resource-feedback")]
use allocatbelt::runtime::resource_feedback_sensor::{
  IoFeedbackSource, ProcessCpuSensor, RuntimeFeedbackSensor,
};
use allocatbelt::runtime::time::TimerDriver;
#[cfg(feature = "resource-feedback")]
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
#[cfg(feature = "resource-feedback")]
use std::ops::Range;
#[cfg(feature = "resource-feedback")]
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
#[cfg(feature = "resource-feedback")]
use std::time::Instant;
#[cfg(feature = "resource-feedback")]
use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::PathBuf};

use super::{Workload, resource_limits};

pub(crate) const APPLICATION_TASK_CEILING: usize = 64;
pub(crate) const RUNTIME_BINDING_RECEIPT_SCHEMA_V2: &str =
  "allocatbelt.application-runtime-binding.v2";
#[cfg(feature = "resource-feedback")]
pub(crate) const FEEDBACK_MINIMUM_DENSE_OBSERVATIONS: u32 = 1;
#[cfg(feature = "resource-feedback")]
pub(super) const CAPACITY_FLOOR_POLICY_ID: &str = "application_capacity_relative_tenth_v1";
#[cfg(feature = "resource-feedback")]
pub(super) const CAPACITY_FLOOR_RULE_VERSION: &str = "application-feedback-capacity-resolution-v2";
#[cfg(feature = "resource-feedback")]
pub(super) const CAPACITY_FLOOR_RULE: &str = "max_one_min_static_floor_capacity_div_ten";
#[cfg(feature = "resource-feedback")]
pub(super) const CAPACITY_FLOOR_PROBE_ACTIVATION: &str = "explicit_policy_id_and_capacity_artifact";
#[cfg(feature = "resource-feedback")]
pub(super) const CAPACITY_FLOOR_RUNTIME_ACTIVATION: &str =
  "explicit_pressure_qualification_and_policy_id_and_capacity_artifact";
#[cfg(feature = "resource-feedback")]
pub(super) const CAPACITY_FLOOR_DIVISOR: u64 = 10;
#[cfg(feature = "resource-feedback")]
pub(super) const CAPACITY_FLOOR_MINIMUM_BYTES_PER_SECOND: u64 = 1;
pub(crate) const CPU_WAITER_CEILING: usize = APPLICATION_TASK_CEILING;
// CPU-gate waiter leases consume 64 fixed slots. The remaining 192 slots
// cover the owning async pool, filesystem pool, and bounded service roles.
const DOMAIN_WAITER_CEILING: usize = 256;
const DOMAIN_CONTROL_CEILING: usize = 64 * 1024 * 1024;
pub(super) const APPLICATION_RATE_CEILING_BYTES_PER_SECOND: u64 = 16 * 1024 * 1024 * 1024;
const RATE_BURST_BYTES: usize = 64 * 1024;
const RATE_RESERVATIONS: usize = 64;
const RATE_TIMER_REGISTRATIONS: usize = 256;
#[cfg(feature = "resource-feedback")]
pub(super) const FEEDBACK_RATE_FLOOR: u64 = 64 * 1024 * 1024;
#[cfg(feature = "resource-feedback")]
const FEEDBACK_LOW_UTILIZATION_BPS: u16 = 3_000;
#[cfg(feature = "resource-feedback")]
const FEEDBACK_HIGH_UTILIZATION_BPS: u16 = 8_000;

#[cfg(feature = "resource-feedback")]
fn feedback_history_config() -> Result<FeedbackHistoryConfig, String> {
  NonZeroUsize::new(super::feedback_trace::TRACE_HISTORY_CAPACITY)
    .map(FeedbackHistoryConfig::new)
    .ok_or_else(|| "feedback history capacity must be nonzero".to_owned())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplicationMode {
  Fixed,
  ExternalPressure,
}

impl ApplicationMode {
  pub(crate) fn from_comparison_family(value: Option<&str>) -> Result<Self, String> {
    match value {
      None | Some("fixed_policy") => Ok(Self::Fixed),
      Some("external_pressure") => {
        #[cfg(feature = "resource-feedback")]
        {
          Ok(Self::ExternalPressure)
        }
        #[cfg(not(feature = "resource-feedback"))]
        {
          Err("external-pressure comparison requires the resource-feedback feature".into())
        }
      }
      Some(_) => Err("unknown application comparison family".into()),
    }
  }

  pub(crate) const fn comparison_family(self) -> &'static str {
    match self {
      Self::Fixed => "fixed_policy",
      Self::ExternalPressure => "external_pressure",
    }
  }

  pub(crate) const fn feedback_enabled(self) -> bool {
    matches!(self, Self::ExternalPressure)
  }
}

#[cfg(feature = "resource-feedback")]
pub(super) const APPLICATION_BYTE_CALIBRATION_UNITS: &str = "application_bytes_per_second";
#[cfg(feature = "resource-feedback")]
pub(super) const CAPACITY_CALIBRATION_SCHEMA: &str = "allocatbelt.app-byte-capacity.v1";
#[cfg(feature = "resource-feedback")]
const MAX_CAPACITY_CALIBRATION_BYTES: u64 = 4096;
#[cfg(feature = "resource-feedback")]
const CAPACITY_CALIBRATION_FIELDS: [&str; 12] = [
  "schema",
  "calibration_id",
  "host_id",
  "profile",
  "workload",
  "source_sha256",
  "disk.bytes_per_second",
  "disk.units",
  "disk.provenance",
  "download.bytes_per_second",
  "download.units",
  "download.provenance",
];

#[cfg(feature = "resource-feedback")]
const CALIBRATION_ARTIFACT_CONTROL_CHARGE: usize = 3 * MAX_CAPACITY_CALIBRATION_BYTES as usize
  + std::mem::size_of::<CapacityCalibrationArtifact>()
  + 2 * std::mem::size_of::<usize>();

// `source_sha256` is the candidate source-tree digest already supplied through
// `ALLOCATBELT_APP_SOURCE_SHA256`, not the calibration producer or binary hash.

#[cfg(feature = "resource-feedback")]
#[derive(Clone, Debug)]
pub(super) struct DirectionCalibration {
  pub(super) bytes_per_second: Option<NonZeroU64>,
  pub(super) provenance: Range<usize>,
}

#[cfg(feature = "resource-feedback")]
struct ParsedCapacityCalibration {
  calibration_id: Range<usize>,
  host_id: Range<usize>,
  profile: Range<usize>,
  workload: Range<usize>,
  source_sha256: Range<usize>,
  disk: DirectionCalibration,
  download: DirectionCalibration,
}

#[cfg(feature = "resource-feedback")]
#[derive(Debug)]
pub(super) struct CapacityCalibrationArtifact {
  pub(super) payload: String,
  pub(super) calibration_id: Range<usize>,
  pub(super) host_id: Range<usize>,
  pub(super) profile: Range<usize>,
  pub(super) workload: Range<usize>,
  pub(super) source_sha256: Range<usize>,
  pub(super) artifact_sha256: [u8; 64],
  pub(super) disk: DirectionCalibration,
  pub(super) download: DirectionCalibration,
  _charge: DomainReservation,
}

#[cfg(feature = "resource-feedback")]
#[derive(Clone, Copy)]
struct CalibrationRunIdentity<'a> {
  host_id: &'a str,
  profile: &'a str,
  workload: &'a str,
  source_sha256: &'a str,
  pressure_qualification: bool,
}

#[cfg(feature = "resource-feedback")]
impl CapacityCalibrationArtifact {
  pub(super) fn value(&self, range: &Range<usize>) -> &str {
    &self.payload[range.clone()]
  }
}

#[cfg(feature = "resource-feedback")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum CapacityFloorPolicy {
  #[default]
  StaticDefault,
  CapacityRelativeTenth,
}

#[cfg(feature = "resource-feedback")]
impl CapacityFloorPolicy {
  pub(super) fn from_id(value: Option<&str>) -> Result<Self, String> {
    match value {
      None => Ok(Self::StaticDefault),
      Some(CAPACITY_FLOOR_POLICY_ID) => Ok(Self::CapacityRelativeTenth),
      Some(_) => Err("capacity floor policy ID is unknown".into()),
    }
  }

  const fn id(self) -> Option<&'static str> {
    match self {
      Self::StaticDefault => None,
      Self::CapacityRelativeTenth => Some(CAPACITY_FLOOR_POLICY_ID),
    }
  }
}

#[cfg(feature = "resource-feedback")]
#[derive(Clone, Copy)]
pub(super) struct CapacityCalibrationProbeInput<'a> {
  pub(super) path: &'a std::path::Path,
  pub(super) sha256: &'a str,
  pub(super) host_id: &'a str,
  pub(super) source_sha256: &'a str,
  pub(super) capacity_floor_policy_id: Option<&'a str>,
}

#[cfg(feature = "resource-feedback")]
#[derive(Clone, Debug, Default)]
pub(super) struct FeedbackCalibrations {
  pub(super) artifact: Option<Arc<CapacityCalibrationArtifact>>,
  pub(super) pressure_qualification: bool,
  pub(super) capacity_floor_policy: CapacityFloorPolicy,
}

#[cfg(feature = "resource-feedback")]
impl FeedbackCalibrations {
  fn from_explicit_probe_file(
    tenant: &TenantDomain,
    workload: Workload,
    profile: &str,
    input: CapacityCalibrationProbeInput<'_>,
  ) -> Result<Self, String> {
    let identity = CalibrationRunIdentity {
      host_id: input.host_id,
      profile,
      workload: workload.label(),
      source_sha256: input.source_sha256,
      pressure_qualification: false,
    };
    let floor_policy = CapacityFloorPolicy::from_id(input.capacity_floor_policy_id)?;
    let mut calibrations = Self::from_file(tenant, input.path, input.sha256, &identity)?;
    calibrations.capacity_floor_policy = floor_policy;
    Ok(calibrations)
  }

  fn from_environment(
    tenant: &TenantDomain,
    workload: Workload,
    selected_profile: &str,
  ) -> Result<Self, String> {
    let pressure_qualification = pressure_qualification_requested()?;
    let floor_policy_value = match std::env::var("ALLOCATBELT_APP_CAPACITY_FLOOR_POLICY_ID") {
      Ok(value) => Some(value),
      Err(std::env::VarError::NotPresent) => None,
      Err(std::env::VarError::NotUnicode(_)) => {
        return Err("capacity floor policy ID is not valid Unicode".into());
      }
    };
    let floor_policy = CapacityFloorPolicy::from_id(floor_policy_value.as_deref())?;
    validate_capacity_floor_activation(floor_policy, pressure_qualification, None)?;
    if pressure_qualification && std::env::var_os("ALLOCATBELT_APP_FEEDBACK_TRACE_DIR").is_none() {
      return Err("pressure qualification requires ALLOCATBELT_APP_FEEDBACK_TRACE_DIR".into());
    }
    if !super::is_token(selected_profile) {
      return Err("selected workload profile is malformed for capacity calibration".into());
    }
    validate_optional_calibration_identity("ALLOCATBELT_APP_PROFILE", selected_profile)?;
    validate_optional_calibration_identity("ALLOCATBELT_APP_WORKLOAD", workload.label())?;
    let path = std::env::var_os("ALLOCATBELT_APP_CAPACITY_CALIBRATION_FILE");
    let supplied_sha256 = std::env::var("ALLOCATBELT_APP_CAPACITY_CALIBRATION_SHA256");
    let (path, supplied_sha256) = match (path, supplied_sha256) {
      (None, Err(std::env::VarError::NotPresent)) if !pressure_qualification => {
        validate_capacity_floor_activation(floor_policy, pressure_qualification, Some(false))?;
        return Ok(Self::default());
      }
      (None, Err(std::env::VarError::NotPresent)) => {
        return Err(
          "pressure qualification requires a capacity calibration artifact and SHA-256".into(),
        );
      }
      (Some(_), Err(std::env::VarError::NotPresent))
      | (None, Ok(_))
      | (None, Err(std::env::VarError::NotUnicode(_)))
      | (Some(_), Err(std::env::VarError::NotUnicode(_))) => {
        return Err(
          "capacity calibration artifact path and SHA-256 must be supplied together".into(),
        );
      }
      (Some(path), Ok(hash)) => (path, hash),
    };
    if !super::is_hex(&supplied_sha256, 64) {
      return Err("capacity calibration SHA-256 must contain 64 hexadecimal digits".into());
    }
    let host_id = required_calibration_identity("ALLOCATBELT_APP_HOST_ID")?;
    let source_sha256 = required_calibration_identity("ALLOCATBELT_APP_SOURCE_SHA256")?;
    let identity = CalibrationRunIdentity {
      host_id: &host_id,
      profile: selected_profile,
      workload: workload.label(),
      source_sha256: &source_sha256,
      pressure_qualification,
    };
    validate_capacity_floor_activation(floor_policy, pressure_qualification, Some(true))?;
    let mut calibrations =
      Self::from_file(tenant, &PathBuf::from(path), &supplied_sha256, &identity)?;
    calibrations.capacity_floor_policy = floor_policy;
    Ok(calibrations)
  }

  fn from_file(
    tenant: &TenantDomain,
    path: &std::path::Path,
    supplied_sha256: &str,
    identity: &CalibrationRunIdentity<'_>,
  ) -> Result<Self, String> {
    let charge = tenant
      .try_acquire(
        DomainResources::ZERO.with(DomainResource::Control, CALIBRATION_ARTIFACT_CONTROL_CHARGE),
      )
      .map_err(|error| format!("capacity calibration Control charge failed: {error:?}"))?;
    let bytes = read_capacity_calibration(path)?;
    Self::from_bytes_with_charge(bytes, supplied_sha256, identity, charge)
  }

  fn from_bytes_with_charge(
    bytes: Vec<u8>,
    supplied_sha256: &str,
    identity: &CalibrationRunIdentity<'_>,
    charge: DomainReservation,
  ) -> Result<Self, String> {
    if !super::is_hex(supplied_sha256, 64) {
      return Err("capacity calibration SHA-256 must contain 64 hexadecimal digits".into());
    }
    if bytes.len() as u64 > MAX_CAPACITY_CALIBRATION_BYTES
      || bytes.capacity() > (2 * MAX_CAPACITY_CALIBRATION_BYTES as usize)
    {
      return Err("capacity calibration artifact buffer exceeds its charged bound".into());
    }
    let artifact_sha256 = capacity_artifact_hash::sha256_ascii(&bytes);
    if !capacity_artifact_hash::matches_hex(&artifact_sha256, supplied_sha256.as_bytes()) {
      return Err("capacity calibration artifact SHA-256 mismatch".into());
    }
    if !super::is_token(identity.host_id)
      || !super::is_token(identity.profile)
      || !super::is_token(identity.workload)
      || !super::is_hex(identity.source_sha256, 64)
    {
      return Err("capacity calibration run identity is malformed".into());
    }
    let parsed = parse_capacity_calibration(&bytes, identity)?;
    if identity.pressure_qualification {
      let (needs_disk, needs_download) = match identity.workload {
        "cpu" | "memory" => (false, false),
        "disk" => (true, false),
        "http" => (false, true),
        "mixed" => (true, true),
        _ => return Err("pressure calibration names an unsupported workload".into()),
      };
      if (needs_disk && parsed.disk.bytes_per_second.is_none())
        || (needs_download && parsed.download.bytes_per_second.is_none())
      {
        return Err(
          "pressure qualification requires capacities for the workload's application-byte sources"
            .into(),
        );
      }
    }
    let payload = String::from_utf8(bytes)
      .map_err(|_| "capacity calibration artifact is not UTF-8".to_owned())?;
    if payload.capacity() > (2 * MAX_CAPACITY_CALIBRATION_BYTES as usize) {
      return Err("capacity calibration string exceeds its charged bound".into());
    }
    let artifact = CapacityCalibrationArtifact {
      payload,
      calibration_id: parsed.calibration_id,
      host_id: parsed.host_id,
      profile: parsed.profile,
      workload: parsed.workload,
      source_sha256: parsed.source_sha256,
      artifact_sha256,
      disk: parsed.disk,
      download: parsed.download,
      _charge: charge,
    };
    Ok(Self {
      artifact: Some(Arc::new(artifact)),
      pressure_qualification: identity.pressure_qualification,
      capacity_floor_policy: CapacityFloorPolicy::StaticDefault,
    })
  }

  fn disk_capacity(&self) -> Option<NonZeroU64> {
    self
      .artifact
      .as_ref()
      .and_then(|artifact| artifact.disk.bytes_per_second)
  }

  fn download_capacity(&self) -> Option<NonZeroU64> {
    self
      .artifact
      .as_ref()
      .and_then(|artifact| artifact.download.bytes_per_second)
  }
}

#[cfg(feature = "resource-feedback")]
fn pressure_qualification_requested() -> Result<bool, String> {
  match std::env::var("ALLOCATBELT_APP_PRESSURE_QUALIFICATION") {
    Ok(value) if value == "true" => Ok(true),
    Ok(value) if value == "false" => Ok(false),
    Ok(_) => Err("ALLOCATBELT_APP_PRESSURE_QUALIFICATION must be true or false".into()),
    Err(std::env::VarError::NotPresent) => Ok(false),
    Err(std::env::VarError::NotUnicode(_)) => {
      Err("ALLOCATBELT_APP_PRESSURE_QUALIFICATION is not valid Unicode".into())
    }
  }
}

#[cfg(feature = "resource-feedback")]
fn required_calibration_identity(name: &str) -> Result<String, String> {
  let value =
    std::env::var(name).map_err(|_| format!("capacity calibration identity is missing {name}"))?;
  if !super::is_token(&value) {
    return Err(format!("capacity calibration identity {name} is malformed"));
  }
  Ok(value)
}

#[cfg(feature = "resource-feedback")]
fn validate_optional_calibration_identity(name: &str, expected: &str) -> Result<(), String> {
  match std::env::var(name) {
    Ok(value) if value == expected => Ok(()),
    Ok(_) => Err(format!(
      "capacity calibration {name} differs from the selected run"
    )),
    Err(std::env::VarError::NotPresent) => Ok(()),
    Err(std::env::VarError::NotUnicode(_)) => Err(format!(
      "capacity calibration identity {name} is not valid Unicode"
    )),
  }
}

#[cfg(feature = "resource-feedback")]
fn read_capacity_calibration(path: &std::path::Path) -> Result<Vec<u8>, String> {
  let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32;
  let mut options = OpenOptions::new();
  options.read(true).custom_flags(flags);
  let mut file = options
    .open(path)
    .map_err(|error| format!("capacity calibration artifact open failed: {error}"))?;
  let metadata = file
    .metadata()
    .map_err(|error| format!("capacity calibration artifact metadata failed: {error}"))?;
  if !metadata.file_type().is_file() || metadata.len() > MAX_CAPACITY_CALIBRATION_BYTES {
    return Err(
      "capacity calibration artifact must be a regular file no larger than 4096 bytes".into(),
    );
  }
  let mut bounded = [0; MAX_CAPACITY_CALIBRATION_BYTES as usize + 1];
  let mut length = 0;
  loop {
    let read = file
      .read(&mut bounded[length..])
      .map_err(|error| format!("capacity calibration artifact read failed: {error}"))?;
    if read == 0 {
      break;
    }
    length += read;
    if length > MAX_CAPACITY_CALIBRATION_BYTES as usize {
      return Err("capacity calibration artifact exceeds 4096 bytes".into());
    }
  }
  let mut bytes = Vec::with_capacity(length);
  bytes.extend_from_slice(&bounded[..length]);
  if bytes.capacity() > (2 * MAX_CAPACITY_CALIBRATION_BYTES as usize) {
    return Err("capacity calibration artifact buffer exceeds its charged bound".into());
  }
  Ok(bytes)
}

#[cfg(feature = "resource-feedback")]
fn parse_capacity_calibration(
  bytes: &[u8],
  identity: &CalibrationRunIdentity<'_>,
) -> Result<ParsedCapacityCalibration, String> {
  let text = std::str::from_utf8(bytes)
    .map_err(|_| "capacity calibration artifact is not UTF-8".to_owned())?;
  if !text.ends_with('\n') || text.contains(['\r', '\0']) {
    return Err("capacity calibration artifact must use LF lines and end with LF".into());
  }
  let mut values = [None; CAPACITY_CALIBRATION_FIELDS.len()];
  let mut offset = 0;
  for line in text[..text.len() - 1].split('\n') {
    let (key, value) = line
      .split_once('\t')
      .ok_or_else(|| "capacity calibration artifact contains an unframed row".to_owned())?;
    if key.is_empty()
      || value.is_empty()
      || value.contains('\t')
      || value.chars().any(char::is_control)
    {
      return Err("capacity calibration artifact contains an invalid field".into());
    }
    let Some(index) = CAPACITY_CALIBRATION_FIELDS
      .iter()
      .position(|expected| *expected == key)
    else {
      return Err("capacity calibration artifact contains an unknown field".into());
    };
    let span = (offset + key.len() + 1, offset + line.len());
    if values[index].replace(span).is_some() {
      return Err("capacity calibration artifact contains a duplicate field".into());
    }
    offset += line.len() + 1;
  }
  if CAPACITY_CALIBRATION_FIELDS
    .iter()
    .any(|name| calibration_field_span(&values, name).is_err())
  {
    return Err("capacity calibration artifact is missing a required field".into());
  }
  let field_range = |name: &str| calibration_field_span(&values, name);
  let field = |name: &str| -> Result<&str, String> {
    let range = field_range(name)?;
    Ok(&text[range])
  };
  if field("schema")? != CAPACITY_CALIBRATION_SCHEMA {
    return Err("capacity calibration artifact schema is unsupported".into());
  }
  let calibration_id = field("calibration_id")?;
  let host_id = field("host_id")?;
  let profile = field("profile")?;
  let workload = field("workload")?;
  let source_sha256 = field("source_sha256")?;
  if !super::is_token(calibration_id)
    || host_id != identity.host_id
    || profile != identity.profile
    || workload != identity.workload
    || source_sha256 != identity.source_sha256
  {
    return Err("capacity calibration artifact identity does not match this run".into());
  }
  if !super::is_hex(source_sha256, 64) {
    return Err("capacity calibration source SHA-256 is malformed".into());
  }
  let disk = parse_direction_calibration(
    "disk",
    field("disk.bytes_per_second")?,
    field("disk.units")?,
    field("disk.provenance")?,
    field_range("disk.provenance")?,
  )?;
  let download = parse_direction_calibration(
    "download",
    field("download.bytes_per_second")?,
    field("download.units")?,
    field("download.provenance")?,
    field_range("download.provenance")?,
  )?;
  Ok(ParsedCapacityCalibration {
    calibration_id: field_range("calibration_id")?,
    host_id: field_range("host_id")?,
    profile: field_range("profile")?,
    workload: field_range("workload")?,
    source_sha256: field_range("source_sha256")?,
    disk,
    download,
  })
}

#[cfg(feature = "resource-feedback")]
fn calibration_field_span(
  values: &[Option<(usize, usize)>; CAPACITY_CALIBRATION_FIELDS.len()],
  name: &str,
) -> Result<Range<usize>, String> {
  let index = CAPACITY_CALIBRATION_FIELDS
    .iter()
    .position(|expected| *expected == name)
    .ok_or_else(|| "capacity calibration field table is inconsistent".to_owned())?;
  let (start, end) =
    values[index].ok_or_else(|| format!("capacity calibration artifact is missing {name}"))?;
  Ok(start..end)
}

#[cfg(feature = "resource-feedback")]
fn parse_direction_calibration(
  direction: &str,
  capacity_text: &str,
  units: &str,
  provenance: &str,
  provenance_range: Range<usize>,
) -> Result<DirectionCalibration, String> {
  if provenance.trim().is_empty() {
    return Err(format!(
      "{direction} calibration provenance must be nonempty"
    ));
  }
  let bytes_per_second = if capacity_text == "missing" {
    if units != "missing" {
      return Err(format!(
        "missing {direction} capacity must use missing units"
      ));
    }
    None
  } else {
    if units != APPLICATION_BYTE_CALIBRATION_UNITS {
      return Err(format!(
        "{direction} calibration units must be {APPLICATION_BYTE_CALIBRATION_UNITS}"
      ));
    }
    Some(
      capacity_text
        .parse::<u64>()
        .ok()
        .and_then(NonZeroU64::new)
        .ok_or_else(|| format!("{direction} calibration capacity must be positive"))?,
    )
  };
  Ok(DirectionCalibration {
    bytes_per_second,
    provenance: provenance_range,
  })
}

#[cfg(feature = "resource-feedback")]
#[derive(Clone)]
struct FeedbackMeters {
  disk: IoFeedbackMeter,
  upload: IoFeedbackMeter,
  download: IoFeedbackMeter,
}

#[cfg(feature = "resource-feedback")]
struct FeedbackMeterCaptureOwner {
  meters: Mutex<Option<FeedbackMeters>>,
  _charge: DomainReservation,
}

#[cfg(feature = "resource-feedback")]
impl FeedbackMeterCaptureOwner {
  fn new(tenant: &TenantDomain) -> Result<Arc<Self>, String> {
    let charge_bytes = std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>();
    let charge = tenant
      .try_acquire(DomainResources::ZERO.with(DomainResource::Control, charge_bytes))
      .map_err(|error| format!("feedback meter capture Control charge failed: {error:?}"))?;
    Ok(Arc::new(Self {
      meters: Mutex::new(None),
      _charge: charge,
    }))
  }
}

pub(crate) fn fixed_rate_config() -> ByteRateConfig {
  ByteRateConfig {
    bytes_per_second: APPLICATION_RATE_CEILING_BYTES_PER_SECOND,
    burst_bytes: RATE_BURST_BYTES,
    max_reservations: RATE_RESERVATIONS,
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ApplicationRateConfigs {
  pub(crate) disk: ByteRateConfig,
  pub(crate) upload: ByteRateConfig,
  pub(crate) download: ByteRateConfig,
}

impl ApplicationRateConfigs {
  fn fixed() -> Self {
    Self {
      disk: fixed_rate_config(),
      upload: fixed_rate_config(),
      download: fixed_rate_config(),
    }
  }
}

#[cfg(feature = "resource-feedback")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedApplicationFeedback {
  pub(crate) policy: ResourceFeedbackPolicyConfig,
  pub(crate) rates: ApplicationRateConfigs,
  pub(crate) capacity_floor_policy_id: Option<&'static str>,
}

#[cfg(feature = "resource-feedback")]
fn resolve_application_feedback(
  workload: Workload,
  workers: usize,
  calibrations: &FeedbackCalibrations,
) -> Result<ResolvedApplicationFeedback, String> {
  let mut policy = feedback_policy(workers);
  let mut rates = ApplicationRateConfigs::fixed();
  let Some(artifact) = calibrations.artifact.as_deref() else {
    if calibrations.capacity_floor_policy != CapacityFloorPolicy::StaticDefault {
      return Err("capacity floor policy requires a validated capacity artifact".into());
    }
    return Ok(ResolvedApplicationFeedback {
      policy,
      rates,
      capacity_floor_policy_id: None,
    });
  };

  let needs_disk = matches!(workload, Workload::Disk | Workload::Mixed);
  let needs_download = matches!(workload, Workload::Http | Workload::Mixed);
  if needs_disk {
    resolve_calibrated_rate(
      "disk",
      artifact.disk.bytes_per_second,
      calibrations.capacity_floor_policy,
      &mut policy.disk_rate,
      &mut rates.disk,
    )?;
  }
  if needs_download {
    resolve_calibrated_rate(
      "download",
      artifact.download.bytes_per_second,
      calibrations.capacity_floor_policy,
      &mut policy.network_rate,
      &mut rates.download,
    )?;
  }
  Ok(ResolvedApplicationFeedback {
    policy,
    rates,
    capacity_floor_policy_id: calibrations.capacity_floor_policy.id(),
  })
}

#[cfg(feature = "resource-feedback")]
fn validate_capacity_floor_activation(
  floor_policy: CapacityFloorPolicy,
  pressure_qualification: bool,
  capacity_artifact_present: Option<bool>,
) -> Result<(), String> {
  if floor_policy == CapacityFloorPolicy::StaticDefault {
    return Ok(());
  }
  if !pressure_qualification {
    return Err("capacity-relative floor policy requires pressure qualification".into());
  }
  if capacity_artifact_present == Some(false) {
    return Err("capacity floor policy requires a validated capacity artifact".into());
  }
  Ok(())
}

#[cfg(feature = "resource-feedback")]
fn capacity_relative_floor(default_floor: u64, measured_capacity: u64) -> Result<u64, String> {
  let relative = measured_capacity
    .checked_div(CAPACITY_FLOOR_DIVISOR)
    .ok_or_else(|| "capacity-relative floor divisor is zero".to_owned())?;
  let floor = relative
    .min(default_floor)
    .max(CAPACITY_FLOOR_MINIMUM_BYTES_PER_SECOND);
  if floor > measured_capacity {
    return Err("capacity-relative floor exceeds measured application-byte capacity".into());
  }
  Ok(floor)
}

#[cfg(feature = "resource-feedback")]
fn resolve_calibrated_rate(
  direction: &str,
  measured_capacity: Option<NonZeroU64>,
  floor_policy: CapacityFloorPolicy,
  control: &mut FeedbackControlConfig,
  bucket: &mut ByteRateConfig,
) -> Result<(), String> {
  let measured_capacity = measured_capacity.ok_or_else(|| {
    format!("capacity calibration is missing the relevant {direction} application-byte source")
  })?;
  let raw_capacity = measured_capacity.get();
  let resolved = raw_capacity.min(APPLICATION_RATE_CEILING_BYTES_PER_SECOND);
  let floor = match floor_policy {
    CapacityFloorPolicy::StaticDefault => control.floor,
    CapacityFloorPolicy::CapacityRelativeTenth => {
      capacity_relative_floor(control.floor, raw_capacity)?
    }
  };
  if resolved < floor {
    return Err(format!(
      "{direction} application-byte capacity is below the selected feedback floor"
    ));
  }
  control.floor = floor;
  control.initial = resolved;
  control.ceiling = resolved;
  bucket.bytes_per_second = resolved;
  Ok(())
}

pub(crate) fn application_domain_limits(
  local_limits: ResourceLimits,
  workers: usize,
) -> Result<DomainResources, String> {
  if workers == 0 || workers > 4 {
    return Err("feedback policy probe requires a two- or four-worker bound".into());
  }
  Ok(
    DomainResources::ZERO
      .with(DomainResource::Cpu, workers)
      .with(DomainResource::Memory, local_limits.managed_memory)
      .with(DomainResource::Disk, local_limits.disk_concurrent_ops)
      .with(DomainResource::Network, local_limits.network_concurrent_ops)
      .with(DomainResource::Tasks, APPLICATION_TASK_CEILING)
      .with(DomainResource::Control, DOMAIN_CONTROL_CEILING),
  )
}

#[cfg(feature = "resource-feedback")]
pub(crate) fn construction_global_control_baseline(
  domain_limits: DomainResources,
) -> Result<usize, String> {
  let domain = ResourceDomain::with_waiters(domain_limits, 1, DOMAIN_WAITER_CEILING)
    .map_err(|error| format!("feedback policy baseline construction failed: {error:?}"))?;
  let snapshot = domain.snapshot();
  if snapshot.live_tenants != 0 {
    return Err("feedback policy baseline construction unexpectedly created a tenant".into());
  }
  let baseline = snapshot.used.get(DomainResource::Control);
  drop(domain);
  Ok(baseline)
}

#[cfg(feature = "resource-feedback")]
pub(crate) fn feedback_policy_control_config(workers: usize) -> ResourceFeedbackPolicyConfig {
  feedback_policy(workers)
}

/// Pre-runtime owner shared by both executor variants.
pub(crate) struct ApplicationDomain {
  domain: ResourceDomain,
  tenant: TenantDomain,
  cpu_gate: CpuGate,
  local_limits: ResourceLimits,
  domain_limits: DomainResources,
  fixed_global_control_baseline: usize,
  application_rates: ApplicationRateConfigs,
  #[cfg(feature = "resource-feedback")]
  workers: usize,
  #[cfg(feature = "resource-feedback")]
  feedback_calibrations: FeedbackCalibrations,
  #[cfg(feature = "resource-feedback")]
  resolved_feedback: ResolvedApplicationFeedback,
  mode: ApplicationMode,
  #[cfg(feature = "resource-feedback")]
  feedback_meters: Option<Arc<FeedbackMeterCaptureOwner>>,
}

impl ApplicationDomain {
  #[cfg(test)]
  pub(crate) fn new(workload: Workload, workers: usize) -> Result<Self, String> {
    let comparison_family = std::env::var("ALLOCATBELT_APP_COMPARISON_FAMILY").ok();
    let mode = ApplicationMode::from_comparison_family(comparison_family.as_deref())?;
    Self::new_with_mode(workload, workers, mode)
  }

  pub(crate) fn new_for_profile(
    workload: Workload,
    workers: usize,
    selected_profile: &str,
  ) -> Result<Self, String> {
    let comparison_family = std::env::var("ALLOCATBELT_APP_COMPARISON_FAMILY").ok();
    let mode = ApplicationMode::from_comparison_family(comparison_family.as_deref())?;
    Self::build_with_profile(workload, workers, mode, Some(selected_profile))
  }

  #[cfg(test)]
  fn new_with_mode(
    workload: Workload,
    workers: usize,
    mode: ApplicationMode,
  ) -> Result<Self, String> {
    Self::build_with_profile(workload, workers, mode, None)
  }

  fn build_with_profile(
    workload: Workload,
    workers: usize,
    mode: ApplicationMode,
    selected_profile: Option<&str>,
  ) -> Result<Self, String> {
    #[cfg(not(feature = "resource-feedback"))]
    let _ = selected_profile;
    Self::build(
      workload,
      workers,
      mode,
      #[cfg(feature = "resource-feedback")]
      selected_profile,
      #[cfg(feature = "resource-feedback")]
      None,
      #[cfg(feature = "resource-feedback")]
      None,
    )
  }

  #[cfg(feature = "resource-feedback")]
  #[cfg(test)]
  fn new_with_calibrations(
    workload: Workload,
    workers: usize,
    mode: ApplicationMode,
    feedback_calibrations: FeedbackCalibrations,
  ) -> Result<Self, String> {
    Self::build(
      workload,
      workers,
      mode,
      None,
      Some(feedback_calibrations),
      None,
    )
  }

  #[cfg(feature = "resource-feedback")]
  pub(super) fn new_for_feedback_probe(
    workload: Workload,
    workers: usize,
    selected_profile: &str,
    calibration: CapacityCalibrationProbeInput<'_>,
  ) -> Result<Self, String> {
    Self::build(
      workload,
      workers,
      ApplicationMode::ExternalPressure,
      Some(selected_profile),
      None,
      Some(calibration),
    )
  }

  fn build(
    workload: Workload,
    workers: usize,
    mode: ApplicationMode,
    #[cfg(feature = "resource-feedback")] selected_profile: Option<&str>,
    #[cfg(feature = "resource-feedback")] injected_calibrations: Option<FeedbackCalibrations>,
    #[cfg(feature = "resource-feedback")] probe_calibration: Option<
      CapacityCalibrationProbeInput<'_>,
    >,
  ) -> Result<Self, String> {
    if workers == 0 || workers > 4 {
      return Err("application runtime requires a frozen two- or four-worker bound".into());
    }
    let local_limits = resource_limits(workload);
    let domain_limits = application_domain_limits(local_limits, workers)?;
    let domain = ResourceDomain::with_waiters(domain_limits, 1, DOMAIN_WAITER_CEILING)
      .map_err(|error| format!("application resource-domain startup failed: {error:?}"))?;
    let fixed_global_control_baseline = domain.snapshot().used.get(DomainResource::Control);
    let tenant = domain
      .tenant(domain_limits)
      .map_err(|error| format!("application tenant startup failed: {error:?}"))?;
    let cpu_gate = CpuGate::new(tenant.clone(), CPU_WAITER_CEILING)
      .map_err(|error| format!("application CPU gate startup failed: {error:?}"))?;
    #[cfg(feature = "resource-feedback")]
    let feedback_calibrations = if mode.feedback_enabled() {
      match (injected_calibrations, probe_calibration) {
        (Some(calibrations), None) => calibrations,
        (None, Some(calibration)) => {
          let selected_profile = selected_profile
            .ok_or_else(|| "calibration probe requires the selected workload profile".to_owned())?;
          FeedbackCalibrations::from_explicit_probe_file(
            &tenant,
            workload,
            selected_profile,
            calibration,
          )?
        }
        (None, None) => {
          let selected_profile = selected_profile.ok_or_else(|| {
            "external-pressure application bindings require the selected workload profile"
              .to_owned()
          })?;
          FeedbackCalibrations::from_environment(&tenant, workload, selected_profile)?
        }
        (Some(_), Some(_)) => {
          return Err("application feedback calibration source was supplied more than once".into());
        }
      }
    } else {
      if injected_calibrations.is_some() || probe_calibration.is_some() {
        return Err("fixed-policy application cannot load feedback calibration".into());
      }
      if pressure_qualification_requested()? {
        return Err(
          "pressure qualification requires the external-pressure comparison family".into(),
        );
      }
      FeedbackCalibrations::default()
    };
    #[cfg(feature = "resource-feedback")]
    let resolved_feedback =
      resolve_application_feedback(workload, workers, &feedback_calibrations)?;
    #[cfg(feature = "resource-feedback")]
    let application_rates = resolved_feedback.rates;
    #[cfg(not(feature = "resource-feedback"))]
    let application_rates = ApplicationRateConfigs::fixed();
    #[cfg(feature = "resource-feedback")]
    let feedback_meters = if mode.feedback_enabled() {
      Some(FeedbackMeterCaptureOwner::new(&tenant)?)
    } else {
      None
    };
    #[cfg(not(feature = "resource-feedback"))]
    if mode.feedback_enabled() {
      return Err("external-pressure comparison requires the resource-feedback feature".into());
    }
    Ok(Self {
      domain,
      tenant,
      cpu_gate,
      local_limits,
      domain_limits,
      fixed_global_control_baseline,
      application_rates,
      #[cfg(feature = "resource-feedback")]
      workers,
      #[cfg(feature = "resource-feedback")]
      feedback_calibrations,
      #[cfg(feature = "resource-feedback")]
      resolved_feedback,
      mode,
      #[cfg(feature = "resource-feedback")]
      feedback_meters,
    })
  }

  #[cfg(feature = "resource-feedback")]
  pub(crate) fn feedback_factory(
    &self,
  ) -> Result<Option<allocatbelt::runtime::driver::FeedbackFactory>, String> {
    if self.mode != ApplicationMode::ExternalPressure {
      return Ok(None);
    }
    let workers = NonZeroU32::new(
      u32::try_from(self.workers)
        .map_err(|_| "feedback CPU capacity does not fit u32".to_owned())?,
    )
    .ok_or_else(|| "feedback CPU capacity must be positive".to_owned())?;
    let capture = self
      .feedback_meters
      .as_ref()
      .cloned()
      .ok_or_else(|| "feedback meter capture owner is missing".to_owned())?;
    let expected_tenant = self.tenant.clone();
    let expected_limits = self.local_limits;
    let disk_capacity = self.feedback_calibrations.disk_capacity();
    let download_capacity = self.feedback_calibrations.download_capacity();
    let resolved = self.resolved_feedback;
    let upload_rate_config = self.application_rates.upload;
    let policy = resolved.policy;
    let history = feedback_history_config()?;
    Ok(Some(
      allocatbelt::runtime::driver::feedback_sources_with_history(
        policy,
        history,
        move |context| {
          if context.resources.limits() != expected_limits {
            return Err(std::io::Error::new(
              std::io::ErrorKind::InvalidInput,
              "feedback scope limits differ from the application workload",
            ));
          }
          let tenant = context.resources.tenant_domain().cloned().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "feedback tenant missing")
          })?;
          if !tenant.same_account(&expected_tenant) {
            return Err(std::io::Error::new(
              std::io::ErrorKind::InvalidInput,
              "feedback service was bound to a different tenant account",
            ));
          }
          let disk_rate = context.disk_rate.clone().ok_or_else(|| {
            std::io::Error::new(
              std::io::ErrorKind::InvalidInput,
              "feedback disk rate missing",
            )
          })?;
          let download_rate = context.download_rate.clone().ok_or_else(|| {
            std::io::Error::new(
              std::io::ErrorKind::InvalidInput,
              "feedback download rate missing",
            )
          })?;
          let upload_rate = context.upload_rate.as_ref().ok_or_else(|| {
            std::io::Error::new(
              std::io::ErrorKind::InvalidInput,
              "feedback upload bucket missing from matched runtime",
            )
          })?;
          validate_initial_feedback_rates(&disk_rate, &download_rate, resolved)?;
          let upload_snapshot = upload_rate.snapshot();
          if upload_snapshot.bytes_per_second != upload_rate_config.bytes_per_second
            || upload_snapshot.ceiling_bytes_per_second != upload_rate_config.bytes_per_second
          {
            return Err(std::io::Error::new(
              std::io::ErrorKind::InvalidInput,
              "upload rate differs from the matched fixed bucket",
            ));
          }
          let sensor = RuntimeFeedbackSensor::new(
            ProcessCpuSensor::new(workers)?,
            disk_capacity
              .map(|capacity| IoFeedbackSource::new(context.disk_meter.clone(), capacity)),
            download_capacity
              .map(|capacity| IoFeedbackSource::new(context.download_meter.clone(), capacity)),
            NonZeroU32::new(FEEDBACK_MINIMUM_DENSE_OBSERVATIONS).ok_or_else(|| {
              std::io::Error::new(std::io::ErrorKind::InvalidInput, "zero density threshold")
            })?,
          );
          let meters = FeedbackMeters {
            disk: context.disk_meter,
            upload: context.upload_meter,
            download: context.download_meter,
          };
          let mut slot = capture
            .meters
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
          if slot.is_some() {
            return Err(std::io::Error::new(
              std::io::ErrorKind::AlreadyExists,
              "feedback context was initialized more than once",
            ));
          }
          *slot = Some(meters);
          Ok((
            sensor,
            RuntimeFeedbackActuator::new(
              CpuFeedbackTarget::Tenant(tenant),
              disk_rate,
              download_rate,
            ),
          ))
        },
      ),
    ))
  }

  pub(crate) fn tenant(&self) -> TenantDomain {
    self.tenant.clone()
  }

  #[cfg(feature = "resource-feedback")]
  pub(crate) fn reserve_task(&self) -> Result<ApplicationTaskLease, String> {
    ApplicationTaskAdmission {
      tenant: self.tenant.clone(),
    }
    .reserve()
  }

  pub(crate) fn local_limits(&self) -> ResourceLimits {
    self.local_limits
  }

  #[cfg(test)]
  pub(crate) fn domain_limits(&self) -> DomainResources {
    self.domain_limits
  }

  pub(crate) fn fixed_global_control_baseline(&self) -> usize {
    self.fixed_global_control_baseline
  }

  pub(crate) fn readback_domain(&self) -> ResourceDomain {
    self.domain.clone()
  }

  pub(crate) fn rate_configs(&self) -> ApplicationRateConfigs {
    self.application_rates
  }

  #[cfg(feature = "resource-feedback")]
  pub(super) fn resolved_feedback(&self) -> ResolvedApplicationFeedback {
    self.resolved_feedback
  }

  #[cfg(feature = "resource-feedback")]
  pub(super) fn feedback_calibrations(&self) -> &FeedbackCalibrations {
    &self.feedback_calibrations
  }

  pub(crate) fn for_native(
    &self,
    driver: &MultiThreadDriver,
  ) -> Result<ApplicationRunBindings, String> {
    validate_native_scope_binding(&self.tenant, driver.resources(), self.local_limits)?;
    let io = driver
      .io_bindings()
      .map_err(|error| format!("native I/O bindings failed: {error:?}"))?;
    let disk_rate = driver
      .disk_rate()
      .ok_or_else(|| "native filesystem driver lacks the fixed disk byte bucket".to_owned())?;
    let upload_rate = driver
      .upload_rate()
      .ok_or_else(|| "native runtime lacks the fixed upload byte bucket".to_owned())?;
    let download_rate = driver
      .download_rate()
      .ok_or_else(|| "native runtime lacks the fixed download byte bucket".to_owned())?;
    #[cfg(feature = "resource-feedback")]
    let (meters, metrics) = if self.mode.feedback_enabled() {
      let meters = self
        .feedback_meters
        .as_ref()
        .ok_or_else(|| "native feedback meter capture owner is missing".to_owned())?
        .meters
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .ok_or_else(|| "native feedback factory did not expose its selected meters".to_owned())?;
      let metrics = driver
        .feedback_metrics()
        .ok_or_else(|| "native external-pressure service did not start".to_owned())?;
      (Some(meters), Some(metrics))
    } else {
      (None, None)
    };
    let blocking_disk_io = None;
    Ok(ApplicationRunBindings {
      domain: self.domain.clone(),
      tenant: self.tenant.clone(),
      cpu_gate: self.cpu_gate.clone(),
      resources: driver.resources().clone(),
      io: ApplicationIoBindings {
        bindings: io,
        disk_rate,
        upload_rate,
        download_rate,
        blocking_disk_io,
        #[cfg(feature = "resource-feedback")]
        meters,
      },
      rate_timer_owner: None,
      #[cfg(feature = "resource-feedback")]
      feedback: FeedbackOwner {
        mode: self.mode,
        metrics,
        service: None,
        workers: self.workers,
        calibrations: self.feedback_calibrations.clone(),
        resolved: self.resolved_feedback,
      },
      #[cfg(not(feature = "resource-feedback"))]
      mode: self.mode,
      domain_limits: self.domain_limits,
      fixed_global_control_baseline: self.fixed_global_control_baseline,
    })
  }

  pub(crate) fn for_tokio(&self) -> Result<ApplicationRunBindings, String> {
    let resources = ResourceScope::try_from_tenant(self.local_limits, self.tenant.clone())
      .map_err(|error| format!("Tokio tenant-bound scope startup failed: {error:?}"))?;
    let timer_owner =
      TimerDriver::new_realtime_in_tenant(RATE_TIMER_REGISTRATIONS, &self.tenant)
        .map_err(|error| format!("Tokio fixed-rate timer startup failed: {error:?}"))?;
    let timer = timer_owner.handle();
    let disk_rate = ByteRateLimit::new_in_tenant(self.application_rates.disk, &self.tenant)
      .map_err(|error| format!("Tokio disk byte bucket startup failed: {error:?}"))?;
    let upload = ByteRateLimit::new_in_tenant(self.application_rates.upload, &self.tenant)
      .map_err(|error| format!("Tokio upload byte bucket startup failed: {error:?}"))?;
    let download = ByteRateLimit::new_in_tenant(self.application_rates.download, &self.tenant)
      .map_err(|error| format!("Tokio download byte bucket startup failed: {error:?}"))?;
    #[cfg(feature = "resource-feedback")]
    let meters = if self.mode.feedback_enabled() {
      let meters = FeedbackMeters {
        disk: IoFeedbackMeter::new_in_tenant(&self.tenant)
          .map_err(|error| format!("Tokio disk meter startup failed: {error:?}"))?,
        upload: IoFeedbackMeter::new_in_tenant(&self.tenant)
          .map_err(|error| format!("Tokio upload meter startup failed: {error:?}"))?,
        download: IoFeedbackMeter::new_in_tenant(&self.tenant)
          .map_err(|error| format!("Tokio download meter startup failed: {error:?}"))?,
      };
      Some(meters)
    } else {
      None
    };
    #[cfg(feature = "resource-feedback")]
    let io = if let Some(meters) = meters.as_ref() {
      IoBindings::from_metered_components(
        &resources,
        Some(&disk_rate),
        Some(&upload),
        Some(&download),
        Some(&timer),
        (&meters.disk, &meters.upload, &meters.download),
      )
    } else {
      IoBindings::from_components(
        &resources,
        Some(&disk_rate),
        Some(&upload),
        Some(&download),
        Some(&timer),
      )
    }
    .map_err(|error| format!("Tokio I/O bindings failed: {error:?}"))?;
    #[cfg(not(feature = "resource-feedback"))]
    let io = IoBindings::from_components(
      &resources,
      Some(&disk_rate),
      Some(&upload),
      Some(&download),
      Some(&timer),
    )
    .map_err(|error| format!("Tokio I/O bindings failed: {error:?}"))?;
    #[cfg(feature = "resource-feedback")]
    let blocking_disk_io = (self.local_limits.disk_concurrent_ops != 0)
      .then(|| match meters.as_ref() {
        Some(meters) => BlockingByteIo::new_metered(&disk_rate, Some(&self.tenant), &meters.disk),
        None => BlockingByteIo::new(&disk_rate, Some(&self.tenant)),
      })
      .transpose()
      .map_err(|error| format!("Tokio blocking disk byte adapter failed: {error:?}"))?;
    #[cfg(feature = "resource-feedback")]
    let feedback_service = if let Some(meters) = meters.as_ref() {
      let sensor = feedback_sensor(self.workers, meters, &self.feedback_calibrations)?;
      validate_initial_feedback_rates(&disk_rate, &download, self.resolved_feedback)
        .map_err(|error| format!("Tokio feedback rate construction mismatch: {error}"))?;
      let upload_snapshot = upload.snapshot();
      if upload_snapshot.bytes_per_second != self.application_rates.upload.bytes_per_second
        || upload_snapshot.ceiling_bytes_per_second
          != self.application_rates.upload.bytes_per_second
      {
        return Err("Tokio upload rate differs from the matched fixed bucket".into());
      }
      Some(
        ResourceFeedbackService::start_in_tenant_with_history(
          self.resolved_feedback.policy,
          sensor,
          RuntimeFeedbackActuator::new(
            CpuFeedbackTarget::Tenant(self.tenant.clone()),
            disk_rate.clone(),
            download.clone(),
          ),
          &self.tenant,
          feedback_history_config()?,
        )
        .map_err(|error| format!("Tokio external-pressure service startup failed: {error}"))?,
      )
    } else {
      None
    };
    #[cfg(not(feature = "resource-feedback"))]
    let blocking_disk_io = (self.local_limits.disk_concurrent_ops != 0)
      .then(|| BlockingByteIo::new(&disk_rate, Some(&self.tenant)))
      .transpose()
      .map_err(|error| format!("Tokio blocking disk byte adapter failed: {error:?}"))?;
    Ok(ApplicationRunBindings {
      domain: self.domain.clone(),
      tenant: self.tenant.clone(),
      cpu_gate: self.cpu_gate.clone(),
      resources: resources.clone(),
      io: ApplicationIoBindings {
        bindings: io,
        disk_rate,
        upload_rate: upload,
        download_rate: download,
        blocking_disk_io,
        #[cfg(feature = "resource-feedback")]
        meters,
      },
      rate_timer_owner: Some(timer_owner),
      #[cfg(feature = "resource-feedback")]
      feedback: FeedbackOwner {
        mode: self.mode,
        metrics: feedback_service
          .as_ref()
          .map(ResourceFeedbackService::metrics_handle),
        service: feedback_service,
        workers: self.workers,
        calibrations: self.feedback_calibrations.clone(),
        resolved: self.resolved_feedback,
      },
      #[cfg(not(feature = "resource-feedback"))]
      mode: self.mode,
      domain_limits: self.domain_limits,
      fixed_global_control_baseline: self.fixed_global_control_baseline,
    })
  }
}

#[cfg(feature = "resource-feedback")]
pub(crate) fn feedback_policy(workers: usize) -> ResourceFeedbackPolicyConfig {
  let cpu = workers as u64;
  ResourceFeedbackPolicyConfig {
    cpu_concurrency: FeedbackControlConfig::new(
      1,
      cpu,
      cpu,
      FEEDBACK_LOW_UTILIZATION_BPS,
      FEEDBACK_HIGH_UTILIZATION_BPS,
    ),
    disk_rate: FeedbackControlConfig::new(
      FEEDBACK_RATE_FLOOR,
      APPLICATION_RATE_CEILING_BYTES_PER_SECOND,
      APPLICATION_RATE_CEILING_BYTES_PER_SECOND,
      FEEDBACK_LOW_UTILIZATION_BPS,
      FEEDBACK_HIGH_UTILIZATION_BPS,
    ),
    network_rate: FeedbackControlConfig::new(
      FEEDBACK_RATE_FLOOR,
      APPLICATION_RATE_CEILING_BYTES_PER_SECOND,
      APPLICATION_RATE_CEILING_BYTES_PER_SECOND,
      FEEDBACK_LOW_UTILIZATION_BPS,
      FEEDBACK_HIGH_UTILIZATION_BPS,
    ),
  }
}

#[cfg(feature = "resource-feedback")]
fn validate_initial_feedback_rates(
  disk_rate: &ByteRateLimit,
  download_rate: &ByteRateLimit,
  resolved: ResolvedApplicationFeedback,
) -> std::io::Result<()> {
  for (name, rate, control, bucket) in [
    (
      "disk",
      disk_rate,
      resolved.policy.disk_rate,
      resolved.rates.disk,
    ),
    (
      "download",
      download_rate,
      resolved.policy.network_rate,
      resolved.rates.download,
    ),
  ] {
    let snapshot = rate.snapshot();
    if snapshot.bytes_per_second != control.initial
      || snapshot.ceiling_bytes_per_second != control.ceiling
      || snapshot.ceiling_bytes_per_second != bucket.bytes_per_second
    {
      return Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("{name} feedback rate differs from the resolved initial value or ceiling"),
      ));
    }
  }
  Ok(())
}

#[cfg(feature = "resource-feedback")]
fn feedback_sensor(
  workers: usize,
  meters: &FeedbackMeters,
  calibrations: &FeedbackCalibrations,
) -> Result<RuntimeFeedbackSensor, String> {
  let cpu_capacity =
    NonZeroU32::new(u32::try_from(workers).map_err(|_| "feedback CPU capacity does not fit u32")?)
      .ok_or("feedback CPU capacity must be positive")?;
  let density = NonZeroU32::new(FEEDBACK_MINIMUM_DENSE_OBSERVATIONS)
    .ok_or("feedback density threshold must be positive")?;
  Ok(RuntimeFeedbackSensor::new(
    ProcessCpuSensor::new(cpu_capacity)
      .map_err(|error| format!("process CPU sensor startup failed: {error}"))?,
    calibrations
      .disk_capacity()
      .map(|capacity| IoFeedbackSource::new(meters.disk.clone(), capacity)),
    calibrations
      .download_capacity()
      .map(|capacity| IoFeedbackSource::new(meters.download.clone(), capacity)),
    density,
  ))
}

#[cfg(all(test, feature = "resource-feedback"))]
#[path = "feedback_bindings_tests.rs"]
mod feedback_tests;

fn validate_native_scope_binding(
  expected_tenant: &TenantDomain,
  scope: &ResourceScope,
  expected_limits: ResourceLimits,
) -> Result<(), String> {
  if scope.limits() != expected_limits {
    return Err("native runtime resource scope limits differ from the selected domain".into());
  }
  let actual_tenant = scope
    .tenant_domain()
    .ok_or_else(|| "native runtime resource scope is not tenant-bound".to_owned())?;
  if !actual_tenant.same_account(expected_tenant) {
    return Err("native runtime resource scope belongs to a different tenant account".into());
  }
  Ok(())
}

pub(crate) struct ApplicationRunBindings {
  domain: ResourceDomain,
  tenant: TenantDomain,
  cpu_gate: CpuGate,
  resources: ResourceScope,
  io: ApplicationIoBindings,
  rate_timer_owner: Option<TimerDriver>,
  #[cfg(feature = "resource-feedback")]
  feedback: FeedbackOwner,
  #[cfg(not(feature = "resource-feedback"))]
  mode: ApplicationMode,
  domain_limits: DomainResources,
  fixed_global_control_baseline: usize,
}

impl Drop for ApplicationRunBindings {
  fn drop(&mut self) {
    #[cfg(feature = "resource-feedback")]
    if let Some(mut service) = self.feedback.service.take() {
      let Some(deadline) = Instant::now().checked_add(Duration::from_secs(5)) else {
        service.request_stop();
        return;
      };
      loop {
        match service.try_shutdown() {
          Ok(allocatbelt::runtime::resource_feedback::FeedbackShutdownProgress::Complete)
          | Err(_) => break,
          Ok(allocatbelt::runtime::resource_feedback::FeedbackShutdownProgress::Pending) => {
            if Instant::now() >= deadline {
              break;
            }
            std::thread::sleep(Duration::from_millis(1));
          }
        }
      }
    }
  }
}

impl ApplicationRunBindings {
  pub(crate) fn mode(&self) -> ApplicationMode {
    #[cfg(feature = "resource-feedback")]
    {
      self.feedback.mode
    }
    #[cfg(not(feature = "resource-feedback"))]
    {
      self.mode
    }
  }

  pub(crate) fn feedback_started(&self) -> bool {
    #[cfg(feature = "resource-feedback")]
    {
      self.feedback.metrics.is_some()
    }
    #[cfg(not(feature = "resource-feedback"))]
    {
      false
    }
  }

  #[cfg(feature = "resource-feedback")]
  pub(crate) fn wait_for_feedback_startup_observation(&self) -> Result<Instant, String> {
    if !self.mode().feedback_enabled() {
      return Err("fixed-policy runs do not wait for feedback startup telemetry".into());
    }
    let metrics = self
      .feedback
      .metrics
      .as_ref()
      .ok_or_else(|| "feedback startup metrics handle is missing".to_owned())?;
    let deadline = Instant::now()
      .checked_add(SAMPLE_INTERVAL + MAX_DENSE_SAMPLE_GAP)
      .ok_or_else(|| "feedback startup observation deadline overflow".to_owned())?;
    loop {
      if Instant::now() >= deadline {
        return Err(
          "feedback service did not accept fresh dense CPU telemetry before the startup deadline"
            .into(),
        );
      }
      let snapshot = metrics.snapshot();
      if let Some(failure) = snapshot.worker_failure {
        return Err(format!(
          "feedback worker failed before production: {failure:?}"
        ));
      }
      if snapshot.stop_requested || snapshot.shutdown_complete {
        return Err("feedback service stopped before startup telemetry was accepted".into());
      }
      if let Some(sample_at) = snapshot.last_sample_at {
        let cpu = snapshot.control(FeedbackResource::CpuConcurrency);
        if cpu.policy_faulted {
          return Err("CPU feedback policy faulted before production".into());
        }
        let plan_published_for_sample = snapshot
          .last_plan_at
          .is_some_and(|plan_at| plan_at >= sample_at);
        let now = Instant::now();
        if snapshot.sample_count > 0
          && plan_published_for_sample
          && cpu.telemetry == TelemetryStatus::Fresh
          && cpu.utilization_basis_points.is_some()
          && now
            .checked_duration_since(sample_at)
            .is_some_and(|age| age <= TELEMETRY_FRESHNESS)
        {
          if Instant::now() >= deadline {
            return Err(
              "feedback service did not accept fresh dense CPU telemetry before the startup deadline"
                .into(),
            );
          }
          return Ok(sample_at);
        }
      }
      if Instant::now() >= deadline {
        return Err(
          "feedback service did not accept fresh dense CPU telemetry before the startup deadline"
            .into(),
        );
      }
      std::thread::sleep(Duration::from_millis(1));
    }
  }

  #[cfg(feature = "resource-feedback")]
  pub(crate) fn wait_for_feedback_observation_after(
    &self,
    minimum_sample_lower_ns: u128,
    mut map_bounds: impl FnMut(Instant) -> Result<(u128, u128), String>,
  ) -> Result<Instant, String> {
    if !self.mode().feedback_enabled() {
      return Err("post-drain feedback observation was supplied to a fixed-policy run".into());
    }
    let metrics = self
      .feedback
      .metrics
      .as_ref()
      .ok_or_else(|| "post-drain feedback metrics handle is missing".to_owned())?;
    let deadline = Instant::now()
      .checked_add(SAMPLE_INTERVAL + MAX_DENSE_SAMPLE_GAP)
      .ok_or_else(|| "post-drain feedback observation deadline overflow".to_owned())?;
    loop {
      if Instant::now() >= deadline {
        return Err(
          "feedback service did not accept a fresh dense CPU sample after the drain clock bracket before the finite deadline"
            .into(),
        );
      }
      let snapshot = metrics.snapshot();
      if let Some(failure) = snapshot.worker_failure {
        return Err(format!(
          "feedback worker failed while waiting for a post-drain observation: {failure:?}"
        ));
      }
      if snapshot.stop_requested || snapshot.shutdown_complete {
        return Err(
          "feedback service stopped before its post-drain observation was accepted".into(),
        );
      }
      if snapshot.sample_count > 0 {
        let cpu = snapshot.control(FeedbackResource::CpuConcurrency);
        if cpu.policy_faulted {
          return Err("CPU feedback policy faulted before the post-drain observation".into());
        }
        if let Some(sample_at) = snapshot.last_sample_at {
          let plan_published_for_sample = snapshot
            .last_plan_at
            .is_some_and(|plan_at| plan_at >= sample_at);
          let fresh = Instant::now()
            .checked_duration_since(sample_at)
            .is_some_and(|age| age <= TELEMETRY_FRESHNESS);
          if fresh
            && plan_published_for_sample
            && cpu.telemetry == TelemetryStatus::Fresh
            && cpu.utilization_basis_points.is_some()
          {
            let (sample_lower_ns, sample_upper_ns) = map_bounds(sample_at)?;
            if sample_lower_ns > sample_upper_ns {
              return Err("post-drain feedback sample clock bracket is inverted".into());
            }
            if Instant::now() >= deadline {
              return Err(
                "feedback service did not accept a fresh dense CPU sample after the drain clock bracket before the finite deadline"
                  .into(),
              );
            }
            if sample_lower_ns >= minimum_sample_lower_ns {
              return Ok(sample_at);
            }
          }
        }
      }
      if Instant::now() >= deadline {
        return Err(
          "feedback service did not accept a fresh dense CPU sample after the drain clock bracket before the finite deadline"
            .into(),
        );
      }
      std::thread::sleep(Duration::from_millis(1));
    }
  }

  #[cfg(feature = "resource-feedback")]
  pub(crate) fn validate_feedback_startup_observation(
    &self,
    sample_at: Instant,
    production_start: Instant,
    sample_bounds: Option<(u128, u128)>,
    production_bounds: Option<(u128, u128)>,
  ) -> Result<(), String> {
    if !self.mode().feedback_enabled() {
      return Err("startup feedback observation was supplied to a fixed-policy run".into());
    }
    let Some(age) = production_start.checked_duration_since(sample_at) else {
      return Err("feedback startup sample occurred after production start".into());
    };
    if age > TELEMETRY_FRESHNESS {
      return Err("feedback startup CPU telemetry was stale at production start".into());
    }
    match (sample_bounds, production_bounds) {
      (Some((sample_lower, sample_upper)), Some((start_lower, start_upper)))
        if sample_lower <= sample_upper
          && start_lower <= start_upper
          && sample_upper <= start_lower => {}
      (None, None) => {}
      (Some(_), Some(_)) => {
        return Err(
          "feedback sample clock bracket overlaps or follows production-start bracket".into(),
        );
      }
      _ => return Err("feedback startup clock bounds were only partially captured".into()),
    }
    // Startup telemetry is admitted by `wait_for_feedback_startup_observation`
    // before production begins. Re-reading live metrics here would make the
    // post-run check depend on later sensor state (which can legitimately be
    // Missing after the workload has ended), instead of the captured startup
    // sample and its clock relationship to production.
    Ok(())
  }

  #[cfg(feature = "resource-feedback")]
  pub(crate) fn feedback_shutdown_status(&self) -> Option<(bool, Option<FeedbackWorkerFailure>)> {
    self.feedback.metrics.as_ref().map(|metrics| {
      let snapshot = metrics.snapshot();
      (snapshot.shutdown_complete, snapshot.worker_failure)
    })
  }

  #[cfg(feature = "resource-feedback")]
  pub(super) fn start_feedback_trace(
    &self,
    run_mode: super::Mode,
  ) -> Result<Option<super::feedback_trace::FeedbackTraceCollector>, String> {
    self.start_feedback_trace_inner(run_mode.label(), false)
  }

  #[cfg(feature = "resource-feedback")]
  pub(crate) fn start_feedback_trace_for_mode(
    &self,
    run_mode: &'static str,
  ) -> Result<Option<super::feedback_trace::FeedbackTraceCollector>, String> {
    self.start_feedback_trace_inner(run_mode, true)
  }

  #[cfg(feature = "resource-feedback")]
  fn start_feedback_trace_inner(
    &self,
    run_mode: &'static str,
    require_trace: bool,
  ) -> Result<Option<super::feedback_trace::FeedbackTraceCollector>, String> {
    let trace_directory = std::env::var_os("ALLOCATBELT_APP_FEEDBACK_TRACE_DIR");
    if !self.mode().feedback_enabled() {
      return if trace_directory.is_some() {
        Err("feedback trace output is only supported for external-pressure runs".into())
      } else {
        Ok(None)
      };
    }
    let pressure_qualification = self.feedback.calibrations.pressure_qualification;
    let Some(trace_directory) = trace_directory else {
      if pressure_qualification {
        return Err("pressure qualification requires ALLOCATBELT_APP_FEEDBACK_TRACE_DIR".into());
      }
      if require_trace {
        return Err("external soak requires ALLOCATBELT_APP_FEEDBACK_TRACE_DIR".into());
      }
      return Ok(None);
    };

    // Reserve the collector's fixed payload and task slot before cloning any
    // service, ledger, bucket, or meter handle into its long-lived owner.
    let control = self
      .tenant
      .try_acquire(DomainResources::ZERO.with(
        DomainResource::Control,
        super::feedback_trace::control_charge_bytes(),
      ))
      .map_err(|error| format!("feedback trace Control reservation failed: {error:?}"))?;
    let task = self.reserve_task()?;
    let admission = super::feedback_trace::FeedbackTraceAdmission::new(control, task);
    let metrics = self
      .feedback
      .metrics
      .as_ref()
      .cloned()
      .ok_or_else(|| "external-pressure feedback metrics handle is missing".to_owned())?;
    let meters = self
      .io
      .meters
      .as_ref()
      .ok_or_else(|| "external-pressure feedback meters are missing".to_owned())?;
    let inputs = super::feedback_trace::FeedbackTraceInputs {
      metrics,
      domain: self.domain.clone(),
      tenant: self.tenant.clone(),
      resources: self.resources.clone(),
      disk_rate: self.io.disk_rate.clone(),
      upload_rate: self.io.upload_rate.clone(),
      download_rate: self.io.download_rate.clone(),
      disk_meter: meters.disk.clone(),
      upload_meter: meters.upload.clone(),
      download_meter: meters.download.clone(),
      fixed_global_control_baseline: self.fixed_global_control_baseline,
    };
    super::feedback_trace::FeedbackTraceCollector::start(
      trace_directory,
      pressure_qualification,
      run_mode,
      inputs,
      admission,
    )
    .map(Some)
  }

  pub(crate) fn policy_rows(&self) -> Vec<(String, String)> {
    let rows = vec![
      (
        "configuration.resource_policy".to_owned(),
        if self.mode().feedback_enabled() {
          "external_pressure_v1".to_owned()
        } else {
          "fixed_primary_v1".to_owned()
        },
      ),
      (
        "configuration.feedback_enabled".to_owned(),
        self.mode().feedback_enabled().to_string(),
      ),
      (
        "configuration.network_direction".to_owned(),
        if self.mode().feedback_enabled() {
          "download_only".to_owned()
        } else {
          "upload_and_download".to_owned()
        },
      ),
    ];
    #[cfg(feature = "resource-feedback")]
    {
      let mut rows = rows;
      if self.mode().feedback_enabled() {
        let disk_source = if self.resources.limits().disk_concurrent_ops == 0 {
          "no_disk_source_in_workload"
        } else if self.io.has_blocking_disk_byte_io() {
          "Tokio_BlockingByteIo_application_bytes"
        } else {
          "owning_FsRate_application_bytes"
        };
        rows.extend(feedback_policy_rows(
          self.feedback.workers,
          &self.feedback.calibrations,
          self.feedback.resolved,
          disk_source,
        ));
      }
      rows
    }
    #[cfg(not(feature = "resource-feedback"))]
    {
      rows
    }
  }

  pub(crate) fn resources(&self) -> ResourceScope {
    self.resources.clone()
  }

  pub(crate) fn cpu_gate(&self) -> CpuGate {
    self.cpu_gate.clone()
  }

  pub(crate) fn io(&self) -> ApplicationIoBindings {
    self.io.clone()
  }

  pub(crate) fn reserve_task(&self) -> Result<ApplicationTaskLease, String> {
    self.task_admission().reserve()
  }

  pub(crate) fn task_admission(&self) -> ApplicationTaskAdmission {
    ApplicationTaskAdmission {
      tenant: self.tenant.clone(),
    }
  }

  pub(crate) fn snapshots(
    &self,
  ) -> Result<
    (
      allocatbelt::runtime::resource_domain::DomainSnapshot,
      allocatbelt::runtime::resource_domain::DomainSnapshot,
      allocatbelt::runtime::managed::ResourceSnapshot,
    ),
    String,
  > {
    let global = self.domain.snapshot();
    let tenant = self
      .tenant
      .snapshot()
      .map_err(|error| format!("application tenant readback failed: {error:?}"))?;
    Ok((global, tenant, self.resources.snapshot()))
  }

  pub(crate) fn domain_limits(&self) -> DomainResources {
    self.domain_limits
  }

  pub(crate) fn fixed_global_control_baseline(&self) -> usize {
    self.fixed_global_control_baseline
  }

  pub(crate) fn runtime_rows(&self, stage: &str) -> Result<Vec<(String, String)>, String> {
    let (global, tenant, scope) = self.snapshots()?;
    let mut rows = Vec::new();
    let dimensions = [
      ("cpu", DomainResource::Cpu),
      ("memory", DomainResource::Memory),
      ("disk", DomainResource::Disk),
      ("network", DomainResource::Network),
      ("tasks", DomainResource::Tasks),
      ("control", DomainResource::Control),
    ];
    for (owner, snapshot) in [("global", global), ("tenant", tenant)] {
      for (name, resource) in dimensions {
        rows.push((
          format!("{stage}.{owner}.ceiling.{name}"),
          snapshot.ceiling.get(resource).to_string(),
        ));
        rows.push((
          format!("{stage}.{owner}.limit.{name}"),
          snapshot.limit.get(resource).to_string(),
        ));
        rows.push((
          format!("{stage}.{owner}.used.{name}"),
          snapshot.used.get(resource).to_string(),
        ));
      }
      rows.push((
        format!("{stage}.{owner}.live_tenants"),
        snapshot.live_tenants.to_string(),
      ));
    }
    for (name, value) in [
      ("managed_memory_limit", scope.limits.managed_memory),
      ("disk_operation_limit", scope.limits.disk_concurrent_ops),
      (
        "network_operation_limit",
        scope.limits.network_concurrent_ops,
      ),
      ("managed_memory_used", scope.managed_memory),
      ("disk_operations_used", scope.disk_ops),
      ("network_operations_used", scope.network_ops),
    ] {
      rows.push((format!("{stage}.scope.{name}"), value.to_string()));
    }
    rows.extend(
      self
        .io
        .readback_rows()
        .into_iter()
        .map(|(name, value)| (format!("{stage}.io.{name}"), value)),
    );
    #[cfg(feature = "resource-feedback")]
    if self.mode().feedback_enabled() {
      let metrics = self
        .feedback
        .metrics
        .as_ref()
        .ok_or_else(|| "external-pressure metrics handle was not retained".to_owned())?
        .snapshot();
      let sampled_at = Instant::now();
      rows.push((
        format!("{stage}.feedback.sample_count"),
        metrics.sample_count.to_string(),
      ));
      rows.push((
        format!("{stage}.feedback.worker_failure"),
        option_debug(metrics.worker_failure),
      ));
      rows.push((
        format!("{stage}.feedback.last_diagnostic"),
        option_debug(metrics.last_diagnostic),
      ));
      rows.push((
        format!("{stage}.feedback.last_sample_offset_ns"),
        instant_offset_ns(metrics.started_at, metrics.last_sample_at),
      ));
      rows.push((
        format!("{stage}.feedback.last_sample_age_ns"),
        instant_age_ns(sampled_at, metrics.last_sample_at),
      ));
      rows.push((
        format!("{stage}.feedback.last_plan_offset_ns"),
        instant_offset_ns(metrics.started_at, metrics.last_plan_at),
      ));
      rows.push((
        format!("{stage}.feedback.last_plan_age_ns"),
        instant_age_ns(sampled_at, metrics.last_plan_at),
      ));
      rows.push((
        format!("{stage}.feedback.stop_requested"),
        metrics.stop_requested.to_string(),
      ));
      rows.push((
        format!("{stage}.feedback.shutdown_complete"),
        metrics.shutdown_complete.to_string(),
      ));
      rows.push((
        format!("{stage}.feedback.reconciliation_pending"),
        option_debug(metrics.reconciliation_pending),
      ));
      rows.push((
        format!("{stage}.feedback.reconciliation_in_flight"),
        option_debug(metrics.reconciliation_in_flight),
      ));
      rows.push((
        format!("{stage}.feedback.decision_evidence"),
        "latest_fixed_snapshot_per_control_only".to_owned(),
      ));
      for resource in [
        FeedbackResource::CpuConcurrency,
        FeedbackResource::DiskRate,
        FeedbackResource::NetworkRate,
      ] {
        let control = metrics.control(resource);
        let prefix = match resource {
          FeedbackResource::CpuConcurrency => "cpu",
          FeedbackResource::DiskRate => "disk_rate",
          FeedbackResource::NetworkRate => "download_rate",
        };
        rows.push((
          format!("{stage}.feedback.{prefix}.current_limit"),
          control.current_limit.to_string(),
        ));
        rows.push((
          format!("{stage}.feedback.{prefix}.utilization_basis_points"),
          control
            .utilization_basis_points
            .map_or_else(|| "missing".to_owned(), |value| value.to_string()),
        ));
        rows.push((
          format!("{stage}.feedback.{prefix}.telemetry"),
          format!("{:?}", control.telemetry).to_ascii_lowercase(),
        ));
        rows.push((
          format!("{stage}.feedback.{prefix}.policy_faulted"),
          control.policy_faulted.to_string(),
        ));
        rows.push((
          format!("{stage}.feedback.{prefix}.no_change"),
          control
            .no_change
            .map_or_else(|| "none".to_owned(), no_change_label),
        ));
        rows.push((
          format!("{stage}.feedback.{prefix}.pending_generation"),
          control
            .pending_generation
            .map_or_else(|| "none".to_owned(), |generation| generation.to_string()),
        ));
        rows.push((
          format!("{stage}.feedback.{prefix}.last_diagnostic"),
          option_debug(control.last_diagnostic),
        ));
        rows.push((
          format!("{stage}.feedback.{prefix}.decision_evidence"),
          decision_evidence(control),
        ));
      }
    }
    Ok(rows)
  }

  pub(crate) fn validate_feedback_health(&self, stage: &str) -> Result<(), String> {
    #[cfg(feature = "resource-feedback")]
    if self.mode().feedback_enabled() {
      let metrics = self
        .feedback
        .metrics
        .as_ref()
        .ok_or_else(|| format!("{stage} feedback metrics handle is missing"))?
        .snapshot();
      if let Some(failure) = metrics.worker_failure {
        return Err(format!("{stage} feedback worker failed: {failure:?}"));
      }
      if let Some(control) = metrics
        .controls
        .iter()
        .find(|control| control.policy_faulted)
      {
        return Err(format!(
          "{stage} feedback policy fault is latched for {:?}: {:?}",
          control.resource, control.last_diagnostic
        ));
      }
      if stage == "after_shutdown" && !metrics.shutdown_complete {
        return Err(format!("{stage} feedback service did not join"));
      }
    }
    #[cfg(not(feature = "resource-feedback"))]
    let _ = stage;
    Ok(())
  }

  pub(crate) fn shutdown_auxiliary_timer(&mut self) -> Result<(), String> {
    if let Some(timer) = self.rate_timer_owner.take() {
      timer
        .shutdown()
        .map_err(|error| format!("Tokio rate timer shutdown failed: {error:?}"))?;
    }
    Ok(())
  }

  pub(crate) fn shutdown_feedback(&mut self, deadline: Duration) -> Result<(), String> {
    #[cfg(feature = "resource-feedback")]
    {
      if let Some(service) = self.feedback.service.as_mut() {
        let expires = Instant::now()
          .checked_add(deadline)
          .ok_or_else(|| "feedback shutdown deadline overflow".to_owned())?;
        loop {
          match service
            .try_shutdown()
            .map_err(|error| format!("feedback service shutdown failed: {error}"))?
          {
            allocatbelt::runtime::resource_feedback::FeedbackShutdownProgress::Complete => {
              self.feedback.service.take();
              break;
            }
            allocatbelt::runtime::resource_feedback::FeedbackShutdownProgress::Pending => {
              if Instant::now() >= expires {
                return Err("feedback service exceeded its finite shutdown deadline".into());
              }
              std::thread::sleep(Duration::from_millis(1));
            }
          }
        }
      }
      if self.feedback.mode.feedback_enabled()
        && !self
          .feedback
          .metrics
          .as_ref()
          .is_some_and(|metrics| metrics.snapshot().shutdown_complete)
      {
        return Err("owning executor did not join its selected feedback service".into());
      }
    }
    #[cfg(not(feature = "resource-feedback"))]
    let _ = deadline;
    Ok(())
  }
}

#[cfg(feature = "resource-feedback")]
fn instant_offset_ns(origin: Instant, value: Option<Instant>) -> String {
  value
    .and_then(|at| at.checked_duration_since(origin))
    .map_or_else(
      || "missing".to_owned(),
      |elapsed| elapsed.as_nanos().to_string(),
    )
}

#[cfg(feature = "resource-feedback")]
fn instant_age_ns(now: Instant, value: Option<Instant>) -> String {
  value
    .and_then(|at| now.checked_duration_since(at))
    .map_or_else(|| "missing".to_owned(), |age| age.as_nanos().to_string())
}

#[cfg(feature = "resource-feedback")]
fn option_debug<T: std::fmt::Debug>(value: Option<T>) -> String {
  value.map_or_else(
    || "none".to_owned(),
    |item| format!("{:?}", item).to_ascii_lowercase(),
  )
}

#[cfg(feature = "resource-feedback")]
fn no_change_label(
  reason: allocatbelt::runtime::resource_feedback_policy::NoChangeReason,
) -> String {
  use allocatbelt::runtime::resource_feedback_policy::NoChangeReason;

  match reason {
    NoChangeReason::TelemetryUnavailable => "telemetry_unavailable".to_owned(),
    NoChangeReason::PlanPending => "plan_pending".to_owned(),
    NoChangeReason::ActuationFaultLatched => "actuation_fault_latched".to_owned(),
    NoChangeReason::BreachSamplesRemaining { observed, required } => {
      format!("breach_samples_remaining:{observed}/{required}")
    }
    NoChangeReason::HysteresisBand => "hysteresis_band".to_owned(),
    NoChangeReason::CoolingDown { remaining } => {
      format!("cooling_down_remaining_ns:{}", remaining.as_nanos())
    }
    NoChangeReason::AtFloor => "at_floor".to_owned(),
    NoChangeReason::AtCeiling => "at_ceiling".to_owned(),
    NoChangeReason::ReductionQuantized => "reduction_quantized".to_owned(),
    NoChangeReason::RecoveryQuantized => "recovery_quantized".to_owned(),
  }
}

#[cfg(feature = "resource-feedback")]
fn decision_evidence(
  control: allocatbelt::runtime::resource_feedback::FeedbackControlMetrics,
) -> String {
  if let Some(reason) = control.no_change {
    no_change_label(reason)
  } else if let Some(generation) = control.pending_generation {
    format!("pending_generation:{generation}")
  } else {
    "change_published_or_recently_settled".to_owned()
  }
}

#[cfg(feature = "resource-feedback")]
struct FeedbackOwner {
  mode: ApplicationMode,
  metrics: Option<FeedbackMetricsHandle>,
  service: Option<ResourceFeedbackService>,
  workers: usize,
  calibrations: FeedbackCalibrations,
  resolved: ResolvedApplicationFeedback,
}

#[must_use = "retain through the lifetime of the task, producer or observer owner"]
pub(crate) struct ApplicationTaskLease(DomainReservation);

/// Build the final global rows from the snapshot taken after application-owner release.
pub(crate) fn after_release_global_snapshot_rows(
  snapshot: &DomainSnapshot,
  fixed_global_control_baseline: usize,
) -> Result<Vec<(String, String)>, String> {
  let mut rows = Vec::with_capacity(9);
  rows.push((
    "after_release.global.live_tenants".to_owned(),
    snapshot.live_tenants.to_string(),
  ));
  for (name, resource) in [
    ("cpu", DomainResource::Cpu),
    ("memory", DomainResource::Memory),
    ("disk", DomainResource::Disk),
    ("network", DomainResource::Network),
    ("tasks", DomainResource::Tasks),
  ] {
    let used = snapshot.used.get(resource);
    if used != 0 {
      return Err(format!(
        "application binding cleanup retained global {name} usage: {used}"
      ));
    }
    rows.push((
      format!("after_release.global.used.{name}"),
      used.to_string(),
    ));
  }
  let control = snapshot.used.get(DomainResource::Control);
  rows.push((
    "after_release.global.used.control".to_owned(),
    control.to_string(),
  ));
  rows.push((
    "after_release.expected_global_control_baseline".to_owned(),
    fixed_global_control_baseline.to_string(),
  ));
  rows.push((
    "after_release.control_matches_fixed_baseline".to_owned(),
    (control == fixed_global_control_baseline && snapshot.live_tenants == 0).to_string(),
  ));
  if snapshot.live_tenants != 0 {
    return Err(format!(
      "application binding cleanup retained {} global tenants",
      snapshot.live_tenants
    ));
  }
  if control != fixed_global_control_baseline {
    return Err(format!(
      "application binding cleanup retained global Control {control}, expected {fixed_global_control_baseline}"
    ));
  }
  Ok(rows)
}

impl std::fmt::Debug for ApplicationTaskLease {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ApplicationTaskLease")
      .field("resources", &self.0.resources())
      .finish()
  }
}

#[derive(Clone)]
pub(crate) struct ApplicationTaskAdmission {
  tenant: TenantDomain,
}

impl ApplicationTaskAdmission {
  #[cfg(all(test, feature = "resource-feedback"))]
  pub(super) fn for_tenant(tenant: TenantDomain) -> Self {
    Self { tenant }
  }

  pub(crate) fn reserve(&self) -> Result<ApplicationTaskLease, String> {
    self
      .tenant
      .try_acquire(DomainResources::ZERO.with(DomainResource::Tasks, 1))
      .map(ApplicationTaskLease)
      .map_err(|error| format!("application task ceiling refused a role: {error:?}"))
  }
}

#[derive(Clone)]
pub(crate) struct ApplicationIoBindings {
  bindings: IoBindings,
  disk_rate: ByteRateLimit,
  upload_rate: ByteRateLimit,
  download_rate: ByteRateLimit,
  blocking_disk_io: Option<BlockingByteIo>,
  #[cfg(feature = "resource-feedback")]
  meters: Option<FeedbackMeters>,
}

impl ApplicationIoBindings {
  pub(crate) fn rate_io<T>(&self, endpoint: T) -> Result<RateLimitedIo<T>, String>
  where
    T: AsyncRead + AsyncWrite + Unpin,
  {
    self.bindings.rate_io(endpoint).map_err(|error| {
      format!(
        "application stream rate adapter failed: {:?}",
        error.failure()
      )
    })
  }

  pub(crate) fn blocking_disk_io(&self) -> Option<BlockingByteIo> {
    self.blocking_disk_io.clone()
  }

  #[cfg(test)]
  pub(crate) fn fixed_rate_parameters(&self) -> ByteRateConfig {
    fixed_rate_config()
  }

  pub(crate) fn has_blocking_disk_byte_io(&self) -> bool {
    self.blocking_disk_io.is_some()
  }

  pub(crate) fn readback_rows(&self) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    for (direction, bucket) in [
      ("disk", &self.disk_rate),
      ("upload", &self.upload_rate),
      ("download", &self.download_rate),
    ] {
      let snapshot = bucket.snapshot();
      rows.push((
        format!("{direction}_bytes_per_second"),
        snapshot.bytes_per_second.to_string(),
      ));
      rows.push((
        format!("{direction}_burst_bytes"),
        snapshot.burst_bytes.to_string(),
      ));
      rows.push((
        format!("{direction}_ceiling_bytes_per_second"),
        snapshot.ceiling_bytes_per_second.to_string(),
      ));
      rows.push((
        format!("{direction}_ceiling_burst_bytes"),
        snapshot.ceiling_burst_bytes.to_string(),
      ));
      rows.push((
        format!("{direction}_max_reservations"),
        snapshot.max_reservations.to_string(),
      ));
      rows.push((
        format!("{direction}_available_bytes"),
        snapshot.available_bytes.to_string(),
      ));
      rows.push((
        format!("{direction}_reserved_bytes"),
        snapshot.reserved_bytes.to_string(),
      ));
      rows.push((
        format!("{direction}_reservations"),
        snapshot.reservations.to_string(),
      ));
    }
    #[cfg(feature = "resource-feedback")]
    if let Some(meters) = &self.meters {
      for (direction, meter) in [
        ("disk", &meters.disk),
        ("upload", &meters.upload),
        ("download", &meters.download),
      ] {
        rows.extend(feedback_meter_rows(direction, meter.snapshot()));
      }
    }
    rows
  }
}

#[cfg(feature = "resource-feedback")]
fn feedback_policy_rows(
  workers: usize,
  calibrations: &FeedbackCalibrations,
  resolved: ResolvedApplicationFeedback,
  disk_source: &str,
) -> Vec<(String, String)> {
  let policy = resolved.policy;
  let mut rows = vec![
    (
      "feedback.schema".to_owned(),
      "runtime-feedback-v2".to_owned(),
    ),
    (
      "feedback.policy.version".to_owned(),
      FEEDBACK_POLICY_VERSION.to_owned(),
    ),
    (
      "feedback.sample_interval_ms".to_owned(),
      SAMPLE_INTERVAL.as_millis().to_string(),
    ),
    (
      "feedback.max_dense_sample_gap_ms".to_owned(),
      MAX_DENSE_SAMPLE_GAP.as_millis().to_string(),
    ),
    (
      "feedback.telemetry_freshness_ms".to_owned(),
      TELEMETRY_FRESHNESS.as_millis().to_string(),
    ),
    (
      "feedback.required_breach_samples".to_owned(),
      REQUIRED_BREACH_SAMPLES.to_string(),
    ),
    (
      "feedback.actuation_cooldown_ms".to_owned(),
      ACTUATION_COOLDOWN.as_millis().to_string(),
    ),
    (
      "feedback.minimum_dense_observations".to_owned(),
      FEEDBACK_MINIMUM_DENSE_OBSERVATIONS.to_string(),
    ),
    (
      "feedback.cpu_reduction_rule".to_owned(),
      "floor_current_limit_over_10_zero_is_quantized".to_owned(),
    ),
    ("feedback.cpu_recovery_increment".to_owned(), "1".to_owned()),
    (
      "feedback.cpu_capacity_equivalents".to_owned(),
      workers.to_string(),
    ),
    ("feedback.disk_source".to_owned(), disk_source.to_owned()),
    (
      "feedback.network_source".to_owned(),
      "IoBindings_download_application_bytes_only".to_owned(),
    ),
    (
      "feedback.network_direction".to_owned(),
      "download_only".to_owned(),
    ),
    ("feedback.upload_controlled".to_owned(), "false".to_owned()),
    (
      "feedback.pressure_qualification_requested".to_owned(),
      calibrations.pressure_qualification.to_string(),
    ),
    (
      "feedback.pressure_claim".to_owned(),
      "application_byte_throughput_only_external_contention_unmeasured".to_owned(),
    ),
    (
      "feedback.calibration.schema".to_owned(),
      CAPACITY_CALIBRATION_SCHEMA.to_owned(),
    ),
    (
      "feedback.calibration.id".to_owned(),
      calibrations.artifact.as_ref().map_or_else(
        || "missing".to_owned(),
        |artifact| artifact.value(&artifact.calibration_id).to_owned(),
      ),
    ),
    (
      "feedback.calibration.artifact_sha256".to_owned(),
      calibrations.artifact.as_ref().map_or_else(
        || "missing".to_owned(),
        |artifact| String::from_utf8_lossy(&artifact.artifact_sha256).into_owned(),
      ),
    ),
    (
      "feedback.calibration.hash_scope".to_owned(),
      "exact_bounded_artifact_bytes".to_owned(),
    ),
    (
      "feedback.calibration.host_id".to_owned(),
      calibrations.artifact.as_ref().map_or_else(
        || "missing".to_owned(),
        |artifact| artifact.value(&artifact.host_id).to_owned(),
      ),
    ),
    (
      "feedback.calibration.profile".to_owned(),
      calibrations.artifact.as_ref().map_or_else(
        || "missing".to_owned(),
        |artifact| artifact.value(&artifact.profile).to_owned(),
      ),
    ),
    (
      "feedback.calibration.workload".to_owned(),
      calibrations.artifact.as_ref().map_or_else(
        || "missing".to_owned(),
        |artifact| artifact.value(&artifact.workload).to_owned(),
      ),
    ),
    (
      "feedback.calibration.source_sha256".to_owned(),
      calibrations.artifact.as_ref().map_or_else(
        || "missing".to_owned(),
        |artifact| artifact.value(&artifact.source_sha256).to_owned(),
      ),
    ),
    (
      "feedback.calibration.source_sha256_meaning".to_owned(),
      "candidate_source_tree_sha256_from_ALLOCATBELT_APP_SOURCE_SHA256".to_owned(),
    ),
    (
      "feedback.policy.canonicalization".to_owned(),
      format!(
        "{FEEDBACK_POLICY_VERSION};cpu_floor_current_limit_over_10,disk,download;floor,initial,ceiling,low_bps,high_bps;capacity,density,sample,freshness,sparsity,breach,cooldown"
      ),
    ),
  ];
  rows.extend(calibration_direction_rows(
    "disk",
    calibrations.artifact.as_deref(),
  ));
  rows.extend(calibration_direction_rows(
    "download",
    calibrations.artifact.as_deref(),
  ));
  for (name, control) in [
    ("cpu", policy.cpu_concurrency),
    ("disk", policy.disk_rate),
    ("download", policy.network_rate),
  ] {
    for (field, value) in [
      ("floor", control.floor),
      ("initial", control.initial),
      ("ceiling", control.ceiling),
      (
        "low_utilization_basis_points",
        u64::from(control.low_utilization_basis_points),
      ),
      (
        "high_utilization_basis_points",
        u64::from(control.high_utilization_basis_points),
      ),
    ] {
      rows.push((format!("feedback.policy.{name}.{field}"), value.to_string()));
    }
  }
  rows
}

#[cfg(feature = "resource-feedback")]
fn calibration_direction_rows(
  direction: &str,
  artifact: Option<&CapacityCalibrationArtifact>,
) -> Vec<(String, String)> {
  let calibration = artifact.and_then(|artifact| match direction {
    "disk" => Some(&artifact.disk),
    "download" => Some(&artifact.download),
    _ => None,
  });
  let (capacity, units, provenance) = match (artifact, calibration) {
    (Some(artifact), Some(calibration)) => match calibration.bytes_per_second {
      Some(capacity) => (
        capacity.get().to_string(),
        APPLICATION_BYTE_CALIBRATION_UNITS,
        artifact.value(&calibration.provenance),
      ),
      None => (
        "missing".to_owned(),
        "missing",
        artifact.value(&calibration.provenance),
      ),
    },
    _ => ("missing".to_owned(), "missing", "missing"),
  };
  vec![
    (
      format!("feedback.calibration.{direction}.status"),
      if capacity == "missing" {
        "missing".to_owned()
      } else {
        "calibrated".to_owned()
      },
    ),
    (
      format!("feedback.calibration.{direction}.bytes_per_second"),
      capacity,
    ),
    (
      format!("feedback.calibration.{direction}.units"),
      units.to_owned(),
    ),
    (
      format!("feedback.calibration.{direction}.provenance"),
      provenance.to_owned(),
    ),
  ]
}

#[cfg(feature = "resource-feedback")]
fn feedback_meter_rows(
  direction: &str,
  snapshot: IoFeedbackMeterSnapshot,
) -> Vec<(String, String)> {
  let mut rows = [
    ("committed_bytes", snapshot.committed_bytes.to_string()),
    ("completions", snapshot.completions.to_string()),
    ("attached_sources", snapshot.attached_sources.to_string()),
    ("generation", snapshot.generation.to_string()),
    (
      "diagnostics_clear",
      snapshot.diagnostics.is_clear().to_string(),
    ),
  ]
  .into_iter()
  .map(|(field, value)| (format!("feedback.meter.{direction}.{field}"), value))
  .collect::<Vec<_>>();
  rows.extend([
    (
      format!("feedback.meter.{direction}.diagnostics.counter_overflow"),
      snapshot.diagnostics.counter_overflow.to_string(),
    ),
    (
      format!("feedback.meter.{direction}.diagnostics.invalid_io"),
      snapshot.diagnostics.invalid_io.to_string(),
    ),
    (
      format!("feedback.meter.{direction}.diagnostics.source_count_overflow"),
      snapshot.diagnostics.source_count_overflow.to_string(),
    ),
    (
      format!("feedback.meter.{direction}.diagnostics.generation_overflow"),
      snapshot.diagnostics.generation_overflow.to_string(),
    ),
  ]);
  rows
}

#[cfg(test)]
#[path = "runtime_bindings_tests.rs"]
mod tests;

#[cfg(feature = "resource-feedback")]
pub(super) mod capacity_artifact_hash {
  pub(super) fn sha256_ascii(bytes: &[u8]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finish();
    let mut output = [0; 64];
    for (index, byte) in digest.into_iter().enumerate() {
      output[index * 2] = HEX[(byte >> 4) as usize];
      output[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    output
  }

  pub(super) fn matches_hex(digest: &[u8; 64], supplied: &[u8]) -> bool {
    digest.len() == supplied.len()
      && digest
        .iter()
        .zip(supplied)
        .all(|(expected, supplied)| expected.eq_ignore_ascii_case(supplied))
  }

  #[cfg(test)]
  pub(in crate::application) fn sha256_hex(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&sha256_ascii(bytes)).into_owned()
  }

  pub(super) struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    used: usize,
    length: u64,
  }

  impl Sha256 {
    pub(super) const fn new() -> Self {
      Self {
        state: [
          0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
          0x5be0cd19,
        ],
        block: [0; 64],
        used: 0,
        length: 0,
      }
    }

    pub(super) fn update(&mut self, mut input: &[u8]) {
      self.length = self.length.wrapping_add(input.len() as u64);
      while !input.is_empty() {
        let count = (64 - self.used).min(input.len());
        self.block[self.used..self.used + count].copy_from_slice(&input[..count]);
        self.used += count;
        input = &input[count..];
        if self.used == 64 {
          compress(&mut self.state, &self.block);
          self.used = 0;
        }
      }
    }

    pub(super) fn finish(mut self) -> [u8; 32] {
      let bit_length = self.length.wrapping_mul(8);
      self.block[self.used] = 0x80;
      self.used += 1;
      if self.used > 56 {
        self.block[self.used..].fill(0);
        compress(&mut self.state, &self.block);
        self.block = [0; 64];
        self.used = 0;
      }
      self.block[self.used..56].fill(0);
      self.block[56..64].copy_from_slice(&bit_length.to_be_bytes());
      compress(&mut self.state, &self.block);
      let mut output = [0u8; 32];
      for (chunk, word) in output.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
        chunk.copy_from_slice(&word.to_be_bytes());
      }
      output
    }
  }

  fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    const K: [u32; 64] = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
      0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
      0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
      0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
      0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
      0xc67178f2,
    ];
    let mut words = [0u32; 64];
    for (index, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
      words[index] = u32::from_be_bytes(*chunk);
    }
    for index in 16..64 {
      let x = words[index - 15];
      let y = words[index - 2];
      let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
      let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
      words[index] = words[index - 16]
        .wrapping_add(s0)
        .wrapping_add(words[index - 7])
        .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
      let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
      let choice = (e & f) ^ (!e & g);
      let temp1 = h
        .wrapping_add(sum1)
        .wrapping_add(choice)
        .wrapping_add(K[index])
        .wrapping_add(words[index]);
      let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
      let majority = (a & b) ^ (a & c) ^ (b & c);
      let temp2 = sum0.wrapping_add(majority);
      h = g;
      g = f;
      f = e;
      e = d.wrapping_add(temp1);
      d = c;
      c = b;
      b = a;
      a = temp1.wrapping_add(temp2);
    }
    for (target, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
      *target = target.wrapping_add(value);
    }
  }

  #[cfg(test)]
  mod tests {
    use super::sha256_hex;

    #[test]
    fn sha256_matches_standard_empty_and_abc_vectors() {
      assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      );
      assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
      );
    }

    #[test]
    fn sha256_matches_independent_padding_and_maximum_artifact_vectors() {
      let bytes55 = [b'a'; 55];
      let bytes56 = [b'a'; 56];
      let bytes63 = [b'a'; 63];
      let bytes64 = [b'a'; 64];
      let bytes65 = [b'a'; 65];
      let maximum_artifact = [b'a'; super::super::MAX_CAPACITY_CALIBRATION_BYTES as usize];
      // These expected digests were generated with GNU coreutils sha256sum.
      for (input, expected) in [
        (
          &bytes55[..],
          "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
        ),
        (
          &bytes56[..],
          "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
        ),
        (
          &bytes63[..],
          "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
        ),
        (
          &bytes64[..],
          "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        ),
        (
          &bytes65[..],
          "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
        ),
        (
          &maximum_artifact[..],
          "c93eee2d0db02f10acc7460d9576e122dcf8cd53c4bf8dfcae1b3e74ebcfff5a",
        ),
      ] {
        assert_eq!(sha256_hex(input), expected);
      }
    }
  }
}

#[cfg(feature = "resource-feedback")]
pub(super) struct FeedbackTraceHasher(capacity_artifact_hash::Sha256);

#[cfg(feature = "resource-feedback")]
impl FeedbackTraceHasher {
  pub(super) const fn new() -> Self {
    Self(capacity_artifact_hash::Sha256::new())
  }

  pub(super) fn update(&mut self, bytes: &[u8]) {
    self.0.update(bytes);
  }

  pub(super) fn finish_hex(self) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = self.0.finish();
    let mut output = [0; 64];
    for (index, byte) in digest.into_iter().enumerate() {
      output[index * 2] = HEX[(byte >> 4) as usize];
      output[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    output
  }
}
