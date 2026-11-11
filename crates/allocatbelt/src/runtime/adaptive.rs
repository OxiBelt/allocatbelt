//! Caller-driven, bounded feedback for CPU quota and `memory.high` in a
//! caller-supplied cgroup v2 group.
//!
//! The controller has no sensor thread and makes no performance claim. The
//! caller supplies p99 latency and utilization samples, and explicitly calls
//! [`AdaptiveController::observe`]. It changes only `cpu.max` and
//! `memory.high`; it never changes `memory.max` or `io.max`. Each transition
//! applies CPU first and memory second through [`CgroupV2`]'s existing
//! synchronous setters. The two controls and each setter's readback are
//! separate kernel operations, not an atomic transaction.
//!
//! Construction consumes the [`CgroupV2`] handle, preventing another setter
//! call through that same handle while the controller is live. The caller
//! must still coordinate with other processes and descriptor aliases. A
//! pre-write snapshot detects observed drift, but cannot close the race with
//! an external writer between separate cgroup file operations. Lowering
//! `memory.high` may synchronously reclaim or block. A failed write or
//! readback latches the controller fail-closed; it does not retry, roll back,
//! or infer that a failed setter had no effect. Recovery requires an explicit
//! readback reconciliation through [`AdaptiveController::resume_from_readback`].
//!
//! Cgroup files, kernel state and fixed controller metadata are outside the
//! managed-storage ledger. The tier table has a fixed maximum of sixteen
//! entries and does not grow.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use rustix::param::page_size;

use super::cgroup::{
  CgroupApplyError, CgroupCeilings, CgroupReadError, CgroupSnapshot, CgroupV2, CpuMax,
  CpuMaxReadback, Limit,
};

/// Maximum number of fixed caller-supplied tiers.
pub const MAX_ADAPTIVE_TIERS: usize = 16;
const MAX_STREAK_SAMPLES: u32 = 1024;
const MAX_COOLDOWN: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_CPU_QUOTA_US: u64 = (1 << 44) - 1;
const MIN_CPU_QUOTA_US: u64 = 1_000;
const MIN_CPU_PERIOD_US: u64 = 1_000;
const MAX_CPU_PERIOD_US: u64 = 1_000_000;

/// One finite pair of CPU and `memory.high` limits.
///
/// Tiers are ordered from least to most permissive. Both CPU quota fraction
/// and memory.high must increase strictly at each step. Every tier uses the
/// same CPU period.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptiveTier {
  /// Finite CPU quota and period for `cpu.max`.
  pub cpu_max: CpuMax,
  /// Finite host-page-aligned `memory.high` in bytes.
  pub memory_high_bytes: u64,
}

/// High and low thresholds for the three caller-measured signals.
///
/// A breach is any metric at or above its high threshold. Recovery requires
/// all metrics at or below their low thresholds. Samples between the bands
/// are neutral and reset both sustained-sample streaks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptiveThresholds {
  p99_low: Duration,
  p99_high: Duration,
  cpu_low_basis_points: u16,
  cpu_high_basis_points: u16,
  memory_low_basis_points: u16,
  memory_high_basis_points: u16,
}

impl AdaptiveThresholds {
  /// Creates high/low latency and utilization bands.
  pub fn new(
    p99_low: Duration,
    p99_high: Duration,
    cpu_low_basis_points: u16,
    cpu_high_basis_points: u16,
    memory_low_basis_points: u16,
    memory_high_basis_points: u16,
  ) -> Result<Self, AdaptiveConfigError> {
    if p99_low >= p99_high {
      return Err(AdaptiveConfigError::LatencyHysteresis);
    }
    validate_utilization_band(cpu_low_basis_points, cpu_high_basis_points)?;
    validate_utilization_band(memory_low_basis_points, memory_high_basis_points)?;
    Ok(Self {
      p99_low,
      p99_high,
      cpu_low_basis_points,
      cpu_high_basis_points,
      memory_low_basis_points,
      memory_high_basis_points,
    })
  }
}

fn validate_utilization_band(low: u16, high: u16) -> Result<(), AdaptiveConfigError> {
  if high == 0 || high > 10_000 || low >= high {
    return Err(AdaptiveConfigError::UtilizationHysteresis);
  }
  Ok(())
}

/// Hysteresis and caller-clock policy for an adaptive controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptiveConfig {
  thresholds: AdaptiveThresholds,
  breach_samples: NonZeroU32,
  recovery_samples: NonZeroU32,
  minimum_sample_interval: Duration,
  maximum_sample_gap: Duration,
  cooldown: Duration,
}

impl AdaptiveConfig {
  /// Creates validated controller policy. Sustained counts are limited to
  /// 1024 and cooldown is finite, nonzero, and at most 24 hours.
  pub fn new(
    thresholds: AdaptiveThresholds,
    breach_samples: u32,
    recovery_samples: u32,
    minimum_sample_interval: Duration,
    maximum_sample_gap: Duration,
    cooldown: Duration,
  ) -> Result<Self, AdaptiveConfigError> {
    let breach_samples = NonZeroU32::new(breach_samples)
      .filter(|count| count.get() <= MAX_STREAK_SAMPLES)
      .ok_or(AdaptiveConfigError::InvalidSampleCount)?;
    let recovery_samples = NonZeroU32::new(recovery_samples)
      .filter(|count| count.get() <= MAX_STREAK_SAMPLES)
      .ok_or(AdaptiveConfigError::InvalidSampleCount)?;
    if minimum_sample_interval.is_zero() {
      return Err(AdaptiveConfigError::ZeroSampleInterval);
    }
    if maximum_sample_gap < minimum_sample_interval {
      return Err(AdaptiveConfigError::GapShorterThanInterval);
    }
    if cooldown.is_zero() || cooldown > MAX_COOLDOWN {
      return Err(AdaptiveConfigError::InvalidCooldown);
    }
    Ok(Self {
      thresholds,
      breach_samples,
      recovery_samples,
      minimum_sample_interval,
      maximum_sample_gap,
      cooldown,
    })
  }
}

/// Why caller-supplied adaptive policy is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptiveConfigError {
  /// The low p99 threshold must be strictly below the high threshold.
  LatencyHysteresis,
  /// Each utilization low threshold must be below a high threshold in 1..=10000.
  UtilizationHysteresis,
  /// Sustained breach/recovery counts must be in 1..=1024.
  InvalidSampleCount,
  /// The minimum sample interval must be nonzero.
  ZeroSampleInterval,
  /// Maximum gap must be at least the minimum interval.
  GapShorterThanInterval,
  /// Cooldown must be nonzero and no longer than 24 hours.
  InvalidCooldown,
}

impl fmt::Display for AdaptiveConfigError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::LatencyHysteresis => "p99 low threshold must be below high threshold",
      Self::UtilizationHysteresis => "utilization bands require low < high <= 10000",
      Self::InvalidSampleCount => "sustained sample count must be in 1..=1024",
      Self::ZeroSampleInterval => "minimum sample interval must be nonzero",
      Self::GapShorterThanInterval => "maximum sample gap must cover the minimum interval",
      Self::InvalidCooldown => "cooldown must be nonzero and at most 24 hours",
    })
  }
}

impl std::error::Error for AdaptiveConfigError {}

/// One sample measured by the caller at a monotonic instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeedbackSample {
  /// Caller-clock sample time. All samples and resume times must use the same
  /// monotonic clock domain.
  pub at: Instant,
  /// Measured p99 latency.
  pub p99: Duration,
  /// CPU utilization in basis points, from 0 through 10000.
  pub cpu_basis_points: u16,
  /// Memory utilization in basis points, from 0 through 10000.
  pub memory_basis_points: u16,
}

/// Classification of a valid feedback sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackSignal {
  /// At least one metric reached its high threshold.
  Breach,
  /// Every metric reached its low threshold or lower.
  Healthy,
  /// The sample is between the high and low bands.
  Neutral,
}

/// Result of one valid feedback sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptiveDecision {
  /// No tier change occurred for this sample.
  Stable {
    /// Current tier index.
    tier: usize,
    /// Classified signal.
    signal: FeedbackSignal,
    /// Current consecutive breach count.
    breach_samples: u32,
    /// Current consecutive recovery count.
    recovery_samples: u32,
  },
  /// One transition completed successfully.
  Changed {
    /// Tier before the transition.
    from: usize,
    /// Tier after the transition.
    to: usize,
  },
  /// Sustained breach reached the most permissive tier.
  AtCeiling { tier: usize },
  /// Sustained recovery reached the least permissive tier.
  AtFloor { tier: usize },
  /// A sustained signal is waiting for the minimum time between changes.
  CoolingDown { tier: usize },
}

/// Why a valid sample could not be consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
  clippy::large_enum_variant,
  reason = "bounded snapshots carry the fixed 16-entry I/O table; boxing would allocate on errors"
)]
pub enum AdaptiveObserveError {
  /// Caller utilization is outside 0..=10000 basis points.
  InvalidUtilization,
  /// The sample instant is earlier than the latest accepted event.
  NonMonotonicTime,
  /// The sample arrived before the configured minimum interval.
  SampleTooSoon,
  /// The controller is faulted and requires explicit readback recovery.
  Faulted,
  /// A cgroup update or its preflight verification failed.
  Apply(AdaptiveApplyError),
}

impl fmt::Display for AdaptiveObserveError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "adaptive cgroup sample failed: {self:?}")
  }
}

impl std::error::Error for AdaptiveObserveError {}

/// Which part of a two-control transition failed or drifted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptiveApplyFailure {
  /// The pre-write cgroup snapshot could not be read.
  PreflightRead(CgroupReadError),
  /// Pre-write controls no longer match the tracked tier or original max.
  Drift,
  /// `cpu.max` setter failed; it may have changed state before reporting error.
  Cpu(CgroupApplyError),
  /// `cpu.max` returned success but its separate-file snapshot was inconsistent.
  CpuReadbackMismatch,
  /// `memory.high` setter failed after the reported CPU progress.
  MemoryHigh(CgroupApplyError),
  /// `memory.high` returned success but its snapshot was inconsistent.
  MemoryHighReadbackMismatch,
}

/// Nontransactional failure during one adaptive transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptiveApplyError {
  /// Previously tracked tier index.
  pub from_tier: usize,
  /// Requested next tier index.
  pub to_tier: usize,
  /// Whether `set_cpu_max` returned `Ok`. A separate readback mismatch is
  /// reported by [`AdaptiveApplyFailure::CpuReadbackMismatch`].
  pub cpu_setter_succeeded: bool,
  /// Whether `set_memory_high` returned `Ok`. A separate readback mismatch is
  /// reported by [`AdaptiveApplyFailure::MemoryHighReadbackMismatch`].
  pub memory_high_setter_succeeded: bool,
  /// Latest state known from startup or readback. If post-failure state is
  /// unknown, this remains an earlier observation and is not a rollback claim.
  pub last_known: CgroupSnapshot,
  /// State observed immediately before the first write, if the read succeeded.
  pub preflight: Option<CgroupSnapshot>,
  /// Post-failure snapshot if the failing setter or drift check supplied one.
  /// `None` means post-failure state is unknown; `last_known` remains an
  /// earlier confirmed observation and does not imply rollback.
  pub observed: Option<CgroupSnapshot>,
  /// Exact failure stage.
  pub failure: AdaptiveApplyFailure,
}

impl fmt::Display for AdaptiveApplyError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "adaptive cgroup transition {} -> {} failed: {:?}",
      self.from_tier, self.to_tier, self.failure
    )
  }
}

impl std::error::Error for AdaptiveApplyError {}

/// Why controller startup or recovery could not accept observed state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
  clippy::large_enum_variant,
  reason = "bounded snapshots carry the fixed 16-entry I/O table; boxing would allocate on errors"
)]
pub enum AdaptiveStateError {
  /// The cgroup snapshot could not be read.
  Readback(CgroupReadError),
  /// `memory.max` is unlimited, exceeds its fixed ceiling, or is malformed for this policy.
  InvalidMemoryMax(Limit),
  /// CPU or memory.high does not exactly match one configured tier.
  NoMatchingTier(CgroupSnapshot),
}

/// Why a configured tier table was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptiveTierError {
  /// There must be two through sixteen tiers.
  Count,
  /// CPU limits must be finite and within Linux's supported numeric range.
  InvalidCpu(usize),
  /// A tier exceeds the immutable CPU quota ceiling.
  CpuAboveCeiling(usize),
  /// All tiers must use one period.
  DifferentCpuPeriods,
  /// CPU quota fractions must increase strictly with each tier.
  CpuOrder(usize),
  /// `memory.high` must be page-aligned and within the fixed high ceiling.
  InvalidMemoryHigh(usize),
  /// `memory.high` must not exceed the initial finite `memory.max`.
  MemoryHighAboveMax(usize),
  /// `memory.high` must increase strictly with each tier.
  MemoryOrder(usize),
}

/// Startup error retaining the readback or tier-validation reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
  clippy::large_enum_variant,
  reason = "state errors preserve fixed-size readback without heap allocation"
)]
pub enum AdaptiveStartError {
  /// The table failed static validation.
  Tiers(AdaptiveTierError),
  /// Initial cgroup controls could not be read or validated.
  State(AdaptiveStateError),
}

impl fmt::Display for AdaptiveStartError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "adaptive cgroup startup failed: {self:?}")
  }
}

impl std::error::Error for AdaptiveStartError {}

/// Why an explicit resume request did not clear a controller fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
  clippy::large_enum_variant,
  reason = "state errors preserve fixed-size readback without heap allocation"
)]
pub enum AdaptiveResumeError {
  /// Resume is only meaningful after an apply/drift failure.
  NotFaulted,
  /// Resume time predates the latest accepted sample or resume watermark.
  NonMonotonicTime,
  /// The state could not be read.
  State(AdaptiveStateError),
}

/// Caller-driven controller. No background thread samples or changes limits.
pub struct AdaptiveController {
  state: ControllerState<CgroupV2>,
}

impl fmt::Debug for AdaptiveController {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AdaptiveController")
      .field("tier", &self.state.tier)
      .field("faulted", &self.state.faulted)
      .field("tiers", &self.state.tier_count)
      .finish_non_exhaustive()
  }
}

impl AdaptiveController {
  /// Takes an exclusive adapter handle, validates two to sixteen monotonic
  /// tiers against its immutable ceilings, and reads the initial cgroup state.
  ///
  /// Startup performs no writes. Current `memory.max` must be finite and no
  /// greater than its caller ceiling. The current CPU and `memory.high` must
  /// exactly match one tier, and every tier's memory.high must fit under that
  /// already-established `memory.max`.
  pub fn new(
    cgroup: CgroupV2,
    tiers: &[AdaptiveTier],
    config: AdaptiveConfig,
  ) -> Result<Self, AdaptiveStartError> {
    let ceilings = cgroup.ceilings();
    let (tiers, tier_count) = validate_tiers(tiers, ceilings)?;
    let initial = cgroup
      .readback()
      .map_err(|error| AdaptiveStartError::State(AdaptiveStateError::Readback(error)))?;
    let memory_max = finite_memory_max(initial.memory_max, ceilings.memory_max_bytes())
      .map_err(AdaptiveStartError::State)?;
    validate_tiers_under_memory_max(&tiers, tier_count, memory_max)
      .map_err(AdaptiveStartError::Tiers)?;
    if let Some((index, _)) = tiers.0[..tier_count]
      .iter()
      .flatten()
      .enumerate()
      .find(|(_, tier)| snapshot_matches_tier(initial, **tier, memory_max))
    {
      Ok(Self {
        state: ControllerState::new(
          cgroup, tiers, tier_count, config, index, memory_max, initial,
        ),
      })
    } else {
      Err(AdaptiveStartError::State(
        AdaptiveStateError::NoMatchingTier(initial),
      ))
    }
  }

  /// Current configured tier index.
  #[must_use]
  pub const fn tier_index(&self) -> usize {
    self.state.tier
  }

  /// Whether a failed/unknown transition currently blocks automatic writes.
  #[must_use]
  pub const fn is_faulted(&self) -> bool {
    self.state.faulted
  }

  /// Reads cgroup controls without changing them, including while faulted.
  pub fn readback(&self) -> Result<CgroupSnapshot, CgroupReadError> {
    self.state.controls.readback()
  }

  /// Evaluates one caller-measured sample and may apply at most one adjacent
  /// tier transition. Samples must share a monotonic clock domain with resume
  /// timestamps. Invalid samples leave policy state unchanged.
  pub fn observe(
    &mut self,
    sample: FeedbackSample,
  ) -> Result<AdaptiveDecision, AdaptiveObserveError> {
    self.state.observe(sample)
  }

  /// Reconciles a fault against live state and resumes only if that snapshot
  /// exactly matches a configured tier and the original finite memory.max.
  /// `now` must use the same monotonic clock and be no earlier than the last
  /// accepted sample or resume attempt. Successful recovery starts a fresh
  /// sampling interval and cooldown at `now`.
  pub fn resume_from_readback(&mut self, now: Instant) -> Result<usize, AdaptiveResumeError> {
    self.state.resume_from_readback(now)
  }
}

#[derive(Clone, Copy, Debug)]
struct TierTable([Option<AdaptiveTier>; MAX_ADAPTIVE_TIERS]);

fn validate_tiers(
  input: &[AdaptiveTier],
  ceilings: &CgroupCeilings,
) -> Result<(TierTable, usize), AdaptiveStartError> {
  if !(2..=MAX_ADAPTIVE_TIERS).contains(&input.len()) {
    return Err(AdaptiveStartError::Tiers(AdaptiveTierError::Count));
  }
  let mut table: [Option<AdaptiveTier>; MAX_ADAPTIVE_TIERS] = [None; MAX_ADAPTIVE_TIERS];
  let mut period = None;
  let page = page_size() as u64;
  for (index, tier) in input.iter().copied().enumerate() {
    let quota = tier.cpu_max.quota_us();
    let cpu_period = tier.cpu_max.period_us();
    if !(MIN_CPU_QUOTA_US..=MAX_CPU_QUOTA_US).contains(&quota)
      || !(MIN_CPU_PERIOD_US..=MAX_CPU_PERIOD_US).contains(&cpu_period)
    {
      return Err(AdaptiveStartError::Tiers(AdaptiveTierError::InvalidCpu(
        index,
      )));
    }
    if !cpu_within(tier.cpu_max, ceilings.cpu_max()) {
      return Err(AdaptiveStartError::Tiers(
        AdaptiveTierError::CpuAboveCeiling(index),
      ));
    }
    if let Some(expected) = period {
      if expected != cpu_period {
        return Err(AdaptiveStartError::Tiers(
          AdaptiveTierError::DifferentCpuPeriods,
        ));
      }
    } else {
      period = Some(cpu_period);
    }
    if tier.memory_high_bytes == 0
      || !tier.memory_high_bytes.is_multiple_of(page)
      || tier.memory_high_bytes > ceilings.memory_high_bytes()
    {
      return Err(AdaptiveStartError::Tiers(
        AdaptiveTierError::InvalidMemoryHigh(index),
      ));
    }
    if index > 0 {
      let previous = table[index - 1].ok_or(AdaptiveStartError::Tiers(
        AdaptiveTierError::CpuOrder(index),
      ))?;
      if !cpu_less(previous.cpu_max, tier.cpu_max) {
        return Err(AdaptiveStartError::Tiers(AdaptiveTierError::CpuOrder(
          index,
        )));
      }
      if previous.memory_high_bytes >= tier.memory_high_bytes {
        return Err(AdaptiveStartError::Tiers(AdaptiveTierError::MemoryOrder(
          index,
        )));
      }
    }
    table[index] = Some(tier);
  }
  Ok((TierTable(table), input.len()))
}

fn finite_memory_max(value: Limit, ceiling: u64) -> Result<u64, AdaptiveStateError> {
  match value {
    Limit::Value(value) if value <= ceiling => Ok(value),
    other => Err(AdaptiveStateError::InvalidMemoryMax(other)),
  }
}

fn validate_tiers_under_memory_max(
  tiers: &TierTable,
  tier_count: usize,
  memory_max: u64,
) -> Result<(), AdaptiveTierError> {
  for (index, tier) in tiers.0[..tier_count].iter().flatten().enumerate() {
    if tier.memory_high_bytes > memory_max {
      return Err(AdaptiveTierError::MemoryHighAboveMax(index));
    }
  }
  Ok(())
}

fn cpu_within(value: CpuMax, ceiling: CpuMax) -> bool {
  u128::from(value.quota_us()) * u128::from(ceiling.period_us())
    <= u128::from(ceiling.quota_us()) * u128::from(value.period_us())
}

fn cpu_less(left: CpuMax, right: CpuMax) -> bool {
  u128::from(left.quota_us()) * u128::from(right.period_us())
    < u128::from(right.quota_us()) * u128::from(left.period_us())
}

fn snapshot_matches_tier(snapshot: CgroupSnapshot, tier: AdaptiveTier, memory_max: u64) -> bool {
  snapshot.cpu_max
    == CpuMaxReadback {
      quota_us: Limit::Value(tier.cpu_max.quota_us()),
      period_us: tier.cpu_max.period_us(),
    }
    && snapshot.memory_high == Limit::Value(tier.memory_high_bytes)
    && snapshot.memory_max == Limit::Value(memory_max)
}

trait Controls {
  fn readback(&self) -> Result<CgroupSnapshot, CgroupReadError>;
  fn set_cpu_max(&self, value: CpuMax) -> Result<CgroupSnapshot, CgroupApplyError>;
  fn set_memory_high(&self, value: u64) -> Result<CgroupSnapshot, CgroupApplyError>;
}

impl Controls for CgroupV2 {
  fn readback(&self) -> Result<CgroupSnapshot, CgroupReadError> {
    CgroupV2::readback(self)
  }

  fn set_cpu_max(&self, value: CpuMax) -> Result<CgroupSnapshot, CgroupApplyError> {
    CgroupV2::set_cpu_max(self, value)
  }

  fn set_memory_high(&self, value: u64) -> Result<CgroupSnapshot, CgroupApplyError> {
    CgroupV2::set_memory_high(self, value)
  }
}

struct ControllerState<C> {
  controls: C,
  tiers: [Option<AdaptiveTier>; MAX_ADAPTIVE_TIERS],
  tier_count: usize,
  config: AdaptiveConfig,
  tier: usize,
  memory_max: u64,
  last_known: CgroupSnapshot,
  last_sample: Option<Instant>,
  time_watermark: Option<Instant>,
  last_transition: Option<Instant>,
  breach_count: u32,
  recovery_count: u32,
  faulted: bool,
}

impl<C: Controls> ControllerState<C> {
  fn new(
    controls: C,
    tiers: TierTable,
    tier_count: usize,
    config: AdaptiveConfig,
    tier: usize,
    memory_max: u64,
    last_known: CgroupSnapshot,
  ) -> Self {
    Self {
      controls,
      tiers: tiers.0,
      tier_count,
      config,
      tier,
      memory_max,
      last_known,
      last_sample: None,
      time_watermark: None,
      last_transition: None,
      breach_count: 0,
      recovery_count: 0,
      faulted: false,
    }
  }

  fn observe(&mut self, sample: FeedbackSample) -> Result<AdaptiveDecision, AdaptiveObserveError> {
    if self.faulted {
      return Err(AdaptiveObserveError::Faulted);
    }
    if sample.cpu_basis_points > 10_000 || sample.memory_basis_points > 10_000 {
      return Err(AdaptiveObserveError::InvalidUtilization);
    }
    if let Some(watermark) = self.time_watermark {
      let Some(elapsed) = sample.at.checked_duration_since(watermark) else {
        return Err(AdaptiveObserveError::NonMonotonicTime);
      };
      if elapsed < self.config.minimum_sample_interval {
        return Err(AdaptiveObserveError::SampleTooSoon);
      }
    }
    let gap = self
      .last_sample
      .and_then(|last| sample.at.checked_duration_since(last));
    if gap.is_some_and(|elapsed| elapsed > self.config.maximum_sample_gap) {
      self.breach_count = 0;
      self.recovery_count = 0;
    }
    self.last_sample = Some(sample.at);
    self.time_watermark = Some(sample.at);

    let signal = self.signal(sample);
    match signal {
      FeedbackSignal::Breach => {
        self.breach_count = self
          .breach_count
          .saturating_add(1)
          .min(self.config.breach_samples.get());
        self.recovery_count = 0;
      }
      FeedbackSignal::Healthy => {
        self.recovery_count = self
          .recovery_count
          .saturating_add(1)
          .min(self.config.recovery_samples.get());
        self.breach_count = 0;
      }
      FeedbackSignal::Neutral => {
        self.breach_count = 0;
        self.recovery_count = 0;
      }
    }

    let target = if signal == FeedbackSignal::Breach
      && self.breach_count == self.config.breach_samples.get()
    {
      if self.tier + 1 == self.tier_count {
        return Ok(AdaptiveDecision::AtCeiling { tier: self.tier });
      }
      Some(self.tier + 1)
    } else if signal == FeedbackSignal::Healthy
      && self.recovery_count == self.config.recovery_samples.get()
    {
      if self.tier == 0 {
        return Ok(AdaptiveDecision::AtFloor { tier: self.tier });
      }
      Some(self.tier - 1)
    } else {
      None
    };
    let Some(target) = target else {
      return Ok(AdaptiveDecision::Stable {
        tier: self.tier,
        signal,
        breach_samples: self.breach_count,
        recovery_samples: self.recovery_count,
      });
    };
    if self.last_transition.is_some_and(|last| {
      sample
        .at
        .checked_duration_since(last)
        .is_none_or(|elapsed| elapsed < self.config.cooldown)
    }) {
      return Ok(AdaptiveDecision::CoolingDown { tier: self.tier });
    }
    self.apply_tier(target).map_err(AdaptiveObserveError::Apply)
  }

  fn signal(&self, sample: FeedbackSample) -> FeedbackSignal {
    let t = self.config.thresholds;
    if sample.p99 >= t.p99_high
      || sample.cpu_basis_points >= t.cpu_high_basis_points
      || sample.memory_basis_points >= t.memory_high_basis_points
    {
      FeedbackSignal::Breach
    } else if sample.p99 <= t.p99_low
      && sample.cpu_basis_points <= t.cpu_low_basis_points
      && sample.memory_basis_points <= t.memory_low_basis_points
    {
      FeedbackSignal::Healthy
    } else {
      FeedbackSignal::Neutral
    }
  }

  fn apply_tier(&mut self, target: usize) -> Result<AdaptiveDecision, AdaptiveApplyError> {
    let from = self.tier;
    let old = self.tiers[from].unwrap_or_else(|| std::process::abort());
    let next = self.tiers[target].unwrap_or_else(|| std::process::abort());
    let preflight = match self.controls.readback() {
      Ok(snapshot) => snapshot,
      Err(error) => {
        return Err(self.fail(
          from,
          target,
          false,
          false,
          None,
          None,
          AdaptiveApplyFailure::PreflightRead(error),
        ));
      }
    };
    if !snapshot_matches_tier(preflight, old, self.memory_max) {
      return Err(self.fail(
        from,
        target,
        false,
        false,
        Some(preflight),
        Some(preflight),
        AdaptiveApplyFailure::Drift,
      ));
    }
    // The preflight is the latest confirmed state until the CPU setter
    // returns a more recent snapshot.
    self.last_known = preflight;
    let cpu = match self.controls.set_cpu_max(next.cpu_max) {
      Ok(snapshot) => snapshot,
      Err(error) => {
        return Err(self.fail(
          from,
          target,
          false,
          false,
          Some(preflight),
          error.observed,
          AdaptiveApplyFailure::Cpu(error),
        ));
      }
    };
    if !snapshot_matches_tier(
      cpu,
      AdaptiveTier {
        cpu_max: next.cpu_max,
        memory_high_bytes: old.memory_high_bytes,
      },
      self.memory_max,
    ) {
      return Err(self.fail(
        from,
        target,
        true,
        false,
        Some(preflight),
        Some(cpu),
        AdaptiveApplyFailure::CpuReadbackMismatch,
      ));
    }
    self.last_known = cpu;
    let memory = match self.controls.set_memory_high(next.memory_high_bytes) {
      Ok(snapshot) => snapshot,
      Err(error) => {
        return Err(self.fail(
          from,
          target,
          true,
          false,
          Some(preflight),
          error.observed,
          AdaptiveApplyFailure::MemoryHigh(error),
        ));
      }
    };
    if !snapshot_matches_tier(memory, next, self.memory_max) {
      return Err(self.fail(
        from,
        target,
        true,
        true,
        Some(preflight),
        Some(memory),
        AdaptiveApplyFailure::MemoryHighReadbackMismatch,
      ));
    }
    self.tier = target;
    self.last_known = memory;
    self.breach_count = 0;
    self.recovery_count = 0;
    self.last_transition = self.last_sample;
    Ok(AdaptiveDecision::Changed { from, to: target })
  }

  #[allow(
    clippy::too_many_arguments,
    reason = "failure construction preserves ordered partial progress and both distinct observations"
  )]
  fn fail(
    &mut self,
    from_tier: usize,
    to_tier: usize,
    cpu_setter_succeeded: bool,
    memory_high_setter_succeeded: bool,
    preflight: Option<CgroupSnapshot>,
    observed: Option<CgroupSnapshot>,
    failure: AdaptiveApplyFailure,
  ) -> AdaptiveApplyError {
    self.faulted = true;
    self.breach_count = 0;
    self.recovery_count = 0;
    if let Some(snapshot) = observed {
      self.last_known = snapshot;
    }
    AdaptiveApplyError {
      from_tier,
      to_tier,
      cpu_setter_succeeded,
      memory_high_setter_succeeded,
      last_known: self.last_known,
      preflight,
      observed,
      failure,
    }
  }

  fn resume_from_readback(&mut self, now: Instant) -> Result<usize, AdaptiveResumeError> {
    if !self.faulted {
      return Err(AdaptiveResumeError::NotFaulted);
    }
    if self
      .time_watermark
      .is_some_and(|watermark| now.checked_duration_since(watermark).is_none())
    {
      return Err(AdaptiveResumeError::NonMonotonicTime);
    }
    // A failed reconciliation attempt still advances the time watermark;
    // stale samples cannot count after a later successful recovery.
    self.time_watermark = Some(now);
    let snapshot = self
      .controls
      .readback()
      .map_err(|error| AdaptiveResumeError::State(AdaptiveStateError::Readback(error)))?;
    if snapshot.memory_max != Limit::Value(self.memory_max) {
      return Err(AdaptiveResumeError::State(
        AdaptiveStateError::InvalidMemoryMax(snapshot.memory_max),
      ));
    }
    let Some((index, _)) = self.tiers[..self.tier_count]
      .iter()
      .flatten()
      .enumerate()
      .find(|(_, tier)| snapshot_matches_tier(snapshot, **tier, self.memory_max))
    else {
      return Err(AdaptiveResumeError::State(
        AdaptiveStateError::NoMatchingTier(snapshot),
      ));
    };
    self.tier = index;
    self.last_known = snapshot;
    self.faulted = false;
    self.last_sample = Some(now);
    self.time_watermark = Some(now);
    self.last_transition = Some(now);
    self.breach_count = 0;
    self.recovery_count = 0;
    Ok(index)
  }
}

#[cfg(test)]
fn empty_snapshot(tier: AdaptiveTier, memory_max: u64) -> CgroupSnapshot {
  CgroupSnapshot {
    cpu_max: CpuMaxReadback {
      quota_us: Limit::Value(tier.cpu_max.quota_us()),
      period_us: tier.cpu_max.period_us(),
    },
    memory_high: Limit::Value(tier.memory_high_bytes),
    memory_max: Limit::Value(memory_max),
    io_max: [None; super::cgroup::MAX_IO_DEVICES],
    io_max_len: 0,
  }
}

#[cfg(test)]
mod tests {
  #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

  use super::super::cgroup::{
    ApplyFailure, CgroupIoError, CgroupRequest, Control, MAX_IO_DEVICES, ReadFailure,
  };
  use super::*;
  use std::cell::Cell;

  const PERIOD: u64 = 100_000;
  const PAGE: u64 = 4096;
  const MAX_BYTES: u64 = 64 * PAGE;

  fn cpu(quota: u64) -> CpuMax {
    CpuMax::new(
      std::num::NonZeroU64::new(quota).unwrap(),
      std::num::NonZeroU64::new(PERIOD).unwrap(),
    )
  }

  fn tiers() -> [AdaptiveTier; 3] {
    [
      AdaptiveTier {
        cpu_max: cpu(10_000),
        memory_high_bytes: 8 * PAGE,
      },
      AdaptiveTier {
        cpu_max: cpu(20_000),
        memory_high_bytes: 16 * PAGE,
      },
      AdaptiveTier {
        cpu_max: cpu(30_000),
        memory_high_bytes: 24 * PAGE,
      },
    ]
  }

  fn thresholds() -> AdaptiveThresholds {
    AdaptiveThresholds::new(
      Duration::from_millis(20),
      Duration::from_millis(40),
      4_000,
      8_000,
      5_000,
      9_000,
    )
    .unwrap()
  }

  fn config() -> AdaptiveConfig {
    AdaptiveConfig::new(
      thresholds(),
      2,
      2,
      Duration::from_millis(10),
      Duration::from_secs(1),
      Duration::from_millis(50),
    )
    .unwrap()
  }

  fn snap(tier: AdaptiveTier, memory_max: u64) -> CgroupSnapshot {
    empty_snapshot(tier, memory_max)
  }

  #[derive(Clone, Copy)]
  enum FailurePoint {
    None,
    Readback,
    Cpu,
    CpuMismatch,
    Memory,
    MemoryMismatch,
  }

  struct FakeControls {
    snapshot: Cell<CgroupSnapshot>,
    failure: Cell<FailurePoint>,
    writes: Cell<(usize, usize)>,
  }

  impl FakeControls {
    fn new(tier: AdaptiveTier) -> Self {
      Self {
        snapshot: Cell::new(snap(tier, MAX_BYTES)),
        failure: Cell::new(FailurePoint::None),
        writes: Cell::new((0, 0)),
      }
    }

    fn set(&self, tier: AdaptiveTier) {
      self.snapshot.set(snap(tier, MAX_BYTES));
    }

    fn cgroup_error(control: Control) -> CgroupApplyError {
      CgroupApplyError {
        control,
        requested: CgroupRequest {
          cpu_max: None,
          memory_bytes: None,
          io_max: [None; MAX_IO_DEVICES],
          io_copied: 0,
          io_requested: 0,
        },
        failure: ApplyFailure::Io(CgroupIoError {
          kind: std::io::ErrorKind::PermissionDenied,
          raw_os_error: Some(1),
        }),
        io_entries_written: 0,
        observed: None,
      }
    }

    fn read_error() -> CgroupReadError {
      CgroupReadError {
        control: Control::CpuMax,
        failure: ReadFailure::Io(CgroupIoError {
          kind: std::io::ErrorKind::PermissionDenied,
          raw_os_error: Some(1),
        }),
      }
    }
  }

  impl Controls for FakeControls {
    fn readback(&self) -> Result<CgroupSnapshot, CgroupReadError> {
      if matches!(self.failure.get(), FailurePoint::Readback) {
        Err(Self::read_error())
      } else {
        Ok(self.snapshot.get())
      }
    }

    fn set_cpu_max(&self, value: CpuMax) -> Result<CgroupSnapshot, CgroupApplyError> {
      self
        .writes
        .set((self.writes.get().0 + 1, self.writes.get().1));
      if matches!(self.failure.get(), FailurePoint::Cpu) {
        return Err(Self::cgroup_error(Control::CpuMax));
      }
      let mut state = self.snapshot.get();
      state.cpu_max = CpuMaxReadback {
        quota_us: Limit::Value(value.quota_us()),
        period_us: value.period_us(),
      };
      if matches!(self.failure.get(), FailurePoint::CpuMismatch) {
        state.memory_high = Limit::Value(9 * PAGE);
      }
      self.snapshot.set(state);
      Ok(state)
    }

    fn set_memory_high(&self, value: u64) -> Result<CgroupSnapshot, CgroupApplyError> {
      self
        .writes
        .set((self.writes.get().0, self.writes.get().1 + 1));
      if matches!(self.failure.get(), FailurePoint::Memory) {
        return Err(Self::cgroup_error(Control::MemoryHigh));
      }
      let mut state = self.snapshot.get();
      state.memory_high = Limit::Value(value);
      if matches!(self.failure.get(), FailurePoint::MemoryMismatch) {
        state.memory_max = Limit::Value(MAX_BYTES - PAGE);
      }
      self.snapshot.set(state);
      Ok(state)
    }
  }

  fn controller(tier: usize) -> ControllerState<FakeControls> {
    let table = validate_tiers(
      &tiers(),
      &CgroupCeilings::new(cpu(30_000), 32 * PAGE, MAX_BYTES),
    )
    .unwrap();
    let initial = snap(tiers()[tier], MAX_BYTES);
    ControllerState::new(
      FakeControls::new(tiers()[tier]),
      table.0,
      table.1,
      config(),
      tier,
      MAX_BYTES,
      initial,
    )
  }

  fn sample(at: Instant, signal: FeedbackSignal) -> FeedbackSample {
    match signal {
      FeedbackSignal::Breach => FeedbackSample {
        at,
        p99: Duration::from_millis(50),
        cpu_basis_points: 8_000,
        memory_basis_points: 9_000,
      },
      FeedbackSignal::Healthy => FeedbackSample {
        at,
        p99: Duration::from_millis(10),
        cpu_basis_points: 2_000,
        memory_basis_points: 3_000,
      },
      FeedbackSignal::Neutral => FeedbackSample {
        at,
        p99: Duration::from_millis(30),
        cpu_basis_points: 6_000,
        memory_basis_points: 7_000,
      },
    }
  }

  #[test]
  fn config_validates_hysteresis_intervals_counts_and_cooldown() {
    assert_eq!(
      AdaptiveThresholds::new(
        Duration::from_millis(5),
        Duration::from_millis(5),
        0,
        1,
        0,
        1
      ),
      Err(AdaptiveConfigError::LatencyHysteresis)
    );
    assert_eq!(
      AdaptiveThresholds::new(Duration::ZERO, Duration::from_millis(1), 0, 10_001, 0, 1),
      Err(AdaptiveConfigError::UtilizationHysteresis)
    );
    assert!(
      AdaptiveConfig::new(
        thresholds(),
        0,
        1,
        Duration::from_millis(1),
        Duration::from_millis(1),
        Duration::from_secs(1)
      )
      .is_err()
    );
    assert!(
      AdaptiveConfig::new(
        thresholds(),
        1,
        1,
        Duration::ZERO,
        Duration::from_millis(1),
        Duration::from_secs(1)
      )
      .is_err()
    );
    assert!(
      AdaptiveConfig::new(
        thresholds(),
        1,
        1,
        Duration::from_millis(2),
        Duration::from_millis(1),
        Duration::from_secs(1)
      )
      .is_err()
    );
    assert!(
      AdaptiveConfig::new(
        thresholds(),
        1,
        1,
        Duration::from_millis(1),
        Duration::from_millis(1),
        Duration::ZERO
      )
      .is_err()
    );
    assert!(
      AdaptiveConfig::new(
        thresholds(),
        1,
        1,
        Duration::from_millis(1),
        Duration::from_millis(1),
        Duration::from_secs(86_401)
      )
      .is_err()
    );
  }

  #[test]
  fn tiers_require_shared_period_strict_order_and_all_ceilings() {
    let ceilings = CgroupCeilings::new(cpu(30_000), 32 * PAGE, MAX_BYTES);
    assert_eq!(validate_tiers(&tiers(), &ceilings).unwrap().1, 3);
    let mut invalid = tiers();
    invalid[1].cpu_max = CpuMax::new(
      std::num::NonZeroU64::new(20_000).unwrap(),
      std::num::NonZeroU64::new(PERIOD * 2).unwrap(),
    );
    assert_eq!(
      validate_tiers(&invalid, &ceilings).unwrap_err(),
      AdaptiveStartError::Tiers(AdaptiveTierError::DifferentCpuPeriods)
    );
    let mut invalid = tiers();
    invalid[2].memory_high_bytes = MAX_BYTES + PAGE;
    assert_eq!(
      validate_tiers(&invalid, &ceilings).unwrap_err(),
      AdaptiveStartError::Tiers(AdaptiveTierError::InvalidMemoryHigh(2))
    );
    assert_eq!(
      validate_tiers(&tiers()[..1], &ceilings).unwrap_err(),
      AdaptiveStartError::Tiers(AdaptiveTierError::Count)
    );
    let (table, count) = validate_tiers(&tiers(), &ceilings).unwrap();
    assert_eq!(
      validate_tiers_under_memory_max(&table, count, 16 * PAGE),
      Err(AdaptiveTierError::MemoryHighAboveMax(2))
    );
    assert_eq!(
      finite_memory_max(Limit::Max, MAX_BYTES),
      Err(AdaptiveStateError::InvalidMemoryMax(Limit::Max))
    );
    assert_eq!(
      finite_memory_max(Limit::Value(MAX_BYTES + PAGE), MAX_BYTES),
      Err(AdaptiveStateError::InvalidMemoryMax(Limit::Value(
        MAX_BYTES + PAGE
      )))
    );
    assert_eq!(
      finite_memory_max(Limit::Value(MAX_BYTES), MAX_BYTES),
      Ok(MAX_BYTES)
    );
  }

  #[test]
  fn sustained_breach_and_recovery_move_one_tier_with_cooldown() {
    let mut state = controller(0);
    let start = Instant::now();
    assert!(matches!(
      state.observe(sample(start, FeedbackSignal::Breach)),
      Ok(AdaptiveDecision::Stable { .. })
    ));
    assert_eq!(
      state.observe(sample(
        start + Duration::from_millis(10),
        FeedbackSignal::Breach
      )),
      Ok(AdaptiveDecision::Changed { from: 0, to: 1 })
    );
    assert_eq!(
      state.observe(sample(
        start + Duration::from_millis(20),
        FeedbackSignal::Breach
      )),
      Ok(AdaptiveDecision::Stable {
        tier: 1,
        signal: FeedbackSignal::Breach,
        breach_samples: 1,
        recovery_samples: 0
      })
    );
    assert_eq!(
      state.observe(sample(
        start + Duration::from_millis(30),
        FeedbackSignal::Breach
      )),
      Ok(AdaptiveDecision::CoolingDown { tier: 1 })
    );
    assert_eq!(
      state.observe(sample(
        start + Duration::from_millis(40),
        FeedbackSignal::Breach
      )),
      Ok(AdaptiveDecision::CoolingDown { tier: 1 })
    );
    assert_eq!(
      state.observe(sample(
        start + Duration::from_millis(50),
        FeedbackSignal::Breach
      )),
      Ok(AdaptiveDecision::CoolingDown { tier: 1 })
    );
    assert_eq!(
      state.observe(sample(
        start + Duration::from_millis(60),
        FeedbackSignal::Breach
      )),
      Ok(AdaptiveDecision::Changed { from: 1, to: 2 })
    );

    assert_eq!(
      state.observe(sample(
        start + Duration::from_millis(70),
        FeedbackSignal::Healthy
      )),
      Ok(AdaptiveDecision::Stable {
        tier: 2,
        signal: FeedbackSignal::Healthy,
        breach_samples: 0,
        recovery_samples: 1
      })
    );
    assert_eq!(
      state.observe(sample(
        start + Duration::from_millis(80),
        FeedbackSignal::Healthy
      )),
      Ok(AdaptiveDecision::CoolingDown { tier: 2 })
    );
    assert_eq!(
      state.observe(sample(
        start + Duration::from_millis(90),
        FeedbackSignal::Healthy
      )),
      Ok(AdaptiveDecision::CoolingDown { tier: 2 })
    );
    assert_eq!(
      state.observe(sample(
        start + Duration::from_millis(100),
        FeedbackSignal::Healthy
      )),
      Ok(AdaptiveDecision::CoolingDown { tier: 2 })
    );
    assert_eq!(
      state.observe(sample(
        start + Duration::from_millis(110),
        FeedbackSignal::Healthy
      )),
      Ok(AdaptiveDecision::Changed { from: 2, to: 1 })
    );
  }

  #[test]
  fn invalid_time_and_utilization_leave_streak_and_watermark_unchanged() {
    let mut state = controller(0);
    let start = Instant::now();
    state
      .observe(sample(start, FeedbackSignal::Breach))
      .unwrap();
    let before = (state.breach_count, state.time_watermark);
    assert_eq!(
      state.observe(sample(
        start + Duration::from_millis(1),
        FeedbackSignal::Breach
      )),
      Err(AdaptiveObserveError::SampleTooSoon)
    );
    assert_eq!(
      state.observe(sample(
        start - Duration::from_millis(1),
        FeedbackSignal::Breach
      )),
      Err(AdaptiveObserveError::NonMonotonicTime)
    );
    let mut bad = sample(start + Duration::from_millis(10), FeedbackSignal::Breach);
    bad.memory_basis_points = 10_001;
    assert_eq!(
      state.observe(bad),
      Err(AdaptiveObserveError::InvalidUtilization)
    );
    assert_eq!((state.breach_count, state.time_watermark), before);
  }

  #[test]
  fn long_gap_resets_streak_and_neutral_resets_both_directions() {
    let mut state = controller(0);
    let start = Instant::now();
    state
      .observe(sample(start, FeedbackSignal::Breach))
      .unwrap();
    let long_gap = start + Duration::from_secs(2);
    assert_eq!(
      state.observe(sample(long_gap, FeedbackSignal::Breach)),
      Ok(AdaptiveDecision::Stable {
        tier: 0,
        signal: FeedbackSignal::Breach,
        breach_samples: 1,
        recovery_samples: 0
      })
    );
    assert_eq!(
      state.observe(sample(
        long_gap + Duration::from_millis(10),
        FeedbackSignal::Neutral
      )),
      Ok(AdaptiveDecision::Stable {
        tier: 0,
        signal: FeedbackSignal::Neutral,
        breach_samples: 0,
        recovery_samples: 0
      })
    );
  }

  #[test]
  fn failure_after_cpu_write_latches_until_matching_explicit_resume() {
    let mut state = controller(0);
    state.controls.failure.set(FailurePoint::Memory);
    let start = Instant::now();
    state
      .observe(sample(start, FeedbackSignal::Breach))
      .unwrap();
    let error = state
      .observe(sample(
        start + Duration::from_millis(10),
        FeedbackSignal::Breach,
      ))
      .unwrap_err();
    let AdaptiveObserveError::Apply(error) = error else {
      panic!("expected apply failure")
    };
    assert!(error.cpu_setter_succeeded);
    assert!(!error.memory_high_setter_succeeded);
    assert_eq!(
      error.failure,
      AdaptiveApplyFailure::MemoryHigh(FakeControls::cgroup_error(Control::MemoryHigh))
    );
    assert_eq!(error.preflight, Some(snap(tiers()[0], MAX_BYTES)));
    assert_eq!(error.observed, None);
    let mut cpu_confirmed = snap(tiers()[0], MAX_BYTES);
    cpu_confirmed.cpu_max = CpuMaxReadback {
      quota_us: Limit::Value(tiers()[1].cpu_max.quota_us()),
      period_us: tiers()[1].cpu_max.period_us(),
    };
    assert_eq!(error.last_known, cpu_confirmed);
    assert_eq!(state.controls.writes.get(), (1, 1));
    assert!(state.faulted);
    assert_eq!(
      state.observe(sample(
        start + Duration::from_millis(20),
        FeedbackSignal::Breach
      )),
      Err(AdaptiveObserveError::Faulted)
    );
    assert_eq!(state.controls.writes.get(), (1, 1));

    state.controls.failure.set(FailurePoint::None);
    let resume_at = start + Duration::from_millis(30);
    assert_eq!(
      state.resume_from_readback(resume_at),
      Err(AdaptiveResumeError::State(
        AdaptiveStateError::NoMatchingTier(state.controls.snapshot.get())
      ))
    );
    assert!(state.faulted);
    state.controls.set(tiers()[1]);
    assert_eq!(
      state.resume_from_readback(resume_at - Duration::from_millis(1)),
      Err(AdaptiveResumeError::NonMonotonicTime)
    );
    assert_eq!(state.resume_from_readback(resume_at), Ok(1));
    assert!(!state.faulted);
    assert_eq!(
      state.observe(sample(resume_at, FeedbackSignal::Breach)),
      Err(AdaptiveObserveError::SampleTooSoon)
    );

    let mut cpu_failure = controller(0);
    cpu_failure.controls.failure.set(FailurePoint::Cpu);
    cpu_failure
      .observe(sample(start, FeedbackSignal::Breach))
      .unwrap();
    let error = cpu_failure
      .observe(sample(
        start + Duration::from_millis(10),
        FeedbackSignal::Breach,
      ))
      .unwrap_err();
    assert!(matches!(
      error,
      AdaptiveObserveError::Apply(AdaptiveApplyError {
        failure: AdaptiveApplyFailure::Cpu(_),
        cpu_setter_succeeded: false,
        memory_high_setter_succeeded: false,
        ..
      })
    ));
    assert_eq!(cpu_failure.controls.writes.get(), (1, 0));
  }

  #[test]
  fn setter_snapshot_mismatches_latch_with_latest_observation_without_replay() {
    let start = Instant::now();
    let mut cpu_mismatch = controller(0);
    cpu_mismatch.controls.failure.set(FailurePoint::CpuMismatch);
    cpu_mismatch
      .observe(sample(start, FeedbackSignal::Breach))
      .unwrap();
    let error = cpu_mismatch
      .observe(sample(
        start + Duration::from_millis(10),
        FeedbackSignal::Breach,
      ))
      .unwrap_err();
    let AdaptiveObserveError::Apply(error) = error else {
      panic!("expected CPU readback mismatch")
    };
    assert_eq!(error.failure, AdaptiveApplyFailure::CpuReadbackMismatch);
    assert!(error.cpu_setter_succeeded);
    assert!(!error.memory_high_setter_succeeded);
    assert_eq!(error.observed, Some(cpu_mismatch.controls.snapshot.get()));
    assert_eq!(error.last_known, cpu_mismatch.controls.snapshot.get());
    assert_eq!(cpu_mismatch.controls.writes.get(), (1, 0));
    assert!(cpu_mismatch.faulted);
    assert_eq!(
      cpu_mismatch.observe(sample(
        start + Duration::from_millis(20),
        FeedbackSignal::Breach,
      )),
      Err(AdaptiveObserveError::Faulted)
    );
    assert_eq!(cpu_mismatch.controls.writes.get(), (1, 0));

    let mut memory_mismatch = controller(0);
    memory_mismatch
      .controls
      .failure
      .set(FailurePoint::MemoryMismatch);
    memory_mismatch
      .observe(sample(start, FeedbackSignal::Breach))
      .unwrap();
    let error = memory_mismatch
      .observe(sample(
        start + Duration::from_millis(10),
        FeedbackSignal::Breach,
      ))
      .unwrap_err();
    let AdaptiveObserveError::Apply(error) = error else {
      panic!("expected memory.high readback mismatch")
    };
    assert_eq!(
      error.failure,
      AdaptiveApplyFailure::MemoryHighReadbackMismatch
    );
    assert!(error.cpu_setter_succeeded);
    assert!(error.memory_high_setter_succeeded);
    assert_eq!(
      error.observed,
      Some(memory_mismatch.controls.snapshot.get())
    );
    assert_eq!(error.last_known, memory_mismatch.controls.snapshot.get());
    assert_eq!(memory_mismatch.controls.writes.get(), (1, 1));
    assert!(memory_mismatch.faulted);
    assert_eq!(
      memory_mismatch.observe(sample(
        start + Duration::from_millis(20),
        FeedbackSignal::Breach,
      )),
      Err(AdaptiveObserveError::Faulted)
    );
    assert_eq!(memory_mismatch.controls.writes.get(), (1, 1));
  }

  #[test]
  fn preflight_drift_and_readback_failure_never_write() {
    let mut state = controller(0);
    let mut drift = state.controls.snapshot.get();
    drift.memory_high = Limit::Value(12 * PAGE);
    state.controls.snapshot.set(drift);
    let start = Instant::now();
    state
      .observe(sample(start, FeedbackSignal::Breach))
      .unwrap();
    let error = state
      .observe(sample(
        start + Duration::from_millis(10),
        FeedbackSignal::Breach,
      ))
      .unwrap_err();
    assert!(matches!(
      error,
      AdaptiveObserveError::Apply(AdaptiveApplyError {
        failure: AdaptiveApplyFailure::Drift,
        ..
      })
    ));
    assert_eq!(state.controls.writes.get(), (0, 0));
    assert!(state.faulted);

    let mut unknown = controller(0);
    unknown.controls.failure.set(FailurePoint::Readback);
    unknown
      .observe(sample(start, FeedbackSignal::Breach))
      .unwrap();
    let error = unknown
      .observe(sample(
        start + Duration::from_millis(10),
        FeedbackSignal::Breach,
      ))
      .unwrap_err();
    assert!(matches!(
      error,
      AdaptiveObserveError::Apply(AdaptiveApplyError {
        failure: AdaptiveApplyFailure::PreflightRead(_),
        observed: None,
        ..
      })
    ));
    assert_eq!(unknown.controls.writes.get(), (0, 0));
  }

  #[test]
  fn boundaries_stop_without_writes() {
    let mut top = controller(2);
    let start = Instant::now();
    top.observe(sample(start, FeedbackSignal::Breach)).unwrap();
    assert_eq!(
      top.observe(sample(
        start + Duration::from_millis(10),
        FeedbackSignal::Breach
      )),
      Ok(AdaptiveDecision::AtCeiling { tier: 2 })
    );
    assert_eq!(top.controls.writes.get(), (0, 0));

    let mut bottom = controller(0);
    bottom
      .observe(sample(start, FeedbackSignal::Healthy))
      .unwrap();
    assert_eq!(
      bottom.observe(sample(
        start + Duration::from_millis(10),
        FeedbackSignal::Healthy
      )),
      Ok(AdaptiveDecision::AtFloor { tier: 0 })
    );
    assert_eq!(bottom.controls.writes.get(), (0, 0));
  }
}
