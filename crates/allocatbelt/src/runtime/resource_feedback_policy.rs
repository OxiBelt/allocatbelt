//! Fixed-storage policy for autonomous CPU, disk, and network feedback.
//!
//! This module consumes caller-measured utilization and returns immutable
//! limit-change tickets. It does not collect telemetry or apply operating
//! system controls. Callers must acknowledge each ticket after the actuator
//! reports its result, and must reconcile a failed or ambiguous application
//! against the actuator's actual readback before that control can resume.
//!
//! The policy uses real monotonic [`Instant`] values, fixed arrays, and no
//! dynamic collections. Sampling, planning, acknowledgement, and reconciliation
//! do not allocate. A caller should sample every 100 ms; a control freezes when
//! its required telemetry is missing, sparse, or older than 500 ms.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::time::{Duration, Instant};

/// Required interval between accepted utilization samples.
pub const SAMPLE_INTERVAL: Duration = Duration::from_millis(100);
/// Largest inter-reading gap still treated as dense telemetry.
///
/// This is two nominal sample intervals, allowing one delayed sample or
/// ordinary scheduling jitter. Longer gaps freeze the affected control as
/// sparse; readings older than [`TELEMETRY_FRESHNESS`] are stale.
pub const MAX_DENSE_SAMPLE_GAP: Duration = Duration::from_millis(200);
/// Maximum age at which a telemetry reading can inform a decision.
pub const TELEMETRY_FRESHNESS: Duration = Duration::from_millis(500);
/// Number of consecutive high readings required before reducing a limit.
pub const REQUIRED_BREACH_SAMPLES: u8 = 3;
/// Minimum time between changes to the same control after success or readback.
pub const ACTUATION_COOLDOWN: Duration = Duration::from_secs(1);
/// Version bound into benchmark receipts for the original 10-percent CPU rule.
pub const FEEDBACK_POLICY_VERSION: &str = "runtime-feedback-policy-v1";

const RESOURCE_COUNT: usize = 3;
const RESOURCES: [FeedbackResource; RESOURCE_COUNT] = [
  FeedbackResource::CpuConcurrency,
  FeedbackResource::DiskRate,
  FeedbackResource::NetworkRate,
];

/// A limit controlled by the feedback policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum FeedbackResource {
  /// Concurrent CPU work slots.
  CpuConcurrency = 0,
  /// Disk application bytes per second.
  DiskRate = 1,
  /// Network application bytes per second.
  NetworkRate = 2,
}

impl FeedbackResource {
  const fn index(self) -> usize {
    self as usize
  }
}

/// Floors, ceilings, and utilization hysteresis for one controlled limit.
///
/// Utilization is in basis points: 10,000 means 100%. A reading at or above
/// `high_utilization_basis_points` is a breach; a reading at or below
/// `low_utilization_basis_points` is healthy. Readings between the thresholds
/// hold the limit steady and reset a partial breach streak.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeedbackControlConfig {
  /// Smallest permitted concurrency or rate.
  pub floor: u64,
  /// Limit used when the policy is first created.
  pub initial: u64,
  /// Largest permitted concurrency or rate.
  pub ceiling: u64,
  /// Healthy utilization threshold, in 0..=10000 basis points.
  pub low_utilization_basis_points: u16,
  /// Breach utilization threshold, in 1..=10000 basis points.
  pub high_utilization_basis_points: u16,
}

impl FeedbackControlConfig {
  /// Describes one control. [`ResourceFeedbackPolicy::new`] validates it.
  pub const fn new(
    floor: u64,
    initial: u64,
    ceiling: u64,
    low_utilization_basis_points: u16,
    high_utilization_basis_points: u16,
  ) -> Self {
    Self {
      floor,
      initial,
      ceiling,
      low_utilization_basis_points,
      high_utilization_basis_points,
    }
  }
}

/// Complete fixed-size configuration for the three autonomous controls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceFeedbackPolicyConfig {
  /// CPU concurrency slot limits.
  pub cpu_concurrency: FeedbackControlConfig,
  /// Disk byte-rate limits.
  pub disk_rate: FeedbackControlConfig,
  /// Network byte-rate limits.
  pub network_rate: FeedbackControlConfig,
}

impl ResourceFeedbackPolicyConfig {
  const fn controls(self) -> [FeedbackControlConfig; RESOURCE_COUNT] {
    [self.cpu_concurrency, self.disk_rate, self.network_rate]
  }
}

/// Why feedback policy construction was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyConfigError {
  /// The initial limit is outside its inclusive floor and ceiling.
  InvalidBounds(FeedbackResource),
  /// The high threshold must be above the low threshold and at most 10000.
  InvalidHysteresis(FeedbackResource),
  /// CPU concurrency is represented by a bounded 32-bit slot count.
  CpuCeilingTooLarge,
}

impl fmt::Display for PolicyConfigError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "resource feedback configuration is invalid: {self:?}")
  }
}

impl std::error::Error for PolicyConfigError {}

/// One measured utilization sample. Missing fields freeze only their control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeedbackSample {
  /// Monotonic time when the readings were measured.
  pub at: Instant,
  /// CPU utilization in basis points, when available.
  pub cpu_utilization_basis_points: Option<u16>,
  /// Disk utilization in basis points, when available.
  pub disk_utilization_basis_points: Option<u16>,
  /// Network utilization in basis points, when available.
  pub network_utilization_basis_points: Option<u16>,
}

impl FeedbackSample {
  /// Creates a sample. Values are validated when submitted to the policy.
  pub const fn new(
    at: Instant,
    cpu_utilization_basis_points: Option<u16>,
    disk_utilization_basis_points: Option<u16>,
    network_utilization_basis_points: Option<u16>,
  ) -> Self {
    Self {
      at,
      cpu_utilization_basis_points,
      disk_utilization_basis_points,
      network_utilization_basis_points,
    }
  }

  const fn utilization(self, resource: FeedbackResource) -> Option<u16> {
    match resource {
      FeedbackResource::CpuConcurrency => self.cpu_utilization_basis_points,
      FeedbackResource::DiskRate => self.disk_utilization_basis_points,
      FeedbackResource::NetworkRate => self.network_utilization_basis_points,
    }
  }
}

/// Utilization freshness for one control at plan time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryStatus {
  /// No reading is available for this control.
  Missing,
  /// Readings did not arrive at the required 100 ms cadence.
  Sparse,
  /// The newest reading is older than 500 ms.
  Stale,
  /// A current reading is available at the required cadence.
  Fresh,
}

/// An issued, single-use request to change one control.
///
/// Ticket fields are private so callers cannot alter the expected old limit,
/// target, resource, or generation. Copying a ticket is harmless: only the
/// still-pending generation can be acknowledged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanTicket {
  resource: FeedbackResource,
  generation: u64,
  from_limit: u64,
  to_limit: u64,
  /// Measurement time of the telemetry that justified this ticket.
  telemetry_at: Instant,
  planned_at: Instant,
}

impl PlanTicket {
  /// Control this ticket targets.
  pub const fn resource(self) -> FeedbackResource {
    self.resource
  }

  /// Globally increasing generation, never reused or wrapped.
  pub const fn generation(self) -> u64 {
    self.generation
  }

  /// Limit the actuator must still observe before applying this ticket.
  pub const fn from_limit(self) -> u64 {
    self.from_limit
  }

  /// Requested limit, always inside the configured floor and ceiling.
  pub const fn to_limit(self) -> u64 {
    self.to_limit
  }

  /// Monotonic time when this plan was issued.
  pub const fn planned_at(self) -> Instant {
    self.planned_at
  }
}

/// Stable diagnostic or a planned one-control change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionStatus {
  /// A caller may attempt the change and must acknowledge its actual result.
  Planned(PlanTicket),
  /// No new actuation should be attempted for this control.
  NoChange(NoChangeReason),
}

/// Why a control has no new plan at this time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoChangeReason {
  /// Telemetry is missing, sparse, or stale; inspect `ResourceDecision::telemetry`.
  TelemetryUnavailable,
  /// An earlier ticket for this control is still awaiting acknowledgement.
  PlanPending,
  /// A prior ambiguous application is latched until explicit reconciliation.
  ActuationFaultLatched,
  /// Fewer than three consecutive high readings have arrived.
  BreachSamplesRemaining {
    /// Consecutive fresh high readings observed so far.
    observed: u8,
    /// Required consecutive fresh high readings.
    required: u8,
  },
  /// Utilization is between the low and high hysteresis thresholds.
  HysteresisBand,
  /// The one-second cooldown since success or reconciliation has not elapsed.
  CoolingDown {
    /// Time remaining before another control change can be planned.
    remaining: Duration,
  },
  /// A reduction would cross the configured floor.
  AtFloor,
  /// A recovery would cross the configured ceiling.
  AtCeiling,
  /// The integer control cannot decrease without exceeding a 10% reduction.
  ReductionQuantized,
  /// The rate ceiling is too small to recover by one whole unit within 1%.
  RecoveryQuantized,
}

/// Decision and diagnostics for one control in a policy-plan snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceDecision {
  /// Control represented by this result.
  pub resource: FeedbackResource,
  /// Limit known after the latest successful acknowledgement or reconciliation.
  pub current_limit: u64,
  /// Most recently measured utilization, if available.
  pub utilization_basis_points: Option<u16>,
  /// Whether the required utilization reading can currently inform a decision.
  pub telemetry: TelemetryStatus,
  /// Planned ticket or typed no-change diagnostic.
  pub status: DecisionStatus,
}

/// One immutable, fixed-size set of per-control decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyPlan {
  /// Monotonic planning time.
  pub at: Instant,
  /// CPU concurrency decision.
  pub cpu_concurrency: ResourceDecision,
  /// Disk rate decision.
  pub disk_rate: ResourceDecision,
  /// Network rate decision.
  pub network_rate: ResourceDecision,
}

impl PolicyPlan {
  /// Returns one decision without allocating.
  pub const fn decision(self, resource: FeedbackResource) -> ResourceDecision {
    match resource {
      FeedbackResource::CpuConcurrency => self.cpu_concurrency,
      FeedbackResource::DiskRate => self.disk_rate,
      FeedbackResource::NetworkRate => self.network_rate,
    }
  }
}

/// Whether the actuator confirmed the requested change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActuationResult {
  /// The requested limit was applied successfully.
  Applied,
  /// Application failed or its result is ambiguous.
  Failed,
}

/// Timestamp validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampError {
  /// An operation timestamp equals the previous accepted event timestamp.
  Duplicate,
  /// A timestamp precedes the previous accepted event or sample.
  OutOfOrder,
  /// A sample or actuation timestamp is later than the operation's current time.
  Future,
}

/// Why sampling, planning, acknowledgement, or reconciliation was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
  /// Construction-time settings are inconsistent.
  InvalidConfiguration(PolicyConfigError),
  /// A caller supplied utilization outside 0..=10000 basis points.
  InvalidUtilization {
    /// Control associated with the invalid metric.
    resource: FeedbackResource,
    /// Invalid basis-point value.
    value: u16,
  },
  /// A timestamp is future, duplicate, or out of order.
  Timestamp(TimestampError),
  /// A sample arrived less than 100 ms after the last accepted sample.
  SampleTooSoon {
    /// Time since the prior accepted sample.
    elapsed: Duration,
  },
  /// No ticket is pending for the requested acknowledgement.
  NoPendingTicket,
  /// The ticket is not the current generation for its control.
  StaleTicket,
  /// The actuator's tracked limit changed outside the policy's ticket flow.
  LimitMismatch {
    /// Limit expected by the pending ticket.
    expected: u64,
    /// Actual limit reported by the caller.
    actual: u64,
  },
  /// Ticket generations are exhausted; they are never allowed to wrap.
  GenerationExhausted,
  /// Reconciliation is valid only after a failed or ambiguous application.
  ReconcileWithoutFault,
  /// A pending ticket must be acknowledged before reconciliation.
  ReconcileWhilePending,
  /// Readback is outside the configured inclusive floor and ceiling.
  ReconciledLimitOutOfBounds {
    /// Readback limit supplied by the caller.
    actual: u64,
    /// Configured floor for the control.
    floor: u64,
    /// Configured ceiling for the control.
    ceiling: u64,
  },
}

impl fmt::Display for PolicyError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "resource feedback policy refused operation: {self:?}")
  }
}

impl std::error::Error for PolicyError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DimensionState {
  current_limit: u64,
  latest_utilization: Option<u16>,
  latest_at: Option<Instant>,
  last_present_at: Option<Instant>,
  last_observation_at: Option<Instant>,
  telemetry_invalidated_at: Option<Instant>,
  sparse: bool,
  breach_streak: u8,
  pending: Option<PlanTicket>,
  faulted: bool,
  last_successful_actuation: Option<Instant>,
  last_reconciliation_barrier: Option<Instant>,
  last_acknowledgement: Option<Instant>,
}

impl DimensionState {
  const fn new(initial_limit: u64) -> Self {
    Self {
      current_limit: initial_limit,
      latest_utilization: None,
      latest_at: None,
      last_present_at: None,
      last_observation_at: None,
      telemetry_invalidated_at: None,
      sparse: false,
      breach_streak: 0,
      pending: None,
      faulted: false,
      last_successful_actuation: None,
      last_reconciliation_barrier: None,
      last_acknowledgement: None,
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DraftAction {
  Change { from: u64, to: u64 },
  NoChange(NoChangeReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DraftDecision {
  current_limit: u64,
  utilization_basis_points: Option<u16>,
  telemetry: TelemetryStatus,
  action: DraftAction,
}

/// Safe fixed-storage engine for CPU, disk, and network feedback decisions.
///
/// The owner should serialize calls. The caller supplies utilization gathered
/// by its own service and performs each requested actuation outside this
/// policy. A failed acknowledgement blocks that dimension until
/// [`Self::reconcile`] confirms the actuator's actual limit.
pub struct ResourceFeedbackPolicy {
  controls: [FeedbackControlConfig; RESOURCE_COUNT],
  dimensions: [DimensionState; RESOURCE_COUNT],
  last_event_at: Option<Instant>,
  last_sample_at: Option<Instant>,
  next_generation: u64,
  generations_exhausted: bool,
}

impl fmt::Debug for ResourceFeedbackPolicy {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ResourceFeedbackPolicy")
      .field("current_limits", &self.current_limits())
      .field("pending_tickets", &self.pending_tickets())
      .field("faulted", &self.faults())
      .finish()
  }
}

impl ResourceFeedbackPolicy {
  /// Creates a policy with explicit limits and hysteresis for every control.
  pub fn new(config: ResourceFeedbackPolicyConfig) -> Result<Self, PolicyError> {
    let controls = config.controls();
    for resource in RESOURCES {
      let control = controls[resource.index()];
      if control.floor == 0 || control.floor > control.initial || control.initial > control.ceiling
      {
        return Err(PolicyError::InvalidConfiguration(
          PolicyConfigError::InvalidBounds(resource),
        ));
      }
      if control.high_utilization_basis_points == 0
        || control.high_utilization_basis_points > 10_000
        || control.low_utilization_basis_points >= control.high_utilization_basis_points
      {
        return Err(PolicyError::InvalidConfiguration(
          PolicyConfigError::InvalidHysteresis(resource),
        ));
      }
    }
    if config.cpu_concurrency.ceiling > u64::from(u32::MAX) {
      return Err(PolicyError::InvalidConfiguration(
        PolicyConfigError::CpuCeilingTooLarge,
      ));
    }
    Ok(Self {
      controls,
      dimensions: [
        DimensionState::new(config.cpu_concurrency.initial),
        DimensionState::new(config.disk_rate.initial),
        DimensionState::new(config.network_rate.initial),
      ],
      last_event_at: None,
      last_sample_at: None,
      next_generation: 1,
      generations_exhausted: false,
    })
  }

  /// Records one caller-measured sample using the real monotonic clock.
  ///
  /// Sample times must strictly increase and samples must be at least 100 ms
  /// apart. A missing metric affects only its own control.
  pub fn observe(&mut self, sample: FeedbackSample) -> Result<(), PolicyError> {
    self.observe_at(sample, Instant::now())
  }

  /// Produces a fixed-size plan using the real monotonic clock.
  pub fn plan(&mut self) -> Result<PolicyPlan, PolicyError> {
    self.plan_at(Instant::now())
  }

  /// Acknowledges a ticket at the caller-captured monotonic actuation time.
  ///
  /// Capture `at` immediately after the actuator reports success or failure.
  /// On success it starts that control's one-second cooldown. A failed or
  /// ambiguous result latches only that control; this method never rolls back
  /// another limit or assumes the failed actuator had no effect.
  pub fn acknowledge(
    &mut self,
    ticket: PlanTicket,
    result: ActuationResult,
    at: Instant,
  ) -> Result<(), PolicyError> {
    self.acknowledge_at(ticket, result, at, Instant::now())
  }

  /// Reconciles a faulted control to an actuator's explicit actual readback.
  ///
  /// Reconciliation clears its pending fault, resets its breach streak, and
  /// invalidates its old telemetry. A fresh reading is required before it can
  /// receive another plan. It does not count as a successful actuation.
  pub fn reconcile(
    &mut self,
    resource: FeedbackResource,
    actual_limit: u64,
  ) -> Result<(), PolicyError> {
    self.reconcile_at(resource, actual_limit, Instant::now())
  }

  /// Returns the policy's latest known control limits in fixed resource order.
  pub const fn current_limits(&self) -> [u64; RESOURCE_COUNT] {
    [
      self.dimensions[0].current_limit,
      self.dimensions[1].current_limit,
      self.dimensions[2].current_limit,
    ]
  }

  /// Returns whether each control is latched pending explicit reconciliation.
  pub const fn faults(&self) -> [bool; RESOURCE_COUNT] {
    [
      self.dimensions[0].faulted,
      self.dimensions[1].faulted,
      self.dimensions[2].faulted,
    ]
  }

  /// Returns the still-pending ticket for each control, if one exists.
  pub const fn pending_tickets(&self) -> [Option<PlanTicket>; RESOURCE_COUNT] {
    [
      self.dimensions[0].pending,
      self.dimensions[1].pending,
      self.dimensions[2].pending,
    ]
  }

  /// Expires a planned ticket when its required telemetry is sparse or stale.
  ///
  /// Call this immediately before beginning the actuator write, after any
  /// potentially blocking pre-write readback. A stale ticket is removed
  /// without faulting the control, changing its breach streak, or charging
  /// actuation cooldown. The caller must only use this for a ticket whose
  /// actuator write has not been attempted.
  #[cfg(feature = "resource-feedback")]
  pub(crate) fn expire_stale_ticket(
    &mut self,
    ticket: PlanTicket,
    now: Instant,
  ) -> Result<TelemetryStatus, PolicyError> {
    let index = ticket.resource.index();
    match self.dimensions[index].pending {
      None => return Err(PolicyError::NoPendingTicket),
      Some(pending) if pending != ticket => return Err(PolicyError::StaleTicket),
      Some(_) => {}
    }

    let age = now
      .checked_duration_since(ticket.telemetry_at)
      .unwrap_or(Duration::MAX);
    let telemetry = if age > TELEMETRY_FRESHNESS {
      TelemetryStatus::Stale
    } else if age > MAX_DENSE_SAMPLE_GAP {
      TelemetryStatus::Sparse
    } else {
      TelemetryStatus::Fresh
    };
    if telemetry != TelemetryStatus::Fresh {
      self.dimensions[index].pending = None;
    }
    Ok(telemetry)
  }

  fn observe_at(&mut self, sample: FeedbackSample, now: Instant) -> Result<(), PolicyError> {
    validate_event_time(now, self.last_event_at)?;
    if sample.at > now {
      return Err(PolicyError::Timestamp(TimestampError::Future));
    }
    let sample_elapsed = if let Some(last_sample) = self.last_sample_at {
      validate_after(sample.at, last_sample)?;
      Some(
        sample
          .at
          .checked_duration_since(last_sample)
          .ok_or(PolicyError::Timestamp(TimestampError::OutOfOrder))?,
      )
    } else {
      None
    };
    if let Some(elapsed) = sample_elapsed
      && elapsed < SAMPLE_INTERVAL
    {
      return Err(PolicyError::SampleTooSoon { elapsed });
    }
    for resource in RESOURCES {
      if let Some(value) = sample.utilization(resource)
        && value > 10_000
      {
        return Err(PolicyError::InvalidUtilization { resource, value });
      }
    }

    for resource in RESOURCES {
      let index = resource.index();
      let dimension = &mut self.dimensions[index];
      if dimension
        .telemetry_invalidated_at
        .is_some_and(|watermark| sample.at <= watermark)
      {
        dimension.latest_utilization = None;
        dimension.latest_at = None;
        dimension.sparse = false;
        dimension.breach_streak = 0;
        continue;
      }
      let utilization = sample.utilization(resource);
      let cadence_gap = dimension
        .last_observation_at
        .and_then(|previous| sample.at.checked_duration_since(previous))
        .is_some_and(|elapsed| elapsed > MAX_DENSE_SAMPLE_GAP);
      match utilization {
        None => {
          dimension.latest_utilization = None;
          dimension.latest_at = None;
          dimension.sparse = cadence_gap;
          dimension.breach_streak = 0;
        }
        Some(value) => {
          let present_gap = dimension
            .last_present_at
            .and_then(|previous| sample.at.checked_duration_since(previous))
            .is_some_and(|elapsed| elapsed > MAX_DENSE_SAMPLE_GAP);
          dimension.sparse = cadence_gap || present_gap;
          dimension.latest_utilization = Some(value);
          dimension.latest_at = Some(sample.at);
          dimension.last_present_at = Some(sample.at);
          if dimension.sparse {
            dimension.breach_streak = 0;
          } else {
            let control = self.controls[index];
            if value >= control.high_utilization_basis_points {
              dimension.breach_streak = dimension
                .breach_streak
                .saturating_add(1)
                .min(REQUIRED_BREACH_SAMPLES);
            } else {
              dimension.breach_streak = 0;
            }
          }
        }
      }
      dimension.last_observation_at = Some(sample.at);
    }
    self.last_sample_at = Some(sample.at);
    self.last_event_at = Some(now);
    Ok(())
  }

  fn plan_at(&mut self, now: Instant) -> Result<PolicyPlan, PolicyError> {
    validate_event_time(now, self.last_event_at)?;
    if self.last_sample_at.is_some_and(|sample_at| sample_at > now) {
      return Err(PolicyError::Timestamp(TimestampError::Future));
    }

    let drafts = [
      evaluate_dimension(
        FeedbackResource::CpuConcurrency,
        self.controls[0],
        self.dimensions[0],
        now,
      ),
      evaluate_dimension(
        FeedbackResource::DiskRate,
        self.controls[1],
        self.dimensions[1],
        now,
      ),
      evaluate_dimension(
        FeedbackResource::NetworkRate,
        self.controls[2],
        self.dimensions[2],
        now,
      ),
    ];
    let required_generations = drafts
      .iter()
      .filter(|draft| matches!(draft.action, DraftAction::Change { .. }))
      .count();
    if !self.can_issue_generations(required_generations) {
      return Err(PolicyError::GenerationExhausted);
    }

    let mut decisions = [empty_decision(FeedbackResource::CpuConcurrency); RESOURCE_COUNT];
    for resource in RESOURCES {
      let index = resource.index();
      let draft = drafts[index];
      let status = match draft.action {
        DraftAction::NoChange(reason) => DecisionStatus::NoChange(reason),
        DraftAction::Change { from, to } => {
          let generation = self.issue_generation();
          let ticket = PlanTicket {
            resource,
            generation,
            from_limit: from,
            to_limit: to,
            telemetry_at: self.dimensions[index].latest_at.unwrap_or(now),
            planned_at: now,
          };
          self.dimensions[index].pending = Some(ticket);
          DecisionStatus::Planned(ticket)
        }
      };
      decisions[index] = ResourceDecision {
        resource,
        current_limit: draft.current_limit,
        utilization_basis_points: draft.utilization_basis_points,
        telemetry: draft.telemetry,
        status,
      };
    }
    self.last_event_at = Some(now);
    Ok(PolicyPlan {
      at: now,
      cpu_concurrency: decisions[0],
      disk_rate: decisions[1],
      network_rate: decisions[2],
    })
  }

  fn acknowledge_at(
    &mut self,
    ticket: PlanTicket,
    result: ActuationResult,
    at: Instant,
    now: Instant,
  ) -> Result<(), PolicyError> {
    let index = ticket.resource.index();
    let pending = self.dimensions[index].pending;
    if pending.is_none() {
      return Err(PolicyError::NoPendingTicket);
    }
    if pending != Some(ticket) {
      return Err(PolicyError::StaleTicket);
    }

    let timestamp_result = (|| {
      validate_event_time(now, self.last_event_at)?;
      if at > now {
        return Err(PolicyError::Timestamp(TimestampError::Future));
      }
      validate_after(at, ticket.planned_at)?;
      if let Some(previous_ack) = self.dimensions[index].last_acknowledgement {
        validate_after(at, previous_ack)?;
      }
      Ok(())
    })();
    if let Err(error) = timestamp_result {
      // A malformed acknowledgement after a real attempt leaves actual state
      // uncertain. Drop the ticket and fail closed until explicit readback.
      self.dimensions[index].faulted = true;
      self.dimensions[index].pending = None;
      return Err(error);
    }

    let current = self.dimensions[index].current_limit;
    if current != ticket.from_limit {
      self.dimensions[index].faulted = true;
      self.dimensions[index].pending = None;
      self.dimensions[index].last_acknowledgement = Some(at);
      self.last_event_at = Some(now);
      return Err(PolicyError::LimitMismatch {
        expected: ticket.from_limit,
        actual: current,
      });
    }

    let dimension = &mut self.dimensions[index];
    dimension.pending = None;
    dimension.last_acknowledgement = Some(at);
    match result {
      ActuationResult::Applied => {
        dimension.current_limit = ticket.to_limit;
        dimension.last_successful_actuation = Some(at);
      }
      ActuationResult::Failed => {
        dimension.faulted = true;
      }
    }
    self.last_event_at = Some(now);
    Ok(())
  }

  fn reconcile_at(
    &mut self,
    resource: FeedbackResource,
    actual_limit: u64,
    now: Instant,
  ) -> Result<(), PolicyError> {
    validate_event_time(now, self.last_event_at)?;
    let index = resource.index();
    let control = self.controls[index];
    let dimension = self.dimensions[index];
    if dimension.pending.is_some() {
      return Err(PolicyError::ReconcileWhilePending);
    }
    if !dimension.faulted {
      return Err(PolicyError::ReconcileWithoutFault);
    }
    if actual_limit < control.floor || actual_limit > control.ceiling {
      return Err(PolicyError::ReconciledLimitOutOfBounds {
        actual: actual_limit,
        floor: control.floor,
        ceiling: control.ceiling,
      });
    }

    let dimension = &mut self.dimensions[index];
    dimension.current_limit = actual_limit;
    dimension.faulted = false;
    dimension.latest_utilization = None;
    dimension.latest_at = None;
    dimension.telemetry_invalidated_at = Some(now);
    dimension.sparse = false;
    dimension.breach_streak = 0;
    dimension.last_reconciliation_barrier = Some(now);
    self.last_event_at = Some(now);
    Ok(())
  }

  fn can_issue_generations(&self, count: usize) -> bool {
    if count == 0 {
      return true;
    }
    if self.generations_exhausted {
      return false;
    }
    let available = u128::from(u64::MAX) - u128::from(self.next_generation) + 1;
    available >= count as u128
  }

  fn issue_generation(&mut self) -> u64 {
    let generation = self.next_generation;
    if generation == u64::MAX {
      self.generations_exhausted = true;
    } else {
      self.next_generation = generation + 1;
    }
    generation
  }
}

fn empty_decision(resource: FeedbackResource) -> ResourceDecision {
  ResourceDecision {
    resource,
    current_limit: 0,
    utilization_basis_points: None,
    telemetry: TelemetryStatus::Missing,
    status: DecisionStatus::NoChange(NoChangeReason::TelemetryUnavailable),
  }
}

fn evaluate_dimension(
  resource: FeedbackResource,
  control: FeedbackControlConfig,
  dimension: DimensionState,
  now: Instant,
) -> DraftDecision {
  let telemetry = match (dimension.latest_utilization, dimension.latest_at) {
    (None, _) | (_, None) => TelemetryStatus::Missing,
    (Some(_), Some(at)) => {
      let age = now.checked_duration_since(at).unwrap_or(Duration::MAX);
      if age > TELEMETRY_FRESHNESS {
        TelemetryStatus::Stale
      } else if dimension.sparse || age > MAX_DENSE_SAMPLE_GAP {
        TelemetryStatus::Sparse
      } else {
        TelemetryStatus::Fresh
      }
    }
  };
  let mut draft = DraftDecision {
    current_limit: dimension.current_limit,
    utilization_basis_points: dimension.latest_utilization,
    telemetry,
    action: DraftAction::NoChange(NoChangeReason::TelemetryUnavailable),
  };

  if dimension.faulted {
    draft.action = DraftAction::NoChange(NoChangeReason::ActuationFaultLatched);
    return draft;
  }
  if dimension.pending.is_some() {
    draft.action = DraftAction::NoChange(NoChangeReason::PlanPending);
    return draft;
  }
  if telemetry != TelemetryStatus::Fresh {
    draft.action = DraftAction::NoChange(NoChangeReason::TelemetryUnavailable);
    return draft;
  }

  let Some(utilization) = dimension.latest_utilization else {
    return draft;
  };
  if utilization >= control.high_utilization_basis_points {
    if dimension.breach_streak < REQUIRED_BREACH_SAMPLES {
      draft.action = DraftAction::NoChange(NoChangeReason::BreachSamplesRemaining {
        observed: dimension.breach_streak,
        required: REQUIRED_BREACH_SAMPLES,
      });
      return draft;
    }
    if let Some(remaining) = cooldown_remaining(
      dimension.last_successful_actuation,
      dimension.last_reconciliation_barrier,
      now,
    ) {
      draft.action = DraftAction::NoChange(NoChangeReason::CoolingDown { remaining });
      return draft;
    }
    let reduction = dimension.current_limit / 10;
    if reduction == 0 {
      draft.action = DraftAction::NoChange(NoChangeReason::ReductionQuantized);
      return draft;
    }
    if dimension.current_limit == control.floor {
      draft.action = DraftAction::NoChange(NoChangeReason::AtFloor);
      return draft;
    }
    let proposed = dimension.current_limit - reduction;
    let target = proposed.max(control.floor);
    if target == dimension.current_limit {
      draft.action = DraftAction::NoChange(NoChangeReason::AtFloor);
      return draft;
    }
    draft.action = DraftAction::Change {
      from: dimension.current_limit,
      to: target,
    };
    return draft;
  }

  if utilization <= control.low_utilization_basis_points {
    if dimension.current_limit == control.ceiling {
      draft.action = DraftAction::NoChange(NoChangeReason::AtCeiling);
      return draft;
    }
    if let Some(remaining) = cooldown_remaining(
      dimension.last_successful_actuation,
      dimension.last_reconciliation_barrier,
      now,
    ) {
      draft.action = DraftAction::NoChange(NoChangeReason::CoolingDown { remaining });
      return draft;
    }
    let available = control.ceiling - dimension.current_limit;
    let increment = match resource {
      FeedbackResource::CpuConcurrency => 1,
      FeedbackResource::DiskRate | FeedbackResource::NetworkRate => control.ceiling / 100,
    };
    if increment == 0 {
      draft.action = DraftAction::NoChange(NoChangeReason::RecoveryQuantized);
      return draft;
    }
    let target = dimension.current_limit + increment.min(available);
    draft.action = DraftAction::Change {
      from: dimension.current_limit,
      to: target,
    };
    return draft;
  }

  draft.action = DraftAction::NoChange(NoChangeReason::HysteresisBand);
  draft
}

fn cooldown_remaining(
  last_success: Option<Instant>,
  last_reconciliation: Option<Instant>,
  now: Instant,
) -> Option<Duration> {
  let successful_remaining = remaining_since(last_success, now);
  let reconciliation_remaining = remaining_since(last_reconciliation, now);
  match (successful_remaining, reconciliation_remaining) {
    (Some(successful), Some(reconciled)) => Some(successful.max(reconciled)),
    (Some(remaining), None) | (None, Some(remaining)) => Some(remaining),
    (None, None) => None,
  }
}

fn remaining_since(anchor: Option<Instant>, now: Instant) -> Option<Duration> {
  let elapsed = now.checked_duration_since(anchor?)?;
  if elapsed < ACTUATION_COOLDOWN {
    Some(ACTUATION_COOLDOWN - elapsed)
  } else {
    None
  }
}

fn validate_event_time(now: Instant, last: Option<Instant>) -> Result<(), PolicyError> {
  if let Some(last) = last {
    validate_after(now, last)?;
  }
  Ok(())
}

fn validate_after(candidate: Instant, previous: Instant) -> Result<(), PolicyError> {
  if candidate == previous {
    Err(PolicyError::Timestamp(TimestampError::Duplicate))
  } else if candidate < previous {
    Err(PolicyError::Timestamp(TimestampError::OutOfOrder))
  } else {
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn control(floor: u64, initial: u64, ceiling: u64, low: u16, high: u16) -> FeedbackControlConfig {
    FeedbackControlConfig::new(floor, initial, ceiling, low, high)
  }

  fn config(
    cpu: FeedbackControlConfig,
    disk: FeedbackControlConfig,
    network: FeedbackControlConfig,
  ) -> ResourceFeedbackPolicyConfig {
    ResourceFeedbackPolicyConfig {
      cpu_concurrency: cpu,
      disk_rate: disk,
      network_rate: network,
    }
  }

  fn standard_config() -> ResourceFeedbackPolicyConfig {
    let control = control(10, 100, 1_000, 4_000, 8_000);
    config(control, control, control)
  }

  fn sample(
    at: Instant,
    cpu: Option<u16>,
    disk: Option<u16>,
    network: Option<u16>,
  ) -> FeedbackSample {
    FeedbackSample::new(at, cpu, disk, network)
  }

  fn observe_at(
    policy: &mut ResourceFeedbackPolicy,
    at: Instant,
    now: Instant,
    cpu: Option<u16>,
    disk: Option<u16>,
    network: Option<u16>,
  ) -> Result<(), PolicyError> {
    policy.observe_at(sample(at, cpu, disk, network), now)
  }

  fn status(plan: PolicyPlan, resource: FeedbackResource) -> DecisionStatus {
    plan.decision(resource).status
  }

  #[test]
  fn config_requires_bounds_and_separated_hysteresis() {
    let bad_bounds = control(11, 10, 100, 4_000, 8_000);
    assert_eq!(
      ResourceFeedbackPolicy::new(config(
        bad_bounds,
        control(1, 10, 100, 4_000, 8_000),
        control(1, 10, 100, 4_000, 8_000),
      ))
      .err(),
      Some(PolicyError::InvalidConfiguration(
        PolicyConfigError::InvalidBounds(FeedbackResource::CpuConcurrency)
      ))
    );

    let bad_band = control(1, 10, 100, 8_000, 8_000);
    assert_eq!(
      ResourceFeedbackPolicy::new(config(
        control(1, 10, 100, 4_000, 8_000),
        bad_band,
        control(1, 10, 100, 4_000, 8_000),
      ))
      .err(),
      Some(PolicyError::InvalidConfiguration(
        PolicyConfigError::InvalidHysteresis(FeedbackResource::DiskRate)
      ))
    );
  }

  #[test]
  fn invalid_utilization_and_bad_timestamps_do_not_consume_a_sample() {
    let mut policy = ResourceFeedbackPolicy::new(standard_config()).unwrap();
    let base = Instant::now();
    assert_eq!(
      observe_at(
        &mut policy,
        base + Duration::from_millis(1),
        base,
        Some(5_000),
        Some(5_000),
        Some(5_000),
      ),
      Err(PolicyError::Timestamp(TimestampError::Future))
    );

    observe_at(
      &mut policy,
      base,
      base + Duration::from_millis(1),
      Some(5_000),
      Some(5_000),
      Some(5_000),
    )
    .unwrap();
    let next = base + Duration::from_millis(100);
    assert_eq!(
      observe_at(
        &mut policy,
        next,
        next + Duration::from_millis(1),
        Some(10_001),
        Some(5_000),
        Some(5_000),
      ),
      Err(PolicyError::InvalidUtilization {
        resource: FeedbackResource::CpuConcurrency,
        value: 10_001,
      })
    );
    observe_at(
      &mut policy,
      next,
      next + Duration::from_millis(2),
      Some(5_000),
      Some(5_000),
      Some(5_000),
    )
    .unwrap();
    assert_eq!(
      observe_at(
        &mut policy,
        next,
        next + Duration::from_millis(3),
        Some(5_000),
        Some(5_000),
        Some(5_000),
      ),
      Err(PolicyError::Timestamp(TimestampError::Duplicate))
    );
    assert_eq!(
      observe_at(
        &mut policy,
        base + Duration::from_millis(50),
        next + Duration::from_millis(4),
        Some(5_000),
        Some(5_000),
        Some(5_000),
      ),
      Err(PolicyError::Timestamp(TimestampError::OutOfOrder))
    );
    assert_eq!(
      observe_at(
        &mut policy,
        next + Duration::from_millis(50),
        next + Duration::from_millis(60),
        Some(5_000),
        Some(5_000),
        Some(5_000),
      ),
      Err(PolicyError::SampleTooSoon {
        elapsed: Duration::from_millis(50),
      })
    );
  }

  #[test]
  fn plan_timestamps_must_advance_strictly() {
    let mut policy = ResourceFeedbackPolicy::new(standard_config()).unwrap();
    let base = Instant::now();
    policy.plan_at(base).unwrap();
    assert_eq!(
      policy.plan_at(base),
      Err(PolicyError::Timestamp(TimestampError::Duplicate))
    );
    assert_eq!(
      policy.plan_at(base - Duration::from_millis(1)),
      Err(PolicyError::Timestamp(TimestampError::OutOfOrder))
    );
  }

  #[test]
  fn missing_sparse_and_stale_telemetry_freeze_each_control_independently() {
    let mut policy = ResourceFeedbackPolicy::new(standard_config()).unwrap();
    let base = Instant::now();
    observe_at(
      &mut policy,
      base,
      base + Duration::from_millis(1),
      Some(7_000),
      Some(7_000),
      Some(7_000),
    )
    .unwrap();
    let first = policy.plan_at(base + Duration::from_millis(2)).unwrap();
    assert_eq!(first.cpu_concurrency.telemetry, TelemetryStatus::Fresh);

    let second_at = base + Duration::from_millis(100);
    observe_at(
      &mut policy,
      second_at,
      second_at + Duration::from_millis(1),
      Some(7_000),
      None,
      Some(7_000),
    )
    .unwrap();
    let second = policy
      .plan_at(second_at + Duration::from_millis(2))
      .unwrap();
    assert_eq!(second.disk_rate.telemetry, TelemetryStatus::Missing);
    assert_eq!(second.cpu_concurrency.telemetry, TelemetryStatus::Fresh);
    assert_eq!(
      status(second, FeedbackResource::DiskRate),
      DecisionStatus::NoChange(NoChangeReason::TelemetryUnavailable)
    );

    let third_at = base + Duration::from_millis(250);
    observe_at(
      &mut policy,
      third_at,
      third_at + Duration::from_millis(1),
      Some(7_000),
      Some(7_000),
      Some(7_000),
    )
    .unwrap();
    let third = policy.plan_at(third_at + Duration::from_millis(2)).unwrap();
    assert_eq!(third.disk_rate.telemetry, TelemetryStatus::Sparse);
    assert_eq!(third.network_rate.telemetry, TelemetryStatus::Fresh);

    let stale = policy.plan_at(base + Duration::from_millis(801)).unwrap();
    assert_eq!(stale.cpu_concurrency.telemetry, TelemetryStatus::Stale);
    assert_eq!(stale.disk_rate.telemetry, TelemetryStatus::Stale);
    assert_eq!(stale.network_rate.telemetry, TelemetryStatus::Stale);
  }

  #[test]
  fn one_delayed_sample_is_jitter_but_a_longer_gap_is_sparse() {
    let mut policy = ResourceFeedbackPolicy::new(standard_config()).unwrap();
    let base = Instant::now();
    observe_at(
      &mut policy,
      base,
      base + Duration::from_millis(1),
      Some(9_000),
      Some(7_000),
      Some(7_000),
    )
    .unwrap();
    let jittered_at = base + Duration::from_millis(100) + Duration::from_nanos(1);
    observe_at(
      &mut policy,
      jittered_at,
      jittered_at + Duration::from_millis(1),
      Some(9_000),
      Some(7_000),
      Some(7_000),
    )
    .unwrap();
    let jittered = policy
      .plan_at(jittered_at + Duration::from_millis(2))
      .unwrap();
    assert_eq!(jittered.cpu_concurrency.telemetry, TelemetryStatus::Fresh);
    assert_eq!(
      status(jittered, FeedbackResource::CpuConcurrency),
      DecisionStatus::NoChange(NoChangeReason::BreachSamplesRemaining {
        observed: 2,
        required: REQUIRED_BREACH_SAMPLES,
      })
    );

    let missed_at = jittered_at + Duration::from_millis(250);
    observe_at(
      &mut policy,
      missed_at,
      missed_at + Duration::from_millis(1),
      Some(9_000),
      Some(7_000),
      Some(7_000),
    )
    .unwrap();
    let missed = policy
      .plan_at(missed_at + Duration::from_millis(2))
      .unwrap();
    assert_eq!(missed.cpu_concurrency.telemetry, TelemetryStatus::Sparse);
    assert_eq!(
      status(missed, FeedbackResource::CpuConcurrency),
      DecisionStatus::NoChange(NoChangeReason::TelemetryUnavailable)
    );
  }

  #[test]
  fn delayed_measurement_after_a_plan_is_ordered_by_sample_time() {
    let mut policy = ResourceFeedbackPolicy::new(standard_config()).unwrap();
    let base = Instant::now();
    observe_at(
      &mut policy,
      base,
      base + Duration::from_millis(1),
      Some(9_000),
      Some(7_000),
      Some(7_000),
    )
    .unwrap();
    let plan_at = base + Duration::from_millis(101);
    assert_eq!(
      policy.plan_at(plan_at).unwrap().cpu_concurrency.telemetry,
      TelemetryStatus::Fresh
    );

    let measured_at = base + Duration::from_millis(100);
    let delivered_at = base + Duration::from_millis(102);
    observe_at(
      &mut policy,
      measured_at,
      delivered_at,
      Some(9_000),
      Some(7_000),
      Some(7_000),
    )
    .unwrap();
    let after_delivery = policy.plan_at(base + Duration::from_millis(103)).unwrap();
    assert_eq!(
      after_delivery.cpu_concurrency.telemetry,
      TelemetryStatus::Fresh
    );
    assert_eq!(
      status(after_delivery, FeedbackResource::CpuConcurrency),
      DecisionStatus::NoChange(NoChangeReason::BreachSamplesRemaining {
        observed: 2,
        required: REQUIRED_BREACH_SAMPLES,
      })
    );
  }

  #[test]
  fn reconciliation_rejects_pre_readback_samples_and_starts_safety_cooldown() {
    let mut policy = ResourceFeedbackPolicy::new(standard_config()).unwrap();
    let base = Instant::now();
    observe_at(
      &mut policy,
      base,
      base + Duration::from_millis(1),
      Some(7_000),
      Some(3_000),
      Some(7_000),
    )
    .unwrap();
    let plan = policy.plan_at(base + Duration::from_millis(2)).unwrap();
    let ticket = match status(plan, FeedbackResource::DiskRate) {
      DecisionStatus::Planned(ticket) => ticket,
      other => panic!("expected a disk recovery plan, found {other:?}"),
    };
    assert_eq!(ticket.to_limit(), 110);

    let failed_at = base + Duration::from_millis(3);
    policy
      .acknowledge_at(
        ticket,
        ActuationResult::Failed,
        failed_at,
        failed_at + Duration::from_millis(1),
      )
      .unwrap();
    let reconciled_at = base + Duration::from_millis(250);
    policy
      .reconcile_at(FeedbackResource::DiskRate, 110, reconciled_at)
      .unwrap();
    assert_eq!(policy.current_limits()[1], 110);

    // This sample is newer than the prior sample but was measured before the
    // readback. It must not restore telemetry for the reconciled control.
    let delayed_at = base + Duration::from_millis(100);
    observe_at(
      &mut policy,
      delayed_at,
      base + Duration::from_millis(251),
      Some(7_000),
      Some(3_000),
      Some(7_000),
    )
    .unwrap();
    let delayed = policy.plan_at(base + Duration::from_millis(252)).unwrap();
    assert_eq!(delayed.disk_rate.telemetry, TelemetryStatus::Missing);

    let first_fresh_at = base + Duration::from_millis(300);
    observe_at(
      &mut policy,
      first_fresh_at,
      base + Duration::from_millis(301),
      Some(7_000),
      Some(3_000),
      Some(7_000),
    )
    .unwrap();
    let sparse = policy.plan_at(base + Duration::from_millis(302)).unwrap();
    assert_eq!(sparse.disk_rate.telemetry, TelemetryStatus::Sparse);

    let fresh_at = base + Duration::from_millis(400);
    observe_at(
      &mut policy,
      fresh_at,
      base + Duration::from_millis(401),
      Some(7_000),
      Some(3_000),
      Some(7_000),
    )
    .unwrap();
    let cooling = policy.plan_at(base + Duration::from_millis(402)).unwrap();
    assert_eq!(cooling.disk_rate.telemetry, TelemetryStatus::Fresh);
    assert_eq!(
      status(cooling, FeedbackResource::DiskRate),
      DecisionStatus::NoChange(NoChangeReason::CoolingDown {
        remaining: Duration::from_millis(848),
      })
    );
  }

  #[test]
  fn three_breaches_make_one_pending_ticket_and_success_starts_actual_cooldown() {
    let mut policy = ResourceFeedbackPolicy::new(standard_config()).unwrap();
    let base = Instant::now();
    let mut third_plan = None;
    for index in 0..REQUIRED_BREACH_SAMPLES {
      let sample_at = base + Duration::from_millis(u64::from(index) * 100);
      observe_at(
        &mut policy,
        sample_at,
        sample_at + Duration::from_millis(1),
        Some(9_000),
        Some(7_000),
        Some(7_000),
      )
      .unwrap();
      let plan = policy
        .plan_at(sample_at + Duration::from_millis(2))
        .unwrap();
      if index < REQUIRED_BREACH_SAMPLES - 1 {
        assert!(matches!(
          status(plan, FeedbackResource::CpuConcurrency),
          DecisionStatus::NoChange(NoChangeReason::BreachSamplesRemaining { .. })
        ));
      } else {
        third_plan = Some(plan);
      }
    }
    let plan = third_plan.unwrap();
    let ticket = match status(plan, FeedbackResource::CpuConcurrency) {
      DecisionStatus::Planned(ticket) => ticket,
      other => panic!("expected a CPU plan, found {other:?}"),
    };
    assert_eq!(ticket.from_limit(), 100);
    assert_eq!(ticket.to_limit(), 90);
    assert_eq!(policy.current_limits()[0], 100);
    assert_eq!(
      status(
        policy.plan_at(base + Duration::from_millis(205)).unwrap(),
        FeedbackResource::CpuConcurrency
      ),
      DecisionStatus::NoChange(NoChangeReason::PlanPending)
    );

    for index in 3_u64..5 {
      let sample_at = base + Duration::from_millis(index * 100);
      observe_at(
        &mut policy,
        sample_at,
        sample_at + Duration::from_millis(1),
        Some(9_000),
        Some(7_000),
        Some(7_000),
      )
      .unwrap();
      let pending = policy
        .plan_at(sample_at + Duration::from_millis(2))
        .unwrap();
      assert_eq!(
        status(pending, FeedbackResource::CpuConcurrency),
        DecisionStatus::NoChange(NoChangeReason::PlanPending)
      );
    }

    let actual_at = base + Duration::from_millis(450);
    policy
      .acknowledge_at(
        ticket,
        ActuationResult::Applied,
        actual_at,
        actual_at + Duration::from_millis(1),
      )
      .unwrap();
    assert_eq!(policy.current_limits()[0], 90);
    assert_eq!(
      policy.acknowledge_at(
        ticket,
        ActuationResult::Applied,
        actual_at + Duration::from_millis(2),
        actual_at + Duration::from_millis(3),
      ),
      Err(PolicyError::NoPendingTicket)
    );

    let sample_at = base + Duration::from_millis(500);
    observe_at(
      &mut policy,
      sample_at,
      sample_at + Duration::from_millis(1),
      Some(9_000),
      Some(7_000),
      Some(7_000),
    )
    .unwrap();
    let cooldown = policy
      .plan_at(sample_at + Duration::from_millis(2))
      .unwrap();
    match status(cooldown, FeedbackResource::CpuConcurrency) {
      DecisionStatus::NoChange(NoChangeReason::CoolingDown { remaining }) => {
        assert_eq!(remaining, Duration::from_millis(948));
      }
      other => panic!("expected cooldown from actual actuation, found {other:?}"),
    }
  }

  #[test]
  fn cpu_reduction_and_small_rate_recovery_report_quantization() {
    let mut policy = ResourceFeedbackPolicy::new(config(
      control(1, 9, 20, 4_000, 8_000),
      control(1, 50, 100, 4_000, 8_000),
      control(1, 50, 99, 4_000, 8_000),
    ))
    .unwrap();
    let base = Instant::now();
    let mut last = None;
    for index in 0..REQUIRED_BREACH_SAMPLES {
      let at = base + Duration::from_millis(u64::from(index) * 100);
      observe_at(
        &mut policy,
        at,
        at + Duration::from_millis(1),
        Some(9_000),
        Some(7_000),
        Some(3_000),
      )
      .unwrap();
      last = Some(policy.plan_at(at + Duration::from_millis(2)).unwrap());
    }
    let plan = last.unwrap();
    assert_eq!(
      status(plan, FeedbackResource::CpuConcurrency),
      DecisionStatus::NoChange(NoChangeReason::ReductionQuantized)
    );
    assert_eq!(
      status(plan, FeedbackResource::NetworkRate),
      DecisionStatus::NoChange(NoChangeReason::RecoveryQuantized)
    );
  }

  #[test]
  fn cpu_reduction_is_quantized_below_ten_and_respects_its_floor() {
    for initial in [2, 4, 1] {
      let mut policy = ResourceFeedbackPolicy::new(config(
        control(1, initial, 4, 4_000, 8_000),
        control(1, 100, 100, 4_000, 8_000),
        control(1, 100, 100, 4_000, 8_000),
      ))
      .unwrap();
      let base = Instant::now();
      let mut plan = None;
      for index in 0..REQUIRED_BREACH_SAMPLES {
        let at = base + Duration::from_millis(u64::from(index) * 100);
        observe_at(
          &mut policy,
          at,
          at + Duration::from_millis(1),
          Some(9_000),
          Some(7_000),
          Some(7_000),
        )
        .unwrap();
        plan = Some(policy.plan_at(at + Duration::from_millis(2)).unwrap());
      }
      assert_eq!(
        status(plan.unwrap(), FeedbackResource::CpuConcurrency),
        DecisionStatus::NoChange(NoChangeReason::ReductionQuantized)
      );
    }
  }

  #[test]
  fn cpu_reduction_at_ten_slots_is_exactly_ten_percent() {
    let mut policy = ResourceFeedbackPolicy::new(config(
      control(1, 10, 10, 4_000, 8_000),
      control(1, 100, 100, 4_000, 8_000),
      control(1, 100, 100, 4_000, 8_000),
    ))
    .unwrap();
    let base = Instant::now();
    let mut plan = None;
    for index in 0..REQUIRED_BREACH_SAMPLES {
      let at = base + Duration::from_millis(u64::from(index) * 100);
      observe_at(
        &mut policy,
        at,
        at + Duration::from_millis(1),
        Some(9_000),
        Some(7_000),
        Some(7_000),
      )
      .unwrap();
      plan = Some(policy.plan_at(at + Duration::from_millis(2)).unwrap());
    }
    let ticket = match status(plan.unwrap(), FeedbackResource::CpuConcurrency) {
      DecisionStatus::Planned(ticket) => ticket,
      other => panic!("expected the exact 10-percent CPU reduction, found {other:?}"),
    };
    assert_eq!((ticket.from_limit(), ticket.to_limit()), (10, 9));
  }

  #[test]
  fn cpu_recovers_one_slot_after_cooldown_without_crossing_its_ceiling() {
    let mut policy = ResourceFeedbackPolicy::new(config(
      control(1, 1, 4, 4_000, 8_000),
      control(1, 100, 100, 4_000, 8_000),
      control(1, 100, 100, 4_000, 8_000),
    ))
    .unwrap();
    let base = Instant::now();
    observe_at(
      &mut policy,
      base,
      base + Duration::from_millis(1),
      Some(1_000),
      Some(5_000),
      Some(5_000),
    )
    .unwrap();
    let recovery = policy.plan_at(base + Duration::from_millis(2)).unwrap();
    let ticket = match status(recovery, FeedbackResource::CpuConcurrency) {
      DecisionStatus::Planned(ticket) => ticket,
      other => panic!("expected one-slot CPU recovery, found {other:?}"),
    };
    assert_eq!(ticket.from_limit(), 1);
    assert_eq!(ticket.to_limit(), 2);
    policy
      .acknowledge_at(
        ticket,
        ActuationResult::Applied,
        base + Duration::from_millis(3),
        base + Duration::from_millis(4),
      )
      .unwrap();
    assert_eq!(policy.current_limits()[0], 2);

    let mut next = None;
    for index in 1..=12_u64 {
      let at = base + Duration::from_millis(index * 100);
      observe_at(
        &mut policy,
        at,
        at + Duration::from_millis(1),
        Some(1_000),
        Some(5_000),
        Some(5_000),
      )
      .unwrap();
      let plan = policy.plan_at(at + Duration::from_millis(2)).unwrap();
      let status = status(plan, FeedbackResource::CpuConcurrency);
      if matches!(status, DecisionStatus::Planned(_)) {
        next = Some(status);
        break;
      }
    }
    let cpu_status = next.unwrap_or_else(|| panic!("CPU never recovered after cooldown"));
    assert!(
      matches!(
        cpu_status,
        DecisionStatus::Planned(ticket) if ticket.from_limit() == 2 && ticket.to_limit() == 3
      ),
      "unexpected CPU recovery at the ceiling: {cpu_status:?}"
    );
  }

  #[test]
  fn cpu_recovery_holds_at_the_configured_ceiling() {
    let mut policy = ResourceFeedbackPolicy::new(config(
      control(1, 4, 4, 4_000, 8_000),
      control(1, 100, 100, 4_000, 8_000),
      control(1, 100, 100, 4_000, 8_000),
    ))
    .unwrap();
    let at = Instant::now();
    observe_at(
      &mut policy,
      at,
      at + Duration::from_millis(1),
      Some(1_000),
      Some(5_000),
      Some(5_000),
    )
    .unwrap();
    let plan = policy.plan_at(at + Duration::from_millis(2)).unwrap();
    assert_eq!(
      status(plan, FeedbackResource::CpuConcurrency),
      DecisionStatus::NoChange(NoChangeReason::AtCeiling)
    );
  }

  #[test]
  fn failed_actuation_latches_until_bounded_readback_reconciliation() {
    let mut policy = ResourceFeedbackPolicy::new(standard_config()).unwrap();
    let base = Instant::now();
    let mut ticket = None;
    for index in 0..REQUIRED_BREACH_SAMPLES {
      let at = base + Duration::from_millis(u64::from(index) * 100);
      observe_at(
        &mut policy,
        at,
        at + Duration::from_millis(1),
        Some(9_000),
        Some(7_000),
        Some(7_000),
      )
      .unwrap();
      let plan = policy.plan_at(at + Duration::from_millis(2)).unwrap();
      if let DecisionStatus::Planned(value) = status(plan, FeedbackResource::CpuConcurrency) {
        ticket = Some(value);
      }
    }
    let ticket = ticket.unwrap();
    let failed_at = base + Duration::from_millis(205);
    policy
      .acknowledge_at(
        ticket,
        ActuationResult::Failed,
        failed_at,
        failed_at + Duration::from_millis(1),
      )
      .unwrap();
    assert_eq!(policy.current_limits()[0], 100);
    assert_eq!(policy.faults(), [true, false, false]);

    let blocked_at = failed_at + Duration::from_millis(2);
    let blocked = policy.plan_at(blocked_at).unwrap();
    assert_eq!(
      status(blocked, FeedbackResource::CpuConcurrency),
      DecisionStatus::NoChange(NoChangeReason::ActuationFaultLatched)
    );
    assert_eq!(
      policy.reconcile_at(
        FeedbackResource::CpuConcurrency,
        1_001,
        blocked_at + Duration::from_millis(1),
      ),
      Err(PolicyError::ReconciledLimitOutOfBounds {
        actual: 1_001,
        floor: 10,
        ceiling: 1_000,
      })
    );
    policy
      .reconcile_at(
        FeedbackResource::CpuConcurrency,
        90,
        blocked_at + Duration::from_millis(2),
      )
      .unwrap();
    assert_eq!(policy.current_limits()[0], 90);
    assert_eq!(policy.faults(), [false, false, false]);
    let fresh_required = policy
      .plan_at(blocked_at + Duration::from_millis(3))
      .unwrap();
    assert_eq!(
      fresh_required.cpu_concurrency.telemetry,
      TelemetryStatus::Missing
    );
  }

  #[test]
  fn acknowledgement_rejects_future_time_and_faults_ambiguous_attempt() {
    let mut policy = ResourceFeedbackPolicy::new(standard_config()).unwrap();
    let base = Instant::now();
    let mut ticket = None;
    for index in 0..REQUIRED_BREACH_SAMPLES {
      let at = base + Duration::from_millis(u64::from(index) * 100);
      observe_at(
        &mut policy,
        at,
        at + Duration::from_millis(1),
        Some(9_000),
        Some(7_000),
        Some(7_000),
      )
      .unwrap();
      let plan = policy.plan_at(at + Duration::from_millis(2)).unwrap();
      if let DecisionStatus::Planned(value) = status(plan, FeedbackResource::CpuConcurrency) {
        ticket = Some(value);
      }
    }
    let ticket = ticket.unwrap();
    let receipt_at = base + Duration::from_millis(203);
    assert_eq!(
      policy.acknowledge_at(
        ticket,
        ActuationResult::Applied,
        receipt_at + Duration::from_millis(1),
        receipt_at,
      ),
      Err(PolicyError::Timestamp(TimestampError::Future))
    );
    assert_eq!(policy.pending_tickets()[0], None);
    assert!(policy.faults()[0]);
    assert_eq!(policy.current_limits()[0], 100);
  }
}
