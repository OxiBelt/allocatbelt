//! Opt-in autonomous sampling and actuation for resource feedback.
//!
//! [`ResourceFeedbackService::start`] validates all policy limits and actuator
//! readbacks before it starts a worker. The worker samples on real monotonic
//! 100 ms deadlines and uses the fixed-storage [`super::resource_feedback_policy`]
//! engine to plan CPU concurrency, disk-rate, and network-rate changes. This
//! service is off until explicitly constructed; it does not alter any default
//! runtime configuration. An opted-in service starts one sampler and one
//! bounded join-monitor thread so shutdown polling never joins on the caller.
//! Policy and metrics use fixed-size storage and the join handoff has capacity
//! one, but this service does not currently charge those allocations or its
//! thread stacks to `ResourceDomain::Control`.
//!
//! Sensor and actuator callbacks run outside the snapshot lock and are
//! panic-contained. A ticket is applied only after a readback confirms its
//! expected old limit. Every attempted write is followed by a readback, even
//! when stop was requested during the callback. A failed or ambiguous result
//! latches that control until the owner explicitly requests reconciliation.
//! Dropping the owner requests stop and detaches a live join monitor; the
//! monitor retains the sampler handle, and the sampler retains its policy,
//! sensor, actuator, and shared state until callbacks and cleanup finish.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::any::Any;
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::resource_feedback_policy::{
  ActuationResult, DecisionStatus, FeedbackResource, FeedbackSample, NoChangeReason, PlanTicket,
  PolicyError, PolicyPlan, ResourceFeedbackPolicy, ResourceFeedbackPolicyConfig, SAMPLE_INTERVAL,
  TelemetryStatus,
};

const RESOURCE_COUNT: usize = 3;
const RESOURCES: [FeedbackResource; RESOURCE_COUNT] = [
  FeedbackResource::CpuConcurrency,
  FeedbackResource::DiskRate,
  FeedbackResource::NetworkRate,
];
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// Why a sensor could not produce one complete sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FeedbackSensorError {
  /// The sensor is temporarily unavailable.
  Unavailable,
  /// A source read failed.
  ReadFailed,
  /// The source no longer supports this metric set.
  Unsupported,
}

/// Caller-provided telemetry source used by the worker thread.
pub trait FeedbackSensor: Send + 'static {
  /// Reads one sample with its measurement time from the real monotonic clock.
  fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError>;
}

/// Why an actuator operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FeedbackActuatorError {
  /// The control is temporarily unavailable.
  Unavailable,
  /// The current process lacks permission for the operation.
  PermissionDenied,
  /// The actuator could not complete the operation.
  OperationFailed,
}

/// Actuator for the three configured feedback controls.
pub trait FeedbackActuator: Send + 'static {
  /// Reads the actual current limit for one control.
  fn readback(&mut self, resource: FeedbackResource) -> Result<u64, FeedbackActuatorError>;

  /// Attempts one already-planned limit change.
  fn apply(&mut self, ticket: PlanTicket) -> Result<(), FeedbackActuatorError>;
}

/// Which actuator callback produced a diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackActuatorPhase {
  /// Readback before applying a ticket.
  PreApplyReadback,
  /// The limit-change callback.
  Apply,
  /// Mandatory readback after an attempted write.
  PostApplyReadback,
  /// Explicit owner-requested reconciliation readback.
  ReconcileReadback,
}

/// Bounded, typed diagnostic retained in the metrics snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FeedbackDiagnostic {
  /// Sensor returned an error; required telemetry is frozen until it recovers.
  SensorFailed(FeedbackSensorError),
  /// Sensor panicked; the worker caught the panic and continues sampling.
  SensorPanicked,
  /// A sample failed policy validation.
  SampleRejected(PolicyError),
  /// A planning, acknowledgement, or reconciliation operation failed.
  PolicyOperationRejected(PolicyError),
  /// Policy planning failed.
  PlanRejected(PolicyError),
  /// The most recent plan could not use telemetry for this control.
  TelemetryUnavailable(TelemetryStatus),
  /// Actuator returned a typed error during the named phase.
  ActuatorFailed {
    /// Callback phase.
    phase: FeedbackActuatorPhase,
    /// Fixed actuator error category.
    error: FeedbackActuatorError,
  },
  /// Actuator panicked during the named phase.
  ActuatorPanicked(FeedbackActuatorPhase),
  /// Pre-apply readback drifted from the ticket's expected starting limit.
  ExternalDrift {
    /// Limit required by the ticket.
    expected: u64,
    /// Actual limit read before the write.
    actual: u64,
  },
  /// Post-apply readback did not equal the requested target.
  ReadbackMismatch {
    /// Requested ticket limit.
    expected: u64,
    /// Actual post-apply limit.
    actual: u64,
  },
  /// Explicit readback did not satisfy policy reconciliation.
  ReconciliationRejected(PolicyError),
  /// Worker-owned code panicked outside a contained sensor or actuator call.
  WorkerPanicked,
  /// The monotonic deadline could not be represented by `Instant`.
  ClockExhausted,
  /// A worker-owned callback payload destructor panicked during containment.
  PayloadCleanupPanicked,
}

/// Fixed per-control metrics and diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeedbackControlMetrics {
  /// Control represented by this entry.
  pub resource: FeedbackResource,
  /// Last limit confirmed by an applied ticket or explicit readback.
  pub current_limit: u64,
  /// Latest usable utilization, if any.
  pub utilization_basis_points: Option<u16>,
  /// Current telemetry quality reported by the policy.
  pub telemetry: TelemetryStatus,
  /// Latest policy decision diagnostic, if a new ticket was not planned.
  pub no_change: Option<NoChangeReason>,
  /// Pending ticket generation, if the worker still owns a ticket.
  pub pending_generation: Option<u64>,
  /// Whether policy has latched this control pending explicit reconciliation.
  pub policy_faulted: bool,
  /// Most recent diagnostic retained for this control.
  pub last_diagnostic: Option<FeedbackDiagnostic>,
}

impl FeedbackControlMetrics {
  const fn new(resource: FeedbackResource, current_limit: u64) -> Self {
    Self {
      resource,
      current_limit,
      utilization_basis_points: None,
      telemetry: TelemetryStatus::Missing,
      no_change: Some(NoChangeReason::TelemetryUnavailable),
      pending_generation: None,
      policy_faulted: false,
      last_diagnostic: None,
    }
  }
}

/// Worker failure that remains visible after service shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackWorkerFailure {
  /// The worker's internal loop panicked outside a contained callback.
  Panicked,
  /// The worker could not schedule a representable future monotonic deadline.
  ClockExhausted,
  /// A retained sensor or actuator destructor panicked during worker cleanup.
  PayloadCleanupPanicked,
}

/// Fixed-size snapshot; retrieving it never allocates or invokes user code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeedbackMetricsSnapshot {
  /// Time at which the service was constructed.
  pub started_at: Instant,
  /// Measurement time of the last accepted sample.
  pub last_sample_at: Option<Instant>,
  /// Time of the last policy plan.
  pub last_plan_at: Option<Instant>,
  /// Accepted sample count, saturating at `u64::MAX`.
  pub sample_count: u64,
  /// Whether stop has been requested.
  pub stop_requested: bool,
  /// Whether the sampler thread, including thread-local destructors, was joined.
  /// The service owner may still need to collect a typed shutdown failure.
  pub shutdown_complete: bool,
  /// One queued explicit reconciliation request, if any.
  pub reconciliation_pending: Option<FeedbackResource>,
  /// Reconciliation currently running outside the state lock, if any.
  pub reconciliation_in_flight: Option<FeedbackResource>,
  /// Worker failure, if the worker stopped abnormally.
  pub worker_failure: Option<FeedbackWorkerFailure>,
  /// Latest service-wide diagnostic.
  pub last_diagnostic: Option<FeedbackDiagnostic>,
  /// CPU, disk, and network snapshots in that order.
  pub controls: [FeedbackControlMetrics; RESOURCE_COUNT],
}

impl FeedbackMetricsSnapshot {
  fn new(started_at: Instant, limits: [u64; RESOURCE_COUNT]) -> Self {
    Self {
      started_at,
      last_sample_at: None,
      last_plan_at: None,
      sample_count: 0,
      stop_requested: false,
      shutdown_complete: false,
      reconciliation_pending: None,
      reconciliation_in_flight: None,
      worker_failure: None,
      last_diagnostic: None,
      controls: [
        FeedbackControlMetrics::new(RESOURCES[0], limits[0]),
        FeedbackControlMetrics::new(RESOURCES[1], limits[1]),
        FeedbackControlMetrics::new(RESOURCES[2], limits[2]),
      ],
    }
  }

  /// Returns one per-control entry without allocating.
  pub const fn control(self, resource: FeedbackResource) -> FeedbackControlMetrics {
    self.controls[resource as usize]
  }
}

struct SharedState {
  stop_requested: bool,
  reconciliation_pending: Option<FeedbackResource>,
  reconciliation_in_flight: Option<FeedbackResource>,
  worker_joined: bool,
  worker_join_panicked: bool,
  worker_panic_payload: Option<Box<dyn Any + Send>>,
  owner_attached: bool,
  metrics: FeedbackMetricsSnapshot,
}

struct Shared {
  state: Mutex<SharedState>,
  wakeup: Condvar,
}

impl Drop for Shared {
  fn drop(&mut self) {
    let payload = self
      .state
      .get_mut()
      .unwrap_or_else(PoisonError::into_inner)
      .worker_panic_payload
      .take();
    if let Some(payload) = payload {
      discard_worker_payload(payload);
    }
  }
}

enum JoinCommand {
  Worker(JoinHandle<()>),
  Stop,
}

fn lock_state(shared: &Shared) -> MutexGuard<'_, SharedState> {
  shared.state.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Cloneable read-only view of fixed service metrics.
#[derive(Clone)]
pub struct FeedbackMetricsHandle {
  shared: Arc<Shared>,
}

impl FeedbackMetricsHandle {
  /// Takes a coherent, fixed-size snapshot.
  #[must_use]
  pub fn snapshot(&self) -> FeedbackMetricsSnapshot {
    lock_state(&self.shared).metrics
  }
}

impl fmt::Debug for FeedbackMetricsHandle {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_tuple("FeedbackMetricsHandle")
      .field(&self.snapshot())
      .finish()
  }
}

/// Construction-time failure before the autonomous worker is started.
#[derive(Debug)]
#[non_exhaustive]
pub enum FeedbackStartError {
  /// Policy thresholds or bounds were invalid.
  Policy(PolicyError),
  /// Startup actuator readback failed.
  InitialReadback {
    /// Control being validated.
    resource: FeedbackResource,
    /// Typed actuator error.
    error: FeedbackActuatorError,
  },
  /// Startup actuator readback panicked.
  InitialReadbackPanicked(FeedbackResource),
  /// Actual startup limit differed from the configured initial limit.
  InitialLimitMismatch {
    /// Control being validated.
    resource: FeedbackResource,
    /// Configured initial limit.
    expected: u64,
    /// Actual limit returned by the actuator.
    actual: u64,
  },
  /// OS thread creation failed.
  ThreadSpawn(std::io::Error),
}

impl fmt::Display for FeedbackStartError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "resource feedback service could not start: {self:?}")
  }
}

impl std::error::Error for FeedbackStartError {}

/// Why an explicit reconciliation request was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileRequestError {
  /// The selected control has no latched actuator fault.
  NotFaulted,
  /// One bounded reconciliation is already queued or running.
  Busy,
  /// Stop has begun or the worker has exited.
  Stopping,
}

impl fmt::Display for ReconcileRequestError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::NotFaulted => "resource feedback control is not faulted",
      Self::Busy => "resource feedback reconciliation slot is busy",
      Self::Stopping => "resource feedback service is stopping",
    })
  }
}

impl std::error::Error for ReconcileRequestError {}

/// Nonblocking progress reported by [`ResourceFeedbackService::try_shutdown`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackShutdownProgress {
  /// A callback, callback-payload destructor, or worker cleanup is still running.
  Pending,
  /// Worker cleanup finished and the worker handle has been joined.
  Complete,
}

/// Sticky failure reported after the worker terminates abnormally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackShutdownError {
  /// A worker panic or panic outside a contained sensor/actuator callback.
  WorkerPanicked,
  /// The worker stopped because its monotonic deadline could not be represented.
  ClockExhausted,
  /// A retained worker-owned payload destructor panicked.
  PayloadCleanupPanicked,
}

impl fmt::Display for FeedbackShutdownError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::WorkerPanicked => "resource feedback worker panicked",
      Self::ClockExhausted => "resource feedback monotonic clock exhausted",
      Self::PayloadCleanupPanicked => "resource feedback payload cleanup panicked",
    })
  }
}

impl std::error::Error for FeedbackShutdownError {}

/// Off-by-default autonomous resource sampling and actuation owner.
///
/// An opted-in instance owns a sampler worker and a small join-monitor thread.
/// The monitor joins the sampler away from callers and publishes completion
/// only after that thread has finished its thread-local destructors.
///
/// Startup actuator readbacks are synchronous and may block; this constructor
/// has no startup timeout. Use [`Self::try_shutdown`] to poll actual worker
/// completion without waiting on a live sensor, actuator, or payload cleanup.
pub struct ResourceFeedbackService {
  shared: Arc<Shared>,
  join_monitor: Option<JoinHandle<()>>,
  shutdown_error: Option<FeedbackShutdownError>,
  /// At most one joined panic payload is retained until owner drop.
  panic_payload: Mutex<Option<Box<dyn Any + Send>>>,
}

impl fmt::Debug for ResourceFeedbackService {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ResourceFeedbackService")
      .field("metrics", &self.metrics())
      .field("join_monitor_owned", &self.join_monitor.is_some())
      .field("shutdown_error", &self.shutdown_error)
      .finish()
  }
}

impl ResourceFeedbackService {
  /// Validates the policy and all actual limits before starting either thread.
  ///
  /// All three controls must be configured explicitly. The actuator is read
  /// once for each control and every value must match its configured initial
  /// limit. These startup readbacks run synchronously, outside any service
  /// lock, and may block.
  pub fn start<S, A>(
    config: ResourceFeedbackPolicyConfig,
    sensor: S,
    mut actuator: A,
  ) -> Result<Self, FeedbackStartError>
  where
    S: FeedbackSensor,
    A: FeedbackActuator,
  {
    let policy = ResourceFeedbackPolicy::new(config).map_err(FeedbackStartError::Policy)?;
    let limits = policy.current_limits();
    for resource in RESOURCES {
      let result = panic::catch_unwind(AssertUnwindSafe(|| actuator.readback(resource)));
      let actual = match result {
        Ok(Ok(actual)) => actual,
        Ok(Err(error)) => {
          return Err(FeedbackStartError::InitialReadback { resource, error });
        }
        Err(payload) => {
          discard_worker_payload(payload);
          return Err(FeedbackStartError::InitialReadbackPanicked(resource));
        }
      };
      let expected = limits[resource as usize];
      if actual != expected {
        return Err(FeedbackStartError::InitialLimitMismatch {
          resource,
          expected,
          actual,
        });
      }
    }

    let started_at = Instant::now();
    let metrics = FeedbackMetricsSnapshot::new(started_at, limits);
    let shared = Arc::new(Shared {
      state: Mutex::new(SharedState {
        stop_requested: false,
        reconciliation_pending: None,
        reconciliation_in_flight: None,
        worker_joined: false,
        worker_join_panicked: false,
        worker_panic_payload: None,
        owner_attached: true,
        metrics,
      }),
      wakeup: Condvar::new(),
    });
    let (join_sender, join_receiver) = mpsc::sync_channel(1);
    let monitor_shared = Arc::clone(&shared);
    let join_monitor = thread::Builder::new()
      .name("allocatbelt-feedback-join".to_owned())
      .spawn(move || {
        if let Ok(JoinCommand::Worker(worker)) = join_receiver.recv() {
          publish_worker_join(&monitor_shared, worker.join());
        }
      })
      .map_err(FeedbackStartError::ThreadSpawn)?;
    let worker_shared = Arc::clone(&shared);
    let worker = match thread::Builder::new()
      .name("allocatbelt-resource-feedback".to_owned())
      .spawn(move || {
        let mut policy = policy;
        let mut sensor = sensor;
        let mut actuator = actuator;
        let run = panic::catch_unwind(AssertUnwindSafe(|| {
          run_worker(&worker_shared, &mut policy, &mut sensor, &mut actuator)
        }));
        if let Err(payload) = run {
          discard_worker_payload(payload);
          record_worker_failure(&worker_shared, FeedbackWorkerFailure::Panicked);
        }
        let policy_dropped = drop_worker_value(policy);
        let sensor_dropped = drop_worker_value(sensor);
        let actuator_dropped = drop_worker_value(actuator);
        if !policy_dropped || !sensor_dropped || !actuator_dropped {
          record_worker_failure(
            &worker_shared,
            FeedbackWorkerFailure::PayloadCleanupPanicked,
          );
        }
      }) {
      Ok(worker) => worker,
      Err(error) => {
        let _ = join_sender.send(JoinCommand::Stop);
        if let Err(payload) = join_monitor.join() {
          discard_worker_payload(payload);
        }
        return Err(FeedbackStartError::ThreadSpawn(error));
      }
    };
    if let Err(error) = join_sender.send(JoinCommand::Worker(worker)) {
      let worker = match error.0 {
        JoinCommand::Worker(worker) => worker,
        JoinCommand::Stop => {
          drop(join_monitor);
          return Err(FeedbackStartError::ThreadSpawn(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "feedback join monitor exited before taking worker ownership",
          )));
        }
      };
      {
        let mut state = lock_state(&shared);
        state.stop_requested = true;
        state.metrics.stop_requested = true;
      }
      shared.wakeup.notify_all();
      drop(worker);
      drop(join_monitor);
      return Err(FeedbackStartError::ThreadSpawn(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "feedback join monitor exited before taking worker ownership",
      )));
    }
    Ok(Self {
      shared,
      join_monitor: Some(join_monitor),
      shutdown_error: None,
      panic_payload: Mutex::new(None),
    })
  }

  /// Returns a cloneable metrics handle with no actuator or sensor access.
  #[must_use]
  pub fn metrics_handle(&self) -> FeedbackMetricsHandle {
    FeedbackMetricsHandle {
      shared: Arc::clone(&self.shared),
    }
  }

  /// Takes a coherent fixed-size metrics snapshot.
  #[must_use]
  pub fn metrics(&self) -> FeedbackMetricsSnapshot {
    lock_state(&self.shared).metrics
  }

  /// Requests stop and wakes the worker without joining or waiting on callbacks.
  pub fn request_stop(&self) {
    {
      let mut state = lock_state(&self.shared);
      state.stop_requested = true;
      state.metrics.stop_requested = true;
    }
    self.shared.wakeup.notify_all();
  }

  /// Queues one caller-requested actual-limit readback for a faulted control.
  ///
  /// The readback callback runs on the worker outside the metrics lock. This
  /// method never calls user code and never automatically retries a fault.
  pub fn request_reconcile(&self, resource: FeedbackResource) -> Result<(), ReconcileRequestError> {
    let mut state = lock_state(&self.shared);
    if state.stop_requested || state.metrics.shutdown_complete {
      return Err(ReconcileRequestError::Stopping);
    }
    if !state.metrics.control(resource).policy_faulted {
      return Err(ReconcileRequestError::NotFaulted);
    }
    if state.reconciliation_pending.is_some() || state.reconciliation_in_flight.is_some() {
      return Err(ReconcileRequestError::Busy);
    }
    state.reconciliation_pending = Some(resource);
    state.metrics.reconciliation_pending = Some(resource);
    drop(state);
    self.shared.wakeup.notify_one();
    Ok(())
  }

  /// Requests stop and polls a dedicated join monitor until the sampler and
  /// its thread-local destructors have fully exited.
  ///
  /// A `Pending` return retains the join-monitor handle while that monitor owns
  /// the exact sampler `JoinHandle` and every callback owner. If the sampler
  /// panics, its payload stays in this owner after publication and the typed
  /// failure remains sticky; payload destruction happens only when this owner
  /// is dropped.
  pub fn try_shutdown(&mut self) -> Result<FeedbackShutdownProgress, FeedbackShutdownError> {
    self.request_stop();
    let (worker_joined, worker_panicked, panic_payload) = {
      let mut state = lock_state(&self.shared);
      if !state.worker_joined {
        (false, false, None)
      } else {
        (
          true,
          state.worker_join_panicked,
          state.worker_panic_payload.take(),
        )
      }
    };
    if !worker_joined {
      return Ok(FeedbackShutdownProgress::Pending);
    }
    self.join_monitor.take();
    if worker_panicked {
      let unretained_payload = {
        let mut retained = self
          .panic_payload
          .lock()
          .unwrap_or_else(PoisonError::into_inner);
        match (retained.is_none(), panic_payload) {
          (true, Some(payload)) => {
            *retained = Some(payload);
            None
          }
          (_, payload) => payload,
        }
      };
      if let Some(payload) = unretained_payload {
        discard_worker_payload(payload);
      }
      self.shutdown_error = Some(FeedbackShutdownError::WorkerPanicked);
    }
    if let Some(error) = self.shutdown_error {
      return Err(error);
    }
    if let Some(failure) = self.metrics().worker_failure {
      let error = shutdown_error(failure);
      self.shutdown_error = Some(error);
      return Err(error);
    }
    if !self.metrics().shutdown_complete {
      Ok(FeedbackShutdownProgress::Pending)
    } else {
      Ok(FeedbackShutdownProgress::Complete)
    }
  }

  /// Whether the sampler thread was joined and its result was collected.
  #[must_use]
  pub fn is_shutdown_complete(&self) -> bool {
    self.join_monitor.is_none() && lock_state(&self.shared).worker_joined
  }
}

impl Drop for ResourceFeedbackService {
  fn drop(&mut self) {
    self.request_stop();
    {
      let mut state = lock_state(&self.shared);
      state.owner_attached = false;
      let payload = state.worker_panic_payload.take();
      drop(state);
      if let Some(payload) = payload {
        discard_worker_payload(payload);
      }
    }
    // The join monitor owns the sampler handle, and that worker owns the
    // sensor, actuator, and policy until callbacks and cleanup end.
    drop(self.join_monitor.take());
    // A joined panic payload is bounded to one object. Its destructor may
    // block; contain a destructor panic so it cannot escape this owner Drop.
    let payload = self
      .panic_payload
      .get_mut()
      .unwrap_or_else(PoisonError::into_inner)
      .take();
    if let Some(payload) = payload {
      discard_worker_payload(payload);
    }
  }
}

fn publish_worker_join(shared: &Shared, result: thread::Result<()>) {
  let mut cleanup_payload = None;
  {
    let mut state = lock_state(shared);
    if let Err(payload) = result {
      state.worker_join_panicked = true;
      state.metrics.worker_failure = Some(FeedbackWorkerFailure::Panicked);
      state.metrics.last_diagnostic = Some(FeedbackDiagnostic::WorkerPanicked);
      for control in &mut state.metrics.controls {
        control.last_diagnostic = Some(FeedbackDiagnostic::WorkerPanicked);
      }
      if state.owner_attached {
        state.worker_panic_payload = Some(payload);
      } else {
        cleanup_payload = Some(payload);
      }
    }
    if cleanup_payload.is_none() {
      state.worker_joined = true;
      state.metrics.shutdown_complete = true;
    }
  }
  if let Some(payload) = cleanup_payload {
    // When the service owner has already been dropped, contain arbitrary
    // payload cleanup here before publishing worker completion.
    discard_worker_payload(payload);
    let mut state = lock_state(shared);
    state.worker_joined = true;
    state.metrics.shutdown_complete = true;
  }
  shared.wakeup.notify_all();
}

#[derive(Clone, Copy)]
enum Work {
  Stop,
  Sample,
  Reconcile(FeedbackResource),
}

fn run_worker<S, A>(
  shared: &Shared,
  policy: &mut ResourceFeedbackPolicy,
  sensor: &mut S,
  actuator: &mut A,
) where
  S: FeedbackSensor,
  A: FeedbackActuator,
{
  let Some(mut next_sample) = Instant::now().checked_add(SAMPLE_INTERVAL) else {
    record_worker_failure(shared, FeedbackWorkerFailure::ClockExhausted);
    return;
  };
  let mut last_accepted_sample = None;
  loop {
    let work = wait_for_work(shared, next_sample);
    let accepted_sample = match work {
      Work::Stop => return,
      Work::Sample => run_sample_cycle(shared, policy, sensor, actuator),
      Work::Reconcile(resource) => {
        run_reconciliation(shared, policy, actuator, resource);
        None
      }
    };
    if accepted_sample.is_some() {
      last_accepted_sample = accepted_sample;
    }
    if stop_requested(shared) && !has_pending_reconciliation(shared) {
      return;
    }
    let now = Instant::now();
    let Some(mut deadline) = next_deadline(next_sample, now) else {
      record_worker_failure(shared, FeedbackWorkerFailure::ClockExhausted);
      return;
    };
    if let Some(sample_at) = last_accepted_sample
      && let Some(minimum_next) = sample_at.checked_add(SAMPLE_INTERVAL)
      && deadline < minimum_next
    {
      deadline = minimum_next;
    }
    next_sample = deadline;
  }
}

fn wait_for_work(shared: &Shared, deadline: Instant) -> Work {
  let mut state = lock_state(shared);
  loop {
    if let Some(resource) = state.reconciliation_pending.take() {
      state.reconciliation_in_flight = Some(resource);
      state.metrics.reconciliation_pending = None;
      state.metrics.reconciliation_in_flight = Some(resource);
      return Work::Reconcile(resource);
    }
    if state.stop_requested {
      return Work::Stop;
    }
    let now = Instant::now();
    if now >= deadline {
      return Work::Sample;
    }
    let remaining = deadline.duration_since(now);
    state = match shared.wakeup.wait_timeout(state, remaining) {
      Ok((state, _)) => state,
      Err(poisoned) => poisoned.into_inner().0,
    };
  }
}

fn run_sample_cycle<S, A>(
  shared: &Shared,
  policy: &mut ResourceFeedbackPolicy,
  sensor: &mut S,
  actuator: &mut A,
) -> Option<Instant>
where
  S: FeedbackSensor,
  A: FeedbackActuator,
{
  if stop_requested(shared) {
    return None;
  }
  let sensed = catch_callback(|| sensor.sample());
  let sample = match sensed {
    Ok(Ok(sample)) => sanitize_sample(shared, sample),
    Ok(Err(error)) => {
      record_all_diagnostics(shared, FeedbackDiagnostic::SensorFailed(error));
      missing_sample()
    }
    Err(()) => {
      record_all_diagnostics(shared, FeedbackDiagnostic::SensorPanicked);
      missing_sample()
    }
  };
  if stop_requested(shared) {
    return None;
  }
  let sample_at = sample.at;
  if let Err(error) = policy.observe(sample) {
    record_all_diagnostics(shared, FeedbackDiagnostic::SampleRejected(error));
    return None;
  }
  {
    let mut state = lock_state(shared);
    state.metrics.sample_count = state.metrics.sample_count.saturating_add(1);
    state.metrics.last_sample_at = Some(sample_at);
  }
  let plan = match policy.plan() {
    Ok(plan) => plan,
    Err(error) => {
      record_all_diagnostics(shared, FeedbackDiagnostic::PlanRejected(error));
      return Some(sample_at);
    }
  };
  publish_plan(shared, policy, plan);
  for resource in RESOURCES {
    let decision = plan.decision(resource);
    if let DecisionStatus::Planned(ticket) = decision.status {
      if stop_requested(shared) {
        return Some(sample_at);
      }
      process_ticket(shared, policy, actuator, ticket);
    }
  }
  Some(sample_at)
}

fn sanitize_sample(shared: &Shared, sample: FeedbackSample) -> FeedbackSample {
  let cpu = valid_utilization(
    shared,
    FeedbackResource::CpuConcurrency,
    sample.cpu_utilization_basis_points,
  );
  let disk = valid_utilization(
    shared,
    FeedbackResource::DiskRate,
    sample.disk_utilization_basis_points,
  );
  let network = valid_utilization(
    shared,
    FeedbackResource::NetworkRate,
    sample.network_utilization_basis_points,
  );
  FeedbackSample::new(sample.at, cpu, disk, network)
}

fn valid_utilization(
  shared: &Shared,
  resource: FeedbackResource,
  value: Option<u16>,
) -> Option<u16> {
  if let Some(value) = value
    && value > 10_000
  {
    record_control_diagnostic(
      shared,
      resource,
      FeedbackDiagnostic::SampleRejected(PolicyError::InvalidUtilization { resource, value }),
    );
    None
  } else {
    value
  }
}

fn missing_sample() -> FeedbackSample {
  FeedbackSample::new(Instant::now(), None, None, None)
}

fn publish_plan(shared: &Shared, policy: &ResourceFeedbackPolicy, plan: PolicyPlan) {
  let faults = policy.faults();
  let pending = policy.pending_tickets();
  let mut state = lock_state(shared);
  state.metrics.last_plan_at = Some(plan.at);
  for resource in RESOURCES {
    let index = resource as usize;
    let decision = plan.decision(resource);
    let control = &mut state.metrics.controls[index];
    control.current_limit = decision.current_limit;
    control.utilization_basis_points = decision.utilization_basis_points;
    control.telemetry = decision.telemetry;
    control.policy_faulted = faults[index];
    control.pending_generation = pending[index].map(PlanTicket::generation);
    control.no_change = match decision.status {
      DecisionStatus::Planned(_) => None,
      DecisionStatus::NoChange(reason) => Some(reason),
    };
    if decision.telemetry != TelemetryStatus::Fresh {
      control.last_diagnostic = Some(FeedbackDiagnostic::TelemetryUnavailable(decision.telemetry));
    }
  }
}

fn process_ticket<A: FeedbackActuator>(
  shared: &Shared,
  policy: &mut ResourceFeedbackPolicy,
  actuator: &mut A,
  ticket: PlanTicket,
) {
  let resource = ticket.resource();
  match catch_callback_raw(|| actuator.readback(resource)) {
    CallbackOutcome::Returned(Ok(actual)) if actual == ticket.from_limit() => {}
    CallbackOutcome::Returned(Ok(actual)) => {
      fail_ticket(
        shared,
        policy,
        ticket,
        FeedbackDiagnostic::ExternalDrift {
          expected: ticket.from_limit(),
          actual,
        },
      );
      return;
    }
    CallbackOutcome::Returned(Err(error)) => {
      fail_ticket(
        shared,
        policy,
        ticket,
        FeedbackDiagnostic::ActuatorFailed {
          phase: FeedbackActuatorPhase::PreApplyReadback,
          error,
        },
      );
      return;
    }
    CallbackOutcome::Panicked(payload) => {
      fail_ticket(
        shared,
        policy,
        ticket,
        FeedbackDiagnostic::ActuatorPanicked(FeedbackActuatorPhase::PreApplyReadback),
      );
      discard_worker_payload(payload);
      return;
    }
  }
  if stop_requested(shared) {
    return;
  }

  let applied = catch_callback_raw(|| actuator.apply(ticket));
  // This is captured immediately after the apply callback returns or panics.
  // The mandatory readback may block, but it must not move the cooldown start.
  let applied_at = Instant::now();
  let actual = catch_callback_raw(|| actuator.readback(resource));
  let apply_succeeded = matches!(&applied, CallbackOutcome::Returned(Ok(())));
  let reached_target = matches!(
    &actual,
    CallbackOutcome::Returned(Ok(limit)) if *limit == ticket.to_limit()
  );
  let result = if apply_succeeded && reached_target {
    ActuationResult::Applied
  } else {
    ActuationResult::Failed
  };
  if let Err(error) = policy.acknowledge(ticket, result, applied_at) {
    record_control_diagnostic(
      shared,
      resource,
      FeedbackDiagnostic::PolicyOperationRejected(error),
    );
  }
  sync_policy_control(shared, policy, resource);

  match &applied {
    CallbackOutcome::Panicked(_) => record_control_diagnostic(
      shared,
      resource,
      FeedbackDiagnostic::ActuatorPanicked(FeedbackActuatorPhase::Apply),
    ),
    CallbackOutcome::Returned(Err(error)) => record_control_diagnostic(
      shared,
      resource,
      FeedbackDiagnostic::ActuatorFailed {
        phase: FeedbackActuatorPhase::Apply,
        error: *error,
      },
    ),
    CallbackOutcome::Returned(Ok(())) => {}
  }

  match &actual {
    CallbackOutcome::Returned(Ok(limit)) if *limit == ticket.to_limit() => {}
    CallbackOutcome::Returned(Ok(limit)) => record_control_diagnostic(
      shared,
      resource,
      FeedbackDiagnostic::ReadbackMismatch {
        expected: ticket.to_limit(),
        actual: *limit,
      },
    ),
    CallbackOutcome::Returned(Err(error)) => record_control_diagnostic(
      shared,
      resource,
      FeedbackDiagnostic::ActuatorFailed {
        phase: FeedbackActuatorPhase::PostApplyReadback,
        error: *error,
      },
    ),
    CallbackOutcome::Panicked(_) => record_control_diagnostic(
      shared,
      resource,
      FeedbackDiagnostic::ActuatorPanicked(FeedbackActuatorPhase::PostApplyReadback),
    ),
  }

  // Panic payloads may run user destructors that block. The write result,
  // mandatory readback, policy acknowledgement, and diagnostics are already
  // published before either payload is dropped.
  if let CallbackOutcome::Panicked(payload) = applied {
    discard_worker_payload(payload);
  }
  if let CallbackOutcome::Panicked(payload) = actual {
    discard_worker_payload(payload);
  }
}

fn fail_ticket(
  shared: &Shared,
  policy: &mut ResourceFeedbackPolicy,
  ticket: PlanTicket,
  diagnostic: FeedbackDiagnostic,
) {
  let at = Instant::now();
  if let Err(error) = policy.acknowledge(ticket, ActuationResult::Failed, at) {
    record_control_diagnostic(
      shared,
      ticket.resource(),
      FeedbackDiagnostic::PolicyOperationRejected(error),
    );
  }
  sync_policy_control(shared, policy, ticket.resource());
  record_control_diagnostic(shared, ticket.resource(), diagnostic);
}

fn run_reconciliation<A: FeedbackActuator>(
  shared: &Shared,
  policy: &mut ResourceFeedbackPolicy,
  actuator: &mut A,
  resource: FeedbackResource,
) {
  let result = catch_callback_raw(|| actuator.readback(resource));
  match &result {
    CallbackOutcome::Returned(Ok(actual)) => match policy.reconcile(resource, *actual) {
      Ok(()) => {
        sync_policy_control(shared, policy, resource);
        let mut state = lock_state(shared);
        let control = &mut state.metrics.controls[resource as usize];
        control.telemetry = TelemetryStatus::Missing;
        control.utilization_basis_points = None;
        control.no_change = Some(NoChangeReason::TelemetryUnavailable);
      }
      Err(error) => {
        record_control_diagnostic(
          shared,
          resource,
          FeedbackDiagnostic::ReconciliationRejected(error),
        );
      }
    },
    CallbackOutcome::Returned(Err(error)) => record_control_diagnostic(
      shared,
      resource,
      FeedbackDiagnostic::ActuatorFailed {
        phase: FeedbackActuatorPhase::ReconcileReadback,
        error: *error,
      },
    ),
    CallbackOutcome::Panicked(_) => record_control_diagnostic(
      shared,
      resource,
      FeedbackDiagnostic::ActuatorPanicked(FeedbackActuatorPhase::ReconcileReadback),
    ),
  }
  if let CallbackOutcome::Panicked(payload) = result {
    discard_worker_payload(payload);
  }
  {
    let mut state = lock_state(shared);
    state.reconciliation_in_flight = None;
    state.metrics.reconciliation_in_flight = None;
  }
  shared.wakeup.notify_all();
}

fn sync_policy_control(
  shared: &Shared,
  policy: &ResourceFeedbackPolicy,
  resource: FeedbackResource,
) {
  let index = resource as usize;
  let mut state = lock_state(shared);
  let control = &mut state.metrics.controls[index];
  control.current_limit = policy.current_limits()[index];
  control.pending_generation = policy.pending_tickets()[index].map(PlanTicket::generation);
  control.policy_faulted = policy.faults()[index];
}

fn record_all_diagnostics(shared: &Shared, diagnostic: FeedbackDiagnostic) {
  let mut state = lock_state(shared);
  state.metrics.last_diagnostic = Some(diagnostic);
  for control in &mut state.metrics.controls {
    control.last_diagnostic = Some(diagnostic);
  }
}

fn record_control_diagnostic(
  shared: &Shared,
  resource: FeedbackResource,
  diagnostic: FeedbackDiagnostic,
) {
  let mut state = lock_state(shared);
  state.metrics.last_diagnostic = Some(diagnostic);
  state.metrics.controls[resource as usize].last_diagnostic = Some(diagnostic);
}

fn record_worker_failure(shared: &Shared, failure: FeedbackWorkerFailure) {
  let diagnostic = match failure {
    FeedbackWorkerFailure::Panicked => FeedbackDiagnostic::WorkerPanicked,
    FeedbackWorkerFailure::ClockExhausted => FeedbackDiagnostic::ClockExhausted,
    FeedbackWorkerFailure::PayloadCleanupPanicked => FeedbackDiagnostic::PayloadCleanupPanicked,
  };
  let mut state = lock_state(shared);
  state.metrics.worker_failure = Some(failure);
  state.metrics.last_diagnostic = Some(diagnostic);
  for control in &mut state.metrics.controls {
    control.last_diagnostic = Some(diagnostic);
  }
}

fn stop_requested(shared: &Shared) -> bool {
  lock_state(shared).stop_requested
}

fn has_pending_reconciliation(shared: &Shared) -> bool {
  lock_state(shared).reconciliation_pending.is_some()
}

enum CallbackOutcome<T> {
  Returned(T),
  Panicked(Box<dyn Any + Send>),
}

fn catch_callback_raw<T>(callback: impl FnOnce() -> T) -> CallbackOutcome<T> {
  match panic::catch_unwind(AssertUnwindSafe(callback)) {
    Ok(value) => CallbackOutcome::Returned(value),
    Err(payload) => CallbackOutcome::Panicked(payload),
  }
}

fn catch_callback<T>(callback: impl FnOnce() -> T) -> Result<T, ()> {
  match catch_callback_raw(callback) {
    CallbackOutcome::Returned(value) => Ok(value),
    CallbackOutcome::Panicked(payload) => {
      discard_worker_payload(payload);
      Err(())
    }
  }
}

fn discard_worker_payload(payload: Box<dyn Any + Send>) {
  if let Err(nested) = panic::catch_unwind(AssertUnwindSafe(|| drop(payload))) {
    // The panic payload's destructor panicked too. It cannot safely be dropped
    // again while containing that second panic, so retain no growing storage.
    std::mem::forget(nested);
  }
}

fn drop_worker_value<T>(value: T) -> bool {
  match panic::catch_unwind(AssertUnwindSafe(|| drop(value))) {
    Ok(()) => true,
    Err(payload) => {
      discard_worker_payload(payload);
      false
    }
  }
}

fn next_deadline(deadline: Instant, now: Instant) -> Option<Instant> {
  if now < deadline {
    return Some(deadline);
  }
  let elapsed = now.checked_duration_since(deadline)?;
  let interval_ns = SAMPLE_INTERVAL.as_nanos();
  let periods = elapsed
    .as_nanos()
    .checked_div(interval_ns)?
    .checked_add(1)?;
  let advance_ns = periods.checked_mul(interval_ns)?;
  let seconds = u64::try_from(advance_ns / NANOS_PER_SECOND).ok()?;
  let nanos = (advance_ns % NANOS_PER_SECOND) as u32;
  deadline.checked_add(Duration::new(seconds, nanos))
}

fn shutdown_error(failure: FeedbackWorkerFailure) -> FeedbackShutdownError {
  match failure {
    FeedbackWorkerFailure::Panicked => FeedbackShutdownError::WorkerPanicked,
    FeedbackWorkerFailure::ClockExhausted => FeedbackShutdownError::ClockExhausted,
    FeedbackWorkerFailure::PayloadCleanupPanicked => FeedbackShutdownError::PayloadCleanupPanicked,
  }
}

#[cfg(test)]
mod tests {
  use super::super::resource_feedback_policy::{ACTUATION_COOLDOWN, FeedbackControlConfig};
  use super::*;
  use std::cell::RefCell;
  use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
  use std::sync::mpsc;

  #[derive(Clone, Copy)]
  enum Signal {
    CpuPressure,
    CpuPressureDiskMissing,
    DiskHealthy,
    DiskHealthyExternalDrift,
    SensorPanicsOnce,
    Neutral,
  }

  type Flag = Arc<(Mutex<bool>, Condvar)>;

  struct ThreadExitGate {
    entered: Flag,
    release: Flag,
  }

  impl Drop for ThreadExitGate {
    fn drop(&mut self) {
      set_flag(&self.entered);
      let _ = wait_flag(&self.release, Duration::from_secs(10));
    }
  }

  struct NestedThreadExitGate {
    entered: Flag,
    release: Flag,
  }

  impl Drop for NestedThreadExitGate {
    fn drop(&mut self) {
      set_flag(&self.entered);
      let _ = wait_flag(&self.release, Duration::from_secs(10));
    }
  }

  struct InitializeNestedThreadExitGate {
    entered: Flag,
    release: Flag,
  }

  impl Drop for InitializeNestedThreadExitGate {
    fn drop(&mut self) {
      let entered = Arc::clone(&self.entered);
      let release = Arc::clone(&self.release);
      NESTED_THREAD_EXIT_GATE.with(|slot| {
        *slot.borrow_mut() = Some(NestedThreadExitGate { entered, release });
      });
    }
  }

  thread_local! {
    static THREAD_EXIT_GATE: RefCell<Option<ThreadExitGate>> = const { RefCell::new(None) };
    static NESTED_THREAD_EXIT_GATE: RefCell<Option<NestedThreadExitGate>> = const { RefCell::new(None) };
    static INITIALIZE_NESTED_THREAD_EXIT_GATE: RefCell<Option<InitializeNestedThreadExitGate>> = const { RefCell::new(None) };
  }

  struct CleanupPanickingSensor {
    entered: Flag,
    release: Flag,
    installed: bool,
  }

  impl FeedbackSensor for CleanupPanickingSensor {
    fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
      if !self.installed {
        let entered = Arc::clone(&self.entered);
        let release = Arc::clone(&self.release);
        THREAD_EXIT_GATE.with(|slot| {
          *slot.borrow_mut() = Some(ThreadExitGate { entered, release });
        });
        self.installed = true;
      }
      Ok(FeedbackSample::new(
        Instant::now(),
        Some(7_000),
        Some(7_000),
        Some(7_000),
      ))
    }
  }

  impl Drop for CleanupPanickingSensor {
    fn drop(&mut self) {
      panic!("mock sensor destructor panic");
    }
  }

  struct NestedTlsSensor {
    entered: Flag,
    release: Flag,
    installed: bool,
  }

  impl FeedbackSensor for NestedTlsSensor {
    fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
      if !self.installed {
        let entered = Arc::clone(&self.entered);
        let release = Arc::clone(&self.release);
        INITIALIZE_NESTED_THREAD_EXIT_GATE.with(|slot| {
          *slot.borrow_mut() = Some(InitializeNestedThreadExitGate { entered, release });
        });
        self.installed = true;
      }
      Ok(FeedbackSample::new(Instant::now(), None, None, None))
    }
  }

  struct TestSensor {
    signal: Signal,
    calls: Arc<AtomicUsize>,
    block: Option<(Flag, Flag)>,
    did_block: bool,
    drift_state: Option<Arc<ActuatorState>>,
    did_drift: bool,
    dropped: Option<Arc<AtomicBool>>,
  }

  impl TestSensor {
    fn new(signal: Signal) -> (Self, Arc<AtomicUsize>) {
      let calls = Arc::new(AtomicUsize::new(0));
      (
        Self {
          signal,
          calls: Arc::clone(&calls),
          block: None,
          did_block: false,
          drift_state: None,
          did_drift: false,
          dropped: None,
        },
        calls,
      )
    }

    fn blocking(entered: Flag, release: Flag, dropped: Arc<AtomicBool>) -> Self {
      Self {
        signal: Signal::Neutral,
        calls: Arc::new(AtomicUsize::new(0)),
        block: Some((entered, release)),
        did_block: false,
        drift_state: None,
        did_drift: false,
        dropped: Some(dropped),
      }
    }

    fn with_drop(signal: Signal, dropped: Arc<AtomicBool>) -> Self {
      let (mut sensor, _) = Self::new(signal);
      sensor.dropped = Some(dropped);
      sensor
    }

    fn drifting_disk(state: Arc<ActuatorState>) -> (Self, Arc<AtomicUsize>) {
      let (mut sensor, calls) = Self::new(Signal::DiskHealthyExternalDrift);
      sensor.drift_state = Some(state);
      (sensor, calls)
    }
  }

  impl FeedbackSensor for TestSensor {
    fn sample(&mut self) -> Result<FeedbackSample, FeedbackSensorError> {
      self.calls.fetch_add(1, Ordering::SeqCst);
      if !self.did_block
        && let Some((entered, release)) = &self.block
      {
        self.did_block = true;
        set_flag(entered);
        if !wait_flag(release, Duration::from_secs(3)) {
          return Err(FeedbackSensorError::Unavailable);
        }
      }
      if !self.did_drift
        && let Some(state) = &self.drift_state
      {
        state.limits[FeedbackResource::DiskRate as usize].store(105, Ordering::SeqCst);
        self.did_drift = true;
      }
      let (cpu, disk, network) = match self.signal {
        Signal::CpuPressure => (Some(9_000), Some(7_000), Some(7_000)),
        Signal::CpuPressureDiskMissing => (Some(9_000), None, Some(7_000)),
        Signal::DiskHealthy | Signal::DiskHealthyExternalDrift => {
          (Some(7_000), Some(3_000), Some(7_000))
        }
        Signal::SensorPanicsOnce if self.calls.load(Ordering::SeqCst) == 1 => {
          panic!("mock sensor panic")
        }
        Signal::SensorPanicsOnce => (Some(7_000), Some(7_000), Some(7_000)),
        Signal::Neutral => (Some(7_000), Some(7_000), Some(7_000)),
      };
      Ok(FeedbackSample::new(Instant::now(), cpu, disk, network))
    }
  }

  impl Drop for TestSensor {
    fn drop(&mut self) {
      if let Some(dropped) = &self.dropped {
        dropped.store(true, Ordering::SeqCst);
      }
    }
  }

  struct ActuatorState {
    limits: [AtomicU64; RESOURCE_COUNT],
    readbacks: [AtomicUsize; RESOURCE_COUNT],
    applies: AtomicUsize,
    apply_times: Mutex<Vec<(FeedbackResource, Instant)>>,
  }

  impl ActuatorState {
    fn new(limits: [u64; RESOURCE_COUNT]) -> Arc<Self> {
      Arc::new(Self {
        limits: std::array::from_fn(|index| AtomicU64::new(limits[index])),
        readbacks: std::array::from_fn(|_| AtomicUsize::new(0)),
        applies: AtomicUsize::new(0),
        apply_times: Mutex::new(Vec::new()),
      })
    }

    fn actual(&self, resource: FeedbackResource) -> u64 {
      self.limits[resource as usize].load(Ordering::SeqCst)
    }
  }

  #[derive(Clone, Copy)]
  enum DiskApplyMode {
    Normal,
    PartialThenError,
    TargetThenError,
    TargetThenBlockingPanic,
  }

  struct BlockingPanicPayload {
    entered: Flag,
    release: Flag,
  }

  impl Drop for BlockingPanicPayload {
    fn drop(&mut self) {
      set_flag(&self.entered);
      let _ = wait_flag(&self.release, Duration::from_secs(10));
    }
  }

  struct TestActuator {
    state: Arc<ActuatorState>,
    disk_mode: DiskApplyMode,
    panic_payload_gate: Option<(Flag, Flag)>,
    dropped: Option<Arc<AtomicBool>>,
  }

  impl TestActuator {
    fn new(state: Arc<ActuatorState>) -> Self {
      Self {
        state,
        disk_mode: DiskApplyMode::Normal,
        panic_payload_gate: None,
        dropped: None,
      }
    }

    fn with_disk_mode(state: Arc<ActuatorState>, disk_mode: DiskApplyMode) -> Self {
      Self {
        state,
        disk_mode,
        panic_payload_gate: None,
        dropped: None,
      }
    }

    fn blocking_disk_panic(
      state: Arc<ActuatorState>,
      entered: Flag,
      release: Flag,
      dropped: Arc<AtomicBool>,
    ) -> Self {
      Self {
        state,
        disk_mode: DiskApplyMode::TargetThenBlockingPanic,
        panic_payload_gate: Some((entered, release)),
        dropped: Some(dropped),
      }
    }
  }

  impl Drop for TestActuator {
    fn drop(&mut self) {
      if let Some(dropped) = &self.dropped {
        dropped.store(true, Ordering::SeqCst);
      }
    }
  }

  impl FeedbackActuator for TestActuator {
    fn readback(&mut self, resource: FeedbackResource) -> Result<u64, FeedbackActuatorError> {
      let index = resource as usize;
      self.state.readbacks[index].fetch_add(1, Ordering::SeqCst);
      Ok(self.state.limits[index].load(Ordering::SeqCst))
    }

    fn apply(&mut self, ticket: PlanTicket) -> Result<(), FeedbackActuatorError> {
      let resource = ticket.resource();
      let index = resource as usize;
      self
        .state
        .apply_times
        .lock()
        .unwrap()
        .push((resource, Instant::now()));
      self.state.applies.fetch_add(1, Ordering::SeqCst);
      let current = self.state.limits[index].load(Ordering::SeqCst);
      if current != ticket.from_limit() {
        return Err(FeedbackActuatorError::OperationFailed);
      }
      if resource == FeedbackResource::DiskRate {
        match self.disk_mode {
          DiskApplyMode::Normal => {}
          DiskApplyMode::PartialThenError => {
            self.state.limits[index].store(ticket.to_limit() - 5, Ordering::SeqCst);
            return Err(FeedbackActuatorError::OperationFailed);
          }
          DiskApplyMode::TargetThenError => {
            self.state.limits[index].store(ticket.to_limit(), Ordering::SeqCst);
            return Err(FeedbackActuatorError::OperationFailed);
          }
          DiskApplyMode::TargetThenBlockingPanic => {
            self.state.limits[index].store(ticket.to_limit(), Ordering::SeqCst);
            let Some((entered, release)) = &self.panic_payload_gate else {
              panic!("blocking panic mode requires a gate");
            };
            panic::panic_any(BlockingPanicPayload {
              entered: Arc::clone(entered),
              release: Arc::clone(release),
            });
          }
        }
      }
      self.state.limits[index].store(ticket.to_limit(), Ordering::SeqCst);
      Ok(())
    }
  }

  fn control(floor: u64, initial: u64, ceiling: u64) -> FeedbackControlConfig {
    FeedbackControlConfig::new(floor, initial, ceiling, 4_000, 8_000)
  }

  fn config() -> ResourceFeedbackPolicyConfig {
    ResourceFeedbackPolicyConfig {
      cpu_concurrency: control(10, 100, 1_000),
      disk_rate: control(1, 100, 1_000),
      network_rate: control(1, 100, 1_000),
    }
  }

  fn start(signal: Signal, state: Arc<ActuatorState>) -> ResourceFeedbackService {
    let (sensor, _) = TestSensor::new(signal);
    ResourceFeedbackService::start(config(), sensor, TestActuator::new(state)).unwrap()
  }

  fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
      if predicate() {
        return true;
      }
      let now = Instant::now();
      if now >= deadline {
        return predicate();
      }
      thread::sleep((deadline - now).min(Duration::from_millis(5)));
    }
  }

  fn stop_and_join(service: &mut ResourceFeedbackService) {
    service.request_stop();
    let stopped = wait_until(Duration::from_secs(2), || {
      matches!(
        service.try_shutdown(),
        Ok(FeedbackShutdownProgress::Complete)
      )
    });
    assert!(stopped, "feedback worker did not stop promptly");
  }

  fn new_flag() -> Flag {
    Arc::new((Mutex::new(false), Condvar::new()))
  }

  fn set_flag(flag: &Flag) {
    let (lock, wakeup) = &**flag;
    *lock.lock().unwrap() = true;
    wakeup.notify_all();
  }

  fn wait_flag(flag: &Flag, timeout: Duration) -> bool {
    let (lock, wakeup) = &**flag;
    let deadline = Instant::now() + timeout;
    let mut value = lock.lock().unwrap();
    while !*value {
      let now = Instant::now();
      if now >= deadline {
        return false;
      }
      let (next, result) = wakeup.wait_timeout(value, deadline - now).unwrap();
      value = next;
      if result.timed_out() && !*value {
        return false;
      }
    }
    true
  }

  #[test]
  fn feedback_service_remains_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ResourceFeedbackService>();
  }

  #[test]
  fn startup_rejects_actual_limit_mismatch_before_spawning_sensor() {
    let state = ActuatorState::new([100, 99, 100]);
    let (sensor, calls) = TestSensor::new(Signal::Neutral);
    let result = ResourceFeedbackService::start(config(), sensor, TestActuator::new(state));
    assert!(matches!(
      result,
      Err(FeedbackStartError::InitialLimitMismatch {
        resource: FeedbackResource::DiskRate,
        expected: 100,
        actual: 99,
      })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
  }

  #[test]
  fn external_drift_is_latched_without_overwriting_the_actual_limit() {
    let state = ActuatorState::new([100, 100, 100]);
    let (sensor, _) = TestSensor::drifting_disk(Arc::clone(&state));
    let mut service =
      ResourceFeedbackService::start(config(), sensor, TestActuator::new(Arc::clone(&state)))
        .unwrap();
    assert!(wait_until(Duration::from_secs(2), || {
      service
        .metrics()
        .control(FeedbackResource::DiskRate)
        .policy_faulted
    }));
    let disk = service.metrics().control(FeedbackResource::DiskRate);
    assert_eq!(disk.current_limit, 100);
    assert_eq!(state.actual(FeedbackResource::DiskRate), 105);
    assert_eq!(state.applies.load(Ordering::SeqCst), 0);
    assert_eq!(
      disk.last_diagnostic,
      Some(FeedbackDiagnostic::ExternalDrift {
        expected: 100,
        actual: 105,
      })
    );
    stop_and_join(&mut service);
  }

  #[test]
  fn sensor_panics_are_reported_and_sampling_continues() {
    let state = ActuatorState::new([100, 100, 100]);
    let (sensor, calls) = TestSensor::new(Signal::SensorPanicsOnce);
    let mut service =
      ResourceFeedbackService::start(config(), sensor, TestActuator::new(Arc::clone(&state)))
        .unwrap();
    assert!(wait_until(Duration::from_secs(2), || {
      service.metrics().sample_count >= 2 && calls.load(Ordering::SeqCst) >= 2
    }));
    let snapshot = service.metrics();
    assert_eq!(
      snapshot.last_diagnostic,
      Some(FeedbackDiagnostic::SensorPanicked)
    );
    assert_eq!(snapshot.worker_failure, None);
    assert_eq!(
      snapshot.control(FeedbackResource::DiskRate).telemetry,
      TelemetryStatus::Fresh
    );
    stop_and_join(&mut service);
  }

  #[test]
  fn autonomous_cpu_breach_uses_real_cadence_and_cooldown() {
    let state = ActuatorState::new([100, 100, 100]);
    let mut service = start(Signal::CpuPressure, Arc::clone(&state));
    assert!(wait_until(Duration::from_secs(2), || state
      .actual(FeedbackResource::CpuConcurrency)
      == 90));
    assert!(wait_until(Duration::from_secs(3), || {
      state.apply_times.lock().unwrap().len() >= 2
    }));
    let cpu_times: Vec<Instant> = state
      .apply_times
      .lock()
      .unwrap()
      .iter()
      .filter_map(|(resource, at)| (*resource == FeedbackResource::CpuConcurrency).then_some(*at))
      .collect();
    assert!(cpu_times.len() >= 2);
    assert!(cpu_times[1].duration_since(cpu_times[0]) >= ACTUATION_COOLDOWN);
    assert_eq!(state.actual(FeedbackResource::CpuConcurrency), 81);
    stop_and_join(&mut service);
  }

  #[test]
  fn missing_disk_telemetry_freezes_only_disk_control() {
    let state = ActuatorState::new([100, 100, 100]);
    let mut service = start(Signal::CpuPressureDiskMissing, Arc::clone(&state));
    assert!(wait_until(Duration::from_secs(2), || state
      .actual(FeedbackResource::CpuConcurrency)
      == 90));
    let snapshot = service.metrics();
    assert_eq!(
      snapshot.control(FeedbackResource::DiskRate).telemetry,
      TelemetryStatus::Missing
    );
    assert_eq!(
      snapshot.control(FeedbackResource::DiskRate).current_limit,
      100
    );
    assert_eq!(state.actual(FeedbackResource::DiskRate), 100);
    stop_and_join(&mut service);
  }

  #[test]
  fn blocked_sensor_keeps_worker_and_sensor_owner_alive_after_drop() {
    let state = ActuatorState::new([100, 100, 100]);
    let entered = new_flag();
    let release = new_flag();
    let dropped = Arc::new(AtomicBool::new(false));
    let sensor = TestSensor::blocking(
      Arc::clone(&entered),
      Arc::clone(&release),
      Arc::clone(&dropped),
    );
    let mut service =
      ResourceFeedbackService::start(config(), sensor, TestActuator::new(Arc::clone(&state)))
        .unwrap();
    let metrics = service.metrics_handle();
    assert!(wait_flag(&entered, Duration::from_secs(2)));
    service.request_stop();
    assert_eq!(
      service.try_shutdown(),
      Ok(FeedbackShutdownProgress::Pending)
    );
    assert!(service.join_monitor.is_some());
    drop(service);
    assert!(!dropped.load(Ordering::SeqCst));
    assert!(!metrics.snapshot().shutdown_complete);

    set_flag(&release);
    assert!(wait_until(Duration::from_secs(2), || {
      dropped.load(Ordering::SeqCst) && metrics.snapshot().shutdown_complete
    }));
  }

  #[test]
  fn worker_failure_does_not_report_complete_before_tls_cleanup_finishes() {
    let state = ActuatorState::new([100, 100, 100]);
    let entered = new_flag();
    let release = new_flag();
    let mut service = ResourceFeedbackService::start(
      config(),
      CleanupPanickingSensor {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
        installed: false,
      },
      TestActuator::new(state),
    )
    .unwrap();
    assert!(wait_until(Duration::from_secs(2), || {
      service.metrics().sample_count > 0
    }));
    service.request_stop();
    assert!(wait_flag(&entered, Duration::from_secs(2)));
    let snapshot = service.metrics();
    assert_eq!(
      snapshot.worker_failure,
      Some(FeedbackWorkerFailure::PayloadCleanupPanicked)
    );
    assert!(!snapshot.shutdown_complete);
    assert!(!service.is_shutdown_complete());
    assert_eq!(
      service.try_shutdown(),
      Ok(FeedbackShutdownProgress::Pending)
    );
    assert!(service.join_monitor.is_some());

    set_flag(&release);
    assert!(wait_until(Duration::from_secs(2), || {
      service.try_shutdown() == Err(FeedbackShutdownError::PayloadCleanupPanicked)
        && service.is_shutdown_complete()
    }));
  }

  #[test]
  fn joined_status_waits_for_tls_destructors_initialized_by_another_destructor() {
    let entered = new_flag();
    let release = new_flag();
    let mut service = ResourceFeedbackService::start(
      config(),
      NestedTlsSensor {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
        installed: false,
      },
      TestActuator::new(ActuatorState::new([100, 100, 100])),
    )
    .unwrap();
    assert!(wait_until(Duration::from_secs(2), || {
      service.metrics().sample_count > 0
    }));
    service.request_stop();
    assert!(wait_flag(&entered, Duration::from_secs(2)));
    assert!(!service.is_shutdown_complete());
    let (status_sender, status_receiver) = mpsc::sync_channel(1);
    let status_thread = thread::spawn(move || {
      let status = service.try_shutdown();
      let _ = status_sender.send((service, status));
    });
    let first_status = status_receiver.recv_timeout(Duration::from_secs(1));
    let returned_before_release = first_status.is_ok();
    set_flag(&release);
    let (mut service, status) = match first_status {
      Ok(value) => value,
      Err(mpsc::RecvTimeoutError::Timeout) => status_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|error| {
          panic!("shutdown poll remained blocked after TLS release: {error}")
        }),
      Err(error) => panic!("shutdown poll channel failed: {error}"),
    };
    status_thread
      .join()
      .unwrap_or_else(|_| panic!("bounded shutdown poll thread panicked"));
    assert!(
      returned_before_release,
      "shutdown poll blocked during TLS teardown"
    );
    assert_eq!(status, Ok(FeedbackShutdownProgress::Pending));
    assert!(service.join_monitor.is_some());

    assert!(wait_until(Duration::from_secs(2), || {
      service.try_shutdown() == Ok(FeedbackShutdownProgress::Complete)
        && service.is_shutdown_complete()
    }));
  }

  #[test]
  fn ambiguous_write_stays_faulted_until_explicit_readback_reconcile() {
    let state = ActuatorState::new([100, 100, 100]);
    let (sensor, _) = TestSensor::new(Signal::DiskHealthy);
    let mut service = ResourceFeedbackService::start(
      config(),
      sensor,
      TestActuator::with_disk_mode(Arc::clone(&state), DiskApplyMode::PartialThenError),
    )
    .unwrap();
    assert!(wait_until(Duration::from_secs(2), || {
      service
        .metrics()
        .control(FeedbackResource::DiskRate)
        .policy_faulted
    }));
    assert_eq!(state.actual(FeedbackResource::DiskRate), 105);
    assert_eq!(
      service
        .metrics()
        .control(FeedbackResource::DiskRate)
        .current_limit,
      100
    );
    let readbacks_after_failure =
      state.readbacks[FeedbackResource::DiskRate as usize].load(Ordering::SeqCst);
    thread::sleep(Duration::from_millis(250));
    assert_eq!(
      state.readbacks[FeedbackResource::DiskRate as usize].load(Ordering::SeqCst),
      readbacks_after_failure,
      "faulted controls must not reconcile automatically"
    );
    assert_eq!(state.applies.load(Ordering::SeqCst), 1);

    service
      .request_reconcile(FeedbackResource::DiskRate)
      .unwrap();
    assert!(wait_until(Duration::from_secs(1), || {
      let control = service.metrics().control(FeedbackResource::DiskRate);
      !control.policy_faulted && control.current_limit == 105
    }));
    assert!(wait_until(Duration::from_secs(1), || {
      let control = service.metrics().control(FeedbackResource::DiskRate);
      control.telemetry == TelemetryStatus::Fresh
        && matches!(control.no_change, Some(NoChangeReason::CoolingDown { .. }))
    }));
    assert_eq!(state.actual(FeedbackResource::DiskRate), 105);
    assert_eq!(state.applies.load(Ordering::SeqCst), 1);
    stop_and_join(&mut service);
  }

  #[test]
  fn error_after_reaching_target_still_latches_until_explicit_reconcile() {
    let state = ActuatorState::new([100, 100, 100]);
    let (sensor, _) = TestSensor::new(Signal::DiskHealthy);
    let mut service = ResourceFeedbackService::start(
      config(),
      sensor,
      TestActuator::with_disk_mode(Arc::clone(&state), DiskApplyMode::TargetThenError),
    )
    .unwrap();
    assert!(wait_until(Duration::from_secs(2), || {
      service
        .metrics()
        .control(FeedbackResource::DiskRate)
        .policy_faulted
    }));
    let disk = service.metrics().control(FeedbackResource::DiskRate);
    assert_eq!(state.actual(FeedbackResource::DiskRate), 110);
    assert_eq!(disk.current_limit, 100);
    assert_eq!(
      disk.last_diagnostic,
      Some(FeedbackDiagnostic::ActuatorFailed {
        phase: FeedbackActuatorPhase::Apply,
        error: FeedbackActuatorError::OperationFailed,
      })
    );
    assert_eq!(
      state.readbacks[FeedbackResource::DiskRate as usize].load(Ordering::SeqCst),
      3
    );

    service
      .request_reconcile(FeedbackResource::DiskRate)
      .unwrap();
    assert!(wait_until(Duration::from_secs(1), || {
      let disk = service.metrics().control(FeedbackResource::DiskRate);
      !disk.policy_faulted && disk.current_limit == 110
    }));
    stop_and_join(&mut service);
  }

  #[test]
  fn blocking_apply_panic_payload_waits_until_readback_and_fault_ack() {
    let state = ActuatorState::new([100, 100, 100]);
    let panic_drop_started = new_flag();
    let release_panic_drop = new_flag();
    let sensor_dropped = Arc::new(AtomicBool::new(false));
    let actuator_dropped = Arc::new(AtomicBool::new(false));
    let sensor = TestSensor::with_drop(Signal::DiskHealthy, Arc::clone(&sensor_dropped));
    let actuator = TestActuator::blocking_disk_panic(
      Arc::clone(&state),
      Arc::clone(&panic_drop_started),
      Arc::clone(&release_panic_drop),
      Arc::clone(&actuator_dropped),
    );
    let mut service = ResourceFeedbackService::start(config(), sensor, actuator).unwrap();

    assert!(wait_flag(&panic_drop_started, Duration::from_secs(2)));
    let disk = service.metrics().control(FeedbackResource::DiskRate);
    assert_eq!(
      state.readbacks[FeedbackResource::DiskRate as usize].load(Ordering::SeqCst),
      3
    );
    assert_eq!(state.actual(FeedbackResource::DiskRate), 110);
    assert_eq!(disk.current_limit, 100);
    assert!(disk.policy_faulted);
    assert_eq!(
      disk.last_diagnostic,
      Some(FeedbackDiagnostic::ActuatorPanicked(
        FeedbackActuatorPhase::Apply
      ))
    );

    service.request_stop();
    assert_eq!(
      service.try_shutdown(),
      Ok(FeedbackShutdownProgress::Pending)
    );
    assert!(service.join_monitor.is_some());
    assert!(!sensor_dropped.load(Ordering::SeqCst));
    assert!(!actuator_dropped.load(Ordering::SeqCst));

    set_flag(&release_panic_drop);
    assert!(wait_until(Duration::from_secs(2), || {
      sensor_dropped.load(Ordering::SeqCst)
        && actuator_dropped.load(Ordering::SeqCst)
        && matches!(
          service.try_shutdown(),
          Ok(FeedbackShutdownProgress::Complete)
        )
    }));
    assert!(
      service
        .metrics()
        .control(FeedbackResource::DiskRate)
        .policy_faulted
    );
  }
}
