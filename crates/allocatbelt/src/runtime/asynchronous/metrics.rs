//! Retained, point-in-time diagnostics for an asynchronous runtime.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::thread_options::AsyncThreadContext;
use crate::runtime::resource_domain::{ControlCharge, DomainError, TenantDomain, payload_bytes};

#[derive(Debug)]
pub(super) enum MetricsBuildError {
  OutOfMemory,
  ResourceDomain(DomainError),
}

pub(super) struct RuntimeMetricsInner {
  pub(super) workers: usize,
  pub(super) alive_tasks: AtomicUsize,
  pub(super) queue_depth: AtomicUsize,
  pub(super) hook_panics: AtomicUsize,
  pub(super) threads: Vec<ThreadMetrics>,
  _control: ControlCharge,
}

pub(super) struct ThreadMetrics {
  pub(super) context: AsyncThreadContext,
  pub(super) alive: AtomicBool,
  pub(super) starts: AtomicUsize,
  pub(super) stops: AtomicUsize,
  pub(super) parks: AtomicUsize,
  pub(super) unparks: AtomicUsize,
  busy_nanos: AtomicU64,
}

impl ThreadMetrics {
  pub(super) fn new(context: AsyncThreadContext) -> Self {
    Self {
      context,
      alive: AtomicBool::new(false),
      starts: AtomicUsize::new(0),
      stops: AtomicUsize::new(0),
      parks: AtomicUsize::new(0),
      unparks: AtomicUsize::new(0),
      busy_nanos: AtomicU64::new(0),
    }
  }

  pub(super) fn add_busy_nanos(&self, nanos: u64) {
    let _ = self
      .busy_nanos
      .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(nanos))
      });
  }
}

/// A cloneable diagnostic view that remains usable after runtime shutdown.
///
/// The executor updates these counters on every runtime, whether or not the
/// application reads them. Busy accounting takes a monotonic timestamp at
/// each turn boundary. Scalar and per-thread getters allocate nothing;
/// [`snapshot`](Self::snapshot) allocates a vector, while
/// [`try_snapshot`](Self::try_snapshot) reports reservation failure. Every
/// counter is sampled independently with relaxed ordering; these reads do not
/// form a transactional snapshot across fields or threads.
#[derive(Clone)]
pub struct RuntimeMetrics(Arc<RuntimeMetricsInner>);

impl RuntimeMetrics {
  pub(super) fn try_new(
    workers: usize,
    contexts: impl IntoIterator<Item = AsyncThreadContext>,
    capacity: usize,
    tenant: Option<&TenantDomain>,
  ) -> Result<Self, MetricsBuildError> {
    let requested = std::mem::size_of::<RuntimeMetricsInner>()
      .checked_add(
        payload_bytes::<ThreadMetrics>(capacity).map_err(MetricsBuildError::ResourceDomain)?,
      )
      .ok_or(MetricsBuildError::ResourceDomain(DomainError::Invalid))?;
    let mut control =
      ControlCharge::try_new(tenant, requested).map_err(MetricsBuildError::ResourceDomain)?;
    let mut threads = Vec::new();
    threads
      .try_reserve_exact(capacity)
      .map_err(|_| MetricsBuildError::OutOfMemory)?;
    threads.extend(contexts.into_iter().map(ThreadMetrics::new));
    let actual = std::mem::size_of::<RuntimeMetricsInner>()
      .checked_add(
        payload_bytes::<ThreadMetrics>(threads.capacity())
          .map_err(MetricsBuildError::ResourceDomain)?,
      )
      .ok_or(MetricsBuildError::ResourceDomain(DomainError::Invalid))?;
    control
      .try_resize(actual)
      .map_err(MetricsBuildError::ResourceDomain)?;
    Ok(Self(Arc::new(RuntimeMetricsInner {
      workers,
      alive_tasks: AtomicUsize::new(0),
      queue_depth: AtomicUsize::new(0),
      hook_panics: AtomicUsize::new(0),
      threads,
      _control: control,
    })))
  }

  pub(super) fn inner(&self) -> &Arc<RuntimeMetricsInner> {
    &self.0
  }

  /// Returns the configured primary worker count.
  #[must_use]
  pub fn num_workers(&self) -> usize {
    self.0.workers
  }

  /// Returns the maximum simultaneous dispatchers, equal to `num_workers`.
  #[must_use]
  pub fn dispatch_ceiling(&self) -> usize {
    self.0.workers
  }

  /// Returns the current number of admitted task slots, including cleanup.
  #[must_use]
  pub fn num_alive_tasks(&self) -> usize {
    self.0.alive_tasks.load(Ordering::Relaxed)
  }

  /// Returns the current number of tokens in the bounded ready queue.
  #[must_use]
  pub fn global_queue_depth(&self) -> usize {
    self.0.queue_depth.load(Ordering::Relaxed)
  }

  /// Returns the number of contained lifecycle hook panics.
  #[must_use]
  pub fn hook_panics(&self) -> usize {
    self.0.hook_panics.load(Ordering::Relaxed)
  }

  /// Returns the fixed number of physical worker and helper entries.
  #[must_use]
  pub fn thread_count(&self) -> usize {
    self.0.threads.len()
  }

  /// Samples one physical thread without allocating.
  #[must_use]
  pub fn thread(&self, physical_index: usize) -> Option<AsyncThreadMetrics> {
    self.0.thread(physical_index).map(AsyncThreadMetrics::read)
  }

  /// Builds an owned snapshot after fallibly reserving its per-thread vector.
  /// Concurrent changes can make fields describe adjacent moments rather than
  /// one atomic instant.
  pub fn try_snapshot(&self) -> Result<RuntimeMetricsSnapshot, std::collections::TryReserveError> {
    let mut threads = Vec::new();
    threads.try_reserve_exact(self.thread_count())?;
    for thread in &self.0.threads {
      threads.push(AsyncThreadMetrics::read(thread));
    }
    Ok(RuntimeMetricsSnapshot {
      num_workers: self.num_workers(),
      dispatch_ceiling: self.dispatch_ceiling(),
      num_alive_tasks: self.num_alive_tasks(),
      global_queue_depth: self.global_queue_depth(),
      hook_panics: self.hook_panics(),
      threads,
    })
  }

  /// Samples all counters independently. Concurrent changes can therefore
  /// make fields describe adjacent moments rather than one atomic instant.
  /// This convenience method allocates a vector; use [`try_snapshot`](Self::try_snapshot)
  /// when allocation failure must be reported.
  #[must_use]
  pub fn snapshot(&self) -> RuntimeMetricsSnapshot {
    RuntimeMetricsSnapshot {
      num_workers: self.0.workers,
      dispatch_ceiling: self.0.workers,
      num_alive_tasks: self.0.alive_tasks.load(Ordering::Relaxed),
      global_queue_depth: self.0.queue_depth.load(Ordering::Relaxed),
      hook_panics: self.0.hook_panics.load(Ordering::Relaxed),
      threads: self
        .0
        .threads
        .iter()
        .map(AsyncThreadMetrics::read)
        .collect(),
    }
  }
}

/// One thread's physical role and independently sampled diagnostic counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsyncThreadMetrics {
  /// Physical role and stable runtime-local indices.
  pub context: AsyncThreadContext,
  /// Whether the thread is currently alive.
  pub alive: bool,
  /// Number of thread starts observed (zero or one for a runtime).
  pub starts: usize,
  /// Number of thread stops observed (zero or one for a runtime).
  pub stops: usize,
  /// Number of times this thread entered a scheduler wait.
  pub parks: usize,
  /// Number of returns from scheduler waits, including spurious wakeups.
  pub unparks: usize,
  /// Wall time spent dispatching turns, including their cleanup and excluding
  /// parking and successful handoff closures/restoration waits.
  pub busy_duration: std::time::Duration,
}

/// Point-in-time runtime and per-thread diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeMetricsSnapshot {
  /// Configured primary executor thread count.
  pub num_workers: usize,
  /// Maximum simultaneous dispatchers, equal to `num_workers`.
  pub dispatch_ceiling: usize,
  /// Admitted task slots still owned by the executor, including cleanup.
  pub num_alive_tasks: usize,
  /// Current tokens in the single bounded global ready queue.
  pub global_queue_depth: usize,
  /// Number of contained lifecycle hook panics. A naming callback panic
  /// rejects construction before a metrics handle is returned.
  pub hook_panics: usize,
  /// Counters indexed by physical thread, with primary workers first.
  pub threads: Vec<AsyncThreadMetrics>,
}

impl RuntimeMetricsInner {
  pub(super) fn thread(&self, physical_index: usize) -> Option<&ThreadMetrics> {
    self.threads.get(physical_index)
  }
}

impl AsyncThreadMetrics {
  fn read(thread: &ThreadMetrics) -> Self {
    Self {
      context: thread.context,
      alive: thread.alive.load(Ordering::Relaxed),
      starts: thread.starts.load(Ordering::Relaxed),
      stops: thread.stops.load(Ordering::Relaxed),
      parks: thread.parks.load(Ordering::Relaxed),
      unparks: thread.unparks.load(Ordering::Relaxed),
      busy_duration: std::time::Duration::from_nanos(thread.busy_nanos.load(Ordering::Relaxed)),
    }
  }
}
