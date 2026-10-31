//! A bounded, owned-future executor. This is an experimental foundation;
//! it does not provide I/O, borrowed spawned tasks, or Tokio compatibility.
//! [`AsyncRuntime::block_on`] may poll one borrowed or non-`Send` root future
//! on its caller thread. Spawned work remains owned and `Send + 'static`.
//! Runtime-owned outer polls enable a shared 64-operation cooperative budget
//! for ready channel, oneshot, semaphore, mutex, reader-writer-lock, notify,
//! watch, broadcast, barrier, sleep, timeout, interval-tick, and live
//! asynchronous initialization futures, and registered child-pipe I/O trait
//! polls. The budget is scoped to those polls;
//! timeout and initialization polls coalesce a ready charge with supported
//! descendants, retaining descendant charges on pending polls or unwinding.
//! Completed initialization futures retain their immediate error. Manual polls and
//! futures polled by another executor bypass automatic accounting.
//! [`yield_now`] schedules one self-wake; [`consume_budget`] remains an
//! explicit checkpoint for other long-running future work. No checkpoint
//! preempts synchronous code or arbitrary futures that never yield.
//! [`try_block_in_place`] runs a blocking closure on its caller's thread; a
//! runtime built with [`AsyncRuntime::new_with_handoffs`] keeps dispatching
//! on a bounded set of prestarted helpers meanwhile.

//! Strict dispatch preserves per-scope order; opt-in Distributed uses FIFO
//! lanes with bounded stealing and currently requires handoffs to be disabled.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

mod entry;
mod handoff;
mod handoff_protocol;
mod identity;
mod join;
mod lane;
mod local;
mod metrics;
mod protocol;
mod scheduler;
mod task;
mod task_set;
mod thread_options;

#[cfg(all(test, not(loom)))]
mod cooperative_tests;
#[cfg(all(test, not(loom)))]
mod handoff_tests;
#[cfg(all(test, not(loom)))]
mod metrics_tests;
#[cfg(all(test, not(loom)))]
mod tests;

use std::any::Any;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;

use crate::runtime::managed::ResourceScope;
use crate::runtime::resource_domain::{ControlCharge, DomainError, payload_bytes};
use crate::runtime::task::drop_contained;
use crate::runtime::thread_completion::{DeferredJoin, PreparedJoins};
use scheduler::{ScopeRef, Shared};

pub use entry::{
  ConsumeBudget, EnterGuard, YieldNow, consume_budget, current, current_resource_scope, task_id,
  try_current, try_current_resource_scope, try_task_id, yield_now,
};
pub(super) use entry::{poll_cooperative, poll_cooperative_composed};
pub use handoff::{BlockInPlaceError, BlockInPlaceErrorKind, HandoffConfig, try_block_in_place};
pub use identity::TaskId;
pub use join::{AbortHandle, AsyncJob, AsyncJoinError};
pub use local::{
  LocalConfig, LocalEnterGuard, LocalError, LocalHandle, LocalRuntime, LocalScopeClose,
  LocalSendHandle, LocalSpawnError, LocalTaskScope,
};
use metrics::MetricsBuildError;
pub use metrics::{AsyncThreadMetrics, RuntimeMetrics, RuntimeMetricsSnapshot};
pub use scheduler::{OwnedTaskScope, ScopeClose};
pub use task_set::{JoinNext, SetTaskId, TaskSet, TaskSetError};
pub use thread_options::{AsyncThreadContext, AsyncThreadOptions, AsyncThreadRole};

#[cfg(all(test, not(loom)))]
fn strict_runtime(config: AsyncConfig) -> Result<AsyncRuntime, AsyncError> {
  AsyncRuntime::new_with_options(
    config,
    AsyncRuntimeOptions::new().dispatch(AsyncDispatch::Strict),
  )
}

fn thread_contexts(workers: usize, handoffs: usize) -> impl Iterator<Item = AsyncThreadContext> {
  (0..workers + handoffs).map(move |physical_index| {
    if physical_index < workers {
      AsyncThreadContext {
        role: AsyncThreadRole::Worker,
        index: physical_index,
        physical_index,
      }
    } else {
      AsyncThreadContext {
        role: AsyncThreadRole::HandoffHelper,
        index: physical_index - workers,
        physical_index,
      }
    }
  })
}

struct ControlledThreadOptions {
  options: AsyncThreadOptions,
  _control: ControlCharge,
}

impl ControlledThreadOptions {
  #[cfg(test)]
  pub(super) fn unbounded(options: AsyncThreadOptions) -> Self {
    Self {
      options,
      _control: ControlCharge::unbounded(0),
    }
  }
}

impl std::ops::Deref for ControlledThreadOptions {
  type Target = AsyncThreadOptions;

  fn deref(&self) -> &Self::Target {
    &self.options
  }
}

/// Fixed limits for an [`AsyncRuntime`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsyncConfig {
  /// Number of executor threads.
  pub workers: usize,
  /// Maximum admitted, unfinished tasks, including cancellation cleanup.
  pub max_outstanding: usize,
  /// Maximum number of simultaneously live owned scopes. The runtime's
  /// implicit scope used by [`AsyncHandle::spawn`] counts toward this bound.
  pub max_scopes: usize,
}

/// How an [`AsyncRuntime`] orders ready owned tasks.
/// The default is currently [`AsyncDispatch::Strict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(not(test), derive(Default))]
#[non_exhaustive]
pub enum AsyncDispatch {
  /// FIFO lanes with bounded stealing. Available without handoffs; combining
  /// this mode with handoffs returns [`AsyncError::InvalidConfig`].
  Distributed,
  /// Ordinary ready work keeps per-scope FIFO order, with ready scopes
  /// rotating one poll per turn. Cancellation cleanup can pass queued
  /// ordinary work. Restoring threads precede every new turn.
  // Keep the established ordering as the default during opt-in rollout.
  #[cfg_attr(not(test), default)]
  Strict,
}

#[cfg(test)]
impl Default for AsyncDispatch {
  fn default() -> Self {
    if std::env::var("ALLOCATBELT_ASYNC_DISPATCH").as_deref() == Ok("distributed") {
      return Self::Distributed;
    }
    Self::Strict
  }
}

/// Additive construction options for [`AsyncRuntime::new_with_options`].
#[derive(Clone, Debug, Default)]
pub struct AsyncRuntimeOptions {
  dispatch: AsyncDispatch,
  handoffs: Option<HandoffConfig>,
  thread_options: AsyncThreadOptions,
}

impl AsyncRuntimeOptions {
  /// Starts with the default dispatch mode (currently [`AsyncDispatch::Strict`]),
  /// no handoffs and default thread options.
  #[must_use]
  pub fn new() -> Self {
    Self::default()
  }

  /// Selects how ready owned tasks are ordered.
  #[must_use]
  pub const fn dispatch(mut self, dispatch: AsyncDispatch) -> Self {
    self.dispatch = dispatch;
    self
  }

  /// Prestarts bounded helper threads for [`try_block_in_place`].
  #[must_use]
  pub const fn handoffs(mut self, handoffs: HandoffConfig) -> Self {
    self.handoffs = Some(handoffs);
    self
  }

  /// Applies names, stack sizes and lifecycle hooks to executor threads.
  #[must_use]
  pub fn thread_options(mut self, options: AsyncThreadOptions) -> Self {
    self.thread_options = options;
    self
  }
}

/// Polling limits for one owned scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsyncScopeConfig {
  /// Maximum number of this scope's futures that may be inside `Future::poll`
  /// simultaneously. Must be nonzero; the runtime worker count remains the
  /// overall concurrency ceiling.
  pub max_active_polls: usize,
}

/// A scope's point-in-time task and active-poll counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsyncScopeSnapshot {
  /// Admitted unfinished tasks, including cleanup after polling.
  /// This count can change concurrently with a snapshot.
  pub active_tasks: usize,
  /// Poll slots reserved before dispatch and held through `Future::poll`
  /// return. Strict samples under the scheduler lock. Distributed uses the
  /// scope quota lock for binding limits, otherwise a relaxed diagnostic count.
  /// A reserved task may be about to enter its poll call.
  pub active_polls: usize,
  /// The configured active-poll limit for this scope.
  pub max_active_polls: usize,
}

/// Construction, admission, block-on entry, or shutdown failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AsyncError {
  /// A required bound or thread stack size is zero, thread naming is invalid,
  /// or the configuration cannot be represented by the runtime.
  InvalidConfig,
  /// Pre-reserving bounded scheduler storage or starting a worker failed.
  OutOfMemory,
  /// The outstanding-task bound is full.
  Full,
  /// The runtime or scope is closing.
  Closed,
  /// A scope slot is unavailable.
  TooManyScopes,
  /// Joining workers from one of those workers would deadlock.
  WouldDeadlock,
  /// `block_on` was called from an executor worker.
  BlockOnFromWorker,
  /// A nested `block_on` was attempted on the same thread.
  NestedBlockOn,
  /// A worker exited unexpectedly.
  WorkerPanicked,
  /// A finite shutdown poll could not start a worker completion monitor.
  /// Retry shutdown polling; the original worker handle remains owned.
  JoinMonitorSpawnFailed,
  /// The process-wide task identifier space is exhausted.
  TaskIdExhausted,
  /// A bound global/tenant resource could not be admitted.
  ResourceDomain(DomainError),
}

impl fmt::Display for AsyncError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::InvalidConfig => "invalid async runtime configuration",
      Self::OutOfMemory => "async runtime could not reserve bounded storage",
      Self::Full => "async outstanding-task bound reached",
      Self::Closed => "async runtime or task scope is closed",
      Self::TooManyScopes => "async scope bound reached",
      Self::WouldDeadlock => "async shutdown from a worker would deadlock",
      Self::BlockOnFromWorker => "block_on from an async executor worker is not allowed",
      Self::NestedBlockOn => "nested block_on on one thread is not allowed",
      Self::WorkerPanicked => "an async worker exited unexpectedly",
      Self::JoinMonitorSpawnFailed => {
        "async shutdown could not start a join monitor; retry shutdown polling"
      }
      Self::TaskIdExhausted => "process-wide async task identifiers are exhausted",
      Self::ResourceDomain(_) => "async resource-domain admission failed",
    })
  }
}

impl std::error::Error for AsyncError {}

/// A rejected submission together with the unchanged future.
pub struct AsyncSpawnError<F> {
  /// Why the future was not admitted.
  pub kind: AsyncError,
  future: F,
}

impl<F> AsyncSpawnError<F> {
  pub(super) fn new(kind: AsyncError, future: F) -> Self {
    Self { kind, future }
  }

  /// Returns ownership of the future that was not admitted.
  #[must_use]
  pub fn into_future(self) -> F {
    self.future
  }
}

impl<F> fmt::Debug for AsyncSpawnError<F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AsyncSpawnError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl<F> fmt::Display for AsyncSpawnError<F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "async submission rejected: {}", self.kind)
  }
}

impl<F> std::error::Error for AsyncSpawnError<F> {}

/// How explicit shutdown handles unfinished futures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncShutdown {
  /// Close admission and poll admitted tasks until they finish.
  Drain,
  /// Close admission and request cancellation of every admitted task.
  CancelPending,
}

/// A fixed worker pool for bounded, owned `Send + 'static` futures.
pub struct AsyncRuntime {
  shared: Arc<Shared>,
  workers: Vec<DeferredJoin>,
  panic_payloads: Mutex<Vec<Box<dyn Any + Send>>>,
  root: ScopeRef,
  shutdown_complete: bool,
  shutdown_panicked: bool,
  _control: ControlCharge,
  launch_control: Option<Arc<ControlCharge>>,
}

impl AsyncRuntime {
  /// Reserves all bounded scheduler tables before starting worker threads.
  /// The runtime has exactly `config.workers` threads and no handoff slots:
  /// [`try_block_in_place`] on one of its turns returns
  /// [`BlockInPlaceErrorKind::Disabled`].
  pub fn new(config: AsyncConfig) -> Result<Self, AsyncError> {
    Self::new_with_options(config, AsyncRuntimeOptions::new())
  }

  /// Creates a runtime with additive per-thread naming, stack and lifecycle options.
  pub fn new_with_thread_options(
    config: AsyncConfig,
    options: AsyncThreadOptions,
  ) -> Result<Self, AsyncError> {
    Self::new_with_options(config, AsyncRuntimeOptions::new().thread_options(options))
  }

  /// Creates a runtime with the selected dispatch, handoff and thread options.
  ///
  /// # Errors
  ///
  /// Returns [`AsyncError::InvalidConfig`] for a zero required bound, a zero
  /// handoff bound, worker/helper count overflow, invalid thread options or
  /// an unavailable dispatch mode. Storage reservation or thread startup can
  /// return [`AsyncError::OutOfMemory`].
  ///
  /// ```
  /// use allocatbelt::runtime::asynchronous::{
  ///   AsyncConfig, AsyncDispatch, AsyncRuntime, AsyncRuntimeOptions, AsyncShutdown,
  /// };
  ///
  /// let runtime = AsyncRuntime::new_with_options(
  ///   AsyncConfig { workers: 1, max_outstanding: 8, max_scopes: 2 },
  ///   AsyncRuntimeOptions::new().dispatch(AsyncDispatch::Strict),
  /// )?;
  /// assert_eq!(runtime.dispatch(), AsyncDispatch::Strict);
  /// assert_eq!(runtime.metrics().dispatch(), AsyncDispatch::Strict);
  /// runtime.shutdown(AsyncShutdown::Drain)?;
  /// # Ok::<(), allocatbelt::runtime::asynchronous::AsyncError>(())
  /// ```
  pub fn new_with_options(
    config: AsyncConfig,
    options: AsyncRuntimeOptions,
  ) -> Result<Self, AsyncError> {
    Self::start_with_options(config, None, options)
  }

  /// Creates a runtime whose implicit root scope uses `resources` for every
  /// root handle, worker context and task admitted through that root.
  ///
  /// Test helper that binds the existing root scope without consuming an
  /// additional scope slot.
  #[cfg(test)]
  pub(super) fn with_resources(
    config: AsyncConfig,
    resources: ResourceScope,
  ) -> Result<Self, AsyncError> {
    Self::with_resources_and_options(config, resources, AsyncRuntimeOptions::new())
  }

  /// Resource-bound thread-options constructor for tests.
  #[cfg(test)]
  pub(super) fn with_resources_and_thread_options(
    config: AsyncConfig,
    resources: ResourceScope,
    options: AsyncThreadOptions,
  ) -> Result<Self, AsyncError> {
    Self::with_resources_and_options(
      config,
      resources,
      AsyncRuntimeOptions::new().thread_options(options),
    )
  }

  /// Like [`AsyncRuntime::new`], and also prestarts
  /// `handoffs.max_handoffs` helper threads so that up to that many owned
  /// turns at once can run a [`try_block_in_place`] closure on their own
  /// thread while a helper keeps dispatching. At most `config.workers`
  /// threads dispatch owned turns at any time; scope and root poll limits are
  /// unchanged. If any thread fails to start, every started thread is joined
  /// before the error is returned.
  ///
  /// # Errors
  ///
  /// [`AsyncError::InvalidConfig`] for a zero bound or when
  /// `workers + max_handoffs` overflows, and [`AsyncError::OutOfMemory`] when
  /// bounded storage cannot be reserved or a thread cannot start.
  pub fn new_with_handoffs(
    config: AsyncConfig,
    handoffs: HandoffConfig,
  ) -> Result<Self, AsyncError> {
    Self::new_with_options(config, AsyncRuntimeOptions::new().handoffs(handoffs))
  }

  /// Like [`AsyncRuntime::new_with_thread_options`], with prestarted helpers
  /// available while an owned turn runs a [`try_block_in_place`] closure.
  pub fn new_with_handoffs_and_thread_options(
    config: AsyncConfig,
    handoffs: HandoffConfig,
    options: AsyncThreadOptions,
  ) -> Result<Self, AsyncError> {
    Self::new_with_options(
      config,
      AsyncRuntimeOptions::new()
        .handoffs(handoffs)
        .thread_options(options),
    )
  }

  /// Resource-bound handoff constructor for tests.
  #[cfg(test)]
  pub(super) fn with_resources_and_handoffs(
    config: AsyncConfig,
    handoffs: HandoffConfig,
    resources: ResourceScope,
  ) -> Result<Self, AsyncError> {
    Self::with_resources_and_options(
      config,
      resources,
      AsyncRuntimeOptions::new().handoffs(handoffs),
    )
  }

  /// Resource-bound handoff and thread-options constructor for tests.
  #[cfg(test)]
  pub(super) fn with_resources_handoffs_and_thread_options(
    config: AsyncConfig,
    handoffs: HandoffConfig,
    resources: ResourceScope,
    options: AsyncThreadOptions,
  ) -> Result<Self, AsyncError> {
    Self::with_resources_and_options(
      config,
      resources,
      AsyncRuntimeOptions::new()
        .handoffs(handoffs)
        .thread_options(options),
    )
  }

  /// Resource-bound counterpart used by the owning runtime facade.
  pub(super) fn with_resources_and_options(
    config: AsyncConfig,
    resources: ResourceScope,
    options: AsyncRuntimeOptions,
  ) -> Result<Self, AsyncError> {
    Self::start_with_options(config, Some(resources), options)
  }

  fn start_with_options(
    config: AsyncConfig,
    resources: Option<ResourceScope>,
    options: AsyncRuntimeOptions,
  ) -> Result<Self, AsyncError> {
    let max_handoffs = match options.handoffs {
      Some(HandoffConfig { max_handoffs: 0 }) => return Err(AsyncError::InvalidConfig),
      Some(handoffs) => handoffs.max_handoffs,
      None => 0,
    };
    Self::start(
      config,
      max_handoffs,
      resources,
      options.thread_options,
      options.dispatch,
    )
  }

  fn start(
    config: AsyncConfig,
    max_handoffs: usize,
    resources: Option<ResourceScope>,
    options: AsyncThreadOptions,
    dispatch: AsyncDispatch,
  ) -> Result<Self, AsyncError> {
    if dispatch == AsyncDispatch::Distributed && max_handoffs != 0 {
      return Err(AsyncError::InvalidConfig);
    }
    if config.workers == 0 || config.max_outstanding == 0 || config.max_scopes == 0 {
      return Err(AsyncError::InvalidConfig);
    }
    let Some(threads) = config.workers.checked_add(max_handoffs) else {
      return Err(AsyncError::InvalidConfig);
    };
    let tenant = resources.as_ref().and_then(ResourceScope::tenant_domain);
    let stack_size = options.stack_size();
    if stack_size.is_some_and(|size| size == 0) {
      return Err(AsyncError::InvalidConfig);
    }
    let mut prepared_contexts =
      entry::PreparedContextNodes::new(tenant, threads).map_err(AsyncError::ResourceDomain)?;
    let mut prepared_joins =
      PreparedJoins::new(tenant, threads).map_err(AsyncError::ResourceDomain)?;
    let option_control = ControlCharge::try_new(tenant, options.control_name_capacity())
      .map_err(AsyncError::ResourceDomain)?;
    let options = ControlledThreadOptions {
      options,
      _control: option_control,
    };
    let tenant = resources.as_ref().and_then(ResourceScope::tenant_domain);
    let metrics = RuntimeMetrics::try_new(
      dispatch,
      config.workers,
      thread_contexts(config.workers, max_handoffs),
      threads,
      tenant,
    )
    .map_err(|error| match error {
      MetricsBuildError::OutOfMemory => AsyncError::OutOfMemory,
      MetricsBuildError::ResourceDomain(error) => AsyncError::ResourceDomain(error),
    })?;
    let mut names_control = ControlCharge::try_new(
      tenant,
      payload_bytes::<String>(threads).map_err(AsyncError::ResourceDomain)?,
    )
    .map_err(AsyncError::ResourceDomain)?;
    let mut names = Vec::new();
    names
      .try_reserve_exact(threads)
      .map_err(|_| AsyncError::OutOfMemory)?;
    names_control
      .try_resize(payload_bytes::<String>(names.capacity()).map_err(AsyncError::ResourceDomain)?)
      .map_err(AsyncError::ResourceDomain)?;
    for context in thread_contexts(config.workers, max_handoffs) {
      let name = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        options.resolve_name(context)
      }));
      match name {
        Ok(Ok(name)) => {
          let charged = names_control
            .bytes()
            .checked_add(name.capacity())
            .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
          names_control
            .try_resize(charged)
            .map_err(AsyncError::ResourceDomain)?;
          names.push(name);
        }
        Ok(Err(())) => return Err(AsyncError::InvalidConfig),
        Err(payload) => {
          crate::runtime::task::drop_contained(payload);
          return Err(AsyncError::InvalidConfig);
        }
      }
    }
    let runtime_control_bytes = std::mem::size_of::<AsyncRuntime>()
      .checked_add(payload_bytes::<DeferredJoin>(threads).map_err(AsyncError::ResourceDomain)?)
      .and_then(|bytes| {
        payload_bytes::<Box<dyn Any + Send>>(threads)
          .ok()
          .and_then(|payload_bytes| bytes.checked_add(payload_bytes))
      })
      .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
    let mut runtime_control =
      ControlCharge::try_new(tenant, runtime_control_bytes).map_err(AsyncError::ResourceDomain)?;
    let launch_control = if let Some(tenant) = tenant {
      let launch_payload =
        payload_bytes::<(Arc<Shared>, AsyncThreadContext, Option<Arc<ControlCharge>>)>(threads)
          .map_err(AsyncError::ResourceDomain)?;
      let launch_bytes = std::mem::size_of::<ControlCharge>()
        .checked_add(launch_payload)
        .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
      Some(Arc::new(
        ControlCharge::try_new(Some(tenant), launch_bytes).map_err(AsyncError::ResourceDomain)?,
      ))
    } else {
      None
    };
    let (shared, root) = Shared::new(config, dispatch, max_handoffs, resources, options, metrics)?;
    let mut workers: Vec<DeferredJoin> = Vec::new();
    workers
      .try_reserve_exact(threads)
      .map_err(|_| AsyncError::OutOfMemory)?;
    let mut panic_payloads = Vec::new();
    panic_payloads
      .try_reserve_exact(threads)
      .map_err(|_| AsyncError::OutOfMemory)?;
    let actual_runtime_control = std::mem::size_of::<AsyncRuntime>()
      .checked_add(
        payload_bytes::<DeferredJoin>(workers.capacity()).map_err(AsyncError::ResourceDomain)?,
      )
      .and_then(|bytes| {
        payload_bytes::<Box<dyn Any + Send>>(panic_payloads.capacity())
          .ok()
          .and_then(|payload_bytes| bytes.checked_add(payload_bytes))
      })
      .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
    runtime_control
      .try_resize(actual_runtime_control)
      .map_err(AsyncError::ResourceDomain)?;
    for (index, name) in names.into_iter().enumerate() {
      let Some(prepared_join) = prepared_joins.pop() else {
        shared.close(true);
        for mut worker in workers {
          if let Err(payload) = worker.join_blocking() {
            drop_contained(payload);
          }
        }
        return Err(AsyncError::ResourceDomain(DomainError::Invalid));
      };
      let Some(context_control) = prepared_contexts.pop() else {
        shared.close(true);
        drop(prepared_join);
        for mut worker in workers {
          if let Err(payload) = worker.join_blocking() {
            drop_contained(payload);
          }
        }
        return Err(AsyncError::ResourceDomain(DomainError::Invalid));
      };
      let completion_owner = prepared_join.thread_owner();
      let thread_shared = Arc::clone(&shared);
      let thread_launch_control = launch_control.clone();
      let context = if index < config.workers {
        thread_options::AsyncThreadContext {
          role: thread_options::AsyncThreadRole::Worker,
          index,
          physical_index: index,
        }
      } else {
        thread_options::AsyncThreadContext {
          role: thread_options::AsyncThreadRole::HandoffHelper,
          index: index - config.workers,
          physical_index: index,
        }
      };
      let builder = thread::Builder::new().name(name);
      let builder = if let Some(size) = stack_size {
        builder.stack_size(size)
      } else {
        builder
      };
      let started = if context.role == thread_options::AsyncThreadRole::Worker {
        builder.spawn(move || {
          completion_owner.retain_until_thread_exit();
          let _launch_control = thread_launch_control;
          scheduler::worker(thread_shared, context, context_control)
        })
      } else {
        builder.spawn(move || {
          completion_owner.retain_until_thread_exit();
          let _launch_control = thread_launch_control;
          scheduler::helper(thread_shared, context, context_control)
        })
      };
      match started {
        Ok(worker) => workers.push(prepared_join.attach(worker)),
        Err(_) => {
          shared.close(true);
          drop(prepared_join);
          for mut worker in workers {
            if let Err(payload) = worker.join_blocking() {
              drop_contained(payload);
            }
          }
          return Err(AsyncError::OutOfMemory);
        }
      }
    }
    drop(prepared_joins);
    drop(prepared_contexts);
    drop(names_control);
    Ok(Self {
      shared,
      workers,
      panic_payloads: Mutex::new(panic_payloads),
      root,
      shutdown_complete: false,
      shutdown_panicked: false,
      _control: runtime_control,
      launch_control,
    })
  }

  /// A clonable handle to the runtime's implicit scope.
  #[must_use]
  pub fn handle(&self) -> AsyncHandle {
    AsyncHandle {
      shared: Arc::clone(&self.shared),
      scope: self.root,
      resources: self.shared.root_resources(),
      _scope_owner: None,
    }
  }

  /// Returns the dispatch mode chosen at construction.
  #[must_use]
  pub fn dispatch(&self) -> AsyncDispatch {
    self.shared.dispatch
  }

  /// Returns a cloneable diagnostic view that remains usable after shutdown.
  #[must_use]
  pub fn metrics(&self) -> RuntimeMetrics {
    self.shared.metrics.clone()
  }

  /// Polls a caller-owned future on this thread until it completes. The root
  /// future need not be `Send` or `'static`; spawned tasks remain owned and
  /// `Send + 'static`. Calling this from an executor worker or from another
  /// `block_on` on the same thread returns an error. This runtime-root poll
  /// has no task ID. A runtime created by the owning facade binds its root
  /// ledger for this poll; otherwise it clears any enclosing task's resource
  /// context until it returns.
  pub fn block_on<F: std::future::Future>(&self, future: F) -> Result<F::Output, AsyncError> {
    self.handle().block_on(future)
  }

  /// Creates an independently cancellable owned scope without a resource
  /// binding.
  pub fn scope(&self) -> Result<OwnedTaskScope, AsyncError> {
    self
      .shared
      .new_scope(self.shared.default_scope_poll_limit(), None)
  }

  /// Creates an independently cancellable owned scope with a per-scope
  /// simultaneous polling limit and no resource binding.
  pub fn scope_with_config(&self, config: AsyncScopeConfig) -> Result<OwnedTaskScope, AsyncError> {
    self.shared.new_scope(config.max_active_polls, None)
  }

  /// Creates an owned scope whose tasks may explicitly access `resources`
  /// through [`current_resource_scope`]. Only managed buffers and operation
  /// permits are charged; ordinary Rust allocations are unaffected.
  pub fn scope_with_resources(
    &self,
    resources: &ResourceScope,
  ) -> Result<OwnedTaskScope, AsyncError> {
    self.shared.new_scope(
      self.shared.default_scope_poll_limit(),
      Some(resources.clone()),
    )
  }

  /// Creates a resource-bound owned scope with an explicit active-poll limit.
  pub fn scope_with_config_and_resources(
    &self,
    config: AsyncScopeConfig,
    resources: &ResourceScope,
  ) -> Result<OwnedTaskScope, AsyncError> {
    self
      .shared
      .new_scope(config.max_active_polls, Some(resources.clone()))
  }

  /// Closes admission and joins every worker and handoff helper. Admitted
  /// tasks, including tasks inside a [`try_block_in_place`] closure, keep
  /// their turns: a handed-off closure is never interrupted, so this waits
  /// for blocked closures without a time limit. Called from one of this
  /// runtime's threads, handed-off closures included, it closes admission
  /// with cancellation and returns [`AsyncError::WouldDeadlock`] instead.
  pub fn shutdown(mut self, mode: AsyncShutdown) -> Result<(), AsyncError> {
    if scheduler::is_worker(&self.shared)
      || self.workers.iter().any(DeferredJoin::is_current_thread)
    {
      self.shared.close(true);
      return Err(AsyncError::WouldDeadlock);
    }
    self.shared.close(mode == AsyncShutdown::CancelPending);
    let mut panicked = false;
    while let Some(mut worker) = self.workers.pop() {
      if let Err(payload) = worker.join_blocking() {
        panicked = true;
        self.lock_panic_payloads().push(payload);
      }
    }
    drop(self.launch_control.take());
    let result = if panicked || self.shutdown_panicked {
      Err(AsyncError::WorkerPanicked)
    } else {
      Ok(())
    };
    self.drop_panic_payloads();
    result
  }

  /// Requests close without waiting for task polling or destructors. The
  /// owner remains available for [`AsyncRuntime::poll_shutdown`] until every
  /// worker and handoff helper has exited.
  pub(super) fn request_shutdown(&mut self, mode: AsyncShutdown) {
    self.shared.close(mode == AsyncShutdown::CancelPending);
  }

  /// Checks real worker completion without blocking. A small monitor joins
  /// each original worker so its thread-local destructors have finished
  /// before completion is published. `Pending` retains all remaining owners.
  /// If a worker panicked, its panic payload remains owned by this runtime
  /// until the runtime is explicitly shut down or dropped. Dropping that
  /// payload may run user code and block.
  pub(super) fn poll_shutdown(&mut self) -> Result<bool, AsyncError> {
    if self.shutdown_complete {
      return if self.shutdown_panicked {
        Err(AsyncError::WorkerPanicked)
      } else {
        Ok(true)
      };
    }
    let mut index = 0;
    while index < self.workers.len() {
      let result = self.workers[index]
        .try_join()
        .map_err(|_| AsyncError::JoinMonitorSpawnFailed)?;
      let Some(result) = result else {
        index += 1;
        continue;
      };

      // A DeferredJoin is one-shot: once its result is taken, remove it so a
      // later poll cannot start a second monitor for an already-consumed join.
      drop(self.workers.swap_remove(index));
      if let Err(payload) = result {
        self.shutdown_panicked = true;
        self.lock_panic_payloads().push(payload);
      }
    }
    if !self.workers.is_empty() {
      return Ok(false);
    }
    drop(self.launch_control.take());
    self.shutdown_complete = true;
    if self.shutdown_panicked {
      Err(AsyncError::WorkerPanicked)
    } else {
      Ok(true)
    }
  }

  pub(super) fn shutdown_complete(&self) -> bool {
    self.shutdown_complete
  }

  fn lock_panic_payloads(&self) -> MutexGuard<'_, Vec<Box<dyn Any + Send>>> {
    self
      .panic_payloads
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
  }

  fn drop_panic_payloads(&self) {
    loop {
      let payload = self.lock_panic_payloads().pop();
      let Some(payload) = payload else {
        break;
      };
      drop_contained(payload);
    }
  }
}

impl Drop for AsyncRuntime {
  fn drop(&mut self) {
    self.shared.close(true);
    // Dropping JoinHandles detaches. Runtime drop never blocks on user work.
    self.workers.clear();
    self.drop_panic_payloads();
  }
}

/// A clonable admission handle for one owned scope.
#[derive(Clone)]
pub struct AsyncHandle {
  shared: Arc<Shared>,
  scope: ScopeRef,
  resources: Option<ResourceScope>,
  _scope_owner: Option<Arc<scheduler::ScopeCell>>,
}

impl AsyncHandle {
  /// Returns a cloneable diagnostic view that remains usable after shutdown.
  #[must_use]
  pub fn metrics(&self) -> RuntimeMetrics {
    self.shared.metrics.clone()
  }
  /// Polls a caller-owned future on this thread until it completes. This
  /// borrowed root poll has no spawned task ID; if this handle belongs to a
  /// resource-bound scope, it exposes that explicitly bound resource ledger
  /// for the duration of the poll. See [`AsyncRuntime::block_on`] for the
  /// root-future and reentrancy contract.
  pub fn block_on<F: std::future::Future>(&self, future: F) -> Result<F::Output, AsyncError> {
    let control = self.shared.reserve_root_control(
      self.scope,
      self.resources.as_ref(),
      std::mem::size_of::<F>(),
    )?;
    let result = entry::block_on(self, future);
    drop(control);
    result
  }

  /// Enters this handle as the current runtime context on the calling thread.
  /// The current context is the most recently entered live guard. Dropping
  /// guards out of order removes only the dropped context.
  ///
  /// # Panics
  ///
  /// Panics when the bound tenant refuses the context node's Control charge.
  #[must_use]
  pub fn enter(&self) -> EnterGuard {
    EnterGuard::enter(self)
  }

  /// Tries to enter this handle as the current runtime context.
  pub fn try_enter(&self) -> Result<EnterGuard, AsyncError> {
    entry::EnterGuard::try_enter(self).map_err(AsyncError::ResourceDomain)
  }

  /// Returns the current entered handle, panicking when no context is active.
  #[must_use]
  pub fn current() -> Self {
    current()
  }

  /// Returns the current entered handle, if any.
  #[must_use]
  pub fn try_current() -> Option<Self> {
    try_current()
  }

  /// Admits an owned future, returning that unchanged future in the error
  /// when the runtime is closed or its outstanding-task bound is full.
  pub fn spawn<F>(&self, future: F) -> Result<AsyncJob<F::Output>, AsyncSpawnError<F>>
  where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
  {
    self.shared.spawn(self.scope, future)
  }
}

impl fmt::Debug for AsyncHandle {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AsyncHandle").finish_non_exhaustive()
  }
}

impl fmt::Debug for AsyncRuntime {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AsyncRuntime")
      .field("workers", &self.workers.len())
      .finish_non_exhaustive()
  }
}

#[cfg(all(test, not(loom)))]
mod completion_tests {
  use super::{AsyncConfig, AsyncRuntime, AsyncShutdown, AsyncThreadOptions, DeferredJoin};
  use crate::runtime::managed::{ResourceLimits, ResourceScope};
  use crate::runtime::resource_domain::payload_bytes;
  use crate::runtime::resource_domain::{
    DomainError, DomainResource, DomainResources, ResourceDomain,
  };
  use std::any::Any;
  use std::cell::RefCell;
  use std::sync::Arc;
  use std::sync::mpsc::{self, Receiver, SyncSender};
  use std::task::Poll;
  use std::thread;
  use std::time::{Duration, Instant};

  struct Gate {
    entered: SyncSender<()>,
    release: Receiver<()>,
  }

  impl Gate {
    fn wait(self) {
      let _ = self.entered.send(());
      let _ = self.release.recv_timeout(Duration::from_secs(4));
    }
  }

  struct WaitOnDrop(RefCell<Option<Gate>>);

  impl Drop for WaitOnDrop {
    fn drop(&mut self) {
      if let Some(gate) = self.0.get_mut().take() {
        gate.wait();
      }
    }
  }

  thread_local! {
    static NESTED_TLS: WaitOnDrop = const { WaitOnDrop(RefCell::new(None)) };
    static OUTER_TLS: OuterTls = const { OuterTls(RefCell::new(None)) };
  }

  struct OuterTls(RefCell<Option<Gate>>);

  impl Drop for OuterTls {
    fn drop(&mut self) {
      if let Some(gate) = self.0.get_mut().take() {
        NESTED_TLS.with(|slot| {
          *slot.0.borrow_mut() = Some(gate);
        });
      }
    }
  }

  fn wait_for_completion(runtime: &mut AsyncRuntime) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
      match runtime.poll_shutdown() {
        Ok(true) => return,
        Ok(false) if Instant::now() < deadline => thread::yield_now(),
        result => panic!("async worker completion did not finish: {result:?}"),
      }
    }
  }

  #[test]
  fn runtime_control_fee_uses_deferred_join_capacity() {
    let runtime = AsyncRuntime::new(AsyncConfig {
      workers: 2,
      max_outstanding: 2,
      max_scopes: 2,
    })
    .unwrap_or_else(|error| panic!("async runtime setup failed: {error}"));
    let panic_capacity = runtime
      .panic_payloads
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .capacity();
    let expected = std::mem::size_of::<AsyncRuntime>()
      + payload_bytes::<DeferredJoin>(runtime.workers.capacity())
        .unwrap_or_else(|error| panic!("worker payload size failed: {error}"))
      + payload_bytes::<Box<dyn Any + Send>>(panic_capacity)
        .unwrap_or_else(|error| panic!("panic payload size failed: {error}"));
    assert_eq!(runtime._control.bytes(), expected);
    runtime
      .shutdown(AsyncShutdown::Drain)
      .unwrap_or_else(|error| panic!("async shutdown failed: {error}"));
  }

  #[test]
  fn context_control_exhaustion_precedes_name_and_start_callbacks() {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 2)
      .with(DomainResource::Tasks, 8)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 4)
      .unwrap_or_else(|error| panic!("resource domain setup failed: {error}"));
    let tenant = domain
      .tenant(ceiling)
      .unwrap_or_else(|error| panic!("tenant setup failed: {error}"));
    let resources = ResourceScope::from_tenant(ResourceLimits::default(), tenant.clone());
    let domain_before = domain.snapshot();
    let tenant_before = tenant
      .snapshot()
      .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"));
    domain
      .set_limits(domain_before.limit.with(
        DomainResource::Control,
        domain_before.used.get(DomainResource::Control),
      ))
      .unwrap_or_else(|error| panic!("global Control clamp failed: {error}"));
    tenant
      .set_limits(tenant_before.limit.with(
        DomainResource::Control,
        tenant_before.used.get(DomainResource::Control),
      ))
      .unwrap_or_else(|error| panic!("tenant Control clamp failed: {error}"));

    let name_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let start_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let name_count = Arc::clone(&name_calls);
    let start_count = Arc::clone(&start_calls);
    let options = AsyncThreadOptions::new()
      .thread_name_fn(move |_| {
        name_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        String::from("prepared-control-test")
      })
      .on_thread_start(move |_| {
        start_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
      });
    let error = AsyncRuntime::with_resources_and_thread_options(
      AsyncConfig {
        workers: 1,
        max_outstanding: 2,
        max_scopes: 2,
      },
      resources,
      options,
    )
    .err()
    .unwrap_or_else(|| panic!("prepared completion Control exhaustion was ignored"));
    assert_eq!(
      error,
      super::AsyncError::ResourceDomain(DomainError::Exhausted(DomainResource::Control))
    );
    assert_eq!(name_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(start_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(domain.snapshot().used, domain_before.used);
    assert_eq!(
      tenant
        .snapshot()
        .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"))
        .used,
      tenant_before.used
    );
  }

  #[test]
  fn polling_removes_a_completed_nested_tls_worker_slot_once() {
    let mut runtime = AsyncRuntime::new(AsyncConfig {
      workers: 1,
      max_outstanding: 2,
      max_scopes: 2,
    })
    .unwrap_or_else(|error| panic!("async runtime setup failed: {error}"));
    let handle = runtime.handle();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::channel();
    let mut gate = Some(Gate {
      entered: entered_tx,
      release: release_rx,
    });
    let job = handle
      .spawn(std::future::poll_fn(move |_| {
        if let Some(gate) = gate.take() {
          OUTER_TLS.with(|slot| {
            *slot.0.borrow_mut() = Some(gate);
          });
        }
        Poll::Ready(())
      }))
      .unwrap_or_else(|error| panic!("async task admission failed: {error}"));
    handle
      .block_on(job)
      .unwrap_or_else(|error| panic!("async task wait failed: {error}"))
      .unwrap_or_else(|error| panic!("async task failed: {error}"));

    runtime.request_shutdown(AsyncShutdown::Drain);
    entered_rx
      .recv_timeout(Duration::from_secs(3))
      .unwrap_or_else(|error| panic!("nested TLS destructor did not start: {error}"));
    assert!(
      !runtime
        .poll_shutdown()
        .unwrap_or_else(|error| panic!("async shutdown poll failed: {error}"))
    );
    assert_eq!(runtime.workers.len(), 1);

    release_tx
      .send(())
      .unwrap_or_else(|error| panic!("nested TLS destructor release failed: {error}"));
    wait_for_completion(&mut runtime);
    assert!(runtime.workers.is_empty());
    assert!(
      runtime
        .poll_shutdown()
        .unwrap_or_else(|error| panic!("repeated async shutdown poll failed: {error}"))
    );
  }
}
