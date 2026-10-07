//! A bounded, owned-future executor. This is an experimental foundation;
//! it does not provide I/O, borrowed spawned tasks, or Tokio compatibility.
//! [`AsyncRuntime::block_on`] may poll one borrowed or non-`Send` root future
//! on its caller thread. Spawned work remains owned and `Send + 'static`.
//! Runtime-owned outer polls enable a shared 64-operation cooperative budget
//! for ready channel, oneshot, semaphore, mutex, reader-writer-lock, notify,
//! watch, broadcast, and barrier futures. The budget is scoped to those polls;
//! manually polled primitives and futures polled by another executor bypass
//! automatic accounting.
//! [`yield_now`] schedules one self-wake; [`consume_budget`] remains an
//! explicit checkpoint for other long-running future work. No checkpoint
//! preempts synchronous code or arbitrary futures that never yield.
//! [`try_block_in_place`] runs a blocking closure on its caller's thread; a
//! runtime built with [`AsyncRuntime::new_with_handoffs`] keeps dispatching
//! on a bounded set of prestarted helpers meanwhile.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

mod entry;
mod handoff;
mod handoff_protocol;
mod identity;
mod join;
mod local;
mod protocol;
mod scheduler;
mod task;
mod task_set;

#[cfg(all(test, not(loom)))]
mod cooperative_tests;
#[cfg(all(test, not(loom)))]
mod handoff_tests;
#[cfg(all(test, not(loom)))]
mod tests;

use std::fmt;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crate::runtime::managed::ResourceScope;
use scheduler::{ScopeRef, Shared};

pub(super) use entry::poll_cooperative;
pub use entry::{
  ConsumeBudget, EnterGuard, YieldNow, consume_budget, current, current_resource_scope, task_id,
  try_current, try_current_resource_scope, try_task_id, yield_now,
};
pub use handoff::{BlockInPlaceError, BlockInPlaceErrorKind, HandoffConfig, try_block_in_place};
pub use identity::TaskId;
pub use join::{AbortHandle, AsyncJob, AsyncJoinError};
pub use local::{
  LocalConfig, LocalEnterGuard, LocalError, LocalHandle, LocalRuntime, LocalScopeClose,
  LocalSendHandle, LocalSpawnError, LocalTaskScope,
};
pub use scheduler::{OwnedTaskScope, ScopeClose};
pub use task_set::{JoinNext, SetTaskId, TaskSet, TaskSetError};

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
  /// return, sampled under the scheduler lock with `max_active_polls`.
  /// A reserved task may be about to enter its poll call.
  pub active_polls: usize,
  /// The configured active-poll limit for this scope.
  pub max_active_polls: usize,
}

/// Construction, admission, block-on entry, or shutdown failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AsyncError {
  /// A required bound is zero or cannot be represented by the runtime.
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
  /// The process-wide task identifier space is exhausted.
  TaskIdExhausted,
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
      Self::TaskIdExhausted => "process-wide async task identifiers are exhausted",
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
  workers: Vec<JoinHandle<()>>,
  root: ScopeRef,
}

impl AsyncRuntime {
  /// Reserves all bounded scheduler tables before starting worker threads.
  /// The runtime has exactly `config.workers` threads and no handoff slots:
  /// [`try_block_in_place`] on one of its turns returns
  /// [`BlockInPlaceErrorKind::Disabled`].
  pub fn new(config: AsyncConfig) -> Result<Self, AsyncError> {
    Self::start(config, 0)
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
    if handoffs.max_handoffs == 0 {
      return Err(AsyncError::InvalidConfig);
    }
    Self::start(config, handoffs.max_handoffs)
  }

  fn start(config: AsyncConfig, max_handoffs: usize) -> Result<Self, AsyncError> {
    if config.workers == 0 || config.max_outstanding == 0 || config.max_scopes == 0 {
      return Err(AsyncError::InvalidConfig);
    }
    let Some(threads) = config.workers.checked_add(max_handoffs) else {
      return Err(AsyncError::InvalidConfig);
    };
    let (shared, root) = Shared::new(config, max_handoffs)?;
    let mut workers = Vec::new();
    workers
      .try_reserve_exact(threads)
      .map_err(|_| AsyncError::OutOfMemory)?;
    for index in 0..threads {
      let thread_shared = Arc::clone(&shared);
      let started = if index < config.workers {
        thread::Builder::new()
          .name(format!("allocatbelt-async-{index}"))
          .spawn(move || scheduler::worker(thread_shared, index))
      } else {
        // Helpers continue the workers' shard hints, one per thread.
        thread::Builder::new()
          .name(format!(
            "allocatbelt-async-handoff-{}",
            index - config.workers
          ))
          .spawn(move || scheduler::helper(thread_shared, index))
      };
      match started {
        Ok(worker) => workers.push(worker),
        Err(_) => {
          shared.close(true);
          for worker in workers {
            let _ = worker.join();
          }
          return Err(AsyncError::OutOfMemory);
        }
      }
    }
    Ok(Self {
      shared,
      workers,
      root,
    })
  }

  /// A clonable handle to the runtime's implicit scope.
  #[must_use]
  pub fn handle(&self) -> AsyncHandle {
    AsyncHandle {
      shared: Arc::clone(&self.shared),
      scope: self.root,
      resources: None,
    }
  }

  /// Polls a caller-owned future on this thread until it completes. The root
  /// future need not be `Send` or `'static`; spawned tasks remain owned and
  /// `Send + 'static`. Calling this from an executor worker or from another
  /// `block_on` on the same thread returns an error. This runtime-root poll
  /// has no task ID or managed-resource binding, and clears any enclosing
  /// task's resource context until it returns.
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
    if scheduler::is_worker(&self.shared) {
      self.shared.close(true);
      return Err(AsyncError::WouldDeadlock);
    }
    self.shared.close(mode == AsyncShutdown::CancelPending);
    let mut panicked = false;
    for worker in self.workers.drain(..) {
      panicked |= worker.join().is_err();
    }
    if panicked {
      Err(AsyncError::WorkerPanicked)
    } else {
      Ok(())
    }
  }
}

impl Drop for AsyncRuntime {
  fn drop(&mut self) {
    self.shared.close(true);
    // Dropping JoinHandles detaches. Runtime drop never blocks on user work.
    self.workers.clear();
  }
}

/// A clonable admission handle for one owned scope.
#[derive(Clone)]
pub struct AsyncHandle {
  shared: Arc<Shared>,
  scope: ScopeRef,
  resources: Option<ResourceScope>,
}

impl AsyncHandle {
  /// Polls a caller-owned future on this thread until it completes. This
  /// borrowed root poll has no spawned task ID; if this handle belongs to a
  /// resource-bound scope, it exposes that explicitly bound resource ledger
  /// for the duration of the poll. See [`AsyncRuntime::block_on`] for the
  /// root-future and reentrancy contract.
  pub fn block_on<F: std::future::Future>(&self, future: F) -> Result<F::Output, AsyncError> {
    entry::block_on(self, future)
  }

  /// Enters this handle as the current runtime context on the calling thread.
  /// The current context is the most recently entered live guard. Dropping
  /// guards out of order removes only the dropped context.
  #[must_use]
  pub fn enter(&self) -> EnterGuard {
    EnterGuard::enter(self)
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
