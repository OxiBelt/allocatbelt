//! A bounded, owned-future executor. This is an experimental foundation:
//! it does not provide timers, I/O, borrowed tasks, or Tokio compatibility.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

mod join;
mod protocol;
mod scheduler;
mod task;

#[cfg(all(test, not(loom)))]
mod tests;

use std::fmt;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use scheduler::{ScopeRef, Shared};

pub use join::{AsyncJob, AsyncJoinError};
pub use scheduler::{OwnedTaskScope, ScopeClose};

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

/// Construction, admission, or shutdown failure.
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
  /// A worker exited unexpectedly.
  WorkerPanicked,
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
      Self::WorkerPanicked => "an async worker exited unexpectedly",
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
  pub fn new(config: AsyncConfig) -> Result<Self, AsyncError> {
    if config.workers == 0 || config.max_outstanding == 0 || config.max_scopes == 0 {
      return Err(AsyncError::InvalidConfig);
    }
    let (shared, root) = Shared::new(config)?;
    let mut workers = Vec::new();
    workers
      .try_reserve_exact(config.workers)
      .map_err(|_| AsyncError::OutOfMemory)?;
    for index in 0..config.workers {
      let worker_shared = Arc::clone(&shared);
      match thread::Builder::new()
        .name(format!("allocatbelt-async-{index}"))
        .spawn(move || scheduler::worker(worker_shared, index))
      {
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
    }
  }

  /// Creates an independently cancellable owned scope.
  pub fn scope(&self) -> Result<OwnedTaskScope, AsyncError> {
    self.shared.new_scope()
  }

  /// Closes admission and joins every worker.
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
}

impl AsyncHandle {
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
