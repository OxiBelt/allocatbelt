//! The runtime: its configuration, worker threads, submission handles and
//! shutdown.

use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::thread::{self, JoinHandle};

use crate::error::SubmitError;
use crate::job::{CancellationToken, Job};
use crate::resources::Resources;
use crate::scheduler::{Shared, Snapshot};
use crate::worker;

/// A runtime's size and bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
  /// Worker threads; at least 1. Worker `i` prefers allocatbelt shard `i`.
  pub workers: usize,
  /// Jobs admitted and not yet released (queued, running or cancelling);
  /// at least 1.
  pub max_outstanding: usize,
  /// Resources the outstanding jobs may reserve together.
  pub capacity: Resources,
}

/// How [`Runtime::shutdown`] treats admitted jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownMode {
  /// Run every admitted job (except those cancelled through their handle)
  /// and wait for them.
  Drain,
  /// Drop the queued jobs unstarted (their joins return
  /// [`JoinError::Cancelled`](crate::JoinError::Cancelled) once each
  /// closure is dropped and its admission released). Signal the
  /// [`CancellationToken`]s of the jobs queued or running at that point,
  /// and wait for the running ones to return. Cancellation is cooperative:
  /// running closures are not preempted.
  CancelPending,
}

/// A fixed pool of worker threads running submitted closures in FIFO
/// order, under an outstanding-job bound and a resource capacity.
///
/// Dropping a runtime that was not shut down does not join its workers. It
/// closes the runtime and signals the running jobs' tokens. It drops the
/// queued jobs' closures unstarted, synchronously on the dropping thread,
/// so a capture's `Drop` that blocks also blocks the drop. Then it
/// detaches the worker threads, which exit after their current job.
/// Running jobs may outlive the runtime; call [`Runtime::shutdown`] to wait
/// for them.
pub struct Runtime {
  shared: Arc<Shared>,
  workers: Vec<JoinHandle<()>>,
}

/// A cloneable, thread-safe submission handle. Submissions after the
/// runtime closed (or was dropped) are rejected as
/// [`SubmitErrorKind::Closed`](crate::SubmitErrorKind::Closed).
#[derive(Clone)]
pub struct Handle {
  shared: Arc<Shared>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

impl Runtime {
  /// Starts `config.workers` worker threads.
  ///
  /// # Errors
  ///
  /// `InvalidInput` for zero workers or a zero outstanding bound, or the
  /// error of a failed thread spawn, after the workers already started
  /// were stopped and joined. `Other` once the process created
  /// `u64::MAX - 2` runtimes, rather than reuse an id.
  pub fn new(config: Config) -> io::Result<Self> {
    Self::with_spawner(config, |builder, f| builder.spawn(f), |_| {})
  }

  /// [`Runtime::new`] with the thread spawn replaceable and the shared
  /// state adjustable before any worker starts, for the tests.
  pub(crate) fn with_spawner(
    config: Config,
    mut spawn: impl FnMut(thread::Builder, Box<dyn FnOnce() + Send>) -> io::Result<JoinHandle<()>>,
    setup: impl FnOnce(&mut Shared),
  ) -> io::Result<Self> {
    if config.workers == 0 || config.max_outstanding == 0 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "workers and max_outstanding must be at least 1",
      ));
    }
    let id = worker::next_id(&NEXT_ID).ok_or_else(|| io::Error::other("runtime ids exhausted"))?;
    let mut shared = Shared::new(id, config.workers, config.max_outstanding, config.capacity);
    setup(&mut shared);
    let shared = Arc::new(shared);
    let mut workers = Vec::with_capacity(config.workers);
    for index in 0..config.workers {
      let worker_shared = Arc::clone(&shared);
      let spawned = spawn(
        thread::Builder::new().name(format!("allocatbelt-runtime-{index}")),
        Box::new(move || worker::run(&worker_shared, index)),
      );
      match spawned {
        Ok(handle) => workers.push(handle),
        Err(error) => {
          // No job was admitted yet: the started workers are idle.
          let _ = shared.close(true);
          for handle in workers {
            let _ = handle.join();
          }
          return Err(error);
        }
      }
    }
    Ok(Self { shared, workers })
  }

  /// A submission handle for other threads, workers included.
  #[must_use]
  pub fn handle(&self) -> Handle {
    Handle {
      shared: Arc::clone(&self.shared),
    }
  }

  /// Admits `f` with `request` reserved, or returns it. See
  /// [`Handle::try_spawn`].
  ///
  /// # Errors
  ///
  /// See [`Handle::try_spawn`].
  pub fn try_spawn<F, T>(&self, request: Resources, f: F) -> Result<Job<T>, SubmitError<F>>
  where
    F: FnOnce(CancellationToken) -> T + Send + 'static,
    T: Send + 'static,
  {
    self.shared.try_spawn(request, f)
  }

  /// The current accounting.
  #[must_use]
  pub fn snapshot(&self) -> Snapshot {
    self.shared.snapshot()
  }

  /// Closes the runtime and waits for its workers to exit.
  ///
  /// With [`ShutdownMode::Drain`] every admitted job runs first; with
  /// [`ShutdownMode::CancelPending`] queued jobs are dropped unstarted, on
  /// this thread, and running ones see their token cancelled but are not
  /// preempted. Once a shutdown has returned, the runtime is finished and
  /// later calls (either mode) and the runtime's drop do nothing: they
  /// change no token, not even of a job a `Drain` ran.
  ///
  /// # Errors
  ///
  /// `Deadlock` when called from one of this runtime's workers (it would
  /// wait for itself); nothing is closed then. `Other` if a worker thread
  /// panicked outside a job, after every worker was joined; the runtime is
  /// finished all the same.
  pub fn shutdown(&mut self, mode: ShutdownMode) -> io::Result<()> {
    if self.workers.is_empty() {
      return Ok(());
    }
    if worker::is_worker_of(self.shared.ident.id) {
      return Err(io::Error::new(
        io::ErrorKind::Deadlock,
        "shutdown called from one of the runtime's own workers",
      ));
    }
    worker::abandon_all(
      &self.shared,
      self.shared.close(mode == ShutdownMode::CancelPending),
    );
    let mut panicked = false;
    for handle in self.workers.drain(..) {
      panicked |= handle.join().is_err();
    }
    if panicked {
      return Err(io::Error::other("a runtime worker panicked"));
    }
    Ok(())
  }
}

impl Handle {
  /// Admits `f` with `request` reserved in full until it returns, or
  /// returns `f` in the error. Never blocks on the queue.
  ///
  /// # Errors
  ///
  /// [`SubmitErrorKind`](crate::SubmitErrorKind): `Closed`, then
  /// `InvalidRequest` (exceeds the capacity), `Full` (the outstanding bound
  /// is reached), `InsufficientResources` (does not fit what is free now).
  pub fn try_spawn<F, T>(&self, request: Resources, f: F) -> Result<Job<T>, SubmitError<F>>
  where
    F: FnOnce(CancellationToken) -> T + Send + 'static,
    T: Send + 'static,
  {
    self.shared.try_spawn(request, f)
  }

  /// The current accounting.
  #[must_use]
  pub fn snapshot(&self) -> Snapshot {
    self.shared.snapshot()
  }
}

impl Drop for Runtime {
  fn drop(&mut self) {
    if !self.workers.is_empty() {
      worker::abandon_all(&self.shared, self.shared.close(true));
      // Dropping the handles detaches the threads.
      self.workers.clear();
    }
  }
}

impl std::fmt::Debug for Runtime {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Runtime")
      .field("snapshot", &self.snapshot())
      .finish_non_exhaustive()
  }
}

impl std::fmt::Debug for Handle {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Handle").finish_non_exhaustive()
  }
}
