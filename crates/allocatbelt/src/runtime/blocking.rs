//! The runtime: its configuration, worker threads, submission handles and
//! shutdown.

use std::any::Any;
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};

use crate::runtime::error::SubmitError;
use crate::runtime::job::{CancellationToken, Job};
use crate::runtime::managed::ResourceScope;
use crate::runtime::resources::Resources;
use crate::runtime::scheduler::{Entry, Shared, Snapshot};
use crate::runtime::task::drop_contained;
use crate::runtime::time::TimerHandle;
use crate::runtime::worker;

/// A runtime's size and bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
  /// Worker threads; at least 1. Worker `i` prefers allocatbelt shard `i`.
  pub workers: usize,
  /// Jobs admitted and not yet released (queued, running or cancelling);
  /// at least 1.
  /// The FIFO queue reserves storage for all configured jobs before workers start.
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
  /// [`JoinError::Cancelled`](crate::runtime::JoinError::Cancelled) once each
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
/// A panic payload retained by a prior nonblocking shutdown check is also
/// dropped here; its destructor can block.
/// Running jobs may outlive the runtime; call [`Runtime::shutdown`] to wait
/// for them.
pub struct Runtime {
  shared: Arc<Shared>,
  workers: Vec<JoinHandle<()>>,
  panic_payloads: Mutex<Vec<Box<dyn Any + Send>>>,
  shutdown_pending: Mutex<VecDeque<Entry>>,
  shutdown_requested: bool,
  shutdown_complete: bool,
  shutdown_panicked: bool,
}

/// A cloneable, thread-safe submission handle. Submissions after the
/// runtime closed (or was dropped) are rejected as
/// [`SubmitErrorKind::Closed`](crate::runtime::SubmitErrorKind::Closed).
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
  /// `InvalidInput` for zero workers or a zero outstanding bound;
  /// `OutOfMemory` if reserving the bounded queue or worker storage fails,
  /// including when its requested capacity cannot be represented, before any
  /// worker starts; or the
  /// error of a failed thread spawn, after the workers already started
  /// were stopped and joined. `Other` once the process created
  /// `u64::MAX - 2` runtimes, rather than reuse an id.
  pub fn new(config: Config) -> io::Result<Self> {
    Self::with_spawner_and_resources(config, None, |builder, f| builder.spawn(f), |_| {})
  }

  /// Starts a pool whose admitted closures take Tasks and active CPU charges
  /// from the tenant bound to resources. Its waiter share is reserved before
  /// worker startup; failure returns before any worker is exposed.
  pub(crate) fn with_resources(config: Config, resources: ResourceScope) -> io::Result<Self> {
    Self::with_spawner_and_resources(
      config,
      Some(resources),
      |builder, f| builder.spawn(f),
      |_| {},
    )
  }

  /// Associates facade-owned blocking admissions with a paused-auto clock.
  /// The facade calls this before exposing any blocking handle. Low-level
  /// runtimes created with [`Runtime::new`] remain unassociated.
  pub(crate) fn bind_clock(&mut self, timer: TimerHandle) {
    self.shared.bind_clock(timer);
  }

  /// [`Runtime::new`] with the thread spawn replaceable and the shared
  /// state adjustable before any worker starts, for the tests.
  #[cfg(test)]
  pub(crate) fn with_spawner(
    config: Config,
    spawn: impl FnMut(thread::Builder, Box<dyn FnOnce() + Send>) -> io::Result<JoinHandle<()>>,
    setup: impl FnOnce(&mut Shared),
  ) -> io::Result<Self> {
    Self::with_spawner_and_resources(config, None, spawn, setup)
  }

  fn with_spawner_and_resources(
    config: Config,
    resources: Option<ResourceScope>,
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
    let mut shared = Shared::new(
      id,
      config.workers,
      config.max_outstanding,
      config.capacity,
      resources,
    )?;
    setup(&mut shared);
    let shared = Arc::new(shared);
    let mut workers = Vec::new();
    workers
      .try_reserve_exact(config.workers)
      .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    let mut panic_payloads = Vec::new();
    panic_payloads
      .try_reserve_exact(config.workers)
      .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
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
    Ok(Self {
      shared,
      workers,
      panic_payloads: Mutex::new(panic_payloads),
      shutdown_pending: Mutex::new(VecDeque::new()),
      shutdown_requested: false,
      shutdown_complete: false,
      shutdown_panicked: false,
    })
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
      if !self.lock_shutdown_pending().is_empty() {
        worker::abandon_all(&self.shared, self.take_shutdown_pending());
        self.shutdown_complete = true;
      }
      if !self.lock_panic_payloads().is_empty() {
        self.shutdown_complete = true;
        self.shutdown_panicked = true;
        self.drop_panic_payloads();
        return Err(io::Error::other("a runtime worker panicked"));
      }
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
    worker::abandon_all(&self.shared, self.take_shutdown_pending());
    let mut panicked = false;
    for handle in std::mem::take(&mut self.workers) {
      if let Err(payload) = handle.join() {
        panicked = true;
        self.lock_panic_payloads().push(payload);
      }
    }
    self.shutdown_requested = true;
    self.shutdown_complete = true;
    self.shutdown_panicked |= panicked;
    self.drop_panic_payloads();
    if self.shutdown_panicked {
      return Err(io::Error::other("a runtime worker panicked"));
    }
    Ok(())
  }

  /// Closes admission and signals cancellation without running queued job
  /// destructors on the caller. The returned queue remains owned by this
  /// runtime until later [`Runtime::poll_shutdown`] calls abandon it.
  pub(crate) fn request_shutdown(&mut self, mode: ShutdownMode) -> io::Result<()> {
    if self.shutdown_complete || self.shutdown_requested {
      return Ok(());
    }
    if worker::is_worker_of(self.shared.ident.id) {
      return Err(io::Error::new(
        io::ErrorKind::Deadlock,
        "shutdown called from one of the runtime's own workers",
      ));
    }
    let pending = self.shared.close(mode == ShutdownMode::CancelPending);
    *self.lock_shutdown_pending() = pending;
    self.shutdown_requested = true;
    Ok(())
  }

  /// Drops at most one queued job, then checks whether all workers and
  /// retained queue cleanup have actually completed. A job capture's
  /// destructor may take unbounded time while one item is abandoned, so this
  /// explicit cleanup step is separate from the facade's status check.
  pub(crate) fn drive_shutdown_step(&mut self) -> io::Result<bool> {
    if self.shutdown_complete {
      return if self.shutdown_panicked {
        Err(io::Error::other("a runtime worker panicked"))
      } else {
        Ok(true)
      };
    }
    if !self.shutdown_requested {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "shutdown has not been requested",
      ));
    }
    let pending = { self.lock_shutdown_pending().pop_front() };
    if let Some(entry) = pending {
      let _cleaning = worker::Cleaning::enter(&self.shared.ident);
      worker::abandon(&self.shared, entry);
      return Ok(false);
    }
    self.poll_shutdown()
  }

  /// Checks completion without dropping queued job captures. It joins workers
  /// only after every queued cancellation owner is cleaned and every worker
  /// has actually exited. Worker panic payloads stay owned by this runtime;
  /// their destructors may run when it is explicitly shut down or dropped.
  pub(crate) fn poll_shutdown(&mut self) -> io::Result<bool> {
    if self.shutdown_complete {
      return if self.shutdown_panicked {
        Err(io::Error::other("a runtime worker panicked"))
      } else {
        Ok(true)
      };
    }
    if !self.shutdown_requested {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "shutdown has not been requested",
      ));
    }
    if !self.lock_shutdown_pending().is_empty()
      || self.workers.iter().any(|worker| !worker.is_finished())
    {
      return Ok(false);
    }
    for worker in std::mem::take(&mut self.workers) {
      if let Err(payload) = worker.join() {
        self.shutdown_panicked = true;
        self.lock_panic_payloads().push(payload);
      }
    }
    self.shutdown_complete = true;
    if self.shutdown_panicked {
      Err(io::Error::other("a runtime worker panicked"))
    } else {
      Ok(true)
    }
  }

  pub(crate) fn shutdown_complete(&self) -> bool {
    self.shutdown_complete
  }

  fn lock_shutdown_pending(&self) -> MutexGuard<'_, VecDeque<Entry>> {
    self
      .shutdown_pending
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
  }

  fn take_shutdown_pending(&self) -> VecDeque<Entry> {
    std::mem::take(&mut *self.lock_shutdown_pending())
  }

  fn take_panic_payloads(&self) -> Vec<Box<dyn Any + Send>> {
    std::mem::take(&mut *self.lock_panic_payloads())
  }

  fn drop_panic_payloads(&self) {
    for payload in self.take_panic_payloads() {
      drop_contained(payload);
    }
  }

  fn lock_panic_payloads(&self) -> MutexGuard<'_, Vec<Box<dyn Any + Send>>> {
    self
      .panic_payloads
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
  }
}

impl Handle {
  /// Admits `f` with `request` reserved in full until it returns, or
  /// returns `f` in the error. Never blocks on the queue.
  ///
  /// # Errors
  ///
  /// [`SubmitErrorKind`](crate::runtime::SubmitErrorKind): `Closed`, then
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
    worker::abandon_all(&self.shared, self.take_shutdown_pending());
    self.drop_panic_payloads();
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

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::mpsc;
  use std::time::{Duration, Instant};

  struct PanicOnDrop;

  impl Drop for PanicOnDrop {
    fn drop(&mut self) {
      panic!("retained worker panic payload destructor panicked");
    }
  }

  struct DropSignal(mpsc::SyncSender<()>);

  impl Drop for DropSignal {
    fn drop(&mut self) {
      let _ = self.0.send(());
    }
  }

  #[test]
  fn drop_contains_payload_destructor_panic_and_continues_cleanup() {
    let (cleanup_tx, cleanup_rx) = mpsc::sync_channel(1);
    let mut next_worker = 0;
    let mut cleanup_tx = Some(cleanup_tx);
    let mut runtime = Runtime::with_spawner(
      Config {
        workers: 2,
        max_outstanding: 1,
        capacity: Resources::ZERO,
      },
      move |builder, _worker| {
        let index = next_worker;
        next_worker += 1;
        if index == 0 {
          builder.spawn(|| std::panic::panic_any(PanicOnDrop))
        } else {
          let Some(cleanup_tx) = cleanup_tx.take() else {
            return Err(io::Error::other("unexpected extra worker"));
          };
          builder.spawn(move || std::panic::panic_any(DropSignal(cleanup_tx)))
        }
      },
      |_| {},
    )
    .unwrap_or_else(|error| panic!("blocking runtime build failed: {error}"));
    runtime
      .request_shutdown(ShutdownMode::Drain)
      .unwrap_or_else(|error| panic!("shutdown request failed: {error}"));

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      match runtime.poll_shutdown() {
        Err(error) => {
          assert_eq!(error.kind(), io::ErrorKind::Other);
          break;
        }
        Ok(false) if Instant::now() < deadline => thread::yield_now(),
        result => panic!("unexpected shutdown status: {result:?}"),
      }
    }
    let repeated = runtime
      .poll_shutdown()
      .err()
      .unwrap_or_else(|| panic!("worker panic error was not retained"));
    assert_eq!(repeated.kind(), io::ErrorKind::Other);

    drop(runtime);
    cleanup_rx
      .recv_timeout(Duration::from_secs(2))
      .unwrap_or_else(|error| panic!("remaining payload cleanup did not run: {error}"));
  }
}
