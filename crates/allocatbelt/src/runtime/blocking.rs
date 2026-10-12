//! The runtime: its configuration, worker threads, submission handles and
//! shutdown.

use std::any::Any;
use std::io;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};

use crate::runtime::error::SubmitError;
use crate::runtime::job::{CancellationToken, Job};
use crate::runtime::managed::ResourceScope;
use crate::runtime::resource_domain::{ControlCharge, DomainError, payload_bytes};
use crate::runtime::resources::Resources;
use crate::runtime::scheduler::{ClosedQueue, Shared, Snapshot, domain_build_error};
use crate::runtime::task::drop_contained;
use crate::runtime::thread_completion::{DeferredJoin, MonitorSpawnError};
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
  workers: Vec<DeferredJoin>,
  panic_payloads: Mutex<Vec<Box<dyn Any + Send>>>,
  shutdown_pending: Mutex<ClosedQueue>,
  shutdown_requested: bool,
  shutdown_complete: bool,
  shutdown_panicked: bool,
  _control: ControlCharge,
  launch_control: Option<Arc<ControlCharge>>,
}

/// A cloneable, thread-safe submission handle. Submissions after the
/// runtime closed (or was dropped) are rejected as
/// [`SubmitErrorKind::Closed`](crate::runtime::SubmitErrorKind::Closed).
#[derive(Clone)]
pub struct Handle {
  shared: Arc<Shared>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn control_build_error(error: DomainError, bound: bool) -> io::Error {
  if !bound && matches!(error, DomainError::Invalid) {
    io::ErrorKind::OutOfMemory.into()
  } else {
    domain_build_error(error)
  }
}

fn abandon_closed_queue(shared: &Shared, pending: ClosedQueue) {
  let (entries, control) = pending.into_parts();
  worker::abandon_all(shared, entries);
  drop(control);
}

fn stop_started_workers(shared: &Shared, workers: &mut Vec<DeferredJoin>) {
  abandon_closed_queue(shared, shared.close(true));
  while let Some(mut worker) = workers.pop() {
    if let Err(payload) = worker.join_blocking() {
      drop_contained(payload);
    }
  }
}

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
    let tenant = resources
      .as_ref()
      .and_then(ResourceScope::tenant_domain)
      .cloned();
    let bound = tenant.is_some();
    let name_bound = "allocatbelt-runtime-"
      .len()
      .checked_add(std::mem::size_of::<usize>() * 3)
      .ok_or_else(|| control_build_error(DomainError::Invalid, bound))?;
    let worker_bytes = payload_bytes::<DeferredJoin>(config.workers)
      .map_err(|error| control_build_error(error, bound))?;
    let panic_bytes = payload_bytes::<Box<dyn Any + Send>>(config.workers)
      .map_err(|error| control_build_error(error, bound))?;
    let persistent_bytes = std::mem::size_of::<Runtime>()
      .checked_add(worker_bytes)
      .and_then(|bytes| bytes.checked_add(panic_bytes))
      .ok_or_else(|| control_build_error(DomainError::Invalid, bound))?;
    let startup_bytes = name_bound
      .checked_add(std::mem::size_of::<thread::Builder>())
      .ok_or_else(|| control_build_error(DomainError::Invalid, bound))?;
    let runtime_bytes = persistent_bytes
      .checked_add(startup_bytes)
      .ok_or_else(|| control_build_error(DomainError::Invalid, bound))?;
    let mut runtime_control = ControlCharge::try_new(tenant.as_ref(), runtime_bytes)
      .map_err(|error| control_build_error(error, bound))?;
    let launch_control = if let Some(tenant) = tenant.as_ref() {
      let launch_bytes = std::mem::size_of::<ControlCharge>()
        .checked_add(
          payload_bytes::<(Arc<Shared>, usize, Option<Arc<ControlCharge>>)>(config.workers)
            .map_err(|error| control_build_error(error, bound))?,
        )
        .ok_or_else(|| control_build_error(DomainError::Invalid, bound))?;
      Some(Arc::new(
        ControlCharge::try_new(Some(tenant), launch_bytes)
          .map_err(|error| control_build_error(error, bound))?,
      ))
    } else {
      None
    };
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
    let actual_persistent_bytes = std::mem::size_of::<Runtime>()
      .checked_add(
        payload_bytes::<DeferredJoin>(workers.capacity())
          .map_err(|error| control_build_error(error, bound))?,
      )
      .and_then(|bytes| {
        payload_bytes::<Box<dyn Any + Send>>(panic_payloads.capacity())
          .ok()
          .and_then(|payload_bytes| bytes.checked_add(payload_bytes))
      })
      .ok_or_else(|| control_build_error(DomainError::Invalid, bound))?;
    let actual_startup_bytes = name_bound
      .checked_add(std::mem::size_of::<thread::Builder>())
      .ok_or_else(|| control_build_error(DomainError::Invalid, bound))?;
    runtime_control
      .try_resize(
        actual_persistent_bytes
          .checked_add(actual_startup_bytes)
          .ok_or_else(|| control_build_error(DomainError::Invalid, bound))?,
      )
      .map_err(|error| control_build_error(error, bound))?;
    for index in 0..config.workers {
      let worker_shared = Arc::clone(&shared);
      let thread_launch_control = launch_control.clone();
      let name = format!("allocatbelt-runtime-{index}");
      let name_capacity = name.capacity();
      if name_capacity > name_bound {
        let actual = actual_persistent_bytes
          .checked_add(name_capacity)
          .and_then(|bytes| bytes.checked_add(std::mem::size_of::<thread::Builder>()))
          .ok_or_else(|| control_build_error(DomainError::Invalid, bound))?;
        if let Err(error) = runtime_control.try_resize(actual) {
          drop(name);
          stop_started_workers(&shared, &mut workers);
          return Err(control_build_error(error, bound));
        }
      }
      let spawned = spawn(
        thread::Builder::new().name(name),
        Box::new(move || {
          let _launch_control = thread_launch_control;
          worker::run(&worker_shared, index);
        }),
      );
      match spawned {
        Ok(handle) => workers.push(DeferredJoin::new(handle)),
        Err(error) => {
          stop_started_workers(&shared, &mut workers);
          return Err(error);
        }
      }
    }
    runtime_control
      .try_resize(actual_persistent_bytes)
      .map_err(|error| {
        stop_started_workers(&shared, &mut workers);
        control_build_error(error, bound)
      })?;
    Ok(Self {
      shared,
      workers,
      panic_payloads: Mutex::new(panic_payloads),
      shutdown_pending: Mutex::new(ClosedQueue::empty()),
      shutdown_requested: false,
      shutdown_complete: false,
      shutdown_panicked: false,
      _control: runtime_control,
      launch_control,
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
      let pending = self.take_shutdown_pending();
      let had_pending = !pending.is_empty();
      abandon_closed_queue(&self.shared, pending);
      if had_pending {
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
    if worker::is_worker_of(self.shared.ident.id)
      || self.workers.iter().any(DeferredJoin::is_current_thread)
    {
      return Err(io::Error::new(
        io::ErrorKind::Deadlock,
        "shutdown called from one of the runtime's own workers",
      ));
    }
    abandon_closed_queue(
      &self.shared,
      self.shared.close(mode == ShutdownMode::CancelPending),
    );
    abandon_closed_queue(&self.shared, self.take_shutdown_pending());
    let mut panicked = false;
    while let Some(mut handle) = self.workers.pop() {
      if let Err(payload) = handle.join_blocking() {
        panicked = true;
        self.lock_panic_payloads().push(payload);
      }
    }
    drop(self.launch_control.take());
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
    let old = {
      let mut slot = self.lock_shutdown_pending();
      std::mem::replace(&mut *slot, pending)
    };
    drop(old);
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
    if !self.lock_shutdown_pending().is_empty() {
      return Ok(false);
    }

    let mut index = 0;
    while index < self.workers.len() {
      let result = self.workers[index]
        .try_join()
        .map_err(monitor_spawn_io_error)?;
      let Some(result) = result else {
        index += 1;
        continue;
      };

      // DeferredJoin is one-shot. Remove completed owners before returning so
      // a later poll cannot start a monitor after its result was consumed.
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
    drop(self.take_shutdown_pending());
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

  fn lock_shutdown_pending(&self) -> MutexGuard<'_, ClosedQueue> {
    self
      .shutdown_pending
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
  }

  fn take_shutdown_pending(&self) -> ClosedQueue {
    std::mem::take(&mut *self.lock_shutdown_pending())
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

  fn lock_panic_payloads(&self) -> MutexGuard<'_, Vec<Box<dyn Any + Send>>> {
    self
      .panic_payloads
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
  }
}

fn monitor_spawn_io_error(error: MonitorSpawnError) -> io::Error {
  io::Error::new(io::ErrorKind::WouldBlock, error)
}

impl Handle {
  /// Admits `f` with `request` reserved in full until it returns, or
  /// returns `f` in the error. Never blocks on the queue.
  ///
  /// # Errors
  ///
  /// [`SubmitErrorKind`](crate::runtime::SubmitErrorKind): `Closed`, then
  /// `InvalidRequest` (exceeds the capacity), `Full` (the outstanding bound
  /// is reached), `InsufficientResources` (declared task resources do not fit
  /// what is free now), or `ResourceDomain` when the bound domain refuses the
  /// task and Control admission.
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
      abandon_closed_queue(&self.shared, self.shared.close(true));
      // Dropping the handles detaches the threads.
      self.workers.clear();
    }
    abandon_closed_queue(&self.shared, self.take_shutdown_pending());
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
  use crate::runtime::error::JoinError;
  use crate::runtime::managed::{ResourceLimits, ResourceScope};
  use crate::runtime::resource_domain::{DomainResource, DomainResources, ResourceDomain};
  use std::sync::atomic::{AtomicUsize, Ordering};
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

  struct TlsGate {
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
  }

  impl TlsGate {
    fn wait(self) {
      let _ = self.entered.send(());
      let _ = self.release.recv_timeout(Duration::from_secs(4));
    }
  }

  struct WaitOnDrop(std::cell::RefCell<Option<TlsGate>>);

  impl Drop for WaitOnDrop {
    fn drop(&mut self) {
      if let Some(gate) = self.0.get_mut().take() {
        gate.wait();
      }
    }
  }

  thread_local! {
    static NESTED_TLS: WaitOnDrop = const { WaitOnDrop(std::cell::RefCell::new(None)) };
    static OUTER_TLS: OuterTls = const { OuterTls(std::cell::RefCell::new(None)) };
  }

  struct OuterTls(std::cell::RefCell<Option<TlsGate>>);

  impl Drop for OuterTls {
    fn drop(&mut self) {
      if let Some(gate) = self.0.get_mut().take() {
        NESTED_TLS.with(|slot| {
          *slot.0.borrow_mut() = Some(gate);
        });
      }
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

  #[test]
  fn runtime_control_fee_uses_deferred_join_capacity() {
    let mut runtime = Runtime::new(Config {
      workers: 2,
      max_outstanding: 2,
      capacity: Resources::ZERO,
    })
    .unwrap_or_else(|error| panic!("blocking runtime setup failed: {error}"));
    let panic_capacity = runtime
      .panic_payloads
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .capacity();
    let expected = std::mem::size_of::<Runtime>()
      + payload_bytes::<DeferredJoin>(runtime.workers.capacity())
        .unwrap_or_else(|error| panic!("worker payload size failed: {error}"))
      + payload_bytes::<Box<dyn Any + Send>>(panic_capacity)
        .unwrap_or_else(|error| panic!("panic payload size failed: {error}"));
    assert_eq!(runtime._control.bytes(), expected);
    runtime
      .shutdown(ShutdownMode::Drain)
      .unwrap_or_else(|error| panic!("blocking shutdown failed: {error}"));
  }

  #[test]
  fn polling_waits_for_nested_tls_worker_completion_and_removes_slot_once() {
    let mut runtime = Runtime::new(Config {
      workers: 1,
      max_outstanding: 2,
      capacity: Resources::ZERO,
    })
    .unwrap_or_else(|error| panic!("blocking runtime setup failed: {error}"));
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::channel();
    let job = runtime
      .try_spawn(Resources::ZERO, move |_| {
        OUTER_TLS.with(|slot| {
          *slot.0.borrow_mut() = Some(TlsGate {
            entered: entered_tx,
            release: release_rx,
          });
        });
      })
      .unwrap_or_else(|error| panic!("blocking task admission failed: {}", error.kind));
    job
      .join()
      .unwrap_or_else(|error| panic!("blocking task join failed: {error}"));

    runtime
      .request_shutdown(ShutdownMode::Drain)
      .unwrap_or_else(|error| panic!("blocking shutdown request failed: {error}"));
    entered_rx
      .recv_timeout(Duration::from_secs(3))
      .unwrap_or_else(|error| panic!("nested TLS destructor did not start: {error}"));
    assert!(
      !runtime
        .poll_shutdown()
        .unwrap_or_else(|error| panic!("blocking shutdown poll failed: {error}"))
    );
    assert_eq!(runtime.workers.len(), 1);

    release_tx
      .send(())
      .unwrap_or_else(|error| panic!("nested TLS destructor release failed: {error}"));
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
      match runtime.poll_shutdown() {
        Ok(true) => break,
        Ok(false) if Instant::now() < deadline => thread::yield_now(),
        result => panic!("blocking worker completion did not finish: {result:?}"),
      }
    }
    assert!(runtime.workers.is_empty());
    assert!(
      runtime
        .poll_shutdown()
        .unwrap_or_else(|error| panic!("repeated blocking shutdown poll failed: {error}"))
    );
  }

  #[test]
  fn bound_startup_failure_joins_started_workers_and_releases_control() {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 2)
      .with(DomainResource::Tasks, 4)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 8)
      .unwrap_or_else(|error| panic!("resource domain setup failed: {error}"));
    let tenant = domain
      .tenant(ceiling)
      .unwrap_or_else(|error| panic!("tenant setup failed: {error}"));
    let resources = ResourceScope::from_tenant(ResourceLimits::default(), tenant);
    let control_before = domain.snapshot().used.get(DomainResource::Control);
    let attempts = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let spawn_attempts = Arc::clone(&attempts);
    let active_workers = Arc::clone(&active);

    let result = Runtime::with_spawner_and_resources(
      Config {
        workers: 2,
        max_outstanding: 2,
        capacity: Resources::ZERO,
      },
      Some(resources),
      move |builder, worker| {
        if spawn_attempts.fetch_add(1, Ordering::SeqCst) == 1 {
          return Err(io::Error::other("injected worker start failure"));
        }
        let active = Arc::clone(&active_workers);
        builder.spawn(move || {
          active.fetch_add(1, Ordering::SeqCst);
          struct ActiveWorker(Arc<AtomicUsize>);
          impl Drop for ActiveWorker {
            fn drop(&mut self) {
              self.0.fetch_sub(1, Ordering::SeqCst);
            }
          }
          let _active = ActiveWorker(active);
          worker();
        })
      },
      |_| {},
    );

    let error = result
      .err()
      .unwrap_or_else(|| panic!("injected startup failure was ignored"));
    assert_eq!(error.to_string(), "injected worker start failure");
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      control_before
    );
  }

  #[test]
  fn blocking_cpu_wait_waker_control_failure_keeps_closure_unrun() {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 1)
      .with(DomainResource::Tasks, 4)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::with_waiters(ceiling, 1, 8)
      .unwrap_or_else(|error| panic!("resource domain setup failed: {error}"));
    let tenant = domain
      .tenant(ceiling)
      .unwrap_or_else(|error| panic!("tenant setup failed: {error}"));
    let resources = ResourceScope::from_tenant(ResourceLimits::default(), tenant.clone());
    let control_before = domain.snapshot().used.get(DomainResource::Control);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let release_rx = Arc::new(Mutex::new(release_rx));
    let mut runtime = Runtime::with_spawner_and_resources(
      Config {
        workers: 1,
        max_outstanding: 2,
        capacity: Resources::ZERO,
      },
      Some(resources),
      move |builder, worker| {
        let entered_tx = entered_tx.clone();
        let release_rx = Arc::clone(&release_rx);
        builder.spawn(move || {
          entered_tx.send(()).unwrap();
          release_rx
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv()
            .unwrap();
          worker();
        })
      },
      |_| {},
    )
    .unwrap_or_else(|error| panic!("blocking runtime setup failed: {error}"));
    entered_rx
      .recv_timeout(Duration::from_secs(2))
      .unwrap_or_else(|error| panic!("worker did not reach its gate: {error}"));
    let ran = Arc::new(AtomicUsize::new(0));
    let run_count = Arc::clone(&ran);
    let job = runtime
      .try_spawn(Resources::ZERO, move |_| {
        run_count.fetch_add(1, Ordering::SeqCst);
        5_usize
      })
      .unwrap_or_else(|error| panic!("job admission failed: {}", error.kind));

    let global = domain.snapshot();
    domain
      .set_limits(global.limit.with(
        DomainResource::Control,
        global.used.get(DomainResource::Control),
      ))
      .unwrap_or_else(|error| panic!("global Control limit update failed: {error}"));
    let tenant_snapshot = tenant
      .snapshot()
      .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"));
    tenant
      .set_limits(tenant_snapshot.limit.with(
        DomainResource::Control,
        tenant_snapshot.used.get(DomainResource::Control),
      ))
      .unwrap_or_else(|error| panic!("tenant Control limit update failed: {error}"));
    release_tx
      .send(())
      .unwrap_or_else(|error| panic!("worker release failed: {error}"));

    let deadline = Instant::now() + Duration::from_secs(2);
    while !job.is_finished() {
      assert!(Instant::now() < deadline, "blocking job did not finish");
      thread::yield_now();
    }
    assert!(matches!(
      job.join(),
      Err(JoinError::ResourceDomain(DomainError::Exhausted(
        DomainResource::Control
      )))
    ));
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 0);
    drop(job);
    runtime
      .shutdown(ShutdownMode::Drain)
      .unwrap_or_else(|error| panic!("blocking shutdown failed: {error}"));
    drop(runtime);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      control_before
    );
  }
}
