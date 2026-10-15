//! Bounded child-process ownership with an executor-independent reaper.
//!
//! A [`ProcessDriver`] reserves one of its fixed child slots before it calls
//! [`Command::spawn`]. A dedicated service thread polls every admitted child
//! with nonblocking `try_wait`; it does not borrow a runtime worker or require
//! an async executor. A Linux pidfd registered with the runtime reactor wakes
//! that thread promptly when a child exits. If pidfd setup or reactor
//! registration fails after spawn, the reserved slot remains owned and the
//! service uses its bounded-cadence polling fallback.
//!
//! Dropping a [`ProcessChild`] detaches it from the caller while the reaper
//! retains the process until the kernel reports its exit. `kill_on_drop` is an
//! opt-in request to kill before detaching. [`ProcessDriver::shutdown`] closes
//! admission and waits for actual reaping; dropping the driver only closes
//! admission and detaches its service thread.
//!
//! The child bound counts unreaped processes. Once a process has been reaped,
//! its table slot can be reused even while its handle remains alive: each
//! handle owns an `Arc` completion record containing its stable status. A
//! child that inherits a piped output stream can still block if the caller
//! does not take and drain that stream. Pipe accessors transfer the standard
//! child handles; [`pipe`] registers them with an explicit reactor for async
//! I/O. [`output`] collects both streams into caller-sized managed buffers.
//! The driver requires exclusive wait ownership: unrelated `waitpid` calls,
//! a chained `SIGCHLD` handler that reaps children, and `SIGCHLD` auto-reaping
//! (`SIG_IGN` or `SA_NOCLDWAIT`) are outside its contract. Observed `ECHILD`
//! releases the slot and publishes a tracking error. It cannot establish that
//! a post-spawn pidfd refers to the original child after a foreign reaper has
//! allowed the process identifier to be reused.
//!
//! [`ProcessDriver::new_in_tenant`] charges its declared owner, shared state,
//! fixed slot and reaper scratch capacities, reaper capture, nested reactor,
//! and thread-completion owner to the supplied tenant before starting service
//! threads. Each child completion is charged before its command reaches
//! `Command::spawn`, and its charge follows the stable completion record until
//! the last handle drops. Arc allocator headers, standard-library and OS
//! process/thread metadata, OS stacks, kernel resources, `Command` storage,
//! arbitrary user-reachable heap allocations, and physical RSS are outside
//! this logical Control accounting boundary. The process-owner fee excludes
//! its inline `Reactor` payload because that reactor retains its own fee.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::any::Any;
use std::fmt;
use std::future::Future;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::process::{Child as StdChild, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::Duration;

use rustix::fd::OwnedFd;
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};

use super::reactor::{AsyncFd, OwnedReadiness, Reactor, ReactorConfig, ReactorError};
use super::resource_domain::{ControlCharge, DomainError, TenantDomain, payload_bytes};
use super::task::drop_contained;
use super::thread_completion::{DeferredJoin, PreparedJoins};
mod completion;
pub mod output;
pub mod pipe;
pub use completion::WaitError;
use completion::{Completion, Registration, wake_contained};

const MAX_CHILDREN: usize = 1 << 24;
const REAPER_INTERVAL: Duration = Duration::from_millis(25);
const INTERRUPT_RETRIES: usize = 64;
const REAPER_THREAD_NAME: &str = "allocatbelt-process-reaper";

/// Creates a process driver with fixed capacity for `max_children` active
/// children.
///
/// Construction reserves every table before starting either service thread.
/// A zero bound, a bound larger than the reactor table limit, allocation
/// failure, reactor setup failure, or reaper thread startup failure is
/// reported before the driver is returned.
pub struct ProcessDriver {
  shared: Arc<Shared>,
  reaper: Option<DeferredJoin>,
  reactor: Option<Reactor>,
  reaper_panic: Mutex<Option<Box<dyn Any + Send>>>,
  shutdown_requested: bool,
  shutdown_complete: bool,
  shutdown_error: Option<ProcessShutdownError>,
  _control: ControlCharge,
  #[cfg(test)]
  service_storage_capacities: ServiceStorageCapacities,
}

/// Policy used when a process driver is explicitly shut down.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessShutdownMode {
  /// Stop admitting new children and wait for existing children to exit.
  Wait,
  /// Stop admitting new children, request termination, and wait for reaping.
  KillAndWait,
}

/// Why process-driver construction failed.
#[derive(Debug)]
pub enum ProcessBuildError {
  /// At least one child slot is required.
  ZeroCapacity,
  /// The configured bound exceeds the reactor's fixed registration limit.
  CapacityTooLarge,
  /// A fixed process table could not be allocated.
  AllocationFailed,
  /// The tenant refused a declared Control reservation.
  ResourceDomain(DomainError),
  /// Reactor setup failed before the reaper started.
  Reactor(io::Error),
  /// The dedicated reaper thread could not be started.
  Thread(io::Error),
}

impl fmt::Display for ProcessBuildError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::ZeroCapacity => "process child capacity must be nonzero",
      Self::CapacityTooLarge => "process child capacity exceeds the fixed table limit",
      Self::AllocationFailed => "process child table allocation failed",
      Self::ResourceDomain(_) => "resource domain refused process metadata",
      Self::Reactor(_) => "process pidfd reactor setup failed",
      Self::Thread(_) => "process reaper thread startup failed",
    })
  }
}

impl std::error::Error for ProcessBuildError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::ResourceDomain(error) => Some(error),
      Self::Reactor(error) | Self::Thread(error) => Some(error),
      _ => None,
    }
  }
}

/// Why a child could not be admitted or started.
#[derive(Debug)]
pub enum SpawnErrorKind {
  /// The bounded table has no free unreaped-child slot.
  Full,
  /// Shutdown has closed process admission.
  Closed,
  /// Every slot generation has been retired rather than wrapped.
  Exhausted,
  /// The tenant refused the child's fixed completion record.
  ResourceDomain(DomainError),
  /// The operating system rejected the spawn attempt.
  Spawn(io::Error),
}

/// A failed spawn together with the original command.
///
/// For `Full`, `Closed`, and `Exhausted`, the command has not been passed to
/// `Command::spawn` and is returned unchanged. An operating-system spawn
/// failure also returns the command object, although OS setup such as a
/// `pre_exec` callback or pipe creation may already have run.
pub struct SpawnError {
  kind: SpawnErrorKind,
  command: Command,
}

impl SpawnError {
  /// Returns the reason for rejection.
  #[must_use]
  pub const fn kind(&self) -> &SpawnErrorKind {
    &self.kind
  }

  /// Borrows the rejected command.
  #[must_use]
  pub const fn command(&self) -> &Command {
    &self.command
  }

  /// Returns the rejected command and error kind.
  #[must_use]
  pub fn into_parts(self) -> (Command, SpawnErrorKind) {
    (self.command, self.kind)
  }

  /// Returns the rejected command.
  #[must_use]
  pub fn into_command(self) -> Command {
    self.command
  }
}

impl fmt::Debug for SpawnError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("SpawnError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl fmt::Display for SpawnError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self.kind {
      SpawnErrorKind::Full => "process child table is full",
      SpawnErrorKind::Closed => "process driver is closed",
      SpawnErrorKind::Exhausted => "process child generations are exhausted",
      SpawnErrorKind::ResourceDomain(_) => "resource domain refused child completion metadata",
      SpawnErrorKind::Spawn(_) => "operating system rejected child process",
    })
  }
}

impl std::error::Error for SpawnError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match &self.kind {
      SpawnErrorKind::Spawn(error) => Some(error),
      SpawnErrorKind::ResourceDomain(error) => Some(error),
      _ => None,
    }
  }
}

/// Why a process-driver shutdown could not finish normally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessShutdownError {
  /// Shutdown was called from the reaper thread, which cannot join itself.
  WouldDeadlock,
  /// The dedicated reaper panicked; it continued in the fallback reaper.
  ReaperPanicked,
  /// The process reactor failed to stop cleanly.
  ReactorPanicked,
  /// A nonblocking join monitor could not be started. The original reaper
  /// handle remains owned, and a later shutdown poll may retry.
  JoinMonitorSpawn,
}

impl fmt::Display for ProcessShutdownError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::WouldDeadlock => "process shutdown would join its reaper thread",
      Self::ReaperPanicked => "process reaper panicked before entering fallback mode",
      Self::ReactorPanicked => "process reactor thread panicked",
      Self::JoinMonitorSpawn => "process shutdown join monitor could not be started",
    })
  }
}

impl std::error::Error for ProcessShutdownError {}

struct Shared {
  state: Mutex<State>,
  changed: Condvar,
  signal: Arc<WakeSignal>,
  reactor: super::reactor::ReactorHandle,
  force_pidfd_fallback: bool,
  tenant: Option<TenantDomain>,
  _control: ControlCharge,
}

struct State {
  slots: Vec<Slot>,
  admissions_open: bool,
  shutdown: Option<ProcessShutdownMode>,
  active: usize,
  reserved: usize,
  worker_exited: bool,
  worker_panicked: bool,
}

struct Slot {
  generation: u64,
  state: SlotState,
  child: Option<StdChild>,
  completion: Option<Arc<Completion>>,
  pidfd: Option<AsyncFd<OwnedFd>>,
  readiness: Option<OwnedReadiness<OwnedFd>>,
  kill_sent: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
  Free,
  Reserved,
  Running,
  Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SlotKey {
  index: usize,
  generation: u64,
}

/// A handle to one admitted child process. It is not cloneable; a dropped
/// handle detaches while the bounded service keeps ownership until reaping.
pub struct ProcessChild {
  shared: Arc<Shared>,
  completion: Arc<Completion>,
  key: SlotKey,
  id: u32,
  kill_on_drop: bool,
  stdin: Option<ChildStdin>,
  stdout: Option<ChildStdout>,
  stderr: Option<ChildStderr>,
}

/// A cancellation-safe wait borrowing its child handle.
#[must_use = "futures do nothing unless polled"]
pub struct ChildWait<'a> {
  child: &'a mut ProcessChild,
  waiter: Option<u64>,
  completed: bool,
}

impl ProcessDriver {
  /// Creates a fixed-capacity process driver and starts its independent
  /// reaper and pidfd reactor services.
  pub fn new(max_children: usize) -> Result<Self, ProcessBuildError> {
    Self::new_inner(max_children, false, None)
  }

  /// Creates a fixed-capacity process driver whose declared metadata is
  /// reserved from `tenant` before service threads start.
  ///
  /// The reservation covers this owner, the shared process table and wake
  /// signal, actual slot and reaper scratch capacities, the reaper capture,
  /// the nested pidfd reactor, and the reaper's prepared completion owner.
  /// Each child completion is charged before its command is passed to the
  /// operating system. Standard-library and OS process/thread metadata,
  /// stacks, Arc allocator headers, command storage, arbitrary reachable heap
  /// allocations, kernel resources and physical RSS remain outside this
  /// logical Control accounting boundary.
  pub fn new_in_tenant(
    max_children: usize,
    tenant: &TenantDomain,
  ) -> Result<Self, ProcessBuildError> {
    Self::new_inner(max_children, false, Some(tenant))
  }

  #[cfg(test)]
  fn new_without_pidfd(max_children: usize) -> Result<Self, ProcessBuildError> {
    Self::new_inner(max_children, true, None)
  }

  fn inline_owner_control_payload_bytes(tenant_bound: bool) -> Result<usize, DomainError> {
    let bytes = std::mem::size_of::<Self>();
    if tenant_bound {
      bytes
        .checked_sub(std::mem::size_of::<Reactor>())
        .ok_or(DomainError::Invalid)
    } else {
      Ok(bytes)
    }
  }

  fn owner_control_payload_bytes(
    name_capacity: usize,
    tenant_bound: bool,
  ) -> Result<usize, DomainError> {
    let mut bytes = Self::inline_owner_control_payload_bytes(tenant_bound)?;
    for payload in [
      std::mem::size_of::<thread::Builder>(),
      payload_bytes::<u8>(name_capacity)?,
    ] {
      bytes = bytes.checked_add(payload).ok_or(DomainError::Invalid)?;
    }
    Ok(bytes)
  }

  fn shared_control_payload_bytes(slot_capacity: usize) -> Result<usize, DomainError> {
    std::mem::size_of::<Shared>()
      .checked_add(std::mem::size_of::<WakeSignal>())
      .and_then(|bytes| bytes.checked_add(payload_bytes::<Slot>(slot_capacity).ok()?))
      .ok_or(DomainError::Invalid)
  }

  fn new_inner(
    max_children: usize,
    force_pidfd_fallback: bool,
    tenant: Option<&TenantDomain>,
  ) -> Result<Self, ProcessBuildError> {
    if max_children == 0 {
      return Err(ProcessBuildError::ZeroCapacity);
    }
    if max_children > MAX_CHILDREN {
      return Err(ProcessBuildError::CapacityTooLarge);
    }

    // Reserve every process-owned component before allocating its backing or
    // invoking the nested reactor or either thread's startup path.
    let owner_final_bytes = Self::inline_owner_control_payload_bytes(tenant.is_some())
      .map_err(ProcessBuildError::ResourceDomain)?;
    let mut owner_control = ControlCharge::try_new(
      tenant,
      Self::owner_control_payload_bytes(REAPER_THREAD_NAME.len(), tenant.is_some())
        .map_err(ProcessBuildError::ResourceDomain)?,
    )
    .map_err(ProcessBuildError::ResourceDomain)?;
    let mut shared_control = ControlCharge::try_new(
      tenant,
      Self::shared_control_payload_bytes(max_children)
        .map_err(ProcessBuildError::ResourceDomain)?,
    )
    .map_err(ProcessBuildError::ResourceDomain)?;
    let service_requested = ServiceStorage::control_payload_bytes(max_children, max_children)
      .map_err(ProcessBuildError::ResourceDomain)?;
    let service_control = ControlCharge::try_new(tenant, service_requested)
      .map_err(ProcessBuildError::ResourceDomain)?;
    let mut prepared = PreparedJoins::new(tenant, 1).map_err(ProcessBuildError::ResourceDomain)?;
    let reaper_prepared = prepared.pop().ok_or(ProcessBuildError::AllocationFailed)?;
    drop(prepared);

    let mut slots = Vec::new();
    slots
      .try_reserve_exact(max_children)
      .map_err(|_| ProcessBuildError::AllocationFailed)?;
    slots.resize_with(max_children, Slot::empty);
    shared_control
      .try_resize(
        Self::shared_control_payload_bytes(slots.capacity())
          .map_err(ProcessBuildError::ResourceDomain)?,
      )
      .map_err(ProcessBuildError::ResourceDomain)?;

    let signal = Arc::new(WakeSignal::new());
    let service_storage = ServiceStorage::allocate(max_children, service_control)?;
    #[cfg(test)]
    let service_storage_capacities = service_storage.capacities();

    let mut reaper_name = String::new();
    reaper_name
      .try_reserve_exact(REAPER_THREAD_NAME.len())
      .map_err(|_| ProcessBuildError::AllocationFailed)?;
    reaper_name.push_str(REAPER_THREAD_NAME);
    owner_control
      .try_resize(
        Self::owner_control_payload_bytes(reaper_name.capacity(), tenant.is_some())
          .map_err(ProcessBuildError::ResourceDomain)?,
      )
      .map_err(ProcessBuildError::ResourceDomain)?;

    let reactor_config = ReactorConfig {
      max_registrations: max_children,
      max_waiters: max_children,
    };
    let reactor = match tenant {
      Some(tenant) => Reactor::new_in_tenant(reactor_config, tenant),
      None => Reactor::new(reactor_config),
    }
    .map_err(|error| match ReactorError::of(&error) {
      Some(ReactorError::Domain(domain_error)) => ProcessBuildError::ResourceDomain(domain_error),
      _ => ProcessBuildError::Reactor(error),
    })?;
    let shared = Arc::new(Shared {
      state: Mutex::new(State {
        slots,
        admissions_open: true,
        shutdown: None,
        active: 0,
        reserved: 0,
        worker_exited: false,
        worker_panicked: false,
      }),
      changed: Condvar::new(),
      signal: Arc::clone(&signal),
      reactor: reactor.handle(),
      force_pidfd_fallback,
      tenant: tenant.cloned(),
      _control: shared_control,
    });
    let service = Arc::clone(&shared);
    let thread_owner = reaper_prepared.thread_owner();
    let reaper = match thread::Builder::new().name(reaper_name).spawn(move || {
      thread_owner.retain_until_thread_exit();
      run_service(service, service_storage);
    }) {
      Ok(reaper) => reaper,
      Err(error) => {
        let _ = reactor.shutdown();
        return Err(ProcessBuildError::Thread(error));
      }
    };
    // The builder and name backing have been consumed by thread startup. The
    // owner fee now covers the process-owned inline payload; the nested
    // Reactor's inline payload is covered by its own Control fee.
    let _ = owner_control.try_resize(owner_final_bytes);

    Ok(Self {
      shared,
      reaper: Some(reaper_prepared.attach(reaper)),
      reactor: Some(reactor),
      reaper_panic: Mutex::new(None),
      shutdown_requested: false,
      shutdown_complete: false,
      shutdown_error: None,
      _control: owner_control,
      #[cfg(test)]
      service_storage_capacities,
    })
  }

  /// Returns the configured maximum number of unreaped child processes.
  #[must_use]
  pub fn max_children(&self) -> usize {
    lock(&self.shared.state).slots.len()
  }

  /// Returns the number of reserved or unreaped children.
  #[must_use]
  pub fn active_children(&self) -> usize {
    let state = lock(&self.shared.state);
    state.active + state.reserved
  }

  /// Starts a command if one fixed child slot is available.
  ///
  /// The slot is reserved before the OS call. Capacity or shutdown rejection
  /// returns the untouched command. Once `spawn` succeeds, the reserved slot
  /// remains live through pidfd setup and the `Child` is installed before the
  /// worker can examine it, so setup failure cannot abandon a started process.
  pub fn spawn(&self, mut command: Command) -> Result<ProcessChild, SpawnError> {
    let key = match reserve(&self.shared) {
      Ok(key) => key,
      Err(kind) => return Err(SpawnError { kind, command }),
    };
    let completion_result = match self.shared.tenant.as_ref() {
      Some(tenant) => Completion::new_in_tenant(tenant),
      None => Ok(Completion::new()),
    };
    let completion = match completion_result {
      Ok(completion) => Arc::new(completion),
      Err(error) => {
        release_reservation(&self.shared, key);
        return Err(SpawnError {
          kind: SpawnErrorKind::ResourceDomain(error),
          command,
        });
      }
    };
    if !attach_completion(&self.shared, key, Arc::clone(&completion)) {
      release_reservation(&self.shared, key);
      return Err(SpawnError {
        kind: SpawnErrorKind::Closed,
        command,
      });
    }

    let spawned = panic::catch_unwind(AssertUnwindSafe(|| command.spawn()));
    let mut child = match spawned {
      Ok(Ok(child)) => child,
      Ok(Err(error)) => {
        release_reservation(&self.shared, key);
        return Err(SpawnError {
          kind: SpawnErrorKind::Spawn(error),
          command,
        });
      }
      Err(payload) => {
        release_reservation(&self.shared, key);
        panic::resume_unwind(payload);
      }
    };

    let id = child.id();
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    // Reserve remains visible while readiness is set up, so shutdown waits
    // for this spawn and the worker cannot reap/reuse the slot before the
    // pidfd is attached. Any pidfd or reactor failure falls back to polling.
    // std exposes pidfd_open only after spawn. Check once before looking up
    // the numeric pid, avoiding a lookup after the child is already reaped.
    // Exclusive wait ownership is still required to exclude an external
    // reaper racing between this check and pidfd_open.
    let preflight = try_wait_bounded(&mut child);
    let registered = if self.shared.force_pidfd_fallback || !matches!(preflight, Ok(None)) {
      None
    } else {
      match panic::catch_unwind(AssertUnwindSafe(|| {
        let pid = Pid::from_raw(id as i32)?;
        let pidfd = pidfd_open(pid, PidfdFlags::NONBLOCK).ok()?;
        self.shared.reactor.register(pidfd).ok()
      })) {
        Ok(registered) => registered,
        Err(payload) => {
          drop_contained(payload);
          None
        }
      }
    };
    install_child(&self.shared, key, child, registered);

    self.shared.signal.notify();
    Ok(ProcessChild {
      shared: Arc::clone(&self.shared),
      completion,
      key,
      id,
      kill_on_drop: false,
      stdin,
      stdout,
      stderr,
    })
  }

  /// Closes admission and waits until every reserved or started process has
  /// actually been reaped. `KillAndWait` also applies to a spawn already in
  /// its OS call when that process is committed to the table.
  pub fn shutdown(&mut self, mode: ProcessShutdownMode) -> Result<(), ProcessShutdownError> {
    if self.shutdown_complete {
      let result = match self.shutdown_error {
        Some(error) => Err(error),
        None => Ok(()),
      };
      self.drop_reaper_panic();
      return result;
    }
    close_admission(&self.shared, mode);
    if self.shared.signal.is_current_thread() {
      return Err(ProcessShutdownError::WouldDeadlock);
    }

    let mut state = lock(&self.shared.state);
    while !state.worker_exited {
      state = self
        .shared
        .changed
        .wait(state)
        .unwrap_or_else(PoisonError::into_inner);
    }
    let reaper_panicked = state.worker_panicked;
    drop(state);

    let reaper_result = self.reaper.as_mut().map(DeferredJoin::join_blocking);
    self.reaper.take();
    if let Some(Err(payload)) = reaper_result {
      drop_contained(payload);
      return Err(ProcessShutdownError::ReaperPanicked);
    }

    if let Some(reactor) = self.reactor.take()
      && reactor.shutdown().is_err()
    {
      return Err(ProcessShutdownError::ReactorPanicked);
    }

    if reaper_panicked {
      Err(ProcessShutdownError::ReaperPanicked)
    } else {
      Ok(())
    }
  }

  /// Closes admission and requests shutdown of the private pidfd reactor.
  /// This does not wait for a child or run a process completion waker.
  pub(crate) fn request_shutdown(&mut self, mode: ProcessShutdownMode) -> std::io::Result<()> {
    if self.shutdown_complete {
      return Ok(());
    }
    close_admission(&self.shared, mode);
    if let Some(reactor) = self.reactor.as_mut() {
      reactor.request_shutdown()?;
    }
    self.shutdown_requested = true;
    Ok(())
  }

  /// Checks whether all children were reaped and the private reactor thread
  /// exited. It never waits for a child or joins an original service thread
  /// on this caller. One bounded helper joins each service thread and
  /// publishes its result only after thread-local destructors finish. A helper
  /// startup error leaves the original handle owned for a later retry. A
  /// reaper panic payload stays owned by this driver; dropping that payload
  /// can run user code and block when the driver is explicitly shut down or
  /// dropped.
  pub(crate) fn poll_shutdown(&mut self) -> Result<bool, ProcessShutdownError> {
    if self.shutdown_complete {
      return match self.shutdown_error {
        Some(error) => Err(error),
        None => Ok(true),
      };
    }
    if !self.shutdown_requested {
      return Ok(false);
    }
    let (worker_exited, worker_panicked) = {
      let state = lock(&self.shared.state);
      (state.worker_exited, state.worker_panicked)
    };
    if !worker_exited {
      return Ok(false);
    }
    if let Some(reaper) = self.reaper.as_mut() {
      match reaper.try_join() {
        Err(_) => return Err(ProcessShutdownError::JoinMonitorSpawn),
        Ok(None) => return Ok(false),
        Ok(Some(result)) => {
          self.reaper.take();
          if let Err(payload) = result {
            *lock(&self.reaper_panic) = Some(payload);
            self.shutdown_error = Some(ProcessShutdownError::ReaperPanicked);
          }
        }
      }
    }
    if worker_panicked {
      self.shutdown_error = Some(ProcessShutdownError::ReaperPanicked);
    }
    if let Some(reactor) = self.reactor.as_mut() {
      match reactor.poll_shutdown() {
        Ok(false) => return Ok(false),
        Ok(true) => self.reactor = None,
        Err(ReactorError::JoinMonitorSpawn) => {
          return Err(ProcessShutdownError::JoinMonitorSpawn);
        }
        Err(_) => {
          self.shutdown_error = Some(ProcessShutdownError::ReactorPanicked);
        }
      }
    }
    self.shutdown_complete = true;
    match self.shutdown_error {
      Some(error) => Err(error),
      None => Ok(true),
    }
  }

  pub(crate) fn shutdown_complete(&self) -> bool {
    self.shutdown_complete
  }

  fn take_reaper_panic(&self) -> Option<Box<dyn Any + Send>> {
    lock(&self.reaper_panic).take()
  }

  fn drop_reaper_panic(&self) {
    if let Some(payload) = self.take_reaper_panic() {
      drop_contained(payload);
    }
  }
}

impl Drop for ProcessDriver {
  fn drop(&mut self) {
    close_admission(&self.shared, ProcessShutdownMode::Wait);
    // Dropping never waits for a service thread's TLS destructors. A started
    // monitor retains and joins the exact reaper handle off-caller; otherwise
    // dropping the original handle preserves the driver's detach contract.
    self.reaper.take();
    // Reactor::drop is itself nonblocking and switches registered pidfds to
    // the service's fixed-cadence try_wait fallback.
    self.reactor.take();
    // A reaper panic payload is dropped only after releasing its mutex.
    self.drop_reaper_panic();
  }
}

impl Slot {
  fn empty() -> Self {
    Self {
      generation: 0,
      state: SlotState::Free,
      child: None,
      completion: None,
      pidfd: None,
      readiness: None,
      kill_sent: false,
    }
  }
}

impl ProcessChild {
  /// Returns the original operating-system identifier for diagnostics.
  ///
  /// This value remains after reaping and may then identify another process.
  /// Use this handle's guarded kill methods to signal the managed child.
  #[must_use]
  pub const fn id(&self) -> u32 {
    self.id
  }

  /// Returns a cached exit status or error, without waiting.
  ///
  /// This does not probe the kernel. With the polling fallback, a new exit
  /// normally becomes visible on the next 25-millisecond service pass.
  pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, WaitError> {
    match self.completion.outcome() {
      Some(Ok(status)) => Ok(Some(status)),
      Some(Err(error)) => Err(error),
      None => Ok(None),
    }
  }

  /// Requests process termination. The reaper still owns and waits for the
  /// child; this method never releases the bounded child slot.
  pub fn start_kill(&mut self) -> io::Result<()> {
    if matches!(self.completion.outcome(), Some(Ok(_))) {
      return Ok(());
    }
    let mut state = lock(&self.shared.state);
    let Some(slot) = state.slots.get_mut(self.key.index) else {
      return Ok(());
    };
    if slot.generation != self.key.generation
      || slot.state != SlotState::Running
      || !slot
        .completion
        .as_ref()
        .is_some_and(|completion| Arc::ptr_eq(completion, &self.completion))
    {
      return Ok(());
    }
    let Some(child) = slot.child.as_mut() else {
      return Ok(());
    };
    request_kill(slot.pidfd.as_ref(), child)?;
    slot.kill_sent = true;
    drop(state);
    self.shared.signal.notify();
    Ok(())
  }

  /// Enables or disables the opt-in kill request made when this handle drops.
  pub fn set_kill_on_drop(&mut self, enabled: bool) {
    self.kill_on_drop = enabled;
  }

  /// Takes the child's piped stdin, if it has not already been taken.
  pub fn take_stdin(&mut self) -> Option<ChildStdin> {
    self.stdin.take()
  }

  /// Takes the child's piped stdout, if it has not already been taken.
  pub fn take_stdout(&mut self) -> Option<ChildStdout> {
    self.stdout.take()
  }

  /// Takes the child's piped stderr, if it has not already been taken.
  pub fn take_stderr(&mut self) -> Option<ChildStderr> {
    self.stderr.take()
  }

  /// Waits for this child, closing its still-owned stdin first.
  pub fn wait(&mut self) -> ChildWait<'_> {
    let stdin = self.take_stdin();
    drop_contained(stdin);
    ChildWait {
      child: self,
      waiter: None,
      completed: false,
    }
  }

  /// Requests termination and waits for the reaper's cached exit result.
  pub async fn kill_and_wait(&mut self) -> Result<ExitStatus, WaitError> {
    self
      .start_kill()
      .map_err(|error| WaitError::Kill(error.kind(), error.raw_os_error()))?;
    self.wait().await
  }
}

impl Drop for ProcessChild {
  fn drop(&mut self) {
    if self.kill_on_drop {
      self
        .completion
        .kill_requested
        .store(true, Ordering::Release);
      self.shared.signal.notify();
    }
  }
}

impl Future for ChildWait<'_> {
  type Output = Result<ExitStatus, WaitError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.completed {
      return Poll::Ready(Err(WaitError::AlreadyCompleted));
    }
    super::asynchronous::poll_cooperative(cx, |cx| {
      match this
        .child
        .completion
        .poll_register(&mut this.waiter, cx.waker())
      {
        Ok(Registration::Ready(outcome)) => {
          this.completed = true;
          Poll::Ready(outcome)
        }
        Ok(Registration::Pending) => Poll::Pending,
        Err(error) => {
          this.completed = true;
          Poll::Ready(Err(error))
        }
      }
    })
  }
}

impl ChildWait<'_> {
  fn cancel_waiter(&mut self) {
    self.child.completion.cancel_waiter(&mut self.waiter);
  }
}

impl Drop for ChildWait<'_> {
  fn drop(&mut self) {
    self.cancel_waiter();
  }
}

impl fmt::Debug for ProcessDriver {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ProcessDriver")
      .field("max_children", &self.max_children())
      .field("active_children", &self.active_children())
      .finish_non_exhaustive()
  }
}

impl fmt::Debug for ProcessChild {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ProcessChild")
      .field("id", &self.id)
      .field("completed", &self.completion.outcome().is_some())
      .finish_non_exhaustive()
  }
}

impl fmt::Debug for ChildWait<'_> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ChildWait")
      .field("id", &self.child.id)
      .field("registered", &self.waiter.is_some())
      .field("completed", &self.completed)
      .finish()
  }
}

fn reserve(shared: &Shared) -> Result<SlotKey, SpawnErrorKind> {
  let mut state = lock(&shared.state);
  if !state.admissions_open {
    return Err(SpawnErrorKind::Closed);
  }
  for (index, slot) in state.slots.iter_mut().enumerate() {
    if slot.state != SlotState::Free {
      continue;
    }
    let Some(generation) = slot.generation.checked_add(1) else {
      slot.state = SlotState::Retired;
      continue;
    };
    slot.generation = generation;
    slot.state = SlotState::Reserved;
    state.reserved += 1;
    return Ok(SlotKey { index, generation });
  }
  if state
    .slots
    .iter()
    .all(|slot| slot.state == SlotState::Retired)
  {
    Err(SpawnErrorKind::Exhausted)
  } else {
    Err(SpawnErrorKind::Full)
  }
}

fn attach_completion(shared: &Shared, key: SlotKey, completion: Arc<Completion>) -> bool {
  let mut state = lock(&shared.state);
  let Some(slot) = state.slots.get_mut(key.index) else {
    return false;
  };
  if slot.generation != key.generation || slot.state != SlotState::Reserved {
    return false;
  }
  debug_assert!(slot.completion.is_none());
  slot.completion = Some(completion);
  true
}

fn release_reservation(shared: &Shared, key: SlotKey) {
  let completion = {
    let mut state = lock(&shared.state);
    let completion = {
      let Some(slot) = state.slots.get_mut(key.index) else {
        return;
      };
      if slot.generation != key.generation || slot.state != SlotState::Reserved {
        return;
      }
      slot.state = SlotState::Free;
      slot.completion.take()
    };
    state.reserved = state.reserved.saturating_sub(1);
    completion
  };
  drop_contained(completion);
  shared.changed.notify_all();
  shared.signal.notify();
}

fn install_child(shared: &Shared, key: SlotKey, child: StdChild, pidfd: Option<AsyncFd<OwnedFd>>) {
  let installed = {
    let mut state = lock(&shared.state);
    let Some(slot) = state.slots.get_mut(key.index) else {
      return;
    };
    if slot.generation != key.generation || slot.state != SlotState::Reserved {
      return;
    }
    slot.child = Some(child);
    debug_assert!(slot.completion.is_some());
    if let Some(pidfd) = pidfd {
      slot.readiness = Some(pidfd.readable_owned());
      slot.pidfd = Some(pidfd);
    }
    slot.state = SlotState::Running;
    state.reserved = state.reserved.saturating_sub(1);
    state.active += 1;
    true
  };
  if installed {
    shared.changed.notify_all();
    shared.signal.notify();
  }
}

fn close_admission(shared: &Shared, mode: ProcessShutdownMode) {
  {
    let mut state = lock(&shared.state);
    state.admissions_open = false;
    state.shutdown = Some(match (state.shutdown, mode) {
      (Some(ProcessShutdownMode::KillAndWait), _) | (_, ProcessShutdownMode::KillAndWait) => {
        ProcessShutdownMode::KillAndWait
      }
      _ => ProcessShutdownMode::Wait,
    });
  }
  shared.changed.notify_all();
  shared.signal.notify();
}

struct Reaped {
  child: StdChild,
  completion: Arc<Completion>,
  pidfd: Option<AsyncFd<OwnedFd>>,
  readiness: Option<OwnedReadiness<OwnedFd>>,
  waker: Option<Waker>,
}

/// Fixed service-thread scratch. The charge follows the vectors and the
/// capture owner through actual reaper-thread exit.
struct ServiceStorage {
  reaped: Vec<Reaped>,
  wakes: Vec<Waker>,
  _control: ControlCharge,
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct ServiceStorageCapacities {
  reaped: usize,
  wakes: usize,
}

impl ServiceStorage {
  #[cfg(test)]
  fn capacities(&self) -> ServiceStorageCapacities {
    ServiceStorageCapacities {
      reaped: self.reaped.capacity(),
      wakes: self.wakes.capacity(),
    }
  }

  fn control_payload_bytes(
    reaped_capacity: usize,
    wakes_capacity: usize,
  ) -> Result<usize, DomainError> {
    let mut bytes = std::mem::size_of::<Self>()
      .checked_add(std::mem::size_of::<Arc<Shared>>())
      .ok_or(DomainError::Invalid)?;
    for payload in [
      payload_bytes::<Reaped>(reaped_capacity)?,
      payload_bytes::<Waker>(wakes_capacity)?,
    ] {
      bytes = bytes.checked_add(payload).ok_or(DomainError::Invalid)?;
    }
    Ok(bytes)
  }

  fn allocate(capacity: usize, mut control: ControlCharge) -> Result<Self, ProcessBuildError> {
    let mut reaped = Vec::new();
    reaped
      .try_reserve_exact(capacity)
      .map_err(|_| ProcessBuildError::AllocationFailed)?;
    let mut wakes = Vec::new();
    wakes
      .try_reserve_exact(capacity)
      .map_err(|_| ProcessBuildError::AllocationFailed)?;
    control
      .try_resize(
        Self::control_payload_bytes(reaped.capacity(), wakes.capacity())
          .map_err(ProcessBuildError::ResourceDomain)?,
      )
      .map_err(ProcessBuildError::ResourceDomain)?;
    Ok(Self {
      reaped,
      wakes,
      _control: control,
    })
  }
}

fn run_service(shared: Arc<Shared>, mut storage: ServiceStorage) {
  shared.signal.install_current_thread();
  let mut use_reactor = true;
  loop {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
      service_loop(
        &shared,
        &mut storage.reaped,
        &mut storage.wakes,
        use_reactor,
      )
    }));
    match result {
      Ok(()) => break,
      Err(payload) => {
        drop_contained(payload);
        lock(&shared.state).worker_panicked = true;
        finish_reaped(&mut storage.reaped, &mut storage.wakes);
        use_reactor = false;
        shared.signal.park_timeout(REAPER_INTERVAL);
      }
    }
  }
  let mut state = lock(&shared.state);
  state.worker_exited = true;
  drop(state);
  shared.changed.notify_all();
}

fn service_loop(
  shared: &Shared,
  reaped: &mut Vec<Reaped>,
  wakes: &mut Vec<Waker>,
  use_reactor: bool,
) {
  let signal_waker = Waker::from(Arc::clone(&shared.signal));
  let mut context = Context::from_waker(&signal_waker);

  loop {
    reaped.clear();
    wakes.clear();
    let exit = {
      let mut state = lock(&shared.state);
      let kill_all = state.shutdown == Some(ProcessShutdownMode::KillAndWait);
      let mut newly_reaped = 0usize;
      for slot in &mut state.slots {
        if slot.state != SlotState::Running {
          continue;
        }

        if use_reactor && let Some(readiness) = slot.readiness.as_mut() {
          match Pin::new(readiness).poll(&mut context) {
            Poll::Ready(Ok(guard)) => {
              guard.clear_ready();
              slot.readiness = slot.pidfd.as_ref().map(AsyncFd::readable_owned);
            }
            Poll::Ready(Err(_)) => {
              slot.readiness = None;
              slot.pidfd = None;
            }
            Poll::Pending => {}
          }
        }

        let Some(child) = slot.child.as_mut() else {
          continue;
        };
        let wait_result = try_wait_bounded(child);
        let request_kill_now = (kill_all
          || slot
            .completion
            .as_ref()
            .is_some_and(|completion| completion.kill_requested.load(Ordering::Acquire)))
          && !slot.kill_sent;
        if matches!(&wait_result, Ok(None))
          && request_kill_now
          && request_kill(slot.pidfd.as_ref(), child).is_ok()
        {
          slot.kill_sent = true;
        }

        match wait_result {
          Ok(Some(status)) => {
            let child = slot.child.take();
            let completion = slot.completion.take();
            let pidfd = slot.pidfd.take();
            let readiness = slot.readiness.take();
            slot.kill_sent = false;
            slot.state = SlotState::Free;
            newly_reaped += 1;
            if let (Some(child), Some(completion)) = (child, completion) {
              let waker = completion.publish(Ok(status));
              reaped.push(Reaped {
                child,
                completion,
                pidfd,
                readiness,
                waker,
              });
            }
          }
          Ok(None) => {}
          Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
          Err(error) if error.raw_os_error() == Some(rustix::io::Errno::CHILD.raw_os_error()) => {
            let child = slot.child.take();
            let completion = slot.completion.take();
            let pidfd = slot.pidfd.take();
            let readiness = slot.readiness.take();
            slot.kill_sent = false;
            slot.state = SlotState::Free;
            newly_reaped += 1;
            if let (Some(child), Some(completion)) = (child, completion) {
              let waker =
                completion.publish(Err(WaitError::Reap(error.kind(), error.raw_os_error())));
              reaped.push(Reaped {
                child,
                completion,
                pidfd,
                readiness,
                waker,
              });
            }
          }
          Err(_) => {}
        }
      }
      state.active = state.active.saturating_sub(newly_reaped);
      state.shutdown.is_some() && state.active == 0 && state.reserved == 0
    };

    finish_reaped(reaped, wakes);
    shared.changed.notify_all();

    if exit {
      return;
    }
    shared.signal.park_timeout(REAPER_INTERVAL);
  }
}

fn finish_reaped(reaped: &mut Vec<Reaped>, wakes: &mut Vec<Waker>) {
  for mut item in reaped.drain(..) {
    drop(item.readiness.take());
    drop(item.pidfd.take());
    drop(item.child);
    wake_contained(item.waker.take());
    drop_contained(item.completion);
  }
  for waker in wakes.drain(..) {
    wake_contained(Some(waker));
  }
}

struct WakeSignal {
  thread: Mutex<Option<Thread>>,
  notified: AtomicBool,
}

impl WakeSignal {
  fn new() -> Self {
    Self {
      thread: Mutex::new(None),
      notified: AtomicBool::new(false),
    }
  }

  fn install_current_thread(&self) {
    *lock(&self.thread) = Some(thread::current());
  }

  fn notify(&self) {
    self.notified.store(true, Ordering::Release);
    if let Some(thread) = lock(&self.thread).as_ref() {
      thread.unpark();
    }
  }

  fn park_timeout(&self, timeout: Duration) {
    if !self.notified.swap(false, Ordering::AcqRel) {
      thread::park_timeout(timeout);
      let _ = self.notified.swap(false, Ordering::AcqRel);
    }
  }

  fn is_current_thread(&self) -> bool {
    lock(&self.thread)
      .as_ref()
      .is_some_and(|thread| thread.id() == thread::current().id())
  }
}

impl Wake for WakeSignal {
  fn wake(self: Arc<Self>) {
    self.notify();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.notify();
  }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn try_wait_bounded(child: &mut StdChild) -> io::Result<Option<ExitStatus>> {
  for _ in 0..INTERRUPT_RETRIES {
    match child.try_wait() {
      Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
      result => return result,
    }
  }
  Err(io::Error::from(io::ErrorKind::Interrupted))
}

fn request_kill(pidfd: Option<&AsyncFd<OwnedFd>>, child: &mut StdChild) -> io::Result<()> {
  for _ in 0..INTERRUPT_RETRIES {
    let result = if let Some(pidfd) = pidfd {
      pidfd_send_signal(pidfd.get_ref(), Signal::KILL).map_err(io::Error::from)
    } else {
      // Guard the numeric fallback with a fresh Child status check. This
      // reduces PID-reuse exposure; exclusive wait ownership remains required
      // because an unrelated reaper could still race this check and kill.
      match try_wait_bounded(child)? {
        Some(_) => return Ok(()),
        None => child.kill(),
      }
    };
    match result {
      Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
      Err(error) if error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) => {
        return Ok(());
      }
      result => return result,
    }
  }
  Err(io::Error::from(io::ErrorKind::Interrupted))
}

#[cfg(test)]
mod tests {
  use super::{
    ProcessBuildError, ProcessDriver, ProcessShutdownMode, SpawnErrorKind, WaitError, WakeSignal,
  };
  use crate::runtime::asynchronous::{AsyncConfig, AsyncRuntime, AsyncShutdown};
  use crate::runtime::reactor::{Reactor, ReactorConfig};
  use crate::runtime::resource_domain::{
    DomainError, DomainResource, DomainResources, ResourceDomain,
  };
  use std::future::Future;
  use std::future::poll_fn;
  use std::io::{Read, Write};
  use std::process::{Command, Stdio};
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::{Context, Poll, Wake, Waker};
  use std::thread;
  use std::time::{Duration, Instant};

  fn helper(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    let test_name = module_path!()
      .strip_prefix("allocatbelt::")
      .unwrap_or(module_path!());
    command
      .args([
        "--exact",
        &format!("{test_name}::child_helper_entrypoint"),
        "--quiet",
      ])
      .env("ALLOCATBELT_PROCESS_HELPER", mode)
      .stdout(Stdio::null())
      .stderr(Stdio::inherit());
    command
  }

  #[test]
  fn child_helper_entrypoint() {
    let Ok(mode) = std::env::var("ALLOCATBELT_PROCESS_HELPER") else {
      return;
    };
    match mode.as_str() {
      "short-sleep" => thread::sleep(Duration::from_millis(120)),
      "long-sleep" => thread::sleep(Duration::from_secs(20)),
      "exit-23" => std::process::exit(23),
      "write-marker" => {
        thread::sleep(Duration::from_millis(100));
        if let Ok(path) = std::env::var("ALLOCATBELT_PROCESS_MARKER") {
          let _ = std::fs::write(path, b"finished");
        }
      }
      "sigchld-ignore-test" => {
        let mut driver = ProcessDriver::new(1).unwrap();
        let mut child = driver.spawn(helper("short-sleep")).unwrap();
        let outcome = block_on(child.wait());
        assert!(
          matches!(
            outcome,
            Err(WaitError::Reap(_, Some(code)))
              if code == rustix::io::Errno::CHILD.raw_os_error()
          ),
          "unexpected SIGCHLD-ignore outcome: {outcome:?}"
        );
        driver.shutdown(ProcessShutdownMode::Wait).unwrap();
      }
      _ => {}
    }
  }

  fn block_on<F: Future>(future: F) -> F::Output {
    let signal = Arc::new(WakeSignal::new());
    signal.install_current_thread();
    let waker = Waker::from(Arc::clone(&signal));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
      match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => return value,
        Poll::Pending => signal.park_timeout(Duration::from_secs(1)),
      }
    }
  }

  fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !ready() {
      assert!(Instant::now() < deadline, "condition timed out");
      thread::sleep(Duration::from_millis(5));
    }
  }

  fn tenant_with_control(
    domain_control: usize,
    tenant_control: usize,
  ) -> (
    ResourceDomain,
    crate::runtime::resource_domain::TenantDomain,
  ) {
    let domain_ceiling = DomainResources::ZERO.with(DomainResource::Control, domain_control);
    let tenant_ceiling = DomainResources::ZERO.with(DomainResource::Control, tenant_control);
    let domain = ResourceDomain::new(domain_ceiling, 1).unwrap();
    let tenant = domain.tenant(tenant_ceiling).unwrap();
    (domain, tenant)
  }

  fn reactor_control_fee(
    tenant: &crate::runtime::resource_domain::TenantDomain,
    capacity: usize,
  ) -> usize {
    let before = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    let reactor = Reactor::new_in_tenant(
      ReactorConfig {
        max_registrations: capacity,
        max_waiters: capacity,
      },
      tenant,
    )
    .unwrap();
    let after_start = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    reactor.shutdown().unwrap();
    wait_until(|| tenant.snapshot().unwrap().used.get(DomainResource::Control) == before);
    after_start - before
  }

  fn allocatbelt_threads() -> Vec<(String, String)> {
    let mut threads = std::fs::read_dir("/proc/self/task")
      .unwrap()
      .map(|entry| {
        let entry = entry.unwrap();
        let id = entry.file_name().to_string_lossy().into_owned();
        let name = std::fs::read_to_string(entry.path().join("comm")).unwrap();
        (id, name.trim().to_owned())
      })
      .filter(|(_, name)| name.starts_with("allocatbelt"))
      .collect::<Vec<_>>();
    threads.sort_unstable();
    threads
  }

  #[test]
  fn validates_capacity_bounds() {
    assert!(matches!(
      ProcessDriver::new(0),
      Err(ProcessBuildError::ZeroCapacity)
    ));
    assert!(matches!(
      ProcessDriver::new((1 << 24) + 1),
      Err(ProcessBuildError::CapacityTooLarge)
    ));
  }

  #[test]
  fn tenant_control_refusal_happens_before_process_service_threads_start() {
    const ISOLATED: &str = "ALLOCATBELT_TEST_PROCESS_CONTROL_REFUSAL_ISOLATED";
    if std::env::var_os(ISOLATED).is_none() {
      let test_name = module_path!()
        .strip_prefix("allocatbelt::")
        .unwrap_or(module_path!());
      let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
          "--exact",
          &format!(
            "{test_name}::tenant_control_refusal_happens_before_process_service_threads_start"
          ),
          "--test-threads=1",
          "--quiet",
        ])
        .env(ISOLATED, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
      let deadline = Instant::now() + Duration::from_secs(10);
      loop {
        match child.try_wait() {
          Ok(Some(status)) => {
            assert!(
              status.success(),
              "isolated Control refusal test failed: {status}"
            );
            return;
          }
          Ok(None) if Instant::now() < deadline => {
            thread::sleep(Duration::from_millis(5));
          }
          result => {
            let kill_result = child.kill();
            let wait_result = child.wait();
            panic!(
              "isolated Control refusal test did not complete: {result:?}; \
               kill: {kill_result:?}; wait: {wait_result:?}"
            );
          }
        }
      }
    }
    let (_domain, tenant) = tenant_with_control(1 << 20, 0);
    let before_threads = allocatbelt_threads();
    let before_control = tenant.snapshot().unwrap().used.get(DomainResource::Control);

    let error = match ProcessDriver::new_in_tenant(1, &tenant) {
      Ok(_) => panic!("zero-Control tenant admitted a process driver"),
      Err(error) => error,
    };

    assert!(matches!(
      error,
      ProcessBuildError::ResourceDomain(DomainError::AboveCeiling(DomainResource::Control))
    ));
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      before_control
    );
    assert_eq!(allocatbelt_threads(), before_threads);
  }

  #[test]
  fn tenant_process_fee_equals_independent_nonoverlapping_owner_payloads() {
    let (_domain, tenant) = tenant_with_control(1 << 20, 1 << 20);
    let nested_reactor_fee = reactor_control_fee(&tenant, 2);
    let baseline = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    let mut driver = ProcessDriver::new_in_tenant(2, &tenant).unwrap();
    let actual = tenant.snapshot().unwrap().used.get(DomainResource::Control) - baseline;

    let process_owner_payload =
      std::mem::size_of::<ProcessDriver>() - std::mem::size_of::<Reactor>();
    let slot_capacity = super::lock(&driver.shared.state).slots.capacity();
    let shared_payload = std::mem::size_of::<super::Shared>()
      + std::mem::size_of::<super::WakeSignal>()
      + slot_capacity * std::mem::size_of::<super::Slot>();
    let service_storage = driver.service_storage_capacities;
    let service_payload = std::mem::size_of::<super::ServiceStorage>()
      + std::mem::size_of::<Arc<super::Shared>>()
      + service_storage.reaped * std::mem::size_of::<super::Reaped>()
      + service_storage.wakes * std::mem::size_of::<Waker>();
    let reaper_completion_fee = driver.reaper.as_ref().unwrap().control_bytes();
    let independently_summed = process_owner_payload
      + shared_payload
      + service_payload
      + reaper_completion_fee
      + nested_reactor_fee;

    assert_eq!(driver._control.bytes(), process_owner_payload);
    assert_eq!(driver.shared._control.bytes(), shared_payload);
    assert_eq!(actual, independently_summed);
    driver.shutdown(ProcessShutdownMode::Wait).unwrap();
    drop(driver);
    wait_until(|| tenant.snapshot().unwrap().used.get(DomainResource::Control) == baseline);
  }

  #[test]
  fn child_completion_refusal_returns_unspawned_command_and_marker_is_recoverable() {
    let (_domain, tenant) = tenant_with_control(1 << 20, 1 << 20);
    let mut driver = ProcessDriver::new_in_tenant(1, &tenant).unwrap();
    let snapshot = tenant.snapshot().unwrap();
    let used = snapshot.used.get(DomainResource::Control);
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-process-control-marker-{}-{}",
      std::process::id(),
      NEXT_PATH.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let marker = path.to_string_lossy().into_owned();
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf reached > \"$1\"", "sh", &marker]);
    tenant
      .set_limits(snapshot.limit.with(DomainResource::Control, used))
      .unwrap();

    let error = match driver.spawn(command) {
      Ok(_) => panic!("child completion charge refusal still spawned the command"),
      Err(error) => error,
    };
    assert!(matches!(
      error.kind(),
      SpawnErrorKind::ResourceDomain(DomainError::Exhausted(DomainResource::Control))
    ));
    assert!(!path.exists(), "refused command had a side effect");
    assert_eq!(error.command().get_program(), "/bin/sh");
    let recovered = error.into_command();

    tenant.set_limits(snapshot.limit).unwrap();
    let mut child = driver.spawn(recovered).unwrap();
    assert!(block_on(child.wait()).unwrap().success());
    assert_eq!(std::fs::read(&path).unwrap(), b"reached");
    let _ = std::fs::remove_file(path);
    driver.shutdown(ProcessShutdownMode::Wait).unwrap();
  }

  #[test]
  fn tenant_charges_bound_reused_slots_and_follow_retained_completion_handles() {
    let (_domain, tenant) = tenant_with_control(1 << 20, 1 << 20);
    let baseline = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    let mut driver = ProcessDriver::new_in_tenant(1, &tenant).unwrap();
    let startup = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    assert!(startup > baseline);

    for _ in 0..4 {
      let mut child = driver.spawn(helper("exit-23")).unwrap();
      assert_eq!(block_on(child.wait()).unwrap().code(), Some(23));
      drop(child);
      wait_until(|| tenant.snapshot().unwrap().used.get(DomainResource::Control) == startup);
    }

    let mut retained = driver.spawn(helper("exit-23")).unwrap();
    let status = block_on(retained.wait()).unwrap();
    assert_eq!(status.code(), Some(23));
    assert!(tenant.snapshot().unwrap().used.get(DomainResource::Control) > startup);
    driver.shutdown(ProcessShutdownMode::Wait).unwrap();
    drop(driver);

    assert_eq!(retained.try_wait(), Ok(Some(status)));
    assert!(tenant.snapshot().unwrap().used.get(DomainResource::Control) > baseline);
    drop(retained);
    wait_until(|| tenant.snapshot().unwrap().used.get(DomainResource::Control) == baseline);
  }

  #[test]
  fn admission_closure_and_generation_exhaustion_are_typed() {
    let mut driver = ProcessDriver::new(1).unwrap();
    {
      let mut state = super::lock(&driver.shared.state);
      state.slots[0].generation = u64::MAX;
    }
    let error = driver.spawn(Command::new("/bin/true")).unwrap_err();
    assert!(matches!(error.kind(), SpawnErrorKind::Exhausted));
    let error = driver.spawn(Command::new("/bin/true")).unwrap_err();
    assert!(matches!(error.kind(), SpawnErrorKind::Exhausted));
    driver.shutdown(ProcessShutdownMode::Wait).unwrap();

    let error = driver.spawn(Command::new("/bin/true")).unwrap_err();
    assert!(matches!(error.kind(), SpawnErrorKind::Closed));
    assert_eq!(error.command().get_program(), "/bin/true");

    let mut driver = ProcessDriver::new(2).unwrap();
    let mut active = driver.spawn(helper("long-sleep")).unwrap();
    {
      let mut state = super::lock(&driver.shared.state);
      state.slots[1].generation = u64::MAX;
    }
    let error = driver.spawn(Command::new("/bin/true")).unwrap_err();
    assert!(matches!(error.kind(), SpawnErrorKind::Full));
    driver.shutdown(ProcessShutdownMode::KillAndWait).unwrap();
    assert!(block_on(active.wait()).is_ok());
  }

  #[test]
  fn full_admission_returns_original_args_env_and_stdio() {
    let mut driver = ProcessDriver::new(1).unwrap();
    let mut first = driver.spawn(helper("short-sleep")).unwrap();

    let mut command = Command::new("/bin/bash");
    command
      .args([
        "-c",
        "IFS= read -r value; printf '%s|%s|%s' \"$value\" \"$KEEP\" \"$1\"",
        "sh",
        "original-arg",
      ])
      .env("KEEP", "original-env")
      .stdin(Stdio::piped())
      .stdout(Stdio::piped());
    let rejected = match driver.spawn(command) {
      Ok(_) => panic!("second child exceeded fixed capacity"),
      Err(error) => {
        assert!(matches!(error.kind(), SpawnErrorKind::Full));
        error.into_command()
      }
    };
    assert!(block_on(first.wait()).unwrap().success());

    let mut restored = driver.spawn(rejected).unwrap();
    let mut stdin = restored.take_stdin().unwrap();
    writeln!(stdin, "original-input").unwrap();
    drop(stdin);
    let mut stdout = restored.take_stdout().unwrap();
    let mut result = String::new();
    stdout.read_to_string(&mut result).unwrap();
    assert_eq!(result, "original-input|original-env|original-arg");
    drop(stdout);
    assert!(block_on(restored.wait()).unwrap().success());
    driver.shutdown(ProcessShutdownMode::Wait).unwrap();
  }

  #[test]
  fn detached_child_is_reaped_and_default_drop_does_not_kill() {
    let mut driver = ProcessDriver::new(1).unwrap();
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-process-marker-{}-{}",
      std::process::id(),
      NEXT_PATH.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    let mut command = helper("write-marker");
    command.env("ALLOCATBELT_PROCESS_MARKER", &path);
    let child = driver.spawn(command).unwrap();
    drop(child);
    driver.shutdown(ProcessShutdownMode::Wait).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"finished");
    let _ = std::fs::remove_file(path);
  }

  static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);

  #[test]
  fn kill_on_drop_is_opt_in_and_shutdown_reaps_it() {
    let mut driver = ProcessDriver::new(1).unwrap();
    let mut child = driver.spawn(helper("long-sleep")).unwrap();
    child.set_kill_on_drop(true);
    let started = Instant::now();
    drop(child);
    driver.shutdown(ProcessShutdownMode::Wait).unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
  }

  #[test]
  fn shutdown_kill_and_wait_covers_admitted_children() {
    let mut driver = ProcessDriver::new(1).unwrap();
    let mut child = driver.spawn(helper("long-sleep")).unwrap();
    driver.shutdown(ProcessShutdownMode::KillAndWait).unwrap();
    assert!(block_on(child.wait()).is_ok());
  }

  struct CountWake(Arc<AtomicUsize>);
  impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  #[test]
  fn canceled_wait_removes_waker_and_later_wait_observes_completion() {
    let driver = ProcessDriver::new(1).unwrap();
    let mut child = driver.spawn(helper("short-sleep")).unwrap();
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountWake(Arc::clone(&wakes))));
    let mut context = Context::from_waker(&waker);
    let mut wait = Box::pin(child.wait());
    assert!(wait.as_mut().poll(&mut context).is_pending());
    drop(wait);
    wait_until(|| child.try_wait().unwrap().is_some());
    assert_eq!(wakes.load(Ordering::SeqCst), 0);
    let status = block_on(child.wait()).unwrap();
    assert!(status.success());
    assert_eq!(child.try_wait(), Ok(Some(status)));
  }

  #[test]
  fn child_wait_gates_registration_and_refunds_pending_polls() {
    let runtime = AsyncRuntime::new(AsyncConfig {
      workers: 1,
      max_outstanding: 2,
      max_scopes: 1,
    })
    .unwrap();
    let mut driver = ProcessDriver::new(1).unwrap();
    let mut child = driver.spawn(helper("long-sleep")).unwrap();
    let mut wait = Box::pin(child.wait());

    runtime
      .block_on(poll_fn(|cx| {
        for _ in 0..64 {
          assert!(super::super::asynchronous::poll_cooperative(cx, |_| Poll::Ready(())).is_ready());
        }
        assert!(wait.as_mut().poll(cx).is_pending());
        assert!(
          wait.waiter.is_none(),
          "zero budget must not register a waiter"
        );
        Poll::Ready(())
      }))
      .unwrap();

    runtime
      .block_on(poll_fn(|cx| {
        assert!(wait.as_mut().poll(cx).is_pending());
        assert!(wait.waiter.is_some());
        for _ in 0..64 {
          assert!(super::super::asynchronous::poll_cooperative(cx, |_| Poll::Ready(())).is_ready());
        }
        assert!(super::super::asynchronous::poll_cooperative(cx, |_| Poll::Ready(())).is_pending());
        Poll::Ready(())
      }))
      .unwrap();

    driver.shutdown(ProcessShutdownMode::KillAndWait).unwrap();
    runtime
      .block_on(poll_fn(|cx| {
        assert!(matches!(wait.as_mut().poll(cx), Poll::Ready(Ok(_))));
        for _ in 0..63 {
          assert!(super::super::asynchronous::poll_cooperative(cx, |_| Poll::Ready(())).is_ready());
        }
        assert_eq!(
          wait.as_mut().poll(cx),
          Poll::Ready(Err(WaitError::AlreadyCompleted))
        );
        Poll::Ready(())
      }))
      .unwrap();
    drop(wait);
    runtime.shutdown(AsyncShutdown::Drain).unwrap();
  }

  #[test]
  fn completed_handle_keeps_status_while_reaped_slot_is_reused() {
    let mut driver = ProcessDriver::new(1).unwrap();
    let mut first = driver.spawn(helper("exit-23")).unwrap();
    let first_status = block_on(first.wait()).unwrap();
    assert_eq!(first_status.code(), Some(23));
    assert_eq!(first.try_wait(), Ok(Some(first_status)));

    let mut second = driver.spawn(helper("exit-23")).unwrap();
    let second_status = block_on(second.wait()).unwrap();
    assert_eq!(second_status.code(), Some(23));
    assert_eq!(first.try_wait(), Ok(Some(first_status)));
    driver.shutdown(ProcessShutdownMode::Wait).unwrap();
  }

  #[test]
  fn dropping_driver_detaches_reaper_from_executor_and_handle() {
    let driver = ProcessDriver::new(1).unwrap();
    let mut child = driver.spawn(helper("short-sleep")).unwrap();
    drop(driver);
    let status = block_on(child.wait()).unwrap();
    assert!(status.success());
  }

  #[test]
  fn pidfd_setup_failure_uses_bounded_polling_fallback() {
    let mut driver = ProcessDriver::new_without_pidfd(1).unwrap();
    let mut child = driver.spawn(helper("short-sleep")).unwrap();
    {
      let state = super::lock(&driver.shared.state);
      let slot = &state.slots[child.key.index];
      assert_eq!(slot.generation, child.key.generation);
      assert!(slot.pidfd.is_none());
    }
    let status = block_on(child.wait()).unwrap();
    assert!(status.success());
    driver.shutdown(ProcessShutdownMode::Wait).unwrap();
    assert_eq!(driver.active_children(), 0);
  }

  #[test]
  fn ignored_sigchld_reports_lost_tracking_in_isolated_subprocess() {
    let test_name = module_path!()
      .strip_prefix("allocatbelt::")
      .unwrap_or(module_path!());
    let executable = std::env::current_exe().unwrap();
    let mut command = Command::new("/bin/bash");
    command
      .args([
        "-c",
        "trap '' CHLD; exec \"$@\"",
        "sh",
        executable.to_str().unwrap(),
        "--exact",
        &format!("{test_name}::child_helper_entrypoint"),
        "--quiet",
      ])
      .env("ALLOCATBELT_PROCESS_HELPER", "sigchld-ignore-test");
    let output = command.output().unwrap();
    assert!(
      output.status.success(),
      "isolated SIGCHLD subprocess failed:\nstdout:\n{}\nstderr:\n{}",
      String::from_utf8_lossy(&output.stdout),
      String::from_utf8_lossy(&output.stderr),
    );
  }
}
