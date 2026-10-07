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

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::future::Future;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::process::{Child as StdChild, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, JoinHandle, Thread};
use std::time::Duration;

use rustix::fd::OwnedFd;
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};

use super::reactor::{AsyncFd, OwnedReadiness, Reactor, ReactorConfig};
use super::task::drop_contained;
mod completion;
pub mod output;
pub mod pipe;
pub use completion::WaitError;
use completion::{Completion, Registration, wake_contained};

const MAX_CHILDREN: usize = 1 << 24;
const REAPER_INTERVAL: Duration = Duration::from_millis(25);
const INTERRUPT_RETRIES: usize = 64;

/// Creates a process driver with fixed capacity for `max_children` active
/// children.
///
/// Construction reserves every table before starting either service thread.
/// A zero bound, a bound larger than the reactor table limit, allocation
/// failure, reactor setup failure, or reaper thread startup failure is
/// reported before the driver is returned.
pub struct ProcessDriver {
  shared: Arc<Shared>,
  reaper: Option<JoinHandle<()>>,
  reactor: Option<Reactor>,
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
      Self::Reactor(_) => "process pidfd reactor setup failed",
      Self::Thread(_) => "process reaper thread startup failed",
    })
  }
}

impl std::error::Error for ProcessBuildError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
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
      SpawnErrorKind::Spawn(_) => "operating system rejected child process",
    })
  }
}

impl std::error::Error for SpawnError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match &self.kind {
      SpawnErrorKind::Spawn(error) => Some(error),
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
}

impl fmt::Display for ProcessShutdownError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::WouldDeadlock => "process shutdown would join its reaper thread",
      Self::ReaperPanicked => "process reaper panicked before entering fallback mode",
      Self::ReactorPanicked => "process reactor thread panicked",
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
    Self::new_inner(max_children, false)
  }

  #[cfg(test)]
  fn new_without_pidfd(max_children: usize) -> Result<Self, ProcessBuildError> {
    Self::new_inner(max_children, true)
  }

  fn new_inner(max_children: usize, force_pidfd_fallback: bool) -> Result<Self, ProcessBuildError> {
    if max_children == 0 {
      return Err(ProcessBuildError::ZeroCapacity);
    }
    if max_children > MAX_CHILDREN {
      return Err(ProcessBuildError::CapacityTooLarge);
    }

    let mut slots = Vec::new();
    slots
      .try_reserve_exact(max_children)
      .map_err(|_| ProcessBuildError::AllocationFailed)?;
    slots.resize_with(max_children, Slot::empty);

    let signal = Arc::new(WakeSignal::new());
    let mut reaped = Vec::new();
    reaped
      .try_reserve_exact(max_children)
      .map_err(|_| ProcessBuildError::AllocationFailed)?;
    let mut wakes = Vec::new();
    wakes
      .try_reserve_exact(max_children)
      .map_err(|_| ProcessBuildError::AllocationFailed)?;
    let reactor = Reactor::new(ReactorConfig {
      max_registrations: max_children,
      max_waiters: max_children,
    })
    .map_err(ProcessBuildError::Reactor)?;
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
    });
    let service = Arc::clone(&shared);
    let reaper = thread::Builder::new()
      .name("allocatbelt-process-reaper".to_owned())
      .spawn(move || run_service(service, reaped, wakes))
      .map_err(ProcessBuildError::Thread)?;

    Ok(Self {
      shared,
      reaper: Some(reaper),
      reactor: Some(reactor),
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
    let completion = Arc::new(Completion::new());
    let key = match reserve(&self.shared, &completion) {
      Ok(key) => key,
      Err(kind) => return Err(SpawnError { kind, command }),
    };

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
    install_child(&self.shared, key, completion.clone(), child, registered);

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

    if let Some(reaper) = self.reaper.take()
      && let Err(payload) = reaper.join()
    {
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
}

impl Drop for ProcessDriver {
  fn drop(&mut self) {
    close_admission(&self.shared, ProcessShutdownMode::Wait);
    // Dropping a JoinHandle detaches. The service owns `Shared` until it has
    // reaped every started child, independent of this driver and executor.
    self.reaper.take();
    // Reactor::drop is itself nonblocking and switches registered pidfds to
    // the service's fixed-cadence try_wait fallback.
    self.reactor.take();
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

fn reserve(shared: &Shared, completion: &Arc<Completion>) -> Result<SlotKey, SpawnErrorKind> {
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
    slot.completion = Some(Arc::clone(completion));
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

fn install_child(
  shared: &Shared,
  key: SlotKey,
  completion: Arc<Completion>,
  child: StdChild,
  pidfd: Option<AsyncFd<OwnedFd>>,
) {
  let installed = {
    let mut state = lock(&shared.state);
    let Some(slot) = state.slots.get_mut(key.index) else {
      return;
    };
    if slot.generation != key.generation || slot.state != SlotState::Reserved {
      return;
    }
    slot.child = Some(child);
    slot.completion = Some(completion);
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

fn run_service(shared: Arc<Shared>, mut reaped: Vec<Reaped>, mut wakes: Vec<Waker>) {
  shared.signal.install_current_thread();
  let mut use_reactor = true;
  loop {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
      service_loop(&shared, &mut reaped, &mut wakes, use_reactor)
    }));
    match result {
      Ok(()) => break,
      Err(payload) => {
        drop_contained(payload);
        lock(&shared.state).worker_panicked = true;
        finish_reaped(&mut reaped, &mut wakes);
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
  use std::future::Future;
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
      .env("ALLOCATBELT_PROCESS_HELPER", mode);
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
    let status = command.status().unwrap();
    assert!(status.success());
  }
}
