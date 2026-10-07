//! Bounded, owned-buffer positional file operations over a dedicated io_uring
//! issuer.
//!
//! This service is independent of the allocator's purge ring. It admits at
//! most `max_operations` requests total, including requests that have
//! completed but whose [`UringOperation`] has not been polled or dropped.
//! Each request owns one unique [`ManagedBuf`], one [`OwnedFd`], and one disk
//! operation permit. The permit lasts through the actual kernel completion;
//! the buffer's managed-memory charge lasts until its final buffer owner is
//! dropped.
//!
//! Dropping an operation future cancels work while it is still queued. Once
//! the issuer claims it for submission, the request is irrevocable: dropping
//! the future detaches observation, and the service keeps the descriptor and
//! buffer alive until the original CQE. It never cancels or replays a
//! published operation. If completion ownership becomes uncertain, the
//! service fails stop rather than releasing kernel-visible memory.
//!
//! Callers must provide a regular file. The service checks the file type and
//! observed access/status flags at admission. Do not concurrently change
//! `O_APPEND` or `O_DIRECT` through this descriptor or any alias while this
//! service owns it; POSIX file-status flags may be shared by duplicated
//! descriptors. Positional
//! requests use one kernel operation and may complete short; the returned
//! byte count and buffer are preserved for the caller to decide what to do
//! next. Requests are limited to `u32::MAX` bytes, the io_uring SQE length
//! width, and their end offsets are checked before admission.
//!
//! Small service/slot metadata uses ordinary allocations. The slot table is
//! reserved fallibly and never grows; the standard `Arc` and thread metadata
//! follow Rust's ordinary allocation behavior. The ring backend is an
//! internal unsafe boundary; this module contains no unsafe code.

#![cfg(not(loom))]

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io;
use std::os::fd::OwnedFd;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::Duration;

use rustix::fs::{self, FileType, OFlags};

use super::managed::{ManagedBuf, OperationPermit, OperationRequest, ResourceError, ResourceScope};
use super::uring_protocol::{Completion, Detach, NotPublished, Phase, SlotProtocol};
use crate::sys::runtime_ring::{
  NotPublished as RingNotPublished, OperationKind, RingCompletion, RingOperation, RingStartError,
  RuntimeRing,
};

const MAX_OPERATIONS: usize = 1024;
const WAIT_SLICE: Duration = Duration::from_millis(20);

/// Fixed service limits. The ring depth is the next power of two above
/// `max_operations`; the service rejects more than 1024 public slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UringConfig {
  /// Maximum accepted operations, including queued, kernel-owned and
  /// completed-but-unclaimed requests. Must be in `1..=1024`.
  pub max_operations: usize,
}

impl Default for UringConfig {
  fn default() -> Self {
    Self { max_operations: 64 }
  }
}

/// Why the io_uring service could not start. Startup completes before any
/// handle is returned, so these failures cannot strand admitted inputs.
#[derive(Debug)]
#[non_exhaustive]
pub enum UringStartErrorKind {
  /// The configured slot count is zero or exceeds the fixed implementation
  /// ceiling.
  InvalidConfig,
  /// The fixed slot table could not reserve its metadata.
  OutOfMemory,
  /// The issuer thread could not be created.
  ThreadSpawn(io::Error),
  /// The backend failed while creating/probing the ring.
  Ring {
    phase: &'static str,
    error: io::Error,
  },
  /// The issuer exited before the startup handshake completed.
  IssuerStopped,
}

/// Startup failure with a stable public error type.
#[derive(Debug)]
pub struct UringStartError {
  /// The failure stage.
  pub kind: UringStartErrorKind,
}

impl fmt::Display for UringStartError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match &self.kind {
      UringStartErrorKind::InvalidConfig => {
        f.write_str("io_uring operation capacity must be in 1..=1024")
      }
      UringStartErrorKind::OutOfMemory => f.write_str("io_uring slot table allocation failed"),
      UringStartErrorKind::ThreadSpawn(error) => write!(f, "io_uring issuer thread: {error}"),
      UringStartErrorKind::Ring { phase, error } => {
        write!(f, "io_uring startup {phase}: {error}")
      }
      UringStartErrorKind::IssuerStopped => f.write_str("io_uring issuer stopped during startup"),
    }
  }
}

impl Error for UringStartError {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    match &self.kind {
      UringStartErrorKind::ThreadSpawn(error) | UringStartErrorKind::Ring { error, .. } => {
        Some(error)
      }
      _ => None,
    }
  }
}

/// Why a request was rejected before acceptance. The original tuple remains
/// available in [`UringSubmitError::input`].
#[derive(Debug)]
#[non_exhaustive]
pub enum UringSubmitErrorKind {
  /// The explicit scope could not reserve one disk operation permit.
  Resource(ResourceError),
  /// The service has closed admission.
  Closed,
  /// All fixed slots are occupied, including completed unclaimed results.
  Full,
  /// Another `ManagedBuf` clone prevents exclusive kernel access.
  SharedBuffer,
  /// The buffer length exceeds the io_uring single-operation field.
  BufferTooLarge,
  /// `offset + buffer.len()` is not representable.
  OffsetOverflow,
  /// The descriptor was opened with `O_PATH` and cannot perform I/O.
  PathOnly,
  /// `O_DIRECT` alignment requirements are outside this service's contract.
  DirectIo,
  /// The descriptor does not refer to a regular file.
  NotRegularFile,
  /// The observed descriptor access/status mode does not match the request.
  AccessMode,
  /// The file-type or status-flag query failed before admission.
  FileQuery(io::Error),
}

impl fmt::Display for UringSubmitErrorKind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Resource(error) => write!(f, "io_uring request refused: {error}"),
      Self::Closed => f.write_str("io_uring service is closed"),
      Self::Full => f.write_str("io_uring operation table is full"),
      Self::SharedBuffer => f.write_str("io_uring requires a uniquely owned managed buffer"),
      Self::BufferTooLarge => f.write_str("buffer exceeds the io_uring operation length limit"),
      Self::OffsetOverflow => f.write_str("file offset plus buffer length overflows"),
      Self::PathOnly => f.write_str("io_uring file operations reject O_PATH descriptors"),
      Self::DirectIo => f.write_str("io_uring file operations reject O_DIRECT descriptors"),
      Self::NotRegularFile => f.write_str("io_uring file operations require a regular file"),
      Self::AccessMode => f.write_str("file descriptor access mode does not match the operation"),
      Self::FileQuery(error) => write!(
        f,
        "query file descriptor before io_uring admission: {error}"
      ),
    }
  }
}

impl Error for UringSubmitErrorKind {
  fn source(&self) -> Option<&(dyn Error + 'static)> {
    match self {
      Self::Resource(error) => Some(error),
      Self::FileQuery(error) => Some(error),
      _ => None,
    }
  }
}

/// Request rejection together with the exact original owned inputs.
pub struct UringSubmitError<I> {
  /// Why the request was not accepted.
  pub kind: UringSubmitErrorKind,
  /// The unchanged input, available for another strategy or retry.
  pub input: I,
}

impl<I> UringSubmitError<I> {
  /// Returns the inputs that were not admitted.
  #[must_use]
  pub fn into_input(self) -> I {
    self.input
  }
}

impl<I> fmt::Debug for UringSubmitError<I> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("UringSubmitError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl<I> fmt::Display for UringSubmitError<I> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.kind.fmt(f)
  }
}

impl<I: 'static> Error for UringSubmitError<I> {}

/// One completed positional operation. I/O failures and partial results keep
/// both owned inputs so the caller can inspect/reuse them.
#[derive(Debug)]
pub struct UringOutcome {
  /// The descriptor, retained until the original kernel completion.
  pub fd: OwnedFd,
  /// The managed buffer, retained until the final buffer owner is dropped.
  pub buffer: ManagedBuf,
  /// Bytes transferred by the one kernel operation.
  pub bytes: usize,
  /// Kernel I/O error, if any. A partial byte count is preserved.
  pub error: Option<io::Error>,
}

/// A coherent slot-table snapshot. Completed unclaimed outcomes count as
/// occupied slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UringSnapshot {
  /// Fixed accepted-operation capacity.
  pub max_operations: usize,
  /// Occupied slots in any non-vacant state.
  pub occupied: usize,
  /// Requests waiting in FIFO order.
  pub queued: usize,
  /// Requests owned by the kernel backend.
  pub published: usize,
  /// CQEs observed while their disk permit is being released before
  /// completion publication.
  pub completing: usize,
  /// CQEs stored until their operation futures consume or drop them.
  pub completed: usize,
  /// Whether new submissions are refused.
  pub closed: bool,
}

/// Owner for the dedicated issuer thread. Dropping it closes admission and
/// detaches the issuer; the issuer retains its ring and every in-flight owner
/// while draining actual CQEs. Use [`shutdown`](Self::shutdown) to wait.
pub struct UringRuntime {
  shared: Arc<Shared>,
  issuer_id: ThreadId,
  issuer: Option<JoinHandle<()>>,
}

impl fmt::Debug for UringRuntime {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let snapshot = self.snapshot();
    f.debug_struct("UringRuntime")
      .field("snapshot", &snapshot)
      .finish_non_exhaustive()
  }
}

impl UringRuntime {
  /// Starts a dedicated issuer and returns only after the kernel ring has been
  /// created and both positional READ/WRITE operations have been probed.
  pub fn start(config: UringConfig, resources: ResourceScope) -> Result<Self, UringStartError> {
    if config.max_operations == 0 || config.max_operations > MAX_OPERATIONS {
      return Err(UringStartError {
        kind: UringStartErrorKind::InvalidConfig,
      });
    }
    let depth = u32::try_from(config.max_operations)
      .ok()
      .and_then(u32::checked_next_power_of_two)
      .ok_or(UringStartError {
        kind: UringStartErrorKind::InvalidConfig,
      })?;
    Self::start_with(config.max_operations, resources, move || {
      RuntimeRing::new(depth).map_err(map_ring_start_error)
    })
  }

  fn start_with<D, Make>(
    max_operations: usize,
    resources: ResourceScope,
    make_driver: Make,
  ) -> Result<Self, UringStartError>
  where
    D: RingDriver + 'static,
    Make: FnOnce() -> Result<D, UringStartErrorKind> + Send + 'static,
  {
    let mut slots = Vec::new();
    slots
      .try_reserve_exact(max_operations)
      .map_err(|_| UringStartError {
        kind: UringStartErrorKind::OutOfMemory,
      })?;
    slots.resize_with(max_operations, Slot::new);
    let shared = Arc::new(Shared {
      max_operations,
      resources,
      state: Mutex::new(Inner {
        slots,
        queue_head: None,
        queue_tail: None,
        occupied: 0,
        published: 0,
        closed: false,
      }),
      changed: Condvar::new(),
    });
    let issuer_shared = Arc::clone(&shared);
    let (startup_tx, startup_rx) = mpsc::sync_channel(1);
    let issuer = thread::Builder::new()
      .name("allocatbelt-io-uring".to_owned())
      .spawn(move || {
        let made = panic::catch_unwind(AssertUnwindSafe(make_driver));
        let driver = match made {
          Ok(Ok(driver)) => driver,
          Ok(Err(error)) => {
            let _ = startup_tx.send(Err(error));
            return;
          }
          Err(payload) => {
            drop_contained(payload);
            let _ = startup_tx.send(Err(UringStartErrorKind::IssuerStopped));
            return;
          }
        };
        let issuer_id = thread::current().id();
        if startup_tx.send(Ok(issuer_id)).is_err() {
          // No handle was returned and no request could have been admitted.
          return;
        }
        let run = panic::catch_unwind(AssertUnwindSafe(|| issuer_loop(driver, issuer_shared)));
        if let Err(payload) = run {
          // The driver owns possibly kernel-visible buffers. Its Drop is
          // itself fail-stop while any CQE is outstanding; abort here also
          // prevents unwinding through any still-live runtime owners.
          drop_contained(payload);
          std::process::abort();
        }
      })
      .map_err(|error| UringStartError {
        kind: UringStartErrorKind::ThreadSpawn(error),
      })?;
    match startup_rx.recv() {
      Ok(Ok(issuer_id)) => Ok(Self {
        shared,
        issuer_id,
        issuer: Some(issuer),
      }),
      Ok(Err(kind)) => {
        join_startup_thread(issuer);
        Err(UringStartError { kind })
      }
      Err(_) => {
        join_startup_thread(issuer);
        Err(UringStartError {
          kind: UringStartErrorKind::IssuerStopped,
        })
      }
    }
  }

  /// Returns a cloneable submission handle. Handles keep result slots alive
  /// after this owner closes or drops the service.
  #[must_use]
  pub fn handle(&self) -> UringHandle {
    UringHandle {
      shared: Arc::clone(&self.shared),
    }
  }

  /// Closes admission, drains queued and published work to actual CQEs, then
  /// joins the issuer. This may wait indefinitely for the kernel operation.
  pub fn shutdown(&mut self) -> Result<(), UringShutdownError> {
    if thread::current().id() == self.issuer_id {
      return Err(UringShutdownError::WouldDeadlock);
    }
    close_admission(&self.shared);
    let Some(issuer) = self.issuer.take() else {
      return Ok(());
    };
    if let Err(payload) = issuer.join() {
      drop_contained(payload);
      return Err(UringShutdownError::IssuerPanicked);
    }
    Ok(())
  }

  /// Returns a coherent snapshot of service slot states.
  #[must_use]
  pub fn snapshot(&self) -> UringSnapshot {
    snapshot(&self.shared)
  }
}

impl Drop for UringRuntime {
  fn drop(&mut self) {
    close_admission(&self.shared);
    // Dropping JoinHandle detaches. Shared ownership in the issuer keeps the
    // ring, permits and kernel-visible buffers alive while it drains.
    drop(self.issuer.take());
  }
}

/// Why an explicit shutdown could not join normally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UringShutdownError {
  /// Shutdown was called by the issuer thread from a reentrant callback.
  WouldDeadlock,
  /// The issuer panicked before its fail-stop boundary was entered.
  IssuerPanicked,
}

impl fmt::Display for UringShutdownError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::WouldDeadlock => "io_uring shutdown from its issuer would deadlock",
      Self::IssuerPanicked => "io_uring issuer panicked",
    })
  }
}

impl Error for UringShutdownError {}

/// Cloneable handle for a fixed-capacity io_uring service.
#[derive(Clone)]
pub struct UringHandle {
  shared: Arc<Shared>,
}

impl UringHandle {
  /// Submits one positional read. On rejection, the original descriptor,
  /// buffer, and offset are returned unchanged.
  pub fn try_read_at(
    &self,
    fd: OwnedFd,
    buffer: ManagedBuf,
    offset: u64,
  ) -> Result<UringOperation, UringSubmitError<(OwnedFd, ManagedBuf, u64)>> {
    self.submit(OperationKind::ReadAt, fd, buffer, offset)
  }

  /// Submits one positional write. On rejection, the original descriptor,
  /// buffer, and offset are returned unchanged.
  pub fn try_write_at(
    &self,
    fd: OwnedFd,
    buffer: ManagedBuf,
    offset: u64,
  ) -> Result<UringOperation, UringSubmitError<(OwnedFd, ManagedBuf, u64)>> {
    self.submit(OperationKind::WriteAt, fd, buffer, offset)
  }

  /// Returns a coherent capacity snapshot.
  #[must_use]
  pub fn snapshot(&self) -> UringSnapshot {
    snapshot(&self.shared)
  }

  fn submit(
    &self,
    kind: OperationKind,
    fd: OwnedFd,
    buffer: ManagedBuf,
    offset: u64,
  ) -> Result<UringOperation, UringSubmitError<(OwnedFd, ManagedBuf, u64)>> {
    let mut input = (fd, buffer, offset);
    if let Err(kind) = validate(kind, &input.0, &mut input.1, input.2) {
      return Err(UringSubmitError { kind, input });
    }
    let permit = match self.shared.resources.try_acquire(OperationRequest {
      disk: 1,
      network: 0,
    }) {
      Ok(permit) => permit,
      Err(error) => {
        return Err(UringSubmitError {
          kind: UringSubmitErrorKind::Resource(error),
          input,
        });
      }
    };
    let mut permit = Some(permit);
    let mut state = lock(&self.shared.state);
    if state.closed {
      drop(state);
      drop(permit.take());
      return Err(UringSubmitError {
        kind: UringSubmitErrorKind::Closed,
        input,
      });
    }
    let mut selected = None;
    for (index, slot) in state.slots.iter_mut().enumerate() {
      if slot.protocol.phase() == Phase::Vacant
        && let Some(generation) = slot.protocol.reserve()
      {
        selected = Some((index, generation));
        break;
      }
    }
    let Some((index, generation)) = selected else {
      drop(state);
      drop(permit.take());
      return Err(UringSubmitError {
        kind: UringSubmitErrorKind::Full,
        input,
      });
    };
    let slot = &mut state.slots[index];
    slot.operation = Some(RingOperation {
      user_data: user_data(index, generation),
      fd: input.0,
      buffer: input.1,
      offset: input.2,
      kind,
    });
    slot.permit = permit.take();
    state.occupied += 1;
    enqueue_back(&mut state, index);
    drop(state);
    self.shared.changed.notify_one();
    Ok(UringOperation {
      shared: Arc::clone(&self.shared),
      index,
      generation,
      done: false,
    })
  }
}

/// Future for one owned positional operation. It is intentionally not
/// cloneable; dropping it cancels only a request still queued for the issuer.
pub struct UringOperation {
  shared: Arc<Shared>,
  index: usize,
  generation: u32,
  done: bool,
}

impl fmt::Debug for UringOperation {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("UringOperation")
      .field("slot", &self.index)
      .field("generation", &self.generation)
      .field("done", &self.done)
      .finish_non_exhaustive()
  }
}

impl Future for UringOperation {
  type Output = UringOutcome;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.done {
      return Poll::Pending;
    }
    let immediate = {
      let mut state = lock(&this.shared.state);
      let slot = state
        .slots
        .get_mut(this.index)
        .unwrap_or_else(|| std::process::abort());
      if !slot.protocol.matches(this.generation) {
        std::process::abort();
      }
      if slot.protocol.phase() == Phase::Completed {
        if !slot.protocol.consume(this.generation) {
          std::process::abort();
        }
        let result = slot.outcome.take().unwrap_or_else(|| std::process::abort());
        let old = slot.waker.take();
        state.occupied -= 1;
        Some((result, old))
      } else {
        None
      }
    };
    if let Some((outcome, old_waker)) = immediate {
      drop_contained(old_waker);
      this.done = true;
      return Poll::Ready(outcome);
    }

    // Clone user-provided wakers outside the service mutex. A panic leaves
    // the accepted operation and its previous registration intact.
    let candidate = cx.waker().clone();
    let (ready, old, unused) = {
      let mut state = lock(&this.shared.state);
      let slot = state
        .slots
        .get_mut(this.index)
        .unwrap_or_else(|| std::process::abort());
      if !slot.protocol.matches(this.generation) {
        std::process::abort();
      }
      if slot.protocol.phase() == Phase::Completed {
        if !slot.protocol.consume(this.generation) {
          std::process::abort();
        }
        let result = slot.outcome.take().unwrap_or_else(|| std::process::abort());
        let old = slot.waker.take();
        state.occupied -= 1;
        (Some(result), old, Some(candidate))
      } else {
        let old = slot.waker.replace(candidate);
        (None, old, None)
      }
    };
    drop_contained(old);
    drop_contained(unused);
    if let Some(outcome) = ready {
      this.done = true;
      Poll::Ready(outcome)
    } else {
      Poll::Pending
    }
  }
}

impl Drop for UringOperation {
  fn drop(&mut self) {
    if self.done {
      return;
    }
    let (operation, permit, outcome, waker, notify) = {
      let mut state = lock(&self.shared.state);
      let Some(slot) = state.slots.get_mut(self.index) else {
        return;
      };
      match slot.protocol.detach(self.generation) {
        Detach::Stale => return,
        Detach::CancelQueued => {
          unlink(&mut state, self.index);
          state.occupied -= 1;
          let slot = &mut state.slots[self.index];
          (
            slot.operation.take(),
            slot.permit.take(),
            slot.outcome.take(),
            slot.waker.take(),
            true,
          )
        }
        Detach::MarkDetached => {
          let waker = state.slots[self.index].waker.take();
          (None, None, None, waker, false)
        }
        Detach::DropCompleted => {
          state.occupied -= 1;
          let slot = &mut state.slots[self.index];
          (
            slot.operation.take(),
            slot.permit.take(),
            slot.outcome.take(),
            slot.waker.take(),
            false,
          )
        }
      }
    };
    drop_contained(operation);
    drop_contained(permit);
    drop_contained(outcome);
    drop_contained(waker);
    if notify {
      self.shared.changed.notify_one();
    }
  }
}

struct Shared {
  max_operations: usize,
  resources: ResourceScope,
  state: Mutex<Inner>,
  changed: Condvar,
}

struct Inner {
  slots: Vec<Slot>,
  queue_head: Option<usize>,
  queue_tail: Option<usize>,
  occupied: usize,
  published: usize,
  closed: bool,
}

struct Slot {
  protocol: SlotProtocol,
  operation: Option<RingOperation>,
  permit: Option<OperationPermit>,
  waker: Option<Waker>,
  outcome: Option<UringOutcome>,
  previous: Option<usize>,
  next: Option<usize>,
}

impl Slot {
  fn new() -> Self {
    Self {
      protocol: SlotProtocol::new(),
      operation: None,
      permit: None,
      waker: None,
      outcome: None,
      previous: None,
      next: None,
    }
  }
}

trait RingDriver {
  fn publish(&mut self, operation: RingOperation) -> Result<(), RingNotPublished>;
  fn poll_completion(&mut self) -> Option<RingCompletion>;
  fn wait_with_timeout(&mut self, timeout: Duration) -> Option<RingCompletion>;
}

impl RingDriver for RuntimeRing {
  fn publish(&mut self, operation: RingOperation) -> Result<(), RingNotPublished> {
    RuntimeRing::publish(self, operation)
  }

  fn poll_completion(&mut self) -> Option<RingCompletion> {
    RuntimeRing::poll_completion(self)
  }

  fn wait_with_timeout(&mut self, timeout: Duration) -> Option<RingCompletion> {
    RuntimeRing::wait_with_timeout(self, timeout)
  }
}

fn issuer_loop<D: RingDriver>(mut driver: D, shared: Arc<Shared>) {
  let mut ring_blocked = false;
  loop {
    let queued = if ring_blocked {
      None
    } else {
      let mut state = lock(&shared.state);
      if let Some(index) = pop_front(&mut state) {
        let slot = &mut state.slots[index];
        let generation = slot.protocol.generation();
        if !slot.protocol.claim(generation) {
          std::process::abort();
        }
        let operation = slot
          .operation
          .take()
          .unwrap_or_else(|| std::process::abort());
        Some((index, generation, operation))
      } else if state.closed && state.published == 0 {
        None
      } else if state.published == 0 {
        state = shared
          .changed
          .wait_while(state, |inner| {
            inner.queue_head.is_none() && !(inner.closed && inner.published == 0)
          })
          .unwrap_or_else(PoisonError::into_inner);
        drop(state);
        continue;
      } else {
        None
      }
    };

    if let Some((index, generation, operation)) = queued {
      if operation.buffer.is_empty() {
        complete_local(&shared, index, generation, operation);
      } else {
        match driver.publish(operation) {
          Ok(()) => {
            let mut state = lock(&shared.state);
            let slot = &mut state.slots[index];
            if !slot.protocol.published(generation) {
              std::process::abort();
            }
            state.published += 1;
          }
          Err(not_published) => {
            let ring_has_in_flight = lock(&shared.state).published > 0;
            if not_published.error.kind() == io::ErrorKind::WouldBlock && ring_has_in_flight {
              retry_not_published(&shared, index, generation, not_published.operation);
              ring_blocked = true;
            } else {
              fail_not_published(
                &shared,
                index,
                generation,
                not_published.operation,
                not_published.error,
              );
            }
          }
        }
      }
      if !ring_blocked {
        continue;
      }
    }

    if let Some(completion) = driver.poll_completion() {
      complete_cqe(&shared, completion);
      ring_blocked = false;
      continue;
    }

    let has_published = lock(&shared.state).published > 0;
    if has_published {
      if let Some(completion) = driver.wait_with_timeout(WAIT_SLICE) {
        complete_cqe(&shared, completion);
        ring_blocked = false;
      }
      continue;
    }

    let mut state = lock(&shared.state);
    if state.closed && state.published == 0 && state.queue_head.is_none() {
      break;
    }
    if state.published == 0 && state.queue_head.is_some() {
      state = shared
        .changed
        .wait_while(state, |inner| {
          inner.published == 0 && inner.queue_head.is_some() && !inner.closed
        })
        .unwrap_or_else(PoisonError::into_inner);
      drop(state);
    }
  }
}

fn retry_not_published(shared: &Shared, index: usize, generation: u32, operation: RingOperation) {
  let (drop_operation, drop_permit, drop_waker, notify) = {
    let mut state = lock(&shared.state);
    let slot = &mut state.slots[index];
    match slot.protocol.not_published(generation) {
      NotPublished::Requeue => {
        slot.operation = Some(operation);
        enqueue_front(&mut state, index);
        (None, None, None, true)
      }
      NotPublished::Cancel => {
        state.occupied -= 1;
        let slot = &mut state.slots[index];
        (
          Some(operation),
          slot.permit.take(),
          slot.waker.take(),
          false,
        )
      }
      NotPublished::Stale => std::process::abort(),
    }
  };
  drop_contained(drop_operation);
  drop_contained(drop_permit);
  drop_contained(drop_waker);
  if notify {
    shared.changed.notify_one();
  }
}

fn fail_not_published(
  shared: &Shared,
  index: usize,
  generation: u32,
  operation: RingOperation,
  error: io::Error,
) {
  let permit = {
    let mut state = lock(&shared.state);
    let slot = &mut state.slots[index];
    if slot.protocol.fail_unpublished(generation).is_none() {
      std::process::abort();
    }
    slot.permit.take()
  };
  drop_contained(permit);
  let outcome = outcome_from_operation(operation, Err(error));
  let (drop_outcome, wake) = {
    let mut state = lock(&shared.state);
    match state.slots[index].protocol.finish_completion(generation) {
      Completion::FatalStale => std::process::abort(),
      Completion::DropDetached => {
        state.occupied -= 1;
        (Some(outcome), state.slots[index].waker.take())
      }
      Completion::PublishResult => {
        let slot = &mut state.slots[index];
        slot.outcome = Some(outcome);
        (None, slot.waker.take())
      }
    }
  };
  drop_contained(drop_outcome);
  wake_contained(wake);
}

fn complete_local(shared: &Shared, index: usize, generation: u32, operation: RingOperation) {
  {
    let mut state = lock(&shared.state);
    let slot = &mut state.slots[index];
    if slot.protocol.local_complete(generation).is_none() {
      std::process::abort();
    }
  }
  let permit = lock(&shared.state).slots[index].permit.take();
  drop_contained(permit);
  let outcome = outcome_from_operation(operation, Ok(0));
  let (drop_outcome, wake) = {
    let mut state = lock(&shared.state);
    match state.slots[index].protocol.finish_completion(generation) {
      Completion::FatalStale => std::process::abort(),
      Completion::DropDetached => {
        state.occupied -= 1;
        (Some(outcome), state.slots[index].waker.take())
      }
      Completion::PublishResult => {
        let slot = &mut state.slots[index];
        slot.outcome = Some(outcome);
        (None, slot.waker.take())
      }
    }
  };
  drop_contained(drop_outcome);
  wake_contained(wake);
}

fn complete_cqe(shared: &Shared, completion: RingCompletion) {
  let (index, generation) = decode_user_data(completion.user_data);
  let mut completion = Some(completion);
  if completion
    .as_ref()
    .is_some_and(|cqe| matches!(&cqe.result, Ok(bytes) if *bytes > cqe.buffer.len()))
  {
    std::process::abort();
  }
  let permit = {
    let mut state = lock(&shared.state);
    let Some(slot) = state.slots.get_mut(index) else {
      std::process::abort();
    };
    if !slot.protocol.begin_kernel_completion(generation) {
      std::process::abort();
    }
    state.published = state
      .published
      .checked_sub(1)
      .unwrap_or_else(|| std::process::abort());
    state.slots[index].permit.take()
  };
  drop_contained(permit);
  let outcome = outcome_from_completion(completion.take().unwrap_or_else(|| std::process::abort()));
  let (drop_outcome, wake) = {
    let mut state = lock(&shared.state);
    match state.slots[index].protocol.finish_completion(generation) {
      Completion::FatalStale => std::process::abort(),
      Completion::DropDetached => {
        state.occupied -= 1;
        (Some(outcome), state.slots[index].waker.take())
      }
      Completion::PublishResult => {
        let slot = &mut state.slots[index];
        slot.outcome = Some(outcome);
        (None, slot.waker.take())
      }
    }
  };
  drop_contained(drop_outcome);
  drop_contained(completion);
  wake_contained(wake);
  shared.changed.notify_one();
}

fn outcome_from_completion(completion: RingCompletion) -> UringOutcome {
  let (bytes, error) = match completion.result {
    Ok(bytes) => (bytes, None),
    Err(error) => (0, Some(error)),
  };
  UringOutcome {
    fd: completion.fd,
    buffer: completion.buffer,
    bytes,
    error,
  }
}

fn outcome_from_operation(operation: RingOperation, result: io::Result<usize>) -> UringOutcome {
  let (bytes, error) = match result {
    Ok(bytes) => (bytes, None),
    Err(error) => (0, Some(error)),
  };
  UringOutcome {
    fd: operation.fd,
    buffer: operation.buffer,
    bytes,
    error,
  }
}

fn validate(
  kind: OperationKind,
  fd: &OwnedFd,
  buffer: &mut ManagedBuf,
  offset: u64,
) -> Result<(), UringSubmitErrorKind> {
  if buffer.get_mut().is_none() {
    return Err(UringSubmitErrorKind::SharedBuffer);
  }
  let len = buffer.len();
  if len > u32::MAX as usize {
    return Err(UringSubmitErrorKind::BufferTooLarge);
  }
  let len_u64 = u64::try_from(len).map_err(|_| UringSubmitErrorKind::OffsetOverflow)?;
  let end = offset
    .checked_add(len_u64)
    .ok_or(UringSubmitErrorKind::OffsetOverflow)?;
  if end > i64::MAX as u64 {
    return Err(UringSubmitErrorKind::OffsetOverflow);
  }
  let stat = fs::fstat(fd).map_err(|error| UringSubmitErrorKind::FileQuery(error.into()))?;
  if !FileType::from_raw_mode(stat.st_mode).is_file() {
    return Err(UringSubmitErrorKind::NotRegularFile);
  }
  let flags = fs::fcntl_getfl(fd).map_err(|error| UringSubmitErrorKind::FileQuery(error.into()))?;
  if flags.contains(OFlags::PATH) {
    return Err(UringSubmitErrorKind::PathOnly);
  }
  if flags.contains(OFlags::DIRECT) {
    return Err(UringSubmitErrorKind::DirectIo);
  }
  let mode = flags & OFlags::ACCMODE;
  match kind {
    OperationKind::ReadAt if mode == OFlags::WRONLY => {
      return Err(UringSubmitErrorKind::AccessMode);
    }
    OperationKind::WriteAt if mode == OFlags::RDONLY || flags.contains(OFlags::APPEND) => {
      return Err(UringSubmitErrorKind::AccessMode);
    }
    _ => {}
  }
  Ok(())
}

fn map_ring_start_error(error: RingStartError) -> UringStartErrorKind {
  UringStartErrorKind::Ring {
    phase: error.phase,
    error: error.error,
  }
}

fn join_startup_thread(issuer: JoinHandle<()>) {
  if let Err(payload) = issuer.join() {
    drop_contained(payload);
  }
}

fn close_admission(shared: &Shared) {
  {
    let mut state = lock(&shared.state);
    state.closed = true;
  }
  shared.changed.notify_all();
}

fn snapshot(shared: &Shared) -> UringSnapshot {
  let state = lock(&shared.state);
  let queued = state
    .slots
    .iter()
    .filter(|slot| slot.protocol.phase() == Phase::Queued)
    .count();
  let completed = state
    .slots
    .iter()
    .filter(|slot| slot.protocol.phase() == Phase::Completed)
    .count();
  let completing = state
    .slots
    .iter()
    .filter(|slot| slot.protocol.phase() == Phase::Completing)
    .count();
  UringSnapshot {
    max_operations: shared.max_operations,
    occupied: state.occupied,
    queued,
    published: state.published,
    completing,
    completed,
    closed: state.closed,
  }
}

fn enqueue_back(state: &mut Inner, index: usize) {
  let tail = state.queue_tail;
  {
    let slot = &mut state.slots[index];
    slot.previous = tail;
    slot.next = None;
  }
  if let Some(tail) = tail {
    state.slots[tail].next = Some(index);
  } else {
    state.queue_head = Some(index);
  }
  state.queue_tail = Some(index);
}

fn enqueue_front(state: &mut Inner, index: usize) {
  let head = state.queue_head;
  {
    let slot = &mut state.slots[index];
    slot.previous = None;
    slot.next = head;
  }
  if let Some(head) = head {
    state.slots[head].previous = Some(index);
  } else {
    state.queue_tail = Some(index);
  }
  state.queue_head = Some(index);
}

fn pop_front(state: &mut Inner) -> Option<usize> {
  let index = state.queue_head?;
  unlink(state, index);
  Some(index)
}

fn unlink(state: &mut Inner, index: usize) {
  let previous = state.slots[index].previous;
  let next = state.slots[index].next;
  if let Some(previous) = previous {
    state.slots[previous].next = next;
  } else {
    state.queue_head = next;
  }
  if let Some(next) = next {
    state.slots[next].previous = previous;
  } else {
    state.queue_tail = previous;
  }
  state.slots[index].previous = None;
  state.slots[index].next = None;
}

const fn user_data(index: usize, generation: u32) -> u64 {
  ((generation as u64) << 32) | (index as u64)
}

const fn decode_user_data(user_data: u64) -> (usize, u32) {
  (user_data as u32 as usize, (user_data >> 32) as u32)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn wake_contained(waker: Option<Waker>) {
  if let Some(waker) = waker
    && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
  {
    drop_contained(payload);
  }
}

fn drop_contained<T>(value: T) {
  if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(value)))
    && let Err(second) = panic::catch_unwind(AssertUnwindSafe(|| drop(payload)))
  {
    std::mem::forget(second);
  }
}

#[cfg(test)]
#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::VecDeque;
  use std::fs::{File, OpenOptions};
  use std::os::fd::OwnedFd;
  use std::os::unix::fs::OpenOptionsExt;
  use std::os::unix::net::UnixStream;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::Waker;

  use super::super::managed::ResourceLimits;

  struct FakeState {
    max_in_flight: usize,
    auto_complete: bool,
    pending: VecDeque<RingOperation>,
    completed: VecDeque<RingCompletion>,
    published_ids: Vec<u64>,
  }

  struct FakeControl {
    state: Mutex<FakeState>,
    changed: Condvar,
  }

  struct FakeDriver {
    control: Arc<FakeControl>,
  }

  impl RingDriver for FakeDriver {
    fn publish(&mut self, operation: RingOperation) -> Result<(), RingNotPublished> {
      let mut state = lock(&self.control.state);
      if state.pending.len() >= state.max_in_flight && !state.auto_complete {
        return Err(RingNotPublished {
          operation,
          error: io::ErrorKind::WouldBlock.into(),
        });
      }
      state.published_ids.push(operation.user_data);
      if state.auto_complete {
        let result = Ok(operation.buffer.len());
        state.completed.push_back(RingCompletion {
          user_data: operation.user_data,
          fd: operation.fd,
          buffer: operation.buffer,
          result,
        });
      } else {
        state.pending.push_back(operation);
      }
      self.control.changed.notify_all();
      Ok(())
    }

    fn poll_completion(&mut self) -> Option<RingCompletion> {
      lock(&self.control.state).completed.pop_front()
    }

    fn wait_with_timeout(&mut self, timeout: Duration) -> Option<RingCompletion> {
      let state = lock(&self.control.state);
      let (mut state, _) = self
        .control
        .changed
        .wait_timeout_while(state, timeout, |state| state.completed.is_empty())
        .unwrap_or_else(PoisonError::into_inner);
      state.completed.pop_front()
    }
  }

  fn test_scope() -> ResourceScope {
    ResourceScope::new(ResourceLimits {
      managed_memory: 1024,
      disk_concurrent_ops: 8,
      network_concurrent_ops: 0,
    })
  }

  fn buffer(scope: &ResourceScope, len: usize) -> ManagedBuf {
    scope.try_alloc_zeroed(len).unwrap()
  }

  fn regular_fd() -> OwnedFd {
    OwnedFd::from(File::open(std::env::current_exe().unwrap()).unwrap())
  }

  fn regular_rw_fd() -> OwnedFd {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-uring-{}-{}",
      std::process::id(),
      NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let file = OpenOptions::new()
      .create_new(true)
      .read(true)
      .write(true)
      .open(&path)
      .unwrap();
    std::fs::remove_file(path).unwrap();
    OwnedFd::from(file)
  }

  fn append_fd() -> OwnedFd {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-uring-append-{}-{}",
      std::process::id(),
      NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let file = OpenOptions::new()
      .create_new(true)
      .append(true)
      .open(&path)
      .unwrap();
    std::fs::remove_file(path).unwrap();
    OwnedFd::from(file)
  }

  fn flagged_fd(flag: i32, label: &str) -> OwnedFd {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
      "allocatbelt-uring-{label}-{}-{}",
      std::process::id(),
      NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    File::create(&path).unwrap();
    let file = OpenOptions::new()
      .read(true)
      .write(true)
      .custom_flags(flag)
      .open(&path)
      .unwrap();
    std::fs::remove_file(path).unwrap();
    OwnedFd::from(file)
  }

  fn start_fake(
    max_operations: usize,
    resources: ResourceScope,
    max_in_flight: usize,
    auto_complete: bool,
  ) -> (UringRuntime, Arc<FakeControl>) {
    let control = Arc::new(FakeControl {
      state: Mutex::new(FakeState {
        max_in_flight,
        auto_complete,
        pending: VecDeque::new(),
        completed: VecDeque::new(),
        published_ids: Vec::new(),
      }),
      changed: Condvar::new(),
    });
    let worker_control = Arc::clone(&control);
    let runtime = UringRuntime::start_with(max_operations, resources, move || {
      Ok(FakeDriver {
        control: worker_control,
      })
    })
    .unwrap();
    (runtime, control)
  }

  fn wait_until(mut check: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !check() {
      assert!(
        std::time::Instant::now() < deadline,
        "condition did not become true"
      );
      thread::yield_now();
    }
  }

  fn complete_one(control: &FakeControl) {
    let mut state = lock(&control.state);
    let operation = state.pending.pop_front().expect("one published operation");
    let result = Ok(operation.buffer.len());
    state.completed.push_back(RingCompletion {
      user_data: operation.user_data,
      fd: operation.fd,
      buffer: operation.buffer,
      result,
    });
    control.changed.notify_all();
  }

  #[test]
  fn completed_unclaimed_results_occupy_slots_until_consumed() {
    let resources = test_scope();
    let (mut runtime, _) = start_fake(1, resources.clone(), 1, true);
    let handle = runtime.handle();
    let mut first = handle
      .try_read_at(regular_fd(), buffer(&resources, 4), 0)
      .unwrap();
    wait_until(|| handle.snapshot().completed == 1);
    wait_until(|| resources.snapshot().disk_ops == 0);
    assert_eq!(resources.snapshot().disk_ops, 0);
    assert_eq!(resources.snapshot().managed_memory, 4);

    let rejected_buffer = buffer(&resources, 4);
    let rejected = match handle.try_read_at(regular_fd(), rejected_buffer, 0) {
      Ok(_) => panic!("completed but unclaimed result should occupy the only slot"),
      Err(error) => error,
    };
    assert!(matches!(rejected.kind, UringSubmitErrorKind::Full));
    let (rejected_fd, returned, offset) = rejected.into_input();
    assert_eq!(offset, 0);
    assert_eq!(returned.len(), 4);
    drop(rejected_fd);
    assert_eq!(resources.snapshot().managed_memory, 8);

    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let outcome = match Pin::new(&mut first).poll(&mut context) {
      Poll::Ready(outcome) => outcome,
      Poll::Pending => panic!("completed operation stayed pending"),
    };
    assert_eq!(outcome.bytes, 4);
    assert_eq!(handle.snapshot().occupied, 0);
    assert_eq!(resources.snapshot().managed_memory, 8);
    drop(outcome);
    assert_eq!(resources.snapshot().managed_memory, 4);
    drop(returned);
    assert_eq!(resources.snapshot().managed_memory, 0);
    runtime.shutdown().unwrap();
  }

  #[test]
  fn detached_published_operation_keeps_owners_until_the_real_completion() {
    let resources = test_scope();
    let (mut runtime, control) = start_fake(1, resources.clone(), 1, false);
    let handle = runtime.handle();
    let operation = handle
      .try_read_at(regular_fd(), buffer(&resources, 8), 0)
      .unwrap();
    wait_until(|| lock(&control.state).pending.len() == 1 && handle.snapshot().published == 1);
    drop(operation);
    assert_eq!(handle.snapshot().published, 1);
    assert_eq!(handle.snapshot().occupied, 1);
    assert_eq!(resources.snapshot().disk_ops, 1);
    assert_eq!(resources.snapshot().managed_memory, 8);

    complete_one(&control);
    wait_until(|| handle.snapshot().occupied == 0);
    assert_eq!(resources.snapshot().disk_ops, 0);
    wait_until(|| resources.snapshot().managed_memory == 0);
    assert_eq!(resources.snapshot().managed_memory, 0);
    runtime.shutdown().unwrap();
  }

  #[test]
  fn dropped_runtime_drains_published_owner_and_retained_handle_observes_result() {
    let resources = test_scope();
    let (runtime, control) = start_fake(1, resources.clone(), 1, false);
    let handle = runtime.handle();
    let mut operation = handle
      .try_read_at(regular_fd(), buffer(&resources, 6), 0)
      .unwrap();
    wait_until(|| handle.snapshot().published == 1);

    drop(runtime);
    assert!(handle.snapshot().closed);
    assert_eq!(resources.snapshot().disk_ops, 1);
    complete_one(&control);
    wait_until(|| handle.snapshot().completed == 1);
    let outcome = match Pin::new(&mut operation).poll(&mut Context::from_waker(Waker::noop())) {
      Poll::Ready(outcome) => outcome,
      Poll::Pending => panic!("completed request stayed pending after runtime drop"),
    };
    assert_eq!(outcome.bytes, 6);
    assert_eq!(resources.snapshot().disk_ops, 0);
    assert_eq!(resources.snapshot().managed_memory, 6);
    drop(outcome);
    assert_eq!(resources.snapshot().managed_memory, 0);
  }

  #[test]
  fn shutdown_keeps_completed_unclaimed_result_observable() {
    let resources = test_scope();
    let (mut runtime, _) = start_fake(1, resources.clone(), 1, true);
    let handle = runtime.handle();
    let mut operation = handle
      .try_read_at(regular_fd(), buffer(&resources, 3), 0)
      .unwrap();
    wait_until(|| handle.snapshot().completed == 1);
    runtime.shutdown().unwrap();
    assert!(handle.snapshot().closed);
    assert_eq!(handle.snapshot().occupied, 1);

    let outcome = match Pin::new(&mut operation).poll(&mut Context::from_waker(Waker::noop())) {
      Poll::Ready(outcome) => outcome,
      Poll::Pending => panic!("shutdown discarded a completed, unclaimed result"),
    };
    assert_eq!(outcome.bytes, 3);
    assert_eq!(resources.snapshot().disk_ops, 0);
    drop(outcome);
    assert_eq!(resources.snapshot().managed_memory, 0);
  }

  #[test]
  fn replacing_a_waker_drops_it_outside_the_ledger_lock() {
    struct DropProbe {
      handle: UringHandle,
      observed: Arc<AtomicUsize>,
      wakes: Arc<AtomicUsize>,
    }

    impl std::task::Wake for DropProbe {
      fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
      }

      fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
      }
    }

    impl Drop for DropProbe {
      fn drop(&mut self) {
        let snapshot = self.handle.snapshot();
        self
          .observed
          .store(snapshot.occupied + 1, Ordering::Release);
      }
    }

    let resources = test_scope();
    let (mut runtime, control) = start_fake(1, resources.clone(), 1, false);
    let handle = runtime.handle();
    let mut operation = handle
      .try_read_at(regular_fd(), buffer(&resources, 1), 0)
      .unwrap();
    wait_until(|| handle.snapshot().published == 1);

    let observed = Arc::new(AtomicUsize::new(0));
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(DropProbe {
      handle: handle.clone(),
      observed: Arc::clone(&observed),
      wakes: Arc::clone(&wakes),
    }));
    assert!(
      Pin::new(&mut operation)
        .poll(&mut Context::from_waker(&waker))
        .is_pending()
    );
    drop(waker);
    assert!(
      Pin::new(&mut operation)
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending()
    );
    assert_eq!(
      observed.load(Ordering::Acquire),
      handle.snapshot().occupied + 1
    );
    assert_eq!(wakes.load(Ordering::Relaxed), 0);

    drop(operation);
    complete_one(&control);
    wait_until(|| handle.snapshot().occupied == 0);
    runtime.shutdown().unwrap();
  }

  #[test]
  fn queued_drop_cancels_without_reordering_or_losing_inflight_owner() {
    let resources = test_scope();
    let (mut runtime, control) = start_fake(2, resources.clone(), 1, false);
    let handle = runtime.handle();
    let first = handle
      .try_read_at(regular_fd(), buffer(&resources, 5), 0)
      .unwrap();
    let second = handle
      .try_write_at(regular_rw_fd(), buffer(&resources, 7), 0)
      .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
      let snapshot = handle.snapshot();
      if snapshot.queued == 1 && snapshot.published == 1 {
        break;
      }
      if std::time::Instant::now() >= deadline {
        panic!("queued admission did not settle: {snapshot:?}");
      }
      thread::yield_now();
    }
    drop(second);
    assert_eq!(resources.snapshot().disk_ops, 1);
    assert_eq!(resources.snapshot().managed_memory, 5);

    complete_one(&control);
    wait_until(|| handle.snapshot().completed == 1);
    let published_ids = lock(&control.state).published_ids.clone();
    assert_eq!(published_ids.len(), 1);
    assert_eq!(published_ids[0] as u32 as usize, 0);
    drop(first);
    wait_until(|| handle.snapshot().occupied == 0);
    runtime.shutdown().unwrap();
  }

  #[test]
  fn queued_requests_publish_in_fifo_admission_order() {
    let resources = test_scope();
    let (mut runtime, control) = start_fake(3, resources.clone(), 1, false);
    let handle = runtime.handle();
    let first = handle
      .try_read_at(regular_fd(), buffer(&resources, 1), 0)
      .unwrap();
    let second = handle
      .try_read_at(regular_fd(), buffer(&resources, 2), 1)
      .unwrap();
    let third = handle
      .try_read_at(regular_fd(), buffer(&resources, 3), 2)
      .unwrap();
    wait_until(|| handle.snapshot().queued == 2 && handle.snapshot().published == 1);

    complete_one(&control);
    wait_until(|| lock(&control.state).published_ids.len() == 2);
    complete_one(&control);
    wait_until(|| lock(&control.state).published_ids.len() == 3);
    complete_one(&control);
    wait_until(|| handle.snapshot().completed == 3);
    let ids = lock(&control.state).published_ids.clone();
    assert_eq!(
      ids.iter().map(|id| *id as u32 as usize).collect::<Vec<_>>(),
      [0, 1, 2]
    );

    drop((first, second, third));
    wait_until(|| handle.snapshot().occupied == 0);
    runtime.shutdown().unwrap();
  }

  #[test]
  fn admission_rejection_returns_shared_buffer_nonregular_fd_and_bad_offset() {
    let resources = test_scope();
    let (mut runtime, _) = start_fake(2, resources.clone(), 1, true);
    let handle = runtime.handle();

    let shared = buffer(&resources, 3);
    let alias = shared.clone();
    let error = match handle.try_read_at(regular_fd(), shared, 0) {
      Ok(_) => panic!("shared buffer must be rejected"),
      Err(error) => error,
    };
    assert!(matches!(error.kind, UringSubmitErrorKind::SharedBuffer));
    assert_eq!(error.input.1.len(), 3);
    drop(alias);

    let (stream, _peer) = UnixStream::pair().unwrap();
    let error = match handle.try_read_at(OwnedFd::from(stream), buffer(&resources, 2), 0) {
      Ok(_) => panic!("nonregular descriptor must be rejected"),
      Err(error) => error,
    };
    assert!(matches!(error.kind, UringSubmitErrorKind::NotRegularFile));
    drop(error.into_input());

    let error = match handle.try_read_at(regular_fd(), buffer(&resources, 2), u64::MAX) {
      Ok(_) => panic!("overflowing offset must be rejected"),
      Err(error) => error,
    };
    assert!(matches!(error.kind, UringSubmitErrorKind::OffsetOverflow));
    drop(error.into_input());

    let error = match handle.try_read_at(regular_fd(), buffer(&resources, 2), i64::MAX as u64) {
      Ok(_) => panic!("offset extent beyond loff_t must be rejected"),
      Err(error) => error,
    };
    assert!(matches!(error.kind, UringSubmitErrorKind::OffsetOverflow));
    drop(error.into_input());

    let error = match handle.try_read_at(
      flagged_fd(libc::O_PATH, "path-only"),
      buffer(&resources, 1),
      0,
    ) {
      Ok(_) => panic!("O_PATH descriptor must be rejected"),
      Err(error) => error,
    };
    assert!(matches!(error.kind, UringSubmitErrorKind::PathOnly));
    drop(error.into_input());

    let error = match handle.try_read_at(
      flagged_fd(libc::O_DIRECT, "direct"),
      buffer(&resources, 1),
      0,
    ) {
      Ok(_) => panic!("O_DIRECT descriptor must be rejected"),
      Err(error) => error,
    };
    assert!(matches!(error.kind, UringSubmitErrorKind::DirectIo));
    drop(error.into_input());

    assert_eq!(resources.snapshot().disk_ops, 0);
    runtime.shutdown().unwrap();
  }

  #[test]
  fn append_writes_and_closed_service_return_original_inputs() {
    let resources = test_scope();
    let (mut runtime, _) = start_fake(2, resources.clone(), 1, true);
    let handle = runtime.handle();
    let append_buffer = buffer(&resources, 3);
    let error = match handle.try_write_at(append_fd(), append_buffer, 0) {
      Ok(_) => panic!("append-mode writes do not have positional semantics"),
      Err(error) => error,
    };
    assert!(matches!(error.kind, UringSubmitErrorKind::AccessMode));
    let (append_fd, append_buffer, _) = error.into_input();
    assert_eq!(append_buffer.len(), 3);
    drop(append_fd);
    drop(append_buffer);
    assert_eq!(resources.snapshot().disk_ops, 0);

    runtime.shutdown().unwrap();
    let closed_buffer = buffer(&resources, 2);
    let error = match handle.try_read_at(regular_fd(), closed_buffer, 5) {
      Ok(_) => panic!("closed service must reject before admission"),
      Err(error) => error,
    };
    assert!(matches!(error.kind, UringSubmitErrorKind::Closed));
    let (fd, buffer, offset) = error.into_input();
    assert_eq!(offset, 5);
    assert_eq!(buffer.len(), 2);
    drop(fd);
    drop(buffer);
    assert_eq!(resources.snapshot().disk_ops, 0);
    assert_eq!(resources.snapshot().managed_memory, 0);
  }

  #[test]
  fn zero_capacity_is_rejected_before_backend_startup() {
    let error = UringRuntime::start(UringConfig { max_operations: 0 }, test_scope()).unwrap_err();
    assert!(matches!(error.kind, UringStartErrorKind::InvalidConfig));
    let error = UringRuntime::start(
      UringConfig {
        max_operations: MAX_OPERATIONS + 1,
      },
      test_scope(),
    )
    .unwrap_err();
    assert!(matches!(error.kind, UringStartErrorKind::InvalidConfig));
  }

  #[test]
  fn waker_panics_are_contained_after_result_publication() {
    struct PanicWake(Arc<AtomicUsize>);
    impl std::task::Wake for PanicWake {
      fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
        panic!("expected wake panic");
      }
    }

    let resources = test_scope();
    let (mut runtime, control) = start_fake(1, resources.clone(), 1, false);
    let handle = runtime.handle();
    let mut operation = Box::pin(
      handle
        .try_read_at(regular_fd(), buffer(&resources, 2), 0)
        .unwrap(),
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(PanicWake(Arc::clone(&calls))));
    let mut context = Context::from_waker(&waker);
    assert!(operation.as_mut().poll(&mut context).is_pending());
    wait_until(|| lock(&control.state).pending.len() == 1);
    complete_one(&control);
    wait_until(|| handle.snapshot().completed == 1);
    wait_until(|| calls.load(Ordering::Relaxed) == 1);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(resources.snapshot().disk_ops, 0);
    let outcome = match operation
      .as_mut()
      .poll(&mut Context::from_waker(Waker::noop()))
    {
      Poll::Ready(outcome) => outcome,
      Poll::Pending => panic!("published result not available"),
    };
    drop(outcome);
    runtime.shutdown().unwrap();
  }
}
