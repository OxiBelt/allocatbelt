//! Nonblocking observation of a thread's actual completion.
//!
//! `JoinHandle::is_finished` can become true before thread-local destructors
//! finish. `DeferredJoin` therefore transfers the exact original handle to a
//! small, per-thread monitor and publishes the `join` result only after those
//! destructors have run. Polling never joins either thread.
//!
//! Bound startup charges the declared `Shared` payload, its worker TLS owner,
//! one possible monitor Arc capture, builder payload, and the fixed monitor
//! name template plus one attempt's name capacity before spawning. Pool code
//! separately charges its actual `Vec<DeferredJoin>` capacity. A Shared
//! reservation stays alive through the original worker's TLS cleanup and any
//! monitor's final exit. These declared payloads exclude Arc allocator
//! headers, OS thread/provider metadata and stacks, operating-system name
//! backing, and arbitrary application TLS, destructor or panic-payload heap
//! allocations. The reserved monitor-name and Arc-capture capacity is one
//! helper attempt per original worker, including when that attempt is lazy or
//! must be retried.
//! [`PreparedJoins::new_embedded`] charges only its vector backing when the
//! containing owner already charges the inline `PreparedJoins` payload.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle, ThreadId};

use crate::runtime::resource_domain::{ControlCharge, DomainError, TenantDomain, payload_bytes};

use super::task::drop_contained;

type JoinResult = thread::Result<()>;
const MONITOR_THREAD_NAME: &str = "allocatbelt-join-monitor";

#[cfg(all(test, not(loom)))]
thread_local! {
  static FAIL_NEXT_MONITOR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Deterministically fail one launch on this test's polling thread only.
#[cfg(all(test, not(loom)))]
pub(crate) fn fail_next_monitor_for_test() {
  FAIL_NEXT_MONITOR.set(true);
}

/// One original thread and at most one helper that joins it off-caller.
pub(crate) struct DeferredJoin {
  shared: Arc<Shared>,
  monitor: Option<JoinHandle<()>>,
  thread_id: ThreadId,
}

/// Fixed startup storage for the completion owners belonging to a worker set.
/// Its vector allocation is charged while the owners are prepared, then the
/// charge is released when startup finishes; each Shared owner retains its
/// own charge for as long as a worker, wrapper or monitor still references it.
pub(crate) struct PreparedJoins {
  entries: Vec<PreparedJoin>,
  _control: ControlCharge,
}

/// A precharged worker completion owner that can be attached without failure
/// after the original worker thread has started.
pub(crate) struct PreparedJoin {
  shared: Arc<Shared>,
}

/// The original worker's one Arc owner, moved into a TLS sentinel before any
/// runtime callback or user task can initialize its own thread-local values.
pub(crate) struct CompletionThreadOwner {
  shared: Arc<Shared>,
}

struct Shared {
  state: Mutex<State>,
  changed: Condvar,
  monitor_name: String,
  _control: ControlCharge,
}

struct State {
  original: Option<JoinHandle<()>>,
  result: Option<JoinResult>,
  owner_attached: bool,
}

struct CompletionTlsOwner(std::cell::RefCell<Option<Arc<Shared>>>);

thread_local! {
  static COMPLETION_TLS_OWNER: CompletionTlsOwner = const {
    CompletionTlsOwner(std::cell::RefCell::new(None))
  };
}

impl Drop for CompletionTlsOwner {
  fn drop(&mut self) {
    let shared = self.0.get_mut().take();
    drop(shared);
  }
}

impl PreparedJoins {
  /// Precharges the actual vector capacity and every per-worker Shared owner
  /// before any worker or lifecycle callback can start. The reservation
  /// includes this value's declared inline payload and is for owners that
  /// store `PreparedJoins` separately.
  pub(crate) fn new(tenant: Option<&TenantDomain>, count: usize) -> Result<Self, DomainError> {
    Self::new_with_layout(tenant, count, true)
  }

  /// Prepares join owners when this value is embedded in a larger owner whose
  /// Control fee already covers `size_of::<PreparedJoins>()`. The vector
  /// backing and every per-worker Shared owner remain independently charged.
  pub(crate) fn new_embedded(
    tenant: Option<&TenantDomain>,
    count: usize,
  ) -> Result<Self, DomainError> {
    Self::new_with_layout(tenant, count, false)
  }

  fn new_with_layout(
    tenant: Option<&TenantDomain>,
    count: usize,
    include_inline: bool,
  ) -> Result<Self, DomainError> {
    if count == 0 {
      return Err(DomainError::Invalid);
    }
    let inline_bytes = if include_inline {
      std::mem::size_of::<Self>()
    } else {
      0
    };
    let requested = inline_bytes
      .checked_add(payload_bytes::<PreparedJoin>(count)?)
      .ok_or(DomainError::Invalid)?;
    let mut control = ControlCharge::try_new(tenant, requested)?;
    let mut entries = Vec::new();
    entries
      .try_reserve_exact(count)
      .map_err(|_| DomainError::OutOfMemory)?;
    let actual = inline_bytes
      .checked_add(payload_bytes::<PreparedJoin>(entries.capacity())?)
      .ok_or(DomainError::Invalid)?;
    control.try_resize(actual)?;
    for _ in 0..count {
      entries.push(PreparedJoin::new(tenant)?);
    }
    Ok(Self {
      entries,
      _control: control,
    })
  }

  #[cfg(all(test, not(loom)))]
  pub(crate) fn control_bytes(&self) -> usize {
    self._control.bytes()
  }

  #[cfg(all(test, not(loom)))]
  pub(crate) fn entries_capacity(&self) -> usize {
    self.entries.capacity()
  }

  #[cfg(all(test, not(loom)))]
  pub(crate) fn prepared_shared_control_bytes(&self) -> Result<usize, DomainError> {
    self.entries.iter().try_fold(0_usize, |total, prepared| {
      total
        .checked_add(prepared.shared._control.bytes())
        .ok_or(DomainError::Invalid)
    })
  }

  /// Takes one precharged owner. The caller must attach it if the matching
  /// original worker thread starts.
  pub(crate) fn pop(&mut self) -> Option<PreparedJoin> {
    self.entries.pop()
  }
}

impl PreparedJoin {
  fn shared_control_bytes(name_capacity: usize) -> Result<usize, DomainError> {
    // One CompletionThreadOwner is moved from the worker closure into TLS,
    // so this one payload fee follows it through the transfer rather than
    // being charged again in the runtime's launch-capture aggregate. The two
    // name capacities are the retained template and one lazy/retry attempt.
    let owners = std::mem::size_of::<CompletionThreadOwner>()
      .checked_add(std::mem::size_of::<Arc<Shared>>())
      .and_then(|bytes| bytes.checked_add(std::mem::size_of::<thread::Builder>()))
      .and_then(|bytes| name_capacity.checked_mul(2)?.checked_add(bytes))
      .ok_or(DomainError::Invalid)?;
    std::mem::size_of::<Shared>()
      .checked_add(owners)
      .ok_or(DomainError::Invalid)
  }

  fn new(tenant: Option<&TenantDomain>) -> Result<Self, DomainError> {
    let requested_name_capacity = MONITOR_THREAD_NAME.len();
    let mut control =
      ControlCharge::try_new(tenant, Self::shared_control_bytes(requested_name_capacity)?)?;
    let monitor_name = String::from(MONITOR_THREAD_NAME);
    let actual_control = Self::shared_control_bytes(monitor_name.capacity())?;
    control.try_resize(actual_control)?;
    let shared = Arc::new(Shared {
      state: Mutex::new(State {
        original: None,
        result: None,
        owner_attached: false,
      }),
      changed: Condvar::new(),
      monitor_name,
      _control: control,
    });
    Ok(Self { shared })
  }

  /// Clones the owner to be moved into the original worker's TLS sentinel.
  /// Its pointer payload is included in this Shared's pre-spawn Control fee.
  pub(crate) fn thread_owner(&self) -> CompletionThreadOwner {
    CompletionThreadOwner {
      shared: Arc::clone(&self.shared),
    }
  }

  /// Transfers the exact original handle into the already-prepared Shared
  /// owner. This operation does not allocate or fail after a spawn succeeds.
  pub(crate) fn attach(self, original: JoinHandle<()>) -> DeferredJoin {
    let thread_id = original.thread().id();
    {
      let mut state = lock(&self.shared.state);
      debug_assert!(state.original.is_none());
      debug_assert!(!state.owner_attached);
      state.original = Some(original);
      state.owner_attached = true;
    }
    DeferredJoin {
      shared: self.shared,
      monitor: None,
      thread_id,
    }
  }
}

impl CompletionThreadOwner {
  /// Installs this owner before the worker invokes any user or runtime code.
  /// Its Arc is released by the thread-local sentinel after later-registered
  /// TLS destructors, including destructors registered during another Drop.
  pub(crate) fn retain_until_thread_exit(self) {
    let previous = COMPLETION_TLS_OWNER.with(|owner| owner.0.replace(Some(self.shared)));
    debug_assert!(previous.is_none());
    drop(previous);
  }
}

/// Failure to create the helper. The original handle remains owned and a
/// later poll can retry.
#[derive(Debug)]
pub(crate) struct MonitorSpawnError(io::Error);

impl fmt::Display for MonitorSpawnError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "join monitor could not be started: {}", self.0)
  }
}

impl std::error::Error for MonitorSpawnError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.0)
  }
}

impl DeferredJoin {
  /// Retains the exact handle until a monitor starts successfully or a
  /// caller explicitly chooses the blocking join path.
  #[cfg(test)]
  pub(crate) fn new(original: JoinHandle<()>) -> Self {
    let prepared = match PreparedJoin::new(None) {
      Ok(prepared) => prepared,
      Err(error) => panic!("unbound completion owner preparation failed: {error}"),
    };
    prepared.attach(original)
  }

  /// Whether the original thread is the current thread.
  pub(crate) fn is_current_thread(&self) -> bool {
    self.thread_id == thread::current().id()
  }

  #[cfg(all(test, not(loom)))]
  pub(crate) fn control_bytes(&self) -> usize {
    self.shared._control.bytes()
  }

  /// Starts the helper once, then takes a result if the original thread has
  /// fully joined. A pending return retains either the original handle in
  /// shared state or the helper handle that owns it.
  pub(crate) fn try_join(&mut self) -> Result<Option<JoinResult>, MonitorSpawnError> {
    #[cfg(all(test, not(loom)))]
    if FAIL_NEXT_MONITOR.replace(false) {
      return self.try_join_with(|_, _| {
        Err(io::Error::new(
          io::ErrorKind::WouldBlock,
          "injected monitor startup refusal",
        ))
      });
    }
    self.try_join_with(|shared, name| {
      thread::Builder::new()
        .name(name)
        .spawn(move || monitor_join(shared))
    })
  }

  fn try_join_with(
    &mut self,
    spawn: impl FnOnce(Arc<Shared>, String) -> io::Result<JoinHandle<()>>,
  ) -> Result<Option<JoinResult>, MonitorSpawnError> {
    if let Some(result) = self.take_result() {
      self.monitor.take();
      return Ok(Some(result));
    }

    if self.monitor.is_none() {
      let monitor = spawn(Arc::clone(&self.shared), self.shared.monitor_name.clone())
        .map_err(MonitorSpawnError)?;
      self.monitor = Some(monitor);
    }

    let result = self.take_result();
    if result.is_some() {
      // The helper publishes only after the original join returned and holds
      // no arbitrary payload or callback owner after publication.
      self.monitor.take();
    }
    Ok(result)
  }

  /// Waits for the original thread's full completion. Explicit shutdown may
  /// block; finite polling must use [`Self::try_join`]. If a helper was
  /// already started, this waits on its publication instead of joining the
  /// helper on the caller.
  pub(crate) fn join_blocking(&mut self) -> JoinResult {
    if let Some(result) = self.take_result() {
      self.monitor.take();
      return result;
    }

    if self.monitor.is_none() {
      let original = {
        let mut state = lock(&self.shared.state);
        if let Some(result) = state.result.take() {
          drop(state);
          return result;
        }
        state.original.take()
      };
      if let Some(original) = original {
        return original.join();
      }
    }

    let mut state = lock(&self.shared.state);
    loop {
      if let Some(result) = state.result.take() {
        drop(state);
        self.monitor.take();
        return result;
      }
      state = self
        .shared
        .changed
        .wait(state)
        .unwrap_or_else(PoisonError::into_inner);
    }
  }

  fn take_result(&self) -> Option<JoinResult> {
    lock(&self.shared.state).result.take()
  }

  #[cfg(test)]
  fn retains_pending_join(&self) -> bool {
    let state = lock(&self.shared.state);
    state.original.is_some() || self.monitor.is_some()
  }
}

impl Drop for DeferredJoin {
  fn drop(&mut self) {
    let result = {
      let mut state = lock(&self.shared.state);
      state.owner_attached = false;
      state.result.take()
    };
    if let Some(Err(payload)) = result {
      drop_contained(payload);
    }
    // Dropping a monitor handle detaches only the helper. If it already owns
    // the original handle, it still joins that thread before exiting.
  }
}

impl Drop for Shared {
  fn drop(&mut self) {
    let result = self
      .state
      .get_mut()
      .unwrap_or_else(PoisonError::into_inner)
      .result
      .take();
    if let Some(Err(payload)) = result {
      drop_contained(payload);
    }
  }
}

fn monitor_join(shared: Arc<Shared>) {
  let original = lock(&shared.state).original.take();
  let Some(original) = original else {
    return;
  };
  let result = original.join();
  let cleanup = {
    let mut state = lock(&shared.state);
    if state.owner_attached {
      state.result = Some(result);
      None
    } else {
      result.err()
    }
  };
  if let Some(payload) = cleanup {
    // If the shutdown owner disappeared before publication, contain arbitrary
    // panic-payload cleanup on this helper, outside the state mutex.
    drop_contained(payload);
  }
  shared.changed.notify_all();
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
  state.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::{DeferredJoin, JoinResult, PreparedJoin, PreparedJoins, fail_next_monitor_for_test};
  use crate::runtime::resource_domain::{
    DomainResource, DomainResources, ResourceDomain, TenantDomain, payload_bytes,
  };
  use std::cell::RefCell;
  use std::sync::mpsc::{self, Receiver, Sender};
  use std::thread;
  use std::time::{Duration, Instant};

  struct Gate {
    entered: Sender<()>,
    release: Receiver<()>,
  }

  impl Gate {
    fn wait(self) {
      let _ = self.entered.send(());
      let _ = self.release.recv();
    }
  }

  struct BlockOnDrop(RefCell<Option<Gate>>);

  impl Drop for BlockOnDrop {
    fn drop(&mut self) {
      if let Some(gate) = self.0.get_mut().take() {
        gate.wait();
      }
    }
  }

  thread_local! {
    static BLOCKING_TLS: BlockOnDrop = const { BlockOnDrop(RefCell::new(None)) };
    static OUTER_TLS: OuterTls = const { OuterTls(RefCell::new(None)) };
    static NESTED_TLS: BlockOnDrop = const { BlockOnDrop(RefCell::new(None)) };
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

  fn await_signal(receiver: &Receiver<()>, deadline: Instant) {
    let remaining = deadline.saturating_duration_since(Instant::now());
    receiver
      .recv_timeout(remaining)
      .expect("TLS destructor watchdog expired");
  }

  fn start_release_watchdog(release: Sender<()>) -> (Sender<()>, thread::JoinHandle<()>) {
    let watchdog_release = release.clone();
    let (cancel_watchdog, watchdog_cancelled) = mpsc::channel();
    let watchdog = thread::spawn(move || {
      if watchdog_cancelled
        .recv_timeout(Duration::from_secs(3))
        .is_err()
      {
        let _ = watchdog_release.send(());
      }
    });
    (cancel_watchdog, watchdog)
  }

  fn assert_pending_then_release(
    mut join: DeferredJoin,
    release: Sender<()>,
    cancel_watchdog: Sender<()>,
    watchdog: thread::JoinHandle<()>,
  ) {
    let started = Instant::now();
    assert!(join.try_join().expect("monitor should start").is_none());
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(join.retains_pending_join());
    release.send(()).expect("release TLS destructor");

    let result = poll_until_joined(&mut join);
    assert!(result.is_ok());
    let _ = cancel_watchdog.send(());
    watchdog.join().expect("watchdog thread");
  }

  fn poll_until_joined(join: &mut DeferredJoin) -> JoinResult {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
      if let Some(result) = join.try_join().expect("monitor retry") {
        return result;
      }
      assert!(
        Instant::now() < deadline,
        "monitor did not publish completion"
      );
      thread::yield_now();
    }
  }

  fn bound_domain() -> (ResourceDomain, TenantDomain) {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Cpu, 2)
      .with(DomainResource::Tasks, 8)
      .with(DomainResource::Control, 1 << 20);
    let domain = ResourceDomain::new(ceiling, 1)
      .unwrap_or_else(|error| panic!("resource domain setup failed: {error}"));
    let tenant = domain
      .tenant(ceiling)
      .unwrap_or_else(|error| panic!("tenant setup failed: {error}"));
    (domain, tenant)
  }

  fn global_control(domain: &ResourceDomain) -> usize {
    domain.snapshot().used.get(DomainResource::Control)
  }

  fn tenant_control(tenant: &TenantDomain) -> usize {
    tenant
      .snapshot()
      .unwrap_or_else(|error| panic!("tenant snapshot failed: {error}"))
      .used
      .get(DomainResource::Control)
  }

  fn wait_for_global_control(domain: &ResourceDomain, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while global_control(domain) != expected {
      assert!(
        Instant::now() < deadline,
        "completion Control owner did not drain"
      );
      thread::yield_now();
    }
  }

  fn spawn_bound_tls_worker(prepared: PreparedJoin, gate: Gate, nested: bool) -> DeferredJoin {
    let owner = prepared.thread_owner();
    let handle = thread::spawn(move || {
      owner.retain_until_thread_exit();
      if nested {
        OUTER_TLS.with(|slot| {
          *slot.0.borrow_mut() = Some(gate);
        });
      } else {
        BLOCKING_TLS.with(|slot| {
          *slot.0.borrow_mut() = Some(gate);
        });
      }
    });
    prepared.attach(handle)
  }

  #[test]
  fn waits_for_tls_destructor_after_worker_returns() {
    blocked_tls_destructor_case(false);
  }

  #[test]
  fn waits_for_nested_tls_destructor_initialized_during_drop() {
    blocked_tls_destructor_case(true);
  }

  #[test]
  fn monitor_start_failure_retains_original_for_retry() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (cancel_watchdog, watchdog) = start_release_watchdog(release_tx.clone());
    let handle = thread::spawn(move || {
      let _ = entered_tx.send(());
      let _ = release_rx.recv();
    });
    let mut join = DeferredJoin::new(handle);
    await_signal(&entered_rx, Instant::now() + Duration::from_secs(3));

    let error = join
      .try_join_with(|_, _| {
        Err(std::io::Error::new(
          std::io::ErrorKind::WouldBlock,
          "injected monitor spawn failure",
        ))
      })
      .expect_err("injected spawn failure must be reported");
    assert_eq!(error.0.kind(), std::io::ErrorKind::WouldBlock);
    assert!(join.retains_pending_join());
    assert!(join.try_join().expect("retry should start").is_none());
    release_tx.send(()).expect("release original thread");
    assert!(poll_until_joined(&mut join).is_ok());
    let _ = cancel_watchdog.send(());
    watchdog.join().expect("watchdog thread");
  }

  #[test]
  fn prepared_shared_control_survives_failed_monitor_retry_and_detached_owner() {
    let (domain, tenant) = bound_domain();
    let global_baseline = global_control(&domain);
    let tenant_baseline = tenant_control(&tenant);
    let mut prepared = PreparedJoins::new(Some(&tenant), 1)
      .unwrap_or_else(|error| panic!("completion preparation failed: {error}"));
    let prepared_capacity = prepared.entries.capacity();
    let shared_bytes = PreparedJoin::shared_control_bytes(
      prepared
        .entries
        .last()
        .unwrap_or_else(|| panic!("prepared completion slot is missing"))
        .shared
        .monitor_name
        .capacity(),
    )
    .unwrap_or_else(|error| panic!("completion payload size failed: {error}"));
    let prepared_vector_bytes = std::mem::size_of::<PreparedJoins>()
      + payload_bytes::<PreparedJoin>(prepared_capacity)
        .unwrap_or_else(|error| panic!("prepared vector size failed: {error}"));
    assert_eq!(
      global_control(&domain) - global_baseline,
      prepared_vector_bytes + shared_bytes
    );
    assert_eq!(
      tenant_control(&tenant) - tenant_baseline,
      prepared_vector_bytes + shared_bytes
    );
    let prepared_join = prepared
      .pop()
      .unwrap_or_else(|| panic!("prepared completion slot could not be taken"));
    drop(prepared);
    assert_eq!(global_control(&domain) - global_baseline, shared_bytes);

    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (cancel_watchdog, watchdog) = start_release_watchdog(release_tx.clone());
    let mut join = spawn_bound_tls_worker(
      prepared_join,
      Gate {
        entered: entered_tx,
        release: release_rx,
      },
      true,
    );
    await_signal(&entered_rx, Instant::now() + Duration::from_secs(3));

    fail_next_monitor_for_test();
    let error = join
      .try_join()
      .expect_err("injected monitor spawn failure must be reported");
    assert_eq!(error.0.kind(), std::io::ErrorKind::WouldBlock);
    assert!(join.retains_pending_join());
    assert_eq!(global_control(&domain) - global_baseline, shared_bytes);
    assert_eq!(tenant_control(&tenant) - tenant_baseline, shared_bytes);

    assert!(
      join
        .try_join()
        .expect("monitor retry should start")
        .is_none()
    );
    drop(join);
    assert_eq!(global_control(&domain) - global_baseline, shared_bytes);
    release_tx.send(()).expect("release nested TLS destructor");
    wait_for_global_control(&domain, global_baseline);
    assert_eq!(tenant_control(&tenant), tenant_baseline);
    let _ = cancel_watchdog.send(());
    watchdog.join().expect("watchdog thread");
  }

  #[test]
  fn detached_owner_without_monitor_keeps_control_through_nested_tls_cleanup() {
    let (domain, tenant) = bound_domain();
    let global_baseline = global_control(&domain);
    let tenant_baseline = tenant_control(&tenant);
    let mut prepared = PreparedJoins::new(Some(&tenant), 1)
      .unwrap_or_else(|error| panic!("completion preparation failed: {error}"));
    let shared_bytes = PreparedJoin::shared_control_bytes(
      prepared
        .entries
        .last()
        .unwrap_or_else(|| panic!("prepared completion slot is missing"))
        .shared
        .monitor_name
        .capacity(),
    )
    .unwrap_or_else(|error| panic!("completion payload size failed: {error}"));
    let prepared_join = prepared
      .pop()
      .unwrap_or_else(|| panic!("prepared completion slot could not be taken"));
    drop(prepared);

    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (cancel_watchdog, watchdog) = start_release_watchdog(release_tx.clone());
    let join = spawn_bound_tls_worker(
      prepared_join,
      Gate {
        entered: entered_tx,
        release: release_rx,
      },
      true,
    );
    await_signal(&entered_rx, Instant::now() + Duration::from_secs(3));
    drop(join);

    assert_eq!(global_control(&domain) - global_baseline, shared_bytes);
    assert_eq!(tenant_control(&tenant) - tenant_baseline, shared_bytes);
    release_tx.send(()).expect("release nested TLS destructor");
    wait_for_global_control(&domain, global_baseline);
    assert_eq!(tenant_control(&tenant), tenant_baseline);
    let _ = cancel_watchdog.send(());
    watchdog.join().expect("watchdog thread");
  }

  fn blocked_tls_destructor_case(nested: bool) {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (cancel_watchdog, watchdog) = start_release_watchdog(release_tx.clone());
    let gate = Gate {
      entered: entered_tx,
      release: release_rx,
    };
    let handle = thread::spawn(move || {
      if nested {
        OUTER_TLS.with(|slot| {
          *slot.0.borrow_mut() = Some(gate);
        });
      } else {
        BLOCKING_TLS.with(|slot| {
          *slot.0.borrow_mut() = Some(gate);
        });
      }
    });
    let join = DeferredJoin::new(handle);
    await_signal(&entered_rx, Instant::now() + Duration::from_secs(3));
    assert_pending_then_release(join, release_tx, cancel_watchdog, watchdog);
  }
}
