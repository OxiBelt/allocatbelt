//! Nonblocking observation of a thread's actual completion.
//!
//! `JoinHandle::is_finished` can become true before thread-local destructors
//! finish. `DeferredJoin` therefore transfers the exact original handle to a
//! small, per-thread monitor and publishes the `join` result only after those
//! destructors have run. Polling never joins either thread.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle, ThreadId};

use super::task::drop_contained;

type JoinResult = thread::Result<()>;

/// One original thread and at most one helper that joins it off-caller.
pub(crate) struct DeferredJoin {
  shared: Arc<Shared>,
  monitor: Option<JoinHandle<()>>,
  thread_id: ThreadId,
}

struct Shared {
  state: Mutex<State>,
  changed: Condvar,
}

struct State {
  original: Option<JoinHandle<()>>,
  result: Option<JoinResult>,
  owner_attached: bool,
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
  pub(crate) fn new(original: JoinHandle<()>) -> Self {
    let thread_id = original.thread().id();
    Self {
      shared: Arc::new(Shared {
        state: Mutex::new(State {
          original: Some(original),
          result: None,
          owner_attached: true,
        }),
        changed: Condvar::new(),
      }),
      monitor: None,
      thread_id,
    }
  }

  /// Whether the original thread is the current thread.
  pub(crate) fn is_current_thread(&self) -> bool {
    self.thread_id == thread::current().id()
  }

  /// Starts the helper once, then takes a result if the original thread has
  /// fully joined. A pending return retains either the original handle in
  /// shared state or the helper handle that owns it.
  pub(crate) fn try_join(&mut self) -> Result<Option<JoinResult>, MonitorSpawnError> {
    self.try_join_with(|shared| {
      thread::Builder::new()
        .name("allocatbelt-join-monitor".to_owned())
        .spawn(move || monitor_join(shared))
    })
  }

  fn try_join_with(
    &mut self,
    spawn: impl FnOnce(Arc<Shared>) -> io::Result<JoinHandle<()>>,
  ) -> Result<Option<JoinResult>, MonitorSpawnError> {
    if let Some(result) = self.take_result() {
      self.monitor.take();
      return Ok(Some(result));
    }

    if self.monitor.is_none() {
      let monitor = spawn(Arc::clone(&self.shared)).map_err(MonitorSpawnError)?;
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
  use super::{DeferredJoin, JoinResult};
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
      .try_join_with(|_| {
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
