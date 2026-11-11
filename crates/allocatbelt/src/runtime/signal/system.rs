use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::task::Waker;
use std::thread;

use super::protocol::{Shared, wake_all};
use super::{Signal, SignalError, SignalKind};
use crate::runtime::task::drop_contained;

static BUILD_LOCK: Mutex<()> = Mutex::new(());
static GLOBAL: OnceLock<Bridge> = OnceLock::new();
static STARTED: OnceLock<Result<(), SignalError>> = OnceLock::new();

struct Bridge {
  protocol: std::sync::Arc<Shared>,
  reader: UnixStream,
  writer: UnixStream,
  pending: AtomicU64,
  registrations: [Registration; 64],
  // The dispatcher takes this preallocated wake storage once at startup.
  wakes: Mutex<Option<Vec<Waker>>>,
}

struct Registration {
  state: Mutex<InstallState>,
  changed: Condvar,
}

#[derive(Clone, Copy)]
enum InstallState {
  Unattempted,
  Installing,
  Finished(Result<(), SignalError>),
}

/// A handle to the single bounded process-wide signal bridge.
///
/// The first published bridge fixes `max_listeners` for the process.
/// Subsequent drivers share that ceiling and must request the same value.
/// The bridge and its thread remain live for the process lifetime. No handler
/// is installed until a subscription has first reserved its listener slot.
#[derive(Clone)]
pub struct SignalDriver {
  bridge: &'static Bridge,
}

impl SignalDriver {
  /// Initializes or joins the permanent bridge. Startup failure is cached
  /// without installing handlers. Table construction failures can be retried.
  pub fn new(max_listeners: usize) -> Result<Self, SignalError> {
    {
      let build = lock(&BUILD_LOCK);
      if GLOBAL.get().is_none() {
        let protocol = Shared::new(max_listeners)?;
        let (reader, writer) = UnixStream::pair().map_err(|e| SignalError::Bridge(e.kind()))?;
        writer
          .set_nonblocking(true)
          .map_err(|e| SignalError::Bridge(e.kind()))?;
        let mut wakes = Vec::new();
        wakes
          .try_reserve_exact(max_listeners)
          .map_err(|_| SignalError::AllocationFailed)?;
        let bridge = Bridge {
          protocol,
          reader,
          writer,
          pending: AtomicU64::new(0),
          registrations: std::array::from_fn(|_| Registration {
            state: Mutex::new(InstallState::Unattempted),
            changed: Condvar::new(),
          }),
          wakes: Mutex::new(Some(wakes)),
        };
        if GLOBAL.set(bridge).is_err() {
          return Err(SignalError::ConfigurationMismatch);
        }
      }
      drop(build);
    }
    let bridge = GLOBAL
      .get()
      .ok_or(SignalError::Bridge(io::ErrorKind::Other))?;
    if bridge.protocol.capacity() != max_listeners {
      return Err(SignalError::ConfigurationMismatch);
    }
    let startup = STARTED.get_or_init(|| {
      thread::Builder::new()
        .name("allocatbelt-signal".into())
        .spawn(move || dispatch(bridge))
        .map(drop)
        .map_err(|e| SignalError::Bridge(e.kind()))
    });
    (*startup)?;
    if bridge.protocol.is_closed() {
      return Err(SignalError::Closed);
    }
    Ok(Self { bridge })
  }

  /// Reserves a listener before installing the process-wide handler.
  /// An ordinary capacity failure makes no handler-registration attempt.
  pub fn subscribe(&self, kind: SignalKind) -> Result<Signal, SignalError> {
    let signal = Shared::subscribe(&self.bridge.protocol, kind)?;
    if let Err(error) = install(self.bridge, kind) {
      drop(signal);
      return Err(error);
    }
    Ok(signal)
  }

  /// Creates an interrupt subscription for an explicit Ctrl-C port.
  pub fn ctrl_c(&self) -> Result<Signal, SignalError> {
    self.subscribe(SignalKind::interrupt())
  }

  /// The immutable process-wide listener ceiling.
  pub fn max_listeners(&self) -> usize {
    self.bridge.protocol.capacity()
  }

  /// Whether an unrecoverable dispatcher read failure closed subscriptions.
  pub fn is_closed(&self) -> bool {
    self.bridge.protocol.is_closed()
  }
}

impl std::fmt::Debug for SignalDriver {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let capacity = self.max_listeners();
    let closed = self.is_closed();
    f.debug_struct("SignalDriver")
      .field("max_listeners", &capacity)
      .field("closed", &closed)
      .finish()
  }
}

fn install(bridge: &'static Bridge, kind: SignalKind) -> Result<(), SignalError> {
  let cell = &bridge.registrations[(kind.as_raw() - 1) as usize];
  loop {
    let mut state = lock(&cell.state);
    match *state {
      InstallState::Finished(result) => return result,
      InstallState::Installing => {
        drop(
          cell
            .changed
            .wait(state)
            .unwrap_or_else(PoisonError::into_inner),
        );
      }
      InstallState::Unattempted => {
        *state = InstallState::Installing;
        drop(state);
        // No library lock crosses registration or a chained prior handler.
        let result = match panic::catch_unwind(AssertUnwindSafe(|| {
          crate::sys::runtime_signal::register(kind, &bridge.pending, bridge.writer.as_fd())
        })) {
          Ok(result) => result.map_err(|e| SignalError::Registration(e.kind())),
          Err(payload) => {
            drop_contained(payload);
            Err(SignalError::Registration(io::ErrorKind::Other))
          }
        };
        *lock(&cell.state) = InstallState::Finished(result);
        cell.changed.notify_all();
        return result;
      }
    }
  }
}

fn dispatch(bridge: &'static Bridge) {
  let Some(mut wakes) = lock(&bridge.wakes).take() else {
    return;
  };
  let mut bytes = [0; 256];
  loop {
    let read = (&bridge.reader).read(&mut bytes);
    match read {
      Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
      Ok(0) | Err(_) => {
        bridge.protocol.close(&mut wakes);
        wake_all(&mut wakes);
        return;
      }
      Ok(_) => {
        let pending = bridge.pending.swap(0, Ordering::SeqCst);
        bridge.protocol.deliver(pending, &mut wakes);
        wake_all(&mut wakes);
      }
    }
  }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
