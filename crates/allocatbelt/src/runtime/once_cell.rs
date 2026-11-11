//! Bounded asynchronous initialization with owned value snapshots.
//!
//! Values are returned as `Arc<T>` rather than Tokio's borrowed references.
//! Initializer cancellation, errors and panics leave an empty cell retryable.
//! Recursive initialization of the same cell can wait for itself and deadlock.
//! Cell metadata is ordinary storage outside the managed-buffer ledger.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::any::Any;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::PoisonError;
use std::task::{Context, Poll};

#[cfg(loom)]
use loom::sync::{Arc, Mutex, MutexGuard};
#[cfg(not(loom))]
use std::sync::{Arc, Mutex, MutexGuard};

use super::semaphore::{AcquireError, AcquireMany, Permit, Semaphore, SemaphoreBuildError};
use super::task::drop_contained;

/// An initialization cell with an explicit FIFO waiter bound.
///
/// Local values need no thread or lifetime bounds. Sharing the cell or its
/// snapshots between threads requires `T: Send + Sync`. There is no close,
/// reset, mutable-reference or stable-address API, and cloning a cell is not
/// supported. Initializers are called lazily by the winning poll.
///
/// A local `Cell` value cannot be shared between runtime threads:
///
/// ```compile_fail
/// use allocatbelt::runtime::once_cell::AsyncOnceCell;
/// use std::cell::Cell;
/// fn share<T: Send + Sync>(_: T) {}
/// share(AsyncOnceCell::new_with(Cell::new(1), 1).unwrap());
/// ```
///
/// `Rc` values remain local, including their owned snapshots:
///
/// ```compile_fail
/// use allocatbelt::runtime::once_cell::AsyncOnceCell;
/// use std::rc::Rc;
/// fn move_to_thread<T: Send>(_: T) {}
/// let cell = AsyncOnceCell::new_with(Rc::new(1), 1).unwrap();
/// move_to_thread(cell.get().unwrap());
/// ```
pub struct AsyncOnceCell<T> {
  shared: Arc<Shared<T>>,
}

struct Shared<T> {
  value: Mutex<Option<Arc<T>>>,
  gate: Semaphore,
}

/// An already initialized cell or a concurrent initializer rejected `set`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SetErrorKind {
  /// A value has already been published.
  Initialized,
  /// An initializer or an earlier FIFO waiter owns admission.
  Busy,
}

/// A rejected synchronous value, preserved unchanged.
pub struct SetError<T> {
  /// Why setting the cell failed.
  pub kind: SetErrorKind,
  value: T,
}

impl<T> SetError<T> {
  /// Recovers the rejected value.
  pub fn into_value(self) -> T {
    self.value
  }
}

impl<T> fmt::Debug for SetError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("SetError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

/// Construction failure with an unchanged proposed initial value.
pub struct CellBuildError<T> {
  /// Why the waiter table could not be created.
  pub kind: SemaphoreBuildError,
  value: T,
}

impl<T> CellBuildError<T> {
  /// Recovers the initial value.
  pub fn into_value(self) -> T {
    self.value
  }
}

impl<T> fmt::Debug for CellBuildError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("CellBuildError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

/// Why a bounded initialization did not produce a snapshot.
pub enum InitError<E, F> {
  /// Admission failed before the factory was invoked; the original factory
  /// is returned for recovery or retry.
  Admission { kind: AcquireError, factory: F },
  /// The winning initializer returned an application error.
  Initialization(E),
  /// This initialization future was polled after completion or a panic.
  Completed,
}

impl<E: fmt::Debug, F> fmt::Debug for InitError<E, F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Admission { kind, .. } => f
        .debug_struct("Admission")
        .field("kind", kind)
        .finish_non_exhaustive(),
      Self::Initialization(error) => f.debug_tuple("Initialization").field(error).finish(),
      Self::Completed => f.write_str("Completed"),
    }
  }
}

/// A named owned initialization future. The inner initializer is pinned;
/// the never-pinned factory can be recovered before invocation.
#[must_use = "futures do nothing unless polled"]
pub struct InitFuture<T, F, Fut: Future, E> {
  shared: Arc<Shared<T>>,
  acquire: Option<AcquireMany>,
  factory: Option<F>,
  initializer: Option<Pin<Box<Fut>>>,
  permit: Option<Permit>,
  convert: fn(Fut::Output) -> Result<T, E>,
  completed: bool,
}

// Only `initializer` is pinned, inside its box. No projection pins `factory`.
impl<T, F, Fut: Future, E> Unpin for InitFuture<T, F, Fut, E> {}

impl<T> AsyncOnceCell<T> {
  /// Creates an empty cell. Zero waiters allows immediate initialization but
  /// rejects contention instead of waiting.
  pub fn new(max_waiters: usize) -> Result<Self, SemaphoreBuildError> {
    Ok(Self {
      shared: Arc::new(Shared {
        value: Mutex::new(None),
        gate: Semaphore::new(1, max_waiters)?,
      }),
    })
  }

  /// Creates a populated cell, returning the initial value on a reported
  /// construction failure. Arc headers use ordinary allocation handling.
  pub fn new_with(value: T, max_waiters: usize) -> Result<Self, CellBuildError<T>> {
    let gate = match Semaphore::new(1, max_waiters) {
      Ok(gate) => gate,
      Err(kind) => return Err(CellBuildError { kind, value }),
    };
    Ok(Self {
      shared: Arc::new(Shared {
        value: Mutex::new(Some(Arc::new(value))),
        gate,
      }),
    })
  }

  /// Whether a successfully initialized value has been published.
  pub fn initialized(&self) -> bool {
    lock(&self.shared.value).is_some()
  }

  /// Returns an owned snapshot if initialization has completed.
  pub fn get(&self) -> Option<Arc<T>> {
    get(&self.shared)
  }

  /// Publishes a value immediately, or returns it unchanged if initialized
  /// or admission is held. This never waits for an initializer.
  pub fn set(&self, value: T) -> Result<(), SetError<T>> {
    if self.initialized() {
      return Err(SetError {
        kind: SetErrorKind::Initialized,
        value,
      });
    }
    let permit = match self.shared.gate.try_acquire_many(1) {
      Ok(permit) => permit,
      Err(_) => {
        let kind = if self.initialized() {
          SetErrorKind::Initialized
        } else {
          SetErrorKind::Busy
        };
        return Err(SetError { kind, value });
      }
    };
    // Another publisher may have finished between the first value check and
    // this acquisition. The issued permit now excludes every other publisher.
    if self.initialized() {
      drop(permit);
      return Err(SetError {
        kind: SetErrorKind::Initialized,
        value,
      });
    }
    let candidate = Arc::new(value);
    let old = { lock(&self.shared.value).replace(candidate) };
    debug_assert!(old.is_none());
    drop_contained(old);
    drop(permit);
    Ok(())
  }

  /// Initializes with a fallible future, or returns the existing snapshot.
  /// The original uncalled factory is returned on bounded admission failure.
  pub fn get_or_try_init<F, Fut, E>(&self, factory: F) -> InitFuture<T, F, Fut, E>
  where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, E>>,
  {
    self.start(factory, |result| result)
  }

  /// Initializes with an infallible future. Admission can still fail and
  /// return the uncalled factory, even though initialization cannot fail.
  pub fn get_or_init<F, Fut>(&self, factory: F) -> InitFuture<T, F, Fut, Infallible>
  where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
  {
    self.start(factory, Ok)
  }

  fn start<F, Fut: Future, E>(
    &self,
    factory: F,
    convert: fn(Fut::Output) -> Result<T, E>,
  ) -> InitFuture<T, F, Fut, E> {
    InitFuture {
      shared: Arc::clone(&self.shared),
      acquire: Some(self.shared.gate.acquire_many(1)),
      factory: Some(factory),
      initializer: None,
      permit: None,
      convert,
      completed: false,
    }
  }
}

fn get<T>(shared: &Shared<T>) -> Option<Arc<T>> {
  lock(&shared.value).as_ref().map(Arc::clone)
}

type PanicPayload = Box<dyn Any + Send + 'static>;

impl<T, F, Fut: Future, E> InitFuture<T, F, Fut, E> {
  /// Cancels this future and recovers its factory if it was not invoked.
  /// A started initializer is destroyed before its permit is released.
  pub fn into_factory(mut self) -> Option<F> {
    self.factory.take()
  }

  fn cleanup(&mut self) -> Option<PanicPayload> {
    let mut first = None;
    for outcome in [
      panic::catch_unwind(AssertUnwindSafe(|| drop(self.initializer.take()))),
      panic::catch_unwind(AssertUnwindSafe(|| drop(self.factory.take()))),
    ] {
      if let Err(payload) = outcome {
        if first.is_none() {
          first = Some(payload);
        } else {
          drop_contained(payload);
        }
      }
    }
    drop_contained(self.acquire.take());
    drop_contained(self.permit.take());
    first
  }

  fn fail_panic(&mut self, payload: PanicPayload) -> ! {
    self.completed = true;
    if let Some(secondary) = self.cleanup() {
      drop_contained(secondary);
    }
    panic::resume_unwind(payload)
  }

  fn existing(&mut self, snapshot: Arc<T>) -> Poll<Result<Arc<T>, InitError<E, F>>> {
    self.completed = true;
    if let Some(payload) = self.cleanup() {
      drop_contained(snapshot);
      panic::resume_unwind(payload);
    }
    Poll::Ready(Ok(snapshot))
  }
}

impl<T, F, Fut, E> Future for InitFuture<T, F, Fut, E>
where
  F: FnOnce() -> Fut,
  Fut: Future,
{
  type Output = Result<Arc<T>, InitError<E, F>>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.completed {
      return Poll::Ready(Err(InitError::Completed));
    }
    super::asynchronous::poll_cooperative_composed(cx, |cx| {
      if this.permit.is_none() {
        if let Some(snapshot) = get(&this.shared) {
          return this.existing(snapshot);
        }
        let Some(acquire) = this.acquire.as_mut() else {
          this.completed = true;
          return Poll::Ready(Err(InitError::Completed));
        };
        let acquired = panic::catch_unwind(AssertUnwindSafe(|| Pin::new(acquire).poll(cx)));
        match acquired {
          Err(payload) => this.fail_panic(payload),
          Ok(Poll::Pending) => return Poll::Pending,
          Ok(Poll::Ready(Ok(permit))) => {
            this.permit = Some(permit);
            this.acquire = None;
          }
          Ok(Poll::Ready(Err(kind))) => {
            if let Some(snapshot) = get(&this.shared) {
              return this.existing(snapshot);
            }
            this.completed = true;
            let factory = this.factory.take();
            if let Some(payload) = this.cleanup() {
              drop_contained(factory);
              panic::resume_unwind(payload);
            }
            return Poll::Ready(Err(match factory {
              Some(factory) => InitError::Admission { kind, factory },
              None => InitError::Completed,
            }));
          }
        }
        if let Some(snapshot) = get(&this.shared) {
          return this.existing(snapshot);
        }
      }
      if this.initializer.is_none() {
        let Some(factory) = this.factory.take() else {
          this.completed = true;
          if let Some(payload) = this.cleanup() {
            panic::resume_unwind(payload);
          }
          return Poll::Ready(Err(InitError::Completed));
        };
        match panic::catch_unwind(AssertUnwindSafe(factory)) {
          Ok(initializer) => this.initializer = Some(Box::pin(initializer)),
          Err(payload) => this.fail_panic(payload),
        }
      }
      let polled = panic::catch_unwind(AssertUnwindSafe(|| match this.initializer.as_mut() {
        Some(initializer) => initializer.as_mut().poll(cx),
        None => Poll::Pending,
      }));
      let output = match polled {
        Err(payload) => this.fail_panic(payload),
        Ok(Poll::Pending) => return Poll::Pending,
        Ok(Poll::Ready(output)) => output,
      };
      // Keep the permit while destroying the completed initializer. If its Drop
      // panics, discard the proposed result and allow a later initializer retry.
      if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(this.initializer.take())))
      {
        drop_contained(output);
        this.fail_panic(payload);
      }
      let result = (this.convert)(output);
      this.completed = true;
      let outcome = match result {
        Ok(value) => {
          let snapshot = Arc::new(value);
          let old = { lock(&this.shared.value).replace(Arc::clone(&snapshot)) };
          debug_assert!(old.is_none());
          drop_contained(old);
          Ok(snapshot)
        }
        Err(error) => Err(InitError::Initialization(error)),
      };
      if let Some(payload) = this.cleanup() {
        drop_contained(outcome);
        panic::resume_unwind(payload);
      }
      Poll::Ready(outcome)
    })
  }
}

impl<T, F, Fut: Future, E> Drop for InitFuture<T, F, Fut, E> {
  fn drop(&mut self) {
    if let Some(payload) = self.cleanup() {
      if std::thread::panicking() {
        drop_contained(payload);
      } else {
        panic::resume_unwind(payload);
      }
    }
  }
}

impl<T> fmt::Debug for AsyncOnceCell<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let initialized = self.initialized();
    f.debug_struct("AsyncOnceCell")
      .field("initialized", &initialized)
      .finish_non_exhaustive()
  }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;
  use std::cell::Cell;
  use std::future::{pending, ready};
  use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
  use std::thread;

  fn poll<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(std::task::Waker::noop()))
  }

  #[test]
  fn initialized_snapshot_skips_the_factory_and_shares_the_value() {
    let local = Cell::new(3);
    let cell = AsyncOnceCell::new_with(&local, 0).unwrap();
    let mut init = cell.get_or_init(|| async { panic!("must not initialize") });
    let Poll::Ready(Ok(snapshot)) = poll(&mut init) else {
      panic!("missing snapshot")
    };
    snapshot.set(4);
    assert_eq!(local.get(), 4);
    assert!(Arc::ptr_eq(&snapshot, &cell.get().unwrap()));
    assert!(matches!(
      poll(&mut init),
      Poll::Ready(Err(InitError::Completed))
    ));
  }

  #[test]
  fn full_rejection_returns_the_uncalled_original_factory() {
    let cell = AsyncOnceCell::<usize>::new(0).unwrap();
    let mut winner = cell.get_or_init(pending);
    assert!(poll(&mut winner).is_pending());
    let calls = Arc::new(AtomicUsize::new(0));
    let captured = Arc::clone(&calls);
    let mut rejected = cell.get_or_init(move || {
      captured.fetch_add(1, Ordering::SeqCst);
      ready(7)
    });
    let Poll::Ready(Err(InitError::Admission { kind, factory })) = poll(&mut rejected) else {
      panic!("missing rejection")
    };
    assert_eq!(kind, AcquireError::Full);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(winner);
    let mut retry = cell.get_or_init(factory);
    assert!(matches!(poll(&mut retry), Poll::Ready(Ok(value)) if *value == 7));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
  }

  struct PendingCleanup(Arc<AtomicBool>);
  impl Future for PendingCleanup {
    type Output = usize;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<usize> {
      Poll::Pending
    }
  }
  impl Drop for PendingCleanup {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }

  #[test]
  fn cancellation_finishes_capture_cleanup_before_next_initializer() {
    let cell = AsyncOnceCell::<usize>::new(1).unwrap();
    let cleaned = Arc::new(AtomicBool::new(false));
    let held = Arc::clone(&cleaned);
    let mut first = cell.get_or_init(|| PendingCleanup(held));
    assert!(poll(&mut first).is_pending());
    let check = Arc::clone(&cleaned);
    let mut next = cell.get_or_init(move || {
      assert!(check.load(Ordering::SeqCst));
      ready(8)
    });
    struct CleanupWake {
      cleaned: Arc<AtomicBool>,
      observed: Arc<AtomicBool>,
    }
    impl std::task::Wake for CleanupWake {
      fn wake(self: Arc<Self>) {
        self
          .observed
          .store(self.cleaned.load(Ordering::SeqCst), Ordering::SeqCst);
      }
    }
    let observed = Arc::new(AtomicBool::new(false));
    let waker = std::task::Waker::from(Arc::new(CleanupWake {
      cleaned,
      observed: Arc::clone(&observed),
    }));
    assert!(
      Pin::new(&mut next)
        .poll(&mut Context::from_waker(&waker))
        .is_pending()
    );
    drop(first);
    assert!(observed.load(Ordering::SeqCst));
    assert!(matches!(poll(&mut next), Poll::Ready(Ok(value)) if *value == 8));
  }

  struct ReadyDropPanic;
  impl Future for ReadyDropPanic {
    type Output = usize;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<usize> {
      Poll::Ready(1)
    }
  }
  impl Drop for ReadyDropPanic {
    fn drop(&mut self) {
      panic!("initializer destructor panic")
    }
  }

  #[test]
  fn completed_initializer_drop_panic_prevents_publication_and_allows_retry() {
    let cell = AsyncOnceCell::<usize>::new(1).unwrap();
    let mut bad = cell.get_or_init(|| ReadyDropPanic);
    assert!(panic::catch_unwind(AssertUnwindSafe(|| poll(&mut bad))).is_err());
    assert!(!cell.initialized());
    assert!(matches!(
      poll(&mut bad),
      Poll::Ready(Err(InitError::Completed))
    ));
    let mut retry = cell.get_or_init(|| ready(2));
    assert!(matches!(poll(&mut retry), Poll::Ready(Ok(value)) if *value == 2));
  }

  #[test]
  fn factory_poll_and_application_errors_leave_cell_retryable() {
    let cell = AsyncOnceCell::<usize>::new(1).unwrap();
    let mut factory_panic =
      cell.get_or_init(|| -> std::future::Ready<usize> { panic!("factory panic") });
    assert!(panic::catch_unwind(AssertUnwindSafe(|| poll(&mut factory_panic))).is_err());
    let mut poll_panic = cell.get_or_init(|| async {
      panic!("poll panic");
      #[allow(unreachable_code)]
      1
    });
    assert!(panic::catch_unwind(AssertUnwindSafe(|| poll(&mut poll_panic))).is_err());
    let mut application_error = cell.get_or_try_init(|| ready(Err::<usize, _>("retry")));
    assert!(matches!(
      poll(&mut application_error),
      Poll::Ready(Err(InitError::Initialization("retry")))
    ));
    let mut success = cell.get_or_try_init(|| ready(Ok::<_, &str>(9)));
    assert!(matches!(poll(&mut success), Poll::Ready(Ok(value)) if *value == 9));
  }

  #[test]
  fn unpolled_factory_recovery_and_constructor_rejection_preserve_inputs() {
    let cell = AsyncOnceCell::<usize>::new(0).unwrap();
    let calls = Cell::new(0);
    let init = cell.get_or_init(|| {
      calls.set(calls.get() + 1);
      ready(3)
    });
    let factory = init.into_factory().unwrap();
    assert_eq!(calls.get(), 0);
    assert_eq!(factory().into_inner(), 3);
    let error = AsyncOnceCell::new_with(Box::new(17), usize::MAX)
      .err()
      .unwrap();
    assert_eq!(error.kind, SemaphoreBuildError::CapacityOverflow);
    assert_eq!(*error.into_value(), 17);
  }

  #[test]
  fn concurrent_initializers_publish_one_snapshot() {
    let cell = AsyncOnceCell::new(8).unwrap();
    let calls = AtomicUsize::new(0);
    let snapshots = thread::scope(|scope| {
      let tasks: Vec<_> = (0..8)
        .map(|value| {
          let cell = &cell;
          let calls = &calls;
          scope.spawn(move || {
            let mut init = cell.get_or_init(|| {
              calls.fetch_add(1, Ordering::SeqCst);
              ready(value)
            });
            loop {
              match poll(&mut init) {
                Poll::Ready(Ok(value)) => break value,
                Poll::Ready(Err(error)) => panic!("unexpected error: {error:?}"),
                Poll::Pending => thread::yield_now(),
              }
            }
          })
        })
        .collect();
      tasks
        .into_iter()
        .map(|task| task.join().unwrap())
        .collect::<Vec<_>>()
    });
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
      snapshots
        .iter()
        .all(|value| Arc::ptr_eq(value, &snapshots[0]))
    );
    assert_eq!(cell.set(100).unwrap_err().kind, SetErrorKind::Initialized);
  }

  #[test]
  fn managed_charge_survives_cell_destruction_until_final_snapshot() {
    use super::super::managed::{ResourceLimits, ResourceScope};
    let scope = ResourceScope::new(ResourceLimits {
      managed_memory: 64,
      disk_concurrent_ops: 0,
      network_concurrent_ops: 0,
    });
    let buffer = scope.try_alloc_zeroed(64).unwrap();
    let cell = AsyncOnceCell::new_with(buffer, 1).unwrap();
    let snapshot = cell.get().unwrap();
    drop(cell);
    assert_eq!(scope.snapshot().managed_memory, 64);
    drop(snapshot);
    assert_eq!(scope.snapshot().managed_memory, 0);
  }

  #[test]
  fn ordinary_cells_snapshots_and_initializers_can_move_between_threads() {
    fn send_sync<T: Send + Sync>() {}
    fn send<T: Send>(_: &T) {}
    send_sync::<AsyncOnceCell<usize>>();
    send_sync::<Arc<usize>>();
    let cell = AsyncOnceCell::<usize>::new(1).unwrap();
    send(&cell.get_or_init(|| ready(1)));
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use super::*;
  use loom::thread;
  use std::future::{pending, ready};

  fn poll<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(std::task::Waker::noop()))
  }

  #[test]
  fn set_racing_initializer_publishes_only_one_value() {
    loom::model(|| {
      let cell = Arc::new(AsyncOnceCell::new(1).unwrap());
      let initializing = Arc::clone(&cell);
      let initialized = thread::spawn(move || {
        let mut init = initializing.get_or_init(|| ready(1));
        loop {
          match poll(&mut init) {
            Poll::Ready(Ok(snapshot)) => break snapshot,
            Poll::Ready(Err(error)) => panic!("unexpected result: {error:?}"),
            Poll::Pending => thread::yield_now(),
          }
        }
      });
      let set_result = cell.set(2);
      let snapshot = initialized.join().unwrap();
      assert!(Arc::ptr_eq(&snapshot, &cell.get().unwrap()));
      if set_result.is_ok() {
        assert_eq!(*snapshot, 2);
      } else {
        assert_eq!(*snapshot, 1);
      }
    });
  }

  #[test]
  fn concurrent_set_attempts_cannot_replace_a_published_value() {
    loom::model(|| {
      let cell = Arc::new(AsyncOnceCell::new(1).unwrap());
      let other = Arc::clone(&cell);
      let first = thread::spawn(move || other.set(1));
      let second = cell.set(2);
      let first = first.join().unwrap();
      assert_ne!(first.is_ok(), second.is_ok());
      let expected = if first.is_ok() { 1 } else { 2 };
      assert_eq!(*cell.get().unwrap(), expected);
      if let Err(error) = first {
        assert_eq!(error.into_value(), 1);
      }
      if let Err(error) = second {
        assert_eq!(error.into_value(), 2);
      }
    });
  }

  #[test]
  fn canceled_initializer_releases_admission_for_retry() {
    loom::model(|| {
      let cell = Arc::new(AsyncOnceCell::<usize>::new(1).unwrap());
      let mut first = cell.get_or_init(pending);
      assert!(poll(&mut first).is_pending());
      let contender = Arc::clone(&cell);
      let waiter = thread::spawn(move || {
        let mut next = contender.get_or_init(|| ready(5));
        let first_poll = poll(&mut next);
        (next, first_poll)
      });
      drop(first);
      let (mut next, first_poll) = waiter.join().unwrap();
      let outcome = if first_poll.is_pending() {
        poll(&mut next)
      } else {
        first_poll
      };
      assert!(matches!(outcome, Poll::Ready(Ok(snapshot)) if *snapshot == 5));
      assert!(cell.initialized());
    });
  }
}
