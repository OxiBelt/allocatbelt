//! A bounded asynchronous mutex built from the runtime's fair semaphore.
//!
//! The mutex moves its protected value out of a short standard mutex critical
//! section after acquiring the semaphore and moves it back before releasing
//! the permit. No standard mutex guard is held across an await or while user
//! code runs. The semaphore bounds and fairly orders queued lock futures.
//!
//! A lock future owns its semaphore acquisition state and can be cancelled
//! safely. `lock` returns a guard tied to the mutex borrow; `lock_owned`
//! clones the shared state and returns a guard that can outlive the handle
//! used to create it. Closing the mutex rejects queued and future lock
//! attempts, while an already-issued guard remains valid and returns the
//! value when dropped.
//!
//! ```compile_fail
//! use allocatbelt::runtime::mutex::AsyncMutex;
//! use std::rc::Rc;
//!
//! fn assert_send<T: Send>() {}
//! let mutex = AsyncMutex::new(Rc::new(()), 1).unwrap();
//! assert_send::<AsyncMutex<Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::mutex::{AsyncMutex, MutexGuard};
//! use std::rc::Rc;
//!
//! fn assert_send<T: Send>() {}
//! let mutex = AsyncMutex::new(Rc::new(()), 1).unwrap();
//! let guard: MutexGuard<'_, Rc<()>> = mutex.try_lock().unwrap();
//! assert_send::<MutexGuard<'static, Rc<()>>>();
//! drop(guard);
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::mutex::OwnedMutexGuard;
//! use std::rc::Rc;
//! fn assert_send<T: Send>() {}
//! assert_send::<OwnedMutexGuard<Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::mutex::LockFuture;
//! use std::rc::Rc;
//! fn assert_send<T: Send>() {}
//! assert_send::<LockFuture<'static, Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::mutex::OwnedLockFuture;
//! use std::rc::Rc;
//! fn assert_send<T: Send>() {}
//! assert_send::<OwnedLockFuture<Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::mutex::MutexGuard;
//! use std::cell::Cell;
//! fn assert_sync<T: Sync>() {}
//! assert_sync::<MutexGuard<'static, Cell<usize>>>();
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::PoisonError;
use std::task::{Context, Poll};

#[cfg(loom)]
use loom::sync::{Arc, Mutex as StateMutex, MutexGuard as StateMutexGuard};
#[cfg(not(loom))]
use std::sync::{Arc, Mutex as StateMutex, MutexGuard as StateMutexGuard};

use crate::runtime::semaphore::{
  AcquireError, AcquireMany, Permit, Semaphore, SemaphoreBuildError,
};

struct Shared<T> {
  value: StateMutex<Option<T>>,
  semaphore: Semaphore,
}

/// A bounded asynchronous mutex.
///
/// `T` remains in the mutex between guards. While a guard exists, it owns the
/// value and the only semaphore permit. The semaphore's `max_waiters` bounds
/// lock futures that are queued or have been granted but not yet polled to
/// completion.
pub struct AsyncMutex<T> {
  shared: Arc<Shared<T>>,
}

/// A borrow-tied asynchronous mutex guard.
///
/// The value is restored to its mutex before the held semaphore permit is
/// released. Guards can move between threads when `T: Send`, unlike a
/// platform mutex guard, because this guard contains an owned value and no
/// standard mutex guard.
pub struct MutexGuard<'a, T> {
  shared: Arc<Shared<T>>,
  value: Option<T>,
  permit: Option<Permit>,
  _borrow: PhantomData<&'a AsyncMutex<T>>,
}

/// An owned asynchronous mutex guard that can outlive the handle used to
/// acquire it.
pub struct OwnedMutexGuard<T> {
  shared: Arc<Shared<T>>,
  value: Option<T>,
  permit: Option<Permit>,
}

/// A future returned by [`AsyncMutex::lock`].
#[must_use = "futures do nothing unless polled"]
pub struct LockFuture<'a, T> {
  mutex: &'a AsyncMutex<T>,
  acquire: AcquireMany,
  completed: bool,
}

/// An owned future returned by [`AsyncMutex::lock_owned`].
#[must_use = "futures do nothing unless polled"]
pub struct OwnedLockFuture<T> {
  shared: Arc<Shared<T>>,
  acquire: AcquireMany,
  completed: bool,
}

/// Why construction of an asynchronous mutex failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutexBuildErrorKind {
  /// The waiter-table capacity overflowed or could not be represented.
  CapacityOverflow,
  /// The preallocated waiter table could not be reserved.
  AllocationFailed,
}

/// A mutex construction error that returns the original protected value.
pub struct MutexBuildError<T> {
  /// The value passed to the constructor.
  pub value: T,
  /// Why construction failed.
  pub kind: MutexBuildErrorKind,
}

/// Why a lock attempt did not produce a guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LockError {
  /// The mutex is closed.
  Closed,
  /// No immediate permit was available or the bounded waiter table is full.
  Full,
  /// A completed lock future was polled again.
  Completed,
  /// The value slot was unexpectedly empty after a permit was issued.
  ValueUnavailable,
}

impl<T> fmt::Debug for MutexBuildError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("MutexBuildError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Display for MutexBuildError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self.kind {
      MutexBuildErrorKind::CapacityOverflow => "mutex waiter capacity overflowed",
      MutexBuildErrorKind::AllocationFailed => "mutex waiter table allocation failed",
    })
  }
}

impl<T: fmt::Debug> std::error::Error for MutexBuildError<T> {}

impl fmt::Display for LockError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Closed => "mutex is closed",
      Self::Full => "mutex waiter bound reached",
      Self::Completed => "lock future was already completed",
      Self::ValueUnavailable => "mutex value was unavailable after acquiring its permit",
    })
  }
}

impl std::error::Error for LockError {}

impl<T> AsyncMutex<T> {
  /// Creates a mutex protecting `value`, with at most `max_waiters` pending
  /// or granted-but-unobserved lock futures.
  ///
  /// If the semaphore waiter table cannot be allocated, the error returns
  /// `value` unchanged.
  pub fn new(value: T, max_waiters: usize) -> Result<Self, MutexBuildError<T>> {
    let semaphore = match Semaphore::new(1, max_waiters) {
      Ok(semaphore) => semaphore,
      Err(error) => {
        let kind = match error {
          SemaphoreBuildError::CapacityOverflow => MutexBuildErrorKind::CapacityOverflow,
          SemaphoreBuildError::AllocationFailed => MutexBuildErrorKind::AllocationFailed,
        };
        return Err(MutexBuildError { value, kind });
      }
    };
    Ok(Self {
      shared: Arc::new(Shared {
        value: StateMutex::new(Some(value)),
        semaphore,
      }),
    })
  }

  /// Returns a borrow-tied future that waits for the mutex.
  pub fn lock(&self) -> LockFuture<'_, T> {
    LockFuture {
      mutex: self,
      acquire: self.shared.semaphore.acquire_many(1),
      completed: false,
    }
  }

  /// Returns an owned future that keeps shared mutex state alive independently
  /// of this handle.
  pub fn lock_owned(&self) -> OwnedLockFuture<T> {
    OwnedLockFuture {
      shared: Arc::clone(&self.shared),
      acquire: self.shared.semaphore.acquire_many(1),
      completed: false,
    }
  }

  /// Tries to acquire the mutex without waiting.
  pub fn try_lock(&self) -> Result<MutexGuard<'_, T>, LockError> {
    let permit = self
      .shared
      .semaphore
      .try_acquire_many(1)
      .map_err(map_acquire_error)?;
    make_borrowed_guard(&self.shared, permit)
  }

  /// Tries to acquire the mutex without waiting, returning a guard independent
  /// of this handle's borrow.
  pub fn try_lock_owned(&self) -> Result<OwnedMutexGuard<T>, LockError> {
    let permit = self
      .shared
      .semaphore
      .try_acquire_many(1)
      .map_err(map_acquire_error)?;
    make_owned_guard(Arc::clone(&self.shared), permit)
  }

  /// Closes the mutex, rejecting queued and future lock attempts.
  ///
  /// An already-issued guard remains valid and restores its value before
  /// returning its permit.
  pub fn close(&self) {
    self.shared.semaphore.close();
  }

  /// Whether the mutex is closed.
  #[must_use]
  pub fn is_closed(&self) -> bool {
    self.shared.semaphore.is_closed()
  }

  /// The configured bound on queued and granted-but-unobserved lock futures.
  #[must_use]
  pub fn max_waiters(&self) -> usize {
    self.shared.semaphore.max_waiters()
  }
}

fn lock<T>(mutex: &StateMutex<T>) -> StateMutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn map_acquire_error(error: AcquireError) -> LockError {
  match error {
    AcquireError::Closed => LockError::Closed,
    AcquireError::Full => LockError::Full,
    AcquireError::Completed => LockError::Completed,
  }
}

fn take_value<T>(shared: &Shared<T>) -> Option<T> {
  lock(&shared.value).take()
}

fn make_borrowed_guard<'a, T>(
  shared: &Arc<Shared<T>>,
  permit: Permit,
) -> Result<MutexGuard<'a, T>, LockError> {
  match take_value(shared) {
    Some(value) => Ok(MutexGuard {
      shared: Arc::clone(shared),
      value: Some(value),
      permit: Some(permit),
      _borrow: PhantomData,
    }),
    None => {
      drop(permit);
      Err(LockError::ValueUnavailable)
    }
  }
}

fn make_owned_guard<T>(
  shared: Arc<Shared<T>>,
  permit: Permit,
) -> Result<OwnedMutexGuard<T>, LockError> {
  match take_value(&shared) {
    Some(value) => Ok(OwnedMutexGuard {
      shared,
      value: Some(value),
      permit: Some(permit),
    }),
    None => {
      drop(permit);
      Err(LockError::ValueUnavailable)
    }
  }
}

/// Puts a guard's value back before its semaphore permit can wake another
/// waiter. Any unexpectedly replaced value is dropped after the mutex unlocks.
fn restore_value<T>(shared: &Shared<T>, value: &mut Option<T>) {
  let Some(value) = value.take() else {
    return;
  };
  let replaced = {
    let mut slot = lock(&shared.value);
    slot.replace(value)
  };
  drop(replaced);
}

impl<'a, T> Future for LockFuture<'a, T> {
  type Output = Result<MutexGuard<'a, T>, LockError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.completed {
      return Poll::Ready(Err(LockError::Completed));
    }
    match Pin::new(&mut this.acquire).poll(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Ok(permit)) => {
        this.completed = true;
        Poll::Ready(make_borrowed_guard(&this.mutex.shared, permit))
      }
      Poll::Ready(Err(error)) => {
        this.completed = true;
        Poll::Ready(Err(map_acquire_error(error)))
      }
    }
  }
}

impl<T> Future for OwnedLockFuture<T> {
  type Output = Result<OwnedMutexGuard<T>, LockError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.completed {
      return Poll::Ready(Err(LockError::Completed));
    }
    match Pin::new(&mut this.acquire).poll(cx) {
      Poll::Pending => Poll::Pending,
      Poll::Ready(Ok(permit)) => {
        this.completed = true;
        Poll::Ready(make_owned_guard(Arc::clone(&this.shared), permit))
      }
      Poll::Ready(Err(error)) => {
        this.completed = true;
        Poll::Ready(Err(map_acquire_error(error)))
      }
    }
  }
}

impl<T> Deref for MutexGuard<'_, T> {
  type Target = T;

  fn deref(&self) -> &Self::Target {
    match self.value.as_ref() {
      Some(value) => value,
      None => unreachable!("live mutex guard always owns its value"),
    }
  }
}

impl<T> DerefMut for MutexGuard<'_, T> {
  fn deref_mut(&mut self) -> &mut Self::Target {
    match self.value.as_mut() {
      Some(value) => value,
      None => unreachable!("live mutex guard always owns its value"),
    }
  }
}

impl<T> Drop for MutexGuard<'_, T> {
  fn drop(&mut self) {
    restore_value(&self.shared, &mut self.value);
    drop(self.permit.take());
  }
}

impl<T> Deref for OwnedMutexGuard<T> {
  type Target = T;

  fn deref(&self) -> &Self::Target {
    match self.value.as_ref() {
      Some(value) => value,
      None => unreachable!("live owned mutex guard always owns its value"),
    }
  }
}

impl<T> DerefMut for OwnedMutexGuard<T> {
  fn deref_mut(&mut self) -> &mut Self::Target {
    match self.value.as_mut() {
      Some(value) => value,
      None => unreachable!("live owned mutex guard always owns its value"),
    }
  }
}

impl<T> Drop for OwnedMutexGuard<T> {
  fn drop(&mut self) {
    restore_value(&self.shared, &mut self.value);
    drop(self.permit.take());
  }
}

impl<T> fmt::Debug for AsyncMutex<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AsyncMutex")
      .field("semaphore", &self.shared.semaphore)
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Debug for LockFuture<'_, T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("LockFuture")
      .field("completed", &self.completed)
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Debug for OwnedLockFuture<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("OwnedLockFuture")
      .field("completed", &self.completed)
      .finish_non_exhaustive()
  }
}

impl<T: fmt::Debug> fmt::Debug for MutexGuard<'_, T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_tuple("MutexGuard").field(&**self).finish()
  }
}

impl<T: fmt::Debug> fmt::Debug for OwnedMutexGuard<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_tuple("OwnedMutexGuard").field(&**self).finish()
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use std::cell::Cell;
  use std::future::Future;
  use std::panic::{self, AssertUnwindSafe};
  use std::pin::pin;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::{Context, Poll, Wake, Waker};

  use super::{AsyncMutex, LockError, MutexBuildErrorKind};

  struct CountWake(AtomicUsize);

  impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
      self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.0.fetch_add(1, Ordering::Relaxed);
    }
  }

  fn context() -> Context<'static> {
    Context::from_waker(Waker::noop())
  }

  fn assert_send_sync<T: Send + Sync>() {}

  #[test]
  fn fifo_waiters_take_and_return_the_single_value() {
    let mutex = AsyncMutex::new(7usize, 2).unwrap();
    let held = mutex.try_lock().unwrap();
    let mut first = pin!(mutex.lock());
    let mut second = pin!(mutex.lock());
    let mut cx = context();

    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(second.as_mut().poll(&mut cx).is_pending());
    drop(held);

    let mut first_guard = match first.as_mut().poll(&mut cx) {
      Poll::Ready(Ok(guard)) => guard,
      other => panic!("first lock was not granted: {other:?}"),
    };
    *first_guard += 1;
    assert!(second.as_mut().poll(&mut cx).is_pending());
    drop(first_guard);
    let second_guard = match second.as_mut().poll(&mut cx) {
      Poll::Ready(Ok(guard)) => guard,
      other => panic!("second lock was not granted: {other:?}"),
    };
    assert_eq!(*second_guard, 8);
  }

  #[test]
  fn cancelling_queued_and_granted_futures_returns_capacity() {
    let mutex = AsyncMutex::new(0usize, 1).unwrap();
    let held = mutex.try_lock().unwrap();
    {
      let mut queued = pin!(mutex.lock());
      let mut cx = context();
      assert!(queued.as_mut().poll(&mut cx).is_pending());
    }
    drop(held);
    assert!(mutex.try_lock().is_ok());

    let held = mutex.try_lock().unwrap();
    let wakes = Arc::new(CountWake(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    {
      let mut granted = pin!(mutex.lock_owned());
      assert!(granted.as_mut().poll(&mut cx).is_pending());
      drop(held);
      assert!(wakes.0.load(Ordering::Relaxed) > 0);
    }
    assert!(mutex.try_lock().is_ok());
  }

  #[test]
  fn close_rejects_queued_locks_but_preserves_an_issued_guard() {
    let mutex = AsyncMutex::new(3usize, 2).unwrap();
    let mut issued = mutex.try_lock().unwrap();
    let mut queued = pin!(mutex.lock());
    let mut cx = context();
    assert!(queued.as_mut().poll(&mut cx).is_pending());
    mutex.close();
    assert!(matches!(
      queued.as_mut().poll(&mut cx),
      Poll::Ready(Err(LockError::Closed))
    ));
    *issued = 4;
    drop(issued);
    assert!(mutex.is_closed());
    assert_eq!(mutex.try_lock().unwrap_err(), LockError::Closed);
  }

  struct ReenterOnWake {
    mutex: Arc<AsyncMutex<usize>>,
    result: AtomicUsize,
  }

  impl Wake for ReenterOnWake {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      let result = match self.mutex.try_lock() {
        Err(LockError::Full) => 1,
        Err(LockError::Closed) => 2,
        Ok(_) => 3,
        _ => 4,
      };
      self.result.store(result, Ordering::Relaxed);
    }
  }

  #[test]
  fn wake_callback_can_reenter_mutex_after_unlock() {
    let mutex = Arc::new(AsyncMutex::new(0usize, 1).unwrap());
    let held = mutex.try_lock().unwrap();
    let waker_state = Arc::new(ReenterOnWake {
      mutex: Arc::clone(&mutex),
      result: AtomicUsize::new(0),
    });
    let waker = Waker::from(waker_state.clone());
    let mut cx = Context::from_waker(&waker);
    let mut queued = pin!(mutex.lock());
    assert!(queued.as_mut().poll(&mut cx).is_pending());

    drop(held);
    assert_eq!(waker_state.result.load(Ordering::Relaxed), 1);
    assert!(matches!(queued.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
  }

  #[test]
  fn panic_while_using_guard_does_not_poison_or_lose_mutex_value() {
    let mutex = AsyncMutex::new(5usize, 1).unwrap();
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
      let mut guard = mutex.try_lock().unwrap();
      *guard = 9;
      panic!("test panic while guard owns value");
    }));
    assert!(result.is_err());
    assert_eq!(*mutex.try_lock().unwrap(), 9);
  }

  #[test]
  fn owned_guard_outlives_handle_and_guard_traits_are_bounded_by_value() {
    assert_send_sync::<AsyncMutex<u32>>();
    assert_send_sync::<super::MutexGuard<'static, u32>>();
    assert_send_sync::<super::OwnedMutexGuard<u32>>();

    fn assert_send<T: Send>() {}
    assert_send::<AsyncMutex<Cell<usize>>>();
    assert_send::<super::MutexGuard<'static, Cell<usize>>>();
    assert_send::<super::OwnedMutexGuard<Cell<usize>>>();
    assert_send::<super::LockFuture<'static, Cell<usize>>>();
    assert_send::<super::OwnedLockFuture<Cell<usize>>>();

    let guard = {
      let mutex = AsyncMutex::new(String::from("retained"), 0).unwrap();
      mutex.try_lock_owned().unwrap()
    };
    assert_eq!(&*guard, "retained");
    drop(guard);
  }

  #[test]
  fn owned_lock_future_and_issued_guard_keep_shared_state_alive() {
    let mutex = AsyncMutex::new(11usize, 1).unwrap();
    let held = mutex.try_lock_owned().unwrap();
    let mut waiting = pin!(mutex.lock_owned());
    let mut cx = context();
    assert!(waiting.as_mut().poll(&mut cx).is_pending());
    drop(mutex);
    drop(held);

    let mut guard = match waiting.as_mut().poll(&mut cx) {
      Poll::Ready(Ok(guard)) => guard,
      other => panic!("owned lock did not survive handle drop: {other:?}"),
    };
    *guard += 1;
    assert_eq!(*guard, 12);
  }

  #[test]
  fn constructor_failure_returns_original_value() {
    let error = AsyncMutex::new(String::from("recover me"), usize::MAX).unwrap_err();
    assert_eq!(error.kind, MutexBuildErrorKind::CapacityOverflow);
    assert_eq!(error.value, "recover me");
  }

  #[test]
  fn full_waiter_bound_is_reported_without_losing_future_state() {
    let mutex = AsyncMutex::new(1usize, 0).unwrap();
    let held = mutex.try_lock().unwrap();
    let mut future = pin!(mutex.lock_owned());
    let mut cx = context();
    assert!(matches!(
      future.as_mut().poll(&mut cx),
      Poll::Ready(Err(LockError::Full))
    ));
    drop(held);
    assert!(mutex.try_lock().is_ok());
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use loom::sync::Arc;
  use loom::thread;

  use super::AsyncMutex;

  #[test]
  fn concurrent_try_lock_updates_are_serialized() {
    loom::model(|| {
      let mutex = Arc::new(AsyncMutex::new(0usize, 2).unwrap());
      let mut threads = Vec::new();
      for _ in 0..2 {
        let mutex = Arc::clone(&mutex);
        threads.push(thread::spawn(move || {
          loop {
            if let Ok(mut guard) = mutex.try_lock() {
              *guard += 1;
              break;
            }
            thread::yield_now();
          }
        }));
      }
      for thread in threads {
        thread.join().unwrap();
      }
      assert_eq!(*mutex.try_lock().unwrap(), 2);
    });
  }
}
