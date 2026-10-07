//! A bounded asynchronous reader-writer lock built from the runtime's fair
//! semaphore.
//!
//! Readers each hold one semaphore permit and an `Arc<T>` clone. A writer
//! waits for all configured reader permits, takes the unique `Arc<T>` out of
//! the state slot, and mutates through `Arc::get_mut`; writes never allocate a
//! replacement `Arc`. Read guards drop their value clone before returning
//! their permit, and writers restore the value before returning any permits,
//! so a newly woken writer always observes the value in the state slot.
//!
//! The reader count and FIFO waiter table are fixed at construction. A queued
//! writer forms a barrier to later readers through the semaphore's FIFO
//! ordering. Closing rejects pending and future acquisitions but leaves
//! issued guards valid. There is no upgrade operation. Downgrade converts one
//! writer permit into one reader permit, restores the shared value, and then
//! releases the writer's remaining permits.
//!
//! ```compile_fail
//! use allocatbelt::runtime::rwlock::AsyncRwLock;
//! use std::rc::Rc;
//! fn assert_send_sync<T: Send + Sync>() {}
//! assert_send_sync::<AsyncRwLock<Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::rwlock::ReadGuard;
//! use std::rc::Rc;
//! fn assert_send<T: Send>() {}
//! assert_send::<ReadGuard<'static, Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::rwlock::WriteGuard;
//! use std::rc::Rc;
//! fn assert_send<T: Send>() {}
//! assert_send::<WriteGuard<'static, Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::rwlock::OwnedReadGuard;
//! use std::rc::Rc;
//! fn assert_send<T: Send>() {}
//! assert_send::<OwnedReadGuard<Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::rwlock::OwnedWriteGuard;
//! use std::rc::Rc;
//! fn assert_send<T: Send>() {}
//! assert_send::<OwnedWriteGuard<Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::rwlock::OwnedReadFuture;
//! use std::rc::Rc;
//! fn assert_send<T: Send>() {}
//! assert_send::<OwnedReadFuture<Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::rwlock::OwnedWriteFuture;
//! use std::rc::Rc;
//! fn assert_send<T: Send>() {}
//! assert_send::<OwnedWriteFuture<Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::rwlock::ReadFuture;
//! use std::rc::Rc;
//! fn assert_send<T: Send>() {}
//! assert_send::<ReadFuture<'static, Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::rwlock::WriteFuture;
//! use std::rc::Rc;
//! fn assert_send<T: Send>() {}
//! assert_send::<WriteFuture<'static, Rc<()>>>();
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::rwlock::ReadGuard;
//! use std::cell::Cell;
//! fn assert_sync<T: Sync>() {}
//! assert_sync::<ReadGuard<'static, Cell<usize>>>();
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
  value: StateMutex<Option<Arc<T>>>,
  semaphore: Semaphore,
}

/// A bounded asynchronous reader-writer lock.
///
/// The value is shared behind `Arc` while readers hold permits. A writer
/// acquires every permit before taking the unique `Arc` and exposing mutable
/// access. `max_readers` must be nonzero; `max_waiters` bounds queued and
/// granted-but-unobserved acquisitions across both directions.
pub struct AsyncRwLock<T> {
  shared: Arc<Shared<T>>,
  max_readers: usize,
}

/// A borrow-tied shared read guard.
pub struct ReadGuard<'a, T> {
  value: Option<Arc<T>>,
  permit: Option<Permit>,
  _borrow: PhantomData<&'a AsyncRwLock<T>>,
}

/// An owned shared read guard.
pub struct OwnedReadGuard<T> {
  value: Option<Arc<T>>,
  permit: Option<Permit>,
}

/// A borrow-tied exclusive write guard.
pub struct WriteGuard<'a, T> {
  shared: Arc<Shared<T>>,
  value: Option<Arc<T>>,
  permit: Option<Permit>,
  _borrow: PhantomData<&'a AsyncRwLock<T>>,
}

/// An owned exclusive write guard.
pub struct OwnedWriteGuard<T> {
  shared: Arc<Shared<T>>,
  value: Option<Arc<T>>,
  permit: Option<Permit>,
}

/// A future returned by [`AsyncRwLock::read`].
#[must_use = "futures do nothing unless polled"]
pub struct ReadFuture<'a, T> {
  lock: &'a AsyncRwLock<T>,
  acquire: AcquireMany,
  completed: bool,
}

/// An owned future returned by [`AsyncRwLock::read_owned`].
#[must_use = "futures do nothing unless polled"]
pub struct OwnedReadFuture<T> {
  shared: Arc<Shared<T>>,
  acquire: AcquireMany,
  completed: bool,
}

/// A future returned by [`AsyncRwLock::write`].
#[must_use = "futures do nothing unless polled"]
pub struct WriteFuture<'a, T> {
  lock: &'a AsyncRwLock<T>,
  acquire: AcquireMany,
  completed: bool,
}

/// An owned future returned by [`AsyncRwLock::write_owned`].
#[must_use = "futures do nothing unless polled"]
pub struct OwnedWriteFuture<T> {
  shared: Arc<Shared<T>>,
  acquire: AcquireMany,
  completed: bool,
}

/// Why construction of an asynchronous reader-writer lock failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RwLockBuildErrorKind {
  /// Reader concurrency must be at least one.
  ZeroReaders,
  /// The waiter-table capacity overflowed or could not be represented.
  CapacityOverflow,
  /// The preallocated waiter table could not be reserved.
  AllocationFailed,
}

/// A construction error that returns the original protected value.
pub struct RwLockBuildError<T> {
  /// The value passed to the constructor.
  pub value: T,
  /// Why construction failed.
  pub kind: RwLockBuildErrorKind,
}

/// Why a read or write attempt did not produce a guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RwLockError {
  /// The lock is closed.
  Closed,
  /// No immediate permit was available or the bounded waiter table is full.
  Full,
  /// A completed acquisition future was polled again.
  Completed,
  /// The shared value slot was unexpectedly empty after acquiring permits.
  ValueUnavailable,
}

impl<T> fmt::Debug for RwLockBuildError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("RwLockBuildError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Display for RwLockBuildError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self.kind {
      RwLockBuildErrorKind::ZeroReaders => "reader count must be nonzero",
      RwLockBuildErrorKind::CapacityOverflow => "rwlock waiter capacity overflowed",
      RwLockBuildErrorKind::AllocationFailed => "rwlock waiter table allocation failed",
    })
  }
}

impl<T: fmt::Debug> std::error::Error for RwLockBuildError<T> {}

impl fmt::Display for RwLockError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Closed => "rwlock is closed",
      Self::Full => "rwlock waiter bound reached",
      Self::Completed => "rwlock acquisition future was already completed",
      Self::ValueUnavailable => "rwlock value was unavailable after acquiring permits",
    })
  }
}

impl std::error::Error for RwLockError {}

impl<T> fmt::Debug for AsyncRwLock<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AsyncRwLock")
      .field("max_readers", &self.max_readers)
      .field("semaphore", &self.shared.semaphore)
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Debug for ReadFuture<'_, T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ReadFuture")
      .field("completed", &self.completed)
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Debug for OwnedReadFuture<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("OwnedReadFuture")
      .field("completed", &self.completed)
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Debug for WriteFuture<'_, T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("WriteFuture")
      .field("completed", &self.completed)
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Debug for OwnedWriteFuture<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("OwnedWriteFuture")
      .field("completed", &self.completed)
      .finish_non_exhaustive()
  }
}

impl<T: fmt::Debug> fmt::Debug for ReadGuard<'_, T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_tuple("ReadGuard").field(&**self).finish()
  }
}

impl<T: fmt::Debug> fmt::Debug for OwnedReadGuard<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_tuple("OwnedReadGuard").field(&**self).finish()
  }
}

impl<T: fmt::Debug> fmt::Debug for WriteGuard<'_, T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_tuple("WriteGuard").field(&**self).finish()
  }
}

impl<T: fmt::Debug> fmt::Debug for OwnedWriteGuard<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_tuple("OwnedWriteGuard").field(&**self).finish()
  }
}

impl<T> AsyncRwLock<T> {
  /// Creates a lock protecting `value` with the given reader and waiter bounds.
  ///
  /// `max_readers` must be nonzero. If construction fails, the error returns
  /// the original value unchanged.
  pub fn new(
    value: T,
    max_readers: usize,
    max_waiters: usize,
  ) -> Result<Self, RwLockBuildError<T>> {
    if max_readers == 0 {
      return Err(RwLockBuildError {
        value,
        kind: RwLockBuildErrorKind::ZeroReaders,
      });
    }
    let semaphore = match Semaphore::new(max_readers, max_waiters) {
      Ok(semaphore) => semaphore,
      Err(error) => {
        let kind = match error {
          SemaphoreBuildError::CapacityOverflow => RwLockBuildErrorKind::CapacityOverflow,
          SemaphoreBuildError::AllocationFailed => RwLockBuildErrorKind::AllocationFailed,
        };
        return Err(RwLockBuildError { value, kind });
      }
    };
    Ok(Self {
      shared: Arc::new(Shared {
        value: StateMutex::new(Some(Arc::new(value))),
        semaphore,
      }),
      max_readers,
    })
  }

  /// Returns a borrow-tied future that acquires one shared reader permit.
  pub fn read(&self) -> ReadFuture<'_, T> {
    ReadFuture {
      lock: self,
      acquire: self.shared.semaphore.acquire_many(1),
      completed: false,
    }
  }

  /// Returns an owned future that acquires one shared reader permit.
  pub fn read_owned(&self) -> OwnedReadFuture<T> {
    OwnedReadFuture {
      shared: Arc::clone(&self.shared),
      acquire: self.shared.semaphore.acquire_many(1),
      completed: false,
    }
  }

  /// Returns a borrow-tied future that acquires every reader permit
  /// exclusively.
  pub fn write(&self) -> WriteFuture<'_, T> {
    WriteFuture {
      lock: self,
      acquire: self.shared.semaphore.acquire_many(self.max_readers),
      completed: false,
    }
  }

  /// Returns an owned future that acquires every reader permit exclusively.
  pub fn write_owned(&self) -> OwnedWriteFuture<T> {
    OwnedWriteFuture {
      shared: Arc::clone(&self.shared),
      acquire: self.shared.semaphore.acquire_many(self.max_readers),
      completed: false,
    }
  }

  /// Tries to acquire a shared read guard without waiting.
  pub fn try_read(&self) -> Result<ReadGuard<'_, T>, RwLockError> {
    let permit = self
      .shared
      .semaphore
      .try_acquire_many(1)
      .map_err(map_acquire_error)?;
    make_read_guard(&self.shared, permit)
  }

  /// Tries to acquire an owned shared read guard without waiting.
  pub fn try_read_owned(&self) -> Result<OwnedReadGuard<T>, RwLockError> {
    let permit = self
      .shared
      .semaphore
      .try_acquire_many(1)
      .map_err(map_acquire_error)?;
    make_owned_read_guard(Arc::clone(&self.shared), permit)
  }

  /// Tries to acquire an exclusive write guard without waiting.
  pub fn try_write(&self) -> Result<WriteGuard<'_, T>, RwLockError> {
    let permit = self
      .shared
      .semaphore
      .try_acquire_many(self.max_readers)
      .map_err(map_acquire_error)?;
    make_write_guard(&self.shared, permit)
  }

  /// Tries to acquire an owned exclusive write guard without waiting.
  pub fn try_write_owned(&self) -> Result<OwnedWriteGuard<T>, RwLockError> {
    let permit = self
      .shared
      .semaphore
      .try_acquire_many(self.max_readers)
      .map_err(map_acquire_error)?;
    make_owned_write_guard(Arc::clone(&self.shared), permit)
  }

  /// Closes the lock, rejecting queued and future acquisitions.
  ///
  /// Guards already issued remain valid. They restore their value or release
  /// their read reference before returning their semaphore permits.
  pub fn close(&self) {
    self.shared.semaphore.close();
  }

  /// Whether the lock is closed.
  #[must_use]
  pub fn is_closed(&self) -> bool {
    self.shared.semaphore.is_closed()
  }

  /// The configured maximum number of concurrent readers.
  #[must_use]
  pub const fn max_readers(&self) -> usize {
    self.max_readers
  }

  /// The configured bound on queued and granted-but-unobserved acquisitions.
  #[must_use]
  pub fn max_waiters(&self) -> usize {
    self.shared.semaphore.max_waiters()
  }
}

fn lock<T>(mutex: &StateMutex<T>) -> StateMutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn map_acquire_error(error: AcquireError) -> RwLockError {
  match error {
    AcquireError::Closed => RwLockError::Closed,
    AcquireError::Full => RwLockError::Full,
    AcquireError::Completed => RwLockError::Completed,
  }
}

fn make_read_guard<'a, T>(
  shared: &Arc<Shared<T>>,
  permit: Permit,
) -> Result<ReadGuard<'a, T>, RwLockError> {
  let value = lock(&shared.value).as_ref().map(Arc::clone);
  match value {
    Some(value) => Ok(ReadGuard {
      value: Some(value),
      permit: Some(permit),
      _borrow: PhantomData,
    }),
    None => {
      drop(permit);
      Err(RwLockError::ValueUnavailable)
    }
  }
}

fn make_owned_read_guard<T>(
  shared: Arc<Shared<T>>,
  permit: Permit,
) -> Result<OwnedReadGuard<T>, RwLockError> {
  let value = lock(&shared.value).as_ref().map(Arc::clone);
  match value {
    Some(value) => Ok(OwnedReadGuard {
      value: Some(value),
      permit: Some(permit),
    }),
    None => {
      drop(permit);
      Err(RwLockError::ValueUnavailable)
    }
  }
}

fn make_write_guard<'a, T>(
  shared: &Arc<Shared<T>>,
  permit: Permit,
) -> Result<WriteGuard<'a, T>, RwLockError> {
  let value = lock(&shared.value).take();
  match value {
    Some(value) => Ok(WriteGuard {
      shared: Arc::clone(shared),
      value: Some(value),
      permit: Some(permit),
      _borrow: PhantomData,
    }),
    None => {
      drop(permit);
      Err(RwLockError::ValueUnavailable)
    }
  }
}

fn make_owned_write_guard<T>(
  shared: Arc<Shared<T>>,
  permit: Permit,
) -> Result<OwnedWriteGuard<T>, RwLockError> {
  let value = lock(&shared.value).take();
  match value {
    Some(value) => Ok(OwnedWriteGuard {
      shared,
      value: Some(value),
      permit: Some(permit),
    }),
    None => {
      drop(permit);
      Err(RwLockError::ValueUnavailable)
    }
  }
}

fn restore_value<T>(shared: &Shared<T>, value: &mut Option<Arc<T>>) {
  let Some(value) = value.take() else {
    return;
  };
  let replaced = {
    let mut slot = lock(&shared.value);
    slot.replace(value)
  };
  drop(replaced);
}

fn downgrade_value<T>(shared: &Shared<T>, value: &Arc<T>) -> Arc<T> {
  let new_slot = Arc::clone(value);
  let replaced = {
    let mut slot = lock(&shared.value);
    slot.replace(new_slot)
  };
  drop(replaced);
  Arc::clone(value)
}

impl<'a, T> Future for ReadFuture<'a, T> {
  type Output = Result<ReadGuard<'a, T>, RwLockError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if this.completed {
        return Poll::Ready(Err(RwLockError::Completed));
      }
      match Pin::new(&mut this.acquire).poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(permit)) => {
          this.completed = true;
          Poll::Ready(make_read_guard(&this.lock.shared, permit))
        }
        Poll::Ready(Err(error)) => {
          this.completed = true;
          Poll::Ready(Err(map_acquire_error(error)))
        }
      }
    })
  }
}

impl<T> Future for OwnedReadFuture<T> {
  type Output = Result<OwnedReadGuard<T>, RwLockError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if this.completed {
        return Poll::Ready(Err(RwLockError::Completed));
      }
      match Pin::new(&mut this.acquire).poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(permit)) => {
          this.completed = true;
          Poll::Ready(make_owned_read_guard(Arc::clone(&this.shared), permit))
        }
        Poll::Ready(Err(error)) => {
          this.completed = true;
          Poll::Ready(Err(map_acquire_error(error)))
        }
      }
    })
  }
}

impl<'a, T> Future for WriteFuture<'a, T> {
  type Output = Result<WriteGuard<'a, T>, RwLockError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if this.completed {
        return Poll::Ready(Err(RwLockError::Completed));
      }
      match Pin::new(&mut this.acquire).poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(permit)) => {
          this.completed = true;
          Poll::Ready(make_write_guard(&this.lock.shared, permit))
        }
        Poll::Ready(Err(error)) => {
          this.completed = true;
          Poll::Ready(Err(map_acquire_error(error)))
        }
      }
    })
  }
}

impl<T> Future for OwnedWriteFuture<T> {
  type Output = Result<OwnedWriteGuard<T>, RwLockError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if this.completed {
        return Poll::Ready(Err(RwLockError::Completed));
      }
      match Pin::new(&mut this.acquire).poll(cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(permit)) => {
          this.completed = true;
          Poll::Ready(make_owned_write_guard(Arc::clone(&this.shared), permit))
        }
        Poll::Ready(Err(error)) => {
          this.completed = true;
          Poll::Ready(Err(map_acquire_error(error)))
        }
      }
    })
  }
}

impl<T> Deref for ReadGuard<'_, T> {
  type Target = T;

  fn deref(&self) -> &Self::Target {
    match self.value.as_deref() {
      Some(value) => value,
      None => unreachable!("live read guard always owns its value reference"),
    }
  }
}

impl<T> Drop for ReadGuard<'_, T> {
  fn drop(&mut self) {
    drop(self.value.take());
    drop(self.permit.take());
  }
}

impl<T> Deref for OwnedReadGuard<T> {
  type Target = T;

  fn deref(&self) -> &Self::Target {
    match self.value.as_deref() {
      Some(value) => value,
      None => unreachable!("live owned read guard always owns its value reference"),
    }
  }
}

impl<T> Drop for OwnedReadGuard<T> {
  fn drop(&mut self) {
    drop(self.value.take());
    drop(self.permit.take());
  }
}

impl<'a, T> WriteGuard<'a, T> {
  /// Converts this exclusive guard into a shared guard while retaining one
  /// reader permit.
  ///
  /// The current value is restored to the state slot before the remaining
  /// writer permits are released. `Err(self)` is possible only if the private
  /// permit split invariant is violated; on that path this guard is unchanged.
  pub fn downgrade(mut self) -> Result<ReadGuard<'a, T>, Self> {
    let Some(read_permit) = self.permit.as_mut().and_then(|permit| permit.split(1)) else {
      return Err(self);
    };
    let value = match self.value.take() {
      Some(value) => value,
      None => unreachable!("live write guard always owns its value"),
    };
    let read_value = downgrade_value(&self.shared, &value);
    drop(self.permit.take());
    Ok(ReadGuard {
      value: Some(read_value),
      permit: Some(read_permit),
      _borrow: PhantomData,
    })
  }
}

impl<T> OwnedWriteGuard<T> {
  /// Converts this exclusive guard into an owned shared guard while retaining
  /// one reader permit.
  pub fn downgrade(mut self) -> Result<OwnedReadGuard<T>, Self> {
    let Some(read_permit) = self.permit.as_mut().and_then(|permit| permit.split(1)) else {
      return Err(self);
    };
    let value = match self.value.take() {
      Some(value) => value,
      None => unreachable!("live owned write guard always owns its value"),
    };
    let read_value = downgrade_value(&self.shared, &value);
    drop(self.permit.take());
    Ok(OwnedReadGuard {
      value: Some(read_value),
      permit: Some(read_permit),
    })
  }
}

impl<T> Deref for WriteGuard<'_, T> {
  type Target = T;

  fn deref(&self) -> &Self::Target {
    match self.value.as_deref() {
      Some(value) => value,
      None => unreachable!("live write guard always owns its value"),
    }
  }
}

impl<T> DerefMut for WriteGuard<'_, T> {
  fn deref_mut(&mut self) -> &mut Self::Target {
    match self.value.as_mut().and_then(Arc::get_mut) {
      Some(value) => value,
      None => unreachable!("write guard owns the unique value reference"),
    }
  }
}

impl<T> Drop for WriteGuard<'_, T> {
  fn drop(&mut self) {
    restore_value(&self.shared, &mut self.value);
    drop(self.permit.take());
  }
}

impl<T> Deref for OwnedWriteGuard<T> {
  type Target = T;

  fn deref(&self) -> &Self::Target {
    match self.value.as_deref() {
      Some(value) => value,
      None => unreachable!("live owned write guard always owns its value"),
    }
  }
}

impl<T> DerefMut for OwnedWriteGuard<T> {
  fn deref_mut(&mut self) -> &mut Self::Target {
    match self.value.as_mut().and_then(Arc::get_mut) {
      Some(value) => value,
      None => unreachable!("owned write guard owns the unique value reference"),
    }
  }
}

impl<T> Drop for OwnedWriteGuard<T> {
  fn drop(&mut self) {
    restore_value(&self.shared, &mut self.value);
    drop(self.permit.take());
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use std::future::Future;
  use std::panic::{self, AssertUnwindSafe};
  use std::pin::pin;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::{Context, Poll, Wake, Waker};

  use super::{AsyncRwLock, RwLockBuildErrorKind, RwLockError};

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
  fn concurrent_readers_share_value_and_reader_limit_is_enforced() {
    let lock = AsyncRwLock::new(17usize, 2, 2).unwrap();
    let first = lock.try_read().unwrap();
    let second = lock.try_read().unwrap();
    assert_eq!((*first, *second), (17, 17));
    assert!(matches!(lock.try_read(), Err(RwLockError::Full)));
    assert!(matches!(lock.try_write(), Err(RwLockError::Full)));

    drop(first);
    assert!(lock.try_read().is_ok());
    drop(second);
  }

  #[test]
  fn queued_writer_blocks_later_readers_and_runs_first() {
    let lock = AsyncRwLock::new(0usize, 2, 3).unwrap();
    let first_read = lock.try_read().unwrap();
    let second_read = lock.try_read().unwrap();
    let mut writer = pin!(lock.write());
    let mut reader = pin!(lock.read());
    let mut cx = context();
    assert!(writer.as_mut().poll(&mut cx).is_pending());
    assert!(reader.as_mut().poll(&mut cx).is_pending());

    drop(first_read);
    assert!(writer.as_mut().poll(&mut cx).is_pending());
    assert!(reader.as_mut().poll(&mut cx).is_pending());
    drop(second_read);
    let mut write_guard = match writer.as_mut().poll(&mut cx) {
      Poll::Ready(Ok(guard)) => guard,
      other => panic!("writer did not receive all permits: {other:?}"),
    };
    *write_guard = 23;
    assert!(reader.as_mut().poll(&mut cx).is_pending());
    drop(write_guard);
    let read_guard = match reader.as_mut().poll(&mut cx) {
      Poll::Ready(Ok(guard)) => guard,
      other => panic!("reader did not follow the writer: {other:?}"),
    };
    assert_eq!(*read_guard, 23);
  }

  #[test]
  fn last_reader_drops_its_arc_before_waking_writer() {
    let lock = AsyncRwLock::new(31usize, 1, 1).unwrap();
    let reader = lock.try_read().unwrap();
    let mut writer = pin!(lock.write());
    let mut cx = context();
    assert!(writer.as_mut().poll(&mut cx).is_pending());
    drop(reader);
    let mut guard = match writer.as_mut().poll(&mut cx) {
      Poll::Ready(Ok(guard)) => guard,
      other => panic!("writer did not receive the unique Arc: {other:?}"),
    };
    *guard += 1;
    assert_eq!(*guard, 32);
  }

  #[test]
  fn cancelling_queued_and_granted_writes_returns_all_permits() {
    let lock = AsyncRwLock::new(5usize, 2, 1).unwrap();
    let held = lock.try_write().unwrap();
    {
      let mut queued = pin!(lock.write());
      let mut cx = context();
      assert!(queued.as_mut().poll(&mut cx).is_pending());
    }
    drop(held);
    assert!(lock.try_write().is_ok());

    let held = lock.try_write().unwrap();
    let wakes = Arc::new(CountWake(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    {
      let mut granted = pin!(lock.write_owned());
      assert!(granted.as_mut().poll(&mut cx).is_pending());
      drop(held);
      assert!(wakes.0.load(Ordering::Relaxed) > 0);
    }
    assert!(lock.try_write().is_ok());
  }

  #[test]
  fn downgrade_keeps_one_reader_until_queued_writer_can_run() {
    let lock = AsyncRwLock::new(41usize, 2, 2).unwrap();
    let mut first = lock.try_write().unwrap();
    *first += 1;
    let mut next_writer = pin!(lock.write());
    let mut reader = pin!(lock.read());
    let mut cx = context();
    assert!(next_writer.as_mut().poll(&mut cx).is_pending());
    assert!(reader.as_mut().poll(&mut cx).is_pending());

    let read_guard = first.downgrade().unwrap();
    assert_eq!(*read_guard, 42);
    assert!(next_writer.as_mut().poll(&mut cx).is_pending());
    assert!(reader.as_mut().poll(&mut cx).is_pending());
    drop(read_guard);
    let next_guard = match next_writer.as_mut().poll(&mut cx) {
      Poll::Ready(Ok(guard)) => guard,
      other => panic!("queued writer did not receive all permits: {other:?}"),
    };
    assert!(reader.as_mut().poll(&mut cx).is_pending());
    drop(next_guard);
    assert!(matches!(reader.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
  }

  #[test]
  fn close_rejects_waiters_but_issued_guard_remains_valid() {
    let lock = AsyncRwLock::new(9usize, 1, 2).unwrap();
    let mut issued = lock.try_write().unwrap();
    let mut queued = pin!(lock.read());
    let mut cx = context();
    assert!(queued.as_mut().poll(&mut cx).is_pending());
    lock.close();
    assert!(matches!(
      queued.as_mut().poll(&mut cx),
      Poll::Ready(Err(RwLockError::Closed))
    ));
    *issued = 10;
    drop(issued);
    assert!(lock.is_closed());
    assert_eq!(lock.try_read().unwrap_err(), RwLockError::Closed);
  }

  #[test]
  fn reentrant_waker_can_attempt_acquisition_after_unlock() {
    struct Reenter {
      lock: Arc<AsyncRwLock<usize>>,
      result: AtomicUsize,
    }

    impl Wake for Reenter {
      fn wake(self: Arc<Self>) {
        self.wake_by_ref();
      }

      fn wake_by_ref(self: &Arc<Self>) {
        let result = match self.lock.try_write() {
          Err(RwLockError::Full) => 1,
          Err(RwLockError::Closed) => 2,
          Ok(_) => 3,
          _ => 4,
        };
        self.result.store(result, Ordering::Relaxed);
      }
    }

    let lock = Arc::new(AsyncRwLock::new(0usize, 1, 1).unwrap());
    let held = lock.try_write().unwrap();
    let state = Arc::new(Reenter {
      lock: Arc::clone(&lock),
      result: AtomicUsize::new(0),
    });
    let waker = Waker::from(state.clone());
    let mut cx = Context::from_waker(&waker);
    let mut queued = pin!(lock.write());
    assert!(queued.as_mut().poll(&mut cx).is_pending());
    drop(held);
    assert_eq!(state.result.load(Ordering::Relaxed), 1);
    assert!(matches!(queued.as_mut().poll(&mut cx), Poll::Ready(Ok(_))));
  }

  #[test]
  fn panic_while_mutating_writer_restores_value_and_releases_lock() {
    let lock = AsyncRwLock::new(13usize, 2, 1).unwrap();
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
      let mut guard = lock.try_write().unwrap();
      *guard = 21;
      panic!("test panic while writer owns value");
    }));
    assert!(result.is_err());
    assert_eq!(*lock.try_read().unwrap(), 21);
  }

  #[test]
  fn constructor_rejects_zero_readers_and_returns_original_value() {
    let error = AsyncRwLock::new(String::from("value"), 0, 3).unwrap_err();
    assert_eq!(error.kind, RwLockBuildErrorKind::ZeroReaders);
    assert_eq!(error.value, "value");
  }

  #[test]
  fn owned_guards_and_futures_outlive_the_lock_handle() {
    assert_send_sync::<AsyncRwLock<usize>>();
    assert_send_sync::<super::ReadGuard<'static, usize>>();
    assert_send_sync::<super::OwnedReadGuard<usize>>();
    assert_send_sync::<super::WriteGuard<'static, usize>>();
    assert_send_sync::<super::OwnedWriteGuard<usize>>();
    assert_send_sync::<super::ReadFuture<'static, usize>>();
    assert_send_sync::<super::OwnedReadFuture<usize>>();
    assert_send_sync::<super::WriteFuture<'static, usize>>();
    assert_send_sync::<super::OwnedWriteFuture<usize>>();

    let mut guard = {
      let lock = AsyncRwLock::new(String::from("owned"), 2, 0).unwrap();
      lock.try_write_owned().unwrap()
    };
    guard.push('!');
    assert_eq!(&*guard, "owned!");
  }

  #[test]
  fn owned_read_guard_keeps_value_alive_after_lock_drop() {
    let guard = {
      let lock = AsyncRwLock::new(String::from("read-owned"), 2, 0).unwrap();
      lock.try_read_owned().unwrap()
    };
    assert_eq!(&*guard, "read-owned");
  }

  #[test]
  fn owned_waiting_writer_future_keeps_shared_state_after_handle_drop() {
    let lock = AsyncRwLock::new(String::from("waiting"), 1, 1).unwrap();
    let reader = lock.try_read_owned().unwrap();
    let mut writer = pin!(lock.write_owned());
    let mut cx = context();
    assert!(writer.as_mut().poll(&mut cx).is_pending());
    drop(lock);
    drop(reader);

    let mut guard = match writer.as_mut().poll(&mut cx) {
      Poll::Ready(Ok(guard)) => guard,
      other => panic!("owned writer future lost shared state: {other:?}"),
    };
    guard.push('!');
    assert_eq!(&*guard, "waiting!");
  }

  #[test]
  fn max_one_reader_can_downgrade_after_close_and_handle_drop() {
    let writer = {
      let lock = AsyncRwLock::new(String::from("closed"), 1, 0).unwrap();
      let writer = lock.try_write_owned().unwrap();
      lock.close();
      writer
    };
    let reader = writer.downgrade().unwrap();
    assert_eq!(&*reader, "closed");
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use loom::sync::Arc;
  use loom::sync::atomic::{AtomicBool, Ordering};
  use loom::thread;

  use super::AsyncRwLock;

  #[test]
  fn racing_reader_and_writer_preserve_exclusive_mutation() {
    loom::model(|| {
      let lock = Arc::new(AsyncRwLock::new(0usize, 2, 4).unwrap());
      let started = Arc::new(AtomicBool::new(false));
      let worker_lock = Arc::clone(&lock);
      let worker_started = Arc::clone(&started);
      let reader = thread::spawn(move || {
        worker_started.store(true, Ordering::Release);
        match worker_lock.try_read() {
          Ok(guard) => {
            assert!(*guard <= 1);
            true
          }
          Err(_) => false,
        }
      });

      while !started.load(Ordering::Acquire) {
        thread::yield_now();
      }
      let writer_acquired = match lock.try_write() {
        Ok(mut guard) => {
          *guard += 1;
          true
        }
        Err(_) => false,
      };
      let reader_acquired = reader.join().unwrap();
      if !writer_acquired {
        *lock.try_write().unwrap() += 1;
      }
      assert_eq!(*lock.try_read().unwrap(), 1);
      assert!(writer_acquired || reader_acquired);
    });
  }
}
