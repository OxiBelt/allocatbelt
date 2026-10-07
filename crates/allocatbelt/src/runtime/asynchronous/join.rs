//! Awaitable single-consumer task outcomes.

use std::any::Any;
use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

/// Why an async task did not produce its output.
pub enum AsyncJoinError {
  /// The task was aborted or its scope/runtime was cancelled.
  Cancelled,
  /// Polling or cleanup panicked; the original panic payload is retained.
  Panicked(Box<dyn Any + Send + 'static>),
}

impl fmt::Debug for AsyncJoinError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Cancelled => f.write_str("Cancelled"),
      Self::Panicked(_) => f.write_str("Panicked(..)"),
    }
  }
}

impl fmt::Display for AsyncJoinError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Cancelled => "async task was cancelled",
      Self::Panicked(_) => "async task panicked",
    })
  }
}

impl std::error::Error for AsyncJoinError {}

enum Slot<T> {
  Pending(Option<Waker>),
  Ready(Option<Result<T, AsyncJoinError>>),
  Taken,
}

pub(super) struct JoinState<T> {
  slot: Mutex<Slot<T>>,
}

impl<T> JoinState<T> {
  pub(super) fn new() -> Arc<Self> {
    Arc::new(Self {
      slot: Mutex::new(Slot::Pending(None)),
    })
  }

  fn lock(&self) -> MutexGuard<'_, Slot<T>> {
    self.slot.lock().unwrap_or_else(PoisonError::into_inner)
  }

  /// Publishes once. Returns an unobserved output for destruction by the
  /// worker after the join-state lock has been released.
  pub(super) fn publish(
    &self,
    result: Result<T, AsyncJoinError>,
  ) -> Option<Result<T, AsyncJoinError>> {
    let mut slot = self.lock();
    match std::mem::replace(&mut *slot, Slot::Taken) {
      Slot::Pending(waker) => {
        *slot = Slot::Ready(Some(result));
        drop(slot);
        if let Some(waker) = waker
          && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
        {
          drop_contained(payload);
        }
        None
      }
      Slot::Ready(ready) => {
        *slot = Slot::Ready(ready);
        drop(slot);
        Some(result)
      }
      Slot::Taken => {
        *slot = Slot::Taken;
        drop(slot);
        Some(result)
      }
    }
  }
}

fn drop_contained<T>(value: T) {
  if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(value)))
    && let Err(second) = panic::catch_unwind(AssertUnwindSafe(|| drop(payload)))
  {
    std::mem::forget(second);
  }
}

/// The awaitable result of a submitted future. Dropping it detaches the
/// task; call [`AsyncJob::abort`] to request cancellation.
pub struct AsyncJob<T> {
  state: Arc<JoinState<T>>,
  abort: Arc<dyn Fn() + Send + Sync>,
  finished: bool,
}

impl<T> AsyncJob<T> {
  pub(super) fn new(state: Arc<JoinState<T>>, abort: Arc<dyn Fn() + Send + Sync>) -> Self {
    Self {
      state,
      abort,
      finished: false,
    }
  }

  /// Requests cancellation. A running future is cancelled after its
  /// current poll returns; it is never preempted.
  pub fn abort(&self) {
    (self.abort)();
  }
}

impl<T> Future for AsyncJob<T> {
  type Output = Result<T, AsyncJoinError>;

  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let replacement = cx.waker().clone();
    let mut slot = self.state.lock();
    match &mut *slot {
      Slot::Pending(waker) => {
        let old = waker.replace(replacement);
        drop(slot);
        drop(old);
        Poll::Pending
      }
      Slot::Ready(outcome) => {
        let result = outcome.take();
        *slot = Slot::Taken;
        drop(slot);
        self.finished = true;
        Poll::Ready(result.unwrap_or(Err(AsyncJoinError::Cancelled)))
      }
      Slot::Taken => {
        drop(slot);
        self.finished = true;
        Poll::Ready(Err(AsyncJoinError::Cancelled))
      }
    }
  }
}

impl<T> Drop for AsyncJob<T> {
  fn drop(&mut self) {
    if !self.finished {
      let outcome = {
        let mut slot = self.state.lock();
        std::mem::replace(&mut *slot, Slot::Taken)
      };
      // Results and wakers may run user code from Drop; do so without the
      // join mutex held.
      drop(outcome);
    }
  }
}

impl<T> fmt::Debug for AsyncJob<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AsyncJob").finish_non_exhaustive()
  }
}
