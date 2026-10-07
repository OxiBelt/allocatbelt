//! A submitted job's shared state: its cancellation flags, its start state
//! and the slot its outcome is published to.

use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use crate::runtime::error::JoinError;
use crate::runtime::state::StartState;
use crate::runtime::worker::{self, Ident};

#[cfg(all(test, not(loom)))]
#[path = "job_future_tests.rs"]
mod future_tests;

/// Shared by a job's handle, its token and its queued task. Holds no user
/// data, so dropping it under a lock runs no user code.
pub(crate) struct Control {
  pub(crate) start: StartState,
  cancelled: AtomicBool,
  runtime: Arc<Ident>,
}

impl Control {
  pub(crate) fn new(runtime: Arc<Ident>) -> Arc<Self> {
    Arc::new(Self {
      start: StartState::new(),
      cancelled: AtomicBool::new(false),
      runtime,
    })
  }

  /// Sets the token's flag; it never clears.
  pub(crate) fn mark_cancelled(&self) {
    self.cancelled.store(true, Ordering::Release);
  }

  fn is_cancelled(&self) -> bool {
    self.cancelled.load(Ordering::Acquire)
  }
}

/// Lets a running job observe cancellation of its own handle, or a
/// [`ShutdownMode::CancelPending`](crate::runtime::ShutdownMode) shutdown or runtime
/// drop that happened while it was queued or running. A job that was
/// already released when the runtime was cancelled keeps an uncancelled
/// token. Cancellation is cooperative: the runtime never interrupts a
/// closure that has started.
#[derive(Clone)]
pub struct CancellationToken(Arc<Control>);

impl CancellationToken {
  pub(crate) fn new(control: Arc<Control>) -> Self {
    Self(control)
  }

  /// Whether the job or the runtime was cancelled.
  #[must_use]
  pub fn is_cancelled(&self) -> bool {
    self.0.is_cancelled()
  }
}

impl fmt::Debug for CancellationToken {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("CancellationToken")
      .field("cancelled", &self.is_cancelled())
      .finish()
  }
}

enum Slot<T> {
  Pending(Option<Waker>),
  Ready(Result<T, JoinError>),
  Taken,
}

/// Where the job's outcome goes: written once, by the worker that started
/// it or by the cancellation that won the start transition.
pub(crate) struct Packet<T> {
  slot: Mutex<Slot<T>>,
  ready: Condvar,
}

impl<T> Packet<T> {
  pub(crate) fn new() -> Arc<Self> {
    Arc::new(Self {
      slot: Mutex::new(Slot::Pending(None)),
      ready: Condvar::new(),
    })
  }

  fn lock(&self) -> MutexGuard<'_, Slot<T>> {
    self.slot.lock().unwrap_or_else(PoisonError::into_inner)
  }

  /// Stores the outcome. Returns it back when nobody can take it any more
  /// (the handle was dropped) so the caller drops it outside the lock; this
  /// packet's lock never runs user `Drop` code.
  pub(crate) fn publish(
    self: &Arc<Self>,
    outcome: Result<T, JoinError>,
  ) -> Option<Result<T, JoinError>> {
    let mut slot = self.lock();
    if !matches!(*slot, Slot::Pending(_)) {
      return Some(outcome);
    }
    let prior = std::mem::replace(&mut *slot, Slot::Ready(outcome));
    drop(slot);
    self.ready.notify_all();
    if let Slot::Pending(Some(waker)) = prior
      && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
    {
      crate::runtime::task::drop_contained(payload);
    }
    None
  }
}

/// The handle of a submitted job.
///
/// Dropping a `Job` detaches it: the job still runs (or stays cancelled)
/// and its result is dropped on the worker; dropping is not cancellation.
/// The handle can also be awaited without blocking an executor thread.
pub struct Job<T> {
  control: Arc<Control>,
  packet: Arc<Packet<T>>,
}

impl<T> Job<T> {
  pub(crate) fn new(control: Arc<Control>, packet: Arc<Packet<T>>) -> Self {
    Self { control, packet }
  }

  /// Cancels the job. Returns at once, without waiting for anything.
  ///
  /// If it has not started, it never will. It stays queued, holding its
  /// slot and resources, until a worker dequeues it (or a cancelling
  /// shutdown or the runtime's drop takes it). Its closure is dropped
  /// unstarted, outside the scheduler lock. Then the admission is released,
  /// and only then does [`Job::join`] return [`JoinError::Cancelled`]. If it
  /// has started, its [`CancellationToken`] reports the cancellation and the
  /// closure decides what to do. It is not interrupted, and `join` returns
  /// its result.
  pub fn cancel(&self) {
    self.control.mark_cancelled();
    let _ = self.control.start.try_cancel();
  }

  /// Whether an outcome is ready, so that [`Job::join`] does not wait.
  #[must_use]
  pub fn is_finished(&self) -> bool {
    !matches!(*self.packet.lock(), Slot::Pending(_))
  }

  /// Waits for the job's outcome.
  ///
  /// # Errors
  ///
  /// [`JoinError::Cancelled`] if it was cancelled before it started,
  /// [`JoinError::Panicked`] if its closure panicked.
  ///
  /// [`JoinError::WouldDeadlock`] at once, without waiting, if the outcome
  /// is not ready and the calling thread is one of the job's runtime's
  /// workers, or is dropping the runtime's queued jobs (a cancelling
  /// shutdown or the runtime's drop), even while it cleans up other
  /// runtimes nested inside that. That covers a job joining itself or
  /// any other job of its runtime, and a closure, result, capture or
  /// worker thread-local `Drop` doing so. Such a join could wait on work only that thread can finish.
  /// The job itself is unaffected, but this handle is consumed, so its
  /// result is lost; check [`Job::is_finished`] first to keep it. A join
  /// that is ready returns the outcome from any thread.
  pub fn join(self) -> Result<T, JoinError> {
    let mut slot = self.packet.lock();
    if matches!(*slot, Slot::Pending(_)) && worker::would_deadlock(&self.control.runtime) {
      return Err(JoinError::WouldDeadlock);
    }
    while matches!(*slot, Slot::Pending(_)) {
      slot = self
        .packet
        .ready
        .wait(slot)
        .unwrap_or_else(PoisonError::into_inner);
    }
    let taken = std::mem::replace(&mut *slot, Slot::Taken);
    drop(slot);
    match taken {
      Slot::Ready(outcome) => outcome,
      // `join` consumes the only handle, so nothing took it before.
      Slot::Pending(_) | Slot::Taken => Err(JoinError::Cancelled),
    }
  }
}

impl<T> Future for Job<T> {
  type Output = Result<T, JoinError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    crate::runtime::asynchronous::poll_cooperative(cx, |cx| {
      // Custom waker clone/drop operations may execute user code. Keep them
      // outside the packet lock, and behind the cooperative gate.
      let replacement = cx.waker().clone();
      let mut slot = self.packet.lock();
      if let Slot::Pending(waker) = &mut *slot {
        let old = waker.replace(replacement);
        drop(slot);
        drop(old);
        return Poll::Pending;
      }
      let taken = std::mem::replace(&mut *slot, Slot::Taken);
      drop(slot);
      match taken {
        Slot::Ready(outcome) => Poll::Ready(outcome),
        Slot::Pending(_) | Slot::Taken => Poll::Ready(Err(JoinError::Cancelled)),
      }
    })
  }
}

impl<T> Drop for Job<T> {
  fn drop(&mut self) {
    // A result already published is dropped here, outside the lock.
    let taken = std::mem::replace(&mut *self.packet.lock(), Slot::Taken);
    drop(taken);
  }
}

impl<T> fmt::Debug for Job<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Job")
      .field("finished", &self.is_finished())
      .finish_non_exhaustive()
  }
}
