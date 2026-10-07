//! Awaitable single-consumer task outcomes.

use std::any::Any;
use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
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
  finished: Arc<AtomicBool>,
}

impl<T> JoinState<T> {
  pub(super) fn new() -> Arc<Self> {
    Arc::new(Self {
      slot: Mutex::new(Slot::Pending(None)),
      finished: Arc::new(AtomicBool::new(false)),
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
        self.finished.store(true, Ordering::Release);
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
        self.finished.store(true, Ordering::Release);
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

  /// Returns a clonable cancellation handle independent of the output type.
  /// The handle does not retain the task's future or result.
  #[must_use]
  pub fn abort_handle(&self) -> AbortHandle {
    AbortHandle {
      abort: Arc::clone(&self.abort),
      finished: Arc::clone(&self.state.finished),
    }
  }

  /// Whether the terminal join outcome has been published after task cleanup.
  #[must_use]
  pub fn is_finished(&self) -> bool {
    self.state.finished.load(Ordering::Acquire)
  }
}

/// A clonable, thread-safe cancellation handle, including for local tasks
/// whose outputs are not `Send`. Dropping it neither cancels nor detaches work.
#[derive(Clone)]
pub struct AbortHandle {
  abort: Arc<dyn Fn() + Send + Sync>,
  finished: Arc<AtomicBool>,
}

impl AbortHandle {
  /// Requests cleanup after any current poll returns. This does not wait for
  /// cleanup and cannot preempt a running poll.
  pub fn abort(&self) {
    (self.abort)();
  }

  /// Whether the terminal join outcome has been published. Detaching the join
  /// alone does not make this true; actual task completion still must occur.
  #[must_use]
  pub fn is_finished(&self) -> bool {
    self.finished.load(Ordering::Acquire)
  }
}

impl fmt::Debug for AbortHandle {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AbortHandle")
      .field("finished", &self.is_finished())
      .finish_non_exhaustive()
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

#[cfg(all(test, not(loom)))]
mod tests {
  use super::{AbortHandle, AsyncJob, JoinState};
  use std::future::Future;
  use std::pin::Pin;
  use std::rc::Rc;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::{Context, Poll, Wake, Waker};

  #[test]
  fn local_output_does_not_restrict_abort_handle_thread_safety() {
    let calls = Arc::new(AtomicUsize::new(0));
    let captured = Arc::clone(&calls);
    let state = JoinState::<Rc<()>>::new();
    let job = AsyncJob::new(
      Arc::clone(&state),
      Arc::new(move || {
        captured.fetch_add(1, Ordering::SeqCst);
      }),
    );
    let control = job.abort_handle();
    assert!(!job.is_finished());
    assert!(!control.is_finished());
    std::thread::spawn({
      let control = control.clone();
      move || control.abort()
    })
    .join()
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!control.is_finished());
    assert!(state.publish(Ok(Rc::new(()))).is_none());
    assert!(job.is_finished());
    assert!(control.is_finished());
  }

  #[test]
  fn detached_join_stays_unfinished_until_actual_publication() {
    let state = JoinState::<usize>::new();
    let job = AsyncJob::new(Arc::clone(&state), Arc::new(|| {}));
    let control = job.abort_handle();
    drop(job);
    assert!(!control.is_finished());
    assert_eq!(state.publish(Ok(9)).unwrap().unwrap(), 9);
    assert!(control.is_finished());
  }

  struct ObserveCompletion(AbortHandle, Arc<AtomicUsize>);

  impl Wake for ObserveCompletion {
    fn wake(self: Arc<Self>) {
      assert!(self.0.is_finished());
      self.1.fetch_add(1, Ordering::SeqCst);
    }
  }

  #[test]
  fn completion_waker_observes_finished_and_ready_outcome() {
    let state = JoinState::<usize>::new();
    let mut job = AsyncJob::new(Arc::clone(&state), Arc::new(|| {}));
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(ObserveCompletion(
      job.abort_handle(),
      Arc::clone(&wakes),
    )));
    let mut context = Context::from_waker(&waker);
    assert!(Pin::new(&mut job).poll(&mut context).is_pending());
    assert!(state.publish(Ok(7)).is_none());
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    assert!(matches!(
      Pin::new(&mut job).poll(&mut context),
      Poll::Ready(Ok(7))
    ));
    assert!(job.is_finished());
  }
}
