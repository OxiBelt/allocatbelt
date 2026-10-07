//! Type-erased, serialized polling for owned futures.

use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::Context;

use super::entry::TaskContextGuard;
use super::identity::TaskId;
use super::join::{AsyncJob, AsyncJoinError, JoinState};
use super::scheduler::{Shared, TaskRef};

pub(super) enum PollResult {
  Pending,
  Ready,
}

pub(super) trait ErasedTask: Send + Sync {
  /// Polls once without a scheduler lock. The future mutex prevents a
  /// cancellation cleanup from taking the future concurrently with poll.
  fn poll(&self, cx: &mut Context<'_>) -> PollResult;

  /// Drops a cancelled future and stages its terminal outcome, with no
  /// scheduler lock held.
  fn cancel(&self);

  /// Publishes the staged outcome after scheduler admission has been
  /// released.
  fn publish(&self);
}

pub(super) struct Task<F: Future + Send + 'static> {
  future: Mutex<Option<Pin<Box<F>>>>,
  staged: Mutex<Option<Result<F::Output, AsyncJoinError>>>,
  join: Arc<JoinState<F::Output>>,
  id: TaskId,
}

impl<F: Future + Send + 'static> Task<F> {
  fn lock_future(&self) -> MutexGuard<'_, Option<Pin<Box<F>>>> {
    self.future.lock().unwrap_or_else(PoisonError::into_inner)
  }

  fn finish_future(&self) -> Option<Box<dyn std::any::Any + Send>> {
    let future = self.lock_future().take();
    panic::catch_unwind(AssertUnwindSafe(|| drop(future))).err()
  }

  fn stage(&self, outcome: Result<F::Output, AsyncJoinError>) {
    let mut staged = self.staged.lock().unwrap_or_else(PoisonError::into_inner);
    *staged = Some(outcome);
  }
}

impl<F> ErasedTask for Task<F>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  fn poll(&self, cx: &mut Context<'_>) -> PollResult {
    let _task_context = TaskContextGuard::enter(Some(self.id));
    let Some(mut future) = self.lock_future().take() else {
      return PollResult::Ready;
    };
    // Take ownership before calling user code. The task-state mutex is never
    // held while polling or dropping the future.
    let result = panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx)));
    match result {
      Ok(std::task::Poll::Pending) => {
        *self.lock_future() = Some(future);
        PollResult::Pending
      }
      Ok(std::task::Poll::Ready(output)) => {
        let cleanup_panic = panic::catch_unwind(AssertUnwindSafe(|| drop(future))).err();
        if let Some(payload) = cleanup_panic {
          drop_contained(output);
          self.stage(Err(AsyncJoinError::Panicked(payload)));
        } else {
          self.stage(Ok(output));
        }
        PollResult::Ready
      }
      Err(payload) => {
        if let Err(cleanup_payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(future))) {
          drop_contained(cleanup_payload);
        }
        self.stage(Err(AsyncJoinError::Panicked(payload)));
        PollResult::Ready
      }
    }
  }

  fn cancel(&self) {
    let _task_context = TaskContextGuard::enter(Some(self.id));
    let panic = self.finish_future();
    let outcome = match panic {
      Some(payload) => Err(AsyncJoinError::Panicked(payload)),
      None => Err(AsyncJoinError::Cancelled),
    };
    self.stage(outcome);
  }

  fn publish(&self) {
    let _task_context = TaskContextGuard::enter(Some(self.id));
    let staged = self
      .staged
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .take();
    if let Some(outcome) = staged
      && let Some(unclaimed) = self.join.publish(outcome)
    {
      drop_contained(unclaimed);
    }
  }
}

pub(super) fn drop_contained<T>(value: T) {
  if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(value)))
    && let Err(second) = panic::catch_unwind(AssertUnwindSafe(|| drop(payload)))
  {
    std::mem::forget(second);
  }
}

impl<F> Task<F>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  pub(super) fn create(
    future: F,
    id: TaskId,
    shared: Weak<Shared>,
    task: TaskRef,
  ) -> (Arc<dyn ErasedTask>, AsyncJob<F::Output>) {
    let join = JoinState::with_id(id);
    let abort_shared = shared;
    let abort = Arc::new(move || {
      if let Some(shared) = abort_shared.upgrade() {
        shared.abort(task);
      }
    });
    let task = Arc::new(Self {
      future: Mutex::new(Some(Box::pin(future))),
      staged: Mutex::new(None),
      join: Arc::clone(&join),
      id,
    });
    let erased: Arc<dyn ErasedTask> = task;
    (erased, AsyncJob::new(join, abort))
  }
}
