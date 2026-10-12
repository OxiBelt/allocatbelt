//! Type-erased, serialized polling for owned futures.

use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::Context;

use super::entry::TaskContextGuard;
use super::identity::TaskId;
use super::join::{AsyncJob, AsyncJoinError, JoinState};
use super::scheduler::{PollPermit, Shared, TaskRef};
use crate::runtime::cpu_execution::CpuExecutionGuard;
use crate::runtime::managed::ResourceScope;
use crate::runtime::resource_domain::{DomainError, DomainReservation, DomainWaiter, TenantDomain};

pub(super) enum DomainCpuAdmission {
  Unbounded,
  Acquired(DomainReservation),
  Waiting,
  Rejected(DomainError),
}

pub(super) struct TaskDomainAdmission {
  pub(super) tenant: Option<TenantDomain>,
  pub(super) waiter: Option<DomainWaiter>,
  pub(super) task: Option<DomainReservation>,
}

pub(super) enum PollResult {
  Pending,
  Ready,
}

pub(super) trait ErasedTask: Send + Sync {
  /// Polls once without a scheduler lock. The future mutex prevents a
  /// cancellation cleanup from taking the future concurrently with poll.
  fn poll(&self, cx: &mut Context<'_>, permit: PollPermit) -> PollResult;

  /// Drops a cancelled future and stages its terminal outcome, with no
  /// scheduler lock held.
  fn cancel(&self);

  /// Publishes the staged outcome after scheduler admission has been
  /// released.
  fn publish(&self);

  /// Attempts to take one CPU ticket or enrolls the task's scheduler waker.
  fn acquire_cpu(&self, waker: &std::task::Waker) -> DomainCpuAdmission;

  /// Stages a typed resource failure without polling user code.
  fn fail_resource(&self, error: DomainError);
}

pub(super) struct Task<F: Future + Send + 'static> {
  future: Mutex<Option<Pin<Box<F>>>>,
  staged: Mutex<Option<Result<F::Output, AsyncJoinError>>>,
  join: Arc<JoinState<F::Output>>,
  id: TaskId,
  resources: Option<ResourceScope>,
  tenant: Option<TenantDomain>,
  waiter: Mutex<Option<Arc<DomainWaiter>>>,
  task_admission: Mutex<Option<DomainReservation>>,
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

  fn release_waiter(&self) {
    let waiter = self
      .waiter
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .take();
    drop(waiter);
  }

  fn release_task_admission(&self) {
    let admission = self
      .task_admission
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .take();
    drop(admission);
  }

  fn drop_future_and_stage(&self, error: AsyncJoinError) {
    if let Some(payload) = self.finish_future() {
      self.stage(Err(AsyncJoinError::Panicked(payload)));
    } else {
      self.stage(Err(error));
    }
    self.release_waiter();
    self.release_task_admission();
  }
}

impl<F> ErasedTask for Task<F>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  fn poll(&self, cx: &mut Context<'_>, permit: PollPermit) -> PollResult {
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(self.id), self.resources.clone());
    let Some(mut future) = self.lock_future().take() else {
      self.release_waiter();
      self.release_task_admission();
      return PollResult::Ready;
    };
    // Take ownership before calling user code. The task-state mutex is never
    // held while polling or dropping the future.
    let cpu_execution = CpuExecutionGuard::enter(permit.cpu_domain_identity());
    let result = {
      let _cooperative_poll = super::entry::CooperativePollGuard::enter();
      panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx)))
    };
    drop(cpu_execution);
    // Polling is the only quota-protected region. Release before user
    // destructors, output staging, or cancellation cleanup can execute.
    drop(permit);
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
        self.release_waiter();
        self.release_task_admission();
        PollResult::Ready
      }
      Err(payload) => {
        if let Err(cleanup_payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(future))) {
          drop_contained(cleanup_payload);
        }
        self.stage(Err(AsyncJoinError::Panicked(payload)));
        self.release_waiter();
        self.release_task_admission();
        PollResult::Ready
      }
    }
  }

  fn cancel(&self) {
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(self.id), self.resources.clone());
    let panic = self.finish_future();
    let outcome = match panic {
      Some(payload) => Err(AsyncJoinError::Panicked(payload)),
      None => Err(AsyncJoinError::Cancelled),
    };
    self.stage(outcome);
    self.release_waiter();
    self.release_task_admission();
  }

  fn publish(&self) {
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(self.id), self.resources.clone());
    self.release_waiter();
    self.release_task_admission();
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

  fn acquire_cpu(&self, waker: &std::task::Waker) -> DomainCpuAdmission {
    let Some(tenant) = &self.tenant else {
      return DomainCpuAdmission::Unbounded;
    };
    let waiter = self
      .waiter
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .as_ref()
      .map(Arc::clone);
    let Some(waiter) = waiter else {
      return DomainCpuAdmission::Rejected(DomainError::WaitersFull);
    };
    match waiter.try_acquire_or_register(tenant, waker) {
      Ok(Some(ticket)) => DomainCpuAdmission::Acquired(ticket),
      Ok(None) => DomainCpuAdmission::Waiting,
      Err(error) => DomainCpuAdmission::Rejected(error),
    }
  }

  fn fail_resource(&self, error: DomainError) {
    self.drop_future_and_stage(AsyncJoinError::ResourceDomain(error));
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
    resources: Option<ResourceScope>,
    domain: TaskDomainAdmission,
    shared: Weak<Shared>,
    task: TaskRef,
  ) -> (Arc<dyn ErasedTask>, AsyncJob<F::Output>) {
    let TaskDomainAdmission {
      tenant,
      waiter,
      task: task_admission,
    } = domain;
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
      resources,
      tenant,
      waiter: Mutex::new(waiter.map(Arc::new)),
      task_admission: Mutex::new(task_admission),
    });
    let erased: Arc<dyn ErasedTask> = task;
    (erased, AsyncJob::new(join, abort))
  }
}
