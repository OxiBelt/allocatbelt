//! Type-erased, serialized polling for owned futures.

use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Waker};

use super::entry::TaskContextGuard;
use super::identity::TaskId;
use super::join::{
  AbortAction, AbortMetadata, AsyncJob, AsyncJoinError, JoinState, abort_metadata_bytes,
  finished_flag_bytes, new_abort_metadata,
};
use super::scheduler::{PollPermit, Shared, TaskRef};
use crate::runtime::cpu_execution::CpuExecutionGuard;
use crate::runtime::managed::ResourceScope;
use crate::runtime::resource_domain::{
  ControlCharge, DomainError, DomainReservation, DomainResource, DomainResources, DomainWaiter,
  TenantDomain,
};

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
  pub(super) task_control: ControlCharge,
  pub(super) join_control: ControlCharge,
  pub(super) abort_control: ControlCharge,
  pub(super) finished_control: ControlCharge,
  waiter_control: ControlCharge,
}

pub(super) enum PollResult {
  Pending,
  Ready,
}

pub(super) trait ErasedTask: Send + Sync {
  /// Polls once without a scheduler lock. The future mutex prevents a
  /// cancellation cleanup from taking the future concurrently with poll.
  /// Pending returns the quota permit for the caller's locked completion.
  fn poll(&self, cx: &mut Context<'_>, permit: PollPermit) -> (PollResult, Option<PollPermit>);

  /// Drops a cancelled future and stages its terminal outcome, with no
  /// scheduler lock held.
  fn cancel(&self);

  /// Publishes the staged outcome after scheduler admission has been
  /// released.
  fn publish(&self);

  /// Attempts to take one CPU ticket or enrolls the task's scheduler waker.
  fn acquire_cpu(&self, waker: &std::task::Waker) -> DomainCpuAdmission;

  /// Returns the cached waker, creating it on first use.
  fn task_waker(
    &self,
    create: &mut dyn FnMut() -> Result<Waker, DomainError>,
  ) -> Result<Waker, DomainError>;

  /// The tenant whose Control ledger charges the cached task waker for this
  /// task generation, including any clones retained after completion.
  fn tenant_domain(&self) -> Option<&TenantDomain>;

  /// Stages a typed resource failure without polling user code.
  fn fail_resource(&self, error: DomainError);
}

struct ChargedDomainWaiter {
  waiter: DomainWaiter,
  _control: ControlCharge,
}

pub(super) struct Task<F: Future + Send + 'static> {
  future: Mutex<Option<Pin<Box<F>>>>,
  staged: Mutex<Option<Result<F::Output, AsyncJoinError>>>,
  join: Arc<JoinState<F::Output>>,
  id: TaskId,
  resources: Option<ResourceScope>,
  tenant: Option<TenantDomain>,
  waiter: Mutex<Option<Arc<ChargedDomainWaiter>>>,
  waker: Mutex<Option<Waker>>,
  task_admission: Mutex<Option<DomainReservation>>,
  _abort_metadata: Arc<dyn AbortMetadata>,
  task_control: Mutex<Option<ControlCharge>>,
}

impl<F: Future + Send + 'static> Task<F> {
  fn lock_future(&self) -> MutexGuard<'_, Option<Pin<Box<F>>>> {
    self.future.lock().unwrap_or_else(PoisonError::into_inner)
  }

  fn finish_future(&self) -> Option<Box<dyn std::any::Any + Send>> {
    let future = self.lock_future().take();
    let panic = panic::catch_unwind(AssertUnwindSafe(|| drop(future))).err();
    self.release_future_frame_control();
    panic
  }

  fn release_future_frame_control(&self) {
    if let Some(control) = self
      .task_control
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .as_mut()
    {
      let result = control.try_resize(std::mem::size_of::<Self>());
      debug_assert!(
        result.is_ok(),
        "released future frame Control charge failed"
      );
    }
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

  fn release_task_waker(&self) {
    let waker = self
      .waker
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .take();
    drop(waker);
  }

  fn drop_future_and_stage(&self, error: AsyncJoinError) {
    if let Some(payload) = self.finish_future() {
      self.stage(Err(AsyncJoinError::Panicked(payload)));
    } else {
      self.stage(Err(error));
    }
    self.release_waiter();
    self.release_task_waker();
    self.release_task_admission();
  }
}

impl<F> ErasedTask for Task<F>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  fn poll(&self, cx: &mut Context<'_>, permit: PollPermit) -> (PollResult, Option<PollPermit>) {
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(self.id), self.resources.clone());
    let Some(mut future) = self.lock_future().take() else {
      self.release_waiter();
      self.release_task_waker();
      self.release_task_admission();
      drop(permit);
      return (PollResult::Ready, None);
    };
    // Take ownership before calling user code. The task-state mutex is never
    // held while polling or dropping the future.
    let cpu_execution = CpuExecutionGuard::enter(permit.cpu_domain_identity());
    let result = {
      let _cooperative_poll = super::entry::CooperativePollGuard::enter();
      panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx)))
    };
    drop(cpu_execution);
    match result {
      Ok(std::task::Poll::Pending) => {
        *self.lock_future() = Some(future);
        (PollResult::Pending, Some(permit))
      }
      Ok(std::task::Poll::Ready(output)) => {
        // Release before user destructors, output staging or cleanup.
        drop(permit);
        let cleanup_panic = panic::catch_unwind(AssertUnwindSafe(|| drop(future))).err();
        self.release_future_frame_control();
        if let Some(payload) = cleanup_panic {
          drop_contained(output);
          self.stage(Err(AsyncJoinError::Panicked(payload)));
        } else {
          self.stage(Ok(output));
        }
        self.release_waiter();
        self.release_task_waker();
        self.release_task_admission();
        (PollResult::Ready, None)
      }
      Err(payload) => {
        drop(permit);
        if let Err(cleanup_payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(future))) {
          drop_contained(cleanup_payload);
        }
        self.release_future_frame_control();
        self.stage(Err(AsyncJoinError::Panicked(payload)));
        self.release_waiter();
        self.release_task_waker();
        self.release_task_admission();
        (PollResult::Ready, None)
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
    self.release_task_waker();
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
    match waiter.waiter.try_acquire_or_register(tenant, waker) {
      Ok(Some(ticket)) => DomainCpuAdmission::Acquired(ticket),
      Ok(None) => DomainCpuAdmission::Waiting,
      Err(error) => DomainCpuAdmission::Rejected(error),
    }
  }

  fn tenant_domain(&self) -> Option<&TenantDomain> {
    self.tenant.as_ref()
  }

  fn task_waker(
    &self,
    create: &mut dyn FnMut() -> Result<Waker, DomainError>,
  ) -> Result<Waker, DomainError> {
    let mut cached = self.waker.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(waker) = cached.as_ref() {
      return Ok(waker.clone());
    }
    let waker = create()?;
    *cached = Some(waker.clone());
    Ok(waker)
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
  pub(super) fn reserve_domain_admission(
    tenant: Option<&TenantDomain>,
  ) -> Result<TaskDomainAdmission, DomainError> {
    let task_control_bytes = std::mem::size_of::<Self>()
      .checked_add(std::mem::size_of::<F>())
      .ok_or(DomainError::Invalid)?;
    let join_control_bytes = std::mem::size_of::<JoinState<F::Output>>();
    let abort_control_bytes = abort_metadata_bytes::<AsyncTaskAbort>();
    let finished_control_bytes = finished_flag_bytes();
    let waiter_control_bytes = if tenant.is_some() {
      std::mem::size_of::<ChargedDomainWaiter>()
    } else {
      0
    };
    let all_control_bytes = task_control_bytes
      .checked_add(join_control_bytes)
      .and_then(|bytes| bytes.checked_add(abort_control_bytes))
      .and_then(|bytes| bytes.checked_add(finished_control_bytes))
      .and_then(|bytes| bytes.checked_add(waiter_control_bytes))
      .ok_or(DomainError::Invalid)?;

    let (task, task_control, join_control, abort_control, finished_control, waiter_control) =
      if let Some(tenant) = tenant {
        let request = DomainResources::ZERO
          .with(DomainResource::Tasks, 1)
          .with(DomainResource::Control, all_control_bytes);
        let mut combined = tenant.try_acquire(request)?;
        let task = combined.split_off(DomainResources::ZERO.with(DomainResource::Tasks, 1))?;
        let mut control = ControlCharge::from_ticket(Some(tenant), combined, all_control_bytes);
        let task_control = control.split_off(task_control_bytes)?;
        let join_control = control.split_off(join_control_bytes)?;
        let abort_control = control.split_off(abort_control_bytes)?;
        let finished_control = control.split_off(finished_control_bytes)?;
        (
          Some(task),
          task_control,
          join_control,
          abort_control,
          finished_control,
          control,
        )
      } else {
        (
          None,
          ControlCharge::unbounded(task_control_bytes),
          ControlCharge::unbounded(join_control_bytes),
          ControlCharge::unbounded(abort_control_bytes),
          ControlCharge::unbounded(finished_control_bytes),
          ControlCharge::unbounded(waiter_control_bytes),
        )
      };

    Ok(TaskDomainAdmission {
      tenant: tenant.cloned(),
      waiter: None,
      task,
      task_control,
      join_control,
      abort_control,
      finished_control,
      waiter_control,
    })
  }

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
      task_control,
      join_control,
      abort_control,
      finished_control,
      waiter_control,
    } = domain;
    let join = JoinState::with_id(id, join_control, finished_control);
    let abort = new_abort_metadata(
      AsyncTaskAbort { shared, task },
      join.finished_flag(),
      abort_control,
    );
    let task = Arc::new(Self {
      future: Mutex::new(Some(Box::pin(future))),
      staged: Mutex::new(None),
      join: Arc::clone(&join),
      id,
      resources,
      tenant,
      waker: Mutex::new(None),
      waiter: Mutex::new(waiter.map(|waiter| {
        Arc::new(ChargedDomainWaiter {
          waiter,
          _control: waiter_control,
        })
      })),
      task_admission: Mutex::new(task_admission),
      _abort_metadata: Arc::clone(&abort),
      task_control: Mutex::new(Some(task_control)),
    });
    let erased: Arc<dyn ErasedTask> = task;
    (erased, AsyncJob::new_with_metadata(join, abort))
  }
}

struct AsyncTaskAbort {
  shared: Weak<Shared>,
  task: TaskRef,
}

impl AbortAction for AsyncTaskAbort {
  fn abort(&self) {
    if let Some(shared) = self.shared.upgrade() {
      shared.abort(self.task);
    }
  }
}

#[cfg(all(test, not(loom)))]
mod control_tests {
  use super::*;
  use crate::runtime::resource_domain::{DomainWaitPool, ResourceDomain};

  fn ceiling() -> DomainResources {
    DomainResources::ZERO
      .with(DomainResource::Cpu, 2)
      .with(DomainResource::Tasks, 4)
      .with(DomainResource::Control, 1 << 16)
  }

  #[test]
  fn async_task_admission_charges_every_distinct_control_owner_exactly() {
    let limits = ceiling();
    let domain = ResourceDomain::new(limits, 1).unwrap();
    let tenant = domain.tenant(limits).unwrap();
    let global_base = domain.snapshot().used.get(DomainResource::Control);
    let tenant_base = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    type F = std::future::Ready<()>;
    let expected = std::mem::size_of::<Task<F>>()
      + std::mem::size_of::<F>()
      + std::mem::size_of::<JoinState<()>>()
      + abort_metadata_bytes::<AsyncTaskAbort>()
      + finished_flag_bytes()
      + std::mem::size_of::<ChargedDomainWaiter>();

    let admission = Task::<F>::reserve_domain_admission(Some(&tenant))
      .unwrap_or_else(|error| panic!("combined admission failed: {error}"));
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base + expected
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      tenant_base + expected
    );
    assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 1);
    drop(admission);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      tenant_base
    );
    assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 0);
  }

  #[test]
  fn charged_domain_waiter_arc_retains_exact_payload_until_final_clone() {
    let limits = ceiling();
    let domain = ResourceDomain::with_waiters(limits, 1, 2).unwrap();
    let tenant = domain.tenant(limits).unwrap();
    let global_base = domain.snapshot().used.get(DomainResource::Control);
    let tenant_base = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    let pool_bytes = DomainWaitPool::control_payload_bytes();
    let wrapper_bytes = std::mem::size_of::<ChargedDomainWaiter>();
    let pool = tenant.reserve_waiters(1).unwrap();
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base + pool_bytes
    );
    let waiter = pool.try_lease().unwrap();
    let owner = Arc::new(ChargedDomainWaiter {
      waiter,
      _control: ControlCharge::try_new(Some(&tenant), wrapper_bytes).unwrap(),
    });
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base + pool_bytes + wrapper_bytes
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      tenant_base + pool_bytes + wrapper_bytes
    );

    let last = Arc::clone(&owner);
    drop(pool);
    drop(owner);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base + pool_bytes + wrapper_bytes
    );
    drop(last);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      global_base
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      tenant_base
    );
  }
}
