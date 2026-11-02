//! Type-erased, serialized polling for owned futures.

use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Wake, Waker};

use super::entry::TaskContextGuard;
use super::identity::TaskId;
use super::join::{AbortMetadata, AsyncJob, AsyncJoinError, JoinState};
use super::protocol::PollWord;
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
}

pub(super) enum PollResult {
  Pending,
  Ready,
}

pub(super) trait ErasedTask: Send + Sync {
  /// Polls once without a scheduler lock. The scheduler protocol serializes
  /// polling and cancellation cleanup; the mutex transfers driver ownership.
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

  /// Returns a waker backed by the typed task Arc, without another allocation.
  fn task_waker(self: Arc<Self>) -> Waker;

  /// Task-owned flags, never shared with a later occupant of the slot.
  fn poll_word(&self) -> &PollWord;

  /// Stages a typed resource failure without polling user code.
  fn fail_resource(&self, error: DomainError);
}

type Driver = Pin<Box<dyn Future<Output = ()> + Send>>;

struct TaskState {
  future: Option<Driver>,
  staged: bool,
}

// Taking a waiter for domain admission must not undo concurrent cleanup.
// Domain waker operations run outside this mutex.
enum WaiterState {
  Available(DomainWaiter),
  InUse,
  Released,
}

/// One allocation shared by the scheduler, join, abort handles and wakers.
/// Only the boxed driver contains the user future. Terminal paths take and
/// drop it before publishing, even when stale handles retain this allocation.
pub(super) struct Task<T> {
  state: Mutex<TaskState>,
  word: PollWord,
  pub(super) join: JoinState<T>,
  resources: Option<ResourceScope>,
  // Fixed at construction; only absence permits skipping tenant cleanup locks.
  tenant: Option<TenantDomain>,
  waiter: Mutex<WaiterState>,
  task_admission: Mutex<Option<DomainReservation>>,
  shared: Weak<Shared>,
  reference: TaskRef,
  task_control: Mutex<ControlCharge>,
}

impl<T> Task<T> {
  fn lock_state(&self) -> MutexGuard<'_, TaskState> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }

  fn finish_future(&self) -> Option<Box<dyn std::any::Any + Send>> {
    let future = self.lock_state().future.take();
    let panic = panic::catch_unwind(AssertUnwindSafe(|| drop(future))).err();
    self.release_future_frame_control();
    panic
  }

  fn release_future_frame_control(&self) {
    if self.tenant.is_none() {
      return;
    }
    let result = self
      .task_control
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .try_resize(std::mem::size_of::<Self>());
    debug_assert!(
      result.is_ok(),
      "released future frame Control charge failed"
    );
  }

  fn stage(&self, outcome: Result<T, AsyncJoinError>) {
    self.join.stage(outcome);
    self.lock_state().staged = true;
  }

  fn release_waiter(&self) {
    if self.tenant.is_none() {
      return;
    }
    let waiter = std::mem::replace(
      &mut *self.waiter.lock().unwrap_or_else(PoisonError::into_inner),
      WaiterState::Released,
    );
    drop(waiter);
  }

  fn release_task_admission(&self) {
    if self.tenant.is_none() {
      return;
    }
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

impl<T: Send + 'static> ErasedTask for Task<T> {
  fn poll(&self, cx: &mut Context<'_>, permit: PollPermit) -> (PollResult, Option<PollPermit>) {
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(self.join.id()), self.resources.clone());
    let Some(mut future) = self.lock_state().future.take() else {
      self.release_waiter();
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
      Ok(result) => {
        if result.is_pending() {
          let mut state = self.lock_state();
          if !state.staged {
            state.future = Some(future);
            return (PollResult::Pending, Some(permit));
          }
        }
        // Release before user destructors, output staging or cleanup.
        drop(permit);
        let cleanup_panic = panic::catch_unwind(AssertUnwindSafe(|| drop(future))).err();
        self.release_future_frame_control();
        if let Some(payload) = cleanup_panic {
          let outcome = self.join.take_staged();
          if matches!(outcome, Some(Err(AsyncJoinError::Panicked(_)))) {
            // The original poll panic wins over a second panic from Drop.
            drop_contained(payload);
            if let Some(outcome) = outcome {
              self.stage(outcome);
            }
          } else {
            drop_contained(outcome);
            self.stage(Err(AsyncJoinError::Panicked(payload)));
          }
        }
        self.release_waiter();
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
        self.release_task_admission();
        (PollResult::Ready, None)
      }
    }
  }

  fn cancel(&self) {
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(self.join.id()), self.resources.clone());
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
      TaskContextGuard::enter_with_resource(Some(self.join.id()), self.resources.clone());
    self.release_waiter();
    self.release_task_admission();
    let staged = self.join.take_staged();
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
    let waiter = {
      let mut state = self.waiter.lock().unwrap_or_else(PoisonError::into_inner);
      match std::mem::replace(&mut *state, WaiterState::InUse) {
        WaiterState::Available(waiter) => waiter,
        other => {
          *state = other;
          return DomainCpuAdmission::Rejected(DomainError::WaitersFull);
        }
      }
    };
    let result = waiter.try_acquire_or_register(tenant, waker);
    let mut state = self.waiter.lock().unwrap_or_else(PoisonError::into_inner);
    if matches!(*state, WaiterState::Released) {
      drop(state);
      drop(waiter);
      drop(result);
      return DomainCpuAdmission::Rejected(DomainError::WaitersFull);
    }
    *state = WaiterState::Available(waiter);
    drop(state);
    match result {
      Ok(Some(ticket)) => DomainCpuAdmission::Acquired(ticket),
      Ok(None) => DomainCpuAdmission::Waiting,
      Err(error) => DomainCpuAdmission::Rejected(error),
    }
  }

  fn task_waker(self: Arc<Self>) -> Waker {
    Waker::from(self)
  }

  fn poll_word(&self) -> &PollWord {
    &self.word
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

// The driver is boxed directly. F can itself be a Pin<Box<dyn Future>>;
// moving that value into the frame does not put another box around F.
async fn driver<F>(future: F, owner: Weak<Task<F::Output>>)
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  let mut future = std::pin::pin!(future);
  std::future::poll_fn(|cx| {
    let Some(owner) = owner.upgrade() else {
      return Poll::Ready(());
    };
    // Keep the driver suspended until the caller releases the permit.
    match panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
      Ok(Poll::Ready(output)) => owner.stage(Ok(output)),
      Ok(Poll::Pending) => {}
      Err(payload) => owner.stage(Err(AsyncJoinError::Panicked(payload))),
    }
    Poll::Pending
  })
  .await;
}

fn driver_bytes<F, D>(_: fn(F, Weak<Task<F::Output>>) -> D) -> usize
where
  F: Future,
{
  std::mem::size_of::<D>()
}

impl<T: Send + 'static> Task<T> {
  pub(super) fn reserve_domain_admission<F>(
    tenant: Option<&TenantDomain>,
  ) -> Result<TaskDomainAdmission, DomainError>
  where
    F: Future<Output = T> + Send + 'static,
  {
    let bytes = std::mem::size_of::<Self>()
      .checked_add(driver_bytes(driver::<F>))
      .ok_or(DomainError::Invalid)?;
    let (task, task_control) = if let Some(tenant) = tenant {
      let request = DomainResources::ZERO
        .with(DomainResource::Tasks, 1)
        .with(DomainResource::Control, bytes);
      let mut combined = tenant.try_acquire(request)?;
      let task = combined.split_off(DomainResources::ZERO.with(DomainResource::Tasks, 1))?;
      (
        Some(task),
        ControlCharge::from_ticket(Some(tenant), combined, bytes),
      )
    } else {
      (None, ControlCharge::unbounded(bytes))
    };
    Ok(TaskDomainAdmission {
      tenant: tenant.cloned(),
      waiter: None,
      task,
      task_control,
    })
  }

  pub(super) fn create<F>(
    future: F,
    id: TaskId,
    resources: Option<ResourceScope>,
    domain: TaskDomainAdmission,
    shared: Weak<Shared>,
    reference: TaskRef,
  ) -> (Arc<dyn ErasedTask>, AsyncJob<T>)
  where
    F: Future<Output = T> + Send + 'static,
  {
    let TaskDomainAdmission {
      tenant,
      waiter,
      task: task_admission,
      task_control,
    } = domain;
    #[cfg(all(test, not(loom)))]
    super::allocation_tests::record();
    let task = Arc::new_cyclic(|owner| {
      let driver = driver(future, owner.clone());
      debug_assert_eq!(
        task_control.bytes(),
        std::mem::size_of::<Self>() + std::mem::size_of_val(&driver)
      );
      #[cfg(all(test, not(loom)))]
      super::allocation_tests::record();
      Self {
        state: Mutex::new(TaskState {
          future: Some(Box::pin(driver)),
          staged: false,
        }),
        word: PollWord::new(),
        join: JoinState::embedded(id, ControlCharge::unbounded(0), None),
        resources,
        tenant,
        waiter: Mutex::new(waiter.map_or(WaiterState::Released, WaiterState::Available)),
        task_admission: Mutex::new(task_admission),
        shared,
        reference,
        task_control: Mutex::new(task_control),
      }
    });
    let abort: Arc<dyn AbortMetadata> = task.clone();
    let job = AsyncJob::merged(Arc::clone(&task), abort);
    (task, job)
  }
}

impl<T: Send + 'static> Wake for Task<T> {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    Shared::wake_task(&self.shared, &self.word, self.reference);
  }
}

impl<T: Send + 'static> AbortMetadata for Task<T> {
  fn abort(&self) {
    if let Some(shared) = self.shared.upgrade() {
      shared.abort(self.reference);
    }
  }

  fn is_finished(&self) -> bool {
    self.join.is_finished()
  }

  fn set_finished(&self) {
    self.join.set_finished();
  }
}

#[cfg(all(test, not(loom)))]
mod control_tests {
  use super::*;
  use crate::runtime::resource_domain::ResourceDomain;

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
    let expected = std::mem::size_of::<Task<()>>() + driver_bytes(driver::<F>);
    let admission = Task::<()>::reserve_domain_admission::<F>(Some(&tenant)).unwrap();
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
  fn concurrent_waiter_release_during_acquire_does_not_restore_lease() {
    struct CancelOnDrop(Weak<dyn ErasedTask>);
    // Waker::noop cannot carry the destructor that reenters cancellation.
    #[allow(clippy::manual_noop_waker)]
    impl Wake for CancelOnDrop {
      fn wake(self: Arc<Self>) {}
    }
    impl Drop for CancelOnDrop {
      fn drop(&mut self) {
        if let Some(task) = self.0.upgrade() {
          task.cancel();
        }
      }
    }
    let limits = ceiling();
    let domain = ResourceDomain::with_waiters(limits, 1, 1).unwrap();
    let tenant = domain.tenant(limits).unwrap();
    let pool = tenant.reserve_waiters(1).unwrap();
    let cpu = tenant
      .try_acquire(DomainResources::ZERO.with(DomainResource::Cpu, 2))
      .unwrap();
    type F = std::future::Pending<()>;
    let mut admission = Task::<()>::reserve_domain_admission::<F>(Some(&tenant)).unwrap();
    admission.waiter = Some(pool.try_lease().unwrap());
    let (task, job) = Task::create(
      std::future::pending::<()>(),
      TaskId::test_sentinel(),
      None,
      admission,
      Weak::new(),
      TaskRef::test_sentinel(),
    );
    let old = Waker::from(Arc::new(CancelOnDrop(Arc::downgrade(&task))));
    assert!(matches!(
      task.acquire_cpu(&old),
      DomainCpuAdmission::Waiting
    ));
    drop(old);
    // Replacing the domain's old waker reenters cancellation while the
    // waiter is out of the task mutex. Cleanup must win over reinsertion.
    assert!(matches!(
      task.acquire_cpu(Waker::noop()),
      DomainCpuAdmission::Rejected(DomainError::WaitersFull)
    ));
    drop(pool.try_lease().expect("cancelled waiter was restored"));
    task.publish();
    assert!(job.is_finished());
    drop(cpu);
    assert_eq!(domain.snapshot().used.get(DomainResource::Cpu), 0);
  }

  #[test]
  fn task_output_uses_one_inline_storage_location() {
    let small = std::mem::size_of::<Task<()>>();
    let large = std::mem::size_of::<Task<[u8; 4096]>>();
    println!("Task<()>={small} Task<[u8;4096]>={large}");
    assert!(large - small <= 4096, "output storage was duplicated");
  }

  #[test]
  fn merged_state_retains_exact_charge_until_last_handle_or_waker() {
    type F = std::future::Ready<usize>;
    let limits = ceiling();
    let domain = ResourceDomain::with_waiters(limits, 1, 1).unwrap();
    let tenant = domain.tenant(limits).unwrap();
    let pool = tenant.reserve_waiters(1).unwrap();
    let global_base = domain.snapshot().used.get(DomainResource::Control);
    let tenant_base = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    let assert_control = |bytes| {
      assert_eq!(
        domain.snapshot().used.get(DomainResource::Control),
        global_base + bytes
      );
      assert_eq!(
        tenant.snapshot().unwrap().used.get(DomainResource::Control),
        tenant_base + bytes
      );
    };
    let task_bytes = std::mem::size_of::<Task<usize>>();
    let before = super::super::allocation_tests::count();
    let mut admission = Task::<usize>::reserve_domain_admission::<F>(Some(&tenant)).unwrap();
    admission.waiter = Some(pool.try_lease().unwrap());
    let (task, job) = Task::create(
      std::future::ready(7usize),
      TaskId::test_sentinel(),
      None,
      admission,
      Weak::new(),
      TaskRef::test_sentinel(),
    );
    let abort = job.abort_handle();
    let waker = Arc::clone(&task).task_waker();
    assert_control(task_bytes + driver_bytes(driver::<F>));
    task.cancel();
    assert!(!abort.is_finished());
    assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 0);
    assert_control(task_bytes);
    // Cancellation returns the inline waiter to the pool before publication.
    drop(pool.try_lease().unwrap());
    task.publish();
    assert!(abort.is_finished());
    drop(task);
    assert_control(task_bytes);
    drop(job);
    assert_control(task_bytes);
    drop(abort);
    assert_control(task_bytes);
    drop(waker);
    assert_control(0);
    assert_eq!(super::super::allocation_tests::count() - before, 2);
  }
}

#[cfg(all(test, loom))]
mod model {
  use super::*;
  use loom::sync::Arc as ModelArc;
  use loom::sync::atomic::{AtomicBool, Ordering};

  struct ObserveWake(ModelArc<AtomicBool>);

  impl Wake for ObserveWake {
    fn wake(self: Arc<Self>) {
      self.0.store(true, Ordering::Release);
    }
  }

  #[test]
  fn merged_publication_racing_join_observer_keeps_completion_and_wake() {
    loom::model(|| {
      let admission =
        Task::<usize>::reserve_domain_admission::<std::future::Ready<usize>>(None).unwrap();
      let (task, mut job) = Task::create(
        std::future::ready(7),
        TaskId::test_sentinel(),
        None,
        admission,
        Weak::new(),
        TaskRef::test_sentinel(),
      );
      let abort = job.abort_handle();
      let stale = Arc::clone(&task).task_waker();
      task.cancel();
      assert!(!abort.is_finished());
      stale.wake_by_ref();
      assert!(!abort.is_finished());
      let observed = ModelArc::new(AtomicBool::new(false));
      let notified = ModelArc::clone(&observed);
      let observer = loom::thread::spawn(move || {
        let waker = Waker::from(Arc::new(ObserveWake(notified)));
        let ready = Pin::new(&mut job)
          .poll_finished(&mut Context::from_waker(&waker))
          .is_ready();
        (ready, job)
      });
      let publisher = loom::thread::spawn(move || task.publish());
      let (ready, mut job) = observer.join().unwrap();
      publisher.join().unwrap();
      assert!(ready || observed.load(Ordering::Acquire));
      assert!(abort.is_finished());
      assert!(matches!(
        job.take_finished(),
        Some(Err(AsyncJoinError::Cancelled))
      ));
      stale.wake();
      assert!(abort.is_finished());
    });
  }
}
