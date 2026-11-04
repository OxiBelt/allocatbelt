//! Type-erased, serialized polling for owned futures.

use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Waker};

use super::entry::TaskContextGuard;
use super::identity::TaskId;
use super::join::{AbortMetadata, AsyncJob, AsyncJoinError, JoinState, MergedJoin};
use super::protocol::PollWord;
use super::scheduler::{PollPermit, Shared, TaskRef};
use crate::runtime::cpu_execution::CpuExecutionGuard;
use crate::runtime::managed::ResourceScope;
use crate::runtime::resource_domain::{
  ControlCharge, DomainError, DomainReservation, DomainResource, DomainResources, DomainWaiter,
  TenantDomain,
};
#[cfg(not(loom))]
use crate::sys::runtime_task_cell::{CellPoll, TaskCell, TaskHeader};
#[cfg(loom)]
use loom_cell::{CellPoll, TaskCell, TaskHeader};

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

/// A native task, reached only through its pinned allocation. The methods
/// that may touch the stored future take `Pin<&Self>`, which is all the
/// pinned `Arc` hands out.
pub(super) trait ErasedTask: Send + Sync {
  /// Polls once without a scheduler lock. The scheduler protocol serializes
  /// polling and cancellation cleanup; the future cell's claim serializes
  /// access to the stored future even without it.
  /// Pending returns the quota permit for the caller's locked completion.
  fn poll(
    self: Pin<&Self>,
    cx: &mut Context<'_>,
    permit: PollPermit,
  ) -> (PollResult, Option<PollPermit>);

  /// Drops a cancelled future and stages its terminal outcome, with no
  /// scheduler lock held.
  fn cancel(self: Pin<&Self>);

  /// Publishes the staged outcome after scheduler admission has been
  /// released.
  fn publish(&self);

  /// Attempts to take one CPU ticket or enrolls the task's scheduler waker.
  fn acquire_cpu(&self, waker: &Waker) -> DomainCpuAdmission;

  /// Returns a waker backed by the task allocation, without another
  /// allocation.
  fn task_waker(self: Pin<Arc<Self>>) -> Waker;

  /// Task-owned flags, never shared with a later occupant of the slot.
  fn poll_word(&self) -> &PollWord;

  /// Stages a typed resource failure without polling user code.
  fn fail_resource(self: Pin<&Self>, error: DomainError);

  /// The owners of the allocation besides this consumed handle.
  #[cfg(test)]
  fn strong_count(self: Pin<Arc<Self>>) -> usize;
}

struct TaskState {
  staged: bool,
}

// Taking a waiter for domain admission must not undo concurrent cleanup.
// Domain waker operations run outside this mutex.
enum WaiterState {
  Available(DomainWaiter),
  InUse,
  Released,
}

/// The bookkeeping half of a task allocation, shared by the scheduler, join,
/// abort handles and wakers. It lives next to the user future in the one
/// pinned [`TaskCell`]; terminal paths drop the future in place before
/// publishing, even when stale handles retain the allocation, whose size
/// (and `Control` charge) does not change.
pub(super) struct TaskBookkeeping<F: Future> {
  state: Mutex<TaskState>,
  /// Mirrors `TaskState::staged` for the pending-poll check, which reads it
  /// without the mutex. It only records that an outcome was staged. Like
  /// the mutex beside it, it is a `std` type under Loom too.
  staged: AtomicBool,
  word: PollWord,
  pub(super) join: JoinState<F::Output>,
  resources: Option<ResourceScope>,
  // Fixed at construction; only absence permits skipping tenant cleanup locks.
  tenant: Option<TenantDomain>,
  waiter: Mutex<WaiterState>,
  task_admission: Mutex<Option<DomainReservation>>,
  shared: Weak<Shared>,
  reference: TaskRef,
  // The whole allocation's charge, held until the last handle or waker.
  _task_control: ControlCharge,
}

/// One allocation: the bookkeeping and the user future, pinned together.
pub(super) type Task<F> = TaskCell<TaskBookkeeping<F>, F>;

impl<F> TaskBookkeeping<F>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  fn lock_state(&self) -> MutexGuard<'_, TaskState> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }

  fn stage(&self, outcome: Result<F::Output, AsyncJoinError>) {
    self.join.stage(outcome);
    let mut state = self.lock_state();
    state.staged = true;
    // Written while the mutex is held, after the outcome is staged, so the
    // mirror never reports an outcome the join state does not hold yet.
    self.staged.store(true, Ordering::Release);
  }

  /// Whether a terminal outcome was staged, read without the task-state
  /// mutex.
  ///
  /// The flag only moves from false to true. The pending path needs to see
  /// any `stage` that happens before its check: a cancellation or resource
  /// failure that ran before this poll began, ordered through the scheduler
  /// lock or the cell claim that serialized it with the poll. A load that
  /// happens after the store observes it (write-read coherence), exactly
  /// as the mutex-protected read did. A `stage` that is concurrent with the
  /// check has no such order with either form; both forms then return
  /// Pending and leave the outcome to the staging path, which owns the
  /// future's cleanup. Acquire pairs with the Release store, so a true load
  /// also makes the staged join value visible before
  /// `finish_future_after_staging` takes it, although the join state's own
  /// lock orders that access too.
  fn is_staged(&self) -> bool {
    self.staged.load(Ordering::Acquire)
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
}

impl<F> Task<F>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  /// Drops the future in place; returns the payload of a panicking
  /// destructor.
  fn finish_future(self: Pin<&Self>) -> Option<Box<dyn std::any::Any + Send>> {
    panic::catch_unwind(AssertUnwindSafe(|| self.drop_future())).err()
  }

  /// Drops the future after its outcome was staged. A panicking destructor
  /// replaces the staged outcome unless that outcome is already a panic:
  /// the original poll panic wins over a second panic from `Drop`.
  fn finish_future_after_staging(self: Pin<&Self>) {
    let Some(payload) = self.finish_future() else {
      return;
    };
    let this = self.header();
    let outcome = this.join.take_staged();
    if matches!(outcome, Some(Err(AsyncJoinError::Panicked(_)))) {
      drop_contained(payload);
      if let Some(outcome) = outcome {
        this.stage(outcome);
      }
    } else {
      drop_contained(outcome);
      this.stage(Err(AsyncJoinError::Panicked(payload)));
    }
  }

  fn drop_future_and_stage(self: Pin<&Self>, error: AsyncJoinError) {
    let payload = self.finish_future();
    let this = self.header();
    if let Some(payload) = payload {
      this.stage(Err(AsyncJoinError::Panicked(payload)));
    } else {
      this.stage(Err(error));
    }
    this.release_waiter();
    this.release_task_admission();
  }
}

impl<F> ErasedTask for Task<F>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  fn poll(
    self: Pin<&Self>,
    cx: &mut Context<'_>,
    permit: PollPermit,
  ) -> (PollResult, Option<PollPermit>) {
    let this = self.header();
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(this.join.id()), this.resources.clone());
    // The cell claims the future before calling user code. The task-state
    // mutex is never held while polling or dropping the future.
    let cpu_execution = CpuExecutionGuard::enter(permit.cpu_domain_identity());
    let result = {
      let _cooperative_poll = super::entry::CooperativePollGuard::enter();
      panic::catch_unwind(AssertUnwindSafe(|| self.poll_future(cx)))
    };
    drop(cpu_execution);
    let outcome = match result {
      Ok(CellPoll::Pending) => {
        if !this.is_staged() {
          return (PollResult::Pending, Some(permit));
        }
        // A terminal outcome was staged meanwhile; it owns the result.
        None
      }
      Ok(CellPoll::Ready(output)) => Some(Ok(output)),
      Ok(CellPoll::Rejected) => {
        // No future to poll: it already completed, was cancelled or failed.
        debug_assert!(
          this.lock_state().staged && this.is_staged(),
          "rejected poll without a staged outcome"
        );
        this.release_waiter();
        this.release_task_admission();
        drop(permit);
        return (PollResult::Ready, None);
      }
      Err(payload) => Some(Err(AsyncJoinError::Panicked(payload))),
    };
    if let Some(outcome) = outcome {
      this.stage(outcome);
    }
    // Release before user destructors or cleanup.
    drop(permit);
    self.finish_future_after_staging();
    this.release_waiter();
    this.release_task_admission();
    (PollResult::Ready, None)
  }

  fn cancel(self: Pin<&Self>) {
    let this = self.header();
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(this.join.id()), this.resources.clone());
    let panic = self.finish_future();
    let outcome = match panic {
      Some(payload) => Err(AsyncJoinError::Panicked(payload)),
      None => Err(AsyncJoinError::Cancelled),
    };
    this.stage(outcome);
    this.release_waiter();
    this.release_task_admission();
  }

  fn publish(&self) {
    let this = self.header();
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(this.join.id()), this.resources.clone());
    this.release_waiter();
    this.release_task_admission();
    if let Some(unclaimed) = this.join.publish_staged() {
      drop_contained(unclaimed);
    }
  }

  fn acquire_cpu(&self, waker: &Waker) -> DomainCpuAdmission {
    let this = self.header();
    let Some(tenant) = &this.tenant else {
      return DomainCpuAdmission::Unbounded;
    };
    let waiter = {
      let mut state = this.waiter.lock().unwrap_or_else(PoisonError::into_inner);
      match std::mem::replace(&mut *state, WaiterState::InUse) {
        WaiterState::Available(waiter) => waiter,
        other => {
          *state = other;
          return DomainCpuAdmission::Rejected(DomainError::WaitersFull);
        }
      }
    };
    let result = waiter.try_acquire_or_register(tenant, waker);
    let mut state = this.waiter.lock().unwrap_or_else(PoisonError::into_inner);
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

  fn task_waker(self: Pin<Arc<Self>>) -> Waker {
    // The waker takes over this owner; no second clone of the allocation.
    TaskCell::into_waker(self)
  }

  fn poll_word(&self) -> &PollWord {
    &self.header().word
  }

  fn fail_resource(self: Pin<&Self>, error: DomainError) {
    self.drop_future_and_stage(AsyncJoinError::ResourceDomain(error));
  }

  #[cfg(test)]
  fn strong_count(self: Pin<Arc<Self>>) -> usize {
    TaskCell::strong_count(&self) - 1
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
  /// Reserves the task count and the `Control` charge of the one task
  /// allocation, which stores the future inline. `F` can itself be a
  /// `Pin<Box<dyn Future>>`; moving that value in does not box it again.
  pub(super) fn reserve_domain_admission(
    tenant: Option<&TenantDomain>,
  ) -> Result<TaskDomainAdmission, DomainError> {
    let bytes = std::mem::size_of::<Self>();
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

  pub(super) fn create(
    future: F,
    id: TaskId,
    resources: Option<ResourceScope>,
    domain: TaskDomainAdmission,
    shared: Weak<Shared>,
    reference: TaskRef,
  ) -> (Pin<Arc<dyn ErasedTask>>, AsyncJob<F::Output>) {
    let TaskDomainAdmission {
      tenant,
      waiter,
      task: task_admission,
      task_control,
    } = domain;
    debug_assert_eq!(task_control.bytes(), std::mem::size_of::<Self>());
    #[cfg(all(test, not(loom)))]
    super::allocation_tests::record();
    let task = TaskCell::new(
      TaskBookkeeping {
        state: Mutex::new(TaskState { staged: false }),
        staged: AtomicBool::new(false),
        word: PollWord::new(),
        join: JoinState::embedded(id, ControlCharge::unbounded(0), None),
        resources,
        tenant,
        waiter: Mutex::new(waiter.map_or(WaiterState::Released, WaiterState::Available)),
        task_admission: Mutex::new(task_admission),
        shared,
        reference,
        _task_control: task_control,
      },
      future,
    );
    // One clone serves the job's join and abort sides; an abort handle
    // clones the same allocation again only when it is requested.
    let merged: Pin<Arc<dyn MergedJoin<F::Output>>> = task.clone();
    let job = AsyncJob::merged(merged);
    (task, job)
  }
}

impl<F> MergedJoin<F::Output> for Task<F>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  fn join_state(&self) -> &JoinState<F::Output> {
    &self.header().join
  }
}

impl<F> TaskHeader for TaskBookkeeping<F>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  fn wake_by_ref(&self) {
    Shared::wake_task(&self.shared, &self.word, self.reference);
  }
}

impl<F> AbortMetadata for Task<F>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  fn abort(&self) {
    let this = self.header();
    if let Some(shared) = this.shared.upgrade() {
      shared.abort(this.reference);
    }
  }

  fn is_finished(&self) -> bool {
    self.header().join.is_finished()
  }

  fn set_finished(&self) {
    self.header().join.set_finished();
  }
}

/// Loom compiles the runtime source in the unpublished façade, without
/// `crate::sys`, so a boxed future stands in for the inline cell with the
/// same state machine and the same pinned-handle API. Loom models therefore
/// do not cover the unsafe cell; its own Miri-checked unit tests do.
#[cfg(loom)]
mod loom_cell {
  use std::future::Future;
  use std::pin::Pin;
  use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
  use std::task::{Context, Poll, Wake, Waker};

  pub(crate) enum CellPoll<T> {
    Ready(T),
    Pending,
    Rejected,
  }

  pub(crate) trait TaskHeader: Send + Sync + 'static {
    fn wake_by_ref(&self);
  }

  struct Slot<F> {
    future: Option<Pin<Box<F>>>,
    pollable: bool,
  }

  /// Boxes both halves, so the stand-in is `Unpin` whatever `H` and `F`
  /// are and `Pin::into_inner` recovers the `Arc` for its wakers.
  pub(crate) struct TaskCell<H, F> {
    header: Box<H>,
    slot: Mutex<Slot<F>>,
  }

  impl<H, F> TaskCell<H, F> {
    pub(crate) fn new(header: H, future: F) -> Pin<Arc<Self>> {
      Arc::pin(Self {
        header: Box::new(header),
        slot: Mutex::new(Slot {
          future: Some(Box::pin(future)),
          pollable: true,
        }),
      })
    }

    pub(crate) fn header(&self) -> &H {
      &self.header
    }

    #[cfg(test)]
    pub(crate) fn strong_count(this: &Pin<Arc<Self>>) -> usize {
      Arc::strong_count(&Pin::into_inner(Pin::clone(this))) - 1
    }

    pub(crate) fn into_waker(this: Pin<Arc<Self>>) -> Waker
    where
      H: TaskHeader,
      F: Send + 'static,
    {
      Waker::from(Pin::into_inner(this))
    }

    fn try_claim(&self) -> Option<MutexGuard<'_, Slot<F>>> {
      match self.slot.try_lock() {
        Ok(slot) => Some(slot),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
      }
    }

    pub(crate) fn poll_future(self: Pin<&Self>, cx: &mut Context<'_>) -> CellPoll<F::Output>
    where
      F: Future,
    {
      let Some(mut guard) = self.try_claim() else {
        return CellPoll::Rejected;
      };
      let slot: &mut Slot<F> = &mut guard;
      if !slot.pollable {
        return CellPoll::Rejected;
      }
      let Some(future) = slot.future.as_mut() else {
        return CellPoll::Rejected;
      };
      // Stays unpollable (poisoned) if the poll unwinds or completes.
      slot.pollable = false;
      let result = future.as_mut().poll(cx);
      match result {
        Poll::Ready(output) => CellPoll::Ready(output),
        Poll::Pending => {
          slot.pollable = true;
          CellPoll::Pending
        }
      }
    }

    pub(crate) fn drop_future(self: Pin<&Self>) -> bool {
      let Some(mut slot) = self.try_claim() else {
        return false;
      };
      let taken = slot.future.take();
      drop(slot);
      let dropped = taken.is_some();
      drop(taken);
      dropped
    }
  }

  impl<H: TaskHeader, F: Send + 'static> Wake for TaskCell<H, F> {
    fn wake(self: Arc<Self>) {
      self.header.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.header.wake_by_ref();
    }
  }
}

#[cfg(all(test, not(loom)))]
mod control_tests {
  use super::*;
  use crate::runtime::resource_domain::ResourceDomain;
  use std::task::Wake;

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
    let expected = std::mem::size_of::<Task<F>>();
    let admission = Task::<F>::reserve_domain_admission(Some(&tenant)).unwrap();
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
    struct CancelOnDrop(Pin<Arc<dyn ErasedTask>>);
    // Waker::noop cannot carry the destructor that reenters cancellation.
    #[allow(clippy::manual_noop_waker)]
    impl Wake for CancelOnDrop {
      fn wake(self: Arc<Self>) {}
    }
    impl Drop for CancelOnDrop {
      fn drop(&mut self) {
        self.0.as_ref().cancel();
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
    let mut admission = Task::<F>::reserve_domain_admission(Some(&tenant)).unwrap();
    admission.waiter = Some(pool.try_lease().unwrap());
    let (task, job) = Task::create(
      std::future::pending::<()>(),
      TaskId::test_sentinel(),
      None,
      admission,
      Weak::new(),
      TaskRef::test_sentinel(),
    );
    let old = Waker::from(Arc::new(CancelOnDrop(task.clone())));
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
    // `Pending<T>` has no state, so only the output slot grows.
    let small = std::mem::size_of::<Task<std::future::Pending<()>>>();
    let large = std::mem::size_of::<Task<std::future::Pending<[u8; 4096]>>>();
    println!("Task<Pending<()>>={small} Task<Pending<[u8;4096]>>={large}");
    assert!(large - small <= 4096, "output storage was duplicated");
  }

  #[test]
  fn task_stores_the_future_inline() {
    // Same output type; only the future's state (none versus 4097 bytes)
    // differs, and it is part of the one task allocation.
    let stateless = std::mem::size_of::<Task<std::future::Pending<[u8; 4096]>>>();
    let stateful = std::mem::size_of::<Task<std::future::Ready<[u8; 4096]>>>();
    assert!(stateful - stateless >= 4096, "future storage is not inline");
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
    let task_bytes = std::mem::size_of::<Task<F>>();
    let before = super::super::allocation_tests::count();
    let mut admission = Task::<F>::reserve_domain_admission(Some(&tenant)).unwrap();
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
    let waker = task.clone().task_waker();
    assert_control(task_bytes);
    task.as_ref().cancel();
    assert!(!abort.is_finished());
    assert_eq!(domain.snapshot().used.get(DomainResource::Tasks), 0);
    // The future was dropped in place; the one allocation keeps its size.
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
    assert_eq!(super::super::allocation_tests::count() - before, 1);
  }
}

#[cfg(all(test, loom))]
mod model {
  use super::*;
  use loom::sync::Arc as ModelArc;
  use loom::sync::atomic::{AtomicBool, Ordering};
  use std::task::Wake;

  struct ObserveWake(ModelArc<AtomicBool>);

  impl Wake for ObserveWake {
    fn wake(self: Arc<Self>) {
      self.0.store(true, Ordering::Release);
    }
  }

  #[test]
  fn merged_publication_racing_join_observer_keeps_completion_and_wake() {
    loom::model(|| {
      let admission = Task::<std::future::Ready<usize>>::reserve_domain_admission(None).unwrap();
      let (task, mut job) = Task::create(
        std::future::ready(7),
        TaskId::test_sentinel(),
        None,
        admission,
        Weak::new(),
        TaskRef::test_sentinel(),
      );
      let abort = job.abort_handle();
      let stale = task.clone().task_waker();
      task.as_ref().cancel();
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
