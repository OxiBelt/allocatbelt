//! Type-erased, serialized polling for owned futures.

use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::task::{Context, Waker};

use super::entry::TaskContextGuard;
use super::identity::TaskId;
use super::join::{AbortMetadata, AsyncJob, AsyncJoinError, MergedJoin};
use super::scheduler::{PollPermit, Shared, TaskRef};
use crate::runtime::cpu_execution::CpuExecutionGuard;
use crate::runtime::managed::ResourceScope;
use crate::runtime::resource_domain::{
  ControlCharge, DomainError, DomainReservation, DomainResource, DomainResources, DomainWaiter,
  TenantDomain,
};
#[cfg(not(loom))]
pub(super) use crate::sys::runtime_task_cell::{
  CellPoll, JoinSide, Lease, PollNotify, TaskCell, TaskHeader, TaskJoin, TaskLend, TaskSlot,
  TaskWord,
};
#[cfg(loom)]
pub(super) use loom_cell::{CellPoll, JoinSide, Lease, TaskCell, TaskHeader, TaskLend, TaskSlot};
#[cfg(loom)]
pub(super) use word::{PollNotify, PollWord, TaskJoin, TaskWord};

/// The task word and join protocol, compiled from the cell's own source so
/// the Loom models exercise the same transitions.
#[cfg(loom)]
#[path = "../../sys/runtime_task_word.rs"]
mod word;

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
pub(super) trait ErasedTask: TaskLend {
  /// Polls once without a scheduler lock. The scheduler protocol serializes
  /// polling and cancellation cleanup; the future cell's claim serializes
  /// access to the stored future even without it.
  /// Pending returns the quota permit for the caller's locked completion.
  /// `cpu_ticket` is the CPU ticket held for this poll, if any; a ready poll
  /// drops it right after the permit, and a pending poll leaves it with the
  /// caller.
  fn poll(
    self: Pin<&Self>,
    cx: &mut Context<'_>,
    permit: PollPermit,
    cpu_ticket: &mut Option<DomainReservation>,
  ) -> (PollResult, Option<PollPermit>);

  /// Drops a cancelled future and stores its terminal outcome, with no
  /// scheduler lock held.
  fn cancel(self: Pin<&Self>);

  /// Publishes the stored outcome after scheduler admission has been
  /// released.
  fn publish(&self);

  /// Attempts to take one CPU ticket or enrolls the task's scheduler waker.
  fn acquire_cpu(&self, waker: &Waker) -> DomainCpuAdmission;

  /// Returns a waker backed by the task allocation, without another
  /// allocation. A turn uses the waker its lease borrows instead.
  #[cfg(test)]
  fn task_waker(self: Pin<Arc<Self>>) -> Waker;

  /// The scheduling face of the task-owned word, never shared with a later
  /// occupant of the slot.
  fn poll_word(&self) -> &TaskWord;

  /// Stores a typed resource failure without polling user code.
  fn fail_resource(self: Pin<&Self>, error: DomainError);

  /// The owners of the allocation besides this consumed handle.
  #[cfg(test)]
  fn strong_count(self: Pin<Arc<Self>>) -> usize;
}

// Taking a waiter for domain admission must not undo concurrent cleanup.
// Domain waker operations run outside this mutex.
enum WaiterState {
  Available(DomainWaiter),
  InUse,
  Released,
}

/// The bookkeeping half of a task allocation, shared by the scheduler, join,
/// abort handles and wakers. It lives next to the user future, the task
/// word and the outcome in the one pinned [`TaskCell`]; terminal paths drop
/// the future in place before publishing, even when stale handles retain
/// the allocation, whose size (and `Control` charge) does not change.
// `repr(C)` keeps the fields every poll reads (identity, reference,
// resources, tenant presence) first; tenant-only state lives in one boxed
// allocation that untenanted tasks do not have.
#[repr(C)]
pub(super) struct TaskBookkeeping {
  id: TaskId,
  reference: TaskRef,
  resources: Option<ResourceScope>,
  shared: Weak<Shared>,
  // Fixed at construction; only absence permits skipping tenant cleanup locks.
  tenant: Option<Box<TenantTask>>,
}

/// The tenant-only half of a task's bookkeeping. Its box is charged in the
/// task's `Control` bytes together with the task allocation.
struct TenantTask {
  domain: TenantDomain,
  waiter: Mutex<WaiterState>,
  task_admission: Mutex<Option<DomainReservation>>,
  // The task allocation's and this box's charge, held until the last
  // handle or waker.
  _task_control: ControlCharge,
}

/// The terminal outcome a join handle receives.
pub(super) type Outcome<T> = Result<T, AsyncJoinError>;

/// One allocation: the bookkeeping, the word, the user future and its
/// outcome, pinned together.
pub(super) type Task<F> = TaskCell<TaskBookkeeping, F, Outcome<<F as Future>::Output>>;

impl TaskBookkeeping {
  #[inline]
  fn release_waiter(&self) {
    let Some(tenant) = &self.tenant else {
      return;
    };
    let waiter = std::mem::replace(
      &mut *tenant.waiter.lock().unwrap_or_else(PoisonError::into_inner),
      WaiterState::Released,
    );
    drop(waiter);
  }

  #[inline]
  fn release_task_admission(&self) {
    let Some(tenant) = &self.tenant else {
      return;
    };
    let admission = tenant
      .task_admission
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .take();
    drop(admission);
  }
}

/// The outcome of a future whose destructor may have panicked after it
/// produced `outcome`: the original poll panic wins over a second panic
/// from `Drop`; any other outcome is replaced by the destructor's panic.
fn after_drop<T>(
  outcome: Outcome<T>,
  payload: Option<Box<dyn std::any::Any + Send>>,
) -> Outcome<T> {
  let Some(payload) = payload else {
    return outcome;
  };
  if matches!(outcome, Err(AsyncJoinError::Panicked(_))) {
    drop_contained(payload);
    outcome
  } else {
    drop_contained(outcome);
    Err(AsyncJoinError::Panicked(payload))
  }
}

impl<F> Task<F>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  /// Drops the future in place and stores `error`, or the destructor's
  /// panic, as the outcome.
  fn drop_future_and_store(self: Pin<&Self>, error: AsyncJoinError) {
    let stored = self.finish(|payload| after_drop(Err(error), payload));
    // The scheduler runs cleanup only inside the task's own turn or as the
    // final owner, so no poll can hold the future here.
    debug_assert!(stored || self.is_finished(), "cleanup raced a poll");
    let this = self.header();
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
    cpu_ticket: &mut Option<DomainReservation>,
  ) -> (PollResult, Option<PollPermit>) {
    let this = self.header();
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(this.id), this.resources.clone());
    // The cell claims the future before calling user code.
    let cpu_execution =
      CpuExecutionGuard::enter(cpu_ticket.as_ref().map(DomainReservation::domain_identity));
    let result = {
      let _cooperative_poll = super::entry::CooperativePollGuard::enter();
      panic::catch_unwind(AssertUnwindSafe(|| self.poll_future(cx)))
    };
    drop(cpu_execution);
    let outcome = match result {
      Ok(CellPoll::Pending) => return (PollResult::Pending, Some(permit)),
      Ok(CellPoll::Ready(output)) => Ok(output),
      Ok(CellPoll::Rejected) => {
        // No future to poll: it completed, was cancelled or failed, and
        // that path stored the outcome.
        debug_assert!(self.is_finished(), "rejected poll without an outcome");
        this.release_waiter();
        this.release_task_admission();
        drop(permit);
        drop(cpu_ticket.take());
        return (PollResult::Ready, None);
      }
      Err(payload) => Err(AsyncJoinError::Panicked(payload)),
    };
    // Release before user destructors or cleanup.
    drop(permit);
    drop(cpu_ticket.take());
    let stored = self.finish(|payload| after_drop(outcome, payload));
    debug_assert!(stored, "a completed poll holds the cell's only claim");
    this.release_waiter();
    this.release_task_admission();
    (PollResult::Ready, None)
  }

  fn cancel(self: Pin<&Self>) {
    let this = self.header();
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(this.id), this.resources.clone());
    self.drop_future_and_store(AsyncJoinError::Cancelled);
  }

  fn publish(&self) {
    let this = self.header();
    let _task_context =
      TaskContextGuard::enter_with_resource(Some(this.id), this.resources.clone());
    this.release_waiter();
    this.release_task_admission();
    let publication = TaskCell::publish(self);
    debug_assert!(publication.published, "published before an outcome");
    // An unobserved outcome, a waker whose handle detached meanwhile, or a
    // panicking wake: dropped here, without any scheduler lock.
    let [first, second] = publication.wake_panics;
    drop_contained(first);
    drop_contained(second);
    drop_contained(publication.wakers);
    drop_contained(publication.output);
  }

  fn acquire_cpu(&self, waker: &Waker) -> DomainCpuAdmission {
    let this = self.header();
    let Some(tenant_task) = &this.tenant else {
      return DomainCpuAdmission::Unbounded;
    };
    let tenant = &tenant_task.domain;
    let waiter = {
      let mut state = tenant_task
        .waiter
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
      match std::mem::replace(&mut *state, WaiterState::InUse) {
        WaiterState::Available(waiter) => waiter,
        other => {
          *state = other;
          return DomainCpuAdmission::Rejected(DomainError::WaitersFull);
        }
      }
    };
    let result = waiter.try_acquire_or_register(tenant, waker);
    let mut state = tenant_task
      .waiter
      .lock()
      .unwrap_or_else(PoisonError::into_inner);
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

  #[cfg(test)]
  fn task_waker(self: Pin<Arc<Self>>) -> Waker {
    // The waker takes over this owner; no second clone of the allocation.
    TaskCell::into_waker(self)
  }

  fn poll_word(&self) -> &TaskWord {
    self.word()
  }

  fn fail_resource(self: Pin<&Self>, error: DomainError) {
    self.drop_future_and_store(AsyncJoinError::ResourceDomain(error));
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
  /// The `Control` bytes of one task: the allocation, plus the boxed
  /// tenant state of a tenant task.
  pub(super) fn charged_bytes(tenant: bool) -> usize {
    std::mem::size_of::<Self>()
      + if tenant {
        std::mem::size_of::<TenantTask>()
      } else {
        0
      }
  }

  /// Reserves the task count and the `Control` charge of the one task
  /// allocation, which stores the future and its outcome inline, and of a
  /// tenant task's boxed tenant state. `F` can itself be a
  /// `Pin<Box<dyn Future>>`; moving that value in does not box it again.
  pub(super) fn reserve_domain_admission(
    tenant: Option<&TenantDomain>,
  ) -> Result<TaskDomainAdmission, DomainError> {
    let bytes = Self::charged_bytes(tenant.is_some());
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
    debug_assert_eq!(task_control.bytes(), Self::charged_bytes(tenant.is_some()));
    #[cfg(all(test, not(loom)))]
    super::allocation_tests::record();
    // The one join handle shares the allocation; an abort handle clones the
    // same allocation again only when it is requested.
    let (task, join) = TaskCell::new_with_join_queued(
      TaskBookkeeping {
        id,
        reference,
        resources,
        shared,
        tenant: tenant.map(|domain| {
          Box::new(TenantTask {
            domain,
            waiter: Mutex::new(waiter.map_or(WaiterState::Released, WaiterState::Available)),
            task_admission: Mutex::new(task_admission),
            _task_control: task_control,
          })
        }),
      },
      future,
      |task| -> Pin<Arc<dyn MergedJoin<F::Output>>> { task },
    );
    (task, AsyncJob::merged(join))
  }
}

impl<F> MergedJoin<F::Output> for Task<F>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  fn task_id(&self) -> TaskId {
    self.header().id
  }
}

impl TaskHeader for TaskBookkeeping {
  fn wake_by_ref(&self, word: &TaskWord) {
    Shared::wake_task(&self.shared, word, self.reference);
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
    self.is_complete()
  }

  fn set_finished(&self) {
    // Publication sets the word's `COMPLETE`; nothing else may.
  }
}

/// Loom compiles the runtime source in the unpublished façade, without
/// `crate::sys`, so a boxed future stands in for the inline cell with the
/// same state machine and the same pinned-handle API, and mutex cells with
/// an overlap witness stand in for the outcome and join waker cells. The
/// task word and the join protocol are the cell's own source (`word`), so
/// the models cover them; they do not cover the unsafe cell, which its own
/// Miri-checked unit tests do.
#[cfg(loom)]
mod loom_cell {
  use super::word::{
    self, JoinCells, JoinWakers, PollWord, Publication, TaskJoin, TaskWord, WakerSlot,
  };
  use loom::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
  use std::any::Any;
  use std::future::Future;
  use std::panic::{self, AssertUnwindSafe};
  use std::pin::Pin;
  use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, TryLockError};
  use std::task::{Context, Poll, Wake, Waker};

  pub(crate) use super::word::JoinSide;

  pub(crate) enum CellPoll<T> {
    Ready(T),
    Pending,
    Rejected,
  }

  pub(crate) trait TaskHeader: Send + Sync + 'static {
    fn wake_by_ref(&self, word: &TaskWord);
  }

  struct Slot<F> {
    future: Option<Pin<Box<F>>>,
    pollable: bool,
    finished: bool,
  }

  /// A cell whose exclusive accesses must never overlap any other access;
  /// each access is a Loom atomic step, so the model explores overlaps.
  struct Witnessed<T> {
    writing: AtomicBool,
    readers: AtomicUsize,
    value: RwLock<T>,
  }

  impl<T> Witnessed<T> {
    fn new(value: T) -> Self {
      Self {
        writing: AtomicBool::new(false),
        readers: AtomicUsize::new(0),
        value: RwLock::new(value),
      }
    }

    fn write<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
      assert!(
        !self.writing.swap(true, Ordering::Relaxed),
        "overlapping exclusive accesses"
      );
      assert_eq!(
        self.readers.load(Ordering::Relaxed),
        0,
        "write during a read"
      );
      let result = f(&mut self.value.write().unwrap_or_else(PoisonError::into_inner));
      self.writing.store(false, Ordering::Relaxed);
      result
    }

    fn read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
      self.readers.fetch_add(1, Ordering::Relaxed);
      assert!(!self.writing.load(Ordering::Relaxed), "read during a write");
      let result = f(&self.value.read().unwrap_or_else(PoisonError::into_inner));
      self.readers.fetch_sub(1, Ordering::Relaxed);
      result
    }
  }

  /// The outcome cell: exclusive accesses only, which must never overlap.
  struct Exclusive<T> {
    writing: AtomicBool,
    value: Mutex<T>,
  }

  impl<T> Exclusive<T> {
    fn new(value: T) -> Self {
      Self {
        writing: AtomicBool::new(false),
        value: Mutex::new(value),
      }
    }

    fn write<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
      assert!(
        !self.writing.swap(true, Ordering::Relaxed),
        "overlapping exclusive accesses"
      );
      let result = f(&mut self.value.lock().unwrap_or_else(PoisonError::into_inner));
      self.writing.store(false, Ordering::Relaxed);
      result
    }
  }

  /// Boxes both halves, so the stand-in is `Unpin` whatever `H` and `F`
  /// are and `Pin::into_inner` recovers the `Arc` for its wakers.
  pub(crate) struct TaskCell<H, F, O> {
    header: Box<H>,
    word: TaskWord,
    slot: Mutex<Slot<F>>,
    stored: AtomicBool,
    output: Box<Exclusive<Option<O>>>,
    join_waker: Witnessed<JoinWakers>,
  }

  impl<H, F, O> TaskCell<H, F, O> {
    fn build(header: H, future: F, join_interest: bool) -> Pin<Arc<Self>> {
      Arc::pin(Self {
        header: Box::new(header),
        word: TaskWord::new(join_interest),
        slot: Mutex::new(Slot {
          future: Some(Box::pin(future)),
          pollable: true,
          finished: false,
        }),
        stored: AtomicBool::new(false),
        output: Box::new(Exclusive::new(None)),
        join_waker: Witnessed::new(JoinWakers::default()),
      })
    }

    pub(crate) fn new_with_join<J>(
      header: H,
      future: F,
      erase: impl FnOnce(Pin<Arc<Self>>) -> Pin<Arc<J>>,
    ) -> (Pin<Arc<Self>>, TaskJoin<J>)
    where
      J: ?Sized + JoinSide<Output = O>,
    {
      let task = Self::build(header, future, true);
      let join = erase(Pin::clone(&task));
      (task, TaskJoin::new(join))
    }

    pub(crate) fn new_with_join_queued<J>(
      header: H,
      future: F,
      erase: impl FnOnce(Pin<Arc<Self>>) -> Pin<Arc<J>>,
    ) -> (Pin<Arc<Self>>, TaskJoin<J>)
    where
      J: ?Sized + JoinSide<Output = O>,
    {
      let (task, join) = Self::new_with_join(header, future, erase);
      assert_eq!(task.word.notify(), super::PollNotify::Enqueue);
      (task, join)
    }

    pub(crate) fn header(&self) -> &H {
      &self.header
    }

    pub(crate) fn word(&self) -> &TaskWord {
      &self.word
    }

    pub(crate) fn is_complete(&self) -> bool {
      self.word.is_complete()
    }

    pub(crate) fn is_finished(&self) -> bool {
      self
        .slot
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .finished
    }

    #[cfg(test)]
    pub(crate) fn strong_count(this: &Pin<Arc<Self>>) -> usize {
      Arc::strong_count(&Pin::into_inner(Pin::clone(this))) - 1
    }

    pub(crate) fn into_waker(this: Pin<Arc<Self>>) -> Waker
    where
      H: TaskHeader,
      F: Send + 'static,
      O: Send + 'static,
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

    pub(crate) fn finish(
      self: Pin<&Self>,
      make: impl FnOnce(Option<Box<dyn Any + Send>>) -> O,
    ) -> bool {
      let Some(mut slot) = self.try_claim() else {
        return false;
      };
      if slot.finished {
        return false;
      }
      slot.finished = true;
      slot.pollable = false;
      let taken = slot.future.take();
      drop(slot);
      let payload = panic::catch_unwind(AssertUnwindSafe(|| drop(taken))).err();
      let outcome = make(payload);
      self.output.write(|output| *output = Some(outcome));
      self.stored.store(true, Ordering::Release);
      true
    }

    pub(crate) fn publish(&self) -> Publication<O> {
      if !self.stored.load(Ordering::Acquire) {
        return Publication::refused();
      }
      word::publish(self.word.inner(), self)
    }
  }

  impl<H, F, O> JoinCells for TaskCell<H, F, O> {
    type Output = O;

    fn waker_will_wake(&self, slot: WakerSlot, waker: &Waker) -> bool {
      self.join_waker.read(|stored| {
        stored
          .get(slot)
          .is_some_and(|stored| stored.will_wake(waker))
      })
    }

    fn wake_join(&self, slot: WakerSlot) {
      self.join_waker.read(|stored| {
        if let Some(waker) = stored.get(slot) {
          waker.wake_by_ref();
        }
      });
    }

    fn update_join_wakers<R>(&self, update: impl FnOnce(&mut JoinWakers) -> R) -> R {
      self.join_waker.write(update)
    }

    fn take_output(&self) -> Option<O> {
      self.output.write(Option::take)
    }
  }

  impl<H, F, O> word::Sealed for TaskCell<H, F, O> {}

  impl<H: Send + Sync, F: Send, O: Send> JoinSide for TaskCell<H, F, O> {
    type Output = O;

    fn join_complete(&self) -> bool {
      self.word.is_complete()
    }

    fn join_poll(
      &self,
      _key: word::JoinKey,
      slot: word::WakerSlot,
      waker: &Waker,
      take: bool,
    ) -> Poll<Option<O>> {
      word::join_poll(self.word.inner(), self, slot, waker, take)
    }

    fn join_take(&self, _key: word::JoinKey) -> Option<Option<O>> {
      word::join_take(self.word.inner(), self)
    }

    fn join_detach(&self, _key: word::JoinKey) -> (Option<O>, word::JoinWakers) {
      word::join_detach(self.word.inner(), self)
    }
  }

  pub(crate) trait TaskLend: word::Sealed + Send + Sync {
    fn lend_word(&self) -> &PollWord;
    fn lend_waker(self: Pin<Arc<Self>>) -> Waker;
  }

  impl<H: TaskHeader, F: Send + 'static, O: Send + 'static> TaskLend for TaskCell<H, F, O> {
    fn lend_word(&self) -> &PollWord {
      self.word.inner()
    }

    fn lend_waker(self: Pin<Arc<Self>>) -> Waker {
      Self::into_waker(self)
    }
  }

  /// The slot container; the stand-in lease holds its own clone, so Loom
  /// models the word transitions, not the borrowed owner.
  pub(crate) struct TaskSlot<T: ?Sized + TaskLend> {
    task: Option<Pin<Arc<T>>>,
  }

  impl<T: ?Sized + TaskLend> TaskSlot<T> {
    pub(crate) const fn empty() -> Self {
      Self { task: None }
    }

    pub(crate) fn is_occupied(&self) -> bool {
      self.task.is_some()
    }

    pub(crate) fn get(&self) -> Option<&Pin<Arc<T>>> {
      self.task.as_ref()
    }

    pub(crate) fn install(&mut self, task: Pin<Arc<T>>) {
      assert!(self.task.is_none(), "task slot already occupied");
      self.task = Some(task);
    }

    pub(crate) fn lend(&mut self) -> Option<Lease<T>> {
      let task = self.task.as_ref()?;
      if !task.lend_word().begin() {
        return None;
      }
      Some(Lease {
        task: Some(Pin::clone(task)),
      })
    }

    pub(crate) fn take(&mut self, mut lease: Lease<T>) -> Pin<Arc<T>> {
      let lent = lease.task.take();
      let task = self.task.take();
      match (task, lent) {
        (Some(task), Some(lent)) if std::ptr::addr_eq(&*task, &*lent) => task,
        _ => panic!("lease returned to another task slot"),
      }
    }

    pub(crate) fn take_idle(&mut self) -> Option<Pin<Arc<T>>> {
      if self.task.as_ref()?.lend_word().is_running() {
        return None;
      }
      self.task.take()
    }
  }

  pub(crate) struct Lease<T: ?Sized + TaskLend> {
    task: Option<Pin<Arc<T>>>,
  }

  impl<T: ?Sized + TaskLend> Lease<T> {
    pub(crate) fn task(&self) -> Pin<&T> {
      match &self.task {
        Some(task) => task.as_ref(),
        None => unreachable!("a live lease holds its task"),
      }
    }

    pub(crate) fn waker(&self) -> WakerRef<'_> {
      let task = match &self.task {
        Some(task) => Pin::clone(task),
        None => unreachable!("a live lease holds its task"),
      };
      WakerRef {
        waker: T::lend_waker(task),
        _lease: std::marker::PhantomData,
      }
    }

    pub(crate) fn finish_pending(mut self) -> bool {
      match self.task.take() {
        Some(task) => task.lend_word().finish_pending(),
        None => unreachable!("a live lease holds its task"),
      }
    }
  }

  impl<T: ?Sized + TaskLend> Drop for Lease<T> {
    fn drop(&mut self) {
      if let Some(task) = self.task.take() {
        let _ = task.lend_word().finish_pending();
      }
    }
  }

  pub(crate) struct WakerRef<'a> {
    waker: Waker,
    _lease: std::marker::PhantomData<&'a ()>,
  }

  impl std::ops::Deref for WakerRef<'_> {
    type Target = Waker;

    fn deref(&self) -> &Waker {
      &self.waker
    }
  }

  impl<H: TaskHeader, F: Send + 'static, O: Send + 'static> Wake for TaskCell<H, F, O> {
    fn wake(self: Arc<Self>) {
      self.header.wake_by_ref(&self.word);
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.header.wake_by_ref(&self.word);
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
    let expected = Task::<F>::charged_bytes(true);
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
    let task_bytes = Task::<F>::charged_bytes(true);
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
