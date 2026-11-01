//! Awaitable single-consumer task outcomes.

#[cfg(loom)]
use loom::sync::atomic::{AtomicBool, Ordering};
#[cfg(loom)]
use loom::sync::{Mutex, MutexGuard};
use std::any::Any;
use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
#[cfg(not(loom))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
#[cfg(not(loom))]
use std::sync::{Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use super::identity::TaskId;
use crate::runtime::resource_domain::{ControlCharge, DomainError};

pub(super) trait AbortAction: Send + Sync {
  fn abort(&self);
}

/// Shared completion and cancellation metadata retained by join and abort
/// handles independently of the future and scheduler task slot.
/// Spawned joins and their tasks retain this same owner, so embedding the
/// completion flag preserves its lifetime without a separate allocation.
pub(super) trait AbortMetadata: Send + Sync {
  fn abort(&self);
  fn is_finished(&self) -> bool;
  fn set_finished(&self);
}

struct FinishedFlag {
  value: AtomicBool,
  _control: ControlCharge,
}

impl FinishedFlag {
  fn new(control: ControlCharge) -> Self {
    Self {
      value: AtomicBool::new(false),
      _control: control,
    }
  }

  fn is_set(&self) -> bool {
    self.value.load(Ordering::Acquire)
  }

  fn set(&self) {
    self.value.store(true, Ordering::Release);
  }
}

struct AbortOwner<A> {
  action: A,
  finished: FinishedFlag,
  _control: ControlCharge,
}

impl<A: AbortAction> AbortMetadata for AbortOwner<A> {
  fn abort(&self) {
    self.action.abort();
  }

  fn is_finished(&self) -> bool {
    self.finished.is_set()
  }

  fn set_finished(&self) {
    self.finished.set();
  }
}

pub(super) fn abort_metadata_bytes<A>() -> usize {
  // The embedded flag retains its own declared payload charge. Include all
  // remaining bytes (including padding) in the abort owner's charge.
  std::mem::size_of::<AbortOwner<A>>() - finished_flag_bytes()
}

pub(super) fn finished_flag_bytes() -> usize {
  std::mem::size_of::<FinishedFlag>()
}

pub(super) fn new_abort_metadata<A: AbortAction + 'static>(
  action: A,
  control: ControlCharge,
  finished_control: ControlCharge,
) -> Arc<dyn AbortMetadata> {
  #[cfg(all(test, not(loom)))]
  super::allocation_tests::record();
  Arc::new(AbortOwner {
    action,
    finished: FinishedFlag::new(finished_control),
    _control: control,
  })
}

#[cfg(test)]
struct CallbackAbort {
  callback: Arc<dyn Fn() + Send + Sync>,
  completion: Arc<dyn AbortMetadata>,
}

#[cfg(test)]
impl AbortMetadata for CallbackAbort {
  fn abort(&self) {
    (self.callback)();
  }

  fn is_finished(&self) -> bool {
    self.completion.is_finished()
  }

  fn set_finished(&self) {
    self.completion.set_finished();
  }
}

#[cfg(test)]
struct NoopAbort;

#[cfg(test)]
impl AbortAction for NoopAbort {
  fn abort(&self) {}
}

/// Why an async task did not produce its output.
pub enum AsyncJoinError {
  /// The task was aborted or its scope/runtime was cancelled.
  Cancelled,
  /// Polling or cleanup panicked; the original panic payload is retained.
  Panicked(Box<dyn Any + Send + 'static>),
  /// A bounded runtime resource could not be acquired before polling.
  ResourceDomain(DomainError),
}

impl fmt::Debug for AsyncJoinError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Cancelled => f.write_str("Cancelled"),
      Self::Panicked(_) => f.write_str("Panicked(..)"),
      Self::ResourceDomain(error) => f.debug_tuple("ResourceDomain").field(error).finish(),
    }
  }
}

impl fmt::Display for AsyncJoinError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Cancelled => "async task was cancelled",
      Self::Panicked(_) => "async task panicked",
      Self::ResourceDomain(_) => "async task resource-domain admission failed",
    })
  }
}

impl std::error::Error for AsyncJoinError {}

struct PendingWakers {
  join: Option<Waker>,
  finished: Option<Waker>,
}

enum Slot<T> {
  Pending(PendingWakers),
  Staged {
    outcome: Result<T, AsyncJoinError>,
    wakers: Option<PendingWakers>,
  },
  Ready(Option<Result<T, AsyncJoinError>>),
  Taken,
}

pub(super) struct JoinState<T> {
  slot: Mutex<Slot<T>>,
  // Output-independent metadata also works for non-Send local outputs.
  finished: Option<Arc<dyn AbortMetadata>>,
  completed: AtomicBool,
  id: TaskId,
  _control: ControlCharge,
}

impl<T> JoinState<T> {
  pub(super) fn with_id(
    id: TaskId,
    control: ControlCharge,
    finished: Arc<dyn AbortMetadata>,
  ) -> Arc<Self> {
    #[cfg(all(test, not(loom)))]
    super::allocation_tests::record();
    Arc::new(Self::embedded(id, control, Some(finished)))
  }

  pub(super) fn embedded(
    id: TaskId,
    control: ControlCharge,
    finished: Option<Arc<dyn AbortMetadata>>,
  ) -> Self {
    Self {
      slot: Mutex::new(Slot::Pending(PendingWakers {
        join: None,
        finished: None,
      })),
      finished,
      completed: AtomicBool::new(false),
      id,
      _control: control,
    }
  }

  #[cfg(test)]
  pub(super) fn new() -> Arc<Self> {
    // Synthetic jobs used by internal state-machine tests are not spawned
    // tasks and never escape those tests.
    Self::with_id(
      TaskId::test_sentinel(),
      ControlCharge::unbounded(std::mem::size_of::<Self>()),
      new_abort_metadata(
        NoopAbort,
        ControlCharge::unbounded(abort_metadata_bytes::<NoopAbort>()),
        ControlCharge::unbounded(finished_flag_bytes()),
      ),
    )
  }

  pub(super) fn id(&self) -> TaskId {
    self.id
  }

  pub(super) fn is_finished(&self) -> bool {
    self.finished.as_ref().map_or_else(
      || self.completed.load(Ordering::Acquire),
      |metadata| metadata.is_finished(),
    )
  }

  pub(super) fn set_finished(&self) {
    if let Some(metadata) = &self.finished {
      metadata.set_finished();
    } else {
      self.completed.store(true, Ordering::Release);
    }
  }

  fn lock(&self) -> MutexGuard<'_, Slot<T>> {
    self.slot.lock().unwrap_or_else(PoisonError::into_inner)
  }

  /// Stores the driver's outcome without making it visible to observers.
  /// A detached join leaves producer-side cleanup to the publishing worker.
  pub(super) fn stage(&self, outcome: Result<T, AsyncJoinError>) {
    let old = {
      let mut slot = self.lock();
      let (wakers, old) = match std::mem::replace(&mut *slot, Slot::Taken) {
        Slot::Pending(wakers) => (Some(wakers), None),
        Slot::Staged { outcome, wakers } => (wakers, Some(outcome)),
        Slot::Taken => (None, None),
        Slot::Ready(_) => unreachable!("cannot stage after publication"),
      };
      *slot = Slot::Staged { outcome, wakers };
      old
    };
    drop_contained(old);
  }

  pub(super) fn has_staged(&self) -> bool {
    matches!(*self.lock(), Slot::Staged { .. })
  }

  pub(super) fn take_staged(&self) -> Option<Result<T, AsyncJoinError>> {
    let mut slot = self.lock();
    match std::mem::replace(&mut *slot, Slot::Taken) {
      Slot::Staged { outcome, wakers } => {
        *slot = wakers.map_or(Slot::Taken, Slot::Pending);
        Some(outcome)
      }
      other => {
        *slot = other;
        None
      }
    }
  }

  /// Publishes once. Returns an unobserved output for destruction by the
  /// worker after the join-state lock has been released.
  pub(super) fn publish(
    &self,
    result: Result<T, AsyncJoinError>,
  ) -> Option<Result<T, AsyncJoinError>> {
    let mut slot = self.lock();
    match std::mem::replace(&mut *slot, Slot::Taken) {
      Slot::Pending(wakers) => {
        *slot = Slot::Ready(Some(result));
        self.set_finished();
        drop(slot);
        if let Some(waker) = wakers.finished
          && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
        {
          drop_contained(payload);
        }
        if let Some(waker) = wakers.join
          && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
        {
          drop_contained(payload);
        }
        None
      }
      staged @ Slot::Staged { .. } => {
        *slot = staged;
        drop(slot);
        Some(result)
      }
      Slot::Ready(ready) => {
        *slot = Slot::Ready(ready);
        drop(slot);
        Some(result)
      }
      Slot::Taken => {
        *slot = Slot::Taken;
        self.set_finished();
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

enum JobState<T> {
  Separate(Arc<JoinState<T>>),
  Merged(Arc<super::task::Task<T>>),
}

impl<T> std::ops::Deref for JobState<T> {
  type Target = JoinState<T>;

  fn deref(&self) -> &Self::Target {
    match self {
      Self::Separate(state) => state,
      Self::Merged(task) => &task.join,
    }
  }
}

/// The awaitable result of a submitted future. Dropping it detaches the
/// task; call [`AsyncJob::abort`] to request cancellation.
pub struct AsyncJob<T> {
  state: JobState<T>,
  abort: Arc<dyn AbortMetadata>,
  finished: bool,
}

impl<T> AsyncJob<T> {
  pub(super) fn new_with_metadata(state: Arc<JoinState<T>>, abort: Arc<dyn AbortMetadata>) -> Self {
    Self {
      state: JobState::Separate(state),
      abort,
      finished: false,
    }
  }

  pub(super) fn merged(state: Arc<super::task::Task<T>>, abort: Arc<dyn AbortMetadata>) -> Self {
    Self {
      state: JobState::Merged(state),
      abort,
      finished: false,
    }
  }

  #[cfg(test)]
  pub(super) fn new(state: Arc<JoinState<T>>, abort: Arc<dyn Fn() + Send + Sync>) -> Self {
    let metadata = Arc::new(CallbackAbort {
      callback: abort,
      completion: Arc::clone(state.finished.as_ref().unwrap()),
    });
    Self::new_with_metadata(state, metadata)
  }

  /// Requests cancellation. A running future is cancelled after its
  /// current poll returns; it is never preempted.
  pub fn abort(&self) {
    self.abort.abort();
  }

  /// The process-wide identity assigned when this task was admitted.
  #[must_use]
  pub fn id(&self) -> TaskId {
    self.state.id
  }

  /// Returns a clonable cancellation handle independent of the output type.
  /// Native task handles retain the shared bookkeeping allocation and its
  /// Control charge. Completion drops the future; consuming or dropping the
  /// join releases its result even if an abort handle remains alive.
  #[must_use]
  pub fn abort_handle(&self) -> AbortHandle {
    AbortHandle {
      abort: Arc::clone(&self.abort),
      id: self.state.id,
    }
  }

  /// Whether the terminal join outcome has been published after task cleanup.
  #[must_use]
  pub fn is_finished(&self) -> bool {
    self.state.is_finished()
  }

  /// Polls for terminal completion without taking the task's result.
  ///
  /// This is intended for completion-order collections that need a separate
  /// notification before they consume this join handle.
  pub fn poll_finished(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
    let this = self.get_mut();
    if this.state.is_finished() {
      return Poll::Ready(());
    }

    let replacement = cx.waker().clone();
    let old = {
      let mut slot = this.state.lock();
      let (Slot::Pending(wakers)
      | Slot::Staged {
        wakers: Some(wakers),
        ..
      }) = &mut *slot
      else {
        drop(slot);
        drop(replacement);
        return Poll::Ready(());
      };
      if this.state.is_finished() {
        drop(slot);
        drop(replacement);
        return Poll::Ready(());
      }
      wakers.finished.replace(replacement)
    };
    drop(old);
    Poll::Pending
  }

  /// Takes an outcome already announced by `poll_finished`, without cloning a
  /// caller waker while consuming a completion notification.
  pub(super) fn take_finished(&mut self) -> Option<Result<T, AsyncJoinError>> {
    if !self.state.is_finished() {
      return None;
    }
    let outcome = {
      let mut slot = self.state.lock();
      match std::mem::replace(&mut *slot, Slot::Taken) {
        Slot::Ready(outcome) => outcome.unwrap_or(Err(AsyncJoinError::Cancelled)),
        Slot::Taken => Err(AsyncJoinError::Cancelled),
        pending @ (Slot::Pending(_) | Slot::Staged { .. }) => {
          *slot = pending;
          return None;
        }
      }
    };
    self.finished = true;
    Some(outcome)
  }
}

/// A clonable, thread-safe cancellation handle, including for local tasks
/// whose outputs are not `Send`. Dropping it neither cancels nor detaches work.
#[derive(Clone)]
pub struct AbortHandle {
  abort: Arc<dyn AbortMetadata>,
  id: TaskId,
}

impl AbortHandle {
  /// Requests cleanup after any current poll returns. This does not wait for
  /// cleanup and cannot preempt a running poll.
  pub fn abort(&self) {
    self.abort.abort();
  }

  /// The process-wide identity of the task this handle can abort.
  #[must_use]
  pub const fn id(&self) -> TaskId {
    self.id
  }

  /// Whether the terminal join outcome has been published. Detaching the join
  /// alone does not make this true; actual task completion still must occur.
  #[must_use]
  pub fn is_finished(&self) -> bool {
    self.abort.is_finished()
  }
}

impl fmt::Debug for AbortHandle {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AbortHandle")
      .field("id", &self.id)
      .field("finished", &self.is_finished())
      .finish_non_exhaustive()
  }
}

impl<T> Future for AsyncJob<T> {
  type Output = Result<T, AsyncJoinError>;

  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::poll_cooperative(cx, |cx| {
      // Gate before custom waker code and before reading or consuming the
      // task's terminal slot.
      let replacement = cx.waker().clone();
      let mut slot = self.state.lock();
      match &mut *slot {
        Slot::Pending(wakers)
        | Slot::Staged {
          wakers: Some(wakers),
          ..
        } => {
          let old = wakers.join.replace(replacement);
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
        Slot::Taken | Slot::Staged { wakers: None, .. } => {
          drop(slot);
          self.finished = true;
          Poll::Ready(Err(AsyncJoinError::Cancelled))
        }
      }
    })
  }
}

impl<T> Drop for AsyncJob<T> {
  fn drop(&mut self) {
    if !self.finished {
      let outcome = {
        let mut slot = self.state.lock();
        match std::mem::replace(&mut *slot, Slot::Taken) {
          Slot::Staged { outcome, wakers } => {
            *slot = Slot::Staged {
              outcome,
              wakers: None,
            };
            wakers.map(Slot::Pending)
          }
          other => Some(other),
        }
      };
      // Results and wakers may run user code from Drop; do so without the
      // join mutex held.
      drop(outcome);
    }
  }
}

impl<T> fmt::Debug for AsyncJob<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AsyncJob")
      .field("id", &self.id())
      .finish_non_exhaustive()
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::{AbortHandle, AsyncJob, JoinState};
  use crate::runtime::resource_domain::{
    ControlCharge, DomainResource, DomainResources, ResourceDomain,
  };
  use std::future::Future;
  use std::pin::Pin;
  use std::rc::Rc;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

  #[test]
  fn finished_observer_does_not_consume_outcome_and_both_observers_are_woken() {
    let state = JoinState::<usize>::new();
    let mut job = AsyncJob::new(Arc::clone(&state), Arc::new(|| {}));
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountWake(Arc::clone(&wakes))));
    let mut context = Context::from_waker(&waker);

    assert!(Pin::new(&mut job).poll_finished(&mut context).is_pending());
    assert!(Pin::new(&mut job).poll(&mut context).is_pending());
    assert!(state.publish(Ok(17)).is_none());
    assert_eq!(wakes.load(Ordering::SeqCst), 2);
    assert!(Pin::new(&mut job).poll_finished(&mut context).is_ready());
    assert!(matches!(
      Pin::new(&mut job).poll(&mut context),
      Poll::Ready(Ok(17))
    ));
  }

  struct CountWake(Arc<AtomicUsize>);

  impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  struct TestAbort;

  impl super::AbortAction for TestAbort {
    fn abort(&self) {}
  }

  #[test]
  fn final_abort_handle_retains_exact_finished_flag_control_owner() {
    let ceiling = DomainResources::ZERO
      .with(DomainResource::Tasks, 2)
      .with(DomainResource::Control, 16 * 1024);
    let domain = ResourceDomain::new(ceiling, 1)
      .unwrap_or_else(|error| panic!("domain construction failed: {error}"));
    let tenant = domain
      .tenant(ceiling)
      .unwrap_or_else(|error| panic!("tenant construction failed: {error}"));
    let base_global = domain.snapshot().used.get(DomainResource::Control);
    let base_tenant = tenant.snapshot().unwrap().used.get(DomainResource::Control);
    let join_bytes = std::mem::size_of::<JoinState<usize>>();
    let finished_bytes = super::finished_flag_bytes();
    let abort_bytes = super::abort_metadata_bytes::<TestAbort>();
    assert_eq!(
      abort_bytes + finished_bytes,
      std::mem::size_of::<super::AbortOwner<TestAbort>>()
    );
    let metadata = super::new_abort_metadata(
      TestAbort,
      ControlCharge::try_new(Some(&tenant), abort_bytes).unwrap(),
      ControlCharge::try_new(Some(&tenant), finished_bytes).unwrap(),
    );
    let join = JoinState::with_id(
      super::TaskId::test_sentinel(),
      ControlCharge::try_new(Some(&tenant), join_bytes).unwrap(),
      Arc::clone(&metadata),
    );
    let job = AsyncJob::new_with_metadata(Arc::clone(&join), metadata);
    let abort = job.abort_handle();
    assert!(join.publish(Ok(17)).is_none());
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      base_global + join_bytes + finished_bytes + abort_bytes
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      base_tenant + join_bytes + finished_bytes + abort_bytes
    );

    drop(job);
    drop(join);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      base_global + finished_bytes + abort_bytes
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      base_tenant + finished_bytes + abort_bytes
    );
    assert!(abort.is_finished());
    drop(abort);
    assert_eq!(
      domain.snapshot().used.get(DomainResource::Control),
      base_global
    );
    assert_eq!(
      tenant.snapshot().unwrap().used.get(DomainResource::Control),
      base_tenant
    );
  }

  #[test]
  fn retained_abort_metadata_does_not_retain_join_or_output() {
    struct Output(Arc<AtomicUsize>);

    impl Drop for Output {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let metadata = super::new_abort_metadata(
      TestAbort,
      ControlCharge::unbounded(super::abort_metadata_bytes::<TestAbort>()),
      ControlCharge::unbounded(super::finished_flag_bytes()),
    );
    let weak_metadata = Arc::downgrade(&metadata);
    let state = JoinState::with_id(
      super::TaskId::test_sentinel(),
      ControlCharge::unbounded(std::mem::size_of::<JoinState<Output>>()),
      Arc::clone(&metadata),
    );
    let weak_state = Arc::downgrade(&state);
    let mut job = AsyncJob::new_with_metadata(Arc::clone(&state), metadata);
    let abort = job.abort_handle();
    assert!(state.publish(Ok(Output(Arc::clone(&drops)))).is_none());
    drop(state);
    // Consuming the result while retaining the job must release the output.
    let output = job.take_finished().unwrap().unwrap();
    drop(output);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    drop(job);
    assert!(weak_state.upgrade().is_none());
    assert!(weak_metadata.upgrade().is_some());
    assert!(abort.is_finished());
    drop(abort);
    assert!(weak_metadata.upgrade().is_none());

    // An unconsumed result is destroyed by detaching, even with an abort
    // handle alive. Detached publication still returns output to the worker.
    for publish_first in [true, false] {
      let state = JoinState::new();
      let job = AsyncJob::new(Arc::clone(&state), Arc::new(|| {}));
      let abort = job.abort_handle();
      if publish_first {
        assert!(state.publish(Ok(Output(Arc::clone(&drops)))).is_none());
      }
      drop(job);
      if !publish_first {
        let staged = state.publish(Ok(Output(Arc::clone(&drops))));
        assert!(staged.is_some());
        drop(staged);
      }
      drop(state);
      assert!(abort.is_finished());
    }
    assert_eq!(drops.load(Ordering::SeqCst), 3);
  }

  #[test]
  fn detaching_drops_join_and_finished_wakers_after_releasing_state_lock() {
    struct LockProbe {
      state: std::sync::Weak<JoinState<usize>>,
      unlocked_on_drop: Arc<AtomicBool>,
      wakes: Arc<AtomicUsize>,
    }

    impl Wake for LockProbe {
      fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
      }
    }

    impl Drop for LockProbe {
      fn drop(&mut self) {
        let unlocked = self
          .state
          .upgrade()
          .is_some_and(|state| state.slot.try_lock().is_ok());
        self.unlocked_on_drop.store(unlocked, Ordering::SeqCst);
      }
    }

    let state = JoinState::<usize>::new();
    let mut job = AsyncJob::new(Arc::clone(&state), Arc::new(|| {}));
    let unlocked_on_drop = Arc::new(AtomicBool::new(false));
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(LockProbe {
      state: Arc::downgrade(&state),
      unlocked_on_drop: Arc::clone(&unlocked_on_drop),
      wakes,
    }));
    let mut context = Context::from_waker(&waker);
    assert!(Pin::new(&mut job).poll_finished(&mut context).is_pending());
    assert!(Pin::new(&mut job).poll(&mut context).is_pending());
    drop(waker);
    drop(job);
    assert!(unlocked_on_drop.load(Ordering::SeqCst));
  }
}

#[cfg(all(test, loom))]
mod model {
  // This models JoinState's observer registration/publication lock and flag.
  // It does not model scheduler cleanup, executor ordering, or user waker code.
  use super::{AsyncJob, JoinState};
  use loom::sync::Arc;
  use loom::sync::atomic::{AtomicBool, Ordering};
  use loom::thread;
  use std::pin::Pin;
  use std::sync::Arc as StdArc;
  use std::task::{Context, Wake, Waker};

  struct WakeFlag(Arc<AtomicBool>);

  impl Wake for WakeFlag {
    fn wake(self: StdArc<Self>) {
      self.0.store(true, Ordering::Release);
    }
  }

  #[test]
  fn staging_and_publication_racing_detach_drop_output_once() {
    loom::model(|| {
      struct Output(Arc<loom::sync::atomic::AtomicUsize>);
      impl Drop for Output {
        fn drop(&mut self) {
          self.0.fetch_add(1, Ordering::SeqCst);
        }
      }
      let drops = Arc::new(loom::sync::atomic::AtomicUsize::new(0));
      let state = JoinState::new();
      let job = AsyncJob::new(StdArc::clone(&state), StdArc::new(|| {}));
      let output = Output(Arc::clone(&drops));
      let producer = thread::spawn(move || {
        state.stage(Ok(output));
        assert!(state.has_staged());
        assert!(!state.is_finished());
        let outcome = state.take_staged().unwrap();
        drop(state.publish(outcome));
        assert!(state.is_finished());
      });
      let consumer = thread::spawn(move || drop(job));
      producer.join().unwrap();
      consumer.join().unwrap();
      assert_eq!(drops.load(Ordering::SeqCst), 1);
    });
  }

  #[test]
  fn publication_racing_finished_observer_registration_is_not_lost() {
    loom::model(|| {
      let state = JoinState::<usize>::new();
      let job = AsyncJob::new(StdArc::clone(&state), StdArc::new(|| {}));
      let observed_wake = Arc::new(AtomicBool::new(false));
      let published = Arc::new(AtomicBool::new(false));

      let observer_wake = Arc::clone(&observed_wake);
      let observer_published = Arc::clone(&published);
      let observer = thread::spawn(move || {
        let mut job = job;
        let waker = Waker::from(StdArc::new(WakeFlag(observer_wake.clone())));
        let mut context = Context::from_waker(&waker);
        let ready = Pin::new(&mut job).poll_finished(&mut context).is_ready();
        while !observer_published.load(Ordering::Acquire) {
          thread::yield_now();
        }
        ready
      });

      let publisher_published = Arc::clone(&published);
      let publisher = thread::spawn(move || {
        assert!(state.publish(Ok(1)).is_none());
        publisher_published.store(true, Ordering::Release);
      });

      let ready = observer.join().unwrap();
      publisher.join().unwrap();
      assert!(ready || observed_wake.load(Ordering::Acquire));
    });
  }
}
