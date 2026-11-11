//! Task-local values installed while a scoped future is polled or cleaned up.
//!
//! Unlike thread-local values, a scoped value is removed before its future
//! returns `Pending` or `Ready`. The future owns the value between polls, so a
//! `Send` future can move between threads without leaving task state behind on
//! the previous thread.
//!
//! This utility allocates ordinary runtime metadata: each future scope
//! allocates a box for its inner future, and each async poll, pending cleanup,
//! or `sync_scope` call creates one temporary `Rc` allocation. The per-thread
//! map grows as keys are first used. These allocations are not managed-storage
//! charges.
//!
//! ```
//! use allocatbelt::runtime::task_local::TaskLocalKey;
//! use std::future;
//!
//! static REQUEST_ID: TaskLocalKey<u64> = TaskLocalKey::new();
//!
//! # fn main() {
//! let scoped = REQUEST_ID.scope(42, future::ready(()));
//! # drop(scoped);
//! # }
//! ```
//!
//! A scoped future is `Send` when both its value and inner future are `Send`.
//! Local values and futures can remain `!Send`:
//!
//! ```compile_fail
//! use allocatbelt::runtime::task_local::TaskLocalKey;
//! use std::future;
//! use std::rc::Rc;
//!
//! static LOCAL: TaskLocalKey<Rc<()>> = TaskLocalKey::new();
//! fn require_send<T: Send>(_: T) {}
//! require_send(LOCAL.scope(Rc::new(()), future::ready(())));
//! ```
//!
//! ```compile_fail
//! use allocatbelt::runtime::task_local::TaskLocalKey;
//! use std::rc::Rc;
//!
//! static LOCAL: TaskLocalKey<()> = TaskLocalKey::new();
//! fn require_send<T: Send>(_: T) {}
//! let local = Rc::new(());
//! require_send(LOCAL.scope((), async move { drop(local) }));
//! ```

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

static NEXT_KEY_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
  // Entries are transient: ScopeFuture restores the prior value before its
  // poll returns. Rc lets `try_with` release this RefCell borrow before calling
  // user code, including code that reenters this module.
  static VALUES: RefCell<HashMap<u64, Rc<dyn Any>>> = RefCell::new(HashMap::new());
}

/// A key for synchronously accessing a value installed by [`TaskLocalKey::scope`].
///
/// Construct keys in static storage with the `const` constructor. IDs are
/// assigned lazily and globally; exhausting the ID space panics rather than
/// reusing an ID and aliasing another key.
pub struct TaskLocalKey<T: 'static> {
  id: AtomicU64,
  value_type: PhantomData<fn() -> T>,
}

impl<T: 'static> TaskLocalKey<T> {
  /// Creates a task-local key suitable for a `static` declaration.
  pub const fn new() -> Self {
    Self {
      id: AtomicU64::new(0),
      value_type: PhantomData,
    }
  }

  /// Calls `f` with the value currently installed for this key.
  ///
  /// The TLS borrow is released before `f` runs. The shared reference remains
  /// valid if `f` reenters this key or installs a nested scope.
  ///
  /// # Panics
  ///
  /// Panics when this key has no value installed on the current thread.
  pub fn with<R>(&self, f: impl FnOnce(&T) -> R) -> R {
    match self.try_with(f) {
      Some(result) => result,
      None => panic!("task-local value is not currently scoped"),
    }
  }

  /// Calls `f` with the current value, or returns `None` when it is not scoped.
  ///
  /// The TLS borrow is released before `f` runs. This permits nested scopes
  /// and calls to other task-local keys from inside the closure.
  pub fn try_with<R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
    let id = self.key_id();
    let value = VALUES
      .try_with(|values| values.borrow().get(&id).cloned())
      .ok()??;
    let value = match Rc::downcast::<T>(value) {
      Ok(value) => value,
      Err(_) => unreachable!("task-local key ID was reused for a different type"),
    };
    Some(f(&value))
  }

  /// Installs `value` while `f` runs, then restores any enclosing scope.
  ///
  /// The TLS borrow is released before `f` runs, so the closure can access
  /// this key again or install nested scopes. The scoped value is dropped only
  /// after the prior context is restored, including when `f` panics. If
  /// thread-local storage has already been destroyed, this method panics
  /// without running `f`; [`TaskLocalKey::try_with`] returns `None` there.
  pub fn sync_scope<R>(&self, value: T, f: impl FnOnce() -> R) -> R {
    let id = self.key_id();
    if VALUES.try_with(|_| ()).is_err() {
      panic!("task-local storage is unavailable on this thread");
    }
    let previous = push_value(id, Rc::new(value));
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    let value = restore_value(id, previous);
    let value = match Rc::downcast::<T>(value) {
      Ok(value) => value,
      Err(_) => unreachable!("task-local key ID was reused for a different type"),
    };
    let value = match Rc::try_unwrap(value) {
      Ok(value) => value,
      Err(_) => unreachable!("task-local value has an unexpected shared owner"),
    };
    let value_panic = panic::catch_unwind(AssertUnwindSafe(|| drop(value))).err();
    match result {
      Ok(result) => {
        resume_drop_panics(None, value_panic);
        result
      }
      Err(payload) => {
        resume_drop_panics(Some(payload), value_panic);
        unreachable!("resuming a panic should not return")
      }
    }
  }

  /// Installs `value` while `future` is polled and while its inner future is
  /// dropped.
  ///
  /// Each poll restores the prior value, even if polling panics. Dropping the
  /// returned future while it is pending drops the inner future while this
  /// value is installed, then restores any enclosing scope before dropping
  /// `value`. The inner future is pinned in its own box; the outer scope
  /// future remains movable and does not pin `T`. If thread-local storage has
  /// already been destroyed, cleanup drops the inner future without installing
  /// a value, and [`TaskLocalKey::try_with`] returns `None`.
  pub fn scope<F>(&self, value: T, future: F) -> ScopeFuture<'_, T, F>
  where
    F: Future,
  {
    ScopeFuture {
      key: self,
      value: Some(value),
      future: Some(Box::pin(future)),
      complete: false,
    }
  }

  fn key_id(&self) -> u64 {
    let current = self.id.load(Ordering::Acquire);
    if current != 0 {
      return current;
    }

    let candidate =
      match NEXT_KEY_ID.try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1)) {
        Ok(id) => id,
        Err(_) => panic!("task-local key ID space exhausted"),
      };
    match self
      .id
      .compare_exchange(0, candidate, Ordering::AcqRel, Ordering::Acquire)
    {
      Ok(_) => candidate,
      Err(existing) => existing,
    }
  }
}

impl<T: 'static> Default for TaskLocalKey<T> {
  fn default() -> Self {
    Self::new()
  }
}

/// A future that installs a task-local value for one inner-future poll.
pub struct ScopeFuture<'key, T: 'static, F: Future> {
  key: &'key TaskLocalKey<T>,
  value: Option<T>,
  future: Option<Pin<Box<F>>>,
  complete: bool,
}

// Moving this wrapper never moves the pinned `F`: it moves only its `Pin<Box<F>>`
// pointer. Neither `T` nor any other field is pinned by this type.
impl<T: 'static, F: Future> Unpin for ScopeFuture<'_, T, F> {}

impl<T: 'static, F: Future> Future for ScopeFuture<'_, T, F> {
  type Output = F::Output;

  fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    assert!(
      !this.complete,
      "task-local scope future polled after completion"
    );
    let id = this.key.key_id();
    let value = match this.value.take() {
      Some(value) => value,
      None => panic!("task-local scope future has no value between polls"),
    };
    let previous = push_value(id, Rc::new(value));

    // Catch unwind only long enough to pop the value and restore it into this
    // future. The original panic resumes after the prior task context is back.
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
      let result = match this.future.as_mut() {
        Some(future) => future.as_mut().poll(context),
        None => panic!("task-local scope future polled after completion"),
      };
      if result.is_ready() {
        drop(this.future.take());
      }
      result
    }));
    let value = restore_value(id, previous);
    let value = match Rc::downcast::<T>(value) {
      Ok(value) => value,
      Err(_) => unreachable!("task-local key ID was reused for a different type"),
    };
    let value = match Rc::try_unwrap(value) {
      Ok(value) => value,
      Err(_) => unreachable!("task-local value has an unexpected shared owner"),
    };
    this.value = Some(value);

    match result {
      Ok(Poll::Pending) => Poll::Pending,
      Ok(Poll::Ready(output)) => {
        this.complete = true;
        Poll::Ready(output)
      }
      Err(payload) => panic::resume_unwind(payload),
    }
  }
}

impl<T: 'static, F: Future> Drop for ScopeFuture<'_, T, F> {
  fn drop(&mut self) {
    let future = match self.future.take() {
      Some(future) => future,
      None => return,
    };

    // During TLS teardown, match the ordinary field-drop fallback: destroy
    // the inner future without installing a context, then destroy the value.
    if VALUES.try_with(|_| ()).is_err() {
      let future_panic = panic::catch_unwind(AssertUnwindSafe(|| drop(future))).err();
      let value_panic = self
        .value
        .take()
        .and_then(|value| panic::catch_unwind(AssertUnwindSafe(|| drop(value))).err());
      resume_drop_panics(future_panic, value_panic);
      return;
    }

    let value = match self.value.take() {
      Some(value) => value,
      None => {
        let future_panic = panic::catch_unwind(AssertUnwindSafe(|| drop(future))).err();
        resume_drop_panics(future_panic, None);
        return;
      }
    };
    let id = self.key.key_id();
    let previous = push_value(id, Rc::new(value));
    let future_panic = panic::catch_unwind(AssertUnwindSafe(|| drop(future))).err();

    // Restore the previous task context before destroying T. Its destructor
    // may reenter task-local access and must observe the enclosing value.
    let value = restore_value(id, previous);
    let value = match Rc::downcast::<T>(value) {
      Ok(value) => value,
      Err(_) => unreachable!("task-local key ID was reused for a different type"),
    };
    let value = match Rc::try_unwrap(value) {
      Ok(value) => value,
      Err(_) => unreachable!("task-local value has an unexpected shared owner"),
    };
    let value_panic = panic::catch_unwind(AssertUnwindSafe(|| drop(value))).err();
    resume_drop_panics(future_panic, value_panic);
  }
}

fn resume_drop_panics(
  first: Option<Box<dyn Any + Send + 'static>>,
  second: Option<Box<dyn Any + Send + 'static>>,
) {
  match (first, second) {
    (Some(first), Some(second)) => {
      if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(second))) {
        std::mem::forget(payload);
      }
      panic::resume_unwind(first);
    }
    (Some(payload), None) | (None, Some(payload)) => panic::resume_unwind(payload),
    (None, None) => {}
  }
}

fn push_value(id: u64, value: Rc<dyn Any>) -> Option<Rc<dyn Any>> {
  VALUES.with(|values| values.borrow_mut().insert(id, value))
}

fn restore_value(id: u64, previous: Option<Rc<dyn Any>>) -> Rc<dyn Any> {
  let value = VALUES.with(|values| {
    let mut values = values.borrow_mut();
    match previous {
      Some(previous) => values.insert(id, previous),
      None => values.remove(&id),
    }
  });
  match value {
    Some(value) => value,
    None => panic!("task-local scope value is missing during restoration"),
  }
}

#[cfg(test)]
mod tests {
  use super::{ScopeFuture, TaskLocalKey};
  use std::future::{self, Future};
  use std::pin::Pin;
  use std::rc::Rc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::{Context, Poll, Waker};

  static VALUE: TaskLocalKey<usize> = TaskLocalKey::new();
  static OTHER: TaskLocalKey<usize> = TaskLocalKey::new();
  static DROP_VALUE: TaskLocalKey<ReentrantDrop> = TaskLocalKey::new();
  static CANCEL_VALUE: TaskLocalKey<DropCheck> = TaskLocalKey::new();
  static PINNED_VALUE: TaskLocalKey<NotUnpin> = TaskLocalKey::new();
  static THREAD_VALUE: TaskLocalKey<DropThread> = TaskLocalKey::new();
  static DROP_ORDER_KEY: TaskLocalKey<DropOrder> = TaskLocalKey::new();
  static TEARDOWN_KEY: TaskLocalKey<TeardownValue> = TaskLocalKey::new();
  static SYNC_TEARDOWN_KEY: TaskLocalKey<SyncTeardownValue> = TaskLocalKey::new();
  static DROPS: AtomicUsize = AtomicUsize::new(0);
  static TEARDOWN_FUTURE_DROPS: AtomicUsize = AtomicUsize::new(0);
  static TEARDOWN_VALUE_DROPS: AtomicUsize = AtomicUsize::new(0);
  static SYNC_TEARDOWN_RAN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
  static SYNC_TEARDOWN_VALUE_DROPS: AtomicUsize = AtomicUsize::new(0);

  thread_local! {
    static RETAINED_SCOPE: std::cell::RefCell<
      Option<ScopeFuture<'static, TeardownValue, TeardownFuture>>
    > = const { std::cell::RefCell::new(None) };
    static RETAINED_SYNC: SyncTeardownGuard = const { SyncTeardownGuard };
  }

  struct ReentrantDrop;

  impl Drop for ReentrantDrop {
    fn drop(&mut self) {
      assert_eq!(VALUE.try_with(|value| *value), Some(61));
      assert_eq!(DROP_VALUE.try_with(|_| ()), None);
      DROPS.fetch_add(1, Ordering::Relaxed);
    }
  }

  struct DropCheck;

  impl Drop for DropCheck {
    fn drop(&mut self) {
      assert_eq!(CANCEL_VALUE.try_with(|_| ()), None);
      assert_eq!(OTHER.try_with(|value| *value), None);
    }
  }

  struct NotUnpin(std::marker::PhantomPinned);

  struct DropThread(std::sync::mpsc::Sender<std::thread::ThreadId>);

  impl Drop for DropThread {
    fn drop(&mut self) {
      assert_eq!(THREAD_VALUE.try_with(|_| ()), None);
      let _ = self.0.send(std::thread::current().id());
    }
  }

  struct DropOrder(usize);

  impl Drop for DropOrder {
    fn drop(&mut self) {
      if self.0 == 2 {
        assert_eq!(DROP_ORDER_KEY.try_with(|outer| outer.0), Some(1));
      }
    }
  }

  struct TeardownValue;

  impl Drop for TeardownValue {
    fn drop(&mut self) {
      assert_eq!(TEARDOWN_KEY.try_with(|_| ()), None);
      TEARDOWN_VALUE_DROPS.fetch_add(1, Ordering::Relaxed);
    }
  }

  struct TeardownFuture;

  impl Future for TeardownFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
      assert!(TEARDOWN_KEY.try_with(|_| ()).is_some());
      Poll::Pending
    }
  }

  impl Drop for TeardownFuture {
    fn drop(&mut self) {
      assert_eq!(TEARDOWN_KEY.try_with(|_| ()), None);
      TEARDOWN_FUTURE_DROPS.fetch_add(1, Ordering::Relaxed);
    }
  }

  struct SyncTeardownValue;

  impl Drop for SyncTeardownValue {
    fn drop(&mut self) {
      assert_eq!(SYNC_TEARDOWN_KEY.try_with(|_| ()), None);
      SYNC_TEARDOWN_VALUE_DROPS.fetch_add(1, Ordering::Relaxed);
    }
  }

  struct SyncTeardownGuard;

  impl Drop for SyncTeardownGuard {
    fn drop(&mut self) {
      assert_eq!(SYNC_TEARDOWN_KEY.try_with(|_| ()), None);
      let closure_ran = &SYNC_TEARDOWN_RAN;
      let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        SYNC_TEARDOWN_KEY.sync_scope(SyncTeardownValue, || {
          closure_ran.store(true, Ordering::Relaxed);
        });
      }));
      assert!(result.is_err());
      assert!(!SYNC_TEARDOWN_RAN.load(Ordering::Relaxed));
    }
  }

  fn poll<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    let mut context = Context::from_waker(Waker::noop());
    Pin::new(future).poll(&mut context)
  }

  struct PendingOnce(bool);

  impl Future for PendingOnce {
    type Output = usize;

    fn poll(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
      assert_eq!(VALUE.try_with(|value| *value), Some(23));
      if self.0 {
        Poll::Ready(23)
      } else {
        self.0 = true;
        Poll::Pending
      }
    }
  }

  #[test]
  fn value_is_visible_only_during_each_poll() {
    let mut scoped = VALUE.scope(23, PendingOnce(false));
    assert_eq!(VALUE.try_with(|value| *value), None);
    assert!(poll(&mut scoped).is_pending());
    assert_eq!(VALUE.try_with(|value| *value), None);
    assert_eq!(poll(&mut scoped), Poll::Ready(23));
    assert_eq!(VALUE.try_with(|value| *value), None);
  }

  #[test]
  fn keys_are_independent_and_same_key_scopes_nest() {
    struct CheckNested<'a> {
      inner: Option<ScopeFuture<'a, usize, future::Ready<()>>>,
    }

    impl Future for CheckNested<'_> {
      type Output = (usize, usize);

      fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        assert_eq!(VALUE.with(|value| *value), 10);
        assert_eq!(OTHER.with(|value| *value), 20);
        if let Some(mut inner) = self.inner.take() {
          assert_eq!(Pin::new(&mut inner).poll(context), Poll::Ready(()));
          drop(inner);
        }
        assert_eq!(VALUE.with(|value| *value), 10);
        assert_eq!(OTHER.try_with(|value| *value), Some(20));
        Poll::Ready((10, 20))
      }
    }

    let inner = VALUE.scope(11, future::ready(()));
    let check = CheckNested { inner: Some(inner) };
    let mut scoped = VALUE.scope(10, OTHER.scope(20, check));
    assert_eq!(poll(&mut scoped), Poll::Ready((10, 20)));
    assert_eq!(VALUE.try_with(|value| *value), None);
    assert_eq!(OTHER.try_with(|value| *value), None);
  }

  #[test]
  fn closure_can_reenter_the_same_key_without_a_tls_borrow() {
    struct Reenter;

    impl Future for Reenter {
      type Output = usize;

      fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let result = VALUE.with(|outer_value| {
          assert_eq!(*outer_value, 31);
          let mut inner = VALUE.scope(32, future::ready(()));
          assert_eq!(Pin::new(&mut inner).poll(context), Poll::Ready(()));
          *outer_value
        });
        Poll::Ready(result)
      }
    }

    let mut outer = VALUE.scope(31, Reenter);
    assert_eq!(poll(&mut outer), Poll::Ready(31));
    assert_eq!(VALUE.try_with(|value| *value), None);
  }

  #[test]
  fn sync_scope_nests_and_drops_inner_value_after_restoring_outer() {
    DROP_ORDER_KEY.sync_scope(DropOrder(1), || {
      assert_eq!(DROP_ORDER_KEY.with(|value| value.0), 1);
      DROP_ORDER_KEY.sync_scope(DropOrder(2), || {
        assert_eq!(DROP_ORDER_KEY.with(|value| value.0), 2);
      });
      assert_eq!(DROP_ORDER_KEY.with(|value| value.0), 1);
    });
    assert_eq!(DROP_ORDER_KEY.try_with(|_| ()), None);
  }

  #[test]
  fn sync_scope_restores_outer_value_after_closure_panic() {
    let result = VALUE.sync_scope(91, || {
      let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        VALUE.sync_scope(92, || panic!("sync scope panic"));
      }));
      assert!(panic.is_err());
      assert_eq!(VALUE.with(|value| *value), 91);
      93
    });
    assert_eq!(result, 93);
    assert_eq!(VALUE.try_with(|_| ()), None);
  }

  struct PanicNow;

  impl Future for PanicNow {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
      panic!("poll panic")
    }
  }

  #[test]
  fn panic_restores_the_enclosing_scope() {
    struct CatchInner<'a> {
      inner: ScopeFuture<'a, usize, PanicNow>,
    }

    impl Future for CatchInner<'_> {
      type Output = usize;

      fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
          Pin::new(&mut self.inner).poll(context)
        }));
        assert!(panicked.is_err());
        assert_eq!(VALUE.with(|value| *value), 41);
        Poll::Ready(41)
      }
    }

    let inner = VALUE.scope(42, PanicNow);
    let catch = CatchInner { inner };
    let mut outer = VALUE.scope(41, catch);
    assert_eq!(poll(&mut outer), Poll::Ready(41));
    assert_eq!(VALUE.try_with(|value| *value), None);
  }

  struct Migrating(usize);

  impl Future for Migrating {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
      let value = VALUE.with(|value| *value);
      let this = self.get_mut();
      if this.0 == 0 {
        this.0 = 1;
        Poll::Pending
      } else {
        Poll::Ready(value)
      }
    }
  }

  fn require_send<T: Send>(_: &T) {}

  #[test]
  fn send_scope_can_move_between_threads_and_has_no_old_thread_context() {
    let mut scoped = VALUE.scope(55, Migrating(0));
    require_send(&scoped);
    assert!(poll(&mut scoped).is_pending());
    assert_eq!(VALUE.try_with(|value| *value), None);
    let result = std::thread::spawn(move || {
      assert_eq!(VALUE.try_with(|value| *value), None);
      let mut context = Context::from_waker(Waker::noop());
      assert_eq!(Pin::new(&mut scoped).poll(&mut context), Poll::Ready(55));
      assert_eq!(VALUE.try_with(|value| *value), None);
    })
    .join();
    assert!(result.is_ok());
  }

  #[test]
  fn scope_value_drops_after_pop_and_can_read_enclosing_context() {
    struct DropInside<'a> {
      inner: Option<ScopeFuture<'a, ReentrantDrop, future::Ready<()>>>,
    }

    impl Future for DropInside<'_> {
      type Output = ();

      fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut inner = self.inner.take().expect("inner scope exists");
        assert_eq!(Pin::new(&mut inner).poll(context), Poll::Ready(()));
        drop(inner);
        assert_eq!(VALUE.with(|value| *value), 61);
        Poll::Ready(())
      }
    }

    DROPS.store(0, Ordering::Relaxed);
    let inner = DROP_VALUE.scope(ReentrantDrop, future::ready(()));
    let mut outer = VALUE.scope(61, DropInside { inner: Some(inner) });
    assert_eq!(poll(&mut outer), Poll::Ready(()));
    assert_eq!(DROPS.load(Ordering::Relaxed), 1);
    assert_eq!(VALUE.try_with(|value| *value), None);
  }

  #[test]
  fn ready_drops_inner_future_while_its_scope_is_still_installed() {
    static FUTURE_DROPS: AtomicUsize = AtomicUsize::new(0);

    struct ReadyWithDrop;

    impl Future for ReadyWithDrop {
      type Output = ();

      fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        assert_eq!(VALUE.with(|value| *value), 71);
        Poll::Ready(())
      }
    }

    impl Drop for ReadyWithDrop {
      fn drop(&mut self) {
        assert_eq!(VALUE.with(|value| *value), 71);
        FUTURE_DROPS.fetch_add(1, Ordering::Relaxed);
      }
    }

    FUTURE_DROPS.store(0, Ordering::Relaxed);
    let mut scoped = VALUE.scope(71, ReadyWithDrop);
    assert_eq!(poll(&mut scoped), Poll::Ready(()));
    assert_eq!(FUTURE_DROPS.load(Ordering::Relaxed), 1);
    assert_eq!(VALUE.try_with(|_| ()), None);
    drop(scoped);
    assert_eq!(FUTURE_DROPS.load(Ordering::Relaxed), 1);
  }

  #[test]
  fn pending_cancel_drops_inner_future_then_value_after_outer_context_restore() {
    struct PendingWithDrop;

    impl Future for PendingWithDrop {
      type Output = ();

      fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        assert_eq!(DROP_ORDER_KEY.with(|value| value.0), 2);
        Poll::Pending
      }
    }

    impl Drop for PendingWithDrop {
      fn drop(&mut self) {
        assert_eq!(DROP_ORDER_KEY.with(|value| value.0), 2);
      }
    }

    struct CancelInner<'a> {
      inner: Option<ScopeFuture<'a, DropOrder, PendingWithDrop>>,
    }

    impl Future for CancelInner<'_> {
      type Output = ();

      fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut inner = self.inner.take().expect("inner scope exists");
        assert!(Pin::new(&mut inner).poll(context).is_pending());
        drop(inner);
        assert_eq!(DROP_ORDER_KEY.with(|value| value.0), 1);
        Poll::Ready(())
      }
    }

    let inner = DROP_ORDER_KEY.scope(DropOrder(2), PendingWithDrop);
    let mut outer = DROP_ORDER_KEY.scope(DropOrder(1), CancelInner { inner: Some(inner) });
    assert!(poll(&mut outer).is_ready());
    assert_eq!(DROP_ORDER_KEY.try_with(|_| ()), None);
  }

  #[test]
  fn panicking_inner_drop_restores_outer_scope_before_resuming() {
    struct PanicOnDrop;

    impl Future for PanicOnDrop {
      type Output = ();

      fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
      }
    }

    impl Drop for PanicOnDrop {
      fn drop(&mut self) {
        assert_eq!(VALUE.with(|value| *value), 82);
        panic!("inner future drop panic");
      }
    }

    struct CatchDrop<'a> {
      inner: Option<ScopeFuture<'a, usize, PanicOnDrop>>,
    }

    impl Future for CatchDrop<'_> {
      type Output = ();

      fn poll(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = self.inner.take().expect("inner scope exists");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(inner)));
        assert!(panic.is_err());
        assert_eq!(VALUE.with(|value| *value), 81);
        Poll::Ready(())
      }
    }

    let inner = VALUE.scope(82, PanicOnDrop);
    let mut outer = VALUE.scope(81, CatchDrop { inner: Some(inner) });
    assert!(poll(&mut outer).is_ready());
    assert_eq!(VALUE.try_with(|_| ()), None);
  }

  #[test]
  fn dropping_scope_during_unwind_restores_context_and_finishes_cleanup() {
    static OBSERVED: AtomicUsize = AtomicUsize::new(0);

    struct CheckDrop;

    impl Future for CheckDrop {
      type Output = ();

      fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
      }
    }

    impl Drop for CheckDrop {
      fn drop(&mut self) {
        OBSERVED.store(VALUE.with(|value| *value), Ordering::Relaxed);
      }
    }

    let mut scoped = VALUE.scope(83, CheckDrop);
    assert!(poll(&mut scoped).is_pending());
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
      let _scoped = scoped;
      panic!("outer unwind");
    }));
    assert!(unwind.is_err());
    assert_eq!(OBSERVED.load(Ordering::Relaxed), 83);
    assert_eq!(VALUE.try_with(|_| ()), None);
  }

  #[test]
  fn pending_scope_cancellation_drops_value_after_restoration() {
    struct Pending;

    impl Future for Pending {
      type Output = ();

      fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        assert_eq!(CANCEL_VALUE.try_with(|_| ()), Some(()));
        Poll::Pending
      }
    }

    let mut scoped = CANCEL_VALUE.scope(DropCheck, Pending);
    assert!(poll(&mut scoped).is_pending());
    drop(scoped);
  }

  #[test]
  fn migrated_pending_scope_drops_its_value_on_the_drop_thread() {
    struct Pending;

    impl Future for Pending {
      type Output = ();

      fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        assert!(THREAD_VALUE.try_with(|_| ()).is_some());
        Poll::Pending
      }
    }

    let (sender, receiver) = std::sync::mpsc::channel();
    let mut scoped = THREAD_VALUE.scope(DropThread(sender), Pending);
    assert!(poll(&mut scoped).is_pending());
    assert!(THREAD_VALUE.try_with(|_| ()).is_none());
    let drop_thread = std::thread::spawn(move || {
      let expected = std::thread::current().id();
      drop(scoped);
      expected
    })
    .join()
    .expect("drop thread should finish");
    assert_eq!(
      receiver.recv().expect("value destructor should run"),
      drop_thread
    );
  }

  #[test]
  fn tls_teardown_falls_back_to_dropping_pending_future_without_context() {
    TEARDOWN_FUTURE_DROPS.store(0, Ordering::Relaxed);
    TEARDOWN_VALUE_DROPS.store(0, Ordering::Relaxed);
    std::thread::spawn(|| {
      RETAINED_SCOPE.with(|slot| {
        let mut scoped = TEARDOWN_KEY.scope(TeardownValue, TeardownFuture);
        assert!(poll(&mut scoped).is_pending());
        *slot.borrow_mut() = Some(scoped);
      });
    })
    .join()
    .expect("TLS teardown thread should finish");
    assert_eq!(TEARDOWN_FUTURE_DROPS.load(Ordering::Relaxed), 1);
    assert_eq!(TEARDOWN_VALUE_DROPS.load(Ordering::Relaxed), 1);
  }

  #[test]
  fn sync_scope_does_not_run_closure_after_tls_teardown() {
    SYNC_TEARDOWN_RAN.store(false, Ordering::Relaxed);
    SYNC_TEARDOWN_VALUE_DROPS.store(0, Ordering::Relaxed);
    std::thread::spawn(|| {
      RETAINED_SYNC.with(|_| {});
      assert!(SYNC_TEARDOWN_KEY.try_with(|_| ()).is_none());
    })
    .join()
    .expect("TLS teardown thread should finish");
    assert!(!SYNC_TEARDOWN_RAN.load(Ordering::Relaxed));
    assert_eq!(SYNC_TEARDOWN_VALUE_DROPS.load(Ordering::Relaxed), 1);
  }

  #[test]
  fn wake_callback_can_reenter_task_local_access_during_poll() {
    struct WakeDuringPoll;

    impl Future for WakeDuringPoll {
      type Output = ();

      fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        context.waker().wake_by_ref();
        Poll::Pending
      }
    }

    struct CheckWaker;

    impl std::task::Wake for CheckWaker {
      fn wake(self: std::sync::Arc<Self>) {
        self.wake_by_ref();
      }

      fn wake_by_ref(self: &std::sync::Arc<Self>) {
        assert_eq!(VALUE.with(|value| *value), 81);
      }
    }

    let mut scoped = VALUE.scope(81, WakeDuringPoll);
    let waker = std::task::Waker::from(std::sync::Arc::new(CheckWaker));
    let mut context = Context::from_waker(&waker);
    assert!(Pin::new(&mut scoped).poll(&mut context).is_pending());
    assert!(VALUE.try_with(|_| ()).is_none());
  }

  #[test]
  fn scope_future_is_unpin_even_when_its_value_is_not() {
    let scoped = PINNED_VALUE.scope(NotUnpin(std::marker::PhantomPinned), future::ready(()));
    fn require_unpin<T: Unpin>(_: &T) {}
    require_unpin(&scoped);
  }

  #[test]
  fn local_non_send_value_and_future_remain_usable() {
    static LOCAL: TaskLocalKey<Rc<usize>> = TaskLocalKey::new();
    let value = Rc::new(73);
    let mut scoped = LOCAL.scope(Rc::clone(&value), async move {
      assert_eq!(LOCAL.with(|local| **local), 73);
      drop(value);
    });
    assert!(poll(&mut scoped).is_ready());
  }

  #[test]
  fn send_scope_does_not_require_value_sync() {
    static CELL: TaskLocalKey<std::cell::Cell<usize>> = TaskLocalKey::new();

    struct ReadCell;

    impl Future for ReadCell {
      type Output = usize;

      fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(CELL.with(std::cell::Cell::get))
      }
    }

    let mut scoped = CELL.scope(std::cell::Cell::new(91), ReadCell);
    require_send(&scoped);
    let result = std::thread::spawn(move || {
      let mut context = Context::from_waker(Waker::noop());
      Pin::new(&mut scoped).poll(&mut context)
    })
    .join();
    assert!(matches!(result, Ok(Poll::Ready(91))));
  }
}
