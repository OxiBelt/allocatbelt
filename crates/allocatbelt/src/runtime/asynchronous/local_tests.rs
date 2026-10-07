use std::cell::{Cell, RefCell};
use std::future::{Future, pending};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::Duration;

use crate::runtime::asynchronous::{
  current_resource_scope, try_current_resource_scope, try_task_id,
};
use crate::runtime::managed::{ResourceLimits, ResourceScope};

use super::*;

struct CloseCallbackState {
  close: Pin<Box<LocalScopeClose>>,
  job: Pin<Box<AsyncJob<()>>>,
  done: Arc<AtomicBool>,
  close_ready: bool,
  join_ready: bool,
  close_ready_implies_join_ready: bool,
}

thread_local! {
  static CLOSE_CALLBACK_STATE: RefCell<Option<Rc<RefCell<CloseCallbackState>>>> = const { RefCell::new(None) };
}

struct PollCloseAndJoin;

impl Wake for PollCloseAndJoin {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    let state = CLOSE_CALLBACK_STATE
      .try_with(|slot| slot.borrow().as_ref().cloned())
      .unwrap_or(None);
    let Some(state) = state else {
      return;
    };
    let mut state = state.borrow_mut();
    let mut context = Context::from_waker(Waker::noop());
    if state.close.as_mut().poll(&mut context).is_ready() {
      state.close_ready = true;
    }
    if let Poll::Ready(result) = state.job.as_mut().poll(&mut context) {
      state.join_ready = true;
      state.close_ready_implies_join_ready =
        result.is_err_and(|error| matches!(error, AsyncJoinError::Cancelled));
    }
    if state.close_ready {
      state.done.store(true, Ordering::Release);
    }
  }
}

fn runtime(max_outstanding: usize, max_scopes: usize) -> LocalRuntime {
  LocalRuntime::new(LocalConfig {
    max_outstanding,
    max_scopes,
  })
  .unwrap_or_else(|error| panic!("local runtime creation failed: {error}"))
}

fn exhaust_budget() {
  super::super::entry::reset_budget();
  let mut context = Context::from_waker(Waker::noop());
  for _ in 0..64 {
    assert!(
      Pin::new(&mut super::super::consume_budget())
        .poll(&mut context)
        .is_ready()
    );
  }
}

#[test]
fn local_root_and_task_polls_start_with_fresh_cooperative_budgets() {
  let mut runtime = runtime(1, 1);
  exhaust_budget();
  assert!(
    runtime
      .block_on(std::future::poll_fn(|cx| {
        Poll::Ready(
          Pin::new(&mut super::super::consume_budget())
            .poll(cx)
            .is_ready(),
        )
      }))
      .unwrap()
  );

  let job = runtime
    .handle()
    .spawn_local(std::future::poll_fn(|cx| {
      Poll::Ready(
        Pin::new(&mut super::super::consume_budget())
          .poll(cx)
          .is_ready(),
      )
    }))
    .unwrap();
  // Each root poll exhausts its own budget before returning Pending. The
  // executor must reset it again before polling the child's first checkpoint.
  let mut job = job;
  let child = runtime
    .block_on(std::future::poll_fn(|cx| {
      exhaust_budget();
      Pin::new(&mut job).poll(cx)
    }))
    .unwrap()
    .unwrap();
  assert!(child);
}

#[test]
fn local_borrowed_root_and_non_send_task_charge_automatic_primitive_polls() {
  let mut runtime = runtime(1, 2);
  let (sender, _receiver) = crate::runtime::channel::channel(1, 2).unwrap();
  let local_value = Rc::new(Cell::new(5));
  let root_value = Rc::clone(&local_value);
  let root_remaining = runtime
    .block_on(std::future::poll_fn(|cx| {
      let mut send = std::pin::pin!(sender.send(Rc::clone(&root_value)));
      assert!(send.as_mut().poll(cx).is_ready());
      Poll::Ready(super::super::entry::budget_remaining())
    }))
    .unwrap();
  assert_eq!(root_remaining, 63);

  let (task_sender, _task_receiver) = crate::runtime::channel::channel(1, 2).unwrap();
  let task_value = Rc::clone(&local_value);
  let child = runtime
    .handle()
    .spawn_local(std::future::poll_fn(move |cx| {
      let mut send = std::pin::pin!(task_sender.send(Rc::clone(&task_value)));
      assert!(send.as_mut().poll(cx).is_ready());
      Poll::Ready((super::super::entry::budget_remaining(), task_value.get()))
    }))
    .unwrap();
  assert_eq!(
    runtime.block_on(child).unwrap().unwrap(),
    (63, 5),
    "the local task gets one fresh budget and keeps non-Send captures"
  );
}

#[test]
fn local_ready_and_panicking_future_cleanup_runs_after_poll_budget_is_disabled() {
  struct CleanupProbe {
    active_during_drop: Rc<Cell<Option<bool>>>,
    panic_during_poll: bool,
  }

  impl Future for CleanupProbe {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
      for _ in 0..64 {
        assert!(
          Pin::new(&mut super::super::consume_budget())
            .poll(cx)
            .is_ready()
        );
      }
      assert_eq!(super::super::entry::budget_remaining(), 0);
      if self.panic_during_poll {
        panic!("injected local task poll panic");
      }
      Poll::Ready(())
    }
  }

  impl Drop for CleanupProbe {
    fn drop(&mut self) {
      self
        .active_during_drop
        .set(Some(super::super::entry::cooperative_poll_active()));
    }
  }

  let mut runtime = runtime(2, 2);
  let ready_state = Rc::new(Cell::new(None));
  let ready_job = runtime
    .handle()
    .spawn_local(CleanupProbe {
      active_during_drop: Rc::clone(&ready_state),
      panic_during_poll: false,
    })
    .unwrap();
  assert!(runtime.block_on(ready_job).unwrap().is_ok());
  assert_eq!(ready_state.get(), Some(false));

  let panic_state = Rc::new(Cell::new(None));
  let panic_job = runtime
    .handle()
    .spawn_local(CleanupProbe {
      active_during_drop: Rc::clone(&panic_state),
      panic_during_poll: true,
    })
    .unwrap();
  assert!(matches!(
    runtime.block_on(panic_job).unwrap(),
    Err(AsyncJoinError::Panicked(_))
  ));
  assert_eq!(panic_state.get(), Some(false));
}

#[test]
fn local_future_and_output_may_be_non_send() {
  let mut runtime = runtime(2, 2);
  let value = Rc::new(Cell::new(0));
  let task_value = Rc::clone(&value);
  let job = runtime
    .handle()
    .spawn_local(async move {
      task_value.set(41);
      Rc::new(task_value.get() + 1)
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  let output = runtime
    .block_on(job)
    .unwrap_or_else(|error| panic!("block_on failed: {error}"))
    .unwrap_or_else(|error| panic!("task failed: {error}"));
  assert_eq!(value.get(), 41);
  assert_eq!(*output, 42);
}

#[test]
fn local_admission_is_bounded_and_rejection_returns_future() {
  let mut runtime = runtime(1, 1);
  let first = runtime
    .handle()
    .spawn_local(async { 7usize })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  let second = std::future::ready(9usize);
  let error = runtime
    .handle()
    .spawn_local(second)
    .err()
    .unwrap_or_else(|| panic!("second task exceeded the configured bound"));
  assert_eq!(error.kind, LocalError::Full);
  let returned = error.into_future();
  assert_eq!(runtime.block_on(returned), Ok(9));
  assert_eq!(runtime.block_on(first).ok().and_then(Result::ok), Some(7));
}

#[test]
fn local_scope_drop_cancels_and_reclaims_after_cleanup() {
  struct DropCount(Arc<AtomicUsize>);
  impl Drop for DropCount {
    fn drop(&mut self) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  let mut runtime = runtime(2, 2);
  let dropped = Arc::new(AtomicUsize::new(0));
  let scope = runtime
    .scope()
    .unwrap_or_else(|error| panic!("scope failed: {error}"));
  let started = Rc::new(Cell::new(false));
  struct MarkPending {
    started: Rc<Cell<bool>>,
    _guard: DropCount,
  }
  impl Future for MarkPending {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
      self.started.set(true);
      Poll::Pending
    }
  }
  let join = scope
    .spawn_local(MarkPending {
      started: Rc::clone(&started),
      _guard: DropCount(Arc::clone(&dropped)),
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  runtime
    .block_on(std::future::poll_fn(|_| {
      if started.get() {
        Poll::Ready(())
      } else {
        Poll::Pending
      }
    }))
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
  let close = scope.close();
  runtime
    .block_on(close)
    .unwrap_or_else(|error| panic!("scope close failed: {error}"));
  assert_eq!(dropped.load(Ordering::SeqCst), 1);
  assert!(matches!(
    runtime.block_on(join),
    Ok(Err(AsyncJoinError::Cancelled))
  ));
  let replacement = runtime
    .scope()
    .unwrap_or_else(|error| panic!("reclaimed scope unavailable: {error}"));
  drop(replacement);
}

#[test]
fn local_spawned_tasks_make_progress_while_root_is_pending() {
  let mut runtime = runtime(2, 1);
  let completed = Rc::new(Cell::new(false));
  let job = runtime
    .handle()
    .spawn_local({
      let completed = Rc::clone(&completed);
      async move {
        completed.set(true);
      }
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  runtime
    .block_on(async {
      let _ = job.await;
      assert!(completed.get());
    })
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
}

#[test]
fn external_send_handle_imports_and_runs_send_tasks() {
  let mut runtime = runtime(2, 1);
  let send_handle = runtime.send_handle();
  let (job_tx, job_rx) = mpsc::sync_channel(1);
  let producer = thread::spawn(move || {
    let job = send_handle
      .spawn(async { 55usize })
      .unwrap_or_else(|error| panic!("external spawn failed: {error}"));
    job_tx
      .send(job)
      .unwrap_or_else(|_| panic!("job receiver unexpectedly closed"));
  });
  let job = job_rx
    .recv()
    .unwrap_or_else(|_| panic!("producer did not submit a job"));
  producer
    .join()
    .unwrap_or_else(|_| panic!("producer thread panicked"));
  assert_eq!(runtime.block_on(job).ok().and_then(Result::ok), Some(55));
}

#[test]
fn external_submission_wakes_a_parked_local_block_on() {
  let mut runtime = runtime(1, 1);
  let completed = Arc::new(AtomicBool::new(false));
  let send_handle = runtime.send_handle();
  let task_completed = Arc::clone(&completed);
  let producer = thread::spawn(move || {
    let job = send_handle
      .spawn(async move {
        task_completed.store(true, Ordering::Release);
      })
      .unwrap_or_else(|error| panic!("external spawn failed: {error}"));
    drop(job);
  });
  runtime
    .block_on(std::future::poll_fn(|_| {
      if completed.load(Ordering::Acquire) {
        Poll::Ready(())
      } else {
        Poll::Pending
      }
    }))
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
  producer
    .join()
    .unwrap_or_else(|_| panic!("producer thread panicked"));
}

#[test]
fn local_parker_keeps_notification_after_a_root_consumes_unpark_permit() {
  struct WakeThenConsumePermit {
    resumed: bool,
    capture: mpsc::SyncSender<Waker>,
  }
  impl Future for WakeThenConsumePermit {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
      if self.resumed {
        Poll::Ready(())
      } else {
        self.resumed = true;
        let _ = self.capture.send(context.waker().clone());
        context.waker().wake_by_ref();
        thread::park_timeout(Duration::ZERO);
        Poll::Pending
      }
    }
  }

  let mut runtime = runtime(1, 1);
  let (capture_tx, capture_rx) = mpsc::sync_channel::<Waker>(1);
  let (done_tx, done_rx) = mpsc::channel();
  let rescued = Arc::new(AtomicBool::new(false));
  let watchdog_rescued = Arc::clone(&rescued);
  let watchdog = thread::spawn(move || {
    if let Ok(waker) = capture_rx.recv_timeout(Duration::from_secs(1))
      && done_rx.recv_timeout(Duration::from_secs(1)).is_err()
    {
      watchdog_rescued.store(true, Ordering::SeqCst);
      waker.wake();
    }
  });

  runtime
    .block_on(WakeThenConsumePermit {
      resumed: false,
      capture: capture_tx,
    })
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
  let _ = done_tx.send(());
  watchdog
    .join()
    .unwrap_or_else(|_| panic!("watchdog thread panicked"));
  assert!(
    !rescued.load(Ordering::SeqCst),
    "watchdog had to rescue block_on"
  );
}

#[test]
fn external_abort_before_import_is_observed() {
  let mut runtime = runtime(1, 1);
  let job = runtime
    .send_handle()
    .spawn(async { 1usize })
    .unwrap_or_else(|error| panic!("external spawn failed: {error}"));
  job.abort();
  assert!(matches!(
    runtime.block_on(job),
    Ok(Err(AsyncJoinError::Cancelled))
  ));
}

#[test]
fn stale_send_handles_reject_after_runtime_drop() {
  let send_handle = {
    let runtime = runtime(1, 1);
    runtime.send_handle()
  };
  let error = send_handle
    .spawn(async { 1usize })
    .err()
    .unwrap_or_else(|| panic!("closed runtime accepted an external task"));
  assert_eq!(error.kind, LocalError::Closed);
  let mut recovered = Box::pin(error.into_future());
  let mut context = Context::from_waker(Waker::noop());
  assert_eq!(recovered.as_mut().poll(&mut context), Poll::Ready(1));
}

#[test]
fn scope_close_future_waits_for_active_cleanup() {
  let mut runtime = runtime(1, 2);
  let scope = runtime
    .scope()
    .unwrap_or_else(|error| panic!("scope failed: {error}"));
  let join = scope
    .spawn_local(pending::<()>())
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  let close = scope.close();
  assert!(runtime.block_on(close).is_ok());
  assert!(matches!(
    runtime.block_on(join),
    Ok(Err(AsyncJoinError::Cancelled))
  ));
}

#[test]
fn scope_close_waker_observes_child_join_after_close_becomes_ready() {
  let mut runtime = runtime(1, 2);
  let scope = runtime
    .scope()
    .unwrap_or_else(|error| panic!("scope failed: {error}"));
  let job = scope
    .spawn_local(pending::<()>())
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  let done = Arc::new(AtomicBool::new(false));
  let state = Rc::new(RefCell::new(CloseCallbackState {
    close: Box::pin(scope.close()),
    job: Box::pin(job),
    done: Arc::clone(&done),
    close_ready: false,
    join_ready: false,
    close_ready_implies_join_ready: false,
  }));
  CLOSE_CALLBACK_STATE.with(|slot| *slot.borrow_mut() = Some(Rc::clone(&state)));

  {
    let mut state = state.borrow_mut();
    let mut join_context = Context::from_waker(Waker::noop());
    assert!(state.job.as_mut().poll(&mut join_context).is_pending());
    let close_waker = Waker::from(Arc::new(PollCloseAndJoin));
    let mut close_context = Context::from_waker(&close_waker);
    assert!(state.close.as_mut().poll(&mut close_context).is_pending());
  }

  runtime
    .block_on(std::future::poll_fn(|_| {
      if done.load(Ordering::Acquire) {
        Poll::Ready(())
      } else {
        Poll::Pending
      }
    }))
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));

  let state = state.borrow();
  assert!(state.close_ready);
  assert!(state.join_ready);
  assert!(state.close_ready_implies_join_ready);
  drop(state);
  CLOSE_CALLBACK_STATE.with(|slot| drop(slot.borrow_mut().take()));
}

#[test]
fn local_handle_context_restores_after_out_of_order_drop() {
  let runtime_a = runtime(1, 1);
  let runtime_b = runtime(1, 1);
  let handle_a = runtime_a.handle();
  let handle_b = runtime_b.handle();
  let guard_a = handle_a.enter();
  let guard_b = handle_b.enter();
  drop(guard_a);
  assert!(Rc::ptr_eq(&LocalHandle::current().core, &handle_b.core));
  drop(guard_b);
  assert!(LocalHandle::try_current().is_none());
}

#[test]
fn local_block_on_shares_nested_entry_rejection() {
  let mut outer = runtime(1, 1);
  let mut inner = runtime(1, 1);
  let result = outer.block_on(async { inner.block_on(async { 5usize }) });
  assert!(matches!(result, Ok(Err(LocalError::BlockOnRejected))));
}

#[test]
fn local_tasks_follow_fifo_within_a_scope() {
  let mut runtime = runtime(4, 1);
  let order = Rc::new(RefCell::new(Vec::new()));
  let handle = runtime.handle();
  let mut jobs = Vec::new();
  for value in 0..3 {
    let order = Rc::clone(&order);
    jobs.push(
      handle
        .spawn_local(async move {
          order.borrow_mut().push(value);
        })
        .unwrap_or_else(|error| panic!("spawn failed: {error}")),
    );
  }
  runtime
    .block_on(async move {
      for job in jobs {
        let _ = job.await;
      }
    })
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
  assert_eq!(*order.borrow(), [0, 1, 2]);
}

#[test]
fn local_task_poll_enters_its_own_scope_context() {
  let mut runtime = runtime(1, 2);
  let scope = runtime
    .scope()
    .unwrap_or_else(|error| panic!("scope failed: {error}"));
  let expected_scope = scope.handle().scope.index;
  let job = scope
    .spawn_local(async { LocalHandle::current().scope.index })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  assert_eq!(
    runtime.block_on(job).ok().and_then(Result::ok),
    Some(expected_scope)
  );
}

#[test]
fn ready_scopes_take_round_robin_poll_turns() {
  let mut runtime = runtime(4, 2);
  let order = Rc::new(RefCell::new(Vec::new()));
  let scope = runtime
    .scope()
    .unwrap_or_else(|error| panic!("scope failed: {error}"));
  let root = runtime.handle();
  let scoped = scope.handle();
  let mut jobs = Vec::new();
  for (handle, label) in [
    (root.clone(), 0),
    (root, 2),
    (scoped.clone(), 1),
    (scoped, 3),
  ] {
    let order = Rc::clone(&order);
    jobs.push(
      handle
        .spawn_local(async move {
          order.borrow_mut().push(label);
        })
        .unwrap_or_else(|error| panic!("spawn failed: {error}")),
    );
  }
  runtime
    .block_on(async move {
      for job in jobs {
        let _ = job.await;
      }
    })
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
  assert_eq!(*order.borrow(), [0, 1, 2, 3]);
}

#[test]
fn stale_task_waker_cannot_wake_a_reused_slot_generation() {
  struct CaptureWaker(Arc<std::sync::Mutex<Option<Waker>>>);
  impl Future for CaptureWaker {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
      *self
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(context.waker().clone());
      Poll::Ready(())
    }
  }

  struct PendingThenReady(Rc<Cell<usize>>);
  impl Future for PendingThenReady {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
      let count = self.0.get() + 1;
      self.0.set(count);
      if count == 1 {
        Poll::Pending
      } else {
        Poll::Ready(())
      }
    }
  }

  let mut runtime = runtime(1, 1);
  let captured = Arc::new(std::sync::Mutex::new(None));
  let first = runtime
    .handle()
    .spawn_local(CaptureWaker(Arc::clone(&captured)))
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  runtime
    .block_on(first)
    .unwrap_or_else(|error| panic!("block_on failed: {error}"))
    .unwrap_or_else(|error| panic!("task failed: {error}"));
  let first_generation = runtime.core.control.lock().tasks[0].protocol.generation();
  let stale_waker = captured
    .lock()
    .unwrap_or_else(std::sync::PoisonError::into_inner)
    .take()
    .unwrap_or_else(|| panic!("task did not capture its waker"));

  let polls = Rc::new(Cell::new(0));
  let second = runtime
    .handle()
    .spawn_local(PendingThenReady(Rc::clone(&polls)))
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  let second_generation = runtime.core.control.lock().tasks[0].protocol.generation();
  assert!(second_generation > first_generation);
  runtime
    .block_on(std::future::poll_fn(|_| {
      if polls.get() == 1 {
        Poll::Ready(())
      } else {
        Poll::Pending
      }
    }))
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
  assert_eq!(polls.get(), 1);

  stale_waker.wake();
  assert!(runtime.core.control.take_ready().is_none());
  assert_eq!(polls.get(), 1);
  drop(second);
}

#[test]
fn local_enter_guard_is_thread_affine() {
  let runtime = runtime(1, 1);
  let guard = runtime.handle().enter();
  assert!(LocalHandle::try_current().is_some());
  drop(guard);
  assert!(LocalHandle::try_current().is_none());
}

#[test]
fn local_root_future_can_borrow_stack_data() {
  let mut runtime = runtime(1, 1);
  let mut value = 3;
  let result = runtime.block_on(async {
    value += 4;
    value
  });
  assert_eq!(result, Ok(7));
}

#[test]
fn external_send_job_rejected_for_full_bound_returns_future() {
  let mut runtime = runtime(1, 1);
  let _first = runtime
    .handle()
    .spawn_local(pending::<usize>())
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  let error = runtime
    .send_handle()
    .spawn(async { 23usize })
    .err()
    .unwrap_or_else(|| panic!("external task exceeded the shared bound"));
  assert_eq!(error.kind, LocalError::Full);
  runtime
    .block_on(error.into_future())
    .unwrap_or_else(|error| panic!("recovered future failed: {error}"));
}

#[test]
fn queued_external_future_drop_sees_the_root_local_context() {
  struct ObserveRootContext(Arc<AtomicBool>);
  impl Future for ObserveRootContext {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for ObserveRootContext {
    fn drop(&mut self) {
      let is_root = LocalHandle::try_current().is_some_and(|handle| handle.scope.index == 0);
      self.0.store(is_root, Ordering::Release);
    }
  }

  let runtime = runtime(1, 1);
  let observed = Arc::new(AtomicBool::new(false));
  let job = runtime
    .send_handle()
    .spawn(ObserveRootContext(Arc::clone(&observed)))
    .unwrap_or_else(|error| panic!("external spawn failed: {error}"));
  drop(job);
  drop(runtime);
  assert!(observed.load(Ordering::Acquire));
}

#[test]
fn local_abort_is_observed_between_polls() {
  struct PendingThenDrop(Arc<AtomicBool>);
  impl Future for PendingThenDrop {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for PendingThenDrop {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }

  let mut runtime = runtime(1, 1);
  let dropped = Arc::new(AtomicBool::new(false));
  let job = runtime
    .handle()
    .spawn_local(PendingThenDrop(Arc::clone(&dropped)))
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  job.abort();
  assert!(matches!(
    runtime.block_on(job),
    Ok(Err(AsyncJoinError::Cancelled))
  ));
  assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn runtime_drop_cleans_local_future_on_owner_without_live_table_borrow() {
  struct ReenterOnDrop {
    handle: LocalHandle,
    result: Rc<Cell<bool>>,
    owner: thread::ThreadId,
    observed_owner: Rc<RefCell<Option<thread::ThreadId>>>,
  }
  impl Future for ReenterOnDrop {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for ReenterOnDrop {
    fn drop(&mut self) {
      *self.observed_owner.borrow_mut() = Some(thread::current().id());
      self.result.set(matches!(
        self.handle.spawn_local(async {}),
        Err(LocalSpawnError {
          kind: LocalError::Closed,
          ..
        })
      ));
      assert_eq!(thread::current().id(), self.owner);
    }
  }

  let rejected = Rc::new(Cell::new(false));
  let observed_owner = Rc::new(RefCell::new(None));
  let owner = thread::current().id();
  let runtime = runtime(1, 1);
  let handle = runtime.handle();
  let _job = handle
    .spawn_local(ReenterOnDrop {
      handle: handle.clone(),
      result: Rc::clone(&rejected),
      owner,
      observed_owner: Rc::clone(&observed_owner),
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  drop(runtime);
  assert!(rejected.get());
  assert_eq!(*observed_owner.borrow(), Some(owner));
}

#[test]
fn panicking_local_future_destructor_is_published_as_join_error() {
  struct PanicOnDrop;
  impl Future for PanicOnDrop {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for PanicOnDrop {
    fn drop(&mut self) {
      panic!("local future cleanup panic");
    }
  }

  let mut runtime = runtime(1, 1);
  let job = runtime
    .handle()
    .spawn_local(PanicOnDrop)
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  job.abort();
  assert!(matches!(
    runtime.block_on(job),
    Ok(Err(AsyncJoinError::Panicked(_)))
  ));
}

#[test]
fn local_resource_binding_charges_buffers_through_close_and_final_drop() {
  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: 20,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let mut runtime = runtime(4, 3);
  let scope = runtime
    .scope_with_resources(&resources)
    .unwrap_or_else(|e| panic!("resource scope failed: {e}"));
  let job = scope
    .spawn_local(async {
      assert_eq!(current_resource_scope().limits().managed_memory, 20);
      current_resource_scope()
        .try_alloc_zeroed(15)
        .unwrap_or_else(|e| panic!("managed buffer allocation failed: {e}"))
    })
    .unwrap_or_else(|e| panic!("bound local task spawn failed: {e}"));
  let buffer = runtime
    .block_on(job)
    .unwrap()
    .unwrap_or_else(|e| panic!("bound local task failed: {e}"));
  assert_eq!(resources.snapshot().managed_memory, 15);

  runtime
    .block_on(scope.close())
    .unwrap_or_else(|e| panic!("scope close failed: {e}"));
  assert_eq!(resources.snapshot().managed_memory, 15);
  drop(buffer);
  assert_eq!(resources.snapshot().managed_memory, 0);
}

#[test]
fn local_task_context_restores_and_covers_cleanup_without_inheritance() {
  use super::super::entry::TaskContextGuard;

  let outer = ResourceScope::new(ResourceLimits {
    managed_memory: 3,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: 29,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let mut runtime = runtime(6, 3);
  let scope = runtime
    .scope_with_resources(&resources)
    .unwrap_or_else(|e| panic!("resource scope failed: {e}"));
  let root = runtime.handle();

  let _outer = TaskContextGuard::enter_with_resource(None, Some(outer.clone()));
  assert!(
    runtime
      .block_on(async { try_current_resource_scope().is_none() && try_task_id().is_none() })
      .unwrap()
  );
  let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    let _ = runtime.block_on(async { panic!("local root poll panic") });
  }));
  assert!(unwind.is_err());
  assert_eq!(current_resource_scope().limits().managed_memory, 3);

  let (child_tx, child_rx) = mpsc::channel();
  let child_producer = scope
    .spawn_local(async move {
      assert_eq!(current_resource_scope().limits().managed_memory, 29);
      let child = root
        .spawn_local(async { try_current_resource_scope().is_none() })
        .unwrap_or_else(|e| panic!("unbound child spawn failed: {e}"));
      child_tx
        .send(child)
        .unwrap_or_else(|_| panic!("child receiver disconnected"));
    })
    .unwrap_or_else(|e| panic!("bound parent spawn failed: {e}"));
  assert!(runtime.block_on(child_producer).unwrap().is_ok());
  let child = child_rx
    .recv()
    .unwrap_or_else(|e| panic!("unbound child was not submitted: {e}"));
  assert!(runtime.block_on(child).unwrap().unwrap());

  struct DropProbe(mpsc::Sender<Option<usize>>);
  impl Future for DropProbe {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for DropProbe {
    fn drop(&mut self) {
      let observed = try_current_resource_scope().map(|scope| scope.limits().managed_memory);
      let _ = self.0.send(observed);
    }
  }
  let (future_tx, future_rx) = mpsc::channel();
  let pending = scope
    .spawn_local(DropProbe(future_tx))
    .unwrap_or_else(|e| panic!("cleanup probe spawn failed: {e}"));
  pending.abort();
  assert!(matches!(
    runtime.block_on(pending),
    Ok(Err(AsyncJoinError::Cancelled))
  ));
  assert_eq!(future_rx.recv().unwrap(), Some(29));

  struct OutputProbe(mpsc::Sender<Option<usize>>);
  impl Drop for OutputProbe {
    fn drop(&mut self) {
      let observed = try_current_resource_scope().map(|scope| scope.limits().managed_memory);
      let _ = self.0.send(observed);
    }
  }
  let (output_tx, output_rx) = mpsc::channel();
  let detached = scope
    .spawn_local(async move { OutputProbe(output_tx) })
    .unwrap_or_else(|e| panic!("detached output spawn failed: {e}"));
  drop(detached);
  let observed = runtime
    .block_on(std::future::poll_fn(move |cx| match output_rx.try_recv() {
      Ok(value) => Poll::Ready(value),
      Err(mpsc::TryRecvError::Empty) => {
        cx.waker().wake_by_ref();
        Poll::Pending
      }
      Err(mpsc::TryRecvError::Disconnected) => panic!("output probe disconnected"),
    }))
    .unwrap();
  assert_eq!(observed, Some(29));

  runtime
    .block_on(scope.close())
    .unwrap_or_else(|e| panic!("scope close failed: {e}"));
}
