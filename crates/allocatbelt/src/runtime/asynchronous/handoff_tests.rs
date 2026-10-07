//! Native tests for bounded original-thread `try_block_in_place`. Every wait
//! has a deadline, and every blocking closure waits on a gate that test
//! unwinding opens, so a failure cannot hang the suite.

use std::cell::Cell;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

use super::entry::{block_on_active, budget_remaining, cooperative_poll_active};
use super::{
  AsyncConfig, AsyncError, AsyncHandle, AsyncJob, AsyncJoinError, AsyncRuntime, AsyncScopeConfig,
  AsyncShutdown, BlockInPlaceErrorKind, HandoffConfig, LocalConfig, LocalRuntime, OwnedTaskScope,
  consume_budget, current_resource_scope, try_block_in_place, try_current_resource_scope,
  try_task_id, yield_now,
};
use crate::runtime::cache;
use crate::runtime::managed::{ResourceLimits, ResourceScope};
use crate::runtime::task_local::TaskLocalKey;

const DEADLINE: Duration = Duration::from_secs(5);

fn config(workers: usize, max_outstanding: usize, max_scopes: usize) -> AsyncConfig {
  AsyncConfig {
    workers,
    max_outstanding,
    max_scopes,
  }
}

fn handoff_runtime(
  workers: usize,
  max_handoffs: usize,
  max_outstanding: usize,
  max_scopes: usize,
) -> AsyncRuntime {
  AsyncRuntime::new_with_handoffs(
    config(workers, max_outstanding, max_scopes),
    HandoffConfig { max_handoffs },
  )
  .unwrap_or_else(|error| panic!("runtime construction failed: {error}"))
}

fn scope_config(max_active_polls: usize) -> AsyncScopeConfig {
  AsyncScopeConfig { max_active_polls }
}

/// A separate cap-1 scope. A handed-off task keeps its scope's poll slot, so
/// with one worker the implicit root scope (limit 1) would block every other
/// root task until the closure returns.
fn own_scope(runtime: &AsyncRuntime) -> OwnedTaskScope {
  runtime
    .scope_with_config(scope_config(1))
    .unwrap_or_else(|error| panic!("scope failed: {error}"))
}

#[derive(Clone, Default)]
struct Gate(Arc<(Mutex<bool>, Condvar)>);

impl Gate {
  fn open(&self) {
    let (lock, cv) = &*self.0;
    *lock.lock().unwrap_or_else(PoisonError::into_inner) = true;
    cv.notify_all();
  }

  fn is_open(&self) -> bool {
    *self.0.0.lock().unwrap_or_else(PoisonError::into_inner)
  }

  /// Waits until the gate opens or the deadline passes; returns whether it
  /// opened.
  fn wait(&self) -> bool {
    let (lock, cv) = &*self.0;
    let deadline = Instant::now() + DEADLINE;
    let mut open = lock.lock().unwrap_or_else(PoisonError::into_inner);
    while !*open {
      let now = Instant::now();
      if now >= deadline {
        return false;
      }
      open = cv
        .wait_timeout(open, deadline - now)
        .unwrap_or_else(PoisonError::into_inner)
        .0;
    }
    true
  }
}

/// Opens its gate when dropped, including while a failing test unwinds.
struct OpenOnDrop(Gate);

impl Drop for OpenOnDrop {
  fn drop(&mut self) {
    self.0.open();
  }
}

fn wait_until(predicate: impl Fn() -> bool, message: &str) {
  let deadline = Instant::now() + DEADLINE;
  while !predicate() {
    assert!(Instant::now() < deadline, "timed out waiting for {message}");
    thread::sleep(Duration::from_millis(1));
  }
}

struct ThreadWake(thread::Thread);

impl Wake for ThreadWake {
  fn wake(self: Arc<Self>) {
    self.0.unpark();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.unpark();
  }
}

fn wait_job<T>(job: AsyncJob<T>) -> Result<T, AsyncJoinError> {
  let deadline = Instant::now() + DEADLINE;
  let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
  let mut context = Context::from_waker(&waker);
  let mut job = pin!(job);
  loop {
    if let Poll::Ready(output) = job.as_mut().poll(&mut context) {
      return output;
    }
    let now = Instant::now();
    assert!(now < deadline, "timed out waiting for a task");
    thread::park_timeout(deadline - now);
  }
}

fn joined<T>(job: AsyncJob<T>) -> T {
  wait_job(job).unwrap_or_else(|error| panic!("join failed: {error}"))
}

fn spawned<F>(handle: &AsyncHandle, future: F) -> AsyncJob<F::Output>
where
  F: Future + Send + 'static,
  F::Output: Send + 'static,
{
  handle
    .spawn(future)
    .unwrap_or_else(|error| panic!("spawn failed: {error}"))
}

fn shutdown_within(runtime: AsyncRuntime, mode: AsyncShutdown) -> Result<(), AsyncError> {
  let (done, result) = mpsc::channel();
  thread::spawn(move || {
    let _ = done.send(runtime.shutdown(mode));
  });
  result
    .recv_timeout(DEADLINE)
    .unwrap_or_else(|_| panic!("shutdown timed out"))
}

fn drained(runtime: AsyncRuntime) {
  shutdown_within(runtime, AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

/// Opens `entered`, then blocks this handed-off closure until `release`.
fn block_until(entered: &Gate, release: &Gate) -> bool {
  entered.open();
  release.wait()
}

fn injected_panic() -> u8 {
  panic!("injected panic")
}

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
  fn drop(&mut self) {
    self.0.store(true, Ordering::SeqCst);
  }
}

#[test]
fn handoff_configuration_is_explicit_and_checked() {
  for (workers, max_handoffs) in [(1, 0), (0, 1), (2, usize::MAX)] {
    assert!(matches!(
      AsyncRuntime::new_with_handoffs(config(workers, 1, 1), HandoffConfig { max_handoffs }),
      Err(AsyncError::InvalidConfig)
    ));
  }
  let fixed = AsyncRuntime::new(config(2, 1, 1))
    .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
  assert!(format!("{fixed:?}").contains("workers: 2"));
  let with_helpers = handoff_runtime(2, 3, 1, 1);
  assert!(format!("{with_helpers:?}").contains("workers: 5"));
  assert_eq!(with_helpers.shared.turn_counts(), (0, 0, 0, 0));
  drained(fixed);
  drained(with_helpers);
}

#[test]
fn w1_b1_closure_waits_for_a_task_in_a_different_free_scope() {
  let runtime = handoff_runtime(1, 1, 4, 3);
  let waiting = runtime
    .scope_with_config(scope_config(1))
    .unwrap_or_else(|error| panic!("scope failed: {error}"));
  let free = runtime
    .scope_with_config(scope_config(1))
    .unwrap_or_else(|error| panic!("scope failed: {error}"));
  let free_handle = free.handle();
  let job = spawned(&waiting.handle(), async move {
    let poll_thread = thread::current().id();
    let (sent, received) = mpsc::channel();
    let dependency = spawned(&free_handle, async move {
      let _ = sent.send(thread::current().id());
    });
    let (closure_thread, dependency_thread) =
      try_block_in_place(|| (thread::current().id(), received.recv_timeout(DEADLINE).ok()))
        .unwrap_or_else(|error| panic!("handoff rejected: {error}"));
    drop(dependency);
    (poll_thread, closure_thread, dependency_thread)
  });
  let (poll_thread, closure_thread, dependency_thread) = joined(job);
  assert_eq!(poll_thread, closure_thread);
  let dependency_thread =
    dependency_thread.unwrap_or_else(|| panic!("the dependency never ran during the handoff"));
  assert_ne!(dependency_thread, poll_thread);
  drained(runtime);
}

static REQUEST: TaskLocalKey<u32> = TaskLocalKey::new();

#[test]
fn closure_borrows_thread_affine_state_and_keeps_the_task_context() {
  let runtime = handoff_runtime(1, 1, 2, 1);
  let shared = Arc::clone(&runtime.shared);
  let job = spawned(
    &runtime.handle(),
    REQUEST.scope(7, async move {
      let task = try_task_id();
      let poll_thread = thread::current().id();
      let flushes = cache::FLUSHES.get();
      let local = Rc::new(Cell::new(1_u32));
      let borrowed = &local;
      let (closure_thread, returned, seen_task, request, entered, flushed) =
        try_block_in_place(|| {
          borrowed.set(borrowed.get() + 1);
          (
            thread::current().id(),
            Rc::clone(borrowed),
            try_task_id(),
            REQUEST.with(|value| *value),
            AsyncHandle::try_current().is_some_and(|current| Arc::ptr_eq(&current.shared, &shared)),
            cache::FLUSHES.get() > flushes,
          )
        })
        .unwrap_or_else(|error| panic!("handoff rejected: {error}"));
      returned.set(returned.get() * 10);
      drop(returned);
      (
        poll_thread == closure_thread,
        local.get(),
        task.is_some() && seen_task == task && try_task_id() == task,
        request,
        entered,
        flushed,
      )
    }),
  );
  assert_eq!(joined(job), (true, 20, true, 7, true, true));
  drained(runtime);
}

#[test]
fn handoff_and_nested_roots_preserve_explicit_resource_bindings() {
  let resources = ResourceScope::new(ResourceLimits {
    managed_memory: 37,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let runtime = handoff_runtime(1, 1, 4, 3);
  let bound = runtime
    .scope_with_resources(&resources)
    .unwrap_or_else(|error| panic!("resource scope failed: {error}"));
  let bound_handle = bound.handle();
  let nested_handle = bound_handle.clone();
  let unbound_handle = runtime.handle();
  let job = spawned(&bound_handle, async move {
    let task = try_task_id();
    assert_eq!(current_resource_scope().limits().managed_memory, 37);
    let (in_closure, nested_root, restored_task, restored_scope) = try_block_in_place(|| {
      let in_closure = current_resource_scope().limits().managed_memory;
      let nested_root = nested_handle
        .block_on(async {
          (
            current_resource_scope().limits().managed_memory,
            try_task_id(),
          )
        })
        .unwrap_or_else(|error| panic!("nested block_on failed: {error}"));
      (
        in_closure,
        nested_root,
        try_task_id(),
        try_current_resource_scope().map(|scope| scope.limits().managed_memory),
      )
    })
    .unwrap_or_else(|error| panic!("handoff rejected: {error}"));
    let detached = spawned(&unbound_handle, async {
      try_current_resource_scope().is_none()
    });
    let detached = detached
      .await
      .unwrap_or_else(|error| panic!("unbound child failed: {error}"));
    (
      in_closure,
      nested_root,
      restored_task == task,
      restored_scope,
      detached,
    )
  });
  assert_eq!(
    joined(job),
    (37, (37, None), true, Some(37), true),
    "handoff and nested roots must restore the caller's explicit binding"
  );
  drained(runtime);

  let local_resources = ResourceScope::new(ResourceLimits {
    managed_memory: 19,
    disk_concurrent_ops: 0,
    network_concurrent_ops: 0,
  });
  let mut local = LocalRuntime::new(LocalConfig {
    max_outstanding: 3,
    max_scopes: 2,
  })
  .unwrap_or_else(|error| panic!("local runtime failed: {error}"));
  let local_scope = local
    .scope_with_resources(&local_resources)
    .unwrap_or_else(|error| panic!("local resource scope failed: {error}"));
  let local_job = local_scope
    .spawn_local(async { current_resource_scope().limits().managed_memory })
    .unwrap_or_else(|error| panic!("local task admission failed: {error}"));
  let local_result = local
    .block_on(async move {
      assert!(try_current_resource_scope().is_none());
      local_job.await
    })
    .unwrap_or_else(|error| panic!("local root block_on failed: {error}"));
  assert!(matches!(local_result, Ok(19)));
}

#[test]
fn same_scope_quota_stays_reserved_through_the_closure() {
  let runtime = handoff_runtime(1, 1, 4, 3);
  let scope = runtime
    .scope_with_config(scope_config(1))
    .unwrap_or_else(|error| panic!("scope failed: {error}"));
  let free = runtime
    .scope_with_config(scope_config(1))
    .unwrap_or_else(|error| panic!("scope failed: {error}"));
  let entered = Gate::default();
  let release = Gate::default();
  let _release_on_unwind = OpenOnDrop(release.clone());
  let blocked = {
    let (entered, release) = (entered.clone(), release.clone());
    spawned(&scope.handle(), async move {
      try_block_in_place(|| block_until(&entered, &release)).unwrap_or(false)
    })
  };
  assert!(entered.wait());
  assert_eq!(scope.snapshot().active_polls, 1);
  let same_ran = Arc::new(AtomicBool::new(false));
  let same = {
    let same_ran = Arc::clone(&same_ran);
    spawned(&scope.handle(), async move {
      same_ran.store(true, Ordering::SeqCst);
    })
  };
  // The helper dispatches the free scope, but the blocked task's poll slot
  // keeps its own scope's queued task waiting.
  joined(spawned(&free.handle(), async {}));
  assert!(!same_ran.load(Ordering::SeqCst));
  assert_eq!(scope.snapshot().active_polls, 1);
  release.open();
  assert!(joined(blocked));
  joined(same);
  assert!(same_ran.load(Ordering::SeqCst));
  drained(runtime);
}

#[test]
fn a_cap_one_same_scope_wait_stalls_while_a_larger_explicit_cap_progresses() {
  let runtime = handoff_runtime(1, 1, 4, 3);
  for (cap, expected) in [(1, false), (2, true)] {
    let scope = runtime
      .scope_with_config(scope_config(cap))
      .unwrap_or_else(|error| panic!("scope failed: {error}"));
    let handle = scope.handle();
    let job = spawned(&scope.handle(), async move {
      let (sent, received) = mpsc::channel();
      let dependency = spawned(&handle, async move {
        let _ = sent.send(());
      });
      // With cap 1 this wait would deadlock; it is bounded here to observe it.
      let wait = if cap == 1 {
        Duration::from_millis(200)
      } else {
        DEADLINE
      };
      let finished = try_block_in_place(|| received.recv_timeout(wait).is_ok()).unwrap_or(false);
      drop(dependency);
      finished
    });
    assert_eq!(
      joined(job),
      expected,
      "same-scope dependency with cap {cap}"
    );
    drop(scope);
  }
  drained(runtime);
}

#[test]
fn disabled_and_full_return_the_original_uncalled_closure() {
  let fixed = AsyncRuntime::new(config(1, 1, 1))
    .unwrap_or_else(|error| panic!("runtime construction failed: {error}"));
  let job = spawned(&fixed.handle(), async {
    let called = Cell::new(false);
    let base = 41;
    match try_block_in_place(|| {
      called.set(true);
      base + 1
    }) {
      Ok(_) => None,
      Err(error) => {
        let kind = error.kind;
        let before = called.get();
        Some((kind, before, error.into_closure()()))
      }
    }
  });
  assert_eq!(
    joined(job),
    Some((BlockInPlaceErrorKind::Disabled, false, 42))
  );
  drained(fixed);

  let runtime = handoff_runtime(1, 1, 4, 2);
  let handle = runtime.handle();
  let holding = own_scope(&runtime);
  let entered = Gate::default();
  let release = Gate::default();
  let _release_on_unwind = OpenOnDrop(release.clone());
  let holder = {
    let (entered, release) = (entered.clone(), release.clone());
    spawned(&holding.handle(), async move {
      try_block_in_place(|| block_until(&entered, &release)).unwrap_or(false)
    })
  };
  assert!(entered.wait());
  let rejected = spawned(&handle, async {
    let called = Cell::new(false);
    match try_block_in_place(|| {
      called.set(true);
      5
    }) {
      Ok(_) => None,
      Err(error) => {
        let kind = error.kind;
        let before = called.get();
        // The rejected turn kept its permit and may still run the closure.
        Some((kind, before, error.into_closure()()))
      }
    }
  });
  assert_eq!(
    joined(rejected),
    Some((BlockInPlaceErrorKind::Full, false, 5))
  );
  release.open();
  assert!(joined(holder));
  drained(runtime);
}

#[test]
fn helpers_hand_off_under_the_same_bound_with_distinct_shards() {
  let runtime = handoff_runtime(1, 2, 8, 3);
  let shared = Arc::clone(&runtime.shared);
  let handle = runtime.handle();
  let (worker_scope, helper_scope) = (own_scope(&runtime), own_scope(&runtime));
  let release = Gate::default();
  let _release_on_unwind = OpenOnDrop(release.clone());
  let worker_entered = Gate::default();
  let worker = {
    let (entered, release) = (worker_entered.clone(), release.clone());
    spawned(&worker_scope.handle(), async move {
      let shard = cache::SHARD.get();
      let thread = thread::current().id();
      let blocked = try_block_in_place(|| block_until(&entered, &release)).unwrap_or(false);
      (shard, thread, blocked)
    })
  };
  assert!(worker_entered.wait());
  let helper_entered = Gate::default();
  let helper = {
    let (entered, release) = (helper_entered.clone(), release.clone());
    spawned(&helper_scope.handle(), async move {
      let shard = cache::SHARD.get();
      let blocked = try_block_in_place(|| block_until(&entered, &release)).unwrap_or(false);
      (shard, blocked)
    })
  };
  assert!(helper_entered.wait());
  wait_until(|| shared.turn_counts().1 == 2, "two loans");
  let rejected = spawned(&handle, async {
    let shard = cache::SHARD.get();
    let kind = try_block_in_place(|| ()).err().map(|error| error.kind);
    (shard, kind)
  });
  let (third_shard, kind) = joined(rejected);
  assert_eq!(kind, Some(BlockInPlaceErrorKind::Full));
  release.open();
  let (worker_shard, worker_thread, worker_blocked) = joined(worker);
  let (helper_shard, helper_blocked) = joined(helper);
  assert!(worker_blocked && helper_blocked);
  assert_eq!(worker_shard, Some(0));
  let mut helper_shards = [helper_shard, third_shard];
  helper_shards.sort_unstable();
  assert_eq!(helper_shards, [Some(1), Some(2)]);

  // Both loans are restored, so the helpers retire and only the worker runs.
  wait_until(|| shared.turn_counts() == (0, 0, 0, 0), "helpers to retire");
  for _ in 0..4 {
    assert_eq!(
      joined(spawned(&handle, async { thread::current().id() })),
      worker_thread
    );
  }
  drained(runtime);
}

#[test]
fn nested_block_in_place_on_the_closure_thread_runs_inline() {
  let runtime = handoff_runtime(1, 1, 2, 1);
  let job = spawned(&runtime.handle(), async {
    try_block_in_place(|| {
      let outer = thread::current().id();
      // The only slot is loaned to this thread, so a second handoff would be
      // `Full`; the nested calls run inline instead.
      let inner = try_block_in_place(|| {
        try_block_in_place(|| thread::current().id())
          .ok()
          .map(|id| (id, try_task_id()))
      });
      (outer, inner.ok().flatten(), try_task_id())
    })
    .ok()
  });
  let (outer, inner, task) =
    joined(job).unwrap_or_else(|| panic!("the outer handoff was rejected"));
  assert_eq!(inner, Some((outer, task)));
  assert!(task.is_some());
  drained(runtime);
}

#[test]
fn a_closure_panic_reacquires_the_turn_before_unwinding_further() {
  let runtime = handoff_runtime(1, 1, 4, 1);
  let shared = Arc::clone(&runtime.shared);
  let handle = runtime.handle();
  let nested = handle.clone();
  let job = spawned(&handle, async move {
    let task = try_task_id();
    let caught = panic::catch_unwind(AssertUnwindSafe(|| {
      try_block_in_place(|| {
        assert!(!cooperative_poll_active());
        injected_panic()
      })
    }));
    let cooperative_restored = cooperative_poll_active();
    let (turns, loans, restoring, _) = shared.turn_counts();
    let again = try_block_in_place(|| (!cooperative_poll_active(), 3)).ok();
    let worker_rejected = matches!(
      nested.block_on(async {}),
      Err(AsyncError::BlockOnFromWorker)
    );
    (
      caught.is_err(),
      cooperative_restored,
      try_task_id() == task,
      (turns, loans, restoring),
      again,
      worker_rejected,
    )
  });
  assert_eq!(
    joined(job),
    (true, true, true, (1, 0, 0), Some((true, 3)), true)
  );

  let propagated = spawned(&handle, async { try_block_in_place(injected_panic).ok() });
  assert!(matches!(
    wait_job(propagated),
    Err(AsyncJoinError::Panicked(_))
  ));
  assert_eq!(
    joined(spawned(&handle, async { try_block_in_place(|| 4).ok() })),
    Some(4)
  );
  drained(runtime);
}

#[test]
fn abort_during_a_closure_cleans_up_only_after_the_poll_returns() {
  let runtime = handoff_runtime(1, 1, 2, 1);
  let entered = Gate::default();
  let release = Gate::default();
  let _release_on_unwind = OpenOnDrop(release.clone());
  let dropped = Arc::new(AtomicBool::new(false));
  let job = {
    let (entered, release) = (entered.clone(), release.clone());
    let flag = DropFlag(Arc::clone(&dropped));
    spawned(&runtime.handle(), async move {
      let _flag = flag;
      let _ = try_block_in_place(|| block_until(&entered, &release));
      std::future::pending::<()>().await;
    })
  };
  assert!(entered.wait());
  job.abort();
  thread::sleep(Duration::from_millis(50));
  assert!(
    !dropped.load(Ordering::SeqCst),
    "abort dropped a task while its closure ran"
  );
  release.open();
  assert!(matches!(wait_job(job), Err(AsyncJoinError::Cancelled)));
  assert!(dropped.load(Ordering::SeqCst));
  drained(runtime);
}

#[test]
fn cancel_pending_shutdown_waits_for_the_closure_and_restores_after_close() {
  let runtime = handoff_runtime(1, 1, 2, 1);
  let handle = runtime.handle();
  let entered = Gate::default();
  let release = Gate::default();
  let _release_on_unwind = OpenOnDrop(release.clone());
  let dropped = Arc::new(AtomicBool::new(false));
  let continued = Arc::new(Mutex::new(None));
  let job = {
    let (entered, release) = (entered.clone(), release.clone());
    let flag = DropFlag(Arc::clone(&dropped));
    let continued = Arc::clone(&continued);
    spawned(&handle, async move {
      let _flag = flag;
      let _ = try_block_in_place(|| block_until(&entered, &release));
      // A second handoff in the same admitted poll, after close.
      let again = try_block_in_place(|| thread::current().id()).is_ok();
      *continued.lock().unwrap_or_else(PoisonError::into_inner) = Some(again);
      std::future::pending::<()>().await;
    })
  };
  assert!(entered.wait());
  let (done, finished) = mpsc::channel();
  thread::spawn(move || {
    let _ = done.send(runtime.shutdown(AsyncShutdown::CancelPending));
  });
  assert!(finished.recv_timeout(Duration::from_millis(100)).is_err());
  assert!(!dropped.load(Ordering::SeqCst));
  let rejected = handle.spawn(async {}).err().map(|error| error.kind);
  assert_eq!(rejected, Some(AsyncError::Closed));
  release.open();
  assert_eq!(
    finished
      .recv_timeout(DEADLINE)
      .unwrap_or_else(|_| panic!("shutdown timed out")),
    Ok(())
  );
  assert!(dropped.load(Ordering::SeqCst));
  assert_eq!(
    *continued.lock().unwrap_or_else(PoisonError::into_inner),
    Some(true)
  );
  assert!(matches!(wait_job(job), Err(AsyncJoinError::Cancelled)));
}

#[test]
fn drain_shutdown_allows_admitted_continuations_to_hand_off() {
  let runtime = handoff_runtime(1, 1, 2, 1);
  let shared = Arc::clone(&runtime.shared);
  let handle = runtime.handle();
  let entered = Gate::default();
  let release = Gate::default();
  let _release_on_unwind = OpenOnDrop(release.clone());
  let job = {
    let (entered, release) = (entered.clone(), release.clone());
    spawned(&handle, async move {
      let first = try_block_in_place(|| block_until(&entered, &release)).unwrap_or(false);
      yield_now().await;
      // A later poll turn of an admitted task, after admission closed.
      let flushes = cache::FLUSHES.get();
      let second = try_block_in_place(|| cache::FLUSHES.get() > flushes).ok();
      (first, second)
    })
  };
  assert!(entered.wait());
  let (done, finished) = mpsc::channel();
  thread::spawn(move || {
    let _ = done.send(runtime.shutdown(AsyncShutdown::Drain));
  });
  assert!(finished.recv_timeout(Duration::from_millis(100)).is_err());
  assert_eq!(
    handle.spawn(async {}).err().map(|error| error.kind),
    Some(AsyncError::Closed)
  );
  release.open();
  assert_eq!(
    finished
      .recv_timeout(DEADLINE)
      .unwrap_or_else(|_| panic!("shutdown timed out")),
    Ok(())
  );
  assert_eq!(joined(job), (true, Some(true)));
  assert_eq!(shared.turn_counts(), (0, 0, 0, 0));
}

#[test]
fn a_restoring_thread_reenters_before_queued_work() {
  let runtime = handoff_runtime(1, 1, 8, 3);
  let shared = Arc::clone(&runtime.shared);
  let handle = runtime.handle();
  let (restored_scope, busy_scope) = (own_scope(&runtime), own_scope(&runtime));
  let order = Arc::new(Mutex::new(Vec::new()));
  let record = |order: &Arc<Mutex<Vec<&'static str>>>, step| {
    order
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .push(step);
  };
  let restored_entered = Gate::default();
  let restored_release = Gate::default();
  let busy_entered = Gate::default();
  let busy_release = Gate::default();
  let _release_on_unwind = (
    OpenOnDrop(restored_release.clone()),
    OpenOnDrop(busy_release.clone()),
  );
  let restored = {
    let (entered, release, order) = (
      restored_entered.clone(),
      restored_release.clone(),
      Arc::clone(&order),
    );
    spawned(&restored_scope.handle(), async move {
      let _ = try_block_in_place(|| block_until(&entered, &release));
      record(&order, "restored");
    })
  };
  assert!(restored_entered.wait());
  // The helper takes the only dispatcher permit and holds it without a
  // handoff.
  let busy = {
    let (entered, release, order) = (
      busy_entered.clone(),
      busy_release.clone(),
      Arc::clone(&order),
    );
    spawned(&busy_scope.handle(), async move {
      let _ = block_until(&entered, &release);
      record(&order, "busy");
    })
  };
  assert!(busy_entered.wait());
  let queued = {
    let order = Arc::clone(&order);
    spawned(&handle, async move { record(&order, "queued") })
  };
  restored_release.open();
  wait_until(|| shared.turn_counts().2 == 1, "the restoration to wait");
  busy_release.open();
  joined(restored);
  joined(busy);
  joined(queued);
  assert_eq!(
    *order.lock().unwrap_or_else(PoisonError::into_inner),
    ["busy", "restored", "queued"]
  );
  drained(runtime);
}

#[test]
fn local_execution_rejects_but_an_entered_local_handle_does_not() {
  let mut local = LocalRuntime::new(LocalConfig {
    max_outstanding: 2,
    max_scopes: 1,
  })
  .unwrap_or_else(|error| panic!("local runtime failed: {error}"));
  let root = local
    .block_on(async {
      try_block_in_place(|| 1).map_err(|error| (error.kind, error.into_closure()()))
    })
    .unwrap_or_else(|error| panic!("local block_on failed: {error}"));
  assert_eq!(root, Err((BlockInPlaceErrorKind::LocalExecutor, 1)));
  let task = local
    .handle()
    .spawn_local(async { try_block_in_place(|| 2).map_err(|error| error.kind) })
    .unwrap_or_else(|error| panic!("local spawn failed: {error}"));
  assert_eq!(
    local
      .block_on(task)
      .unwrap_or_else(|error| panic!("local block_on failed: {error}"))
      .unwrap_or_else(|error| panic!("local join failed: {error}")),
    Err(BlockInPlaceErrorKind::LocalExecutor)
  );

  struct DropProbe(mpsc::Sender<Result<(), BlockInPlaceErrorKind>>);
  impl Drop for DropProbe {
    fn drop(&mut self) {
      let _ = self
        .0
        .send(try_block_in_place(|| ()).map_err(|error| error.kind));
    }
  }
  let (sent, received) = mpsc::channel();
  let probe = DropProbe(sent);
  let _pending = local
    .handle()
    .spawn_local(async move {
      let _probe = probe;
      std::future::pending::<()>().await;
    })
    .unwrap_or_else(|error| panic!("local spawn failed: {error}"));
  let entered = local.handle().enter();
  assert_eq!(try_block_in_place(|| 3).ok(), Some(3));
  drop(entered);
  drop(local);
  assert_eq!(
    received.recv_timeout(DEADLINE),
    Ok(Err(BlockInPlaceErrorKind::LocalExecutor))
  );
}

#[test]
fn a_local_runtime_nested_in_a_handed_off_closure_is_still_rejected() {
  let runtime = handoff_runtime(1, 1, 2, 1);
  let job = spawned(&runtime.handle(), async {
    try_block_in_place(|| {
      let mut local = LocalRuntime::new(LocalConfig {
        max_outstanding: 1,
        max_scopes: 1,
      })
      .unwrap_or_else(|error| panic!("local runtime failed: {error}"));
      let in_local = local
        .block_on(async { try_block_in_place(|| ()).err().map(|error| error.kind) })
        .unwrap_or_else(|error| panic!("nested local block_on failed: {error}"));
      let entered = local.handle().enter();
      let entered_only = try_block_in_place(|| 5).ok();
      drop(entered);
      drop(local);
      (in_local, entered_only, try_block_in_place(|| 6).ok())
    })
    .ok()
  });
  assert_eq!(
    joined(job),
    Some((Some(BlockInPlaceErrorKind::LocalExecutor), Some(5), Some(6)))
  );
  drained(runtime);
}

#[test]
fn borrowed_root_inline_closure_may_block_on_and_restores_identity_and_budget() {
  let runtime = handoff_runtime(1, 1, 4, 1);
  let handle = runtime.handle();
  let nested = handle.clone();
  let outcome = runtime
    .block_on(async move {
      for _ in 0..10 {
        consume_budget().await;
      }
      let before = budget_remaining();
      let caller = thread::current().id();
      let inline = try_block_in_place(|| {
        let marker_cleared = !block_on_active();
        let cooperative_suspended = !cooperative_poll_active();
        let root = nested.block_on(async {
          consume_budget().await;
          (
            try_task_id(),
            thread::current().id(),
            AsyncHandle::try_current().is_some(),
            cooperative_poll_active(),
          )
        });
        let spawned_value = nested.block_on(spawned(&nested, async { 6 }));
        (marker_cleared, cooperative_suspended, root, spawned_value)
      })
      .unwrap_or_else(|error| panic!("borrowed-root closure rejected: {error}"));
      let unwound = panic::catch_unwind(AssertUnwindSafe(|| {
        try_block_in_place(|| nested.block_on(async { injected_panic() }))
      }))
      .is_err();
      (
        before,
        budget_remaining(),
        cooperative_poll_active(),
        block_on_active(),
        try_task_id(),
        caller,
        inline,
        unwound,
        cooperative_poll_active(),
      )
    })
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
  let (
    before,
    after,
    cooperative_after_inline,
    active,
    task,
    caller,
    (cleared, cooperative_suspended, root, spawned_value),
    unwound,
    cooperative_after_unwind,
  ) = outcome;
  assert_eq!(before, 54);
  assert_eq!(after, before);
  assert!(active && cleared && cooperative_suspended && cooperative_after_inline && unwound);
  assert!(cooperative_after_unwind);
  assert_eq!(task, None);
  assert_eq!(root, Ok((None, caller, true, true)));
  assert!(matches!(spawned_value, Ok(Ok(6))));
  assert!(!block_on_active());
  drained(runtime);
}

#[test]
fn a_handed_off_worker_closure_runs_one_nested_root_and_restores_the_worker() {
  let runtime = handoff_runtime(1, 1, 4, 2);
  let nested = runtime.handle();
  let outer = own_scope(&runtime);
  let job = spawned(&outer.handle(), async move {
    for _ in 0..5 {
      consume_budget().await;
    }
    let task = try_task_id();
    let budget = budget_remaining();
    let worker_thread = thread::current().id();
    let (was_suspended, root_task, root_active, helper_thread) = try_block_in_place(|| {
      let was_suspended = !cooperative_poll_active();
      let root = nested.block_on(async { (try_task_id(), cooperative_poll_active()) });
      // The nested root awaits a task that a helper polls meanwhile.
      let helper_thread = nested.block_on(spawned(&nested, async { thread::current().id() }));
      (
        was_suspended,
        root,
        cooperative_poll_active(),
        helper_thread,
      )
    })
    .unwrap_or_else(|error| panic!("handoff rejected: {error}"));
    let rejected_again = matches!(
      nested.block_on(async {}),
      Err(AsyncError::BlockOnFromWorker)
    );
    (
      was_suspended,
      root_task,
      root_active,
      helper_thread
        .ok()
        .and_then(Result::ok)
        .map(|id| id != worker_thread),
      try_task_id() == task && task.is_some(),
      budget_remaining() == budget && budget == 59,
      cooperative_poll_active(),
      rejected_again,
    )
  });
  assert_eq!(
    joined(job),
    (
      true,
      Ok((None, true)),
      false,
      Some(true),
      true,
      true,
      true,
      true
    )
  );
  drained(runtime);
}

#[test]
fn shutdown_from_handed_off_closures_returns_would_deadlock() {
  let runtime = handoff_runtime(1, 1, 2, 1);
  let handle = runtime.handle();
  let slot = Arc::new(Mutex::new(Some(runtime)));
  let task_slot = Arc::clone(&slot);
  let job = spawned(&handle, async move {
    try_block_in_place(|| {
      let runtime = task_slot
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
      // Rejection drops the runtime here, which detaches its threads.
      runtime.map(|runtime| runtime.shutdown(AsyncShutdown::Drain))
    })
    .ok()
    .flatten()
  });
  assert_eq!(joined(job), Some(Err(AsyncError::WouldDeadlock)));
  assert!(
    slot
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .is_none()
  );

  // A helper-origin closure keeps the runtime identity too.
  let runtime = handoff_runtime(1, 2, 4, 2);
  let handle = runtime.handle();
  let holding = own_scope(&runtime);
  let release = Gate::default();
  let _release_on_unwind = OpenOnDrop(release.clone());
  let entered = Gate::default();
  let holder = {
    let (entered, release) = (entered.clone(), release.clone());
    spawned(&holding.handle(), async move {
      try_block_in_place(|| block_until(&entered, &release)).unwrap_or(false)
    })
  };
  assert!(entered.wait());
  let slot = Arc::new(Mutex::new(Some(runtime)));
  let task_slot = Arc::clone(&slot);
  let from_helper = spawned(&handle, async move {
    try_block_in_place(|| {
      let runtime = task_slot
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
      runtime.map(|runtime| runtime.shutdown(AsyncShutdown::Drain))
    })
    .ok()
    .flatten()
  });
  assert_eq!(joined(from_helper), Some(Err(AsyncError::WouldDeadlock)));
  release.open();
  assert!(joined(holder));
}

#[test]
fn dropping_the_runtime_detaches_a_blocked_closure() {
  let runtime = handoff_runtime(1, 1, 2, 1);
  let shared = Arc::clone(&runtime.shared);
  let entered = Gate::default();
  let release = Gate::default();
  let _release_on_unwind = OpenOnDrop(release.clone());
  let job = {
    let (entered, release) = (entered.clone(), release.clone());
    spawned(&runtime.handle(), async move {
      try_block_in_place(|| block_until(&entered, &release)).unwrap_or(false)
    })
  };
  assert!(entered.wait());
  let started = Instant::now();
  drop(runtime);
  assert!(started.elapsed() < Duration::from_secs(1));
  assert!(!release.is_open());
  release.open();
  assert!(joined(job));
  wait_until(
    || shared.turn_counts() == (0, 0, 0, 0),
    "detached threads to finish",
  );
}

struct PublicationProbe(Mutex<Option<mpsc::Sender<Option<bool>>>>);

impl Wake for PublicationProbe {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    let Some(sender) = self.0.lock().unwrap_or_else(PoisonError::into_inner).take() else {
      return;
    };
    let flushes = cache::FLUSHES.get();
    let handed_off = try_block_in_place(|| cache::FLUSHES.get() > flushes).ok();
    let _ = sender.send(handed_off);
  }
}

#[test]
fn a_publication_callback_may_hand_off_while_the_runtime_drains() {
  let runtime = handoff_runtime(1, 1, 2, 1);
  let entered = Gate::default();
  let release = Gate::default();
  let _release_on_unwind = OpenOnDrop(release.clone());
  let job = {
    let (entered, release) = (entered.clone(), release.clone());
    spawned(&runtime.handle(), async move {
      try_block_in_place(|| block_until(&entered, &release)).unwrap_or(false)
    })
  };
  assert!(entered.wait());
  let (sent, received) = mpsc::channel();
  let waker = Waker::from(Arc::new(PublicationProbe(Mutex::new(Some(sent)))));
  let mut job = Box::pin(job);
  assert!(
    job
      .as_mut()
      .poll(&mut Context::from_waker(&waker))
      .is_pending()
  );
  let (done, finished) = mpsc::channel();
  thread::spawn(move || {
    let _ = done.send(runtime.shutdown(AsyncShutdown::Drain));
  });
  release.open();
  assert_eq!(received.recv_timeout(DEADLINE), Ok(Some(true)));
  assert_eq!(
    finished
      .recv_timeout(DEADLINE)
      .unwrap_or_else(|_| panic!("shutdown timed out")),
    Ok(())
  );
  assert!(matches!(
    job.as_mut().poll(&mut Context::from_waker(Waker::noop())),
    Poll::Ready(Ok(true))
  ));
}

/// Counts futures inside `Future::poll`, handed-off ones included, keeping
/// the peak.
struct Counted<F> {
  inner: Pin<Box<F>>,
  polls: Arc<(AtomicUsize, AtomicUsize)>,
}

fn enter(counter: &(AtomicUsize, AtomicUsize)) {
  let now = counter.0.fetch_add(1, Ordering::SeqCst) + 1;
  counter.1.fetch_max(now, Ordering::SeqCst);
}

fn leave(counter: &(AtomicUsize, AtomicUsize)) {
  counter.0.fetch_sub(1, Ordering::SeqCst);
}

impl<F: Future> Future for Counted<F> {
  type Output = F::Output;

  fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<F::Output> {
    enter(&self.polls);
    let output = self.inner.as_mut().poll(context);
    leave(&self.polls);
    output
  }
}

#[test]
fn concurrent_handoffs_never_exceed_the_dispatcher_or_handoff_bounds() {
  const WORKERS: usize = 2;
  const HANDOFFS: usize = 2;
  let runtime = handoff_runtime(WORKERS, HANDOFFS, 32, 4);
  let shared = Arc::clone(&runtime.shared);
  let scopes: Vec<_> = (0..3)
    .map(|_| {
      runtime
        .scope_with_config(scope_config(8))
        .unwrap_or_else(|error| panic!("scope failed: {error}"))
    })
    .collect();
  let mut handles: Vec<_> = scopes.iter().map(OwnedTaskScope::handle).collect();
  handles.push(runtime.handle());
  let polls = Arc::new((AtomicUsize::new(0), AtomicUsize::new(0)));
  let closures = Arc::new((AtomicUsize::new(0), AtomicUsize::new(0)));
  let stop = Arc::new(AtomicBool::new(false));
  // The dispatcher bound is sampled from the coordinator itself: a closure
  // starts only after its permit is released, so user code cannot mark that
  // release without lagging behind a helper's next turn.
  let sampler = {
    let (shared, stop) = (Arc::clone(&shared), Arc::clone(&stop));
    thread::spawn(move || {
      while !stop.load(Ordering::SeqCst) {
        let (turns, loans, _, helpers) = shared.turn_counts();
        assert!(turns <= WORKERS && loans <= HANDOFFS && helpers <= HANDOFFS);
        thread::yield_now();
      }
    })
  };
  let mut jobs = Vec::new();
  for index in 0..24 {
    let closures_in = Arc::clone(&closures);
    let inner = async move {
      let mut handed_off = 0;
      while handed_off < 3 {
        let result = try_block_in_place(|| {
          enter(&closures_in);
          thread::sleep(Duration::from_micros(200));
          leave(&closures_in);
        });
        match result {
          Ok(()) => handed_off += 1,
          Err(error) => assert_eq!(error.kind, BlockInPlaceErrorKind::Full),
        }
        yield_now().await;
      }
      handed_off
    };
    jobs.push(spawned(
      &handles[index % handles.len()],
      Counted {
        inner: Box::pin(inner),
        polls: Arc::clone(&polls),
      },
    ));
  }
  for job in jobs {
    assert_eq!(joined(job), 3);
  }
  stop.store(true, Ordering::SeqCst);
  sampler
    .join()
    .unwrap_or_else(|_| panic!("a coordinator bound was exceeded"));
  assert!(polls.1.load(Ordering::SeqCst) <= WORKERS + HANDOFFS);
  assert!(closures.1.load(Ordering::SeqCst) <= HANDOFFS);
  assert!(closures.1.load(Ordering::SeqCst) >= 1);
  drained(runtime);
  assert_eq!(shared.turn_counts(), (0, 0, 0, 0));
}

#[test]
fn outside_any_runtime_the_closure_runs_inline() {
  let caller: ThreadId = thread::current().id();
  assert_eq!(
    try_block_in_place(|| thread::current().id()).ok(),
    Some(caller)
  );
}
