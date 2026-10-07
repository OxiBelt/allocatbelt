use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use super::{AsyncConfig, AsyncJoinError, AsyncRuntime, AsyncScopeConfig, AsyncShutdown};

fn runtime(workers: usize, max_outstanding: usize, max_scopes: usize) -> AsyncRuntime {
  AsyncRuntime::new(AsyncConfig {
    workers,
    max_outstanding,
    max_scopes,
  })
  .unwrap_or_else(|error| panic!("runtime construction failed: {error}"))
}

fn wait_until(predicate: impl Fn() -> bool, message: &str) {
  let deadline = Instant::now() + Duration::from_secs(3);
  while !predicate() {
    assert!(Instant::now() < deadline, "timed out waiting for {message}");
    std::thread::yield_now();
  }
}

struct ReleaseGate(Arc<(Mutex<bool>, Condvar)>);

impl Drop for ReleaseGate {
  fn drop(&mut self) {
    let (lock, cv) = &*self.0;
    *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
    cv.notify_all();
  }
}

struct ThreadWake(std::thread::Thread);

impl Wake for ThreadWake {
  fn wake(self: Arc<Self>) {
    self.0.unpark();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.unpark();
  }
}

fn block_on<F: Future>(future: F) -> F::Output {
  let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
  let mut context = Context::from_waker(&waker);
  let mut future = std::pin::pin!(future);
  loop {
    if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
      return output;
    }
    std::thread::park_timeout(Duration::from_secs(2));
  }
}

struct WakeDuringPoll {
  polls: Arc<AtomicUsize>,
}

impl Future for WakeDuringPoll {
  type Output = usize;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let count = self.polls.fetch_add(1, Ordering::SeqCst);
    if count == 0 {
      cx.waker().wake_by_ref();
      cx.waker().wake_by_ref();
      cx.waker().wake_by_ref();
      Poll::Pending
    } else {
      Poll::Ready(count + 1)
    }
  }
}

#[test]
fn wakes_during_poll_are_coalesced_without_losing_progress() {
  let runtime = runtime(2, 8, 4);
  let polls = Arc::new(AtomicUsize::new(0));
  let job = runtime
    .handle()
    .spawn(WakeDuringPoll {
      polls: Arc::clone(&polls),
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  assert!(matches!(block_on(job), Ok(2)));
  assert_eq!(polls.load(Ordering::SeqCst), 2);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct NoConcurrentPoll {
  active: Arc<AtomicBool>,
  polls: Arc<AtomicUsize>,
}

impl Future for NoConcurrentPoll {
  type Output = ();

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
    assert!(!self.active.swap(true, Ordering::SeqCst), "concurrent poll");
    let count = self.polls.fetch_add(1, Ordering::SeqCst);
    self.active.store(false, Ordering::SeqCst);
    if count < 20 {
      cx.waker().wake_by_ref();
      Poll::Pending
    } else {
      Poll::Ready(())
    }
  }
}

#[test]
fn a_task_is_never_polled_concurrently() {
  let runtime = runtime(4, 8, 4);
  let active = Arc::new(AtomicBool::new(false));
  let polls = Arc::new(AtomicUsize::new(0));
  let job = runtime
    .handle()
    .spawn(NoConcurrentPoll {
      active: Arc::clone(&active),
      polls: Arc::clone(&polls),
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  assert!(matches!(block_on(job), Ok(())));
  assert_eq!(polls.load(Ordering::SeqCst), 21);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct Gate {
  gate: Arc<(Mutex<bool>, Condvar)>,
  started: Arc<(Mutex<bool>, Condvar)>,
}

impl Future for Gate {
  type Output = ();

  fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
    let (started_lock, started_cv) = &*self.started;
    *started_lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
    started_cv.notify_all();
    let (gate_lock, gate_cv) = &*self.gate;
    let mut ready = gate_lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*ready {
      ready = gate_cv.wait(ready).unwrap_or_else(|e| e.into_inner());
    }
    Poll::Ready(())
  }
}

#[test]
fn abort_before_start_drops_future_on_a_worker_and_publishes_cancelled() {
  let runtime = runtime(1, 4, 2);
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let first = runtime
    .handle()
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  let dropped = Arc::new(AtomicBool::new(false));
  struct DropMark(Arc<AtomicBool>);
  impl Future for DropMark {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for DropMark {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }
  let second = runtime
    .handle()
    .spawn(DropMark(Arc::clone(&dropped)))
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  let control = second.abort_handle();
  assert!(!second.is_finished());
  let external = control.clone();
  std::thread::spawn(move || external.abort()).join().unwrap();
  assert!(!control.is_finished());
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(block_on(second), Err(AsyncJoinError::Cancelled)));
  assert!(control.is_finished());
  assert!(dropped.load(Ordering::SeqCst));
  assert!(matches!(block_on(first), Ok(())));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn full_admission_returns_the_original_future() {
  let runtime = runtime(1, 1, 1);
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let first = runtime
    .handle()
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  struct DropMark(Arc<AtomicBool>);
  impl Future for DropMark {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for DropMark {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }
  let dropped = Arc::new(AtomicBool::new(false));
  let rejected = runtime
    .handle()
    .spawn(DropMark(Arc::clone(&dropped)))
    .err()
    .unwrap_or_else(|| panic!("full runtime admitted another task"));
  assert_eq!(rejected.kind, super::AsyncError::Full);
  let returned = rejected.into_future();
  assert!(!dropped.load(Ordering::SeqCst));
  drop(returned);
  assert!(dropped.load(Ordering::SeqCst));
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(block_on(first), Ok(())));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct SubmitOnWake {
  handle: super::AsyncHandle,
  admitted: Arc<AtomicBool>,
}

impl Wake for SubmitOnWake {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    if let Ok(job) = self.handle.spawn(async {}) {
      self.admitted.store(true, Ordering::SeqCst);
      drop(job);
    }
  }
}

#[test]
fn scheduler_slot_is_released_before_join_waker_runs() {
  let runtime = runtime(1, 1, 1);
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let mut job = runtime
    .handle()
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  let admitted = Arc::new(AtomicBool::new(false));
  let waker = Waker::from(Arc::new(SubmitOnWake {
    handle: runtime.handle(),
    admitted: Arc::clone(&admitted),
  }));
  let mut context = Context::from_waker(&waker);
  assert!(matches!(
    Pin::new(&mut job).poll(&mut context),
    Poll::Pending
  ));
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  let deadline = Instant::now() + Duration::from_secs(2);
  while !admitted.load(Ordering::SeqCst) && Instant::now() < deadline {
    std::thread::yield_now();
  }
  assert!(admitted.load(Ordering::SeqCst));
  let poll_waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
  let mut context = Context::from_waker(&poll_waker);
  assert!(matches!(
    Pin::new(&mut job).poll(&mut context),
    Poll::Ready(Ok(()))
  ));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct PanicWake(Arc<AtomicBool>);

impl Wake for PanicWake {
  fn wake(self: Arc<Self>) {
    self.wake_by_ref();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.0.store(true, Ordering::SeqCst);
    panic!("join waker panic");
  }
}

#[test]
fn panicking_join_waker_does_not_kill_worker() {
  let runtime = runtime(1, 4, 2);
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let mut job = runtime
    .handle()
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  let called = Arc::new(AtomicBool::new(false));
  let waker = Waker::from(Arc::new(PanicWake(Arc::clone(&called))));
  let mut context = Context::from_waker(&waker);
  assert!(matches!(
    Pin::new(&mut job).poll(&mut context),
    Poll::Pending
  ));
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  let deadline = Instant::now() + Duration::from_secs(2);
  while !called.load(Ordering::SeqCst) && Instant::now() < deadline {
    std::thread::yield_now();
  }
  assert!(called.load(Ordering::SeqCst));
  let poll_waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
  let mut context = Context::from_waker(&poll_waker);
  assert!(matches!(
    Pin::new(&mut job).poll(&mut context),
    Poll::Ready(Ok(()))
  ));
  let next = runtime
    .handle()
    .spawn(async { 19usize })
    .unwrap_or_else(|e| panic!("worker died after waker panic: {e}"));
  assert!(matches!(block_on(next), Ok(19)));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct PanicDrop(Arc<AtomicBool>);

impl Drop for PanicDrop {
  fn drop(&mut self) {
    self.0.store(true, Ordering::SeqCst);
    panic!("user destructor panic");
  }
}

#[test]
fn detached_panicking_outputs_and_panic_payloads_do_not_kill_worker() {
  let runtime = runtime(1, 8, 2);
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let blocker = runtime
    .handle()
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  let output_dropped = Arc::new(AtomicBool::new(false));
  let output = Arc::clone(&output_dropped);
  let detached_output = runtime
    .handle()
    .spawn(async move { PanicDrop(output) })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  drop(detached_output);

  let payload_dropped = Arc::new(AtomicBool::new(false));
  let payload = Arc::clone(&payload_dropped);
  let detached_panic = runtime
    .handle()
    .spawn(async move {
      std::panic::panic_any(PanicDrop(payload));
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  drop(detached_panic);

  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(block_on(blocker), Ok(())));
  let deadline = Instant::now() + Duration::from_secs(2);
  while (!output_dropped.load(Ordering::SeqCst) || !payload_dropped.load(Ordering::SeqCst))
    && Instant::now() < deadline
  {
    std::thread::yield_now();
  }
  assert!(output_dropped.load(Ordering::SeqCst));
  assert!(payload_dropped.load(Ordering::SeqCst));
  let next = runtime
    .handle()
    .spawn(async { 23usize })
    .unwrap_or_else(|e| panic!("worker died after destructor panic: {e}"));
  assert!(matches!(block_on(next), Ok(23)));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct AbortRace {
  gate: Arc<(Mutex<bool>, Condvar)>,
  started: Arc<(Mutex<bool>, Condvar)>,
  waker: Arc<Mutex<Option<Waker>>>,
  dropped: Arc<AtomicBool>,
}

impl Future for AbortRace {
  type Output = ();

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
    *self.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
    let (started_lock, started_cv) = &*self.started;
    *started_lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
    started_cv.notify_all();
    let (gate_lock, gate_cv) = &*self.gate;
    let mut ready = gate_lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*ready {
      ready = gate_cv.wait(ready).unwrap_or_else(|e| e.into_inner());
    }
    Poll::Pending
  }
}

impl Drop for AbortRace {
  fn drop(&mut self) {
    self.dropped.store(true, Ordering::SeqCst);
  }
}

#[test]
fn abort_during_poll_is_cleaned_after_that_poll_returns() {
  let runtime = runtime(1, 4, 2);
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let task_waker = Arc::new(Mutex::new(None));
  let dropped = Arc::new(AtomicBool::new(false));
  let job = runtime
    .handle()
    .spawn(AbortRace {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
      waker: Arc::clone(&task_waker),
      dropped: Arc::clone(&dropped),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  task_waker
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .as_ref()
    .unwrap_or_else(|| panic!("task did not publish its waker"))
    .wake_by_ref();
  job.abort();
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(block_on(job), Err(AsyncJoinError::Cancelled)));
  assert!(dropped.load(Ordering::SeqCst));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct RetainWaker {
  retained: Arc<Mutex<Option<Waker>>>,
  dropped: Arc<AtomicBool>,
}

impl Future for RetainWaker {
  type Output = ();

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
    *self.retained.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
    Poll::Ready(())
  }
}

impl Drop for RetainWaker {
  fn drop(&mut self) {
    self.dropped.store(true, Ordering::SeqCst);
  }
}

#[test]
fn retained_waker_does_not_keep_completed_future_alive() {
  let runtime = runtime(1, 4, 2);
  let retained = Arc::new(Mutex::new(None));
  let dropped = Arc::new(AtomicBool::new(false));
  let job = runtime
    .handle()
    .spawn(RetainWaker {
      retained: Arc::clone(&retained),
      dropped: Arc::clone(&dropped),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  assert!(matches!(block_on(job), Ok(())));
  assert!(dropped.load(Ordering::SeqCst));
  assert!(retained.lock().unwrap_or_else(|e| e.into_inner()).is_some());
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

struct WakeCount {
  polls: Arc<AtomicUsize>,
  current: Arc<Mutex<Option<Waker>>>,
}

impl Future for WakeCount {
  type Output = usize;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
    *self.current.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
    let count = self.polls.fetch_add(1, Ordering::SeqCst);
    if count == 0 {
      Poll::Pending
    } else {
      Poll::Ready(count + 1)
    }
  }
}

#[test]
fn stale_waker_from_reused_slot_cannot_wake_the_new_generation() {
  let runtime = runtime(1, 1, 1);
  let stale = Arc::new(Mutex::new(None));
  let first = runtime
    .handle()
    .spawn(RetainWaker {
      retained: Arc::clone(&stale),
      dropped: Arc::new(AtomicBool::new(false)),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  assert!(matches!(block_on(first), Ok(())));
  let stale_waker = stale
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .as_ref()
    .cloned()
    .unwrap_or_else(|| panic!("first task did not retain its waker"));

  let polls = Arc::new(AtomicUsize::new(0));
  let current = Arc::new(Mutex::new(None));
  let second = runtime
    .handle()
    .spawn(WakeCount {
      polls: Arc::clone(&polls),
      current: Arc::clone(&current),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  let deadline = Instant::now() + Duration::from_secs(2);
  while polls.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
    std::thread::yield_now();
  }
  assert_eq!(polls.load(Ordering::SeqCst), 1);
  stale_waker.wake_by_ref();
  std::thread::sleep(Duration::from_millis(10));
  assert_eq!(polls.load(Ordering::SeqCst), 1);
  current
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .take()
    .unwrap_or_else(|| panic!("second task did not retain its waker"))
    .wake();
  assert!(matches!(block_on(second), Ok(2)));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn ready_queue_rotates_fairly_between_scopes() {
  let runtime = runtime(1, 16, 3);
  let first_scope = runtime
    .scope()
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let second_scope = runtime
    .scope()
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let blocker = runtime
    .handle()
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  let order = Arc::new(Mutex::new(Vec::new()));
  let mut jobs = Vec::new();
  for index in 0..3 {
    let order_a = Arc::clone(&order);
    jobs.push(
      first_scope
        .spawn(async move {
          order_a.lock().unwrap_or_else(|e| e.into_inner()).push('A');
          index
        })
        .unwrap_or_else(|e| panic!("spawn failed: {e}")),
    );
    let order_b = Arc::clone(&order);
    jobs.push(
      second_scope
        .spawn(async move {
          order_b.lock().unwrap_or_else(|e| e.into_inner()).push('B');
          index
        })
        .unwrap_or_else(|e| panic!("spawn failed: {e}")),
    );
  }
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(block_on(blocker), Ok(())));
  for job in jobs {
    let _ = block_on(job);
  }
  let order = order.lock().unwrap_or_else(|e| e.into_inner()).clone();
  assert_eq!(order, ['A', 'B', 'A', 'B', 'A', 'B']);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn saturated_scope_preserves_fifo_and_cancellation_leapfrogs_queued_work() {
  let runtime = runtime(2, 8, 4);
  let limited = runtime
    .scope_with_config(AsyncScopeConfig {
      max_active_polls: 1,
    })
    .unwrap_or_else(|e| panic!("limited scope failed: {e}"));
  let other = runtime
    .scope()
    .unwrap_or_else(|e| panic!("other scope failed: {e}"));
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let _release_gate = ReleaseGate(Arc::clone(&gate));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let blocker = limited
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("blocker spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  assert_eq!(limited.snapshot().active_polls, 1);
  assert_eq!(limited.snapshot().max_active_polls, 1);

  let order = Arc::new(Mutex::new(Vec::new()));
  let head_order = Arc::clone(&order);
  let head = limited
    .spawn(async move {
      head_order.lock().unwrap_or_else(|e| e.into_inner()).push(1);
    })
    .unwrap_or_else(|e| panic!("head spawn failed: {e}"));
  let tail_order = Arc::clone(&order);
  let tail = limited
    .spawn(async move {
      tail_order.lock().unwrap_or_else(|e| e.into_inner()).push(2);
    })
    .unwrap_or_else(|e| panic!("tail spawn failed: {e}"));

  struct DropMark(Arc<AtomicBool>);
  impl Future for DropMark {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for DropMark {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }
  let dropped = Arc::new(AtomicBool::new(false));
  let cancelled = limited
    .spawn(DropMark(Arc::clone(&dropped)))
    .unwrap_or_else(|e| panic!("cancelled spawn failed: {e}"));

  let other_ran = Arc::new(AtomicBool::new(false));
  let other_flag = Arc::clone(&other_ran);
  let independent = other
    .spawn(async move {
      other_flag.store(true, Ordering::SeqCst);
    })
    .unwrap_or_else(|e| panic!("other spawn failed: {e}"));
  wait_until(|| other_ran.load(Ordering::SeqCst), "other scope dispatch");
  assert!(order.lock().unwrap_or_else(|e| e.into_inner()).is_empty());

  cancelled.abort_handle().abort();
  wait_until(
    || dropped.load(Ordering::SeqCst),
    "queued cancellation cleanup",
  );
  assert!(matches!(
    block_on(cancelled),
    Err(AsyncJoinError::Cancelled)
  ));
  assert!(order.lock().unwrap_or_else(|e| e.into_inner()).is_empty());

  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(block_on(blocker), Ok(())));
  assert!(matches!(block_on(head), Ok(())));
  assert!(matches!(block_on(tail), Ok(())));
  assert!(matches!(block_on(independent), Ok(())));
  assert_eq!(*order.lock().unwrap_or_else(|e| e.into_inner()), [1, 2]);
  assert_eq!(limited.snapshot().active_polls, 0);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn idle_pending_abort_gets_a_queue_token_and_invalid_poll_limits_reject() {
  assert!(matches!(
    runtime(1, 2, 2).scope_with_config(AsyncScopeConfig {
      max_active_polls: 0
    }),
    Err(super::AsyncError::InvalidConfig)
  ));
  let runtime = runtime(1, 2, 2);
  let scope = runtime
    .scope_with_config(AsyncScopeConfig {
      max_active_polls: 1,
    })
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let polls = Arc::new(AtomicUsize::new(0));
  let observed = Arc::clone(&polls);
  let job = scope
    .spawn(std::future::poll_fn(move |_cx| {
      observed.fetch_add(1, Ordering::SeqCst);
      Poll::<()>::Pending
    }))
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  wait_until(|| polls.load(Ordering::SeqCst) == 1, "first pending poll");
  let sentinel_ran = Arc::new(AtomicBool::new(false));
  let sentinel_flag = Arc::clone(&sentinel_ran);
  let sentinel = scope
    .spawn(async move {
      sentinel_flag.store(true, Ordering::SeqCst);
    })
    .unwrap_or_else(|e| panic!("sentinel spawn failed: {e}"));
  assert!(matches!(block_on(sentinel), Ok(())));
  assert!(sentinel_ran.load(Ordering::SeqCst));
  job.abort_handle().abort();
  assert!(matches!(block_on(job), Err(AsyncJoinError::Cancelled)));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn closing_a_quota_blocked_scope_reactivates_queued_cancellation() {
  let runtime = runtime(2, 4, 2);
  let scope = runtime
    .scope_with_config(AsyncScopeConfig {
      max_active_polls: 1,
    })
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let _release_gate = ReleaseGate(Arc::clone(&gate));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let blocker = scope
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("blocker spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  let dropped = Arc::new(AtomicBool::new(false));
  struct DropMark(Arc<AtomicBool>);
  impl Future for DropMark {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for DropMark {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }
  let queued = scope
    .spawn(DropMark(Arc::clone(&dropped)))
    .unwrap_or_else(|e| panic!("queued spawn failed: {e}"));
  let close = scope.close();
  wait_until(
    || dropped.load(Ordering::SeqCst),
    "scope-close cancellation bypass",
  );
  assert!(matches!(block_on(queued), Err(AsyncJoinError::Cancelled)));
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(block_on(blocker), Ok(())));
  assert_eq!(block_on(close), ());
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn cancel_pending_shutdown_reactivates_quota_blocked_work() {
  let runtime = runtime(2, 4, 3);
  let scope = runtime
    .scope_with_config(AsyncScopeConfig {
      max_active_polls: 1,
    })
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let _release_gate = ReleaseGate(Arc::clone(&gate));
  let started = Arc::new((Mutex::new(false), Condvar::new()));
  let blocker = scope
    .spawn(Gate {
      gate: Arc::clone(&gate),
      started: Arc::clone(&started),
    })
    .unwrap_or_else(|e| panic!("blocker spawn failed: {e}"));
  {
    let (lock, cv) = &*started;
    let mut value = lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*value {
      value = cv.wait(value).unwrap_or_else(|e| e.into_inner());
    }
  }
  let dropped = Arc::new(AtomicBool::new(false));
  struct DropMark(Arc<AtomicBool>);
  impl Future for DropMark {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for DropMark {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }
  let queued = scope
    .spawn(DropMark(Arc::clone(&dropped)))
    .unwrap_or_else(|e| panic!("queued spawn failed: {e}"));
  let release_gate = Arc::clone(&gate);
  let dropped_signal = Arc::clone(&dropped);
  let releaser = std::thread::spawn(move || {
    let _release_on_unwind = ReleaseGate(Arc::clone(&release_gate));
    wait_until(
      || dropped_signal.load(Ordering::SeqCst),
      "shutdown cancellation dispatch",
    );
    let (lock, cv) = &*release_gate;
    *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
    cv.notify_all();
  });
  runtime
    .shutdown(AsyncShutdown::CancelPending)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
  releaser
    .join()
    .unwrap_or_else(|_| panic!("gate releaser panicked"));
  assert!(matches!(block_on(queued), Err(AsyncJoinError::Cancelled)));
  assert!(matches!(block_on(blocker), Ok(())));
}

#[test]
fn poll_quota_releases_before_a_panicking_future_destructor() {
  let runtime = runtime(2, 4, 2);
  let scope = runtime
    .scope_with_config(AsyncScopeConfig {
      max_active_polls: 1,
    })
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let drop_gate = Arc::new((Mutex::new(false), Condvar::new()));
  let _release_drop_gate = ReleaseGate(Arc::clone(&drop_gate));
  let drop_started = Arc::new(AtomicBool::new(false));
  struct PanicOnPoll {
    gate: Arc<(Mutex<bool>, Condvar)>,
    started: Arc<AtomicBool>,
  }
  impl Future for PanicOnPoll {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      panic!("expected poll panic");
    }
  }
  impl Drop for PanicOnPoll {
    fn drop(&mut self) {
      self.started.store(true, Ordering::SeqCst);
      let (lock, cv) = &*self.gate;
      let mut released = lock.lock().unwrap_or_else(|e| e.into_inner());
      while !*released {
        released = cv.wait(released).unwrap_or_else(|e| e.into_inner());
      }
    }
  }
  let panicked = scope
    .spawn(PanicOnPoll {
      gate: Arc::clone(&drop_gate),
      started: Arc::clone(&drop_started),
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  wait_until(
    || drop_started.load(Ordering::SeqCst),
    "panicking future destructor",
  );

  let successor_ran = Arc::new(AtomicBool::new(false));
  let flag = Arc::clone(&successor_ran);
  let successor = scope
    .spawn(async move {
      flag.store(true, Ordering::SeqCst);
    })
    .unwrap_or_else(|e| panic!("successor spawn failed: {e}"));
  wait_until(
    || successor_ran.load(Ordering::SeqCst),
    "successor poll during cleanup",
  );

  let (lock, cv) = &*drop_gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  assert!(matches!(
    block_on(panicked),
    Err(AsyncJoinError::Panicked(_))
  ));
  assert!(matches!(block_on(successor), Ok(())));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn panic_is_published_and_dropping_join_detaches() {
  let runtime = runtime(2, 8, 4);
  let panicked = runtime.handle().spawn(async {
    panic!("task panic");
  });
  let panicked = panicked.unwrap_or_else(|e| panic!("spawn failed: {e}"));
  assert!(matches!(
    block_on(panicked),
    Err(AsyncJoinError::Panicked(_))
  ));
  let ran = Arc::new(AtomicBool::new(false));
  let flag = Arc::clone(&ran);
  drop(
    runtime
      .handle()
      .spawn(async move {
        flag.store(true, Ordering::SeqCst);
      })
      .unwrap_or_else(|e| panic!("spawn failed: {e}")),
  );
  let deadline = Instant::now() + Duration::from_secs(2);
  while !ran.load(Ordering::SeqCst) && Instant::now() < deadline {
    std::thread::yield_now();
  }
  assert!(ran.load(Ordering::SeqCst));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn scope_drop_cancels_and_shutdown_from_worker_is_rejected() {
  let runtime = Arc::new(runtime(1, 8, 3));
  let scope = runtime
    .scope()
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let dropped = Arc::new(AtomicBool::new(false));
  struct Never(Arc<AtomicBool>);
  impl Future for Never {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for Never {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }
  let job = scope
    .spawn(Never(Arc::clone(&dropped)))
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  block_on(scope.close());
  assert!(matches!(block_on(job), Err(AsyncJoinError::Cancelled)));
  assert!(dropped.load(Ordering::SeqCst));
  let runtime_slot = Arc::new(Mutex::new(Some(
    Arc::try_unwrap(runtime).unwrap_or_else(|_| panic!("runtime still shared")),
  )));
  let handle = runtime_slot
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .as_ref()
    .map(AsyncRuntime::handle)
    .unwrap_or_else(|| panic!("runtime missing"));
  let worker_slot = Arc::clone(&runtime_slot);
  let worker_job = handle
    .spawn(async move {
      let runtime = worker_slot
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .unwrap_or_else(|| panic!("runtime missing"));
      runtime.shutdown(AsyncShutdown::Drain)
    })
    .unwrap_or_else(|e| panic!("spawn failed: {e}"));
  assert!(matches!(
    block_on(worker_job),
    Ok(Err(super::AsyncError::WouldDeadlock))
  ));
}

struct ManyGate {
  gate: Arc<(Mutex<bool>, Condvar)>,
  started: Arc<(Mutex<usize>, Condvar)>,
}

impl Future for ManyGate {
  type Output = ();

  fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
    let (started_lock, started_cv) = &*self.started;
    *started_lock.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    started_cv.notify_all();
    let (gate_lock, gate_cv) = &*self.gate;
    let mut ready = gate_lock.lock().unwrap_or_else(|e| e.into_inner());
    while !*ready {
      ready = gate_cv.wait(ready).unwrap_or_else(|e| e.into_inner());
    }
    Poll::Ready(())
  }
}

#[test]
fn concurrent_last_scope_children_release_scope_capacity() {
  let runtime = runtime(2, 8, 2);
  let scope = runtime
    .scope()
    .unwrap_or_else(|e| panic!("scope failed: {e}"));
  let gate = Arc::new((Mutex::new(false), Condvar::new()));
  let started = Arc::new((Mutex::new(0usize), Condvar::new()));
  for _ in 0..2 {
    let job = scope
      .spawn(ManyGate {
        gate: Arc::clone(&gate),
        started: Arc::clone(&started),
      })
      .unwrap_or_else(|e| panic!("spawn failed: {e}"));
    drop(job);
  }
  {
    let (lock, cv) = &*started;
    let mut count = lock.lock().unwrap_or_else(|e| e.into_inner());
    while *count < 2 {
      count = cv.wait(count).unwrap_or_else(|e| e.into_inner());
    }
  }
  let close = scope.close();
  let (lock, cv) = &*gate;
  *lock.lock().unwrap_or_else(|e| e.into_inner()) = true;
  cv.notify_all();
  block_on(close);
  let replacement = runtime
    .scope()
    .unwrap_or_else(|e| panic!("scope slot leaked after concurrent cleanup: {e}"));
  drop(replacement);
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|e| panic!("shutdown failed: {e}"));
}

#[test]
fn block_on_accepts_borrowed_non_send_root_future() {
  use super::AsyncHandle;

  let runtime = runtime(1, 4, 2);
  let local = std::cell::Cell::new(0);
  let result = runtime
    .block_on(async {
      local.set(41);
      (local.get() + 1, AsyncHandle::try_current().is_some())
    })
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
  assert_eq!(result, (42, true));
  assert!(AsyncHandle::try_current().is_none());
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn block_on_parks_while_workers_progress_and_wake_it() {
  let runtime = runtime(2, 4, 2);
  let job = runtime
    .handle()
    .spawn(async {
      std::thread::sleep(Duration::from_millis(10));
      42
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  let joined = runtime
    .block_on(job)
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
  assert!(matches!(joined, Ok(42)));
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn nested_block_on_returns_error_and_entered_context_restores_after_unwind() {
  use super::AsyncHandle;

  let first = runtime(1, 4, 2);
  let second = runtime(1, 4, 2);
  let first_handle = first.handle();
  let second_handle = second.handle();
  assert!(AsyncHandle::try_current().is_none());
  {
    let _outer = first_handle.enter();
    assert!(Arc::ptr_eq(
      &AsyncHandle::current().shared,
      &first_handle.shared
    ));
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let _inner = second_handle.enter();
      assert!(Arc::ptr_eq(
        &AsyncHandle::current().shared,
        &second_handle.shared
      ));
      panic!("exercise context guard unwind");
    }));
    assert!(panic.is_err());
    assert!(Arc::ptr_eq(
      &AsyncHandle::current().shared,
      &first_handle.shared
    ));
  }
  assert!(AsyncHandle::try_current().is_none());

  let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    let _ = first.block_on(async { panic!("exercise block_on unwind guards") });
  }));
  assert!(panic.is_err());
  assert!(AsyncHandle::try_current().is_none());
  assert!(matches!(first.block_on(async { 3 }), Ok(3)));

  let nested = first
    .block_on(async { second_handle.block_on(async { 7 }) })
    .unwrap_or_else(|error| panic!("outer block_on failed: {error}"));
  assert!(matches!(nested, Err(super::AsyncError::NestedBlockOn)));
  first
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  second
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn entered_context_guards_restore_when_dropped_out_of_order() {
  use super::AsyncHandle;

  let first_runtime = runtime(1, 4, 2);
  let second_runtime = runtime(1, 4, 2);
  let first = first_runtime.handle();
  let second = second_runtime.handle();
  let first_guard = first.enter();
  let second_guard = second.enter();
  drop(first_guard);
  assert!(Arc::ptr_eq(&AsyncHandle::current().shared, &second.shared));
  drop(second_guard);
  assert!(AsyncHandle::try_current().is_none());
  first_runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  second_runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn block_on_can_return_an_enter_guard_without_resurrecting_the_root_context() {
  use super::AsyncHandle;

  let runtime = runtime(1, 2, 1);
  let handle = runtime.handle();
  let guard = runtime
    .block_on(async move { handle.enter() })
    .unwrap_or_else(|error| panic!("block_on failed: {error}"));
  assert!(Arc::ptr_eq(
    &AsyncHandle::current().shared,
    &runtime.handle().shared
  ));
  drop(guard);
  assert!(AsyncHandle::try_current().is_none());
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn worker_context_is_entered_and_block_on_is_rejected_there() {
  use super::AsyncHandle;

  let primary_runtime = runtime(1, 4, 2);
  let other_runtime = runtime(1, 4, 2);
  let handle = primary_runtime.handle();
  let other_handle = other_runtime.handle();
  let worker_handle = handle.clone();
  let block_on_handle = other_handle.clone();
  let job = handle
    .spawn(async move {
      (
        AsyncHandle::try_current()
          .is_some_and(|current| Arc::ptr_eq(&current.shared, &worker_handle.shared)),
        block_on_handle.block_on(async { 9 }),
      )
    })
    .unwrap_or_else(|error| panic!("spawn failed: {error}"));
  let result = block_on(job).unwrap_or_else(|error| panic!("join failed: {error}"));
  assert!(result.0);
  assert!(matches!(
    result.1,
    Err(super::AsyncError::BlockOnFromWorker)
  ));
  primary_runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  other_runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
}

#[test]
fn a_handle_retained_after_shutdown_rejects_spawn_and_returns_future() {
  let runtime = runtime(1, 2, 1);
  let handle = runtime.handle();
  runtime
    .shutdown(AsyncShutdown::Drain)
    .unwrap_or_else(|error| panic!("shutdown failed: {error}"));
  let error = handle
    .spawn(async { 19 })
    .err()
    .unwrap_or_else(|| panic!("closed handle unexpectedly admitted a task"));
  assert!(matches!(error.kind, super::AsyncError::Closed));
  assert_eq!(block_on(error.into_future()), 19);
}
