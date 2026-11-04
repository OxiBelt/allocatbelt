use super::super::super::thread_options::{AsyncThreadOptions, AsyncThreadRole};
use super::super::super::{
  AsyncJoinError, AsyncRuntime, AsyncRuntimeOptions, AsyncScopeConfig, AsyncShutdown,
};
use super::*;
use std::pin::Pin;
use std::sync::mpsc;
use std::task::Poll;
use std::time::{Duration, Instant};

use super::super::super::park_spin::Policy;

thread_local! {
  static TEST_SPIN_POLICY: std::cell::Cell<Policy> = std::cell::Cell::new(Policy::default());
  static TEST_SEARCH_CAP: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

fn spin_options() -> AsyncRuntimeOptions {
  AsyncRuntimeOptions {
    park_spin: TEST_SPIN_POLICY.get(),
    ..AsyncRuntimeOptions::new()
  }
}

fn each_spin_configuration(mut test: impl FnMut()) {
  for rounds in [0, 128, 4096] {
    TEST_SPIN_POLICY.set(Policy {
      rounds,
      max_spinners: Some(1),
      max_searchers: TEST_SEARCH_CAP.get(),
    });
    test();
  }
  TEST_SPIN_POLICY.set(Policy::default());
}

/// Runs `test` with the default search limit, a cap of one and unlimited entry.
fn each_search_configuration(mut test: impl FnMut()) {
  for cap in [None, Some(1), Some(usize::MAX)] {
    TEST_SEARCH_CAP.set(cap);
    test();
  }
  TEST_SEARCH_CAP.set(None);
}

/// Binds the steal cap at half of `workers`, rounded up, for this test thread.
fn half_search_cap(workers: usize) {
  TEST_SPIN_POLICY.set(Policy {
    max_searchers: Some(workers.div_ceil(2)),
    ..Policy::default()
  });
}

fn config(workers: usize, tasks: usize) -> AsyncConfig {
  AsyncConfig {
    workers,
    max_outstanding: tasks,
    max_scopes: 4,
  }
}
fn runtime(workers: usize, tasks: usize) -> AsyncRuntime {
  AsyncRuntime::new_with_options(config(workers, tasks), spin_options()).unwrap()
}
fn shared(config: AsyncConfig) -> (Arc<Shared>, ScopeRef) {
  shared_with_handoffs(config, 0)
}
fn shared_with_handoffs(config: AsyncConfig, handoffs: usize) -> (Arc<Shared>, ScopeRef) {
  shared_with(config, handoffs, AsyncThreadOptions::new())
}
// The metrics view holds a weak owner of the scheduler, so thread options
// are supplied at construction rather than through `Arc::get_mut`.
fn shared_with_options(
  config: AsyncConfig,
  options: AsyncThreadOptions,
) -> (Arc<Shared>, ScopeRef) {
  shared_with(config, 0, options)
}
fn shared_with(
  config: AsyncConfig,
  handoffs: usize,
  options: AsyncThreadOptions,
) -> (Arc<Shared>, ScopeRef) {
  let metrics = RuntimeMetrics::try_new(
    config.workers,
    super::super::super::thread_contexts(config.workers, handoffs),
    config.workers + handoffs,
    None,
  )
  .unwrap();
  Shared::new(
    config,
    handoffs,
    None,
    super::super::super::ControlledThreadOptions::unbounded(options),
    metrics,
    TEST_SPIN_POLICY.get(),
  )
  .unwrap()
}
fn engine(shared: &Shared) -> &Distributed {
  &shared.distributed
}
fn wait(mut predicate: impl FnMut() -> bool) {
  let deadline = Instant::now() + Duration::from_secs(30);
  while !predicate() {
    assert!(Instant::now() < deadline, "progress deadline");
    std::thread::yield_now();
  }
}
fn finish<T>(mut job: AsyncJob<T>) -> Result<T, AsyncJoinError> {
  wait(|| job.is_finished());
  match Pin::new(&mut job).poll(&mut Context::from_waker(Waker::noop())) {
    Poll::Ready(result) => result,
    Poll::Pending => panic!("finished job pending"),
  }
}
fn shutdown(runtime: AsyncRuntime, mode: AsyncShutdown) {
  let (tx, rx) = mpsc::channel();
  let thread = std::thread::spawn(move || tx.send(runtime.shutdown(mode)).unwrap());
  rx.recv_timeout(Duration::from_secs(30)).unwrap().unwrap();
  thread.join().unwrap();
}
fn join_worker<T>(thread: std::thread::JoinHandle<T>) -> T {
  wait(|| thread.is_finished());
  thread.join().unwrap()
}
fn lane_sleeping(shared: &Shared, seat: usize) -> bool {
  let _queue = engine(shared).lane(seat);
  let thread = shared.metrics.inner().thread(seat).unwrap();
  thread.parks.load(Ordering::Relaxed) > thread.unparks.load(Ordering::Relaxed)
}
fn start_worker(shared: &Arc<Shared>, index: usize) -> std::thread::JoinHandle<()> {
  let shared = Arc::clone(shared);
  std::thread::spawn(move || {
    worker(
      shared,
      AsyncThreadContext {
        role: AsyncThreadRole::Worker,
        index,
        physical_index: index,
      },
      super::super::super::entry::PreparedContextNodes::new(None, 1)
        .unwrap()
        .pop()
        .unwrap(),
    )
  })
}
fn selected(shared: &Arc<Shared>, seat: usize) -> Option<Selected> {
  let d = engine(shared);
  let mut random = seat as u64 + 1;
  loop {
    let mut guard = None;
    match d.search(shared, seat, &mut random, &mut guard) {
      Search::Got(index) => {
        if let Some(work) = d.dispatch_decision(shared, index) {
          return Some(work);
        }
      }
      Search::Recheck => {}
      Search::Empty => return None,
    }
  }
}
fn run(shared: &Arc<Shared>, work: Selected) {
  let d = engine(shared);
  match work {
    Selected::Cancel(reference, task) => {
      task.as_ref().cancel();
      d.finish_cancel(shared, reference, task);
    }
    Selected::Poll(reference, task, permit) => {
      let (result, permit) = task
        .as_ref()
        .poll(&mut Context::from_waker(Waker::noop()), permit);
      drop(permit);
      d.finish_poll(
        shared,
        reference,
        &task,
        matches!(result, PollResult::Ready),
      );
    }
  }
}

#[test]
fn pushes_and_kicks_notify_a_sleeping_lane_once() {
  each_spin_configuration(pushes_and_kicks_notify_a_sleeping_lane_once_case);
}

fn pushes_and_kicks_notify_a_sleeping_lane_once_case() {
  for kick_first in [false, true] {
    let (shared, root) = shared(config(1, 8));
    let d = engine(&shared);
    d.parked.advertise(0);
    assert!(d.lane(0).prepare_sleep());
    if kick_first {
      d.kick(0);
    }
    let jobs: Vec<_> = (0..8)
      .map(|_| {
        let job = shared.spawn(root, async {}).unwrap();
        d.kick(0);
        job
      })
      .collect();
    assert_eq!(d.lane_notifies.load(Ordering::Relaxed), 1);
    d.lane(0).finish_sleep();
    for job in jobs {
      run(&shared, selected(&shared, 0).unwrap());
      finish(job).unwrap();
    }
    assert!(d.lane(0).take_recheck());
    assert!(d.lane(0).prepare_sleep());
    // A new sleep needs a fresh notify, even after an empty recheck.
    let job = shared.spawn(root, async {}).unwrap();
    assert_eq!(d.lane_notifies.load(Ordering::Relaxed), 2);
    d.lane(0).finish_sleep();
    run(&shared, selected(&shared, 0).unwrap());
    finish(job).unwrap();
    shared.close(false);
    check_distributed(&shared);
  }
}

#[test]
fn dispatcher_rechecks_without_exit_hints_take_no_admission_or_seat_locks() {
  each_spin_configuration(
    dispatcher_rechecks_without_exit_hints_take_no_admission_or_seat_locks_case,
  );
}

fn dispatcher_rechecks_without_exit_hints_take_no_admission_or_seat_locks_case() {
  let (shared, _) = shared(config(1, 1));
  let d = engine(&shared);
  let worker = start_worker(&shared, 0);
  wait(|| lane_sleeping(&shared, 0));
  let admission = shared.lock_acquisitions.load(Ordering::Relaxed);
  let seats = d.seat_locks.load(Ordering::Relaxed);
  for _ in 0..32 {
    let parks = shared
      .metrics
      .inner()
      .thread(0)
      .unwrap()
      .parks
      .load(Ordering::Relaxed);
    d.kick(0);
    wait(|| {
      shared
        .metrics
        .inner()
        .thread(0)
        .unwrap()
        .parks
        .load(Ordering::Relaxed)
        > parks
        && lane_sleeping(&shared, 0)
    });
  }
  assert_eq!(shared.lock_acquisitions.load(Ordering::Relaxed), admission);
  assert_eq!(d.seat_locks.load(Ordering::Relaxed), seats);
  shared.close(false);
  join_worker(worker);
}

#[test]
fn closing_rechecks_finish_drain_and_cancel_pending_before_deadline() {
  each_spin_configuration(closing_rechecks_finish_drain_and_cancel_pending_before_deadline_case);
}

fn closing_rechecks_finish_drain_and_cancel_pending_before_deadline_case() {
  for mode in [AsyncShutdown::Drain, AsyncShutdown::CancelPending] {
    for empty in [false, true] {
      let (shared, root) = shared(config(1, 1));
      let ready = Arc::new(AtomicBool::new(false));
      let (tx, rx) = mpsc::channel();
      let job = (!empty).then(|| {
        let ready = Arc::clone(&ready);
        shared
          .spawn(
            root,
            std::future::poll_fn(move |cx| {
              if ready.load(Ordering::Acquire) {
                Poll::Ready(())
              } else {
                tx.send(cx.waker().clone()).unwrap();
                Poll::Pending
              }
            }),
          )
          .unwrap()
      });
      let worker = start_worker(&shared, 0);
      let waker = (!empty).then(|| rx.recv_timeout(Duration::from_secs(5)).unwrap());
      wait(|| lane_sleeping(&shared, 0));
      shared.close(mode == AsyncShutdown::CancelPending);
      if mode == AsyncShutdown::Drain
        && let Some(waker) = waker
      {
        ready.store(true, Ordering::Release);
        waker.wake();
      }
      if let Some(job) = job {
        let result = finish(job);
        match mode {
          AsyncShutdown::Drain => result.unwrap(),
          AsyncShutdown::CancelPending => {
            assert!(matches!(result, Err(AsyncJoinError::Cancelled)))
          }
        }
      }
      join_worker(worker);
      assert_eq!(shared.turn_counts(), (0, 0, 0, 0));
      check_distributed(&shared);
    }
  }
}

#[test]
fn parked_worker_yields_to_helper_restoration_and_helper_retires_before_deadline() {
  each_spin_configuration(
    parked_worker_yields_to_helper_restoration_and_helper_retires_before_deadline_case,
  );
}

fn parked_worker_yields_to_helper_restoration_and_helper_retires_before_deadline_case() {
  let (shared, _) = shared_with_handoffs(config(1, 1), 2);
  let d = engine(&shared);
  let (turn, helper_loan, lease) = {
    let mut seats = d.seats();
    let worker = seats.claim(0);
    let worker_loan = seats.try_hand_off(worker).unwrap();
    let lease = seats.try_activate_helper().unwrap();
    let helper = seats.try_begin_helper_turn().unwrap();
    let helper_loan = seats.try_hand_off(helper).unwrap();
    let ticket = seats.begin_restore(worker_loan);
    let turn = seats.try_restore(ticket).unwrap();
    d.update_yield(&seats);
    (turn, helper_loan, lease)
  };
  let worker = {
    let shared = Arc::clone(&shared);
    std::thread::spawn(move || {
      let context = worker_context(0);
      run_dispatcher(&shared, context, || {
        engine(&shared).serve(&shared, context, turn, false);
      });
    })
  };
  wait(|| lane_sleeping(&shared, 0));
  let helper = {
    let shared = Arc::clone(&shared);
    std::thread::spawn(move || {
      let d = engine(&shared);
      let context = AsyncThreadContext {
        role: AsyncThreadRole::HandoffHelper,
        index: 0,
        physical_index: 1,
      };
      run_dispatcher(&shared, context, || {
        // All seats are held by workers: this restoration requires a kick
        // and a worker yield before the helper can acquire its turn.
        let turn = d.restore(&shared, helper_loan, context);
        assert!(d.helper_yield.load(Ordering::Acquire));
        // With no loans left, serve must relinquish the helper's turn.
        d.serve(&shared, context, turn, true);
        let mut seats = d.seats();
        seats.retire_helper(lease).unwrap();
        d.update_yield(&seats);
        d.seat_cv.notify_all();
      });
    })
  };
  join_worker(helper);
  wait(|| shared.turn_counts() == (1, 0, 0, 0) && lane_sleeping(&shared, 0));
  shared.close(false);
  join_worker(worker);
  assert_eq!(shared.turn_counts(), (0, 0, 0, 0));
}

#[test]
fn work_arriving_during_spin_runs_without_a_park() {
  for rounds in [128, 4096] {
    TEST_SPIN_POLICY.set(Policy {
      rounds,
      max_spinners: Some(1),
      max_searchers: TEST_SEARCH_CAP.get(),
    });
    work_arriving_during_spin_runs_without_a_park_case();
  }
  TEST_SPIN_POLICY.set(Policy::default());
}

fn work_arriving_during_spin_runs_without_a_park_case() {
  let park_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
  let attempts = Arc::clone(&park_attempts);
  let (shared, root) = shared_with_options(
    config(2, 1),
    AsyncThreadOptions::new().on_thread_park(move |context| {
      if context.role == AsyncThreadRole::Worker && context.index == 0 {
        attempts.fetch_add(1, Ordering::SeqCst);
      }
    }),
  );
  let job = Arc::new(Mutex::new(None));
  let completed = Arc::new(AtomicBool::new(false));
  let thread = {
    let shared = Arc::clone(&shared);
    let job = Arc::clone(&job);
    let completed = Arc::clone(&completed);
    std::thread::spawn(move || {
      let producer = Arc::clone(&shared);
      SPIN_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
          *job.lock().unwrap() = Some(
            producer
              .spawn(root, async move {
                completed.store(true, Ordering::SeqCst);
              })
              .unwrap(),
          );
        }));
      });
      let context = AsyncThreadContext {
        role: AsyncThreadRole::Worker,
        index: 0,
        physical_index: 0,
      };
      let d = engine(&shared);
      let Search::Got(index) = d.search_or_park(&shared, 0, &mut 1, context) else {
        panic!("expected work");
      };
      run(&shared, d.dispatch_decision(&shared, index).unwrap());
    })
  };
  join_worker(thread);
  assert_eq!(engine(&shared).spinners.current(), 0);
  assert!(completed.load(Ordering::SeqCst));
  assert_eq!(shared.metrics.snapshot().threads[0].parks, 0);
  assert_eq!(park_attempts.load(Ordering::SeqCst), 0);
  finish(job.lock().unwrap().take().unwrap()).unwrap();
  shared.close(false);
}

#[test]
fn idle_dispatchers_park_after_spinning() {
  each_spin_configuration(idle_dispatchers_park_after_spinning_case);
}

fn idle_dispatchers_park_after_spinning_case() {
  let runtime = runtime(2, 1);
  wait(|| {
    runtime
      .metrics()
      .snapshot()
      .threads
      .iter()
      .all(|thread| thread.parks > 0)
  });
  std::thread::sleep(Duration::from_millis(20));
  let snapshot = runtime.metrics().snapshot();
  assert!(
    snapshot
      .threads
      .iter()
      .all(|thread| thread.parks > thread.unparks)
  );
  assert!(
    snapshot
      .threads
      .iter()
      .all(|thread| thread.busy_duration == Duration::ZERO)
  );
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn one_spawn_into_four_parked_lanes_wakes_only_its_dispatcher() {
  each_spin_configuration(one_spawn_into_four_parked_lanes_wakes_only_its_dispatcher_case);
}

fn one_spawn_into_four_parked_lanes_wakes_only_its_dispatcher_case() {
  let (shared, root) = shared(config(4, 1));
  let d = engine(&shared);
  // Model all four parked dispatchers without racing their next search.
  for seat in 0..4 {
    d.parked.advertise(seat);
    assert!(d.lane(seat).prepare_sleep());
  }
  let searches = d.wake_searches.load(Ordering::Relaxed);
  let locks = d.lane_locks.load(Ordering::Relaxed);
  let job = shared.spawn(root, async {}).unwrap();
  assert_eq!(d.wake_searches.load(Ordering::Relaxed) - searches, 0);
  assert_eq!(d.lane_locks.load(Ordering::Relaxed) - locks, 1);
  assert!(!d.parked.is_set(0));
  assert!((1..4).all(|seat| d.parked.is_set(seat)));
  run(&shared, selected(&shared, 0).unwrap());
  finish(job).unwrap();
  check_distributed(&shared);
}

#[test]
fn two_blocking_polls_start_before_deadline() {
  each_search_configuration(|| {
    each_spin_configuration(two_blocking_polls_start_before_deadline_case)
  });
}

fn two_blocking_polls_start_before_deadline_case() {
  let (shared, root) = shared(config(2, 2));
  let d = engine(&shared);
  let started = Arc::new(AtomicUsize::new(0));
  let spawn = || {
    d.next_lane.store(0, Ordering::Relaxed);
    let started = Arc::clone(&started);
    shared
      .spawn(
        root,
        std::future::poll_fn(move |_| {
          started.fetch_add(1, Ordering::SeqCst);
          let deadline = Instant::now() + Duration::from_secs(5);
          while started.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            std::thread::yield_now();
          }
          Poll::Ready(started.load(Ordering::SeqCst) == 2)
        }),
      )
      .unwrap()
  };
  let first = spawn();
  let worker0 = start_worker(&shared, 0);
  wait(|| started.load(Ordering::SeqCst) == 1);
  let worker1 = start_worker(&shared, 1);
  wait(|| d.parked.is_set(1));
  let second = spawn();
  let results = (finish(first).unwrap(), finish(second).unwrap());
  shared.close(false);
  join_worker(worker0);
  join_worker(worker1);
  assert_eq!(results, (true, true), "concurrent poll start deadline");
  check_distributed(&shared);
}

#[test]
fn external_spawns_start_all_blocking_polls_before_deadline() {
  each_search_configuration(|| {
    each_spin_configuration(external_spawns_start_all_blocking_polls_before_deadline_case)
  });
}

fn external_spawns_start_all_blocking_polls_before_deadline_case() {
  for workers in [2, 4] {
    let runtime = runtime(workers, workers);
    let d = engine(&runtime.shared);
    wait(|| (0..workers).all(|seat| d.parked.is_set(seat)));
    let handle = runtime.handle();
    // This thread has no dispatcher seat. Wait for each poll to start so that
    // every later insertion targets a busy lane with a lone ready entry.
    let spawner = std::thread::spawn(move || {
      let started = Arc::new(AtomicUsize::new(0));
      let (tx, rx) = mpsc::channel();
      let deadline = Instant::now() + Duration::from_secs(5);
      let mut jobs = Vec::new();
      for _ in 0..workers {
        let started = Arc::clone(&started);
        let tx = tx.clone();
        jobs.push(
          handle
            .spawn(async move {
              started.fetch_add(1, Ordering::SeqCst);
              tx.send(()).unwrap();
              while started.load(Ordering::SeqCst) < workers && Instant::now() < deadline {
                std::thread::yield_now();
              }
              started.load(Ordering::SeqCst) == workers && Instant::now() < deadline
            })
            .unwrap(),
        );
        rx.recv_timeout(Duration::from_secs(10)).unwrap();
      }
      jobs
    });
    let jobs = join_worker(spawner);
    let results: Vec<_> = jobs.into_iter().map(|job| finish(job).unwrap()).collect();
    shutdown(runtime, AsyncShutdown::Drain);
    assert!(
      results.iter().all(|started| *started),
      "{workers} poll start deadline: {results:?}"
    );
  }
}

#[test]
fn external_idle_wake_behind_blocked_poll_runs_before_deadline() {
  each_search_configuration(|| {
    each_spin_configuration(external_idle_wake_behind_blocked_poll_runs_before_deadline_case)
  });
}

fn external_idle_wake_behind_blocked_poll_runs_before_deadline_case() {
  const WORKERS: usize = 4;
  let runtime = runtime(WORKERS, 2);
  let d = engine(&runtime.shared);
  let ready = Arc::new(AtomicBool::new(false));
  let blocker_returned = Arc::new(AtomicBool::new(false));
  let (waker_tx, waker_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let task_ready = Arc::clone(&ready);
  let returned = Arc::clone(&blocker_returned);
  let job = runtime
    .handle()
    .spawn(std::future::poll_fn(move |cx| {
      if task_ready.load(Ordering::Acquire) {
        let ran_while_blocked = !returned.load(Ordering::Acquire);
        let _ = release_tx.send(());
        Poll::Ready(ran_while_blocked)
      } else {
        waker_tx.send(cx.waker().clone()).unwrap();
        Poll::Pending
      }
    }))
    .unwrap();
  let waker = waker_rx.recv_timeout(Duration::from_secs(5)).unwrap();
  // Observe the completed Pending transition, not just waker registration.
  wait(|| (0..WORKERS).all(|seat| d.parked.is_set(seat)));
  let (started_tx, started_rx) = mpsc::channel();
  let blocker = runtime
    .handle()
    .spawn(async move {
      started_tx.send(()).unwrap();
      let released = release_rx.recv_timeout(Duration::from_secs(5)).is_ok();
      blocker_returned.store(true, Ordering::Release);
      released
    })
    .unwrap();
  started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
  wait(|| (0..WORKERS).filter(|seat| d.parked.is_set(*seat)).count() == WORKERS - 1);
  join_worker(std::thread::spawn(move || {
    ready.store(true, Ordering::Release);
    waker.wake();
  }));
  let ran_while_blocked = finish(job).unwrap();
  let released = finish(blocker).unwrap();
  shutdown(runtime, AsyncShutdown::Drain);
  assert!(ran_while_blocked && released, "external idle wake deadline");
}

#[test]
fn lone_entry_behind_blocked_poll_runs_on_idle_worker() {
  each_search_configuration(|| {
    each_spin_configuration(lone_entry_behind_blocked_poll_runs_on_idle_worker_case)
  });
}

fn lone_entry_behind_blocked_poll_runs_on_idle_worker_case() {
  let (shared, root) = shared(config(2, 2));
  let d = engine(&shared);
  let (started_tx, started_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let returned = Arc::new(AtomicBool::new(false));
  let done = Arc::clone(&returned);
  let blocker = shared
    .spawn(root, async move {
      started_tx.send(()).unwrap();
      let released = release_rx.recv_timeout(Duration::from_secs(5)).is_ok();
      done.store(true, Ordering::SeqCst);
      released
    })
    .unwrap();
  let worker0 = start_worker(&shared, 0);
  started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
  let worker1 = start_worker(&shared, 1);
  wait(|| d.parked.is_set(1));
  d.next_lane.store(0, Ordering::Relaxed);
  let job = shared
    .spawn(root, async move { !returned.load(Ordering::SeqCst) })
    .unwrap();
  let ran_while_blocked = finish(job).unwrap();
  let _ = release_tx.send(());
  let released = finish(blocker).unwrap();
  shared.close(false);
  join_worker(worker0);
  join_worker(worker1);
  assert!(ran_while_blocked && released, "idle worker steal deadline");
  check_distributed(&shared);
}

#[test]
fn stealing_last_entry_does_not_wake_or_lock_a_parked_dispatcher() {
  each_spin_configuration(stealing_last_entry_does_not_wake_or_lock_a_parked_dispatcher_case);
}

fn stealing_last_entry_does_not_wake_or_lock_a_parked_dispatcher_case() {
  for count in [1, 2, 3] {
    let (shared, root) = shared(config(3, 3));
    let d = engine(&shared);
    let jobs: Vec<_> = (0..count)
      .map(|_| {
        d.next_lane.store(1, Ordering::Relaxed);
        shared.spawn(root, async {}).unwrap()
      })
      .collect();
    d.next_lane.store(2, Ordering::Relaxed);
    d.parked.advertise(2);
    assert!(d.lane(2).prepare_sleep());
    let before = d.lane_locks.load(Ordering::Relaxed);
    let index = d.try_steal(&shared, 0, &mut 1).unwrap();
    let locks = d.lane_locks.load(Ordering::Relaxed) - before;
    // Only the victim lock, plus the kick of a parked dispatcher while
    // entries remain; the lone stolen entry never enters the thief's lane.
    assert_eq!(locks, if count == 1 { 1 } else { 2 });
    assert!(d.lane(0).check(&d.links).is_empty());
    assert_eq!(d.parked.is_set(2), count == 1);
    assert_eq!(d.lane(2).take_recheck(), count != 1);
    assert_eq!(d.lane(1).check(&d.links).len(), count - 1);
    run(&shared, d.dispatch_decision(&shared, index).unwrap());
    for _ in 1..count {
      run(&shared, selected(&shared, 1).unwrap());
    }
    for job in jobs {
      finish(job).unwrap();
    }
    d.lane(2).finish_sleep();
    check_distributed(&shared);
  }
}

#[test]
fn single_stolen_entry_is_returned_without_entering_the_thief_lane() {
  each_spin_configuration(single_stolen_entry_is_returned_without_entering_the_thief_lane_case);
}

fn single_stolen_entry_is_returned_without_entering_the_thief_lane_case() {
  for count in [1, 2, 3, 4] {
    let (shared, root) = shared(config(2, 4));
    let d = engine(&shared);
    let jobs: Vec<_> = (0..count)
      .map(|_| {
        d.next_lane.store(1, Ordering::Relaxed);
        shared.spawn(root, async {}).unwrap()
      })
      .collect();
    let queued = d.lane(1).check(&d.links);
    let steals = d.steals.load(Ordering::Relaxed);
    let index = d.try_steal(&shared, 0, &mut 1).unwrap();
    assert_eq!(d.steals.load(Ordering::Relaxed) - steals, 1);
    // The oldest entry is returned; only a multi-entry steal reaches lane 0.
    assert_eq!(index, queued[0]);
    let taken = (count / 2).max(1);
    assert_eq!(d.lane(0).check(&d.links), queued[1..taken]);
    assert_eq!(d.lane(1).check(&d.links), queued[taken..]);
    assert_eq!(
      shared.metrics.inner().lane_depth[0]
        .0
        .load(Ordering::SeqCst),
      taken - 1
    );
    assert_eq!(
      shared.metrics.inner().overflow_depth.load(Ordering::SeqCst),
      0
    );
    run(&shared, d.dispatch_decision(&shared, index).unwrap());
    for seat in [0, 0, 1, 1] {
      if let Some(work) = selected(&shared, seat) {
        run(&shared, work);
      }
    }
    for job in jobs {
      finish(job).unwrap();
    }
    check_distributed(&shared);
  }
}

#[test]
fn single_stolen_cleanup_entry_moves_to_overflow_and_is_cancelled() {
  each_spin_configuration(single_stolen_cleanup_entry_moves_to_overflow_and_is_cancelled_case);
}

fn single_stolen_cleanup_entry_moves_to_overflow_and_is_cancelled_case() {
  let (shared, root) = shared(config(2, 2));
  let d = engine(&shared);
  d.next_lane.store(1, Ordering::Relaxed);
  let job = shared.spawn(root, async {}).unwrap();
  let index = d.lane(1).check(&d.links)[0];
  // An abort whose lane scan ran while the entry was detached by the steal.
  {
    let mut slot = d.slot(index);
    d.links[index].cleanup.store(true, Ordering::SeqCst);
    // The entry stays queued on the word, so this abort routes nothing.
    assert!(slot.protocol.abort());
  }
  assert_eq!(d.try_steal(&shared, 0, &mut 1), None);
  assert!(d.lane(0).check(&d.links).is_empty());
  assert!(d.lane(1).check(&d.links).is_empty());
  assert_eq!(
    shared.metrics.inner().lane_depth[0]
      .0
      .load(Ordering::SeqCst),
    0
  );
  assert_eq!(lock(&d.overflow, 4).check(&d.links), [index]);
  assert_eq!(
    shared.metrics.inner().overflow_depth.load(Ordering::SeqCst),
    1
  );
  let work = selected(&shared, 0).unwrap();
  assert!(matches!(work, Selected::Cancel(..)));
  run(&shared, work);
  assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)));
  check_distributed(&shared);
}

#[test]
fn denied_searcher_parks_without_spinning_until_last_finder_exits() {
  TEST_SEARCH_CAP.set(Some(1));
  each_spin_configuration(|| {
    let (shared, root) = shared(config(2, 3));
    let d = engine(&shared);
    let guard = d.searching.try_enter().unwrap();
    d.next_lane.store(0, Ordering::Relaxed);
    let job = shared.spawn(root, async {}).unwrap();
    let worker1 = start_worker(&shared, 1);
    wait(|| lane_sleeping(&shared, 1));
    let rounds = d.spin_rounds.load(Ordering::Relaxed);
    let denials = d.steal_denials.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(20));
    assert!(lane_sleeping(&shared, 1));
    assert_eq!(d.spin_rounds.load(Ordering::Relaxed), rounds);
    assert_eq!(d.steal_denials.load(Ordering::Relaxed), denials);
    assert!(!job.is_finished());
    // Model a finder taking another entry, leaving this entry behind.
    d.found_work(&shared, &mut Some(guard));
    finish(job).unwrap();
    shared.close(false);
    join_worker(worker1);
    assert_eq!(d.searching.current(), 0);
    assert_eq!(d.searching.pending(), 0);
    check_distributed(&shared);
  });
  TEST_SEARCH_CAP.set(None);
}

#[test]
fn zero_search_cap_publishes_and_woken_own_pops_do_not_kick_searchers() {
  TEST_SEARCH_CAP.set(Some(0));
  each_spin_configuration(|| {
    for owner in 0..4 {
      let (shared, root) = shared(config(4, 3));
      let d = engine(&shared);
      for seat in 0..4 {
        d.parked.advertise(seat);
        assert!(d.lane(seat).prepare_sleep());
      }
      d.next_lane.store(owner, Ordering::Relaxed);
      let first = shared.spawn(root, async {}).unwrap();
      assert!(!d.parked.is_set(owner));
      assert_eq!(d.lane_notifies.load(Ordering::Relaxed), 1);
      // Further publishes target the now-claimed owner while other lanes
      // remain parked. Its first two own-pops will leave work queued.
      let second = shared.spawn(root, async {}).unwrap();
      let third = shared.spawn(root, async {}).unwrap();
      assert_eq!(d.lane(owner).len(), 3);
      assert_eq!(d.wake_searches.load(Ordering::Relaxed), 0);
      d.lane(owner).finish_sleep();
      for remaining in (0..3).rev() {
        run(&shared, selected(&shared, owner).unwrap());
        assert_eq!(d.lane(owner).len(), remaining);
        assert_eq!(d.wake_searches.load(Ordering::Relaxed), 0);
        assert_eq!(d.searching.current(), 0);
        assert_eq!(d.searching.pending(), 0);
        for seat in 0..4 {
          assert!(!d.lane(seat).search_kick);
          assert_eq!(d.parked.is_set(seat), seat != owner);
        }
      }
      assert_eq!(d.lane_notifies.load(Ordering::Relaxed), 1);
      finish(first).unwrap();
      finish(second).unwrap();
      finish(third).unwrap();
      for seat in 0..4 {
        d.lane(seat).finish_sleep();
      }
      check_distributed(&shared);
    }
  });
  TEST_SEARCH_CAP.set(None);
}

#[test]
fn producer_suppression_and_last_found_exit_wake_once() {
  for held in [false, true] {
    half_search_cap(4);
    let (shared, root) = shared(config(4, 5));
    let d = engine(&shared);
    let other = held.then(|| d.searching.try_enter().unwrap());
    let mut finder = Some(d.searching.try_enter().unwrap());
    for seat in [2, 3] {
      d.parked.advertise(seat);
      assert!(d.lane(seat).prepare_sleep());
    }
    let wakes = d.wake_searches.load(Ordering::Relaxed);
    d.next_lane.store(1, Ordering::Relaxed);
    let job = shared.spawn(root, async {}).unwrap();
    assert_eq!(d.wake_searches.load(Ordering::Relaxed), wakes);
    d.found_work(&shared, &mut finder);
    assert_eq!(
      d.wake_searches.load(Ordering::Relaxed) - wakes,
      usize::from(!held)
    );
    drop(other);
    // A non-finding park exit sends no wake.
    if held {
      assert!(d.parked.is_set(2) && d.parked.is_set(3));
      d.search_wake();
    }
    let woken = if d.parked.is_set(2) { 3 } else { 2 };
    assert_eq!(d.searching.pending(), 1);
    d.next_lane.store(1, Ordering::Relaxed);
    let second = shared.spawn(root, async {}).unwrap();
    assert_eq!(d.searching.pending(), 1);
    run(&shared, selected(&shared, woken).unwrap());
    run(&shared, selected(&shared, woken).unwrap());
    finish(job).unwrap();
    finish(second).unwrap();
    for seat in [2, 3] {
      d.lane(seat).finish_sleep();
      d.acknowledge_search_kick(seat);
    }
    assert_eq!(d.searching.pending(), 0);
    check_distributed(&shared);
  }
  TEST_SPIN_POLICY.set(Policy::default());
}

#[test]
fn searching_defaults_to_half_and_keeps_accounting_when_unlimited() {
  for (workers, cap, expected) in [
    (1, None, 1),
    (2, None, 1),
    (3, None, 2),
    (4, None, 2),
    (4, Some(1), 1),
    (4, Some(4), 4),
    (4, Some(usize::MAX), 4),
    (4, Some(0), 0),
  ] {
    TEST_SPIN_POLICY.set(Policy {
      max_searchers: cap,
      ..Policy::default()
    });
    let (shared, _) = shared(config(workers, 1));
    let d = engine(&shared);
    let entered: Vec<_> = (0..expected)
      .map(|_| d.searching.try_enter().unwrap())
      .collect();
    assert_eq!(d.searching.current(), expected);
    if cap != Some(usize::MAX) {
      assert!(d.searching.try_enter().is_none());
    }
    drop(entered);
    assert_eq!(d.searching.current(), 0);
  }
  TEST_SPIN_POLICY.set(Policy::default());
  let options = AsyncRuntimeOptions::new().max_searching_dispatchers(3);
  assert_eq!(options.park_spin.max_searchers, Some(3));
}

#[test]
fn abandoned_seat_settles_its_search_kick() {
  let (shared, _) = shared(config(2, 1));
  let d = engine(&shared);
  let turn = d.seats().claim(1);
  d.parked.advertise(1);
  assert!(d.lane(1).prepare_sleep());
  d.search_wake();
  assert_eq!(d.searching.pending(), 1);
  d.abandon_turn(&shared, turn);
  assert_eq!(d.searching.pending(), 0);
  assert!(!d.lane(1).search_kick);
}

#[test]
fn acknowledged_search_kick_allows_later_external_work_to_wake() {
  each_search_configuration(|| {
    each_spin_configuration(|| {
      let (shared, root) = shared(config(2, 2));
      let d = engine(&shared);
      let worker1 = start_worker(&shared, 1);
      wait(|| lane_sleeping(&shared, 1));
      d.search_wake();
      wait(|| lane_sleeping(&shared, 1) && d.searching.pending() == 0);
      d.next_lane.store(0, Ordering::Relaxed);
      let job = shared.spawn(root, async {}).unwrap();
      finish(job).unwrap();
      shared.close(false);
      join_worker(worker1);
      assert_eq!(d.searching.pending(), 0);
    })
  });
}

/// Checks only quiescent points, when no entries or permits are in transit.
fn check_distributed(shared: &Shared) {
  let d = engine(shared);
  let mut locations = vec![0usize; d.slots.len()];
  for seat in 0..d.lanes.len() {
    let queue = d.lane(seat);
    let indices = queue.check(&d.links);
    assert_eq!(
      indices.len(),
      shared.metrics.inner().lane_depth[seat]
        .0
        .load(Ordering::SeqCst)
    );
    for index in indices {
      locations[index] += 1;
    }
  }
  let queue = lock(&d.overflow, 4);
  let indices = queue.check(&d.links);
  assert_eq!(
    indices.len(),
    shared.metrics.inner().overflow_depth.load(Ordering::SeqCst)
  );
  for index in indices {
    locations[index] += 1;
  }
  drop(queue);
  let state = shared.lock();
  let mut blocked = 0;
  for scope in &state.scopes {
    if let Some(cell) = &scope.scope {
      let dispatch = d.scope(cell);
      let indices = dispatch.check(&d.links);
      blocked += indices.len();
      for index in indices {
        locations[index] += 1;
      }
      if cell.binding {
        let active = d
          .slots
          .iter()
          .filter(|slot| {
            let slot = slot.state.lock().unwrap();
            slot
              .scope_cell(shared)
              .is_some_and(|owner| Arc::ptr_eq(owner, cell))
              && (slot.reserved_permit
                || slot
                  .task
                  .as_ref()
                  .is_some_and(|task| task.poll_word().flags().0))
          })
          .count();
        assert_eq!(dispatch.active(), active);
      }
    }
  }
  assert_eq!(
    blocked,
    shared.metrics.inner().blocked_depth.load(Ordering::Relaxed)
  );
  let mut admitted = 0;
  let mut free = Vec::new();
  for (index, count) in locations.into_iter().enumerate() {
    let slot = d.slot(index);
    admitted += usize::from(slot.protocol.admitted());
    assert_eq!(
      count,
      usize::from(
        slot.protocol.admitted()
          && slot
            .task
            .as_ref()
            .is_some_and(|task| task.poll_word().is_queued())
      )
    );
    if !slot.protocol.admitted() && slot.protocol.next_generation().is_some() {
      free.push(index);
    }
  }
  let bitmap: Vec<_> = state.free_tasks.iter().collect();
  assert_eq!(free, bitmap);
  assert_eq!(state.admitted, admitted);
  // The metric reads the admission count under the admission lock.
  drop(state);
  assert_eq!(shared.metrics.num_alive_tasks(), admitted);
}

#[test]
fn pending_self_yields_take_zero_global_one_slot_and_two_lane_locks() {
  each_spin_configuration(pending_self_yields_take_zero_global_one_slot_and_two_lane_locks_case);
}

fn pending_self_yields_take_zero_global_one_slot_and_two_lane_locks_case() {
  let runtime = runtime(1, 1);
  let shared = Arc::clone(&runtime.shared);
  let mut previous = None;
  let mut polls = 0;
  let job = runtime
    .handle()
    .spawn(std::future::poll_fn(move |cx| {
      let d = engine(&shared);
      let counts = (
        shared.lock_acquisitions.load(Ordering::Relaxed),
        d.slot_locks.load(Ordering::Relaxed),
        d.lane_locks.load(Ordering::Relaxed),
      );
      if let Some((g, s, l)) = previous {
        assert_eq!((counts.0 - g, counts.1 - s, counts.2 - l), (0, 1, 2));
      }
      previous = Some(counts);
      polls += 1;
      if polls == 10_001 {
        Poll::Ready(())
      } else {
        cx.waker().wake_by_ref();
        Poll::Pending
      }
    }))
    .unwrap();
  finish(job).unwrap();
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn drain_close_waits_for_reserved_task_rollback() {
  let (shared, root) = shared(config(1, 1));
  let (entered, reached) = mpsc::channel();
  let release = Arc::new((Mutex::new(false), Condvar::new()));
  let gate = Arc::clone(&release);
  shared.set_spawn_reserved_test_hook(Arc::new(move || {
    entered.send(()).unwrap();
    let guard = gate.0.lock().unwrap();
    let (guard, timeout) = gate
      .1
      .wait_timeout_while(guard, Duration::from_secs(5), |open| !*open)
      .unwrap();
    assert!(*guard && !timeout.timed_out());
  }));
  let producer = Arc::clone(&shared);
  let spawner = std::thread::spawn(move || producer.spawn(root, async { 7 }));
  reached.recv_timeout(Duration::from_secs(5)).unwrap();
  shared.close(false);
  assert_eq!(shared.lock().admitted, 1);
  assert!(!engine(&shared).closed_empty.load(Ordering::Acquire));
  assert!(selected(&shared, 0).is_none());
  *release.0.lock().unwrap() = true;
  release.1.notify_all();
  let error = join_worker(spawner).unwrap_err();
  assert_eq!(error.kind, AsyncError::Closed);
  let mut future = std::pin::pin!(error.into_future());
  assert_eq!(
    future
      .as_mut()
      .poll(&mut Context::from_waker(Waker::noop())),
    Poll::Ready(7)
  );
  assert!(selected(&shared, 0).is_none());
  assert!(engine(&shared).closed_empty.load(Ordering::Acquire));
  check_distributed(&shared);
}

#[test]
fn reservation_unwind_drops_the_future_before_releasing_admission() {
  struct Probe {
    shared: Arc<Shared>,
    drops: Arc<AtomicUsize>,
  }
  impl Future for Probe {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
      panic!("unpublished future polled");
    }
  }
  impl Drop for Probe {
    fn drop(&mut self) {
      assert_eq!(self.shared.metrics.num_alive_tasks(), 1);
      assert!(self.shared.state.try_lock().is_ok());
      assert!(engine(&self.shared).slots[0].state.try_lock().is_ok());
      self.drops.fetch_add(1, Ordering::Relaxed);
    }
  }
  let (shared, root) = shared(config(1, 1));
  {
    let mut slot = engine(&shared).slot(0);
    slot.protocol.admit(u64::MAX - 1);
    slot.protocol.release();
  }
  shared.set_spawn_reserved_test_hook(Arc::new(|| panic!("injected allocation failure")));
  let drops = Arc::new(AtomicUsize::new(0));
  let result = panic::catch_unwind(AssertUnwindSafe(|| {
    shared.spawn(
      root,
      Probe {
        shared: Arc::clone(&shared),
        drops: Arc::clone(&drops),
      },
    )
  }));
  assert!(result.is_err());
  assert_eq!(drops.load(Ordering::Relaxed), 1);
  assert_eq!(shared.metrics.num_alive_tasks(), 0);
  assert_eq!(engine(&shared).slot(0).protocol.generation(), u64::MAX - 1);
  check_distributed(&shared);
  shared.set_spawn_reserved_test_hook(Arc::new(|| {}));
  let job = shared.spawn(root, async { 7 }).unwrap();
  run(&shared, selected(&shared, 0).unwrap());
  assert_eq!(finish(job).unwrap(), 7);
  check_distributed(&shared);
}

#[test]
fn spawn_wake_completion_and_steal_lock_counts() {
  each_spin_configuration(spawn_wake_completion_and_steal_lock_counts_case);
}

fn spawn_wake_completion_and_steal_lock_counts_case() {
  let (shared, root) = shared(config(2, 8));
  let d = engine(&shared);
  let before = (
    shared.lock_acquisitions.load(Ordering::Relaxed),
    d.slot_locks.load(Ordering::Relaxed),
    d.lane_locks.load(Ordering::Relaxed),
  );
  let job = shared.spawn(root, std::future::pending::<()>()).unwrap();
  // One admission lock to reserve, one slot lock to admit and install.
  assert_eq!(
    (
      shared.lock_acquisitions.load(Ordering::Relaxed) - before.0,
      d.slot_locks.load(Ordering::Relaxed) - before.1,
      d.lane_locks.load(Ordering::Relaxed) - before.2
    ),
    (1, 1, 1)
  );
  let work = selected(&shared, 0).unwrap();
  let reference = match &work {
    Selected::Poll(r, ..) => *r,
    _ => panic!(),
  };
  run(&shared, work);
  let task = d.slot(reference.index).task.clone().unwrap();
  let before = (
    shared.lock_acquisitions.load(Ordering::Relaxed),
    d.slot_locks.load(Ordering::Relaxed),
    d.lane_locks.load(Ordering::Relaxed),
  );
  // An idle wake wins the queue entry on the task word: no slot lock.
  Shared::wake_task(&Arc::downgrade(&shared), task.poll_word(), reference);
  assert_eq!(
    (
      shared.lock_acquisitions.load(Ordering::Relaxed) - before.0,
      d.slot_locks.load(Ordering::Relaxed) - before.1,
      d.lane_locks.load(Ordering::Relaxed) - before.2
    ),
    (0, 0, 1)
  );
  drop(task);
  shared.abort(reference);
  let work = selected(&shared, 0)
    .or_else(|| selected(&shared, 1))
    .unwrap();
  let before = shared.lock_acquisitions.load(Ordering::Relaxed);
  run(&shared, work);
  assert_eq!(shared.lock_acquisitions.load(Ordering::Relaxed) - before, 1);
  assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)));
  check_distributed(&shared);
  // Force a deterministic steal with three ready entries in the victim.
  d.parked.advertise(0);
  let jobs: Vec<_> = (0..3)
    .map(|_| {
      d.next_lane.store(1, Ordering::Relaxed);
      shared.spawn(root, async {}).unwrap()
    })
    .collect();
  d.lane(0).take_recheck();
  let before = d.lane_locks.load(Ordering::Relaxed);
  let work = selected(&shared, 0).unwrap();
  // Own lane, then the victim; the lone stolen entry skips the thief's lane.
  assert_eq!(d.lane_locks.load(Ordering::Relaxed) - before, 2);
  run(&shared, work);
  for _ in 0..2 {
    run(&shared, selected(&shared, 1).unwrap());
  }
  for job in jobs {
    finish(job).unwrap();
  }
  check_distributed(&shared);
  let job = shared.spawn(root, async {}).unwrap();
  let before = (
    shared.lock_acquisitions.load(Ordering::Relaxed),
    d.slot_locks.load(Ordering::Relaxed),
    d.lane_locks.load(Ordering::Relaxed),
  );
  run(
    &shared,
    selected(&shared, 0)
      .or_else(|| selected(&shared, 1))
      .unwrap(),
  );
  assert_eq!(
    (
      shared.lock_acquisitions.load(Ordering::Relaxed) - before.0,
      d.slot_locks.load(Ordering::Relaxed) - before.1,
      d.lane_locks.load(Ordering::Relaxed) - before.2
    ),
    (1, 2, 1)
  );
  finish(job).unwrap();
  check_distributed(&shared);
}

#[test]
fn blocked_fifo_transfers_without_reblocking_and_abort_bypasses_quota() {
  each_spin_configuration(blocked_fifo_transfers_without_reblocking_and_abort_bypasses_quota_case);
}

fn blocked_fifo_transfers_without_reblocking_and_abort_bypasses_quota_case() {
  let (shared, _) = shared(config(2, 8));
  let scope = shared.new_scope(1, None).unwrap();
  let jobs: Vec<_> = (0..6).map(|_| scope.spawn(async {}).unwrap()).collect();
  let holder = selected(&shared, 0).unwrap();
  for seat in 0..2 {
    assert!(selected(&shared, seat).is_none(), "quota bypass");
  }
  let d = engine(&shared);
  let order = d.scope(&scope.cell).check(&d.links);
  assert_eq!(order.len(), 5);
  check_distributed(&shared);
  // Aborting a blocked entry removes it without waiting for the holder.
  let cancelled = order[2];
  let reference = TaskRef {
    index: cancelled,
    generation: d.slot(cancelled).protocol.generation(),
  };
  shared.abort(reference);
  let work = selected(&shared, 0)
    .or_else(|| selected(&shared, 1))
    .unwrap();
  assert!(matches!(work, Selected::Cancel(..)));
  run(&shared, work);
  assert_eq!(scope.snapshot().active_polls, 1);
  run(&shared, holder);
  for expected in order.into_iter().filter(|index| *index != cancelled) {
    let before = d.scope_locks.load(Ordering::Relaxed);
    let work = selected(&shared, 0)
      .or_else(|| selected(&shared, 1))
      .unwrap();
    match &work {
      Selected::Poll(r, ..) => assert_eq!(r.index, expected),
      _ => panic!(),
    }
    run(&shared, work);
    assert_eq!(d.scope_locks.load(Ordering::Relaxed) - before, 1);
  }
  assert_eq!(scope.snapshot().active_polls, 0);
  assert_eq!(d.scope(&scope.cell).blocked_len(), 0);
  for (index, job) in jobs.into_iter().enumerate() {
    if index == cancelled {
      assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)));
    } else {
      finish(job).unwrap();
    }
  }
  check_distributed(&shared);
  drop(scope.close());
}

#[test]
fn abort_racing_a_reserved_transfer_returns_every_permit() {
  each_spin_configuration(abort_racing_a_reserved_transfer_returns_every_permit_case);
}

fn abort_racing_a_reserved_transfer_returns_every_permit_case() {
  for _ in 0..200 {
    let (shared, _) = shared(config(2, 2));
    let scope = shared.new_scope(1, None).unwrap();
    let first = scope.spawn(async {}).unwrap();
    let second = scope.spawn(async {}).unwrap();
    let holder = selected(&shared, 0).unwrap();
    assert!(selected(&shared, 1).is_none());
    let reference = TaskRef {
      index: 1,
      generation: engine(&shared).slot(1).protocol.generation(),
    };
    let aborter = Arc::clone(&shared);
    let thread = std::thread::spawn(move || aborter.abort(reference));
    run(&shared, holder);
    join_worker(thread);
    run(
      &shared,
      selected(&shared, 0)
        .or_else(|| selected(&shared, 1))
        .unwrap(),
    );
    assert_eq!(scope.snapshot().active_polls, 0);
    finish(first).unwrap();
    assert!(matches!(finish(second), Err(AsyncJoinError::Cancelled)));
    check_distributed(&shared);
    drop(scope.close());
  }
}

#[test]
fn nonbinding_boundary_uses_no_quota_lock() {
  each_spin_configuration(nonbinding_boundary_uses_no_quota_lock_case);
}

fn nonbinding_boundary_uses_no_quota_lock_case() {
  for limit in [3, 4, 5] {
    let (shared, _) = shared(config(4, 1));
    let scope = shared.new_scope(limit, None).unwrap();
    let job = scope.spawn(async {}).unwrap();
    let d = engine(&shared);
    let before = d.scope_locks.load(Ordering::Relaxed);
    run(&shared, selected(&shared, 0).unwrap());
    assert_eq!(
      d.scope_locks.load(Ordering::Relaxed) - before,
      if limit < 4 { 2 } else { 0 }
    );
    assert_eq!(scope.snapshot().active_polls, 0);
    finish(job).unwrap();
    check_distributed(&shared);
  }
}

#[test]
fn stolen_tasks_obey_exact_scope_limits_under_contention() {
  each_search_configuration(|| {
    each_spin_configuration(stolen_tasks_obey_exact_scope_limits_under_contention_case)
  });
}

fn stolen_tasks_obey_exact_scope_limits_under_contention_case() {
  let runtime = runtime(8, 32);
  for limit in [1, 3] {
    let scope = runtime
      .scope_with_config(AsyncScopeConfig {
        max_active_polls: limit,
      })
      .unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let jobs: Vec<_> = (0..16)
      .map(|_| {
        let active = Arc::clone(&active);
        let maximum = Arc::clone(&maximum);
        let mut polls = 0;
        scope
          .spawn(std::future::poll_fn(move |cx| {
            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
            maximum.fetch_max(now, Ordering::Relaxed);
            assert!(now <= limit);
            for _ in 0..4 {
              std::thread::yield_now();
            }
            active.fetch_sub(1, Ordering::SeqCst);
            polls += 1;
            if polls == 100 {
              Poll::Ready(())
            } else {
              cx.waker().wake_by_ref();
              Poll::Pending
            }
          }))
          .unwrap()
      })
      .collect();
    for job in jobs {
      finish(job).unwrap();
    }
    assert!(maximum.load(Ordering::Relaxed) <= limit);
    assert_eq!(scope.snapshot().active_polls, 0);
    drop(scope.close());
  }
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn idle_workers_drain_ready_entries_behind_a_long_poll() {
  each_spin_configuration(idle_workers_drain_ready_entries_behind_a_long_poll_case);
}

fn idle_workers_drain_ready_entries_behind_a_long_poll_case() {
  let (shared, root) = shared(config(4, 17));
  let (entered, arrival) = mpsc::channel();
  let (release, resume) = mpsc::channel();
  let holder = shared
    .spawn(root, async move {
      entered.send(()).unwrap();
      resume.recv_timeout(Duration::from_secs(30)).unwrap();
    })
    .unwrap();
  let d = engine(&shared);
  let (done, completions) = mpsc::channel();
  let (started, starts) = mpsc::channel();
  let release_short = Arc::new(AtomicBool::new(false));
  let jobs: Vec<_> = (0..16)
    .map(|_| {
      d.next_lane.store(0, Ordering::Relaxed);
      let done = done.clone();
      let started = started.clone();
      let release_short = Arc::clone(&release_short);
      shared
        .spawn(root, async move {
          started.send(std::thread::current().id()).unwrap();
          wait(|| release_short.load(Ordering::Acquire));
          done.send(()).unwrap();
        })
        .unwrap()
    })
    .collect();
  let start_worker = |index| {
    let shared = Arc::clone(&shared);
    std::thread::spawn(move || {
      worker(
        shared,
        AsyncThreadContext {
          role: AsyncThreadRole::Worker,
          index,
          physical_index: index,
        },
        super::super::super::entry::PreparedContextNodes::new(None, 1)
          .unwrap()
          .pop()
          .unwrap(),
      )
    })
  };
  let mut workers = vec![start_worker(0)];
  arrival.recv_timeout(Duration::from_secs(30)).unwrap();
  workers.extend((1..4).map(start_worker));
  let mut threads = Vec::new();
  for _ in 0..3 {
    threads.push(starts.recv_timeout(Duration::from_secs(30)).unwrap());
  }
  assert!(
    threads
      .iter()
      .enumerate()
      .all(|(index, id)| !threads[..index].contains(id))
  );
  release_short.store(true, Ordering::Release);
  for _ in 0..16 {
    completions.recv_timeout(Duration::from_secs(30)).unwrap();
  }
  assert!(d.steals.load(Ordering::Relaxed) > 0);
  assert_eq!(
    shared.metrics.inner().lane_depth[0]
      .0
      .load(Ordering::SeqCst),
    0
  );
  release.send(()).unwrap();
  for job in jobs {
    finish(job).unwrap();
  }
  finish(holder).unwrap();
  shared.close(false);
  for thread in workers {
    join_worker(thread);
  }
  check_distributed(&shared);
}

#[test]
fn self_yields_complete_even_when_under_subscribed() {
  each_spin_configuration(self_yields_complete_even_when_under_subscribed_case);
}

fn self_yields_complete_even_when_under_subscribed_case() {
  let runtime = runtime(4, 4);
  let jobs: Vec<_> = (0..4)
    .map(|_| {
      let mut polls = 0;
      runtime
        .handle()
        .spawn(std::future::poll_fn(move |cx| {
          polls += 1;
          if polls == 5_000 {
            Poll::Ready(())
          } else {
            cx.waker().wake_by_ref();
            Poll::Pending
          }
        }))
        .unwrap()
    })
    .collect();
  for job in jobs {
    finish(job).unwrap();
  }
  shutdown(runtime, AsyncShutdown::Drain);
  let runtime = self::runtime(4, 1);
  wait(|| {
    runtime
      .metrics()
      .snapshot()
      .threads
      .iter()
      .all(|t| t.parks > t.unparks)
  });
  let d = engine(&runtime.shared);
  let wakes_before = d.wake_searches.load(Ordering::Relaxed);
  let parks_before: usize = runtime
    .metrics()
    .snapshot()
    .threads
    .iter()
    .map(|t| t.parks)
    .sum();
  let mut polls = 0;
  let job = runtime
    .handle()
    .spawn(std::future::poll_fn(move |cx| {
      polls += 1;
      if polls == 10_000 {
        Poll::Ready(polls)
      } else {
        cx.waker().wake_by_ref();
        Poll::Pending
      }
    }))
    .unwrap();
  assert_eq!(finish(job).unwrap(), 10_000);
  // Poll-end requeues leave a dispatcher searching, without waking and
  // parking an idle searcher for each poll. Count wake attempts as well as
  // actual parks so notification churn cannot hide behind retained wakes.
  wait(|| (0..4).all(|seat| d.parked.is_set(seat)));
  let wakes = d.wake_searches.load(Ordering::Relaxed) - wakes_before;
  let parks: usize = runtime
    .metrics()
    .snapshot()
    .threads
    .iter()
    .map(|t| t.parks)
    .sum();
  assert!(wakes < 32, "{wakes} searcher wakes for 10,000 polls");
  assert!(
    parks - parks_before < 32,
    "park cycles proportional to polls"
  );
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn external_wakes_against_parked_lanes_are_not_lost() {
  each_spin_configuration(external_wakes_against_parked_lanes_are_not_lost_case);
}

fn external_wakes_against_parked_lanes_are_not_lost_case() {
  let runtime = runtime(4, 1);
  let (tx, rx) = mpsc::channel();
  let mut polls = 0;
  let job = runtime
    .handle()
    .spawn(std::future::poll_fn(move |cx| {
      polls += 1;
      if polls == 100_001 {
        Poll::Ready(())
      } else {
        tx.send(cx.waker().clone()).unwrap();
        Poll::Pending
      }
    }))
    .unwrap();
  for _ in 0..100_000 {
    rx.recv_timeout(Duration::from_secs(30)).unwrap().wake();
  }
  finish(job).unwrap();
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn shutdown_and_scope_close_reclaim_pending_and_quota_blocked_tasks() {
  each_spin_configuration(shutdown_and_scope_close_reclaim_pending_and_quota_blocked_tasks_case);
}

fn shutdown_and_scope_close_reclaim_pending_and_quota_blocked_tasks_case() {
  for mode in [AsyncShutdown::Drain, AsyncShutdown::CancelPending] {
    let runtime = runtime(4, 16);
    let scope = runtime
      .scope_with_config(AsyncScopeConfig {
        max_active_polls: 1,
      })
      .unwrap();
    let release = Arc::new(AtomicBool::new(false));
    let jobs: Vec<_> = (0..16)
      .map(|_| {
        let release = Arc::clone(&release);
        scope
          .spawn(std::future::poll_fn(move |cx| {
            if release.load(Ordering::Acquire) {
              Poll::Ready(())
            } else {
              cx.waker().wake_by_ref();
              Poll::Pending
            }
          }))
          .unwrap()
      })
      .collect();
    if mode == AsyncShutdown::Drain {
      release.store(true, Ordering::Release);
    }
    shutdown(runtime, mode);
    for job in jobs {
      match mode {
        AsyncShutdown::Drain => finish(job).unwrap(),
        AsyncShutdown::CancelPending => {
          assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)))
        }
      }
    }
    assert_eq!(scope.snapshot().active_polls, 0);
    drop(scope.close());
  }
}

#[test]
fn search_takes_stealable_work_before_one_overflow_entry() {
  each_spin_configuration(search_takes_stealable_work_before_one_overflow_entry_case);
}

fn search_takes_stealable_work_before_one_overflow_entry_case() {
  let (shared, root) = shared(config(2, 4));
  let d = engine(&shared);
  d.parked.advertise(0);
  let jobs: Vec<_> = (0..4)
    .map(|_| shared.spawn(root, async {}).unwrap())
    .collect();
  // Move one existing ready entry into overflow, preserving unique ownership.
  let overflow_index = {
    let mut queue = d.lane(1);
    let index = queue.pop(&d.links).unwrap();
    d.publish_depth(&shared, 1, &queue);
    index
  };
  {
    let mut queue = lock(&d.overflow, 4);
    queue.push(&d.links, overflow_index);
  }
  shared
    .metrics
    .inner()
    .overflow_depth
    .store(1, Ordering::SeqCst);
  let work = selected(&shared, 0).unwrap();
  match &work {
    Selected::Poll(reference, ..) => assert_ne!(reference.index, overflow_index),
    _ => panic!(),
  }
  run(&shared, work);
  assert_eq!(
    shared.metrics.inner().overflow_depth.load(Ordering::SeqCst),
    1
  );
  while let Some(work) = selected(&shared, 0).or_else(|| selected(&shared, 1)) {
    run(&shared, work);
  }
  for job in jobs {
    finish(job).unwrap();
  }
  check_distributed(&shared);
}

#[test]
fn distributed_control_charges_match_requested_and_actual_tables() {
  each_spin_configuration(distributed_control_charges_match_requested_and_actual_tables_case);
}

fn distributed_control_charges_match_requested_and_actual_tables_case() {
  let cfg = config(65, 129);
  let (shared, _) = shared(cfg);
  let d = engine(&shared);
  let expected = std::mem::size_of::<Shared>()
    + FreeSlots::requested_control(cfg.max_outstanding).unwrap()
    + payload_bytes::<ScopeSlot>(cfg.max_scopes).unwrap()
    + std::mem::size_of::<ScopeCell>()
    + Distributed::requested_control(cfg).unwrap();
  assert_eq!(shared._control.bytes(), expected);
  assert_eq!(
    d.actual_control().unwrap(),
    Distributed::requested_control(cfg).unwrap()
  );
  check_distributed(&shared);
}

#[test]
fn cleanup_is_quota_free_and_slot_reuse_ignores_stale_wakes() {
  each_spin_configuration(cleanup_is_quota_free_and_slot_reuse_ignores_stale_wakes_case);
}

fn cleanup_is_quota_free_and_slot_reuse_ignores_stale_wakes_case() {
  struct Probe {
    cell: Arc<ScopeCell>,
    dropped: Arc<AtomicUsize>,
  }
  impl Future for Probe {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for Probe {
    fn drop(&mut self) {
      // The other task alone owns the scope's permit throughout cleanup.
      assert_eq!(scope_snapshot(&self.cell).active_polls, 1);
      self.dropped.fetch_add(1, Ordering::Relaxed);
    }
  }
  let (shared, _) = shared(config(2, 2));
  let scope = shared.new_scope(1, None).unwrap();
  let first = scope.spawn(async {}).unwrap();
  let dropped = Arc::new(AtomicUsize::new(0));
  let second = scope
    .spawn(Probe {
      cell: Arc::clone(&scope.cell),
      dropped: Arc::clone(&dropped),
    })
    .unwrap();
  let holder = selected(&shared, 0).unwrap();
  assert!(selected(&shared, 1).is_none());
  let d = engine(&shared);
  let old = TaskRef {
    index: 1,
    generation: d.slot(1).protocol.generation(),
  };
  shared.abort(old);
  run(
    &shared,
    selected(&shared, 0)
      .or_else(|| selected(&shared, 1))
      .unwrap(),
  );
  assert_eq!(dropped.load(Ordering::Relaxed), 1);
  assert!(matches!(finish(second), Err(AsyncJoinError::Cancelled)));
  run(&shared, holder);
  finish(first).unwrap();
  let reused = scope.spawn(std::future::pending::<()>()).unwrap();
  let work = selected(&shared, 0)
    .or_else(|| selected(&shared, 1))
    .unwrap();
  let current = match &work {
    Selected::Poll(reference, ..) => *reference,
    _ => panic!(),
  };
  run(&shared, work);
  shared.wake(old);
  assert!(
    selected(&shared, 0)
      .or_else(|| selected(&shared, 1))
      .is_none()
  );
  shared.abort(current);
  run(
    &shared,
    selected(&shared, 0)
      .or_else(|| selected(&shared, 1))
      .unwrap(),
  );
  assert!(matches!(finish(reused), Err(AsyncJoinError::Cancelled)));
  check_distributed(&shared);
  drop(scope.close());
}

#[test]
fn unwind_outside_a_poll_moves_orphaned_entries_to_overflow() {
  each_spin_configuration(unwind_outside_a_poll_moves_orphaned_entries_to_overflow_case);
}

fn unwind_outside_a_poll_moves_orphaned_entries_to_overflow_case() {
  for handoffs in [0, 2] {
    let (shared, root) = shared_with_handoffs(config(2, 4), handoffs);
    let d = engine(&shared);
    let jobs: Vec<_> = (0..4)
      .map(|index| {
        d.next_lane.store(0, Ordering::Relaxed);
        shared.spawn(root, async move { index }).unwrap()
      })
      .collect();
    d.unwind_seat.store(0, Ordering::Relaxed);
    let failed = start_worker(&shared, 0);
    wait(|| failed.is_finished());
    assert!(failed.join().is_err());
    assert_eq!(
      shared.metrics.inner().overflow_depth.load(Ordering::SeqCst),
      4
    );
    assert!(d.parked.is_dead(0));
    check_distributed(&shared);
    let survivor = start_worker(&shared, 1);
    for (index, job) in jobs.into_iter().enumerate() {
      assert_eq!(finish(job).unwrap(), index);
    }
    wait(|| shared.metrics.inner().overflow_depth.load(Ordering::SeqCst) == 0);
    // Future target selection excludes the dead seat, including its last entry.
    for _ in 0..8 {
      d.next_lane.store(0, Ordering::Relaxed);
      finish(shared.spawn(root, async {}).unwrap()).unwrap();
      assert_eq!(d.lane(0).len(), 0);
    }
    shared.close(false);
    join_worker(survivor);
    assert_eq!(shared.turn_counts(), (0, 0, 0, 0));
    check_distributed(&shared);
  }
}

#[test]
fn round_robin_alternative_runs_the_same_wake_and_finish_paths() {
  each_spin_configuration(round_robin_alternative_runs_the_same_wake_and_finish_paths_case);
}

fn round_robin_alternative_runs_the_same_wake_and_finish_paths_case() {
  let runtime = runtime(4, 8);
  engine(&runtime.shared)
    .round_robin
    .store(true, Ordering::Relaxed);
  let jobs: Vec<_> = (0..8)
    .map(|_| {
      let mut polls = 0;
      runtime
        .handle()
        .spawn(std::future::poll_fn(move |cx| {
          polls += 1;
          if polls == 1000 {
            Poll::Ready(())
          } else {
            cx.waker().wake_by_ref();
            Poll::Pending
          }
        }))
        .unwrap()
    })
    .collect();
  for job in jobs {
    finish(job).unwrap();
  }
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn repeated_bursts_and_long_polls_leave_no_stealable_work_asleep() {
  each_search_configuration(|| {
    each_spin_configuration(repeated_bursts_and_long_polls_leave_no_stealable_work_asleep_case)
  });
}

fn repeated_bursts_and_long_polls_leave_no_stealable_work_asleep_case() {
  let runtime = runtime(4, 32);
  let mut random = 17u64;
  for _ in 0..8 {
    let jobs: Vec<_> = (0..32)
      .map(|_| {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let rounds = random as usize % 100 + 20;
        let mut polls = 0;
        runtime
          .handle()
          .spawn(std::future::poll_fn(move |cx| {
            polls += 1;
            if polls % 23 == 0 {
              std::thread::sleep(Duration::from_micros(50));
            }
            if polls == rounds {
              Poll::Ready(())
            } else {
              cx.waker().wake_by_ref();
              Poll::Pending
            }
          }))
          .unwrap()
      })
      .collect();
    for job in jobs {
      finish(job).unwrap();
    }
    wait(|| runtime.metrics().global_queue_depth() == 0);
    wait(|| {
      runtime
        .metrics()
        .snapshot()
        .threads
        .iter()
        .all(|t| t.parks > t.unparks)
    });
  }
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn abort_of_stolen_blocked_task_cleans_up_during_another_poll() {
  each_spin_configuration(abort_of_stolen_blocked_task_cleans_up_during_another_poll_case);
}

fn abort_of_stolen_blocked_task_cleans_up_during_another_poll_case() {
  let (parked, park_attempt) = mpsc::channel();
  let (unpark, continue_park) = mpsc::channel();
  let continue_park = Mutex::new(Some(continue_park));
  // Hold the searcher just before it advertises parking, keeping its parked
  // bit clear while the foreign abort inserts at the next rotating position.
  let (shared, _) = shared_with_options(
    config(2, 3),
    AsyncThreadOptions::new().on_thread_park(move |context| {
      if context.index == 1
        && let Some(resume) = continue_park.lock().unwrap().take()
      {
        parked.send(()).unwrap();
        resume.recv_timeout(Duration::from_secs(30)).unwrap();
      }
    }),
  );
  let scope = shared.new_scope(1, None).unwrap();
  let (entered, arrival) = mpsc::channel();
  let (release, resume) = mpsc::channel();
  let holder = scope
    .spawn(async move {
      entered.send(()).unwrap();
      resume.recv_timeout(Duration::from_secs(30)).unwrap();
    })
    .unwrap();
  struct Mark(Arc<AtomicBool>, Arc<ScopeCell>);
  impl Future for Mark {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for Mark {
    fn drop(&mut self) {
      assert_eq!(scope_snapshot(&self.1).active_polls, 1);
      self.0.store(true, Ordering::Release);
    }
  }
  let d = engine(&shared);
  let dropped = Arc::new(AtomicBool::new(false));
  d.next_lane.store(0, Ordering::Relaxed);
  let blocked = scope
    .spawn(Mark(Arc::clone(&dropped), Arc::clone(&scope.cell)))
    .unwrap();
  d.next_lane.store(0, Ordering::Relaxed);
  let tail = scope.spawn(std::future::pending::<()>()).unwrap();
  let start_worker = |index| {
    let shared = Arc::clone(&shared);
    std::thread::spawn(move || {
      worker(
        shared,
        AsyncThreadContext {
          role: AsyncThreadRole::Worker,
          index,
          physical_index: index,
        },
        super::super::super::entry::PreparedContextNodes::new(None, 1)
          .unwrap()
          .pop()
          .unwrap(),
      )
    })
  };
  let first_worker = start_worker(0);
  arrival.recv_timeout(Duration::from_secs(30)).unwrap();
  let second_worker = start_worker(1);
  park_attempt.recv_timeout(Duration::from_secs(30)).unwrap();
  assert_eq!(
    shared.metrics.inner().blocked_depth.load(Ordering::Relaxed),
    2
  );
  assert!(d.steals.load(Ordering::Relaxed) > 0);
  assert!(!d.parked.is_set(1));
  d.next_lane.store(1, Ordering::Relaxed);
  blocked.abort();
  unpark.send(()).unwrap();
  wait(|| dropped.load(Ordering::Acquire));
  assert_eq!(scope.snapshot().active_polls, 1);
  assert!(matches!(finish(blocked), Err(AsyncJoinError::Cancelled)));
  release.send(()).unwrap();
  finish(holder).unwrap();
  shared.close(true);
  join_worker(first_worker);
  join_worker(second_worker);
  assert!(matches!(finish(tail), Err(AsyncJoinError::Cancelled)));
  assert_eq!(scope.snapshot().active_polls, 0);
  check_distributed(&shared);
  drop(scope.close());
}

#[test]
fn cancellation_cleanup_releases_a_sibling_blocked_inside_poll() {
  each_spin_configuration(cancellation_cleanup_releases_a_sibling_blocked_inside_poll_case);
}

fn cancellation_cleanup_releases_a_sibling_blocked_inside_poll_case() {
  let (shared, root) = shared(config(2, 2));
  let (dropped, cleanup) = mpsc::channel();
  let (entered, arrival) = mpsc::channel();
  let holder = shared
    .spawn(root, async move {
      entered.send(()).unwrap();
      cleanup
        .recv_timeout(Duration::from_secs(5))
        .expect("sibling cancellation cleanup deadline");
    })
    .unwrap();
  struct Cleanup(Option<mpsc::Sender<()>>, mpsc::Sender<()>);
  impl Future for Cleanup {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
      if let Some(polled) = self.0.take() {
        polled.send(()).unwrap();
      }
      Poll::Pending
    }
  }
  impl Drop for Cleanup {
    fn drop(&mut self) {
      let _ = self.1.send(());
    }
  }
  let (polled, first_poll) = mpsc::channel();
  let sibling = shared.spawn(root, Cleanup(Some(polled), dropped)).unwrap();
  let first = start_worker(&shared, 0);
  arrival.recv_timeout(Duration::from_secs(30)).unwrap();
  let second = start_worker(&shared, 1);
  first_poll.recv_timeout(Duration::from_secs(30)).unwrap();
  wait(|| engine(&shared).parked.is_set(1));
  // Cancellation cleanup uses overflow and wakes the parked seat, even
  // though ordinary placement would select the busy dispatcher's lane.
  engine(&shared).next_lane.store(0, Ordering::Relaxed);
  sibling.abort_handle().abort();
  finish(holder).expect("blocked poll must observe cleanup before its deadline");
  assert!(matches!(finish(sibling), Err(AsyncJoinError::Cancelled)));
  shared.close(false);
  join_worker(first);
  join_worker(second);
  check_distributed(&shared);
}

#[test]
fn park_rescan_finds_work_published_before_park_advertisement() {
  each_spin_configuration(park_rescan_finds_work_published_before_park_advertisement_case);
}

fn park_rescan_finds_work_published_before_park_advertisement_case() {
  let (attempt, attempted) = mpsc::channel();
  let (resume, resumed) = mpsc::channel();
  let resumed = Mutex::new(Some(resumed));
  let (shared, root) = shared_with_options(
    config(2, 2),
    AsyncThreadOptions::new().on_thread_park(move |context| {
      if context.index == 1
        && let Some(resumed) = resumed.lock().unwrap().take()
      {
        attempt.send(()).unwrap();
        resumed.recv_timeout(Duration::from_secs(30)).unwrap();
      }
    }),
  );
  let (entered, arrival) = mpsc::channel();
  let (release, released) = mpsc::channel();
  let holder = shared
    .spawn(root, async move {
      entered.send(()).unwrap();
      released.recv_timeout(Duration::from_secs(30)).unwrap();
    })
    .unwrap();
  let first = start_worker(&shared, 0);
  arrival.recv_timeout(Duration::from_secs(30)).unwrap();
  let second = start_worker(&shared, 1);
  attempted.recv_timeout(Duration::from_secs(30)).unwrap();
  let d = engine(&shared);
  assert!(!d.parked.is_set(1));
  let (done, completion) = mpsc::channel();
  d.next_lane.store(0, Ordering::Relaxed);
  let short = shared
    .spawn(root, async move {
      done.send(()).unwrap();
    })
    .unwrap();
  assert_eq!(d.lane(0).len(), 1);
  resume.send(()).unwrap();
  let progress = completion.recv_timeout(Duration::from_secs(5));
  // Release the blocked poll even on a failed assertion.
  let _ = release.send(());
  assert!(
    progress.is_ok(),
    "park rescan deadline: stealable work left asleep"
  );
  finish(short).unwrap();
  finish(holder).unwrap();
  shared.close(false);
  join_worker(first);
  join_worker(second);
  check_distributed(&shared);
}

#[derive(Clone, Default)]
struct HandoffGate(Arc<AtomicBool>);
impl HandoffGate {
  fn open(&self) {
    self.0.store(true, Ordering::Release);
  }
  fn wait(&self) {
    wait(|| self.0.load(Ordering::Acquire));
  }
}
struct ReleaseHandoffs(Vec<HandoffGate>);
impl Drop for ReleaseHandoffs {
  fn drop(&mut self) {
    for gate in &self.0 {
      gate.open();
    }
  }
}

#[test]
fn handoff_restores_onto_another_lane_while_other_workers_keep_polling() {
  each_spin_configuration(handoff_restores_onto_another_lane_while_other_workers_keep_polling_case);
}

fn handoff_restores_onto_another_lane_while_other_workers_keep_polling_case() {
  use super::super::super::{HandoffConfig, try_block_in_place};
  // Keep worker one at its first park boundary until the helper has adopted
  // seat zero. A single entry no longer forces its assigned owner to run it.
  let bootstrap = HandoffGate::default();
  let _release_bootstrap = ReleaseHandoffs(vec![bootstrap.clone()]);
  let hold = bootstrap.clone();
  let once = AtomicBool::new(true);
  let (parked, park_attempt) = mpsc::channel();
  let options = AsyncThreadOptions::new().on_thread_park(move |context| {
    if context.role == AsyncThreadRole::Worker
      && context.index == 1
      && once.swap(false, Ordering::Relaxed)
    {
      parked.send(()).unwrap();
      hold.wait();
    }
  });
  let runtime = AsyncRuntime::new_with_options(
    config(2, 8),
    spin_options()
      .handoffs(HandoffConfig { max_handoffs: 2 })
      .thread_options(options),
  )
  .unwrap();
  let shared = Arc::clone(&runtime.shared);
  let d = engine(&shared);
  d.round_robin.store(true, Ordering::Relaxed);
  wait(|| shared.turn_counts() == (2, 0, 0, 0));
  park_attempt.recv_timeout(Duration::from_secs(30)).unwrap();
  let scopes: Vec<_> = (0..3)
    .map(|_| {
      runtime
        .scope_with_config(AsyncScopeConfig {
          max_active_polls: 4,
        })
        .unwrap()
    })
    .collect();
  let gates: Vec<_> = (0..6).map(|_| HandoffGate::default()).collect();
  let _release = ReleaseHandoffs(gates.clone());
  let (entered, arrival) = mpsc::channel();
  let (restored, restoration) = mpsc::channel();
  let first = {
    let (closure, poll) = (gates[0].clone(), gates[1].clone());
    d.next_lane.store(0, Ordering::Relaxed);
    scopes[0]
      .spawn(async move {
        try_block_in_place(|| {
          entered.send(()).unwrap();
          closure.wait();
        })
        .unwrap();
        restored.send(std::thread::current().id()).unwrap();
        poll.wait();
      })
      .unwrap()
  };
  arrival.recv_timeout(Duration::from_secs(30)).unwrap();
  // With worker one held, only the helper can run the entry on seat zero.
  let (entered, arrival) = mpsc::channel();
  let helper = {
    let gate = gates[2].clone();
    d.next_lane.store(0, Ordering::Relaxed);
    scopes[1]
      .spawn(async move {
        entered.send(()).unwrap();
        gate.wait();
      })
      .unwrap()
  };
  arrival.recv_timeout(Duration::from_secs(30)).unwrap();
  bootstrap.open();
  let (entered, arrival) = mpsc::channel();
  let (advanced, progress) = mpsc::channel();
  let other = {
    let (first_poll, second_poll, closure) = (gates[3].clone(), gates[4].clone(), gates[5].clone());
    let mut polls = 0;
    d.next_lane.store(1, Ordering::Relaxed);
    scopes[2]
      .spawn(std::future::poll_fn(move |cx| {
        polls += 1;
        if polls == 1 {
          entered.send(()).unwrap();
          first_poll.wait();
          cx.waker().wake_by_ref();
          return Poll::Pending;
        }
        advanced.send(()).unwrap();
        second_poll.wait();
        try_block_in_place(|| closure.wait()).unwrap();
        Poll::Ready(())
      }))
      .unwrap()
  };
  arrival.recv_timeout(Duration::from_secs(30)).unwrap();
  gates[0].open();
  wait(|| shared.turn_counts().2 == 1);
  // The worker on seat one starts another poll while restoration waits on
  // the helper's busy seat zero. No global restorer gate blocks this poll.
  d.next_lane.store(1, Ordering::Relaxed);
  gates[3].open();
  progress.recv_timeout(Duration::from_secs(30)).unwrap();
  assert_eq!(shared.turn_counts().2, 1);
  // That worker now hands off too; the waiting restorer must take seat one.
  gates[4].open();
  let original_thread = restoration.recv_timeout(Duration::from_secs(30)).unwrap();
  assert_eq!(shared.turn_counts().1, 1);
  d.next_lane.store(1, Ordering::Relaxed);
  let probe = runtime
    .handle()
    .spawn(async { std::thread::current().id() })
    .unwrap();
  assert_eq!(d.lane(1).len(), 1);
  gates[1].open();
  finish(first).unwrap();
  let deadline = Instant::now() + Duration::from_secs(5);
  while !probe.is_finished() {
    assert!(Instant::now() < deadline, "restored lane probe deadline");
    std::thread::yield_now();
  }
  assert_eq!(
    finish(probe).unwrap(),
    original_thread,
    "restorer must serve its newly acquired lane"
  );
  gates[5].open();
  gates[2].open();
  finish(other).unwrap();
  finish(helper).unwrap();
  wait(|| shared.turn_counts() == (2, 0, 0, 0));
  check_distributed(&shared);
  drop(scopes);
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn handoff_root_limit_stays_binding_and_uses_two_scope_locks() {
  each_spin_configuration(handoff_root_limit_stays_binding_and_uses_two_scope_locks_case);
}

fn handoff_root_limit_stays_binding_and_uses_two_scope_locks_case() {
  use super::super::super::HandoffConfig;
  let runtime = AsyncRuntime::new_with_options(
    config(2, 4),
    spin_options().handoffs(HandoffConfig { max_handoffs: 2 }),
  )
  .unwrap();
  let d = engine(&runtime.shared);
  wait(|| runtime.shared.turn_counts() == (2, 0, 0, 0));
  for limit in [2, 3, 4] {
    let scope = (limit != 2).then(|| {
      runtime
        .scope_with_config(AsyncScopeConfig {
          max_active_polls: limit,
        })
        .unwrap()
    });
    let handle = scope
      .as_ref()
      .map_or_else(|| runtime.handle(), |scope| scope.handle());
    let before = d.scope_locks.load(Ordering::Relaxed);
    finish(handle.spawn(async {}).unwrap()).unwrap();
    let expected = if limit < 4 { 2 } else { 0 };
    wait(|| d.scope_locks.load(Ordering::Relaxed) - before >= expected);
    assert_eq!(d.scope_locks.load(Ordering::Relaxed) - before, expected);
    if let Some(scope) = scope {
      drop(scope.close());
    }
  }
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn uncontended_handoff_and_restore_take_only_seat_and_kick_locks() {
  each_spin_configuration(uncontended_handoff_and_restore_take_only_seat_and_kick_locks_case);
}

fn uncontended_handoff_and_restore_take_only_seat_and_kick_locks_case() {
  let (shared, _) = shared_with_handoffs(config(2, 4), 2);
  let d = engine(&shared);
  let first = d.seats().claim(0);
  let second = d.seats().claim(1);
  let counters = || {
    (
      d.seat_locks.load(Ordering::Relaxed),
      d.lane_locks.load(Ordering::Relaxed),
      d.slot_locks.load(Ordering::Relaxed),
      d.scope_locks.load(Ordering::Relaxed),
      shared.lock_acquisitions.load(Ordering::Relaxed),
    )
  };
  let before = counters();
  let loan = shared.hand_off(first).unwrap();
  let after = counters();
  assert_eq!(
    after,
    (before.0 + 1, before.1, before.2, before.3, before.4)
  );
  let turn = shared.restore(
    loan,
    AsyncThreadContext {
      role: AsyncThreadRole::Worker,
      index: 0,
      physical_index: 0,
    },
  );
  assert_eq!(turn.seat(), 0);
  assert_eq!(
    counters(),
    (after.0 + 1, after.1, after.2, after.3, after.4)
  );
  d.seats().end_turn(turn);
  d.seats().end_turn(second);
  assert_eq!(shared.turn_counts(), (0, 0, 0, 0));
}

#[test]
fn restoration_can_adopt_an_abandoned_seat_after_its_lane_has_drained() {
  each_spin_configuration(restoration_can_adopt_an_abandoned_seat_after_its_lane_has_drained_case);
}

fn restoration_can_adopt_an_abandoned_seat_after_its_lane_has_drained_case() {
  let (shared, root) = shared_with_handoffs(config(2, 2), 1);
  let d = engine(&shared);
  let failed = d.seats().claim(0);
  let survivor = d.seats().claim(1);
  // Exercise a stale parked bit too; a live adopter must clear both masks.
  d.parked.advertise(0);
  d.abandon_turn(&shared, failed);
  assert!(d.parked.is_dead(0));
  let loan = d.hand_off(survivor).unwrap();
  let (lease, helper) = {
    let mut seats = d.seats();
    (
      seats.try_activate_helper().unwrap(),
      seats.try_begin_helper_turn().unwrap(),
    )
  };
  assert_eq!(helper.seat(), 1);
  let restored = shared.restore(
    loan,
    AsyncThreadContext {
      role: AsyncThreadRole::Worker,
      index: 1,
      physical_index: 1,
    },
  );
  assert_eq!(restored.seat(), 0);
  assert!(!d.parked.is_dead(0));
  assert!(!d.parked.is_set(0));
  d.next_lane.store(0, Ordering::Relaxed);
  let job = shared.spawn(root, async { 7 }).unwrap();
  assert_eq!(d.lane(0).len(), 1);
  run(&shared, selected(&shared, 0).unwrap());
  assert_eq!(finish(job).unwrap(), 7);
  let mut seats = d.seats();
  seats.end_turn(helper);
  seats.retire_helper(lease).unwrap();
  seats.end_turn(restored);
  seats.check();
}

fn run_dispatcher(shared: &Arc<Shared>, context: AsyncThreadContext, run: impl FnOnce()) {
  let control = super::super::super::entry::PreparedContextNodes::new(None, 1)
    .unwrap()
    .pop()
    .unwrap();
  super::super::executor_thread(shared, context, control, run);
}

fn helper_context() -> AsyncThreadContext {
  AsyncThreadContext {
    role: AsyncThreadRole::HandoffHelper,
    index: 0,
    physical_index: 2,
  }
}

fn worker_context(index: usize) -> AsyncThreadContext {
  AsyncThreadContext {
    role: AsyncThreadRole::Worker,
    index,
    physical_index: index,
  }
}

// Stop at a seat boundary with one worker waiting to resume and a restored
// helper holding its former seat. The second worker can still hand off.
fn helper_restored_a_yielded_worker_seat(
  d: &Distributed,
) -> (
  DispatchTurn,
  DispatchTurn,
  crate::runtime::asynchronous::handoff_protocol::HelperLease,
) {
  let mut seats = d.seats();
  let worker = seats.claim(0);
  let other = seats.claim(1);
  let loan = seats.try_hand_off(worker).unwrap();
  let lease = seats.try_activate_helper().unwrap();
  let helper = seats.try_begin_helper_turn().unwrap();
  let helper_loan = seats.try_hand_off(helper).unwrap();
  let ticket = seats.begin_restore(loan);
  let worker = seats.try_restore(ticket).unwrap();
  let ticket = seats.begin_restore(helper_loan);
  assert!(seats.worker_should_yield());
  seats.yield_worker(worker);
  let helper = seats.try_restore(ticket).unwrap();
  d.update_yield(&seats);
  seats.check();
  (other, helper, lease)
}

#[test]
fn handoff_helper_parks_instead_of_reacquiring_a_resuming_workers_seat() {
  each_spin_configuration(handoff_helper_parks_instead_of_reacquiring_a_resuming_workers_seat_case);
}

fn handoff_helper_parks_instead_of_reacquiring_a_resuming_workers_seat_case() {
  let (shared, root) = shared_with_handoffs(config(2, 4), 2);
  let d = engine(&shared);
  let (other, helper, lease) = helper_restored_a_yielded_worker_seat(d);
  let loan = {
    let mut seats = d.seats();
    seats.end_turn(helper);
    seats.retire_helper(lease).unwrap();
    let loan = seats.try_hand_off(other).unwrap();
    d.update_yield(&seats);
    loan
  };
  d.round_robin.store(true, Ordering::Relaxed);
  d.next_lane.store(0, Ordering::Relaxed);
  let job = shared.spawn(root, async { 7 }).unwrap();
  let helper = {
    let shared = Arc::clone(&shared);
    std::thread::spawn(move || {
      run_dispatcher(&shared, helper_context(), || {
        engine(&shared).helper(&shared, helper_context());
      });
    })
  };
  // A helper that ignores resuming repeatedly acquires and yields the seat
  // instead of parking. Exercise its actual loop, with a bounded observer.
  let deadline = Instant::now() + Duration::from_secs(5);
  let parks = &shared.metrics.inner().thread(2).unwrap().parks;
  while parks.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
    std::thread::yield_now();
  }
  let parked = parks.load(Ordering::Relaxed) != 0;
  let overtook = job.is_finished();
  let other = d.restore(&shared, loan, worker_context(1));
  let worker = d.resume_worker(&shared, worker_context(0));
  if !job.is_finished() {
    run(&shared, selected(&shared, worker.seat()).unwrap());
  }
  assert_eq!(finish(job).unwrap(), 7);
  shared.close(false);
  d.abandon_turn(&shared, worker);
  d.abandon_turn(&shared, other);
  join_worker(helper);
  assert!(
    parked,
    "helper reacquired a seat instead of parking for a resuming worker"
  );
  assert!(!overtook, "helper polled before the waiting worker resumed");
  assert_eq!(shared.turn_counts(), (0, 0, 0, 0));
}

#[test]
fn handoff_serving_helper_yields_to_a_resuming_worker_without_other_yield_reasons() {
  each_spin_configuration(
    handoff_serving_helper_yields_to_a_resuming_worker_without_other_yield_reasons_case,
  );
}

fn handoff_serving_helper_yields_to_a_resuming_worker_without_other_yield_reasons_case() {
  let (shared, root) = shared_with_handoffs(config(2, 4), 2);
  let d = engine(&shared);
  let (other, helper_turn, lease) = helper_restored_a_yielded_worker_seat(d);
  let loan = d.hand_off(other).unwrap();
  // One helper and one remaining loan: neither an excess helper nor a
  // waiting restoration can mask the resuming-worker condition.
  assert_eq!(shared.turn_counts(), (1, 1, 0, 1));
  d.round_robin.store(true, Ordering::Relaxed);
  d.next_lane.store(helper_turn.seat(), Ordering::Relaxed);
  let job = shared.spawn(root, async { 11 }).unwrap();
  let helper = {
    let shared = Arc::clone(&shared);
    std::thread::spawn(move || {
      run_dispatcher(&shared, helper_context(), || {
        engine(&shared).serve(&shared, helper_context(), helper_turn, true);
      });
    })
  };
  wait(|| helper.is_finished() || job.is_finished());
  let yielded = helper.is_finished();
  let overtook = job.is_finished();
  // Finish both the ordinary and mutated paths before reporting failure.
  let other = d.restore(&shared, loan, worker_context(1));
  let worker = d.resume_worker(&shared, worker_context(0));
  join_worker(helper);
  if !job.is_finished() {
    let work = selected(&shared, worker.seat())
      .or_else(|| selected(&shared, other.seat()))
      .unwrap();
    run(&shared, work);
  }
  assert_eq!(finish(job).unwrap(), 11);
  shared.close(false);
  {
    let mut seats = d.seats();
    seats.retire_helper(lease).unwrap();
    d.update_yield(&seats);
  }
  d.abandon_turn(&shared, worker);
  d.abandon_turn(&shared, other);
  assert!(yielded, "serving helper did not yield to a resuming worker");
  assert!(
    !overtook,
    "serving helper polled before the waiting worker resumed"
  );
  assert_eq!(shared.turn_counts(), (0, 0, 0, 0));
}

#[test]
fn handoff_helper_yield_hint_does_not_lock_worker_seats_per_poll() {
  each_spin_configuration(handoff_helper_yield_hint_does_not_lock_worker_seats_per_poll_case);
}

fn handoff_helper_yield_hint_does_not_lock_worker_seats_per_poll_case() {
  let (shared, root) = shared_with_handoffs(config(2, 4), 2);
  let d = engine(&shared);
  let (worker, helper, ticket, lease) = {
    let mut seats = d.seats();
    let original = seats.claim(0);
    let worker = seats.claim(1);
    let loan = seats.try_hand_off(original).unwrap();
    let lease = seats.try_activate_helper().unwrap();
    let helper = seats.try_begin_helper_turn().unwrap();
    let ticket = seats.begin_restore(loan);
    d.update_yield(&seats);
    (worker, helper, ticket, lease)
  };
  assert!(d.helper_yield.load(Ordering::Acquire));
  assert!(!d.worker_yield.load(Ordering::Acquire));
  d.round_robin.store(true, Ordering::Relaxed);
  d.next_lane.store(1, Ordering::Relaxed);
  let job = {
    let task_shared = Arc::clone(&shared);
    let mut counts = Vec::new();
    let mut polls = 0;
    shared
      .spawn(
        root,
        std::future::poll_fn(move |cx| {
          let d = engine(&task_shared);
          counts.push(d.seat_locks.load(Ordering::Relaxed));
          polls += 1;
          if polls == 16 {
            Poll::Ready(std::mem::take(&mut counts))
          } else {
            d.next_lane.store(1, Ordering::Relaxed);
            cx.waker().wake_by_ref();
            Poll::Pending
          }
        }),
      )
      .unwrap()
  };
  let worker = {
    let shared = Arc::clone(&shared);
    std::thread::spawn(move || {
      run_dispatcher(&shared, worker_context(1), || {
        engine(&shared).serve(&shared, worker_context(1), worker, false);
      });
    })
  };
  let counts = finish(job).unwrap();
  {
    let mut seats = d.seats();
    seats.end_turn(helper);
    let original = seats.try_restore(ticket).unwrap();
    seats.retire_helper(lease).unwrap();
    seats.end_turn(original);
    d.update_yield(&seats);
  }
  shared.close(false);
  join_worker(worker);
  assert_eq!(
    counts,
    vec![counts[0]; 16],
    "worker took seat locks between polls"
  );
  assert_eq!(shared.turn_counts(), (0, 0, 0, 0));
}

#[test]
fn exhausted_task_generation_is_skipped_without_hiding_other_slots() {
  each_spin_configuration(exhausted_task_generation_is_skipped_without_hiding_other_slots_case);
}

fn exhausted_task_generation_is_skipped_without_hiding_other_slots_case() {
  let (shared, root) = shared(config(1, 2));
  let d = engine(&shared);
  shared.lock().free_tasks.remove(0);
  {
    let mut slot = d.slot(0);
    slot.protocol.admit(u64::MAX);
    slot.protocol.release();
  }
  let job = shared.spawn(root, async { 7 }).unwrap();
  assert_eq!(d.slot(0).protocol.generation(), u64::MAX);
  let work = selected(&shared, 0).unwrap();
  assert!(matches!(&work, Selected::Poll(reference, ..) if reference.index == 1));
  run(&shared, work);
  assert_eq!(finish(job).unwrap(), 7);
  check_distributed(&shared);
  shared.close(false);
}

#[test]
fn all_exhausted_task_generations_return_full_without_admission() {
  each_spin_configuration(all_exhausted_task_generations_return_full_without_admission_case);
}

fn all_exhausted_task_generations_return_full_without_admission_case() {
  let (shared, root) = shared(config(1, 2));
  let d = engine(&shared);
  shared.lock().free_tasks.clear();
  for index in 0..2 {
    let mut slot = d.slot(index);
    slot.protocol.admit(u64::MAX);
    slot.protocol.release();
  }
  let error = shared
    .spawn(root, std::future::pending::<()>())
    .unwrap_err();
  assert_eq!(error.kind, AsyncError::Full);
  drop(error.into_future());
  check_distributed(&shared);
  shared.close(false);
}

#[test]
fn free_task_bitmap_reuses_the_lowest_completed_slot() {
  each_spin_configuration(free_task_bitmap_reuses_the_lowest_completed_slot_case);
}

fn free_task_bitmap_reuses_the_lowest_completed_slot_case() {
  let (shared, root) = shared(config(1, 4));
  let d = engine(&shared);
  let jobs: Vec<_> = (0..4)
    .map(|_| shared.spawn(root, std::future::pending::<()>()).unwrap())
    .collect();
  for _ in 0..4 {
    run(&shared, selected(&shared, 0).unwrap());
  }
  for index in [2, 0, 3, 1] {
    shared.abort(TaskRef {
      index,
      generation: 1,
    });
    run(&shared, selected(&shared, 0).unwrap());
    check_distributed(&shared);
  }
  for job in jobs {
    assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)));
  }
  let reused = shared.spawn(root, async {}).unwrap();
  assert_eq!(d.slot(0).protocol.generation(), 2);
  let work = selected(&shared, 0).unwrap();
  assert!(matches!(&work, Selected::Poll(reference, ..) if reference.index == 0));
  run(&shared, work);
  finish(reused).unwrap();
  check_distributed(&shared);
  shared.close(false);
}

#[test]
fn running_wakes_coalesce_and_stale_generations_do_not_wake_reused_slots() {
  each_spin_configuration(
    running_wakes_coalesce_and_stale_generations_do_not_wake_reused_slots_case,
  );
}

fn running_wakes_coalesce_and_stale_generations_do_not_wake_reused_slots_case() {
  let (shared, root) = shared(config(1, 1));
  let d = engine(&shared);
  let old_job = shared.spawn(root, std::future::pending::<()>()).unwrap();
  let old_task = d.slot(0).task.clone().unwrap();
  let old = TaskRef {
    index: 0,
    generation: 1,
  };
  run(&shared, selected(&shared, 0).unwrap());
  shared.abort(old);
  run(&shared, selected(&shared, 0).unwrap());
  assert!(matches!(finish(old_job), Err(AsyncJoinError::Cancelled)));
  let job = shared.spawn(root, std::future::pending::<()>()).unwrap();
  let work = selected(&shared, 0).unwrap();
  let current = match &work {
    Selected::Poll(reference, ..) => *reference,
    _ => panic!("expected a poll"),
  };
  let task = match &work {
    Selected::Poll(_, task, _) => task.clone(),
    _ => panic!(),
  };
  let wake = |task: &Pin<Arc<dyn ErasedTask>>, reference| {
    Shared::wake_task(&Arc::downgrade(&shared), task.poll_word(), reference)
  };
  assert_ne!(old.generation, current.generation);
  wake(&old_task, old);
  assert_eq!(task.poll_word().flags(), (true, false));
  for _ in 0..3 {
    wake(&task, current);
  }
  assert_eq!(task.poll_word().flags(), (true, true));
  run(&shared, work);
  // The pending finish kept `NOTIFIED` for the one requeued entry.
  assert_eq!(task.poll_word().flags(), (false, true));
  assert!(old_task.poll_word().is_complete());
  check_distributed(&shared);
  run(&shared, selected(&shared, 0).unwrap());
  assert_eq!(task.poll_word().flags(), (false, false));
  wake(&old_task, old);
  assert!(selected(&shared, 0).is_none());
  shared.abort(current);
  run(&shared, selected(&shared, 0).unwrap());
  assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)));
  check_distributed(&shared);
  shared.close(false);
}

#[test]
fn abort_during_pending_poll_releases_quota_before_cleanup() {
  each_spin_configuration(abort_during_pending_poll_releases_quota_before_cleanup_case);
}

fn abort_during_pending_poll_releases_quota_before_cleanup_case() {
  let runtime = runtime(1, 1);
  let scope = runtime
    .scope_with_config(AsyncScopeConfig {
      max_active_polls: 1,
    })
    .unwrap();
  let cell = Arc::clone(&scope.cell);
  let (entered, arrival) = mpsc::channel();
  let (release, resume) = mpsc::channel();
  let polls = Arc::new(AtomicUsize::new(0));
  struct Probe {
    cell: Arc<ScopeCell>,
    entered: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
    polls: Arc<AtomicUsize>,
  }
  impl Future for Probe {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
      self.polls.fetch_add(1, Ordering::Relaxed);
      self.entered.send(()).unwrap();
      self.resume.recv_timeout(Duration::from_secs(30)).unwrap();
      cx.waker().wake_by_ref();
      Poll::Pending
    }
  }
  impl Drop for Probe {
    fn drop(&mut self) {
      assert_eq!(scope_snapshot(&self.cell).active_polls, 0);
    }
  }
  let job = scope
    .spawn(Probe {
      cell,
      entered,
      resume,
      polls: Arc::clone(&polls),
    })
    .unwrap();
  arrival.recv_timeout(Duration::from_secs(30)).unwrap();
  job.abort();
  let mut close = Box::pin(scope.close());
  assert!(
    close
      .as_mut()
      .poll(&mut Context::from_waker(Waker::noop()))
      .is_pending()
  );
  release.send(()).unwrap();
  assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)));
  assert_eq!(polls.load(Ordering::Relaxed), 1);
  wait(|| {
    close
      .as_mut()
      .poll(&mut Context::from_waker(Waker::noop()))
      .is_ready()
  });
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn fixed_rounds_are_unchanged_by_repeated_idle_parks() {
  for rounds in [0, 128, 4096] {
    TEST_SPIN_POLICY.set(Policy {
      rounds,
      max_spinners: Some(1),
      max_searchers: TEST_SEARCH_CAP.get(),
    });
    let (shared, root) = shared(config(1, 1));
    let d = engine(&shared);
    let job = shared.spawn(root, async {}).unwrap();
    let worker = start_worker(&shared, 0);
    finish(job).unwrap();
    wait(|| lane_sleeping(&shared, 0));
    assert_eq!(d.spin_rounds.load(Ordering::Relaxed), rounds as usize);
    assert_eq!(d.spinners.current(), 0);
    for _ in 0..12 {
      let before = d.spin_rounds.load(Ordering::Relaxed);
      let parks = shared.metrics.snapshot().threads[0].parks;
      d.kick(0);
      wait(|| shared.metrics.snapshot().threads[0].parks > parks && lane_sleeping(&shared, 0));
      assert_eq!(
        d.spin_rounds.load(Ordering::Relaxed) - before,
        rounds as usize
      );
      assert_eq!(d.spinners.current(), 0);
    }
    shared.close(false);
    join_worker(worker);
    assert_eq!(d.spinners.current(), 0);
  }
  TEST_SPIN_POLICY.set(Policy::default());
}

#[test]
fn public_fixed_spin_and_spinner_cap_options() {
  use super::super::super::ParkSpin;
  for rounds in [0, 128, 4096] {
    for cap in [None, Some(0), Some(1), Some(usize::MAX)] {
      let mut options = AsyncRuntimeOptions::new();
      if let Some(cap) = cap {
        options = options.max_spinning_dispatchers(cap);
      }
      // Setting rounds must preserve the previously selected cap.
      options = options.park_spin(ParkSpin::fixed(rounds));
      let runtime = AsyncRuntime::new_with_options(config(1, 1), options).unwrap();
      let shared = Arc::clone(&runtime.shared);
      wait(|| lane_sleeping(&shared, 0));
      assert_eq!(
        engine(&shared).spin_rounds.load(Ordering::Relaxed),
        if cap == Some(0) { 0 } else { rounds as usize }
      );
      assert_eq!(engine(&shared).spinners.current(), 0);
      shutdown(runtime, AsyncShutdown::Drain);
      assert_eq!(engine(&shared).spinners.current(), 0);
    }
  }
}

#[test]
fn spinner_limit_binds_only_below_the_worker_seat_count() {
  for (rounds, cap, handoffs, limited) in [
    (128, None, 0, false),
    (128, None, 1, false),
    (128, Some(5), 1, false),
    (128, Some(4), 1, false),
    (128, Some(3), 1, true),
    (128, Some(3), 0, true),
    (0, Some(0), 1, false),
  ] {
    let d = Distributed::new(
      config(4, 4),
      handoffs,
      Policy {
        rounds,
        max_spinners: cap,
        max_searchers: TEST_SEARCH_CAP.get(),
      },
    )
    .unwrap();
    assert_eq!(d.limit_spinners, limited);
  }
}

#[test]
fn default_spin_does_not_acquire_spinner_slots() {
  let runtime = AsyncRuntime::new_with_options(config(4, 4), AsyncRuntimeOptions::new()).unwrap();
  let shared = Arc::clone(&runtime.shared);
  wait(|| (0..4).all(|seat| lane_sleeping(&shared, seat)));
  let d = engine(&shared);
  assert!(d.spin_rounds.load(Ordering::Relaxed) > 0);
  assert_eq!(d.spinners.acquisitions(), 0);
  shutdown(runtime, AsyncShutdown::Drain);
  assert_eq!(d.spinners.acquisitions(), 0);
}

#[test]
fn burst_respects_spinner_cap_and_denied_dispatchers_park_immediately() {
  for cap in [1, 2] {
    TEST_SPIN_POLICY.set(Policy {
      rounds: 4096,
      max_spinners: Some(cap),
      max_searchers: TEST_SEARCH_CAP.get(),
    });
    let (shared, root) = shared(config(4, 64));
    let d = engine(&shared);
    // Spinning also requires search admission. Hold the effective cap so
    // the fixture works when search admission is lower than the spin cap.
    let cap = cap.min(d.searching.max_for_test());
    let (entered, entering) = mpsc::channel();
    let mut releases = Vec::new();
    let mut workers = Vec::new();
    // Hold exactly K actual dispatchers inside their first spin round.
    // The remaining dispatchers encounter a full cap during the same burst.
    for index in 0..cap {
      let (release, resume) = mpsc::channel();
      releases.push(release);
      let entered = entered.clone();
      let shared = Arc::clone(&shared);
      workers.push(std::thread::spawn(move || {
        SPIN_HOOK.with(|hook| {
          *hook.borrow_mut() = Some(Box::new(move || {
            entered.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(30)).unwrap();
          }));
        });
        worker(
          shared,
          AsyncThreadContext {
            role: AsyncThreadRole::Worker,
            index,
            physical_index: index,
          },
          super::super::super::entry::PreparedContextNodes::new(None, 1)
            .unwrap()
            .pop()
            .unwrap(),
        );
      }));
    }
    for _ in 0..cap {
      entering.recv_timeout(Duration::from_secs(30)).unwrap();
    }
    assert_eq!(d.spinners.current(), cap);
    let before = d.spin_rounds.load(Ordering::Relaxed);
    for index in cap..4 {
      workers.push(start_worker(&shared, index));
    }
    wait(|| (cap..4).all(|seat| lane_sleeping(&shared, seat)));
    // No spin round ran on any dispatcher denied a slot.
    assert_eq!(d.spin_rounds.load(Ordering::Relaxed), before);
    assert_eq!(d.max_concurrent_spinners.load(Ordering::Relaxed), cap);
    for release in releases {
      release.send(()).unwrap();
    }
    wait(|| (0..4).all(|seat| lane_sleeping(&shared, seat)));
    assert_eq!(d.spinners.current(), 0);
    let jobs: Vec<_> = (0..64)
      .map(|_| {
        shared
          .spawn(root, async {
            for _ in 0..8 {
              super::super::super::yield_now().await;
            }
          })
          .unwrap()
      })
      .collect();
    for job in jobs {
      finish(job).unwrap();
    }
    wait(|| (0..4).all(|seat| lane_sleeping(&shared, seat)));
    assert_eq!(d.spinners.current(), 0);
    shared.close(false);
    for worker in workers {
      join_worker(worker);
    }
    assert_eq!(d.spinners.current(), 0);
    assert!(d.max_concurrent_spinners.load(Ordering::Relaxed) <= cap);
  }
  TEST_SPIN_POLICY.set(Policy::default());
}

#[test]
fn dispatcher_unwind_inside_spin_releases_its_slot() {
  TEST_SPIN_POLICY.set(Policy {
    rounds: 128,
    max_spinners: Some(1),
    max_searchers: TEST_SEARCH_CAP.get(),
  });
  let (shared, _) = shared(config(2, 1));
  SPIN_HOOK.with(|hook| {
    *hook.borrow_mut() = Some(Box::new(|| panic!("injected spin unwind")));
  });
  let d = engine(&shared);
  let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    d.run_seat(
      &shared,
      AsyncThreadContext {
        role: AsyncThreadRole::Worker,
        index: 0,
        physical_index: 0,
      },
    );
  }));
  assert!(result.is_err());
  assert_eq!(d.spinners.current(), 0);
  assert_eq!(shared.turn_counts(), (0, 0, 0, 0));
  assert_eq!(d.spinners.acquisitions(), 1);
  shared.close(false);
  TEST_SPIN_POLICY.set(Policy::default());
}

#[test]
fn final_shared_drop_cleans_admitted_future_with_retained_handles() {
  struct PendingDrop(Arc<AtomicBool>);
  impl Future for PendingDrop {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
      Poll::Pending
    }
  }
  impl Drop for PendingDrop {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
    }
  }
  let (shared, root) = shared(config(1, 1));
  let dropped = Arc::new(AtomicBool::new(false));
  let mut job = shared
    .spawn(root, PendingDrop(Arc::clone(&dropped)))
    .unwrap();
  let abort = job.abort_handle();
  let task = engine(&shared).slot(0).task.as_ref().unwrap().clone();
  let waker = task.clone().task_waker();
  assert!(!dropped.load(Ordering::SeqCst));
  drop(shared);
  assert!(dropped.load(Ordering::SeqCst));
  assert!(abort.is_finished());
  waker.wake_by_ref();
  assert!(matches!(
    Pin::new(&mut job).poll(&mut Context::from_waker(Waker::noop())),
    Poll::Ready(Err(AsyncJoinError::Cancelled))
  ));
}

#[test]
fn woken_own_pop_keeps_a_searcher_or_kick_for_other_lanes() {
  TEST_SPIN_POLICY.set(Policy {
    max_searchers: Some(1),
    ..Policy::default()
  });
  let (shared, root) = shared(config(3, 3));
  let d = engine(&shared);
  let mut finder = Some(d.searching.try_enter().unwrap());
  for seat in [1, 2] {
    d.parked.advertise(seat);
    assert!(d.lane(seat).prepare_sleep());
  }
  d.next_lane.store(0, Ordering::Relaxed);
  let other = shared.spawn(root, async {}).unwrap();
  d.next_lane.store(1, Ordering::Relaxed);
  d.found_work(&shared, &mut finder);
  assert!(d.lane(1).search_kick);
  assert!(d.parked.is_set(2));
  d.next_lane.store(1, Ordering::Relaxed);
  let own = shared.spawn(root, async {}).unwrap();
  let wakes = d.wake_searches.load(Ordering::Relaxed);
  let work = selected(&shared, 1).unwrap();
  assert_eq!(d.lane(0).len(), 1);
  assert_eq!(d.searching.current(), 0);
  assert!(
    d.searching.pending() != 0 || !d.parked.is_set(2),
    "woken own-pop consumed the last search receipt beside another lane's work"
  );
  assert_eq!(d.wake_searches.load(Ordering::Relaxed) - wakes, 1);
  run(&shared, work);
  run(&shared, selected(&shared, 0).unwrap());
  finish(own).unwrap();
  finish(other).unwrap();
}

#[test]
fn yielding_dispatcher_passes_search_coverage_before_seat_handoff() {
  for (receipt, left_before_yield) in [(false, false), (true, false), (false, true)] {
    TEST_SPIN_POLICY.set(Policy {
      max_searchers: Some(1),
      ..Policy::default()
    });
    let (shared, root) = shared(config(3, 1));
    let d = engine(&shared);
    let mut guard = (!receipt).then(|| d.searching.try_enter().unwrap());
    d.parked.advertise(2);
    assert!(d.lane(2).prepare_sleep());
    if receipt {
      d.searching.kicked();
      d.lane(1).search_kick = true;
    }
    d.next_lane.store(0, Ordering::Relaxed);
    let job = shared.spawn(root, async {}).unwrap();
    assert_eq!(d.searching.pending(), usize::from(receipt));
    if left_before_yield {
      // The park path dropped searching and rescanned queued work, then
      // observed a yield hint on its next iteration.
      drop(guard.take());
    }
    let wakes = d.wake_searches.load(Ordering::Relaxed);
    d.retire_search_kick(&shared, 1, &mut guard);
    assert!(guard.is_none());
    assert!(!d.lane(1).search_kick);
    assert!(d.lane(2).search_kick);
    assert_eq!(d.searching.pending(), 1);
    assert_eq!(d.wake_searches.load(Ordering::Relaxed) - wakes, 1);
    run(&shared, selected(&shared, 2).unwrap());
    finish(job).unwrap();
  }
}

#[test]
fn woken_recheck_and_denied_overflow_pop_keep_last_searcher_coverage() {
  TEST_SPIN_POLICY.set(Policy {
    max_searchers: Some(1),
    ..Policy::default()
  });
  let (shared, root) = shared(config(3, 2));
  let d = engine(&shared);
  let mut guard = Some(d.searching.try_enter().unwrap());
  d.parked.advertise(2);
  assert!(d.lane(2).prepare_sleep());
  d.searching.kicked();
  d.lane(1).search_kick = true;
  d.kick(1);
  d.next_lane.store(0, Ordering::Relaxed);
  let other = shared.spawn(root, async {}).unwrap();
  let cleanup = shared.spawn(root, std::future::pending::<()>()).unwrap();
  cleanup.abort();
  let mut denied = None;
  assert!(matches!(
    d.search(&shared, 1, &mut 1, &mut denied),
    Search::Recheck
  ));
  assert!(d.lane(1).search_kick);
  assert_eq!(d.searching.pending(), 1);
  let Search::Got(index) = d.search(&shared, 1, &mut 1, &mut denied) else {
    panic!("denied receiver did not take overflow cleanup");
  };
  assert!(denied.is_none());
  assert_eq!(d.searching.pending(), 0);
  assert!(d.parked.is_set(2));
  d.found_work(&shared, &mut guard);
  assert!(d.lane(2).search_kick);
  run(&shared, d.dispatch_decision(&shared, index).unwrap());
  run(&shared, selected(&shared, 2).unwrap());
  assert!(matches!(finish(cleanup), Err(AsyncJoinError::Cancelled)));
  finish(other).unwrap();
}

#[test]
fn metrics_handle_reads_the_admission_count_and_unbinds_with_the_scheduler() {
  let (shared, root) = shared(config(1, 2));
  let metrics = shared.metrics.clone();
  assert!(metrics.admission_bound());
  assert_eq!(metrics.num_alive_tasks(), 0);
  let job = shared.spawn(root, async {}).unwrap();
  assert_eq!(metrics.num_alive_tasks(), 1);
  run(&shared, selected(&shared, 0).unwrap());
  finish(job).unwrap();
  assert_eq!(metrics.num_alive_tasks(), 0);
  shared.close(false);
  check_distributed(&shared);
  // The scheduler's `Drop` unbinds the handle, so a retained handle neither
  // pins the scheduler's allocation nor reads anything but zero.
  drop(shared);
  assert!(!metrics.admission_bound());
  assert_eq!(metrics.num_alive_tasks(), 0);
}

/// A pending future the test completes by setting its flag.
fn gated(open: &Arc<AtomicBool>) -> impl Future<Output = ()> + Send + 'static {
  let open = Arc::clone(open);
  std::future::poll_fn(move |_| {
    if open.load(Ordering::Acquire) {
      Poll::Ready(())
    } else {
      Poll::Pending
    }
  })
}

fn poll_reference(work: &Selected) -> (TaskRef, Pin<Arc<dyn ErasedTask>>) {
  match work {
    Selected::Poll(reference, task, _) => (*reference, task.clone()),
    Selected::Cancel(..) => panic!("expected a poll"),
  }
}

#[test]
fn wakes_racing_a_pending_finish_leave_exactly_one_entry() {
  let (shared, root) = shared(config(1, 1));
  for round in 0..500 {
    let open = Arc::new(AtomicBool::new(false));
    let job = shared.spawn(root, gated(&open)).unwrap();
    let work = selected(&shared, 0).unwrap();
    let (reference, task) = poll_reference(&work);
    let waker = {
      let shared = Arc::downgrade(&shared);
      let task = task.clone();
      std::thread::spawn(move || {
        for _ in 0..1 + round % 3 {
          Shared::wake_task(&shared, task.poll_word(), reference);
        }
      })
    };
    run(&shared, work);
    waker.join().unwrap();
    // Requeued by the finish or by an idle wake, never both or neither.
    assert_eq!(task.poll_word().flags(), (false, true));
    check_distributed(&shared);
    open.store(true, Ordering::Release);
    run(&shared, selected(&shared, 0).unwrap());
    finish(job).unwrap();
    assert!(task.poll_word().is_complete());
    assert!(selected(&shared, 0).is_none());
    check_distributed(&shared);
  }
}

#[test]
fn external_wakes_racing_running_polls_are_never_lost() {
  const WAKERS: usize = 4;
  const WAKES: usize = 2_000;
  let runtime = runtime(2, 4);
  let tokens = Arc::new(AtomicUsize::new(0));
  let consumed = Arc::new(AtomicUsize::new(0));
  let (tx, rx) = mpsc::channel::<Waker>();
  let job = {
    let tokens = Arc::clone(&tokens);
    let consumed = Arc::clone(&consumed);
    let mut tx = Some(tx);
    runtime
      .handle()
      .spawn(std::future::poll_fn(move |cx| {
        if let Some(tx) = tx.take() {
          for _ in 0..WAKERS {
            tx.send(cx.waker().clone()).unwrap();
          }
        }
        let taken = tokens.swap(0, Ordering::AcqRel);
        if consumed.fetch_add(taken, Ordering::AcqRel) + taken == WAKERS * WAKES {
          Poll::Ready(())
        } else {
          Poll::Pending
        }
      }))
      .unwrap()
  };
  let wakers: Vec<_> = (0..WAKERS)
    .map(|_| {
      let waker = rx.recv_timeout(Duration::from_secs(30)).unwrap();
      let tokens = Arc::clone(&tokens);
      std::thread::spawn(move || {
        for _ in 0..WAKES {
          tokens.fetch_add(1, Ordering::AcqRel);
          waker.wake_by_ref();
        }
      })
    })
    .collect();
  for waker in wakers {
    waker.join().unwrap();
  }
  // A lost wake would leave the last tokens unconsumed and the task idle.
  finish(job).unwrap();
  assert_eq!(consumed.load(Ordering::Acquire), WAKERS * WAKES);
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn abort_while_running_requeues_to_cleanup_and_cancels_on_dispatch() {
  let (shared, root) = shared(config(1, 1));
  let open = Arc::new(AtomicBool::new(false));
  let job = shared.spawn(root, gated(&open)).unwrap();
  let work = selected(&shared, 0).unwrap();
  let (reference, task) = poll_reference(&work);
  shared.abort(reference);
  // Abort only marked the running word; the slot stays admitted.
  assert_eq!(task.poll_word().flags(), (true, true));
  assert!(engine(&shared).slot(reference.index).protocol.aborting());
  // Ready output after the abort would win; keep the poll pending.
  run(&shared, work);
  let d = engine(&shared);
  assert_eq!(lock(&d.overflow, 4).check(&d.links), [reference.index]);
  assert!(d.lane(0).check(&d.links).is_empty());
  check_distributed(&shared);
  match selected(&shared, 0).unwrap() {
    work @ Selected::Cancel(..) => run(&shared, work),
    Selected::Poll(..) => panic!("aborted task was polled again"),
  }
  assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)));
  assert!(task.poll_word().is_complete());
  Shared::wake_task(&Arc::downgrade(&shared), task.poll_word(), reference);
  assert!(selected(&shared, 0).is_none());
  check_distributed(&shared);
}

#[test]
fn abort_of_idle_task_racing_wake_inserts_one_entry_and_cancels() {
  let (shared, root) = shared(config(1, 1));
  for _ in 0..500 {
    let open = Arc::new(AtomicBool::new(false));
    let job = shared.spawn(root, gated(&open)).unwrap();
    let work = selected(&shared, 0).unwrap();
    let (reference, task) = poll_reference(&work);
    run(&shared, work);
    assert_eq!(task.poll_word().flags(), (false, false));
    let start = Arc::new(std::sync::Barrier::new(2));
    let waker = {
      let shared = Arc::downgrade(&shared);
      let task = task.clone();
      let start = Arc::clone(&start);
      std::thread::spawn(move || {
        start.wait();
        Shared::wake_task(&shared, task.poll_word(), reference);
      })
    };
    start.wait();
    shared.abort(reference);
    waker.join().unwrap();
    assert!(task.poll_word().is_queued());
    check_distributed(&shared);
    match selected(&shared, 0).unwrap() {
      work @ Selected::Cancel(..) => run(&shared, work),
      Selected::Poll(..) => panic!("aborted task was polled again"),
    }
    assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)));
    assert!(selected(&shared, 0).is_none());
    check_distributed(&shared);
  }
}

#[test]
fn drain_close_counts_notified_tasks_that_have_not_begun() {
  let (shared, root) = shared(config(1, 2));
  let d = engine(&shared);
  let open = Arc::new(AtomicBool::new(false));
  let woken = shared.spawn(root, gated(&open)).unwrap();
  let work = selected(&shared, 0).unwrap();
  let (reference, task) = poll_reference(&work);
  run(&shared, work);
  // One task woken after an idle finish, one never dispatched.
  Shared::wake_task(&Arc::downgrade(&shared), task.poll_word(), reference);
  let fresh = shared.spawn(root, async { 7 }).unwrap();
  open.store(true, Ordering::Release);
  shared.close(false);
  assert_eq!(shared.lock().admitted, 2);
  assert!(!d.closed_empty.load(Ordering::Acquire));
  run(&shared, selected(&shared, 0).unwrap());
  assert!(!d.closed_empty.load(Ordering::Acquire));
  run(&shared, selected(&shared, 0).unwrap());
  finish(woken).unwrap();
  assert_eq!(finish(fresh).unwrap(), 7);
  assert_eq!(shared.lock().admitted, 0);
  assert!(d.closed_empty.load(Ordering::Acquire));
  check_distributed(&shared);
}

#[test]
fn cancel_close_cancels_notified_tasks_that_have_not_begun() {
  let (shared, root) = shared(config(1, 2));
  let d = engine(&shared);
  let open = Arc::new(AtomicBool::new(false));
  let woken = shared.spawn(root, gated(&open)).unwrap();
  let work = selected(&shared, 0).unwrap();
  let (reference, task) = poll_reference(&work);
  run(&shared, work);
  Shared::wake_task(&Arc::downgrade(&shared), task.poll_word(), reference);
  let fresh = shared.spawn(root, async { 7 }).unwrap();
  shared.close(true);
  assert_eq!(shared.lock().admitted, 2);
  for _ in 0..2 {
    match selected(&shared, 0).unwrap() {
      work @ Selected::Cancel(..) => run(&shared, work),
      Selected::Poll(..) => panic!("cancelled close polled a queued task"),
    }
  }
  assert!(matches!(finish(woken), Err(AsyncJoinError::Cancelled)));
  assert!(matches!(finish(fresh), Err(AsyncJoinError::Cancelled)));
  assert!(d.closed_empty.load(Ordering::Acquire));
  check_distributed(&shared);
}
