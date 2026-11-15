//! `SearchWake::AfterStreak`: search wakes come from a run of own-lane pops
//! that each left work behind, and one parked dispatcher looks at the lanes
//! on a fixed period.

use super::super::super::super::SearchWake;
use super::*;

/// A fixture scheduler with the streak rule.
fn streak_shared(config: AsyncConfig) -> (Arc<Shared>, ScopeRef) {
  TEST_SPIN_POLICY.set(Policy {
    search_wake: SearchWake::AfterStreak,
    ..Policy::default()
  });
  let built = shared(config);
  TEST_SPIN_POLICY.set(Policy::default());
  built
}

fn streak_runtime(workers: usize, tasks: usize) -> AsyncRuntime {
  AsyncRuntime::new_with_options(
    config(workers, tasks),
    AsyncRuntimeOptions::new().search_wake(SearchWake::AfterStreak),
  )
  .unwrap()
}

fn park(shared: &Shared, seat: usize) {
  let d = engine(shared);
  d.parked.advertise(seat);
  assert!(d.lane(seat).prepare_sleep());
}

#[test]
fn insertions_and_single_pops_wake_no_searcher_under_the_streak_rule() {
  let (shared, root) = streak_shared(config(2, 4));
  let d = engine(&shared);
  park(&shared, 0);
  let wakes = d.wake_searches.load(Ordering::Relaxed);
  // Newly ready work on the awake dispatcher's lane: no search wake.
  let jobs: Vec<_> = (0..3)
    .map(|_| {
      d.next_lane.store(1, Ordering::Relaxed);
      shared.spawn(root, async {}).unwrap()
    })
    .collect();
  assert_eq!(d.lane(1).check(&d.links()).len(), 3);
  // Pops that leave work behind, fewer than the streak: none either.
  for _ in 0..3 {
    run(&shared, selected(&shared, 1).unwrap());
  }
  assert_eq!(d.wake_searches.load(Ordering::Relaxed), wakes);
  assert!(d.parked.is_set(0));
  for job in jobs {
    finish(job).unwrap();
  }
  d.lane(0).finish_sleep();
  d.parked.claim(0);
  shared.close(false);
  check_distributed(&shared);
}

#[test]
fn a_run_of_own_lane_pops_that_leave_work_wakes_one_searcher() {
  let streak = SEARCH_WAKE_STREAK as usize;
  let (shared, root) = streak_shared(config(2, 2 * streak + 2));
  let d = engine(&shared);
  let spawn = || {
    d.next_lane.store(1, Ordering::Relaxed);
    shared.spawn(root, async {}).unwrap()
  };
  let mut jobs: Vec<_> = (0..streak + 1).map(|_| spawn()).collect();
  park(&shared, 0);
  let wakes = d.wake_searches.load(Ordering::Relaxed);
  // The first `streak - 1` pops each leave an entry behind and wake nobody.
  for _ in 0..streak - 1 {
    run(&shared, selected(&shared, 1).unwrap());
  }
  assert_eq!(d.wake_searches.load(Ordering::Relaxed), wakes);
  // The next one completes the run: one search wake, as an eager pop makes.
  run(&shared, selected(&shared, 1).unwrap());
  assert_eq!(d.wake_searches.load(Ordering::Relaxed), wakes + 1);
  assert!(d.lane(0).search_kick);
  d.lane(0).finish_sleep();
  assert!(d.lane(0).take_recheck());
  let _ = d.acknowledge_search_kick(0);
  // A pop that empties the lane ends the run: the count starts again.
  run(&shared, selected(&shared, 1).unwrap());
  assert!(d.lane(1).check(&d.links()).is_empty());
  jobs.extend((0..streak).map(|_| spawn()));
  park(&shared, 0);
  let wakes = d.wake_searches.load(Ordering::Relaxed);
  for _ in 0..streak - 1 {
    run(&shared, selected(&shared, 1).unwrap());
  }
  assert_eq!(d.wake_searches.load(Ordering::Relaxed), wakes);
  d.lane(0).finish_sleep();
  d.parked.claim(0);
  run(&shared, selected(&shared, 1).unwrap());
  for job in jobs {
    finish(job).unwrap();
  }
  shared.close(false);
  check_distributed(&shared);
}

#[test]
fn cleanup_work_still_wakes_a_parked_dispatcher_under_the_streak_rule() {
  let (shared, root) = streak_shared(config(2, 1));
  let d = engine(&shared);
  d.next_lane.store(1, Ordering::Relaxed);
  let job = shared.spawn(root, std::future::pending::<()>()).unwrap();
  let index = d.lane(1).check(&d.links())[0];
  // The task goes idle; then both dispatchers are parked.
  let Some(Selected::Poll(reference, lease, permit)) = selected(&shared, 1) else {
    panic!("expected a poll");
  };
  let (_, permit) = lease.task().poll(
    &lease.key(),
    &mut Context::from_waker(Waker::noop()),
    permit,
    &mut None,
  );
  drop(permit);
  assert_eq!(d.finish_poll(&shared, reference, lease, false, None), None);
  park(&shared, 0);
  park(&shared, 1);
  let wakes = d.wake_searches.load(Ordering::Relaxed);
  shared.abort(reference);
  assert_eq!(lock(&d.overflow, 4).check(&d.links()), [index]);
  assert_eq!(d.wake_searches.load(Ordering::Relaxed), wakes + 1);
  for seat in 0..2 {
    d.lane(seat).finish_sleep();
    d.parked.claim(seat);
    let _ = d.lane(seat).take_recheck();
    let _ = d.acknowledge_search_kick(seat);
  }
  run(&shared, selected(&shared, 0).unwrap());
  assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)));
  shared.close(false);
  check_distributed(&shared);
}

#[test]
fn work_queued_behind_a_poll_that_does_not_return_is_taken_by_the_parked_look() {
  let runtime = streak_runtime(4, 40);
  let handle = runtime.handle();
  // Let the dispatchers park and the look go quiet first.
  std::thread::sleep(Duration::from_millis(20));
  let (reached, arrivals) = mpsc::channel();
  let inner = handle.clone();
  let blocker = handle
    .spawn(async move {
      let jobs: Vec<_> = (0..32)
        .map(|_| {
          let reached = reached.clone();
          inner
            .spawn(async move { reached.send(()).unwrap() })
            .unwrap()
        })
        .collect();
      // Every task spawned above runs while this poll is still inside its
      // dispatcher: nothing else would make this loop end.
      let mut ran = 0;
      while ran < 32 && arrivals.recv_timeout(Duration::from_secs(20)).is_ok() {
        ran += 1;
      }
      (ran, jobs)
    })
    .unwrap();
  let (ran, jobs) = finish(blocker).unwrap();
  assert_eq!(ran, 32);
  for job in jobs {
    finish(job).unwrap();
  }
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn the_look_takes_work_only_from_a_lane_whose_dispatcher_completed_no_turn() {
  let (shared, root) = streak_shared(config(2, 4));
  let d = engine(&shared);
  let jobs: Vec<_> = (0..4)
    .map(|_| {
      d.next_lane.store(1, Ordering::Relaxed);
      shared.spawn(root, async {}).unwrap()
    })
    .collect();
  let queued = d.lane(1).check(&d.links());
  let mut random = 1;
  // The first look only records the turn counts it compares the next one
  // with: seat one has completed none so far, and it reads the same.
  d.seat_turns[1].0.store(7, Ordering::Relaxed);
  assert_eq!(d.parked_look(&shared, 0, &mut random), None);
  // Seat one completed a turn since: its lane is being served.
  d.seat_turns[1].0.store(8, Ordering::Relaxed);
  assert_eq!(d.parked_look(&shared, 0, &mut random), None);
  assert_eq!(d.look_steals.load(Ordering::Relaxed), 0);
  assert_eq!(d.lane(1).check(&d.links()), queued);
  // No turn since the previous look, and the lane holds entries: one
  // ordinary steal, the oldest half, of which the look returns the first.
  let wakes = d.wake_searches.load(Ordering::Relaxed);
  assert_eq!(d.parked_look(&shared, 0, &mut random), Some(queued[0]));
  assert_eq!(d.look_steals.load(Ordering::Relaxed), 1);
  assert_eq!(d.lane(0).check(&d.links()), [queued[1]]);
  assert_eq!(d.lane(1).check(&d.links()), queued[2..]);
  // The look woke nobody and stays on.
  assert_eq!(d.wake_searches.load(Ordering::Relaxed), wakes);
  assert!(d.looking.0.load(Ordering::SeqCst));
  run(&shared, d.dispatch_decision(&shared, queued[0]).unwrap());
  for seat in 0..2 {
    while let Some(work) = selected(&shared, seat) {
      run(&shared, work);
    }
  }
  for job in jobs {
    finish(job).unwrap();
  }
  // Two looks that find every lane empty stop the look; an insertion
  // starts it again.
  assert_eq!(d.parked_look(&shared, 0, &mut random), None);
  assert!(d.looking.0.load(Ordering::SeqCst));
  assert_eq!(d.parked_look(&shared, 0, &mut random), None);
  assert!(!d.looking.0.load(Ordering::SeqCst));
  d.next_lane.store(1, Ordering::Relaxed);
  let job = shared.spawn(root, async {}).unwrap();
  assert!(d.looking.0.load(Ordering::SeqCst));
  run(&shared, selected(&shared, 1).unwrap());
  finish(job).unwrap();
  shared.close(false);
  check_distributed(&shared);
}

#[test]
fn a_task_that_waits_in_its_poll_for_the_task_it_spawned_completes() {
  for workers in [2, 4] {
    let runtime = streak_runtime(workers, 4);
    std::thread::sleep(Duration::from_millis(20));
    let handle = runtime.handle();
    let inner = handle.clone();
    let job = handle
      .spawn(async move {
        let (done, wait) = mpsc::channel();
        let spawned = inner.spawn(async move { done.send(()).unwrap() }).unwrap();
        (wait.recv_timeout(Duration::from_secs(20)).is_ok(), spawned)
      })
      .unwrap();
    let (ran, spawned) = finish(job).unwrap();
    assert!(ran, "{workers} workers: the spawned task did not run");
    finish(spawned).unwrap();
    shutdown(runtime, AsyncShutdown::Drain);
  }
}

#[test]
fn the_parked_look_stops_while_no_lane_holds_work() {
  let runtime = streak_runtime(4, 4);
  let d = engine(&runtime.shared);
  let job = runtime.handle().spawn(async {}).unwrap();
  finish(job).unwrap();
  // After looks that find every lane empty, no dispatcher waits with the
  // period any more.
  wait(|| !d.looking.0.load(Ordering::SeqCst) && !d.looker.0.load(Ordering::SeqCst));
  let looks = d.looks.load(Ordering::Relaxed);
  std::thread::sleep(Duration::from_millis(50));
  assert_eq!(d.looks.load(Ordering::Relaxed), looks);
  assert!(!d.looking.0.load(Ordering::SeqCst));
  // The next insertion starts it again.
  let job = runtime.handle().spawn(async {}).unwrap();
  finish(job).unwrap();
  assert!(d.looking.0.load(Ordering::SeqCst) || d.looks.load(Ordering::Relaxed) > looks);
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn every_dispatcher_takes_part_when_work_keeps_every_lane_busy() {
  let runtime = streak_runtime(4, 16);
  let handle = runtime.handle();
  let seen = Arc::new(Mutex::new(std::collections::HashSet::new()));
  let stop = Arc::new(AtomicBool::new(false));
  let jobs: Vec<_> = (0..8)
    .map(|_| {
      let (seen, stop) = (Arc::clone(&seen), Arc::clone(&stop));
      handle
        .spawn(std::future::poll_fn(move |cx| {
          seen.lock().unwrap().insert(std::thread::current().id());
          if stop.load(Ordering::Acquire) {
            return Poll::Ready(());
          }
          std::thread::sleep(Duration::from_micros(200));
          cx.waker().wake_by_ref();
          Poll::Pending
        }))
        .unwrap()
    })
    .collect();
  // Eight tasks that always have work for four dispatchers: the runs of
  // pops that leave work behind bring every dispatcher in.
  wait(|| seen.lock().unwrap().len() == 4);
  stop.store(true, Ordering::Release);
  for job in jobs {
    finish(job).unwrap();
  }
  shutdown(runtime, AsyncShutdown::Drain);
}
