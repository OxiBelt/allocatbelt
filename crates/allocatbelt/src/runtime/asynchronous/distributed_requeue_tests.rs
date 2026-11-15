//! Where the entry of a task that was notified during its poll goes: the
//! tail of the polling dispatcher's own lane, and nowhere else by that rule.

use super::super::super::super::{BlockInPlaceErrorKind, HandoffConfig, try_block_in_place};
use super::*;

/// A task that wakes itself and returns pending `rounds` times.
fn yields(mut rounds: usize) -> impl Future<Output = ()> + Send + 'static {
  std::future::poll_fn(move |cx| {
    if rounds == 0 {
      return Poll::Ready(());
    }
    rounds -= 1;
    cx.waker().wake_by_ref();
    Poll::Pending
  })
}

/// Polls `work` once with the task's own waker and ends the pending poll
/// the way `serve` does for a dispatcher that held seat `own` through it.
fn poll_pending(shared: &Arc<Shared>, work: Selected, own: Option<usize>) -> Option<usize> {
  let own = own.map(|seat| OwnLane { seat, take: true });
  let Selected::Poll(reference, lease, permit) = work else {
    panic!("expected a poll");
  };
  let permit = {
    let waker = lease.waker();
    let (result, permit) = lease.task().poll(
      &lease.key(),
      &mut Context::from_waker(&waker),
      permit,
      &mut None,
    );
    assert!(matches!(result, PollResult::Pending));
    permit
  };
  drop(permit);
  engine(shared).finish_poll(shared, reference, lease, false, own)
}

fn spawn_on<F>(shared: &Arc<Shared>, scope: ScopeRef, lane: usize, future: F) -> AsyncJob<()>
where
  F: Future<Output = ()> + Send + 'static,
{
  engine(shared).next_lane.store(lane, Ordering::Relaxed);
  shared.spawn(scope, future).unwrap()
}

fn lane_entries(shared: &Shared, seat: usize) -> Vec<usize> {
  let d = engine(shared);
  d.lane(seat).check(&d.links())
}

fn park(shared: &Shared, seat: usize) {
  let d = engine(shared);
  d.parked.advertise(seat);
  assert!(d.lane(seat).prepare_sleep());
}

fn unpark(shared: &Shared, seat: usize) {
  let d = engine(shared);
  d.lane(seat).finish_sleep();
  d.parked.claim(seat);
}

/// Serves `seat` until it finds no work, starting with the entry `first`
/// that a requeue took: every poll uses the task's own waker and every
/// requeue the seat's lane.
fn drain(shared: &Arc<Shared>, seat: usize, first: Option<usize>) {
  let d = engine(shared);
  let mut taken = first;
  loop {
    let taken_work = taken
      .take()
      .and_then(|index| d.dispatch_decision(shared, index));
    let Some(work) = taken_work.or_else(|| selected(shared, seat)) else {
      return;
    };
    match work {
      Selected::Poll(reference, lease, permit) => {
        let (result, permit) = {
          let waker = lease.waker();
          lease.task().poll(
            &lease.key(),
            &mut Context::from_waker(&waker),
            permit,
            &mut None,
          )
        };
        drop(permit);
        let ready = matches!(result, PollResult::Ready);
        taken = d.finish_poll(
          shared,
          reference,
          lease,
          ready,
          Some(OwnLane { seat, take: true }),
        );
      }
      cancel => run(shared, cancel),
    }
  }
}

#[test]
fn requeue_appends_to_the_polling_lane_and_takes_its_waiting_front_entry() {
  let (shared, root) = shared(config(2, 4));
  let d = engine(&shared);
  let jobs: Vec<_> = (0..3)
    .map(|_| spawn_on(&shared, root, 1, yields(1)))
    .collect();
  let queued = lane_entries(&shared, 1);
  assert_eq!(queued.len(), 3);
  // The rotating choice would now pick lane zero.
  d.next_lane.store(0, Ordering::Relaxed);
  let notifies = d.lane_notifies.load(Ordering::Relaxed);
  let work = selected(&shared, 1).unwrap();
  let taken = poll_pending(&shared, work, Some(1));
  // The oldest waiting entry is the next turn; the requeued one is last.
  assert_eq!(taken, Some(queued[1]));
  assert_eq!(lane_entries(&shared, 1), [queued[2], queued[0]]);
  assert!(lane_entries(&shared, 0).is_empty());
  assert_eq!(d.own_requeues.load(Ordering::Relaxed), 1);
  // No lane notification, and the rotating index did not advance.
  assert_eq!(d.lane_notifies.load(Ordering::Relaxed), notifies);
  assert_eq!(d.next_lane.start(false), Some(0));
  // The taken entry is dispatched like any popped one.
  let work = d.dispatch_decision(&shared, queued[1]).unwrap();
  let taken = poll_pending(&shared, work, Some(1));
  assert_eq!(taken, Some(queued[2]));
  assert_eq!(lane_entries(&shared, 1), [queued[0], queued[1]]);
  let work = d.dispatch_decision(&shared, queued[2]).unwrap();
  let taken = poll_pending(&shared, work, Some(1));
  assert_eq!(taken, Some(queued[0]));
  assert_eq!(lane_entries(&shared, 1), [queued[1], queued[2]]);
  run(&shared, d.dispatch_decision(&shared, queued[0]).unwrap());
  check_distributed(&shared);
  drain(&shared, 1, None);
  for job in jobs {
    finish(job).unwrap();
  }
  assert_eq!(d.own_requeues.load(Ordering::Relaxed), 3);
  shared.close(false);
  check_distributed(&shared);
}

#[test]
fn requeue_on_an_empty_lane_takes_nothing_wakes_nobody_and_can_be_stolen() {
  let (shared, root) = shared(config(2, 1));
  let d = engine(&shared);
  let job = spawn_on(&shared, root, 1, yields(2));
  let index = lane_entries(&shared, 1)[0];
  let work = selected(&shared, 1).unwrap();
  park(&shared, 0);
  let wakes = d.wake_searches.load(Ordering::Relaxed);
  let notifies = d.lane_notifies.load(Ordering::Relaxed);
  // The requeued task is never the entry taken.
  assert_eq!(poll_pending(&shared, work, Some(1)), None);
  assert_eq!(lane_entries(&shared, 1), [index]);
  assert_eq!(d.wake_searches.load(Ordering::Relaxed), wakes);
  assert_eq!(d.lane_notifies.load(Ordering::Relaxed), notifies);
  assert!(d.parked.is_set(0));
  assert!(!d.lane(0).take_recheck());
  check_distributed(&shared);
  // Another dispatcher steals it as an ordinary lone entry, and its next
  // requeue then goes to that dispatcher's lane.
  unpark(&shared, 0);
  let work = selected(&shared, 0).unwrap();
  assert!(lane_entries(&shared, 1).is_empty());
  assert_eq!(poll_pending(&shared, work, Some(0)), None);
  assert_eq!(lane_entries(&shared, 0), [index]);
  assert!(lane_entries(&shared, 1).is_empty());
  drain(&shared, 0, None);
  finish(job).unwrap();
  shared.close(false);
  check_distributed(&shared);
}

#[test]
fn own_lane_take_wakes_and_acknowledges_like_an_own_lane_pop() {
  let (shared, root) = shared(config(2, 3));
  let d = engine(&shared);
  let jobs: Vec<_> = (0..3)
    .map(|_| spawn_on(&shared, root, 1, yields(1)))
    .collect();
  let queued = lane_entries(&shared, 1);
  let work = selected(&shared, 1).unwrap();
  // This dispatcher was woken to search and has not acknowledged it yet.
  d.searching.kicked();
  d.lane(1).search_kick = true;
  park(&shared, 0);
  let wakes = d.wake_searches.load(Ordering::Relaxed);
  let notifies = d.lane_notifies.load(Ordering::Relaxed);
  let taken = poll_pending(&shared, work, Some(1));
  assert_eq!(taken, Some(queued[1]));
  // The take acknowledged the kick, and with work left behind it woke the
  // parked dispatcher, exactly as the pop of a search does.
  assert!(!d.lane(1).search_kick);
  assert_eq!(d.wake_searches.load(Ordering::Relaxed), wakes + 1);
  assert_eq!(d.lane_notifies.load(Ordering::Relaxed), notifies + 1);
  assert_eq!(d.searching.pending(), 1);
  assert!(d.lane(0).search_kick);
  unpark(&shared, 0);
  assert!(d.lane(0).take_recheck());
  let _ = d.acknowledge_search_kick(0);
  assert_eq!(d.searching.pending(), 0);
  drain(&shared, 1, taken);
  for job in jobs {
    finish(job).unwrap();
  }
  shared.close(false);
  check_distributed(&shared);
}

#[test]
fn requeue_without_a_take_leaves_a_search_kick_for_the_next_search() {
  let (shared, root) = shared(config(2, 1));
  let d = engine(&shared);
  let job = spawn_on(&shared, root, 1, yields(1));
  let work = selected(&shared, 1).unwrap();
  d.searching.kicked();
  d.lane(1).search_kick = true;
  assert_eq!(poll_pending(&shared, work, Some(1)), None);
  assert!(d.lane(1).search_kick);
  assert_eq!(d.searching.pending(), 1);
  // The following search pops the entry and settles the receipt.
  drain(&shared, 1, None);
  assert!(!d.lane(1).search_kick);
  assert_eq!(d.searching.pending(), 0);
  finish(job).unwrap();
  shared.close(false);
  check_distributed(&shared);
}

#[test]
fn requeue_of_a_task_aborted_during_its_poll_goes_to_overflow() {
  let (shared, root) = shared(config(2, 1));
  let d = engine(&shared);
  let job = spawn_on(&shared, root, 1, std::future::pending());
  let index = lane_entries(&shared, 1)[0];
  let Some(Selected::Poll(reference, lease, permit)) = selected(&shared, 1) else {
    panic!("expected a poll");
  };
  let (result, permit) = lease.task().poll(
    &lease.key(),
    &mut Context::from_waker(Waker::noop()),
    permit,
    &mut None,
  );
  assert!(matches!(result, PollResult::Pending));
  drop(permit);
  // The abort notifies the running task and marks its entry for cleanup.
  shared.abort(reference);
  let own = Some(OwnLane {
    seat: 1,
    take: true,
  });
  assert_eq!(d.finish_poll(&shared, reference, lease, false, own), None);
  assert!(lane_entries(&shared, 1).is_empty());
  assert_eq!(lock(&d.overflow, 4).check(&d.links()), [index]);
  assert_eq!(d.own_requeues.load(Ordering::Relaxed), 0);
  check_distributed(&shared);
  run(&shared, selected(&shared, 1).unwrap());
  assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)));
  shared.close(false);
  check_distributed(&shared);
}

#[test]
fn a_task_woken_from_idle_during_another_poll_follows_the_rotating_choice() {
  let (shared, root) = shared(config(2, 2));
  let d = engine(&shared);
  let parked_waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
  let store = Arc::clone(&parked_waker);
  let mut polled = false;
  let sleeper = spawn_on(
    &shared,
    root,
    1,
    std::future::poll_fn(move |cx| {
      if std::mem::replace(&mut polled, true) {
        return Poll::Ready(());
      }
      *store.lock().unwrap() = Some(cx.waker().clone());
      Poll::Pending
    }),
  );
  let index = lane_entries(&shared, 1)[0];
  // The sleeper goes idle: it was not notified during its poll.
  let work = selected(&shared, 1).unwrap();
  assert_eq!(poll_pending(&shared, work, Some(1)), None);
  assert!(lane_entries(&shared, 1).is_empty());
  let waker = spawn_on(&shared, root, 1, async move {
    parked_waker.lock().unwrap().take().unwrap().wake();
  });
  // The dispatcher of seat one polls the waking task; the woken task still
  // goes where the rotating index points.
  d.next_lane.store(0, Ordering::Relaxed);
  run(&shared, selected(&shared, 1).unwrap());
  assert_eq!(lane_entries(&shared, 0), [index]);
  assert!(lane_entries(&shared, 1).is_empty());
  assert_eq!(d.own_requeues.load(Ordering::Relaxed), 0);
  finish(waker).unwrap();
  drain(&shared, 0, None);
  finish(sleeper).unwrap();
  shared.close(false);
  check_distributed(&shared);
}

#[test]
fn a_quota_transfer_during_a_requeueing_turn_follows_the_rotating_choice() {
  let (shared, _) = shared(config(2, 2));
  let d = engine(&shared);
  let scope = shared.new_scope(1, None).unwrap();
  d.next_lane.store(1, Ordering::Relaxed);
  let holder_job = scope.spawn(yields(1)).unwrap();
  d.next_lane.store(1, Ordering::Relaxed);
  let blocked_job = scope.spawn(async {}).unwrap();
  let queued = lane_entries(&shared, 1);
  let holder = selected(&shared, 1).unwrap();
  // The second task waits for the scope's one permit.
  assert!(selected(&shared, 1).is_none());
  assert_eq!(d.scope(&scope.cell).check(&d.links()), [queued[1]]);
  d.next_lane.store(0, Ordering::Relaxed);
  // Ending the holder's turn passes its permit on: the released task takes
  // the rotating choice, the holder's own requeue its dispatcher's lane.
  assert_eq!(poll_pending(&shared, holder, Some(1)), None);
  assert_eq!(lane_entries(&shared, 0), [queued[1]]);
  assert_eq!(lane_entries(&shared, 1), [queued[0]]);
  assert_eq!(d.own_requeues.load(Ordering::Relaxed), 1);
  check_distributed(&shared);
  drain(&shared, 0, None);
  drain(&shared, 1, None);
  finish(blocked_job).unwrap();
  finish(holder_job).unwrap();
  shared.close(false);
  check_distributed(&shared);
}

#[test]
fn every_self_yield_of_a_lone_worker_requeues_on_its_own_lane() {
  let runtime = runtime(1, 4);
  let jobs: Vec<_> = (0..4)
    .map(|_| runtime.handle().spawn(yields(100)).unwrap())
    .collect();
  for job in jobs {
    finish(job).unwrap();
  }
  let d = engine(&runtime.shared);
  assert_eq!(d.own_requeues.load(Ordering::Relaxed), 400);
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn a_poll_that_handed_its_seat_off_requeues_by_the_rotating_choice() {
  let runtime = AsyncRuntime::new_with_options(
    config(1, 1),
    spin_options().handoffs(HandoffConfig { max_handoffs: 1 }),
  )
  .unwrap();
  let shared = Arc::clone(&runtime.shared);
  let mut step = 0;
  let mut before = 0;
  let job = runtime
    .handle()
    .spawn(std::future::poll_fn(move |cx| {
      let count = engine(&shared).own_requeues.load(Ordering::Relaxed);
      step += 1;
      match step {
        1 => {
          // The seat leaves this thread and a seat comes back, possibly
          // the same one: this poll's requeue takes no seat's lane.
          try_block_in_place(|| ()).unwrap();
          before = count;
        }
        2 => assert_eq!(count, before, "a handed-off poll requeued on a seat's lane"),
        // Later polls hold their seat throughout. A helper that has been
        // asked for its seat may run some of them by the rotating choice.
        _ if count > before => return Poll::Ready(()),
        _ => {}
      }
      cx.waker().wake_by_ref();
      Poll::Pending
    }))
    .unwrap();
  finish(job).unwrap();
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn a_poll_whose_handoff_was_refused_kept_its_seat_and_requeues_on_its_own_lane() {
  let runtime = AsyncRuntime::new_with_options(
    config(2, 2),
    spin_options().handoffs(HandoffConfig { max_handoffs: 1 }),
  )
  .unwrap();
  wait(|| runtime.shared.turn_counts() == (2, 0, 0, 0));
  let gate = HandoffGate::default();
  let _release = ReleaseHandoffs(vec![gate.clone()]);
  let (entered, arrival) = mpsc::channel();
  let closure_gate = gate.clone();
  let loaned = runtime
    .handle()
    .spawn(async move {
      try_block_in_place(|| {
        entered.send(()).unwrap();
        closure_gate.wait();
      })
      .unwrap();
    })
    .unwrap();
  arrival.recv_timeout(Duration::from_secs(30)).unwrap();
  let shared = Arc::clone(&runtime.shared);
  let mut before = None;
  let refused = runtime
    .handle()
    .spawn(std::future::poll_fn(move |cx| {
      let count = engine(&shared).own_requeues.load(Ordering::Relaxed);
      if let Some(before) = before {
        assert_eq!(count, before + 1, "a refused handoff changed the placement");
        return Poll::Ready(());
      }
      // The one loan is out, so this turn keeps its permit and its seat.
      let error = try_block_in_place(|| ()).unwrap_err();
      assert_eq!(error.kind, BlockInPlaceErrorKind::Full);
      before = Some(count);
      cx.waker().wake_by_ref();
      Poll::Pending
    }))
    .unwrap();
  finish(refused).unwrap();
  gate.open();
  finish(loaned).unwrap();
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn a_dispatcher_whose_seat_is_asked_for_requeues_by_the_rotating_choice() {
  let runtime = runtime(1, 1);
  let shared = Arc::clone(&runtime.shared);
  let mut asked = None;
  let mut polls_while_asked = 0;
  let job = runtime
    .handle()
    .spawn(std::future::poll_fn(move |cx| {
      let d = engine(&shared);
      let count = d.own_requeues.load(Ordering::Relaxed);
      match asked {
        // Yield normally until one requeue used the own lane, then raise
        // the hint that `serve` reads at each poll boundary. No seat
        // changes hands here, so nothing else rewrites the hint.
        None if count == 0 => {}
        None => {
          d.worker_yield.store(true, Ordering::Release);
          asked = Some(count);
        }
        Some(before) => {
          assert_eq!(count, before, "requeue on a lane whose seat is asked for");
          polls_while_asked += 1;
          if polls_while_asked == 8 {
            d.worker_yield.store(false, Ordering::Release);
            return Poll::Ready(());
          }
        }
      }
      cx.waker().wake_by_ref();
      Poll::Pending
    }))
    .unwrap();
  finish(job).unwrap();
  shutdown(runtime, AsyncShutdown::Drain);
}

/// A task that is polled once, reports it, and then stays idle. Dropping it
/// runs `dropped`.
struct Idle<F: FnMut()> {
  polled: Option<mpsc::Sender<()>>,
  dropped: F,
}

impl<F: FnMut() + Unpin> Future for Idle<F> {
  type Output = ();
  fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
    if let Some(polled) = self.polled.take() {
      polled.send(()).unwrap();
    }
    Poll::Pending
  }
}

impl<F: FnMut()> Drop for Idle<F> {
  fn drop(&mut self) {
    (self.dropped)();
  }
}

/// Puts `count` cancellation entries into shared overflow: tasks polled once
/// by seat `seat`'s fixture dispatcher, gone idle, then aborted.
fn overflow_entries(
  shared: &Arc<Shared>,
  root: ScopeRef,
  seat: usize,
  count: usize,
) -> (Vec<AsyncJob<()>>, Vec<usize>) {
  let d = engine(shared);
  let mut jobs = Vec::new();
  let mut indices = Vec::new();
  for _ in 0..count {
    jobs.push(spawn_on(shared, root, seat, std::future::pending()));
    let index = lane_entries(shared, seat)[0];
    let work = selected(shared, seat).unwrap();
    assert_eq!(poll_pending(shared, work, None), None);
    let generation = d.slot(index).protocol.generation();
    shared.abort(TaskRef { index, generation });
    indices.push(index);
  }
  assert_eq!(lock(&d.overflow, 4).check(&d.links()), indices);
  (jobs, indices)
}

#[test]
fn requeue_before_an_overflow_turn_takes_nothing() {
  let (shared, root) = shared(config(2, 2));
  let d = engine(&shared);
  let jobs: Vec<_> = (0..2)
    .map(|_| spawn_on(&shared, root, 1, yields(1)))
    .collect();
  let queued = lane_entries(&shared, 1);
  let Some(Selected::Poll(reference, lease, permit)) = selected(&shared, 1) else {
    panic!("expected a poll");
  };
  let permit = {
    let waker = lease.waker();
    lease
      .task()
      .poll(
        &lease.key(),
        &mut Context::from_waker(&waker),
        permit,
        &mut None,
      )
      .1
  };
  drop(permit);
  let own = Some(OwnLane {
    seat: 1,
    take: false,
  });
  // The entry still goes to the polling lane; the waiting one stays for
  // the search that follows the look at overflow.
  assert_eq!(d.finish_poll(&shared, reference, lease, false, own), None);
  assert_eq!(lane_entries(&shared, 1), [queued[1], queued[0]]);
  assert_eq!(d.own_requeues.load(Ordering::Relaxed), 1);
  drain(&shared, 1, None);
  for job in jobs {
    finish(job).unwrap();
  }
  shared.close(false);
  check_distributed(&shared);
}

#[test]
fn overflow_turn_takes_one_entry_and_leaves_the_own_lane_queued() {
  let (shared, root) = shared(config(2, 4));
  let d = engine(&shared);
  // With nothing in overflow the turn is an ordinary search: no entry and
  // no lane lock.
  let locks = d.lane_locks.load(Ordering::Relaxed);
  assert_eq!(d.overflow_turn(&shared, 1), None);
  assert_eq!(d.lane_locks.load(Ordering::Relaxed), locks);
  let (cancelled, overflow) = overflow_entries(&shared, root, 1, 2);
  let job = spawn_on(&shared, root, 1, yields(0));
  let queued = lane_entries(&shared, 1);
  // This dispatcher holds an unacknowledged search kick, and another one
  // is parked.
  d.searching.kicked();
  d.lane(1).search_kick = true;
  park(&shared, 0);
  let wakes = d.wake_searches.load(Ordering::Relaxed);
  // One entry, the oldest, handed to the caller; never placed on a lane.
  assert_eq!(d.overflow_turn(&shared, 1), Some(overflow[0]));
  assert_eq!(lock(&d.overflow, 4).check(&d.links()), overflow[1..]);
  assert_eq!(lane_entries(&shared, 1), queued);
  assert!(lane_entries(&shared, 0).is_empty());
  assert_eq!(d.overflow_turns.load(Ordering::Relaxed), 1);
  // The kick is settled, and the own-lane entry left behind for this turn
  // wakes the parked dispatcher, as after an own-lane pop.
  assert!(!d.lane(1).search_kick);
  assert_eq!(d.wake_searches.load(Ordering::Relaxed), wakes + 1);
  assert!(d.lane(0).search_kick);
  unpark(&shared, 0);
  assert!(d.lane(0).take_recheck());
  let _ = d.acknowledge_search_kick(0);
  assert_eq!(d.searching.pending(), 0);
  run(&shared, d.dispatch_decision(&shared, overflow[0]).unwrap());
  drain(&shared, 1, None);
  finish(job).unwrap();
  for job in cancelled {
    assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)));
  }
  shared.close(false);
  check_distributed(&shared);
}

#[test]
fn abort_of_an_idle_task_completes_while_every_dispatcher_keeps_yielding() {
  for (workers, yielders) in [(1, 1), (2, 2), (4, 8)] {
    let runtime = runtime(workers, yielders + 1);
    let handle = runtime.handle();
    let (polled, idle_polled) = mpsc::channel();
    let idle = handle
      .spawn(Idle {
        polled: Some(polled),
        dropped: || {},
      })
      .unwrap();
    idle_polled.recv_timeout(Duration::from_secs(30)).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicUsize::new(0));
    let busy: Vec<_> = (0..yielders)
      .map(|_| {
        let (stop, polls) = (Arc::clone(&stop), Arc::clone(&polls));
        handle
          .spawn(std::future::poll_fn(move |cx| {
            polls.fetch_add(1, Ordering::Relaxed);
            if stop.load(Ordering::Acquire) {
              return Poll::Ready(());
            }
            cx.waker().wake_by_ref();
            Poll::Pending
          }))
          .unwrap()
      })
      .collect();
    wait(|| polls.load(Ordering::Relaxed) > 10_000);
    // No lane runs empty from here on; the cleanup entry is in overflow.
    idle.abort();
    assert!(matches!(finish(idle), Err(AsyncJoinError::Cancelled)));
    assert!(!stop.load(Ordering::Acquire));
    stop.store(true, Ordering::Release);
    for job in busy {
      finish(job).unwrap();
    }
    shutdown(runtime, AsyncShutdown::Drain);
  }
}

#[test]
fn a_dispatcher_looks_at_overflow_first_once_per_fixed_number_of_turns() {
  let runtime = runtime(1, 3);
  let handle = runtime.handle();
  let polls = Arc::new(AtomicUsize::new(0));
  let drops = Arc::new(Mutex::new(Vec::new()));
  let (polled, idle_polled) = mpsc::channel();
  let idle: Vec<_> = (0..2)
    .map(|_| {
      let (polls, drops) = (Arc::clone(&polls), Arc::clone(&drops));
      handle
        .spawn(Idle {
          polled: Some(polled.clone()),
          dropped: move || drops.lock().unwrap().push(polls.load(Ordering::Relaxed)),
        })
        .unwrap()
    })
    .collect();
  for _ in 0..2 {
    idle_polled.recv_timeout(Duration::from_secs(30)).unwrap();
  }
  let aborts: Vec<_> = idle.iter().map(AsyncJob::abort_handle).collect();
  let (counter, seen) = (Arc::clone(&polls), Arc::clone(&drops));
  let mut aborts = Some(aborts);
  let busy = handle
    .spawn(std::future::poll_fn(move |cx| {
      counter.fetch_add(1, Ordering::Relaxed);
      // Both cleanup entries enter overflow during one poll.
      for abort in aborts.take().into_iter().flatten() {
        abort.abort();
      }
      if seen.lock().unwrap().len() == 2 {
        return Poll::Ready(());
      }
      cx.waker().wake_by_ref();
      Poll::Pending
    }))
    .unwrap();
  finish(busy).unwrap();
  for job in idle {
    assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)));
  }
  // The lone dispatcher took one cleanup entry per look, and its own
  // lane's task every turn in between.
  let drops = drops.lock().unwrap();
  assert_eq!(drops[1] - drops[0], OVERFLOW_TURN_INTERVAL as usize - 1);
  assert_eq!(
    engine(&runtime.shared)
      .overflow_turns
      .load(Ordering::Relaxed),
    2
  );
  drop(drops);
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn overflow_turn_makes_one_wake_attempt_and_none_when_it_takes_nothing() {
  let (shared, root) = shared(config(3, 4));
  let d = engine(&shared);
  let settle = |seat: usize| {
    unpark(&shared, seat);
    let _ = d.lane(seat).take_recheck();
    let _ = d.acknowledge_search_kick(seat);
  };
  let job = spawn_on(&shared, root, 2, yields(0));
  let queued = lane_entries(&shared, 2);
  park(&shared, 0);
  park(&shared, 1);
  let wakes = d.wake_searches.load(Ordering::Relaxed);
  let notifies = d.lane_notifies.load(Ordering::Relaxed);
  // Nothing in overflow: the look takes nothing and wakes nobody, although
  // the own lane holds an entry. The ordinary search that follows makes
  // the turn's one attempt when it pops.
  assert_eq!(d.overflow_turn(&shared, 2), None);
  assert_eq!(d.wake_searches.load(Ordering::Relaxed), wakes);
  assert_eq!(d.lane_notifies.load(Ordering::Relaxed), notifies);
  assert!(d.parked.is_set(0) && d.parked.is_set(1));
  settle(0);
  settle(1);
  // Seat one's fixture dispatcher polls and aborts the tasks to cancel.
  let (cancelled, overflow) = overflow_entries(&shared, root, 1, 2);
  assert_eq!(lane_entries(&shared, 2), queued);
  park(&shared, 0);
  park(&shared, 1);
  assert_eq!(d.searching.pending(), 0);
  let wakes = d.wake_searches.load(Ordering::Relaxed);
  let notifies = d.lane_notifies.load(Ordering::Relaxed);
  // An entry taken with the own lane non-empty: exactly one attempt, which
  // wakes one of the two parked dispatchers. Overflow still holds an entry
  // and that adds nothing.
  assert_eq!(d.overflow_turn(&shared, 2), Some(overflow[0]));
  assert_eq!(d.wake_searches.load(Ordering::Relaxed), wakes + 1);
  assert_eq!(d.lane_notifies.load(Ordering::Relaxed), notifies + 1);
  assert_eq!(d.searching.pending(), 1);
  let kicked = (0..2).filter(|&seat| d.lane(seat).search_kick).count();
  assert_eq!(kicked, 1);
  assert_eq!(
    usize::from(d.parked.is_set(0)) + usize::from(d.parked.is_set(1)),
    1
  );
  settle(0);
  settle(1);
  assert_eq!(d.searching.pending(), 0);
  run(&shared, d.dispatch_decision(&shared, overflow[0]).unwrap());
  drain(&shared, 2, None);
  finish(job).unwrap();
  // With the own lane empty and no kick to settle, a taken entry wakes
  // nobody, whatever overflow still holds.
  let (more, late) = overflow_entries(&shared, root, 1, 2);
  park(&shared, 0);
  let wakes = d.wake_searches.load(Ordering::Relaxed);
  assert_eq!(d.overflow_turn(&shared, 2), Some(late[0]));
  assert_eq!(d.wake_searches.load(Ordering::Relaxed), wakes);
  assert!(d.parked.is_set(0));
  settle(0);
  run(&shared, d.dispatch_decision(&shared, late[0]).unwrap());
  drain(&shared, 2, None);
  for job in cancelled.into_iter().chain(more) {
    assert!(matches!(finish(job), Err(AsyncJoinError::Cancelled)));
  }
  shared.close(false);
  check_distributed(&shared);
}
