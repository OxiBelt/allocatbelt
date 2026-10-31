use super::super::super::thread_options::{AsyncThreadOptions, AsyncThreadRole};
use super::super::super::{
  AsyncJoinError, AsyncRuntime, AsyncRuntimeOptions, AsyncScopeConfig, AsyncShutdown,
};
use super::*;
use std::pin::Pin;
use std::sync::mpsc;
use std::task::Poll;
use std::time::{Duration, Instant};

fn config(workers: usize, tasks: usize) -> AsyncConfig {
  AsyncConfig {
    workers,
    max_outstanding: tasks,
    max_scopes: 4,
  }
}
fn runtime(workers: usize, tasks: usize) -> AsyncRuntime {
  AsyncRuntime::new_with_options(
    config(workers, tasks),
    AsyncRuntimeOptions::new().dispatch(AsyncDispatch::Distributed),
  )
  .unwrap()
}
fn shared(config: AsyncConfig) -> (Arc<Shared>, ScopeRef) {
  let metrics = RuntimeMetrics::try_new(
    AsyncDispatch::Distributed,
    config.workers,
    (0..config.workers).map(|index| AsyncThreadContext {
      role: AsyncThreadRole::Worker,
      index,
      physical_index: index,
    }),
    config.workers,
    None,
  )
  .unwrap();
  Shared::new(
    config,
    AsyncDispatch::Distributed,
    0,
    None,
    super::super::super::ControlledThreadOptions::unbounded(AsyncThreadOptions::new()),
    metrics,
  )
  .unwrap()
}
fn engine(shared: &Shared) -> &Distributed {
  shared.distributed.as_ref().unwrap()
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
    match d.search(shared, seat, &mut random) {
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
      task.cancel();
      d.finish_cancel(shared, reference, task);
    }
    Selected::Poll(reference, task, permit) => {
      let (result, permit) = task.poll(&mut Context::from_waker(Waker::noop()), permit);
      drop(permit);
      d.finish_poll(shared, reference, matches!(result, PollResult::Ready));
    }
  }
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
              .scope
              .as_ref()
              .is_some_and(|(_, owner)| Arc::ptr_eq(owner, cell))
              && (slot.reserved_permit || slot.protocol.is_running())
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
      usize::from(slot.protocol.is_queued() && !slot.protocol.is_running())
    );
    if !slot.protocol.admitted() && slot.protocol.next_generation().is_some() {
      free.push(index);
    }
  }
  let mut heap: Vec<_> = state
    .free_tasks
    .iter()
    .map(|Reverse(index)| *index)
    .collect();
  heap.sort_unstable();
  assert_eq!(free, heap);
  assert_eq!(state.admitted, admitted);
  assert_eq!(shared.metrics.num_alive_tasks(), admitted);
}

#[test]
fn pending_self_yields_take_zero_global_two_slot_and_two_lane_locks() {
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
        assert_eq!((counts.0 - g, counts.1 - s, counts.2 - l), (0, 2, 2));
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
fn spawn_wake_completion_and_steal_lock_counts() {
  let (shared, root) = shared(config(2, 8));
  let d = engine(&shared);
  let before = (
    shared.lock_acquisitions.load(Ordering::Relaxed),
    d.slot_locks.load(Ordering::Relaxed),
    d.lane_locks.load(Ordering::Relaxed),
  );
  let job = shared.spawn(root, std::future::pending::<()>()).unwrap();
  assert_eq!(
    (
      shared.lock_acquisitions.load(Ordering::Relaxed) - before.0,
      d.slot_locks.load(Ordering::Relaxed) - before.1,
      d.lane_locks.load(Ordering::Relaxed) - before.2
    ),
    (2, 1, 1)
  );
  let work = selected(&shared, 0).unwrap();
  let reference = match &work {
    Selected::Poll(r, ..) => *r,
    _ => panic!(),
  };
  run(&shared, work);
  let before = (
    shared.lock_acquisitions.load(Ordering::Relaxed),
    d.slot_locks.load(Ordering::Relaxed),
    d.lane_locks.load(Ordering::Relaxed),
  );
  d.wake(&shared, reference);
  assert_eq!(
    (
      shared.lock_acquisitions.load(Ordering::Relaxed) - before.0,
      d.slot_locks.load(Ordering::Relaxed) - before.1,
      d.lane_locks.load(Ordering::Relaxed) - before.2
    ),
    (0, 1, 1)
  );
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
  assert_eq!(d.lane_locks.load(Ordering::Relaxed) - before, 3);
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
fn idle_worker_steals_behind_a_long_poll_without_emptying_the_victim() {
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
  for _ in 0..15 {
    completions.recv_timeout(Duration::from_secs(30)).unwrap();
  }
  assert!(d.steals.load(Ordering::Relaxed) > 0);
  assert_eq!(
    shared.metrics.inner().lane_depth[0]
      .0
      .load(Ordering::SeqCst),
    1
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
fn self_yields_complete_and_under_subscribed_yields_do_not_park_per_poll() {
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
  let mut polls = 0;
  let job = runtime
    .handle()
    .spawn(std::future::poll_fn(move |cx| {
      polls += 1;
      if polls == 10_000 {
        Poll::Ready(())
      } else {
        cx.waker().wake_by_ref();
        Poll::Pending
      }
    }))
    .unwrap();
  finish(job).unwrap();
  assert!(
    runtime
      .metrics()
      .snapshot()
      .threads
      .iter()
      .map(|t| t.parks)
      .sum::<usize>()
      < 50
  );
  shutdown(runtime, AsyncShutdown::Drain);
}

#[test]
fn external_wakes_against_parked_lanes_are_not_lost() {
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
  let cfg = config(65, 129);
  let (shared, _) = shared(cfg);
  let d = engine(&shared);
  let expected = std::mem::size_of::<Shared>()
    + payload_bytes::<Reverse<usize>>(cfg.max_outstanding).unwrap()
    + payload_bytes::<ScopeSlot>(cfg.max_scopes).unwrap()
    + std::mem::size_of::<ScopeCell>()
    + Distributed::requested_control(cfg).unwrap();
  assert_eq!(shared._control.bytes(), expected);
  assert_eq!(
    d.actual_control().unwrap(),
    Distributed::requested_control(cfg).unwrap()
  );
  assert_eq!(shared.lock().tasks.capacity(), 0);
  assert_eq!(shared.lock().round_robin.capacity(), 0);
  assert_eq!(shared.poll_words.capacity(), 0);
  check_distributed(&shared);
}

#[test]
fn cleanup_is_quota_free_and_slot_reuse_ignores_stale_wakes() {
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
  let (shared, root) = shared(config(2, 4));
  let d = engine(&shared);
  let jobs: Vec<_> = (0..4)
    .map(|_| {
      d.next_lane.store(0, Ordering::Relaxed);
      shared.spawn(root, async {}).unwrap()
    })
    .collect();
  let result = panic::catch_unwind(AssertUnwindSafe(|| {
    let _seat = SeatGuard {
      distributed: d,
      shared: &shared,
      turn: Some(lock(&d.seats, 4).claim(0)),
    };
    panic!("injected dispatcher unwind");
  }));
  assert!(result.is_err());
  assert_eq!(
    shared.metrics.inner().overflow_depth.load(Ordering::SeqCst),
    4
  );
  check_distributed(&shared);
  for _ in 0..4 {
    run(&shared, selected(&shared, 1).unwrap());
  }
  for job in jobs {
    finish(job).unwrap();
  }
  assert_eq!(
    shared.metrics.inner().overflow_depth.load(Ordering::SeqCst),
    0
  );
  check_distributed(&shared);
  assert!(d.parked.is_dead(0));
  for _ in 0..8 {
    d.next_lane.store(0, Ordering::Relaxed);
    let fresh = shared.spawn(root, async {}).unwrap();
    assert_eq!(d.lane(0).len(), 0);
    run(&shared, selected(&shared, 1).unwrap());
    finish(fresh).unwrap();
  }
  let survivor = start_worker(&shared, 1);
  wait(|| d.parked.is_set(1));
  shared.close(false);
  join_worker(survivor);
  check_distributed(&shared);
}

#[test]
fn round_robin_alternative_runs_the_same_wake_and_finish_paths() {
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
  let (mut shared, _) = shared(config(2, 3));
  let (parked, park_attempt) = mpsc::channel();
  let (unpark, continue_park) = mpsc::channel();
  let continue_park = Mutex::new(Some(continue_park));
  // Hold the searcher just before it advertises parking, keeping its parked
  // bit clear while the foreign abort inserts at the next rotating position.
  Arc::get_mut(&mut shared).unwrap().thread_options =
    super::super::super::ControlledThreadOptions::unbounded(
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
    1
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
  // Ordinary placement here would select the busy dispatcher's lane, whose
  // last entry cannot be stolen. Cleanup must instead wake the parked seat.
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
  let (mut shared, root) = shared(config(2, 3));
  let (attempt, attempted) = mpsc::channel();
  let (resume, resumed) = mpsc::channel();
  let resumed = Mutex::new(Some(resumed));
  Arc::get_mut(&mut shared).unwrap().thread_options =
    super::super::super::ControlledThreadOptions::unbounded(
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
  d.next_lane.store(0, Ordering::Relaxed);
  let tail = shared.spawn(root, async {}).unwrap();
  assert_eq!(d.lane(0).len(), 2);
  resume.send(()).unwrap();
  let progress = completion.recv_timeout(Duration::from_secs(5));
  // Release the blocked poll even on a failed assertion.
  let _ = release.send(());
  assert!(
    progress.is_ok(),
    "park rescan deadline: stealable work left asleep"
  );
  finish(short).unwrap();
  finish(tail).unwrap();
  finish(holder).unwrap();
  shared.close(false);
  join_worker(first);
  join_worker(second);
  check_distributed(&shared);
}
