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
  shared_with_handoffs(config, 0)
}
fn shared_with_handoffs(config: AsyncConfig, handoffs: usize) -> (Arc<Shared>, ScopeRef) {
  let metrics = RuntimeMetrics::try_new(
    AsyncDispatch::Distributed,
    config.workers,
    super::super::super::thread_contexts(config.workers, handoffs),
    config.workers + handoffs,
    None,
  )
  .unwrap();
  Shared::new(
    config,
    AsyncDispatch::Distributed,
    handoffs,
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
  use super::super::super::{HandoffConfig, try_block_in_place};
  let runtime = AsyncRuntime::new_with_options(
    config(2, 8),
    AsyncRuntimeOptions::new()
      .dispatch(AsyncDispatch::Distributed)
      .handoffs(HandoffConfig { max_handoffs: 2 }),
  )
  .unwrap();
  let shared = Arc::clone(&runtime.shared);
  let d = engine(&shared);
  d.round_robin.store(true, Ordering::Relaxed);
  wait(|| shared.turn_counts() == (2, 0, 0, 0));
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
  // A helper must adopt seat zero to run its last (unstealable) entry.
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
  use super::super::super::HandoffConfig;
  let runtime = AsyncRuntime::new_with_options(
    config(2, 4),
    AsyncRuntimeOptions::new()
      .dispatch(AsyncDispatch::Distributed)
      .handoffs(HandoffConfig { max_handoffs: 2 }),
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
