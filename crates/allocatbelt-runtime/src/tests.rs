//! Runtime tests on real worker threads. Ordering comes from channels and
//! barriers; the only waits on time are bounded polls of the snapshot.

use std::panic;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::cache;
use crate::{
  CancellationToken, Config, Handle, Job, JoinError, Resources, Runtime, ShutdownMode, Snapshot,
  SubmitErrorKind,
};

fn cpu(n: usize) -> Resources {
  Resources {
    cpu: n,
    ..Resources::ZERO
  }
}

const MAX: Resources = Resources {
  cpu: usize::MAX,
  memory: usize::MAX,
  disk: usize::MAX,
  network: usize::MAX,
};

fn runtime(workers: usize, max_outstanding: usize, capacity: Resources) -> Runtime {
  Runtime::new(Config {
    workers,
    max_outstanding,
    capacity,
  })
  .unwrap()
}

fn wait_for(handle: &Handle, what: impl Fn(&Snapshot) -> bool) -> Snapshot {
  let deadline = Instant::now() + Duration::from_secs(30);
  loop {
    let s = handle.snapshot();
    if what(&s) {
      return s;
    }
    assert!(Instant::now() < deadline, "timed out at {s:?}");
    thread::yield_now();
  }
}

/// A job that reports it started, then waits for its gate.
fn gated(rt: &Runtime, request: Resources) -> (Job<CancellationToken>, Receiver<()>, Sender<()>) {
  let (started_tx, started) = mpsc::channel();
  let (gate, gate_rx) = mpsc::channel::<()>();
  let job = rt
    .try_spawn(request, move |token| {
      started_tx.send(()).unwrap();
      let _ = gate_rx.recv();
      token
    })
    .unwrap();
  (job, started, gate)
}

#[test]
fn config_must_have_workers_and_slots() {
  for (workers, max_outstanding) in [(0, 1), (1, 0)] {
    let e = Runtime::new(Config {
      workers,
      max_outstanding,
      capacity: Resources::ZERO,
    })
    .unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
  }
}

#[test]
fn types_are_send_and_sync() {
  fn check<T: Send + Sync>() {}
  check::<Runtime>();
  check::<Handle>();
  check::<Job<u8>>();
  check::<CancellationToken>();
}

#[test]
fn rejection_returns_the_closure_and_reserves_nothing() {
  let mut rt = runtime(1, 2, cpu(2));
  let (blocker, started, gate) = gated(&rt, cpu(2));
  started.recv().unwrap();
  let marker = Arc::new(());
  let m = Arc::clone(&marker);
  let e = rt.try_spawn(cpu(1), move |_| drop(m)).unwrap_err();
  assert_eq!(e.kind, SubmitErrorKind::InsufficientResources);
  assert_eq!(Arc::strong_count(&marker), 2);
  let e = rt.try_spawn(cpu(3), e.into_job()).unwrap_err();
  assert_eq!(e.kind(), SubmitErrorKind::InvalidRequest);
  let zero = rt.try_spawn(Resources::ZERO, |_| 5).unwrap();
  let e = rt.try_spawn(Resources::ZERO, e.job).unwrap_err();
  assert_eq!(e.kind, SubmitErrorKind::Full);
  let s = rt.snapshot();
  assert_eq!(
    (s.outstanding, s.reserved, s.queued, s.running),
    (2, cpu(2), 1, 1)
  );
  gate.send(()).unwrap();
  blocker.join().unwrap();
  assert_eq!(zero.join().unwrap(), 5);
  rt.shutdown(ShutdownMode::Drain).unwrap();
  let e = rt.try_spawn(Resources::ZERO, e.job).unwrap_err();
  assert_eq!(e.kind, SubmitErrorKind::Closed);
  drop(e);
  assert_eq!(Arc::strong_count(&marker), 1);
}

#[test]
fn usize_max_capacity_runs_and_releases() {
  let mut rt = runtime(2, usize::MAX, MAX);
  let (blocker, started, gate) = gated(&rt, MAX);
  started.recv().unwrap();
  let e = rt.try_spawn(cpu(1), |_| ()).unwrap_err();
  assert_eq!(e.kind, SubmitErrorKind::InsufficientResources);
  assert_eq!(
    rt.try_spawn(Resources::ZERO, |_| 1)
      .unwrap()
      .join()
      .unwrap(),
    1
  );
  gate.send(()).unwrap();
  blocker.join().unwrap();
  wait_for(&rt.handle(), |s| s.reserved == Resources::ZERO);
  assert_eq!(rt.try_spawn(MAX, |_| 2).unwrap().join().unwrap(), 2);
  rt.shutdown(ShutdownMode::Drain).unwrap();
  assert_eq!(rt.snapshot().outstanding, 0);
}

#[test]
fn multi_producer_bounds_hold_and_resources_are_conserved() {
  const PRODUCERS: usize = 8;
  const JOBS: usize = 400;
  const BOUND: usize = 6;
  let capacity = Resources {
    cpu: 5,
    memory: 1000,
    disk: 3,
    network: 7,
  };
  let mut rt = runtime(4, BOUND, capacity);
  let live = Arc::new(Mutex::new((Resources::ZERO, 0usize)));
  let ran = Arc::new(AtomicUsize::new(0));
  let start = Arc::new(Barrier::new(PRODUCERS));
  let producers: Vec<_> = (0..PRODUCERS)
    .map(|p| {
      let handle = rt.handle();
      let (live, ran, start) = (Arc::clone(&live), Arc::clone(&ran), Arc::clone(&start));
      thread::spawn(move || {
        start.wait();
        for i in 0..JOBS {
          let request = Resources {
            cpu: (p + i) % 3,
            memory: (p * 37 + i * 11) % 400,
            disk: i % 2,
            network: (p + 2 * i) % 4,
          };
          let (live, ran) = (Arc::clone(&live), Arc::clone(&ran));
          let mut job = move |_: CancellationToken| {
            {
              let mut l = live.lock().unwrap();
              l.0 = l.0.checked_add(&request).unwrap();
              l.1 += 1;
              assert!(l.0.fits_within(&capacity) && l.1 <= BOUND, "{l:?}");
            }
            thread::yield_now();
            let mut l = live.lock().unwrap();
            l.0 = l.0.checked_sub(&request).unwrap();
            l.1 -= 1;
            ran.fetch_add(1, Ordering::SeqCst);
          };
          loop {
            let s = handle.snapshot();
            assert!(s.outstanding <= BOUND && s.reserved.fits_within(&capacity));
            match handle.try_spawn(request, job) {
              Ok(j) => {
                if i % 2 == 0 {
                  j.join().unwrap();
                }
                break;
              }
              Err(e) => {
                assert!(matches!(
                  e.kind,
                  SubmitErrorKind::Full | SubmitErrorKind::InsufficientResources
                ));
                job = e.job;
                thread::yield_now();
              }
            }
          }
        }
      })
    })
    .collect();
  for p in producers {
    p.join().unwrap();
  }
  rt.shutdown(ShutdownMode::Drain).unwrap();
  assert_eq!(ran.load(Ordering::SeqCst), PRODUCERS * JOBS);
  let s = rt.snapshot();
  assert_eq!(
    (s.outstanding, s.reserved, s.queued, s.running),
    (0, Resources::ZERO, 0, 0)
  );
}

/// A capture whose `Drop` reports it began, then waits for its gate.
struct GatedDrop {
  dropping: Sender<()>,
  gate: Receiver<()>,
}

impl Drop for GatedDrop {
  fn drop(&mut self) {
    let _ = self.dropping.send(());
    let _ = self.gate.recv();
  }
}

fn gated_drop() -> (GatedDrop, Receiver<()>, Sender<()>) {
  let (dropping, dropping_rx) = mpsc::channel();
  let (gate_tx, gate) = mpsc::channel();
  (GatedDrop { dropping, gate }, dropping_rx, gate_tx)
}

#[test]
fn cancel_before_start_never_runs_and_keeps_capacity_until_dequeued() {
  let mut rt = runtime(1, 4, cpu(4));
  let (blocker, started, gate) = gated(&rt, cpu(1));
  started.recv().unwrap();
  let ran = Arc::new(AtomicUsize::new(0));
  let r = Arc::clone(&ran);
  let queued = rt
    .try_spawn(cpu(2), move |_| r.fetch_add(1, Ordering::SeqCst))
    .unwrap();
  queued.cancel();
  queued.cancel();
  // Not complete until a worker dequeues it, drops it and releases it.
  assert!(!queued.is_finished());
  let s = rt.snapshot();
  assert_eq!((s.outstanding, s.reserved, s.queued), (2, cpu(3), 1));
  gate.send(()).unwrap();
  assert!(!blocker.join().unwrap().is_cancelled());
  assert!(matches!(queued.join(), Err(JoinError::Cancelled)));
  let s = rt.snapshot();
  assert_eq!(
    (s.outstanding, s.reserved, s.cancelling),
    (0, Resources::ZERO, 0)
  );
  rt.shutdown(ShutdownMode::Drain).unwrap();
  assert_eq!(ran.load(Ordering::SeqCst), 0);
  // The cancelled closure was dropped unstarted.
  assert_eq!(Arc::strong_count(&ran), 1);
}

#[test]
fn a_dequeued_cancelled_job_holds_its_admission_until_its_capture_is_dropped() {
  let mut rt = runtime(1, 2, cpu(2));
  let (blocker, started, gate) = gated(&rt, cpu(1));
  started.recv().unwrap();
  let (capture, dropping, drop_gate) = gated_drop();
  let job = rt.try_spawn(cpu(1), move |_| drop(capture)).unwrap();
  job.cancel();
  gate.send(()).unwrap();
  blocker.join().unwrap();
  // The worker dequeued it and is inside the capture's `Drop`.
  dropping.recv().unwrap();
  let s = rt.snapshot();
  assert_eq!(
    (s.outstanding, s.reserved, s.queued, s.cancelling),
    (1, cpu(1), 0, 1)
  );
  assert!(!job.is_finished());
  let e = rt.try_spawn(cpu(2), |_| ()).unwrap_err();
  assert_eq!(e.kind, SubmitErrorKind::InsufficientResources);
  drop_gate.send(()).unwrap();
  assert!(matches!(job.join(), Err(JoinError::Cancelled)));
  let s = rt.snapshot();
  assert_eq!(
    (s.outstanding, s.reserved, s.cancelling),
    (0, Resources::ZERO, 0)
  );
  assert_eq!(rt.try_spawn(cpu(2), |_| 1).unwrap().join().unwrap(), 1);
  rt.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn cancel_pending_holds_admissions_until_captures_are_dropped() {
  let rt = runtime(1, 3, cpu(3));
  let handle = rt.handle();
  let (started_tx, started) = mpsc::channel();
  let (finish_tx, finish) = mpsc::channel::<()>();
  let running = rt
    .try_spawn(cpu(1), move |token: CancellationToken| {
      started_tx.send(()).unwrap();
      finish.recv().unwrap();
      token.is_cancelled()
    })
    .unwrap();
  started.recv().unwrap();
  let (capture, dropping, drop_gate) = gated_drop();
  let queued = rt.try_spawn(cpu(2), move |_| drop(capture)).unwrap();
  let shutdown = thread::spawn(move || {
    let mut rt = rt;
    rt.shutdown(ShutdownMode::CancelPending)
  });
  // The shutdown thread is inside the capture's `Drop`.
  dropping.recv().unwrap();
  let s = handle.snapshot();
  assert_eq!(
    (s.reserved, s.queued, s.running, s.cancelling, s.closed),
    (cpu(3), 0, 1, 1, true)
  );
  assert!(!queued.is_finished());
  let e = handle.try_spawn(Resources::ZERO, |_| ()).unwrap_err();
  assert_eq!(e.kind, SubmitErrorKind::Closed);
  drop_gate.send(()).unwrap();
  assert!(matches!(queued.join(), Err(JoinError::Cancelled)));
  assert_eq!(handle.snapshot().reserved, cpu(1));
  finish_tx.send(()).unwrap();
  shutdown.join().unwrap().unwrap();
  assert!(running.join().unwrap());
  let s = handle.snapshot();
  assert_eq!(
    (s.outstanding, s.reserved, s.cancelling),
    (0, Resources::ZERO, 0)
  );
}

#[test]
fn cancel_after_start_signals_the_token_and_returns_the_result() {
  let mut rt = runtime(1, 2, cpu(1));
  let (started_tx, started) = mpsc::channel();
  let (go_tx, go) = mpsc::channel::<()>();
  let job = rt
    .try_spawn(cpu(1), move |token: CancellationToken| {
      started_tx.send(token.clone()).unwrap();
      go.recv().unwrap();
      token.is_cancelled()
    })
    .unwrap();
  let token = started.recv().unwrap();
  assert!(!token.is_cancelled());
  job.cancel();
  assert!(token.is_cancelled());
  assert!(!job.is_finished());
  go_tx.send(()).unwrap();
  assert!(job.join().unwrap());
  rt.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn a_cancel_that_wins_the_start_transition_prevents_the_run() {
  // The only worker is held, so every cancellation wins.
  let mut rt = runtime(1, 8, cpu(8));
  let (blocker, started, gate) = gated(&rt, Resources::ZERO);
  started.recv().unwrap();
  let ran = Arc::new(AtomicUsize::new(0));
  let jobs: Vec<_> = (0..6)
    .map(|_| {
      let r = Arc::clone(&ran);
      rt.try_spawn(cpu(1), move |_| r.fetch_add(1, Ordering::SeqCst))
        .unwrap()
    })
    .collect();
  for job in jobs.iter().step_by(2) {
    job.cancel();
  }
  gate.send(()).unwrap();
  blocker.join().unwrap();
  for (i, r) in jobs.into_iter().map(Job::join).enumerate() {
    assert_eq!(i % 2 == 0, matches!(r, Err(JoinError::Cancelled)), "{i}");
  }
  rt.shutdown(ShutdownMode::Drain).unwrap();
  assert_eq!(ran.load(Ordering::SeqCst), 3);
  assert_eq!(rt.snapshot().outstanding, 0);
}

#[test]
fn cancel_racing_start_resolves_exactly_once() {
  const ROUNDS: usize = 500;
  let mut rt = runtime(2, 64, cpu(64));
  let ran = Arc::new(AtomicUsize::new(0));
  let mut finished = 0;
  let mut cancelled = 0;
  for round in 0..ROUNDS {
    let barrier = Arc::new(Barrier::new(2));
    let r = Arc::clone(&ran);
    let job = rt
      .try_spawn(cpu(1 + round % 3), move |_| {
        r.fetch_add(1, Ordering::SeqCst)
      })
      .unwrap();
    let b = Arc::clone(&barrier);
    let canceller = thread::spawn(move || {
      b.wait();
      job.cancel();
      job.join()
    });
    // Released together: the cancel races the worker's dequeue.
    barrier.wait();
    match canceller.join().unwrap() {
      Ok(_) => finished += 1,
      Err(JoinError::Cancelled) => cancelled += 1,
      Err(e) => panic!("{e}"),
    }
  }
  rt.shutdown(ShutdownMode::Drain).unwrap();
  assert_eq!(ran.load(Ordering::SeqCst), finished);
  assert_eq!(finished + cancelled, ROUNDS);
  let s = rt.snapshot();
  assert_eq!((s.outstanding, s.reserved), (0, Resources::ZERO));
}

fn quiet_panics<R>(f: impl FnOnce() -> R) -> R {
  static HOOK: Mutex<()> = Mutex::new(());
  let _serial = HOOK
    .lock()
    .unwrap_or_else(std::sync::PoisonError::into_inner);
  let hook = panic::take_hook();
  panic::set_hook(Box::new(|_| {}));
  let r = panic::catch_unwind(panic::AssertUnwindSafe(f));
  panic::set_hook(hook);
  r.unwrap_or_else(|p| panic::resume_unwind(p))
}

#[test]
fn panics_are_returned_and_the_worker_keeps_running() {
  let mut rt = runtime(1, 4, cpu(1));
  let err = quiet_panics(|| {
    let job = rt.try_spawn(cpu(1), |_| -> u8 { panic!("boom") }).unwrap();
    job.join().unwrap_err()
  });
  let JoinError::Panicked(payload) = err else {
    panic!("not a panic: {err}");
  };
  assert_eq!(payload.downcast_ref::<&str>(), Some(&"boom"));
  let s = rt.snapshot();
  assert_eq!(
    (s.outstanding, s.reserved, s.running),
    (0, Resources::ZERO, 0)
  );
  assert_eq!(rt.try_spawn(cpu(1), |_| 9).unwrap().join().unwrap(), 9);
  rt.shutdown(ShutdownMode::Drain).unwrap();
}

/// Takes the scheduler lock from its `Drop`, then panics if asked: it would
/// deadlock if the runtime dropped it under that lock.
struct LocksOnDrop {
  handle: Handle,
  dropped: Arc<AtomicUsize>,
  panic: bool,
}

impl Drop for LocksOnDrop {
  fn drop(&mut self) {
    let _ = self.handle.snapshot();
    self.dropped.fetch_add(1, Ordering::SeqCst);
    assert!(!self.panic, "drop");
  }
}

#[test]
fn user_drops_run_outside_the_lock_and_their_panics_are_contained() {
  let mut rt = runtime(1, 8, cpu(8));
  let dropped = Arc::new(AtomicUsize::new(0));
  let handle = rt.handle();
  let lod = |panic| LocksOnDrop {
    handle: handle.clone(),
    dropped: Arc::clone(&dropped),
    panic,
  };
  quiet_panics(|| {
    let (blocker, started, gate) = gated(&rt, Resources::ZERO);
    started.recv().unwrap();
    // A detached result, a joined one, a panic payload, cancelled captures
    // and captures dropped by a cancelling shutdown.
    let (a, b, c, d) = (lod(true), lod(false), lod(false), lod(true));
    drop(rt.try_spawn(cpu(1), move |_| a).unwrap());
    let joined = rt.try_spawn(cpu(1), move |_| b).unwrap();
    let payload = rt.try_spawn(cpu(1), move |_| panic::panic_any(c)).unwrap();
    let cancelled = rt.try_spawn(cpu(1), move |_| drop(d)).unwrap();
    cancelled.cancel();
    gate.send(()).unwrap();
    blocker.join().unwrap();
    drop(joined.join().unwrap());
    let JoinError::Panicked(p) = payload.join().unwrap_err() else {
      panic!("not a panic");
    };
    drop(p.downcast::<LocksOnDrop>().unwrap());
    assert!(matches!(cancelled.join(), Err(JoinError::Cancelled)));
    wait_for(&rt.handle(), |s| s.outstanding == 0);
    let (started_tx, started) = mpsc::channel();
    let blocker = rt
      .try_spawn(Resources::ZERO, move |token: CancellationToken| {
        started_tx.send(()).unwrap();
        while !token.is_cancelled() {
          thread::yield_now();
        }
      })
      .unwrap();
    started.recv().unwrap();
    let e = lod(true);
    let pending = rt.try_spawn(cpu(1), move |_| drop(e)).unwrap();
    rt.shutdown(ShutdownMode::CancelPending).unwrap();
    blocker.join().unwrap();
    assert!(matches!(pending.join(), Err(JoinError::Cancelled)));
  });
  assert_eq!(dropped.load(Ordering::SeqCst), 5);
  assert_eq!(rt.snapshot().outstanding, 0);
}

#[test]
fn a_detached_panic_payload_with_a_panicking_drop_is_contained() {
  let mut rt = runtime(1, 2, cpu(1));
  let dropped = Arc::new(AtomicUsize::new(0));
  let c = LocksOnDrop {
    handle: rt.handle(),
    dropped: Arc::clone(&dropped),
    panic: true,
  };
  quiet_panics(|| {
    drop(rt.try_spawn(cpu(1), move |_| panic::panic_any(c)).unwrap());
    wait_for(&rt.handle(), |s| s.outstanding == 0);
  });
  assert_eq!(rt.try_spawn(cpu(1), |_| 4).unwrap().join().unwrap(), 4);
  rt.shutdown(ShutdownMode::Drain).unwrap();
  assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn dropping_a_job_detaches_it() {
  let mut rt = runtime(1, 2, cpu(1));
  let (job, started, gate) = gated(&rt, cpu(1));
  drop(job);
  started.recv().unwrap();
  gate.send(()).unwrap();
  let after = rt.try_spawn(Resources::ZERO, |_| 1).unwrap();
  assert_eq!(after.join().unwrap(), 1);
  rt.shutdown(ShutdownMode::Drain).unwrap();
  assert_eq!(rt.snapshot().outstanding, 0);
}

#[test]
fn drain_runs_every_admitted_job() {
  let mut rt = runtime(2, 32, cpu(32));
  let ran = Arc::new(AtomicUsize::new(0));
  let (blocker, started, gate) = gated(&rt, Resources::ZERO);
  started.recv().unwrap();
  let jobs: Vec<_> = (0..20)
    .map(|_| {
      let r = Arc::clone(&ran);
      rt.try_spawn(cpu(1), move |t| {
        assert!(!t.is_cancelled());
        r.fetch_add(1, Ordering::SeqCst)
      })
      .unwrap()
    })
    .collect();
  let opener = thread::spawn(move || gate.send(()).unwrap());
  rt.shutdown(ShutdownMode::Drain).unwrap();
  opener.join().unwrap();
  assert_eq!(ran.load(Ordering::SeqCst), 20);
  assert!(jobs.into_iter().all(|j| j.join().is_ok()));
  assert!(!blocker.join().unwrap().is_cancelled());
  let s = rt.snapshot();
  assert_eq!(
    (s.outstanding, s.queued, s.running, s.closed),
    (0, 0, 0, true)
  );
}

#[test]
fn cancel_pending_drops_queued_and_signals_running() {
  let mut rt = runtime(1, 8, cpu(8));
  let (started_tx, started) = mpsc::channel();
  let running = rt
    .try_spawn(cpu(1), move |token: CancellationToken| {
      started_tx.send(()).unwrap();
      while !token.is_cancelled() {
        thread::yield_now();
      }
      "saw it"
    })
    .unwrap();
  started.recv().unwrap();
  let marker = Arc::new(());
  let queued: Vec<_> = (0..4)
    .map(|_| {
      let m = Arc::clone(&marker);
      rt.try_spawn(cpu(1), move |_| drop(m)).unwrap()
    })
    .collect();
  rt.shutdown(ShutdownMode::CancelPending).unwrap();
  assert_eq!(running.join().unwrap(), "saw it");
  assert!(
    queued
      .into_iter()
      .all(|j| matches!(j.join(), Err(JoinError::Cancelled)))
  );
  assert_eq!(Arc::strong_count(&marker), 1);
  let s = rt.snapshot();
  assert_eq!((s.outstanding, s.reserved), (0, Resources::ZERO));
}

#[test]
fn shutdown_wakes_idle_workers_and_is_idempotent() {
  let mut rt = runtime(4, 1, Resources::ZERO);
  wait_for(&rt.handle(), |s| s.idle_workers == 4);
  rt.shutdown(ShutdownMode::Drain).unwrap();
  assert_eq!(rt.snapshot().idle_workers, 0);
  rt.shutdown(ShutdownMode::CancelPending).unwrap();
  rt.shutdown(ShutdownMode::Drain).unwrap();
  let e = rt.handle().try_spawn(Resources::ZERO, |_| ()).unwrap_err();
  assert_eq!(e.kind, SubmitErrorKind::Closed);
}

#[test]
fn a_finished_shutdown_changes_no_token() {
  for first in [ShutdownMode::Drain, ShutdownMode::CancelPending] {
    let mut rt = runtime(1, 2, Resources::ZERO);
    let token = rt
      .try_spawn(Resources::ZERO, |t| t)
      .unwrap()
      .join()
      .unwrap();
    rt.shutdown(first).unwrap();
    assert!(!token.is_cancelled(), "{first:?}");
    rt.shutdown(ShutdownMode::CancelPending).unwrap();
    rt.shutdown(ShutdownMode::Drain).unwrap();
    drop(rt);
    assert!(!token.is_cancelled(), "{first:?}");
  }
  // Nor does dropping a runtime change the token of a job released before.
  let rt = runtime(1, 2, Resources::ZERO);
  let token = rt
    .try_spawn(Resources::ZERO, |t| t)
    .unwrap()
    .join()
    .unwrap();
  wait_for(&rt.handle(), |s| s.outstanding == 0);
  drop(rt);
  assert!(!token.is_cancelled());
}

#[test]
fn submissions_racing_shutdown_run_or_are_closed() {
  for round in 0..50 {
    let mut rt = runtime(2, 1024, cpu(1024));
    let ran = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(3));
    let producers: Vec<_> = (0..2)
      .map(|_| {
        let (handle, ran, barrier) = (rt.handle(), Arc::clone(&ran), Arc::clone(&barrier));
        thread::spawn(move || {
          barrier.wait();
          let mut admitted = 0;
          for _ in 0..100 {
            let r = Arc::clone(&ran);
            match handle.try_spawn(cpu(1), move |_| r.fetch_add(1, Ordering::SeqCst)) {
              Ok(_) => admitted += 1,
              Err(e) => assert_eq!(e.kind, SubmitErrorKind::Closed),
            }
          }
          admitted
        })
      })
      .collect();
    barrier.wait();
    let mode = if round % 2 == 0 {
      ShutdownMode::Drain
    } else {
      ShutdownMode::CancelPending
    };
    rt.shutdown(mode).unwrap();
    let admitted: usize = producers.into_iter().map(|p| p.join().unwrap()).sum();
    if mode == ShutdownMode::Drain {
      assert_eq!(ran.load(Ordering::SeqCst), admitted);
    } else {
      assert!(ran.load(Ordering::SeqCst) <= admitted);
    }
    let s = rt.snapshot();
    assert_eq!(
      (s.outstanding, s.reserved, s.queued),
      (0, Resources::ZERO, 0)
    );
  }
}

#[test]
fn a_worker_cannot_shut_down_or_join_its_own_runtime() {
  let rt = Arc::new(Mutex::new(runtime(1, 4, cpu(4))));
  let inner = Arc::clone(&rt);
  let (own_tx, own) = mpsc::channel::<Job<()>>();
  let (report_tx, report) = mpsc::channel();
  let job = rt
    .lock()
    .unwrap()
    .try_spawn(cpu(1), move |_| {
      let selfjoin = own.recv().unwrap().join();
      let shutdown = inner.lock().unwrap().shutdown(ShutdownMode::Drain);
      let closed = inner.lock().unwrap().snapshot().closed;
      report_tx
        .send((
          matches!(selfjoin, Err(JoinError::WouldDeadlock)),
          shutdown.unwrap_err().kind(),
          closed,
        ))
        .unwrap();
    })
    .unwrap();
  own_tx.send(job).unwrap();
  assert_eq!(
    report.recv().unwrap(),
    (true, std::io::ErrorKind::Deadlock, false)
  );
  let mut rt = rt.lock().unwrap();
  rt.shutdown(ShutdownMode::Drain).unwrap();
  // A job of another runtime may shut this one down; it is not a worker.
  let mut other = runtime(1, 1, Resources::ZERO);
  let other_rt = Arc::new(Mutex::new(runtime(1, 1, Resources::ZERO)));
  let target = Arc::clone(&other_rt);
  let r = other.try_spawn(Resources::ZERO, move |_| {
    target.lock().unwrap().shutdown(ShutdownMode::Drain)
  });
  assert!(r.unwrap().join().unwrap().is_ok());
  other.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn a_parent_joining_a_queued_child_on_its_one_worker_fails_at_once() {
  let mut rt = runtime(1, 2, cpu(2));
  let handle = rt.handle();
  let (child_tx, child_rx) = mpsc::channel();
  let parent = rt
    .try_spawn(cpu(1), move |_| {
      let child = handle.try_spawn(cpu(1), |_| 7).unwrap();
      let finished_before = child.is_finished();
      let joined = child.join();
      child_tx.send(()).unwrap();
      (
        finished_before,
        matches!(joined, Err(JoinError::WouldDeadlock)),
      )
    })
    .unwrap();
  assert_eq!(parent.join().unwrap(), (false, true));
  child_rx.recv().unwrap();
  // The child is unaffected and still runs; an external shutdown drains it.
  rt.shutdown(ShutdownMode::Drain).unwrap();
  let s = rt.snapshot();
  assert_eq!((s.outstanding, s.reserved), (0, Resources::ZERO));
}

/// Joins `job` from its `Drop` and reports whether that failed as
/// `WouldDeadlock`.
struct JoinsOnDrop {
  job: Option<Job<()>>,
  report: Sender<bool>,
}

impl Drop for JoinsOnDrop {
  fn drop(&mut self) {
    if let Some(job) = self.job.take() {
      let _ = self
        .report
        .send(matches!(job.join(), Err(JoinError::WouldDeadlock)));
    }
  }
}

#[test]
fn joins_from_destructors_the_runtime_runs_fail_instead_of_waiting() {
  let mut rt = runtime(1, 4, cpu(4));
  let (report_tx, report) = mpsc::channel();
  let (blocker, started, gate) = gated(&rt, Resources::ZERO);
  started.recv().unwrap();
  // A detached result whose `Drop` joins a job queued behind it.
  let (behind_tx, behind_rx) = mpsc::channel::<Job<()>>();
  let r = report_tx.clone();
  drop(
    rt.try_spawn(cpu(1), move |_| JoinsOnDrop {
      job: Some(behind_rx.recv().unwrap()),
      report: r,
    })
    .unwrap(),
  );
  behind_tx
    .send(rt.try_spawn(cpu(1), |_| ()).unwrap())
    .unwrap();
  gate.send(()).unwrap();
  blocker.join().unwrap();
  assert!(report.recv().unwrap(), "result drop on the worker");
  // A cancelled job's capture, dropped by the worker, joining itself.
  let (blocker, started, gate) = gated(&rt, Resources::ZERO);
  started.recv().unwrap();
  let (capture, slot) = joins_slot(report_tx.clone());
  let job = rt.try_spawn(cpu(1), move |_| drop(capture)).unwrap();
  job.cancel();
  *slot.lock().unwrap() = Some(job);
  gate.send(()).unwrap();
  blocker.join().unwrap();
  assert!(report.recv().unwrap(), "capture drop on the worker");
  wait_for(&rt.handle(), |s| s.outstanding == 0);
  rt.shutdown(ShutdownMode::Drain).unwrap();
}

/// A capture that joins, from its `Drop`, the job later put in its slot.
struct JoinsSlot {
  slot: Arc<Mutex<Option<Job<()>>>>,
  report: Sender<bool>,
}

impl Drop for JoinsSlot {
  fn drop(&mut self) {
    let job = self.slot.lock().unwrap().take();
    drop(JoinsOnDrop {
      job,
      report: self.report.clone(),
    });
  }
}

fn joins_slot(report: Sender<bool>) -> (JoinsSlot, Arc<Mutex<Option<Job<()>>>>) {
  let slot = Arc::new(Mutex::new(None));
  let capture = JoinsSlot {
    slot: Arc::clone(&slot),
    report,
  };
  (capture, slot)
}

#[test]
fn captures_dropped_by_a_cancelling_shutdown_cannot_wait_on_its_cleanup() {
  let mut rt = runtime(1, 4, cpu(4));
  let (started_tx, started) = mpsc::channel();
  let running = rt
    .try_spawn(Resources::ZERO, move |token: CancellationToken| {
      started_tx.send(()).unwrap();
      while !token.is_cancelled() {
        thread::yield_now();
      }
    })
    .unwrap();
  started.recv().unwrap();
  let (report_tx, report) = mpsc::channel();
  // The first queued job's capture joins itself; the second's joins the
  // third, which the same shutdown drops after it.
  let (a, a_slot) = joins_slot(report_tx.clone());
  let (b, b_slot) = joins_slot(report_tx);
  let job_a = rt.try_spawn(cpu(1), move |_| drop(a)).unwrap();
  let job_b = rt.try_spawn(cpu(1), move |_| drop(b)).unwrap();
  let job_c = rt.try_spawn(cpu(1), |_| ()).unwrap();
  *a_slot.lock().unwrap() = Some(job_a);
  *b_slot.lock().unwrap() = Some(job_c);
  rt.shutdown(ShutdownMode::CancelPending).unwrap();
  running.join().unwrap();
  assert_eq!(report.iter().collect::<Vec<_>>(), [true, true]);
  assert!(matches!(job_b.join(), Err(JoinError::Cancelled)));
  let s = rt.snapshot();
  assert_eq!(
    (s.outstanding, s.reserved, s.cancelling),
    (0, Resources::ZERO, 0)
  );
}

#[test]
fn dropping_the_runtime_from_its_own_worker_does_not_wait() {
  let rt = runtime(1, 2, cpu(2));
  let handle = rt.handle();
  let (rt_tx, rt_rx) = mpsc::channel::<Runtime>();
  let job = rt
    .try_spawn(cpu(1), move |token| {
      drop(rt_rx.recv().unwrap());
      token.is_cancelled()
    })
    .unwrap();
  rt_tx.send(rt).unwrap();
  assert!(job.join().unwrap());
  let s = wait_for(&handle, |s| s.outstanding == 0);
  assert!(s.closed);
}

#[test]
fn dropping_the_runtime_detaches_running_jobs_and_cancels_queued_ones() {
  let rt = runtime(1, 4, cpu(4));
  let handle = rt.handle();
  let (started_tx, started) = mpsc::channel();
  let (go_tx, go) = mpsc::channel::<()>();
  let running = rt
    .try_spawn(cpu(1), move |token: CancellationToken| {
      started_tx.send(()).unwrap();
      go.recv().unwrap();
      token.is_cancelled()
    })
    .unwrap();
  started.recv().unwrap();
  let queued = rt.try_spawn(cpu(1), |_| ()).unwrap();
  // Returns while the job is still blocked on `go`.
  drop(rt);
  assert!(matches!(queued.join(), Err(JoinError::Cancelled)));
  assert_eq!(
    handle.try_spawn(Resources::ZERO, |_| ()).unwrap_err().kind,
    SubmitErrorKind::Closed
  );
  assert_eq!(handle.snapshot().outstanding, 1);
  go_tx.send(()).unwrap();
  assert!(running.join().unwrap());
  let s = wait_for(&handle, |s| s.outstanding == 0);
  assert_eq!(s.reserved, Resources::ZERO);
}

#[test]
fn a_failed_spawn_stops_and_joins_the_started_workers() {
  let exited = Arc::new(AtomicUsize::new(0));
  let (handles_tx, handles) = mpsc::channel();
  let mut spawned = 0;
  let e = Runtime::with_spawner(
    Config {
      workers: 4,
      max_outstanding: 1,
      capacity: Resources::ZERO,
    },
    |builder, f| {
      if spawned == 2 {
        return Err(std::io::Error::other("no more threads"));
      }
      spawned += 1;
      let exited = Arc::clone(&exited);
      let h = builder.spawn(move || {
        f();
        exited.fetch_add(1, Ordering::SeqCst);
      })?;
      handles_tx.send(h.thread().id()).unwrap();
      Ok(h)
    },
    |_| {},
  )
  .unwrap_err();
  assert_eq!(e.to_string(), "no more threads");
  assert_eq!(handles.try_iter().count(), 2);
  assert_eq!(exited.load(Ordering::SeqCst), 2);
}

/// A one-worker runtime whose worker stops after its first pre-park flush,
/// outside the lock, until the returned gate opens.
fn held_at_park() -> (Runtime, Receiver<()>, Sender<()>) {
  let (at_tx, at) = mpsc::channel();
  let (gate, gate_rx) = mpsc::channel::<()>();
  let once = Mutex::new(Some((at_tx, gate_rx)));
  let rt = Runtime::with_spawner(
    Config {
      workers: 1,
      max_outstanding: 2,
      capacity: cpu(2),
    },
    |builder, f| builder.spawn(f),
    move |shared| {
      shared.park_hook = Some(Box::new(move || {
        if let Some((at_tx, gate_rx)) = once.lock().unwrap().take() {
          at_tx.send(()).unwrap();
          let _ = gate_rx.recv();
        }
      }));
    },
  )
  .unwrap();
  (rt, at, gate)
}

#[test]
fn a_submission_at_the_flush_before_park_boundary_is_not_lost() {
  let (mut rt, at, gate) = held_at_park();
  at.recv().unwrap();
  // The worker has flushed and released the lock and not yet parked.
  let job = rt.try_spawn(cpu(1), |_| 5).unwrap();
  gate.send(()).unwrap();
  assert_eq!(job.join().unwrap(), 5);
  rt.shutdown(ShutdownMode::Drain).unwrap();
}

#[test]
fn a_shutdown_at_the_flush_before_park_boundary_is_not_lost() {
  for mode in [ShutdownMode::Drain, ShutdownMode::CancelPending] {
    let (rt, at, gate) = held_at_park();
    let handle = rt.handle();
    at.recv().unwrap();
    let shutdown = thread::spawn(move || {
      let mut rt = rt;
      rt.shutdown(mode)
    });
    wait_for(&handle, |s| s.closed);
    gate.send(()).unwrap();
    shutdown.join().unwrap().unwrap();
  }
}

#[test]
fn workers_take_their_shard_and_flush_before_parking() {
  let mut rt = runtime(1, 2, Resources::ZERO);
  let probe = || {
    rt.try_spawn(Resources::ZERO, |_| {
      (cache::SHARD.get(), cache::FLUSHES.get())
    })
    .unwrap()
    .join()
    .unwrap()
  };
  let (shard, first) = probe();
  assert_eq!(shard, Some(0));
  wait_for(&rt.handle(), |s| s.idle_workers == 1);
  let (_, second) = probe();
  assert!(second > first, "{first} then {second}");
  rt.shutdown(ShutdownMode::Drain).unwrap();
  let mut rt = runtime(3, 3, Resources::ZERO);
  let barrier = Arc::new(Barrier::new(3));
  let jobs: Vec<_> = (0..3)
    .map(|_| {
      let b = Arc::clone(&barrier);
      rt.try_spawn(Resources::ZERO, move |_| {
        b.wait();
        cache::SHARD.get()
      })
      .unwrap()
    })
    .collect();
  let mut shards: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
  shards.sort_unstable();
  assert_eq!(shards, [Some(0), Some(1), Some(2)]);
  rt.shutdown(ShutdownMode::Drain).unwrap();
}
