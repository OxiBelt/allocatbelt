//! Deadlock-guard regressions: per-runtime cleaner identities through
//! nested cleanups, unwinding and concurrent cleaners, and worker identity
//! through thread-local destructors at exit. Every wait is bounded, and
//! every blocker is released before a failure is asserted, so a regression
//! fails instead of hanging.

use std::cell::RefCell;
use std::panic;
use std::sync::Barrier;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crate::runtime::worker::{self, Cleaning, Ident};
use crate::runtime::{
  CancellationToken, Config, Handle, Job, JoinError, Resources, Runtime, ShutdownMode, Snapshot,
};

const REPORT: Duration = Duration::from_secs(30);

fn cpu(n: usize) -> Resources {
  Resources {
    cpu: n,
    ..Resources::ZERO
  }
}

fn runtime(workers: usize, max_outstanding: usize, capacity: Resources) -> Runtime {
  Runtime::new(Config {
    workers,
    max_outstanding,
    capacity,
  })
  .unwrap()
}

fn wait_for(handle: &Handle, what: impl Fn(&Snapshot) -> bool) -> Snapshot {
  let deadline = Instant::now() + REPORT;
  loop {
    let s = handle.snapshot();
    if what(&s) {
      return s;
    }
    assert!(Instant::now() < deadline, "timed out at {s:?}");
    thread::yield_now();
  }
}

fn released(s: &Snapshot) -> bool {
  (s.outstanding, s.reserved, s.queued, s.running, s.cancelling) == (0, Resources::ZERO, 0, 0, 0)
}

/// A job that reports it started, then waits until its gate is opened or
/// dropped.
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

/// Joins its job from its `Drop` and reports whether that failed as
/// `WouldDeadlock`.
struct JoinOnDrop<T> {
  job: Option<Job<T>>,
  report: Sender<bool>,
}

impl<T> Drop for JoinOnDrop<T> {
  fn drop(&mut self) {
    if let Some(job) = self.job.take() {
      let _ = self
        .report
        .send(matches!(job.join(), Err(JoinError::WouldDeadlock)));
    }
  }
}

#[test]
fn a_nested_cleanup_keeps_the_outer_runtimes_cleaner_identity() {
  let rt_a = runtime(1, 2, cpu(2));
  let rt_b = runtime(1, 2, cpu(2));
  let (handle_a, handle_b) = (rt_a.handle(), rt_b.handle());
  // Both pools busy: each one's only worker held until its gate opens.
  let (blocker_a, started_a, gate_a) = gated(&rt_a, cpu(1));
  let (blocker_b, started_b, gate_b) = gated(&rt_b, cpu(1));
  started_a.recv().unwrap();
  started_b.recv().unwrap();
  let (report_tx, report) = mpsc::channel();
  // B's queued capture owns A's unfinished blocker's handle.
  let joins_a = JoinOnDrop {
    job: Some(blocker_a),
    report: report_tx,
  };
  let queued_b = rt_b.try_spawn(cpu(1), move |_| drop(joins_a)).unwrap();
  // A's queued capture owns runtime B.
  let queued_a = rt_a.try_spawn(cpu(1), move |_| drop(rt_b)).unwrap();
  for handle in [&handle_a, &handle_b] {
    let s = handle.snapshot();
    assert_eq!(
      (s.outstanding, s.reserved, s.queued, s.running),
      (2, cpu(2), 1, 1)
    );
  }
  // A's cancelling shutdown drops B on its thread; B's drop drops B's
  // capture, which joins A's blocker. Only that thread can finish A's
  // cleanup, so the join must fail rather than wait.
  let shutdown = thread::spawn(move || {
    let mut rt_a = rt_a;
    rt_a.shutdown(ShutdownMode::CancelPending)
  });
  let nested = report.recv_timeout(REPORT);
  // Open both gates whatever happened, so a regression cannot hang.
  drop((gate_a, gate_b));
  assert_eq!(nested, Ok(true), "the nested join must not wait");
  shutdown.join().unwrap().unwrap();
  assert!(matches!(queued_a.join(), Err(JoinError::Cancelled)));
  assert!(matches!(queued_b.join(), Err(JoinError::Cancelled)));
  assert!(blocker_b.join().unwrap().is_cancelled());
  for handle in [&handle_a, &handle_b] {
    assert!(wait_for(handle, released).closed);
  }
}

thread_local! {
  static AT_EXIT: RefCell<Option<JoinOnDrop<()>>> = const { RefCell::new(None) };
}

#[test]
fn a_worker_thread_local_destructor_cannot_wait_on_its_own_pool() {
  let mut rt = runtime(2, 2, cpu(2));
  let handle = rt.handle();
  let (gate, gate_rx) = mpsc::channel::<()>();
  let (started_tx, started) = mpsc::channel();
  let blocked = rt
    .try_spawn(cpu(1), move |_| {
      started_tx.send(()).unwrap();
      let _ = gate_rx.recv();
    })
    .unwrap();
  started.recv().unwrap();
  let (report_tx, report) = mpsc::channel();
  let (job_tx, job_rx) = mpsc::channel::<Job<()>>();
  job_tx.send(blocked).unwrap();
  // Runs on the other worker and leaves it a thread-local whose
  // destructor, run as that worker exits, joins the still-blocked job.
  rt.try_spawn(cpu(1), move |_| {
    let job = job_rx.recv().unwrap();
    AT_EXIT.with(|slot| {
      *slot.borrow_mut() = Some(JoinOnDrop {
        job: Some(job),
        report: report_tx,
      });
    });
  })
  .unwrap()
  .join()
  .unwrap();
  let s = wait_for(&handle, |s| s.outstanding == 1);
  assert_eq!((s.running, s.reserved), (1, cpu(1)));
  let shutdown = thread::spawn(move || rt.shutdown(ShutdownMode::Drain));
  // The idle worker exits while the other is still blocked.
  let at_exit = report.recv_timeout(REPORT);
  drop(gate);
  assert_eq!(at_exit, Ok(true), "the exit-time join must not wait");
  shutdown.join().unwrap().unwrap();
  wait_for(&handle, released);
}

#[test]
fn cleaner_identity_is_restored_when_a_cleanup_unwinds() {
  // Ids no runtime gets in a test run.
  let a = Ident::new(u64::MAX - 1);
  let b = Ident::new(u64::MAX - 2);
  let caught = panic::catch_unwind(panic::AssertUnwindSafe(|| {
    let _a = Cleaning::enter(&a);
    assert!(worker::would_deadlock(&a));
    let unwound = panic::catch_unwind(panic::AssertUnwindSafe(|| {
      let _b = Cleaning::enter(&b);
      assert!(worker::would_deadlock(&a) && worker::would_deadlock(&b));
      panic::resume_unwind(Box::new("inner cleanup"));
    }));
    assert!(unwound.is_err());
    // B's guard unwound: B is clear and A is still marked.
    assert!(worker::would_deadlock(&a));
    assert!(!worker::would_deadlock(&b));
    panic::resume_unwind(Box::new("outer cleanup"));
  }));
  assert!(caught.is_err());
  assert!(!worker::would_deadlock(&a));
  assert!(!worker::would_deadlock(&b));
}

#[test]
fn concurrent_cleaners_each_see_only_their_own_runtime() {
  let idents = [Ident::new(u64::MAX - 3), Ident::new(u64::MAX - 4)];
  let barrier = Barrier::new(2);
  // Each thread only records what it sees, and always reaches both
  // barriers, so a failed check cannot leave its peer waiting.
  let seen = thread::scope(|scope| {
    let cleaners: Vec<_> = (0..2)
      .map(|mine| {
        let (idents, barrier) = (&idents, &barrier);
        scope.spawn(move || {
          let cleaning = Cleaning::enter(&idents[mine]);
          // Both marked at once.
          barrier.wait();
          let own = worker::would_deadlock(&idents[mine]);
          let other = worker::would_deadlock(&idents[1 - mine]);
          barrier.wait();
          drop(cleaning);
          (own, other)
        })
      })
      .collect();
    cleaners
      .into_iter()
      .map(|cleaner| cleaner.join().unwrap())
      .collect::<Vec<_>>()
  });
  assert_eq!(seen, [(true, false), (true, false)]);
  // Neither mark was left behind, nor is either seen from here.
  for ident in &idents {
    assert!(!worker::would_deadlock(ident));
  }
}

#[test]
fn ids_never_wrap_or_reach_the_reserved_values() {
  let next = AtomicU64::new(u64::MAX - 3);
  assert_eq!(worker::next_id(&next), Some(u64::MAX - 3));
  assert_eq!(worker::next_id(&next), Some(u64::MAX - 2));
  // `u64::MAX - 1` would leave `u64::MAX` next: exhausted, and it stays so.
  assert_eq!(worker::next_id(&next), None);
  assert_eq!(worker::next_id(&next), None);
  let zero = AtomicU64::new(1);
  assert_eq!(worker::next_id(&zero), Some(1));
}
