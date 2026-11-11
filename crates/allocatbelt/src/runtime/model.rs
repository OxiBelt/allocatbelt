//! Loom models of the runtime's protocols, under `--cfg loom`.
//!
//! Scope: the real [`StartState`] and [`Admission`] run under loom. The
//! queue, the worker's dequeue and finish, `Job::cancel` and the
//! cancelling close are written out here over a loom mutex, mirroring
//! `worker.rs`, `job.rs` and `scheduler.rs`; they are not the runtime's
//! own code. Not modelled: condvar waits and wakeups, the per-worker
//! running slots, the packet and its outcome, user `Drop` code and panics.
//! Those are covered by the thread tests in `tests.rs`.
//!
//! Checked: a queued job runs or is dropped unstarted, never both. Its
//! admission is released exactly once, after its closure ran or was
//! dropped, and its outcome is published only after that release.

use std::collections::VecDeque;

use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::sync::{Arc, Mutex};
use loom::thread;

use crate::runtime::admission::Admission;
use crate::runtime::error::SubmitErrorKind;
use crate::runtime::resources::Resources;
use crate::runtime::state::StartState;

const ONE: Resources = Resources {
  cpu: 1,
  memory: 0,
  disk: 0,
  network: 0,
};

struct Sched {
  admission: Admission,
  queue: VecDeque<Arc<StartState>>,
}

#[derive(Default)]
struct Counts {
  /// The closure was called.
  ran: AtomicUsize,
  /// The closure was dropped unstarted.
  cancelled: AtomicUsize,
  /// The closure (and its captures) is gone, called or dropped.
  cleaned: AtomicUsize,
  released: AtomicUsize,
  published: AtomicUsize,
}

impl Counts {
  /// A job's closure is gone: release, then publish. Every release follows
  /// its own job's cleanup, so cleanups stay ahead of releases.
  fn finish(&self, sched: &Mutex<Sched>) {
    let mut s = sched.lock().unwrap();
    assert!(self.cleaned.load(Ordering::SeqCst) > self.released.load(Ordering::SeqCst));
    assert!(s.admission.release(&ONE));
    self.released.fetch_add(1, Ordering::SeqCst);
    drop(s);
    self.published.fetch_add(1, Ordering::SeqCst);
  }
}

fn admit_one(sched: &Mutex<Sched>) -> Arc<StartState> {
  let job = Arc::new(StartState::new());
  let mut s = sched.lock().unwrap();
  s.admission.try_admit(&ONE).unwrap();
  s.queue.push_back(Arc::clone(&job));
  job
}

/// `worker::next`, then `worker::run` or `worker::abandon`, for one job:
/// the admission stays held through the closure's call or drop.
fn worker_step(sched: &Mutex<Sched>, counts: &Counts) {
  let mut s = sched.lock().unwrap();
  let Some(job) = s.queue.pop_front() else {
    return;
  };
  let started = job.try_start();
  drop(s);
  if started {
    counts.ran.fetch_add(1, Ordering::SeqCst);
  } else {
    counts.cancelled.fetch_add(1, Ordering::SeqCst);
  }
  // The closure was called or dropped unstarted: gone before the release.
  drop(job);
  counts.cleaned.fetch_add(1, Ordering::SeqCst);
  counts.finish(sched);
}

/// A joiner: whenever it sees the outcome, the admission is back.
fn observe(sched: &Mutex<Sched>, counts: &Counts) {
  if counts.published.load(Ordering::SeqCst) == 1 {
    assert_eq!(counts.released.load(Ordering::SeqCst), 1);
    assert_eq!(sched.lock().unwrap().admission.outstanding(), 0);
  }
}

fn check(sched: &Mutex<Sched>, counts: &Counts) {
  let ran = counts.ran.load(Ordering::SeqCst);
  let cancelled = counts.cancelled.load(Ordering::SeqCst);
  assert_eq!(ran + cancelled, 1);
  assert_eq!(counts.released.load(Ordering::SeqCst), 1);
  assert_eq!(counts.published.load(Ordering::SeqCst), 1);
  let s = sched.lock().unwrap();
  assert_eq!(
    (s.admission.outstanding(), s.admission.reserved()),
    (0, Resources::ZERO)
  );
}

fn new_sched(max_outstanding: usize) -> Arc<Mutex<Sched>> {
  Arc::new(Mutex::new(Sched {
    admission: Admission::new(max_outstanding, ONE),
    queue: VecDeque::new(),
  }))
}

#[test]
fn loom_cancel_races_start_exactly_once() {
  loom::model(|| {
    let sched = new_sched(1);
    let counts = Arc::new(Counts::default());
    let job = admit_one(&sched);
    let canceller = {
      let (sched, counts) = (Arc::clone(&sched), Arc::clone(&counts));
      thread::spawn(move || {
        // `Job::cancel`: no lock and no publication, only the swap; then
        // the handle's `join` looks.
        let _ = job.try_cancel();
        observe(&sched, &counts);
      })
    };
    worker_step(&sched, &counts);
    canceller.join().unwrap();
    check(&sched, &counts);
  });
}

#[test]
fn loom_cancelling_shutdown_races_the_worker() {
  loom::model(|| {
    let sched = new_sched(1);
    let counts = Arc::new(Counts::default());
    drop(admit_one(&sched));
    let shutdown = {
      let (sched, counts) = (Arc::clone(&sched), Arc::clone(&counts));
      thread::spawn(move || {
        // `Shared::close(true)` takes the queue, its jobs still admitted.
        // `worker::abandon_all`, per job: the start swap, the closure's
        // drop (here, the job's last reference), then release, then
        // publication.
        let pending = std::mem::take(&mut sched.lock().unwrap().queue);
        for job in pending {
          let _ = job.try_cancel();
          drop(job);
          counts.cancelled.fetch_add(1, Ordering::SeqCst);
          counts.cleaned.fetch_add(1, Ordering::SeqCst);
          counts.finish(&sched);
        }
        observe(&sched, &counts);
      })
    };
    worker_step(&sched, &counts);
    shutdown.join().unwrap();
    check(&sched, &counts);
  });
}

#[test]
fn loom_producers_respect_the_outstanding_bound() {
  loom::model(|| {
    let sched = new_sched(1);
    let counts = Arc::new(Counts::default());
    let producers: Vec<_> = (0..2)
      .map(|_| {
        let sched = Arc::clone(&sched);
        thread::spawn(move || {
          let mut s = sched.lock().unwrap();
          match s.admission.try_admit(&ONE) {
            Ok(()) => {
              s.queue.push_back(Arc::new(StartState::new()));
              assert!(s.admission.outstanding() <= 1);
              true
            }
            Err(kind) => {
              assert_eq!(kind, SubmitErrorKind::Full);
              false
            }
          }
        })
      })
      .collect();
    worker_step(&sched, &counts);
    worker_step(&sched, &counts);
    let admitted: usize = producers
      .into_iter()
      .map(|p| usize::from(p.join().unwrap()))
      .sum();
    worker_step(&sched, &counts);
    assert!(admitted >= 1);
    assert_eq!(counts.ran.load(Ordering::SeqCst), admitted);
    assert_eq!(counts.released.load(Ordering::SeqCst), admitted);
    assert_eq!(sched.lock().unwrap().admission.outstanding(), 0);
  });
}
