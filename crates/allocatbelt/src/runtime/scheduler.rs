//! The shared scheduler: admission, the FIFO queue and closing, under one
//! lock that never runs user code. Closures, results and panic payloads are
//! called and dropped by the callers of these functions, after the lock is
//! released.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use crate::runtime::admission::Admission;
use crate::runtime::error::{SubmitError, SubmitErrorKind};
use crate::runtime::job::{CancellationToken, Control, Job, Packet};
use crate::runtime::resources::Resources;
use crate::runtime::task::{Runnable, Task};
use crate::runtime::worker::Ident;

/// A queued job and the resources it reserved.
pub(crate) struct Entry {
  pub(crate) request: Resources,
  pub(crate) task: Box<dyn Runnable>,
}

pub(crate) struct State {
  pub(crate) admission: Admission,
  pub(crate) queue: VecDeque<Entry>,
  /// The job each worker has started and not yet released, by worker
  /// index: what a cancelling close signals.
  pub(crate) running: Vec<Option<Arc<Control>>>,
  pub(crate) running_count: usize,
  /// Jobs taken off the queue unstarted whose closure is being dropped;
  /// still admitted.
  pub(crate) cancelling: usize,
  pub(crate) idle: usize,
  pub(crate) closed: bool,
}

/// Called by a worker after its pre-park flush, before it relocks: lets a
/// test hold a worker at that boundary.
#[cfg(test)]
pub(crate) type ParkHook = Box<dyn Fn() + Send + Sync>;

pub(crate) struct Shared {
  pub(crate) ident: Arc<Ident>,
  state: Mutex<State>,
  pub(crate) work: Condvar,
  #[cfg(test)]
  pub(crate) park_hook: Option<ParkHook>,
}

/// A point-in-time view of a runtime's accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Snapshot {
  /// Admitted jobs not yet released: `queued + running + cancelling`. At
  /// most `max_outstanding`.
  pub outstanding: usize,
  /// Resources reserved by the outstanding jobs.
  pub reserved: Resources,
  /// Jobs in the queue, cancelled ones included until they are dequeued.
  pub queued: usize,
  /// Jobs whose closure is running, or has returned and whose captures are
  /// being dropped, not yet released.
  pub running: usize,
  /// Jobs taken off the queue unstarted whose closure is being dropped,
  /// not yet released.
  pub cancelling: usize,
  /// Workers parked waiting for work, their caches returned.
  pub idle_workers: usize,
  /// Whether new submissions are rejected as `Closed`.
  pub closed: bool,
}

impl Shared {
  pub(crate) fn new(
    id: u64,
    workers: usize,
    max_outstanding: usize,
    capacity: Resources,
  ) -> io::Result<Self> {
    let mut queue = VecDeque::new();
    queue
      .try_reserve_exact(max_outstanding)
      .map_err(reservation_error)?;
    let mut running = Vec::new();
    running
      .try_reserve_exact(workers)
      .map_err(reservation_error)?;
    running.resize_with(workers, || None);
    Ok(Self {
      ident: Ident::new(id),
      state: Mutex::new(State {
        admission: Admission::new(max_outstanding, capacity),
        queue,
        running,
        running_count: 0,
        cancelling: 0,
        idle: 0,
        closed: false,
      }),
      work: Condvar::new(),
      #[cfg(test)]
      park_hook: None,
    })
  }

  /// The lock never unwinds while held (it runs no user code), so a
  /// poisoned lock still holds consistent counts.
  pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
    self.state.lock().unwrap_or_else(PoisonError::into_inner)
  }

  pub(crate) fn try_spawn<F, T>(&self, request: Resources, f: F) -> Result<Job<T>, SubmitError<F>>
  where
    F: FnOnce(CancellationToken) -> T + Send + 'static,
    T: Send + 'static,
  {
    let control = Control::new(Arc::clone(&self.ident));
    let packet = Packet::new();
    let task = Box::new(Task::new(f, Arc::clone(&control), Arc::clone(&packet)));
    let mut state = self.lock();
    let admitted = if state.closed {
      Err(SubmitErrorKind::Closed)
    } else {
      state.admission.try_admit(&request)
    };
    if let Err(kind) = admitted {
      drop(state);
      return Err(SubmitError { kind, job: task.f });
    }
    // queued <= outstanding <= max_outstanding <= reserved capacity.
    // Admission and insertion hold the same lock, so this cannot grow.
    debug_assert!(state.queue.len() < state.queue.capacity());
    state.queue.push_back(Entry { request, task });
    drop(state);
    self.work.notify_one();
    Ok(Job::new(control, packet))
  }

  pub(crate) fn snapshot(&self) -> Snapshot {
    let state = self.lock();
    Snapshot {
      outstanding: state.admission.outstanding(),
      reserved: state.admission.reserved(),
      queued: state.queue.len(),
      running: state.running_count,
      cancelling: state.cancelling,
      idle_workers: state.idle,
      closed: state.closed,
    }
  }

  /// Rejects new submissions and wakes every worker. With `cancel`, also
  /// signals the tokens of the jobs queued or running now (never of jobs
  /// already released) and takes the queue. The taken jobs stay admitted,
  /// counted as cancelling, until the caller abandons them outside the
  /// lock ([`crate::runtime::worker::abandon`]).
  pub(crate) fn close(&self, cancel: bool) -> VecDeque<Entry> {
    let mut state = self.lock();
    state.closed = true;
    let pending = if cancel {
      for control in state.running.iter().flatten() {
        control.mark_cancelled();
      }
      let pending = std::mem::take(&mut state.queue);
      for entry in &pending {
        entry.task.control().mark_cancelled();
      }
      state.cancelling += pending.len();
      pending
    } else {
      VecDeque::new()
    };
    drop(state);
    self.work.notify_all();
    pending
  }
}

fn reservation_error(_: std::collections::TryReserveError) -> io::Error {
  io::ErrorKind::OutOfMemory.into()
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;
  use crate::runtime::error::JoinError;
  use crate::runtime::task::Release;

  struct Finish<'a> {
    shared: &'a Shared,
    request: Resources,
  }

  impl Release for Finish<'_> {
    fn release(&mut self) {
      assert!(self.shared.lock().admission.release(&self.request));
    }
  }

  #[test]
  fn reserved_fifo_wraps_without_growing_or_losing_admissions() {
    let shared = Shared::new(
      1,
      1,
      3,
      Resources {
        memory: 6,
        ..Resources::ZERO
      },
    )
    .unwrap();
    let capacity = shared.lock().queue.capacity();
    assert!(capacity >= 3);
    let mut jobs: VecDeque<_> = (1..=3)
      .map(|memory| {
        shared
          .try_spawn(
            Resources {
              memory,
              ..Resources::ZERO
            },
            |_| (),
          )
          .unwrap()
      })
      .collect();
    let mut split = false;
    for step in 0..100 {
      assert_eq!(shared.snapshot().outstanding, 3);
      assert_eq!(shared.snapshot().queued, 3);
      let entry = {
        let mut state = shared.lock();
        assert_eq!(state.queue.capacity(), capacity);
        split |= !state.queue.as_slices().1.is_empty();
        state.queue.pop_front().unwrap()
      };
      let memory = step % 3 + 1;
      assert_eq!(entry.request.memory, memory);
      entry.task.abandon(&mut Finish {
        shared: &shared,
        request: entry.request,
      });
      assert!(matches!(
        jobs.pop_front().unwrap().join(),
        Err(JoinError::Cancelled)
      ));
      jobs.push_back(
        shared
          .try_spawn(
            Resources {
              memory,
              ..Resources::ZERO
            },
            |_| (),
          )
          .unwrap(),
      );
    }
    assert!(split, "the FIFO must cross its ring boundary");
    loop {
      let entry = shared.lock().queue.pop_front();
      let Some(entry) = entry else { break };
      entry.task.abandon(&mut Finish {
        shared: &shared,
        request: entry.request,
      });
      assert!(matches!(
        jobs.pop_front().unwrap().join(),
        Err(JoinError::Cancelled)
      ));
    }
    assert_eq!(shared.snapshot().outstanding, 0);
    assert_eq!(shared.snapshot().reserved, Resources::ZERO);
  }
}
