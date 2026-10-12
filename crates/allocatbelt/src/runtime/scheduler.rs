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
use crate::runtime::managed::ResourceScope;
use crate::runtime::resource_domain::{
  ControlCharge, DomainError, DomainReservation, DomainResource, DomainResources, DomainWaitPool,
  DomainWaiter, TenantDomain, payload_bytes,
};
use crate::runtime::resources::Resources;
use crate::runtime::task::{Runnable, Task, TaskDomainAdmission};
use crate::runtime::time::TimerHandle;
use crate::runtime::worker::Ident;

/// A queued job and the resources it reserved.
pub(crate) struct Entry {
  pub(crate) request: Resources,
  pub(crate) task: Box<dyn Runnable>,
}

pub(crate) struct ClosedQueue {
  pub(crate) entries: VecDeque<Entry>,
  _control: Option<ControlCharge>,
}

impl ClosedQueue {
  pub(crate) fn empty() -> Self {
    Self {
      entries: VecDeque::new(),
      _control: None,
    }
  }

  pub(crate) fn is_empty(&self) -> bool {
    self.entries.is_empty()
  }

  pub(crate) fn pop_front(&mut self) -> Option<Entry> {
    self.entries.pop_front()
  }

  pub(crate) fn into_parts(self) -> (VecDeque<Entry>, Option<ControlCharge>) {
    (self.entries, self._control)
  }
}

impl Default for ClosedQueue {
  fn default() -> Self {
    Self::empty()
  }
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
  clock: Mutex<Option<TimerHandle>>,
  tenant: Option<TenantDomain>,
  domain_waiters: Option<DomainWaitPool>,
  runtime_identity_control: Arc<ControlCharge>,
  queue_control: Mutex<Option<ControlCharge>>,
  _control: ControlCharge,
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
    resources: Option<ResourceScope>,
  ) -> io::Result<Self> {
    let tenant = resources.as_ref().and_then(ResourceScope::tenant_domain);
    let shared_bytes = std::mem::size_of::<Shared>()
      .checked_add(payload_bytes::<Option<Arc<Control>>>(workers).map_err(domain_build_error)?)
      .ok_or_else(|| domain_build_error(DomainError::Invalid))?;
    let mut shared_control =
      ControlCharge::try_new(tenant, shared_bytes).map_err(domain_build_error)?;
    let queue_bytes = payload_bytes::<Entry>(max_outstanding).map_err(domain_build_error)?;
    let mut queue_control =
      ControlCharge::try_new(tenant, queue_bytes).map_err(domain_build_error)?;
    let identity_bytes = std::mem::size_of::<Ident>()
      .checked_add(std::mem::size_of::<ControlCharge>())
      .ok_or_else(|| domain_build_error(DomainError::Invalid))?;
    let identity_control =
      Arc::new(ControlCharge::try_new(tenant, identity_bytes).map_err(domain_build_error)?);

    let mut queue = VecDeque::new();
    queue
      .try_reserve_exact(max_outstanding)
      .map_err(reservation_error)?;
    let mut running = Vec::new();
    running
      .try_reserve_exact(workers)
      .map_err(reservation_error)?;
    running.resize_with(workers, || None);
    let (tenant, domain_waiters) = if let Some(tenant) = tenant {
      tenant
        .validate_cpu_execution()
        .map_err(domain_build_error)?;
      let waiters = tenant
        .reserve_waiters(max_outstanding)
        .map_err(domain_build_error)?;
      (Some(tenant.clone()), Some(waiters))
    } else {
      (None, None)
    };
    let actual_shared_bytes = std::mem::size_of::<Shared>()
      .checked_add(
        payload_bytes::<Option<Arc<Control>>>(running.capacity()).map_err(domain_build_error)?,
      )
      .ok_or_else(|| domain_build_error(DomainError::Invalid))?;
    shared_control
      .try_resize(actual_shared_bytes)
      .map_err(domain_build_error)?;
    queue_control
      .try_resize(payload_bytes::<Entry>(queue.capacity()).map_err(domain_build_error)?)
      .map_err(domain_build_error)?;
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
      clock: Mutex::new(None),
      tenant,
      domain_waiters,
      runtime_identity_control: identity_control,
      queue_control: Mutex::new(Some(queue_control)),
      _control: shared_control,
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

  pub(crate) fn bind_clock(&self, timer: TimerHandle) {
    let mut clock = self.clock.lock().unwrap_or_else(PoisonError::into_inner);
    debug_assert!(clock.is_none());
    *clock = Some(timer);
  }

  pub(crate) fn try_spawn<F, T>(&self, request: Resources, f: F) -> Result<Job<T>, SubmitError<F>>
  where
    F: FnOnce(CancellationToken) -> T + Send + 'static,
    T: Send + 'static,
  {
    let domain =
      match reserve_job_admission::<F, T>(self.tenant.as_ref(), self.domain_waiters.as_ref()) {
        Ok(domain) => domain,
        Err(error) => {
          return Err(SubmitError {
            kind: domain_submit_kind(error),
            job: f,
          });
        }
      };
    let JobDomainAdmission {
      tenant,
      task: task_admission,
      waiter,
      task_control,
      control: control_control,
      packet: packet_control,
    } = domain;
    let clock = self
      .clock
      .lock()
      .unwrap_or_else(PoisonError::into_inner)
      .clone();
    let auto_advance_inhibit = clock.map(|timer| timer.inhibit_auto_advance());
    let domain_identity = tenant.as_ref().map(TenantDomain::domain_identity);
    let task_domain = TaskDomainAdmission {
      tenant,
      waiter,
      task_admission,
      task_control,
    };
    let control = Control::with_control(
      Arc::clone(&self.ident),
      domain_identity,
      Arc::clone(&self.runtime_identity_control),
      control_control,
    );
    let packet = Packet::with_control(packet_control);
    let task = Box::new(Task::new(
      f,
      Arc::clone(&control),
      Arc::clone(&packet),
      auto_advance_inhibit,
      task_domain,
    ));
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
  pub(crate) fn close(&self, cancel: bool) -> ClosedQueue {
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
    let queue_control = if cancel {
      self
        .queue_control
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
    } else {
      None
    };
    self.work.notify_all();
    ClosedQueue {
      entries: pending,
      _control: queue_control,
    }
  }
}

pub(crate) fn domain_build_error(error: DomainError) -> io::Error {
  let kind = match error {
    DomainError::OutOfMemory => io::ErrorKind::OutOfMemory,
    DomainError::Invalid | DomainError::AboveCeiling(_) | DomainError::Closed => {
      io::ErrorKind::InvalidInput
    }
    DomainError::Exhausted(_)
    | DomainError::TenantsFull
    | DomainError::WaitersFull
    | DomainError::GenerationExhausted => io::ErrorKind::WouldBlock,
  };
  io::Error::new(kind, error)
}

struct JobDomainAdmission {
  tenant: Option<TenantDomain>,
  task: Option<DomainReservation>,
  waiter: Option<DomainWaiter>,
  task_control: ControlCharge,
  control: ControlCharge,
  packet: ControlCharge,
}

fn reserve_job_admission<F, T>(
  tenant: Option<&TenantDomain>,
  waiters: Option<&DomainWaitPool>,
) -> Result<JobDomainAdmission, DomainError> {
  let task_bytes = std::mem::size_of::<Task<F, T>>();
  let control_bytes = std::mem::size_of::<Control>();
  let packet_bytes = std::mem::size_of::<Packet<T>>();
  let all_control_bytes = task_bytes
    .checked_add(control_bytes)
    .and_then(|bytes| bytes.checked_add(packet_bytes))
    .ok_or(DomainError::Invalid)?;

  let (task, mut control) = if let Some(tenant) = tenant {
    tenant.validate_cpu_execution()?;
    let mut combined = tenant.try_acquire(
      DomainResources::ZERO
        .with(DomainResource::Tasks, 1)
        .with(DomainResource::Control, all_control_bytes),
    )?;
    let task = combined.split_off(DomainResources::ZERO.with(DomainResource::Tasks, 1))?;
    (
      Some(task),
      ControlCharge::from_ticket(Some(tenant), combined, all_control_bytes),
    )
  } else {
    (None, ControlCharge::unbounded(all_control_bytes))
  };
  let task_control = control.split_off(task_bytes)?;
  let control_control = control.split_off(control_bytes)?;
  let packet_control = control;
  let waiter = if tenant.is_some() {
    Some(waiters.ok_or(DomainError::WaitersFull)?.try_lease()?)
  } else {
    None
  };
  Ok(JobDomainAdmission {
    tenant: tenant.cloned(),
    task,
    waiter,
    task_control,
    control: control_control,
    packet: packet_control,
  })
}

fn domain_submit_kind(error: DomainError) -> SubmitErrorKind {
  match error {
    DomainError::Exhausted(DomainResource::Control)
    | DomainError::AboveCeiling(DomainResource::Control) => SubmitErrorKind::ResourceDomain(error),
    DomainError::Closed => SubmitErrorKind::Closed,
    DomainError::AboveCeiling(DomainResource::Tasks | DomainResource::Cpu)
    | DomainError::Invalid => SubmitErrorKind::InvalidRequest,
    DomainError::WaitersFull => SubmitErrorKind::Full,
    DomainError::OutOfMemory
    | DomainError::TenantsFull
    | DomainError::GenerationExhausted
    | DomainError::AboveCeiling(_)
    | DomainError::Exhausted(_) => SubmitErrorKind::InsufficientResources,
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
      None,
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
