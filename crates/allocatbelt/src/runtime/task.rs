//! The type-erased queued job: runs its closure, or drops it unstarted.

use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::task::{Wake, Waker};
use std::thread::{self, Thread};

use crate::runtime::cpu_execution::CpuExecutionGuard;
use crate::runtime::error::JoinError;
use crate::runtime::job::{CancellationToken, Control, Packet};
use crate::runtime::resource_domain::{
  ControlCharge, DomainError, DomainReservation, DomainWaiter, TenantDomain,
};
use crate::runtime::time::AutoAdvanceInhibitGuard;

/// Returns a job's admission. The worker calls it again after the job if
/// the job did not, so it releases exactly once.
pub(crate) trait Release {
  fn release(&mut self);
}

/// A queued job with its result type erased.
pub(crate) trait Runnable: Send {
  /// The job's flags and start state (see [`crate::runtime::state`]).
  fn control(&self) -> &Arc<Control>;

  /// Runs a started job: calls the closure, releases the admission once the
  /// closure returned (or unwound) and its captures were dropped, publishes
  /// the outcome and drops what nobody will take. Called without any
  /// scheduler lock.
  fn run(self: Box<Self>, release: &mut dyn Release);

  /// Finishes a job that will not start: drops the closure (a panic of its
  /// `Drop` contained), then releases the admission, then publishes
  /// `Cancelled`. Called without any scheduler lock.
  fn abandon(self: Box<Self>, release: &mut dyn Release);

  /// Drops a closure that could not acquire resources, then publishes the
  /// typed admission failure. Called without any scheduler lock.
  fn fail_resource(self: Box<Self>, release: &mut dyn Release, error: DomainError);
}

pub(crate) struct TaskDomainAdmission {
  pub(crate) tenant: Option<TenantDomain>,
  pub(crate) waiter: Option<DomainWaiter>,
  pub(crate) task_admission: Option<DomainReservation>,
  pub(crate) task_control: ControlCharge,
}

pub(crate) struct Task<F, T> {
  pub(crate) f: F,
  control: Arc<Control>,
  packet: Arc<Packet<T>>,
  auto_advance_inhibit: Option<AutoAdvanceInhibitGuard>,
  tenant: Option<TenantDomain>,
  waiter: Option<DomainWaiter>,
  task_admission: Option<DomainReservation>,
  _control: ControlCharge,
}

impl<F, T> Task<F, T> {
  pub(crate) fn new(
    f: F,
    control: Arc<Control>,
    packet: Arc<Packet<T>>,
    auto_advance_inhibit: Option<AutoAdvanceInhibitGuard>,
    domain: TaskDomainAdmission,
  ) -> Self {
    let TaskDomainAdmission {
      tenant,
      waiter,
      task_admission,
      task_control,
    } = domain;
    Self {
      f,
      control,
      packet,
      auto_advance_inhibit,
      tenant,
      waiter,
      task_admission,
      _control: task_control,
    }
  }

  fn wait_for_cpu(&self) -> CpuAdmission {
    let Some(tenant) = &self.tenant else {
      return CpuAdmission::Unbounded;
    };
    let Some(waiter) = &self.waiter else {
      return CpuAdmission::Rejected(DomainError::WaitersFull);
    };
    let current = thread::current();
    let control =
      match ControlCharge::try_new(Some(tenant), std::mem::size_of::<BlockingThreadWake>()) {
        Ok(control) => control,
        Err(error) => return CpuAdmission::Rejected(error),
      };
    let waker = Waker::from(Arc::new(BlockingThreadWake {
      thread: current.clone(),
      _control: control,
    }));
    loop {
      if self.control.is_cancelled() {
        self.control.clear_waiting_thread();
        waiter.cancel_wait();
        return CpuAdmission::Cancelled;
      }
      self.control.register_waiting_thread(&current);
      if self.control.is_cancelled() {
        self.control.clear_waiting_thread();
        waiter.cancel_wait();
        return CpuAdmission::Cancelled;
      }
      match waiter.try_acquire_or_register(tenant, &waker) {
        Ok(Some(ticket)) => {
          self.control.clear_waiting_thread();
          return CpuAdmission::Acquired(ticket);
        }
        Ok(None) => thread::park(),
        Err(error) => {
          self.control.clear_waiting_thread();
          waiter.cancel_wait();
          return CpuAdmission::Rejected(error);
        }
      }
    }
  }
}

enum CpuAdmission {
  Unbounded,
  Acquired(DomainReservation),
  Cancelled,
  Rejected(DomainError),
}

struct BlockingThreadWake {
  thread: Thread,
  _control: ControlCharge,
}

impl Wake for BlockingThreadWake {
  fn wake(self: Arc<Self>) {
    self.thread.unpark();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.thread.unpark();
  }
}

/// Drops `value`, containing a panic of its `Drop`. A panic payload whose
/// own drop panics is leaked rather than unwinding into the worker.
pub(crate) fn drop_contained<V>(value: V) {
  if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(move || drop(value)))
    && let Err(again) = panic::catch_unwind(AssertUnwindSafe(move || drop(payload)))
  {
    std::mem::forget(again);
  }
}

impl<F, T> Runnable for Task<F, T>
where
  F: FnOnce(CancellationToken) -> T + Send,
  T: Send,
{
  fn control(&self) -> &Arc<Control> {
    &self.control
  }

  fn run(self: Box<Self>, release: &mut dyn Release) {
    let cpu_ticket = match self.wait_for_cpu() {
      CpuAdmission::Unbounded => None,
      CpuAdmission::Acquired(ticket) => Some(ticket),
      CpuAdmission::Cancelled => {
        self.abandon(release);
        return;
      }
      CpuAdmission::Rejected(error) => {
        self.fail_resource(release, error);
        return;
      }
    };
    let Self {
      f,
      control,
      packet,
      auto_advance_inhibit,
      tenant: _,
      waiter,
      task_admission,
      _control: task_control,
    } = *self;
    let _auto_advance_inhibit = auto_advance_inhibit;
    let token = CancellationToken::new(control);
    let cpu_execution =
      CpuExecutionGuard::enter(cpu_ticket.as_ref().map(DomainReservation::domain_identity));
    let outcome =
      panic::catch_unwind(AssertUnwindSafe(move || f(token))).map_err(JoinError::Panicked);
    drop(cpu_execution);
    drop(cpu_ticket);
    if let Some(waiter) = waiter {
      waiter.cancel_wait();
      drop(waiter);
    }
    drop(task_admission);
    release.release();
    if let Some(unclaimed) = packet.publish(outcome) {
      drop_contained(unclaimed);
    }
    drop(task_control);
  }

  fn abandon(self: Box<Self>, release: &mut dyn Release) {
    let Self {
      f,
      control,
      packet,
      auto_advance_inhibit,
      tenant: _,
      waiter,
      task_admission,
      _control: task_control,
    } = *self;
    let _auto_advance_inhibit = auto_advance_inhibit;
    // A shutdown's take: the job may never start, whatever won before.
    let _ = control.start.try_cancel();
    drop_contained(f);
    if let Some(waiter) = waiter {
      waiter.cancel_wait();
      drop(waiter);
    }
    drop(task_admission);
    release.release();
    // `Cancelled` holds nothing of the user's, so this drops nothing.
    let _ = packet.publish(Err(JoinError::Cancelled));
    drop(task_control);
  }

  fn fail_resource(self: Box<Self>, release: &mut dyn Release, error: DomainError) {
    let Self {
      f,
      control: _,
      packet,
      auto_advance_inhibit,
      tenant: _,
      waiter,
      task_admission,
      _control: task_control,
    } = *self;
    let _auto_advance_inhibit = auto_advance_inhibit;
    let outcome = match panic::catch_unwind(AssertUnwindSafe(|| drop(f))) {
      Ok(()) => Err(JoinError::ResourceDomain(error)),
      Err(payload) => Err(JoinError::Panicked(payload)),
    };
    if let Some(waiter) = waiter {
      waiter.cancel_wait();
      drop(waiter);
    }
    drop(task_admission);
    release.release();
    if let Some(unclaimed) = packet.publish(outcome) {
      drop_contained(unclaimed);
    }
    drop(task_control);
  }
}
