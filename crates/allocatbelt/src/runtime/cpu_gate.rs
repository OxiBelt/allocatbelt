//! Executor-neutral CPU admission for short synchronous polls and closures.
//!
//! A [`CpuGate`] reserves a disjoint share of a tenant's fixed CPU-waiter
//! table. Its clones share that share and its Control owner. A wrapped future
//! takes one CPU ticket only while its inner `Future::poll` runs. [`CpuGate::run`]
//! similarly holds a ticket only while its closure runs; if no ticket is
//! available, it parks the calling thread until the domain wakes its waiter.
//!
//! This gate accounts the declared Rust payloads it owns: its shared owner,
//! each wrapped future and its known payload, per-call waiter state and the
//! blocking thread waker. Allocator headers and runtime/provider internals
//! such as Tokio task allocations are outside that accounting. A CPU ticket
//! bounds simultaneous gated polls or closures, not a whole async transaction
//! and not CPU time.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};

use crate::runtime::cpu_execution::{CpuExecutionGuard, active_for_domain};
use crate::runtime::resource_domain::{
  ControlCharge, DomainError, DomainResource, DomainWaitPool, DomainWaiter, TenantDomain,
};

/// Shared CPU admission for async polls and blocking closures.
///
/// Clones use the same global and tenant resource domain and share one bounded
/// waiter-table reservation. Create one gate and pass clones to every runtime
/// producer, task or blocking closure that should share this CPU bound.
#[derive(Clone)]
pub struct CpuGate {
  inner: Arc<CpuGateInner>,
}

struct CpuGateInner {
  tenant: TenantDomain,
  waiters: DomainWaitPool,
  max_waiters: usize,
  _control: ControlCharge,
}

impl fmt::Debug for CpuGate {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("CpuGate")
      .field("max_waiters", &self.inner.max_waiters)
      .finish_non_exhaustive()
  }
}

impl CpuGate {
  /// Creates a gate with a fixed share of `max_waiters` domain waiter slots.
  ///
  /// The tenant must have nonzero hard CPU and task ceilings, and the shared
  /// resource domain must have enough unleased waiter slots. The gate and its
  /// waiter-pool metadata are charged to global and tenant Control before the
  /// gate is returned.
  pub fn new(tenant: TenantDomain, max_waiters: usize) -> Result<Self, DomainError> {
    if max_waiters == 0 {
      return Err(DomainError::Invalid);
    }
    let control = ControlCharge::try_new(Some(&tenant), std::mem::size_of::<CpuGateInner>())?;
    let waiters = tenant.reserve_waiters(max_waiters)?;
    Ok(Self {
      inner: Arc::new(CpuGateInner {
        tenant,
        waiters,
        max_waiters,
        _control: control,
      }),
    })
  }

  /// Wraps a future so the domain admits each inner poll independently.
  ///
  /// The future is pinned in a box so this accepts ordinary `!Unpin` async
  /// blocks. The Control reservation covers the wrapper payload and the
  /// future's known Rust payload before the box is allocated. A waiter slot
  /// remains leased until the wrapper completes or is dropped.
  ///
  /// # Errors
  ///
  /// Returns the unchanged future if Control admission or a waiter lease is
  /// refused. Errors that occur later while polling are returned by the
  /// wrapper's output.
  pub fn wrap<F: Future>(&self, future: F) -> Result<CpuGated<F>, CpuWrapError<F>> {
    let Some(control_bytes) =
      std::mem::size_of::<CpuGated<F>>().checked_add(std::mem::size_of::<F>())
    else {
      return Err(CpuWrapError {
        kind: DomainError::Invalid,
        future,
      });
    };
    let control = match ControlCharge::try_new(Some(&self.inner.tenant), control_bytes) {
      Ok(control) => control,
      Err(kind) => return Err(CpuWrapError { kind, future }),
    };
    let waiter = match self.inner.waiters.try_lease() {
      Ok(waiter) => waiter,
      Err(kind) => return Err(CpuWrapError { kind, future }),
    };
    Ok(CpuGated {
      gate: Arc::clone(&self.inner),
      future: Some(Box::pin(future)),
      waiter: Some(waiter),
      completed: false,
      _control: control,
    })
  }

  /// Runs `function` only while holding one CPU ticket from this gate's
  /// global and tenant domain.
  ///
  /// If CPU is temporarily unavailable, this method parks the calling thread
  /// on a generation-checked waiter until a ticket becomes available. Calls
  /// made while the current stack already holds a CPU ticket from this domain
  /// fail fast with [`DomainError::Exhausted`] instead of waiting on work that
  /// may require that ticket. The ticket covers the whole closure call, so
  /// use this for synchronous work intended to consume CPU. Admission has no
  /// timeout or cancellation while the caller is parked; use
  /// [`CpuGate::try_run`] when the caller must not wait.
  ///
  /// The ticket is released when `function` returns or unwinds. This method
  /// does not provide cancellation for an already-running closure.
  ///
  /// # Errors
  ///
  /// Returns the unchanged closure when Control admission, waiter leasing or
  /// CPU admission fails before the closure starts.
  pub fn run<F, R>(&self, function: F) -> Result<R, CpuRunError<F>>
  where
    F: FnOnce() -> R,
  {
    self.run_inner(function, true)
  }

  /// Attempts to run `function` without parking for CPU admission.
  ///
  /// On refusal this returns the original closure in [`CpuRunError`].
  pub fn try_run<F, R>(&self, function: F) -> Result<R, CpuRunError<F>>
  where
    F: FnOnce() -> R,
  {
    self.run_inner(function, false)
  }

  fn run_inner<F, R>(&self, function: F, wait_for_cpu: bool) -> Result<R, CpuRunError<F>>
  where
    F: FnOnce() -> R,
  {
    let control =
      match ControlCharge::try_new(Some(&self.inner.tenant), std::mem::size_of::<RunState<F>>()) {
        Ok(control) => control,
        Err(kind) => return Err(CpuRunError { kind, function }),
      };
    let waiter = match self.inner.waiters.try_lease() {
      Ok(waiter) => waiter,
      Err(kind) => return Err(CpuRunError { kind, function }),
    };
    let mut state = RunState {
      gate: Arc::clone(&self.inner),
      waiter,
      function: Some(function),
      _control: control,
    };
    let wake_control =
      match ControlCharge::try_new(Some(&state.gate.tenant), std::mem::size_of::<ThreadWake>()) {
        Ok(control) => control,
        Err(kind) => return Err(state.reject(kind)),
      };
    let wake = Arc::new(ThreadWake {
      thread: thread::current(),
      _control: wake_control,
    });
    let waker = Waker::from(wake);

    loop {
      // Capture the actual caller state before the temporary guard. The guard
      // below covers DomainWaiter waker clone/drop callbacks while admission
      // may already have committed a CPU ticket; without it, a last-waker Drop
      // can reenter this gate and park behind the ticket this call just took.
      let identity = state.gate.tenant.domain_identity();
      let already_active = active_for_domain(&identity);
      let admission_execution = CpuExecutionGuard::enter(Some(identity));
      let acquired = state
        .waiter
        .try_acquire_or_register(&state.gate.tenant, &waker);
      match acquired {
        Ok(Some(ticket)) => {
          drop(admission_execution);
          let function = state.take_function();
          let output = {
            let _execution = CpuExecutionGuard::enter(Some(identity));
            function()
          };
          drop(ticket);
          return Ok(output);
        }
        Ok(None) => {
          drop(admission_execution);
          if already_active || !wait_for_cpu {
            state.waiter.cancel_wait();
            return Err(state.reject(DomainError::Exhausted(DomainResource::Cpu)));
          }
          thread::park();
        }
        Err(kind) => {
          drop(admission_execution);
          state.waiter.cancel_wait();
          return Err(state.reject(kind));
        }
      }
    }
  }
}

struct RunState<F> {
  gate: Arc<CpuGateInner>,
  waiter: DomainWaiter,
  function: Option<F>,
  _control: ControlCharge,
}

impl<F> RunState<F> {
  fn take_function(&mut self) -> F {
    match self.function.take() {
      Some(function) => function,
      None => unreachable!("CPU gate consumed a blocking closure twice"),
    }
  }

  fn reject(&mut self, kind: DomainError) -> CpuRunError<F> {
    CpuRunError {
      kind,
      function: self.take_function(),
    }
  }
}

struct ThreadWake {
  thread: Thread,
  _control: ControlCharge,
}

impl Wake for ThreadWake {
  fn wake(self: Arc<Self>) {
    self.thread.unpark();
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.thread.unpark();
  }
}

/// A future that acquires CPU admission separately for every inner poll.
pub struct CpuGated<F: Future> {
  future: Option<Pin<Box<F>>>,
  waiter: Option<DomainWaiter>,
  gate: Arc<CpuGateInner>,
  completed: bool,
  _control: ControlCharge,
}

impl<F: Future> CpuGated<F> {
  fn finish(&mut self) {
    self.completed = true;
    let waiter = self.waiter.take();
    let future = self.future.take();
    drop(waiter);
    drop(future);
    // The boxed future payload has now been freed. Shrink to the retained
    // wrapper size; if a domain invariant ever refuses this shrink, retaining
    // the larger charge remains conservative until the wrapper is dropped.
    let _ = self._control.try_resize(std::mem::size_of::<Self>());
  }
}

impl<F: Future> Future for CpuGated<F> {
  type Output = Result<F::Output, DomainError>;

  fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.completed {
      panic!("CpuGated polled after completion");
    }
    let Some(waiter) = this.waiter.as_ref() else {
      unreachable!("incomplete CPU gate future has no waiter lease");
    };
    // try_acquire_or_register may commit the CPU ticket, then drop the prior
    // stored Waker outside the domain lock before returning it. Keep this
    // same-domain identity visible to any reentrant Waker destructor, but
    // remember the caller's prior state so a true unavailable poll remains
    // Pending rather than mistaking this temporary guard for a held ticket.
    let identity = this.gate.tenant.domain_identity();
    let already_active = active_for_domain(&identity);
    let admission_execution = CpuExecutionGuard::enter(Some(identity));
    let acquired = waiter.try_acquire_or_register(&this.gate.tenant, context.waker());
    match acquired {
      Ok(None) => {
        drop(admission_execution);
        if already_active {
          waiter.cancel_wait();
          this.finish();
          Poll::Ready(Err(DomainError::Exhausted(DomainResource::Cpu)))
        } else {
          Poll::Pending
        }
      }
      Err(kind) => {
        drop(admission_execution);
        waiter.cancel_wait();
        this.finish();
        Poll::Ready(Err(kind))
      }
      Ok(Some(ticket)) => {
        drop(admission_execution);
        let Some(future) = this.future.as_mut() else {
          unreachable!("incomplete CPU gate future has no inner future");
        };
        let result = {
          let _execution = CpuExecutionGuard::enter(Some(identity));
          future.as_mut().poll(context)
        };
        drop(ticket);
        match result {
          Poll::Pending => Poll::Pending,
          Poll::Ready(output) => {
            this.finish();
            Poll::Ready(Ok(output))
          }
        }
      }
    }
  }
}

impl<F: Future> Drop for CpuGated<F> {
  fn drop(&mut self) {
    let waiter = self.waiter.take();
    drop(waiter);
    // The waiter is removed before the inner future's destructor can run.
  }
}

/// A failed initial future admission, retaining the unchanged future.
#[must_use = "recover the future or handle the CPU gate admission error"]
pub struct CpuWrapError<F> {
  /// The reason the wrapper could not reserve Control or a waiter slot.
  pub kind: DomainError,
  future: F,
}

impl<F> CpuWrapError<F> {
  /// Returns the original future without polling or dropping it.
  #[must_use]
  pub fn into_future(self) -> F {
    self.future
  }
}

impl<F> fmt::Debug for CpuWrapError<F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("CpuWrapError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl<F> fmt::Display for CpuWrapError<F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "CPU gate future admission refused: {}", self.kind)
  }
}

impl<F: 'static> std::error::Error for CpuWrapError<F> {}

/// A failed blocking admission, retaining the closure that was not run.
#[must_use = "recover the closure or handle the CPU gate admission error"]
pub struct CpuRunError<F> {
  /// The reason the closure could not reserve Control, a waiter slot or CPU.
  pub kind: DomainError,
  function: F,
}

impl<F> CpuRunError<F> {
  /// Returns the original closure without running it.
  #[must_use]
  pub fn into_function(self) -> F {
    self.function
  }
}

impl<F> fmt::Debug for CpuRunError<F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("CpuRunError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl<F> fmt::Display for CpuRunError<F> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "CPU gate closure admission refused: {}", self.kind)
  }
}

impl<F: 'static> std::error::Error for CpuRunError<F> {}

#[cfg(all(test, not(loom)))]
#[path = "cpu_gate_tests.rs"]
mod tests;
