//! Bounded helpers for composing a homogeneous list of futures.
//!
//! [`join_all`] waits for every input, [`try_join_all`] returns on the first
//! error, and [`select_many`] returns the first ready enabled branch. Every
//! input shares one future type, so these helpers extend the two-branch
//! helpers in [`concurrency`](super::concurrency) to `N` branches of the same
//! type. They are not replicas of Tokio's `join!`, `try_join!` or `select!`
//! macros: heterogeneous branch lists, patterns and `else` arms are out of
//! scope.
//!
//! # Bounds and allocation
//!
//! Each helper takes a `max_branches` limit, which must be nonzero and at
//! most [`MAX_BRANCHES`], and rejects more inputs than that limit. Before
//! consuming the caller's `Vec`, a helper reserves all of its bookkeeping
//! with `Vec::try_reserve_exact`: [`join_all`] and [`try_join_all`] reserve
//! one slot per input, holding a boxed future or its stored output, plus the
//! output `Vec` they return; [`select_many`] reserves one entry per enabled
//! branch and one per disabled branch. Every rejection, including a failed
//! reservation, returns the original `Vec` unchanged in a [`StartError`]; no
//! input is moved, polled, cloned or dropped.
//!
//! After reservation succeeds, each joined input and each enabled branch is
//! moved into its own `Pin<Box<_>>` (a zero-sized future needs no
//! allocation). The boxes support borrowed, `!Send` and `!Unpin` futures
//! without `'static` or `Send` bounds, and keep each future at one address
//! while the helper itself is `Unpin` and may move. The boxes use the
//! standard infallible allocation path: running out of memory there goes to
//! the global allocation-error handler, which aborts the process by default,
//! and is not reported as a [`StartError`]. Completing a join moves outputs
//! into the reserved `Vec` without allocating.
//!
//! # Polling, cleanup and panics
//!
//! A poll polls each active input at most once: joins in input order, and
//! selections in the order chosen by [`SelectionPolicy`]. A completed input
//! is never polled again, and polling a helper after it completed panics.
//! The helpers never wake their own task: an input that returns `Pending` is
//! responsible for its wake-up, and an empty join completes on its first
//! poll without waking. No locks are taken; inputs are polled and dropped
//! only by the caller polling or dropping the helper.
//!
//! A helper drops a completed future before storing or returning its output,
//! and drops losing futures, disabled futures and unused partial outputs
//! before publishing a result or error. If polling panics, that panic is
//! resumed after cleanup and panics from cleanup are contained. If cleanup
//! is the first operation to panic while completing normally, its first
//! panic is resumed after the remaining values are disposed. Dropping a
//! helper before it completes cancels every owned future and drops stored
//! outputs, then resumes the first destructor panic unless the thread is
//! already panicking. Side effects the futures performed before cancellation
//! are not rolled back.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::any::Any;
use std::convert::{Infallible, identity};
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::mem;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::task::{Context, Poll};

use super::task::drop_contained;

type PanicPayload = Box<dyn Any + Send + 'static>;

/// The largest `max_branches` any helper in this module accepts.
pub const MAX_BRANCHES: usize = 1024;

/// Why a helper rejected its inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StartErrorKind {
  /// `max_branches` is zero.
  ZeroLimit,
  /// `max_branches` exceeds [`MAX_BRANCHES`].
  LimitTooLarge,
  /// More inputs were passed than `max_branches` allows.
  TooManyBranches,
  /// A selection was empty or had every branch disabled.
  NoEnabledBranch,
  /// The helper's bookkeeping could not be reserved.
  AllocationFailed,
}

impl fmt::Display for StartErrorKind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::ZeroLimit => "branch limit is zero",
      Self::LimitTooLarge => "branch limit exceeds the fixed ceiling",
      Self::TooManyBranches => "more branches than the branch limit",
      Self::NoEnabledBranch => "selection has no enabled branch",
      Self::AllocationFailed => "branch bookkeeping could not be reserved",
    })
  }
}

impl std::error::Error for StartErrorKind {}

/// A rejected helper start. Owns the original inputs, unchanged and in
/// their original order: none was moved out, polled or dropped.
pub struct StartError<I> {
  /// Why the helper was not started.
  pub kind: StartErrorKind,
  /// The inputs passed to the helper.
  pub inputs: I,
}

impl<I> StartError<I> {
  /// Why the helper was not started.
  #[must_use]
  pub const fn kind(&self) -> StartErrorKind {
    self.kind
  }

  /// The inputs passed to the helper.
  #[must_use]
  pub fn into_inputs(self) -> I {
    self.inputs
  }
}

impl<I> fmt::Debug for StartError<I> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("StartError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl<I> fmt::Display for StartError<I> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "helper not started: {}", self.kind)
  }
}

impl<I> std::error::Error for StartError<I> {}

/// Creates a future that polls every input until each completes.
///
/// Outputs are returned in input order. An empty `inputs` is accepted and
/// completes with an empty `Vec` on its first poll. Each active input is
/// polled at most once per call to `poll`, in input order, and a completed
/// input is never polled again. Every input is owned once this function
/// returns `Ok`; dropping the returned future cancels all of them.
///
/// # Errors
///
/// Returns `inputs` unchanged if `max_branches` is zero or above
/// [`MAX_BRANCHES`], if `inputs` is longer than `max_branches`, or if the
/// bookkeeping cannot be reserved.
pub fn join_all<F: Future>(
  inputs: Vec<F>,
  max_branches: usize,
) -> Result<JoinAll<F>, StartError<Vec<F>>> {
  Branches::start(inputs, max_branches).map(|branches| JoinAll { branches })
}

/// Future returned by [`join_all`].
pub struct JoinAll<F: Future> {
  branches: Branches<F, F::Output>,
}

// The input futures stay pinned in their boxes. The other fields are not
// structurally pinned, so moving this outer bookkeeping value is safe.
impl<F: Future> Unpin for JoinAll<F> {}

impl<F: Future> Future for JoinAll<F> {
  type Output = Vec<F::Output>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    this
      .branches
      .poll_with(cx, "JoinAll", Ok::<F::Output, Infallible>)
      .map(|outcome| {
        let Ok(outputs) = outcome;
        outputs
      })
  }
}

/// Creates a future that joins `Result`-producing futures and fails fast.
///
/// Successful outputs are returned in input order. On the first observed
/// error it drops every other future and every stored successful output
/// before returning that error. Polling, ownership, limits and rejection
/// follow [`join_all`].
///
/// # Errors
///
/// Returns `inputs` unchanged under the same conditions as [`join_all`].
pub fn try_join_all<F, T, E>(
  inputs: Vec<F>,
  max_branches: usize,
) -> Result<TryJoinAll<F, T, E>, StartError<Vec<F>>>
where
  F: Future<Output = Result<T, E>>,
{
  Branches::start(inputs, max_branches).map(|branches| TryJoinAll {
    branches,
    error: PhantomData,
  })
}

/// Future returned by [`try_join_all`].
pub struct TryJoinAll<F, T, E>
where
  F: Future<Output = Result<T, E>>,
{
  branches: Branches<F, T>,
  error: PhantomData<fn(E)>,
}

impl<F, T, E> Unpin for TryJoinAll<F, T, E> where F: Future<Output = Result<T, E>> {}

impl<F, T, E> Future for TryJoinAll<F, T, E>
where
  F: Future<Output = Result<T, E>>,
{
  type Output = Result<Vec<T>, E>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    this.branches.poll_with(cx, "TryJoinAll", identity)
  }
}

/// One join input: running in its box, completed with its stored output, or
/// already disposed.
enum Slot<F, T> {
  Running(Pin<Box<F>>),
  Done(T),
  Empty,
}

/// Why a join poll stopped before visiting every active input.
enum Interrupt<E> {
  Panicked(PanicPayload),
  Failed(E),
}

/// Bookkeeping shared by [`JoinAll`] and [`TryJoinAll`].
struct Branches<F, T> {
  slots: Vec<Slot<F, T>>,
  outputs: Vec<T>,
  remaining: usize,
  done: bool,
}

impl<F, T> Branches<F, T> {
  fn start(inputs: Vec<F>, max_branches: usize) -> Result<Self, StartError<Vec<F>>> {
    if let Err(kind) = check_limit(inputs.len(), max_branches) {
      return Err(StartError { kind, inputs });
    }
    let mut slots: Vec<Slot<F, T>> = Vec::new();
    let mut outputs: Vec<T> = Vec::new();
    if slots.try_reserve_exact(inputs.len()).is_err()
      || outputs.try_reserve_exact(inputs.len()).is_err()
    {
      return Err(StartError {
        kind: StartErrorKind::AllocationFailed,
        inputs,
      });
    }
    let mut branches = Self {
      slots,
      outputs,
      remaining: 0,
      done: false,
    };
    // The slots are reserved; only boxing a nonzero-sized future allocates.
    branches.slots.extend(
      inputs
        .into_iter()
        .map(|future| Slot::Running(Box::pin(future))),
    );
    branches.remaining = branches.slots.len();
    Ok(branches)
  }

  /// Moves every stored output into the reserved output `Vec`.
  fn publish(&mut self) -> Vec<T> {
    let mut outputs = mem::take(&mut self.outputs);
    for slot in &mut self.slots {
      if let Slot::Done(output) = mem::replace(slot, Slot::Empty) {
        outputs.push(output);
      }
    }
    outputs
  }

  fn abort_with_primary(&mut self, primary: PanicPayload) -> ! {
    drop_contained(self.cleanup_capturing());
    self.done = true;
    panic::resume_unwind(primary)
  }

  /// Drops running futures first, then stored outputs, in input order.
  fn cleanup_capturing(&mut self) -> Option<PanicPayload> {
    let mut primary = None;
    for slot in &mut self.slots {
      if matches!(slot, Slot::Running(_)) {
        record_panic(
          &mut primary,
          drop_capturing(mem::replace(slot, Slot::Empty)),
        );
      }
    }
    for slot in &mut self.slots {
      record_panic(
        &mut primary,
        drop_capturing(mem::replace(slot, Slot::Empty)),
      );
    }
    primary
  }
}

impl<F: Future, T> Branches<F, T> {
  fn poll_with<E>(
    &mut self,
    cx: &mut Context<'_>,
    name: &str,
    split: fn(F::Output) -> Result<T, E>,
  ) -> Poll<Result<Vec<T>, E>> {
    assert!(!self.done, "{name} polled after completion");
    match self.poll_active(cx, split) {
      Ok(()) if self.remaining == 0 => {
        self.done = true;
        Poll::Ready(Ok(self.publish()))
      }
      Ok(()) => Poll::Pending,
      Err(Interrupt::Panicked(payload)) => self.abort_with_primary(payload),
      Err(Interrupt::Failed(error)) => {
        self.done = true;
        if let Some(payload) = self.cleanup_capturing() {
          drop_contained(error);
          panic::resume_unwind(payload);
        }
        Poll::Ready(Err(error))
      }
    }
  }

  fn poll_active<E>(
    &mut self,
    cx: &mut Context<'_>,
    split: fn(F::Output) -> Result<T, E>,
  ) -> Result<(), Interrupt<E>> {
    for slot in &mut self.slots {
      let Slot::Running(future) = slot else {
        continue;
      };
      let output = match poll_boxed(future, cx) {
        Ok(Poll::Pending) => continue,
        Ok(Poll::Ready(output)) => output,
        Err(payload) => return Err(Interrupt::Panicked(payload)),
      };
      if let Some(payload) = drop_capturing(mem::replace(slot, Slot::Empty)) {
        drop_contained(output);
        return Err(Interrupt::Panicked(payload));
      }
      match split(output) {
        Ok(output) => {
          *slot = Slot::Done(output);
          self.remaining -= 1;
        }
        Err(error) => return Err(Interrupt::Failed(error)),
      }
    }
    Ok(())
  }
}

impl<F, T> Drop for Branches<F, T> {
  fn drop(&mut self) {
    propagate_drop_panic(self.cleanup_capturing());
  }
}

/// One [`select_many`] input.
#[derive(Debug)]
pub struct Branch<F> {
  /// Whether the branch may be polled. A disabled branch's future is owned
  /// by the selection and dropped with it, but never polled.
  pub enabled: bool,
  /// The branch's future, already constructed by the caller.
  pub future: F,
}

impl<F> Branch<F> {
  /// Creates a branch from an evaluated future.
  pub const fn new(enabled: bool, future: F) -> Self {
    Self { enabled, future }
  }
}

/// Poll-order policy for [`select_many`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionPolicy {
  /// Start every poll at the first enabled branch.
  Biased,
  /// Start each poll one enabled branch later than the previous poll when
  /// that poll returned `Pending`, wrapping around.
  RoundRobin,
}

/// Creates a future that returns the first ready enabled branch and cancels
/// the rest.
///
/// Every branch's future is constructed by the caller and owned by the
/// returned helper, enabled or not. Enabled branches are polled at most
/// once per call to `poll`, in the order chosen by `policy`; disabled
/// branches are never polled. `RoundRobin` uses no random source. The first
/// enabled branch to return `Ready` wins; the result is its original index
/// in `branches` and its output. The winning future, every losing future and
/// every disabled future are dropped before that result is returned.
///
/// # Errors
///
/// Returns `branches` unchanged if `max_branches` is zero or above
/// [`MAX_BRANCHES`], if `branches` is longer than `max_branches`, if no
/// branch is enabled (including an empty `branches`), or if the bookkeeping
/// cannot be reserved.
pub fn select_many<F: Future>(
  branches: Vec<Branch<F>>,
  max_branches: usize,
  policy: SelectionPolicy,
) -> Result<SelectMany<F>, StartError<Vec<Branch<F>>>> {
  if let Err(kind) = check_limit(branches.len(), max_branches) {
    return Err(StartError {
      kind,
      inputs: branches,
    });
  }
  let enabled = branches.iter().filter(|branch| branch.enabled).count();
  if enabled == 0 {
    return Err(StartError {
      kind: StartErrorKind::NoEnabledBranch,
      inputs: branches,
    });
  }
  let mut active: Vec<Option<Active<F>>> = Vec::new();
  let mut disabled: Vec<Option<F>> = Vec::new();
  if active.try_reserve_exact(enabled).is_err()
    || disabled
      .try_reserve_exact(branches.len() - enabled)
      .is_err()
  {
    return Err(StartError {
      kind: StartErrorKind::AllocationFailed,
      inputs: branches,
    });
  }
  let mut selection = SelectMany {
    active,
    disabled,
    policy,
    next_start: 0,
    done: false,
  };
  // The entries are reserved; only boxing a nonzero-sized future allocates.
  for (index, branch) in branches.into_iter().enumerate() {
    if branch.enabled {
      selection.active.push(Some(Active {
        index,
        future: Box::pin(branch.future),
      }));
    } else {
      selection.disabled.push(Some(branch.future));
    }
  }
  Ok(selection)
}

/// An enabled branch and its index in the caller's `Vec`.
struct Active<F> {
  index: usize,
  future: Pin<Box<F>>,
}

/// Future returned by [`select_many`].
pub struct SelectMany<F: Future> {
  active: Vec<Option<Active<F>>>,
  disabled: Vec<Option<F>>,
  policy: SelectionPolicy,
  next_start: usize,
  done: bool,
}

// Enabled futures stay pinned in their boxes, and disabled futures are never
// pinned or polled, so moving this outer bookkeeping value is safe.
impl<F: Future> Unpin for SelectMany<F> {}

impl<F: Future> Future for SelectMany<F> {
  type Output = (usize, F::Output);

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    assert!(!this.done, "SelectMany polled after completion");
    let start = match this.policy {
      SelectionPolicy::Biased => 0,
      SelectionPolicy::RoundRobin => this.next_start,
    };
    match poll_from(&mut this.active, start, cx) {
      Some(Ok((winner, output))) => this.finish(winner, output),
      Some(Err(payload)) => this.abort_with_primary(payload),
      None => {
        if this.policy == SelectionPolicy::RoundRobin {
          this.next_start = (start + 1) % this.active.len();
        }
        Poll::Pending
      }
    }
  }
}

impl<F: Future> SelectMany<F> {
  fn finish(&mut self, winner: Active<F>, output: F::Output) -> Poll<(usize, F::Output)> {
    let Active { index, future } = winner;
    let mut primary = drop_capturing(future);
    self.dispose_capturing(&mut primary);
    self.done = true;
    if let Some(payload) = primary {
      drop_contained(output);
      panic::resume_unwind(payload);
    }
    Poll::Ready((index, output))
  }

  fn abort_with_primary(&mut self, primary: PanicPayload) -> ! {
    drop_contained(self.cleanup_capturing());
    self.done = true;
    panic::resume_unwind(primary)
  }

  fn cleanup_capturing(&mut self) -> Option<PanicPayload> {
    let mut primary = None;
    self.dispose_capturing(&mut primary);
    primary
  }

  /// Drops enabled futures first, then disabled futures, in input order.
  fn dispose_capturing(&mut self, primary: &mut Option<PanicPayload>) {
    for slot in &mut self.active {
      record_panic(primary, slot.take().and_then(drop_capturing));
    }
    for slot in &mut self.disabled {
      record_panic(primary, slot.take().and_then(drop_capturing));
    }
  }
}

impl<F: Future> Drop for SelectMany<F> {
  fn drop(&mut self) {
    propagate_drop_panic(self.cleanup_capturing());
  }
}

type Selected<F> = Result<(Active<F>, <F as Future>::Output), PanicPayload>;

/// Polls each enabled branch once, beginning at `start` and wrapping around,
/// until one is ready or panics. A ready branch is removed from its entry.
fn poll_from<F: Future>(
  active: &mut [Option<Active<F>>],
  start: usize,
  cx: &mut Context<'_>,
) -> Option<Selected<F>> {
  let (before, from_start) = active.split_at_mut(start);
  for slot in from_start.iter_mut().chain(before) {
    let Some(mut entry) = slot.take() else {
      continue;
    };
    match poll_boxed(&mut entry.future, cx) {
      Ok(Poll::Pending) => *slot = Some(entry),
      Ok(Poll::Ready(output)) => return Some(Ok((entry, output))),
      Err(payload) => {
        *slot = Some(entry);
        return Some(Err(payload));
      }
    }
  }
  None
}

fn check_limit(len: usize, max_branches: usize) -> Result<(), StartErrorKind> {
  if max_branches == 0 {
    Err(StartErrorKind::ZeroLimit)
  } else if max_branches > MAX_BRANCHES {
    Err(StartErrorKind::LimitTooLarge)
  } else if len > max_branches {
    Err(StartErrorKind::TooManyBranches)
  } else {
    Ok(())
  }
}

fn poll_boxed<F: Future>(
  future: &mut Pin<Box<F>>,
  cx: &mut Context<'_>,
) -> Result<Poll<F::Output>, PanicPayload> {
  panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx)))
}

fn drop_capturing<V>(value: V) -> Option<PanicPayload> {
  panic::catch_unwind(AssertUnwindSafe(move || drop(value))).err()
}

/// Keeps the first panic and contains later ones.
fn record_panic(primary: &mut Option<PanicPayload>, payload: Option<PanicPayload>) {
  if let Some(payload) = payload {
    if primary.is_some() {
      drop_contained(payload);
    } else {
      *primary = Some(payload);
    }
  }
}

fn propagate_drop_panic(primary: Option<PanicPayload>) {
  if let Some(payload) = primary {
    if std::thread::panicking() {
      drop_contained(payload);
    } else {
      panic::resume_unwind(payload);
    }
  }
}

#[cfg(test)]
mod tests {
  use std::cell::{Cell, RefCell};
  use std::future::Future;
  use std::marker::PhantomPinned;
  use std::panic::{self, AssertUnwindSafe};
  use std::pin::Pin;
  use std::rc::Rc;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::{Context, Poll, Wake, Waker};

  use super::{
    Branch, MAX_BRANCHES, SelectionPolicy, StartError, StartErrorKind, join_all, select_many,
    try_join_all,
  };

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  enum Event {
    Polled(usize),
    Dropped(usize),
    OutputDropped(usize),
  }

  use Event::{Dropped, OutputDropped, Polled};

  type Log = Rc<RefCell<Vec<Event>>>;

  fn new_log() -> Log {
    Rc::new(RefCell::new(Vec::new()))
  }

  fn take_events(log: &Log) -> Vec<Event> {
    std::mem::take(&mut *log.borrow_mut())
  }

  /// A scripted `!Send`, `!Unpin` future that returns `Pending` a fixed
  /// number of times, then its output once; any later poll panics.
  struct Probe<T> {
    id: usize,
    pending: Cell<usize>,
    output: Cell<Option<T>>,
    poll_panic: Option<&'static str>,
    drop_panic: Option<&'static str>,
    log: Log,
    _pinned: PhantomPinned,
  }

  impl<T> Probe<T> {
    fn ready_after(log: &Log, id: usize, pending: usize, output: T) -> Self {
      Self {
        id,
        pending: Cell::new(pending),
        output: Cell::new(Some(output)),
        poll_panic: None,
        drop_panic: None,
        log: Rc::clone(log),
        _pinned: PhantomPinned,
      }
    }

    fn never(log: &Log, id: usize) -> Self {
      Self {
        id,
        pending: Cell::new(usize::MAX),
        output: Cell::new(None),
        poll_panic: None,
        drop_panic: None,
        log: Rc::clone(log),
        _pinned: PhantomPinned,
      }
    }

    fn panicking_poll(mut self, message: &'static str) -> Self {
      self.poll_panic = Some(message);
      self
    }

    fn panicking_drop(mut self, message: &'static str) -> Self {
      self.drop_panic = Some(message);
      self
    }
  }

  impl<T> Future for Probe<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<T> {
      let this = self.into_ref().get_ref();
      this.log.borrow_mut().push(Polled(this.id));
      if let Some(message) = this.poll_panic {
        panic::panic_any(message);
      }
      match this.pending.get() {
        0 => match this.output.take() {
          Some(output) => Poll::Ready(output),
          None => panic!("completed probe was polled again"),
        },
        pending => {
          this.pending.set(pending - 1);
          Poll::Pending
        }
      }
    }
  }

  impl<T> Drop for Probe<T> {
    fn drop(&mut self) {
      self.log.borrow_mut().push(Dropped(self.id));
      if let Some(message) = self.drop_panic {
        panic::panic_any(message);
      }
    }
  }

  /// An output that records when it is dropped.
  struct Output {
    id: usize,
    log: Log,
  }

  impl Output {
    fn new(log: &Log, id: usize) -> Self {
      Self {
        id,
        log: Rc::clone(log),
      }
    }
  }

  impl Drop for Output {
    fn drop(&mut self) {
      self.log.borrow_mut().push(OutputDropped(self.id));
    }
  }

  struct CountWakes(AtomicUsize);

  impl Wake for CountWakes {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  fn poll_with<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(waker))
  }

  fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    poll_with(future, Waker::noop())
  }

  fn panic_message<R>(operation: impl FnOnce() -> R) -> String {
    match panic::catch_unwind(AssertUnwindSafe(operation)) {
      Ok(_) => panic!("operation did not panic"),
      Err(payload) => match payload.downcast::<&'static str>() {
        Ok(message) => (*message).to_owned(),
        Err(payload) => *payload
          .downcast::<String>()
          .expect("panic payload is a string"),
      },
    }
  }

  fn rejected<T, I>(result: Result<T, StartError<I>>) -> StartError<I> {
    match result {
      Ok(_) => panic!("helper started unexpectedly"),
      Err(error) => error,
    }
  }

  fn nevers<T>(log: &Log, count: usize) -> Vec<Probe<T>> {
    (0..count).map(|id| Probe::never(log, id)).collect()
  }

  fn ids<T>(inputs: &[Probe<T>]) -> Vec<usize> {
    inputs.iter().map(|probe| probe.id).collect()
  }

  #[test]
  fn empty_joins_complete_on_first_poll_without_waking() {
    let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wakes));
    let mut joined = join_all(Vec::<Probe<u8>>::new(), 1).expect("empty join starts");
    assert_eq!(poll_with(&mut joined, &waker), Poll::Ready(Vec::new()));
    let mut tried =
      try_join_all(Vec::<Probe<Result<u8, ()>>>::new(), 1).expect("empty try_join starts");
    assert_eq!(poll_with(&mut tried, &waker), Poll::Ready(Ok(Vec::new())));
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
  }

  #[test]
  fn join_preserves_input_order_and_polls_each_active_input_once_per_poll() {
    let log = new_log();
    let inputs = vec![
      Probe::ready_after(&log, 0, 2, 10_u32),
      Probe::ready_after(&log, 1, 0, 11),
      Probe::ready_after(&log, 2, 1, 12),
    ];
    let mut joined = join_all(inputs, 3).expect("within limit");
    assert!(take_events(&log).is_empty());
    assert!(poll_once(&mut joined).is_pending());
    assert_eq!(
      take_events(&log),
      [Polled(0), Polled(1), Dropped(1), Polled(2)]
    );
    assert!(poll_once(&mut joined).is_pending());
    assert_eq!(take_events(&log), [Polled(0), Polled(2), Dropped(2)]);
    assert_eq!(poll_once(&mut joined), Poll::Ready(vec![10, 11, 12]));
    assert_eq!(take_events(&log), [Polled(0), Dropped(0)]);
  }

  #[test]
  fn try_join_returns_successes_in_input_order() {
    let log = new_log();
    let inputs = vec![
      Probe::ready_after(&log, 0, 1, Ok::<u8, &str>(1)),
      Probe::ready_after(&log, 1, 0, Ok(2)),
    ];
    let mut tried = try_join_all(inputs, 2).expect("within limit");
    assert!(poll_once(&mut tried).is_pending());
    assert_eq!(poll_once(&mut tried), Poll::Ready(Ok(vec![1, 2])));
    assert_eq!(
      take_events(&log),
      [Polled(0), Polled(1), Dropped(1), Polled(0), Dropped(0)]
    );
  }

  #[test]
  fn try_join_first_error_drops_pending_futures_and_stored_outputs_before_returning() {
    let log = new_log();
    let inputs = vec![
      Probe::ready_after(&log, 0, 0, Ok(Output::new(&log, 0))),
      Probe::never(&log, 1),
      Probe::ready_after(&log, 2, 1, Err("failed")),
      Probe::never(&log, 3),
    ];
    let mut tried = try_join_all(inputs, 4).expect("within limit");
    assert!(poll_once(&mut tried).is_pending());
    assert_eq!(
      take_events(&log),
      [Polled(0), Dropped(0), Polled(1), Polled(2), Polled(3)]
    );
    assert!(matches!(poll_once(&mut tried), Poll::Ready(Err("failed"))));
    assert_eq!(
      take_events(&log),
      [
        Polled(1),
        Polled(2),
        Dropped(2),
        Dropped(1),
        Dropped(3),
        OutputDropped(0)
      ]
    );
    drop(tried);
    assert!(take_events(&log).is_empty());
  }

  #[test]
  fn biased_selection_starts_every_poll_at_the_first_enabled_branch() {
    let log = new_log();
    let branches = vec![
      Branch::new(true, Probe::ready_after(&log, 0, 1, 'a')),
      Branch::new(true, Probe::ready_after(&log, 1, 1, 'b')),
      Branch::new(true, Probe::never(&log, 2)),
    ];
    let mut selected = select_many(branches, 3, SelectionPolicy::Biased).expect("enabled");
    assert!(poll_once(&mut selected).is_pending());
    assert_eq!(poll_once(&mut selected), Poll::Ready((0, 'a')));
    assert_eq!(
      take_events(&log),
      [
        Polled(0),
        Polled(1),
        Polled(2),
        Polled(0),
        Dropped(0),
        Dropped(1),
        Dropped(2)
      ]
    );
  }

  #[test]
  fn round_robin_selection_rotates_the_start_after_pending() {
    let log = new_log();
    let branches = vec![
      Branch::new(true, Probe::ready_after(&log, 0, 1, 'a')),
      Branch::new(true, Probe::ready_after(&log, 1, 1, 'b')),
      Branch::new(true, Probe::never(&log, 2)),
    ];
    let mut selected = select_many(branches, 3, SelectionPolicy::RoundRobin).expect("enabled");
    assert!(poll_once(&mut selected).is_pending());
    assert_eq!(poll_once(&mut selected), Poll::Ready((1, 'b')));
    assert_eq!(
      take_events(&log),
      [
        Polled(0),
        Polled(1),
        Polled(2),
        Polled(1),
        Dropped(1),
        Dropped(0),
        Dropped(2)
      ]
    );
  }

  #[test]
  fn round_robin_wraps_around_enabled_branches_only() {
    let log = new_log();
    let branches = vec![
      Branch::new(true, Probe::<u8>::never(&log, 0)),
      Branch::new(false, Probe::never(&log, 1)),
      Branch::new(true, Probe::never(&log, 2)),
      Branch::new(true, Probe::never(&log, 3)),
    ];
    let mut selected = select_many(branches, 4, SelectionPolicy::RoundRobin).expect("enabled");
    for expected in [
      [Polled(0), Polled(2), Polled(3)],
      [Polled(2), Polled(3), Polled(0)],
      [Polled(3), Polled(0), Polled(2)],
      [Polled(0), Polled(2), Polled(3)],
    ] {
      assert!(poll_once(&mut selected).is_pending());
      assert_eq!(take_events(&log), expected);
    }
  }

  #[test]
  fn disabled_branch_is_never_polled_and_is_dropped_before_publication() {
    let log = new_log();
    let branches = vec![
      Branch::new(
        false,
        Probe::ready_after(&log, 0, 0, 0_u8).panicking_poll("disabled branch polled"),
      ),
      Branch::new(true, Probe::ready_after(&log, 1, 1, 1)),
      Branch::new(
        false,
        Probe::ready_after(&log, 2, 0, 2).panicking_poll("disabled branch polled"),
      ),
    ];
    let mut selected = select_many(branches, 3, SelectionPolicy::Biased).expect("enabled");
    assert!(poll_once(&mut selected).is_pending());
    assert_eq!(take_events(&log), [Polled(1)]);
    assert_eq!(poll_once(&mut selected), Poll::Ready((1, 1)));
    assert_eq!(
      take_events(&log),
      [Polled(1), Dropped(1), Dropped(0), Dropped(2)]
    );
  }

  #[test]
  fn selection_without_enabled_branches_returns_the_original_inputs() {
    let log = new_log();
    let branches = vec![
      Branch::new(false, Probe::<u8>::never(&log, 0)),
      Branch::new(false, Probe::never(&log, 1)),
    ];
    let address = branches.as_ptr();
    let error = rejected(select_many(branches, 2, SelectionPolicy::RoundRobin));
    assert_eq!(error.kind(), StartErrorKind::NoEnabledBranch);
    assert!(take_events(&log).is_empty());
    let inputs = error.into_inputs();
    assert_eq!(inputs.as_ptr(), address);
    assert_eq!(
      inputs
        .iter()
        .map(|branch| (branch.enabled, branch.future.id))
        .collect::<Vec<_>>(),
      [(false, 0), (false, 1)]
    );
    drop(inputs);
    assert_eq!(take_events(&log), [Dropped(0), Dropped(1)]);

    let empty = rejected(select_many(
      Vec::<Branch<Probe<u8>>>::new(),
      1,
      SelectionPolicy::Biased,
    ));
    assert_eq!(empty.kind, StartErrorKind::NoEnabledBranch);
  }

  #[test]
  fn limit_rejections_return_inputs_without_moving_or_dropping_them() {
    let cases = [
      (0, 0, StartErrorKind::ZeroLimit),
      (1, 0, StartErrorKind::ZeroLimit),
      (1, MAX_BRANCHES + 1, StartErrorKind::LimitTooLarge),
      (3, 2, StartErrorKind::TooManyBranches),
    ];
    let log = new_log();
    for (count, limit, kind) in cases {
      let expected: Vec<usize> = (0..count).collect();

      let inputs = nevers::<u8>(&log, count);
      let address = inputs.as_ptr();
      let error = rejected(join_all(inputs, limit));
      assert_eq!((error.kind, error.inputs.as_ptr()), (kind, address));
      assert_eq!(ids(&error.inputs), expected);
      assert!(take_events(&log).is_empty());
      drop(error);
      assert_eq!(take_events(&log).len(), count);

      let inputs = nevers::<Result<u8, ()>>(&log, count);
      let address = inputs.as_ptr();
      let error = rejected(try_join_all(inputs, limit));
      assert_eq!((error.kind, error.inputs.as_ptr()), (kind, address));
      assert_eq!(ids(&error.inputs), expected);
      assert!(take_events(&log).is_empty());
      drop(error);
      assert_eq!(take_events(&log).len(), count);

      if count == 0 {
        continue;
      }
      let branches: Vec<_> = nevers::<u8>(&log, count)
        .into_iter()
        .map(|future| Branch::new(true, future))
        .collect();
      let address = branches.as_ptr();
      let error = rejected(select_many(branches, limit, SelectionPolicy::Biased));
      assert_eq!((error.kind, error.inputs.as_ptr()), (kind, address));
      assert!(take_events(&log).is_empty());
      drop(error);
      assert_eq!(take_events(&log).len(), count);
    }
  }

  #[test]
  fn helpers_accept_the_fixed_branch_ceiling() {
    let log = new_log();
    let joined = join_all(nevers::<u8>(&log, MAX_BRANCHES), MAX_BRANCHES);
    assert!(joined.is_ok());
    drop(joined);
    assert_eq!(take_events(&log).len(), MAX_BRANCHES);
  }

  #[test]
  fn helpers_keep_borrowed_non_send_pinned_futures_at_stable_addresses() {
    struct Borrowed<'a> {
      id: usize,
      polls: Cell<usize>,
      addresses: &'a RefCell<Vec<(usize, usize)>>,
      _not_send: Rc<()>,
      _pinned: PhantomPinned,
    }

    impl Future for Borrowed<'_> {
      type Output = usize;

      fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<usize> {
        let this = self.into_ref().get_ref();
        let address = std::ptr::from_ref(this).addr();
        this.addresses.borrow_mut().push((this.id, address));
        this.polls.set(this.polls.get() + 1);
        if this.polls.get() < 2 {
          Poll::Pending
        } else {
          Poll::Ready(this.id)
        }
      }
    }

    fn assert_unpin<T: Unpin>(_: &T) {}

    let mut addresses = RefCell::new(Vec::new());
    {
      let make = |id| Borrowed {
        id,
        polls: Cell::new(0),
        addresses: &addresses,
        _not_send: Rc::new(()),
        _pinned: PhantomPinned,
      };

      let mut joined = join_all(vec![make(0), make(1)], 2).expect("within limit");
      assert_unpin(&joined);
      assert!(poll_once(&mut joined).is_pending());
      let mut moved = Box::new(joined);
      assert_eq!(poll_once(&mut *moved), Poll::Ready(vec![0, 1]));

      let branches = vec![Branch::new(true, make(2)), Branch::new(true, make(3))];
      let mut selected = select_many(branches, 2, SelectionPolicy::Biased).expect("enabled");
      assert_unpin(&selected);
      assert!(poll_once(&mut selected).is_pending());
      let mut moved = Box::new(selected);
      assert_eq!(poll_once(&mut *moved), Poll::Ready((0, 2)));
    }

    // Branch 3 lost after one poll; the others pended once and then completed.
    let recorded = addresses.get_mut();
    for (id, polls) in [(0, 2), (1, 2), (2, 2), (3, 1)] {
      let seen: Vec<usize> = recorded
        .iter()
        .filter(|(owner, _)| *owner == id)
        .map(|(_, address)| *address)
        .collect();
      assert_eq!(seen.len(), polls, "branch {id} poll count");
      assert!(seen.windows(2).all(|pair| pair[0] == pair[1]));
    }
    recorded.clear();
  }

  #[test]
  fn join_poll_panic_stays_primary_after_cleanup_panics() {
    let log = new_log();
    let inputs = vec![
      Probe::ready_after(&log, 0, 0, Output::new(&log, 0)),
      Probe::never(&log, 1)
        .panicking_poll("primary poll panic")
        .panicking_drop("panicked future drop panic"),
      Probe::never(&log, 2).panicking_drop("loser drop panic"),
      Probe::never(&log, 3),
    ];
    let mut joined = join_all(inputs, 4).expect("within limit");
    assert_eq!(
      panic_message(|| poll_once(&mut joined)),
      "primary poll panic"
    );
    assert_eq!(
      take_events(&log),
      [
        Polled(0),
        Dropped(0),
        Polled(1),
        Dropped(1),
        Dropped(2),
        Dropped(3),
        OutputDropped(0)
      ]
    );
    assert_eq!(
      panic_message(|| poll_once(&mut joined)),
      "JoinAll polled after completion"
    );
    drop(joined);
    assert!(take_events(&log).is_empty());
  }

  #[test]
  fn selection_poll_panic_stays_primary_after_cleanup_panics() {
    let log = new_log();
    let branches = vec![
      Branch::new(true, Probe::<u8>::never(&log, 0)),
      Branch::new(
        true,
        Probe::never(&log, 1).panicking_poll("primary poll panic"),
      ),
      Branch::new(
        true,
        Probe::never(&log, 2).panicking_drop("loser drop panic"),
      ),
      Branch::new(
        false,
        Probe::never(&log, 3).panicking_drop("disabled drop panic"),
      ),
    ];
    let mut selected = select_many(branches, 4, SelectionPolicy::Biased).expect("enabled");
    assert_eq!(
      panic_message(|| poll_once(&mut selected)),
      "primary poll panic"
    );
    assert_eq!(
      take_events(&log),
      [
        Polled(0),
        Polled(1),
        Dropped(0),
        Dropped(1),
        Dropped(2),
        Dropped(3)
      ]
    );
  }

  #[test]
  fn first_selection_cleanup_panic_resumes_after_everything_is_disposed() {
    let log = new_log();
    let branches = vec![
      Branch::new(true, Probe::ready_after(&log, 0, 0, Output::new(&log, 0))),
      Branch::new(
        true,
        Probe::never(&log, 1).panicking_drop("first cleanup panic"),
      ),
      Branch::new(
        false,
        Probe::never(&log, 2).panicking_drop("second cleanup panic"),
      ),
      Branch::new(true, Probe::never(&log, 3)),
    ];
    let mut selected = select_many(branches, 4, SelectionPolicy::Biased).expect("enabled");
    assert_eq!(
      panic_message(|| poll_once(&mut selected)),
      "first cleanup panic"
    );
    assert_eq!(
      take_events(&log),
      [
        Polled(0),
        Dropped(0),
        Dropped(1),
        Dropped(3),
        Dropped(2),
        OutputDropped(0)
      ]
    );
    assert_eq!(
      panic_message(|| poll_once(&mut selected)),
      "SelectMany polled after completion"
    );
    assert!(take_events(&log).is_empty());
  }

  #[test]
  fn first_try_join_cleanup_panic_resumes_after_everything_is_disposed() {
    let log = new_log();
    let inputs = vec![
      Probe::ready_after(&log, 0, 0, Ok(Output::new(&log, 0))),
      Probe::never(&log, 1).panicking_drop("first cleanup panic"),
      Probe::ready_after(&log, 2, 0, Err("failed")),
      Probe::never(&log, 3).panicking_drop("second cleanup panic"),
    ];
    let mut tried = try_join_all(inputs, 4).expect("within limit");
    assert_eq!(
      panic_message(|| poll_once(&mut tried)),
      "first cleanup panic"
    );
    assert_eq!(
      take_events(&log),
      [
        Polled(0),
        Dropped(0),
        Polled(1),
        Polled(2),
        Dropped(2),
        Dropped(1),
        Dropped(3),
        OutputDropped(0)
      ]
    );
  }

  #[test]
  fn dropping_pending_helpers_cancels_every_owned_future_and_output() {
    let log = new_log();
    let inputs = vec![
      Probe::ready_after(&log, 0, 0, Output::new(&log, 0)),
      Probe::never(&log, 1),
      Probe::never(&log, 2),
    ];
    let mut joined = join_all(inputs, 3).expect("within limit");
    assert!(poll_once(&mut joined).is_pending());
    take_events(&log);
    drop(joined);
    assert_eq!(
      take_events(&log),
      [Dropped(1), Dropped(2), OutputDropped(0)]
    );

    let inputs = vec![
      Probe::ready_after(&log, 0, 0, Ok::<_, ()>(Output::new(&log, 0))),
      Probe::never(&log, 1),
    ];
    let mut tried = try_join_all(inputs, 2).expect("within limit");
    assert!(poll_once(&mut tried).is_pending());
    take_events(&log);
    drop(tried);
    assert_eq!(take_events(&log), [Dropped(1), OutputDropped(0)]);

    let branches = vec![
      Branch::new(true, Probe::<u8>::never(&log, 0)),
      Branch::new(false, Probe::never(&log, 1)),
      Branch::new(true, Probe::never(&log, 2)),
    ];
    let mut selected = select_many(branches, 3, SelectionPolicy::RoundRobin).expect("enabled");
    assert!(poll_once(&mut selected).is_pending());
    take_events(&log);
    drop(selected);
    assert_eq!(take_events(&log), [Dropped(0), Dropped(2), Dropped(1)]);

    drop(join_all(nevers::<u8>(&log, 2), 2));
    assert_eq!(take_events(&log), [Dropped(0), Dropped(1)]);
  }

  #[test]
  fn cancellation_resumes_first_drop_panic_after_disposing_everything() {
    let log = new_log();
    let inputs = vec![
      Probe::never(&log, 0).panicking_drop("first cancellation panic"),
      Probe::never(&log, 1).panicking_drop("second cancellation panic"),
      Probe::ready_after(&log, 2, 0, Output::new(&log, 2)),
    ];
    let mut joined = join_all(inputs, 3).expect("within limit");
    assert!(poll_once(&mut joined).is_pending());
    take_events(&log);
    assert_eq!(panic_message(|| drop(joined)), "first cancellation panic");
    assert_eq!(
      take_events(&log),
      [Dropped(0), Dropped(1), OutputDropped(2)]
    );
  }

  #[test]
  fn cancellation_during_unwind_preserves_the_outer_panic() {
    let log = new_log();
    let message = panic_message(|| {
      let branches = vec![
        Branch::new(true, Probe::<u8>::never(&log, 0).panicking_drop("cleanup")),
        Branch::new(false, Probe::never(&log, 1).panicking_drop("cleanup")),
      ];
      let _owned = select_many(branches, 2, SelectionPolicy::Biased).expect("enabled");
      panic::panic_any("outer panic");
    });
    assert_eq!(message, "outer panic");
    assert_eq!(take_events(&log), [Dropped(0), Dropped(1)]);
  }

  #[test]
  fn completed_helpers_panic_without_polling_inputs_again() {
    let log = new_log();
    let mut joined = join_all(vec![Probe::ready_after(&log, 0, 0, 0_u8)], 1).expect("within limit");
    assert_eq!(poll_once(&mut joined), Poll::Ready(vec![0]));
    let mut tried =
      try_join_all(vec![Probe::ready_after(&log, 1, 0, Ok::<u8, ()>(1))], 1).expect("within limit");
    assert_eq!(poll_once(&mut tried), Poll::Ready(Ok(vec![1])));
    let branches = vec![Branch::new(true, Probe::ready_after(&log, 2, 0, 2_u8))];
    let mut selected = select_many(branches, 1, SelectionPolicy::RoundRobin).expect("enabled");
    assert_eq!(poll_once(&mut selected), Poll::Ready((0, 2)));
    take_events(&log);

    assert_eq!(
      panic_message(|| poll_once(&mut joined)),
      "JoinAll polled after completion"
    );
    assert_eq!(
      panic_message(|| poll_once(&mut tried)),
      "TryJoinAll polled after completion"
    );
    assert_eq!(
      panic_message(|| poll_once(&mut selected)),
      "SelectMany polled after completion"
    );
    assert!(take_events(&log).is_empty());
  }
}
