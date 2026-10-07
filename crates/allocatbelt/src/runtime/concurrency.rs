//! Bounded-shape helpers for composing two futures.
//!
//! [`join2`] waits for both inputs, [`try_join2`] returns on the first error,
//! and [`select2`] returns the first ready branch while disposing of the
//! other. These are two-branch helpers, not replicas of Tokio's macros or
//! their full API surface.
//!
//! Each helper owns both futures in `Pin<Box<_>>`. This supports borrowed,
//! `!Send`, and `!Unpin` futures without imposing `'static` or `Send` bounds,
//! at the cost of one ordinary metadata allocation per input future. Inputs
//! are constructed by the caller before a helper is called; `select2` has no
//! disabled-branch option, so both passed futures are evaluated and owned
//! immediately. Dropping a pending helper cancels its owned futures, but any
//! side effects they performed before cancellation are not rolled back.
//!
//! A helper drops a completed future before storing its output, and drops
//! losing futures and unused partial outputs before publishing a result. If
//! polling panics, that panic is resumed after cleanup; panics from cleanup
//! are contained. If cleanup is the first operation to panic while completing
//! normally, its first panic is resumed after remaining values are disposed.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::any::Any;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::task::{Context, Poll};

use super::task::drop_contained;

type PanicPayload = Box<dyn Any + Send + 'static>;

/// Creates a future that polls both inputs until each completes.
///
/// Each active input is polled at most once per call to `poll`, in argument
/// order. A completed input is never polled again. Both inputs are owned as
/// soon as this function returns; dropping the returned future cancels both.
pub fn join2<A, B>(first: A, second: B) -> Join2<A, B>
where
  A: Future,
  B: Future,
{
  Join2 {
    first: Some(Box::pin(first)),
    second: Some(Box::pin(second)),
    first_output: None,
    second_output: None,
    done: false,
  }
}

/// Future returned by [`join2`].
pub struct Join2<A: Future, B: Future> {
  first: Option<Pin<Box<A>>>,
  second: Option<Pin<Box<B>>>,
  first_output: Option<A::Output>,
  second_output: Option<B::Output>,
  done: bool,
}

// The input futures stay pinned in their boxes. The other fields are not
// structurally pinned, so moving this outer bookkeeping value is safe.
impl<A: Future, B: Future> Unpin for Join2<A, B> {}

impl<A: Future, B: Future> Future for Join2<A, B> {
  type Output = (A::Output, B::Output);

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    assert!(!this.done, "Join2 polled after completion");

    if let Some(result) = poll_input(&mut this.first, cx) {
      match result {
        Ok(Poll::Pending) => {}
        Ok(Poll::Ready(output)) => {
          if let Some(payload) = drop_input(&mut this.first) {
            drop_contained(output);
            this.abort_with_primary(payload);
          }
          this.first_output = Some(output);
        }
        Err(payload) => this.abort_with_primary(payload),
      }
    }

    if let Some(result) = poll_input(&mut this.second, cx) {
      match result {
        Ok(Poll::Pending) => {}
        Ok(Poll::Ready(output)) => {
          if let Some(payload) = drop_input(&mut this.second) {
            drop_contained(output);
            this.abort_with_primary(payload);
          }
          this.second_output = Some(output);
        }
        Err(payload) => this.abort_with_primary(payload),
      }
    }

    if this.first_output.is_some() && this.second_output.is_some() {
      this.done = true;
      let first = match this.first_output.take() {
        Some(output) => output,
        None => unreachable!("first join output checked above"),
      };
      let second = match this.second_output.take() {
        Some(output) => output,
        None => unreachable!("second join output checked above"),
      };
      Poll::Ready((first, second))
    } else {
      Poll::Pending
    }
  }
}

impl<A: Future, B: Future> Join2<A, B> {
  fn abort_with_primary(&mut self, primary: PanicPayload) -> ! {
    self.cleanup_contained();
    self.done = true;
    panic::resume_unwind(primary)
  }

  fn cleanup_contained(&mut self) {
    drop_contained(self.first.take());
    drop_contained(self.second.take());
    drop_contained(self.first_output.take());
    drop_contained(self.second_output.take());
  }

  fn cleanup_capturing(&mut self) -> Option<PanicPayload> {
    let mut primary = None;
    dispose_capturing(&mut self.first, &mut primary);
    dispose_capturing(&mut self.second, &mut primary);
    dispose_capturing(&mut self.first_output, &mut primary);
    dispose_capturing(&mut self.second_output, &mut primary);
    primary
  }
}

impl<A: Future, B: Future> Drop for Join2<A, B> {
  fn drop(&mut self) {
    propagate_drop_panic(self.cleanup_capturing());
  }
}

/// Creates a future that joins two `Result`-producing futures and fails fast.
///
/// On the first observed error it drops the other future and any previously
/// completed successful output before returning that error. Inputs are polled
/// in argument order on each poll, and completed inputs are never polled again.
pub fn try_join2<A, B, T, U, E>(first: A, second: B) -> TryJoin2<A, B, T, U, E>
where
  A: Future<Output = Result<T, E>>,
  B: Future<Output = Result<U, E>>,
{
  TryJoin2 {
    first: Some(Box::pin(first)),
    second: Some(Box::pin(second)),
    first_output: None,
    second_output: None,
    error: std::marker::PhantomData,
    done: false,
  }
}

/// Future returned by [`try_join2`].
pub struct TryJoin2<A, B, T, U, E>
where
  A: Future<Output = Result<T, E>>,
  B: Future<Output = Result<U, E>>,
{
  first: Option<Pin<Box<A>>>,
  second: Option<Pin<Box<B>>>,
  first_output: Option<T>,
  second_output: Option<U>,
  error: std::marker::PhantomData<fn(E)>,
  done: bool,
}

impl<A, B, T, U, E> Unpin for TryJoin2<A, B, T, U, E>
where
  A: Future<Output = Result<T, E>>,
  B: Future<Output = Result<U, E>>,
{
}

impl<A, B, T, U, E> Future for TryJoin2<A, B, T, U, E>
where
  A: Future<Output = Result<T, E>>,
  B: Future<Output = Result<U, E>>,
{
  type Output = Result<(T, U), E>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    assert!(!this.done, "TryJoin2 polled after completion");

    if let Some(result) = poll_input(&mut this.first, cx) {
      match result {
        Err(payload) => this.abort_with_primary(payload),
        Ok(Poll::Pending) => {}
        Ok(Poll::Ready(Ok(output))) => {
          if let Some(payload) = drop_input(&mut this.first) {
            drop_contained(output);
            this.abort_with_primary(payload);
          }
          this.first_output = Some(output);
        }
        Ok(Poll::Ready(Err(error))) => {
          if let Some(payload) = drop_input(&mut this.first) {
            drop_contained(error);
            this.abort_with_primary(payload);
          }
          this.done = true;
          return match this.cleanup_before_error(error) {
            Ok(error) => Poll::Ready(Err(error)),
            Err(payload) => this.abort_with_primary(payload),
          };
        }
      }
    }

    if let Some(result) = poll_input(&mut this.second, cx) {
      match result {
        Err(payload) => this.abort_with_primary(payload),
        Ok(Poll::Pending) => {}
        Ok(Poll::Ready(Ok(output))) => {
          if let Some(payload) = drop_input(&mut this.second) {
            drop_contained(output);
            this.abort_with_primary(payload);
          }
          this.second_output = Some(output);
        }
        Ok(Poll::Ready(Err(error))) => {
          if let Some(payload) = drop_input(&mut this.second) {
            drop_contained(error);
            this.abort_with_primary(payload);
          }
          this.done = true;
          return match this.cleanup_before_error(error) {
            Ok(error) => Poll::Ready(Err(error)),
            Err(payload) => this.abort_with_primary(payload),
          };
        }
      }
    }

    if this.first_output.is_some() && this.second_output.is_some() {
      this.done = true;
      let first = match this.first_output.take() {
        Some(output) => output,
        None => unreachable!("first try_join output checked above"),
      };
      let second = match this.second_output.take() {
        Some(output) => output,
        None => unreachable!("second try_join output checked above"),
      };
      Poll::Ready(Ok((first, second)))
    } else {
      Poll::Pending
    }
  }
}

impl<A, B, T, U, E> TryJoin2<A, B, T, U, E>
where
  A: Future<Output = Result<T, E>>,
  B: Future<Output = Result<U, E>>,
{
  fn abort_with_primary(&mut self, primary: PanicPayload) -> ! {
    self.cleanup_contained();
    self.done = true;
    panic::resume_unwind(primary)
  }

  fn cleanup_contained(&mut self) {
    drop_contained(self.first.take());
    drop_contained(self.second.take());
    drop_contained(self.first_output.take());
    drop_contained(self.second_output.take());
  }

  fn cleanup_before_error<V>(&mut self, error: V) -> Result<V, PanicPayload> {
    let mut primary = None;
    dispose_capturing(&mut self.first, &mut primary);
    dispose_capturing(&mut self.second, &mut primary);
    dispose_capturing(&mut self.first_output, &mut primary);
    dispose_capturing(&mut self.second_output, &mut primary);
    if let Some(payload) = primary {
      drop_contained(error);
      Err(payload)
    } else {
      Ok(error)
    }
  }

  fn cleanup_capturing(&mut self) -> Option<PanicPayload> {
    let mut primary = None;
    dispose_capturing(&mut self.first, &mut primary);
    dispose_capturing(&mut self.second, &mut primary);
    dispose_capturing(&mut self.first_output, &mut primary);
    dispose_capturing(&mut self.second_output, &mut primary);
    primary
  }
}

impl<A, B, T, U, E> Drop for TryJoin2<A, B, T, U, E>
where
  A: Future<Output = Result<T, E>>,
  B: Future<Output = Result<U, E>>,
{
  fn drop(&mut self) {
    propagate_drop_panic(self.cleanup_capturing());
  }
}

/// The selected branch and its output.
#[derive(Debug, Eq, PartialEq)]
pub enum Either<L, R> {
  /// The first future completed first.
  Left(L),
  /// The second future completed first.
  Right(R),
}

/// Poll-order policy for [`select2`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectPolicy {
  /// Poll the first future before the second on every poll.
  Biased,
  /// Alternate which future is polled first after each poll where both pend.
  RoundRobin,
}

/// Creates a future that returns the first ready branch and cancels the other.
///
/// Both futures are eagerly constructed by the caller and owned by the
/// returned helper. `Biased` always polls the first input before the second.
/// `RoundRobin` begins with the first input, then alternates the first polled
/// input after each call where both inputs return `Pending`; no random source
/// is used. A winning input's output is moved into [`Either`], while both
/// completed and losing future objects are dropped before the result appears.
pub fn select2<A, B>(first: A, second: B, policy: SelectPolicy) -> Select2<A, B>
where
  A: Future,
  B: Future,
{
  Select2 {
    first: Some(Box::pin(first)),
    second: Some(Box::pin(second)),
    policy,
    next_first: true,
    done: false,
  }
}

/// Future returned by [`select2`].
pub struct Select2<A: Future, B: Future> {
  first: Option<Pin<Box<A>>>,
  second: Option<Pin<Box<B>>>,
  policy: SelectPolicy,
  next_first: bool,
  done: bool,
}

impl<A: Future, B: Future> Unpin for Select2<A, B> {}

impl<A: Future, B: Future> Future for Select2<A, B> {
  type Output = Either<A::Output, B::Output>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    assert!(!this.done, "Select2 polled after completion");
    let first_is_left = match this.policy {
      SelectPolicy::Biased => true,
      SelectPolicy::RoundRobin => this.next_first,
    };

    if first_is_left {
      if let Some(result) = poll_input(&mut this.first, cx) {
        match result {
          Err(payload) => this.abort_with_primary(payload),
          Ok(Poll::Ready(output)) => return this.finish_left(output),
          Ok(Poll::Pending) => {}
        }
      }
      if let Some(result) = poll_input(&mut this.second, cx) {
        match result {
          Err(payload) => this.abort_with_primary(payload),
          Ok(Poll::Ready(output)) => return this.finish_right(output),
          Ok(Poll::Pending) => {}
        }
      }
    } else {
      if let Some(result) = poll_input(&mut this.second, cx) {
        match result {
          Err(payload) => this.abort_with_primary(payload),
          Ok(Poll::Ready(output)) => return this.finish_right(output),
          Ok(Poll::Pending) => {}
        }
      }
      if let Some(result) = poll_input(&mut this.first, cx) {
        match result {
          Err(payload) => this.abort_with_primary(payload),
          Ok(Poll::Ready(output)) => return this.finish_left(output),
          Ok(Poll::Pending) => {}
        }
      }
    }

    if this.policy == SelectPolicy::RoundRobin {
      this.next_first = !first_is_left;
    }
    Poll::Pending
  }
}

impl<A: Future, B: Future> Select2<A, B> {
  fn finish_left(&mut self, output: A::Output) -> Poll<Either<A::Output, B::Output>> {
    let mut primary = drop_input(&mut self.first);
    dispose_capturing(&mut self.second, &mut primary);
    if let Some(payload) = primary {
      drop_contained(output);
      self.done = true;
      panic::resume_unwind(payload);
    }
    self.done = true;
    Poll::Ready(Either::Left(output))
  }

  fn finish_right(&mut self, output: B::Output) -> Poll<Either<A::Output, B::Output>> {
    let mut primary = drop_input(&mut self.second);
    dispose_capturing(&mut self.first, &mut primary);
    if let Some(payload) = primary {
      drop_contained(output);
      self.done = true;
      panic::resume_unwind(payload);
    }
    self.done = true;
    Poll::Ready(Either::Right(output))
  }

  fn abort_with_primary(&mut self, primary: PanicPayload) -> ! {
    self.cleanup_contained();
    self.done = true;
    panic::resume_unwind(primary)
  }

  fn cleanup_contained(&mut self) {
    drop_contained(self.first.take());
    drop_contained(self.second.take());
  }

  fn cleanup_capturing(&mut self) -> Option<PanicPayload> {
    let mut primary = None;
    dispose_capturing(&mut self.first, &mut primary);
    dispose_capturing(&mut self.second, &mut primary);
    primary
  }
}

impl<A: Future, B: Future> Drop for Select2<A, B> {
  fn drop(&mut self) {
    propagate_drop_panic(self.cleanup_capturing());
  }
}

fn poll_input<F: Future>(
  slot: &mut Option<Pin<Box<F>>>,
  cx: &mut Context<'_>,
) -> Option<Result<Poll<F::Output>, PanicPayload>> {
  slot
    .as_mut()
    .map(|future| panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))))
}

fn drop_input<F>(slot: &mut Option<Pin<Box<F>>>) -> Option<PanicPayload> {
  let future = slot.take()?;
  panic::catch_unwind(AssertUnwindSafe(|| drop(future))).err()
}

fn dispose_capturing<T>(slot: &mut Option<T>, primary: &mut Option<PanicPayload>) {
  let Some(value) = slot.take() else {
    return;
  };
  match panic::catch_unwind(AssertUnwindSafe(|| drop(value))) {
    Ok(()) => {}
    Err(payload) => {
      if primary.is_some() {
        drop_contained(payload);
      } else {
        *primary = Some(payload);
      }
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
  use std::future::{Future, poll_fn};
  use std::marker::PhantomPinned;
  use std::panic::AssertUnwindSafe;
  use std::pin::Pin;
  use std::rc::Rc;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
  use std::task::{Context, Poll, Waker};

  use super::{Either, SelectPolicy, join2, select2, try_join2};

  fn noop_waker() -> Waker {
    (*Waker::noop()).clone()
  }

  fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    let mut cx = Context::from_waker(waker);
    future.poll(&mut cx)
  }

  #[test]
  fn join_polls_both_and_never_repolls_completed_branch() {
    let first_polls = Arc::new(AtomicUsize::new(0));
    let second_polls = Arc::new(AtomicUsize::new(0));
    let first = {
      let polls = Arc::clone(&first_polls);
      poll_fn(move |_| {
        let count = polls.fetch_add(1, Ordering::SeqCst);
        if count == 0 {
          Poll::Ready(3)
        } else {
          panic!("completed first future was polled again")
        }
      })
    };
    let second = {
      let polls = Arc::clone(&second_polls);
      poll_fn(move |_| {
        let count = polls.fetch_add(1, Ordering::SeqCst);
        if count == 0 {
          Poll::Pending
        } else if count == 1 {
          Poll::Ready(4)
        } else {
          panic!("completed second future was polled again")
        }
      })
    };
    let mut join = Box::pin(join2(first, second));
    let waker = noop_waker();
    assert!(poll(join.as_mut(), &waker).is_pending());
    assert_eq!(poll(join.as_mut(), &waker), Poll::Ready((3, 4)));
    assert_eq!(first_polls.load(Ordering::SeqCst), 1);
    assert_eq!(second_polls.load(Ordering::SeqCst), 2);
  }

  #[test]
  fn helpers_accept_borrowed_non_send_non_unpin_futures() {
    struct BorrowedPinned<'a>(&'a mut String, PhantomPinned, Rc<()>);
    impl Future for BorrowedPinned<'_> {
      type Output = usize;

      fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_ref().get_ref();
        let _not_send = &this.2;
        Poll::Ready(this.0.len())
      }
    }

    let mut local = String::from("borrowed");
    let borrowed = BorrowedPinned(&mut local, PhantomPinned, Rc::new(()));
    let second = std::future::pending::<usize>();
    let mut joined = Box::pin(join2(borrowed, second));
    let waker = noop_waker();
    assert!(poll(joined.as_mut(), &waker).is_pending());
    drop(joined);
    local.push('!');
    assert_eq!(local, "borrowed!");
  }

  #[test]
  fn select_drops_loser_before_result_is_observed() {
    struct DropProbe(Arc<AtomicBool>);
    impl Drop for DropProbe {
      fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
      }
    }

    let dropped = Arc::new(AtomicBool::new(false));
    let loser = {
      let probe = DropProbe(Arc::clone(&dropped));
      poll_fn(move |_| {
        let _keep_alive = &probe;
        Poll::<u8>::Pending
      })
    };
    let mut select = Box::pin(select2(std::future::ready(9), loser, SelectPolicy::Biased));
    assert_eq!(
      poll(select.as_mut(), &noop_waker()),
      Poll::Ready(Either::Left(9))
    );
    assert!(dropped.load(Ordering::SeqCst));
  }

  #[test]
  fn cleanup_drop_panics_are_contained_and_poll_panic_is_primary() {
    struct PanicDrop;
    impl Drop for PanicDrop {
      fn drop(&mut self) {
        panic!("secondary drop panic");
      }
    }

    let first = poll_fn(|_| -> Poll<()> { panic!("primary poll panic") });
    let second = {
      let probe = PanicDrop;
      poll_fn(move |_| {
        let _keep_alive = &probe;
        Poll::<()>::Pending
      })
    };
    let mut joined = Box::pin(join2(first, second));
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
      let _ = poll(joined.as_mut(), &noop_waker());
    }));
    assert_eq!(
      result
        .expect_err("poll panic should propagate")
        .downcast_ref::<&str>(),
      Some(&"primary poll panic")
    );
  }

  #[test]
  fn try_join_drops_completed_value_before_returning_other_error() {
    struct DropProbe(Arc<AtomicBool>);
    impl Drop for DropProbe {
      fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
      }
    }

    let dropped = Arc::new(AtomicBool::new(false));
    let first = {
      let dropped = Arc::clone(&dropped);
      let mut output = Some(DropProbe(dropped));
      poll_fn(move |_| {
        let Some(output) = output.take() else {
          panic!("completed output future was polled again")
        };
        Poll::Ready(Ok::<_, &'static str>(output))
      })
    };
    let second = std::future::ready(Err::<(), _>("failed"));
    let mut joined = Box::pin(try_join2(first, second));
    assert!(matches!(
      poll(joined.as_mut(), &noop_waker()),
      Poll::Ready(Err("failed"))
    ));
    assert!(dropped.load(Ordering::SeqCst));
  }

  #[test]
  fn try_join_does_not_repoll_successful_branch() {
    let polls = Arc::new(AtomicUsize::new(0));
    let first = {
      let polls = Arc::clone(&polls);
      poll_fn(move |_| {
        if polls.fetch_add(1, Ordering::SeqCst) == 0 {
          Poll::Ready(Ok::<_, &'static str>(1))
        } else {
          panic!("completed result future was polled again")
        }
      })
    };
    let second = std::future::pending::<Result<u8, &'static str>>();
    let mut joined = Box::pin(try_join2(first, second));
    assert!(poll(joined.as_mut(), &noop_waker()).is_pending());
    assert_eq!(polls.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn second_error_drops_pending_first_before_completed_helper_is_retained() {
    struct Probe(Arc<AtomicBool>);
    impl Drop for Probe {
      fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
      }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let probe = Probe(Arc::clone(&dropped));
    let first = poll_fn(move |_| {
      let _retained = &probe;
      Poll::<Result<(), &str>>::Pending
    });
    let second = std::future::ready(Err::<(), _>("second error"));
    let mut retained = Box::pin(try_join2(first, second));
    assert_eq!(
      poll(retained.as_mut(), &noop_waker()),
      Poll::Ready(Err("second error"))
    );
    assert!(dropped.load(Ordering::SeqCst));
    assert!(retained.first.is_none());
  }

  #[test]
  fn second_error_propagates_first_loser_destructor_panic_after_cleanup() {
    struct PanicDrop(Arc<AtomicBool>);
    impl Drop for PanicDrop {
      fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
        panic!("first loser destructor panic");
      }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let probe = PanicDrop(Arc::clone(&dropped));
    let first = poll_fn(move |_| {
      let _retained = &probe;
      Poll::<Result<(), &str>>::Pending
    });
    let second = std::future::ready(Err::<(), _>("second error"));
    let mut retained = Box::pin(try_join2(first, second));
    let outcome =
      std::panic::catch_unwind(AssertUnwindSafe(|| poll(retained.as_mut(), &noop_waker())));
    assert_eq!(
      outcome.unwrap_err().downcast_ref::<&str>(),
      Some(&"first loser destructor panic")
    );
    assert!(dropped.load(Ordering::SeqCst));
    assert!(retained.first.is_none() && retained.second.is_none());
  }

  #[test]
  fn later_poll_panic_remains_primary_when_a_stored_output_destructor_panics() {
    struct Output(Arc<AtomicUsize>);
    impl Drop for Output {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("stored output destructor panic");
      }
    }
    struct Capture(Arc<AtomicUsize>);
    impl Drop for Capture {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }
    let output_drops = Arc::new(AtomicUsize::new(0));
    let capture_drops = Arc::new(AtomicUsize::new(0));
    let capture = Capture(Arc::clone(&capture_drops));
    let second = poll_fn(move |_| -> Poll<()> {
      let _retained = &capture;
      panic!("right poll panic");
    });
    let mut joined = Box::pin(join2(
      std::future::ready(Output(Arc::clone(&output_drops))),
      second,
    ));
    let outcome =
      std::panic::catch_unwind(AssertUnwindSafe(|| poll(joined.as_mut(), &noop_waker())));
    let Err(payload) = outcome else {
      panic!("missing primary panic")
    };
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"right poll panic"));
    assert_eq!(output_drops.load(Ordering::SeqCst), 1);
    assert_eq!(capture_drops.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn selected_output_is_disposed_once_when_loser_cleanup_panics() {
    struct Output(Arc<AtomicUsize>);
    impl Drop for Output {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }
    struct Loser(Arc<AtomicUsize>);
    impl Drop for Loser {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("loser cleanup panic");
      }
    }
    let output_drops = Arc::new(AtomicUsize::new(0));
    let loser_drops = Arc::new(AtomicUsize::new(0));
    let loser = Loser(Arc::clone(&loser_drops));
    let second = poll_fn(move |_| {
      let _retained = &loser;
      Poll::<()>::Pending
    });
    let mut selected = Box::pin(select2(
      std::future::ready(Output(Arc::clone(&output_drops))),
      second,
      SelectPolicy::Biased,
    ));
    let outcome =
      std::panic::catch_unwind(AssertUnwindSafe(|| poll(selected.as_mut(), &noop_waker())));
    let Err(payload) = outcome else {
      panic!("missing cleanup panic")
    };
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"loser cleanup panic"));
    assert_eq!(output_drops.load(Ordering::SeqCst), 1);
    assert_eq!(loser_drops.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn helper_cleanup_during_unwind_preserves_outer_panic_and_releases_both_inputs() {
    struct PanicDrop(Arc<AtomicUsize>);
    impl Drop for PanicDrop {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("cleanup while unwinding");
      }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
      let left = PanicDrop(Arc::clone(&drops));
      let right = PanicDrop(Arc::clone(&drops));
      let first = poll_fn(move |_| {
        let _retained = &left;
        Poll::<()>::Pending
      });
      let second = poll_fn(move |_| {
        let _retained = &right;
        Poll::<()>::Pending
      });
      let _owned = join2(first, second);
      panic!("outer primary panic");
    }));
    assert_eq!(
      outcome.unwrap_err().downcast_ref::<&str>(),
      Some(&"outer primary panic")
    );
    assert_eq!(drops.load(Ordering::SeqCst), 2);
  }

  #[test]
  fn round_robin_flips_the_first_polled_branch_after_pending() {
    let order = Rc::new(RefCell::new(Vec::new()));
    let first = {
      let order = Rc::clone(&order);
      poll_fn(move |_| {
        order.borrow_mut().push(0);
        Poll::<u8>::Pending
      })
    };
    let second = {
      let order = Rc::clone(&order);
      poll_fn(move |_| {
        order.borrow_mut().push(1);
        Poll::<u8>::Pending
      })
    };
    let mut select = Box::pin(select2(first, second, SelectPolicy::RoundRobin));
    let waker = noop_waker();
    assert!(poll(select.as_mut(), &waker).is_pending());
    assert!(poll(select.as_mut(), &waker).is_pending());
    assert_eq!(&*order.borrow(), &[0, 1, 1, 0]);
  }

  #[test]
  fn cancellation_drops_both_pending_borrowed_inputs() {
    struct DropProbe(Rc<Cell<usize>>);
    impl Drop for DropProbe {
      fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
      }
    }
    let count = Rc::new(Cell::new(0));
    let first = {
      let probe = DropProbe(Rc::clone(&count));
      poll_fn(move |_| {
        let _keep_alive = &probe;
        Poll::<()>::Pending
      })
    };
    let second = {
      let probe = DropProbe(Rc::clone(&count));
      poll_fn(move |_| {
        let _keep_alive = &probe;
        Poll::<()>::Pending
      })
    };
    let mut joined = Box::pin(join2(first, second));
    assert!(poll(joined.as_mut(), &noop_waker()).is_pending());
    drop(joined);
    assert_eq!(count.get(), 2);
  }

  #[test]
  fn cancellation_propagates_first_drop_panic_after_cleanup() {
    struct PanicDrop;
    impl Drop for PanicDrop {
      fn drop(&mut self) {
        panic!("first cancellation drop panic");
      }
    }
    struct CountDrop(Arc<AtomicUsize>);
    impl Drop for CountDrop {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let first = {
      let probe = PanicDrop;
      poll_fn(move |_| {
        let _keep_alive = &probe;
        Poll::<()>::Pending
      })
    };
    let second = {
      let probe = CountDrop(Arc::clone(&drops));
      poll_fn(move |_| {
        let _keep_alive = &probe;
        Poll::<()>::Pending
      })
    };
    let mut joined = Box::pin(join2(first, second));
    assert!(poll(joined.as_mut(), &noop_waker()).is_pending());
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| drop(joined)));
    assert_eq!(
      result
        .expect_err("first cancellation drop panic should propagate")
        .downcast_ref::<&str>(),
      Some(&"first cancellation drop panic")
    );
    assert_eq!(drops.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn select_panic_drops_loser_before_resuming_primary() {
    struct PanicDrop(Arc<AtomicUsize>);
    impl Drop for PanicDrop {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("loser drop panic");
      }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let first = poll_fn(|_| -> Poll<u8> { panic!("winner poll panic") });
    let second = {
      let probe = PanicDrop(Arc::clone(&drops));
      poll_fn(move |_| {
        let _keep_alive = &probe;
        Poll::<u8>::Pending
      })
    };
    let mut selected = Box::pin(select2(first, second, SelectPolicy::Biased));
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
      let _ = poll(selected.as_mut(), &noop_waker());
    }));
    assert_eq!(
      result
        .expect_err("poll panic should propagate")
        .downcast_ref::<&str>(),
      Some(&"winner poll panic")
    );
    assert_eq!(drops.load(Ordering::SeqCst), 1);
  }
}
