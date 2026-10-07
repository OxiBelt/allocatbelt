//! Heterogeneous, bounded-shape future composition macros.
//!
//! The macros in this module complement [`super::concurrency`]'s two-input
//! helpers. They accept between two and sixteen branches. Branches are owned
//! by the returned future and support borrowed, `!Send`, and `!Unpin` inputs.
//! Each branch future is boxed once to keep it pinned while the outer future
//! moves. No Tokio dependency or procedural macro is used.
//! The syntax is an allocatbelt application port and does not claim Tokio
//! macro compatibility.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::any::Any;
use std::future::Future;
use std::marker::PhantomData;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::task::{Context, Poll};

pub use crate::{join, select, try_join};
/// Pin a future or other value on the stack for use with a runtime entry
/// method such as [`crate::runtime::asynchronous::AsyncHandle::block_on`].
pub use std::pin::pin;

#[doc(hidden)]
pub type PanicPayload = Box<dyn Any + Send + 'static>;

/// The nested winner representation used internally by [`select!`].
#[doc(hidden)]
pub enum Either<L, R> {
  Left(L),
  Right(R),
}

/// Empty tail for the internal heterogeneous branch list.
#[doc(hidden)]
pub struct Nil;

/// One future owned by a selection branch.
#[doc(hidden)]
pub struct Branch<F> {
  future: Option<Pin<Box<F>>>,
  enabled: bool,
}

impl<F: Future> Branch<F> {
  /// Constructs and pins one selection branch.
  #[doc(hidden)]
  pub fn new(future: F, enabled: bool) -> Self {
    Self {
      future: Some(Box::pin(future)),
      enabled,
    }
  }

  fn enabled(&self) -> bool {
    self.enabled
  }

  fn poll(&mut self, cx: &mut Context<'_>) -> Result<Poll<F::Output>, PanicPayload> {
    let Some(future) = self.future.as_mut() else {
      return Ok(Poll::Pending);
    };
    panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx)))
  }

  fn dispose_capturing(&mut self, primary: &mut Option<PanicPayload>) {
    dispose_capturing(&mut self.future, primary);
  }
}

/// One node in the heterogeneous branch list.
#[doc(hidden)]
pub struct Cons<H, T> {
  head: H,
  tail: T,
}

impl<H, T> Cons<H, T> {
  /// Prepends a branch to the list.
  #[doc(hidden)]
  pub fn new(head: H, tail: T) -> Self {
    Self { head, tail }
  }
}

/// Operations shared by every supported heterogeneous branch-list length.
#[doc(hidden)]
pub trait BranchList {
  /// Nested output carrying the selected branch's value.
  type Winner;
  /// Number of branches in the list.
  const LEN: usize;

  fn enabled_at(&self, index: usize) -> bool;
  fn poll_at(
    &mut self,
    index: usize,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Self::Winner>, PanicPayload>>;
  fn dispose_capturing(&mut self, primary: &mut Option<PanicPayload>);

  fn branch_count(&self) -> usize {
    Self::LEN
  }

  fn any_enabled(&self) -> bool {
    (0..Self::LEN).any(|index| self.enabled_at(index))
  }

  fn next_enabled(&self, current: usize) -> usize {
    (1..=Self::LEN)
      .map(|offset| (current + offset) % Self::LEN)
      .find(|index| self.enabled_at(*index))
      .unwrap_or(current)
  }

  fn first_enabled_from(&self, start: usize) -> usize {
    (0..Self::LEN)
      .map(|offset| (start + offset) % Self::LEN)
      .find(|index| self.enabled_at(*index))
      .unwrap_or(start)
  }
}

impl<F, T> BranchList for Cons<Branch<F>, T>
where
  F: Future,
  T: BranchList,
{
  type Winner = Either<F::Output, T::Winner>;
  const LEN: usize = 1 + T::LEN;

  fn enabled_at(&self, index: usize) -> bool {
    if index == 0 {
      self.head.enabled()
    } else {
      self.tail.enabled_at(index - 1)
    }
  }

  fn poll_at(
    &mut self,
    index: usize,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Self::Winner>, PanicPayload>> {
    if index == 0 {
      if !self.head.enabled() {
        return Poll::Ready(Ok(None));
      }
      return match self.head.poll(cx) {
        Ok(Poll::Pending) => Poll::Ready(Ok(None)),
        Ok(Poll::Ready(output)) => Poll::Ready(Ok(Some(Either::Left(output)))),
        Err(payload) => Poll::Ready(Err(payload)),
      };
    }
    self
      .tail
      .poll_at(index - 1, cx)
      .map(|result| result.map(|winner| winner.map(Either::Right)))
  }

  fn dispose_capturing(&mut self, primary: &mut Option<PanicPayload>) {
    self.head.dispose_capturing(primary);
    self.tail.dispose_capturing(primary);
  }
}

impl BranchList for Nil {
  type Winner = std::convert::Infallible;
  const LEN: usize = 0;

  fn enabled_at(&self, _index: usize) -> bool {
    false
  }

  fn poll_at(
    &mut self,
    _index: usize,
    _cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Self::Winner>, PanicPayload>> {
    Poll::Ready(Ok(None))
  }

  fn dispose_capturing(&mut self, _primary: &mut Option<PanicPayload>) {}
}

/// Marker implemented only for lists containing at least two branches.
#[doc(hidden)]
pub trait MultiBranchList: BranchList {}

impl<F, G, T> MultiBranchList for Cons<Branch<F>, Cons<Branch<G>, T>>
where
  F: Future,
  G: Future,
  T: BranchList,
{
}

/// Selection storage whose destructor disposes every branch even when one
/// future destructor panics.
#[doc(hidden)]
pub struct BranchSet<L: MultiBranchList> {
  branches: Option<L>,
}

impl<L: MultiBranchList> BranchSet<L> {
  /// Owns a completed branch list.
  #[doc(hidden)]
  pub fn new(branches: L) -> Self {
    Self {
      branches: Some(branches),
    }
  }

  /// Returns whether at least one branch is enabled.
  #[doc(hidden)]
  pub fn any_enabled(&self) -> bool {
    self
      .branches
      .as_ref()
      .is_some_and(|branches| branches.any_enabled())
  }

  /// Number of original source branches.
  #[doc(hidden)]
  pub fn branch_count(&self) -> usize {
    self
      .branches
      .as_ref()
      .map_or(0, |branches| branches.branch_count())
  }

  /// Polls one original branch index.
  #[doc(hidden)]
  pub fn poll_at(
    &mut self,
    index: usize,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<L::Winner>, PanicPayload>> {
    match self.branches.as_mut() {
      Some(branches) => branches.poll_at(index, cx),
      None => Poll::Ready(Ok(None)),
    }
  }

  /// Advances to the next enabled original branch index.
  #[doc(hidden)]
  pub fn next_enabled(&self, current: usize) -> usize {
    self
      .branches
      .as_ref()
      .map_or(current, |branches| branches.next_enabled(current))
  }

  /// Returns the first enabled original branch at or after `start`.
  #[doc(hidden)]
  pub fn first_enabled_from(&self, start: usize) -> usize {
    self
      .branches
      .as_ref()
      .map_or(start, |branches| branches.first_enabled_from(start))
  }

  /// Disposes all branch futures, then resumes the first
  /// destructor panic if there was one.
  #[doc(hidden)]
  pub fn dispose(&mut self) {
    let mut primary = None;
    self.dispose_capturing(&mut primary);
    propagate_drop_panic(primary);
  }

  /// Disposes all branches before publishing a winner. The winner is safely
  /// disposed if cleanup itself panics.
  #[doc(hidden)]
  pub fn dispose_before_winner(&mut self, winner: L::Winner) -> L::Winner {
    let mut primary = None;
    self.dispose_capturing(&mut primary);
    if let Some(payload) = primary {
      drop_contained(winner);
      panic::resume_unwind(payload);
    }
    winner
  }

  /// Disposes all branches while preserving a polling panic as primary.
  #[doc(hidden)]
  pub fn dispose_after_poll_panic(&mut self, primary: PanicPayload) -> ! {
    let mut ignored = None;
    self.dispose_capturing(&mut ignored);
    drop_contained(ignored);
    panic::resume_unwind(primary)
  }

  fn dispose_capturing(&mut self, primary: &mut Option<PanicPayload>) {
    if let Some(mut branches) = self.branches.take() {
      branches.dispose_capturing(primary);
      // All owned branch values have been taken. Dropping the empty HList is
      // now inert and cannot bypass the contained destructor handling above.
      drop(branches);
    }
  }
}

impl<L: MultiBranchList> Drop for BranchSet<L> {
  fn drop(&mut self) {
    let mut primary = None;
    self.dispose_capturing(&mut primary);
    propagate_drop_panic(primary);
  }
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

fn drop_contained<T>(value: T) {
  if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| drop(value)))
    && let Err(again) = panic::catch_unwind(AssertUnwindSafe(|| drop(payload)))
  {
    std::mem::forget(again);
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

/// One independently owned join input and output slot.
#[doc(hidden)]
pub struct JoinSlot<F, O> {
  future: Option<Pin<Box<F>>>,
  output: Option<O>,
}

impl<F: Future<Output = O>, O> JoinSlot<F, O> {
  /// Creates a pinned join input.
  #[doc(hidden)]
  pub fn new(future: F) -> Self {
    Self {
      future: Some(Box::pin(future)),
      output: None,
    }
  }

  fn poll(&mut self, cx: &mut Context<'_>) -> Result<(), PanicPayload> {
    if self.output.is_some() {
      return Ok(());
    }
    let Some(future) = self.future.as_mut() else {
      return Ok(());
    };
    match panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
      Ok(Poll::Pending) => Ok(()),
      Ok(Poll::Ready(output)) => {
        let future = self.future.take();
        if let Some(payload) = drop_capturing(future) {
          drop_contained(output);
          return Err(payload);
        }
        self.output = Some(output);
        Ok(())
      }
      Err(payload) => Err(payload),
    }
  }

  fn dispose_capturing(&mut self, primary: &mut Option<PanicPayload>) {
    dispose_capturing(&mut self.future, primary);
    dispose_capturing(&mut self.output, primary);
  }
}

/// One join list node.
#[doc(hidden)]
pub struct JoinNode<H, T> {
  head: H,
  tail: T,
}

impl<H, T> JoinNode<H, T> {
  /// Prepends an input slot.
  #[doc(hidden)]
  pub fn new(head: H, tail: T) -> Self {
    Self { head, tail }
  }
}

/// Operations for independently retained heterogeneous join slots.
#[doc(hidden)]
pub trait JoinBranches {
  /// Nested shape used internally before the macro flattens the final tuple.
  type Outputs;
  const LEN: usize;
  fn poll_join(&mut self, cx: &mut Context<'_>) -> Result<(), PanicPayload>;
  fn complete(&self) -> bool;
  fn take_outputs(&mut self) -> Self::Outputs;
  fn dispose_capturing(&mut self, primary: &mut Option<PanicPayload>);
}

impl<F, O, T> JoinBranches for JoinNode<JoinSlot<F, O>, T>
where
  F: Future<Output = O>,
  T: JoinBranches,
{
  type Outputs = (O, T::Outputs);
  const LEN: usize = 1 + T::LEN;

  fn poll_join(&mut self, cx: &mut Context<'_>) -> Result<(), PanicPayload> {
    self.head.poll(cx)?;
    self.tail.poll_join(cx)
  }

  fn complete(&self) -> bool {
    self.head.output.is_some() && self.tail.complete()
  }

  fn take_outputs(&mut self) -> Self::Outputs {
    let output = match self.head.output.take() {
      Some(output) => output,
      None => unreachable!("join outputs are taken only after completion"),
    };
    (output, self.tail.take_outputs())
  }

  fn dispose_capturing(&mut self, primary: &mut Option<PanicPayload>) {
    self.head.dispose_capturing(primary);
    self.tail.dispose_capturing(primary);
  }
}

impl JoinBranches for Nil {
  type Outputs = ();
  const LEN: usize = 0;
  fn poll_join(&mut self, _cx: &mut Context<'_>) -> Result<(), PanicPayload> {
    Ok(())
  }
  fn complete(&self) -> bool {
    true
  }
  fn take_outputs(&mut self) -> Self::Outputs {
    // The empty branch list contributes the tuple terminator.
  }
  fn dispose_capturing(&mut self, _primary: &mut Option<PanicPayload>) {}
}

/// Future used by [`join!`].
#[doc(hidden)]
pub struct JoinFuture<L: JoinBranches> {
  branches: Option<L>,
  done: bool,
}

impl<L: JoinBranches> JoinFuture<L> {
  /// Owns the prepared heterogeneous input list.
  #[doc(hidden)]
  pub fn new(branches: L) -> Self {
    Self {
      branches: Some(branches),
      done: false,
    }
  }

  fn abort_with_primary(&mut self, primary: PanicPayload) -> ! {
    let mut ignored = None;
    self.dispose_capturing(&mut ignored);
    drop_contained(ignored);
    self.done = true;
    panic::resume_unwind(primary)
  }

  fn dispose_capturing(&mut self, primary: &mut Option<PanicPayload>) {
    if let Some(mut branches) = self.branches.take() {
      branches.dispose_capturing(primary);
      drop(branches);
    }
  }
}

impl<L: JoinBranches> Unpin for JoinFuture<L> {}

impl<L: JoinBranches> Future for JoinFuture<L> {
  type Output = L::Outputs;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    assert!(!this.done, "JoinFuture polled after completion");
    let poll_result = match this.branches.as_mut() {
      Some(branches) => branches.poll_join(cx),
      None => Ok(()),
    };
    if let Err(payload) = poll_result {
      this.abort_with_primary(payload);
    }
    let complete = this.branches.as_ref().is_some_and(JoinBranches::complete);
    if !complete {
      return Poll::Pending;
    }
    let outputs = match this.branches.as_mut() {
      Some(branches) => branches.take_outputs(),
      None => unreachable!("join branches remain until their outputs are taken"),
    };
    this.done = true;
    Poll::Ready(outputs)
  }
}

impl<L: JoinBranches> Drop for JoinFuture<L> {
  fn drop(&mut self) {
    let mut primary = None;
    self.dispose_capturing(&mut primary);
    propagate_drop_panic(primary);
  }
}

/// A try-join input slot retaining a successful value separately.
#[doc(hidden)]
pub struct TryJoinSlot<F, T, E> {
  future: Option<Pin<Box<F>>>,
  output: Option<T>,
  _error: PhantomData<fn(E)>,
}

impl<F, T, E> TryJoinSlot<F, T, E>
where
  F: Future<Output = Result<T, E>>,
{
  /// Creates a pinned try-join input.
  #[doc(hidden)]
  pub fn new(future: F) -> Self {
    Self {
      future: Some(Box::pin(future)),
      output: None,
      _error: PhantomData,
    }
  }

  fn poll(&mut self, cx: &mut Context<'_>) -> Result<Option<E>, PanicPayload> {
    if self.output.is_some() {
      return Ok(None);
    }
    let Some(future) = self.future.as_mut() else {
      return Ok(None);
    };
    let result = match panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
      Ok(Poll::Pending) => return Ok(None),
      Ok(Poll::Ready(result)) => result,
      Err(payload) => return Err(payload),
    };
    let future = self.future.take();
    match drop_capturing(future) {
      Some(payload) => {
        drop_contained(result);
        Err(payload)
      }
      None => match result {
        Ok(output) => {
          self.output = Some(output);
          Ok(None)
        }
        Err(error) => Ok(Some(error)),
      },
    }
  }

  fn dispose_capturing(&mut self, primary: &mut Option<PanicPayload>) {
    dispose_capturing(&mut self.future, primary);
    dispose_capturing(&mut self.output, primary);
  }
}

/// A try-join list node.
#[doc(hidden)]
pub struct TryJoinNode<H, T> {
  head: H,
  tail: T,
}

impl<H, T> TryJoinNode<H, T> {
  /// Prepends an input slot.
  #[doc(hidden)]
  pub fn new(head: H, tail: T) -> Self {
    Self { head, tail }
  }
}

/// Operations for independently retained heterogeneous try-join slots.
#[doc(hidden)]
pub trait TryJoinBranches<E> {
  /// Nested shape used internally before the macro flattens the final tuple.
  type Outputs;
  const LEN: usize;
  fn poll_try_join(&mut self, cx: &mut Context<'_>) -> Result<Option<E>, PanicPayload>;
  fn complete(&self) -> bool;
  fn take_outputs(&mut self) -> Self::Outputs;
  fn dispose_capturing(&mut self, primary: &mut Option<PanicPayload>);
}

impl<F, T, E, Tail> TryJoinBranches<E> for TryJoinNode<TryJoinSlot<F, T, E>, Tail>
where
  F: Future<Output = Result<T, E>>,
  Tail: TryJoinBranches<E>,
{
  type Outputs = (T, Tail::Outputs);
  const LEN: usize = 1 + Tail::LEN;

  fn poll_try_join(&mut self, cx: &mut Context<'_>) -> Result<Option<E>, PanicPayload> {
    if let Some(error) = self.head.poll(cx)? {
      return Ok(Some(error));
    }
    self.tail.poll_try_join(cx)
  }

  fn complete(&self) -> bool {
    self.head.output.is_some() && self.tail.complete()
  }

  fn take_outputs(&mut self) -> Self::Outputs {
    let output = match self.head.output.take() {
      Some(output) => output,
      None => unreachable!("try-join outputs are taken only after completion"),
    };
    (output, self.tail.take_outputs())
  }

  fn dispose_capturing(&mut self, primary: &mut Option<PanicPayload>) {
    self.head.dispose_capturing(primary);
    self.tail.dispose_capturing(primary);
  }
}

impl<E> TryJoinBranches<E> for Nil {
  type Outputs = ();
  const LEN: usize = 0;
  fn poll_try_join(&mut self, _cx: &mut Context<'_>) -> Result<Option<E>, PanicPayload> {
    Ok(None)
  }
  fn complete(&self) -> bool {
    true
  }
  fn take_outputs(&mut self) -> Self::Outputs {
    // The empty branch list contributes the tuple terminator.
  }
  fn dispose_capturing(&mut self, _primary: &mut Option<PanicPayload>) {}
}

/// Future used by [`try_join!`].
#[doc(hidden)]
pub struct TryJoinFuture<L: TryJoinBranches<E>, E> {
  branches: Option<L>,
  done: bool,
  _error: PhantomData<fn(E)>,
}

impl<L: TryJoinBranches<E>, E> TryJoinFuture<L, E> {
  /// Owns the prepared heterogeneous input list.
  #[doc(hidden)]
  pub fn new(branches: L) -> Self {
    Self {
      branches: Some(branches),
      done: false,
      _error: PhantomData,
    }
  }

  fn dispose_capturing(&mut self, primary: &mut Option<PanicPayload>) {
    if let Some(mut branches) = self.branches.take() {
      branches.dispose_capturing(primary);
      drop(branches);
    }
  }

  fn abort_with_primary(&mut self, primary: PanicPayload) -> ! {
    let mut ignored = None;
    self.dispose_capturing(&mut ignored);
    drop_contained(ignored);
    self.done = true;
    panic::resume_unwind(primary)
  }
}

impl<L: TryJoinBranches<E>, E> Unpin for TryJoinFuture<L, E> {}

impl<L: TryJoinBranches<E>, E> Future for TryJoinFuture<L, E> {
  type Output = Result<L::Outputs, E>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    assert!(!this.done, "TryJoinFuture polled after completion");
    let poll_result = match this.branches.as_mut() {
      Some(branches) => branches.poll_try_join(cx),
      None => Ok(None),
    };
    match poll_result {
      Err(payload) => this.abort_with_primary(payload),
      Ok(Some(error)) => {
        let mut primary = None;
        this.dispose_capturing(&mut primary);
        this.done = true;
        if let Some(payload) = primary {
          drop_contained(error);
          panic::resume_unwind(payload);
        }
        Poll::Ready(Err(error))
      }
      Ok(None) => {
        let complete = this
          .branches
          .as_ref()
          .is_some_and(TryJoinBranches::complete);
        if !complete {
          return Poll::Pending;
        }
        let outputs = match this.branches.as_mut() {
          Some(branches) => branches.take_outputs(),
          None => unreachable!("try-join branches remain until outputs are taken"),
        };
        this.done = true;
        Poll::Ready(Ok(outputs))
      }
    }
  }
}

impl<L: TryJoinBranches<E>, E> Drop for TryJoinFuture<L, E> {
  fn drop(&mut self) {
    let mut primary = None;
    self.dispose_capturing(&mut primary);
    propagate_drop_panic(primary);
  }
}

fn drop_capturing<T>(value: T) -> Option<PanicPayload> {
  panic::catch_unwind(AssertUnwindSafe(|| drop(value))).err()
}

#[doc(hidden)]
#[macro_export]
macro_rules! __allocatbelt_join_branches {
  ([];) => { $crate::runtime::concurrency_macros::Nil };
  ([]; $($branches:tt)+) => {
    compile_error!("join! supports at most sixteen branches")
  };
  ([$($fuel:tt)*];) => { $crate::runtime::concurrency_macros::Nil };
  ([$fuel:tt $($remaining:tt)*]; $future:expr $(, $rest:expr)*) => {
    $crate::runtime::concurrency_macros::JoinNode::new(
      $crate::runtime::concurrency_macros::JoinSlot::new($future),
      $crate::__allocatbelt_join_branches!([$($remaining)*]; $($rest),*),
    )
  };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __allocatbelt_try_join_branches {
  ([];) => { $crate::runtime::concurrency_macros::Nil };
  ([]; $($branches:tt)+) => {
    compile_error!("try_join! supports at most sixteen branches")
  };
  ([$($fuel:tt)*];) => { $crate::runtime::concurrency_macros::Nil };
  ([$fuel:tt $($remaining:tt)*]; $future:expr $(, $rest:expr)*) => {
    $crate::runtime::concurrency_macros::TryJoinNode::new(
      $crate::runtime::concurrency_macros::TryJoinSlot::new($future),
      $crate::__allocatbelt_try_join_branches!([$($remaining)*]; $($rest),*),
    )
  };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __allocatbelt_select_branches {
  ([];) => { $crate::runtime::concurrency_macros::Nil };
  ([]; $($branches:tt)+) => {
    compile_error!("select! supports at most sixteen branches")
  };
  ([$($fuel:tt)*];) => { $crate::runtime::concurrency_macros::Nil };
  ([$fuel:tt $($remaining:tt)*]; ($pattern:pat = $future:expr $(, if $enabled:expr)? => $handler:expr) $(, $rest:tt)*) => {
    $crate::runtime::concurrency_macros::Cons::new(
      $crate::runtime::concurrency_macros::Branch::new(
        $future,
        true $(&& $enabled)?,
      ),
      $crate::__allocatbelt_select_branches!([$($remaining)*]; $($rest),*),
    )
  };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __allocatbelt_select_dispatch {
  ($winner:expr; ($pattern:pat = $future:expr $(, if $enabled:expr)? => $handler:expr)) => {
    match $winner {
      $crate::runtime::concurrency_macros::Either::Left(__output) => {
        match __output {
          $pattern => $handler,
        }
      }
      $crate::runtime::concurrency_macros::Either::Right(__unreachable) => {
        match __unreachable {}
      }
    }
  };
  ($winner:expr; ($pattern:pat = $future:expr $(, if $enabled:expr)? => $handler:expr), $($rest:tt)+) => {
    match $winner {
      $crate::runtime::concurrency_macros::Either::Left(__output) => {
        match __output {
          $pattern => $handler,
        }
      }
      $crate::runtime::concurrency_macros::Either::Right(__tail) => {
        $crate::__allocatbelt_select_dispatch!(__tail; $($rest)+)
      }
    }
  };
}

/// Joins two to sixteen heterogeneous futures and returns their outputs as a
/// flat tuple in source order.
///
/// The futures are polled in source order, once each per outer poll while
/// pending. Completed futures are not polled again. A polling or destructor
/// panic follows the cleanup behavior of [`super::concurrency::join2`].
/// Branches are evaluated when the returned future is first polled.
///
/// # Example
///
/// ```no_run
/// # #[cfg(all(feature = "runtime", target_os = "linux"))]
/// # async fn example() {
/// let (number, text) = allocatbelt::join!(async { 7 }, async { String::from("ready") }).await;
/// assert_eq!(number, 7);
/// assert_eq!(text, "ready");
/// # }
/// ```
#[macro_export]
macro_rules! join {
  ($f0:expr, $f1:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, ())) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1),
      ).await;
      (__o0, __o1)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, ()))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2),
      ).await;
      (__o0, __o1, __o2)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, ())))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3),
      ).await;
      (__o0, __o1, __o2, __o3)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, ()))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4),
      ).await;
      (__o0, __o1, __o2, __o3, __o4)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, ())))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5),
      ).await;
      (__o0, __o1, __o2, __o3, __o4, __o5)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, ()))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6),
      ).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, ())))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7),
      ).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, ()))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8),
      ).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, ())))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9),
      ).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, ()))))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10),
      ).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, ())))))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11),
      ).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, ()))))))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12),
      ).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr, $f13:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, (__o13, ())))))))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12, $f13),
      ).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12, __o13)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr, $f13:expr, $f14:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, (__o13, (__o14, ()))))))))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12, $f13, $f14),
      ).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12, __o13, __o14)
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr, $f13:expr, $f14:expr, $f15:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, (__o13, (__o14, (__o15, ())))))))))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12, $f13, $f14, $f15),
      ).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12, __o13, __o14, __o15)
    }
  }};
  ($($branches:expr),+ $(,)?) => {
    compile_error!("join! requires between two and sixteen branches")
  };
}

/// Joins heterogeneous `Result` futures, returning the first observed error.
/// Successful values are returned as a flat tuple in source order. All
/// branches share one error type. Branches are evaluated when the returned
/// future is first polled, and each partial value is retained and disposed
/// independently before an error is returned.
#[macro_export]
macro_rules! try_join {
  ($f0:expr, $f1:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1),
      ).await.map(|(__o0, (__o1, ()))| (__o0, __o1))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2),
      ).await.map(|(__o0, (__o1, (__o2, ())))| (__o0, __o1, __o2))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3),
      ).await.map(|(__o0, (__o1, (__o2, (__o3, ()))))| (__o0, __o1, __o2, __o3))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4),
      ).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, ())))))| (__o0, __o1, __o2, __o3, __o4))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5),
      ).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, ()))))))| (__o0, __o1, __o2, __o3, __o4, __o5))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6),
      ).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, ())))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7),
      ).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, ()))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8),
      ).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, ())))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9),
      ).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, ()))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10),
      ).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, ())))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11),
      ).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, ()))))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12),
      ).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, ())))))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr, $f13:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12, $f13),
      ).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, (__o13, ()))))))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12, __o13))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr, $f13:expr, $f14:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12, $f13, $f14),
      ).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, (__o13, (__o14, ())))))))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12, __o13, __o14))
    }
  }};
  ($f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr, $f13:expr, $f14:expr, $f15:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12, $f13, $f14, $f15),
      ).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, (__o13, (__o14, (__o15, ()))))))))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12, __o13, __o14, __o15))
    }
  }};
  ($($branches:expr),+ $(,)?) => {
    compile_error!("try_join! requires between two and sixteen branches")
  };
}

/// Races two to sixteen heterogeneous futures.
///
/// Each branch maps its own output to a common result type:
///
/// ```no_run
/// # #[cfg(all(feature = "runtime", target_os = "linux"))]
/// # async fn example() {
/// use allocatbelt::runtime::concurrency_macros::select;
/// let selected = select! {
///   biased;
///   [
///     (value = async { 4 }, if true => value),
///     (text = async { String::from("ready") } => text.len()),
///   ];
///   else => 0,
/// }.await;
/// assert!(selected == 4 || selected == 5);
/// # }
/// ```
///
/// Branch futures and enabled flags are evaluated once when the returned
/// future is first polled. Disabled futures are owned and never polled; they
/// are disposed when selection completes or is canceled. On a winner, every
/// branch future is disposed before the selected handler runs.
/// `round_robin;` rotates priority among enabled branches by their original
/// source indices after each pending poll. The mandatory `else` arm runs
/// after cleanup when every branch is disabled. Handler expressions are match
/// arms in the enclosing async future; captures they use follow that future's
/// lifetime and are not separately dropped at selection time. Patterns must
/// be irrefutable, and all handlers must produce one common type. For each
/// branch, the future expression is evaluated before its enabled guard; branch
/// expressions and guards run in source order. A panic during this construction
/// phase follows ordinary Rust cleanup until the complete branch set is owned.
#[macro_export]
macro_rules! select {
  (
    biased;
    [ $( $branch:tt, )+ ];
    else => $else:expr $(,)?
  ) => {{
    async move {
      let mut __branches = $crate::runtime::concurrency_macros::BranchSet::new(
        $crate::__allocatbelt_select_branches!(
          [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16];
          $( $branch ),+
        ),
      );
      if !__branches.any_enabled() {
        __branches.dispose();
        return $else;
      }
      let __rotate = false;
      let mut __start = 0usize;
      let __winner = ::std::future::poll_fn(|__cx| {
        for __offset in 0..__branches.branch_count() {
          let __index = (__start + __offset) % __branches.branch_count();
          match __branches.poll_at(__index, __cx) {
            ::std::task::Poll::Ready(Err(__payload)) => {
              __branches.dispose_after_poll_panic(__payload);
            }
            ::std::task::Poll::Ready(Ok(Some(__winner))) => {
              return ::std::task::Poll::Ready(__branches.dispose_before_winner(__winner));
            }
            ::std::task::Poll::Ready(Ok(None)) | ::std::task::Poll::Pending => {}
          }
        }
        if __rotate {
          __start = __branches.next_enabled(__start);
        }
        ::std::task::Poll::Pending
      }).await;
      $crate::__allocatbelt_select_dispatch!(__winner; $( $branch ),+)
    }
  }};
  (
    round_robin;
    [ $( $branch:tt, )+ ];
    else => $else:expr $(,)?
  ) => {{
    async move {
      let mut __branches = $crate::runtime::concurrency_macros::BranchSet::new(
        $crate::__allocatbelt_select_branches!(
          [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16];
          $( $branch ),+
        ),
      );
      if !__branches.any_enabled() {
        __branches.dispose();
        return $else;
      }
      let __rotate = true;
      let mut __start = __branches.first_enabled_from(0);
      let __winner = ::std::future::poll_fn(|__cx| {
        for __offset in 0..__branches.branch_count() {
          let __index = (__start + __offset) % __branches.branch_count();
          match __branches.poll_at(__index, __cx) {
            ::std::task::Poll::Ready(Err(__payload)) => {
              __branches.dispose_after_poll_panic(__payload);
            }
            ::std::task::Poll::Ready(Ok(Some(__winner))) => {
              return ::std::task::Poll::Ready(__branches.dispose_before_winner(__winner));
            }
            ::std::task::Poll::Ready(Ok(None)) | ::std::task::Poll::Pending => {}
          }
        }
        if __rotate {
          __start = __branches.next_enabled(__start);
        }
        ::std::task::Poll::Pending
      }).await;
      $crate::__allocatbelt_select_dispatch!(__winner; $( $branch ),+)
    }
  }};
  ($($tokens:tt)*) => {
    compile_error!("select! requires biased or round_robin, two to sixteen branches, and an else arm")
  };
}

#[cfg(test)]
mod tests {
  use std::cell::Cell;
  use std::future::{Future, poll_fn};
  use std::marker::PhantomPinned;
  use std::pin::Pin;
  use std::process::Command;
  use std::rc::Rc;
  use std::task::{Context, Poll, Waker};

  use super::{Branch, BranchSet, Cons, Nil};

  fn noop_waker() -> Waker {
    (*Waker::noop()).clone()
  }

  fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    let mut cx = Context::from_waker(waker);
    future.poll(&mut cx)
  }

  struct PendingDrop(Rc<Cell<usize>>);

  impl Future for PendingDrop {
    type Output = usize;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
      Poll::Pending
    }
  }

  impl Drop for PendingDrop {
    fn drop(&mut self) {
      self.0.set(self.0.get() + 1);
    }
  }

  struct CountPoll {
    polls: Rc<Cell<usize>>,
    drops: Rc<Cell<usize>>,
  }

  impl Future for CountPoll {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
      self.polls.set(self.polls.get() + 1);
      Poll::Pending
    }
  }

  impl Drop for CountPoll {
    fn drop(&mut self) {
      self.drops.set(self.drops.get() + 1);
    }
  }

  struct PinnedFuture {
    _pin: PhantomPinned,
    ready: bool,
  }

  impl Future for PinnedFuture {
    type Output = &'static str;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
      if self.ready {
        Poll::Ready("pinned")
      } else {
        Poll::Pending
      }
    }
  }

  #[test]
  fn heterogeneous_join_and_try_join_flatten_and_borrow() {
    let borrowed = String::from("borrowed");
    let borrowed_ref = borrowed.as_str();
    let joined = async {
      let (number, text, tuple) = crate::join!(
        std::future::ready(3usize),
        std::future::ready(borrowed_ref),
        std::future::ready((true, 8u8)),
      )
      .await;
      assert_eq!((number, text, tuple), (3, "borrowed", (true, 8)));
      let result: Result<(usize, String), &'static str> = crate::try_join!(
        std::future::ready(Ok::<_, &'static str>(9usize)),
        std::future::ready(Ok::<_, &'static str>(String::from("ok"))),
      )
      .await;
      assert_eq!(result, Ok((9, String::from("ok"))));
    };
    let mut joined = std::pin::pin!(joined);
    assert!(poll(joined.as_mut(), &noop_waker()).is_ready());
  }

  #[test]
  fn all_macros_accept_sixteen_branches_and_keep_send() {
    fn assert_send<T: Send>(_: &T) {}

    let joined = crate::join!(
      std::future::ready(0usize),
      std::future::ready(1usize),
      std::future::ready(2usize),
      std::future::ready(3usize),
      std::future::ready(4usize),
      std::future::ready(5usize),
      std::future::ready(6usize),
      std::future::ready(7usize),
      std::future::ready(8usize),
      std::future::ready(9usize),
      std::future::ready(10usize),
      std::future::ready(11usize),
      std::future::ready(12usize),
      std::future::ready(13usize),
      std::future::ready(14usize),
      std::future::ready(15usize),
    );
    assert_send(&joined);

    let tried = crate::try_join!(
      std::future::ready(Ok::<_, ()>(0usize)),
      std::future::ready(Ok::<_, ()>(1usize)),
      std::future::ready(Ok::<_, ()>(2usize)),
      std::future::ready(Ok::<_, ()>(3usize)),
      std::future::ready(Ok::<_, ()>(4usize)),
      std::future::ready(Ok::<_, ()>(5usize)),
      std::future::ready(Ok::<_, ()>(6usize)),
      std::future::ready(Ok::<_, ()>(7usize)),
      std::future::ready(Ok::<_, ()>(8usize)),
      std::future::ready(Ok::<_, ()>(9usize)),
      std::future::ready(Ok::<_, ()>(10usize)),
      std::future::ready(Ok::<_, ()>(11usize)),
      std::future::ready(Ok::<_, ()>(12usize)),
      std::future::ready(Ok::<_, ()>(13usize)),
      std::future::ready(Ok::<_, ()>(14usize)),
      std::future::ready(Ok::<_, ()>(15usize)),
    );
    assert_send(&tried);

    let selected = crate::select! {
      biased;
      [
        (_value = std::future::ready(0usize) => 0usize),
        (_value = std::future::ready(1usize) => 1usize),
        (_value = std::future::ready(2usize) => 2usize),
        (_value = std::future::ready(3usize) => 3usize),
        (_value = std::future::ready(4usize) => 4usize),
        (_value = std::future::ready(5usize) => 5usize),
        (_value = std::future::ready(6usize) => 6usize),
        (_value = std::future::ready(7usize) => 7usize),
        (_value = std::future::ready(8usize) => 8usize),
        (_value = std::future::ready(9usize) => 9usize),
        (_value = std::future::ready(10usize) => 10usize),
        (_value = std::future::ready(11usize) => 11usize),
        (_value = std::future::ready(12usize) => 12usize),
        (_value = std::future::ready(13usize) => 13usize),
        (_value = std::future::ready(14usize) => 14usize),
        (_value = std::future::ready(15usize) => 15usize),
      ];
      else => 99usize,
    };
    assert_send(&selected);

    let mut selected = std::pin::pin!(selected);
    assert_eq!(poll(selected.as_mut(), &noop_waker()), Poll::Ready(0));
    let mut joined = std::pin::pin!(crate::join!(
      std::future::ready(0usize),
      std::future::ready(1usize),
      std::future::ready(2usize),
      std::future::ready(3usize),
      std::future::ready(4usize),
      std::future::ready(5usize),
      std::future::ready(6usize),
      std::future::ready(7usize),
      std::future::ready(8usize),
      std::future::ready(9usize),
      std::future::ready(10usize),
      std::future::ready(11usize),
      std::future::ready(12usize),
      std::future::ready(13usize),
      std::future::ready(14usize),
      std::future::ready(15usize),
    ));
    let Poll::Ready((v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15)) =
      poll(joined.as_mut(), &noop_waker())
    else {
      panic!("join did not complete")
    };
    assert_eq!(
      [
        v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15
      ],
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
    let mut tried = std::pin::pin!(crate::try_join!(
      std::future::ready(Ok::<_, ()>(0usize)),
      std::future::ready(Ok::<_, ()>(1usize)),
      std::future::ready(Ok::<_, ()>(2usize)),
      std::future::ready(Ok::<_, ()>(3usize)),
      std::future::ready(Ok::<_, ()>(4usize)),
      std::future::ready(Ok::<_, ()>(5usize)),
      std::future::ready(Ok::<_, ()>(6usize)),
      std::future::ready(Ok::<_, ()>(7usize)),
      std::future::ready(Ok::<_, ()>(8usize)),
      std::future::ready(Ok::<_, ()>(9usize)),
      std::future::ready(Ok::<_, ()>(10usize)),
      std::future::ready(Ok::<_, ()>(11usize)),
      std::future::ready(Ok::<_, ()>(12usize)),
      std::future::ready(Ok::<_, ()>(13usize)),
      std::future::ready(Ok::<_, ()>(14usize)),
      std::future::ready(Ok::<_, ()>(15usize)),
    ));
    let Poll::Ready(Ok((v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15))) =
      poll(tried.as_mut(), &noop_waker())
    else {
      panic!("try_join did not complete")
    };
    assert_eq!(
      [
        v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15
      ],
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
  }

  #[test]
  fn select_is_biased_and_drops_owned_loser_before_handler() {
    let drops = Rc::new(Cell::new(0));
    let branch_drops = Rc::clone(&drops);
    let observed = Rc::clone(&drops);
    let future = select! {
      biased;
      [
      (value = std::future::ready(4usize) => {
        assert_eq!(observed.get(), 1);
        async { value + Rc::strong_count(&observed) }.await
      }),
      (_value = PendingDrop(branch_drops) => Rc::strong_count(&observed)),
      ];
      else => 0,
    };
    let mut future = std::pin::pin!(future);
    assert_eq!(poll(future.as_mut(), &noop_waker()), Poll::Ready(6));
    assert_eq!(drops.get(), 1);
  }

  #[test]
  fn losing_handler_capture_lives_through_winner_handler_and_future_drop() {
    struct Capture(Rc<Cell<bool>>);
    impl Drop for Capture {
      fn drop(&mut self) {
        self.0.set(true);
      }
    }

    let released = Rc::new(Cell::new(false));
    let observed = Rc::clone(&released);
    let handler_polls = Rc::new(Cell::new(0));
    let polls = Rc::clone(&handler_polls);
    let capture = Capture(Rc::clone(&released));
    {
      let future = select! {
        biased;
        [
        (value = std::future::ready(7usize) => async {
          std::future::poll_fn(|_| {
            let count = polls.get();
            polls.set(count + 1);
            if count == 0 { Poll::Pending } else { Poll::Ready(()) }
          }).await;
          assert!(!observed.get());
          value
        }.await),
        (_value = std::future::pending::<usize>() => {
          let _ = &capture;
          0usize
        }),
        ];
        else => 0usize,
      };
      let mut future = std::pin::pin!(future);
      assert!(poll(future.as_mut(), &noop_waker()).is_pending());
      assert!(!released.get());
      assert_eq!(poll(future.as_mut(), &noop_waker()), Poll::Ready(7));
    }
    assert!(released.get());
  }

  #[test]
  fn disabled_future_is_constructed_dropped_and_never_polled() {
    let drops = Rc::new(Cell::new(0));
    let polls = Rc::new(Cell::new(0));
    let branch_drops = Rc::clone(&drops);
    let branch_polls = Rc::clone(&polls);
    let enabled = false;
    let future = select! {
      biased;
      [
      (_value = CountPoll { polls: branch_polls, drops: branch_drops }, if enabled => 1),
      (value = std::future::ready("chosen") => value.len()),
      ];
      else => 0,
    };
    let mut future = std::pin::pin!(future);
    assert_eq!(poll(future.as_mut(), &noop_waker()), Poll::Ready(6));
    assert_eq!(drops.get(), 1);
    assert_eq!(polls.get(), 0);
  }

  #[test]
  fn all_disabled_runs_else_after_cleanup() {
    let drops = Rc::new(Cell::new(0));
    let future = select! {
      round_robin;
      [
      (_value = PendingDrop(Rc::clone(&drops)), if false => 1),
      (_text = std::future::ready("unused"), if false => 2),
      ];
      else => drops.get(),
    };
    let mut future = std::pin::pin!(future);
    assert_eq!(poll(future.as_mut(), &noop_waker()), Poll::Ready(1));
  }

  #[test]
  fn round_robin_advances_over_enabled_original_indices() {
    let order = Rc::new(std::cell::RefCell::new(Vec::new()));
    let p0 = Rc::clone(&order);
    let p1 = Rc::clone(&order);
    let p2 = Rc::clone(&order);
    let future = select! {
      round_robin;
      [
      (_a = poll_fn(move |_| { p0.borrow_mut().push(0); Poll::<usize>::Pending }) => 0),
      (_b = poll_fn(move |_| { p1.borrow_mut().push(1); Poll::<usize>::Pending }) => 1),
      (_c = poll_fn(move |_| { p2.borrow_mut().push(2); Poll::<usize>::Pending }) => 2),
      ];
      else => 3,
    };
    let mut future = std::pin::pin!(future);
    let waker = noop_waker();
    assert!(poll(future.as_mut(), &waker).is_pending());
    assert_eq!(*order.borrow(), [0, 1, 2]);
    assert!(poll(future.as_mut(), &waker).is_pending());
    assert_eq!(*order.borrow(), [0, 1, 2, 1, 2, 0]);
    assert!(poll(future.as_mut(), &waker).is_pending());
    assert_eq!(*order.borrow(), [0, 1, 2, 1, 2, 0, 2, 0, 1]);
  }

  #[test]
  fn round_robin_leading_disabled_branch_does_not_repeat_priority() {
    let order = Rc::new(std::cell::RefCell::new(Vec::new()));
    let p1 = Rc::clone(&order);
    let p2 = Rc::clone(&order);
    let future = select! {
      round_robin;
      [
      (_disabled = std::future::ready(()), if false => 0),
      (_one = poll_fn(move |_| { p1.borrow_mut().push(1); Poll::<usize>::Pending }) => 1),
      (_two = poll_fn(move |_| { p2.borrow_mut().push(2); Poll::<usize>::Pending }) => 2),
      ];
      else => 3,
    };
    let mut future = std::pin::pin!(future);
    let waker = noop_waker();
    assert!(poll(future.as_mut(), &waker).is_pending());
    assert_eq!(*order.borrow(), [1, 2]);
    assert!(poll(future.as_mut(), &waker).is_pending());
    assert_eq!(*order.borrow(), [1, 2, 2, 1]);
  }

  #[test]
  fn select_accepts_borrowed_non_send_non_unpin_future() {
    let text = String::from("borrowed");
    let text_ref = text.as_str();
    let future = select! {
      biased;
      [
      (value = std::future::ready(text_ref) => value),
      (value = PinnedFuture { _pin: PhantomPinned, ready: true } => value),
      ];
      else => "none",
    };
    let mut future = std::pin::pin!(future);
    assert_eq!(
      poll(future.as_mut(), &noop_waker()),
      Poll::Ready("borrowed")
    );
  }

  struct PanicOnDrop;
  struct PanicValue;

  impl Drop for PanicValue {
    fn drop(&mut self) {
      panic!("output drop panic");
    }
  }

  impl Future for PanicOnDrop {
    type Output = PanicValue;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
      Poll::Pending
    }
  }

  struct PanicOnPoll(Rc<Cell<usize>>);
  impl Future for PanicOnPoll {
    type Output = usize;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
      panic!("poll panic");
    }
  }
  impl Drop for PanicOnPoll {
    fn drop(&mut self) {
      self.0.set(self.0.get() + 1);
    }
  }

  #[test]
  fn polling_panic_cleans_all_branches_before_resuming() {
    let drops = Rc::new(Cell::new(0));
    let branch_drops = Rc::clone(&drops);
    let future = select! {
      biased;
      [
      (_value = PanicOnPoll(Rc::clone(&branch_drops)) => 1),
      (_value = PendingDrop(branch_drops) => 2),
      ];
      else => 0,
    };
    let mut future = std::pin::pin!(future);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let _ = poll(future.as_mut(), &noop_waker());
    }));
    assert!(result.is_err());
    assert_eq!(drops.get(), 2);
  }
  impl Drop for PanicOnDrop {
    fn drop(&mut self) {
      panic!("drop panic");
    }
  }

  #[test]
  fn loser_drop_panic_is_resumed_after_winner_output_is_contained() {
    let future = select! {
      biased;
      [
      (value = std::future::ready(PanicValue) => value),
      (_value = PanicOnDrop => PanicValue),
      ];
      else => PanicValue,
    };
    let mut future = std::pin::pin!(future);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let _ = poll(future.as_mut(), &noop_waker());
    }));
    assert!(result.is_err());
  }

  #[test]
  fn dropping_pending_selection_cleans_every_future_after_a_drop_panic() {
    let drops = Rc::new(Cell::new(0));
    let normal = Rc::clone(&drops);
    let future = select! {
      biased;
      [
      (_value = PanicOnDrop => 1),
      (_value = PendingDrop(normal) => 2),
      ];
      else => 0,
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let mut future = std::pin::pin!(future);
      assert!(poll(future.as_mut(), &noop_waker()).is_pending());
    }));
    assert!(result.is_err());
    assert_eq!(drops.get(), 1);
  }

  #[test]
  fn internal_list_disposes_all_even_when_destructors_panic() {
    let drops = Rc::new(Cell::new(0));
    let list = Cons::new(
      Branch::new(PanicOnDrop, true),
      Cons::new(Branch::new(PendingDrop(Rc::clone(&drops)), true), Nil),
    );
    let mut set = BranchSet::new(list);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| set.dispose()));
    assert!(result.is_err());
    assert_eq!(drops.get(), 1);
  }

  struct PanicOutput(Rc<Cell<usize>>);

  impl Drop for PanicOutput {
    fn drop(&mut self) {
      self.0.set(self.0.get() + 1);
      panic!("output drop panic");
    }
  }

  struct ReadyPanicOutput(Rc<Cell<usize>>);

  impl Future for ReadyPanicOutput {
    type Output = PanicOutput;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
      Poll::Ready(PanicOutput(Rc::clone(&self.0)))
    }
  }

  struct PendingThenPanic<O> {
    first_poll: bool,
    _output: std::marker::PhantomData<fn() -> O>,
  }

  impl<O> Future for PendingThenPanic<O> {
    type Output = O;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
      if self.first_poll {
        self.first_poll = false;
        Poll::Pending
      } else {
        panic!("poll panic after pending")
      }
    }
  }

  struct PendingThenError {
    first_poll: bool,
  }

  impl Future for PendingThenError {
    type Output = Result<PanicOutput, &'static str>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
      if self.first_poll {
        self.first_poll = false;
        Poll::Pending
      } else {
        Poll::Ready(Err("failure"))
      }
    }
  }

  fn catch_one_poll_and_drop<F: Future>(future: F) -> Result<(), Box<dyn std::any::Any + Send>> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let mut future = std::pin::pin!(future);
      let _ = poll(future.as_mut(), &noop_waker());
    }))
  }

  fn catch_two_polls_and_drop<F: Future>(future: F) -> Result<(), Box<dyn std::any::Any + Send>> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let mut future = std::pin::pin!(future);
      let waker = noop_waker();
      assert!(poll(future.as_mut(), &waker).is_pending());
      let _ = poll(future.as_mut(), &waker);
    }))
  }

  #[test]
  fn multiple_panicking_outputs_are_contained_in_subprocesses() {
    const CHILD: &str = "ALLOCATBELT_MACRO_CLEANUP_CASE";
    const TEST: &str = "runtime::concurrency_macros::tests::multiple_panicking_outputs_are_contained_in_subprocesses";
    let Ok(case) = std::env::var(CHILD) else {
      let executable = std::env::current_exe().unwrap();
      for case in [
        "join_pending",
        "join_poll_panic",
        "try_join_pending",
        "try_join_error",
        "try_join_poll_panic",
      ] {
        let output = Command::new(&executable)
          .arg("--exact")
          .arg(TEST)
          .arg("--nocapture")
          .env(CHILD, case)
          .output()
          .unwrap();
        assert!(
          output.status.success(),
          "cleanup child {case} failed: {}{}",
          String::from_utf8_lossy(&output.stdout),
          String::from_utf8_lossy(&output.stderr),
        );
      }
      return;
    };

    let drops = Rc::new(Cell::new(0));
    let result = match case.as_str() {
      "join_pending" => {
        let first = Rc::clone(&drops);
        let second = Rc::clone(&drops);
        catch_one_poll_and_drop(crate::join!(
          std::future::pending::<PanicOutput>(),
          ReadyPanicOutput(first),
          ReadyPanicOutput(second),
        ))
      }
      "join_poll_panic" => {
        let first = Rc::clone(&drops);
        let second = Rc::clone(&drops);
        catch_two_polls_and_drop(crate::join!(
          PendingThenPanic::<PanicOutput> {
            first_poll: true,
            _output: std::marker::PhantomData,
          },
          ReadyPanicOutput(first),
          ReadyPanicOutput(second),
        ))
      }
      "try_join_pending" => {
        let first = Rc::clone(&drops);
        let second = Rc::clone(&drops);
        catch_one_poll_and_drop(crate::try_join!(
          std::future::pending::<Result<PanicOutput, &'static str>>(),
          async move { Ok::<_, &'static str>(ReadyPanicOutput(first).await) },
          async move { Ok::<_, &'static str>(ReadyPanicOutput(second).await) },
        ))
      }
      "try_join_error" => {
        let first = Rc::clone(&drops);
        let second = Rc::clone(&drops);
        catch_two_polls_and_drop(crate::try_join!(
          PendingThenError { first_poll: true },
          async move { Ok::<_, &'static str>(ReadyPanicOutput(first).await) },
          async move { Ok::<_, &'static str>(ReadyPanicOutput(second).await) },
        ))
      }
      "try_join_poll_panic" => {
        let first = Rc::clone(&drops);
        let second = Rc::clone(&drops);
        catch_two_polls_and_drop(crate::try_join!(
          PendingThenPanic::<Result<PanicOutput, &'static str>> {
            first_poll: true,
            _output: std::marker::PhantomData,
          },
          async move { Ok::<_, &'static str>(ReadyPanicOutput(first).await) },
          async move { Ok::<_, &'static str>(ReadyPanicOutput(second).await) },
        ))
      }
      other => panic!("unknown cleanup child case {other}"),
    };
    assert!(result.is_err(), "cleanup case {case} should resume a panic");
    if case == "join_poll_panic" || case == "try_join_poll_panic" {
      assert_eq!(
        result
          .as_ref()
          .err()
          .and_then(|payload| payload.downcast_ref::<&str>())
          .copied(),
        Some("poll panic after pending"),
        "cleanup must preserve the polling panic as primary",
      );
    }
    assert_eq!(
      drops.get(),
      2,
      "cleanup case {case} must dispose both outputs"
    );
  }
}
