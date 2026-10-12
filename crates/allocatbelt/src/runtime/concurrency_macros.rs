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
type BranchPoll<T> = Poll<Result<Option<(usize, T)>, PanicPayload>>;

/// The nested winner representation used internally by [`select!`].
#[doc(hidden)]
pub enum Either<L, R> {
  Left(L),
  Right(R),
}

/// The initial priority mode for the heterogeneous `select!` macro.
#[doc(hidden)]
pub enum SelectionStart {
  Biased,
  RoundRobin,
  Randomized(super::concurrency::SelectionRng),
}

/// Empty tail for the internal heterogeneous branch list.
#[doc(hidden)]
pub struct Nil;

/// One future owned by a selection branch.
#[doc(hidden)]
pub struct Branch<F: Future> {
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
    match panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
      Ok(Poll::Pending) => Ok(Poll::Pending),
      Ok(Poll::Ready(output)) => {
        self.enabled = false;
        if let Some(payload) = drop_capturing(self.future.take()) {
          drop_contained(output);
          Err(payload)
        } else {
          Ok(Poll::Ready(output))
        }
      }
      Err(payload) => Err(payload),
    }
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
  fn poll_at(&mut self, index: usize, cx: &mut Context<'_>) -> BranchPoll<Self::Winner>;
  fn disable_at(&mut self, index: usize);
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

  fn enabled_count(&self) -> usize {
    (0..Self::LEN)
      .filter(|index| self.enabled_at(*index))
      .count()
  }

  fn enabled_index(&self, rank: usize) -> usize {
    (0..Self::LEN)
      .filter(|index| self.enabled_at(*index))
      .nth(rank)
      .unwrap_or(0)
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

  fn poll_at(&mut self, index: usize, cx: &mut Context<'_>) -> BranchPoll<Self::Winner> {
    if index == 0 {
      if !self.head.enabled() {
        return Poll::Ready(Ok(None));
      }
      return match self.head.poll(cx) {
        Ok(Poll::Pending) => Poll::Pending,
        Ok(Poll::Ready(output)) => Poll::Ready(Ok(Some((0, Either::Left(output))))),
        Err(payload) => Poll::Ready(Err(payload)),
      };
    }
    self.tail.poll_at(index - 1, cx).map(|result| {
      result.map(|winner| {
        winner.map(|(winner_index, output)| (winner_index + 1, Either::Right(output)))
      })
    })
  }

  fn disable_at(&mut self, index: usize) {
    if index == 0 {
      self.head.enabled = false;
    } else {
      self.tail.disable_at(index - 1);
    }
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

  fn poll_at(&mut self, _index: usize, _cx: &mut Context<'_>) -> BranchPoll<Self::Winner> {
    Poll::Ready(Ok(None))
  }

  fn disable_at(&mut self, _index: usize) {}

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

  /// Returns whether one original source branch remains enabled.
  #[doc(hidden)]
  pub fn any_enabled_at(&self, index: usize) -> bool {
    self
      .branches
      .as_ref()
      .is_some_and(|branches| branches.enabled_at(index))
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
  pub fn poll_at(&mut self, index: usize, cx: &mut Context<'_>) -> BranchPoll<L::Winner> {
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

  /// Chooses one enabled source branch using `rng`.
  #[doc(hidden)]
  pub fn random_start(&self, rng: &mut super::concurrency::SelectionRng) -> usize {
    let Some(branches) = self.branches.as_ref() else {
      return 0;
    };
    let count = branches.enabled_count();
    if count == 0 {
      return 0;
    }
    branches.enabled_index(rng.index(count))
  }

  /// Resolves the first enabled branch and whether subsequent pending polls
  /// should rotate priority.
  #[doc(hidden)]
  pub fn initial_start(&self, policy: &mut SelectionStart) -> (bool, usize) {
    match policy {
      SelectionStart::Biased => (false, self.first_enabled_from(0)),
      SelectionStart::RoundRobin => (true, self.first_enabled_from(0)),
      SelectionStart::Randomized(rng) => (true, self.random_start(rng)),
    }
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
  pub fn dispose_before_winner<T>(&mut self, winner: T) -> T {
    let mut primary = None;
    self.dispose_capturing(&mut primary);
    if let Some(payload) = primary {
      drop_contained(winner);
      panic::resume_unwind(payload);
    }
    winner
  }

  /// Disposes all branch futures without resuming a cleanup panic until the
  /// caller has finished leaving the pattern-match scope.
  #[doc(hidden)]
  pub fn dispose_before_winner_capturing<T>(&mut self, winner: T) -> Result<T, PanicPayload> {
    let mut primary = None;
    self.dispose_capturing(&mut primary);
    if let Some(payload) = primary {
      drop_contained(winner);
      Err(payload)
    } else {
      Ok(winner)
    }
  }

  /// Preserves the first selection failure while containing dispatch-state
  /// and branch destructor panics.
  #[doc(hidden)]
  pub fn resolve_dispatch_failures(
    &mut self,
    primary: Option<PanicPayload>,
    poll_panic: Option<PanicPayload>,
    dispatcher_drop_panic: Option<PanicPayload>,
  ) -> Option<PanicPayload> {
    let mut primary = primary;
    if primary.is_none() {
      primary = poll_panic;
    } else {
      drop_contained(poll_panic);
    }
    if primary.is_none() {
      primary = dispatcher_drop_panic;
    } else {
      drop_contained(dispatcher_drop_panic);
    }
    if primary.is_some() {
      let mut ignored = None;
      self.dispose_capturing(&mut ignored);
      drop_contained(ignored);
    }
    primary
  }

  /// Disables a completed branch whose output did not match its pattern.
  #[doc(hidden)]
  pub fn disable_at(&mut self, index: usize) {
    if let Some(branches) = self.branches.as_mut() {
      branches.disable_at(index);
    }
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

/// Poll-order policy for [`join!`] and [`try_join!`].
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoinPolicy {
  /// Poll inputs in source order on every call.
  Biased,
  /// Rotate the first polled input after each pending call.
  RoundRobin,
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
  fn poll_join_at(&mut self, index: usize, cx: &mut Context<'_>) -> Result<(), PanicPayload>;
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

  fn poll_join_at(&mut self, index: usize, cx: &mut Context<'_>) -> Result<(), PanicPayload> {
    if index == 0 {
      self.head.poll(cx)
    } else {
      self.tail.poll_join_at(index - 1, cx)
    }
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
  fn poll_join_at(&mut self, _index: usize, _cx: &mut Context<'_>) -> Result<(), PanicPayload> {
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
  policy: JoinPolicy,
  next_start: usize,
  done: bool,
}

impl<L: JoinBranches> JoinFuture<L> {
  /// Owns the prepared heterogeneous input list.
  #[doc(hidden)]
  pub fn new(branches: L) -> Self {
    Self::with_policy(branches, JoinPolicy::RoundRobin)
  }

  /// Owns a prepared input list and its poll-order policy.
  #[doc(hidden)]
  pub fn with_policy(branches: L, policy: JoinPolicy) -> Self {
    Self {
      branches: Some(branches),
      policy,
      next_start: 0,
      done: false,
    }
  }

  /// Changes the poll-order policy before the first poll.
  #[doc(hidden)]
  pub fn configured(mut self, policy: JoinPolicy) -> Self {
    self.policy = policy;
    self.next_start = 0;
    self
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
    let start = match this.policy {
      JoinPolicy::Biased => 0,
      JoinPolicy::RoundRobin => this.next_start,
    };
    for offset in 0..L::LEN {
      let index = (start + offset) % L::LEN;
      let poll_result = match this.branches.as_mut() {
        Some(branches) => branches.poll_join_at(index, cx),
        None => Ok(()),
      };
      if let Err(payload) = poll_result {
        this.abort_with_primary(payload);
      }
    }
    let complete = this.branches.as_ref().is_some_and(JoinBranches::complete);
    if !complete {
      if this.policy == JoinPolicy::RoundRobin {
        this.next_start = (start + 1) % L::LEN;
      }
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
  fn poll_try_join_at(
    &mut self,
    index: usize,
    cx: &mut Context<'_>,
  ) -> Result<Option<E>, PanicPayload>;
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

  fn poll_try_join_at(
    &mut self,
    index: usize,
    cx: &mut Context<'_>,
  ) -> Result<Option<E>, PanicPayload> {
    if index == 0 {
      self.head.poll(cx)
    } else {
      self.tail.poll_try_join_at(index - 1, cx)
    }
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
  fn poll_try_join_at(
    &mut self,
    _index: usize,
    _cx: &mut Context<'_>,
  ) -> Result<Option<E>, PanicPayload> {
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
  policy: JoinPolicy,
  next_start: usize,
  done: bool,
  _error: PhantomData<fn(E)>,
}

impl<L: TryJoinBranches<E>, E> TryJoinFuture<L, E> {
  /// Owns the prepared heterogeneous input list.
  #[doc(hidden)]
  pub fn new(branches: L) -> Self {
    Self::with_policy(branches, JoinPolicy::RoundRobin)
  }

  /// Owns a prepared input list and its poll-order policy.
  #[doc(hidden)]
  pub fn with_policy(branches: L, policy: JoinPolicy) -> Self {
    Self {
      branches: Some(branches),
      policy,
      next_start: 0,
      done: false,
      _error: PhantomData,
    }
  }

  /// Changes the poll-order policy before the first poll.
  #[doc(hidden)]
  pub fn configured(mut self, policy: JoinPolicy) -> Self {
    self.policy = policy;
    self.next_start = 0;
    self
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
    let start = match this.policy {
      JoinPolicy::Biased => 0,
      JoinPolicy::RoundRobin => this.next_start,
    };
    let mut poll_result = Ok(None);
    for offset in 0..L::LEN {
      let index = (start + offset) % L::LEN;
      poll_result = match this.branches.as_mut() {
        Some(branches) => branches.poll_try_join_at(index, cx),
        None => Ok(None),
      };
      match &poll_result {
        Err(_) | Ok(Some(_)) => break,
        Ok(None) => {}
      }
    }
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
          if this.policy == JoinPolicy::RoundRobin {
            this.next_start = (start + 1) % L::LEN;
          }
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

/// Drops one dispatch future while capturing its destructor panic.
#[doc(hidden)]
pub fn drop_dispatch_capturing<T>(dispatcher: T) -> Option<PanicPayload> {
  drop_capturing(dispatcher)
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
macro_rules! __allocatbelt_select_enabled {
  ([];) => { () };
  ([]; $($branches:tt)+) => {
    compile_error!("select! supports at most sixteen branches")
  };
  ([$($fuel:tt)*];) => { () };
  ([$fuel:tt $($remaining:tt)*]; ($pattern:pat = $future:expr $(, if $enabled:expr)? => $handler:expr) $(, $rest:tt)*) => {
    (true $(&& $enabled)?, $crate::__allocatbelt_select_enabled!([$($remaining)*]; $($rest),*))
  };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __allocatbelt_select_branch {
  ($enabled:expr; ($($branch:tt)*)) => {
    $crate::__allocatbelt_select_branch!(@parse $enabled; $($branch)*)
  };
  (@parse $enabled:expr; $pattern:pat = $future:expr $(, if $condition:expr)? => $handler:expr) => {{
    let __future = $future;
    #[allow(unused_variables)]
    let __branch = $crate::runtime::concurrency_macros::Branch::new(
      __future,
      $enabled,
    );
    __branch
  }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __allocatbelt_select_branches {
  ([]; $enabled:expr;) => { $crate::runtime::concurrency_macros::Nil };
  ([]; $enabled:expr; $($branches:tt)+) => {
    compile_error!("select! supports at most sixteen branches")
  };
  ([$($fuel:tt)*]; $enabled:expr;) => { $crate::runtime::concurrency_macros::Nil };
  ([$fuel:tt $($remaining:tt)*]; $enabled_list:expr; $branch:tt $(, $rest:tt)*) => {{
    let (__enabled_head, __enabled_tail) = $enabled_list;
    $crate::runtime::concurrency_macros::Cons::new(
      $crate::__allocatbelt_select_branch!(__enabled_head; $branch),
      $crate::__allocatbelt_select_branches!([$($remaining)*]; __enabled_tail; $($rest),*),
    )
  }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __allocatbelt_select_dispatch {
  ($branches:ident, $index:ident, $winner:expr, $cleanup:ident; ) => {
    match $winner {}
  };
  ($branches:ident, $index:ident, $winner:expr, $cleanup:ident; ($pattern:pat = $future:expr $(, if $enabled:expr)? => $handler:expr) $(, $rest:tt)*) => {
    match $winner {
      $crate::runtime::concurrency_macros::Either::Left(mut __output) => {
        #[allow(unreachable_patterns)]
        match __output {
          $pattern => {
            let __handler = async { $handler };
            match $branches.dispose_before_winner_capturing(__handler) {
              Ok(__handler) => Some(__handler.await),
              Err(__payload) => {
                $cleanup = Some(__payload);
                None
              }
            }
          }
          _ => {
            $branches.disable_at($index);
            None
          }
        }
      }
      $crate::runtime::concurrency_macros::Either::Right(__tail) => {
        $crate::__allocatbelt_select_dispatch!($branches, $index, __tail, $cleanup; $($rest),*)
      }
    }
  };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __allocatbelt_select_future {
  ($policy:expr; [ $( $branch:tt, )+ ]; else => $else:expr) => {{
    async move {
      let mut __policy = $policy;
      let __enabled = $crate::__allocatbelt_select_enabled!(
        [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16];
        $( $branch ),+
      );
      let mut __branches = $crate::runtime::concurrency_macros::BranchSet::new(
        $crate::__allocatbelt_select_branches!(
          [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16];
          __enabled;
          $( $branch ),+
        ),
      );
      let (__rotate, mut __start) = __branches.initial_start(&mut __policy);
      let mut __visited = 0_u16;
      loop {
        let __candidate = ::std::future::poll_fn(|__cx| {
          let __count = __branches.branch_count();
          for __offset in 0..__count {
            let __index = (__start + __offset) % __count;
            let __mask = 1_u16 << __index;
            if (__visited & __mask) != 0 || !__branches.any_enabled_at(__index) {
              continue;
            }
            __visited |= __mask;
            match __branches.poll_at(__index, __cx) {
              ::std::task::Poll::Ready(Err(__payload)) => {
                __branches.dispose_after_poll_panic(__payload);
              }
              ::std::task::Poll::Ready(Ok(Some((__source_index, __winner)))) => {
                return ::std::task::Poll::Ready(Some((__source_index, __winner)));
              }
              ::std::task::Poll::Ready(Ok(None)) | ::std::task::Poll::Pending => {}
            }
          }
          if !__branches.any_enabled() {
            return ::std::task::Poll::Ready(None);
          }
          __visited = 0;
          if __rotate {
            __start = __branches.next_enabled(__start);
          }
          ::std::task::Poll::Pending
        }).await;
        match __candidate {
          Some((__index, __winner)) => {
            let mut __cleanup_primary = None;
            let mut __dispatcher = ::std::boxed::Box::pin(async {
              $crate::__allocatbelt_select_dispatch!(
                __branches,
                __index,
                __winner,
                __cleanup_primary;
                $( $branch ),+
              )
            });
            let __dispatch_result = ::std::future::poll_fn(|__cx| {
              match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                __dispatcher.as_mut().poll(__cx)
              })) {
                Ok(::std::task::Poll::Pending) => ::std::task::Poll::Pending,
                Ok(::std::task::Poll::Ready(__output)) => {
                  ::std::task::Poll::Ready(Ok(__output))
                }
                Err(__payload) => ::std::task::Poll::Ready(Err(__payload)),
              }
            })
            .await;
            let __dispatcher_drop =
              $crate::runtime::concurrency_macros::drop_dispatch_capturing(__dispatcher);
            let (__dispatch_output, __poll_panic) = match __dispatch_result {
              Ok(__output) => (Some(__output), None),
              Err(__payload) => (None, Some(__payload)),
            };
            if let Some(__payload) = __branches.resolve_dispatch_failures(
              __cleanup_primary,
              __poll_panic,
              __dispatcher_drop,
            ) {
              ::std::panic::resume_unwind(__payload);
            }
            match __dispatch_output {
              Some(Some(__output)) => break __output,
              Some(None) => {}
              None => unreachable!("dispatch poll panic was resumed above"),
            }
          }
          None => {
            __branches.dispose();
            break $else;
          }
        }
      }
    }
  }};
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
///
/// By default `join!` rotates its first polled input after each pending poll.
/// Use `join!(biased; ...)` to keep source order. `try_join!` has the same
/// policies and still returns the first error observed in the chosen poll
/// order.
#[doc(hidden)]
#[macro_export]
macro_rules! __allocatbelt_join_impl {
  ($policy:ident; $f0:expr, $f1:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, ())) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, ()))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, ())))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2, __o3)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, ()))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2, __o3, __o4)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, ())))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2, __o3, __o4, __o5)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, ()))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, ())))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, ()))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, ())))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, ()))))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, ())))))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, ()))))))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr, $f13:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, (__o13, ())))))))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12, $f13),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12, __o13)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr, $f13:expr, $f14:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, (__o13, (__o14, ()))))))))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12, $f13, $f14),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12, __o13, __o14)
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr, $f13:expr, $f14:expr, $f15:expr $(,)?) => {{
    async move {
      let (__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, (__o13, (__o14, (__o15, ())))))))))))))))) = $crate::runtime::concurrency_macros::JoinFuture::new(
        $crate::__allocatbelt_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12, $f13, $f14, $f15),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await;
      (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12, __o13, __o14, __o15)
    }
  }};
  ($policy:ident; $($branches:expr),+ $(,)?) => {
    compile_error!("join! requires between two and sixteen branches")
  };
}

/// Joins two to sixteen heterogeneous futures and returns a flat tuple in
/// source order. It rotates the first polled input after each pending poll;
/// add `biased;` to poll in source order on every call. Completed futures are
/// not polled again, and a polling or cleanup panic follows the helper's
/// contained-cleanup behavior.
#[macro_export]
macro_rules! join {
  (biased; $($branches:expr),+ $(,)?) => {
    $crate::__allocatbelt_join_impl!(Biased; $($branches),+)
  };
  (round_robin; $($branches:expr),+ $(,)?) => {
    $crate::__allocatbelt_join_impl!(RoundRobin; $($branches),+)
  };
  ($($branches:expr),+ $(,)?) => {
    $crate::__allocatbelt_join_impl!(RoundRobin; $($branches),+)
  };
  ($($tokens:tt)*) => {
    compile_error!("join! requires two to sixteen branches and an optional biased or round_robin policy")
  };
}

/// Joins heterogeneous `Result` futures, returning the first observed error.
/// Successful values are returned as a flat tuple in source order. All
/// branches share one error type. Branches are evaluated when the returned
/// future is first polled, and each partial value is retained and disposed
/// independently before an error is returned.
#[doc(hidden)]
#[macro_export]
macro_rules! __allocatbelt_try_join_impl {
  ($policy:ident; $f0:expr, $f1:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, ()))| (__o0, __o1))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, ())))| (__o0, __o1, __o2))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, (__o3, ()))))| (__o0, __o1, __o2, __o3))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, ())))))| (__o0, __o1, __o2, __o3, __o4))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, ()))))))| (__o0, __o1, __o2, __o3, __o4, __o5))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, ())))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, ()))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, ())))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, ()))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, ())))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, ()))))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, ())))))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr, $f13:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12, $f13),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, (__o13, ()))))))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12, __o13))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr, $f13:expr, $f14:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12, $f13, $f14),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, (__o13, (__o14, ())))))))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12, __o13, __o14))
    }
  }};
  ($policy:ident; $f0:expr, $f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr, $f7:expr, $f8:expr, $f9:expr, $f10:expr, $f11:expr, $f12:expr, $f13:expr, $f14:expr, $f15:expr $(,)?) => {{
    async move {
      $crate::runtime::concurrency_macros::TryJoinFuture::new(
        $crate::__allocatbelt_try_join_branches!([1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]; $f0, $f1, $f2, $f3, $f4, $f5, $f6, $f7, $f8, $f9, $f10, $f11, $f12, $f13, $f14, $f15),
      ).configured($crate::runtime::concurrency_macros::JoinPolicy::$policy).await.map(|(__o0, (__o1, (__o2, (__o3, (__o4, (__o5, (__o6, (__o7, (__o8, (__o9, (__o10, (__o11, (__o12, (__o13, (__o14, (__o15, ()))))))))))))))))| (__o0, __o1, __o2, __o3, __o4, __o5, __o6, __o7, __o8, __o9, __o10, __o11, __o12, __o13, __o14, __o15))
    }
  }};
  ($policy:ident; $($branches:expr),+ $(,)?) => {
    compile_error!("try_join! requires between two and sixteen branches")
  };
}

/// Joins two to sixteen heterogeneous `Result` futures and returns the first
/// observed error. Successful values are returned in source order; branch
/// polling rotates after pending polls by default. Add `biased;` to keep
/// source-order polling.
#[macro_export]
macro_rules! try_join {
  (biased; $($branches:expr),+ $(,)?) => {
    $crate::__allocatbelt_try_join_impl!(Biased; $($branches),+)
  };
  (round_robin; $($branches:expr),+ $(,)?) => {
    $crate::__allocatbelt_try_join_impl!(RoundRobin; $($branches),+)
  };
  ($($branches:expr),+ $(,)?) => {
    $crate::__allocatbelt_try_join_impl!(RoundRobin; $($branches),+)
  };
  ($($tokens:tt)*) => {
    compile_error!("try_join! requires two to sixteen branches and an optional biased or round_robin policy")
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
/// Branch preconditions are evaluated first, followed by every future
/// expression in source order; disabled futures are constructed and owned but
/// never polled. The default policy seeds a selection-only generator when the
/// macro is invoked, using nonblocking kernel entropy and a `RandomState`
/// fallback, then rotates the first branch after pending polls. `biased;`
/// always starts with the first enabled branch, `round_robin;` starts there
/// and rotates, and `randomized(rng);` uses a caller-supplied
/// [`SelectionRng`](super::concurrency::SelectionRng). A refutable pattern
/// mismatch disables that completed branch for this selection and continues
/// with the others; if none remain, `else` runs after cleanup. Every branch
/// future is disposed before the selected handler runs. Handlers must produce
/// one common type. Handler captures follow the enclosing async future's
/// lifetime and are not separately dropped at selection time.
#[macro_export]
macro_rules! select {
  (
    biased;
    [ $( $branch:tt, )+ ];
    else => $else:expr $(,)?
  ) => {{
    let __policy = $crate::runtime::concurrency_macros::SelectionStart::Biased;
    $crate::__allocatbelt_select_future!(
      __policy;
      [ $( $branch, )+ ];
      else => $else
    )
  }};
  (
    round_robin;
    [ $( $branch:tt, )+ ];
    else => $else:expr $(,)?
  ) => {{
    let __policy = $crate::runtime::concurrency_macros::SelectionStart::RoundRobin;
    $crate::__allocatbelt_select_future!(
      __policy;
      [ $( $branch, )+ ];
      else => $else
    )
  }};
  (
    randomized($rng:expr);
    [ $( $branch:tt, )+ ];
    else => $else:expr $(,)?
  ) => {{
    let __policy = $crate::runtime::concurrency_macros::SelectionStart::Randomized($rng);
    $crate::__allocatbelt_select_future!(
      __policy;
      [ $( $branch, )+ ];
      else => $else
    )
  }};
  (
    randomized;
    [ $( $branch:tt, )+ ];
    else => $else:expr $(,)?
  ) => {{
    let __policy = $crate::runtime::concurrency_macros::SelectionStart::Randomized(
      $crate::runtime::concurrency::SelectionRng::from_entropy_or_random_state(),
    );
    $crate::__allocatbelt_select_future!(
      __policy;
      [ $( $branch, )+ ];
      else => $else
    )
  }};
  (
    [ $( $branch:tt, )+ ];
    else => $else:expr $(,)?
  ) => {{
    let __policy = $crate::runtime::concurrency_macros::SelectionStart::Randomized(
      $crate::runtime::concurrency::SelectionRng::from_entropy_or_random_state(),
    );
    $crate::__allocatbelt_select_future!(
      __policy;
      [ $( $branch, )+ ];
      else => $else
    )
  }};
  ($($tokens:tt)*) => {
    compile_error!("select! accepts two to sixteen branches, an else arm, and an optional biased, round_robin, randomized, or randomized(RNG) policy")
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
  fn join_and_try_join_rotate_by_default_and_keep_explicit_bias() {
    fn join_probe(
      order: Rc<std::cell::RefCell<Vec<usize>>>,
      id: usize,
    ) -> impl Future<Output = usize> {
      let polls = Cell::new(0);
      poll_fn(move |_| {
        order.borrow_mut().push(id);
        let poll = polls.get();
        polls.set(poll + 1);
        if poll == 0 {
          Poll::Pending
        } else {
          Poll::Ready(id)
        }
      })
    }

    let order = Rc::new(std::cell::RefCell::new(Vec::new()));
    let first_order = Rc::clone(&order);
    let second_order = Rc::clone(&order);
    let mut joined = std::pin::pin!(crate::join!(
      join_probe(first_order, 0),
      join_probe(second_order, 1),
    ));
    let waker = noop_waker();
    assert!(poll(joined.as_mut(), &waker).is_pending());
    assert_eq!(*order.borrow(), [0, 1]);
    assert_eq!(poll(joined.as_mut(), &waker), Poll::Ready((0, 1)));
    assert_eq!(*order.borrow(), [0, 1, 1, 0]);

    let order = Rc::new(std::cell::RefCell::new(Vec::new()));
    let first_order = Rc::clone(&order);
    let second_order = Rc::clone(&order);
    let mut biased = std::pin::pin!(crate::join!(
      biased;
      join_probe(first_order, 0),
      join_probe(second_order, 1),
    ));
    assert!(poll(biased.as_mut(), &waker).is_pending());
    assert!(poll(biased.as_mut(), &waker).is_ready());
    assert_eq!(*order.borrow(), [0, 1, 0, 1]);

    fn try_join_probe(
      order: Rc<std::cell::RefCell<Vec<usize>>>,
      id: usize,
    ) -> impl Future<Output = Result<usize, &'static str>> {
      let polls = Cell::new(0);
      poll_fn(move |_| {
        order.borrow_mut().push(id);
        let poll = polls.get();
        polls.set(poll + 1);
        if poll == 0 {
          Poll::Pending
        } else {
          Poll::Ready(Ok(id))
        }
      })
    }

    let order = Rc::new(std::cell::RefCell::new(Vec::new()));
    let first_order = Rc::clone(&order);
    let second_order = Rc::clone(&order);
    let mut tried = std::pin::pin!(crate::try_join!(
      try_join_probe(first_order, 0),
      try_join_probe(second_order, 1),
    ));
    assert!(poll(tried.as_mut(), &waker).is_pending());
    assert_eq!(poll(tried.as_mut(), &waker), Poll::Ready(Ok((0, 1))));
    assert_eq!(*order.borrow(), [0, 1, 1, 0]);

    let order = Rc::new(std::cell::RefCell::new(Vec::new()));
    let first_order = Rc::clone(&order);
    let second_order = Rc::clone(&order);
    let mut tried_biased = std::pin::pin!(crate::try_join!(
      biased;
      try_join_probe(first_order, 0),
      try_join_probe(second_order, 1),
    ));
    assert!(poll(tried_biased.as_mut(), &waker).is_pending());
    assert_eq!(poll(tried_biased.as_mut(), &waker), Poll::Ready(Ok((0, 1))));
    assert_eq!(*order.borrow(), [0, 1, 0, 1]);
  }

  #[test]
  #[allow(
    clippy::needless_borrow,
    clippy::needless_borrowed_reference,
    reason = "regresses explicit double-reference pattern behavior"
  )]
  fn refutable_patterns_preserve_binding_modes_and_handler_bindings() {
    let owned = String::from("mutable owned binding");
    let owned_result = crate::select! {
      [
      (mut value = std::future::ready(owned) => {
        value.push('!');
        value
      }),
      (_waiting = std::future::pending::<()>() => String::new()),
      ];
      else => String::new(),
    };
    let mut owned_result = std::pin::pin!(owned_result);
    assert_eq!(
      poll(owned_result.as_mut(), &noop_waker()),
      Poll::Ready("mutable owned binding!".to_owned())
    );

    let pair = (String::from("borrowed"), String::from("mutable"));
    let pair_result = crate::select! {
      [
      (Some((ref name, ref mut text)) = std::future::ready(Some(pair)) => {
        text.push('!');
        format!("{name}: {text}")
      }),
      (_waiting = std::future::pending::<()>() => String::from("waiting")),
      ];
      else => String::from("mismatch"),
    };
    let mut pair_result = std::pin::pin!(pair_result);
    assert_eq!(
      poll(pair_result.as_mut(), &noop_waker()),
      Poll::Ready("borrowed: mutable!".to_owned())
    );

    let text = String::from("double reference");
    let first = &text;
    let second = &first;
    let ref_result = crate::select! {
      [
      (&&ref value = std::future::ready(second) => value.len()),
      (_waiting = std::future::pending::<()>() => 0),
      ];
      else => 0,
    };
    let mut ref_result = std::pin::pin!(ref_result);
    assert_eq!(
      poll(ref_result.as_mut(), &noop_waker()),
      Poll::Ready(text.len())
    );

    struct Record {
      name: String,
      body: String,
    }
    let record_result = crate::select! {
      [
      (Record { ref name, ref mut body } = std::future::ready(Record {
        name: String::from("record"),
        body: String::from("text"),
      }) => {
        body.push('!');
        format!("{name}: {body}")
      }),
      (_waiting = std::future::pending::<()>() => String::new()),
      ];
      else => String::from("mismatch"),
    };
    let mut record_result = std::pin::pin!(record_result);
    assert_eq!(
      poll(record_result.as_mut(), &noop_waker()),
      Poll::Ready(String::from("record: text!"))
    );

    let slice_result = crate::select! {
      [
      ([.., ref mut last] = std::future::ready([String::from("one"), String::from("two")]) => {
        last.push('!');
        last.clone()
      }),
      (_waiting = std::future::pending::<()>() => String::new()),
      ];
      else => String::from("mismatch"),
    };
    let mut slice_result = std::pin::pin!(slice_result);
    assert_eq!(
      poll(slice_result.as_mut(), &noop_waker()),
      Poll::Ready(String::from("two!"))
    );

    enum Message {
      Text(String),
      Other(String),
    }
    let _unused_variant = Message::Text(String::new());
    let or_result = crate::select! {
      [
      (Message::Text(ref value) | Message::Other(ref value) = std::future::ready(Message::Other(
        String::from("or-pattern"),
      )) => value.len()),
      (_waiting = std::future::pending::<()>() => 0),
      ];
      else => 0,
    };
    let mut or_result = std::pin::pin!(or_result);
    assert_eq!(
      poll(or_result.as_mut(), &noop_waker()),
      Poll::Ready(String::from("or-pattern").len())
    );

    let absolute_result = crate::select! {
      [
      (::std::option::Option::Some(ref mut value) = std::future::ready(Some(String::from("absolute"))) => {
        value.push('!');
        value.len()
      }),
      (_waiting = std::future::pending::<()>() => 0),
      ];
      else => 0,
    };
    let mut absolute_result = std::pin::pin!(absolute_result);
    assert_eq!(
      poll(absolute_result.as_mut(), &noop_waker()),
      Poll::Ready("absolute!".len())
    );

    let mut mutable_option = Some(17_u8);
    let mutable_reference = &mut mutable_option;
    let mutable_reference_result = crate::select! {
      [
      (&mut _ = std::future::ready(mutable_reference) => true),
      (_waiting = std::future::pending::<()>() => false),
      ];
      else => false,
    };
    let mut mutable_reference_result = std::pin::pin!(mutable_reference_result);
    assert_eq!(
      poll(mutable_reference_result.as_mut(), &noop_waker()),
      Poll::Ready(true)
    );

    enum ReferenceAlternative {
      First(u8),
      Second(u8),
    }
    let _unused_variant = ReferenceAlternative::First(0);
    let alternative = ReferenceAlternative::Second(23);
    let borrowed_alternative = &alternative;
    let alternative_result = crate::select! {
      [
      (&ReferenceAlternative::First(value) | &ReferenceAlternative::Second(value) = std::future::ready(borrowed_alternative) => value),
      (_waiting = std::future::pending::<()>() => 0),
      ];
      else => 0,
    };
    let mut alternative_result = std::pin::pin!(alternative_result);
    assert_eq!(
      poll(alternative_result.as_mut(), &noop_waker()),
      Poll::Ready(23)
    );
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
  fn preconditions_run_before_all_future_expressions() {
    let events = Rc::new(std::cell::RefCell::new(Vec::new()));
    let guard_events = Rc::clone(&events);
    let second_guard_events = Rc::clone(&events);
    let future_events = Rc::clone(&events);
    let second_future_events = Rc::clone(&events);
    let future = select! {
      biased;
      [
      (_a = {
        future_events.borrow_mut().push("future-a");
        std::future::pending::<usize>()
      }, if {
        guard_events.borrow_mut().push("guard-a");
        true
      } => 1),
      (_b = {
        second_future_events.borrow_mut().push("future-b");
        std::future::pending::<usize>()
      }, if {
        second_guard_events.borrow_mut().push("guard-b");
        false
      } => 2),
      ];
      else => 3,
    };
    assert!(events.borrow().is_empty());
    let mut future = std::pin::pin!(future);
    assert!(poll(future.as_mut(), &noop_waker()).is_pending());
    assert_eq!(
      &*events.borrow(),
      &["guard-a", "guard-b", "future-a", "future-b"]
    );
  }

  #[test]
  fn refutable_mismatch_disables_completed_branch_and_continues() {
    let first_polls = Rc::new(Cell::new(0));
    let second_polls = Rc::new(Cell::new(0));
    let first_count = Rc::clone(&first_polls);
    let first = poll_fn(move |_| {
      let count = first_count.get();
      first_count.set(count + 1);
      if count == 0 {
        Poll::Ready(None::<usize>)
      } else {
        panic!("a pattern-mismatched completed branch was polled again")
      }
    });
    let second_count = Rc::clone(&second_polls);
    let second = poll_fn(move |_| {
      let count = second_count.get();
      second_count.set(count + 1);
      if count == 0 {
        Poll::Pending
      } else {
        Poll::Ready(Some(17_usize))
      }
    });
    let future = select! {
      biased;
      [
      (Some(_first) = first => 1),
      (Some(value) = second => value),
      ];
      else => 3,
    };
    let mut future = std::pin::pin!(future);
    assert!(poll(future.as_mut(), &noop_waker()).is_pending());
    assert_eq!(first_polls.get(), 1);
    assert_eq!(second_polls.get(), 1);
    assert_eq!(poll(future.as_mut(), &noop_waker()), Poll::Ready(17));
    assert_eq!(first_polls.get(), 1);
    assert_eq!(second_polls.get(), 2);
  }

  #[test]
  fn mismatch_resume_does_not_repoll_a_pending_sibling_in_one_outer_poll() {
    let first_polls = Rc::new(Cell::new(0));
    let pending_polls = Rc::new(Cell::new(0));
    let winner_polls = Rc::new(Cell::new(0));
    let first_count = Rc::clone(&first_polls);
    let pending_count = Rc::clone(&pending_polls);
    let winner_count = Rc::clone(&winner_polls);
    let future = select! {
      biased;
      [
      (Some(_) = poll_fn(move |_| {
        first_count.set(first_count.get() + 1);
        Poll::Ready(None::<usize>)
      }) => 1),
      (_ = poll_fn(move |_| {
        pending_count.set(pending_count.get() + 1);
        Poll::<usize>::Pending
      }) => 2),
      (value = poll_fn(move |_| {
        winner_count.set(winner_count.get() + 1);
        Poll::Ready(17_usize)
      }) => value),
      ];
      else => 0,
    };
    let mut future = std::pin::pin!(future);
    assert_eq!(poll(future.as_mut(), &noop_waker()), Poll::Ready(17));
    assert_eq!(first_polls.get(), 1);
    assert_eq!(pending_polls.get(), 1);
    assert_eq!(winner_polls.get(), 1);
  }

  #[test]
  fn all_pattern_mismatches_run_else_after_branch_cleanup() {
    struct DropProbe(Rc<Cell<usize>>);
    impl Drop for DropProbe {
      fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
      }
    }

    let drops = Rc::new(Cell::new(0));
    let first_drop = Rc::clone(&drops);
    let second_drop = Rc::clone(&drops);
    let third_drop = Rc::clone(&drops);
    let else_drops = Rc::clone(&drops);
    let future = select! {
      biased;
      [
      (2 = {
        let probe = DropProbe(first_drop);
        poll_fn(move |_| {
          let _probe = &probe;
          Poll::Ready(1_usize)
        })
      } => 10),
      (Some("match") = {
        let probe = DropProbe(second_drop);
        poll_fn(move |_| {
          let _probe = &probe;
          Poll::Ready(Some("miss"))
        })
      } => 20),
      (_never = {
        let probe = DropProbe(third_drop);
        poll_fn(move |_| {
          let _probe = &probe;
          Poll::<usize>::Pending
        })
      }, if false => 30),
      ];
      else => else_drops.get(),
    };
    let mut future = std::pin::pin!(future);
    assert_eq!(poll(future.as_mut(), &noop_waker()), Poll::Ready(3));
    assert_eq!(drops.get(), 3);
  }

  #[test]
  fn select_dispatch_accepts_generic_absolute_and_mutable_reference_patterns() {
    let first = select! {
      biased;
      [
      (::std::option::Option::Some::<String>(ref mut value) = std::future::ready(Some("first".to_owned())) => {
        value.push('!');
        value.len()
      }),
      (_ = std::future::pending::<usize>() => 0),
      ];
      else => 0,
    };
    let mut first = std::pin::pin!(first);
    assert_eq!(poll(first.as_mut(), &noop_waker()), Poll::Ready(6));

    let nested = select! {
      biased;
      [
      ((Some::<Result<String, String>>(ref mut value), _) = std::future::ready((Some(Ok("nested".to_owned())), 1_u8)) => {
        *value = Ok("updated".to_owned());
        value.as_ref().unwrap().len()
      }),
      (_ = std::future::pending::<usize>() => 0),
      ];
      else => 0,
    };
    let mut nested = std::pin::pin!(nested);
    assert_eq!(poll(nested.as_mut(), &noop_waker()), Poll::Ready(7));

    let mut owned = String::from("borrowed");
    let mutable_reference = select! {
      biased;
      [
      (&mut _ = std::future::ready(&mut owned) => 9),
      (_ = std::future::pending::<usize>() => 0),
      ];
      else => 0,
    };
    let mut mutable_reference = std::pin::pin!(mutable_reference);
    assert_eq!(
      poll(mutable_reference.as_mut(), &noop_waker()),
      Poll::Ready(9)
    );
  }

  #[test]
  fn select_dispatch_accepts_reference_prefixed_top_level_alternatives() {
    #[allow(dead_code)]
    enum Alternative {
      First(usize),
      Second(usize),
    }

    let first = Alternative::First(23);
    let future = select! {
      biased;
      [
      (&Alternative::First(value) | &Alternative::Second(value) = std::future::ready(&first) => value),
      (_ = std::future::pending::<usize>() => 0),
      ];
      else => 0,
    };
    let mut future = std::pin::pin!(future);
    assert_eq!(poll(future.as_mut(), &noop_waker()), Poll::Ready(23));
  }

  #[test]
  fn randomized_macro_policy_evaluates_rng_before_poll_and_skips_disabled_starts() {
    let seed = 101;
    let first_rank = super::super::concurrency::SelectionRng::from_seed(seed).index(2);
    let enabled = [1_usize, 3];
    let order = Rc::new(std::cell::RefCell::new(Vec::new()));
    let polls = [
      Rc::clone(&order),
      Rc::clone(&order),
      Rc::clone(&order),
      Rc::clone(&order),
    ];
    let evaluated = Rc::new(Cell::new(false));
    let evaluated_before_poll = Rc::clone(&evaluated);
    let future = select! {
      randomized({
        evaluated.set(true);
        super::super::concurrency::SelectionRng::from_seed(seed)
      });
      [
      (_zero = std::future::ready(()), if false => 0),
      (_one = poll_fn({ let log = Rc::clone(&polls[1]); move |_| { log.borrow_mut().push(1); Poll::<usize>::Pending } }) => 1),
      (_two = std::future::ready(()), if false => 2),
      (_three = poll_fn({ let log = Rc::clone(&polls[3]); move |_| { log.borrow_mut().push(3); Poll::<usize>::Pending } }) => 3),
      ];
      else => 4,
    };
    assert!(evaluated_before_poll.get());
    let mut future = std::pin::pin!(future);
    assert!(poll(future.as_mut(), &noop_waker()).is_pending());
    assert_eq!(
      &*order.borrow(),
      &[enabled[first_rank], enabled[1 - first_rank]]
    );
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
    let payload = match result {
      Err(payload) => payload,
      Ok(()) => panic!("loser cleanup should panic"),
    };
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"drop panic"));
  }

  #[test]
  fn loser_cleanup_panic_stays_primary_when_handler_borrows_winner_output() {
    let future = select! {
      biased;
      [
      (value = std::future::ready(PanicValue) => {
        let _ = &value;
        0
      }),
      (_value = PanicOnDrop => 1),
      ];
      else => 2,
    };
    let mut future = std::pin::pin!(future);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let _ = poll(future.as_mut(), &noop_waker());
    }));
    let payload = match result {
      Err(payload) => payload,
      Ok(()) => panic!("loser cleanup should panic"),
    };
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"drop panic"));
  }

  #[test]
  fn loser_cleanup_panic_stays_primary_when_winner_binding_is_unused() {
    let future = select! {
      biased;
      [
      (_value = std::future::ready(PanicValue) => 0),
      (_value = PanicOnDrop => 1),
      ];
      else => 2,
    };
    let mut future = std::pin::pin!(future);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let _ = poll(future.as_mut(), &noop_waker());
    }));
    let payload = match result {
      Err(payload) => payload,
      Ok(()) => panic!("loser cleanup should panic"),
    };
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"drop panic"));
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
