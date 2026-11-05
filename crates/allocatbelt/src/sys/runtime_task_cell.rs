//! The one pinned allocation of a native async task (optional `runtime`).
//!
//! A native async task is one `Arc`: a [`TaskCell`] that stores the
//! runtime's bookkeeping (`H`) next to the user future (`F`) instead of
//! boxing the future a second time, together with the task's atomic word,
//! its outcome (`O`) and its one join waker. Pinning a future that never
//! leaves its allocation, and handing the outcome and the join waker between
//! threads under the word, need `unsafe`, so this module is the one place
//! that creates the pinned reference, drops the value in place, reaches the
//! outcome and waker cells and builds a `Waker` from the allocation. The
//! runtime, which keeps `#![forbid(unsafe_code)]`, only calls the safe API
//! below; its soundness does not depend on how the runtime orders or
//! interleaves those calls.
//!
//! # Contract
//!
//! The cell exists only inside a `Pin<Arc<TaskCell<H, F, O>>>`:
//! [`TaskCell::new`] and [`TaskCell::new_with_join`] are the only
//! constructors, and no API returns the cell by value, by `&mut` or as an
//! unpinned `Arc` or `Weak`. Everything that touches the stored
//! future ([`TaskCell::poll_future`], [`TaskCell::drop_future`],
//! [`TaskCell::finish`]) takes
//! `self: Pin<&Self>`, which safe code can only obtain through that pinned
//! `Arc`, and the cell is never `Unpin` (it holds the one `Unpin` impl it can
//! have, behind a bound that never holds, so no other impl can be written),
//! so `Pin::into_inner` and `Pin::get_mut` do not apply to it. The pin guarantee of `Arc::pin`
//! therefore holds for the future from its first poll until `Drop` runs in
//! place: it is never moved, and its memory is not reused before its
//! destructor ran. The bookkeeping is reachable only by shared reference
//! ([`TaskCell::header`]). Unsizing a `Pin<Arc<TaskCell<H, F, O>>>` to a
//! `Pin<Arc<dyn Trait>>` keeps all of this.
//!
//! The cell starts with a future (`PRESENT`). `poll_future` claims the
//! cell with one compare-and-swap (`PRESENT` → `POLLING`), pins the future
//! in place, polls it once and releases the claim with one release store.
//! A poll that finds any other state, including a poll in progress on
//! another thread or a reentrant poll from inside the future, is rejected
//! without touching the future. After the future returns `Ready` the cell
//! is `COMPLETE`; after its poll unwinds it is `POISONED`; both reject
//! further polls and keep the value for in-place destruction. `drop_future`
//! claims the value with one compare-and-swap (`PRESENT`, `COMPLETE` or
//! `POISONED` → `ABSENT`) and drops it exactly once; it refuses while a poll
//! is in progress, and the cell's own `Drop` drops a value that is still
//! present. `finish` claims the cell from any of those states or `ABSENT`
//! into `STORING`, drops a value still present in place, writes the outcome
//! once and releases into the final `STORED`. Every claim is an acquire
//! read-modify-write that observes the release of the previous claim, so the
//! value and the outcome are only ever reached through one exclusive
//! reference at a time, and everything a poll wrote is visible to the next
//! poll or to the destructor on any thread.
//!
//! The outcome and the join waker are governed by the task word (see
//! `runtime_task_word.rs`): `publish` sets `COMPLETE` only after it observed
//! `STORED`, after which the outcome belongs to the one [`TaskJoin`] if it
//! still existed at publication and to the publisher otherwise; the join
//! waker cell is written only by that one handle while `JOIN_WAKER` is clear
//! and the task is not complete, and only read while it is set. The runtime
//! sees the word only through [`TaskWord`], whose operations set
//! `NOTIFIED` alone.
//!
//! A [`TaskSlot`] holds the scheduler's owner of a task and lends it to one
//! turn at a time without a reference-count update: [`TaskSlot::lend`] wins
//! `RUNNING` with one compare-and-swap and returns a [`Lease`], the only way
//! to end it (a pending finish, or [`TaskSlot::take`] for the final turn).
//! While `RUNNING` is set no slot drops or gives up its owner except to that
//! lease, so the lease's pointer stays valid; [`Lease::waker`] borrows a
//! `Waker` from it that clones into an owned one only when user code keeps
//! it.

use std::any::Any;
use std::cell::UnsafeCell;
use std::future::Future;
use std::marker::{PhantomData, PhantomPinned};
use std::mem::ManuallyDrop;
use std::ops::Deref;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Wake, Waker};

#[path = "runtime_task_word.rs"]
mod word;

use word::{JoinCells, JoinWakers, WakerSlot};
pub(crate) use word::{JoinSide, PollNotify, Publication, TaskJoin, TaskWord};

/// A future is stored and may be polled.
const PRESENT: u8 = 0;
/// One poll is in progress; nothing else may touch the value.
const POLLING: u8 = 1;
/// The future returned `Ready`; the value waits for in-place destruction.
const COMPLETE: u8 = 2;
/// A poll unwound; the value waits for in-place destruction.
const POISONED: u8 = 3;
/// The value was dropped in place.
const ABSENT: u8 = 4;
/// `finish` holds the claim: it drops the value and writes the outcome.
const STORING: u8 = 5;
/// The value is gone and the outcome was written; final.
const STORED: u8 = 6;

/// The result of one [`TaskCell::poll_future`].
#[derive(Debug)]
pub(crate) enum CellPoll<T> {
  /// The future completed with this output; the value is still stored.
  Ready(T),
  /// The future registered its waker and may be polled again.
  Pending,
  /// No pollable future: it completed, unwound or was dropped, or another
  /// poll is in progress.
  Rejected,
}

/// The bookkeeping half of a task allocation, which also serves its wakers.
pub(crate) trait TaskHeader: Send + Sync + 'static {
  /// Wakes the task; called by every `Waker` built from its allocation,
  /// with the task's word.
  fn wake_by_ref(&self, word: &TaskWord);
}

/// One task allocation: bookkeeping, word, user future, outcome and join
/// waker, pinned together.
///
/// See the module documentation for the contract.
pub(crate) struct TaskCell<H, F, O = ()> {
  header: H,
  state: AtomicU8,
  word: TaskWord,
  future: UnsafeCell<ManuallyDrop<F>>,
  output: UnsafeCell<Option<O>>,
  join_waker: UnsafeCell<JoinWakers>,
  _pin: PhantomPinned,
}

/// Never `Unpin`: this impl takes the one `Unpin` impl the cell may have,
/// and its bound never holds, so no other code can make the cell `Unpin`.
struct NeverUnpin<'a>(std::marker::PhantomData<&'a ()>, PhantomPinned);

impl<'a, H, F, O> Unpin for TaskCell<H, F, O> where NeverUnpin<'a>: Unpin {}

// SAFETY: the stored future is reached only through `poll_future`,
// `drop_future` and `finish`, each of which first claims the cell with an
// acquire read-modify-write on `state` that succeeds for at most one caller
// at a time (`POLLING`, `ABSENT`, `STORING` and `STORED` are states no other
// claim of the value accepts), so two threads never hold references to it at
// once. The outcome is written once under the `STORING` claim and afterwards
// reached by exactly one party chosen by the word's publication RMW; the
// join waker is written only by the one `TaskJoin` while the word gives it
// the cell, and otherwise only read (`Waker` is `Sync`). Outcome and waker
// move between threads, so the cell is `Sync` whenever `F` and `O` may be
// moved between threads and `H` may be shared, like `Mutex<(F, O)>`.
#[expect(unsafe_code, reason = "`UnsafeCell` opts out of `Sync`")]
unsafe impl<H: Sync, F: Send, O: Send> Sync for TaskCell<H, F, O> {}

/// Releases the poll claim, as `POISONED` when the poll unwinds.
struct PollClaim<'a> {
  state: &'a AtomicU8,
  next: u8,
}

impl Drop for PollClaim<'_> {
  fn drop(&mut self) {
    self.state.store(self.next, Ordering::Release);
  }
}

impl<H, F, O> TaskCell<H, F, O> {
  fn build(header: H, future: F, join_interest: bool) -> Pin<Arc<Self>> {
    Arc::pin(Self {
      header,
      state: AtomicU8::new(PRESENT),
      word: TaskWord::new(join_interest),
      future: UnsafeCell::new(ManuallyDrop::new(future)),
      output: UnsafeCell::new(None),
      join_waker: UnsafeCell::new(JoinWakers::default()),
      _pin: PhantomPinned,
    })
  }

  /// Allocates the task without a join handle and pins it; a published
  /// outcome goes back to the publisher.
  #[cfg(test)]
  pub(crate) fn new(header: H, future: F) -> Pin<Arc<Self>> {
    Self::build(header, future, false)
  }

  /// Allocates the task and its one join handle. `erase` converts a clone
  /// of the allocation to the handle's (usually unsized) form and must
  /// return that same allocation.
  pub(crate) fn new_with_join<J>(
    header: H,
    future: F,
    erase: impl FnOnce(Pin<Arc<Self>>) -> Pin<Arc<J>>,
  ) -> (Pin<Arc<Self>>, TaskJoin<J>)
  where
    J: ?Sized + JoinSide<Output = O>,
  {
    let task = Self::build(header, future, true);
    let join = erase(Pin::clone(&task));
    assert!(
      std::ptr::addr_eq(
        std::ptr::from_ref::<J>(&join),
        std::ptr::from_ref::<Self>(&task)
      ),
      "the join handle must share the task allocation"
    );
    (task, TaskJoin::new(join))
  }

  /// The bookkeeping stored next to the future.
  pub(crate) fn header(&self) -> &H {
    &self.header
  }

  /// The scheduling face of the task word.
  pub(crate) fn word(&self) -> &TaskWord {
    &self.word
  }

  /// Whether the outcome was published.
  pub(crate) fn is_complete(&self) -> bool {
    self.word.is_complete()
  }

  /// Whether `finish` claimed the cell (the outcome is being or was
  /// stored).
  pub(crate) fn is_finished(&self) -> bool {
    matches!(self.state.load(Ordering::Acquire), STORING | STORED)
  }

  /// Whether a value is still stored (pollable, complete, poisoned or
  /// being polled). `false` once it was dropped.
  #[cfg(test)]
  pub(crate) fn holds_value(&self) -> bool {
    !matches!(
      self.state.load(Ordering::Acquire),
      ABSENT | STORING | STORED
    )
  }

  /// The number of `Pin<Arc<Self>>` and `Waker` owners of the allocation.
  #[cfg(test)]
  pub(crate) fn strong_count(this: &Pin<Arc<Self>>) -> usize {
    Arc::strong_count(&Self::unpinned(Pin::clone(this))) - 1
  }

  /// A `Waker` that shares this allocation instead of allocating its own.
  #[cfg(test)]
  pub(crate) fn waker(this: &Pin<Arc<Self>>) -> Waker
  where
    H: TaskHeader,
    F: Send + 'static,
    O: Send + 'static,
  {
    Self::into_waker(Pin::clone(this))
  }

  /// A `Waker` that takes over this owner of the allocation, so a caller
  /// that already holds a clone pays no further reference-count update.
  #[cfg(test)]
  pub(crate) fn into_waker(this: Pin<Arc<Self>>) -> Waker
  where
    H: TaskHeader,
    F: Send + 'static,
    O: Send + 'static,
  {
    Waker::from(Self::unpinned(this))
  }

  /// The given owner of the allocation without the `Pin` wrapper, for APIs
  /// that take `Arc<Self>`. Never leaves this module: the pin guarantee is
  /// kept by this module never moving out of, or giving out, such an `Arc`.
  #[cfg(test)]
  fn unpinned(this: Pin<Arc<Self>>) -> Arc<Self> {
    // SAFETY: the unpinned `Arc` does not escape this module's control.
    // Its only uses are `Waker::from`, whose vtable hands the `Arc` back
    // solely to the `Wake` implementation below (which reads the header
    // and never moves out of the `Arc`) and otherwise drops it, in place,
    // like any other owner, and a strong count in tests. No unpinned `Arc`
    // or `Weak` reaches a caller, so the allocation stays pinned until its
    // last owner drops it in place.
    #[expect(unsafe_code, reason = "shares the pinned allocation with a `Waker`")]
    unsafe {
      Pin::into_inner_unchecked(this)
    }
  }

  /// Polls the stored future once, pinned in place.
  ///
  /// Returns [`CellPoll::Rejected`] without touching the future when it is
  /// not pollable, including while another poll is in progress. A panic in
  /// the future's `poll` unwinds out of this call and poisons the cell.
  pub(crate) fn poll_future(self: Pin<&Self>, cx: &mut Context<'_>) -> CellPoll<F::Output>
  where
    F: Future,
  {
    if self
      .state
      .compare_exchange(PRESENT, POLLING, Ordering::Acquire, Ordering::Relaxed)
      .is_err()
    {
      return CellPoll::Rejected;
    }
    let mut claim = PollClaim {
      state: &self.state,
      next: POISONED,
    };
    let pointer: *mut F = self.future.get().cast::<F>();
    // SAFETY: the claim above is the only path to the value while `state`
    // is `POLLING`, so no other reference to it exists; `UnsafeCell` and
    // `ManuallyDrop` are `repr(transparent)`, so the cast pointer is the
    // initialized, aligned `F` this cell was constructed with, which has
    // not been dropped (`drop_future` and `finish` refuse `POLLING`, and a
    // value they dropped never returns to `PRESENT`, which the entry claim
    // requires).
    #[expect(unsafe_code, reason = "exclusive reference into the claimed cell")]
    let future: &mut F = unsafe { &mut *pointer };
    // SAFETY: the value never moves again. This cell is pinned (`self` is
    // `Pin<&Self>`, and the cell is `!Unpin`), it is reachable only through
    // shared references and has no method that moves or replaces the
    // value, and `Drop` destroys the value in place, so the pin guarantee
    // of the cell extends to the field: its memory stays valid and
    // unmoved until `drop_future`, `finish` or `Drop`, all of which need
    // the claim this reference holds to be released first.
    #[expect(unsafe_code, reason = "structural pinning of the stored future")]
    let pinned: Pin<&mut F> = unsafe { Pin::new_unchecked(future) };
    let result = pinned.poll(cx);
    claim.next = if result.is_ready() { COMPLETE } else { PRESENT };
    drop(claim);
    match result {
      Poll::Ready(output) => CellPoll::Ready(output),
      Poll::Pending => CellPoll::Pending,
    }
  }

  /// Drops the stored future in place, exactly once. Returns whether this
  /// call dropped it; `false` when it was dropped before or is being
  /// polled. A panicking destructor unwinds out of this call after the
  /// value counts as dropped.
  #[cfg(test)]
  pub(crate) fn drop_future(self: Pin<&Self>) -> bool {
    self.get_ref().drop_in_place()
  }

  /// Reached only from `drop_future` (pinned) and `Drop` (in place).
  fn drop_in_place(&self) -> bool {
    // A compare-and-swap loop rather than `fetch_update`, whose initial
    // plain load may observe a stale claim; a failed compare-and-swap
    // reads the latest state, so a drop that follows a poll on another
    // thread without any other synchronization still claims the value.
    let mut expected = PRESENT;
    loop {
      match self
        .state
        .compare_exchange(expected, ABSENT, Ordering::AcqRel, Ordering::Acquire)
      {
        Ok(_) => break,
        Err(observed @ (PRESENT | COMPLETE | POISONED)) => expected = observed,
        Err(_) => return false,
      }
    }
    self.destroy_value();
    true
  }

  /// Destroys the value after a claim that took it from a state in which
  /// it is initialized and not being polled.
  fn destroy_value(&self) {
    // SAFETY: the caller's claim succeeded exactly once for this value,
    // from `PRESENT`, `COMPLETE` or `POISONED`, into `ABSENT` or
    // `STORING`, neither of which any claim of the value accepts again, so
    // no other reference to the value exists now or later; the cast
    // pointer is the aligned `F` behind the transparent
    // `UnsafeCell<ManuallyDrop<F>>`, at the address the value was polled
    // at, since only the pinned `drop_future` and `finish` and the
    // in-place `Drop` claim it.
    #[expect(unsafe_code, reason = "in-place destruction of the claimed value")]
    unsafe {
      std::ptr::drop_in_place(self.future.get().cast::<F>());
    }
  }

  /// Ends the task's execution once: drops a future that is still stored
  /// (and not being polled) in place, then stores the outcome that `make`
  /// builds from the destructor's panic payload, if any. Returns false,
  /// without calling `make`, while a poll is in progress or once an
  /// outcome was stored. A panic in `make` stores no outcome.
  pub(crate) fn finish(
    self: Pin<&Self>,
    make: impl FnOnce(Option<Box<dyn Any + Send>>) -> O,
  ) -> bool {
    let mut expected = PRESENT;
    let present = loop {
      match self
        .state
        .compare_exchange(expected, STORING, Ordering::AcqRel, Ordering::Acquire)
      {
        Ok(previous) => break previous != ABSENT,
        Err(observed @ (PRESENT | COMPLETE | POISONED | ABSENT)) => expected = observed,
        Err(_) => return false,
      }
    };
    // Released as `STORED` on every exit, so publication can follow even
    // when the value's destructor or `make` panics.
    let claim = PollClaim {
      state: &self.state,
      next: STORED,
    };
    let payload = if present {
      panic::catch_unwind(AssertUnwindSafe(|| self.get_ref().destroy_value())).err()
    } else {
      None
    };
    let outcome = make(payload);
    // SAFETY: this call holds the `STORING` claim, which it won exactly
    // once (no claim leaves `STORED`, and `STORING` is accepted by none),
    // and nothing reaches the outcome cell before `STORED` is released
    // below: publication first loads `STORED` with acquire ordering.
    #[expect(unsafe_code, reason = "the one write of the outcome")]
    unsafe {
      *self.output.get() = Some(outcome);
    }
    drop(claim);
    true
  }

  /// Publishes a stored outcome once: sets `COMPLETE`, wakes the join
  /// waker, and returns what the caller drops outside every lock. Refuses
  /// before an outcome was stored, and after the first publication.
  pub(crate) fn publish(&self) -> Publication<O> {
    if self.state.load(Ordering::Acquire) != STORED {
      return Publication::refused();
    }
    word::publish(self.word.inner(), self)
  }
}

impl<H, F, O> JoinCells for TaskCell<H, F, O> {
  type Output = O;

  fn waker_will_wake(&self, slot: WakerSlot, waker: &Waker) -> bool {
    // SAFETY: called only while `JOIN_WAKER` is set and the task word gives
    // both sides read access only: the one join handle (here) and
    // publication (`wake_join`) read; the cell is written only by the join
    // handle after it cleared `JOIN_WAKER`, or by publication after its own
    // release of `JOIN_WAKER` showed the handle gone.
    #[expect(unsafe_code, reason = "shared read of the join waker cell")]
    let stored = unsafe { &*self.join_waker.get() };
    stored
      .get(slot)
      .is_some_and(|stored| stored.will_wake(waker))
  }

  fn wake_join(&self, slot: WakerSlot) {
    // SAFETY: called by the one publication that set `COMPLETE` while
    // `JOIN_INTEREST` and `JOIN_WAKER` were set; until it clears
    // `JOIN_WAKER`, the join handle may only read the cell (it cannot clear
    // `JOIN_WAKER` once complete, and its detach leaves the cell to this
    // publication), so shared access is exclusive of every write.
    #[expect(unsafe_code, reason = "shared read of the join waker cell")]
    let stored = unsafe { &*self.join_waker.get() };
    if let Some(waker) = stored.get(slot) {
      waker.wake_by_ref();
    }
  }

  fn update_join_wakers<R>(&self, update: impl FnOnce(&mut JoinWakers) -> R) -> R {
    // SAFETY: called only by the party the word gives the cell: the one
    // join handle while `JOIN_WAKER` is clear and the word was not complete
    // when it last checked (publication reads the cell only if
    // `JOIN_WAKER` was set when it completed), the detaching handle once
    // publication cleared `JOIN_WAKER`, or publication after its own
    // release of `JOIN_WAKER` showed the handle gone. Each of these follows
    // the other side's last access through an acquire-release RMW on the
    // word. The update only moves wakers in and out; it runs no waker code
    // and cannot reach this cell again.
    #[expect(unsafe_code, reason = "exclusive access to the join waker cell")]
    let stored = unsafe { &mut *self.join_waker.get() };
    update(stored)
  }

  fn take_output(&self) -> Option<O> {
    // SAFETY: called only after the word is `COMPLETE`, which publication
    // sets after it observed `STORED` (the one write is finished), by the
    // one party publication chose: the join handle when `JOIN_INTEREST`
    // was set then (publication never touches the cell), or publication
    // when it was not (the handle detached and never touches it again).
    // The one join handle is not shared, so its takes are sequential.
    #[expect(unsafe_code, reason = "exclusive access to the published outcome")]
    let stored = unsafe { &mut *self.output.get() };
    stored.take()
  }
}

impl<H, F, O> word::Sealed for TaskCell<H, F, O> {}

impl<H: Sync + Send, F: Send, O: Send> JoinSide for TaskCell<H, F, O> {
  type Output = O;

  fn join_complete(&self) -> bool {
    self.word.is_complete()
  }

  fn join_poll(
    &self,
    _key: word::JoinKey,
    slot: word::WakerSlot,
    waker: &Waker,
    take: bool,
  ) -> Poll<Option<O>> {
    word::join_poll(self.word.inner(), self, slot, waker, take)
  }

  fn join_take(&self, _key: word::JoinKey) -> Option<Option<O>> {
    word::join_take(self.word.inner(), self)
  }

  fn join_detach(&self, _key: word::JoinKey) -> (Option<O>, word::JoinWakers) {
    word::join_detach(self.word.inner(), self)
  }
}

/// Proof that a lending operation comes from this module.
pub(crate) struct LendKey(());

/// The task's own word and borrowed waker, for [`TaskSlot`] and [`Lease`].
/// Sealed: only the cell implements it, so the word is always the cell's
/// own.
pub(crate) trait TaskLend: word::Sealed + Send + Sync {
  fn lend_word(&self, key: LendKey) -> &word::PollWord;
  /// A waker borrowing the allocation that `data` points into; `data` is
  /// the lease's pointer, taken from the owning `Arc`.
  fn lend_waker(&self, key: LendKey, data: NonNull<()>) -> WakerRef<'_>;
}

impl<H: TaskHeader, F: Send + 'static, O: Send + 'static> TaskLend for TaskCell<H, F, O> {
  fn lend_word(&self, _key: LendKey) -> &word::PollWord {
    self.word.inner()
  }

  fn lend_waker(&self, _key: LendKey, data: NonNull<()>) -> WakerRef<'_> {
    debug_assert!(std::ptr::addr_eq(data.as_ptr(), std::ptr::from_ref(self)));
    Self::waker_ref(data)
  }
}

/// The scheduler's owner of one task, lent to one turn at a time.
pub(crate) struct TaskSlot<T: ?Sized + TaskLend> {
  task: Option<Pin<Arc<T>>>,
}

impl<T: ?Sized + TaskLend> TaskSlot<T> {
  pub(crate) const fn empty() -> Self {
    Self { task: None }
  }

  pub(crate) fn is_occupied(&self) -> bool {
    self.task.is_some()
  }

  /// The installed owner, by shared reference.
  pub(crate) fn get(&self) -> Option<&Pin<Arc<T>>> {
    self.task.as_ref()
  }

  /// Installs an owner into an empty slot.
  pub(crate) fn install(&mut self, task: Pin<Arc<T>>) {
    assert!(self.task.is_none(), "task slot already occupied");
    self.task = Some(task);
  }

  /// Begins a turn for the installed task's queue entry and lends it to
  /// that turn. `None` when the slot is empty or the word is not queued.
  pub(crate) fn lend(&mut self) -> Option<Lease<T>> {
    let task = self.task.as_ref()?;
    if !task.lend_word(LendKey(())).begin() {
      return None;
    }
    Some(Lease {
      task: arc_pointer(task),
    })
  }

  /// Ends the final turn: hands the lent owner to it. The word stays
  /// `RUNNING` (publication then sets `COMPLETE`).
  ///
  /// # Panics
  ///
  /// When the lease is not for the task in this slot.
  pub(crate) fn take(&mut self, lease: Lease<T>) -> Pin<Arc<T>> {
    let lent = lease.task.as_ptr().cast_const();
    let task = self
      .task
      .take_if(|task| std::ptr::addr_eq(std::ptr::from_ref::<T>(task), lent));
    let Some(task) = task else {
      panic!("lease returned to another task slot");
    };
    std::mem::forget(lease);
    task
  }

  /// Takes the owner of a task that no turn holds; `None` when empty or
  /// while a lease is out.
  pub(crate) fn take_idle(&mut self) -> Option<Pin<Arc<T>>> {
    if self.task.as_ref()?.lend_word(LendKey(())).is_running() {
      return None;
    }
    self.task.take()
  }
}

impl<T: ?Sized + TaskLend> Drop for TaskSlot<T> {
  fn drop(&mut self) {
    if let Some(task) = self.task.take()
      && task.lend_word(LendKey(())).is_running()
    {
      // A lease may still point into the allocation: keep it alive.
      std::mem::forget(task);
    }
  }
}

/// The pointer `Arc::as_ptr` returns for a pinned owner: it may reach the
/// whole allocation, including the reference counts a waker updates.
fn arc_pointer<T: ?Sized>(task: &Pin<Arc<T>>) -> NonNull<T> {
  // SAFETY: `Pin<Arc<T>>` is `repr(transparent)` over `Arc<T>`, so the
  // cast reference is a valid `&Arc<T>` for the same borrow. It is used only
  // for `Arc::as_ptr`, which neither moves the value nor gives out an
  // unpinned owner.
  #[expect(unsafe_code, reason = "reads the pinned owner's pointer")]
  let arc: &Arc<T> = unsafe { &*std::ptr::from_ref(task).cast::<Arc<T>>() };
  let pointer = Arc::as_ptr(arc).cast_mut();
  match NonNull::new(pointer) {
    Some(pointer) => pointer,
    None => unreachable!("an `Arc` never points at null"),
  }
}

/// One turn's use of a task that a [`TaskSlot`] owns, without a reference
/// count of its own. Ends with [`Lease::finish_pending`], with
/// [`TaskSlot::take`], or, if dropped, as a pending finish whose requeue is
/// discarded.
pub(crate) struct Lease<T: ?Sized + TaskLend> {
  task: NonNull<T>,
}

impl<T: ?Sized + TaskLend> Lease<T> {
  /// The lent task, pinned.
  pub(crate) fn task(&self) -> Pin<&T> {
    // SAFETY: the pointer came from a `Pin<Arc<T>>` that a `TaskSlot`
    // held when `lend` won `RUNNING` for this lease, and `RUNNING` is
    // cleared only by this lease (its pending finish or its drop) or kept
    // when `take` hands that owner to the turn; until then no slot drops or
    // gives up the owner (`take_idle` and `Drop` refuse while `RUNNING`,
    // `install` refuses an occupied slot, and `take` needs this lease), so
    // the allocation is alive for the lease, and with it for this borrow.
    #[expect(unsafe_code, reason = "borrows the slot-owned task for its turn")]
    let task: &T = unsafe { self.task.as_ref() };
    // SAFETY: the value lives in a `Pin<Arc<T>>` allocation and is only
    // reached by shared reference, so it is pinned for this borrow.
    #[expect(unsafe_code, reason = "the allocation is pinned")]
    unsafe {
      Pin::new_unchecked(task)
    }
  }

  /// A `Waker` borrowed from the lent task, without a reference count.
  pub(crate) fn waker(&self) -> WakerRef<'_> {
    self
      .task()
      .get_ref()
      .lend_waker(LendKey(()), self.task.cast::<()>())
  }

  /// Ends a pending turn (see `finish_pending` on the word). Returns true
  /// when the task was woken during the turn: the caller then owns its new
  /// queue entry and must insert it.
  pub(crate) fn finish_pending(self) -> bool {
    let notified = self
      .task()
      .get_ref()
      .lend_word(LendKey(()))
      .finish_pending();
    std::mem::forget(self);
    notified
  }
}

impl<T: ?Sized + TaskLend> Drop for Lease<T> {
  fn drop(&mut self) {
    // An abandoned turn (an unwinding dispatcher) still releases `RUNNING`,
    // so the slot can drop or cancel the task later.
    let _ = self
      .task()
      .get_ref()
      .lend_word(LendKey(()))
      .finish_pending();
  }
}

/// A `Waker` borrowed from a task allocation for `'a`: it holds no
/// reference count, and its clones hold their own.
pub(crate) struct WakerRef<'a> {
  waker: ManuallyDrop<Waker>,
  _task: PhantomData<&'a ()>,
}

impl Deref for WakerRef<'_> {
  type Target = Waker;

  fn deref(&self) -> &Waker {
    &self.waker
  }
}

impl<H: TaskHeader, F: Send + 'static, O: Send + 'static> TaskCell<H, F, O> {
  const VTABLE: RawWakerVTable = RawWakerVTable::new(
    Self::clone_raw,
    Self::wake_raw,
    Self::wake_by_ref_raw,
    Self::drop_raw,
  );

  /// The one vtable of this cell type's wakers, so a clone and the
  /// borrowed waker it came from compare equal in `Waker::will_wake`. Not
  /// inlined: each inlined copy may promote its own vtable. Still a
  /// best-effort check (Miri does not deduplicate the promoted constant).
  #[inline(never)]
  fn vtable() -> &'static RawWakerVTable {
    &Self::VTABLE
  }

  /// A `Waker` borrowing the allocation `data` points into, for as long as
  /// the caller's borrow of a lease that keeps the allocation alive.
  fn waker_ref<'a>(data: NonNull<()>) -> WakerRef<'a> {
    // SAFETY: `data` is a lease's pointer, which `Arc::as_ptr` returned
    // for the slot's owner of this cell, so it may reach the whole
    // allocation, and the lease keeps that owner alive for the borrow this
    // `WakerRef` carries. The vtable's functions treat `data` as such a
    // pointer: `clone` adds a strong count, `wake` and `drop` give one
    // back, and `wake_by_ref` only reads the header and word. This waker
    // is never dropped (`ManuallyDrop`) and cannot be woken by value, so
    // it gives back no count it did not take.
    #[expect(unsafe_code, reason = "a waker that borrows the task allocation")]
    let waker =
      unsafe { Waker::from_raw(RawWaker::new(data.as_ptr().cast_const(), Self::vtable())) };
    WakerRef {
      waker: ManuallyDrop::new(waker),
      _task: PhantomData,
    }
  }

  /// # Safety
  ///
  /// `data` is `Arc::as_ptr` of a cell in a live `Arc` allocation.
  #[expect(unsafe_code, reason = "an entry of the borrowed waker's vtable")]
  unsafe fn clone_raw(data: *const ()) -> RawWaker {
    // SAFETY: by this function's contract the allocation is live, so its
    // strong count is at least one; the new count is the clone's.
    #[expect(unsafe_code, reason = "the cloned waker's reference count")]
    unsafe {
      Arc::increment_strong_count(data.cast::<Self>());
    }
    RawWaker::new(data, Self::vtable())
  }

  /// # Safety
  ///
  /// `data` points at a cell in a live `Arc` allocation and carries one
  /// strong count, which this call consumes.
  #[expect(unsafe_code, reason = "an entry of the borrowed waker's vtable")]
  unsafe fn wake_raw(data: *const ()) {
    // SAFETY: an owned waker (a clone) holds one strong count of the
    // allocation `data` points into, which this takes over and drops.
    #[expect(unsafe_code, reason = "takes over the waker's count")]
    let task = unsafe { Arc::from_raw(data.cast::<Self>()) };
    task.header.wake_by_ref(&task.word);
  }

  /// # Safety
  ///
  /// `data` points at a cell in a live `Arc` allocation.
  #[expect(unsafe_code, reason = "an entry of the borrowed waker's vtable")]
  unsafe fn wake_by_ref_raw(data: *const ()) {
    // SAFETY: the waker this call reaches through keeps the allocation
    // alive (by its count or, for a `WakerRef`, by its borrow); the cell
    // is only read.
    #[expect(unsafe_code, reason = "reads the woken task")]
    let task = unsafe { &*data.cast::<Self>() };
    task.header.wake_by_ref(&task.word);
  }

  /// # Safety
  ///
  /// `data` points at a cell in a live `Arc` allocation and carries one
  /// strong count, which this call consumes.
  #[expect(unsafe_code, reason = "an entry of the borrowed waker's vtable")]
  unsafe fn drop_raw(data: *const ()) {
    // SAFETY: an owned waker (a clone) holds one strong count, given back
    // here; a `WakerRef` is never dropped.
    #[expect(unsafe_code, reason = "gives back the waker's count")]
    unsafe {
      drop(Arc::from_raw(data.cast::<Self>()));
    }
  }
}

impl<H, F, O> Drop for TaskCell<H, F, O> {
  fn drop(&mut self) {
    // A value still present is dropped once; one that was dropped before
    // or (unreachably, since `&mut self` excludes a running poll) is
    // being polled is left alone. The outcome and the join waker are plain
    // fields and drop with the cell.
    self.drop_in_place();
  }
}

impl<H: TaskHeader, F: Send + 'static, O: Send + 'static> Wake for TaskCell<H, F, O> {
  fn wake(self: Arc<Self>) {
    self.header.wake_by_ref(&self.word);
  }

  fn wake_by_ref(self: &Arc<Self>) {
    self.header.wake_by_ref(&self.word);
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;
  use std::cell::RefCell;
  use std::marker::PhantomData;
  use std::rc::Rc;
  use std::sync::Mutex;
  use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};

  fn context() -> Context<'static> {
    Context::from_waker(Waker::noop())
  }

  type Cell<F> = Pin<Arc<TaskCell<(), F>>>;

  fn cell<F>(future: F) -> Cell<F> {
    TaskCell::new((), future)
  }

  /// A slot through which a future reaches its own cell after construction.
  type SelfSlot<F> = Arc<Mutex<Option<Cell<F>>>>;

  struct Countdown {
    remaining: u32,
    dropped: Arc<AtomicBool>,
  }

  impl Future for Countdown {
    type Output = u32;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<u32> {
      if self.remaining == 0 {
        Poll::Ready(7)
      } else {
        self.remaining -= 1;
        Poll::Pending
      }
    }
  }

  impl Drop for Countdown {
    fn drop(&mut self) {
      assert!(!self.dropped.swap(true, Ordering::SeqCst), "dropped twice");
    }
  }

  fn countdown(remaining: u32) -> (Countdown, Arc<AtomicBool>) {
    let dropped = Arc::new(AtomicBool::new(false));
    let future = Countdown {
      remaining,
      dropped: Arc::clone(&dropped),
    };
    (future, dropped)
  }

  struct YieldOnce(bool);

  impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
      if self.0 {
        Poll::Ready(())
      } else {
        self.0 = true;
        Poll::Pending
      }
    }
  }

  /// Holds a `RefCell` borrow across a yield: the suspended state points
  /// into itself, so it must not move between the first poll and `Drop`.
  #[expect(
    clippy::await_holding_refcell_ref,
    reason = "the live borrow is the self-reference under test"
  )]
  async fn self_borrowing_block() -> u64 {
    let shared = RefCell::new(5u64);
    let mut guard = shared.borrow_mut();
    YieldOnce(false).await;
    *guard += 1;
    drop(guard);
    *shared.borrow()
  }

  #[test]
  fn polls_to_completion_and_drops_exactly_once() {
    let (future, dropped) = countdown(2);
    let cell = cell(future);
    assert!(matches!(
      cell.as_ref().poll_future(&mut context()),
      CellPoll::Pending
    ));
    assert!(matches!(
      cell.as_ref().poll_future(&mut context()),
      CellPoll::Pending
    ));
    assert!(matches!(
      cell.as_ref().poll_future(&mut context()),
      CellPoll::Ready(7)
    ));
    assert!(cell.holds_value());
    assert!(!dropped.load(Ordering::SeqCst));
    assert!(matches!(
      cell.as_ref().poll_future(&mut context()),
      CellPoll::Rejected
    ));
    assert!(cell.as_ref().drop_future());
    assert!(dropped.load(Ordering::SeqCst));
    assert!(!cell.holds_value());
    assert!(!cell.as_ref().drop_future());
    assert!(matches!(
      cell.as_ref().poll_future(&mut context()),
      CellPoll::Rejected
    ));
    drop(cell);
  }

  #[test]
  fn drops_before_completion_and_rejects_later_polls() {
    let (future, dropped) = countdown(5);
    let cell = cell(future);
    assert!(matches!(
      cell.as_ref().poll_future(&mut context()),
      CellPoll::Pending
    ));
    assert!(cell.as_ref().drop_future());
    assert!(dropped.load(Ordering::SeqCst));
    assert!(matches!(
      cell.as_ref().poll_future(&mut context()),
      CellPoll::Rejected
    ));
    assert!(!cell.as_ref().drop_future());
  }

  #[test]
  fn cell_drop_releases_a_present_or_complete_value_once() {
    let (future, dropped) = countdown(1);
    drop(cell(future));
    assert!(dropped.load(Ordering::SeqCst));

    let (future, dropped) = countdown(0);
    let complete = cell(future);
    assert!(matches!(
      complete.as_ref().poll_future(&mut context()),
      CellPoll::Ready(7)
    ));
    drop(complete);
    assert!(dropped.load(Ordering::SeqCst));

    let (future, dropped) = countdown(0);
    let absent = cell(future);
    assert!(absent.as_ref().drop_future());
    drop(absent);
    assert!(dropped.load(Ordering::SeqCst));
  }

  #[test]
  fn header_is_shared_and_dropped_with_the_allocation() {
    struct Header(Arc<AtomicUsize>);
    impl Drop for Header {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let (future, dropped) = countdown(0);
    let cell = TaskCell::<_, _>::new(Header(Arc::clone(&drops)), future);
    assert_eq!(Arc::strong_count(&cell.header().0), 2);
    let other = Pin::clone(&cell);
    assert_eq!(TaskCell::strong_count(&cell), 2);
    drop(other);
    assert_eq!(TaskCell::strong_count(&cell), 1);
    drop(cell);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn waker_shares_the_allocation_and_wakes_through_the_header() {
    struct Header(AtomicUsize);
    impl TaskHeader for Header {
      fn wake_by_ref(&self, _word: &TaskWord) {
        self.0.fetch_add(1, Ordering::SeqCst);
      }
    }
    let (future, dropped) = countdown(0);
    let cell = TaskCell::<_, _>::new(Header(AtomicUsize::new(0)), future);
    let waker = TaskCell::waker(&cell);
    let other = TaskCell::waker(&cell);
    assert!(waker.will_wake(&other));
    assert_eq!(TaskCell::strong_count(&cell), 3);
    waker.wake_by_ref();
    other.wake();
    assert_eq!(cell.header().0.load(Ordering::SeqCst), 2);
    assert_eq!(TaskCell::strong_count(&cell), 2);
    // A stale waker keeps the allocation, and the future in it, alive.
    drop(cell);
    assert!(!dropped.load(Ordering::SeqCst));
    drop(waker);
    assert!(dropped.load(Ordering::SeqCst));
  }

  #[test]
  fn cell_is_never_unpin() {
    // `Pin::into_inner` and `Pin::get_mut`, the safe ways out of a `Pin`,
    // need `Unpin`; autoref specialization reports whether a type has it.
    struct Probe<T>(PhantomData<T>);
    trait Fallback {
      fn is_unpin(&self) -> bool {
        false
      }
    }
    impl<T> Fallback for Probe<T> {}
    impl<T: Unpin> Probe<T> {
      fn is_unpin(&self) -> bool {
        true
      }
    }
    assert!(Probe::<u8>(PhantomData).is_unpin());
    assert!(!Probe::<TaskCell<(), std::future::Ready<()>>>(PhantomData).is_unpin());
    assert!(!Probe::<TaskCell<Mutex<u8>, Countdown>>(PhantomData).is_unpin());
  }

  #[test]
  fn panic_in_poll_poisons_the_cell_and_still_drops_in_place() {
    struct PanicOnce {
      dropped: Arc<AtomicBool>,
    }
    impl Future for PanicOnce {
      type Output = ();
      fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        std::panic::panic_any("poll panic");
      }
    }
    impl Drop for PanicOnce {
      fn drop(&mut self) {
        assert!(!self.dropped.swap(true, Ordering::SeqCst), "dropped twice");
      }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let cell = cell(PanicOnce {
      dropped: Arc::clone(&dropped),
    });
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      cell.as_ref().poll_future(&mut context())
    }));
    let payload = unwound.expect_err("the poll panic unwinds out of the cell");
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"poll panic"));
    assert!(cell.holds_value());
    assert!(!dropped.load(Ordering::SeqCst));
    assert!(matches!(
      cell.as_ref().poll_future(&mut context()),
      CellPoll::Rejected
    ));
    assert!(cell.as_ref().drop_future());
    assert!(dropped.load(Ordering::SeqCst));
    assert!(!cell.as_ref().drop_future());
  }

  #[test]
  #[expect(
    clippy::await_holding_refcell_ref,
    reason = "the live borrow is the self-reference under test"
  )]
  fn poll_after_poison_is_rejected_with_a_live_self_borrow() {
    let cell = cell(async {
      let shared = RefCell::new(1u8);
      let _guard = shared.borrow_mut();
      YieldOnce(false).await;
      panic!("boom");
    });
    assert!(matches!(
      cell.as_ref().poll_future(&mut context()),
      CellPoll::Pending
    ));
    assert!(
      std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cell.as_ref().poll_future(&mut context())
      }))
      .is_err()
    );
    assert!(matches!(
      cell.as_ref().poll_future(&mut context()),
      CellPoll::Rejected
    ));
    assert!(cell.as_ref().drop_future());
  }

  #[test]
  fn panicking_destructor_counts_as_dropped() {
    struct PanicOnDrop;
    impl Future for PanicOnDrop {
      type Output = ();
      fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
      }
    }
    impl Drop for PanicOnDrop {
      fn drop(&mut self) {
        std::panic::panic_any("drop panic");
      }
    }
    let cell = cell(PanicOnDrop);
    assert!(matches!(
      cell.as_ref().poll_future(&mut context()),
      CellPoll::Ready(())
    ));
    let unwound =
      std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cell.as_ref().drop_future()));
    assert!(unwound.is_err());
    assert!(!cell.holds_value());
    assert!(!cell.as_ref().drop_future());
    // The cell's own destructor must not run the destructor again.
    drop(cell);
  }

  #[test]
  fn panicking_destructor_through_cell_drop_runs_once() {
    struct PanicOnDrop(Arc<AtomicU64>);
    impl Future for PanicOnDrop {
      type Output = ();
      fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
      }
    }
    impl Drop for PanicOnDrop {
      fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("drop panic");
      }
    }
    let drops = Arc::new(AtomicU64::new(0));
    let cell = cell(PanicOnDrop(Arc::clone(&drops)));
    assert!(matches!(
      cell.as_ref().poll_future(&mut context()),
      CellPoll::Pending
    ));
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(cell)));
    assert!(unwound.is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn reentrant_and_concurrent_polls_are_rejected_and_drop_waits() {
    // A reentrant poll: the future polls its own cell.
    struct SelfPoll {
      cell: SelfSlot<SelfPoll>,
      observed: Arc<AtomicBool>,
    }
    impl Future for SelfPoll {
      type Output = ();
      fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let cell = self.cell.lock().unwrap().take().expect("cell handed in");
        assert!(matches!(cell.as_ref().poll_future(cx), CellPoll::Rejected));
        assert!(!cell.as_ref().drop_future());
        self.observed.store(true, Ordering::SeqCst);
        Poll::Pending
      }
    }
    let observed = Arc::new(AtomicBool::new(false));
    let slot: SelfSlot<SelfPoll> = Arc::new(Mutex::new(None));
    let reentrant = cell(SelfPoll {
      cell: Arc::clone(&slot),
      observed: Arc::clone(&observed),
    });
    *slot.lock().unwrap() = Some(Pin::clone(&reentrant));
    assert!(matches!(
      reentrant.as_ref().poll_future(&mut context()),
      CellPoll::Pending
    ));
    assert!(observed.load(Ordering::SeqCst));
    assert!(reentrant.as_ref().drop_future());

    // Two threads: the first poll blocks inside the future until the second
    // thread has been rejected.
    struct Gate {
      entered: Arc<AtomicBool>,
      release: Arc<AtomicBool>,
    }
    impl Future for Gate {
      type Output = ();
      fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        self.entered.store(true, Ordering::SeqCst);
        while !self.release.load(Ordering::SeqCst) {
          std::thread::yield_now();
        }
        Poll::Pending
      }
    }
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let gate = cell(Gate {
      entered: Arc::clone(&entered),
      release: Arc::clone(&release),
    });
    let poller = {
      let gate = Pin::clone(&gate);
      std::thread::spawn(move || gate.as_ref().poll_future(&mut context()))
    };
    while !entered.load(Ordering::SeqCst) {
      std::thread::yield_now();
    }
    assert!(matches!(
      gate.as_ref().poll_future(&mut context()),
      CellPoll::Rejected
    ));
    assert!(!gate.as_ref().drop_future());
    release.store(true, Ordering::SeqCst);
    assert!(matches!(poller.join().unwrap(), CellPoll::Pending));
    assert!(gate.as_ref().drop_future());
  }

  #[test]
  fn destructor_reentering_its_own_cell_is_rejected() {
    struct Reenter {
      cell: SelfSlot<Reenter>,
      saw: Arc<AtomicBool>,
    }
    impl Future for Reenter {
      type Output = ();
      fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
      }
    }
    impl Drop for Reenter {
      fn drop(&mut self) {
        let cell = self.cell.lock().unwrap().take().expect("cell handed in");
        assert!(matches!(
          cell.as_ref().poll_future(&mut context()),
          CellPoll::Rejected
        ));
        assert!(!cell.as_ref().drop_future());
        self.saw.store(true, Ordering::SeqCst);
      }
    }
    let saw = Arc::new(AtomicBool::new(false));
    let slot: SelfSlot<Reenter> = Arc::new(Mutex::new(None));
    let reenter = cell(Reenter {
      cell: Arc::clone(&slot),
      saw: Arc::clone(&saw),
    });
    *slot.lock().unwrap() = Some(Pin::clone(&reenter));
    assert!(matches!(
      reenter.as_ref().poll_future(&mut context()),
      CellPoll::Pending
    ));
    assert!(reenter.as_ref().drop_future());
    assert!(saw.load(Ordering::SeqCst));
    drop(reenter);
  }

  #[test]
  fn self_referential_async_block_is_pinned_in_place() {
    use std::future::poll_fn;
    let dropped = Arc::new(AtomicBool::new(false));
    let witness = Arc::clone(&dropped);
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
      fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
      }
    }
    let block = |flag: DropFlag| async move {
      let _flag = flag;
      let local = [1u8, 2, 3, 4];
      let borrowed = &local;
      let mut yields = 0;
      // The borrow is held across the yield points, so the async block's
      // state holds a pointer into itself between polls.
      poll_fn(|_cx| {
        if yields < 3 {
          yields += 1;
          Poll::Pending
        } else {
          Poll::Ready(())
        }
      })
      .await;
      borrowed
        .iter()
        .map(|byte| usize::from(*byte))
        .sum::<usize>()
    };
    // Dropped in place while suspended with the borrow live.
    let suspended = cell(block(DropFlag(witness)));
    for _ in 0..2 {
      assert!(matches!(
        suspended.as_ref().poll_future(&mut context()),
        CellPoll::Pending
      ));
    }
    assert!(!dropped.load(Ordering::SeqCst));
    assert!(suspended.as_ref().drop_future());
    assert!(dropped.load(Ordering::SeqCst));
    // Polled to completion: the output reads through the self-reference.
    let flag = DropFlag(Arc::new(AtomicBool::new(false)));
    let completed = cell(block(flag));
    for _ in 0..3 {
      assert!(matches!(
        completed.as_ref().poll_future(&mut context()),
        CellPoll::Pending
      ));
    }
    assert!(matches!(
      completed.as_ref().poll_future(&mut context()),
      CellPoll::Ready(10)
    ));
    assert!(completed.as_ref().drop_future());
  }

  /// The first reviewer probe in its only expressible form: a future that
  /// holds a `RefCell` borrow across a yield is polled once and then
  /// dropped, in place, by the pinned allocation, through `drop_future`,
  /// through the last owner, or after the owner that polled it is gone.
  /// The unsound form (moving the polled cell out of its box before the
  /// drop) needs the cell by value or an unpinned `Arc`, which no API
  /// provides.
  #[test]
  fn suspended_self_borrow_is_dropped_in_place() {
    let last_owner = cell(self_borrowing_block());
    assert!(matches!(
      last_owner.as_ref().poll_future(&mut context()),
      CellPoll::Pending
    ));
    drop(last_owner);

    let explicit = cell(self_borrowing_block());
    assert!(matches!(
      explicit.as_ref().poll_future(&mut context()),
      CellPoll::Pending
    ));
    assert!(explicit.as_ref().drop_future());
    drop(explicit);

    let polled = cell(self_borrowing_block());
    let stale = Pin::clone(&polled);
    assert!(matches!(
      polled.as_ref().poll_future(&mut context()),
      CellPoll::Pending
    ));
    drop(polled);
    assert!(matches!(
      stale.as_ref().poll_future(&mut context()),
      CellPoll::Ready(6)
    ));
  }

  /// The second reviewer probe: a future that publishes its own address
  /// when polled and withdraws it in `Drop`, as an intrusive list node
  /// does, relying on the pin guarantee. Notifications write through the
  /// published address; the cell keeps the node there until its `Drop`
  /// withdrew the registration, so every write lands in a live node.
  #[test]
  fn intrusive_registration_is_withdrawn_before_the_memory_goes() {
    struct Registry {
      node: Mutex<*mut Node>,
      hits: AtomicU64,
    }
    struct Node {
      registry: Rc<Registry>,
      hits: u64,
      _pin: PhantomPinned,
    }
    impl Future for Node {
      type Output = ();
      fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        // SAFETY: the pointer is only published, not used to move the
        // node; the pinned `Node` is reached through it only while the
        // registration below is in place, which `Drop` withdraws.
        #[expect(unsafe_code, reason = "publishes the pinned node's address")]
        let node: *mut Node = unsafe { self.get_unchecked_mut() };
        *self_registry(node).node.lock().unwrap() = node;
        Poll::Pending
      }
    }
    fn self_registry(node: *mut Node) -> Rc<Registry> {
      // SAFETY: `node` was just derived from a live `Pin<&mut Node>`.
      #[expect(unsafe_code, reason = "reads a field of the node being polled")]
      let registry = unsafe { &(*node).registry };
      Rc::clone(registry)
    }
    impl Drop for Node {
      fn drop(&mut self) {
        let address = std::ptr::from_mut(self);
        let mut registered = self.registry.node.lock().unwrap();
        if *registered == address {
          *registered = std::ptr::null_mut();
        }
      }
    }
    impl Registry {
      fn notify(&self) {
        let registered = self.node.lock().unwrap();
        let node = *registered;
        if !node.is_null() {
          // SAFETY: the pointer was published by a pinned node that is not
          // dropped while registered, and the registry lock held here
          // excludes its `Drop` from withdrawing it concurrently.
          #[expect(unsafe_code, reason = "writes through the registered pointer")]
          unsafe {
            (*node).hits += 1;
          }
          self.hits.fetch_add(1, Ordering::SeqCst);
        }
      }
    }
    let registry = Rc::new(Registry {
      node: Mutex::new(std::ptr::null_mut()),
      hits: AtomicU64::new(0),
    });
    let node = cell(Node {
      registry: Rc::clone(&registry),
      hits: 0,
      _pin: PhantomPinned,
    });
    let stale = Pin::clone(&node);
    assert!(matches!(
      node.as_ref().poll_future(&mut context()),
      CellPoll::Pending
    ));
    registry.notify();
    drop(node);
    // The stale owner keeps the node registered and at its address.
    registry.notify();
    assert_eq!(registry.hits.load(Ordering::SeqCst), 2);
    assert!(stale.as_ref().drop_future());
    assert!(registry.node.lock().unwrap().is_null());
    registry.notify();
    assert_eq!(registry.hits.load(Ordering::SeqCst), 2);
    drop(stale);
  }

  /// Writes on every poll and reads them back in `Drop`, so Miri's
  /// data-race detector reports a hand-over between threads that lacks a
  /// release/acquire pair: the poll-exit store and the next claim are the
  /// only synchronization the tests below allow.
  struct Writes {
    buffer: Box<[u64; 8]>,
    polls: u64,
  }

  impl Future for Writes {
    type Output = u64;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<u64> {
      self.polls += 1;
      let polls = self.polls;
      self.buffer[usize::try_from(polls % 8).unwrap()] = polls;
      if polls > 3 {
        Poll::Ready(polls)
      } else {
        Poll::Pending
      }
    }
  }

  impl Drop for Writes {
    fn drop(&mut self) {
      let sum: u64 = self.buffer.iter().sum();
      self.polls = sum;
    }
  }

  fn writes() -> Writes {
    Writes {
      buffer: Box::new([0; 8]),
      polls: 0,
    }
  }

  #[test]
  fn poll_on_one_thread_is_visible_to_a_drop_on_another() {
    for _ in 0..4 {
      let shared = cell(writes());
      let polled = Arc::new(AtomicBool::new(false));
      let poller = {
        let shared = Pin::clone(&shared);
        let polled = Arc::clone(&polled);
        std::thread::spawn(move || {
          for _ in 0..3 {
            assert!(matches!(
              shared.as_ref().poll_future(&mut context()),
              CellPoll::Pending
            ));
          }
          polled.store(true, Ordering::Relaxed);
        })
      };
      let dropper = {
        let shared = Pin::clone(&shared);
        std::thread::spawn(move || {
          while !polled.load(Ordering::Relaxed) {
            std::thread::yield_now();
          }
          assert!(shared.as_ref().drop_future());
        })
      };
      dropper.join().unwrap();
      poller.join().unwrap();
    }
  }

  #[test]
  fn poll_on_one_thread_is_visible_to_the_last_owner_on_another() {
    let shared = cell(writes());
    let polled = Arc::new(AtomicBool::new(false));
    let poller = {
      let shared = Pin::clone(&shared);
      let polled = Arc::clone(&polled);
      std::thread::spawn(move || {
        for _ in 0..2 {
          assert!(matches!(
            shared.as_ref().poll_future(&mut context()),
            CellPoll::Pending
          ));
        }
        drop(shared);
        polled.store(true, Ordering::Relaxed);
      })
    };
    // The last owner's `Drop` runs the destructor after the poller's
    // owner was released. (The `Arc` count orders this path on its own, so
    // only the test above is sensitive to the claim's ordering.)
    while !polled.load(Ordering::Relaxed) {
      std::thread::yield_now();
    }
    drop(shared);
    poller.join().unwrap();
  }

  /// Three threads race to poll; each keeps trying until one poll of its
  /// own succeeds, so every hand-over between successful polls crosses
  /// threads and is ordered only by the poll-exit store and the next claim.
  #[test]
  fn racing_polls_hand_the_future_over_with_its_writes() {
    for _ in 0..2 {
      let shared = cell(writes());
      let pollers: Vec<_> = (0..3)
        .map(|_| {
          let shared = Pin::clone(&shared);
          std::thread::spawn(move || {
            loop {
              match shared.as_ref().poll_future(&mut context()) {
                CellPoll::Pending => break,
                CellPoll::Ready(polls) => panic!("ready after {polls} polls"),
                CellPoll::Rejected => std::thread::yield_now(),
              }
            }
          })
        })
        .collect();
      for poller in pollers {
        poller.join().unwrap();
      }
      assert!(matches!(
        shared.as_ref().poll_future(&mut context()),
        CellPoll::Ready(4)
      ));
      assert!(shared.as_ref().drop_future());
    }
  }

  #[test]
  fn send_and_sync_follow_the_future_and_header() {
    fn sync<T: Sync>() {}
    fn send<T: Send>() {}
    struct SendNotSync(std::cell::Cell<u8>);
    impl Future for SendNotSync {
      type Output = std::rc::Rc<u8>;
      fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(std::rc::Rc::new(self.0.get()))
      }
    }
    sync::<TaskCell<(), SendNotSync>>();
    send::<TaskCell<(), SendNotSync>>();
    sync::<TaskCell<Mutex<u8>, SendNotSync>>();
  }

  type Joined<F> = Pin<Arc<TaskCell<(), F, u64>>>;

  fn joined<F>(future: F) -> (Joined<F>, TaskJoin<TaskCell<(), F, u64>>)
  where
    F: Send,
  {
    TaskCell::new_with_join((), future, |task| task)
  }

  /// A waker that records its wakes and drops in `Relaxed` counters, so only
  /// the cell's own protocol orders it with the other thread.
  struct Probe {
    wakes: AtomicUsize,
    drops: Arc<AtomicUsize>,
  }

  impl Wake for Probe {
    fn wake(self: Arc<Self>) {
      self.wakes.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.wakes.fetch_add(1, Ordering::Relaxed);
    }
  }

  impl Drop for Probe {
    fn drop(&mut self) {
      self.drops.fetch_add(1, Ordering::Relaxed);
    }
  }

  fn probe() -> (Arc<Probe>, Arc<AtomicUsize>, Waker) {
    let drops = Arc::new(AtomicUsize::new(0));
    let probe = Arc::new(Probe {
      wakes: AtomicUsize::new(0),
      drops: Arc::clone(&drops),
    });
    let waker = Waker::from(Arc::clone(&probe));
    (probe, drops, waker)
  }

  #[test]
  fn finish_drops_the_future_stores_once_and_publication_follows() {
    let (future, dropped) = countdown(5);
    let (task, mut join) = joined(future);
    assert!(!task.publish().published);
    assert!(task.as_ref().finish(|payload| {
      assert!(payload.is_none());
      9
    }));
    assert!(dropped.load(Ordering::SeqCst));
    assert!(!task.holds_value());
    assert!(!task.as_ref().finish(|_| unreachable!("stored twice")));
    assert!(matches!(
      task.as_ref().poll_future(&mut context()),
      CellPoll::Rejected
    ));
    assert!(join.take().is_none());
    let publication = task.publish();
    assert!(publication.published && publication.output.is_none());
    assert!(!task.publish().published);
    assert_eq!(join.take(), Some(Some(9)));
    assert_eq!(join.take(), Some(None));
  }

  #[test]
  fn finish_refuses_while_a_poll_holds_the_value_and_reports_a_panicking_drop() {
    struct FinishWhilePolling(Arc<Mutex<Option<Cell<Self>>>>);
    impl Future for FinishWhilePolling {
      type Output = ();
      fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        let cell = self.0.lock().unwrap().clone().unwrap();
        assert!(!cell.as_ref().finish(|_| unreachable!("finished mid-poll")));
        Poll::Pending
      }
    }
    let slot: SelfSlot<FinishWhilePolling> = Arc::new(Mutex::new(None));
    let cell = cell(FinishWhilePolling(Arc::clone(&slot)));
    *slot.lock().unwrap() = Some(Pin::clone(&cell));
    assert!(matches!(
      cell.as_ref().poll_future(&mut context()),
      CellPoll::Pending
    ));
    slot.lock().unwrap().take();

    struct PanicOnDrop;
    impl Future for PanicOnDrop {
      type Output = ();
      fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
      }
    }
    impl Drop for PanicOnDrop {
      fn drop(&mut self) {
        panic!("destructor");
      }
    }
    let (task, mut join) = joined(PanicOnDrop);
    assert!(task.as_ref().finish(|payload| u64::from(payload.is_some())));
    assert!(task.publish().published);
    assert_eq!(join.take(), Some(Some(1)));
  }

  #[test]
  fn join_and_finished_wakers_are_kept_replaced_and_each_woken_once() {
    let (task, mut join) = joined(std::future::pending::<()>());
    let (first, first_drops, first_waker) = probe();
    let (second, second_drops, second_waker) = probe();
    let (third, third_drops, third_waker) = probe();
    assert!(join.poll(&first_waker).is_pending());
    assert!(join.poll(&first_waker).is_pending());
    assert_eq!(Arc::strong_count(&first), 3);
    // The completion-only waiter has its own slot: the join waker stays.
    assert!(join.poll_complete(&second_waker).is_pending());
    assert_eq!(Arc::strong_count(&first), 3);
    assert_eq!(Arc::strong_count(&second), 3);
    // Re-registering one slot replaces only that slot's waker.
    assert!(join.poll_complete(&third_waker).is_pending());
    assert_eq!(Arc::strong_count(&second), 2);
    assert_eq!(Arc::strong_count(&first), 3);
    assert!(task.as_ref().finish(|_| 4));
    let publication = task.publish();
    assert!(publication.output.is_none());
    assert!(publication.wakers.join.is_none() && publication.wakers.finished.is_none());
    assert_eq!(first.wakes.load(Ordering::Relaxed), 1);
    assert_eq!(second.wakes.load(Ordering::Relaxed), 0);
    assert_eq!(third.wakes.load(Ordering::Relaxed), 1);
    assert!(join.poll_complete(&second_waker).is_ready());
    assert_eq!(join.poll(&first_waker), Poll::Ready(Some(4)));
    drop(join);
    drop((first_waker, second_waker, third_waker, first, second, third));
    assert_eq!(first_drops.load(Ordering::Relaxed), 1);
    assert_eq!(second_drops.load(Ordering::Relaxed), 1);
    assert_eq!(third_drops.load(Ordering::Relaxed), 1);
  }

  #[test]
  fn completion_while_the_handle_holds_the_wakers_wakes_the_other_waiter() {
    // The handle replaces its join waker after publication began from a
    // word without `JOIN_WAKER`: modelled by publishing between a
    // completion-only registration and a join registration on another
    // thread, many times.
    for _ in 0..ROUNDS {
      let (task, mut join) = joined(std::future::pending::<()>());
      let (finished, _, finished_waker) = probe();
      let (joiner, _, join_waker) = probe();
      assert!(join.poll_complete(&finished_waker).is_pending());
      let publisher = std::thread::spawn(move || {
        assert!(task.as_ref().finish(|_| 5));
        drop(task.publish());
      });
      let polled = join.poll(&join_waker);
      publisher.join().unwrap();
      // The completion-only waiter is woken exactly once either way.
      assert_eq!(finished.wakes.load(Ordering::Relaxed), 1);
      match polled {
        Poll::Pending => assert_eq!(joiner.wakes.load(Ordering::Relaxed), 1),
        Poll::Ready(output) => {
          assert_eq!(output, Some(5));
          assert_eq!(joiner.wakes.load(Ordering::Relaxed), 0);
        }
      }
    }
  }

  #[test]
  fn publication_without_a_join_returns_the_outcome() {
    let (task, join) = joined(std::future::pending::<()>());
    let (probe, drops, waker) = probe();
    let mut join = join;
    assert!(join.poll(&waker).is_pending());
    drop(waker);
    drop(probe);
    drop(join);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(task.as_ref().finish(|_| 6));
    let publication = task.publish();
    assert_eq!(publication.output, Some(6));
    assert!(publication.wakers.join.is_none() && publication.wakers.finished.is_none());
  }

  #[test]
  #[should_panic(expected = "share the task allocation")]
  fn join_must_share_the_task_allocation() {
    let other: Joined<std::future::Pending<()>> = TaskCell::new((), std::future::pending());
    let _ = TaskCell::<(), std::future::Pending<()>, u64>::new_with_join(
      (),
      std::future::pending(),
      move |_| other,
    );
  }

  #[test]
  fn registration_on_one_thread_races_publication_on_another() {
    for _ in 0..ROUNDS {
      let (task, mut join) = joined(std::future::pending::<()>());
      let (probe, drops, waker) = probe();
      let publisher = std::thread::spawn(move || {
        assert!(task.as_ref().finish(|_| 11));
        let publication = task.publish();
        assert!(publication.published && publication.output.is_none());
        drop(publication);
      });
      let first = join.poll(&waker);
      publisher.join().unwrap();
      if first.is_pending() {
        assert_eq!(probe.wakes.load(Ordering::Relaxed), 1);
      }
      assert_eq!(join.poll(&waker).map(|_| ()), Poll::Ready(()));
      drop(join);
      drop((waker, probe));
      assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
  }

  #[test]
  fn detach_on_one_thread_races_publication_on_another() {
    for _ in 0..ROUNDS {
      let (task, mut join) = joined(std::future::pending::<()>());
      let (probe, drops, waker) = probe();
      assert!(join.poll(&waker).is_pending());
      drop(waker);
      drop(probe);
      let output_seen = Arc::new(AtomicUsize::new(0));
      let seen = Arc::clone(&output_seen);
      let publisher = std::thread::spawn(move || {
        assert!(task.as_ref().finish(|_| 12));
        let publication = task.publish();
        if publication.output.is_some() {
          seen.fetch_add(1, Ordering::Relaxed);
        }
      });
      drop(join);
      publisher.join().unwrap();
      assert!(output_seen.load(Ordering::Relaxed) <= 1);
      assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
  }

  struct CountHeader(AtomicUsize);

  impl TaskHeader for CountHeader {
    fn wake_by_ref(&self, word: &TaskWord) {
      self.0.fetch_add(1, Ordering::SeqCst);
      let _ = word.notify();
    }
  }

  type Counted = TaskCell<CountHeader, Countdown, ()>;

  fn queued_slot(remaining: u32) -> (TaskSlot<Counted>, Pin<Arc<Counted>>, Arc<AtomicBool>) {
    let (future, dropped) = countdown(remaining);
    let task = TaskCell::new(CountHeader(AtomicUsize::new(0)), future);
    assert_eq!(task.word().notify(), PollNotify::Enqueue);
    let mut slot = TaskSlot::empty();
    slot.install(Pin::clone(&task));
    (slot, task, dropped)
  }

  #[test]
  fn a_lease_borrows_the_slot_owner_and_ends_its_turn() {
    let (mut slot, task, dropped) = queued_slot(1);
    assert_eq!(TaskCell::strong_count(&task), 2);
    let lease = slot.lend().unwrap();
    assert_eq!(TaskCell::strong_count(&task), 2);
    // One turn at a time, and no owner leaves the slot during it.
    assert!(slot.lend().is_none());
    assert!(slot.take_idle().is_none());
    let waker = lease.waker();
    assert_eq!(TaskCell::strong_count(&task), 2);
    let mut cx = Context::from_waker(&waker);
    assert!(matches!(
      lease.task().poll_future(&mut cx),
      CellPoll::Pending
    ));
    waker.wake_by_ref();
    assert_eq!(task.header().0.load(Ordering::SeqCst), 1);
    let kept = (*waker).clone();
    // Vtable identity is a best-effort hint; Miri does not deduplicate the
    // promoted vtable.
    if !cfg!(miri) {
      assert!(kept.will_wake(&waker));
    }
    assert_eq!(TaskCell::strong_count(&task), 3);
    // Woken during the turn: the finish hands back a queue entry.
    assert!(lease.finish_pending());
    assert!(task.word().is_queued());
    kept.wake();
    assert_eq!(TaskCell::strong_count(&task), 2);
    let lease = slot.lend().unwrap();
    let waker = lease.waker();
    assert!(matches!(
      lease.task().poll_future(&mut Context::from_waker(&waker)),
      CellPoll::Ready(7)
    ));
    let owner = slot.take(lease);
    assert!(!slot.is_occupied());
    assert!(owner.as_ref().drop_future());
    assert!(dropped.load(Ordering::SeqCst));
    drop(owner);
    assert_eq!(TaskCell::strong_count(&task), 1);
  }

  #[test]
  fn a_dropped_lease_lets_the_slot_give_up_its_owner() {
    let (mut slot, task, dropped) = queued_slot(3);
    let lease = slot.lend().unwrap();
    assert!(matches!(
      lease.task().poll_future(&mut context()),
      CellPoll::Pending
    ));
    drop(lease);
    let owner = slot.take_idle().unwrap();
    drop(owner);
    drop(slot);
    drop(task);
    assert!(dropped.load(Ordering::SeqCst));
  }

  #[test]
  #[should_panic(expected = "lease returned to another task slot")]
  fn a_lease_cannot_take_another_slots_task() {
    let (mut first, _first_task, _) = queued_slot(1);
    let (mut second, _second_task, _) = queued_slot(1);
    let lease = first.lend().unwrap();
    let _ = second.take(lease);
  }

  #[test]
  fn an_owned_waker_from_the_borrowed_one_outlives_the_turn() {
    let (mut slot, task, _) = queued_slot(1);
    let lease = slot.lend().unwrap();
    let kept = (*lease.waker()).clone();
    assert!(!lease.finish_pending());
    let owner = slot.take_idle().unwrap();
    drop(owner);
    drop(task);
    // The clone is now the last owner; waking it by reference and then by
    // value reads the header and frees the allocation.
    kept.wake_by_ref();
    kept.wake();
  }

  const ROUNDS: usize = if cfg!(miri) { 8 } else { 1000 };
}
