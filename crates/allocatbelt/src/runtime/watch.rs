//! A bounded, latest-value channel for asynchronous receivers.
//!
//! Each receiver tracks the version it has observed. `borrow` returns an
//! owned `Arc<T>` snapshot without marking it seen; `borrow_and_update` also
//! marks that receiver's current version seen. A changed future consumes one
//! unseen version when it completes. Updates may coalesce, so receivers see
//! the latest value rather than every intermediate value.
//!
//! Receiver slots are fixed at construction. The initial receiver occupies
//! one slot, `subscribe` and `try_clone` fail when the table is full, and a
//! slot is retired rather than reusing a wrapped generation. The channel
//! requires no `T: Send + Sync + 'static` bound for local use. Its handles
//! become sendable across threads only when `T` permits `Arc<T>` to be sent.
//!
//! Unlike Tokio's guard-based borrow, snapshots here own an `Arc<T>` and do
//! not keep a lock held. Closure notification is supported, but closure
//! modification callbacks such as `send_modify` are omitted so user code never
//! runs while the channel lock is held.
//!
//! Threaded handles require both `Send` and `Sync` values:
//!
//! ```compile_fail
//! use allocatbelt::runtime::watch;
//! use std::cell::Cell;
//! fn share<T: Send + Sync>(_: T) {}
//! let (sender, _) = watch::channel(Cell::new(1), 1).unwrap();
//! share(sender);
//! ```
//!
//! Local snapshots of `Rc` values cannot move between threads:
//!
//! ```compile_fail
//! use allocatbelt::runtime::watch;
//! use std::rc::Rc;
//! fn move_to_thread<T: Send>(_: T) {}
//! let (_, receiver) = watch::channel(Rc::new(1), 1).unwrap();
//! move_to_thread(receiver.borrow().unwrap());
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::PoisonError;
use std::task::{Context, Poll, Waker};

use super::notify::{Notify, NotifyError, OwnedNotifiedFuture};

#[cfg(loom)]
use loom::sync::{Arc, Mutex, MutexGuard};
#[cfg(not(loom))]
use std::sync::{Arc, Mutex, MutexGuard};

use super::task::drop_contained;

/// Creates a bounded latest-value channel with an initial value.
///
/// `max_receivers` includes the initial receiver and must be nonzero. Receiver
/// slots are allocated before the channel is returned.
pub fn channel<T>(
  initial: T,
  max_receivers: usize,
) -> Result<(Sender<T>, Receiver<T>), WatchBuildError<T>> {
  if max_receivers == 0 {
    return Err(WatchBuildError::new(
      WatchBuildErrorKind::ZeroCapacity,
      initial,
    ));
  }
  let Some(bytes) = max_receivers.checked_mul(std::mem::size_of::<ReceiverSlot>()) else {
    return Err(WatchBuildError::new(
      WatchBuildErrorKind::CapacityOverflow,
      initial,
    ));
  };
  if bytes > isize::MAX as usize {
    return Err(WatchBuildError::new(
      WatchBuildErrorKind::CapacityOverflow,
      initial,
    ));
  }
  let mut slots = Vec::new();
  if slots.try_reserve_exact(max_receivers).is_err() {
    return Err(WatchBuildError::new(
      WatchBuildErrorKind::AllocationFailed,
      initial,
    ));
  }
  for index in 0..max_receivers {
    slots.push(ReceiverSlot {
      generation: 0,
      state: if index == 0 {
        SlotState::Active
      } else {
        SlotState::Free
      },
      seen_version: 0,
      forced_changed: false,
      registered_version: None,
      free_next: index.checked_add(1).filter(|next| *next < max_receivers),
      waker: None,
    });
  }

  let closed_notify = match Notify::new(max_receivers) {
    Ok(notify) => notify,
    Err(super::notify::NotifyBuildError::CapacityOverflow) => {
      return Err(WatchBuildError::new(
        WatchBuildErrorKind::CapacityOverflow,
        initial,
      ));
    }
    Err(super::notify::NotifyBuildError::AllocationFailed) => {
      return Err(WatchBuildError::new(
        WatchBuildErrorKind::AllocationFailed,
        initial,
      ));
    }
  };

  let shared = Arc::new(Shared {
    closed_notify,
    state: Mutex::new(State {
      value: Arc::new(initial),
      version: 0,
      terminal: Terminal::Open,
      receiver_count: 1,
      free_head: (max_receivers > 1).then_some(1),
      slots,
    }),
  });
  let sender = Sender {
    shared: Arc::clone(&shared),
    lifetime: Arc::new(SenderLifetime {
      shared: Arc::clone(&shared),
    }),
  };
  let receiver = Receiver {
    shared,
    key: ReceiverKey {
      index: 0,
      generation: 0,
    },
  };
  Ok((sender, receiver))
}

struct Shared<T> {
  closed_notify: Notify,
  state: Mutex<State<T>>,
}

struct SenderLifetime<T> {
  shared: Arc<Shared<T>>,
}

struct State<T> {
  value: Arc<T>,
  version: u64,
  terminal: Terminal,
  receiver_count: usize,
  free_head: Option<usize>,
  slots: Vec<ReceiverSlot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Terminal {
  Open,
  Closed,
  Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
  Free,
  Active,
  Retired,
}

struct ReceiverSlot {
  generation: u64,
  state: SlotState,
  seen_version: u64,
  forced_changed: bool,
  registered_version: Option<u64>,
  free_next: Option<usize>,
  waker: Option<Waker>,
}

/// The multi-producer handle for a watch channel.
pub struct Sender<T> {
  shared: Arc<Shared<T>>,
  lifetime: Arc<SenderLifetime<T>>,
}

/// A receiver with a fixed slot in the channel's preallocated table.
pub struct Receiver<T> {
  shared: Arc<Shared<T>>,
  key: ReceiverKey,
}

/// An owned snapshot of the latest value and whether this receiver had an
/// unseen version when the snapshot was taken.
pub struct Snapshot<T> {
  value: Arc<T>,
  changed: bool,
}

/// A named, cancellation-safe change future borrowing a receiver.
#[must_use = "futures do nothing unless polled"]
pub struct Changed<'a, T> {
  receiver: &'a mut Receiver<T>,
  registered: bool,
  completed: bool,
}

/// A named change future that owns its receiver.
///
/// On completion it returns both the receiver and the change result. Dropping
/// it while pending drops the receiver and releases its bounded slot.
#[must_use = "futures do nothing unless polled"]
pub struct ChangedOwned<T> {
  receiver: Option<Receiver<T>>,
  registered: bool,
  completed: bool,
}

/// A future that completes after the channel has no live receivers.
#[must_use = "futures do nothing unless polled"]
pub struct Closed<'a, T> {
  sender: &'a Sender<T>,
  notified: Option<OwnedNotifiedFuture>,
  completed: bool,
}

/// Why waiting for all receivers to close could not register.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClosedError {
  /// The bounded closure waiter table is full.
  Full,
  /// The notification generation or source is exhausted.
  Exhausted,
  /// A custom waker panicked while registering or yielding the closure wait.
  WakerPanicked,
  /// This future was polled after it completed.
  Completed,
}

impl fmt::Display for ClosedError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Full => "watch closure waiter table is full",
      Self::Exhausted => "watch closure notification is exhausted",
      Self::WakerPanicked => "watch closure waker callback panicked",
      Self::Completed => "watch closed future was already completed",
    })
  }
}

impl std::error::Error for ClosedError {}

/// Completion of an owned changed future. `receiver` is `None` only if a
/// completed future was polled again; in that case `result` is `Completed`.
pub struct ChangedOwnedOutput<T> {
  /// The receiver returned by the first completed poll.
  pub receiver: Option<Receiver<T>>,
  /// Whether a new version was observed, or why the wait ended.
  pub result: Result<(), WatchError>,
}

/// Why channel construction failed, retaining the rejected initial value.
pub struct WatchBuildError<T> {
  kind: WatchBuildErrorKind,
  initial: T,
}

impl<T> WatchBuildError<T> {
  fn new(kind: WatchBuildErrorKind, initial: T) -> Self {
    Self { kind, initial }
  }

  /// Returns the reason for construction failure.
  pub const fn kind(&self) -> WatchBuildErrorKind {
    self.kind
  }

  /// Recovers the initial value rejected by the constructor.
  pub fn into_value(self) -> T {
    self.initial
  }
}

impl<T> fmt::Debug for WatchBuildError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("WatchBuildError")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

/// Why channel construction failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchBuildErrorKind {
  /// The receiver table must have at least one slot for the initial receiver.
  ZeroCapacity,
  /// The table size overflowed or cannot be represented by a Rust allocation.
  CapacityOverflow,
  /// The preallocated receiver table could not be reserved.
  AllocationFailed,
}

impl<T> fmt::Display for WatchBuildError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self.kind {
      WatchBuildErrorKind::ZeroCapacity => "watch receiver capacity must be nonzero",
      WatchBuildErrorKind::CapacityOverflow => "watch receiver capacity overflowed",
      WatchBuildErrorKind::AllocationFailed => "watch receiver table allocation failed",
    })
  }
}

impl<T> std::error::Error for WatchBuildError<T> {}

/// Why an operation on a receiver could not complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchError {
  /// All senders have dropped. An unread final version is still returned once
  /// by `changed` before this error is produced.
  Closed,
  /// The nonwrapping version counter is exhausted. An unread current version
  /// is still returned once by `changed` before this error is produced.
  Exhausted,
  /// This future was polled after returning a result.
  Completed,
  /// A custom waker panicked while being cloned; this wait was unregistered.
  WakerPanicked,
  /// The receiver slot generation is stale or retired.
  ReceiverExhausted,
}

impl fmt::Display for WatchError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Closed => "watch channel is closed",
      Self::Exhausted => "watch channel version is exhausted",
      Self::Completed => "watch changed future was already completed",
      Self::WakerPanicked => "watch waker clone panicked",
      Self::ReceiverExhausted => "watch receiver slot generation is exhausted",
    })
  }
}

impl std::error::Error for WatchError {}

/// Why a receiver could not be added.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscribeError {
  /// Every nonretired receiver slot is currently occupied.
  Full,
  /// The channel's last sender has been dropped.
  Closed,
  /// The channel version or all receiver slot generations are exhausted.
  Exhausted,
}

impl fmt::Display for SubscribeError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Full => "watch receiver table is full",
      Self::Closed => "watch channel is closed",
      Self::Exhausted => "watch channel or receiver generations are exhausted",
    })
  }
}

impl std::error::Error for SubscribeError {}

/// Why a send was rejected, together with the unchanged original value.
#[derive(Debug)]
pub struct SendError<T> {
  kind: SendErrorKind,
  value: T,
}

/// The reason a send was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendErrorKind {
  /// `send` requires at least one live receiver.
  NoReceivers,
  /// The version counter cannot advance without wrapping.
  Exhausted,
}

impl<T> SendError<T> {
  /// Returns the rejection reason.
  #[must_use]
  pub const fn kind(&self) -> SendErrorKind {
    self.kind
  }

  /// Returns the original rejected value.
  #[must_use]
  pub fn into_value(self) -> T {
    self.value
  }
}

impl<T> fmt::Display for SendError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self.kind {
      SendErrorKind::NoReceivers => "watch send has no receivers",
      SendErrorKind::Exhausted => "watch send version is exhausted",
    })
  }
}

impl<T: fmt::Debug> std::error::Error for SendError<T> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiverKey {
  index: usize,
  generation: u64,
}

impl<T> Sender<T> {
  /// Publishes a new value if at least one receiver is alive.
  ///
  /// If there are no receivers, the original `value` is returned unchanged.
  /// Receiver handles can be added with [`subscribe`](Self::subscribe).
  pub fn send(&self, value: T) -> Result<(), SendError<T>> {
    match self.publish(value, true) {
      Ok(old) => {
        drop_contained(old);
        Ok(())
      }
      Err(error) => Err(error),
    }
  }

  /// Replaces the current value even when no receivers are alive and returns
  /// the previous value as an owned snapshot.
  pub fn send_replace(&self, value: T) -> Result<Arc<T>, SendError<T>> {
    self.publish(value, false)
  }

  fn publish(&self, value: T, require_receiver: bool) -> Result<Arc<T>, SendError<T>> {
    // Allocate the candidate before locking. On rejection it remains uniquely
    // owned and is unwrapped after unlocking, so user `T::drop` never runs in
    // the state critical section.
    let candidate = Arc::new(value);
    let outcome = {
      let mut state = lock(&self.shared.state);
      if state.terminal == Terminal::Exhausted {
        Err((SendErrorKind::Exhausted, candidate))
      } else if require_receiver && state.receiver_count == 0 {
        Err((SendErrorKind::NoReceivers, candidate))
      } else {
        match state.version.checked_add(1) {
          Some(version) => {
            let old = std::mem::replace(&mut state.value, candidate);
            state.version = version;
            Ok(old)
          }
          None => {
            state.terminal = Terminal::Exhausted;
            Err((SendErrorKind::Exhausted, candidate))
          }
        }
      }
    };

    match outcome {
      Ok(old) => {
        wake_ready(&self.shared);
        Ok(old)
      }
      Err((kind, candidate)) => {
        if kind == SendErrorKind::Exhausted {
          wake_ready(&self.shared);
        }
        Err(SendError {
          kind,
          value: unwrap_candidate(candidate),
        })
      }
    }
  }

  /// Creates a receiver whose initial seen version is the current version.
  pub fn subscribe(&self) -> Result<Receiver<T>, SubscribeError> {
    allocate_receiver(&self.shared, None, None, false)
  }

  /// Returns the number of live receiver handles.
  #[must_use]
  pub fn receiver_count(&self) -> usize {
    lock(&self.shared.state).receiver_count
  }

  /// Returns whether no receiver handle remains.
  #[must_use]
  pub fn is_closed(&self) -> bool {
    self.receiver_count() == 0
  }

  /// Waits until the last live receiver handle is dropped.
  ///
  /// Closure waiters share the channel's explicit `max_receivers` bound. A
  /// full waiter table completes with [`ClosedError::Full`]. Receivers can be
  /// subscribed again after a zero-receiver transition, so this future checks
  /// the live count after each notification.
  pub fn closed(&self) -> Closed<'_, T> {
    Closed {
      sender: self,
      notified: Some(self.shared.closed_notify.notified_owned()),
      completed: false,
    }
  }
}

fn allocate_receiver<T>(
  shared: &Arc<Shared<T>>,
  seen_version: Option<u64>,
  forced_changed: Option<bool>,
  allow_terminal: bool,
) -> Result<Receiver<T>, SubscribeError> {
  let key = {
    let mut state = lock(&shared.state);
    if !allow_terminal {
      match state.terminal {
        Terminal::Closed => return Err(SubscribeError::Closed),
        Terminal::Exhausted => return Err(SubscribeError::Exhausted),
        Terminal::Open => {}
      }
    }
    let Some(index) = state.free_head else {
      return Err(
        if state
          .slots
          .iter()
          .all(|slot| slot.state == SlotState::Retired)
        {
          SubscribeError::Exhausted
        } else {
          SubscribeError::Full
        },
      );
    };
    let free_next = state.slots[index].free_next;
    if state.slots[index].state != SlotState::Free {
      return Err(SubscribeError::Full);
    }
    state.free_head = free_next;
    let current = state.version;
    let generation = state.slots[index].generation;
    let slot = &mut state.slots[index];
    slot.free_next = None;
    slot.state = SlotState::Active;
    slot.seen_version = seen_version.unwrap_or(current);
    slot.forced_changed = forced_changed.unwrap_or(false);
    slot.registered_version = None;
    slot.waker = None;
    state.receiver_count += 1;
    ReceiverKey { index, generation }
  };
  Ok(Receiver {
    shared: Arc::clone(shared),
    key,
  })
}

impl<T> Clone for Sender<T> {
  fn clone(&self) -> Self {
    Self {
      shared: Arc::clone(&self.shared),
      lifetime: Arc::clone(&self.lifetime),
    }
  }
}

impl<T> Drop for SenderLifetime<T> {
  fn drop(&mut self) {
    let changed = {
      let mut state = lock(&self.shared.state);
      if state.terminal == Terminal::Open {
        state.terminal = Terminal::Closed;
        true
      } else {
        false
      }
    };
    if changed {
      wake_ready(&self.shared);
    }
  }
}

impl<T> Receiver<T> {
  /// Creates another bounded receiver that starts with the same seen version.
  pub fn try_clone(&self) -> Result<Self, SubscribeError> {
    let seen = {
      let state = lock(&self.shared.state);
      let Some(slot) = state.slots.get(self.key.index) else {
        return Err(SubscribeError::Exhausted);
      };
      if slot.state != SlotState::Active || slot.generation != self.key.generation {
        return Err(SubscribeError::Exhausted);
      }
      (slot.seen_version, slot.forced_changed)
    };
    allocate_receiver(&self.shared, Some(seen.0), Some(seen.1), true)
  }

  /// Returns an owned snapshot without marking its version seen.
  pub fn borrow(&self) -> Result<Snapshot<T>, WatchError> {
    self.snapshot(false)
  }

  /// Returns an owned snapshot and marks its version seen by this receiver.
  pub fn borrow_and_update(&mut self) -> Result<Snapshot<T>, WatchError> {
    self.snapshot(true)
  }

  fn snapshot(&self, mark_seen: bool) -> Result<Snapshot<T>, WatchError> {
    let mut state = lock(&self.shared.state);
    let version = state.version;
    let Some(slot) = state.slots.get(self.key.index) else {
      return Err(WatchError::ReceiverExhausted);
    };
    if slot.state != SlotState::Active || slot.generation != self.key.generation {
      return Err(WatchError::ReceiverExhausted);
    }
    let changed = slot.forced_changed || slot.seen_version != version;
    let value = Arc::clone(&state.value);
    if mark_seen {
      state.slots[self.key.index].seen_version = version;
      state.slots[self.key.index].forced_changed = false;
    }
    Ok(Snapshot { value, changed })
  }

  /// Returns whether the current version is unseen. Like Tokio's
  /// `has_changed`, this returns a closure error whenever the channel is
  /// closed, even if the final version has not yet been observed.
  pub fn has_changed(&self) -> Result<bool, WatchError> {
    let state = lock(&self.shared.state);
    let Some(slot) = state.slots.get(self.key.index) else {
      return Err(WatchError::ReceiverExhausted);
    };
    if slot.state != SlotState::Active || slot.generation != self.key.generation {
      return Err(WatchError::ReceiverExhausted);
    }
    match state.terminal {
      Terminal::Open => Ok(slot.forced_changed || slot.seen_version != state.version),
      Terminal::Closed => Err(WatchError::Closed),
      Terminal::Exhausted => Err(WatchError::Exhausted),
    }
  }

  /// Marks the current value as unseen, so `has_changed` and `changed` report
  /// a change even if the sender has not published another value.
  pub fn mark_changed(&mut self) -> Result<(), WatchError> {
    let mut state = lock(&self.shared.state);
    let Some(slot) = state.slots.get_mut(self.key.index) else {
      return Err(WatchError::ReceiverExhausted);
    };
    if slot.state != SlotState::Active || slot.generation != self.key.generation {
      return Err(WatchError::ReceiverExhausted);
    }
    slot.forced_changed = true;
    Ok(())
  }

  /// Marks the current value as seen by this receiver.
  pub fn mark_unchanged(&mut self) -> Result<(), WatchError> {
    let mut state = lock(&self.shared.state);
    let version = state.version;
    let Some(slot) = state.slots.get_mut(self.key.index) else {
      return Err(WatchError::ReceiverExhausted);
    };
    if slot.state != SlotState::Active || slot.generation != self.key.generation {
      return Err(WatchError::ReceiverExhausted);
    }
    slot.seen_version = version;
    slot.forced_changed = false;
    Ok(())
  }

  /// Waits until the predicate accepts a current value or the channel closes.
  ///
  /// The predicate runs on an owned snapshot outside the channel mutex. Each
  /// examined version is marked seen before the predicate runs, including if
  /// the predicate panics.
  pub async fn wait_for<F>(&mut self, mut predicate: F) -> Result<Snapshot<T>, WatchError>
  where
    F: FnMut(&T) -> bool,
  {
    let mut inspected_since_yield = 0_u8;
    loop {
      let snapshot = self.snapshot(true)?;
      if predicate(&snapshot) {
        return Ok(snapshot);
      }
      drop(snapshot);
      inspected_since_yield += 1;
      if inspected_since_yield == 64 {
        inspected_since_yield = 0;
        super::asynchronous::yield_now().await;
      }
      self.changed().await?;
    }
  }

  /// Waits for an unseen version and marks it seen when this future completes.
  /// Dropping the future removes its registered waker without marking a value
  /// seen, so cancellation is safe.
  pub fn changed(&mut self) -> Changed<'_, T> {
    Changed {
      receiver: self,
      registered: false,
      completed: false,
    }
  }

  /// Consumes this receiver into an owned changed future. Its first completed
  /// poll returns the receiver alongside the result. Dropping it while pending
  /// drops the receiver and frees its slot.
  pub fn changed_owned(self) -> ChangedOwned<T> {
    ChangedOwned {
      receiver: Some(self),
      registered: false,
      completed: false,
    }
  }
}

impl<T> Drop for Receiver<T> {
  fn drop(&mut self) {
    let (old, last_receiver) = {
      let mut state = lock(&self.shared.state);
      if valid_slot(&state, self.key) {
        let old = recycle_slot(&mut state, self.key);
        (old, state.receiver_count == 0)
      } else {
        (None, false)
      }
    };
    drop_waker(old);
    if last_receiver {
      let _ = self.shared.closed_notify.notify_waiters();
    }
  }
}

impl<T> Future for Closed<'_, T> {
  type Output = Result<(), ClosedError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if this.completed {
        return Poll::Ready(Err(ClosedError::Completed));
      }
      let mut rearmed = 0_u8;
      loop {
        if this.sender.is_closed() {
          this.completed = true;
          this.notified.take();
          return Poll::Ready(Ok(()));
        }
        let Some(notified) = this.notified.as_mut() else {
          this.completed = true;
          return Poll::Ready(Err(ClosedError::Completed));
        };
        let polled = panic::catch_unwind(AssertUnwindSafe(|| Pin::new(notified).poll(cx)));
        match polled {
          Ok(Poll::Pending) => return Poll::Pending,
          Ok(Poll::Ready(Ok(()))) => {
            // Arm the next generation before rechecking the count, closing the
            // gap where a receiver drops concurrently with this poll.
            this.notified = Some(this.sender.shared.closed_notify.notified_owned());
            rearmed += 1;
            if rearmed == 64 {
              if let Err(payload) =
                panic::catch_unwind(AssertUnwindSafe(|| cx.waker().wake_by_ref()))
              {
                drop_contained(payload);
                this.completed = true;
                this.notified.take();
                return Poll::Ready(Err(ClosedError::WakerPanicked));
              }
              return Poll::Pending;
            }
          }
          Ok(Poll::Ready(Err(NotifyError::Full))) => {
            this.completed = true;
            this.notified.take();
            return Poll::Ready(Err(ClosedError::Full));
          }
          Ok(Poll::Ready(Err(NotifyError::Closed | NotifyError::GenerationExhausted))) => {
            this.completed = true;
            this.notified.take();
            return Poll::Ready(Err(ClosedError::Exhausted));
          }
          Err(payload) => {
            drop_contained(payload);
            this.completed = true;
            this.notified.take();
            return Poll::Ready(Err(ClosedError::WakerPanicked));
          }
        }
      }
    })
  }
}

impl<T> Snapshot<T> {
  /// Returns whether this receiver had an unseen version at snapshot time.
  #[must_use]
  pub const fn has_changed(&self) -> bool {
    self.changed
  }

  /// Transfers the owned snapshot's `Arc<T>`.
  #[must_use]
  pub fn into_arc(self) -> Arc<T> {
    self.value
  }
}

impl<T> std::ops::Deref for Snapshot<T> {
  type Target = T;

  fn deref(&self) -> &Self::Target {
    self.value.as_ref()
  }
}

impl<T: fmt::Debug> fmt::Debug for Snapshot<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Snapshot")
      .field("value", &self.value)
      .field("changed", &self.changed)
      .finish()
  }
}

impl<T> Future for Changed<'_, T> {
  type Output = Result<(), WatchError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if this.completed {
        return Poll::Ready(Err(WatchError::Completed));
      }
      let result = poll_changed(
        &this.receiver.shared,
        this.receiver.key,
        &mut this.registered,
        cx,
      );
      if result.is_ready() {
        this.completed = true;
      }
      result
    })
  }
}

impl<T> Drop for Changed<'_, T> {
  fn drop(&mut self) {
    if self.registered {
      unregister(&self.receiver.shared, self.receiver.key);
      self.registered = false;
    }
  }
}

impl<T> Future for ChangedOwned<T> {
  type Output = ChangedOwnedOutput<T>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    super::asynchronous::poll_cooperative(cx, |cx| {
      let this = self.get_mut();
      if this.completed {
        return Poll::Ready(ChangedOwnedOutput {
          receiver: None,
          result: Err(WatchError::Completed),
        });
      }
      let Some(receiver) = this.receiver.as_mut() else {
        this.completed = true;
        return Poll::Ready(ChangedOwnedOutput {
          receiver: None,
          result: Err(WatchError::Completed),
        });
      };
      let result = poll_changed(&receiver.shared, receiver.key, &mut this.registered, cx);
      match result {
        Poll::Pending => Poll::Pending,
        Poll::Ready(result) => {
          this.completed = true;
          Poll::Ready(ChangedOwnedOutput {
            receiver: this.receiver.take(),
            result,
          })
        }
      }
    })
  }
}

impl<T> Drop for ChangedOwned<T> {
  fn drop(&mut self) {
    if self.registered {
      if let Some(receiver) = self.receiver.as_ref() {
        unregister(&receiver.shared, receiver.key);
      }
      self.registered = false;
    }
  }
}

fn poll_changed<T>(
  shared: &Arc<Shared<T>>,
  key: ReceiverKey,
  registered: &mut bool,
  cx: &mut Context<'_>,
) -> Poll<Result<(), WatchError>> {
  // First check for an already-published version or closure. This avoids
  // invoking a custom RawWaker clone when the future can complete immediately.
  let (early, old) = {
    let mut state = lock(&shared.state);
    if !valid_slot(&state, key) {
      (Some(Err(WatchError::ReceiverExhausted)), None)
    } else if state.slots[key.index].forced_changed
      || state.slots[key.index].seen_version != state.version
    {
      state.slots[key.index].seen_version = state.version;
      state.slots[key.index].forced_changed = false;
      let old = take_waker(&mut state.slots[key.index]);
      (Some(Ok(())), old)
    } else if state.terminal != Terminal::Open {
      let old = take_waker(&mut state.slots[key.index]);
      let error = terminal_error(state.terminal);
      (Some(Err(error)), old)
    } else {
      (None, None)
    }
  };
  if let Some(result) = early {
    *registered = false;
    drop_waker(old);
    return Poll::Ready(result);
  }

  // Waker clone may execute user RawWaker code; it stays outside the mutex and
  // a panic is contained. A failed re-poll also unregisters the prior waker.
  let mut new_waker = match panic::catch_unwind(AssertUnwindSafe(|| cx.waker().clone())) {
    Ok(waker) => Some(waker),
    Err(payload) => {
      drop_contained(payload);
      if *registered {
        unregister(shared, key);
        *registered = false;
      }
      return Poll::Ready(Err(WatchError::WakerPanicked));
    }
  };

  let (result, old, installed) = {
    let mut state = lock(&shared.state);
    if !valid_slot(&state, key) {
      (Poll::Ready(Err(WatchError::ReceiverExhausted)), None, false)
    } else if state.slots[key.index].forced_changed
      || state.slots[key.index].seen_version != state.version
    {
      state.slots[key.index].seen_version = state.version;
      state.slots[key.index].forced_changed = false;
      let old = take_waker(&mut state.slots[key.index]);
      (Poll::Ready(Ok(())), old, false)
    } else if state.terminal != Terminal::Open {
      let old = take_waker(&mut state.slots[key.index]);
      (Poll::Ready(Err(terminal_error(state.terminal))), old, false)
    } else {
      let version = state.version;
      match new_waker.take() {
        Some(replacement) => {
          let slot = &mut state.slots[key.index];
          let old = slot.waker.replace(replacement);
          slot.registered_version = Some(version);
          (Poll::Pending, old, true)
        }
        None => (Poll::Ready(Err(WatchError::WakerPanicked)), None, false),
      }
    }
  };
  drop_waker(old);
  drop_waker(new_waker.take());
  *registered = installed;
  result
}

fn valid_slot<T>(state: &State<T>, key: ReceiverKey) -> bool {
  state
    .slots
    .get(key.index)
    .is_some_and(|slot| slot.state == SlotState::Active && slot.generation == key.generation)
}

fn take_waker(slot: &mut ReceiverSlot) -> Option<Waker> {
  slot.registered_version = None;
  slot.waker.take()
}

fn terminal_error(terminal: Terminal) -> WatchError {
  match terminal {
    Terminal::Closed => WatchError::Closed,
    Terminal::Exhausted => WatchError::Exhausted,
    Terminal::Open => WatchError::Completed,
  }
}

fn unregister<T>(shared: &Arc<Shared<T>>, key: ReceiverKey) {
  let old = {
    let mut state = lock(&shared.state);
    if valid_slot(&state, key) {
      take_waker(&mut state.slots[key.index])
    } else {
      None
    }
  };
  drop_waker(old);
}

fn wake_ready<T>(shared: &Arc<Shared<T>>) {
  loop {
    let waker = {
      let mut state = lock(&shared.state);
      let version = state.version;
      let terminal = state.terminal;
      state.slots.iter_mut().find_map(|slot| {
        let should_wake = slot.state == SlotState::Active
          && slot.waker.is_some()
          && (terminal != Terminal::Open || slot.registered_version != Some(version));
        should_wake.then(|| take_waker(slot)).flatten()
      })
    };
    let Some(waker) = waker else { return };
    wake_contained(waker);
  }
}

fn recycle_slot<T>(state: &mut State<T>, key: ReceiverKey) -> Option<Waker> {
  if !valid_slot(state, key) {
    return None;
  }
  let old = state.slots[key.index].waker.take();
  let slot = &mut state.slots[key.index];
  slot.registered_version = None;
  slot.free_next = None;
  if let Some(generation) = slot.generation.checked_add(1) {
    slot.generation = generation;
    slot.state = SlotState::Free;
    slot.free_next = state.free_head;
    state.free_head = Some(key.index);
  } else {
    slot.state = SlotState::Retired;
  }
  state.receiver_count = state.receiver_count.saturating_sub(1);
  old
}

fn unwrap_candidate<T>(candidate: Arc<T>) -> T {
  match Arc::try_unwrap(candidate) {
    Ok(value) => value,
    Err(candidate) => {
      drop_contained(candidate);
      unreachable!("rejected candidate is uniquely owned")
    }
  }
}

fn wake_contained(waker: Waker) {
  if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake())) {
    drop_contained(payload);
  }
}

fn drop_waker(waker: Option<Waker>) {
  if let Some(waker) = waker {
    drop_contained(waker);
  }
}

impl<T> fmt::Debug for Sender<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let (version, terminal, receiver_count, max_receivers) = {
      let state = lock(&self.shared.state);
      (
        state.version,
        state.terminal,
        state.receiver_count,
        state.slots.len(),
      )
    };
    f.debug_struct("Sender")
      .field("version", &version)
      .field("terminal", &terminal)
      .field("receiver_count", &receiver_count)
      .field("max_receivers", &max_receivers)
      .finish()
  }
}

impl<T> fmt::Debug for Receiver<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let (version, seen, terminal) = {
      let state = lock(&self.shared.state);
      let seen = state
        .slots
        .get(self.key.index)
        .map(|slot| slot.seen_version);
      (state.version, seen, state.terminal)
    };
    f.debug_struct("Receiver")
      .field("version", &version)
      .field("seen_version", &seen)
      .field("terminal", &terminal)
      .finish()
  }
}

impl<T> fmt::Debug for Changed<'_, T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Changed")
      .field("registered", &self.registered)
      .field("completed", &self.completed)
      .finish()
  }
}

impl<T> fmt::Debug for ChangedOwned<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ChangedOwned")
      .field("has_receiver", &self.receiver.is_some())
      .field("registered", &self.registered)
      .field("completed", &self.completed)
      .finish()
  }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;
  use std::cell::Cell;
  use std::rc::Rc;
  use std::sync::atomic::{AtomicBool, Ordering};
  use std::thread;
  use std::time::{Duration, Instant};

  struct ThreadWake(thread::Thread);
  impl std::task::Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
      self.0.unpark();
    }
    fn wake_by_ref(self: &Arc<Self>) {
      self.0.unpark();
    }
  }

  fn noop_waker() -> Waker {
    Waker::noop().clone()
  }

  fn poll_once<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    let mut cx = Context::from_waker(waker);
    future.poll(&mut cx)
  }

  fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
      if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
        return result;
      }
      assert!(
        Instant::now() < deadline,
        "watch changed wait exceeded deadline"
      );
      thread::park_timeout(Duration::from_millis(10));
    }
  }

  struct PanicWake;
  impl std::task::Wake for PanicWake {
    fn wake(self: Arc<Self>) {
      panic!("intentional watch waker panic");
    }
    fn wake_by_ref(self: &Arc<Self>) {
      panic!("intentional watch waker panic");
    }
  }

  struct ReentrantWake(Sender<i32>, Arc<AtomicBool>);
  impl std::task::Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
      self.0.send_replace(2).ok();
      self.1.store(true, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
      self.0.send_replace(2).ok();
      self.1.store(true, Ordering::SeqCst);
    }
  }

  struct PanicOnDrop(Arc<AtomicBool>);
  impl Drop for PanicOnDrop {
    fn drop(&mut self) {
      self.0.store(true, Ordering::SeqCst);
      panic!("intentional panic payload drop");
    }
  }

  struct PanicPayloadWake(Arc<AtomicBool>);
  impl std::task::Wake for PanicPayloadWake {
    fn wake(self: Arc<Self>) {
      std::panic::panic_any(PanicOnDrop(Arc::clone(&self.0)));
    }
    fn wake_by_ref(self: &Arc<Self>) {
      std::panic::panic_any(PanicOnDrop(Arc::clone(&self.0)));
    }
  }

  struct DropProbe {
    shared: Arc<std::sync::Mutex<Option<std::sync::Weak<Shared<DropProbe>>>>>,
    unlocked: Arc<AtomicBool>,
  }

  impl Drop for DropProbe {
    fn drop(&mut self) {
      let shared = self
        .shared
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|weak| weak.upgrade());
      if let Some(shared) = shared {
        self.unlocked.store(
          matches!(
            shared.state.try_lock(),
            Ok(_) | Err(std::sync::TryLockError::Poisoned(_))
          ),
          Ordering::SeqCst,
        );
      }
    }
  }

  #[test]
  fn bounds_and_receiver_versions_follow_seen_semantics() {
    let error = channel(0_u8, 0).unwrap_err();
    assert_eq!(error.kind(), WatchBuildErrorKind::ZeroCapacity);
    assert_eq!(error.into_value(), 0);
    struct NotDebug;
    let error = channel(NotDebug, usize::MAX).unwrap_err();
    assert_eq!(error.kind(), WatchBuildErrorKind::CapacityOverflow);
    let _ = error.into_value();
    let (sender, mut receiver) = channel(1_u8, 2).unwrap();
    assert_eq!(*receiver.borrow().unwrap(), 1);
    assert!(!receiver.borrow().unwrap().has_changed());
    assert!(!receiver.try_clone().unwrap().has_changed().unwrap());
    sender.send(2).unwrap();
    assert!(receiver.has_changed().unwrap());
    let borrowed = receiver.borrow().unwrap();
    assert!(borrowed.has_changed());
    assert_eq!(*borrowed, 2);
    let snapshot = receiver.borrow_and_update().unwrap();
    assert_eq!(*snapshot, 2);
    assert!(snapshot.has_changed());
    assert!(!receiver.has_changed().unwrap());
    let subscriber = sender.subscribe().unwrap();
    assert!(!subscriber.has_changed().unwrap());
    assert!(matches!(sender.subscribe(), Err(SubscribeError::Full)));
  }

  #[test]
  fn mark_changed_unchanged_and_wait_for_follow_tokio_observation_rules() {
    let (sender, mut receiver) = channel(1, 1).unwrap();
    receiver.mark_changed().unwrap();
    assert!(receiver.has_changed().unwrap());
    assert_eq!(
      *block_on(receiver.wait_for(|value| *value == 1)).unwrap(),
      1
    );
    assert!(!receiver.has_changed().unwrap());

    receiver.mark_changed().unwrap();
    receiver.mark_unchanged().unwrap();
    assert!(!receiver.has_changed().unwrap());

    let producer = sender.clone();
    let thread = thread::spawn(move || {
      thread::yield_now();
      producer.send(2).unwrap();
    });
    assert_eq!(
      *block_on(receiver.wait_for(|value| *value == 2)).unwrap(),
      2
    );
    thread.join().unwrap();
  }

  #[test]
  fn wait_for_yields_after_sixty_four_reentrant_publications() {
    let (sender, mut receiver) = channel(0_u8, 1).unwrap();
    let inspected = Cell::new(0_u8);
    let mut waiting = Box::pin(receiver.wait_for(|_| {
      let count = inspected.get() + 1;
      inspected.set(count);
      sender.send_replace(count).ok();
      count > 64
    }));
    let waker = noop_waker();
    assert!(poll_once(waiting.as_mut(), &waker).is_pending());
    assert_eq!(inspected.get(), 64);
    assert!(matches!(
      poll_once(waiting.as_mut(), &waker),
      Poll::Ready(Ok(_))
    ));
    assert_eq!(inspected.get(), 65);
  }

  #[test]
  fn canceled_wait_for_yield_does_not_consume_an_unexamined_update() {
    let (sender, mut receiver) = channel(0_u8, 1).unwrap();
    let mut waiting = Box::pin(receiver.wait_for(|value| {
      sender.send_replace(*value + 1).ok();
      *value >= 64
    }));
    let waker = noop_waker();
    assert!(poll_once(waiting.as_mut(), &waker).is_pending());
    drop(waiting);
    assert!(receiver.has_changed().unwrap());
    assert_eq!(*receiver.borrow().unwrap(), 64);
  }

  #[test]
  fn ordinary_handles_snapshots_and_owned_waits_are_sendable() {
    fn send_sync<T: Send + Sync>() {}
    fn send<T: Send>(_: &T) {}
    send_sync::<Sender<usize>>();
    send_sync::<Receiver<usize>>();
    send_sync::<Snapshot<usize>>();
    let (_, receiver) = channel(0_usize, 1).unwrap();
    send(&receiver.changed_owned());
  }

  #[test]
  fn closed_wait_is_bounded_and_observes_last_receiver_drop() {
    let (sender, receiver) = channel(0, 1).unwrap();
    let mut first = Box::pin(sender.closed());
    let mut second = Box::pin(sender.closed());
    let waker = noop_waker();
    assert!(poll_once(first.as_mut(), &waker).is_pending());
    assert_eq!(
      poll_once(second.as_mut(), &waker),
      Poll::Ready(Err(ClosedError::Full))
    );
    let dropper = thread::spawn(move || {
      thread::yield_now();
      drop(receiver);
    });
    assert_eq!(block_on(first), Ok(()));
    dropper.join().unwrap();
  }

  #[test]
  fn completed_closed_future_releases_its_waiter_slot_before_resubscribe() {
    let (sender, receiver) = channel(0, 1).unwrap();
    let mut first = Box::pin(sender.closed());
    let waker = noop_waker();
    assert!(poll_once(first.as_mut(), &waker).is_pending());
    drop(receiver);
    assert_eq!(poll_once(first.as_mut(), &waker), Poll::Ready(Ok(())));

    let _receiver = sender.subscribe().unwrap();
    let mut second = Box::pin(sender.closed());
    assert!(poll_once(second.as_mut(), &waker).is_pending());
  }

  #[test]
  fn borrow_is_owned_and_supports_local_non_send_values() {
    let rc = Rc::new(Cell::new(7));
    let (sender, receiver) = channel(Rc::clone(&rc), 1).unwrap();
    let snapshot = receiver.borrow().unwrap();
    drop(sender);
    drop(receiver);
    assert_eq!(snapshot.get(), 7);
    drop(snapshot);

    let value = 11;
    let (_sender, receiver) = channel(&value, 1).unwrap();
    assert_eq!(**receiver.borrow().unwrap(), 11);
  }

  #[test]
  fn receiver_clone_copies_seen_version_but_subscribe_starts_current() {
    let (sender, mut receiver) = channel(0, 4).unwrap();
    sender.send(1).unwrap();
    let mut clone = receiver.try_clone().unwrap();
    assert!(clone.has_changed().unwrap());
    let current = sender.subscribe().unwrap();
    assert!(!current.has_changed().unwrap());
    assert!(receiver.borrow_and_update().unwrap().has_changed());
    assert!(clone.borrow_and_update().unwrap().has_changed());
  }

  #[test]
  fn cancelled_changed_future_does_not_mark_seen_and_removes_its_waker() {
    let (sender, mut receiver) = channel(0, 1).unwrap();
    let waker = noop_waker();
    let mut changed = Box::pin(receiver.changed());
    assert!(poll_once(changed.as_mut(), &waker).is_pending());
    assert!(lock(&sender.shared.state).slots[0].waker.is_some());
    drop(changed);
    assert!(lock(&sender.shared.state).slots[0].waker.is_none());
    sender.send(1).unwrap();
    assert!(receiver.has_changed().unwrap());
    assert_eq!(*receiver.borrow_and_update().unwrap(), 1);
  }

  #[test]
  fn changed_owned_returns_receiver_and_drop_releases_slot() {
    let (sender, receiver) = channel(0, 1).unwrap();
    let mut owned = Box::pin(receiver.changed_owned());
    assert!(poll_once(owned.as_mut(), &noop_waker()).is_pending());
    drop(owned);
    assert_eq!(sender.receiver_count(), 0);
    assert_eq!(
      sender.send(1).unwrap_err().kind(),
      SendErrorKind::NoReceivers
    );

    let (sender, receiver) = channel(0, 1).unwrap();
    let mut owned = Box::pin(receiver.changed_owned());
    sender.send(1).unwrap();
    match poll_once(owned.as_mut(), &noop_waker()) {
      Poll::Ready(output) => {
        assert_eq!(output.result, Ok(()));
        let receiver = output.receiver.unwrap();
        assert!(!receiver.has_changed().unwrap());
      }
      Poll::Pending => panic!("published value must complete changed"),
    }
  }

  #[test]
  fn send_requires_receivers_but_send_replace_preserves_value_for_later_subscribe() {
    let (sender, receiver) = channel(String::from("old"), 1).unwrap();
    drop(receiver);
    let error = sender.send(String::from("rejected")).unwrap_err();
    assert_eq!(error.kind(), SendErrorKind::NoReceivers);
    assert_eq!(error.into_value(), "rejected");
    assert_eq!(*sender.send_replace(String::from("latest")).unwrap(), "old");
    let receiver = sender.subscribe().unwrap();
    assert_eq!(&**receiver.borrow().unwrap(), "latest");
    assert!(!receiver.has_changed().unwrap());
  }

  #[test]
  fn managed_snapshot_keeps_its_resource_charge_until_the_last_arc_drops() {
    use crate::runtime::managed::{ResourceLimits, ResourceScope};

    let scope = ResourceScope::new(ResourceLimits {
      managed_memory: 8,
      disk_concurrent_ops: 0,
      network_concurrent_ops: 0,
    });
    let original = scope.try_alloc_zeroed(4).unwrap();
    let (sender, receiver) = channel(original, 1).unwrap();
    let snapshot = receiver.borrow().unwrap().into_arc();
    let replacement = scope.try_alloc_zeroed(4).unwrap();
    let previous = sender.send_replace(replacement).unwrap();
    assert_eq!(scope.snapshot().managed_memory, 8);
    drop(previous);
    assert_eq!(scope.snapshot().managed_memory, 8);
    drop(snapshot);
    assert_eq!(scope.snapshot().managed_memory, 4);
    drop(sender);
    drop(receiver);
    assert_eq!(scope.snapshot().managed_memory, 0);
  }

  #[test]
  fn last_sender_close_keeps_unread_final_version_observable_once() {
    let (sender, mut receiver) = channel(0, 1).unwrap();
    let second = sender.clone();
    let mut changed = Box::pin(receiver.changed());
    assert!(poll_once(changed.as_mut(), &noop_waker()).is_pending());
    second.send(4).unwrap();
    drop(sender);
    drop(second);
    assert_eq!(
      poll_once(changed.as_mut(), &noop_waker()),
      Poll::Ready(Ok(()))
    );
    drop(changed);
    assert_eq!(*receiver.borrow_and_update().unwrap(), 4);
    assert_eq!(block_on(receiver.changed()), Err(WatchError::Closed));
    assert_eq!(receiver.has_changed(), Err(WatchError::Closed));
  }

  #[test]
  fn version_exhaustion_rejects_value_wakes_waiters_and_preserves_final_snapshot() {
    let (sender, mut final_receiver) = channel(1, 2).unwrap();
    let mut waiting_receiver = sender.subscribe().unwrap();
    {
      let mut state = lock(&sender.shared.state);
      state.version = u64::MAX;
      state.slots[0].seen_version = u64::MAX - 1;
      state.slots[1].seen_version = u64::MAX;
    }
    let mut changed = Box::pin(waiting_receiver.changed());
    assert!(poll_once(changed.as_mut(), &noop_waker()).is_pending());
    let error = sender.send(2).unwrap_err();
    assert_eq!(error.kind(), SendErrorKind::Exhausted);
    assert_eq!(error.into_value(), 2);
    assert_eq!(
      poll_once(changed.as_mut(), &noop_waker()),
      Poll::Ready(Err(WatchError::Exhausted))
    );
    drop(changed);
    assert_eq!(
      block_on(final_receiver.changed()),
      Ok(()),
      "the last published version remains observable before exhausted EOF"
    );
    assert_eq!(*final_receiver.borrow().unwrap(), 1);
    assert_eq!(
      block_on(final_receiver.changed()),
      Err(WatchError::Exhausted)
    );
  }

  #[test]
  fn receiver_generation_retires_without_wrapping() {
    let (sender, mut receiver) = channel(0, 1).unwrap();
    lock(&sender.shared.state).slots[0].generation = u64::MAX;
    receiver.key.generation = u64::MAX;
    drop(receiver);
    assert_eq!(
      lock(&sender.shared.state).slots[0].state,
      SlotState::Retired
    );
    assert_eq!(sender.subscribe().err(), Some(SubscribeError::Exhausted));
  }

  #[test]
  fn panicking_and_reentrant_wakers_run_outside_the_state_lock() {
    let (sender, mut receiver) = channel(0, 1).unwrap();
    let mut changed = Box::pin(receiver.changed());
    assert!(poll_once(changed.as_mut(), &Waker::from(Arc::new(PanicWake))).is_pending());
    sender.send(1).unwrap();
    assert_eq!(
      poll_once(changed.as_mut(), &noop_waker()),
      Poll::Ready(Ok(()))
    );
    drop(changed);

    let (sender, mut receiver) = channel(0, 1).unwrap();
    let woke = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(ReentrantWake(sender.clone(), Arc::clone(&woke))));
    let mut changed = Box::pin(receiver.changed());
    assert!(poll_once(changed.as_mut(), &waker).is_pending());
    sender.send(1).unwrap();
    assert!(woke.load(Ordering::SeqCst));
    assert_eq!(
      poll_once(changed.as_mut(), &noop_waker()),
      Poll::Ready(Ok(()))
    );
    drop(changed);
    assert_eq!(*receiver.borrow_and_update().unwrap(), 2);
  }

  #[test]
  fn panic_payload_drop_and_replaced_values_are_contained_outside_lock() {
    let panic_payload_dropped = Arc::new(AtomicBool::new(false));
    let (sender, mut receiver) = channel(0, 1).unwrap();
    let panic_waker = Waker::from(Arc::new(PanicPayloadWake(Arc::clone(
      &panic_payload_dropped,
    ))));
    let mut changed = Box::pin(receiver.changed());
    assert!(poll_once(changed.as_mut(), &panic_waker).is_pending());
    sender.send(1).unwrap();
    assert!(panic_payload_dropped.load(Ordering::SeqCst));
    drop(changed);

    let shared = Arc::new(std::sync::Mutex::new(None));
    let unlocked = Arc::new(AtomicBool::new(false));
    let initial = DropProbe {
      shared: Arc::clone(&shared),
      unlocked: Arc::clone(&unlocked),
    };
    let (sender, receiver) = channel(initial, 1).unwrap();
    *shared.lock().unwrap() = Some(Arc::downgrade(&sender.shared));
    assert!(
      sender
        .send(DropProbe {
          shared: Arc::clone(&shared),
          unlocked: Arc::clone(&unlocked),
        })
        .is_ok()
    );
    assert!(unlocked.load(Ordering::SeqCst));
    drop(receiver);
    drop(sender);
  }

  #[test]
  fn debug_formatting_happens_after_releasing_the_state_lock() {
    struct ReentrantWriter {
      sender: Sender<u8>,
      lock_available: bool,
      reentered: bool,
    }
    impl fmt::Write for ReentrantWriter {
      fn write_str(&mut self, _: &str) -> fmt::Result {
        self.lock_available = match self.sender.shared.state.try_lock() {
          Ok(guard) => {
            drop(guard);
            true
          }
          Err(std::sync::TryLockError::Poisoned(error)) => {
            drop(error.into_inner());
            true
          }
          Err(std::sync::TryLockError::WouldBlock) => false,
        };
        if self.lock_available && !self.reentered {
          self.sender.send_replace(2).ok();
          self.reentered = true;
        }
        Ok(())
      }
    }
    let (sender, _receiver) = channel(1, 1).unwrap();
    let mut writer = ReentrantWriter {
      sender: sender.clone(),
      lock_available: false,
      reentered: false,
    };
    assert!(fmt::write(&mut writer, format_args!("{sender:?}")).is_ok());
    assert!(writer.lock_available);
    assert!(writer.reentered);
  }

  #[test]
  fn concurrent_receivers_observe_latest_value_within_deadline() {
    let (sender, receiver) = channel(0, 3).unwrap();
    let mut receivers = vec![
      receiver,
      sender.subscribe().unwrap(),
      sender.subscribe().unwrap(),
    ];
    let waits: Vec<_> = receivers
      .drain(..)
      .map(|receiver| {
        thread::spawn(move || {
          block_on(async move {
            let mut receiver = receiver;
            receiver.changed().await?;
            Ok::<_, WatchError>(*receiver.borrow_and_update()?)
          })
        })
      })
      .collect();
    thread::yield_now();
    sender.send(5).unwrap();
    for wait in waits {
      assert_eq!(wait.join().unwrap(), Ok(5));
    }
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use super::*;
  use loom::sync::Arc as LoomArc;
  use loom::sync::atomic::{AtomicUsize as LoomAtomicUsize, Ordering as LoomOrdering};
  use loom::thread;
  use std::sync::Arc as StdArc;

  struct NoopWake;
  impl std::task::Wake for NoopWake {
    fn wake(self: StdArc<Self>) {}
    fn wake_by_ref(self: &StdArc<Self>) {}
  }

  fn noop_waker() -> Waker {
    Waker::from(StdArc::new(NoopWake))
  }

  fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    future.poll(&mut cx)
  }

  fn rendezvous(gate: &LoomAtomicUsize, participants: usize) {
    gate.fetch_add(1, LoomOrdering::SeqCst);
    while gate.load(LoomOrdering::SeqCst) < participants {
      thread::yield_now();
    }
  }

  #[test]
  fn last_receiver_drop_racing_closed_registration_loses_no_wake() {
    struct CountWake(LoomAtomicUsize);
    impl std::task::Wake for CountWake {
      fn wake(self: StdArc<Self>) {
        self.0.fetch_add(1, LoomOrdering::SeqCst);
      }
      fn wake_by_ref(self: &StdArc<Self>) {
        self.0.fetch_add(1, LoomOrdering::SeqCst);
      }
    }
    loom::model(|| {
      let (sender, receiver) = channel(0_u8, 1).unwrap();
      let counter = StdArc::new(CountWake(LoomAtomicUsize::new(0)));
      let waker = Waker::from(StdArc::clone(&counter));
      let mut closed = Box::pin(sender.closed());
      let dropper = thread::spawn(move || drop(receiver));
      let first_poll = closed.as_mut().poll(&mut Context::from_waker(&waker));
      dropper.join().unwrap();
      match first_poll {
        Poll::Ready(result) => assert_eq!(result, Ok(())),
        Poll::Pending => {
          assert!(counter.0.load(LoomOrdering::SeqCst) > 0);
          assert_eq!(
            closed.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Ok(()))
          );
        }
      }
    });
  }

  #[test]
  fn send_racing_changed_cancellation_never_marks_an_unobserved_version() {
    loom::model(|| {
      let (sender, receiver) = channel(0_u8, 1).unwrap();
      let gate = LoomArc::new(LoomAtomicUsize::new(0));
      let waiter_gate = LoomArc::clone(&gate);
      let waiter = thread::spawn(move || {
        let mut receiver = receiver;
        let pending = {
          let mut changed = Box::pin(receiver.changed());
          rendezvous(&waiter_gate, 2);
          poll_once(changed.as_mut()).is_pending()
        };
        (receiver, pending)
      });
      let sender_gate = LoomArc::clone(&gate);
      let producer = thread::spawn(move || {
        rendezvous(&sender_gate, 2);
        sender.send(1).unwrap();
        sender
      });
      let _sender = producer.join().unwrap();
      let (receiver, was_pending) = waiter.join().unwrap();
      assert_eq!(receiver.has_changed().unwrap(), was_pending);
    });
  }

  #[test]
  fn registered_receivers_all_observe_the_latest_published_version() {
    loom::model(|| {
      let (sender, first) = channel(0_u8, 3).unwrap();
      let receivers = [
        first,
        sender.subscribe().unwrap(),
        sender.subscribe().unwrap(),
      ];
      let mut receivers = receivers;
      let waker = noop_waker();
      let mut registered = [false; 3];
      for (receiver, registered) in receivers.iter_mut().zip(&mut registered) {
        let mut cx = Context::from_waker(&waker);
        assert!(poll_changed(&receiver.shared, receiver.key, registered, &mut cx).is_pending());
      }
      let producer = thread::spawn(move || {
        sender.send(7).unwrap();
        sender
      });
      let _sender = producer.join().unwrap();
      for (receiver, registered) in receivers.iter_mut().zip(&mut registered) {
        let mut cx = Context::from_waker(&waker);
        assert_eq!(
          poll_changed(&receiver.shared, receiver.key, registered, &mut cx),
          Poll::Ready(Ok(()))
        );
        assert_eq!(*receiver.borrow_and_update().unwrap(), 7);
      }
    });
  }

  #[test]
  fn last_sender_close_preserves_an_unseen_final_value() {
    loom::model(|| {
      let (sender, mut receiver) = channel(0_u8, 1).unwrap();
      let producer = thread::spawn(move || {
        sender.send(9).unwrap();
        drop(sender);
      });
      producer.join().unwrap();
      assert_eq!(
        poll_once(Box::pin(receiver.changed()).as_mut()),
        Poll::Ready(Ok(()))
      );
      assert_eq!(*receiver.borrow_and_update().unwrap(), 9);
      assert_eq!(
        poll_once(Box::pin(receiver.changed()).as_mut()),
        Poll::Ready(Err(WatchError::Closed))
      );
    });
  }

  #[test]
  fn receiver_drop_racing_send_preserves_linearized_send_result() {
    loom::model(|| {
      let (sender, receiver) = channel(0_u8, 1).unwrap();
      let gate = LoomArc::new(LoomAtomicUsize::new(0));
      let drop_gate = LoomArc::clone(&gate);
      let dropper = thread::spawn(move || {
        rendezvous(&drop_gate, 2);
        drop(receiver);
      });
      let send_gate = LoomArc::clone(&gate);
      let producer = thread::spawn(move || {
        rendezvous(&send_gate, 2);
        let result = sender.send(4);
        (sender, result)
      });
      dropper.join().unwrap();
      let (sender, result) = producer.join().unwrap();
      match result {
        Ok(()) => {
          let mut receiver = sender.subscribe().unwrap();
          assert_eq!(*receiver.borrow_and_update().unwrap(), 4);
        }
        Err(error) => {
          assert_eq!(error.kind(), SendErrorKind::NoReceivers);
          assert_eq!(error.into_value(), 4);
        }
      }
    });
  }
}
