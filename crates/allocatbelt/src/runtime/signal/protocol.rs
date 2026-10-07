use std::fmt;
use std::future::Future;
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::PoisonError;
use std::task::{Context, Poll, Waker};

#[cfg(loom)]
use loom::sync::{Arc, Mutex, MutexGuard};
#[cfg(not(loom))]
use std::sync::{Arc, Mutex, MutexGuard};

use super::{SignalError, SignalKind};
use crate::runtime::task::drop_contained;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Key {
  index: usize,
  generation: u64,
}

struct Slot {
  generation: u64,
  active: bool,
  retired: bool,
  kind: SignalKind,
  pending: bool,
  waker: Option<Waker>,
}

struct State {
  slots: Vec<Slot>,
  closed: bool,
}

pub(super) struct Shared {
  state: Mutex<State>,
  capacity: usize,
}

impl Shared {
  pub(super) fn new(capacity: usize) -> Result<Arc<Self>, SignalError> {
    if capacity == 0
      || capacity
        .checked_mul(std::mem::size_of::<Slot>())
        .is_none_or(|bytes| bytes > isize::MAX as usize)
    {
      return Err(SignalError::InvalidCapacity);
    }
    let mut slots = Vec::new();
    slots
      .try_reserve_exact(capacity)
      .map_err(|_| SignalError::AllocationFailed)?;
    slots.resize_with(capacity, || Slot {
      generation: 0,
      active: false,
      retired: false,
      kind: SignalKind::interrupt(),
      pending: false,
      waker: None,
    });
    Ok(Arc::new(Self {
      state: Mutex::new(State {
        slots,
        closed: false,
      }),
      capacity,
    }))
  }

  pub(super) fn capacity(&self) -> usize {
    self.capacity
  }

  pub(super) fn subscribe(shared: &Arc<Self>, kind: SignalKind) -> Result<Signal, SignalError> {
    let mut state = lock(&shared.state);
    if state.closed {
      return Err(SignalError::Closed);
    }
    let Some((index, slot)) = state
      .slots
      .iter_mut()
      .enumerate()
      .find(|(_, s)| !s.active && !s.retired)
    else {
      return Err(SignalError::Full);
    };
    slot.active = true;
    slot.kind = kind;
    slot.pending = false;
    let key = Key {
      index,
      generation: slot.generation,
    };
    drop(state);
    Ok(Signal {
      shared: Arc::clone(shared),
      key,
      kind,
    })
  }

  pub(super) fn is_closed(&self) -> bool {
    lock(&self.state).closed
  }

  pub(super) fn close(&self, wakes: &mut Vec<Waker>) {
    assert!(wakes.is_empty());
    assert!(wakes.capacity() >= self.capacity);
    let mut state = lock(&self.state);
    state.closed = true;
    for slot in &mut state.slots {
      if let Some(waker) = slot.waker.take() {
        wakes.push(waker);
      }
    }
  }

  /// `wakes` has a permanently reserved capacity of at least our ceiling.
  /// Clear it outside this function so no user Waker is dropped under lock.
  pub(super) fn deliver(&self, signals: u64, wakes: &mut Vec<Waker>) {
    assert!(wakes.is_empty());
    assert!(wakes.capacity() >= self.capacity);
    let mut state = lock(&self.state);
    if state.closed {
      return;
    }
    for slot in state.slots.iter_mut() {
      if slot.active && slot.kind.mask() & signals != 0 {
        slot.pending = true;
        if let Some(waker) = slot.waker.take() {
          wakes.push(waker);
        }
      }
    }
  }
}

/// An owned bounded subscription. Dropping it releases its slot after removing
/// the waker; the process-wide signal disposition remains installed.
pub struct Signal {
  shared: Arc<Shared>,
  key: Key,
  kind: SignalKind,
}

impl Signal {
  /// This subscription's signal kind.
  pub fn kind(&self) -> SignalKind {
    self.kind
  }

  /// Waits for one coalesced event. Cancellation preserves an unseen event.
  pub fn recv(&mut self) -> SignalRecv<'_> {
    SignalRecv {
      signal: self,
      completed: false,
    }
  }

  /// Takes one already dispatched event without registering a waker.
  pub fn try_recv(&mut self) -> Result<bool, SignalError> {
    let mut state = lock(&self.shared.state);
    let slot = active_slot(&mut state.slots, self.key).ok_or(SignalError::Closed)?;
    if std::mem::take(&mut slot.pending) {
      Ok(true)
    } else if state.closed {
      Err(SignalError::Closed)
    } else {
      Ok(false)
    }
  }

  fn remove_waker(&self) {
    let old = {
      let mut state = lock(&self.shared.state);
      active_slot(&mut state.slots, self.key).and_then(|slot| slot.waker.take())
    };
    drop_contained(old);
  }
}

impl fmt::Debug for Signal {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Signal")
      .field("kind", &self.kind)
      .finish_non_exhaustive()
  }
}

impl Drop for Signal {
  fn drop(&mut self) {
    let old = {
      let mut state = lock(&self.shared.state);
      if let Some(slot) = active_slot(&mut state.slots, self.key) {
        slot.active = false;
        slot.pending = false;
        match slot.generation.checked_add(1) {
          Some(generation) => slot.generation = generation,
          None => slot.retired = true,
        }
        slot.waker.take()
      } else {
        None
      }
    };
    drop_contained(old);
  }
}

/// Borrowed receive future; completion consumes one event, cancellation only
/// removes its waker.
#[must_use = "futures do nothing unless polled"]
pub struct SignalRecv<'a> {
  signal: &'a mut Signal,
  completed: bool,
}

impl Future for SignalRecv<'_> {
  type Output = Result<(), SignalError>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    if this.completed {
      return Poll::Ready(Err(SignalError::Completed));
    }
    let waker = match panic::catch_unwind(AssertUnwindSafe(|| cx.waker().clone())) {
      Ok(waker) => waker,
      Err(payload) => {
        this.signal.remove_waker();
        this.completed = true;
        drop_contained(payload);
        return Poll::Ready(Err(SignalError::WakerPanicked));
      }
    };
    let (result, old, unused) = {
      let mut state = lock(&this.signal.shared.state);
      let closed = state.closed;
      match active_slot(&mut state.slots, this.signal.key) {
        None => (Poll::Ready(Err(SignalError::Closed)), None, Some(waker)),
        Some(slot) if slot.pending => {
          slot.pending = false;
          (Poll::Ready(Ok(())), slot.waker.take(), Some(waker))
        }
        Some(slot) if closed => (
          Poll::Ready(Err(SignalError::Closed)),
          slot.waker.take(),
          Some(waker),
        ),
        Some(slot) => (Poll::Pending, slot.waker.replace(waker), None),
      }
    };
    this.completed = result.is_ready();
    drop_contained(old);
    drop_contained(unused);
    result
  }
}

impl fmt::Debug for SignalRecv<'_> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("SignalRecv")
      .field("completed", &self.completed)
      .finish_non_exhaustive()
  }
}

impl Drop for SignalRecv<'_> {
  fn drop(&mut self) {
    self.signal.remove_waker();
  }
}

fn active_slot(slots: &mut [Slot], key: Key) -> Option<&mut Slot> {
  slots
    .get_mut(key.index)
    .filter(|slot| slot.active && slot.generation == key.generation)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(super) fn wake_all(wakes: &mut Vec<Waker>) {
  for waker in wakes.drain(..) {
    if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake())) {
      drop_contained(payload);
    }
  }
}

#[cfg(all(test, not(loom)))]
mod generation_tests {
  use super::*;

  #[test]
  fn exhausted_slot_retires_instead_of_aliasing_an_old_generation() {
    let shared = Shared::new(1).unwrap();
    lock(&shared.state).slots[0].generation = u64::MAX;
    let signal = Shared::subscribe(&shared, SignalKind::interrupt()).unwrap();
    drop(signal);
    assert!(matches!(
      Shared::subscribe(&shared, SignalKind::interrupt()),
      Err(SignalError::Full)
    ));
    assert!(lock(&shared.state).slots[0].retired);
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use super::*;
  use loom::sync::atomic::{AtomicUsize, Ordering};
  use std::task::Wake;

  struct CountWake(AtomicUsize);
  impl Wake for CountWake {
    fn wake(self: std::sync::Arc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  fn deliver(shared: &Shared, mask: u64) {
    let mut wakes = Vec::with_capacity(shared.capacity());
    shared.deliver(mask, &mut wakes);
    wake_all(&mut wakes);
  }

  #[test]
  fn delivery_racing_registration_wakes_a_pending_receiver() {
    loom::model(|| {
      let shared = Shared::new(1).unwrap();
      let kind = SignalKind::interrupt();
      let mut signal = Shared::subscribe(&shared, kind).unwrap();
      let count = std::sync::Arc::new(CountWake(AtomicUsize::new(0)));
      let waker = Waker::from(std::sync::Arc::clone(&count));
      let other = Arc::clone(&shared);
      let sender = loom::thread::spawn(move || deliver(&other, kind.mask()));
      let mut future = signal.recv();
      let first = Pin::new(&mut future).poll(&mut Context::from_waker(&waker));
      sender.join().unwrap();
      if first.is_pending() {
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert_eq!(
          Pin::new(&mut future).poll(&mut Context::from_waker(&waker)),
          Poll::Ready(Ok(()))
        );
      } else {
        assert_eq!(first, Poll::Ready(Ok(())));
      }
    });
  }

  #[test]
  fn cancelled_receive_preserves_a_racing_dispatched_event() {
    loom::model(|| {
      let shared = Shared::new(1).unwrap();
      let kind = SignalKind::interrupt();
      let mut signal = Shared::subscribe(&shared, kind).unwrap();
      let mut future = signal.recv();
      assert_eq!(
        Pin::new(&mut future).poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
      );
      let other = Arc::clone(&shared);
      let sender = loom::thread::spawn(move || deliver(&other, kind.mask()));
      drop(future);
      sender.join().unwrap();
      assert_eq!(signal.try_recv(), Ok(true));
      assert_eq!(signal.try_recv(), Ok(false));
    });
  }

  #[test]
  fn recycled_listener_cannot_receive_the_previous_kind() {
    loom::model(|| {
      let shared = Shared::new(1).unwrap();
      let old_kind = SignalKind::interrupt();
      let old = Shared::subscribe(&shared, old_kind).unwrap();
      let other = Arc::clone(&shared);
      let sender = loom::thread::spawn(move || deliver(&other, old_kind.mask()));
      drop(old);
      let mut replacement = Shared::subscribe(&shared, SignalKind::terminate()).unwrap();
      sender.join().unwrap();
      assert_eq!(replacement.try_recv(), Ok(false));
    });
  }

  #[test]
  fn close_racing_registration_wakes_before_terminal_completion() {
    loom::model(|| {
      let shared = Shared::new(1).unwrap();
      let mut signal = Shared::subscribe(&shared, SignalKind::interrupt()).unwrap();
      let count = std::sync::Arc::new(CountWake(AtomicUsize::new(0)));
      let waker = Waker::from(std::sync::Arc::clone(&count));
      let other = Arc::clone(&shared);
      let closer = loom::thread::spawn(move || {
        let mut wakes = Vec::with_capacity(other.capacity());
        other.close(&mut wakes);
        wake_all(&mut wakes);
      });
      let mut future = signal.recv();
      let first = Pin::new(&mut future).poll(&mut Context::from_waker(&waker));
      closer.join().unwrap();
      assert!(shared.is_closed());
      if first.is_pending() {
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert_eq!(
          Pin::new(&mut future).poll(&mut Context::from_waker(&waker)),
          Poll::Ready(Err(SignalError::Closed))
        );
      } else {
        assert_eq!(first, Poll::Ready(Err(SignalError::Closed)));
      }
    });
  }
}
