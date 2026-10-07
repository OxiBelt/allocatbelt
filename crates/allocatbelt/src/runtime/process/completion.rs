//! Shared completion and waiter-registration protocol for child processes.
//!
//! This module is included by the native process driver and directly by the
//! runtime facade's Loom checker, so models exercise the production state
//! transitions rather than a duplicate.

use std::fmt;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::process::ExitStatus;
use std::task::Waker;

#[cfg(loom)]
use loom::sync::atomic::AtomicBool;
#[cfg(loom)]
use loom::sync::{Mutex, MutexGuard};
#[cfg(not(loom))]
use std::sync::atomic::AtomicBool;
#[cfg(not(loom))]
use std::sync::{Mutex, MutexGuard, PoisonError};

/// A cached process-wait failure or bounded waiter-registration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitError {
  /// The operating system returned an error while the reaper polled the child.
  Reap(io::ErrorKind, Option<i32>),
  /// The operating system rejected the explicit kill request.
  Kill(io::ErrorKind, Option<i32>),
  /// The wait future's waker panicked while being cloned.
  WakerPanicked,
  /// The nonwrapping waker-registration generation was exhausted.
  Exhausted,
  /// The wait future was polled after completion.
  AlreadyCompleted,
}

impl fmt::Display for WaitError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Reap(kind, _) => write!(f, "child reaper failed: {kind}"),
      Self::Kill(kind, _) => write!(f, "child kill request failed: {kind}"),
      Self::WakerPanicked => f.write_str("child wait waker clone panicked"),
      Self::Exhausted => f.write_str("child wait registration is exhausted"),
      Self::AlreadyCompleted => f.write_str("child wait future was already completed"),
    }
  }
}

impl std::error::Error for WaitError {}

pub(super) struct Completion {
  ledger: Mutex<CompletionLedger>,
  pub(super) kill_requested: AtomicBool,
}

struct CompletionLedger {
  outcome: Option<Result<ExitStatus, WaitError>>,
  next_waiter: u64,
  waiter: Option<(u64, Waker)>,
}

/// The outcome observed by the waiter's poll/register linearization point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Registration {
  Ready(Result<ExitStatus, WaitError>),
  Pending,
}

impl Completion {
  pub(super) fn new() -> Self {
    Self {
      ledger: Mutex::new(CompletionLedger {
        outcome: None,
        next_waiter: 0,
        waiter: None,
      }),
      kill_requested: AtomicBool::new(false),
    }
  }

  /// Clone the candidate outside the ledger, then atomically either observe a
  /// published outcome or install the waiter. Any replaced or rejected waker
  /// is destroyed after unlocking.
  pub(super) fn poll_register(
    &self,
    current: &mut Option<u64>,
    waker: &Waker,
  ) -> Result<Registration, WaitError> {
    if let Some(outcome) = self.outcome() {
      return Ok(Registration::Ready(outcome));
    }

    let candidate = match panic::catch_unwind(AssertUnwindSafe(|| waker.clone())) {
      Ok(candidate) => candidate,
      Err(payload) => {
        drop_contained(payload);
        self.cancel_waiter(current);
        return Err(WaitError::WakerPanicked);
      }
    };

    let (result, discarded_old, discarded_candidate) = {
      let mut ledger = lock(&self.ledger);
      if let Some(outcome) = ledger.outcome {
        let old = ledger.waiter.take().map(|(_, old)| old);
        (Registration::Ready(outcome), old, Some(candidate))
      } else if let Some(key) = *current {
        let old = ledger.waiter.take().map(|(_, old)| old);
        ledger.waiter = Some((key, candidate));
        (Registration::Pending, old, None)
      } else if let Some(key) = ledger.next_waiter.checked_add(1) {
        ledger.next_waiter = key;
        let old = ledger.waiter.take().map(|(_, old)| old);
        ledger.waiter = Some((key, candidate));
        *current = Some(key);
        (Registration::Pending, old, None)
      } else {
        let old = ledger.waiter.take().map(|(_, old)| old);
        (
          Registration::Ready(Err(WaitError::Exhausted)),
          old,
          Some(candidate),
        )
      }
    };
    drop_contained(discarded_old);
    drop_contained(discarded_candidate);
    Ok(result)
  }

  /// Publish one terminal result and take the registered waker. The caller
  /// invokes it after releasing every process-table lock.
  pub(super) fn publish(&self, outcome: Result<ExitStatus, WaitError>) -> Option<Waker> {
    let mut ledger = lock(&self.ledger);
    if ledger.outcome.is_none() {
      ledger.outcome = Some(outcome);
    }
    ledger.waiter.take().map(|(_, waker)| waker)
  }

  pub(super) fn outcome(&self) -> Option<Result<ExitStatus, WaitError>> {
    lock(&self.ledger).outcome
  }

  /// Remove only this future's registration. The key prevents a stale future
  /// from canceling a later registration after its own waiter was replaced.
  pub(super) fn cancel_waiter(&self, current: &mut Option<u64>) {
    let Some(key) = current.take() else {
      return;
    };
    let waker = {
      let mut ledger = lock(&self.ledger);
      if ledger
        .waiter
        .as_ref()
        .is_some_and(|(registered, _)| *registered == key)
      {
        ledger.waiter.take().map(|(_, waker)| waker)
      } else {
        None
      }
    };
    drop_contained(waker);
  }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  #[cfg(loom)]
  {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
  }
  #[cfg(not(loom))]
  {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
  }
}

fn drop_contained<T>(value: T) {
  if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(move || drop(value)))
    && let Err(again) = panic::catch_unwind(AssertUnwindSafe(move || drop(payload)))
  {
    std::mem::forget(again);
  }
}

pub(super) fn wake_contained(waker: Option<Waker>) {
  if let Some(waker) = waker
    && let Err(payload) = panic::catch_unwind(AssertUnwindSafe(|| waker.wake()))
  {
    drop_contained(payload);
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::{Completion, Registration, WaitError};
  use std::sync::{Arc, Mutex};
  use std::task::{Wake, Waker};

  struct ReentrantWake(Arc<Completion>, Arc<Mutex<Option<u64>>>);

  impl Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
      let _ = self.0.outcome();
      let mut key = self.1.lock().unwrap();
      self.0.cancel_waiter(&mut key);
    }
  }

  struct PanicWake;

  impl Wake for PanicWake {
    fn wake(self: Arc<Self>) {
      panic!("intentional waiter wake panic");
    }
  }

  struct DropReenters(Arc<Completion>);

  #[expect(
    clippy::manual_noop_waker,
    reason = "the retained waker's destructor reenters the completion ledger"
  )]
  impl Wake for DropReenters {
    fn wake(self: Arc<Self>) {}
  }

  impl Drop for DropReenters {
    fn drop(&mut self) {
      let _ = self.0.outcome();
    }
  }

  #[test]
  fn wake_callbacks_run_outside_completion_lock_and_are_contained() {
    let completion = Arc::new(Completion::new());
    let key = Arc::new(Mutex::new(None));
    let waker = Waker::from(Arc::new(ReentrantWake(
      Arc::clone(&completion),
      Arc::clone(&key),
    )));
    let registration = completion.poll_register(&mut key.lock().unwrap(), &waker);
    assert_eq!(registration, Ok(Registration::Pending));
    let waker = completion.publish(Err(WaitError::Exhausted));
    super::wake_contained(waker);
    assert_eq!(completion.outcome(), Some(Err(WaitError::Exhausted)));

    let completion = Completion::new();
    let waker = Waker::from(Arc::new(PanicWake));
    let mut key = None;
    assert_eq!(
      completion.poll_register(&mut key, &waker),
      Ok(Registration::Pending)
    );
    let waker = completion.publish(Err(WaitError::Exhausted));
    super::wake_contained(waker);
    assert_eq!(completion.outcome(), Some(Err(WaitError::Exhausted)));
  }

  #[test]
  fn replacing_a_retained_waiter_drops_it_after_unlocking() {
    let completion = Arc::new(Completion::new());
    let mut abandoned_key = None;
    let abandoned = Waker::from(Arc::new(DropReenters(Arc::clone(&completion))));
    assert_eq!(
      completion.poll_register(&mut abandoned_key, &abandoned),
      Ok(Registration::Pending)
    );
    drop(abandoned);
    // Models a forgotten future: its registration remains, while the next
    // future starts with no key and must replace that stale waker.
    let _abandoned_key = abandoned_key;

    let fresh = Waker::noop();
    let mut fresh_key = None;
    assert_eq!(
      completion.poll_register(&mut fresh_key, fresh),
      Ok(Registration::Pending)
    );
    completion.cancel_waiter(&mut fresh_key);
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use super::{Completion, Registration, WaitError};
  use loom::sync::Arc;
  use loom::sync::atomic::{AtomicUsize, Ordering};
  use loom::thread;
  use std::sync::Arc as StdArc;
  use std::task::{Wake, Waker};

  struct CountWake(Arc<AtomicUsize>);

  impl Wake for CountWake {
    fn wake(self: StdArc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  #[test]
  fn registration_racing_publication_is_ready_or_woken() {
    loom::model(|| {
      let completion = Arc::new(Completion::new());
      let count = Arc::new(AtomicUsize::new(0));
      let waker = Waker::from(StdArc::new(CountWake(Arc::clone(&count))));
      let publisher = {
        let completion = Arc::clone(&completion);
        thread::spawn(move || {
          super::wake_contained(completion.publish(Err(WaitError::Exhausted)));
        })
      };
      let mut key = None;
      let result = completion.poll_register(&mut key, &waker).unwrap();
      publisher.join().unwrap();
      assert!(matches!(
        result,
        Registration::Pending | Registration::Ready(Err(WaitError::Exhausted))
      ));
      assert_eq!(completion.outcome(), Some(Err(WaitError::Exhausted)));
      if result == Registration::Pending {
        assert!(count.load(Ordering::SeqCst) > 0);
      }
    });
  }

  #[test]
  fn cancellation_racing_publication_never_wakes_a_removed_waiter() {
    loom::model(|| {
      let completion = Arc::new(Completion::new());
      let count = Arc::new(AtomicUsize::new(0));
      let waker = Waker::from(StdArc::new(CountWake(Arc::clone(&count))));
      let mut key = None;
      assert_eq!(
        completion.poll_register(&mut key, &waker).unwrap(),
        Registration::Pending
      );
      let canceler = {
        let completion = Arc::clone(&completion);
        thread::spawn(move || completion.cancel_waiter(&mut key))
      };
      let publisher = {
        let completion = Arc::clone(&completion);
        thread::spawn(move || {
          super::wake_contained(completion.publish(Err(WaitError::Exhausted)));
        })
      };
      canceler.join().unwrap();
      publisher.join().unwrap();
      assert_eq!(completion.outcome(), Some(Err(WaitError::Exhausted)));
      assert!(count.load(Ordering::SeqCst) <= 1);
    });
  }

  #[test]
  fn terminal_completion_arc_survives_new_slot_occupant() {
    loom::model(|| {
      let old = Arc::new(Completion::new());
      old.publish(Err(WaitError::Reap(std::io::ErrorKind::Other, Some(5))));
      old.kill_requested.store(true, Ordering::Release);
      let slot = Arc::new(loom::sync::Mutex::new(Arc::clone(&old)));
      let replacement = Arc::new(Completion::new());
      *slot.lock().unwrap() = Arc::clone(&replacement);
      assert_eq!(
        old.outcome(),
        Some(Err(WaitError::Reap(std::io::ErrorKind::Other, Some(5))))
      );
      assert!(old.kill_requested.load(Ordering::Acquire));
      assert_eq!(replacement.outcome(), None);
      let _other_errors = (
        WaitError::Kill(std::io::ErrorKind::Other, Some(5)),
        WaitError::AlreadyCompleted,
      );
    });
  }
}
