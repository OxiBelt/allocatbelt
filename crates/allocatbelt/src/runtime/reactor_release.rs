//! The lock-protected choice between an empty-waiter fast release and
//! reserving bounded waker storage outside the reactor lock.

/// Runs `begin_release` under the caller's state lock only when the
/// registration has no waiters. The inspection and transition must remain
/// in the same critical section so a waiter cannot arrive between them.
pub(crate) fn begin_if_no_waiters<S, R>(
  state: &mut S,
  has_waiters: impl FnOnce(&S) -> bool,
  begin_release: impl FnOnce(&mut S) -> R,
) -> Option<R> {
  if has_waiters(state) {
    None
  } else {
    Some(begin_release(state))
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use loom::sync::{Arc, Mutex};
  use loom::thread;

  use super::begin_if_no_waiters;

  #[derive(Default)]
  struct State {
    live: bool,
    waiters: usize,
    releases: usize,
    drained: usize,
  }

  #[test]
  fn release_inspection_and_empty_transition_are_atomic_with_waiter_enrollment() {
    loom::model(|| {
      let state = Arc::new(Mutex::new(State {
        live: true,
        ..State::default()
      }));

      let releasing = Arc::clone(&state);
      let release = thread::spawn(move || {
        let needs_waker_storage = {
          let mut state = releasing.lock().unwrap();
          begin_if_no_waiters(
            &mut state,
            |state| state.waiters != 0,
            |state| {
              state.live = false;
              state.drained += state.waiters;
              state.waiters = 0;
              state.releases += 1;
            },
          )
          .is_none()
        };

        if needs_waker_storage {
          // This second lock acquisition represents reserving the bounded
          // vector after dropping the state lock. A concurrent cancellation
          // or registration may change the waiter count, but the release
          // still drains every waiter present at this transition.
          let mut state = releasing.lock().unwrap();
          if state.live {
            state.live = false;
            state.drained += state.waiters;
            state.waiters = 0;
            state.releases += 1;
          }
        }
      });

      let enrolling = Arc::clone(&state);
      let enroll = thread::spawn(move || {
        let mut state = enrolling.lock().unwrap();
        if state.live {
          state.waiters += 1;
        }
      });

      release.join().unwrap();
      enroll.join().unwrap();
      let state = state.lock().unwrap();
      assert!(!state.live);
      assert_eq!(state.waiters, 0);
      assert_eq!(state.releases, 1);
      assert!(state.drained <= 1);
    });
  }
}
