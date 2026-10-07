//! Dispatcher-turn and handoff-slot accounting for `try_block_in_place`.
//! Production keeps one [`TurnCoordinator`] under the scheduler mutex; Loom
//! tests drive the same transitions under Loom's mutex.
//!
//! A *turn* is one owned poll, cancellation or publication step and holds one
//! of `W` dispatcher permits. A *loan* is one of `B` handoff slots: a turn
//! converts into a loan when its thread runs a blocking closure, which frees
//! the permit for an activated helper, and the loan converts back into a turn
//! once the original thread reacquires a permit. At most `W` turns and `B`
//! loans exist at once, so at most `W + B` outer poll stacks. Permits, loans,
//! restoration tickets and helper leases are linear values: none is `Clone`
//! and every release consumes the value it releases, so one acquisition
//! cannot be released twice.

/// One held dispatcher permit.
#[derive(Debug)]
#[must_use]
pub(super) struct DispatchTurn(());

/// One held handoff slot whose dispatcher permit has been released.
#[derive(Debug)]
#[must_use]
pub(super) struct HandoffLoan(());

/// A loan whose original thread is waiting to reacquire a permit. While any
/// ticket is outstanding, no new turn starts.
#[derive(Debug)]
#[must_use]
pub(super) struct RestoreTicket(());

/// One activated helper thread.
#[derive(Debug)]
#[must_use]
pub(super) struct HelperLease(());

/// What ending a turn requires the caller to wake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TurnEnd {
  /// A restoring thread may now reacquire the released permit.
  pub(super) wake_restorer: bool,
  /// No turn, loan or restoration remains.
  pub(super) quiescent: bool,
}

/// Fixed-capacity counters for dispatcher permits, handoff loans, waiting
/// restorations and activated helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TurnCoordinator {
  dispatchers: usize,
  max_handoffs: usize,
  turns: usize,
  handoffs: usize,
  restoring: usize,
  helpers: usize,
}

impl TurnCoordinator {
  pub(super) const fn new(dispatchers: usize, max_handoffs: usize) -> Self {
    Self {
      dispatchers,
      max_handoffs,
      turns: 0,
      handoffs: 0,
      restoring: 0,
      helpers: 0,
    }
  }

  pub(super) const fn handoffs_enabled(&self) -> bool {
    self.max_handoffs != 0
  }

  /// Whether a new turn could start now. A waiting restoration has priority
  /// over every new turn.
  pub(super) const fn can_begin_turn(&self) -> bool {
    self.turns < self.dispatchers && self.restoring == 0
  }

  pub(super) fn try_begin_turn(&mut self) -> Option<DispatchTurn> {
    if !self.can_begin_turn() {
      return None;
    }
    self.turns += 1;
    Some(DispatchTurn(()))
  }

  pub(super) fn end_turn(&mut self, turn: DispatchTurn) -> TurnEnd {
    let DispatchTurn(()) = turn;
    debug_assert!(self.turns > 0);
    self.turns = self.turns.saturating_sub(1);
    TurnEnd {
      wake_restorer: self.restoring != 0,
      quiescent: self.quiescent(),
    }
  }

  /// Reserves a handoff slot before releasing the turn's permit. A full or
  /// disabled bound returns the unchanged turn.
  pub(super) fn try_hand_off(&mut self, turn: DispatchTurn) -> Result<HandoffLoan, DispatchTurn> {
    if self.handoffs >= self.max_handoffs {
      return Err(turn);
    }
    let DispatchTurn(()) = turn;
    self.handoffs += 1;
    debug_assert!(self.turns > 0);
    self.turns = self.turns.saturating_sub(1);
    Ok(HandoffLoan(()))
  }

  /// Registers the loan's thread as waiting to reacquire a permit. The loan
  /// stays counted until [`Self::try_restore`] succeeds.
  pub(super) fn begin_restore(&mut self, loan: HandoffLoan) -> RestoreTicket {
    let HandoffLoan(()) = loan;
    self.restoring += 1;
    RestoreTicket(())
  }

  /// Converts a waiting restoration back into a turn when a permit is free.
  /// Restoration ignores admission closure.
  pub(super) fn try_restore(
    &mut self,
    ticket: RestoreTicket,
  ) -> Result<DispatchTurn, RestoreTicket> {
    if self.turns >= self.dispatchers {
      return Err(ticket);
    }
    let RestoreTicket(()) = ticket;
    debug_assert!(self.restoring > 0 && self.handoffs > 0);
    self.restoring = self.restoring.saturating_sub(1);
    self.handoffs = self.handoffs.saturating_sub(1);
    self.turns += 1;
    Ok(DispatchTurn(()))
  }

  /// Activates one helper while fewer helpers than loans are active.
  pub(super) fn try_activate_helper(&mut self) -> Option<HelperLease> {
    if self.helpers >= self.handoffs {
      return None;
    }
    self.helpers += 1;
    Some(HelperLease(()))
  }

  pub(super) const fn can_activate_helper(&self) -> bool {
    self.helpers < self.handoffs
  }

  /// Retires an active helper between turns once more helpers than loans
  /// are active; otherwise returns the unchanged lease.
  pub(super) fn retire_helper(&mut self, lease: HelperLease) -> Result<(), HelperLease> {
    if self.helpers <= self.handoffs {
      return Err(lease);
    }
    let HelperLease(()) = lease;
    self.helpers -= 1;
    Ok(())
  }

  pub(super) const fn helper_is_excess(&self) -> bool {
    self.helpers > self.handoffs
  }

  pub(super) const fn quiescent(&self) -> bool {
    self.turns == 0 && self.handoffs == 0 && self.restoring == 0
  }

  /// Threads exit only once admission is empty. With handoffs enabled they
  /// also wait until no turn, loan or restoration remains, so a closing
  /// publication or restoration can still hand off or reacquire a permit.
  /// Without handoffs, exit is unchanged from the fixed worker pool.
  pub(super) const fn may_exit(&self, admission_empty: bool) -> bool {
    admission_empty && (!self.handoffs_enabled() || self.quiescent())
  }

  #[cfg(test)]
  pub(super) const fn counts(&self) -> (usize, usize, usize, usize) {
    (self.turns, self.handoffs, self.restoring, self.helpers)
  }

  #[cfg(test)]
  pub(super) fn check(&self) {
    assert!(self.turns <= self.dispatchers, "dispatcher bound exceeded");
    assert!(self.handoffs <= self.max_handoffs, "handoff bound exceeded");
    assert!(self.restoring <= self.handoffs, "restoration without loan");
    assert!(self.helpers <= self.max_handoffs, "helper bound exceeded");
    assert!(
      self.turns + self.handoffs <= self.dispatchers + self.max_handoffs,
      "outer poll stack bound exceeded"
    );
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::TurnCoordinator;

  #[test]
  fn full_and_disabled_handoffs_return_the_unchanged_turn() {
    let mut disabled = TurnCoordinator::new(1, 0);
    let turn = disabled.try_begin_turn().unwrap();
    let turn = disabled.try_hand_off(turn).unwrap_err();
    assert_eq!(disabled.counts(), (1, 0, 0, 0));
    let end = disabled.end_turn(turn);
    assert!(end.quiescent && !end.wake_restorer);

    let mut full = TurnCoordinator::new(2, 1);
    let first = full.try_begin_turn().unwrap();
    let second = full.try_begin_turn().unwrap();
    assert!(full.try_begin_turn().is_none());
    let loan = full.try_hand_off(first).unwrap();
    let second = full.try_hand_off(second).unwrap_err();
    assert_eq!(full.counts(), (1, 1, 0, 0));
    full.check();
    let _ = full.end_turn(second);
    let ticket = full.begin_restore(loan);
    let turn = full.try_restore(ticket).unwrap();
    let _ = full.end_turn(turn);
    assert!(full.quiescent());
  }

  #[test]
  fn restoration_has_priority_and_excess_helpers_retire_between_turns() {
    let mut state = TurnCoordinator::new(1, 1);
    let original = state.try_begin_turn().unwrap();
    let loan = state.try_hand_off(original).unwrap();
    let lease = state.try_activate_helper().unwrap();
    assert!(state.try_activate_helper().is_none());
    let helper_turn = state.try_begin_turn().unwrap();
    let ticket = state.begin_restore(loan);
    // The original cannot preempt the helper's turn; it waits.
    let ticket = state.try_restore(ticket).unwrap_err();
    let lease = state.retire_helper(lease).unwrap_err();
    let end = state.end_turn(helper_turn);
    assert!(end.wake_restorer && !end.quiescent);
    // A new turn cannot overtake the waiting restoration.
    assert!(state.try_begin_turn().is_none());
    assert!(!state.may_exit(true));
    let original = state.try_restore(ticket).unwrap();
    assert!(state.helper_is_excess());
    state.retire_helper(lease).unwrap();
    assert!(!state.may_exit(true));
    let end = state.end_turn(original);
    assert!(end.quiescent && !end.wake_restorer);
    assert!(state.may_exit(true));
    assert!(!state.may_exit(false));
    state.check();
  }

  #[test]
  fn without_handoffs_exit_depends_only_on_admission() {
    let mut state = TurnCoordinator::new(2, 0);
    let turn = state.try_begin_turn().unwrap();
    assert!(state.may_exit(true));
    assert!(!state.may_exit(false));
    let _ = state.end_turn(turn);
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use loom::sync::{Arc, Mutex};
  use loom::thread;

  use super::{DispatchTurn, HelperLease, TurnCoordinator};

  fn lock<T>(mutex: &Mutex<T>) -> loom::sync::MutexGuard<'_, T> {
    mutex
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
  }

  fn bounded_model(check: impl Fn() + Sync + Send + 'static) {
    let mut model = loom::model::Builder::new();
    model.max_permutations = Some(10_000);
    model.check(check);
  }

  struct Model {
    turns: TurnCoordinator,
    restored: bool,
    closure_done: bool,
    helper_turns: usize,
  }

  impl Model {
    fn new(dispatchers: usize, handoffs: usize) -> (Self, DispatchTurn) {
      let mut turns = TurnCoordinator::new(dispatchers, handoffs);
      let original = turns.try_begin_turn().unwrap();
      (
        Self {
          turns,
          restored: false,
          closure_done: false,
          helper_turns: 0,
        },
        original,
      )
    }
  }

  /// The original thread: hand off, run the closure, restore, end the turn.
  fn original(state: &Mutex<Model>, turn: DispatchTurn) {
    let loan = {
      let mut state = lock(state);
      let loan = state.turns.try_hand_off(turn).unwrap();
      state.turns.check();
      loan
    };
    thread::yield_now();
    let mut ticket = {
      let mut state = lock(state);
      state.closure_done = true;
      let ticket = state.turns.begin_restore(loan);
      state.turns.check();
      ticket
    };
    let turn = loop {
      {
        let mut state = lock(state);
        match state.turns.try_restore(ticket) {
          Ok(turn) => {
            state.restored = true;
            state.turns.check();
            break turn;
          }
          Err(waiting) => ticket = waiting,
        }
      }
      thread::yield_now();
    };
    let mut state = lock(state);
    let _ = state.turns.end_turn(turn);
    state.turns.check();
  }

  /// A helper: activate while a loan exists, run turns, retire when excess.
  /// Stops once the protocol is quiescent and it holds no lease.
  fn helper(state: &Mutex<Model>, try_nested_handoff: bool) {
    let mut lease: Option<HelperLease> = None;
    loop {
      {
        let mut state = lock(state);
        if let Some(held) = lease.take() {
          match state.turns.retire_helper(held) {
            Ok(()) => {}
            Err(held) => {
              if let Some(turn) = state.turns.try_begin_turn() {
                assert!(!state.restored || state.closure_done);
                state.helper_turns += 1;
                let turn = if try_nested_handoff {
                  // The single slot is held by the original: the helper's
                  // nested request is rejected and keeps its turn.
                  state.turns.try_hand_off(turn).unwrap_err()
                } else {
                  turn
                };
                state.turns.check();
                let _ = state.turns.end_turn(turn);
              }
              lease = Some(held);
            }
          }
        } else if let Some(held) = state.turns.try_activate_helper() {
          lease = Some(held);
        } else if state.turns.quiescent() {
          state.turns.check();
          return;
        }
        state.turns.check();
      }
      thread::yield_now();
    }
  }

  #[test]
  fn loom_handoff_activation_and_reentry_conserve_permits_and_slots() {
    bounded_model(|| {
      let (model, turn) = Model::new(1, 1);
      let state = Arc::new(Mutex::new(model));
      let original_thread = {
        let state = Arc::clone(&state);
        thread::spawn(move || original(&state, turn))
      };
      let helper_thread = {
        let state = Arc::clone(&state);
        thread::spawn(move || helper(&state, false))
      };
      original_thread.join().unwrap();
      helper_thread.join().unwrap();
      let state = lock(&state);
      assert!(state.restored);
      assert_eq!(state.turns.counts(), (0, 0, 0, 0));
      assert!(state.turns.may_exit(true));
    });
  }

  #[test]
  fn loom_helper_origin_handoff_is_bounded_by_the_shared_slots() {
    bounded_model(|| {
      let (model, turn) = Model::new(1, 1);
      let state = Arc::new(Mutex::new(model));
      let original_thread = {
        let state = Arc::clone(&state);
        thread::spawn(move || original(&state, turn))
      };
      let helper_thread = {
        let state = Arc::clone(&state);
        thread::spawn(move || helper(&state, true))
      };
      original_thread.join().unwrap();
      helper_thread.join().unwrap();
      assert_eq!(lock(&state).turns.counts(), (0, 0, 0, 0));
    });
  }

  #[test]
  fn loom_waiting_restoration_has_priority_over_new_turns() {
    bounded_model(|| {
      let (mut model, original_turn) = Model::new(1, 1);
      let loan = model.turns.try_hand_off(original_turn).unwrap();
      // A dispatcher already occupies the freed permit.
      let busy = model.turns.try_begin_turn().unwrap();
      let ticket = model.turns.begin_restore(loan);
      let state = Arc::new(Mutex::new(model));
      let restorer = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          let mut ticket = ticket;
          let turn = loop {
            {
              let mut state = lock(&state);
              match state.turns.try_restore(ticket) {
                Ok(turn) => {
                  state.restored = true;
                  break turn;
                }
                Err(waiting) => ticket = waiting,
              }
            }
            thread::yield_now();
          };
          let mut state = lock(&state);
          let _ = state.turns.end_turn(turn);
        })
      };
      let dispatcher = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          let end = lock(&state).turns.end_turn(busy);
          assert!(end.wake_restorer || lock(&state).restored);
        })
      };
      let newcomer = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          let mut state = lock(&state);
          if let Some(turn) = state.turns.try_begin_turn() {
            assert!(state.restored, "a new turn overtook a waiting restoration");
            let _ = state.turns.end_turn(turn);
          }
        })
      };
      restorer.join().unwrap();
      dispatcher.join().unwrap();
      newcomer.join().unwrap();
      assert_eq!(lock(&state).turns.counts(), (0, 0, 0, 0));
    });
  }

  #[test]
  fn loom_close_cannot_observe_exit_before_restoration_finishes() {
    bounded_model(|| {
      let (model, turn) = Model::new(1, 1);
      let state = Arc::new(Mutex::new(model));
      let original_thread = {
        let state = Arc::clone(&state);
        thread::spawn(move || original(&state, turn))
      };
      let helper_thread = {
        let state = Arc::clone(&state);
        thread::spawn(move || helper(&state, false))
      };
      let closer = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          // Admission is already empty and closed: exit is allowed only when
          // the original has restored and ended its turn.
          let state = lock(&state);
          if state.turns.may_exit(true) {
            assert!(state.restored);
            assert_eq!(state.turns.counts().0, 0);
          }
        })
      };
      original_thread.join().unwrap();
      helper_thread.join().unwrap();
      closer.join().unwrap();
      assert!(lock(&state).turns.may_exit(true));
    });
  }
}
