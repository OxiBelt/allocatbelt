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
//! cannot be released twice. Only this module can construct dispatcher turns;
//! callers can read their seat identity without creating or changing a token.

/// One held dispatcher permit.
#[derive(Debug)]
#[must_use]
pub(super) struct DispatchTurn {
  seat: usize,
}

impl DispatchTurn {
  pub(super) const fn seat(&self) -> usize {
    self.seat
  }
}

/// One held handoff slot whose dispatcher permit has been released.
#[derive(Debug)]
#[must_use]
pub(super) struct HandoffLoan {
  helper: bool,
}

/// A loan whose original thread is waiting to reacquire a permit. While any
/// ticket is outstanding, no new turn starts.
#[derive(Debug)]
#[must_use]
pub(super) struct RestoreTicket {
  helper: bool,
}

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
    Some(DispatchTurn { seat: 0 })
  }

  pub(super) fn end_turn(&mut self, turn: DispatchTurn) -> TurnEnd {
    let DispatchTurn { seat: _ } = turn;
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
    let DispatchTurn { seat: _ } = turn;
    self.handoffs += 1;
    debug_assert!(self.turns > 0);
    self.turns = self.turns.saturating_sub(1);
    Ok(HandoffLoan { helper: false })
  }

  /// Registers the loan's thread as waiting to reacquire a permit. The loan
  /// stays counted until [`Self::try_restore`] succeeds.
  pub(super) fn begin_restore(&mut self, loan: HandoffLoan) -> RestoreTicket {
    let HandoffLoan { helper } = loan;
    self.restoring += 1;
    RestoreTicket { helper }
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
    let RestoreTicket { helper: _ } = ticket;
    debug_assert!(self.restoring > 0 && self.handoffs > 0);
    self.restoring = self.restoring.saturating_sub(1);
    self.handoffs = self.handoffs.saturating_sub(1);
    self.turns += 1;
    Ok(DispatchTurn { seat: 0 })
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

/// Seat identity around the existing turn counters. This table is only
/// used by distributed dispatch; strict keeps using the counters.
#[derive(Debug)]
pub(super) struct SeatTable {
  turns: TurnCoordinator,
  vacant: Vec<usize>,
  helper_held: Vec<bool>,
}

#[cfg_attr(
  not(test),
  expect(
    dead_code,
    reason = "handoff operations reserved for distributed handoffs"
  )
)]
impl SeatTable {
  #[cfg(test)]
  pub(super) fn new(workers: usize, max_handoffs: usize) -> Self {
    Self {
      turns: TurnCoordinator::new(workers, max_handoffs),
      vacant: (0..workers).rev().collect(),
      helper_held: vec![false; workers],
    }
  }

  pub(super) fn try_new(
    workers: usize,
    max_handoffs: usize,
  ) -> Result<Self, std::collections::TryReserveError> {
    let mut vacant = Vec::new();
    vacant.try_reserve_exact(workers)?;
    vacant.extend((0..workers).rev());
    let mut helper_held = Vec::new();
    helper_held.try_reserve_exact(workers)?;
    helper_held.resize(workers, false);
    Ok(Self {
      turns: TurnCoordinator::new(workers, max_handoffs),
      vacant,
      helper_held,
    })
  }

  pub(super) fn capacities(&self) -> (usize, usize) {
    (self.vacant.capacity(), self.helper_held.capacity())
  }

  pub(super) fn claim(&mut self, seat: usize) -> DispatchTurn {
    let Some(position) = self.vacant.iter().position(|&vacant| vacant == seat) else {
      panic!("seat is already held");
    };
    let Some(mut turn) = self.turns.try_begin_turn() else {
      panic!("worker startup cannot acquire a turn");
    };
    self.vacant.swap_remove(position);
    turn.seat = seat;
    turn
  }

  fn assign(&mut self, mut turn: DispatchTurn, helper: bool) -> DispatchTurn {
    let Some(seat) = self.vacant.pop() else {
      panic!("turn without a vacant seat");
    };
    turn.seat = seat;
    self.helper_held[seat] = helper;
    turn
  }

  pub(super) fn try_begin_helper_turn(&mut self) -> Option<DispatchTurn> {
    let turn = self.turns.try_begin_turn()?;
    Some(self.assign(turn, true))
  }

  pub(super) fn end_turn(&mut self, turn: DispatchTurn) -> TurnEnd {
    self.vacant.push(turn.seat());
    self.helper_held[turn.seat()] = false;
    self.turns.end_turn(turn)
  }

  pub(super) fn try_hand_off(&mut self, turn: DispatchTurn) -> Result<HandoffLoan, DispatchTurn> {
    let seat = turn.seat();
    let mut loan = self.turns.try_hand_off(turn)?;
    // Preserve helper identity even if an activated helper hands off and
    // later restores onto a different seat.
    loan.helper = self.helper_held[seat];
    self.helper_held[seat] = false;
    self.vacant.push(seat);
    Ok(loan)
  }

  pub(super) fn begin_restore(&mut self, loan: HandoffLoan) -> RestoreTicket {
    self.turns.begin_restore(loan)
  }

  pub(super) fn try_restore(
    &mut self,
    ticket: RestoreTicket,
  ) -> Result<DispatchTurn, RestoreTicket> {
    let helper = ticket.helper;
    let turn = self.turns.try_restore(ticket)?;
    Ok(self.assign(turn, helper))
  }

  pub(super) fn try_activate_helper(&mut self) -> Option<HelperLease> {
    self.turns.try_activate_helper()
  }

  pub(super) fn retire_helper(&mut self, lease: HelperLease) -> Result<(), HelperLease> {
    self.turns.retire_helper(lease)
  }

  pub(super) const fn helper_is_excess(&self) -> bool {
    self.turns.helper_is_excess()
  }

  pub(super) const fn may_exit(&self, admission_empty: bool) -> bool {
    admission_empty && self.turns.handoffs == 0 && self.turns.restoring == 0
  }

  #[cfg(test)]
  pub(super) fn check(&self) {
    self.turns.check();
    assert_eq!(self.turns.turns + self.vacant.len(), self.turns.dispatchers);
    assert_eq!(self.helper_held.len(), self.turns.dispatchers);
    for (position, &seat) in self.vacant.iter().enumerate() {
      assert!(seat < self.turns.dispatchers);
      assert!(
        !self.vacant[..position].contains(&seat),
        "duplicate vacant seat"
      );
      assert!(!self.helper_held[seat]);
    }
    assert!(self.helper_held.iter().filter(|&&held| held).count() <= self.turns.helpers);
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

  #[test]
  fn loom_seat_handoff_restore_and_helper_retirement_conserve_identity() {
    use super::SeatTable;

    bounded_model(|| {
      let mut seats = SeatTable::new(2, 1);
      let original = seats.claim(0);
      let second = seats.claim(1);
      let state = Arc::new(Mutex::new((seats, false)));
      let worker = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          let loan = {
            let mut state = lock(&state);
            let loan = state.0.try_hand_off(original).unwrap();
            state.0.check();
            assert!(!state.0.may_exit(true));
            loan
          };
          thread::yield_now();
          let mut ticket = lock(&state).0.begin_restore(loan);
          let turn = loop {
            {
              let mut state = lock(&state);
              match state.0.try_restore(ticket) {
                Ok(turn) => {
                  state.1 = true;
                  state.0.check();
                  break turn;
                }
                Err(waiting) => ticket = waiting,
              }
            }
            thread::yield_now();
          };
          let mut state = lock(&state);
          let _ = state.0.end_turn(turn);
          state.0.check();
        })
      };
      let helper = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          let mut lease = None;
          let mut turn = None;
          loop {
            {
              let mut state = lock(&state);
              if let Some(held) = turn.take() {
                let _ = state.0.end_turn(held);
              }
              if let Some(held) = lease.take() {
                match state.0.retire_helper(held) {
                  Ok(()) => {}
                  Err(held) => lease = Some(held),
                }
              }
              if lease.is_none() {
                lease = state.0.try_activate_helper();
              }
              if lease.is_some() {
                turn = state.0.try_begin_helper_turn();
              }
              state.0.check();
              // Admission stays occupied until the original worker restores.
              if state.0.may_exit(state.1) {
                assert!(state.1, "exit before restoration");
                if let Some(held) = turn.take() {
                  let _ = state.0.end_turn(held);
                }
                if let Some(held) = lease.take() {
                  assert!(state.0.helper_is_excess());
                  state.0.retire_helper(held).unwrap();
                }
                state.0.check();
                break;
              }
            }
            thread::yield_now();
          }
        })
      };
      let other = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          thread::yield_now();
          let mut state = lock(&state);
          assert_eq!(second.seat(), 1);
          assert!(!state.0.vacant.contains(&second.seat()));
          let _ = state.0.end_turn(second);
          state.0.check();
        })
      };
      worker.join().unwrap();
      helper.join().unwrap();
      other.join().unwrap();
      let state = lock(&state);
      state.0.check();
      assert!(state.1);
      assert_eq!(state.0.turns.counts(), (0, 0, 0, 0));
      assert_eq!(state.0.vacant.len(), 2);
    });
  }
}

#[cfg(all(test, not(loom)))]
mod seat_tests {
  use super::SeatTable;

  #[test]
  fn seats_are_distinct_and_restore_has_priority() {
    let mut seats = SeatTable::new(2, 1);
    let first = seats.claim(0);
    let second = seats.claim(1);
    assert_ne!(first.seat(), second.seat());
    assert!(seats.try_begin_helper_turn().is_none());
    let loan = seats.try_hand_off(first).unwrap();
    assert!(!seats.may_exit(true));
    let lease = seats.try_activate_helper().unwrap();
    let helper = seats.try_begin_helper_turn().unwrap();
    assert_eq!(helper.seat(), 0);
    assert!(seats.helper_held[helper.seat()]);
    seats.check();
    let ticket = seats.begin_restore(loan);
    let ticket = seats.try_restore(ticket).unwrap_err();
    assert!(seats.end_turn(helper).wake_restorer);
    assert!(seats.try_begin_helper_turn().is_none());
    let first = seats.try_restore(ticket).unwrap();
    assert_eq!(first.seat(), 0);
    assert!(!seats.helper_held[first.seat()]);
    assert!(seats.helper_is_excess());
    seats.retire_helper(lease).unwrap();
    seats.check();
    assert!(seats.may_exit(true));
    assert!(!seats.may_exit(false));
    let _ = seats.end_turn(first);
    let _ = seats.end_turn(second);
    seats.check();
    assert_eq!(seats.vacant.len(), 2);
  }

  #[test]
  fn full_handoff_preserves_seat_and_helper_restore_preserves_kind() {
    let mut seats = SeatTable::new(2, 2);
    let first = seats.claim(0);
    let second = seats.claim(1);
    let loan = seats.try_hand_off(first).unwrap();
    let lease = seats.try_activate_helper().unwrap();
    let helper = seats.try_begin_helper_turn().unwrap();
    let helper_loan = seats.try_hand_off(helper).unwrap();
    let second = seats.try_hand_off(second).unwrap_err();
    assert_eq!(second.seat(), 1);
    let ticket = seats.begin_restore(helper_loan);
    let helper = seats.try_restore(ticket).unwrap();
    assert!(seats.helper_held[helper.seat()]);
    seats.check();
    let ticket = seats.begin_restore(loan);
    let ticket = seats.try_restore(ticket).unwrap_err();
    let _ = seats.end_turn(helper);
    let first = seats.try_restore(ticket).unwrap();
    seats.retire_helper(lease).unwrap();
    let _ = seats.end_turn(first);
    let _ = seats.end_turn(second);
    seats.check();
    assert!(seats.may_exit(true));
  }

  #[test]
  #[should_panic(expected = "seat is already held")]
  fn an_occupied_seat_cannot_be_claimed_twice() {
    let mut seats = SeatTable::new(1, 0);
    let _turn = seats.claim(0);
    let _duplicate = seats.claim(0);
  }
}
