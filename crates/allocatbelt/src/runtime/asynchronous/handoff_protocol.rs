//! Dispatcher-turn and handoff-slot accounting for `try_block_in_place`.
//! Production keeps a [`SeatTable`] under its seat mutex; Loom tests drive
//! the same transitions under Loom's mutex.
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

/// Fixed-capacity counters for dispatcher permits, handoff loans, waiting
/// restorations and activated helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TurnCoordinator {
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

  /// Whether a vacant seat may be assigned to a helper or resuming worker.
  /// Waiting restorations have priority for those seats; dispatchers already
  /// holding other seats continue polling.
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

  fn end_turn(&mut self, turn: DispatchTurn) {
    let DispatchTurn { seat: _ } = turn;
    debug_assert!(self.turns > 0);
    self.turns = self.turns.saturating_sub(1);
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

/// Seat identity and handoff counters for dispatchers and helpers.
#[derive(Debug)]
pub(super) struct SeatTable {
  turns: TurnCoordinator,
  vacant: Vec<usize>,
  helper_held: Vec<bool>,
  // Helpers/restorers must not consume seats reserved for starting workers.
  unclaimed: usize,
  resuming: usize,
  helper_restoring: usize,
}

impl SeatTable {
  #[cfg(test)]
  pub(super) fn new(workers: usize, max_handoffs: usize) -> Self {
    Self {
      turns: TurnCoordinator::new(workers, max_handoffs),
      vacant: (0..workers).rev().collect(),
      helper_held: vec![false; workers],
      unclaimed: workers,
      resuming: 0,
      helper_restoring: 0,
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
      unclaimed: workers,
      resuming: 0,
      helper_restoring: 0,
    })
  }

  pub(super) fn capacities(&self) -> (usize, usize) {
    (self.vacant.capacity(), self.helper_held.capacity())
  }

  pub(super) fn claim(&mut self, seat: usize) -> DispatchTurn {
    let Some(position) = self.vacant.iter().position(|&vacant| vacant == seat) else {
      panic!("seat is already held");
    };
    // Startup seats are reserved for their original workers. A loan may
    // already be restoring while a later worker is still starting.
    assert!(self.turns.turns < self.turns.dispatchers);
    self.turns.turns += 1;
    self.vacant.swap_remove(position);
    self.unclaimed -= 1;
    DispatchTurn { seat }
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
    if self.unclaimed != 0 || self.resuming != 0 {
      return None;
    }
    let turn = self.turns.try_begin_turn()?;
    Some(self.assign(turn, true))
  }

  pub(super) fn yield_worker(&mut self, turn: DispatchTurn) {
    self.end_turn(turn);
    self.resuming += 1;
  }

  pub(super) fn try_resume_worker(&mut self) -> Option<DispatchTurn> {
    if self.unclaimed != 0 {
      return None;
    }
    let turn = self.turns.try_begin_turn()?;
    self.resuming -= 1;
    Some(self.assign(turn, false))
  }

  // A helper-origin loan can outlive the worker's loan. If its helper
  // replacement retired after the worker restored, only a worker can yield.
  // Count seats already given up, excluding startup reservations, so another
  // worker cannot yield for a restorer whose seat is already available.
  pub(super) fn worker_should_yield(&self) -> bool {
    self.helper_restoring > self.vacant.len() - self.unclaimed
      && self.helper_seats().next().is_none()
  }

  pub(super) fn end_turn(&mut self, turn: DispatchTurn) {
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
    self.helper_restoring += usize::from(loan.helper);
    self.turns.begin_restore(loan)
  }

  pub(super) fn try_restore(
    &mut self,
    ticket: RestoreTicket,
  ) -> Result<DispatchTurn, RestoreTicket> {
    if self.unclaimed != 0 {
      return Err(ticket);
    }
    let helper = ticket.helper;
    let turn = self.turns.try_restore(ticket)?;
    self.helper_restoring -= usize::from(helper);
    Ok(self.assign(turn, helper))
  }

  pub(super) fn try_activate_helper(&mut self) -> Option<HelperLease> {
    self.turns.try_activate_helper()
  }

  pub(super) fn retire_helper(&mut self, lease: HelperLease) -> Result<(), HelperLease> {
    self.turns.retire_helper(lease)
  }

  pub(super) const fn helper_should_yield(&self) -> bool {
    self.turns.restoring != 0 || self.resuming != 0 || self.helper_is_excess()
  }

  pub(super) fn helper_seats(&self) -> impl Iterator<Item = usize> + '_ {
    self
      .helper_held
      .iter()
      .enumerate()
      .filter_map(|(seat, &held)| held.then_some(seat))
  }

  #[cfg(test)]
  pub(super) fn counts(&self) -> (usize, usize, usize, usize) {
    self.check();
    self.turns.counts()
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
    assert!(self.unclaimed <= self.vacant.len());
    assert!(self.helper_restoring <= self.turns.restoring);
    assert!(self.resuming <= self.turns.dispatchers);
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

// A worker has already restored, leaving a helper-origin loan waiting while
// all seats are held by workers. The helper still owns its activation lease.
#[cfg(test)]
fn waiting_helper_restorer(
  workers: usize,
) -> (SeatTable, Vec<DispatchTurn>, RestoreTicket, HelperLease) {
  let mut seats = SeatTable::new(workers, 2);
  let mut turns: Vec<_> = (0..workers).map(|seat| seats.claim(seat)).collect();
  let worker_loan = seats.try_hand_off(turns.pop().unwrap()).unwrap();
  let lease = seats.try_activate_helper().unwrap();
  let helper = seats.try_begin_helper_turn().unwrap();
  let helper_loan = seats.try_hand_off(helper).unwrap();
  let ticket = seats.begin_restore(worker_loan);
  turns.push(seats.try_restore(ticket).unwrap());
  let ticket = seats.begin_restore(helper_loan);
  seats.check();
  (seats, turns, ticket, lease)
}

#[cfg(all(test, loom))]
mod seat_loom_tests {
  use loom::sync::{Arc, Mutex};
  use loom::thread;

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

  #[test]
  fn loom_helper_origin_restoration_yields_a_worker_and_returns_its_seat() {
    use super::SeatTable;
    bounded_model(|| {
      let mut seats = SeatTable::new(1, 2);
      let worker = seats.claim(0);
      let worker_loan = seats.try_hand_off(worker).unwrap();
      let helper_lease = seats.try_activate_helper().unwrap();
      let helper = seats.try_begin_helper_turn().unwrap();
      let helper_loan = seats.try_hand_off(helper).unwrap();
      let replacement = seats.try_activate_helper().unwrap();
      let replacement_turn = seats.try_begin_helper_turn().unwrap();
      seats.end_turn(replacement_turn);
      let ticket = seats.begin_restore(worker_loan);
      let worker = seats.try_restore(ticket).unwrap();
      seats.retire_helper(replacement).unwrap();
      let ticket = seats.begin_restore(helper_loan);
      assert!(seats.worker_should_yield());
      let state = Arc::new(Mutex::new(seats));
      let original = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          {
            let mut seats = lock(&state);
            seats.yield_worker(worker);
            seats.check();
          }
          loop {
            {
              let mut seats = lock(&state);
              if let Some(turn) = seats.try_resume_worker() {
                seats.check();
                seats.end_turn(turn);
                break;
              }
            }
            thread::yield_now();
          }
        })
      };
      let helper = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          let mut ticket = ticket;
          let turn = loop {
            {
              let mut seats = lock(&state);
              match seats.try_restore(ticket) {
                Ok(turn) => {
                  seats.check();
                  break turn;
                }
                Err(waiting) => ticket = waiting,
              }
            }
            thread::yield_now();
          };
          let mut seats = lock(&state);
          assert!(seats.helper_should_yield());
          seats.end_turn(turn);
          seats.retire_helper(helper_lease).unwrap();
          seats.check();
        })
      };
      original.join().unwrap();
      helper.join().unwrap();
      let seats = lock(&state);
      assert_eq!(seats.counts(), (0, 0, 0, 0));
      assert_eq!(seats.resuming, 0);
    });
  }

  fn one_restorer_yields_one_worker(workers: usize) {
    bounded_model(move || {
      let (seats, turns, ticket, lease) = super::waiting_helper_restorer(workers);
      let state = Arc::new(Mutex::new((seats, 0)));
      let workers: Vec<_> = turns
        .into_iter()
        .map(|turn| {
          let state = Arc::clone(&state);
          thread::spawn(move || {
            let mut state = lock(&state);
            if state.0.worker_should_yield() {
              state.0.yield_worker(turn);
              state.1 += 1;
              assert!(state.1 <= 1, "one restorer made multiple workers yield");
              state.0.check();
              None
            } else {
              Some(turn)
            }
          })
        })
        .collect();
      let restorer = {
        let state = Arc::clone(&state);
        thread::spawn(move || {
          let mut ticket = ticket;
          loop {
            {
              let mut state = lock(&state);
              match state.0.try_restore(ticket) {
                Ok(turn) => {
                  state.0.check();
                  break turn;
                }
                Err(waiting) => ticket = waiting,
              }
            }
            thread::yield_now();
          }
        })
      };
      let turns: Vec<_> = workers
        .into_iter()
        .filter_map(|worker| worker.join().unwrap())
        .collect();
      let helper = restorer.join().unwrap();
      let mut state = lock(&state);
      assert_eq!(state.1, 1);
      state.0.end_turn(helper);
      state.0.retire_helper(lease).unwrap();
      let resumed = state.0.try_resume_worker().unwrap();
      state.0.end_turn(resumed);
      for turn in turns {
        state.0.end_turn(turn);
      }
      state.0.check();
      assert_eq!(state.0.resuming, 0);
      assert_eq!(state.0.counts(), (0, 0, 0, 0));
    });
  }

  #[test]
  fn loom_one_helper_restorer_yields_at_most_one_of_two_workers() {
    one_restorer_yields_one_worker(2);
  }

  #[test]
  fn loom_one_helper_restorer_yields_at_most_one_of_three_workers() {
    one_restorer_yields_one_worker(3);
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
          state.0.end_turn(turn);
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
                state.0.end_turn(held);
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
                  state.0.end_turn(held);
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
          state.0.end_turn(second);
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
    seats.end_turn(helper);
    assert!(seats.try_begin_helper_turn().is_none());
    let first = seats.try_restore(ticket).unwrap();
    assert_eq!(first.seat(), 0);
    assert!(!seats.helper_held[first.seat()]);
    assert!(seats.helper_is_excess());
    seats.retire_helper(lease).unwrap();
    seats.check();
    assert!(seats.may_exit(true));
    assert!(!seats.may_exit(false));
    seats.end_turn(first);
    seats.end_turn(second);
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
    seats.end_turn(helper);
    let first = seats.try_restore(ticket).unwrap();
    seats.retire_helper(lease).unwrap();
    seats.end_turn(first);
    seats.end_turn(second);
    seats.check();
    assert!(seats.may_exit(true));
  }

  #[test]
  fn one_helper_restorer_needs_exactly_one_vacated_worker_seat() {
    for workers in [2, 3] {
      let (mut seats, turns, ticket, lease) = super::waiting_helper_restorer(workers);
      let mut remaining = Vec::new();
      let mut yielded = 0;
      for turn in turns {
        if seats.worker_should_yield() {
          seats.yield_worker(turn);
          yielded += 1;
        } else {
          remaining.push(turn);
        }
        seats.check();
      }
      assert_eq!(yielded, 1);
      assert!(!seats.worker_should_yield());
      let helper = seats.try_restore(ticket).unwrap();
      seats.end_turn(helper);
      seats.retire_helper(lease).unwrap();
      let worker = seats.try_resume_worker().unwrap();
      seats.end_turn(worker);
      for turn in remaining {
        seats.end_turn(turn);
      }
      seats.check();
      assert_eq!(seats.resuming, 0);
      assert_eq!(seats.counts(), (0, 0, 0, 0));
    }
  }

  #[test]
  fn an_existing_vacancy_already_covers_a_waiting_helper_restorer() {
    let (mut seats, mut turns, ticket, lease) = super::waiting_helper_restorer(3);
    let loan = seats.try_hand_off(turns.pop().unwrap()).unwrap();
    assert!(!seats.worker_should_yield());
    let helper = seats.try_restore(ticket).unwrap();
    seats.end_turn(helper);
    let ticket = seats.begin_restore(loan);
    let worker = seats.try_restore(ticket).unwrap();
    seats.retire_helper(lease).unwrap();
    seats.end_turn(worker);
    for turn in turns {
      seats.end_turn(turn);
    }
    seats.check();
  }

  #[test]
  #[should_panic(expected = "seat is already held")]
  fn an_occupied_seat_cannot_be_claimed_twice() {
    let mut seats = SeatTable::new(1, 0);
    let _turn = seats.claim(0);
    let _duplicate = seats.claim(0);
  }
}
