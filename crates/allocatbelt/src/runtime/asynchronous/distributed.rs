//! Distributed dispatch with seat adoption for bounded handoffs. Admission precedes slot, then scope
//! locks. Lane, overflow and seat locks stand alone. User code and wakes run
//! after releasing these locks; a detached chain belongs only to its mover.

#![forbid(unsafe_code)]

use super::super::handoff_protocol::SeatTable;
use super::super::lane::{LaneQueue, ParkedMask, QueueLink, VictimOrder, choose_lane};
use super::*;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::AtomicBool;

#[cfg(debug_assertions)]
thread_local! {
  static LOCK_LEVEL: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

fn lock_level() -> u8 {
  #[cfg(debug_assertions)]
  {
    LOCK_LEVEL.get()
  }
  #[cfg(not(debug_assertions))]
  {
    0
  }
}
fn set_lock_level(level: u8) {
  #[cfg(debug_assertions)]
  LOCK_LEVEL.set(level);
  #[cfg(not(debug_assertions))]
  let _ = level;
}

pub(super) fn assert_admission_order() {
  debug_assert_eq!(lock_level(), 0, "admission after a dispatch lock");
}

struct Guard<'a, T> {
  inner: Option<MutexGuard<'a, T>>,
  previous: u8,
}

impl<T> Deref for Guard<'_, T> {
  type Target = T;
  fn deref(&self) -> &T {
    match &self.inner {
      Some(guard) => guard,
      None => unreachable!("guard in wait"),
    }
  }
}
impl<T> DerefMut for Guard<'_, T> {
  fn deref_mut(&mut self) -> &mut T {
    match &mut self.inner {
      Some(guard) => guard,
      None => unreachable!("guard in wait"),
    }
  }
}
impl<T> Drop for Guard<'_, T> {
  fn drop(&mut self) {
    drop(self.inner.take());
    set_lock_level(self.previous);
  }
}

fn lock<T>(mutex: &Mutex<T>, level: u8) -> Guard<'_, T> {
  let previous = lock_level();
  debug_assert!(
    match level {
      1 => previous == 0,
      2 => previous <= 1,
      3 => previous == 0 || previous == 2,
      _ => previous == 0,
    },
    "invalid dispatch lock nesting {previous} -> {level}"
  );
  let inner = mutex.lock().unwrap_or_else(PoisonError::into_inner);
  set_lock_level(level);
  Guard {
    inner: Some(inner),
    previous,
  }
}

#[repr(align(64))]
struct SlotCell {
  word: PollWord,
  state: Mutex<SlotState>,
}
struct SlotState {
  protocol: PollProtocol,
  task: Option<Arc<dyn ErasedTask>>,
  scope: Option<(ScopeRef, Arc<ScopeCell>)>,
  reserved_permit: bool,
}
#[repr(align(128))]
struct Lane {
  queue: Mutex<LaneQueue>,
  cv: Condvar,
}

struct SeatGuard<'a> {
  distributed: &'a Distributed,
  shared: &'a Shared,
  turn: Option<DispatchTurn>,
}
impl Drop for SeatGuard<'_> {
  fn drop(&mut self) {
    if let Some(turn) = self.turn.take() {
      self.distributed.abandon_turn(self.shared, turn);
    }
  }
}
impl SeatGuard<'_> {
  fn seat(&self) -> usize {
    match &self.turn {
      Some(turn) => turn.seat(),
      None => unreachable!("seat is in TLS"),
    }
  }
  fn take(&mut self) -> DispatchTurn {
    match self.turn.take() {
      Some(turn) => turn,
      None => unreachable!("seat is in TLS"),
    }
  }
}

pub(super) struct Distributed {
  slots: Vec<SlotCell>,
  links: Vec<QueueLink>,
  lanes: Vec<Lane>,
  parked: ParkedMask,
  next_lane: AtomicUsize,
  overflow: Mutex<LaneQueue>,
  seats: Mutex<SeatTable>,
  seat_cv: Condvar,
  helper_yield: AtomicBool,
  worker_yield: AtomicBool,
  closed_empty: AtomicBool,
  #[cfg(all(test, not(loom)))]
  slot_locks: AtomicUsize,
  #[cfg(all(test, not(loom)))]
  seat_locks: AtomicUsize,
  #[cfg(all(test, not(loom)))]
  scope_locks: AtomicUsize,
  #[cfg(all(test, not(loom)))]
  lane_locks: AtomicUsize,
  #[cfg(all(test, not(loom)))]
  steals: AtomicUsize,
  #[cfg(all(test, not(loom)))]
  round_robin: AtomicBool,
  #[cfg(all(test, not(loom)))]
  unwind_seat: AtomicUsize,
}

fn table<T>(len: usize, mut new: impl FnMut() -> T) -> Result<Vec<T>, AsyncError> {
  let mut result = Vec::new();
  result
    .try_reserve_exact(len)
    .map_err(|_| AsyncError::OutOfMemory)?;
  result.resize_with(len, &mut new);
  Ok(result)
}

fn control_sizes(
  slots: usize,
  links: usize,
  lanes: usize,
  words: usize,
  vacant: usize,
  helpers: usize,
) -> Result<usize, AsyncError> {
  let mut total = 0usize;
  for bytes in [
    payload_bytes::<SlotCell>(slots),
    payload_bytes::<QueueLink>(links),
    payload_bytes::<Lane>(lanes),
    payload_bytes::<AtomicU64>(words),
    payload_bytes::<usize>(vacant),
    payload_bytes::<bool>(helpers),
  ] {
    total = total
      .checked_add(bytes.map_err(AsyncError::ResourceDomain)?)
      .ok_or(AsyncError::ResourceDomain(DomainError::Invalid))?;
  }
  Ok(total)
}

impl Distributed {
  pub(super) fn requested_control(config: AsyncConfig) -> Result<usize, AsyncError> {
    control_sizes(
      config.max_outstanding,
      config.max_outstanding,
      config.workers,
      config.workers.div_ceil(64) * 2,
      config.workers,
      config.workers,
    )
  }

  pub(super) fn actual_control(&self) -> Result<usize, AsyncError> {
    let (vacant, helpers) = self.seats().capacities();
    control_sizes(
      self.slots.capacity(),
      self.links.capacity(),
      self.lanes.capacity(),
      self.parked.capacity(),
      vacant,
      helpers,
    )
  }

  pub(super) fn new(config: AsyncConfig, max_handoffs: usize) -> Result<Self, AsyncError> {
    Ok(Self {
      slots: table(config.max_outstanding, || SlotCell {
        word: PollWord::new(),
        state: Mutex::new(SlotState {
          protocol: PollProtocol::new(),
          task: None,
          scope: None,
          reserved_permit: false,
        }),
      })?,
      links: table(config.max_outstanding, QueueLink::new)?,
      lanes: table(config.workers, || Lane {
        queue: Mutex::new(LaneQueue::new()),
        cv: Condvar::new(),
      })?,
      parked: ParkedMask::try_new(config.workers).map_err(|_| AsyncError::OutOfMemory)?,
      next_lane: AtomicUsize::new(0),
      overflow: Mutex::new(LaneQueue::new()),
      seats: Mutex::new(
        SeatTable::try_new(config.workers, max_handoffs).map_err(|_| AsyncError::OutOfMemory)?,
      ),
      seat_cv: Condvar::new(),
      helper_yield: AtomicBool::new(false),
      worker_yield: AtomicBool::new(false),
      closed_empty: AtomicBool::new(false),
      #[cfg(all(test, not(loom)))]
      slot_locks: AtomicUsize::new(0),
      #[cfg(all(test, not(loom)))]
      seat_locks: AtomicUsize::new(0),
      #[cfg(all(test, not(loom)))]
      scope_locks: AtomicUsize::new(0),
      #[cfg(all(test, not(loom)))]
      lane_locks: AtomicUsize::new(0),
      #[cfg(all(test, not(loom)))]
      steals: AtomicUsize::new(0),
      #[cfg(all(test, not(loom)))]
      round_robin: AtomicBool::new(super::super::lane::ROUND_ROBIN_PLACEMENT),
      #[cfg(all(test, not(loom)))]
      unwind_seat: AtomicUsize::new(usize::MAX),
    })
  }

  pub(super) fn slots_len(&self) -> usize {
    self.slots.len()
  }

  fn admission<'a>(&self, shared: &'a Shared) -> Guard<'a, State> {
    let inner = shared.lock();
    let previous = lock_level();
    set_lock_level(1);
    Guard {
      inner: Some(inner),
      previous,
    }
  }

  fn seats(&self) -> Guard<'_, SeatTable> {
    #[cfg(all(test, not(loom)))]
    self.seat_locks.fetch_add(1, Ordering::Relaxed);
    lock(&self.seats, 4)
  }

  fn slot(&self, index: usize) -> Guard<'_, SlotState> {
    #[cfg(all(test, not(loom)))]
    self.slot_locks.fetch_add(1, Ordering::Relaxed);
    lock(&self.slots[index].state, 2)
  }

  fn scope<'a>(&self, cell: &'a ScopeCell) -> Guard<'a, super::super::protocol::ScopeDispatch> {
    #[cfg(all(test, not(loom)))]
    self.scope_locks.fetch_add(1, Ordering::Relaxed);
    lock(&cell.dispatch, 3)
  }

  fn lane(&self, seat: usize) -> Guard<'_, LaneQueue> {
    #[cfg(all(test, not(loom)))]
    self.lane_locks.fetch_add(1, Ordering::Relaxed);
    lock(&self.lanes[seat].queue, 4)
  }

  fn publish_depth(&self, shared: &Shared, seat: usize, queue: &LaneQueue) {
    shared.metrics.inner().lane_depth[seat]
      .0
      .store(queue.len(), Ordering::SeqCst);
  }

  fn push_ready(&self, shared: &Shared, index: usize) {
    let next = self.next_lane.fetch_add(1, Ordering::Relaxed);
    #[cfg(all(test, not(loom)))]
    let round_robin = self.round_robin.load(Ordering::Relaxed);
    #[cfg(any(not(test), loom))]
    let round_robin = super::super::lane::ROUND_ROBIN_PLACEMENT;
    let seat = if round_robin {
      super::super::lane::choose_lane_round_robin(next, &self.parked)
    } else {
      choose_lane(next, &self.parked)
    };
    let (notify, remains) = {
      let mut queue = self.lane(seat);
      // Serialize with abort's lane scan and seat retirement. A publisher or
      // quota transfer that was in flight when abort ran must use overflow.
      if self.parked.is_dead(seat) || self.links[index].cleanup.load(Ordering::SeqCst) {
        drop(queue);
        self.push_cleanup(shared, index);
        return;
      }
      let notify = queue.push(&self.links, index);
      self.publish_depth(shared, seat, &queue);
      // A single entry on a busy lane is stealable too. A sleeping owner
      // already receives the notification; otherwise kick a parked searcher.
      (notify, queue.len() >= 2 || !notify)
    };
    if notify {
      self.lanes[seat].cv.notify_one();
    }
    if remains {
      self.wake_one_parked();
    }
  }

  fn push_cleanup(&self, shared: &Shared, index: usize) {
    {
      let mut queue = lock(&self.overflow, 4);
      queue.push(&self.links, index);
      shared
        .metrics
        .inner()
        .overflow_depth
        .store(queue.len(), Ordering::SeqCst);
    }
    self.wake_one_parked();
  }

  fn kick(&self, seat: usize) {
    let notify = self.lane(seat).request_recheck();
    if notify {
      self.lanes[seat].cv.notify_one();
    }
  }
  fn kick_all(&self) {
    for seat in 0..self.lanes.len() {
      self.kick(seat);
    }
  }
  fn wake_one_parked(&self) {
    if let Some(seat) = self
      .parked
      .claim_any(self.next_lane.load(Ordering::Relaxed))
    {
      self.kick(seat);
    }
  }

  pub(super) fn spawn<F>(
    &self,
    shared: &Arc<Shared>,
    scope: ScopeRef,
    future: F,
  ) -> Result<AsyncJob<F::Output>, AsyncSpawnError<F>>
  where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
  {
    let scope_cell = {
      let state = self.admission(shared);
      if state.closed {
        return Err(AsyncSpawnError::new(AsyncError::Closed, future));
      }
      let Some(scope_cell) = get_scope(&state, scope).cloned() else {
        return Err(AsyncSpawnError::new(AsyncError::Closed, future));
      };
      if scope_cell.protocol.is_closed() {
        return Err(AsyncSpawnError::new(AsyncError::Closed, future));
      }
      if state.free_tasks.peek().is_none() {
        return Err(AsyncSpawnError::new(AsyncError::Full, future));
      }
      scope_cell
    };

    let tenant = scope_cell.tenant.as_ref();
    if let Some(tenant) = tenant
      && let Err(error) = tenant.validate_cpu_execution()
    {
      return Err(AsyncSpawnError::new(
        AsyncError::ResourceDomain(error),
        future,
      ));
    }
    let mut domain = match Task::<F>::reserve_domain_admission(tenant) {
      Ok(domain) => domain,
      Err(error) => {
        return Err(AsyncSpawnError::new(
          AsyncError::ResourceDomain(error),
          future,
        ));
      }
    };
    if tenant.is_some() {
      let waiter = match scope_cell
        .task_waiters
        .as_ref()
        .ok_or(DomainError::WaitersFull)
        .and_then(DomainWaitPool::try_lease)
      {
        Ok(waiter) => waiter,
        Err(error) => {
          drop(domain);
          return Err(AsyncSpawnError::new(
            AsyncError::ResourceDomain(error),
            future,
          ));
        }
      };
      domain.waiter = Some(waiter);
    }
    let Some(task_id) = identity::allocate() else {
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::TaskIdExhausted, future));
    };
    #[cfg(all(test, not(loom)))]
    // Resource reservations are complete, and no scheduler lock is held.
    shared.before_spawn_admission_for_test();
    let mut state = self.admission(shared);
    if state.closed {
      drop(state);
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::Closed, future));
    }
    let Some(current_scope) = get_scope(&state, scope) else {
      drop(state);
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::Closed, future));
    };
    if current_scope.protocol.is_closed() {
      drop(state);
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::Closed, future));
    }
    if !Arc::ptr_eq(current_scope, &scope_cell) {
      drop(state);
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::Full, future));
    }
    let Some(Reverse(index)) = state.free_tasks.peek().copied() else {
      drop(state);
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::Full, future));
    };
    let mut slot = self.slot(index);
    let Some(generation) = (slot.task.is_none() && !slot.protocol.admitted())
      .then(|| slot.protocol.next_generation())
      .flatten()
    else {
      drop(slot);
      drop(state);
      drop(domain);
      return Err(AsyncSpawnError::new(AsyncError::Full, future));
    };
    let popped = state.free_tasks.pop();
    debug_assert_eq!(popped, Some(Reverse(index)));
    let task_ref = TaskRef { index, generation };
    let (task, job) = Task::create(
      future,
      task_id,
      scope_cell.resources.clone(),
      domain,
      Arc::downgrade(shared),
      task_ref,
    );
    self.links[index].cleanup.store(false, Ordering::SeqCst);
    slot.protocol.admit(generation);
    slot.scope = Some((scope, Arc::clone(&scope_cell)));
    slot.task = Some(task);
    let inserted = slot.protocol.queue();
    debug_assert!(inserted);
    scope_cell.protocol.add_task();
    shared
      .metrics
      .inner()
      .alive_tasks
      .fetch_add(1, Ordering::Relaxed);
    state.admitted += 1;
    drop(slot);
    drop(state);
    self.push_ready(shared, index);
    Ok(job)
  }

  pub(super) fn wake(&self, shared: &Shared, task_ref: TaskRef) {
    let Some(cell) = self.slots.get(task_ref.index) else {
      return;
    };
    if cell.word.notify_running(task_ref.generation) {
      return;
    }
    let inserted = {
      let mut slot = self.slot(task_ref.index);
      if !slot.protocol.matches(task_ref.generation) || slot.task.is_none() {
        return;
      }
      slot.protocol.wake()
    };
    if inserted {
      self.push_ready(shared, task_ref.index);
    }
  }

  pub(super) fn abort(&self, shared: &Shared, task_ref: TaskRef) {
    self.abort_slot(shared, task_ref.index, Some(task_ref.generation), None);
  }

  fn abort_slot(
    &self,
    shared: &Shared,
    index: usize,
    generation: Option<u64>,
    scope: Option<ScopeRef>,
  ) {
    if index >= self.slots.len() {
      return;
    }
    let requeue = {
      let mut slot = self.slot(index);
      if slot.task.is_none()
        || generation.is_some_and(|g| !slot.protocol.matches(g))
        || scope.is_some_and(|s| slot.scope.as_ref().is_none_or(|(r, _)| *r != s))
      {
        return;
      }
      self.links[index].cleanup.store(true, Ordering::SeqCst);
      let inserted = slot.protocol.abort();
      let unlinked = if !inserted
        && slot.protocol.aborting_queued()
        && let Some((_, cell)) = &slot.scope
        && cell.binding
      {
        self.scope(cell).unlink_blocked(&self.links, index)
      } else {
        false
      };
      if unlinked {
        shared
          .metrics
          .inner()
          .blocked_depth
          .fetch_sub(1, Ordering::Relaxed);
      }
      inserted || unlinked
    };
    if requeue {
      self.push_cleanup(shared, index);
    } else {
      // A ready entry may already be on a busy dispatcher's lane. Move only
      // this cancellation entry; never acquire ordinary work via this scan.
      for seat in 0..self.lanes.len() {
        let removed = {
          let mut queue = self.lane(seat);
          let removed =
            self.links[index].cleanup.load(Ordering::SeqCst) && queue.remove(&self.links, index);
          self.publish_depth(shared, seat, &queue);
          removed
        };
        if removed {
          self.push_cleanup(shared, index);
          break;
        }
      }
    }
  }

  pub(super) fn close(&self, shared: &Shared, cancel: bool) {
    {
      let mut state = self.admission(shared);
      state.closed = true;
      self
        .closed_empty
        .store(state.admitted == 0, Ordering::Release);
    }
    if cancel {
      for index in 0..self.slots.len() {
        self.abort_slot(shared, index, None, None);
      }
      let state = self.admission(shared);
      for scope in &state.scopes {
        if let Some(cell) = &scope.scope {
          cell.protocol.close();
        }
      }
    }
    self.kick_all();
    self.notify_seats();
  }

  pub(super) fn request_scope_close(&self, shared: &Shared, scope: ScopeRef) {
    let cell = {
      let state = self.admission(shared);
      let cell = get_scope(&state, scope).cloned();
      if let Some(cell) = &cell {
        cell.protocol.close();
      }
      cell
    };
    for index in 0..self.slots.len() {
      self.abort_slot(shared, index, None, Some(scope));
    }
    if let Some(cell) = cell {
      if cell.protocol.can_reclaim() {
        debug_assert_eq!(self.scope(&cell).blocked_len(), 0);
      }
      shared.release_scope(scope, &cell);
    }
  }

  pub(super) fn release_permit(&self, shared: &Shared, cell: &ScopeCell) {
    let transfer = {
      let mut dispatch = self.scope(cell);
      let transfer = dispatch.release_or_transfer(&self.links);
      if transfer.is_some() {
        shared
          .metrics
          .inner()
          .blocked_depth
          .fetch_sub(1, Ordering::Relaxed);
      }
      transfer
    };
    if let Some(index) = transfer {
      // The removed entry is in hand; abort cannot unlink or dispatch it.
      self.slot(index).reserved_permit = true;
      self.push_ready(shared, index);
    }
  }

  fn dispatch_decision(&self, shared: &Arc<Shared>, index: usize) -> Option<Selected> {
    let mut slot = self.slot(index);
    let task = Arc::clone(slot.task.as_ref()?);
    let (_, cell) = slot.scope.as_ref()?;
    let cell = Arc::clone(cell);
    let task_ref = TaskRef {
      index,
      generation: slot.protocol.generation(),
    };
    let reserved = std::mem::take(&mut slot.reserved_permit);
    if slot.protocol.aborting_queued() {
      let began = slot.protocol.begin_poll();
      debug_assert_eq!(began, Some(true));
      drop(slot);
      if reserved {
        self.release_permit(shared, &cell);
      }
      return Some(Selected::Cancel(task_ref, task));
    }
    let release = if cell.binding {
      if !reserved {
        let mut dispatch = self.scope(&cell);
        if !dispatch.try_acquire() {
          dispatch.block(&self.links, index);
          shared
            .metrics
            .inner()
            .blocked_depth
            .fetch_add(1, Ordering::Relaxed);
          return None;
        }
      }
      PermitRelease::Scope {
        shared: Arc::downgrade(shared),
        cell,
      }
    } else if cell.reference.is_some() {
      cell.active_stat.fetch_add(1, Ordering::Relaxed);
      PermitRelease::Counted { cell }
    } else {
      PermitRelease::Free
    };
    let began = slot.protocol.begin_poll();
    debug_assert_eq!(began, Some(false));
    self.slots[index].word.begin(task_ref.generation);
    Some(Selected::Poll(
      task_ref,
      task,
      PollPermit {
        release,
        cpu_ticket: None,
      },
    ))
  }

  fn finish_poll(&self, shared: &Arc<Shared>, task_ref: TaskRef, ready: bool) {
    let mut slot = self.slot(task_ref.index);
    if !slot.protocol.matches(task_ref.generation) || slot.task.is_none() {
      return;
    }
    if self.slots[task_ref.index].word.finish() {
      let inserted = slot.protocol.wake();
      debug_assert!(!inserted);
    }
    match slot.protocol.finish_poll(ready, false) {
      PollFinish::Complete => {
        let task = slot.task.take();
        let scope = slot.scope.take();
        let reusable = slot.protocol.next_generation().is_some();
        drop(slot);
        self.complete(shared, task_ref.index, reusable, task, scope);
      }
      PollFinish::CancelCleanup => {
        let task = slot.task.as_ref().map(Arc::clone);
        drop(slot);
        if let Some(task) = task {
          task.cancel();
          self.finish_cancel(shared, task_ref, task);
        }
      }
      PollFinish::Requeue => {
        drop(slot);
        self.push_ready(shared, task_ref.index);
      }
      PollFinish::Idle | PollFinish::Stale => {}
    }
  }

  fn finish_cancel(&self, shared: &Arc<Shared>, task_ref: TaskRef, task: Arc<dyn ErasedTask>) {
    let mut slot = self.slot(task_ref.index);
    if !slot.protocol.matches(task_ref.generation) || slot.task.is_none() {
      return;
    }
    let slot_task = slot.task.take();
    let scope = slot.scope.take();
    slot.protocol.finish_cancel();
    let reusable = slot.protocol.next_generation().is_some();
    drop(slot);
    self.complete(shared, task_ref.index, reusable, slot_task, scope);
    drop(task);
  }

  fn complete(
    &self,
    shared: &Shared,
    index: usize,
    reusable: bool,
    task: Option<Arc<dyn ErasedTask>>,
    scope: Option<(ScopeRef, Arc<ScopeCell>)>,
  ) {
    let empty_after_close = {
      let mut state = self.admission(shared);
      if reusable {
        state.free_tasks.push(Reverse(index));
      }
      state.admitted -= 1;
      shared
        .metrics
        .inner()
        .alive_tasks
        .fetch_sub(1, Ordering::Relaxed);
      state.closed && state.admitted == 0
    };
    if let Some(task) = task {
      task.publish();
    }
    if let Some((_, cell)) = scope {
      cell.completed();
    }
    if empty_after_close {
      self.closed_empty.store(true, Ordering::Release);
      self.notify_seats();
      self.kick_all();
    }
  }

  fn try_steal(&self, shared: &Shared, seat: usize, random: &mut u64) -> Option<usize> {
    for victim in VictimOrder::new(random, self.lanes.len()).victims(seat) {
      if shared.metrics.inner().lane_depth[victim]
        .0
        .load(Ordering::SeqCst)
        == 0
      {
        continue;
      }
      let (chain, remains) = {
        let mut queue = self.lane(victim);
        let before = queue.len();
        let Some(chain) = queue.steal_front(&self.links) else {
          continue;
        };
        debug_assert!(before == 1 || queue.len() >= 1);
        debug_assert!(before - queue.len() <= (before / 2).max(1));
        debug_assert!(before - queue.len() <= super::super::lane::STEAL_MAX);
        self.publish_depth(shared, victim, &queue);
        (chain, queue.len() != 0)
      };
      if remains {
        self.wake_one_parked();
      }
      let (first, remains, cleanup) = {
        let mut queue = self.lane(seat);
        queue.append_chain(&self.links, chain);
        let cleanup = queue.extract_cleanup(&self.links);
        let first = queue.pop(&self.links);
        self.publish_depth(shared, seat, &queue);
        (first, queue.len() != 0, cleanup)
      };
      if let Some(cleanup) = cleanup {
        let count = {
          let mut queue = lock(&self.overflow, 4);
          let before = queue.len();
          queue.append_chain(&self.links, cleanup);
          shared
            .metrics
            .inner()
            .overflow_depth
            .store(queue.len(), Ordering::SeqCst);
          queue.len() - before
        };
        for _ in 0..count {
          self.wake_one_parked();
        }
      }
      #[cfg(all(test, not(loom)))]
      self.steals.fetch_add(1, Ordering::Relaxed);
      if remains {
        self.wake_one_parked();
      }
      return first;
    }
    None
  }

  fn search(&self, shared: &Shared, seat: usize, random: &mut u64) -> Search {
    let (first, recheck, remains) = {
      let mut queue = self.lane(seat);
      let first = queue.pop(&self.links);
      let recheck = first.is_none() && queue.take_recheck();
      self.publish_depth(shared, seat, &queue);
      (first, recheck, queue.len() != 0)
    };
    if let Some(index) = first {
      if remains {
        self.wake_one_parked();
      }
      return Search::Got(index);
    }
    if recheck {
      return Search::Recheck;
    }
    if let Some(index) = self.try_steal(shared, seat, random) {
      return Search::Got(index);
    }
    if shared.metrics.inner().overflow_depth.load(Ordering::SeqCst) != 0 {
      let mut queue = lock(&self.overflow, 4);
      let first = queue.pop(&self.links);
      shared
        .metrics
        .inner()
        .overflow_depth
        .store(queue.len(), Ordering::SeqCst);
      if let Some(index) = first {
        return Search::Got(index);
      }
    }
    Search::Empty
  }

  fn search_or_park(
    &self,
    shared: &Shared,
    seat: usize,
    random: &mut u64,
    context: AsyncThreadContext,
  ) -> Search {
    loop {
      let should_yield =
        if context.role == super::super::thread_options::AsyncThreadRole::HandoffHelper {
          self.helper_yield.load(Ordering::Acquire)
        } else {
          self.worker_yield.load(Ordering::Acquire) && self.seats().worker_should_yield()
        };
      if should_yield {
        return Search::Recheck;
      }
      match self.search(shared, seat, random) {
        Search::Empty => {}
        found => return found,
      }
      cache::flush();
      shared.thread_park_attempted(context);
      if !super::super::lane::search_or_park(
        seat,
        &self.parked,
        shared
          .metrics
          .inner()
          .lane_depth
          .iter()
          .enumerate()
          .map(|(index, len)| (index, len.0.load(Ordering::SeqCst))),
        || shared.metrics.inner().overflow_depth.load(Ordering::SeqCst),
      ) {
        shared.thread_unpark_callback(context);
        cache::set_shard(context.physical_index);
        continue;
      }
      let mut queue = self.lane(seat);
      if queue.prepare_sleep() {
        shared.thread_parked(context);
        let guard = match queue.inner.take() {
          Some(guard) => guard,
          None => unreachable!(),
        };
        queue.inner = Some(
          self.lanes[seat]
            .cv
            .wait(guard)
            .unwrap_or_else(PoisonError::into_inner),
        );
        queue.finish_sleep();
        drop(queue);
        self.parked.claim(seat);
        shared.thread_unparked(context);
      } else {
        drop(queue);
        self.parked.claim(seat);
        shared.thread_unpark_callback(context);
      }
      cache::set_shard(context.physical_index);
    }
  }

  pub(super) fn abandon_turn(&self, shared: &Shared, turn: DispatchTurn) {
    let seat = turn.seat();
    {
      let _queue = self.lane(seat);
      self.parked.mark_dead(seat);
    }
    loop {
      let first = {
        let mut queue = self.lane(seat);
        let first = queue.pop(&self.links);
        self.publish_depth(shared, seat, &queue);
        first
      };
      let Some(index) = first else {
        break;
      };
      let mut queue = lock(&self.overflow, 4);
      queue.push(&self.links, index);
      shared
        .metrics
        .inner()
        .overflow_depth
        .store(queue.len(), Ordering::SeqCst);
    }
    // Keep the seat held until its lane has drained: a helper or restorer
    // must not adopt it while abandonment is moving entries to overflow.
    {
      let mut seats = self.seats();
      seats.end_turn(turn);
      self.update_yield(&seats);
      self.seat_cv.notify_all();
    }
    self.kick_all();
  }

  fn adopt(&self, turn: &DispatchTurn) {
    if self.parked.is_dead(turn.seat()) {
      let _queue = self.lane(turn.seat());
      self.parked.claim(turn.seat());
      self.parked.revive(turn.seat());
    }
  }

  fn update_yield(&self, seats: &SeatTable) {
    self
      .helper_yield
      .store(seats.helper_should_yield(), Ordering::Release);
    self
      .worker_yield
      .store(seats.worker_should_yield(), Ordering::Release);
  }

  fn notify_seats(&self) {
    let _seats = self.seats();
    self.seat_cv.notify_all();
  }

  #[cfg(all(test, not(loom)))]
  pub(super) fn turn_counts(&self) -> (usize, usize, usize, usize) {
    self.seats().counts()
  }

  pub(super) fn hand_off(&self, turn: DispatchTurn) -> Result<HandoffLoan, DispatchTurn> {
    let mut seats = self.seats();
    let loan = seats.try_hand_off(turn)?;
    self.update_yield(&seats);
    self.seat_cv.notify_all();
    Ok(loan)
  }

  /// Wait on the seat predicate only after hooks ran outside every lock.
  fn wait_seat(
    &self,
    shared: &Shared,
    context: AsyncThreadContext,
    mut seats: Guard<'_, SeatTable>,
  ) {
    shared.thread_parked(context);
    let guard = seats.inner.take().unwrap_or_else(|| unreachable!());
    seats.inner = Some(
      self
        .seat_cv
        .wait(guard)
        .unwrap_or_else(PoisonError::into_inner),
    );
    drop(seats);
    shared.thread_unparked(context);
    cache::set_shard(context.physical_index);
  }

  pub(super) fn restore(
    &self,
    shared: &Shared,
    loan: HandoffLoan,
    context: AsyncThreadContext,
  ) -> DispatchTurn {
    let mut seats = self.seats();
    let mut ticket = seats.begin_restore(loan);
    self.update_yield(&seats);
    let mut prepared = false;
    let mut flushed = false;
    let mut kicked = false;
    loop {
      match seats.try_restore(ticket) {
        Ok(turn) => {
          self.update_yield(&seats);
          self.seat_cv.notify_all();
          drop(seats);
          if prepared {
            shared.thread_unpark_callback(context);
            cache::set_shard(context.physical_index);
          }
          self.adopt(&turn);
          // Retire excess helpers, including those parked on their lanes.
          // Also release closed, empty workers after the final restoration.
          if self.helper_yield.load(Ordering::Acquire) || self.closed_empty.load(Ordering::Acquire)
          {
            self.kick_all();
          }
          return turn;
        }
        Err(waiting) => ticket = waiting,
      }
      if !kicked {
        // A helper-origin loan can outlive its worker's loan, so the kick
        // includes worker lanes for the between-poll fallback. Leaf locks.
        drop(seats);
        self.kick_all();
        seats = self.seats();
        kicked = true;
        continue;
      }
      if prepared {
        self.wait_seat(shared, context, seats);
        prepared = false;
      } else {
        drop(seats);
        if !flushed {
          cache::flush();
          flushed = true;
        }
        shared.thread_park_attempted(context);
        prepared = true;
      }
      seats = self.seats();
    }
  }

  /// Activated helpers acquire a vacant seat and use the worker search loop.
  pub(super) fn helper(&self, shared: &Arc<Shared>, context: AsyncThreadContext) {
    let mut lease = None;
    let mut prepared = false;
    loop {
      let mut seats = self.seats();
      if let Some(active) = lease.take() {
        lease = seats.retire_helper(active).err();
        self.update_yield(&seats);
      }
      if seats.may_exit(self.closed_empty.load(Ordering::Acquire)) && lease.is_none() {
        drop(seats);
        if prepared {
          shared.thread_unpark_callback(context);
        }
        return;
      }
      if lease.is_none() {
        lease = seats.try_activate_helper();
        self.update_yield(&seats);
      }
      if lease.is_some()
        && let Some(turn) = seats.try_begin_helper_turn()
      {
        self.update_yield(&seats);
        drop(seats);
        if prepared {
          shared.thread_unpark_callback(context);
        }
        cache::set_shard(context.physical_index);
        self.adopt(&turn);
        self.serve(shared, context, turn, true);
        prepared = false;
        continue;
      }
      if prepared {
        self.wait_seat(shared, context, seats);
        prepared = false;
      } else {
        drop(seats);
        cache::flush();
        shared.thread_park_attempted(context);
        prepared = true;
      }
    }
  }

  fn resume_worker(&self, shared: &Shared, context: AsyncThreadContext) -> DispatchTurn {
    let mut prepared = false;
    loop {
      let mut seats = self.seats();
      if let Some(turn) = seats.try_resume_worker() {
        self.update_yield(&seats);
        self.seat_cv.notify_all();
        drop(seats);
        if prepared {
          shared.thread_unpark_callback(context);
        }
        cache::set_shard(context.physical_index);
        self.adopt(&turn);
        return turn;
      }
      if prepared {
        self.wait_seat(shared, context, seats);
        prepared = false;
      } else {
        drop(seats);
        cache::flush();
        shared.thread_park_attempted(context);
        prepared = true;
      }
    }
  }

  pub(super) fn run_seat(&self, shared: &Arc<Shared>, context: AsyncThreadContext) {
    let turn = {
      let mut seats = self.seats();
      let turn = seats.claim(context.index);
      self.update_yield(&seats);
      self.seat_cv.notify_all();
      turn
    };
    self.serve(shared, context, turn, false);
  }

  fn serve(
    &self,
    shared: &Arc<Shared>,
    context: AsyncThreadContext,
    turn: DispatchTurn,
    helper: bool,
  ) {
    let mut seat = SeatGuard {
      distributed: self,
      shared,
      turn: Some(turn),
    };
    #[cfg(all(test, not(loom)))]
    assert_ne!(
      self.unwind_seat.load(Ordering::Relaxed),
      seat.seat(),
      "injected dispatcher unwind"
    );
    let mut random = context.physical_index as u64 + 1;
    loop {
      let yield_pending = if helper {
        self.helper_yield.load(Ordering::Acquire)
      } else {
        self.worker_yield.load(Ordering::Acquire)
      };
      if yield_pending {
        let mut seats = self.seats();
        if helper && seats.helper_should_yield() {
          seats.end_turn(seat.take());
          self.update_yield(&seats);
          self.seat_cv.notify_all();
          return;
        }
        if !helper && seats.worker_should_yield() {
          seats.yield_worker(seat.take());
          self.update_yield(&seats);
          self.seat_cv.notify_all();
          drop(seats);
          seat.turn = Some(self.resume_worker(shared, context));
          continue;
        }
      }
      let index = match self.search_or_park(shared, seat.seat(), &mut random, context) {
        Search::Got(index) => index,
        Search::Recheck => {
          let empty = {
            let state = self.admission(shared);
            state.closed && state.admitted == 0
          };
          let mut seats = self.seats();
          if seats.may_exit(empty) {
            seats.end_turn(seat.take());
            self.update_yield(&seats);
            self.seat_cv.notify_all();
            return;
          }
          continue;
        }
        Search::Empty => unreachable!(),
      };
      let Some(selected) = self.dispatch_decision(shared, index) else {
        continue;
      };
      handoff::enter_turn(seat.take());
      match selected {
        Selected::Cancel(task_ref, task) => {
          task.cancel();
          self.finish_cancel(shared, task_ref, task);
        }
        Selected::Poll(task_ref, task, permit) => {
          super::super::entry::reset_budget();
          match task.task_waker(&mut || task_waker(shared, task_ref, task.tenant_domain())) {
            Err(error) => {
              drop(permit);
              task.fail_resource(error);
              self.finish_poll(shared, task_ref, true);
            }
            Ok(waker) => {
              let mut context = Context::from_waker(&waker);
              let (result, mut permit) = match task.acquire_cpu(&waker) {
                DomainCpuAdmission::Unbounded => task.poll(&mut context, permit),
                DomainCpuAdmission::Acquired(ticket) => {
                  let mut permit = permit;
                  permit.set_cpu_ticket(ticket);
                  task.poll(&mut context, permit)
                }
                DomainCpuAdmission::Waiting => (PollResult::Pending, Some(permit)),
                DomainCpuAdmission::Rejected(error) => {
                  drop(permit);
                  task.fail_resource(error);
                  (PollResult::Ready, None)
                }
              };
              drop(permit.as_mut().and_then(PollPermit::take_cpu_ticket));
              drop(permit);
              self.finish_poll(shared, task_ref, matches!(result, PollResult::Ready));
            }
          }
        }
      }
      seat.turn = Some(match handoff::leave_turn() {
        Some(turn) => turn,
        None => unreachable!("distributed dispatch keeps its seat"),
      });
    }
  }
}

enum Search {
  Got(usize),
  Recheck,
  Empty,
}

pub(super) fn scope_snapshot(cell: &ScopeCell) -> super::super::AsyncScopeSnapshot {
  let active_polls = if cell.binding {
    let dispatch = lock(&cell.dispatch, 3);
    debug_assert_eq!(dispatch.maximum(), cell.max_active_polls);
    dispatch.active()
  } else {
    cell.active_stat.load(Ordering::Relaxed)
  };
  super::super::AsyncScopeSnapshot {
    active_tasks: cell.protocol.active(),
    active_polls,
    max_active_polls: cell.max_active_polls,
  }
}

#[cfg(all(test, not(loom)))]
#[path = "distributed_tests.rs"]
mod tests;
