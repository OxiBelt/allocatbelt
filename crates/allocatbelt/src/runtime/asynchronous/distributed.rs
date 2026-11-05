//! Distributed dispatch with seat adoption for bounded handoffs. Admission precedes slot, then scope
//! locks. Lane, overflow and seat locks stand alone. User code and wakes run
//! after releasing these locks; a detached chain belongs only to its mover.

#![forbid(unsafe_code)]

use super::super::handoff_protocol::SeatTable;
use super::super::lane::{
  LaneQueue, ParkedMask, QueueLink, SearchGuard, Searching, VictimOrder, choose_lane,
};
use super::super::metrics::Padded;
#[cfg(not(loom))]
use super::super::park_spin::SpinnerSlots;
use super::*;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;

thread_local! {
  /// This thread's rotating start index for lane choice.
  static LANE_CURSOR: std::cell::Cell<usize> = const { std::cell::Cell::new(UNSEEDED_CURSOR) };
}

/// Spreads the first lane choice of each thread; read once per thread.
static LANE_CURSOR_SEED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const UNSEEDED_CURSOR: usize = usize::MAX;

/// Returns this thread's lane start index and, when `advance` is set, moves
/// the next call on this thread to the following lane.
fn lane_cursor(advance: bool) -> usize {
  LANE_CURSOR.with(|cursor| {
    let mut start = cursor.get();
    if start == UNSEEDED_CURSOR {
      start = LANE_CURSOR_SEED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    cursor.set(if advance {
      start.wrapping_add(1)
    } else {
      start
    });
    start
  })
}

/// A shared start index that a test sets (`store`) to choose lanes
/// deterministically. Until then, and after `use_thread_cursor`, lane choice
/// uses the calling thread's cursor as outside tests.
#[cfg(all(test, not(loom)))]
struct LaneStartOverride {
  armed: AtomicBool,
  next: AtomicUsize,
}

#[cfg(all(test, not(loom)))]
impl LaneStartOverride {
  fn new() -> Self {
    Self {
      armed: AtomicBool::new(false),
      next: AtomicUsize::new(0),
    }
  }

  fn store(&self, next: usize, order: Ordering) {
    self.next.store(next, order);
    self.armed.store(true, Ordering::Release);
  }

  fn use_thread_cursor(&self) {
    self.armed.store(false, Ordering::Release);
  }

  fn start(&self, advance: bool) -> Option<usize> {
    if !self.armed.load(Ordering::Acquire) {
      return None;
    }
    Some(if advance {
      self.next.fetch_add(1, Ordering::Relaxed)
    } else {
      self.next.load(Ordering::Relaxed)
    })
  }
}

#[cfg(all(test, not(loom)))]
thread_local! {
  static SPIN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

fn lock_level() -> u8 {
  super::super::entry::dispatch_lock_level()
}
fn set_lock_level(level: u8) {
  super::super::entry::set_dispatch_lock_level(level);
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

#[repr(align(128))]
struct SlotCell {
  state: Mutex<SlotState>,
}
struct SlotState {
  protocol: SlotProtocol,
  task: Option<Pin<Arc<dyn ErasedTask>>>,
  scope: Option<ScopeRef>,
  /// The admitted task's retained scope owner. Root-scope tasks leave it
  /// `None` and reach the root cell through `Shared::root`; other scopes
  /// install the spawn's one clone together with the task.
  cell: Option<Arc<ScopeCell>>,
  reserved_permit: bool,
}

impl SlotState {
  /// The scope cell of an installed task. The scope, the task and the
  /// owner are installed together at publication and cleared together on
  /// release; before publication the spawner holds the owner.
  fn scope_cell<'a>(&'a self, shared: &'a Shared) -> Option<&'a Arc<ScopeCell>> {
    debug_assert_eq!(self.scope.is_some(), self.task.is_some());
    self
      .scope
      .map(|_| self.cell.as_ref().unwrap_or(&shared.root))
  }
}
#[repr(align(128))]
struct Lane {
  queue: Mutex<LaneQueue>,
  cv: Condvar,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadyInsertion {
  Publish,
  PollRequeue,
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
  #[cfg(not(loom))]
  spin_limit: u32,
  #[cfg(not(loom))]
  spinners: SpinnerSlots,
  #[cfg(not(loom))]
  limit_spinners: bool,
  #[cfg(all(test, not(loom)))]
  max_concurrent_spinners: AtomicUsize,
  #[cfg(all(test, not(loom)))]
  spin_rounds: AtomicUsize,
  searching: Searching,
  #[cfg(all(test, not(loom)))]
  steal_denials: AtomicUsize,
  slots: Vec<SlotCell>,
  links: Vec<QueueLink>,
  lanes: Vec<Lane>,
  parked: ParkedMask,
  #[cfg(all(test, not(loom)))]
  next_lane: LaneStartOverride,
  overflow: Padded<Mutex<LaneQueue>>,
  seats: Mutex<SeatTable>,
  seat_cv: Condvar,
  helper_yield: Padded<AtomicBool>,
  worker_yield: Padded<AtomicBool>,
  closing: Padded<AtomicBool>,
  closed_empty: Padded<AtomicBool>,
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
  wake_searches: AtomicUsize,
  #[cfg(all(test, not(loom)))]
  lane_notifies: AtomicUsize,
  #[cfg(all(test, not(loom)))]
  round_robin: AtomicBool,
  #[cfg(all(test, not(loom)))]
  unwind_seat: AtomicUsize,
}

/// A slot taken from the free bitmap and counted in `admitted`, with no
/// generation consumed and nothing installed: close scans skip it, and only
/// publication admits it. Dropping an unpublished reservation returns the
/// slot and the scope's task count under the admission lock alone.
struct SpawnReservation<'a> {
  distributed: &'a Distributed,
  shared: &'a Shared,
  index: Option<usize>,
  scope: ScopeRef,
  /// Cleared only when the slot's generations ran out at publication.
  reusable: bool,
  /// The scope owner until publication installs it in the slot; `None` for
  /// the root scope.
  cell: Option<Arc<ScopeCell>>,
}

impl Drop for SpawnReservation<'_> {
  fn drop(&mut self) {
    if let Some(index) = self.index.take() {
      let cell = self.cell.take();
      self.distributed.complete(
        self.shared,
        index,
        self.reusable,
        None,
        Some(self.scope),
        cell,
      );
    }
  }
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
    payload_bytes::<Padded<AtomicU64>>(words),
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

  pub(super) fn new(
    config: AsyncConfig,
    max_handoffs: usize,
    park_spin: super::super::park_spin::Policy,
  ) -> Result<Self, AsyncError> {
    let max_searchers = park_spin
      .max_searchers
      .unwrap_or(config.workers.div_ceil(2));
    Ok(Self {
      #[cfg(not(loom))]
      spin_limit: park_spin.rounds,
      #[cfg(not(loom))]
      spinners: SpinnerSlots::new(park_spin.max_spinners.unwrap_or(config.workers)),
      #[cfg(not(loom))]
      // Every spinner holds one of the `workers` seats, so a cap of at least
      // the worker count cannot bind and needs no counter.
      limit_spinners: park_spin.rounds != 0
        && park_spin.max_spinners.is_some_and(|max| max < config.workers),
      #[cfg(all(test, not(loom)))]
      max_concurrent_spinners: AtomicUsize::new(0),
      #[cfg(all(test, not(loom)))]
      spin_rounds: AtomicUsize::new(0),
      searching: Searching::new(max_searchers),
      #[cfg(all(test, not(loom)))]
      steal_denials: AtomicUsize::new(0),
      slots: table(config.max_outstanding, || SlotCell {
        state: Mutex::new(SlotState {
          protocol: SlotProtocol::new(),
          task: None,
          scope: None,
          cell: None,
          reserved_permit: false,
        }),
      })?,
      links: table(config.max_outstanding, QueueLink::new)?,
      lanes: table(config.workers, || Lane {
        queue: Mutex::new(LaneQueue::new()),
        cv: Condvar::new(),
      })?,
      parked: ParkedMask::try_new(config.workers).map_err(|_| AsyncError::OutOfMemory)?,
      #[cfg(all(test, not(loom)))]
      next_lane: LaneStartOverride::new(),
      overflow: Padded(Mutex::new(LaneQueue::new())),
      seats: Mutex::new(
        SeatTable::try_new(config.workers, max_handoffs).map_err(|_| AsyncError::OutOfMemory)?,
      ),
      seat_cv: Condvar::new(),
      helper_yield: Padded(AtomicBool::new(false)),
      worker_yield: Padded(AtomicBool::new(false)),
      closing: Padded(AtomicBool::new(false)),
      closed_empty: Padded(AtomicBool::new(false)),
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
      wake_searches: AtomicUsize::new(0),
      #[cfg(all(test, not(loom)))]
      lane_notifies: AtomicUsize::new(0),
      #[cfg(all(test, not(loom)))]
      round_robin: AtomicBool::new(false),
      #[cfg(all(test, not(loom)))]
      unwind_seat: AtomicUsize::new(usize::MAX),
    })
  }

  pub(super) fn cancel_remaining(&mut self) {
    for cell in &mut self.slots {
      let task = cell
        .state
        .get_mut()
        .unwrap_or_else(PoisonError::into_inner)
        .task
        .take();
      if let Some(task) = task {
        // Final-owner cleanup runs without any scheduler mutex held.
        task.as_ref().cancel();
        task.publish();
      }
    }
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

  /// The start index for lane choice: the calling thread's own rotating
  /// cursor, independent of which dispatcher runs on the thread.
  fn lane_start(&self, advance: bool) -> usize {
    #[cfg(all(test, not(loom)))]
    if let Some(start) = self.next_lane.start(advance) {
      return start;
    }
    lane_cursor(advance)
  }

  fn push_ready(&self, shared: &Shared, index: usize, insertion: ReadyInsertion) {
    let next = self.lane_start(true);
    #[cfg(all(test, not(loom)))]
    let (seat, claimed_parked) = if self.round_robin.load(Ordering::Relaxed) {
      super::super::lane::choose_lane_round_robin(next, &self.parked)
    } else {
      choose_lane(next, &self.parked)
    };
    #[cfg(any(not(test), loom))]
    let (seat, claimed_parked) = choose_lane(next, &self.parked);
    let (notify, search) = {
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
      // Newly ready work may sit behind a blocked poll, even as a lone entry.
      // A poll-end requeue leaves its finishing dispatcher available to search.
      // Selection may already have claimed this lane's parked owner; the
      // lane notification below is then the insertion's only wake.
      let search =
        insertion == ReadyInsertion::Publish && !claimed_parked && !self.parked.is_set(seat);
      (notify, search)
    };
    if notify {
      #[cfg(all(test, not(loom)))]
      self.lane_notifies.fetch_add(1, Ordering::Relaxed);
      self.lanes[seat].cv.notify_one();
    }
    if search {
      self.search_wake();
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
    self.search_wake();
  }

  fn kick(&self, seat: usize) {
    let notify = self.lane(seat).request_recheck();
    if notify {
      #[cfg(all(test, not(loom)))]
      self.lane_notifies.fetch_add(1, Ordering::Relaxed);
      self.lanes[seat].cv.notify_one();
    }
  }
  fn kick_all(&self) {
    for seat in 0..self.lanes.len() {
      self.kick(seat);
    }
  }
  fn search_wake(&self) {
    if !self.searching.wake_allowed() {
      return;
    }
    #[cfg(all(test, not(loom)))]
    self.wake_searches.fetch_add(1, Ordering::Relaxed);
    let mut notify = false;
    let claimed = self.parked.claim_any_with(self.lane_start(false), |seat| {
      let mut queue = self.lane(seat);
      if self.parked.is_dead(seat) || !self.parked.claim(seat) {
        return false;
      }
      // Advertisement and receipt installation share the lane lock, so a
      // seat cannot be claimed twice before acknowledging its prior kick.
      debug_assert!(!queue.search_kick);
      self.searching.kicked();
      queue.search_kick = true;
      notify = queue.request_recheck();
      true
    });
    if let Some(seat) = claimed
      && notify
    {
      #[cfg(all(test, not(loom)))]
      self.lane_notifies.fetch_add(1, Ordering::Relaxed);
      self.lanes[seat].cv.notify_one();
    }
  }

  #[cfg(test)]
  fn acknowledge_search_kick(&self, seat: usize) -> bool {
    let received = std::mem::take(&mut self.lane(seat).search_kick);
    received && self.searching.acknowledge(false)
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
    #[cfg(all(test, not(loom)))]
    shared.before_spawn_admission_for_test();
    let (owner, index) = {
      let mut state = self.admission(shared);
      if state.closed {
        return Err(AsyncSpawnError::new(AsyncError::Closed, future));
      }
      let Some(scope_cell) = get_scope(&state, scope) else {
        return Err(AsyncSpawnError::new(AsyncError::Closed, future));
      };
      if scope_cell.protocol.is_closed() {
        return Err(AsyncSpawnError::new(AsyncError::Closed, future));
      }
      // The bitmap holds only released slots with a generation to spare, so
      // this is the whole capacity decision; the slot is first locked at
      // publication, outside the admission lock.
      let Some(index) = state.free_tasks.first() else {
        return Err(AsyncSpawnError::new(AsyncError::Full, future));
      };
      scope_cell.protocol.add_task();
      // The root cell outlives every slot and is reached through
      // `shared.root`; any other scope is retained once, first by the
      // reservation and then by the slot.
      let owner = (!Arc::ptr_eq(scope_cell, &shared.root)).then(|| Arc::clone(scope_cell));
      state.free_tasks.remove(index);
      // `admitted` counts the reservation until publication or rollback and
      // is also the alive-task metric; it is read under this lock.
      state.admitted += 1;
      (owner, index)
    };
    // Until publication the slot is not admitted: close cannot mark it, and
    // the publication recheck returns the original future when close won.
    // Any failure returns the reserved slot through this guard.
    let mut reservation = SpawnReservation {
      distributed: self,
      shared,
      index: Some(index),
      scope,
      reusable: true,
      cell: owner,
    };
    let scope_cell: &ScopeCell = reservation.cell.as_deref().unwrap_or(&shared.root);
    // On unwind, drop the uninstalled future before returning its admission.
    let future = future;
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
    shared.after_spawn_reservation_for_test();
    let job = {
      // The one slot lock of a spawn: generation, admission, installation.
      let mut slot = self.slot(index);
      debug_assert!(slot.task.is_none() && !slot.protocol.admitted());
      debug_assert!(slot.scope.is_none() && slot.cell.is_none());
      let Some(generation) = slot.protocol.next_generation() else {
        // Unreachable through the bitmap, which never offers an exhausted
        // slot; retire the slot instead of returning it.
        drop(slot);
        drop(domain);
        reservation.reusable = false;
        return Err(AsyncSpawnError::new(AsyncError::Full, future));
      };
      // Publication wins only while both runtime and scope remain open.
      // Keep F movable until this check, and serialize installation with
      // close's slot scan. Allocation holds no admission lock.
      if self.closing.load(Ordering::Acquire) || scope_cell.protocol.is_closed() {
        drop(slot);
        drop(domain);
        return Err(AsyncSpawnError::new(AsyncError::Closed, future));
      }
      let task_ref = TaskRef { index, generation };
      let (task, job) = Task::create(
        future,
        task_id,
        scope_cell.resources.clone(),
        domain,
        Arc::downgrade(shared),
        task_ref,
      );
      // Relaxed: every store to this flag runs under this slot lock, so the
      // reset precedes any abort of this generation in modification order,
      // and every load for this generation, including the lock-free steal
      // check, follows the entry's push under the lane lock, which follows
      // this reset. The abort/cleanup pairing keeps its SeqCst accesses.
      self.links[index].cleanup.store(false, Ordering::Relaxed);
      slot.protocol.admit(generation);
      // No waker or abort handle exists yet, so publication owns the first
      // queue entry.
      let queued = task.poll_word().notify();
      debug_assert_eq!(queued, PollNotify::Enqueue);
      slot.scope = Some(scope);
      slot.task = Some(task);
      slot.cell = reservation.cell.take();
      job
    };
    reservation.index = None;
    self.push_ready(shared, index, ReadyInsertion::Publish);
    Ok(job)
  }

  /// Inserts the queue entry a wake won from an idle task word, without the
  /// slot mutex. The word belongs to the task object, and the slot is
  /// released only by the task's final turn, whose word stays `RUNNING`
  /// until publication sets `COMPLETE`, so an idle word means the index
  /// still names that task here; a finished task's word never wins an entry
  /// again.
  pub(super) fn enqueue_woken(&self, shared: &Shared, task_ref: TaskRef) {
    if task_ref.index < self.slots.len() {
      self.push_ready(shared, task_ref.index, ReadyInsertion::Publish);
    }
  }

  /// Wakes by reference, checking the generation under the slot mutex.
  #[cfg(test)]
  pub(super) fn wake(&self, shared: &Shared, task_ref: TaskRef) {
    let Some(cell) = self.slots.get(task_ref.index) else {
      return;
    };
    let task = {
      let slot = lock(&cell.state, 2);
      if !slot.protocol.matches(task_ref.generation) {
        return;
      }
      slot.task.clone()
    };
    if let Some(task) = task
      && task.poll_word().notify() == PollNotify::Enqueue
    {
      self.enqueue_woken(shared, task_ref);
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
      if !slot.protocol.admitted()
        || generation.is_some_and(|g| !slot.protocol.matches(g))
        || scope.is_some_and(|s| slot.scope.is_none_or(|r| r != s))
      {
        return;
      }
      self.links[index].cleanup.store(true, Ordering::SeqCst);
      slot.protocol.abort();
      let Some(task) = slot.task.as_ref() else {
        // Publication installs the task with the admission; only a fixture
        // admits a slot without one, and it has nothing to route.
        return;
      };
      // The wake RMW decides the route. An idle task's entry is won here
      // and goes straight to cleanup. A running task gains `NOTIFIED`, so
      // its finish requeues it and dispatch then selects cancellation. A
      // queued entry stays where it is unless it waits on a scope quota.
      let notified = task.poll_word().notify();
      let inserted = notified == PollNotify::Enqueue;
      let unlinked = if notified == PollNotify::Queued
        && let Some(cell) = slot.scope_cell(shared)
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
    self.closing.store(true, Ordering::Release);
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
      self.push_ready(shared, index, ReadyInsertion::Publish);
    }
  }

  fn dispatch_decision(&self, shared: &Arc<Shared>, index: usize) -> Option<Selected> {
    let mut slot = self.slot(index);
    let task = Pin::clone(slot.task.as_ref()?);
    let task_ref = TaskRef {
      index,
      generation: slot.protocol.generation(),
    };
    let reserved = std::mem::take(&mut slot.reserved_permit);
    if slot.protocol.aborting() {
      let cell = if reserved {
        Some(Arc::clone(slot.scope_cell(shared)?))
      } else {
        None
      };
      task.poll_word().begin();
      drop(slot);
      if let Some(cell) = cell {
        self.release_permit(shared, &cell);
      }
      return Some(Selected::Cancel(task_ref, task));
    }
    let cell = slot.scope_cell(shared)?;
    let release = if cell.binding {
      if !reserved {
        let mut dispatch = self.scope(cell);
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
        cell: Arc::clone(cell),
      }
    } else if cell.reference.is_some() {
      cell.active_stat.fetch_add(1, Ordering::Relaxed);
      PermitRelease::Counted {
        cell: Arc::clone(cell),
      }
    } else {
      PermitRelease::Free
    };
    // The dequeued entry becomes this poll; wakes from here on set
    // `NOTIFIED` on the running word.
    task.poll_word().begin();
    Some(Selected::Poll(task_ref, task, PollPermit { release }))
  }

  /// Ends a poll. A pending poll changes only the task's word: it goes idle,
  /// or, when woken or aborted during the poll, keeps the queue entry this
  /// finish then inserts; dispatch reads any abort under the slot mutex. A
  /// completed poll releases the slot under its mutex.
  fn finish_poll(
    &self,
    shared: &Arc<Shared>,
    task_ref: TaskRef,
    task: &Pin<Arc<dyn ErasedTask>>,
    ready: bool,
  ) {
    if !ready {
      if task.poll_word().finish_pending() {
        self.push_ready(shared, task_ref.index, ReadyInsertion::PollRequeue);
      }
      return;
    }
    let mut slot = self.slot(task_ref.index);
    if !slot.protocol.matches(task_ref.generation) || slot.task.is_none() {
      return;
    }
    // The word stays `RUNNING` until publication sets `COMPLETE`, so wakes
    // from here on queue nothing.
    slot.protocol.release();
    let task = slot.task.take();
    let scope = slot.scope.take();
    let cell = slot.cell.take();
    let reusable = slot.protocol.next_generation().is_some();
    drop(slot);
    self.complete(shared, task_ref.index, reusable, task, scope, cell);
  }

  fn finish_cancel(&self, shared: &Arc<Shared>, task_ref: TaskRef, task: Pin<Arc<dyn ErasedTask>>) {
    let mut slot = self.slot(task_ref.index);
    if !slot.protocol.matches(task_ref.generation) || slot.task.is_none() {
      return;
    }
    let slot_task = slot.task.take();
    let scope = slot.scope.take();
    let cell = slot.cell.take();
    slot.protocol.release();
    let reusable = slot.protocol.next_generation().is_some();
    drop(slot);
    self.complete(shared, task_ref.index, reusable, slot_task, scope, cell);
    drop(task);
  }

  fn complete(
    &self,
    shared: &Shared,
    index: usize,
    reusable: bool,
    task: Option<Pin<Arc<dyn ErasedTask>>>,
    scope: Option<ScopeRef>,
    cell: Option<Arc<ScopeCell>>,
  ) {
    let empty_after_close = {
      let mut state = self.admission(shared);
      if reusable {
        state.free_tasks.insert(index);
      }
      state.admitted -= 1;
      state.closed && state.admitted == 0
    };
    if let Some(task) = task {
      task.publish();
    }
    if let Some(scope) = scope {
      debug_assert!(cell.is_some() || scope == ScopeRef::ROOT);
      // The root scope's last task never reclaims it, so completion only
      // decrements its count; owned scopes release their retained cell here.
      cell.as_deref().unwrap_or(&shared.root).completed();
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
        self.search_wake();
      }
      // A lone stolen entry bypasses the receiving lane. An abort that set its
      // cleanup flag before this load routes it to overflow; a later abort is
      // seen under the slot lock by the dispatch decision, as after a pop.
      let chain = match chain.into_single() {
        Ok(index) => {
          #[cfg(all(test, not(loom)))]
          self.steals.fetch_add(1, Ordering::Relaxed);
          if self.links[index].cleanup.load(Ordering::SeqCst) {
            self.push_cleanup(shared, index);
            return None;
          }
          return Some(index);
        }
        Err(chain) => chain,
      };
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
        if count != 0 {
          self.search_wake();
        }
      }
      #[cfg(all(test, not(loom)))]
      self.steals.fetch_add(1, Ordering::Relaxed);
      if remains {
        self.search_wake();
      }
      return first;
    }
    None
  }

  fn any_work(&self, shared: &Shared) -> bool {
    let metrics = shared.metrics.inner();
    metrics
      .lane_depth
      .iter()
      .any(|depth| depth.0.load(Ordering::SeqCst) != 0)
      || metrics.overflow_depth.load(Ordering::SeqCst) != 0
  }

  fn found_work(&self, shared: &Shared, guard: &mut Option<SearchGuard<'_>>) {
    if guard.take().is_some_and(SearchGuard::leave) && self.any_work(shared) {
      self.search_wake();
    }
  }

  fn park_rescan(&self, shared: &Shared, seat: usize, searched: bool) -> bool {
    let queue = self.lane(seat);
    // A kick arriving after the entry decision requires another iteration.
    // Serialize this test and advertisement with search_wake's claim.
    if queue.search_kick {
      return false;
    }
    super::super::lane::search_or_park(
      seat,
      &self.parked,
      &self.searching,
      shared
        .metrics
        .inner()
        .lane_depth
        .iter()
        .enumerate()
        .map(|(index, len)| (index, len.0.load(Ordering::SeqCst))),
      || shared.metrics.inner().overflow_depth.load(Ordering::SeqCst),
      searched,
    )
  }

  fn search<'a>(
    &'a self,
    shared: &Shared,
    seat: usize,
    random: &mut u64,
    guard: &mut Option<SearchGuard<'a>>,
  ) -> Search {
    let (first, recheck, remains, woken) = {
      let mut queue = self.lane(seat);
      let first = queue.pop(&self.links);
      let recheck = first.is_none() && queue.take_recheck();
      self.publish_depth(shared, seat, &queue);
      let woken = !recheck && std::mem::take(&mut queue.search_kick);
      (first, recheck, queue.len() != 0, woken)
    };
    if let Some(index) = first {
      // Own-lane work is the entry decision; it needs no search admission.
      // Taking own-lane work consumes the kick without entering searching.
      // If acknowledgement finds no searcher, pass coverage to a sleeper
      // before this task can block inside its poll.
      let uncovered = woken && self.searching.acknowledge(false);
      if remains || (uncovered && self.any_work(shared)) {
        self.search_wake();
      }
      self.found_work(shared, guard);
      return Search::Got(index);
    }
    if recheck {
      return Search::Recheck;
    }
    if guard.is_none() {
      *guard = self.searching.try_enter();
      #[cfg(all(test, not(loom)))]
      if guard.is_none() {
        self.steal_denials.fetch_add(1, Ordering::Relaxed);
      }
    }
    if woken && self.searching.acknowledge(guard.is_some()) {
      return Search::Recheck;
    }
    if guard.is_some()
      && let Some(index) = self.try_steal(shared, seat, random)
    {
      self.found_work(shared, guard);
      return Search::Got(index);
    }
    if shared.metrics.inner().overflow_depth.load(Ordering::SeqCst) != 0 {
      let first = {
        let mut queue = lock(&self.overflow, 4);
        let first = queue.pop(&self.links);
        shared
          .metrics
          .inner()
          .overflow_depth
          .store(queue.len(), Ordering::SeqCst);
        first
      };
      if let Some(index) = first {
        self.found_work(shared, guard);
        return Search::Got(index);
      }
    }
    Search::Empty
  }

  fn retire_search_kick(&self, shared: &Shared, seat: usize, guard: &mut Option<SearchGuard<'_>>) {
    drop(guard.take());
    {
      let mut queue = self.lane(seat);
      self.parked.claim(seat);
      if std::mem::take(&mut queue.search_kick) {
        self.searching.acknowledge(false);
      }
    }
    // A yielding seat may wait for a restorer before searching again. Pass
    // coverage now, after settling its receipt and releasing the lane lock.
    // Its search slot may already have been dropped for the park rescan
    // before it observed the yield hint. The wake gate checks coverage now.
    if self.any_work(shared) {
      self.search_wake();
    }
  }

  fn search_or_park(
    &self,
    shared: &Shared,
    seat: usize,
    random: &mut u64,
    context: AsyncThreadContext,
  ) -> Search {
    let mut searcher = None;
    loop {
      let should_yield =
        if context.role == super::super::thread_options::AsyncThreadRole::HandoffHelper {
          self.helper_yield.load(Ordering::Acquire)
        } else {
          self.worker_yield.load(Ordering::Acquire) && self.seats().worker_should_yield()
        };
      if should_yield {
        self.retire_search_kick(shared, seat, &mut searcher);
        return Search::Recheck;
      }
      match self.search(shared, seat, random, &mut searcher) {
        Search::Empty => {}
        Search::Recheck => {
          if self.closing.load(Ordering::Acquire)
            || self.helper_yield.load(Ordering::Acquire)
            || self.worker_yield.load(Ordering::Acquire)
          {
            self.retire_search_kick(shared, seat, &mut searcher);
            return Search::Recheck;
          }
          continue;
        }
        found => return found,
      }
      #[cfg(not(loom))]
      let spinner = if searcher.is_some() && self.spin_limit != 0 && self.limit_spinners {
        self.spinners.try_acquire()
      } else {
        None
      };
      #[cfg(not(loom))]
      if searcher.is_some() && self.spin_limit != 0 && (!self.limit_spinners || spinner.is_some()) {
        #[cfg(test)]
        self
          .max_concurrent_spinners
          .fetch_max(self.spinners.current(), Ordering::Relaxed);
        let mut work = false;
        debug_assert_eq!(lock_level(), 0, "spin under a dispatch lock");
        for _ in 0..self.spin_limit {
          // Stop on the raw worker-yield hint without locking seats: while a
          // handoff keeps it set, no worker spins, intentionally.
          if self.closing.load(Ordering::Acquire)
            || self.helper_yield.load(Ordering::Acquire)
            || self.worker_yield.load(Ordering::Acquire)
          {
            break;
          }
          std::hint::spin_loop();
          #[cfg(all(test, not(loom)))]
          self.spin_rounds.fetch_add(1, Ordering::Relaxed);
          #[cfg(all(test, not(loom)))]
          SPIN_HOOK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
              hook();
            }
          });
          if self.any_work(shared) {
            work = true;
            break;
          }
        }
        if work {
          continue;
        }
      }
      #[cfg(not(loom))]
      drop(spinner);
      let searched = searcher.is_some();
      drop(searcher.take());
      cache::flush();
      shared.thread_park_attempted(context);
      if !self.park_rescan(shared, seat, searched) {
        shared.thread_unpark_callback(context);
        cache::set_shard(context.physical_index);
        continue;
      }
      let mut queue = self.lane(seat);
      if queue.prepare_sleep() {
        handoff::pause_busy();
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
      let mut queue = self.lane(seat);
      self.parked.mark_dead(seat);
      self.parked.claim(seat);
      if std::mem::take(&mut queue.search_kick) {
        self.searching.acknowledge(false);
      }
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
      self.push_cleanup(shared, index);
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
    handoff::pause_busy();
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
          // Close publishes before its kick; seat transitions publish the
          // worker-yield hint. Helper retirement is handled above each search.
          if !self.closing.load(Ordering::Acquire) && !self.worker_yield.load(Ordering::Acquire) {
            continue;
          }
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
          task.as_ref().cancel();
          self.finish_cancel(shared, task_ref, task);
        }
        Selected::Poll(task_ref, task, permit) => {
          super::super::entry::reset_budget();
          let waker = task.clone().task_waker();
          let mut context = Context::from_waker(&waker);
          // Unbounded polls carry no ticket. A pending poll drops its ticket
          // before the permit; a ready poll drops both, permit first.
          let mut cpu_ticket = None;
          let (result, permit) = match task.acquire_cpu(&waker) {
            DomainCpuAdmission::Unbounded => {
              task.as_ref().poll(&mut context, permit, &mut cpu_ticket)
            }
            DomainCpuAdmission::Acquired(ticket) => {
              cpu_ticket = Some(ticket);
              task.as_ref().poll(&mut context, permit, &mut cpu_ticket)
            }
            DomainCpuAdmission::Waiting => (PollResult::Pending, Some(permit)),
            DomainCpuAdmission::Rejected(error) => {
              drop(permit);
              task.as_ref().fail_resource(error);
              (PollResult::Ready, None)
            }
          };
          drop(cpu_ticket);
          drop(permit);
          self.finish_poll(shared, task_ref, &task, matches!(result, PollResult::Ready));
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
