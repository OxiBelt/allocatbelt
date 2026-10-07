//! A bounded Linux readiness reactor: one service thread waits in
//! `epoll_wait` and wakes tasks waiting for registered file descriptors to
//! become readable or writable. Like the rest of the runtime this is an
//! experimental research foundation, not a network library: it reports
//! readiness, and the caller performs nonblocking I/O itself.
//!
//! # Readiness is not success
//!
//! A [`ReadinessGuard`] means only that the kernel reported the descriptor
//! readable or writable (or hung up, or in error) at some point since the
//! readiness was last cleared. It is a hint, never a promise: another
//! reader may drain the data first, a socket's state may change, and a
//! cached report may be stale. An operation run through
//! [`ReadinessGuard::try_io`] can therefore still fail with
//! [`io::ErrorKind::WouldBlock`]; `try_io` then clears the cached readiness
//! so the next wait asks the kernel again. The reactor never retries or
//! replays an operation: `try_io` consumes its guard and calls its closure
//! exactly once, and whether to try again is the caller's decision.
//!
//! # Ownership
//!
//! A [`Reactor`] owns the service thread. [`ReactorHandle`]s are clonable,
//! register descriptors, and do not keep the reactor running.
//! [`ReactorHandle::register`] takes ownership of a `T: AsFd` and returns an
//! [`AsyncFd<T>`]; cloning an `AsyncFd` shares the same `T` and the same
//! registration (`T` need not be `Clone`), and [`AsyncFd::get_ref`] lends
//! `&T`. The registration is released when the last clone is dropped, and
//! `T` is dropped after that, on the dropping thread, with no reactor lock
//! held. A refused registration hands the original `T` back inside
//! [`RegisterError`].
//!
//! # Registration
//!
//! Registering duplicates the descriptor (`F_DUPFD_CLOEXEC`) and adds the
//! duplicate, not `T`'s own descriptor, to the epoll instance. The reactor
//! owns that duplicate until the registration is released, so the epoll
//! registration, and any kernel event already queued for it, can never
//! refer to a descriptor number `T` closed and the process reused.
//! `T::as_fd` and descriptor duplication run before the reactor lock is
//! acquired; `T` must keep the returned descriptor valid and stable for that
//! call. Closing and installing the duplicate are serialized, so a close
//! that wins before installation leaves the original descriptor flags alone.
//! Releasing deletes the duplicate from epoll and closes it; only then is
//! the registration's capacity returned.
//!
//! The duplicate is added first, so a descriptor epoll cannot watch is
//! refused with the kernel's own error (`EPERM` for a regular file or a
//! directory) before anything about it changes. Then `O_NONBLOCK` is set,
//! keeping every other status flag. `O_NONBLOCK` belongs to the open file
//! description, not to the descriptor: it also applies to `T`'s descriptor
//! and to every other descriptor sharing that description, in this process
//! or another one, and it stays set after the registration is released.
//!
//! # Kernel interest
//!
//! Every registration is level-triggered and `EPOLLONESHOT`. The reactor
//! arms only the directions that have a waiting task and no cached
//! readiness, and the kernel disables the registration again after
//! reporting one event. An idle writable socket nobody waits to write to is
//! therefore never reported more than once, rather than on every
//! `epoll_wait`. Because the registration is level-triggered, arming it
//! makes the kernel evaluate the descriptor's current state, so readiness
//! that arrived while it was disabled, or that a cleared cache forgot, is
//! reported as soon as somebody waits for it again: clearing never loses
//! readiness. Arming and the record of what is armed change together under
//! the driver lock.
//!
//! An event sets cached readiness: `EPOLLIN` readable, `EPOLLOUT` writable,
//! `EPOLLRDHUP` read-closed, and `EPOLLHUP` and `EPOLLERR` both directions,
//! so end of file, hang-up and errors wake every waiter of the descriptor.
//! Clearing a direction ([`ReadinessGuard::clear_ready`], or `try_io`
//! returning `WouldBlock`) forgets its readable or writable bit, its closed
//! bit and the error bit; a condition that persists is reported again by the
//! next arming.
//!
//! # Waiters
//!
//! [`AsyncFd::readable`] and [`AsyncFd::writable`] return futures that
//! complete with a [`ReadinessGuard`] when the direction has cached
//! readiness. A future that has to wait takes one of the reactor's
//! `max_waiters` waiter entries, which are shared by every registration;
//! when none is free the future fails with [`ReactorError::WaitersFull`].
//! Readers and writers of a descriptor wait concurrently and independently.
//! Waiters of one direction queue in arrival order, and readiness of that
//! direction completes all of them, waking them in that order. Each then
//! competes for the readiness; one that loses gets `WouldBlock` and waits
//! again. A waiter's entry is freed when it is completed, when the reactor
//! closes, and when its future is dropped (cancelled); it is freed before
//! the completion is published or its waker is woken, so a woken task
//! observes the freed capacity.
//! Closing wakes waiters outside the state lock and waits for callbacks
//! already running on other threads. A callback may close its own reactor
//! without waiting for itself; callbacks for another reactor still drain
//! normally. The service thread likewise never waits for callbacks that can
//! only finish after that thread exits.
//!
//! # Identity
//!
//! The registration table, the waiter table and the event buffer are
//! allocated when the reactor is created, before the service thread starts.
//! An epoll event carries its registration's table index and a 40-bit
//! generation, which changes every time the slot is reused; an event whose
//! generation is not the slot's current one is ignored, so an event queued
//! before a release never reaches a later registration. Generations are
//! checked, never wrapped: a slot whose generations are used up is retired
//! for good, which permanently lowers the registration capacity by one
//! after about 2^40 reuses of that slot. Waiter ids are 64-bit and checked
//! the same way ([`ReactorError::Exhausted`]).
//!
//! # Errors
//!
//! When re-arming a registration fails (`epoll_ctl` returns an error), the
//! error is recorded on the registration and every waiter of it is
//! completed with it, as is every later wait: such a registration is broken
//! and should be dropped. When `epoll_wait` itself fails with anything but
//! `EINTR`, or the service thread exits for any reason, the reactor closes.
//! No waiter is left waiting on a kernel request that failed.
//!
//! # Locks and user code
//!
//! One driver lock guards the tables. `T`'s [`AsFd::as_fd`], the `try_io`
//! closure, `T`'s destructor and every waker clone, `wake` and `Drop` run
//! with no reactor lock held. A future clones its task's waker before taking
//! the lock and re-checks under it, and the service thread publishes
//! readiness and takes waiters' wakers under the same lock, so a wakeup is
//! never lost. A panic of a waker's `wake` or `Drop` run by the reactor is
//! contained, and a panic payload whose own `Drop` panics is leaked, so the
//! service thread keeps running.
//! Close waits for callbacks already claimed by the service thread or another
//! closer. A callback closing its own reactor skips that wait to avoid waiting
//! for itself; an external closer still waits for the full claimed batch.
//!
//! # Shutdown
//!
//! Dropping the reactor, or [`Reactor::shutdown`], closes it: every waiting
//! future is completed with [`ReactorError::Closed`] and its callback is
//! finished before that call returns (unless close is called inside a
//! callback), every later wait and
//! registration through any handle is refused with `Closed`, and an eventfd
//! interrupts the service thread's `epoll_wait`. `shutdown` then joins the
//! service thread unless it runs on that thread (from a waker the reactor
//! wakes), where it returns [`ReactorError::WouldDeadlock`]. Dropping never
//! joins. Registrations and their `T` may outlive the reactor; their waits
//! resolve `Closed`, `try_io` on a guard obtained earlier still runs, and
//! dropping them still releases their registration.
//!
//! # Limitations
//!
//! There are no timeouts (combine with [`crate::runtime::time`]), no
//! priority (`EPOLLPRI`) readiness, no edge-triggered mode and no I/O
//! helpers. Readiness wakes every waiter of a direction, which favours
//! simplicity over avoiding a thundering herd. The bounds count
//! registrations and waiters, not memory or kernel resources.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::collections::{HashMap, TryReserveError};
use std::fmt;
use std::fs::File;
use std::future::Future;
use std::io::{self, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::panic::{self, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};

use rustix::event::epoll::{self, Event, EventData, EventFlags};
use rustix::event::{EventfdFlags, eventfd};
use rustix::fs::{self as rfs, OFlags};
use rustix::io::Errno;

use crate::runtime::task::drop_contained;

/// Events taken per `epoll_wait`.
const EVENTS: usize = 64;

/// Bits of an event token holding the table index.
const INDEX_BITS: u32 = 24;
const INDEX_MASK: u64 = (1 << INDEX_BITS) - 1;
/// The largest registration and waiter bound.
const MAX_TABLE: usize = 1 << INDEX_BITS;
/// The last usable generation, so no token equals [`WAKE_TOKEN`].
const MAX_GENERATION: u64 = (1 << (64 - INDEX_BITS)) - 2;
/// The eventfd's token.
const WAKE_TOKEN: u64 = u64::MAX;

/// No waiter: the end of a waiter list.
const NIL: u32 = u32::MAX;

// Cached readiness bits.
const READABLE: u8 = 1 << 0;
const WRITABLE: u8 = 1 << 1;
const READ_CLOSED: u8 = 1 << 2;
const WRITE_CLOSED: u8 = 1 << 3;
const ERROR: u8 = 1 << 4;

// Kernel interest bits.
const INTEREST_READ: u8 = 1 << 0;
const INTEREST_WRITE: u8 = 1 << 1;

/// Why the reactor refused, failed or could not shut down. Carried inside
/// an [`io::Error`] where an operation returns one; see
/// [`ReactorError::of`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReactorError {
  /// A zero bound, or one above 2^24.
  Invalid,
  /// Every registration is taken.
  Full,
  /// Every waiter entry is taken.
  WaitersFull,
  /// The 64-bit waiter ids are exhausted (never in practice).
  Exhausted,
  /// The reactor was shut down or dropped, or its service thread exited.
  Closed,
  /// The service thread could not be started.
  Spawn,
  /// [`Reactor::shutdown`] ran on the service thread, which cannot join
  /// itself. The reactor is closed nonetheless.
  WouldDeadlock,
  /// The service thread panicked.
  DriverPanicked,
}

impl ReactorError {
  /// The reactor error `error` carries, if it carries one.
  #[must_use]
  pub fn of(error: &io::Error) -> Option<Self> {
    error.get_ref()?.downcast_ref::<Self>().copied()
  }
}

impl fmt::Display for ReactorError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(match self {
      Self::Invalid => "invalid reactor bound",
      Self::Full => "reactor registration bound reached",
      Self::WaitersFull => "reactor waiter bound reached",
      Self::Exhausted => "reactor waiter ids exhausted",
      Self::Closed => "reactor is closed",
      Self::Spawn => "reactor service thread could not be started",
      Self::WouldDeadlock => "reactor shutdown from its service thread would deadlock",
      Self::DriverPanicked => "reactor service thread panicked",
    })
  }
}

impl std::error::Error for ReactorError {}

impl From<ReactorError> for io::Error {
  fn from(error: ReactorError) -> Self {
    Self::other(error)
  }
}

/// A refused registration: the error and the original, unregistered `T`.
pub struct RegisterError<T> {
  io: T,
  error: io::Error,
}

impl<T> RegisterError<T> {
  /// Why the registration was refused: a [`ReactorError`] (see
  /// [`ReactorError::of`]) or the kernel's error.
  #[must_use]
  pub const fn error(&self) -> &io::Error {
    &self.error
  }

  /// The value that was not registered.
  #[must_use]
  pub const fn get_ref(&self) -> &T {
    &self.io
  }

  /// Returns the value that was not registered.
  #[must_use]
  pub fn into_inner(self) -> T {
    self.io
  }

  /// Returns the value that was not registered and the error.
  #[must_use]
  pub fn into_parts(self) -> (T, io::Error) {
    (self.io, self.error)
  }
}

impl<T> fmt::Debug for RegisterError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("RegisterError")
      .field("error", &self.error)
      .finish_non_exhaustive()
  }
}

impl<T> fmt::Display for RegisterError<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "registration refused: {}", self.error)
  }
}

impl<T> std::error::Error for RegisterError<T> {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    Some(&self.error)
  }
}

/// The reactor's bounds, both between 1 and 2^24.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReactorConfig {
  /// Registrations held at once, from registering until the last
  /// [`AsyncFd`] clone is dropped and the descriptor leaves epoll.
  pub max_registrations: usize,
  /// Futures waiting for readiness at once, across all registrations.
  pub max_waiters: usize,
}

/// A direction of readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
  Read,
  Write,
}

impl Direction {
  const ALL: [Self; 2] = [Self::Read, Self::Write];

  const fn index(self) -> usize {
    match self {
      Self::Read => 0,
      Self::Write => 1,
    }
  }

  /// The cached bits that make this direction ready, and that clearing it
  /// forgets.
  const fn ready_mask(self) -> u8 {
    match self {
      Self::Read => READABLE | READ_CLOSED | ERROR,
      Self::Write => WRITABLE | WRITE_CLOSED | ERROR,
    }
  }

  const fn interest(self) -> u8 {
    match self {
      Self::Read => INTEREST_READ,
      Self::Write => INTEREST_WRITE,
    }
  }
}

/// A registration's epoll token: its generation above its table index.
const fn token(index: u32, generation: u64) -> u64 {
  (generation << INDEX_BITS) | index as u64
}

/// The table index and generation of a token.
const fn decode(token: u64) -> (u32, u64) {
  ((token & INDEX_MASK) as u32, token >> INDEX_BITS)
}

/// The epoll flags arming `interest`: always level-triggered one-shot.
fn interest_flags(interest: u8) -> EventFlags {
  let mut flags = EventFlags::ONESHOT;
  if interest & INTEREST_READ != 0 {
    flags |= EventFlags::IN | EventFlags::RDHUP;
  }
  if interest & INTEREST_WRITE != 0 {
    flags |= EventFlags::OUT;
  }
  flags
}

/// The cached readiness an event reports.
fn ready_bits(flags: EventFlags) -> u8 {
  let mut ready = 0;
  if flags.contains(EventFlags::IN) {
    ready |= READABLE;
  }
  if flags.contains(EventFlags::OUT) {
    ready |= WRITABLE;
  }
  if flags.contains(EventFlags::RDHUP) {
    ready |= READ_CLOSED;
  }
  if flags.contains(EventFlags::HUP) {
    ready |= READ_CLOSED | WRITE_CLOSED;
  }
  if flags.contains(EventFlags::ERR) {
    ready |= ERROR;
  }
  ready
}

fn os_error(errno: Errno) -> io::Error {
  io::Error::from_raw_os_error(errno.raw_os_error())
}

/// A waiter's identity: its table index and the id it was given there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WaiterKey {
  index: u32,
  id: u64,
}

/// A FIFO list of waiters, linked through the waiter table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct List {
  head: u32,
  tail: u32,
}

impl List {
  const EMPTY: Self = Self {
    head: NIL,
    tail: NIL,
  };

  const fn is_empty(self) -> bool {
    self.head == NIL
  }
}

/// A waiter entry; free when `id` is 0.
struct Waiter {
  id: u64,
  slot: u32,
  dir: Direction,
  prev: u32,
  next: u32,
  /// Set while the entry is live.
  waker: Option<Waker>,
}

impl Waiter {
  const fn free() -> Self {
    Self {
      id: 0,
      slot: 0,
      dir: Direction::Read,
      prev: NIL,
      next: NIL,
      waker: None,
    }
  }
}

/// The waiter table.
///
/// Invariant: every live entry is in exactly one list, its registration's
/// list for its direction, and every free index is in `free` once.
struct Waiters {
  table: Vec<Waiter>,
  free: Vec<u32>,
  /// The id the next waiter gets; ids start at 1 and never repeat.
  next_id: u64,
}

impl Waiters {
  fn new(max: u32) -> Result<Self, TryReserveError> {
    let mut table = Vec::new();
    table.try_reserve_exact(max as usize)?;
    table.resize_with(max as usize, Waiter::free);
    let mut free = Vec::new();
    free.try_reserve_exact(max as usize)?;
    free.extend((0..max).rev());
    Ok(Self {
      table,
      free,
      next_id: 1,
    })
  }

  fn live(&self) -> usize {
    self.table.len() - self.free.len()
  }

  fn get_mut(&mut self, key: WaiterKey) -> Option<&mut Waiter> {
    let waiter = self.table.get_mut(key.index as usize)?;
    (waiter.id == key.id).then_some(waiter)
  }

  /// Appends a waiter to `list`, or returns the waker when no entry or id
  /// is left.
  fn push(
    &mut self,
    list: &mut List,
    slot: u32,
    dir: Direction,
    waker: Waker,
  ) -> Result<WaiterKey, (Waker, ReactorError)> {
    let Some(next_id) = self.next_id.checked_add(1) else {
      return Err((waker, ReactorError::Exhausted));
    };
    let Some(index) = self.free.pop() else {
      return Err((waker, ReactorError::WaitersFull));
    };
    let id = self.next_id;
    self.next_id = next_id;
    self.table[index as usize] = Waiter {
      id,
      slot,
      dir,
      prev: list.tail,
      next: NIL,
      waker: Some(waker),
    };
    if list.tail == NIL {
      list.head = index;
    } else {
      self.table[list.tail as usize].next = index;
    }
    list.tail = index;
    Ok(WaiterKey { index, id })
  }

  /// Unlinks the live entry `index` from `list` and frees it, returning its
  /// waker.
  fn unlink(&mut self, list: &mut List, index: u32) -> Option<Waker> {
    let waiter = &mut self.table[index as usize];
    let (prev, next) = (waiter.prev, waiter.next);
    let waker = waiter.waker.take();
    *waiter = Waiter::free();
    if prev == NIL {
      list.head = next;
    } else {
      self.table[prev as usize].next = next;
    }
    if next == NIL {
      list.tail = prev;
    } else {
      self.table[next as usize].prev = prev;
    }
    self.free.push(index);
    waker
  }

  /// Frees every waiter of `list`, collecting their wakers in list order.
  fn drain(&mut self, list: &mut List, wakers: &mut Vec<Waker>) {
    while !list.is_empty() {
      let head = list.head;
      if let Some(waker) = self.unlink(list, head) {
        wakers.push(waker);
      }
    }
  }
}

/// A live registration's state.
struct Entry {
  /// The reactor's duplicate, the descriptor added to epoll.
  fd: OwnedFd,
  /// Cached readiness bits.
  ready: u8,
  /// The interest the kernel may still report (armed and not yet
  /// delivered).
  armed: u8,
  /// The error a failed re-arm recorded; sticky.
  error: Option<i32>,
  /// Waiters, per direction.
  lists: [List; 2],
}

impl Entry {
  const fn new(fd: OwnedFd) -> Self {
    Self {
      fd,
      ready: 0,
      armed: 0,
      error: None,
      lists: [List::EMPTY; 2],
    }
  }

  /// The directions with a waiter and no cached readiness.
  fn desired(&self) -> u8 {
    let mut want = 0;
    for dir in Direction::ALL {
      if !self.lists[dir.index()].is_empty() && self.ready & dir.ready_mask() == 0 {
        want |= dir.interest();
      }
    }
    want
  }
}

enum SlotState {
  Free,
  /// Taken by a registration still being set up.
  Reserved,
  Live(Entry),
  /// Being deleted from epoll; still charged.
  Releasing,
  /// Out of generations; never used again.
  Retired,
}

struct Slot {
  generation: u64,
  state: SlotState,
}

/// An interest to apply with `EPOLL_CTL_MOD` before the driver lock is
/// released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Arm {
  index: u32,
  generation: u64,
  interest: u8,
}

#[derive(Debug, Clone, Copy)]
struct ArmFailure {
  index: u32,
  generation: u64,
}

/// Why a wait failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
  Reactor(ReactorError),
  Os(i32),
}

impl From<Failure> for io::Error {
  fn from(failure: Failure) -> Self {
    match failure {
      Failure::Reactor(error) => error.into(),
      Failure::Os(errno) => Self::from_raw_os_error(errno),
    }
  }
}

/// What one pass over a wait decided.
#[derive(Debug)]
enum Step {
  Ready,
  Failed(Failure),
  /// Waiting; apply the arm, if any, under the same lock.
  Pending(Option<Arm>),
  /// Clone the task's waker outside the lock and pass it in again.
  NeedWaker,
}

/// A [`Step`] and a waker it released, to drop outside the lock.
#[derive(Debug)]
struct Polled {
  step: Step,
  released: Option<Waker>,
}

/// The reactor's tables, under the driver lock. Every state transition is
/// here, free of system calls; callers apply the returned [`Arm`]s.
///
/// Invariants: `live` counts the slots that are reserved, live or
/// releasing, and `free_slots` holds every free slot index once. Once
/// `closed` is set nothing becomes live and no waiter is added.
struct State {
  closed: bool,
  /// Wakers claimed under this lock but not yet finished outside it.
  callbacks_pending: usize,
  slots: Vec<Slot>,
  free_slots: Vec<u32>,
  live: usize,
  waiters: Waiters,
}

impl State {
  fn new(max_registrations: u32, max_waiters: u32) -> Result<Self, TryReserveError> {
    let mut slots = Vec::new();
    slots.try_reserve_exact(max_registrations as usize)?;
    slots.resize_with(max_registrations as usize, || Slot {
      generation: 0,
      state: SlotState::Free,
    });
    let mut free_slots = Vec::new();
    free_slots.try_reserve_exact(max_registrations as usize)?;
    free_slots.extend((0..max_registrations).rev());
    Ok(Self {
      closed: false,
      callbacks_pending: 0,
      slots,
      free_slots,
      live: 0,
      waiters: Waiters::new(max_waiters)?,
    })
  }

  fn entry(&self, index: u32, generation: u64) -> Option<&Entry> {
    let slot = self.slots.get(index as usize)?;
    match &slot.state {
      SlotState::Live(entry) if slot.generation == generation => Some(entry),
      _ => None,
    }
  }

  fn entry_mut(&mut self, index: u32, generation: u64) -> Option<&mut Entry> {
    let slot = self.slots.get_mut(index as usize)?;
    match &mut slot.state {
      SlotState::Live(entry) if slot.generation == generation => Some(entry),
      _ => None,
    }
  }

  /// Takes a free slot with a fresh generation. Retires slots whose
  /// generations are used up instead of wrapping.
  fn reserve(&mut self) -> Result<(u32, u64), ReactorError> {
    if self.closed {
      return Err(ReactorError::Closed);
    }
    while let Some(index) = self.free_slots.pop() {
      let slot = &mut self.slots[index as usize];
      let next = slot.generation.checked_add(1);
      let Some(generation) = next.filter(|&next| next <= MAX_GENERATION) else {
        slot.state = SlotState::Retired;
        continue;
      };
      slot.generation = generation;
      slot.state = SlotState::Reserved;
      self.live += 1;
      return Ok((index, generation));
    }
    Err(ReactorError::Full)
  }

  fn is_reserved(&self, index: u32, generation: u64) -> bool {
    !self.closed
      && self.slots.get(index as usize).is_some_and(|slot| {
        slot.generation == generation && matches!(slot.state, SlotState::Reserved)
      })
  }

  /// Returns a reservation that did not become live.
  fn unreserve(&mut self, index: u32, generation: u64) {
    let Some(slot) = self.slots.get_mut(index as usize) else {
      return;
    };
    if slot.generation == generation && matches!(slot.state, SlotState::Reserved) {
      slot.state = SlotState::Free;
      self.free_slots.push(index);
      self.live -= 1;
    }
  }

  /// Makes a reservation live with the descriptor epoll watches, or hands
  /// the descriptor back once the reactor closed.
  #[cfg(test)]
  fn install(&mut self, index: u32, generation: u64, fd: OwnedFd) -> Result<(), OwnedFd> {
    if self.closed {
      return Err(fd);
    }
    match self.slots.get_mut(index as usize) {
      Some(slot) if slot.generation == generation && matches!(slot.state, SlotState::Reserved) => {
        slot.state = SlotState::Live(Entry::new(fd));
        Ok(())
      }
      _ => Err(fd),
    }
  }

  /// Starts releasing a live registration: its events become stale at
  /// once, all outstanding waiters are freed, and its descriptor is returned
  /// to be deleted from epoll and closed. The slot stays charged until
  /// [`State::finish_release`].
  fn begin_release(
    &mut self,
    index: u32,
    generation: u64,
    wakers: &mut Vec<Waker>,
  ) -> Option<OwnedFd> {
    let Self { slots, .. } = self;
    let slot = slots.get_mut(index as usize)?;
    if slot.generation != generation || !matches!(slot.state, SlotState::Live(_)) {
      return None;
    }
    let released = std::mem::replace(&mut slot.state, SlotState::Releasing);
    let SlotState::Live(mut entry) = released else {
      return None;
    };
    for list in &mut entry.lists {
      self.waiters.drain(list, wakers);
    }
    Some(entry.fd)
  }

  /// Frees a released slot once its descriptor has left epoll.
  fn finish_release(&mut self, index: u32) {
    let Some(slot) = self.slots.get_mut(index as usize) else {
      return;
    };
    if matches!(slot.state, SlotState::Releasing) {
      slot.state = SlotState::Free;
      self.free_slots.push(index);
      self.live -= 1;
    }
  }

  /// Frees a waiter whose future gave up, returning its waker.
  fn cancel(&mut self, key: WaiterKey) -> Option<Waker> {
    let waiter = self.waiters.get_mut(key)?;
    let (slot, dir) = (waiter.slot, waiter.dir);
    let Self { slots, waiters, .. } = self;
    let SlotState::Live(entry) = &mut slots.get_mut(slot as usize)?.state else {
      return None;
    };
    waiters.unlink(&mut entry.lists[dir.index()], key.index)
  }

  /// One pass of a wait for `dir` of registration `(index, generation)`.
  ///
  /// `key` is the future's waiter, if it holds one; `current` is the task's
  /// waker and `waker` a clone of it, when the caller made one. The clone
  /// is consumed when a waiter is added or its waker replaced, and is left
  /// in `waker` otherwise.
  fn poll_ready(
    &mut self,
    index: u32,
    generation: u64,
    dir: Direction,
    key: &mut Option<WaiterKey>,
    current: &Waker,
    waker: &mut Option<Waker>,
  ) -> Polled {
    let failure = if self.closed {
      Some(Failure::Reactor(ReactorError::Closed))
    } else {
      match self.entry(index, generation) {
        None => Some(Failure::Reactor(ReactorError::Closed)),
        Some(entry) => entry.error.map(Failure::Os),
      }
    };
    let ready = self
      .entry(index, generation)
      .is_some_and(|entry| entry.ready & dir.ready_mask() != 0);
    if failure.is_some() || ready {
      let released = key.take().and_then(|key| self.cancel(key));
      let step = failure.map_or(Step::Ready, Step::Failed);
      return Polled { step, released };
    }
    if let Some(held) = *key {
      if let Some(waiter) = self.waiters.get_mut(held) {
        let stored = &mut waiter.waker;
        if stored
          .as_ref()
          .is_some_and(|stored| stored.will_wake(current))
        {
          let step = Step::Pending(None);
          return Polled {
            step,
            released: None,
          };
        }
        let Some(new) = waker.take() else {
          return Polled {
            step: Step::NeedWaker,
            released: None,
          };
        };
        let released = stored.replace(new);
        return Polled {
          step: Step::Pending(None),
          released,
        };
      }
      // Completed since, but the readiness is gone again: wait anew.
      *key = None;
    }
    let Some(new) = waker.take() else {
      return Polled {
        step: Step::NeedWaker,
        released: None,
      };
    };
    let Self { slots, waiters, .. } = self;
    let state = slots.get_mut(index as usize).map(|slot| &mut slot.state);
    let Some(SlotState::Live(entry)) = state else {
      *waker = Some(new);
      let step = Step::Failed(Failure::Reactor(ReactorError::Closed));
      return Polled {
        step,
        released: None,
      };
    };
    match waiters.push(&mut entry.lists[dir.index()], index, dir, new) {
      Ok(added) => *key = Some(added),
      Err((new, error)) => {
        *waker = Some(new);
        let step = Step::Failed(Failure::Reactor(error));
        return Polled {
          step,
          released: None,
        };
      }
    }
    let want = entry.desired();
    let arm = (want & !entry.armed != 0).then(|| {
      entry.armed |= want;
      Arm {
        index,
        generation,
        interest: entry.armed,
      }
    });
    Polled {
      step: Step::Pending(arm),
      released: None,
    }
  }

  /// Applies a kernel event. A stale token (released or reused slot) is
  /// ignored. Otherwise the one-shot registration is now disabled, the
  /// readiness is cached, every waiter of a now-ready direction is freed
  /// with its waker pushed to `wakers` in FIFO order, and the directions
  /// still waited for are returned to be re-armed.
  fn dispatch(&mut self, token: u64, ready: u8, wakers: &mut Vec<Waker>) -> Option<Arm> {
    let (index, generation) = decode(token);
    let Self { slots, waiters, .. } = self;
    let slot = slots.get_mut(index as usize)?;
    let SlotState::Live(entry) = &mut slot.state else {
      return None;
    };
    if slot.generation != generation {
      return None;
    }
    entry.armed = 0;
    entry.ready |= ready;
    for dir in Direction::ALL {
      if entry.ready & dir.ready_mask() != 0 {
        waiters.drain(&mut entry.lists[dir.index()], wakers);
      }
    }
    let want = entry.desired();
    (want != 0).then(|| {
      entry.armed = want;
      Arm {
        index,
        generation,
        interest: want,
      }
    })
  }

  /// Records a failed re-arm. Waiters are popped and woken one at a time
  /// outside the state lock by `Shared::wake_failed_waiters`.
  fn arm_failed(&mut self, index: u32, generation: u64, errno: i32) {
    if let Some(entry) = self.entry_mut(index, generation) {
      entry.error = Some(errno);
      entry.armed = 0;
    }
  }

  fn pop_failed_waker(&mut self, index: u32, generation: u64) -> Option<Waker> {
    let Self { slots, waiters, .. } = self;
    let slot = slots.get_mut(index as usize)?;
    if slot.generation != generation {
      return None;
    }
    let SlotState::Live(entry) = &mut slot.state else {
      return None;
    };
    entry.error?;
    for dir in Direction::ALL {
      let list = &mut entry.lists[dir.index()];
      if !list.is_empty() {
        return waiters.unlink(list, list.head);
      }
    }
    None
  }

  /// Forgets cached readiness of `dir`.
  fn clear(&mut self, index: u32, generation: u64, dir: Direction) {
    if let Some(entry) = self.entry_mut(index, generation) {
      entry.ready &= !dir.ready_mask();
    }
  }

  /// Closes: refuses everything later and frees every waiter, collecting
  /// their wakers. Returns whether this call closed it.
  fn close(&mut self, wakers: &mut Vec<Waker>) -> bool {
    let newly = !self.closed;
    self.closed = true;
    let Self { slots, waiters, .. } = self;
    for slot in slots {
      if let SlotState::Live(entry) = &mut slot.state {
        for list in &mut entry.lists {
          waiters.drain(list, wakers);
        }
      }
    }
    newly
  }
}

struct Shared {
  state: Mutex<State>,
  /// Threads currently running a reactor-owned waker callback. This map is
  /// transient callback metadata and is cleared when the last callback exits.
  callback_owners: Mutex<HashMap<thread::ThreadId, usize>>,
  callbacks_drained: Condvar,
  service_thread: OnceLock<thread::ThreadId>,
  epoll: OwnedFd,
  /// The eventfd that interrupts `epoll_wait` on close.
  wake: File,
  max_registrations: usize,
  max_waiters: usize,
  /// Registration events the service thread dispatched, stale included.
  fd_events: AtomicU64,
}

/// No user code runs, and nothing the reactor does panics, while the
/// driver lock is held, so a poisoned lock still holds consistent state.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
  mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Wakes `waker`, containing a panic of its `wake` or of the `Drop` that
/// `wake` may run.
fn wake_contained(shared: &Shared, waker: Waker) {
  callback_scope(shared, || {
    if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(move || waker.wake())) {
      drop_contained(payload);
    }
  });
}

fn drop_waker_contained(shared: &Shared, waker: Option<Waker>) {
  if let Some(waker) = waker {
    callback_scope(shared, || drop_contained(waker));
  }
}

fn wake_all(shared: &Shared, wakers: &mut Vec<Waker>) -> usize {
  let count = wakers.len();
  for waker in wakers.drain(..) {
    wake_contained(shared, waker);
  }
  count
}

struct CallbackScope<'a> {
  shared: &'a Shared,
  thread: thread::ThreadId,
}

impl Drop for CallbackScope<'_> {
  fn drop(&mut self) {
    let mut owners = lock(&self.shared.callback_owners);
    if let Some(depth) = owners.get_mut(&self.thread) {
      if *depth > 1 {
        *depth -= 1;
      } else {
        owners.remove(&self.thread);
        if owners.is_empty() {
          // Do not retain capacity based on a past peak in concurrent
          // callbacks; this metadata is outside the reactor's resource bound.
          *owners = HashMap::new();
        }
      }
    }
  }
}

fn callback_scope<R>(shared: &Shared, f: impl FnOnce() -> R) -> R {
  let current = thread::current().id();
  *lock(&shared.callback_owners).entry(current).or_insert(0) += 1;
  let _scope = CallbackScope {
    shared,
    thread: current,
  };
  f()
}

fn in_callback(shared: &Shared) -> bool {
  lock(&shared.callback_owners).contains_key(&thread::current().id())
}

/// Sets `O_NONBLOCK` on the open file description, keeping other flags.
fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
  let flags = rfs::fcntl_getfl(fd).map_err(os_error)?;
  if !flags.contains(OFlags::NONBLOCK) {
    rfs::fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(os_error)?;
  }
  Ok(())
}

impl Shared {
  /// Applies `arm` with `EPOLL_CTL_MOD` while the caller holds the driver
  /// lock, so the kernel's interest and `Entry::armed` change together. A
  /// failure resolves the registration's waiters with the error, their
  /// wakers going to `wakers`. Returns whether it failed.
  fn arm(&self, state: &mut State, arm: Arm) -> Option<ArmFailure> {
    let entry = state.entry(arm.index, arm.generation)?;
    let data = EventData::new_u64(token(arm.index, arm.generation));
    let flags = interest_flags(arm.interest);
    match epoll::modify(&self.epoll, &entry.fd, data, flags) {
      Ok(()) => None,
      Err(errno) => {
        let errno = errno.raw_os_error();
        state.arm_failed(arm.index, arm.generation, errno);
        Some(ArmFailure {
          index: arm.index,
          generation: arm.generation,
        })
      }
    }
  }

  fn wake_failed_waiters(&self, failure: ArmFailure) {
    loop {
      let waker = {
        let mut state = lock(&self.state);
        let waker = state.pop_failed_waker(failure.index, failure.generation);
        state.callbacks_pending += usize::from(waker.is_some());
        waker
      };
      let Some(waker) = waker else {
        return;
      };
      wake_contained(self, waker);
      self.finish_callbacks(1);
    }
  }

  /// Duplicates `io`'s descriptor before taking the lock. Close and the
  /// epoll/flag/install sequence then serialize on `state`, so a close that
  /// wins first cannot leave `O_NONBLOCK` changed on the shared description.
  fn attach(&self, io: &impl AsFd, index: u32, generation: u64) -> io::Result<()> {
    let fd = io.as_fd().try_clone_to_owned()?;
    let mut state = lock(&self.state);
    if !state.is_reserved(index, generation) {
      return Err(ReactorError::Closed.into());
    }
    let data = EventData::new_u64(token(index, generation));
    epoll::add(&self.epoll, &fd, data, EventFlags::ONESHOT).map_err(os_error)?;
    if let Err(error) = set_nonblocking(&fd) {
      let _ = epoll::delete(&self.epoll, &fd);
      return Err(error);
    }
    let slot = &mut state.slots[index as usize];
    slot.state = SlotState::Live(Entry::new(fd));
    Ok(())
  }

  /// Releases a registration: stale at once, deleted from epoll and closed
  /// outside the lock, and only then uncharged.
  fn release(&self, index: u32, generation: u64) {
    let mut wakers = Vec::with_capacity(self.max_waiters);
    let (fd, expected_callbacks) = {
      let mut state = lock(&self.state);
      let fd = state.begin_release(index, generation, &mut wakers);
      let callbacks = wakers.len();
      state.callbacks_pending += callbacks;
      (fd, callbacks)
    };
    if let Some(fd) = fd {
      let _ = epoll::delete(&self.epoll, &fd);
      drop(fd);
      lock(&self.state).finish_release(index);
    }
    let callbacks = wake_all(self, &mut wakers);
    debug_assert_eq!(callbacks, expected_callbacks);
    self.finish_callbacks(callbacks);
  }

  /// Polls a wait until it is ready, failed or registered with the task's
  /// current waker.
  fn poll_ready(
    &self,
    index: u32,
    generation: u64,
    dir: Direction,
    key: &mut Option<WaiterKey>,
    cx: &Context<'_>,
  ) -> Poll<Result<(), Failure>> {
    let mut waker = None;
    loop {
      let (polled, arm_failure, callbacks) = {
        let mut state = lock(&self.state);
        let polled = state.poll_ready(index, generation, dir, key, cx.waker(), &mut waker);
        let callbacks = usize::from(polled.released.is_some()) + usize::from(waker.is_some());
        let arm_failure = match polled.step {
          Step::Pending(Some(arm)) => self.arm(&mut state, arm),
          _ => None,
        };
        state.callbacks_pending += callbacks;
        (polled, arm_failure, callbacks)
      };
      drop_waker_contained(self, polled.released);
      drop_waker_contained(self, waker.take());
      self.finish_callbacks(callbacks);
      if let Some(failure) = arm_failure {
        self.wake_failed_waiters(failure);
      }
      match polled.step {
        Step::Ready => return Poll::Ready(Ok(())),
        Step::Failed(failure) => return Poll::Ready(Err(failure)),
        // The failure freed this waiter too; the next pass reports it.
        Step::Pending(_) if arm_failure.is_some() => {}
        Step::Pending(_) => return Poll::Pending,
        // Cloned with no lock held; the next pass re-checks everything.
        Step::NeedWaker => {
          waker = Some(cx.waker().clone());
        }
      }
    }
  }

  /// Gives up a wait, freeing its waiter.
  fn cancel(&self, key: WaiterKey) {
    let waker = {
      let mut state = lock(&self.state);
      let waker = state.cancel(key);
      state.callbacks_pending += usize::from(waker.is_some());
      waker
    };
    let callbacks = usize::from(waker.is_some());
    drop_waker_contained(self, waker);
    self.finish_callbacks(callbacks);
  }

  /// Closes the reactor: refuses everything later, completes every waiter
  /// with `Closed` and wakes it on this thread, and interrupts the service
  /// thread. Idempotent.
  fn close(&self) {
    let mut wakers = Vec::with_capacity(self.max_waiters);
    let newly = {
      let mut state = lock(&self.state);
      let newly = state.close(&mut wakers);
      state.callbacks_pending += wakers.len();
      newly
    };
    if newly {
      // Never fails in practice: the counter only overflows after 2^64 - 1
      // closes. The service thread also stops once it sees the close.
      let _ = (&self.wake).write(&1u64.to_ne_bytes());
    }
    let callbacks = wake_all(self, &mut wakers);
    self.finish_callbacks(callbacks);
    let on_service_thread = self
      .service_thread
      .get()
      .is_some_and(|id| *id == thread::current().id());
    if !in_callback(self) && !on_service_thread {
      let mut state = lock(&self.state);
      while state.callbacks_pending != 0 {
        state = self
          .callbacks_drained
          .wait(state)
          .unwrap_or_else(PoisonError::into_inner);
      }
    }
  }

  fn finish_callbacks(&self, count: usize) {
    if count == 0 {
      return;
    }
    let mut state = lock(&self.state);
    state.callbacks_pending -= count;
    if state.callbacks_pending == 0 {
      self.callbacks_drained.notify_all();
    }
  }

  fn is_closed(&self) -> bool {
    lock(&self.state).closed
  }
}

/// Closes the reactor when the service thread exits, unwinding included,
/// so no waiter waits on a thread that is gone.
struct CloseOnExit<'a>(&'a Shared);

impl Drop for CloseOnExit<'_> {
  fn drop(&mut self) {
    self.0.close();
  }
}

/// The service thread: waits for events, dispatches them under the driver
/// lock, re-arms what is still waited for, and wakes waiters outside the
/// lock, until the reactor closes. `wakers` holds `max_waiters` wakers
/// without growing: a waiter is freed when its waker is collected.
fn drive(shared: &Shared, mut wakers: Vec<Waker>) {
  let _ = shared.service_thread.set(thread::current().id());
  let _close = CloseOnExit(shared);
  let empty = Event {
    flags: EventFlags::empty(),
    data: EventData::new_u64(0),
  };
  let mut events = [empty; EVENTS];
  loop {
    let count = match epoll::wait(&shared.epoll, &mut events[..], None) {
      Ok(count) => count,
      Err(errno) if errno == Errno::INTR => continue,
      // Unrecoverable: `_close` resolves every waiter with `Closed`.
      Err(_) => return,
    };
    let mut failures = [None; EVENTS];
    let mut failure_count = 0;
    {
      let mut state = lock(&shared.state);
      if state.closed {
        return;
      }
      for event in events.iter().take(count) {
        let Event { flags, data } = *event;
        let token = data.u64();
        if token == WAKE_TOKEN {
          continue;
        }
        shared.fd_events.fetch_add(1, Ordering::Relaxed);
        if let Some(arm) = state.dispatch(token, ready_bits(flags), &mut wakers)
          && let Some(failure) = shared.arm(&mut state, arm)
        {
          failures[failure_count] = Some(failure);
          failure_count += 1;
        }
      }
      state.callbacks_pending += wakers.len();
    }
    let callbacks = wake_all(shared, &mut wakers);
    shared.finish_callbacks(callbacks);
    for failure in failures.into_iter().take(failure_count).flatten() {
      shared.wake_failed_waiters(failure);
    }
  }
}

/// Owns the reactor's service thread; see the module documentation.
pub struct Reactor {
  shared: Arc<Shared>,
  thread: Option<JoinHandle<()>>,
}

impl Reactor {
  /// Creates the epoll instance and the interrupting eventfd, reserves the
  /// registration and waiter tables, and starts the service thread.
  ///
  /// # Errors
  ///
  /// [`ReactorError::Invalid`] for a bound of zero or above 2^24,
  /// [`ReactorError::Spawn`] when the thread cannot be started,
  /// `OutOfMemory` when the tables cannot be reserved, or the kernel's
  /// error from `epoll_create1` or `eventfd`.
  pub fn new(config: ReactorConfig) -> io::Result<Self> {
    let ReactorConfig {
      max_registrations,
      max_waiters,
    } = config;
    let bound = |max: usize| {
      u32::try_from(max)
        .ok()
        .filter(|&max| max != 0 && max as usize <= MAX_TABLE)
        .ok_or(ReactorError::Invalid)
    };
    let state = State::new(bound(max_registrations)?, bound(max_waiters)?)
      .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    let mut wakers = Vec::new();
    wakers
      .try_reserve_exact(max_waiters)
      .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    let epoll = epoll::create(epoll::CreateFlags::CLOEXEC).map_err(os_error)?;
    let wake = eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK).map_err(os_error)?;
    let wake = File::from(wake);
    let data = EventData::new_u64(WAKE_TOKEN);
    epoll::add(&epoll, &wake, data, EventFlags::IN).map_err(os_error)?;
    let shared = Arc::new(Shared {
      state: Mutex::new(state),
      callback_owners: Mutex::new(HashMap::new()),
      callbacks_drained: Condvar::new(),
      service_thread: OnceLock::new(),
      epoll,
      wake,
      max_registrations,
      max_waiters,
      fd_events: AtomicU64::new(0),
    });
    let worker = Arc::clone(&shared);
    let thread = thread::Builder::new()
      .name("allocatbelt-reactor".into())
      .spawn(move || drive(&worker, wakers))
      .map_err(|_| io::Error::from(ReactorError::Spawn))?;
    Ok(Self {
      shared,
      thread: Some(thread),
    })
  }

  /// A clonable handle that registers descriptors on this reactor.
  #[must_use]
  pub fn handle(&self) -> ReactorHandle {
    ReactorHandle {
      shared: Arc::clone(&self.shared),
    }
  }

  /// Closes the reactor, completing and waking every waiting future with
  /// `Closed` on this thread, then waits for the service thread to exit.
  ///
  /// # Errors
  ///
  /// `WouldDeadlock` when called on the service thread, which is then left
  /// to exit on its own; `DriverPanicked` when the service thread panicked.
  pub fn shutdown(mut self) -> Result<(), ReactorError> {
    self.shared.close();
    let Some(thread) = self.thread.take() else {
      return Ok(());
    };
    if thread.thread().id() == thread::current().id() {
      return Err(ReactorError::WouldDeadlock);
    }
    thread.join().map_err(|payload| {
      drop_contained(payload);
      ReactorError::DriverPanicked
    })
  }
}

impl Drop for Reactor {
  fn drop(&mut self) {
    self.shared.close();
    // Dropping the `JoinHandle` detaches; the thread sees the close and
    // exits. Dropping the reactor never blocks on a waker it is running.
    self.thread = None;
  }
}

impl fmt::Debug for Reactor {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt::Debug::fmt(&self.handle(), f)
  }
}

/// Registers descriptors on a [`Reactor`]. Cloning shares the reactor; a
/// handle does not keep the reactor open.
#[derive(Clone)]
pub struct ReactorHandle {
  shared: Arc<Shared>,
}

impl ReactorHandle {
  /// Registers `io`, taking ownership of it; see the module documentation
  /// for what registering does to the descriptor.
  ///
  /// # Errors
  ///
  /// Returns `io` unregistered with the error: [`ReactorError::Closed`]
  /// once the reactor closed, [`ReactorError::Full`] when every
  /// registration is taken (in both cases nothing about the descriptor
  /// changed), or the kernel's error from duplicating the descriptor,
  /// `epoll_ctl` (`EPERM` for a descriptor epoll cannot watch, such as a
  /// regular file) or `fcntl`.
  pub fn register<T>(&self, io: T) -> Result<AsyncFd<T>, RegisterError<T>>
  where
    T: AsFd + Send + Sync + 'static,
  {
    let shared = &self.shared;
    let reserved = lock(&shared.state).reserve();
    let (index, generation) = match reserved {
      Ok(reserved) => reserved,
      Err(error) => {
        let error = error.into();
        return Err(RegisterError { io, error });
      }
    };
    let mut reservation = Reservation {
      shared,
      index,
      generation,
      held: true,
    };
    if let Err(error) = shared.attach(&io, index, generation) {
      // `reservation` returns the slot when it is dropped here.
      return Err(RegisterError { io, error });
    }
    reservation.held = false;
    let inner = Arc::new(Registration {
      io,
      shared: Arc::clone(shared),
      index,
      generation,
    });
    Ok(AsyncFd { inner })
  }

  /// Registrations charged now, including ones being released.
  #[must_use]
  pub fn registrations(&self) -> usize {
    lock(&self.shared.state).live
  }

  /// Futures waiting now.
  #[must_use]
  pub fn waiters(&self) -> usize {
    lock(&self.shared.state).waiters.live()
  }

  /// The registration bound the reactor was created with.
  #[must_use]
  pub fn max_registrations(&self) -> usize {
    self.shared.max_registrations
  }

  /// The waiter bound the reactor was created with.
  #[must_use]
  pub fn max_waiters(&self) -> usize {
    self.shared.max_waiters
  }

  /// Whether the reactor has closed.
  #[must_use]
  pub fn is_closed(&self) -> bool {
    self.shared.is_closed()
  }

  /// A diagnostic: kernel events the service thread has dispatched to
  /// registrations, stale ones included, since the reactor started.
  #[must_use]
  pub fn fd_events(&self) -> u64 {
    self.shared.fd_events.load(Ordering::Relaxed)
  }
}

impl fmt::Debug for ReactorHandle {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ReactorHandle")
      .field("registrations", &self.registrations())
      .field("max_registrations", &self.max_registrations())
      .field("waiters", &self.waiters())
      .field("max_waiters", &self.max_waiters())
      .finish_non_exhaustive()
  }
}

/// Returns a reserved slot that did not become live, including when `T`'s
/// `as_fd` unwinds out of [`ReactorHandle::register`].
struct Reservation<'a> {
  shared: &'a Shared,
  index: u32,
  generation: u64,
  held: bool,
}

impl Drop for Reservation<'_> {
  fn drop(&mut self) {
    if self.held {
      lock(&self.shared.state).unreserve(self.index, self.generation);
    }
  }
}

/// One registration, shared by the clones of an [`AsyncFd`].
struct Registration<T> {
  io: T,
  shared: Arc<Shared>,
  index: u32,
  generation: u64,
}

impl<T> Drop for Registration<T> {
  fn drop(&mut self) {
    // Released before `io` is dropped; `io` is dropped after this returns,
    // with no reactor lock held.
    self.shared.release(self.index, self.generation);
  }
}

/// A registered `T` whose readiness can be awaited. Clones share `T` and
/// the registration, which is released when the last clone is dropped.
pub struct AsyncFd<T> {
  inner: Arc<Registration<T>>,
}

impl<T> AsyncFd<T> {
  /// The registered value.
  #[must_use]
  pub fn get_ref(&self) -> &T {
    &self.inner.io
  }

  /// Completes when the descriptor has cached read readiness (readable,
  /// read-closed or in error); see [`Readiness`].
  pub fn readable(&self) -> Readiness<'_, T> {
    self.readiness(Direction::Read)
  }

  /// Completes when the descriptor has cached write readiness (writable,
  /// write-closed or in error); see [`Readiness`].
  pub fn writable(&self) -> Readiness<'_, T> {
    self.readiness(Direction::Write)
  }

  const fn readiness(&self, dir: Direction) -> Readiness<'_, T> {
    Readiness {
      fd: self,
      dir,
      key: None,
    }
  }

  fn clear(&self, dir: Direction) {
    let inner = &self.inner;
    lock(&inner.shared.state).clear(inner.index, inner.generation, dir);
  }
}

impl<T> Clone for AsyncFd<T> {
  fn clone(&self) -> Self {
    Self {
      inner: Arc::clone(&self.inner),
    }
  }
}

impl<T> fmt::Debug for AsyncFd<T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("AsyncFd")
      .field("index", &self.inner.index)
      .field("generation", &self.inner.generation)
      .finish_non_exhaustive()
  }
}

/// Waits for one direction of an [`AsyncFd`]'s readiness.
///
/// It resolves to a [`ReadinessGuard`] once the direction has cached
/// readiness, and fails with [`ReactorError::Closed`] once the reactor
/// closed, [`ReactorError::WaitersFull`] when it has to wait and no waiter
/// entry is free, or the error a failed re-arm recorded. While waiting it
/// holds one waiter entry; dropping it frees the entry before `drop`
/// returns. Polling it again after it completed waits again.
#[must_use = "futures do nothing unless polled"]
pub struct Readiness<'a, T> {
  fd: &'a AsyncFd<T>,
  dir: Direction,
  key: Option<WaiterKey>,
}

impl<'a, T> Future for Readiness<'a, T> {
  type Output = io::Result<ReadinessGuard<'a, T>>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let this = self.get_mut();
    let inner = &this.fd.inner;
    let shared = &inner.shared;
    let polled = shared.poll_ready(inner.index, inner.generation, this.dir, &mut this.key, cx);
    polled.map(|outcome| {
      outcome.map_err(io::Error::from)?;
      Ok(ReadinessGuard {
        fd: this.fd,
        dir: this.dir,
      })
    })
  }
}

impl<T> Drop for Readiness<'_, T> {
  fn drop(&mut self) {
    if let Some(key) = self.key.take() {
      self.fd.inner.shared.cancel(key);
    }
  }
}

impl<T> fmt::Debug for Readiness<'_, T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Readiness")
      .field("direction", &self.dir)
      .field("waiting", &self.key.is_some())
      .finish_non_exhaustive()
  }
}

/// Cached readiness of one direction, observed by a [`Readiness`] future.
///
/// Readiness is a hint, not a promise that an operation will succeed; see
/// the module documentation. Dropping the guard keeps the readiness cached.
#[must_use = "readiness is used through `try_io` or `clear_ready`"]
pub struct ReadinessGuard<'a, T> {
  fd: &'a AsyncFd<T>,
  dir: Direction,
}

impl<T> ReadinessGuard<'_, T> {
  /// The registered value.
  #[must_use]
  pub fn get_ref(&self) -> &T {
    self.fd.get_ref()
  }

  /// Calls `f` once with the registered value, with no reactor lock held,
  /// and returns its result. When `f` fails with
  /// [`io::ErrorKind::WouldBlock`] the direction's cached readiness is
  /// cleared, so the next wait asks the kernel again. Nothing is retried:
  /// the guard is consumed, and `f` must perform a nonblocking operation.
  ///
  /// # Errors
  ///
  /// Whatever `f` returns.
  pub fn try_io<R>(self, f: impl FnOnce(&T) -> io::Result<R>) -> io::Result<R> {
    let result = f(self.fd.get_ref());
    if let Err(error) = &result
      && error.kind() == io::ErrorKind::WouldBlock
    {
      self.fd.clear(self.dir);
    }
    result
  }

  /// Clears the direction's cached readiness, for a caller that observed
  /// `WouldBlock` itself.
  pub fn clear_ready(self) {
    self.fd.clear(self.dir);
  }
}

impl<T> fmt::Debug for ReadinessGuard<'_, T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ReadinessGuard")
      .field("direction", &self.dir)
      .finish_non_exhaustive()
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use std::fs::File;
  use std::future::Future;
  use std::io::{self, Read, Write};
  use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
  use std::os::unix::net::UnixStream;
  use std::pin::{Pin, pin};
  use std::process::{Command, Stdio};
  use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
  use std::sync::{Arc, Mutex, mpsc};
  use std::task::{Context, Poll, Wake, Waker};
  use std::thread::{self, Thread};
  use std::time::{Duration, Instant};

  use rustix::fs::{OFlags, fcntl_getfl};

  use super::*;

  /// Bounds every blocking wait, so a lost wakeup fails a test instead of
  /// hanging it.
  const WATCHDOG: Duration = Duration::from_secs(10);
  /// How long the idle checks watch for unwanted events.
  const QUIET: Duration = Duration::from_millis(50);

  type ThreadExitAction = Box<dyn FnOnce() + Send>;

  struct ThreadExitCallback(Mutex<Option<ThreadExitAction>>);

  impl Drop for ThreadExitCallback {
    fn drop(&mut self) {
      if let Some(action) = self.0.get_mut().unwrap().take() {
        action();
      }
    }
  }

  thread_local! {
    static THREAD_EXIT_CALLBACK: ThreadExitCallback = const {
      ThreadExitCallback(Mutex::new(None))
    };
  }

  struct Unpark(Thread);

  impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
      self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.0.unpark();
    }
  }

  /// Polls `future` on this thread, parking between polls. A pending poll
  /// must be followed by a wakeup within [`WATCHDOG`]; the timeout fails the
  /// test rather than polling again, so a lost wakeup cannot pass.
  fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
      if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
        return output;
      }
      let limit = Instant::now() + WATCHDOG;
      thread::park_timeout(WATCHDOG);
      assert!(
        Instant::now() < limit,
        "lost wakeup: the task was not woken"
      );
    }
  }

  /// Parks until `done` holds. The wakers it waits on unpark this thread
  /// after recording their effect; the watchdog only bounds a lost wakeup.
  fn wait_until(done: impl Fn() -> bool) {
    let limit = Instant::now() + WATCHDOG;
    while !done() {
      let now = Instant::now();
      assert!(now < limit, "lost wakeup: the waker never ran");
      thread::park_timeout(limit - now);
    }
  }

  fn assert_close_still_waiting(done: &mpsc::Receiver<()>) {
    let limit = Instant::now() + Duration::from_millis(50);
    loop {
      match done.try_recv() {
        Err(mpsc::TryRecvError::Empty) if Instant::now() < limit => thread::yield_now(),
        Err(mpsc::TryRecvError::Empty) => return,
        Ok(()) => panic!("close returned while a claimed callback was blocked"),
        Err(mpsc::TryRecvError::Disconnected) => panic!("close waiter exited unexpectedly"),
      }
    }
  }

  /// Counts its wakes and unparks the thread that created it.
  struct Counter {
    wakes: AtomicUsize,
    owner: Thread,
  }

  impl Counter {
    fn wakes(&self) -> usize {
      self.wakes.load(Ordering::SeqCst)
    }
  }

  impl Wake for Counter {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.wakes.fetch_add(1, Ordering::SeqCst);
      self.owner.unpark();
    }
  }

  fn counter() -> (Arc<Counter>, Waker) {
    let counter = Arc::new(Counter {
      wakes: AtomicUsize::new(0),
      owner: thread::current(),
    });
    (Arc::clone(&counter), Waker::from(counter))
  }

  struct CloseThenGate {
    handle: ReactorHandle,
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    first: AtomicBool,
  }

  impl Wake for CloseThenGate {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      if self.first.swap(false, Ordering::SeqCst) {
        self.handle.shared.close();
        let _ = self.entered.send(());
        let _ = self.release.lock().unwrap().recv_timeout(WATCHDOG);
      }
    }
  }

  struct CountWake(Arc<AtomicUsize>);

  impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.0.fetch_add(1, Ordering::SeqCst);
    }
  }

  struct CloseOther {
    target: ReactorHandle,
    entered: mpsc::Sender<()>,
    finished: mpsc::Sender<()>,
  }

  impl Wake for CloseOther {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      let _ = self.entered.send(());
      self.target.shared.close();
      let _ = self.finished.send(());
    }
  }

  struct ShutdownOnDrop {
    reactor: Mutex<Option<Reactor>>,
    finished: mpsc::Sender<Result<(), ReactorError>>,
  }

  #[allow(clippy::manual_noop_waker)]
  impl Wake for ShutdownOnDrop {
    fn wake(self: Arc<Self>) {}

    fn wake_by_ref(self: &Arc<Self>) {}
  }

  impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
      if let Some(reactor) = self.reactor.lock().unwrap().take() {
        let _ = self.finished.send(reactor.shutdown());
      }
    }
  }

  fn poll_with<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(waker))
  }

  fn reactor(max_registrations: usize, max_waiters: usize) -> (Reactor, ReactorHandle) {
    let config = ReactorConfig {
      max_registrations,
      max_waiters,
    };
    let reactor = Reactor::new(config).unwrap();
    let handle = reactor.handle();
    (reactor, handle)
  }

  /// A registered stream and its unregistered, blocking peer.
  fn registered(handle: &ReactorHandle) -> (AsyncFd<UnixStream>, UnixStream) {
    let (stream, peer) = UnixStream::pair().unwrap();
    (handle.register(stream).unwrap(), peer)
  }

  fn nonblocking(fd: &impl AsFd) -> bool {
    fcntl_getfl(fd).unwrap().contains(OFlags::NONBLOCK)
  }

  fn read_from(stream: &UnixStream, buf: &mut [u8]) -> io::Result<usize> {
    let mut stream = stream;
    stream.read(buf)
  }

  fn write_to(stream: &UnixStream, buf: &[u8]) -> io::Result<usize> {
    let mut stream = stream;
    stream.write(buf)
  }

  /// Writes to a nonblocking stream until its send buffer is full.
  fn fill(stream: &UnixStream) {
    let chunk = [0u8; 4096];
    for _ in 0..100_000 {
      match write_to(stream, &chunk) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
        Err(error) => panic!("fill failed: {error}"),
      }
    }
    panic!("the send buffer never filled");
  }

  /// Reads everything queued for `stream`, leaving it nonblocking.
  fn drain(stream: &UnixStream) {
    stream.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 4096];
    loop {
      match read_from(stream, &mut buf) {
        Ok(0) => return,
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
        Err(error) => panic!("drain failed: {error}"),
      }
    }
  }

  fn ready<T>(poll: Poll<io::Result<ReadinessGuard<'_, T>>>) -> ReadinessGuard<'_, T> {
    match poll {
      Poll::Ready(Ok(guard)) => guard,
      Poll::Ready(Err(error)) => panic!("wait failed: {error}"),
      Poll::Pending => panic!("not ready"),
    }
  }

  fn failed<T>(poll: Poll<io::Result<ReadinessGuard<'_, T>>>) -> Option<ReactorError> {
    match poll {
      Poll::Ready(Err(error)) => ReactorError::of(&error),
      Poll::Ready(Ok(_)) => panic!("unexpectedly ready"),
      Poll::Pending => panic!("unexpectedly pending"),
    }
  }

  #[test]
  fn construction_is_validated_and_types_are_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<Reactor>();
    check::<ReactorHandle>();
    check::<AsyncFd<UnixStream>>();
    check::<Readiness<'static, UnixStream>>();
    check::<ReadinessGuard<'static, UnixStream>>();
    let bounds = [(0, 1), (1, 0), (MAX_TABLE + 1, 1), (1, MAX_TABLE + 1)];
    for (max_registrations, max_waiters) in bounds {
      let config = ReactorConfig {
        max_registrations,
        max_waiters,
      };
      let error = Reactor::new(config).map(drop).unwrap_err();
      assert_eq!(ReactorError::of(&error), Some(ReactorError::Invalid));
    }
    let (reactor, handle) = reactor(2, 3);
    assert_eq!((handle.max_registrations(), handle.max_waiters()), (2, 3));
    assert_eq!((handle.registrations(), handle.waiters()), (0, 0));
    reactor.shutdown().unwrap();
  }

  #[test]
  fn tokens_round_trip_and_never_alias_the_eventfd() {
    let last = u32::try_from(MAX_TABLE - 1).unwrap();
    for (index, generation) in [(0, 1), (1, 1), (last, MAX_GENERATION), (7, 1 << 39)] {
      let token = token(index, generation);
      assert_eq!(decode(token), (index, generation));
      assert_ne!(token, WAKE_TOKEN);
    }
  }

  #[test]
  fn readable_and_writable_readiness_complete_waits() {
    let (reactor, handle) = reactor(2, 2);
    let (fd, mut peer) = registered(&handle);
    // Registering made the shared file description nonblocking.
    assert!(nonblocking(fd.get_ref()));
    let guard = block_on(fd.writable()).unwrap();
    assert_eq!(guard.try_io(|stream| write_to(stream, b"ping")).unwrap(), 4);
    let mut buf = [0u8; 4];
    peer.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");
    let (woken, waker) = counter();
    let mut readable = fd.readable();
    assert!(poll_with(&mut readable, &waker).is_pending());
    assert_eq!(handle.waiters(), 1);
    peer.write_all(b"pong").unwrap();
    wait_until(|| woken.wakes() == 1);
    // The waiter entry was freed before the wake.
    assert_eq!(handle.waiters(), 0);
    let guard = ready(poll_with(&mut readable, Waker::noop()));
    let mut buf = [0u8; 8];
    let read = guard.try_io(|stream| read_from(stream, &mut buf)).unwrap();
    assert_eq!(&buf[..read], b"pong");
    drop(readable);
    reactor.shutdown().unwrap();
  }

  #[test]
  fn would_block_clears_readiness_and_the_next_wait_rearms() {
    let (reactor, handle) = reactor(1, 2);
    let (fd, mut peer) = registered(&handle);
    let mut buf = [0u8; 16];
    peer.write_all(b"x").unwrap();
    let guard = block_on(fd.readable()).unwrap();
    assert_eq!(
      guard.try_io(|stream| read_from(stream, &mut buf)).unwrap(),
      1
    );
    // Still cached, so the wait completes at once; the read finds nothing,
    // which clears it. The closure ran exactly once.
    let calls = AtomicUsize::new(0);
    let guard = ready(poll_with(&mut fd.readable(), Waker::noop()));
    let error = guard
      .try_io(|stream| {
        calls.fetch_add(1, Ordering::SeqCst);
        read_from(stream, &mut buf)
      })
      .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Cleared: the next wait waits and is armed again.
    let (woken, waker) = counter();
    let mut readable = fd.readable();
    assert!(poll_with(&mut readable, &waker).is_pending());
    peer.write_all(b"y").unwrap();
    wait_until(|| woken.wakes() == 1);
    let guard = ready(poll_with(&mut readable, Waker::noop()));
    assert_eq!(
      guard.try_io(|stream| read_from(stream, &mut buf)).unwrap(),
      1
    );
    drop(readable);
    // Clear by hand, then let data arrive while nothing waits and the
    // registration is disarmed: the level-triggered re-arm reports it.
    block_on(fd.readable()).unwrap().clear_ready();
    peer.write_all(b"z").unwrap();
    let guard = block_on(fd.readable()).unwrap();
    assert_eq!(
      guard.try_io(|stream| read_from(stream, &mut buf)).unwrap(),
      1
    );
    reactor.shutdown().unwrap();
  }

  #[test]
  fn read_and_write_waiters_wait_independently() {
    let (reactor, handle) = reactor(1, 2);
    let (fd, mut peer) = registered(&handle);
    fill(fd.get_ref());
    let (read_woken, read_waker) = counter();
    let (write_woken, write_waker) = counter();
    let mut readable = fd.readable();
    let mut writable = fd.writable();
    assert!(poll_with(&mut readable, &read_waker).is_pending());
    assert!(poll_with(&mut writable, &write_waker).is_pending());
    assert_eq!(handle.waiters(), 2);
    peer.write_all(b"r").unwrap();
    wait_until(|| read_woken.wakes() == 1);
    assert_eq!(write_woken.wakes(), 0);
    drop(ready(poll_with(&mut readable, Waker::noop())));
    assert_eq!(handle.waiters(), 1);
    // Reading on the peer frees the send buffer: the writer, still armed
    // after the reader's event, is woken.
    drain(&peer);
    wait_until(|| write_woken.wakes() == 1);
    drop(ready(poll_with(&mut writable, Waker::noop())));
    assert_eq!(handle.waiters(), 0);
    reactor.shutdown().unwrap();
  }

  #[test]
  fn hang_up_wakes_both_directions_and_reads_end_of_file() {
    let (reactor, handle) = reactor(1, 2);
    let (fd, peer) = registered(&handle);
    fill(fd.get_ref());
    let (read_woken, read_waker) = counter();
    let (write_woken, write_waker) = counter();
    let mut readable = fd.readable();
    let mut writable = fd.writable();
    assert!(poll_with(&mut readable, &read_waker).is_pending());
    assert!(poll_with(&mut writable, &write_waker).is_pending());
    drop(peer);
    wait_until(|| read_woken.wakes() == 1 && write_woken.wakes() == 1);
    let guard = ready(poll_with(&mut readable, Waker::noop()));
    let mut buf = [0u8; 8];
    match guard.try_io(|stream| read_from(stream, &mut buf)) {
      Ok(0) => {}
      Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
      other => panic!("unexpected hang-up read result: {other:?}"),
    }
    drop(ready(poll_with(&mut writable, Waker::noop())));
    assert_eq!(handle.waiters(), 0);
    reactor.shutdown().unwrap();
  }

  #[test]
  fn graceful_peer_close_reads_end_of_file() {
    let (reactor, handle) = reactor(1, 1);
    let (fd, peer) = registered(&handle);
    let (woken, waker) = counter();
    let mut readable = fd.readable();
    assert!(poll_with(&mut readable, &waker).is_pending());
    drop(peer);
    wait_until(|| woken.wakes() == 1);
    let guard = ready(poll_with(&mut readable, Waker::noop()));
    let mut buf = [0u8; 8];
    assert_eq!(
      guard.try_io(|stream| read_from(stream, &mut buf)).unwrap(),
      0
    );
    drop(readable);
    reactor.shutdown().unwrap();
  }

  #[test]
  fn close_waits_for_the_rest_of_a_service_claimed_wake_batch() {
    let (reactor, handle) = reactor(1, 2);
    let (fd, mut peer) = registered(&handle);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let first_waker = Waker::from(Arc::new(CloseThenGate {
      handle: handle.clone(),
      entered: entered_tx,
      release: Mutex::new(release_rx),
      first: AtomicBool::new(true),
    }));
    let second_count = Arc::new(AtomicUsize::new(0));
    let second_waker = Waker::from(Arc::new(CountWake(Arc::clone(&second_count))));
    let mut first = fd.readable();
    let mut second = fd.readable();
    assert!(poll_with(&mut first, &first_waker).is_pending());
    assert!(poll_with(&mut second, &second_waker).is_pending());
    peer.write_all(b"ready").unwrap();
    entered_rx.recv_timeout(WATCHDOG).unwrap();

    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let closer = handle.clone();
    let external = thread::spawn(move || {
      started_tx.send(()).unwrap();
      closer.shared.close();
      done_tx.send(()).unwrap();
    });
    started_rx.recv_timeout(WATCHDOG).unwrap();
    assert_close_still_waiting(&done_rx);
    assert_eq!(second_count.load(Ordering::SeqCst), 0);

    release_tx.send(()).unwrap();
    wait_until(|| second_count.load(Ordering::SeqCst) == 1);
    done_rx.recv_timeout(WATCHDOG).unwrap();
    external.join().unwrap();
    assert_eq!(handle.waiters(), 0);
    drop((first, second));
    reactor.shutdown().unwrap();
  }

  #[test]
  fn close_drains_more_than_64_wakers_and_concurrent_reentrant_closes_wait() {
    const WAITERS: usize = 70;
    let (reactor, handle) = reactor(1, WAITERS);
    let (fd, _peer) = registered(&handle);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let first_waker = Waker::from(Arc::new(CloseThenGate {
      handle: handle.clone(),
      entered: entered_tx,
      release: Mutex::new(release_rx),
      first: AtomicBool::new(true),
    }));
    let other_count = Arc::new(AtomicUsize::new(0));
    let other_waker = Waker::from(Arc::new(CountWake(Arc::clone(&other_count))));
    let mut waits: Vec<_> = (0..WAITERS).map(|_| fd.readable()).collect();
    assert!(poll_with(&mut waits[0], &first_waker).is_pending());
    for wait in &mut waits[1..] {
      assert!(poll_with(wait, &other_waker).is_pending());
    }

    let (first_done_tx, first_done_rx) = mpsc::channel();
    let first_closer = handle.clone();
    let first_closer_thread = thread::spawn(move || {
      first_closer.shared.close();
      first_done_tx.send(()).unwrap();
    });
    entered_rx.recv_timeout(WATCHDOG).unwrap();

    let (second_started_tx, second_started_rx) = mpsc::channel();
    let (second_done_tx, second_done_rx) = mpsc::channel();
    let second_closer = handle.clone();
    let second_closer_thread = thread::spawn(move || {
      second_started_tx.send(()).unwrap();
      second_closer.shared.close();
      second_done_tx.send(()).unwrap();
    });
    second_started_rx.recv_timeout(WATCHDOG).unwrap();
    assert_close_still_waiting(&first_done_rx);
    assert_close_still_waiting(&second_done_rx);
    assert_eq!(other_count.load(Ordering::SeqCst), 0);

    release_tx.send(()).unwrap();
    wait_until(|| other_count.load(Ordering::SeqCst) == WAITERS - 1);
    first_done_rx.recv_timeout(WATCHDOG).unwrap();
    second_done_rx.recv_timeout(WATCHDOG).unwrap();
    first_closer_thread.join().unwrap();
    second_closer_thread.join().unwrap();
    assert_eq!(handle.waiters(), 0);
    drop(waits);
    reactor.shutdown().unwrap();
  }

  /// Records its id in a shared log when woken, then unparks its owner.
  struct Order {
    id: usize,
    log: Arc<Mutex<Vec<usize>>>,
    owner: Thread,
  }

  impl Wake for Order {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.log.lock().unwrap().push(self.id);
      self.owner.unpark();
    }
  }

  #[test]
  fn same_direction_waiters_wake_in_fifo_order_within_the_bound() {
    let (reactor, handle) = reactor(1, 3);
    let (fd, mut peer) = registered(&handle);
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut waits: Vec<_> = (0..3).map(|_| fd.readable()).collect();
    for (id, wait) in waits.iter_mut().enumerate() {
      let order = Order {
        id,
        log: Arc::clone(&log),
        owner: thread::current(),
      };
      assert!(poll_with(wait, &Waker::from(Arc::new(order))).is_pending());
    }
    assert_eq!(handle.waiters(), 3);
    // Every entry is taken: a fourth wait fails at once.
    assert_eq!(
      failed(poll_with(&mut fd.readable(), Waker::noop())),
      Some(ReactorError::WaitersFull)
    );
    peer.write_all(b"x").unwrap();
    wait_until(|| log.lock().unwrap().len() == 3);
    assert_eq!(*log.lock().unwrap(), [0, 1, 2]);
    for wait in &mut waits {
      drop(ready(poll_with(wait, Waker::noop())));
    }
    assert_eq!(handle.waiters(), 0);
    drop(waits);
    reactor.shutdown().unwrap();
  }

  #[test]
  fn cancelling_a_wait_frees_its_waiter_at_once() {
    let (reactor, handle) = reactor(1, 1);
    let (fd, mut peer) = registered(&handle);
    let (cancelled_woken, cancelled_waker) = counter();
    let mut cancelled = fd.readable();
    assert!(poll_with(&mut cancelled, &cancelled_waker).is_pending());
    assert_eq!(
      failed(poll_with(&mut fd.writable(), Waker::noop())),
      Some(ReactorError::WaitersFull)
    );
    drop(cancelled);
    assert_eq!(handle.waiters(), 0);
    // The freed entry serves the next wait; the cancelled one is never woken.
    let (woken, waker) = counter();
    let mut readable = fd.readable();
    assert!(poll_with(&mut readable, &waker).is_pending());
    peer.write_all(b"x").unwrap();
    wait_until(|| woken.wakes() == 1);
    assert_eq!(cancelled_woken.wakes(), 0);
    drop(ready(poll_with(&mut readable, Waker::noop())));
    reactor.shutdown().unwrap();
  }

  #[test]
  fn concurrent_readiness_and_waiting_lose_no_wakeups() {
    const ROUNDS: usize = 200;
    let (reactor, handle) = reactor(1, 4);
    let (fd, peer) = registered(&handle);
    thread::scope(|s| {
      let reader = fd.clone();
      let consumer = s.spawn(move || {
        let mut buf = [0u8; 1];
        for _ in 0..ROUNDS {
          loop {
            let guard = block_on(reader.readable()).unwrap();
            match guard.try_io(|stream| read_from(stream, &mut buf)) {
              Ok(1) => break,
              Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
              other => panic!("unexpected read: {other:?}"),
            }
          }
        }
      });
      let writer = fd.clone();
      let other_direction = s.spawn(move || {
        for _ in 0..ROUNDS {
          drop(block_on(writer.writable()).unwrap());
        }
      });
      for round in 0..ROUNDS {
        write_to(&peer, b"x").unwrap();
        if round % 8 == 0 {
          thread::yield_now();
        }
      }
      consumer.join().unwrap();
      other_direction.join().unwrap();
    });
    assert_eq!(handle.waiters(), 0);
    reactor.shutdown().unwrap();
  }

  #[test]
  fn a_reused_slot_ignores_events_of_its_previous_registration() {
    let (reactor, handle) = reactor(1, 1);
    let (old, _old_peer) = registered(&handle);
    let (index, generation) = (old.inner.index, old.inner.generation);
    drop(old);
    assert_eq!(handle.registrations(), 0);
    let (fd, _peer) = registered(&handle);
    assert_eq!(fd.inner.index, index);
    assert!(fd.inner.generation > generation);
    let (woken, waker) = counter();
    let mut readable = fd.readable();
    assert!(poll_with(&mut readable, &waker).is_pending());
    let mut wakers = Vec::new();
    {
      let mut state = lock(&handle.shared.state);
      let stale = token(index, generation);
      assert_eq!(
        state.dispatch(stale, READABLE | READ_CLOSED, &mut wakers),
        None
      );
      assert!(wakers.is_empty());
      assert_eq!(state.entry(index, fd.inner.generation).unwrap().ready, 0);
    }
    assert_eq!((woken.wakes(), handle.waiters()), (0, 1));
    drop(readable);
    drop(fd);
    // Generations are checked, never wrapped: a used-up slot retires.
    lock(&handle.shared.state).slots[index as usize].generation = MAX_GENERATION;
    let (stream, _peer) = UnixStream::pair().unwrap();
    let refused = handle.register(stream).unwrap_err();
    assert_eq!(ReactorError::of(refused.error()), Some(ReactorError::Full));
    assert_eq!(handle.registrations(), 0);
    reactor.shutdown().unwrap();
  }

  #[test]
  fn refused_registrations_return_the_original_value_unchanged() {
    let (reactor, handle) = reactor(1, 1);
    // epoll cannot watch a regular file: the kernel's own error.
    let file = File::open(std::env::current_exe().unwrap()).unwrap();
    let raw = file.as_raw_fd();
    let refused = handle.register(file).unwrap_err();
    assert_eq!(refused.error().raw_os_error(), Some(libc::EPERM));
    assert_eq!(refused.get_ref().as_raw_fd(), raw);
    let file = refused.into_inner();
    assert!(!nonblocking(&file));
    assert_eq!(handle.registrations(), 0);
    // Full: the stream comes back with its flags untouched.
    let (_fd, _peer) = registered(&handle);
    let (stream, _other) = UnixStream::pair().unwrap();
    let raw = stream.as_raw_fd();
    let (stream, error) = handle.register(stream).unwrap_err().into_parts();
    assert_eq!(ReactorError::of(&error), Some(ReactorError::Full));
    assert_eq!(stream.as_raw_fd(), raw);
    assert!(!nonblocking(&stream));
    drop(reactor);
    let (stream, error) = handle.register(stream).unwrap_err().into_parts();
    assert_eq!(ReactorError::of(&error), Some(ReactorError::Closed));
    assert_eq!(stream.as_raw_fd(), raw);
    drop(file);
  }

  struct GatedAsFd {
    stream: UnixStream,
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
  }

  impl AsFd for GatedAsFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
      let _ = self.entered.send(());
      let _ = self.release.lock().unwrap().recv_timeout(WATCHDOG);
      self.stream.as_fd()
    }
  }

  #[test]
  fn close_winning_while_as_fd_is_resolved_leaves_original_flags_unchanged() {
    let (reactor, handle) = reactor(1, 1);
    let (stream, _peer) = UnixStream::pair().unwrap();
    assert!(!nonblocking(&stream));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let registering_handle = handle.clone();
    let registration = thread::spawn(move || {
      registering_handle.register(GatedAsFd {
        stream,
        entered: entered_tx,
        release: Mutex::new(release_rx),
      })
    });
    entered_rx.recv_timeout(WATCHDOG).unwrap();

    let (closed_tx, closed_rx) = mpsc::channel();
    let shutdown = thread::spawn(move || closed_tx.send(reactor.shutdown()).unwrap());
    let close_result = closed_rx.recv_timeout(WATCHDOG);
    if close_result.is_err() {
      let _ = release_tx.send(());
      let _ = registration.join();
      panic!("close waited while `AsFd::as_fd` was outside the state lock");
    }
    assert_eq!(close_result.unwrap(), Ok(()));
    release_tx.send(()).unwrap();
    shutdown.join().unwrap();

    let refused = registration.join().unwrap().unwrap_err();
    assert_eq!(
      ReactorError::of(refused.error()),
      Some(ReactorError::Closed)
    );
    assert!(!nonblocking(&refused.get_ref().stream));
  }

  #[test]
  fn clones_share_the_value_and_the_last_one_releases_it() {
    let (reactor, handle) = reactor(1, 1);
    let (fd, _peer) = registered(&handle);
    let clone = fd.clone();
    assert_eq!(clone.get_ref().as_raw_fd(), fd.get_ref().as_raw_fd());
    assert_eq!(handle.registrations(), 1);
    drop(fd);
    assert_eq!(handle.registrations(), 1);
    drop(clone);
    assert_eq!(handle.registrations(), 0);
    reactor.shutdown().unwrap();
  }

  #[test]
  fn shutdown_and_drop_resolve_and_wake_every_wait() {
    for explicit in [true, false] {
      let (reactor, handle) = reactor(2, 4);
      let (fd, mut peer) = registered(&handle);
      fill(fd.get_ref());
      let (read_woken, read_waker) = counter();
      let (write_woken, write_waker) = counter();
      let mut readable = fd.readable();
      let mut writable = fd.writable();
      assert!(poll_with(&mut readable, &read_waker).is_pending());
      assert!(poll_with(&mut writable, &write_waker).is_pending());
      if explicit {
        reactor.shutdown().unwrap();
      } else {
        drop(reactor);
      }
      // Woken on this thread before the close returned, entries freed first.
      assert_eq!((read_woken.wakes(), write_woken.wakes()), (1, 1));
      assert_eq!(handle.waiters(), 0);
      assert!(handle.is_closed());
      for wait in [&mut readable, &mut writable] {
        let closed = failed(poll_with(wait, Waker::noop()));
        assert_eq!(closed, Some(ReactorError::Closed));
      }
      // The registration outlives the reactor; its waits resolve `Closed`.
      peer.write_all(b"x").unwrap();
      let closed = failed(poll_with(&mut fd.readable(), Waker::noop()));
      assert_eq!(closed, Some(ReactorError::Closed));
      let (stream, _other) = UnixStream::pair().unwrap();
      let refused = handle.register(stream).unwrap_err();
      assert_eq!(
        ReactorError::of(refused.error()),
        Some(ReactorError::Closed)
      );
      drop((readable, writable));
      drop(fd);
      assert_eq!(handle.registrations(), 0);
    }
  }

  /// Shuts down the reactor it owns from its `wake`.
  struct ShutdownOnWake {
    reactor: Mutex<Option<Reactor>>,
    result: mpsc::Sender<Result<(), ReactorError>>,
  }

  impl Wake for ShutdownOnWake {
    fn wake(self: Arc<Self>) {
      let reactor = self.reactor.lock().unwrap().take();
      if let Some(reactor) = reactor {
        let _ = self.result.send(reactor.shutdown());
      }
    }
  }

  #[test]
  fn shutdown_on_the_service_thread_closes_without_joining_itself() {
    let (reactor, handle) = reactor(1, 1);
    let (fd, mut peer) = registered(&handle);
    let (result, results) = mpsc::channel();
    let waker = Waker::from(Arc::new(ShutdownOnWake {
      reactor: Mutex::new(Some(reactor)),
      result,
    }));
    let mut readable = fd.readable();
    assert!(poll_with(&mut readable, &waker).is_pending());
    drop(waker);
    peer.write_all(b"x").unwrap();
    assert_eq!(
      results.recv_timeout(WATCHDOG),
      Ok(Err(ReactorError::WouldDeadlock))
    );
    assert!(handle.is_closed());
    // The close wins over the readiness that woke the waiter.
    let closed = failed(poll_with(&mut readable, Waker::noop()));
    assert_eq!(closed, Some(ReactorError::Closed));
  }

  #[test]
  fn dropping_a_pending_waker_can_shutdown_and_join_its_reactor() {
    let (done_tx, done_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
      let (reactor, handle) = reactor(1, 1);
      let (fd, _peer) = registered(&handle);
      let (shutdown_tx, shutdown_rx) = mpsc::channel();
      let waker = Waker::from(Arc::new(ShutdownOnDrop {
        reactor: Mutex::new(Some(reactor)),
        finished: shutdown_tx,
      }));
      let mut readable = fd.readable();
      assert!(poll_with(&mut readable, &waker).is_pending());
      drop(waker);
      drop(readable);
      let result = shutdown_rx.recv_timeout(WATCHDOG).unwrap();
      assert_eq!(result, Ok(()));
      done_tx.send(handle.is_closed()).unwrap();
    });

    assert_eq!(done_rx.recv_timeout(WATCHDOG), Ok(true));
    worker.join().unwrap();
  }

  #[test]
  fn callback_closing_another_reactor_waits_for_its_callbacks() {
    let (reactor_a, handle_a) = reactor(1, 1);
    let (reactor_b, handle_b) = reactor(1, 2);
    let (fd_a, mut peer_a) = registered(&handle_a);
    let (fd_b, mut peer_b) = registered(&handle_b);

    let (gate_entered_tx, gate_entered_rx) = mpsc::channel();
    let (gate_release_tx, gate_release_rx) = mpsc::channel();
    let gate = Waker::from(Arc::new(CloseThenGate {
      handle: handle_b.clone(),
      entered: gate_entered_tx,
      release: Mutex::new(gate_release_rx),
      first: AtomicBool::new(true),
    }));
    let count = Arc::new(AtomicUsize::new(0));
    let count_waker = Waker::from(Arc::new(CountWake(Arc::clone(&count))));
    let mut b_first = fd_b.readable();
    let mut b_second = fd_b.readable();
    assert!(poll_with(&mut b_first, &gate).is_pending());
    assert!(poll_with(&mut b_second, &count_waker).is_pending());

    let (other_entered_tx, other_entered_rx) = mpsc::channel();
    let (other_finished_tx, other_finished_rx) = mpsc::channel();
    let other_waker = Waker::from(Arc::new(CloseOther {
      target: handle_b.clone(),
      entered: other_entered_tx,
      finished: other_finished_tx,
    }));
    let mut a_wait = fd_a.readable();
    assert!(poll_with(&mut a_wait, &other_waker).is_pending());
    drop((gate, count_waker, other_waker));

    peer_b.write_all(b"b").unwrap();
    gate_entered_rx.recv_timeout(WATCHDOG).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 0);
    peer_a.write_all(b"a").unwrap();
    other_entered_rx.recv_timeout(WATCHDOG).unwrap();
    assert!(other_finished_rx.recv_timeout(QUIET).is_err());

    gate_release_tx.send(()).unwrap();
    other_finished_rx.recv_timeout(WATCHDOG).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    reactor_a.shutdown().unwrap();
    reactor_b.shutdown().unwrap();
  }

  #[test]
  fn callback_tracking_survives_thread_local_teardown() {
    const CHILD_ENV: &str = "ALLOCATBELT_REACTOR_TLS_TEARDOWN_CHILD";

    if std::env::var_os(CHILD_ENV).is_some() {
      THREAD_EXIT_CALLBACK.with(|_| {});
      let (reactor, handle) = reactor(1, 1);
      let (fd, _peer) = registered(&handle);
      let fd = Box::leak(Box::new(fd));
      let (counter, waker) = counter();
      let mut readable = fd.readable();
      assert!(poll_with(&mut readable, &waker).is_pending());
      THREAD_EXIT_CALLBACK.with(|callback| {
        *lock(&callback.0) = Some(Box::new(move || {
          drop(readable);
          drop(reactor);
        }));
      });
      drop(waker);
      drop(counter);
      return;
    }

    let executable = std::env::current_exe().unwrap();
    let mut child = Command::new(executable)
      .arg("--exact")
      .arg("runtime::reactor::tests::callback_tracking_survives_thread_local_teardown")
      .env(CHILD_ENV, "1")
      .stdout(Stdio::null())
      .stderr(Stdio::inherit())
      .spawn()
      .unwrap();
    let deadline = Instant::now() + WATCHDOG;
    loop {
      if let Some(status) = child.try_wait().unwrap() {
        assert!(
          status.success(),
          "thread-local teardown child failed: {status}"
        );
        break;
      }
      if Instant::now() >= deadline {
        let _ = child.kill();
        let _ = child.wait();
        panic!("thread-local teardown child exceeded watchdog");
      }
      thread::sleep(Duration::from_millis(10));
    }
  }

  #[test]
  fn releasing_registration_frees_waiters_from_forgotten_futures() {
    let (reactor, handle) = reactor(1, 1);
    let (fd, _peer) = registered(&handle);
    let (woken, waker) = counter();
    let mut readable = fd.readable();
    assert!(poll_with(&mut readable, &waker).is_pending());
    std::mem::forget(readable);
    drop(fd);

    assert_eq!(handle.waiters(), 0);
    assert_eq!(handle.registrations(), 0);
    assert_eq!(woken.wakes(), 1);

    let (replacement, _peer) = registered(&handle);
    let mut replacement_wait = replacement.readable();
    assert!(poll_with(&mut replacement_wait, &waker).is_pending());
    drop(replacement_wait);
    assert_eq!(handle.waiters(), 0);
    reactor.shutdown().unwrap();
  }

  /// Counts its wakes and unparks its owner, then panics with a payload
  /// whose own `Drop` panics.
  struct PanicOnWake {
    wakes: AtomicUsize,
    owner: Thread,
  }

  impl Wake for PanicOnWake {
    fn wake(self: Arc<Self>) {
      self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
      self.wakes.fetch_add(1, Ordering::SeqCst);
      self.owner.unpark();
      std::panic::panic_any(PanicOnDrop);
    }
  }

  struct PanicOnDrop;

  impl Drop for PanicOnDrop {
    fn drop(&mut self) {
      panic!("panic payload dropped");
    }
  }

  /// A waker whose last reference, when dropped, records it and unparks
  /// its owner, then panics.
  struct PanicOnRelease {
    released: Arc<AtomicBool>,
    owner: Thread,
  }

  impl Wake for PanicOnRelease {
    fn wake(self: Arc<Self>) {
      drop(self);
    }
  }

  impl Drop for PanicOnRelease {
    fn drop(&mut self) {
      self.released.store(true, Ordering::SeqCst);
      self.owner.unpark();
      panic!("waker dropped");
    }
  }

  fn release_waker(released: &Arc<AtomicBool>) -> Waker {
    Waker::from(Arc::new(PanicOnRelease {
      released: Arc::clone(released),
      owner: thread::current(),
    }))
  }

  #[test]
  fn waker_panics_are_contained_and_the_service_thread_keeps_running() {
    let (reactor, handle) = reactor(1, 4);
    let (fd, mut peer) = registered(&handle);
    let panicking = Arc::new(PanicOnWake {
      wakes: AtomicUsize::new(0),
      owner: thread::current(),
    });
    let released = Arc::new(AtomicBool::new(false));
    let mut woken = fd.readable();
    let mut dropped = fd.readable();
    let panicking_waker = Waker::from(Arc::clone(&panicking));
    assert!(poll_with(&mut woken, &panicking_waker).is_pending());
    drop(panicking_waker);
    assert!(poll_with(&mut dropped, &release_waker(&released)).is_pending());
    peer.write_all(b"x").unwrap();
    wait_until(|| panicking.wakes.load(Ordering::SeqCst) == 1 && released.load(Ordering::SeqCst));
    assert!(!handle.is_closed());
    let mut buf = [0u8; 8];
    let guard = ready(poll_with(&mut woken, Waker::noop()));
    assert_eq!(
      guard.try_io(|stream| read_from(stream, &mut buf)).unwrap(),
      1
    );
    let guard = ready(poll_with(&mut dropped, Waker::noop()));
    let error = guard
      .try_io(|stream| read_from(stream, &mut buf))
      .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    // A waker replaced in `poll` is dropped outside the lock, contained too.
    let replaced = Arc::new(AtomicBool::new(false));
    let mut readable = fd.readable();
    assert!(poll_with(&mut readable, &release_waker(&replaced)).is_pending());
    assert!(poll_with(&mut readable, Waker::noop()).is_pending());
    assert!(replaced.load(Ordering::SeqCst));
    drop(readable);
    // The service thread survived every panic.
    peer.write_all(b"y").unwrap();
    drop(block_on(fd.readable()).unwrap());
    assert!(!handle.is_closed());
    reactor.shutdown().unwrap();
  }

  /// A correctness check, not a measurement: with nobody waiting, or only
  /// a reader waiting, an idle writable socket produces no events.
  #[test]
  fn an_idle_writable_descriptor_is_not_reported_again_and_again() {
    let (reactor, handle) = reactor(1, 1);
    let (fd, _peer) = registered(&handle);
    drop(block_on(fd.writable()).unwrap());
    let seen = handle.fd_events();
    assert!(seen >= 1);
    thread::sleep(QUIET);
    assert_eq!(handle.fd_events(), seen);
    let mut readable = fd.readable();
    assert!(poll_with(&mut readable, Waker::noop()).is_pending());
    thread::sleep(QUIET);
    assert_eq!(handle.fd_events(), seen);
    drop(readable);
    reactor.shutdown().unwrap();
  }

  /// The state machine alone: a reserved, live registration on a socket
  /// the kernel never sees.
  fn live_state(max_waiters: u32) -> (State, u32, u64, UnixStream) {
    let mut state = State::new(1, max_waiters).unwrap();
    let (index, generation) = state.reserve().unwrap();
    let (stream, peer) = UnixStream::pair().unwrap();
    state
      .install(index, generation, OwnedFd::from(stream))
      .unwrap();
    (state, index, generation, peer)
  }

  #[test]
  fn events_rearm_only_the_directions_still_waited_for() {
    let (mut state, index, generation, _peer) = live_state(2);
    let (woken, waker) = counter();
    let (mut read_key, mut write_key) = (None, None);
    let polled = state.poll_ready(
      index,
      generation,
      Direction::Read,
      &mut read_key,
      &waker,
      &mut Some(waker.clone()),
    );
    let read_arm = Arm {
      index,
      generation,
      interest: INTEREST_READ,
    };
    assert!(matches!(polled.step, Step::Pending(Some(arm)) if arm == read_arm));
    let polled = state.poll_ready(
      index,
      generation,
      Direction::Write,
      &mut write_key,
      &waker,
      &mut Some(waker.clone()),
    );
    let both = INTEREST_READ | INTEREST_WRITE;
    assert!(matches!(polled.step, Step::Pending(Some(arm)) if arm.interest == both));
    // Writable: the writer completes, and only reading is re-armed.
    let mut wakers = Vec::new();
    let token = token(index, generation);
    assert_eq!(state.dispatch(token, WRITABLE, &mut wakers), Some(read_arm));
    assert_eq!((wakers.len(), state.waiters.live()), (1, 1));
    // Ready and nobody waiting: nothing is re-armed.
    wakers.clear();
    assert_eq!(state.dispatch(token, READABLE, &mut wakers), None);
    assert_eq!((wakers.len(), state.waiters.live()), (1, 0));
    assert_eq!(woken.wakes(), 0);
  }

  #[test]
  fn a_failed_rearm_resolves_every_waiter_of_the_registration() {
    let (mut state, index, generation, _peer) = live_state(2);
    let (_, waker) = counter();
    let (mut read_key, mut write_key) = (None, None);
    for (dir, key) in [
      (Direction::Read, &mut read_key),
      (Direction::Write, &mut write_key),
    ] {
      let polled = state.poll_ready(
        index,
        generation,
        dir,
        key,
        &waker,
        &mut Some(waker.clone()),
      );
      assert!(matches!(polled.step, Step::Pending(Some(_))));
    }
    state.arm_failed(index, generation, libc::ENOMEM);
    assert_eq!(state.waiters.live(), 2);
    assert!(state.pop_failed_waker(index, generation).is_some());
    assert!(state.pop_failed_waker(index, generation).is_some());
    assert!(state.pop_failed_waker(index, generation).is_none());
    assert_eq!(state.waiters.live(), 0);
    let polled = state.poll_ready(
      index,
      generation,
      Direction::Read,
      &mut read_key,
      &waker,
      &mut None,
    );
    assert!(matches!(
      polled.step,
      Step::Failed(Failure::Os(libc::ENOMEM))
    ));
    assert!(read_key.is_none());
  }
}
