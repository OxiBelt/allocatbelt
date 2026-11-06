//! Intrusive FIFO lanes and the search-to-park handshake. A queue's lock owns
//! its links; detached chains belong to their mover until appended under the
//! receiving lock. Lane locks are leaves: cut, unlock, then append.

#![forbid(unsafe_code)]

use super::metrics::Padded;

#[cfg(loom)]
use loom::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

pub(super) const NIL: usize = usize::MAX;
pub(super) const STEAL_MAX: usize = 32;

#[derive(Debug)]
pub(super) struct QueueLink {
  pub(super) next: AtomicUsize,
  // Only the scope blocked list uses back-links, for constant-time unlink.
  pub(super) prev: AtomicUsize,
  pub(super) blocked: AtomicBool,
  pub(super) cleanup: AtomicBool,
}

impl QueueLink {
  pub(super) fn new() -> Self {
    Self {
      next: AtomicUsize::new(NIL),
      prev: AtomicUsize::new(NIL),
      blocked: AtomicBool::new(false),
      cleanup: AtomicBool::new(false),
    }
  }
}

/// Exclusive ownership of a detached chain; moving it consumes this value.
#[derive(Debug)]
#[must_use]
pub(super) struct Chain {
  first: usize,
  last: usize,
  len: usize,
}

impl Chain {
  /// Consume a one-entry chain and return its index. A longer chain is
  /// returned unchanged for appending.
  pub(super) fn into_single(self) -> Result<usize, Self> {
    if self.len == 1 {
      debug_assert_eq!(self.first, self.last);
      Ok(self.first)
    } else {
      Err(self)
    }
  }
}

#[derive(Debug)]
pub(super) struct LaneQueue {
  head: usize,
  tail: usize,
  len: usize,
  sleeping: bool,
  notified: bool,
  recheck: bool,
  pub(super) search_kick: bool,
}

impl LaneQueue {
  pub(super) const fn new() -> Self {
    Self {
      head: NIL,
      tail: NIL,
      len: 0,
      sleeping: false,
      notified: false,
      recheck: false,
      search_kick: false,
    }
  }

  pub(super) fn push(
    &mut self,
    links: &(impl std::ops::Index<usize, Output = QueueLink> + ?Sized),
    index: usize,
  ) -> bool {
    links[index].next.store(NIL, Ordering::Relaxed);
    self.append_chain(
      links,
      Chain {
        first: index,
        last: index,
        len: 1,
      },
    )
  }

  pub(super) fn pop(
    &mut self,
    links: &(impl std::ops::Index<usize, Output = QueueLink> + ?Sized),
  ) -> Option<usize> {
    if self.len == 0 {
      return None;
    }
    let index = self.head;
    self.head = links[index].next.load(Ordering::Relaxed);
    self.len -= 1;
    if self.len == 0 {
      self.tail = NIL;
    }
    links[index].next.store(NIL, Ordering::Relaxed);
    Some(index)
  }

  /// Remove an entry without acquiring it for polling. Used only to relocate
  /// cancellation cleanup; ordinary dispatch still pops one FIFO entry.
  pub(super) fn remove(
    &mut self,
    links: &(impl std::ops::Index<usize, Output = QueueLink> + ?Sized),
    target: usize,
  ) -> bool {
    let mut previous = NIL;
    let mut index = self.head;
    while index != NIL {
      let next = links[index].next.load(Ordering::Relaxed);
      if index == target {
        if previous == NIL {
          self.head = next;
        } else {
          links[previous].next.store(next, Ordering::Relaxed);
        }
        if self.tail == index {
          self.tail = previous;
        }
        self.len -= 1;
        links[index].next.store(NIL, Ordering::Relaxed);
        return true;
      }
      previous = index;
      index = next;
    }
    false
  }

  /// Filter a stolen chain while its receiving lane is locked. An abort may
  /// have scanned that lane while the chain was detached from both queues.
  pub(super) fn extract_cleanup(
    &mut self,
    links: &(impl std::ops::Index<usize, Output = QueueLink> + ?Sized),
  ) -> Option<Chain> {
    let mut cleanup = Self::new();
    let mut index = self.head;
    while index != NIL {
      let next = links[index].next.load(Ordering::Relaxed);
      if links[index].cleanup.load(Ordering::SeqCst) {
        let removed = self.remove(links, index);
        debug_assert!(removed);
        cleanup.push(links, index);
      }
      index = next;
    }
    (cleanup.len != 0).then_some(Chain {
      first: cleanup.head,
      last: cleanup.tail,
      len: cleanup.len,
    })
  }

  /// Takes a single remaining entry or the oldest bounded half of a larger lane.
  pub(super) fn steal_front(
    &mut self,
    links: &(impl std::ops::Index<usize, Output = QueueLink> + ?Sized),
  ) -> Option<Chain> {
    if self.len == 0 {
      return None;
    }
    let len = (self.len / 2).clamp(1, STEAL_MAX);
    let first = self.head;
    let mut last = first;
    for _ in 1..len {
      last = links[last].next.load(Ordering::Relaxed);
    }
    self.head = links[last].next.load(Ordering::Relaxed);
    links[last].next.store(NIL, Ordering::Relaxed);
    self.len -= len;
    if self.len == 0 {
      self.tail = NIL;
    }
    Some(Chain { first, last, len })
  }

  pub(super) fn append_chain(
    &mut self,
    links: &(impl std::ops::Index<usize, Output = QueueLink> + ?Sized),
    chain: Chain,
  ) -> bool {
    if self.len == 0 {
      self.head = chain.first;
    } else {
      links[self.tail].next.store(chain.first, Ordering::Relaxed);
    }
    self.tail = chain.last;
    self.len += chain.len;
    self.take_notify()
  }

  // The lane mutex serializes producers and the sole dispatcher. Once a
  // notification is owed, later pushes/kicks are covered by its next search.
  fn take_notify(&mut self) -> bool {
    let notify = self.sleeping && !self.notified;
    self.notified |= notify;
    notify
  }

  pub(super) fn request_recheck(&mut self) -> bool {
    self.recheck = true;
    self.take_notify()
  }

  pub(super) fn take_recheck(&mut self) -> bool {
    std::mem::take(&mut self.recheck)
  }

  /// Called under the lane lock immediately before its condvar wait.
  pub(super) fn prepare_sleep(&mut self) -> bool {
    if self.len != 0 || self.recheck {
      return false;
    }
    self.sleeping = true;
    // Each new wait must be eligible for a notification, including a re-wait
    // under the lane lock after a wake whose work was stolen.
    self.notified = false;
    true
  }

  pub(super) fn finish_sleep(&mut self) {
    self.sleeping = false;
    self.notified = false;
  }

  pub(super) const fn len(&self) -> usize {
    self.len
  }

  #[cfg(test)]
  pub(super) fn check(
    &self,
    links: &(impl std::ops::Index<usize, Output = QueueLink> + ?Sized),
  ) -> Vec<usize> {
    let mut indices = Vec::new();
    let mut last = NIL;
    let mut index = self.head;
    while index != NIL {
      assert!(indices.len() < self.len, "cycle or incorrect length");
      indices.push(index);
      last = index;
      index = links[index].next.load(Ordering::Relaxed);
    }
    assert_eq!(indices.len(), self.len);
    assert_eq!(last, self.tail);
    indices
  }
}

#[derive(Debug)]
pub(super) struct ParkedMask {
  words: Vec<Padded<AtomicU64>>,
  dead: Vec<Padded<AtomicU64>>,
  lanes: usize,
}

impl ParkedMask {
  #[cfg(test)]
  pub(super) fn new(lanes: usize) -> Self {
    assert!(lanes > 0);
    Self {
      words: (0..lanes.div_ceil(64))
        .map(|_| Padded(AtomicU64::new(0)))
        .collect(),
      dead: (0..lanes.div_ceil(64))
        .map(|_| Padded(AtomicU64::new(0)))
        .collect(),
      lanes,
    }
  }

  pub(super) fn try_new(lanes: usize) -> Result<Self, std::collections::TryReserveError> {
    let mut words = Vec::new();
    words.try_reserve_exact(lanes.div_ceil(64))?;
    words.resize_with(lanes.div_ceil(64), || Padded(AtomicU64::new(0)));
    let mut dead = Vec::new();
    dead.try_reserve_exact(lanes.div_ceil(64))?;
    dead.resize_with(lanes.div_ceil(64), || Padded(AtomicU64::new(0)));
    Ok(Self { words, dead, lanes })
  }

  pub(super) fn capacity(&self) -> usize {
    self.words.capacity() + self.dead.capacity()
  }

  pub(super) fn advertise(&self, lane: usize) {
    self.words[lane / 64].fetch_or(1 << (lane % 64), Ordering::SeqCst);
    // Loom weakens SeqCst accesses to AcqRel. Its supported SeqCst fence
    // models the total ordering between advertising and the final rescan.
    #[cfg(loom)]
    loom::sync::atomic::fence(Ordering::SeqCst);
  }

  pub(super) fn mark_dead(&self, lane: usize) {
    self.dead[lane / 64].fetch_or(1 << (lane % 64), Ordering::SeqCst);
  }

  /// An adopted seat has a live server again. Caller serializes with its lane.
  pub(super) fn revive(&self, lane: usize) {
    self.dead[lane / 64].fetch_and(!(1 << (lane % 64)), Ordering::SeqCst);
  }

  pub(super) fn is_dead(&self, lane: usize) -> bool {
    self.dead[lane / 64].load(Ordering::SeqCst) & (1 << (lane % 64)) != 0
  }

  pub(super) fn is_set(&self, lane: usize) -> bool {
    self.is_dead(lane) || self.words[lane / 64].load(Ordering::SeqCst) & (1 << (lane % 64)) != 0
  }

  pub(super) fn claim(&self, lane: usize) -> bool {
    let bit = 1 << (lane % 64);
    self.words[lane / 64].fetch_and(!bit, Ordering::SeqCst) & bit != 0
  }

  #[cfg(test)]
  pub(super) fn claim_any(&self, start: usize) -> Option<usize> {
    // Pair the producer's length publication with its mask scan in Loom's
    // model of the SeqCst total order. Native accesses already have it.
    #[cfg(loom)]
    loom::sync::atomic::fence(Ordering::SeqCst);
    self.claim_any_with(start, |lane| self.claim(lane))
  }

  /// The callback serializes a claim with the lane sleep state.
  pub(super) fn claim_any_with(
    &self,
    start: usize,
    mut claim: impl FnMut(usize) -> bool,
  ) -> Option<usize> {
    #[cfg(loom)]
    loom::sync::atomic::fence(Ordering::SeqCst);
    // One SeqCst load of each mask word instead of per-lane loads and
    // divisions; the same candidates in the same cyclic order.
    self.cyclic_find(
      start,
      |word| {
        let dead = self.dead[word].load(Ordering::SeqCst);
        !dead & self.words[word].load(Ordering::SeqCst)
      },
      &mut claim,
    )
  }

  /// Whether any live lane is parked, one SeqCst load of each
  /// mask word pair. A parker advertises before its rescan, so a waker that
  /// published work before this load and finds no parked lane leaves the
  /// rescan to find that work.
  #[inline]
  pub(super) fn any_live_parked(&self) -> bool {
    #[cfg(loom)]
    loom::sync::atomic::fence(Ordering::SeqCst);
    (0..self.words.len()).any(|word| {
      self.words[word].load(Ordering::SeqCst) & !self.dead[word].load(Ordering::SeqCst) != 0
    })
  }

  pub(super) fn first_clear_from(&self, start: usize) -> Option<usize> {
    self.cyclic_find(
      start,
      |word| {
        let dead = self.dead[word].load(Ordering::SeqCst);
        !(dead | self.words[word].load(Ordering::SeqCst))
      },
      |_| true,
    )
  }

  /// The first live lane at or after `start`, cyclically.
  pub(super) fn first_live_from(&self, start: usize) -> Option<usize> {
    self.cyclic_find(
      start,
      |word| !self.dead[word].load(Ordering::SeqCst),
      |_| true,
    )
  }

  /// `cyclic_find` for at most 64 lanes, with the one word's
  /// candidate bits loaded once: the bits at or above the start lane first,
  /// then the wrapped low bits. No division for a single lane.
  #[inline]
  fn cyclic_find_one(
    &self,
    start: usize,
    bits: u64,
    mut accept: impl FnMut(usize) -> bool,
  ) -> Option<usize> {
    let lanes = self.lanes;
    debug_assert!((1..=64).contains(&lanes));
    let start = if lanes == 1 {
      0
    } else if start < lanes {
      start
    } else {
      start % lanes
    };
    let bits = bits & (u64::MAX >> (64 - lanes));
    let high = u64::MAX << start;
    for mut candidates in [bits & high, bits & !high] {
      while candidates != 0 {
        let lane = candidates.trailing_zeros() as usize;
        if accept(lane) {
          return Some(lane);
        }
        candidates &= candidates - 1;
      }
    }
    None
  }

  /// Visits lanes whose bit `bits(word)` sets, in cyclic order from
  /// `start % lanes`, until `accept` returns true. Each word is loaded once
  /// per visit; the start word is visited twice (high bits first, low bits
  /// last) to close the cycle.
  fn cyclic_find(
    &self,
    start: usize,
    mut bits: impl FnMut(usize) -> u64,
    mut accept: impl FnMut(usize) -> bool,
  ) -> Option<usize> {
    if self.lanes <= 64 {
      return self.cyclic_find_one(start, bits(0), accept);
    }
    let words = self.lanes.div_ceil(64);
    let start = start % self.lanes;
    let (first_word, first_bit) = (start / 64, start % 64);
    for step in 0..=words {
      let mut word = first_word + step;
      if word >= words {
        word -= words;
      }
      let mut mask = if word + 1 == words && !self.lanes.is_multiple_of(64) {
        (1u64 << (self.lanes % 64)) - 1
      } else {
        u64::MAX
      };
      if step == 0 {
        mask &= u64::MAX << first_bit;
      } else if step == words {
        mask &= (1u64 << first_bit).wrapping_sub(1);
      }
      if mask == 0 {
        continue;
      }
      let mut candidates = bits(word) & mask;
      while candidates != 0 {
        let lane = word * 64 + candidates.trailing_zeros() as usize;
        if accept(lane) {
          return Some(lane);
        }
        candidates &= candidates - 1;
      }
    }
    None
  }
}

/// Skip parked lanes using only the rotating counter value and parked state.
/// The caller advances the counter, independent of its identity. Return the
/// chosen seat and whether its parked bit was cleared by this selection.
#[inline]
pub(super) fn choose_lane(next_lane: usize, parked: &ParkedMask) -> (usize, bool) {
  // A single lane is chosen without a scan: the same result as
  // the scan (its parked bit, if set, is claimed; dead or not).
  if parked.lanes == 1 {
    return (0, parked.is_set(0) && parked.claim(0));
  }
  choose_lane_scan(next_lane, parked)
}

fn choose_lane_scan(next_lane: usize, parked: &ParkedMask) -> (usize, bool) {
  let start = next_lane % parked.lanes;
  if let Some(seat) = parked.first_clear_from(start) {
    return (seat, false);
  }
  let live = parked.first_live_from(start).unwrap_or(start);
  (live, parked.claim(live))
}

/// Test-only comparison policy that selects the next live lane without
/// skipping parked dispatchers. Return whether selection cleared its bit.
#[cfg(test)]
pub(super) fn choose_lane_round_robin(next_lane: usize, parked: &ParkedMask) -> (usize, bool) {
  let start = next_lane % parked.lanes;
  let live = (0..parked.lanes)
    .map(|offset| (start + offset) % parked.lanes)
    .find(|&lane| !parked.is_dead(lane))
    .unwrap_or(start);
  (live, parked.claim(live))
}

/// A random start followed by a complete cyclic traversal. Filtering out the
/// caller happens after choosing the start, and never ranks victims by depth.
pub(super) struct VictimOrder {
  start: usize,
  lanes: usize,
}

impl VictimOrder {
  pub(super) fn new(state: &mut u64, lanes: usize) -> Self {
    assert!(lanes > 0);
    if *state == 0 {
      *state = 0x9e37_79b9_7f4a_7c15;
    }
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    Self {
      start: (*state % lanes as u64) as usize,
      lanes,
    }
  }

  pub(super) fn victims(&self, own: usize) -> impl Iterator<Item = usize> + '_ {
    (0..self.lanes)
      .map(|offset| (self.start + offset) % self.lanes)
      .filter(move |&lane| lane != own)
  }
}

/// Construction-time admission and outstanding search notifications. The two
/// counters are separate words; neither records a dispatcher identity.
#[derive(Debug)]
pub(super) struct Searching {
  searching: Padded<AtomicUsize>,
  waking: Padded<AtomicUsize>,
  max: usize,
}

impl Searching {
  pub(super) fn new(max: usize) -> Self {
    Self {
      searching: Padded(AtomicUsize::new(0)),
      waking: Padded(AtomicUsize::new(0)),
      max,
    }
  }

  pub(super) fn try_enter(&self) -> Option<SearchGuard<'_>> {
    let mut current = self.searching.load(Ordering::SeqCst);
    loop {
      if current >= self.max {
        return None;
      }
      match self.searching.compare_exchange_weak(
        current,
        current + 1,
        Ordering::SeqCst,
        Ordering::SeqCst,
      ) {
        Ok(_) => {
          return Some(SearchGuard {
            state: self,
            active: true,
          });
        }
        Err(actual) => current = actual,
      }
    }
  }

  pub(super) fn wake_allowed(&self) -> bool {
    #[cfg(loom)]
    loom::sync::atomic::fence(Ordering::SeqCst);
    self.max != 0
      && self.searching.load(Ordering::SeqCst) == 0
      && self.waking.load(Ordering::SeqCst) == 0
  }

  pub(super) fn kicked(&self) {
    self.waking.fetch_add(1, Ordering::SeqCst);
  }

  /// Called by the receiving seat after its entry decision, or on abandonment.
  /// Return whether a denied receiver must restart. The search-count load
  /// follows the decrement, crossing a last exit that observed this receipt.
  pub(super) fn acknowledge(&self, in_search: bool) -> bool {
    let previous = self.waking.fetch_sub(1, Ordering::SeqCst);
    debug_assert_ne!(previous, 0);
    #[cfg(loom)]
    loom::sync::atomic::fence(Ordering::SeqCst);
    self.searching.load(Ordering::SeqCst) == 0 && !in_search
  }

  /// Only the post-advertisement check of whether entry could now succeed.
  fn entry_possible(&self) -> bool {
    self.searching.load(Ordering::SeqCst) < self.max
  }

  #[cfg(all(test, not(loom)))]
  pub(super) fn max_for_test(&self) -> usize {
    self.max
  }

  #[cfg(test)]
  pub(super) fn current(&self) -> usize {
    self.searching.load(Ordering::SeqCst)
  }

  #[cfg(test)]
  pub(super) fn pending(&self) -> usize {
    self.waking.load(Ordering::SeqCst)
  }
}

/// Owns exactly one successful increment, including across a spin retry.
pub(super) struct SearchGuard<'a> {
  state: &'a Searching,
  active: bool,
}

impl SearchGuard<'_> {
  /// Return whether this decrement was the last. No wake is owed by Drop.
  pub(super) fn leave(mut self) -> bool {
    self.active = false;
    self.decrement() == 1
  }

  fn decrement(&self) -> usize {
    let previous = self.state.searching.fetch_sub(1, Ordering::SeqCst);
    #[cfg(loom)]
    loom::sync::atomic::fence(Ordering::SeqCst);
    previous
  }
}

impl Drop for SearchGuard<'_> {
  fn drop(&mut self) {
    if self.active {
      self.decrement();
    }
  }
}

/// The store, if any, that publishes a lane's new queue length `len` over
/// the last published `published`. The caller holds the lane lock, so
/// `published` is the latest value. Readers that pair with parking test
/// only `!= 0`: a change between empty and non-empty is a SeqCst store, a
/// change that stays non-zero keeps the exact metric with a Relaxed store,
/// and an unchanged length stores nothing.
pub(super) const fn depth_store(published: usize, len: usize) -> Option<Ordering> {
  if (published != 0) != (len != 0) {
    Some(Ordering::SeqCst)
  } else if len != published {
    Some(Ordering::Relaxed)
  } else {
    None
  }
}

/// The final park handshake after own/steal/overflow searches
/// failed. A true result permits the caller to test `prepare_sleep` under its
/// lane lock and wait there. A false result requires a fresh full search.
/// The iterator must load SeqCst lengths lazily, after advertisement, and the
/// closure must load overflow the same way. Producers publish a length (see
/// [`depth_store`]) before claiming and kicking a sleeper. A denied
/// dispatcher may ignore other lanes only while admission is still full after
/// advertisement.
pub(super) fn search_or_park(
  seat: usize,
  parked: &ParkedMask,
  searching: &Searching,
  lane_len: impl IntoIterator<Item = (usize, usize)>,
  overflow_hint: impl FnOnce() -> usize,
  searched: bool,
) -> bool {
  parked.advertise(seat);
  // SeqCst orders the parker's ack -> advertise -> admission read against
  // the finder's searching decrement -> waking read -> parked claim. If the
  // finder exits first, available admission makes us rescan other lanes;
  // otherwise our advertisement precedes its claim (or a covering kick).
  // This read asks only whether entry could succeed, never reserves a slot.
  let entry_possible = searching.entry_possible();
  let work = lane_len
    .into_iter()
    .any(|(lane, len)| (searched || entry_possible || lane == seat) && len != 0)
    || overflow_hint() != 0;
  if work {
    let _ = parked.claim(seat);
  }
  !work
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::*;

  #[test]
  fn depth_store_is_seq_cst_only_across_empty() {
    for published in 0..4 {
      for len in 0..4 {
        let expected = if (published == 0) != (len == 0) {
          Some(Ordering::SeqCst)
        } else if published != len {
          Some(Ordering::Relaxed)
        } else {
          None
        };
        assert_eq!(
          depth_store(published, len),
          expected,
          "{published} -> {len}"
        );
      }
    }
  }

  #[test]
  fn steal_bounds_oldest_first_and_chain_links() {
    for len in 0..=STEAL_MAX * 4 {
      let links: Vec<_> = (0..=len).map(|_| QueueLink::new()).collect();
      let mut victim = LaneQueue::new();
      for index in 0..len {
        assert!(!victim.push(&links, index));
      }
      let mut thief = LaneQueue::new();
      let chain = victim.steal_front(&links);
      if len == 0 {
        assert!(chain.is_none());
        assert_eq!(victim.len(), len);
        victim.check(&links);
        continue;
      }
      let chain = chain.unwrap();
      let taken = (len / 2).clamp(1, STEAL_MAX);
      assert_eq!(chain.len, taken);
      assert_eq!(chain.first, 0);
      assert_eq!(chain.last, taken - 1);
      assert_eq!(victim.len(), len - taken);
      assert!(len == 1 || victim.len() >= 1);
      assert_eq!(victim.check(&links), (taken..len).collect::<Vec<_>>());
      // A push during the move stays ahead of the detached chain.
      thief.push(&links, len);
      assert!(!thief.append_chain(&links, chain));
      let expected: Vec<_> = std::iter::once(len).chain(0..taken).collect();
      assert_eq!(thief.check(&links), expected);
      for index in expected {
        assert_eq!(thief.pop(&links), Some(index));
        assert_eq!(links[index].next.load(Ordering::Relaxed), NIL);
        assert_eq!(links[index].prev.load(Ordering::Relaxed), NIL);
        thief.check(&links);
      }
      assert_eq!(thief.pop(&links), None);
    }
  }

  #[test]
  fn append_to_empty_and_park_recheck() {
    let links = [QueueLink::new(), QueueLink::new()];
    let mut victim = LaneQueue::new();
    victim.push(&links, 0);
    victim.push(&links, 1);
    let mut queue = LaneQueue::new();
    assert!(queue.prepare_sleep());
    assert!(queue.append_chain(&links, victim.steal_front(&links).unwrap()));
    queue.finish_sleep();
    assert!(!queue.prepare_sleep());
    assert_eq!(queue.pop(&links), Some(0));
    assert!(!queue.request_recheck());
    assert!(!queue.prepare_sleep());
    assert!(queue.take_recheck());
    assert!(!queue.take_recheck());
    assert!(queue.prepare_sleep());
    assert!(queue.request_recheck());
    queue.finish_sleep();
  }

  #[test]
  fn empty_rewait_and_search_allow_a_fresh_notification() {
    let links = [QueueLink::new()];
    let mut queue = LaneQueue::new();
    assert!(queue.prepare_sleep());
    assert!(queue.push(&links, 0));
    assert!(!queue.request_recheck());
    // A thief can consume all work before the dispatcher reacquires its lock.
    assert!(queue.steal_front(&links).is_some());
    assert!(queue.take_recheck());
    // Rearm under the lock, as in a condvar predicate loop with no intervening
    // search. The old notification must not suppress the next producer.
    assert!(queue.prepare_sleep());
    assert!(queue.push(&links, 0));
    assert!(!queue.request_recheck());
    queue.finish_sleep();
    assert!(!queue.notified);
    assert_eq!(queue.pop(&links), Some(0));
    assert!(queue.take_recheck());
    assert!(queue.prepare_sleep());
    assert!(queue.request_recheck());
    queue.finish_sleep();
  }

  #[test]
  fn parked_mask_spans_words_claims_once_and_wraps() {
    let mask = ParkedMask::new(130);
    assert_eq!(mask.claim_any(usize::MAX), None);
    for lane in 0..130 {
      mask.advertise(lane);
      assert!(mask.is_set(lane));
    }
    assert_eq!(mask.first_clear_from(65), None);
    assert!(mask.claim(64));
    assert!(!mask.claim(64));
    assert_eq!(mask.first_clear_from(65), Some(64));
    assert_eq!(mask.claim_any(129), Some(129));
    assert_eq!(mask.claim_any(129), Some(0));
    assert_eq!(mask.claim_any(63), Some(63));
    for lane in 0..130 {
      let _ = mask.claim(lane);
    }
    assert_eq!(mask.claim_any(0), None);
  }

  #[test]
  fn lane_choice_uses_only_counter_and_parked_state() {
    let mask = ParkedMask::new(3);
    for counter in 0..12 {
      assert_eq!(choose_lane(counter, &mask), (counter % 3, false));
    }
    mask.advertise(1);
    assert_eq!(choose_lane(1, &mask), (2, false));
    assert!(mask.is_set(1));
    assert_eq!(choose_lane_round_robin(1, &mask), (1, true));
    assert_eq!(choose_lane_round_robin(1, &mask), (1, false));
    for lane in 0..3 {
      mask.advertise(lane);
    }
    assert_eq!(choose_lane(4, &mask), (1, true));
    assert!(!mask.is_set(1));
    assert_eq!(choose_lane(4, &mask), (1, false));
  }

  #[test]
  fn lane_choice_is_independent_of_calling_thread() {
    let sequence = || {
      let mask = ParkedMask::new(4);
      mask.advertise(1);
      mask.advertise(3);
      (0..32)
        .map(|counter| choose_lane(counter, &mask))
        .collect::<Vec<_>>()
    };
    let expected = sequence();
    let first = std::thread::spawn(sequence);
    let second = std::thread::spawn(sequence);
    assert_eq!(first.join().unwrap(), expected);
    assert_eq!(second.join().unwrap(), expected);
  }

  #[test]
  fn victim_order_covers_every_other_lane_once() {
    let mut state = 0;
    let mut starts = std::collections::BTreeSet::new();
    for lanes in 1..=130 {
      for own in 0..lanes {
        let order = VictimOrder::new(&mut state, lanes);
        let victims: Vec<_> = order.victims(own).collect();
        assert_eq!(victims.len(), lanes - 1);
        assert!(!victims.contains(&own));
        let mut sorted = victims;
        sorted.sort_unstable();
        assert_eq!(
          sorted,
          (0..lanes).filter(|&lane| lane != own).collect::<Vec<_>>()
        );
        starts.insert(order.start);
      }
    }
    assert!(starts.len() > 1);
    let mut first = 42;
    let mut second = 42;
    assert_eq!(
      VictimOrder::new(&mut first, 8).start,
      VictimOrder::new(&mut second, 8).start
    );
  }

  #[test]
  fn searching_caps_entry_and_releases_during_unwind() {
    let state = Searching::new(2);
    let first = state.try_enter().unwrap();
    assert!(
      std::panic::catch_unwind(|| {
        let _second = state.try_enter().unwrap();
        assert!(state.try_enter().is_none());
        panic!("injected search unwind");
      })
      .is_err()
    );
    assert_eq!(state.current(), 1);
    assert!(first.leave());
    assert_eq!(state.current(), 0);
    assert!(state.wake_allowed());
  }

  #[test]
  fn park_rescan_ignores_other_lanes_only_while_steal_is_denied() {
    let mask = ParkedMask::new(2);
    let lengths = [AtomicUsize::new(0), AtomicUsize::new(1)];
    let searching = Searching::new(1);
    let guard = searching.try_enter().unwrap();
    let rescan = |searched: bool, overflow: usize| {
      search_or_park(
        0,
        &mask,
        &searching,
        lengths
          .iter()
          .enumerate()
          .map(|(lane, len)| (lane, len.load(Ordering::SeqCst))),
        || overflow,
        searched,
      )
    };
    assert!(!rescan(true, 0));
    assert!(!mask.is_set(0));
    assert!(rescan(false, 0));
    assert!(mask.claim(0));
    assert!(!rescan(false, 1));
    assert!(!mask.is_set(0));
    drop(guard);
    // The prior denial no longer permits sleep beside another lane's work.
    assert!(!rescan(false, 0));
    assert!(!mask.is_set(0));
    let guard = searching.try_enter().unwrap();
    // If a competitor fills the slot before our retry, it covers that work.
    assert!(searching.try_enter().is_none());
    assert!(rescan(false, 0));
    assert!(mask.claim(0));
    drop(guard);
  }

  #[test]
  fn park_rescans_stealable_lanes_and_overflow() {
    let mask = ParkedMask::new(2);
    let lengths = [AtomicUsize::new(0), AtomicUsize::new(0)];
    let overflow = AtomicUsize::new(0);
    assert!(search_or_park(
      0,
      &mask,
      &Searching::new(1),
      lengths
        .iter()
        .enumerate()
        .map(|(lane, len)| (lane, len.load(Ordering::SeqCst))),
      || overflow.load(Ordering::SeqCst),
      true,
    ));
    assert!(mask.claim(0));
    lengths[1].store(1, Ordering::SeqCst);
    assert!(!search_or_park(
      0,
      &mask,
      &Searching::new(1),
      lengths
        .iter()
        .enumerate()
        .map(|(lane, len)| (lane, len.load(Ordering::SeqCst))),
      || overflow.load(Ordering::SeqCst),
      true,
    ));
    assert!(!mask.is_set(0));
    lengths[1].store(0, Ordering::SeqCst);
    overflow.store(1, Ordering::SeqCst);
    assert!(!search_or_park(
      0,
      &mask,
      &Searching::new(1),
      lengths
        .iter()
        .enumerate()
        .map(|(lane, len)| (lane, len.load(Ordering::SeqCst))),
      || overflow.load(Ordering::SeqCst),
      true,
    ));
  }
}

#[cfg(all(test, loom))]
mod loom_tests {
  use loom::sync::{Arc, Condvar, Mutex};
  use loom::thread;

  use super::*;

  fn bounded_model(check: impl Fn() + Sync + Send + 'static) {
    let mut model = loom::model::Builder::new();
    model.max_permutations = Some(10_000);
    model.check(check);
  }

  #[test]
  fn loom_lane_push_pop_park_progress() {
    bounded_model(|| {
      let links = Arc::new((0..4).map(|_| QueueLink::new()).collect::<Vec<_>>());
      let lane = Arc::new((Mutex::new(LaneQueue::new()), Condvar::new()));
      let owner = {
        let links = Arc::clone(&links);
        let lane = Arc::clone(&lane);
        thread::spawn(move || {
          let mut popped = Vec::new();
          while popped.len() < 4 {
            {
              let mut queue = lane.0.lock().unwrap();
              queue.check(&links[..]);
              if let Some(index) = queue.pop(&links[..]) {
                popped.push(index);
                continue;
              }
              if queue.take_recheck() {
                continue;
              }
            }
            // A push or kick may arrive between the own-lane search and
            // the final decision to sleep under the lane lock.
            let mut queue = lane.0.lock().unwrap();
            if queue.prepare_sleep() {
              assert_eq!(queue.len(), 0);
              assert!(!queue.recheck);
              queue = lane.1.wait(queue).unwrap();
              queue.finish_sleep();
            }
          }
          popped
        })
      };
      let pushers: Vec<_> = [0, 2]
        .into_iter()
        .map(|first| {
          let links = Arc::clone(&links);
          let lane = Arc::clone(&lane);
          thread::spawn(move || {
            for index in first..first + 2 {
              let notify = {
                let mut queue = lane.0.lock().unwrap();
                let notify = queue.push(&links[..], index);
                queue.check(&links[..]);
                notify
              };
              if notify {
                lane.1.notify_one();
              }
            }
          })
        })
        .collect();
      let kicker = {
        let lane = Arc::clone(&lane);
        thread::spawn(move || {
          let notify = lane.0.lock().unwrap().request_recheck();
          if notify {
            lane.1.notify_one();
          }
        })
      };
      for pusher in pushers {
        pusher.join().unwrap();
      }
      kicker.join().unwrap();
      let popped = owner.join().unwrap();
      for first in [0, 2] {
        assert_eq!(
          popped
            .iter()
            .copied()
            .filter(|&i| i / 2 == first / 2)
            .collect::<Vec<_>>(),
          [first, first + 1]
        );
      }
      assert!(lane.0.lock().unwrap().check(&links[..]).is_empty());
    });
  }

  #[test]
  fn loom_lane_empty_rewait_does_not_lose_push_notification() {
    loom::model(|| {
      let links = Arc::new([QueueLink::new()]);
      let mut queue = LaneQueue::new();
      assert!(queue.prepare_sleep());
      assert!(queue.push(&links[..], 0));
      // The dispatcher has consumed its notification, but a thief removed
      // the entry. Re-wait while retaining the lane lock and sleeping state.
      assert!(queue.steal_front(&links[..]).is_some());
      let lane = Arc::new((Mutex::new(queue), Condvar::new()));
      let owner = {
        let lane = Arc::clone(&lane);
        let links = Arc::clone(&links);
        thread::spawn(move || {
          let mut queue = lane.0.lock().unwrap();
          while queue.len() == 0 {
            assert!(queue.prepare_sleep());
            queue = lane.1.wait(queue).unwrap();
          }
          queue.finish_sleep();
          assert!(!queue.notified);
          assert_eq!(queue.pop(&links[..]), Some(0));
        })
      };
      let producer = {
        let lane = Arc::clone(&lane);
        thread::spawn(move || {
          let mut queue = lane.0.lock().unwrap();
          let notify = queue.push(&links[..], 0);
          // A kick and a push share the same outstanding notification.
          assert!(!queue.request_recheck());
          drop(queue);
          if notify {
            lane.1.notify_one();
          }
        })
      };
      producer.join().unwrap();
      owner.join().unwrap();
      assert!(lane.0.lock().unwrap().take_recheck());
    });
  }

  #[test]
  fn loom_steal_races_owner_pop() {
    for count in [1, 2, 3, 4] {
      loom::model(move || {
        let links = Arc::new((0..=count).map(|_| QueueLink::new()).collect::<Vec<_>>());
        let mut initial = LaneQueue::new();
        for index in 0..count {
          initial.push(&links[..], index);
        }
        let victim = Arc::new(Mutex::new(initial));
        let owner = {
          let links = Arc::clone(&links);
          let victim = Arc::clone(&victim);
          thread::spawn(move || {
            let mut popped = Vec::new();
            for _ in 0..count {
              let mut queue = victim.lock().unwrap();
              if let Some(index) = queue.pop(&links[..]) {
                popped.push(index);
              }
              queue.check(&links[..]);
            }
            popped
          })
        };
        let thief = {
          let links = Arc::clone(&links);
          let victim = Arc::clone(&victim);
          thread::spawn(move || {
            let stolen = {
              let mut queue = victim.lock().unwrap();
              let before = queue.check(&links[..]);
              queue.steal_front(&links[..]).map(|chain| {
                assert!(before.len() == 1 || queue.len() >= 1);
                assert_eq!(chain.len, (before.len() / 2).clamp(1, STEAL_MAX));
                assert_eq!(chain.first, before[0]);
                assert_eq!(chain.last, before[chain.len - 1]);
                queue.check(&links[..]);
                let expected = before[..chain.len].to_vec();
                (chain, expected)
              })
            };
            // A lone stolen entry is dispatched directly; a larger chain is
            // appended to the receiving lane only after releasing the victim.
            let mut popped = Vec::new();
            let own = Mutex::new(LaneQueue::new());
            let mut own = own.lock().unwrap();
            own.push(&links[..], count);
            let mut expected = vec![count];
            if let Some((chain, indices)) = stolen {
              match chain.into_single() {
                Ok(index) => {
                  assert_eq!(indices, [index]);
                  popped.push(index);
                }
                Err(chain) => {
                  expected.extend(indices);
                  own.append_chain(&links[..], chain);
                }
              }
            }
            assert_eq!(own.check(&links[..]), expected);
            let direct = popped.len();
            while let Some(index) = own.pop(&links[..]) {
              popped.push(index);
              own.check(&links[..]);
            }
            assert_eq!(popped[direct..], expected);
            popped
          })
        };
        let mut popped = owner.join().unwrap();
        popped.extend(thief.join().unwrap());
        popped.sort_unstable();
        assert_eq!(popped, (0..=count).collect::<Vec<_>>());
        assert!(victim.lock().unwrap().check(&links[..]).is_empty());
      });
    }
  }

  /// Keep the final sleep decision observable rather than actually waiting:
  /// an invalid decision fails an assertion instead of hanging the model.
  fn steal_push_park(other_parked: bool, initial_entry: bool) {
    let links = Arc::new([QueueLink::new(), QueueLink::new()]);
    let mut initial = LaneQueue::new();
    if initial_entry {
      initial.push(&links[..], 0);
    }
    let victim = Arc::new(Mutex::new(initial));
    let sleeper = Arc::new(Mutex::new(LaneQueue::new()));
    let other = Arc::new(Mutex::new(LaneQueue::new()));
    let parked = Arc::new(ParkedMask::new(3));
    if other_parked {
      parked.advertise(2);
      assert!(other.lock().unwrap().prepare_sleep());
    }
    let lengths = Arc::new([
      AtomicUsize::new(0),
      AtomicUsize::new(usize::from(initial_entry)),
      AtomicUsize::new(0),
    ]);
    let kick = Arc::new(Mutex::new(None));
    let dispatched = Arc::new(Mutex::new(Vec::new()));
    let searcher = {
      let (links, victim, sleeper, parked, lengths, other, dispatched) = (
        Arc::clone(&links),
        Arc::clone(&victim),
        Arc::clone(&sleeper),
        Arc::clone(&parked),
        Arc::clone(&lengths),
        Arc::clone(&other),
        Arc::clone(&dispatched),
      );
      thread::spawn(move || {
        let (chain, remains, before) = {
          let mut queue = victim.lock().unwrap();
          let before = queue.len();
          let chain = queue.steal_front(&links[..]);
          if let Some(chain) = &chain {
            assert!(before == 1 || queue.len() >= 1);
            assert_eq!(chain.len, (before / 2).clamp(1, STEAL_MAX));
          }
          lengths[1].store(queue.len(), Ordering::SeqCst);
          queue.check(&links[..]);
          (chain, queue.len() != 0, before)
        };
        if let Some(chain) = chain {
          let kicked = if remains {
            parked.claim_any(2).map(|seat| {
              assert_eq!(seat, 2);
              let mut queue = other.lock().unwrap();
              let notify = queue.request_recheck();
              assert!(notify || queue.notified);
              seat
            })
          } else {
            None
          };
          assert!(
            before != 1 || kicked.is_none(),
            "last-entry steal woke a holder"
          );
          // Victims here hold at most two entries, so every steal takes one
          // entry, which bypasses the receiving lane for direct dispatch.
          let index = chain.into_single().unwrap();
          dispatched.lock().unwrap().push(index);
          return false;
        }
        if search_or_park(
          0,
          &parked,
          &Searching::new(1),
          lengths
            .iter()
            .enumerate()
            .map(|(lane, len)| (lane, len.load(Ordering::SeqCst))),
          || 0,
          true,
        ) {
          sleeper.lock().unwrap().prepare_sleep()
        } else {
          false
        }
      })
    };
    let pusher = {
      let (links, victim, sleeper, parked, lengths, kick, other) = (
        Arc::clone(&links),
        Arc::clone(&victim),
        Arc::clone(&sleeper),
        Arc::clone(&parked),
        Arc::clone(&lengths),
        Arc::clone(&kick),
        Arc::clone(&other),
      );
      thread::spawn(move || {
        let remains = {
          let mut queue = victim.lock().unwrap();
          queue.push(&links[..], 1);
          lengths[1].store(queue.len(), Ordering::SeqCst);
          queue.check(&links[..]);
          queue.len() != 0
        };
        if remains && let Some(seat) = parked.claim_any(if other_parked { 2 } else { 0 }) {
          assert!(seat == 0 || (other_parked && seat == 2));
          // A claimed holder gets a recheck even before it enters wait.
          let holder = if seat == 0 { &sleeper } else { &other };
          let mut queue = holder.lock().unwrap();
          let notify = queue.request_recheck();
          // A prior kick may already cover this sleeping holder.
          let covered = notify || queue.notified;
          *kick.lock().unwrap() = Some((seat, covered));
        }
      })
    };
    let asleep = searcher.join().unwrap();
    pusher.join().unwrap();
    let kick = *kick.lock().unwrap();
    assert!(
      !asleep || lengths[1].load(Ordering::SeqCst) == 0 || kick.is_some(),
      "parked with stealable work and no kick"
    );
    if let Some((seat, covered)) = kick {
      // A kick before the final lane check must prevent sleep; a later
      // kick must have sent a notification or be covered by an earlier one.
      assert!(
        (seat == 0 && !asleep) || covered,
        "holder slept without a covering notification"
      );
    }
    let mut popped = dispatched.lock().unwrap().clone();
    for queue in [&victim, &sleeper] {
      let mut queue = queue.lock().unwrap();
      queue.finish_sleep();
      while let Some(index) = queue.pop(&links[..]) {
        popped.push(index);
      }
      queue.check(&links[..]);
    }
    popped.sort_unstable();
    assert_eq!(popped, if initial_entry { vec![0, 1] } else { vec![1] });
  }

  #[test]
  fn loom_steal_push_park_has_a_searcher_or_kick() {
    for initial_entry in [false, true] {
      loom::model(move || steal_push_park(false, initial_entry));
    }
  }

  #[test]
  fn loom_work_remains_may_wake_another_parked_holder() {
    for initial_entry in [false, true] {
      loom::model(move || steal_push_park(true, initial_entry));
    }
  }

  /// Publishes `queue`'s length the way the scheduler does under the lane
  /// lock.
  fn publish(depth: &AtomicUsize, queue: &LaneQueue) {
    if let Some(order) = depth_store(depth.load(Ordering::Relaxed), queue.len()) {
      depth.store(queue.len(), order);
    }
  }

  /// Lane 1 is shared by `producers` (each pushes one entry and then runs the
  /// parked-lane check and the claim scan of a search wake) and, when `pop`
  /// is set, an owner that pops one entry. The dispatcher on seat 0 reads the
  /// published depth before each steal attempt, then advertises and rescans
  /// it before sleeping. Pushes onto a non-empty lane and pops that leave it
  /// non-empty publish with Relaxed stores; the dispatcher may sleep only on
  /// an empty lane or with a covering kick, and the final depth is exact.
  /// Loom models the SeqCst order through the fences beside advertisement
  /// and the parked-lane checks, so this checks which publications may be
  /// skipped or Relaxed rather than the native store ordering itself.
  fn depth_publication_park(initial: usize, producers: usize, pop: bool) {
    let mut model = loom::model::Builder::new();
    model.preemption_bound = Some(3);
    model.check(move || {
      let entries = initial + producers;
      let links = Arc::new((0..entries).map(|_| QueueLink::new()).collect::<Vec<_>>());
      let mut queue = LaneQueue::new();
      for index in 0..initial {
        queue.push(&links[..], index);
      }
      let depth = Arc::new(AtomicUsize::new(queue.len()));
      let lane = Arc::new(Mutex::new(queue));
      let sleeper = Arc::new(Mutex::new(LaneQueue::new()));
      let parked = Arc::new(ParkedMask::new(2));
      let kick = Arc::new(Mutex::new(None));
      let mut threads: Vec<_> = (initial..entries)
        .map(|index| {
          let (links, lane, depth, sleeper, parked, kick) = (
            Arc::clone(&links),
            Arc::clone(&lane),
            Arc::clone(&depth),
            Arc::clone(&sleeper),
            Arc::clone(&parked),
            Arc::clone(&kick),
          );
          thread::spawn(move || {
            let remains = {
              let mut queue = lane.lock().unwrap();
              queue.push(&links[..], index);
              publish(&depth, &queue);
              queue.len() != 0
            };
            if remains
              && parked.any_live_parked()
              && let Some(seat) = parked.claim_any(0)
            {
              assert_eq!(seat, 0);
              let mut queue = sleeper.lock().unwrap();
              let covered = queue.request_recheck() || queue.notified;
              *kick.lock().unwrap() = Some(covered);
            }
            Vec::new()
          })
        })
        .collect();
      if pop {
        let (links, lane, depth) = (Arc::clone(&links), Arc::clone(&lane), Arc::clone(&depth));
        threads.push(thread::spawn(move || {
          let mut queue = lane.lock().unwrap();
          let popped = queue.pop(&links[..]);
          publish(&depth, &queue);
          popped.into_iter().collect()
        }));
      }
      let mut taken = Vec::new();
      let asleep = loop {
        // The steal pre-check skips a lane whose published depth is zero.
        if depth.load(Ordering::SeqCst) != 0 {
          let chain = {
            let mut queue = lane.lock().unwrap();
            let chain = queue.steal_front(&links[..]);
            publish(&depth, &queue);
            chain
          };
          if let Some(chain) = chain {
            taken.push(chain.into_single().unwrap());
            continue;
          }
        }
        break search_or_park(
          0,
          &parked,
          &Searching::new(1),
          std::iter::once((0, 0)).chain(std::iter::once_with(|| (1, depth.load(Ordering::SeqCst)))),
          || 0,
          true,
        ) && sleeper.lock().unwrap().prepare_sleep();
      };
      for thread in threads {
        taken.extend(thread.join().unwrap());
      }
      let mut queue = lane.lock().unwrap();
      let remaining = queue.len();
      assert_eq!(depth.load(Ordering::SeqCst), remaining, "inexact depth");
      assert!(
        !asleep || remaining == 0 || kick.lock().unwrap().is_some_and(|covered| covered),
        "slept beside a non-empty lane without a covering kick"
      );
      while let Some(index) = queue.pop(&links[..]) {
        taken.push(index);
      }
      taken.sort_unstable();
      assert_eq!(taken, (0..entries).collect::<Vec<_>>());
    });
  }

  #[test]
  fn loom_depth_publication_push_and_pop_race_a_parking_dispatcher() {
    for initial in [0, 1] {
      depth_publication_park(initial, 1, true);
    }
  }

  #[test]
  fn loom_depth_publication_two_producers_race_a_stealing_parker() {
    depth_publication_park(0, 2, false);
  }

  /// One busy owner keeps an entry queued. The last finder is about to run
  /// another entry; a woken dispatcher races that exit and a new producer.
  fn denied_woken_last_exit_and_producer(cap: usize) {
    let mut model = loom::model::Builder::new();
    model.preemption_bound = Some(3);
    model.check(move || {
      let searching = Arc::new(Searching::new(cap));
      // One seat per searcher, plus the denied seat and a busy owner.
      let parked = Arc::new(ParkedMask::new(cap + 2));
      let sleeper = Arc::new(Mutex::new(LaneQueue::new()));
      let depth = Arc::new(AtomicUsize::new(1));
      // Own-lane pop has taken an earlier receipt; entry is still pending.
      searching.kicked();
      let exiting = Arc::new(AtomicBool::new(false));
      let wake = {
        let (searching, parked, sleeper) = (
          Arc::clone(&searching),
          Arc::clone(&parked),
          Arc::clone(&sleeper),
        );
        move || {
          if searching.wake_allowed() {
            parked.claim_any_with(0, |seat| {
              assert_eq!(seat, 0);
              let mut queue = sleeper.lock().unwrap();
              if !parked.claim(seat) {
                return false;
              }
              searching.kicked();
              assert!(!queue.search_kick);
              queue.search_kick = true;
              queue.request_recheck();
              true
            });
          }
        }
      };
      let last = {
        let (searching, depth, wake, exiting) = (
          Arc::clone(&searching),
          Arc::clone(&depth),
          wake.clone(),
          Arc::clone(&exiting),
        );
        thread::spawn(move || {
          let mut guards: Vec<_> = (0..cap).map(|_| searching.try_enter().unwrap()).collect();
          exiting.store(true, Ordering::SeqCst);
          while guards.len() > 1 {
            drop(guards.pop());
          }
          if guards.pop().unwrap().leave() && depth.load(Ordering::SeqCst) != 0 {
            wake();
          }
        })
      };
      // Wait only for initial occupancy, before racing the final exit.
      while !exiting.load(Ordering::SeqCst) {
        thread::yield_now();
      }
      let producer = {
        let (depth, wake) = (Arc::clone(&depth), wake.clone());
        thread::spawn(move || {
          depth.fetch_add(1, Ordering::SeqCst);
          wake();
        })
      };
      let mut guard = searching.try_enter();
      let restart = searching.acknowledge(guard.is_some());
      if restart {
        guard = searching.try_enter();
        assert!(guard.is_some());
      }
      let asleep = if let Some(guard) = guard {
        depth.swap(0, Ordering::SeqCst);
        if guard.leave() && depth.load(Ordering::SeqCst) != 0 {
          wake();
        }
        false
      } else {
        let mut queue = sleeper.lock().unwrap();
        if queue.search_kick {
          false
        } else {
          search_or_park(
            0,
            &parked,
            &searching,
            std::iter::once((0, 0))
              .chain(std::iter::once_with(|| (1, depth.load(Ordering::SeqCst)))),
            || 0,
            false,
          ) && queue.prepare_sleep()
        }
      };
      last.join().unwrap();
      producer.join().unwrap();
      let queue = sleeper.lock().unwrap();
      assert!(
        !asleep || depth.load(Ordering::SeqCst) == 0 || queue.search_kick,
        "denied woken dispatcher slept beside queued work without a search kick"
      );
    });
  }

  #[test]
  fn loom_denied_woken_last_exit_and_producer_cap_one() {
    denied_woken_last_exit_and_producer(1);
  }

  #[test]
  fn loom_denied_woken_last_exit_and_producer_cap_two() {
    denied_woken_last_exit_and_producer(2);
  }

  #[test]
  fn loom_woken_ack_crossing_last_exit_requires_restart() {
    for cap in [1, 2] {
      loom::model(move || {
        let searching = Arc::new(Searching::new(cap));
        let mut guards: Vec<_> = (0..cap).map(|_| searching.try_enter().unwrap()).collect();
        searching.kicked();
        // A woken receiver makes its own entry decision and is denied.
        assert!(searching.try_enter().is_none());
        let depth = Arc::new(AtomicUsize::new(0));
        let producer = {
          let (searching, depth) = (Arc::clone(&searching), Arc::clone(&depth));
          thread::spawn(move || {
            depth.store(1, Ordering::SeqCst);
            assert!(!searching.wake_allowed());
          })
        };
        producer.join().unwrap();
        while guards.len() > 1 {
          drop(guards.pop());
        }
        assert!(guards.pop().unwrap().leave());
        assert_eq!(searching.current(), 0);
        // Last exit cannot kick: the old receipt is still outstanding.
        assert!(!searching.wake_allowed());
        let restart = searching.acknowledge(false);
        assert_eq!(searching.pending(), 0);
        assert!(
          restart,
          "last exit left work to a denied receiver that did not restart"
        );
        let guard = searching.try_enter().unwrap();
        assert_eq!(depth.swap(0, Ordering::SeqCst), 1);
        assert!(guard.leave());
      });
    }
  }

  #[test]
  fn loom_woken_own_pop_crosses_last_exit_and_suppressed_producer() {
    bounded_model(|| {
      let searching = Arc::new(Searching::new(1));
      let parked = Arc::new(ParkedMask::new(3));
      let sleeper = Arc::new(Mutex::new(LaneQueue::new()));
      parked.advertise(2);
      assert!(sleeper.lock().unwrap().prepare_sleep());
      let depth = Arc::new(AtomicUsize::new(0));
      // Seat 1 has already received a kick and will pop its own entry.
      searching.kicked();
      let last = searching.try_enter().unwrap();
      let wake = {
        let (searching, parked, sleeper) = (
          Arc::clone(&searching),
          Arc::clone(&parked),
          Arc::clone(&sleeper),
        );
        move || {
          if searching.wake_allowed() {
            parked.claim_any_with(0, |seat| {
              assert_eq!(seat, 2);
              let mut queue = sleeper.lock().unwrap();
              if !parked.claim(seat) {
                return false;
              }
              searching.kicked();
              assert!(!queue.search_kick);
              queue.search_kick = true;
              queue.request_recheck();
              true
            });
          }
        }
      };
      let producer = {
        let (searching, depth) = (Arc::clone(&searching), Arc::clone(&depth));
        thread::spawn(move || {
          depth.store(1, Ordering::SeqCst);
          // The outstanding receipt suppresses this producer even if the
          // last searcher has already left.
          assert!(!searching.wake_allowed());
        })
      };
      producer.join().unwrap();
      let receiver = {
        let (searching, depth, wake) = (Arc::clone(&searching), Arc::clone(&depth), wake.clone());
        thread::spawn(move || {
          let links = [QueueLink::new()];
          let mut own = LaneQueue::new();
          own.search_kick = true;
          own.push(&links[..], 0);
          assert_eq!(own.pop(&links[..]), Some(0));
          let woken = std::mem::take(&mut own.search_kick);
          let uncovered = woken && searching.acknowledge(false);
          if uncovered && depth.load(Ordering::SeqCst) != 0 {
            wake();
          }
        })
      };
      if last.leave() && depth.load(Ordering::SeqCst) != 0 {
        wake();
      }
      receiver.join().unwrap();
      assert_eq!(searching.current(), 0);
      assert_eq!(depth.load(Ordering::SeqCst), 1);
      assert!(sleeper.lock().unwrap().search_kick);
      assert_eq!(searching.pending(), 1);
    });
  }

  #[test]
  fn target_and_victim_choices_use_only_policy_inputs() {
    bounded_model(|| {
      let parked = ParkedMask::new(3);
      parked.advertise(1);
      assert_eq!(choose_lane(1, &parked), (2, false));
      parked.advertise(0);
      parked.advertise(2);
      assert_eq!(choose_lane(1, &parked), (1, true));
      parked.advertise(1);
      assert_eq!(choose_lane_round_robin(1, &parked), (1, true));
      let mut state = 7;
      let order = VictimOrder::new(&mut state, 3);
      for own in 0..3 {
        let mut victims: Vec<_> = order.victims(own).collect();
        victims.sort_unstable();
        assert_eq!(
          victims,
          (0..3).filter(|&lane| lane != own).collect::<Vec<_>>()
        );
      }
    });
  }

  #[test]
  fn parked_claims_by_concurrent_wakers_are_distinct() {
    bounded_model(|| {
      let parked = Arc::new(ParkedMask::new(2));
      parked.advertise(0);
      parked.advertise(1);
      let first = {
        let parked = Arc::clone(&parked);
        thread::spawn(move || parked.claim_any(0).unwrap())
      };
      let second = {
        let parked = Arc::clone(&parked);
        thread::spawn(move || parked.claim_any(0).unwrap())
      };
      assert_ne!(first.join().unwrap(), second.join().unwrap());
      assert_eq!(parked.claim_any(0), None);
    });
  }
}

#[cfg(all(test, not(loom)))]
mod cyclic_scan_tests {
  use super::*;

  #[test]
  fn cyclic_find_matches_per_lane_scan() {
    let mut seed = 0x1234_5678_9abc_def1u64;
    let mut next = || {
      seed ^= seed << 13;
      seed ^= seed >> 7;
      seed ^= seed << 17;
      seed
    };
    for lanes in [1usize, 2, 3, 7, 8, 63, 64, 65, 127, 128, 130] {
      for _ in 0..200 {
        let mask = ParkedMask::new(lanes);
        for lane in 0..lanes {
          if next() % 3 == 0 {
            mask.advertise(lane);
          }
          if next() % 7 == 0 {
            mask.mark_dead(lane);
          }
        }
        for start in 0..(2 * lanes + 3) {
          let clear = (0..lanes)
            .map(|offset| (start % lanes + offset) % lanes)
            .find(|&lane| !mask.is_set(lane));
          assert_eq!(mask.first_clear_from(start), clear, "clear {lanes} {start}");
          let live = (0..lanes)
            .map(|offset| (start % lanes + offset) % lanes)
            .find(|&lane| !mask.is_dead(lane));
          assert_eq!(mask.first_live_from(start), live, "live {lanes} {start}");
          let mut seen = Vec::new();
          let _ = mask.claim_any_with(start, |lane| {
            seen.push(lane);
            false
          });
          let expected: Vec<_> = (0..lanes)
            .map(|offset| (start % lanes + offset) % lanes)
            .filter(|&lane| !mask.is_dead(lane) && mask.is_set(lane))
            .collect();
          assert_eq!(seen, expected, "claim order {lanes} {start}");
        }
      }
    }
  }
}
