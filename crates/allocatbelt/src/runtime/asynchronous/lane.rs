//! Intrusive FIFO lanes and the search-to-park handshake. A queue's lock owns
//! its links; detached chains belong to their mover until appended under the
//! receiving lock. Lane locks are leaves: cut, unlock, then append.

#![forbid(unsafe_code)]

#[cfg(loom)]
use loom::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

pub(super) const NIL: usize = usize::MAX;
pub(super) const STEAL_MAX: usize = 32;
// Build-time comparison knob; ordinary placement skips parked lanes.
pub(super) const ROUND_ROBIN_PLACEMENT: bool = false;

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

#[derive(Debug)]
pub(super) struct LaneQueue {
  head: usize,
  tail: usize,
  len: usize,
  sleeping: bool,
  recheck: bool,
}

impl LaneQueue {
  pub(super) const fn new() -> Self {
    Self {
      head: NIL,
      tail: NIL,
      len: 0,
      sleeping: false,
      recheck: false,
    }
  }

  pub(super) fn push(&mut self, links: &[QueueLink], index: usize) -> bool {
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

  pub(super) fn pop(&mut self, links: &[QueueLink]) -> Option<usize> {
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
  pub(super) fn remove(&mut self, links: &[QueueLink], target: usize) -> bool {
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
  pub(super) fn extract_cleanup(&mut self, links: &[QueueLink]) -> Option<Chain> {
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

  /// Takes the oldest bounded half, always leaving the victim an entry.
  pub(super) fn steal_front(&mut self, links: &[QueueLink]) -> Option<Chain> {
    if self.len < 2 {
      return None;
    }
    let len = (self.len / 2).min(STEAL_MAX);
    let first = self.head;
    let mut last = first;
    for _ in 1..len {
      last = links[last].next.load(Ordering::Relaxed);
    }
    self.head = links[last].next.load(Ordering::Relaxed);
    links[last].next.store(NIL, Ordering::Relaxed);
    self.len -= len;
    Some(Chain { first, last, len })
  }

  pub(super) fn append_chain(&mut self, links: &[QueueLink], chain: Chain) -> bool {
    if self.len == 0 {
      self.head = chain.first;
    } else {
      links[self.tail].next.store(chain.first, Ordering::Relaxed);
    }
    self.tail = chain.last;
    self.len += chain.len;
    self.sleeping
  }

  pub(super) fn request_recheck(&mut self) -> bool {
    self.recheck = true;
    self.sleeping
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
    true
  }

  pub(super) fn finish_sleep(&mut self) {
    self.sleeping = false;
  }

  pub(super) const fn len(&self) -> usize {
    self.len
  }

  #[cfg(test)]
  pub(super) fn check(&self, links: &[QueueLink]) -> Vec<usize> {
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
  words: Vec<AtomicU64>,
  dead: Vec<AtomicU64>,
  lanes: usize,
}

impl ParkedMask {
  #[cfg(test)]
  pub(super) fn new(lanes: usize) -> Self {
    assert!(lanes > 0);
    Self {
      words: (0..lanes.div_ceil(64)).map(|_| AtomicU64::new(0)).collect(),
      dead: (0..lanes.div_ceil(64)).map(|_| AtomicU64::new(0)).collect(),
      lanes,
    }
  }

  pub(super) fn try_new(lanes: usize) -> Result<Self, std::collections::TryReserveError> {
    let mut words = Vec::new();
    words.try_reserve_exact(lanes.div_ceil(64))?;
    words.resize_with(lanes.div_ceil(64), || AtomicU64::new(0));
    let mut dead = Vec::new();
    dead.try_reserve_exact(lanes.div_ceil(64))?;
    dead.resize_with(lanes.div_ceil(64), || AtomicU64::new(0));
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

  pub(super) fn claim_any(&self, start: usize) -> Option<usize> {
    // Pair the producer's length publication with its mask scan in Loom's
    // model of the SeqCst total order. Native accesses already have it.
    #[cfg(loom)]
    loom::sync::atomic::fence(Ordering::SeqCst);
    (0..self.lanes)
      .map(|offset| (start % self.lanes + offset) % self.lanes)
      .find(|&lane| !self.is_dead(lane) && self.is_set(lane) && self.claim(lane))
  }

  pub(super) fn first_clear_from(&self, start: usize) -> Option<usize> {
    (0..self.lanes)
      .map(|offset| (start % self.lanes + offset) % self.lanes)
      .find(|&lane| !self.is_set(lane))
  }
}

/// Skip parked lanes using only the rotating counter value and parked state. The caller advances the counter, independent of its identity.
pub(super) fn choose_lane(next_lane: usize, parked: &ParkedMask) -> usize {
  let start = next_lane % parked.lanes;
  parked.first_clear_from(start).unwrap_or_else(|| {
    let live = (0..parked.lanes)
      .map(|offset| (start + offset) % parked.lanes)
      .find(|&lane| !parked.is_dead(lane))
      .unwrap_or(start);
    let _ = parked.claim(live);
    live
  })
}

/// Round-robin selection, retained for comparison by the upcoming engine.
pub(super) fn choose_lane_round_robin(next_lane: usize, parked: &ParkedMask) -> usize {
  let start = next_lane % parked.lanes;
  let live = (0..parked.lanes)
    .map(|offset| (start + offset) % parked.lanes)
    .find(|&lane| !parked.is_dead(lane))
    .unwrap_or(start);
  let _ = parked.claim(live);
  live
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

/// The final park handshake after own/steal/overflow searches
/// failed. A true result permits the caller to test `prepare_sleep` under its
/// lane lock and wait there. A false result requires a fresh full search.
/// The iterator must load SeqCst lengths lazily, after advertisement, and the
/// closure must load overflow the same way. Producers publish a SeqCst length
/// before claiming and kicking a sleeper.
pub(super) fn search_or_park(
  seat: usize,
  parked: &ParkedMask,
  lane_len: impl IntoIterator<Item = (usize, usize)>,
  overflow_hint: impl FnOnce() -> usize,
) -> bool {
  parked.advertise(seat);
  let work = lane_len
    .into_iter()
    .any(|(lane, len)| lane != seat && len >= 2)
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
  fn steal_bounds_oldest_first_and_chain_links() {
    for len in 0..=STEAL_MAX * 4 {
      let links: Vec<_> = (0..=len).map(|_| QueueLink::new()).collect();
      let mut victim = LaneQueue::new();
      for index in 0..len {
        assert!(!victim.push(&links, index));
      }
      let mut thief = LaneQueue::new();
      let chain = victim.steal_front(&links);
      if len < 2 {
        assert!(chain.is_none());
        assert_eq!(victim.len(), len);
        victim.check(&links);
        continue;
      }
      let chain = chain.unwrap();
      let taken = (len / 2).min(STEAL_MAX);
      assert_eq!(chain.len, taken);
      assert_eq!(chain.first, 0);
      assert_eq!(chain.last, taken - 1);
      assert_eq!(victim.len(), len - taken);
      assert!(victim.len() >= 1);
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
  fn both_lane_choices_use_only_counter_and_parked_state() {
    let mask = ParkedMask::new(3);
    for counter in 0..12 {
      assert_eq!(choose_lane(counter, &mask), counter % 3);
      assert_eq!(choose_lane_round_robin(counter, &mask), counter % 3);
    }
    mask.advertise(1);
    assert_eq!(choose_lane(1, &mask), 2);
    assert!(mask.is_set(1));
    assert_eq!(choose_lane_round_robin(1, &mask), 1);
    assert!(!mask.is_set(1));
    for variant in [choose_lane, choose_lane_round_robin] {
      for lane in 0..3 {
        mask.advertise(lane);
      }
      assert_eq!(variant(4, &mask), 1);
      assert!(!mask.is_set(1));
    }
  }

  #[test]
  fn lane_choice_is_independent_of_calling_thread() {
    for variant in [choose_lane, choose_lane_round_robin] {
      let sequence = move || {
        let mask = ParkedMask::new(4);
        mask.advertise(1);
        mask.advertise(3);
        (0..32)
          .map(|counter| variant(counter, &mask))
          .collect::<Vec<_>>()
      };
      let expected = sequence();
      let first = std::thread::spawn(sequence);
      let second = std::thread::spawn(sequence);
      assert_eq!(first.join().unwrap(), expected);
      assert_eq!(second.join().unwrap(), expected);
    }
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
  fn park_rescans_stealable_lanes_and_overflow() {
    let mask = ParkedMask::new(2);
    let lengths = [AtomicUsize::new(0), AtomicUsize::new(1)];
    let overflow = AtomicUsize::new(0);
    assert!(search_or_park(
      0,
      &mask,
      lengths
        .iter()
        .enumerate()
        .map(|(lane, len)| (lane, len.load(Ordering::SeqCst))),
      || overflow.load(Ordering::SeqCst),
    ));
    assert!(mask.claim(0));
    lengths[1].store(2, Ordering::SeqCst);
    assert!(!search_or_park(
      0,
      &mask,
      lengths
        .iter()
        .enumerate()
        .map(|(lane, len)| (lane, len.load(Ordering::SeqCst))),
      || overflow.load(Ordering::SeqCst),
    ));
    assert!(!mask.is_set(0));
    lengths[1].store(1, Ordering::SeqCst);
    overflow.store(1, Ordering::SeqCst);
    assert!(!search_or_park(
      0,
      &mask,
      lengths
        .iter()
        .enumerate()
        .map(|(lane, len)| (lane, len.load(Ordering::SeqCst))),
      || overflow.load(Ordering::SeqCst),
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
              queue.check(&links);
              if let Some(index) = queue.pop(&links) {
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
                let notify = queue.push(&links, index);
                queue.check(&links);
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
      assert!(lane.0.lock().unwrap().check(&links).is_empty());
    });
  }

  #[test]
  fn loom_steal_races_owner_pop() {
    bounded_model(|| {
      for count in [3, 4] {
        let links = Arc::new((0..=count).map(|_| QueueLink::new()).collect::<Vec<_>>());
        let mut initial = LaneQueue::new();
        for index in 0..count {
          initial.push(&links, index);
        }
        let victim = Arc::new(Mutex::new(initial));
        let owner = {
          let links = Arc::clone(&links);
          let victim = Arc::clone(&victim);
          thread::spawn(move || {
            let mut popped = Vec::new();
            for _ in 0..count {
              let mut queue = victim.lock().unwrap();
              if let Some(index) = queue.pop(&links) {
                popped.push(index);
              }
              queue.check(&links);
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
              let before = queue.check(&links);
              queue.steal_front(&links).map(|chain| {
                assert!(queue.len() >= 1, "steal emptied victim");
                assert_eq!(chain.len, (before.len() / 2).min(STEAL_MAX));
                assert_eq!(chain.first, before[0]);
                assert_eq!(chain.last, before[chain.len - 1]);
                queue.check(&links);
                let expected = before[..chain.len].to_vec();
                (chain, expected)
              })
            };
            // Acquiring the receiving lane only after releasing the victim.
            let own = Mutex::new(LaneQueue::new());
            let mut own = own.lock().unwrap();
            own.push(&links, count);
            let mut expected = vec![count];
            if let Some((chain, indices)) = stolen {
              expected.extend(indices);
              own.append_chain(&links, chain);
            }
            assert_eq!(own.check(&links), expected);
            let mut popped = Vec::new();
            while let Some(index) = own.pop(&links) {
              popped.push(index);
              own.check(&links);
            }
            assert_eq!(popped, expected);
            popped
          })
        };
        let mut popped = owner.join().unwrap();
        popped.extend(thief.join().unwrap());
        popped.sort_unstable();
        assert_eq!(popped, (0..=count).collect::<Vec<_>>());
        assert!(victim.lock().unwrap().check(&links).is_empty());
      }
    });
  }

  /// Keep the final sleep decision observable rather than actually waiting:
  /// an invalid decision fails an assertion instead of hanging the model.
  fn steal_push_park(other_parked: bool) {
    let links = Arc::new([QueueLink::new(), QueueLink::new()]);
    let mut initial = LaneQueue::new();
    initial.push(&links[..], 0);
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
      AtomicUsize::new(1),
      AtomicUsize::new(0),
    ]);
    let kick = Arc::new(Mutex::new(None));
    let searcher = {
      let (links, victim, sleeper, parked, lengths) = (
        Arc::clone(&links),
        Arc::clone(&victim),
        Arc::clone(&sleeper),
        Arc::clone(&parked),
        Arc::clone(&lengths),
      );
      thread::spawn(move || {
        let chain = {
          let mut queue = victim.lock().unwrap();
          let chain = queue.steal_front(&links[..]);
          lengths[1].store(queue.len(), Ordering::SeqCst);
          queue.check(&links[..]);
          chain
        };
        if let Some(chain) = chain {
          let mut own = sleeper.lock().unwrap();
          own.append_chain(&links[..], chain);
          return false;
        }
        if search_or_park(
          0,
          &parked,
          lengths
            .iter()
            .enumerate()
            .map(|(lane, len)| (lane, len.load(Ordering::SeqCst))),
          || 0,
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
          queue.len() >= 2
        };
        if remains && let Some(seat) = parked.claim_any(if other_parked { 2 } else { 0 }) {
          assert!(seat == 0 || (other_parked && seat == 2));
          // A claimed holder gets a recheck even before it enters wait.
          let holder = if seat == 0 { &sleeper } else { &other };
          let saw_sleeping = holder.lock().unwrap().request_recheck();
          *kick.lock().unwrap() = Some((seat, saw_sleeping));
        }
      })
    };
    let asleep = searcher.join().unwrap();
    pusher.join().unwrap();
    let kick = *kick.lock().unwrap();
    assert!(
      !asleep || lengths[1].load(Ordering::SeqCst) < 2 || kick.is_some(),
      "parked with stealable work and no kick"
    );
    if let Some((seat, saw_sleeping)) = kick {
      // A kick before the final lane check must prevent sleep; a later
      // kick must observe sleeping so that its caller sends a notification.
      assert!(
        (seat == 0 && !asleep) || saw_sleeping,
        "holder slept but its kick did not observe sleeping"
      );
    }
    let mut popped = Vec::new();
    for queue in [&victim, &sleeper] {
      let mut queue = queue.lock().unwrap();
      queue.finish_sleep();
      while let Some(index) = queue.pop(&links[..]) {
        popped.push(index);
      }
      queue.check(&links[..]);
    }
    popped.sort_unstable();
    assert_eq!(popped, [0, 1]);
  }

  #[test]
  fn loom_steal_push_park_has_a_searcher_or_kick() {
    bounded_model(|| steal_push_park(false));
  }

  #[test]
  fn loom_work_remains_may_wake_another_parked_holder() {
    bounded_model(|| steal_push_park(true));
  }

  #[test]
  fn target_and_victim_choices_use_only_policy_inputs() {
    bounded_model(|| {
      let parked = ParkedMask::new(3);
      parked.advertise(1);
      assert_eq!(choose_lane(1, &parked), 2);
      assert_eq!(choose_lane_round_robin(1, &parked), 1);
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
