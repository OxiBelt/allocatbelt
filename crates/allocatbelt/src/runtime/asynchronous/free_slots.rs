//! Lowest-index free task slots, accessed only under the admission mutex.

#![forbid(unsafe_code)]

use super::{AsyncError, payload_bytes};

// Declaration order is layout order: the inline word leads, next to the
// admission state's other hot fields.
#[repr(C)]
pub(super) struct FreeSlots {
  // One bit per slot; no additional index or summary storage. The first
  // word is stored inline, with the admission state the admission lock
  // brings in, so lowest-index reuse of the first 64 slots never touches
  // the heap table that holds the remaining words.
  first: u64,
  rest: Vec<u64>,
}

impl FreeSlots {
  pub(super) fn requested_control(slots: usize) -> Result<usize, AsyncError> {
    payload_bytes::<u64>(slots.div_ceil(64).saturating_sub(1)).map_err(AsyncError::ResourceDomain)
  }

  pub(super) fn actual_control(&self) -> Result<usize, AsyncError> {
    payload_bytes::<u64>(self.rest.capacity()).map_err(AsyncError::ResourceDomain)
  }

  pub(super) fn new(slots: usize) -> Result<Self, AsyncError> {
    let count = slots.div_ceil(64);
    let mut rest = Vec::new();
    rest
      .try_reserve_exact(count.saturating_sub(1))
      .map_err(|_| AsyncError::OutOfMemory)?;
    rest.resize(count.saturating_sub(1), u64::MAX);
    let mut this = Self {
      first: if count == 0 { 0 } else { u64::MAX },
      rest,
    };
    if !slots.is_multiple_of(64) {
      *this.word_mut(count - 1) = (1u64 << (slots % 64)) - 1;
    }
    Ok(this)
  }

  fn word_mut(&mut self, index: usize) -> &mut u64 {
    match index.checked_sub(1) {
      None => &mut self.first,
      Some(rest) => &mut self.rest[rest],
    }
  }

  fn words(&self) -> impl Iterator<Item = u64> + '_ {
    std::iter::once(self.first).chain(self.rest.iter().copied())
  }

  pub(super) fn first(&self) -> Option<usize> {
    self
      .words()
      .enumerate()
      .find_map(|(index, word)| (word != 0).then(|| index * 64 + word.trailing_zeros() as usize))
  }

  #[cfg(all(test, not(loom)))]
  pub(super) fn pop(&mut self) -> Option<usize> {
    let index = self.first()?;
    self.remove(index);
    Some(index)
  }

  pub(super) fn remove(&mut self, index: usize) {
    *self.word_mut(index / 64) &= !(1u64 << (index % 64));
  }

  pub(super) fn insert(&mut self, index: usize) {
    let word = self.word_mut(index / 64);
    let bit = 1u64 << (index % 64);
    debug_assert_eq!(*word & bit, 0);
    *word |= bit;
  }

  #[cfg(all(test, not(loom)))]
  pub(super) fn clear(&mut self) {
    self.first = 0;
    self.rest.fill(0);
  }

  #[cfg(all(test, not(loom)))]
  pub(super) fn iter(&self) -> impl Iterator<Item = usize> + '_ {
    self.words().enumerate().flat_map(|(index, word)| {
      (0..64).filter_map(move |bit| (word & (1u64 << bit) != 0).then_some(index * 64 + bit))
    })
  }
}

#[cfg(all(test, not(loom)))]
mod tests {
  use super::FreeSlots;

  #[test]
  fn lowest_reuse_across_bitmap_words_and_partial_words() {
    for capacity in [0, 1, 63, 64, 65, 2048, 4095, 4096, 4097, 8193] {
      let mut slots = FreeSlots::new(capacity).unwrap();
      assert_eq!(slots.rest.len(), capacity.div_ceil(64).saturating_sub(1));
      for index in 0..capacity {
        assert_eq!(slots.pop(), Some(index));
      }
      assert_eq!(slots.pop(), None);
      for index in (0..capacity).rev().filter(|index| !index.is_multiple_of(3)) {
        slots.insert(index);
      }
      let expected: Vec<_> = (0..capacity)
        .filter(|index| !index.is_multiple_of(3))
        .collect();
      assert_eq!(slots.iter().collect::<Vec<_>>(), expected);
      for index in expected {
        assert_eq!(slots.pop(), Some(index));
      }
      assert_eq!(slots.pop(), None);
      slots.clear();
      assert_eq!(slots.first(), None);
    }
  }
}
