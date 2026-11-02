//! Lowest-index free task slots, accessed only under the admission mutex.

#![forbid(unsafe_code)]

use super::{AsyncError, payload_bytes};

pub(super) struct FreeSlots {
  // One bit per slot; no additional index or summary storage.
  words: Vec<u64>,
}

impl FreeSlots {
  pub(super) fn requested_control(slots: usize) -> Result<usize, AsyncError> {
    payload_bytes::<u64>(slots.div_ceil(64)).map_err(AsyncError::ResourceDomain)
  }

  pub(super) fn actual_control(&self) -> Result<usize, AsyncError> {
    payload_bytes::<u64>(self.words.capacity()).map_err(AsyncError::ResourceDomain)
  }

  pub(super) fn new(slots: usize) -> Result<Self, AsyncError> {
    let count = slots.div_ceil(64);
    let mut words = Vec::new();
    words
      .try_reserve_exact(count)
      .map_err(|_| AsyncError::OutOfMemory)?;
    words.resize(count, u64::MAX);
    if !slots.is_multiple_of(64) {
      words[count - 1] = (1u64 << (slots % 64)) - 1;
    }
    Ok(Self { words })
  }

  pub(super) fn first(&self) -> Option<usize> {
    self
      .words
      .iter()
      .enumerate()
      .find_map(|(index, &word)| (word != 0).then(|| index * 64 + word.trailing_zeros() as usize))
  }

  #[cfg(all(test, not(loom)))]
  pub(super) fn pop(&mut self) -> Option<usize> {
    let index = self.first()?;
    self.remove(index);
    Some(index)
  }

  pub(super) fn remove(&mut self, index: usize) {
    self.words[index / 64] &= !(1u64 << (index % 64));
  }

  pub(super) fn insert(&mut self, index: usize) {
    let word = &mut self.words[index / 64];
    let bit = 1u64 << (index % 64);
    debug_assert_eq!(*word & bit, 0);
    *word |= bit;
  }

  #[cfg(all(test, not(loom)))]
  pub(super) fn clear(&mut self) {
    self.words.fill(0);
  }

  #[cfg(all(test, not(loom)))]
  pub(super) fn iter(&self) -> impl Iterator<Item = usize> + '_ {
    self.words.iter().enumerate().flat_map(|(index, &word)| {
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
      for index in 0..capacity {
        assert_eq!(slots.pop(), Some(index));
      }
      assert_eq!(slots.pop(), None);
      for index in (0..capacity).rev().filter(|index| !index.is_multiple_of(3)) {
        slots.insert(index);
      }
      for index in (0..capacity).filter(|index| !index.is_multiple_of(3)) {
        assert_eq!(slots.pop(), Some(index));
      }
      assert_eq!(slots.pop(), None);
    }
  }
}
