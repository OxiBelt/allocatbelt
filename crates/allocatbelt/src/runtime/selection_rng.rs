//! Small pseudorandom state for fair future-selection start positions.
//!
//! This generator only changes which enabled future is polled first. It is
//! not suitable for allocator hardening, secrets, or any security decision.

#![forbid(unsafe_code)]

use std::collections::hash_map::RandomState;
use std::error::Error;
use std::fmt;
use std::hash::{BuildHasher, Hasher};

/// A nonblocking OS-entropy request did not produce a complete seed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectionRngError;

impl fmt::Display for SelectionRngError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("nonblocking OS entropy was unavailable")
  }
}

impl Error for SelectionRngError {}

/// A small pseudorandom generator used only to choose the first selection
/// branch to poll. It is not a cryptographic random number generator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectionRng {
  state: u64,
}

impl SelectionRng {
  /// Creates a selection generator from 64 bits of nonblocking kernel entropy.
  ///
  /// This performs `getrandom(GRND_NONBLOCK)` immediately, so callers should
  /// construct the generator before polling a selection future. An early-boot
  /// entropy shortage is returned as an error rather than blocking.
  pub fn from_entropy() -> Result<Self, SelectionRngError> {
    #[cfg(not(loom))]
    {
      let mut bytes = [0_u8; 8];
      match rustix::rand::getrandom(&mut bytes, rustix::rand::GetRandomFlags::NONBLOCK) {
        Ok(8) => Ok(Self::from_seed(u64::from_ne_bytes(bytes))),
        Ok(_) | Err(_) => Err(SelectionRngError),
      }
    }
    // Same-source protocol models have no operating-system entropy service.
    #[cfg(loom)]
    Err(SelectionRngError)
  }

  /// Creates a deterministic selection generator from `seed`.
  ///
  /// This is useful for reproducible tests and simulations. The seed is not
  /// expanded or protected for cryptographic use.
  #[must_use]
  pub const fn from_seed(seed: u64) -> Self {
    Self { state: seed }
  }

  /// Creates a generator from nonblocking kernel entropy, or from the
  /// standard library's process-randomized hash seed when the kernel refuses
  /// a nonblocking request.
  ///
  /// This is the default used by [`select!`](crate::select!). The fallback
  /// affects fairness only and must never be used for allocator hardening.
  #[must_use]
  pub fn from_entropy_or_random_state() -> Self {
    Self::from_entropy().unwrap_or_else(|_| {
      let mut hasher = RandomState::new().build_hasher();
      hasher.write_u64(0x7365_6c65_6374_696f);
      Self::from_seed(hasher.finish())
    })
  }

  pub(in crate::runtime) fn index(&mut self, upper: usize) -> usize {
    assert!(upper != 0, "selection needs an enabled branch");
    let upper = upper as u64;
    let threshold = upper.wrapping_neg() % upper;
    loop {
      let value = self.next_u64();
      if value >= threshold {
        return (value % upper) as usize;
      }
    }
  }

  fn next_u64(&mut self) -> u64 {
    self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = self.state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
  }
}

#[cfg(test)]
mod tests {
  use super::SelectionRng;

  #[test]
  fn seeded_generators_repeat_and_cover_a_small_range() {
    fn assert_copy<T: Copy>() {}
    assert_copy::<SelectionRng>();
    assert_copy::<crate::runtime::concurrency::SelectPolicy>();
    assert_copy::<crate::runtime::concurrency_many::SelectionPolicy>();

    let mut first = SelectionRng::from_seed(7);
    let mut second = SelectionRng::from_seed(7);
    let sequence = (0..128).map(|_| first.index(5)).collect::<Vec<_>>();
    let repeated = (0..128).map(|_| second.index(5)).collect::<Vec<_>>();
    assert_eq!(sequence, repeated);
    assert!(sequence.iter().all(|index| *index < 5));
    assert!((0..5).all(|index| sequence.contains(&index)));
  }

  #[test]
  fn zero_seed_still_advances() {
    let mut rng = SelectionRng::from_seed(0);
    let initial = rng.state;
    let _ = rng.next_u64();
    assert_ne!(rng.state, initial);
  }
}
